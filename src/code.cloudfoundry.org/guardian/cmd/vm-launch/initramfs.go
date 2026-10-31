//go:build linux

package main

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// File type bits of a newc cpio header mode field.
const (
	cpioTypeDir     = 0o040000
	cpioTypeRegular = 0o100000
	cpioTypeCharDev = 0o020000
	cpioTypeFIFO    = 0o010000

	cpioPermMask   = 0o7777
	cpioHeaderSize = 110
	cpioTrailer    = "TRAILER!!!"
	cpioMaxSize    = 0xffffffff
)

// cpioWriter writes a newc ("070701") cpio archive, the format the Linux
// kernel unpacks as an initramfs. Entries must be added parents first.
type cpioWriter struct {
	w   io.Writer
	ino uint32
}

func newCPIOWriter(w io.Writer) *cpioWriter {
	return &cpioWriter{w: w}
}

// Dir adds a directory entry.
func (c *cpioWriter) Dir(name string, perm uint32) error {
	return c.entry(name, cpioTypeDir, perm, 2, 0, 0, 0)
}

// CharDevice adds a character device node with the given major and minor numbers.
func (c *cpioWriter) CharDevice(name string, perm, major, minor uint32) error {
	return c.entry(name, cpioTypeCharDev, perm, 1, 0, major, minor)
}

// FIFO adds a named pipe.
func (c *cpioWriter) FIFO(name string, perm uint32) error {
	return c.entry(name, cpioTypeFIFO, perm, 1, 0, 0, 0)
}

// File adds a regular file holding exactly size bytes read from r.
func (c *cpioWriter) File(name string, perm uint32, size int64, r io.Reader) error {
	if size < 0 || size > cpioMaxSize {
		return fmt.Errorf("cpio entry %q: size %d outside newc range 0..%d", name, size, uint32(cpioMaxSize))
	}
	if err := c.entry(name, cpioTypeRegular, perm, 1, uint32(size), 0, 0); err != nil {
		return err
	}
	n, err := io.CopyN(c.w, r, size)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("cpio entry %q: source ended after %d of %d bytes", name, n, size)
		}
		return fmt.Errorf("cpio entry %q: copying data: %w", name, err)
	}
	return c.pad(size)
}

// Close writes the trailer entry. It does not close the underlying writer.
func (c *cpioWriter) Close() error {
	return c.header(cpioTrailer, 0, 0, 1, 0, 0, 0)
}

func (c *cpioWriter) entry(name string, fileType, perm, nlink, size, major, minor uint32) error {
	if name == "" || name == cpioTrailer || strings.HasPrefix(name, "/") || path.Clean(name) != name || strings.ContainsRune(name, 0) {
		return fmt.Errorf("cpio entry name %q must be a clean relative path", name)
	}
	if perm&^cpioPermMask != 0 {
		return fmt.Errorf("cpio entry %q: permission bits %o outside %o", name, perm, cpioPermMask)
	}
	c.ino++
	return c.header(name, c.ino, fileType|perm, nlink, size, major, minor)
}

func (c *cpioWriter) header(name string, ino, mode, nlink, size, major, minor uint32) error {
	namesize := len(name) + 1
	hdr := fmt.Sprintf("070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		ino, mode, 0, 0, nlink, 0, size, 0, 0, major, minor, namesize, 0)
	if _, err := io.WriteString(c.w, hdr+name+"\x00"); err != nil {
		return fmt.Errorf("cpio entry %q: writing header: %w", name, err)
	}
	return c.pad(int64(cpioHeaderSize + namesize))
}

func (c *cpioWriter) pad(n int64) error {
	if rem := n % 4; rem != 0 {
		if _, err := c.w.Write(make([]byte, 4-rem)); err != nil {
			return fmt.Errorf("cpio: writing padding: %w", err)
		}
	}
	return nil
}

// Serial console markers written by the guest's stage 2, /rvm/init. The
// nonce makes them impossible to forge by accident from guest command
// output. The guest command runs as root and can read the nonce from
// /rvm/init, so it can forge them on purpose, which changes only what
// vm-launch reports for that command: its exit status, whether its own
// ports are open, and whether vm-launch reports that the guest ran out of
// memory.
func startTag(nonce string) string  { return "RVM_START_" + nonce }
func exitTag(nonce string) string   { return "RVM_EXIT_" + nonce + "=" }
func listenTag(nonce string) string { return "RVM_LISTEN_" + nonce + "=" }
func oomTag(nonce string) string    { return "RVM_OOM_" + nonce + "=" }

// stopTag is the stop request, the one line vm-launch writes to the guest's
// serial console, which the guest's stop reader acts on (see
// guestStopReader). The nonce frames the request, so no other console input
// matches it by accident. It is no secret from the guest command, which can
// read it from /rvm/init, and a forged request only stops that command,
// which it can do anyway.
func stopTag(nonce string) string { return "RVM_STOP_" + nonce }

// guestRootInit is the guest /init, stage 1 of the guest's boot. It
// installs busybox's applets, mounts /proc, /sys, and /dev, and finds the
// guest's drives by their identities, which /rvm/disks gives (see disksFile
// and newGuestDrives), because neither hypervisor promises a device order
// and drives may share a size. A guest with a root disk then gets its
// overlay root: stage 1 formats the root disk as ext2, mounts it with online
// discard, mounts an overlay with the initramfs as the lower layer and the
// disk as the upper, moves /proc, /sys, and /dev into it, moves it onto /,
// and runs stage 2, /rvm/init (see initScript), inside it through chroot.
// switch_root would first delete the initramfs, which is the lower layer,
// and the kernel refuses pivot_root on rootfs, so stage 1 takes switch_root's
// last two steps by hand. A guest without a root disk, which is a guest
// without a disk quota, runs stage 2 on the initramfs, its root in RAM.
// Either way stage 2 gets one argument per volume, in volume order, each the
// device of that volume's drive, and no argument without a volume, because a
// variable /init exported would reach the command. The kernel hands /init
// the boot parameters it does not know as arguments, so stage 1 replaces
// them.
//
// Stage 1 must never format a volume, so it formats only the device whose
// identity is the root's, and only when that device's first 64 KiB read as
// all zero, as a new image's do. Each other case fails the boot: a malformed
// /rvm/disks, a root size without an inode ratio, two drives that /rvm/disks
// gives one identity, a vd device whose identity /rvm/disks gives no drive,
// two devices with one drive's identity, a drive whose size is not the one
// /rvm/disks gives, a root disk that is not blank, a /dev that is not a
// devtmpfs mount, an overlay root without a shell or a stage 2, and a drive
// that has not appeared, as a sysfs entry with a readable identity and size
// and as a device node, after six checks a second apart. Stage 1 writes no
// console marker, so a failure reboots before the start tag and vm-launch
// shows the console, which ends with the failed step.
const guestRootInit = `#!/bin/busybox sh
/bin/busybox --install -s /bin
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
rvm_devtmpfs=
mount -t devtmpfs dev /dev 2>/dev/null && rvm_devtmpfs=1
` + guestFailFunc + guestDiskFind + guestRootSetup + `exec /bin/sh ` + guestStage2 + ` "$@"
`

// guestStage2 is where the initramfs holds stage 2 of the guest's boot.
const guestStage2 = "/rvm/init"

// guestDiskFunc defines the helpers of the drive search. rvm_number
// succeeds for a positive decimal number without leading zeros, the form in
// which sysfs gives a size, and rvm_ident for an identity as checkDriveIDs
// allows one: 1 to virtioBlockIDBytes letters, digits, and hyphens.
//
// rvm_scan makes one pass over the vd devices under /sys/block, and it
// succeeds only when every drive in rvm_drives has turned up in that pass,
// so a pass that ran before a late probe never satisfies it. Each drive key
// in rvm_drives, root or volN, has its identity in rvm_want_KEY, its size in
// sectors in rvm_sectors_KEY, and the words that name it in rvm_label_KEY,
// and the pass sets rvm_dev_KEY to the device it found the drive on. A
// device is a drive's when its serial, the identity both hypervisors give
// the guest at /sys/block/vdX/serial, equals the drive's identity exactly.
// Every vd device must be one drive's: a device without an identity or with
// an identity no drive has, two devices with one drive's identity, and a
// drive whose device has another size fail the boot at once, because stage
// 1 never guesses which device is which and never uses a device of the
// right size and the wrong identity. A device whose identity or size cannot
// be read yet, and a drive without its device node, make the pass fail, with
// rvm_missing saying why, so that the caller checks again.
const guestDiskFunc = `rvm_number() { case "$1" in '' | 0* | *[!0-9]*) return 1 ;; esac; }
rvm_ident() {
	case "$1" in '' | *[!A-Za-z0-9-]*) return 1 ;; esac
	[ "${#1}" -le ` + virtioBlockIDBytesText + ` ]
}
rvm_scan() {
	rvm_missing=
	for rvm_d in $rvm_drives; do
		eval "rvm_dev_$rvm_d="
	done
	for rvm_b in /sys/block/vd*; do
		[ -e "$rvm_b" ] || continue
		rvm_n=/dev/${rvm_b##*/}
		if ! rvm_id=$(cat "$rvm_b/serial" 2>/dev/null); then
			rvm_missing="${rvm_missing:+$rvm_missing, and }no readable identity yet on the block device $rvm_n"
			continue
		fi
		[ -n "$rvm_id" ] || rvm_fail "the block device $rvm_n has no identity, so it is no drive /rvm/disks names, and the guest will not boot with it"
		rvm_m=
		for rvm_d in $rvm_drives; do
			eval "rvm_w=\$rvm_want_$rvm_d"
			if [ "$rvm_w" = "$rvm_id" ]; then
				rvm_m=$rvm_d
				break
			fi
		done
		[ -n "$rvm_m" ] || rvm_fail "the block device $rvm_n has the identity $rvm_id, which /rvm/disks gives no drive, so the guest will not boot with it"
		eval "rvm_o=\$rvm_dev_$rvm_m rvm_l=\$rvm_label_$rvm_m rvm_w=\$rvm_sectors_$rvm_m"
		[ -z "$rvm_o" ] || rvm_fail "two block devices, $rvm_o and $rvm_n, have the identity $rvm_id of the $rvm_l, so the guest cannot tell which one it is"
		eval "rvm_dev_$rvm_m=\$rvm_n"
		if [ -r "$rvm_b/size" ] && read -r rvm_s 2>/dev/null <"$rvm_b/size"; then
			[ "$rvm_s" = "$rvm_w" ] || rvm_fail "the $rvm_l $rvm_n has $rvm_s sectors, and /rvm/disks gives it $rvm_w, so the guest will not use it"
			[ -b "$rvm_n" ] || rvm_missing="${rvm_missing:+$rvm_missing, and }no device node $rvm_n yet for the $rvm_l"
		else
			rvm_missing="${rvm_missing:+$rvm_missing, and }no readable size yet for the $rvm_l on $rvm_n"
		fi
	done
	for rvm_d in $rvm_drives; do
		eval "rvm_o=\$rvm_dev_$rvm_d rvm_l=\$rvm_label_$rvm_d rvm_w=\$rvm_want_$rvm_d"
		[ -n "$rvm_o" ] || rvm_missing="${rvm_missing:+$rvm_missing, and }no block device with the identity $rvm_w for the $rvm_l"
	done
	[ -z "$rvm_missing" ]
}
`

// virtioBlockIDBytesText is virtioBlockIDBytes in decimal, as the guest's
// shell compares it. A spec keeps the two equal.
const virtioBlockIDBytesText = "20"

// guestDiskFind reads and checks /rvm/disks, waits for the drives it names,
// and leaves the root's device in rvm_root, or nothing without a root, and
// the volumes' devices, in volume order, as stage 1's positional arguments,
// which it hands to stage 2. It checks every drive /rvm/disks names before
// it looks at any device: each identity must be one rvm_ident accepts and no
// other drive's, each size a positive number of sectors, and the volume
// count from 0 to maxVolumes. Volumes are numbered by volume index across
// every volume, shares included. An image volume and a block volume each
// have a drive, which stage 1 finds in the same way, by identity and size. A
// share has no drive, so its index is skipped and its argument is empty; a
// vd device is still one of the drives /rvm/disks names or the boot fails. A
// volume without a kind is an error, since a cut-short table would otherwise
// read as volumes without drives, and so is a kind the guest does not know.
// A share that /rvm/disks gives a drive identity or size fails the boot too,
// since a share has no drive. Every drive is built into the guest kernel and
// normally ready before /init runs; the wait covers a late probe. A drive
// that has not appeared after six checks fails the boot with a line that
// names it and its identity. rvm_dev_root is cleared with the drive list, so
// that a variable the kernel left in init's environment can never stand in
// for a root drive that /rvm/disks does not name.
const guestDiskFind = guestDiskFunc + `. /rvm/disks
rvm_drives=
rvm_dev_root=
if [ -n "${RVM_ROOT_ID:-}${RVM_ROOT_SECTORS:-}" ]; then
	rvm_number "${RVM_ROOT_SECTORS:-}" && rvm_number "${RVM_ROOT_INODE_RATIO:-}" || rvm_fail "the guest root size or inode ratio in /rvm/disks is not a positive number"
	rvm_ident "${RVM_ROOT_ID:-}" || rvm_fail "the guest root drive's identity in /rvm/disks is not 1 to ` + virtioBlockIDBytesText + ` letters, digits, and hyphens"
	rvm_drives=root
	rvm_want_root=$RVM_ROOT_ID
	rvm_sectors_root=$RVM_ROOT_SECTORS
	rvm_label_root="guest root drive"
fi
case "${RVM_VOLUMES:-}" in
[0-` + maxVolumesText + `]) ;;
*) rvm_fail "the volume count in /rvm/disks is not a number from 0 to ` + maxVolumesText + `" ;;
esac
rvm_i=0
while [ "$rvm_i" -lt "$RVM_VOLUMES" ]; do
	rvm_l="volume drive vol$rvm_i"
	eval "rvm_k=\${RVM_VOL${rvm_i}_KIND:-} rvm_w=\${RVM_VOL${rvm_i}_ID:-} rvm_s=\${RVM_VOL${rvm_i}_SECTORS:-}"
	case "$rvm_k" in
	` + string(driveImage) + ` | ` + string(driveBlock) + `) ;;
	` + volumeKindShare + `)
		[ -z "$rvm_w$rvm_s" ] || rvm_fail "the volume vol$rvm_i in /rvm/disks is a share, which has no drive, yet it has a drive identity or size"
		eval "rvm_dev_vol$rvm_i="
		rvm_i=$((rvm_i + 1))
		continue
		;;
	'') rvm_fail "the $rvm_l in /rvm/disks has no kind" ;;
	*) rvm_fail "the $rvm_l in /rvm/disks has the kind $rvm_k, which the guest does not know" ;;
	esac
	rvm_ident "$rvm_w" || rvm_fail "the $rvm_l's identity in /rvm/disks is not 1 to ` + virtioBlockIDBytesText + ` letters, digits, and hyphens"
	rvm_number "$rvm_s" || rvm_fail "the $rvm_l's size in /rvm/disks is not a positive number"
	for rvm_d in $rvm_drives; do
		eval "rvm_o=\$rvm_want_$rvm_d rvm_ol=\$rvm_label_$rvm_d"
		[ "$rvm_o" != "$rvm_w" ] || rvm_fail "the $rvm_ol and the $rvm_l have the one identity $rvm_w in /rvm/disks, so the guest cannot tell them apart"
	done
	eval "rvm_want_vol$rvm_i=\$rvm_w rvm_sectors_vol$rvm_i=\$rvm_s rvm_label_vol$rvm_i=\$rvm_l"
	rvm_drives="$rvm_drives vol$rvm_i"
	rvm_i=$((rvm_i + 1))
done
n=0
until rvm_scan; do
	n=$((n + 1))
	[ "$n" -gt 5 ] && rvm_fail "$rvm_missing"
	sleep 1
done
rvm_root=${rvm_dev_root:-}
set --
rvm_i=0
while [ "$rvm_i" -lt "$RVM_VOLUMES" ]; do
	eval "set -- \"\$@\" \"\$rvm_dev_vol$rvm_i\""
	rvm_i=$((rvm_i + 1))
done
`

// volumeKindShare is the kind /rvm/disks gives a volume that is served as a
// share, which has no drive.
const volumeKindShare = "share"

// maxVolumesText is maxVolumes in decimal, as the guest's shell matches it
// with a one-digit pattern. A spec keeps the two equal.
const maxVolumesText = "4"

// Guest scratch files of the root disk's blank check. They live on the
// initramfs and are gone before the overlay is mounted.
const (
	guestRootHead = "/rvm/root-head"
	guestRootUsed = "/rvm/root-used"
)

// guestRootSetup formats the root disk, when the guest has one, and enters
// the overlay root on it. The blank check reads the disk as the volume's
// does (see guestVolumeSetup), and a read error fails the boot. mke2fs makes
// 4096-byte blocks, so that every block the guest frees lines up with the
// host's discard granularity, at the inode ratio vm-launch picked (see
// inodeRatioFor), with no reserved blocks and 256-byte inodes, which hold
// the overlay's extended attributes and 64-bit timestamps even in an image
// under 512 MiB, where busybox would otherwise make 128-byte ones. ext4
// mounts the disk without a journal, which busybox mke2fs never makes, with
// discard, which gives the blocks the guest frees back to the container's
// quota at once, and with errors=continue, so an I/O error from a quota that
// another writer used up leaves the root writable. Overlayfs never crosses a mount in its lower
// layer, so /proc, /sys, /dev, and the two mount points show through it as
// plain directories.
//
// Stage 1 checks everything that can fail before the moves, while it can
// still name the step: that /dev is a devtmpfs mount, and that the overlay
// root holds the shell and the stage 2 script. The last step, exec, replaces
// stage 1 with chroot, and a failure after it ends PID 1 and shows on the
// console as a kernel panic, not as a setup line.
const guestRootSetup = `if [ -n "$rvm_root" ]; then
	[ -n "$rvm_devtmpfs" ] || rvm_fail "mounting devtmpfs at /dev failed"
	dd if="$rvm_root" of=` + guestRootHead + ` bs=4096 count=16 || rvm_fail "reading the start of the guest root disk $rvm_root failed"
	tr -d '\000' <` + guestRootHead + ` >` + guestRootUsed + ` || rvm_fail "checking whether the guest root disk $rvm_root is blank failed"
	rvm_blank=
	[ -s ` + guestRootHead + ` ] && [ ! -s ` + guestRootUsed + ` ] && rvm_blank=1
	rm -f ` + guestRootHead + ` ` + guestRootUsed + `
	[ -n "$rvm_blank" ] || rvm_fail "the guest root disk $rvm_root is not blank, so vm-launch will not format it"
	mke2fs -F -b 4096 -m 0 -I 256 -i "$RVM_ROOT_INODE_RATIO" -L rvm-root "$rvm_root" || rvm_fail "formatting the guest root disk $rvm_root failed"
	mkdir -p /rvm/disk /rvm/root || rvm_fail "creating the guest root mount points failed"
	mount -t ext4 -o noatime,discard,errors=continue "$rvm_root" /rvm/disk || rvm_fail "mounting the guest root disk $rvm_root failed"
	mkdir /rvm/disk/upper /rvm/disk/work || rvm_fail "creating the overlay directories failed"
	mount -t overlay -o lowerdir=/,upperdir=/rvm/disk/upper,workdir=/rvm/disk/work overlay /rvm/root || rvm_fail "mounting the overlay root failed; the guest kernel needs overlayfs"
	[ -x /rvm/root/bin/sh ] || rvm_fail "the overlay root has no /bin/sh to run stage 2"
	[ -r /rvm/root` + guestStage2 + ` ] || rvm_fail "the overlay root has no ` + guestStage2 + `"
	for rvm_m in proc sys dev; do
		mount -o move "/$rvm_m" "/rvm/root/$rvm_m" || rvm_fail "moving /$rvm_m into the overlay root failed"
	done
	cd /rvm/root && mount -o move . / || rvm_fail "moving the overlay root onto / failed"
	exec chroot . /bin/sh ` + guestStage2 + ` "$@"
fi
`

// initScript is the guest /rvm/init, stage 2 of the guest's boot, which
// stage 1 runs on the guest root once it has mounted it (see guestRootInit),
// with each volume's device as an argument, in volume order. It runs the
// command with stdin from /dev/null (the serial console never delivers EOF),
// reports its status on the console, and reboots: with -no-reboot (QEMU) or
// reboot=k (Firecracker) that ends the hypervisor. poweroff -f hangs
// Firecracker, so it is not used. The reboot is reboot -nf: without -n,
// busybox calls sync(2) first, which writes every dirty page of the guest
// root to the root image, data that is discarded at once and that could keep
// the hypervisor up past its grace period. Each volume has its own flush
// (see guestVolumeTeardown), and an image volume's mount is synchronous
// unless the operator turned that off for images with a journal.
//
// First, stage 2 defines rvm_fail, which every setup step uses, and turns
// off console echo. It then mounts /dev/shm, brings up lo and eth0 from
// /rvm/net (in every guest, a task's included), prepares the open-files
// limit from /rvm/limits, and checks that /rvm/env sources. A guest with
// volumes then mounts each one by its kind, formatting only a blank volume
// image, preening every other image with e2fsck -p, never formatting or
// checking a block volume, and growing an image or a block volume online
// when its device is bigger (see guestVolumeSetup). When a setup step
// fails, stage 2 reboots before the start tag, so vm-launch reports a guest
// that never started its command and shows the console output, which ends
// with the failed step. Last before the start tag, stage 2 starts the stop
// reader (see guestStopReader), which it stops again once the command has
// ended.
//
// The command runs in a subshell that records its pid, sets its open-files
// limit, sources /rvm/env, and then becomes the shell that runs /rvm/cmd
// with sh -c, so its status is the command's (see guestRunCommand). Stage 2
// writes the exit line through its own open of /dev/console, because the
// command may have left the console that it shares with stage 2
// non-blocking, and through the shared console only when that open fails.
// The guest environment applies only inside that subshell, never to stage
// 2's own steps, such as the unquoted status in the exit line or the volume
// teardown. A guest with ports watches, while the command runs, whether
// anything listens on each (see guestListenWatch). With volumes, stage 2
// flushes the image and block volumes once, stops the processes the command
// left behind, and then syncs and unmounts each volume, the drive volumes
// before the shares, after the command and before it reports the status,
// and a volume that does not flush or unmount turns a status of 0 into a
// failure (see guestVolumeTeardown).
func initScript(nonce string, volume bool) string {
	setup := guestFailFunc + guestConsoleSetup + guestShmSetup + guestNetworkSetup + guestLimitsSetup + guestEnvChecks
	if volume {
		setup += guestVolumeSetup
	}
	setup += guestStopReader(nonce)
	run := guestListenWatch(nonce) + guestRunCommand + guestRunStatus + guestStopReaderStop + guestListenStop + guestOOMReport(nonce)
	if volume {
		run += guestVolumeTeardown
	}
	exit := "echo " + exitTag(nonce) + "$rvm_status"
	run += exit + " >/dev/console || " + exit + "\n"
	return `#!/bin/busybox sh
export PATH=/bin
` + setup + `echo ` + startTag(nonce) + "\n" + run + `reboot -nf
`
}

// guestConsoleSetup turns off echo on the guest's console, so that the
// stop request vm-launch writes to it never shows in the command's output.
// A console that keeps echo on still delivers the request, so a failure only
// warns.
const guestConsoleSetup = `stty -echo </dev/console || echo "vm-launch guest setup: turning off console echo failed; a stop request will appear in the output"
`

// guestStopReader starts, in every guest, the background stop reader, which
// sends SIGTERM to the command's top process when vm-launch writes the stop
// request (see stopTag) to the console, as runC sends SIGTERM to a
// container's first process. It starts before the start tag, so it is in
// place before vm-launch may write the request, and a request that comes
// before the reader opens the console waits in the console's input buffer.
// The reader compares each console line, blanks and backslashes kept, with
// the request exactly and never evaluates one. It acts on the first request, and then it exits.
//
// The command's subshell records its pid in guestAppPid as it starts (see
// guestRunCommand), so the reader polls for that file every 50 ms when the
// request comes before it. That poll runs sleep; everything else in the
// reader is the shell's builtins, so, like the listen watcher, it keeps
// working when the command has used up the processes the guest can start.
// The reader also sets its own oom_score_adj to -1000, so the guest kernel
// never picks it when the guest runs out of memory.
//
// Stage 2 stops the reader as soon as the command ends (see
// guestStopReaderStop), so a late request can never signal another process
// or stage 2's own steps after the command, such as the volume teardown. Its
// standard input is /dev/null; it opens the console for itself.
func guestStopReader(nonce string) string {
	return `(
	echo -1000 >/proc/self/oom_score_adj
	rvm_stop=
	while IFS= read -r rvm_line; do
		if [ "$rvm_line" = "` + stopTag(nonce) + `" ]; then
			rvm_stop=1
			break
		fi
	done </dev/console
	[ -n "$rvm_stop" ] || exit 0
	until read -r rvm_app 2>/dev/null <` + guestAppPid + ` && [ -n "$rvm_app" ]; do
		sleep 0.05
	done
	kill -TERM "$rvm_app"
) </dev/null &
rvm_reader=$!
`
}

// guestStopReaderStop stops the stop reader once the command has ended and
// its status is kept in rvm_status. A reader that has already acted on a
// request has exited, and kill then fails quietly. The shell's report of
// the reader that the kill ended goes to /dev/null.
const guestStopReaderStop = `kill "$rvm_reader" 2>/dev/null
wait "$rvm_reader" 2>/dev/null
`

// guestFailFunc defines rvm_fail, which a setup step calls when it fails: it
// names the step on the console and reboots before the start tag, without
// the global sync that reboot makes unless it has -n (see initScript).
const guestFailFunc = `rvm_fail() { echo "vm-launch guest setup: $1"; reboot -nf; exit 1; }
`

// guestShmSetup mounts a tmpfs at /dev/shm with the options Garden gives a
// container's /dev/shm (noexec, nosuid, nodev, and mode 1777), so POSIX
// shared memory and semaphores work in the guest as they do in a container.
// Garden sets no size, unlike runc's own 64 MiB default, so a container's
// /dev/shm can grow to half the host's memory, bounded in practice by the
// container's memory limit. The guest's bound is its memory, so stage 2
// asks for half of what the guest kernel has, which is the tmpfs default
// spelled out: about 51 MiB in the smallest guest, whose kernel keeps part
// of its 128 MiB. Pages in it count as guest memory in use, as they count
// against a container's limit.
const guestShmSetup = `mkdir -p /dev/shm && mount -t tmpfs -o noexec,nosuid,nodev,mode=1777,size=50% tmpfs /dev/shm || rvm_fail "mounting /dev/shm failed"
`

// guestNetworkSetup configures the guest NIC. The virtio-net driver is built
// into the kernel and normally has eth0 ready before stage 2 runs; the wait
// covers a late probe.
const guestNetworkSetup = `. /rvm/net
ip link set lo up || rvm_fail "bringing up lo failed"
n=0
while [ ! -e /sys/class/net/eth0 ]; do
	n=$((n + 1))
	[ "$n" -gt 5 ] && rvm_fail "no eth0 network device"
	sleep 1
done
if [ -n "${RVM_MTU:-}" ]; then
	ip link set eth0 mtu "$RVM_MTU" || echo "vm-launch guest setup: setting the mtu of eth0 to $RVM_MTU failed; keeping the default mtu"
fi
ip link set eth0 up || rvm_fail "bringing up eth0 failed"
ip addr add "$RVM_ADDRESS" dev eth0 || rvm_fail "adding $RVM_ADDRESS to eth0 failed"
ip route add default via "$RVM_GATEWAY" dev eth0 || rvm_fail "adding the default route via $RVM_GATEWAY failed"
`

// guestLimitsSetup prepares the command's open-files limit from
// /rvm/limits. A guest kernel caps every process at fs.nr_open, which is
// 1048576 by default, so stage 2 raises it to the hard limit when that is
// higher, and it lifts fs.file-max, which the kernel sizes from guest RAM,
// to the highest value, as systemd does, so that the guest-wide count of
// open files never binds before a process limit does. A failure there only
// warns, because the command runs as root, which fs.file-max does not
// limit. Stage 2 then checks, in a subshell, that the limits apply, so that a
// limit that cannot be set is a failed setup step; the command's own
// subshell sets them again (see guestRunCommand). busybox ulimit without -H
// or -S sets both limits.
const guestLimitsSetup = `. /rvm/limits
echo 9223372036854775807 >/proc/sys/fs/file-max || echo "vm-launch guest setup: raising fs.file-max failed; keeping the default"
rvm_nr_open=$(cat /proc/sys/fs/nr_open) || rvm_fail "reading fs.nr_open failed"
if [ "$rvm_nr_open" -lt "$RVM_NOFILE_HARD" ]; then
	echo "$RVM_NOFILE_HARD" >/proc/sys/fs/nr_open || rvm_fail "raising fs.nr_open to $RVM_NOFILE_HARD failed"
fi
( ` + guestSetLimits + ` ) || rvm_fail "setting the open files limit to $RVM_NOFILE_SOFT soft and $RVM_NOFILE_HARD hard failed"
`

// guestSetLimits sets the open-files limit of the shell that runs it: both
// limits to the hard one first, which works whether the limit rises or
// falls, and then the soft one.
const guestSetLimits = `ulimit -n "$RVM_NOFILE_HARD" && ulimit -S -n "$RVM_NOFILE_SOFT"`

// guestListenWatch starts, in a guest with ports (RVM_PORTS in /rvm/net),
// a background watcher that tells vm-launch whether anything in the guest
// listens on each port, so that vm-launch opens a port of the container only
// while the guest listens on it, as a container's port refuses connections
// until its app listens. Once a second, the watcher looks in /proc/net/tcp
// and /proc/net/tcp6 for listening sockets on the ports at an address other
// than loopback, which is what a connection forwarded from the container
// reaches, in one pass over the tables, and prints a listen line, the listen
// tag, the port, a colon, and 1 or 0, each time the answer for a port
// changes. The ports change independently of each other. Every
// guestListenRefresh looks, it prints the answer for every port whether or
// not it changed, so a listen line that vm-launch lost, as when the console
// dropped it, is made good within that many seconds; vm-launch takes each
// line as the port's state, so a line that repeats the state changes
// nothing. It starts after the start tag, so vm-launch reads every listen
// line as part of the command's run. The kernel writes an IPv4
// address in /proc/net/tcp as eight hex digits in host byte order, so a
// loopback address, 127.0.0.0/8, ends in 7F; ::1 and ::ffff:127.0.0.0/104
// are the IPv6 loopback forms.
//
// The watcher runs no other process once it has started: it reads the
// tables with the shell's read, and it waits out each second with a read
// that times out on guestListenTick, a FIFO that nothing writes. A shell
// exits when it cannot fork, so a watcher that ran commands would stop in a
// guest short of memory or of processes, and leave the port as it was for
// the rest of the VM; this one goes on. When the FIFO is missing or cannot
// be opened, the watcher waits with sleep instead; a read that timed out on
// any other file would return at once.
//
// The kernel lists every listening socket of a table before any socket in
// another state, so the watcher reads each table only up to the first line
// that is not a listening socket. A look therefore costs time in proportion
// to the listening sockets, and not to the connections the guest has. The
// shell's read makes one system call for each byte, so in the guest's
// busybox a look costs about 0.09 ms of CPU for each listening socket, and
// a little more for each port, which is checked once per look.
// Measured over 20 seconds, an idle guest used 6 ticks of CPU, a guest with
// 201 listening sockets and 2000 connections used 62 ticks, about 3% of a
// core, and a guest with 2001 listening sockets used 372 ticks, about 19%.
//
// A look at a table fails when the table cannot be opened or yields no
// header line; the kernel allocates its buffer for a table at the first
// read, so a read that succeeds once does not fail later. A listening
// socket that the watcher finds is an answer, whatever the other table gave.
// Otherwise a look that failed keeps the last answer of each port, so a look
// that fails never closes the port of an app that still listens. The watcher reads
// only the tables the guest kernel has, as /proc/net/tcp6 is missing from a
// kernel without IPv6.
//
// The watcher opens /dev/console for each listen line, so it writes through
// its own open file and not the one it shares with the command, which the
// command may have made non-blocking. It takes a new state only once the
// line is written, so a line that fails is written again a second later.
func guestListenWatch(nonce string) string {
	return `rvm_watch=
if [ -n "${RVM_PORTS:-}" ]; then
	rvm_ports=
	rvm_hexes=" "
	for rvm_dec in $RVM_PORTS; do
		rvm_hex=$(printf '%04X' "$rvm_dec")
		rvm_ports="$rvm_ports $rvm_dec:$rvm_hex"
		rvm_hexes="$rvm_hexes$rvm_hex "
	done
	rvm_tables=
	for rvm_table in /proc/net/tcp /proc/net/tcp6; do
		[ -e "$rvm_table" ] && rvm_tables="$rvm_tables $rvm_table"
	done
	(
		if [ -p ` + guestListenTick + ` ] && command exec 3<>` + guestListenTick + `; then
			rvm_pause() { read -t 1 -u 3 rvm_tick; }
		else
			rvm_pause() { sleep 1; }
		fi
		rvm_upset=" "
		rvm_look=0
		while :; do
			rvm_seen=" "
			rvm_failed=
			for rvm_table in $rvm_tables; do
				rvm_head=
				while read -r rvm_sl rvm_local rvm_remote rvm_st rvm_rest; do
					if [ -z "$rvm_head" ]; then
						rvm_head=1
						continue
					fi
					[ "$rvm_st" = 0A ] || break
					case "$rvm_hexes" in
					*" ${rvm_local##*:} "*) ;;
					*) continue ;;
					esac
					case ${rvm_local%:*} in
					??????7F | 00000000000000000000000001000000 | 0000000000000000FFFF0000??????7F) ;;
					*) rvm_seen="$rvm_seen${rvm_local##*:} " ;;
					esac
				done 2>/dev/null <"$rvm_table"
				[ -n "$rvm_head" ] || rvm_failed=1
			done
			rvm_look=$((rvm_look + 1))
			rvm_all=
			if [ "$rvm_look" -ge ` + strconv.Itoa(guestListenRefresh) + ` ]; then
				rvm_all=1
				rvm_look=0
			fi
			rvm_nextup=" "
			for rvm_pp in $rvm_ports; do
				rvm_hex=${rvm_pp#*:}
				case "$rvm_seen" in
				*" $rvm_hex "*) rvm_now=1 ;;
				*) rvm_now=0 ;;
				esac
				case "$rvm_upset" in
				*" $rvm_hex "*) rvm_was=1 ;;
				*) rvm_was=0 ;;
				esac
				if [ "$rvm_now" = 0 ] && [ -n "$rvm_failed" ]; then
					rvm_now=$rvm_was
				fi
				if [ "$rvm_now" != "$rvm_was" ] || [ -n "$rvm_all" ]; then
					echo "` + listenTag(nonce) + `${rvm_pp%:*}:$rvm_now" >/dev/console && rvm_was=$rvm_now
				fi
				if [ "$rvm_was" = 1 ]; then
					rvm_nextup="$rvm_nextup$rvm_hex "
				fi
			done
			rvm_upset=$rvm_nextup
			rvm_pause
		done
	) </dev/null &
	rvm_watch=$!
fi
`
}

// guestListenRefresh is how many looks the listen watcher makes between the
// lines in which it reports every port, changed or not.
const guestListenRefresh = 5

// guestListenTick is the FIFO the listen watcher waits on. The initramfs of
// a guest with ports holds it, and nothing ever writes it.
const guestListenTick = "/rvm/listen-tick"

// guestListenStop stops the listen watcher once the command has ended and
// before stage 2 reports its status, so no listen line follows the exit line.
const guestListenStop = `if [ -n "$rvm_watch" ]; then
	kill "$rvm_watch"
	wait "$rvm_watch"
fi
`

// guestOOMReport tells vm-launch, once the command has ended, how many
// processes the guest kernel killed for lack of memory, so that vm-launch can
// report a guest OOM as the container runtime reports a cgroup OOM. It reads
// the oom_kill counter of /proc/vmstat, which counts every process in the
// guest and does not depend on the kernel's log level or message text, and
// it writes the count on the console as an oomTag line before the exit line
// when the count is above zero. The report is the shell's builtins only,
// because a guest that ran out of memory may have no room to start a process.
// A kernel without the counter gives no report.
func guestOOMReport(nonce string) string {
	report := "echo " + oomTag(nonce) + "$rvm_oom"
	return `rvm_oom=0
while read -r rvm_key rvm_val; do
	if [ "$rvm_key" = oom_kill ]; then
		rvm_oom=$rvm_val
		break
	fi
done 2>/dev/null </proc/vmstat
case "$rvm_oom" in
'' | *[!0-9]* | 0 | 0[0-9]*) ;;
*) ` + report + ` >/dev/console || ` + report + `;;
esac
`
}

// guestEnvChecks makes a broken /rvm/env a failed setup step, with the
// console shown, instead of a command that fails to start. It sources
// /rvm/env in a subshell, so stage 2 itself never gets the guest environment.
const guestEnvChecks = `( . /rvm/env ) || rvm_fail "reading /rvm/env failed"
`

// guestRunCommand runs the guest command with its open-files limit and the
// guest environment, in a subshell that becomes the shell running the
// command. Only that subshell gets the limit, so stage 2's own steps never run
// short of descriptors under a low one.
//
// The subshell first records its own pid in guestAppPid, which it reads
// from /proc/self/stat with the shell's builtin read, so the pid is the
// subshell's and not that of a child. It then runs the command as the
// argument of sh -c, under the same pid, since exec keeps it. The guest's
// busybox sh execs the last simple command of a -c string, after a list or
// inside an if too, so the recorded pid is then the command itself, as it is
// under the CF launcher's bash -c. A pipeline, or a string that sets a trap,
// keeps the shell as that process. sh FILE would keep the shell even for a
// single simple command. The command
// substitution drops the trailing newlines of /rvm/cmd, which the shell
// ignores anyway. A pid that cannot be recorded is reported, and the
// command still runs.
//
// Stage 2 waits for the subshell with its own standard error on /dev/null,
// and the subshell takes stage 2's standard error back from fd 3, which it
// then closes, so the command never sees fd 3. A shell that is not
// interactive reports a foreground job that a signal ended, such as
// "Terminated" after a stop request, on its standard error, and that line is
// the shell's, not the command's. command keeps a failed redirection from
// ending stage 2 or the subshell; the command then still runs.
const guestRunCommand = "command exec 3>&2 2>/dev/null\n( command exec 2>&3 3>&-; { read -r rvm_self rvm_rest </proc/self/stat && echo \"$rvm_self\" >" + guestAppPid + "; } || echo \"vm-launch guest: recording the command's pid in " + guestAppPid + " failed; a stop request cannot reach the command\"; " +
	guestSetLimits + " && . /rvm/env && exec sh -c \"$(cat /rvm/cmd)\" ) </dev/null\n"

// guestRunStatus keeps the command's status in rvm_status and gives stage 2
// its standard error back (see guestRunCommand).
const guestRunStatus = "rvm_status=$?\ncommand exec 2>&3 3>&-\n"

// guestAppPid is the file in which the command's subshell records its pid,
// which is the pid of the command's top process.
const guestAppPid = "/rvm/app-pid"

// Guest scratch files of the blank check and of the superblock reads. They
// live under /rvm, which no volume path may use, so that an app's
// container_dir can never collide with them.
const (
	guestVolumeHead   = "/rvm/volume-head"
	guestVolumeUsed   = "/rvm/volume-used"
	guestVolumeBackup = "/rvm/volume-backup"
	guestVolumeSuper  = "/rvm/volume-super"
)

// guestLegacyJournalMiB is the size in MiB of the journal stage 2 gives an
// image without one before it grows it, as tune2fs -J size takes it, and
// guestLegacyJournalBytesText the same size in bytes. guestLegacyJournalSlack
// is the blocks beyond the journal's own that the image must have free for
// it: the indirect blocks that map a journal inode without extents, at most
// 17 with 1024-byte blocks, with room to spare. They are decimal text, as
// the guest's shell takes them, and a spec keeps them in step.
const (
	guestLegacyJournalMiB       = "4"
	guestLegacyJournalBytesText = "4194304"
	guestLegacyJournalSlack     = "32"
)

// sectorBytesText is sectorBytes in decimal, as the guest's shell takes it.
// A spec keeps the two equal.
const sectorBytesText = "512"

// guestVolumeFuncs defines the helpers of the image and block arms of the
// volume setup (see guestVolumeSetup), which work on the volume in
// rvm_vdev, named in the guest's lines as rvm_vname, at rvm_vpath.
//
// rvm_vsize reads the device's size in 512-byte sectors from /sys/block, where
// stage 1 read and checked it, into rvm_vsectors, and fails the boot when
// it cannot.
//
// rvm_vsuper reads the filesystem's superblock with tune2fs -l, which only
// reads, into rvm_vblocks, its size in blocks, rvm_vbsize, the bytes in a
// block, rvm_vfree, its free blocks, or 0 when tune2fs gives none, and
// rvm_vjournal, which is yes when the features name has_journal, no when
// they name others, and unknown when tune2fs gives none. It succeeds when
// tune2fs ran and gave a size and a block size the guest can use. The loop
// is the shell's own read, so the parse starts no process.
//
// rvm_vfits compares the filesystem's size with the device's, in the
// filesystem's blocks. A filesystem larger than its device fails the boot
// before the mount, because it means a device that was shrunk or that holds
// another filesystem's data, and a read-write mount of it could lose data.
// rvm_vgrow is set when the device holds more blocks than the filesystem.
//
// rvm_vgrow_now runs ext4grow on the mounted filesystem when rvm_vgrow is
// set. ext4grow asks the kernel to resize the filesystem online to fill its
// device (see guestExt4grow). The kernel adds block groups one batch at a
// time, so a grow that fails may have stopped partway, and stage 2 does not
// read the size again. When the volume is still mounted read-write, the
// filesystem is consistent but may be between its old and new sizes, so
// stage 2 says so with a line that names the volume and goes on. When the
// failure left the volume read-only, which errors=remount-ro does once ext4
// finds an inconsistency, the boot fails, as it does for a volume that
// mounts read-only.
//
// rvm_vrw sets rvm_vmode to rw or ro, the first mount option the kernel
// gives in /proc/mounts for the last mount of rvm_vdev, or to nothing when
// /proc/mounts does not list the device or cannot be read. Stage 2 matches
// the mount by its device, which stage 2 mounts once and which is never
// escaped the way a mount point with a space is. The loop is the shell's
// own read, so the check starts no process. rvm_vwritable fails the boot
// unless the volume is mounted read-write, because busybox mount retries a
// read-write mount that fails with EACCES or EROFS as a read-only one and
// still exits 0, and an app that cannot write its volume must not start.
//
// rvm_vfsck_why fails the boot for an e2fsck status of 8 or more, in
// rvm_vrc, with a line for its cause, so that a check that could not run
// or did not finish is never reported as errors in the image. Its first
// argument names the check as the line gives it, such as "e2fsck -p", and
// its second, which may be empty, says when the check ran, set off with
// commas, such as ", run after adding a journal to it failed,". A status of 8 to
// 125 and 128 are e2fsck's own codes added up, of which 8 is an operational
// error, 16 a usage error, 32 a cancelled check, and 128 a library error.
// The shell gives 126 for a tool it could not execute and 127 for one it
// could not find. A status above 128 is a signal, 128 plus its number, and
// 137 is SIGKILL, which in a guest at setup most likely comes from the
// kernel for lack of memory. A status from 4 to 7 is left to the caller,
// which names the errors e2fsck left.
const guestVolumeFuncs = `rvm_vsize() {
	rvm_vsectors=
	read -r rvm_vsectors 2>/dev/null <"/sys/block/${rvm_vdev##*/}/size"
	case "$rvm_vsectors" in
	'' | 0* | *[!0-9]*) rvm_fail "reading the size of $rvm_vdev for $rvm_vname at $rvm_vpath from /sys/block failed" ;;
	esac
}
rvm_vsuper() {
	rvm_vblocks= rvm_vbsize= rvm_vfree= rvm_vfeat= rvm_vjournal=unknown
	if ! ` + guestTune2fs + ` -l "$rvm_vdev" >` + guestVolumeSuper + ` 2>/dev/null; then
		rm -f ` + guestVolumeSuper + `
		return 1
	fi
	while IFS= read -r rvm_vl; do
		case "$rvm_vl" in
		"Block count:"*) rvm_vblocks=${rvm_vl##* } ;;
		"Block size:"*) rvm_vbsize=${rvm_vl##* } ;;
		"Free blocks:"*) rvm_vfree=${rvm_vl##* } ;;
		"Filesystem features:"*) rvm_vfeat=${rvm_vl#Filesystem features:} ;;
		esac
	done <` + guestVolumeSuper + `
	rm -f ` + guestVolumeSuper + `
	case " $rvm_vfeat " in
	*" has_journal "*) rvm_vjournal=yes ;;
	*[a-z0-9]*) rvm_vjournal=no ;;
	esac
	case "$rvm_vfree" in
	'' | 0?* | *[!0-9]*) rvm_vfree=0 ;;
	esac
	case "$rvm_vblocks" in
	'' | 0* | *[!0-9]*) return 1 ;;
	esac
	case "$rvm_vbsize" in
	1024 | 2048 | 4096 | 8192 | 16384 | 32768 | 65536) ;;
	*) return 1 ;;
	esac
}
rvm_vfits() {
	rvm_vdevblocks=$((rvm_vsectors * ` + sectorBytesText + ` / rvm_vbsize))
	[ "$((rvm_vblocks > rvm_vdevblocks))" = 0 ] || rvm_fail "the filesystem on $rvm_vname at $rvm_vpath has $rvm_vblocks blocks of $rvm_vbsize bytes, more than the $rvm_vdevblocks its device holds, so the device was shrunk or holds another filesystem's data; vm-launch never mounts a filesystem larger than its device; inspect it on the volume"
	rvm_vgrow=
	[ "$((rvm_vdevblocks > rvm_vblocks))" = 0 ] || rvm_vgrow=1
}
rvm_vrw() {
	rvm_vmode=
	while read -r rvm_vms rvm_vmp rvm_vmt rvm_vmo rvm_vmr; do
		[ "$rvm_vms" = "$rvm_vdev" ] && rvm_vmode=${rvm_vmo%%,*}
	done 2>/dev/null <` + guestProcMounts + `
}
rvm_vwritable() {
	rvm_vrw
	case "$rvm_vmode" in
	rw) ;;
	ro) rvm_fail "$rvm_vname at $rvm_vpath mounted read-only, as busybox mount does when the device or the filesystem refuses a read-write mount, and the guest never starts the app on a volume it cannot write; inspect it on the volume" ;;
	*) rvm_fail "$rvm_vname at $rvm_vpath does not show in ` + guestProcMounts + ` after its mount, so the guest cannot tell whether the app can write it" ;;
	esac
}
rvm_vgrow_now() {
	[ -n "$rvm_vgrow" ] || return 0
	` + guestExt4grow + ` "$rvm_vdev" "$rvm_vpath" && return 0
	rvm_vrw
	[ "$rvm_vmode" = rw ] || rvm_fail "growing $rvm_vname at $rvm_vpath from $rvm_vblocks to $rvm_vdevblocks blocks of $rvm_vbsize bytes failed, and the volume is no longer mounted read-write, which errors=remount-ro does when ext4 finds an inconsistency; inspect it on the volume"
	echo "vm-launch guest: growing $rvm_vname at $rvm_vpath from $rvm_vblocks to $rvm_vdevblocks blocks of $rvm_vbsize bytes failed; the resize may have stopped partway, so the filesystem is consistent but may be between sizes, and it stays mounted read-write"
}
rvm_vfsck_why() {
	[ "$rvm_vrc" -ge 8 ] || return 0
	rvm_vwhat="$1 for $rvm_vname at $rvm_vpath$2"
	case "$rvm_vrc" in
	126 | 127) rvm_fail "$rvm_vwhat could not run, since the shell gave the status $rvm_vrc, which means the tool would not execute or was not found, so the image was not checked, and vm-launch never formats an image that is not blank" ;;
	137) rvm_fail "$rvm_vwhat was killed with SIGKILL (status 137) before it finished, most likely by the guest kernel for lack of memory, so give the app more memory and start it again; vm-launch never formats an image that is not blank" ;;
	esac
	[ "$rvm_vrc" -le 128 ] || rvm_fail "$rvm_vwhat ended on signal $((rvm_vrc - 128)) (status $rvm_vrc) before it finished, so the image was not fully checked, and vm-launch never formats an image that is not blank"
	rvm_fail "$rvm_vwhat exited $rvm_vrc, which means it could not check the image, not that the image has errors it can't repair (the check adds 8 for an operational error, 16 for a usage error, 32 for a cancelled check, 128 for a library error, and 4 for errors it left); inspect it on the volume, and vm-launch never formats an image that is not blank"
}
`

// guestProcMounts is where the guest reads its mounts, which a spec moves.
const guestProcMounts = "/proc/mounts"

// guestVolumeBackupCheck runs on an image whose first 64 KiB read as zero,
// before stage 2 takes it as blank. An ext2, ext3, or ext4 filesystem keeps
// a copy of its superblock at the start of block group 1, which is block
// 8193 with 1024-byte blocks, 16384 with 2048-byte blocks, and 32768 with
// 4096-byte blocks, and a superblock holds the magic 0xEF53, little endian,
// 56 bytes in. For each block size, stage 2 reads the two bytes where the
// magic would be, in a superblock at the start of that block and in one
// 1024 bytes further in, wherever the image holds the whole superblock. An
// image with the magic there lost its start but not its filesystem, so it
// is never formatted, and the boot fails with a line that asks for a repair
// by hand from the backup superblock with e2fsck -b. For a superblock at the
// start of its block, the line gives the e2fsck -b and -B that read it. One
// 1024 bytes in starts no block of that size, so the line gives its byte
// and asks the operator to find the filesystem's block size first.
//
// A filesystem that stage 2 made on an image smaller than guestFullZeroEnd
// bytes may hold no backup superblock, and the host may have grown the image
// since, so neither the backups nor the device's size tell a zeroed start
// from a new image. Every image whose start reads as zero and whose backup
// places hold no magic is therefore blank only when its first
// guestFullZeroEnd bytes, or all of a smaller image, read as zero too, which
// cmp checks against /dev/zero without holding the image in memory. The read
// runs whatever the device's size, and it costs at most guestFullZeroEnd
// bytes once, at the first boot of a new image. An image with data anywhere
// in those bytes fails the boot as a damaged filesystem. Both lines also say
// that a first format that was interrupted leaves such an image, and that
// deleting an image that never held data has the next start create it
// fresh, because the guest has no way to tell the two apart.
//
// A read error fails the boot too, and never counts as blank. dd reads the
// two bytes of each place on its own, so od never has to skip past the end
// of what it reads. Every line names the volume.
const guestVolumeBackupCheck = `			for rvm_vsb in 1024:8193 2048:16384 4096:32768; do
				rvm_vbs=${rvm_vsb%:*}
				rvm_vgb=${rvm_vsb#*:}
				for rvm_vat in 0 1024; do
					rvm_voff=$((rvm_vgb * rvm_vbs + rvm_vat))
					[ "$((rvm_voff + 1024 <= rvm_vsectors * ` + sectorBytesText + `))" = 1 ] || continue
					dd if="$rvm_vdev" of=` + guestVolumeBackup + ` bs=2 skip=$(((rvm_voff + 56) / 2)) count=1 2>/dev/null || rvm_fail "reading $rvm_vdev at byte $rvm_voff, where a backup superblock would be, failed for $rvm_vname at $rvm_vpath"
					rvm_vmagic=$(od -An -tx1 ` + guestVolumeBackup + `) || rvm_fail "checking $rvm_vdev for a backup superblock at byte $rvm_voff failed for $rvm_vname at $rvm_vpath"
					case "$rvm_vmagic" in
					*"53 ef"*)
						if [ "$rvm_vat" = 0 ]; then
							rvm_vhint="e2fsck -b $rvm_vgb -B $rvm_vbs for $rvm_vbs-byte blocks"
						else
							rvm_vhint="the magic is 1024 bytes into block $rvm_vgb of $rvm_vbs bytes, where e2fsck -b -B $rvm_vbs does not look, so find the filesystem's block size and backup superblocks first"
						fi
						rvm_fail "the volume image $rvm_vimage for $rvm_vpath reads as zero in its first 64 KiB but holds the magic of an ext2, ext3, or ext4 superblock at byte $rvm_voff, where a backup superblock is kept, so it looks like a damaged filesystem, and vm-launch never formats it; if the volume never held data, an interrupted first format can cause this, and deleting $rvm_vimage on the volume lets the next start create it fresh; otherwise repair it by hand on the volume with e2fsck -b from a backup superblock ($rvm_vhint)"
						;;
					esac
				done
			done
			rm -f ` + guestVolumeBackup + `
			rvm_vzero=$((rvm_vsectors * ` + sectorBytesText + `))
			[ "$((rvm_vzero > ` + guestFullZeroEnd + `))" = 0 ] || rvm_vzero=` + guestFullZeroEnd + `
			rvm_vrc=0
			cmp -s -n "$rvm_vzero" "$rvm_vdev" /dev/zero || rvm_vrc=$?
			case "$rvm_vrc" in
			0) ;;
			1) rvm_fail "the volume image $rvm_vimage for $rvm_vpath reads as zero in its first 64 KiB but not in all of its first $rvm_vzero bytes, and a filesystem that vm-launch made on an image no larger than that, which the host may have grown since, may have no backup superblock that would tell a damaged filesystem from a new image, so it looks like a damaged filesystem, and vm-launch never formats it; if the volume never held data, an interrupted first format can cause this, and deleting $rvm_vimage on the volume lets the next start create it fresh; otherwise repair it by hand on the volume, where e2fsck -b needs a backup superblock that a filesystem this small may not have" ;;
			*) rvm_fail "reading the first $rvm_vzero bytes of $rvm_vdev for $rvm_vname at $rvm_vpath failed, and they must all read as zero before the guest formats the image" ;;
			esac
`

// guestFullZeroEnd is the start, in bytes and in decimal as the guest's
// shell takes it, of block group 2 of a filesystem with 4096-byte blocks and
// 32768 blocks per group. The superblock of block group 1 ends 1024 bytes
// after block 32768, but mke2fs drops a last group that is shorter than its
// own overhead plus 50 blocks, so an image a little larger than block group
// 1's start can still get one group and no backup superblock. A filesystem
// that ends below block group 2, a wide margin over that, may thus have no
// backup, and the host may grow its image past that point before the guest
// grows the filesystem. Every image must therefore read as zero up to here,
// or to its end when it is smaller, before it counts as blank, and one that
// holds a backup superblock is refused before that read. A spec keeps the
// value in step with the arithmetic.
const guestFullZeroEnd = "268435456"

// guestVolumeSetup mounts every volume, in volume order, each on the device
// that stage 1 found by the drive's identity and passed as stage 2's argument
// in the same place (see guestRootInit), at the path and as the kind that
// /rvm/mounts gives it (see mountsFile). A count of arguments other than the
// volume count in /rvm/mounts, a sync mount setting other than true or false,
// a volume without a path, and a kind stage 2 does not know are setup
// failures. The kind decides everything else, and only the image arm can
// format or check a filesystem. The image and block arms grow a filesystem
// online when its device is bigger (see guestVolumeFuncs).
//
// An image volume must have a block device, and the guest must have the
// guest filesystem tools that vm-launch puts below guestToolsDir. Stage 2
// runs them by their full paths and never falls back to busybox's mke2fs,
// so a missing tool fails the boot before stage 2 reads the device. Stage 2
// formats only an image whose first 64 KiB it reads itself as all zero,
// that holds no backup superblock where an ext2, ext3, or ext4 filesystem
// keeps one, and whose first guestFullZeroEnd bytes, or all of whose bytes
// when it is smaller, read as zero (see guestVolumeBackupCheck). That is a
// new image or one whose creator died before the first boot; the host never
// tells it an image is new. A read error is a setup failure, never a blank
// image, and an image whose start is zero but which holds a backup
// superblock, or data elsewhere in those bytes, fails the boot as a damaged
// filesystem. A blank image gets a journalled ext4 from the shipped
// mke2fs with the pinned mke2fs.conf (see guestVolumeMke2fsArgs). The format
// skips zeroing the inode tables and the journal, so it never writes the
// image's whole size, which is safe because vm-launch makes every image with
// fallocate or zero writes, so every block of a blank image reads as zero.
//
// Every image that is not blank is preened with e2fsck -p before it mounts,
// at every boot. e2fsck(8) gives its exit status as the sum of 1 for errors
// it corrected, 2 for a corrected system that should reboot, 4 for errors
// it left, 8 for an operational error, 16 for a usage error, 32 for a
// cancelled check, and 128 for a library error. A status below 4 lets the
// boot go on: the reboot that 2 asks for matters only for a mounted
// filesystem, and the image is not mounted yet, so stage 2 says so and goes
// on. A status from 4 to 7 fails the boot with a line that names the image
// and the errors e2fsck left and asks an operator to inspect it. A status of
// 8 or more means that e2fsck could not check the image, could not run, or
// was killed, and it fails the boot with a line that says which (see
// rvm_vfsck_why in guestVolumeFuncs). Either way the image is never
// formatted.
// Stage 2 never runs e2fsck -y. An image that is not blank and does not
// mount after its preen is never formatted either. Before the preen, stage 2
// reads the superblock with tune2fs -l, and an image whose filesystem is
// larger than its device fails the boot there, before e2fsck writes to it;
// a superblock that tune2fs cannot read then is left to the preen to
// report. After the preen the superblock must read, or the boot fails,
// because the guest could not tell whether the filesystem fits its device.
//
// An image whose device holds more blocks than its filesystem, because the
// host grew the image file, grows online after the mount (see
// guestVolumeFuncs). The kernel journals the resize, so a crash in the
// middle replays at the next mount, and an image without a journal, such as
// an rvm.6 ext2 image, first gets one: stage 2 checks it in full with
// e2fsck -f -p and adds a 4 MiB journal with tune2fs -O has_journal before
// the mount. Without 4 MiB free for the journal, the image mounts at its
// old size with a line that asks the app to free 4 MiB, and the boot goes
// on. A journal that tune2fs cannot add leaves the image at its old size
// after a second full check, with a line that says so. An image whose
// features tune2fs does not give is not grown either. An image that does
// not need to grow is left as it is apart from the preen, and a blank image
// fills its device from the format.
//
// An image mounts with sync and dirsync, which put every completed write on
// the image before the syscall returns, because the hypervisors stop at once
// on SIGTERM, without a guest shutdown, so a failure that reboots after some
// volumes are mounted loses nothing on them. noinit_itable keeps the kernel
// from zeroing inode tables, which mke2fs left unwritten and which already
// read as zero. When the operator turned sync mounts off (see
// volumeSyncMountsFlag), an image whose filesystem has a journal, as tune2fs
// -l reports it, mounts without sync and dirsync, because the journal keeps
// the filesystem consistent through a sudden stop. An image without a
// journal, such as an rvm.6 ext2 image or a new image too small for one,
// keeps sync and dirsync, and so does an image whose features tune2fs cannot
// read, with a line that says so. An rvm.6 image that got a journal so that
// it could grow has one from then on.
//
// A block volume is a whole disk that holds the app's data, and stage 2
// never formats it or checks it, because the volume driver checks it before
// it hands it over. It must have a block device and the guest tune2fs and
// ext4grow. Stage 2 reads its superblock with tune2fs -l, which only reads,
// and a disk whose superblock does not read, a blank one included, fails
// the boot with a line that names the volume's disk, never an image file,
// and says vm-launch never formats a block volume, as does a filesystem
// larger than its disk. Stage 2 mounts the disk as ext4 with noatime and
// errors=remount-ro and without sync or dirsync, so the disk keeps the
// speed of a local disk; the teardown's sync -f flushes it after the
// command. A disk that does not mount fails the boot with the same line. A
// disk bigger than its filesystem grows online after the mount, as an image
// does, when it has a journal, which the volume driver requires; a disk
// without one stays at its old size, with a line that says so.
//
// A share has no drive, so stage 1 passes it an empty argument, and any
// other argument is a setup failure. Stage 2 mounts it with mount -t virtiofs
// by its tag, which is shareTagPrefix and the volume's index, such as
// rvm-vol1, the tag that QEMU gives the share's vhost-user-fs device. It
// creates the mount point first and gives no mount options. A share that does
// not mount, for lack of a device with that tag or for any other reason,
// fails the boot with a line that names the volume's path, because the app
// would otherwise write to the guest's own disk, which the next start throws
// away.
//
// Every image and block volume must be mounted read-write once its mount
// returns, as /proc/mounts shows it, or the boot fails with a line that
// names the volume (see rvm_vwritable in guestVolumeFuncs). A share is not
// checked, since virtiofsd decides what the guest may write.
//
// The mount points are created on the guest root, which is the overlay when
// the guest has a root disk. vm-launch refuses a volume path under another
// (see checkNotNested), so the mounts never depend on their order.
const guestVolumeSetup = `. /rvm/mounts
case "${RVM_VOLUMES:-}" in
[1-` + maxVolumesText + `]) ;;
*) rvm_fail "the volume count in /rvm/mounts is not a number from 1 to ` + maxVolumesText + `" ;;
esac
[ "$#" -eq "$RVM_VOLUMES" ] || rvm_fail "stage 1 passed $# volume devices for the $RVM_VOLUMES volumes in /rvm/mounts"
case "${RVM_SYNC_MOUNTS:-}" in
true | false) ;;
*) rvm_fail "the sync mount setting in /rvm/mounts is not true or false" ;;
esac
` + guestVolumeFuncs + `rvm_vi=0
for rvm_vdev in "$@"; do
	eval "rvm_vkind=\${RVM_VOL${rvm_vi}_KIND:-} rvm_vpath=\${RVM_VOL${rvm_vi}_PATH:-} rvm_vimage=\${RVM_VOL${rvm_vi}_IMAGE:-} rvm_vdev_$rvm_vi=\$rvm_vdev"
	[ -n "$rvm_vpath" ] || rvm_fail "/rvm/mounts gives volume $rvm_vi no path"
	case "$rvm_vkind" in
	` + string(driveImage) + `)
		[ -b "$rvm_vdev" ] || rvm_fail "no block device for the volume image $rvm_vimage at $rvm_vpath"
		for rvm_vtool in ` + guestMke2fs + ` ` + guestE2fsck + ` ` + guestTune2fs + ` ` + guestExt4grow + `; do
			[ -f "$rvm_vtool" ] && [ -x "$rvm_vtool" ] || rvm_fail "the guest has no $rvm_vtool for the volume image $rvm_vimage at $rvm_vpath, and it never formats or checks a volume image with another tool"
		done
		[ -f ` + guestMke2fsConfig + ` ] && [ -r ` + guestMke2fsConfig + ` ] || rvm_fail "the guest has no ` + guestMke2fsConfig + ` for the volume image $rvm_vimage at $rvm_vpath"
		mkdir -p "$rvm_vpath" || rvm_fail "creating $rvm_vpath failed"
		rvm_vname="the volume image $rvm_vimage"
		rvm_vsize
		dd if="$rvm_vdev" of=` + guestVolumeHead + ` bs=4096 count=16 || rvm_fail "reading the start of $rvm_vdev for $rvm_vname at $rvm_vpath failed"
		tr -d '\000' <` + guestVolumeHead + ` >` + guestVolumeUsed + ` || rvm_fail "checking whether $rvm_vdev for $rvm_vname at $rvm_vpath is blank failed"
		rvm_blank=
		[ -s ` + guestVolumeHead + ` ] && [ ! -s ` + guestVolumeUsed + ` ] && rvm_blank=1
		rm -f ` + guestVolumeHead + ` ` + guestVolumeUsed + `
		if [ -n "$rvm_blank" ]; then
` + guestVolumeBackupCheck + `		fi
		rvm_vgrow=
		if [ -n "$rvm_blank" ]; then
			MKE2FS_CONFIG=` + guestMke2fsConfig + ` ` + guestMke2fs + ` ` + guestVolumeMke2fsArgs + ` "$rvm_vdev" || rvm_fail "formatting the blank volume image $rvm_vimage for $rvm_vpath failed"
			rvm_vjournal=unknown
			[ "$RVM_SYNC_MOUNTS" = true ] || rvm_vsuper
		else
			! rvm_vsuper || rvm_vfits
			rvm_vrc=0
			` + guestE2fsck + ` -p "$rvm_vdev" || rvm_vrc=$?
			rvm_vfsck_why "e2fsck -p" ""
			[ "$rvm_vrc" -lt 4 ] || rvm_fail "the volume image $rvm_vimage has errors that e2fsck -p can't repair; inspect it on the volume (e2fsck -p exited $rvm_vrc for $rvm_vpath, and vm-launch never formats an image that is not blank)"
			[ $((rvm_vrc & 2)) -eq 0 ] || echo "vm-launch guest: e2fsck -p repaired the volume image $rvm_vimage and asked for a reboot, which only a mounted filesystem needs; the image is not mounted yet, so the guest goes on"
			rvm_vsuper || rvm_fail "reading the superblock of the volume image $rvm_vimage for $rvm_vpath with tune2fs -l failed after its preen, so the guest cannot tell whether it fits its device; inspect it on the volume"
			rvm_vfits
			if [ -n "$rvm_vgrow" ] && [ "$rvm_vjournal" = unknown ]; then
				echo "vm-launch guest: tune2fs -l gives no filesystem features for the volume image $rvm_vimage, so the guest cannot tell whether it has the journal it needs to grow, and it mounts at its old size of $rvm_vblocks blocks of $rvm_vbsize bytes"
				rvm_vgrow=
			fi
			if [ -n "$rvm_vgrow" ] && [ "$rvm_vjournal" = no ]; then
				rvm_vrc=0
				` + guestE2fsck + ` -f -p "$rvm_vdev" || rvm_vrc=$?
				rvm_vfsck_why "e2fsck -f -p" ", run before the image got the journal it needs to grow,"
				[ "$rvm_vrc" -lt 4 ] || rvm_fail "the volume image $rvm_vimage has errors that e2fsck -f -p can't repair; inspect it on the volume (e2fsck -f -p exited $rvm_vrc for $rvm_vpath before the image got the journal it needs to grow, and vm-launch never formats an image that is not blank)"
				rvm_vsuper || rvm_fail "reading the superblock of the volume image $rvm_vimage for $rvm_vpath with tune2fs -l failed after its check, so the guest cannot tell whether it has room for a journal; inspect it on the volume"
				if [ "$((rvm_vfree >= ` + guestLegacyJournalBytesText + ` / rvm_vbsize + ` + guestLegacyJournalSlack + `))" = 1 ]; then
					if ` + guestTune2fs + ` -O has_journal -J size=` + guestLegacyJournalMiB + ` "$rvm_vdev"; then
						rvm_vsuper || rvm_fail "reading the superblock of the volume image $rvm_vimage for $rvm_vpath with tune2fs -l failed after it got a journal; inspect it on the volume"
						rvm_vfits
						if [ "$rvm_vjournal" != yes ]; then
							echo "vm-launch guest: tune2fs gave the volume image $rvm_vimage no journal, so it mounts at its old size of $rvm_vblocks blocks of $rvm_vbsize bytes"
							rvm_vgrow=
						fi
					else
						rvm_vrc=0
						` + guestE2fsck + ` -f -p "$rvm_vdev" || rvm_vrc=$?
						rvm_vfsck_why "e2fsck -f -p" ", run after adding a journal to it failed,"
						[ "$rvm_vrc" -lt 4 ] || rvm_fail "the volume image $rvm_vimage has errors that e2fsck -f -p can't repair after adding a journal to it failed; inspect it on the volume (e2fsck -f -p exited $rvm_vrc for $rvm_vpath, and vm-launch never formats an image that is not blank)"
						rvm_vsuper || rvm_fail "reading the superblock of the volume image $rvm_vimage for $rvm_vpath with tune2fs -l failed after adding a journal to it failed; inspect it on the volume"
						rvm_vfits
						echo "vm-launch guest: adding a ` + guestLegacyJournalMiB + ` MiB journal to the volume image $rvm_vimage failed, so it mounts at its old size of $rvm_vblocks blocks of $rvm_vbsize bytes; its data is intact"
						rvm_vgrow=
					fi
				else
					echo "vm-launch guest: the volume image $rvm_vimage at $rvm_vpath has no journal and only $((rvm_vfree * rvm_vbsize / 1024)) KiB free, and it needs ` + guestLegacyJournalMiB + ` MiB free for the journal it must have before it grows, so it mounts at its old size of $rvm_vblocks blocks of $rvm_vbsize bytes; free ` + guestLegacyJournalMiB + ` MiB in $rvm_vpath and restart the app to grow it"
					rvm_vgrow=
				fi
			fi
		fi
		rvm_vopts=` + guestImageSyncOptions + `,` + guestImageMountOptions + `
		if [ "$RVM_SYNC_MOUNTS" = false ]; then
			case "$rvm_vjournal" in
			yes) rvm_vopts=` + guestImageMountOptions + ` ;;
			unknown) echo "vm-launch guest: reading the filesystem features of the volume image $rvm_vimage failed, so it mounts with sync and dirsync" ;;
			esac
		fi
		if [ -n "$rvm_blank" ]; then
			mount -t ext4 -o "$rvm_vopts" "$rvm_vdev" "$rvm_vpath" || rvm_fail "mounting the newly formatted volume image $rvm_vimage at $rvm_vpath failed"
		else
			mount -t ext4 -o "$rvm_vopts" "$rvm_vdev" "$rvm_vpath" || rvm_fail "mounting the volume image $rvm_vimage at $rvm_vpath failed; it is not blank, so vm-launch will not format it; inspect or delete $rvm_vimage on the volume"
		fi
		rvm_vwritable
		rvm_vgrow_now
		;;
	` + string(driveBlock) + `)
		[ -b "$rvm_vdev" ] || rvm_fail "no block device for volume $rvm_vi's disk at $rvm_vpath"
		for rvm_vtool in ` + guestTune2fs + ` ` + guestExt4grow + `; do
			[ -f "$rvm_vtool" ] && [ -x "$rvm_vtool" ] || rvm_fail "the guest has no $rvm_vtool for volume $rvm_vi's disk at $rvm_vpath, and it never grows a block volume with another tool"
		done
		mkdir -p "$rvm_vpath" || rvm_fail "creating $rvm_vpath failed"
		rvm_vname="volume $rvm_vi's disk $rvm_vdev"
		rvm_vsize
		rvm_vsuper || rvm_fail "reading the filesystem on volume $rvm_vi's disk $rvm_vdev for $rvm_vpath with tune2fs -l failed; vm-launch never formats a block volume, so the guest will not boot with it"
		rvm_vfits
		if [ -n "$rvm_vgrow" ] && [ "$rvm_vjournal" != yes ]; then
			echo "vm-launch guest: volume $rvm_vi's disk $rvm_vdev has no journal that tune2fs -l shows, so it mounts at its old size of $rvm_vblocks blocks of $rvm_vbsize bytes and does not grow"
			rvm_vgrow=
		fi
		mount -t ext4 -o noatime,errors=remount-ro "$rvm_vdev" "$rvm_vpath" || rvm_fail "mounting volume $rvm_vi's disk $rvm_vdev at $rvm_vpath failed; vm-launch never formats a block volume, so the guest will not boot with it"
		rvm_vwritable
		rvm_vgrow_now
		;;
	` + volumeKindShare + `)
		[ -z "$rvm_vdev" ] || rvm_fail "stage 1 passed the device $rvm_vdev for the share at $rvm_vpath, which has no drive"
		mkdir -p "$rvm_vpath" || rvm_fail "creating $rvm_vpath failed"
		mount -t virtiofs ` + shareTagPrefix + `"$rvm_vi" "$rvm_vpath" || rvm_fail "mounting the share ` + shareTagPrefix + `$rvm_vi at $rvm_vpath failed; the hypervisor must give the guest a virtiofs device with that tag"
		;;
	'') rvm_fail "/rvm/mounts gives the volume at $rvm_vpath no kind" ;;
	*) rvm_fail "/rvm/mounts gives the volume at $rvm_vpath the kind $rvm_vkind, which the guest does not know" ;;
	esac
	rvm_vi=$((rvm_vi + 1))
done
`

// guestVolumeMke2fsArgs are the arguments with which stage 2 formats a blank
// volume image, before the device. The filesystem is ext4 with the features
// of the pinned mke2fs.conf, 4096-byte blocks, no reserved blocks, and the
// label rvm-volume. lazy_itable_init and lazy_journal_init leave the inode
// tables and the journal unwritten, and assume_storage_prezeroed, from
// e2fsprogs 1.47.0, marks the inode tables as zeroed, so the format writes
// only metadata and never the image's whole size. nodiscard keeps mke2fs
// from discarding the whole device first. All of it relies on every block of
// a blank image reading as zero.
const guestVolumeMke2fsArgs = "-t ext4 -F -b 4096 -m 0 -L rvm-volume -E lazy_itable_init=1,lazy_journal_init=1,nodiscard,assume_storage_prezeroed=1"

// guestImageSyncOptions are the mount options that make an image's mount
// synchronous, and guestImageMountOptions the ones every image mounts with.
const (
	guestImageSyncOptions  = "sync,dirsync"
	guestImageMountOptions = "noatime,noinit_itable,errors=remount-ro"
)

// guestVolumeTeardown follows the command, once its status is kept in
// rvm_status. It first flushes every image and block volume once with
// sync -f, last first, before any wait, because a block volume, and an image
// when the operator turned sync mounts off, mounts without sync, and the
// host kills the hypervisor at stopDeadline whether or not the teardown has
// reached its later flush. That flush only moves the writeback earlier, so
// it prints nothing and changes no status, and the later flush, which every
// volume gets, decides whether a volume's data is safe. A share gets no
// early flush, since a share whose virtiofsd hangs would hold up the drive
// volumes' flush with it.
//
// It then stops every process the command left behind, so that nothing
// writes to a volume after its last flush and nothing keeps a volume busy:
// kill -TERM -1, which reaches every process but stage 2, which is PID 1, a
// wait of up to guestTeardownTermWait that ends as soon as no other process
// runs, then kill -KILL -1 and a wait of up to guestTeardownKillWait, which
// covers the time the kernel takes to end the killed processes and close
// their files. Each wait polls every guestTeardownPoll (see
// guestOtherProcesses). A process that is still running at the end of
// either wait is reported with a line, and the teardown goes on.
//
// It then flushes and unmounts every volume that stage 2 mounted: every image
// and block volume first, last first, and then every share, last first, so a
// share that hangs in its flush or unmount never keeps a drive volume from
// its own. vm-launch refuses a volume path under another (see
// checkNotNested), so no unmount waits on another. A volume of a kind stage 2
// does not know, which setup refuses, goes with the shares. sync -f flushes
// the volume's filesystem only, so that the guest root's dirty pages never
// take up the time the guest has to stop, and the reboot that follows is
// reboot -nf, which makes no global sync of its own. The volumes are
// therefore flushed here, before the reboot. For a share, sync -f has the
// guest kernel ask virtiofsd to flush the shared directory. sync -f exits
// non-zero when syncfs(2) fails, which from Linux 5.8 includes a writeback
// error that the host's disk or quota gave the drive, so a failed flush means
// that data the app wrote may be lost. A failed flush and a failed unmount
// each print a line that names the volume's kind, its path, and its image,
// device, or share tag, with what the tool said. When either fails for any
// volume and the command exited 0, stage 2 reports guestFlushFailStatus,
// vm-launch's own exit status for a launch that failed, in place of the
// command's, so a task whose output may be lost never passes. A command that
// failed keeps its own status.
//
// The waits take at most guestTeardownTermWait plus guestTeardownKillWait,
// 3 seconds, which a spec keeps inside stopDeadline, the time the guest
// command and this teardown share after a stop request. The early flush
// adds little to the teardown's time, because it writes what the later
// flush would otherwise write, and a deadline that ends the guest during
// the waits loses only what the leftover processes wrote after it.
const guestVolumeTeardown = guestOtherProcesses + `rvm_vi=$RVM_VOLUMES
while [ "$rvm_vi" -gt 0 ]; do
	rvm_vi=$((rvm_vi - 1))
	eval "rvm_vkind=\${RVM_VOL${rvm_vi}_KIND:-} rvm_vpath=\$RVM_VOL${rvm_vi}_PATH"
	case "$rvm_vkind" in
	` + string(driveImage) + ` | ` + string(driveBlock) + `) sync -f "$rvm_vpath" >/dev/null 2>&1 ;;
	esac
done
kill -TERM -1 2>/dev/null
rvm_n=0
while [ "$rvm_n" -lt ` + guestTeardownTermPolls + ` ] && rvm_others; do
	sleep ` + guestTeardownPollText + `
	rvm_n=$((rvm_n + 1))
done
rvm_others && echo "vm-launch guest: processes the command left were still running ` + guestTeardownTermSeconds + ` seconds after SIGTERM, so the guest sends them SIGKILL before it flushes the volumes"
kill -KILL -1 2>/dev/null
rvm_n=0
while [ "$rvm_n" -lt ` + guestTeardownKillPolls + ` ] && rvm_others; do
	sleep ` + guestTeardownPollText + `
	rvm_n=$((rvm_n + 1))
done
rvm_others && echo "vm-launch guest: processes were still running ` + guestTeardownKillSeconds + ` second after SIGKILL, so what they write after the flush may be lost"
rvm_vbad=
for rvm_vpass in drive other; do
	rvm_vi=$RVM_VOLUMES
	while [ "$rvm_vi" -gt 0 ]; do
		rvm_vi=$((rvm_vi - 1))
		eval "rvm_vkind=\${RVM_VOL${rvm_vi}_KIND:-} rvm_vpath=\$RVM_VOL${rvm_vi}_PATH rvm_vimage=\${RVM_VOL${rvm_vi}_IMAGE:-} rvm_vdev=\${rvm_vdev_$rvm_vi:-}"
		case "$rvm_vpass:$rvm_vkind" in
		drive:` + string(driveImage) + `) rvm_vname="the volume image $rvm_vimage on $rvm_vdev" ;;
		drive:` + string(driveBlock) + `) rvm_vname="the block volume on $rvm_vdev" ;;
		drive:* | other:` + string(driveImage) + ` | other:` + string(driveBlock) + `) continue ;;
		other:` + volumeKindShare + `) rvm_vname="the share ` + shareTagPrefix + `$rvm_vi" ;;
		*) rvm_vname="the volume of kind $rvm_vkind" ;;
		esac
		if ! rvm_verr=$(sync -f "$rvm_vpath" 2>&1); then
			echo "vm-launch guest: flushing $rvm_vname at $rvm_vpath with sync -f failed (${rvm_verr:-it gave no reason}), so data the app wrote to it may be lost"
			rvm_vbad=1
		fi
		if ! rvm_verr=$(umount "$rvm_vpath" 2>&1); then
			echo "vm-launch guest: unmounting $rvm_vname at $rvm_vpath failed (${rvm_verr:-it gave no reason}), so writes that reached it after its flush may be lost"
			rvm_vbad=1
		fi
	done
done
if [ -n "$rvm_vbad" ] && [ "$rvm_status" = 0 ]; then
	echo "vm-launch guest: the command exited 0, but a volume did not flush or unmount, so the guest reports the status ` + guestFlushFailStatus + `"
	rvm_status=` + guestFlushFailStatus + `
fi
`

// guestOtherProcesses defines rvm_others, which succeeds while any process
// other than stage 2 runs in the guest. It looks at each /proc/PID/stat
// with the shell's own read, so the look starts no process, and it passes
// over PID 1, its own shell, a process that has ended and waits to be
// reaped (state Z or X), and a kernel thread, which has PF_KTHREAD in its
// flags, the ninth field. The fields after the command name follow its
// last ") ", since the name itself may hold spaces and parentheses. A
// process whose flags do not read as a number counts as running, so a
// stat line the guest cannot parse only makes the wait longer.
const guestOtherProcesses = `rvm_others() {
	for rvm_p in ` + guestProcDir + `/[0-9]*; do
		rvm_pid=${rvm_p##*/}
		[ "$rvm_pid" != 1 ] && [ "$rvm_pid" != "$$" ] || continue
		read -r rvm_pl 2>/dev/null <"$rvm_p/stat" || continue
		rvm_pl=${rvm_pl##*") "}
		case "${rvm_pl%% *}" in
		Z | X | x) continue ;;
		esac
		rvm_pl=${rvm_pl#*" "*" "*" "*" "*" "*" "}
		rvm_pf=${rvm_pl%% *}
		case "$rvm_pf" in
		'' | *[!0-9]*) return 0 ;;
		esac
		[ "$((rvm_pf & ` + guestPFKthread + `))" != 0 ] || return 0
	done
	return 1
}
`

// guestProcDir is the guest's /proc, which a spec moves.
const guestProcDir = "/proc"

// guestPFKthread is PF_KTHREAD from the kernel's include/linux/sched.h, in
// decimal as the guest's shell takes it.
const guestPFKthread = "2097152"

// The teardown's waits for the processes the command left behind (see
// guestVolumeTeardown), as durations and as the text the guest's shell
// takes. A spec keeps the two in step and the waits inside stopDeadline.
const (
	guestTeardownPoll     = 100 * time.Millisecond
	guestTeardownTermWait = 2 * time.Second
	guestTeardownKillWait = 1 * time.Second

	guestTeardownPollText    = "0.1"
	guestTeardownTermPolls   = "20"
	guestTeardownKillPolls   = "10"
	guestTeardownTermSeconds = "2"
	guestTeardownKillSeconds = "1"
)

// guestFlushFailStatus is the status stage 2 reports, in decimal, when the
// command exited 0 but a volume did not flush or unmount: exitLaunchError,
// the status vm-launch gives a launch that failed, which a spec keeps in
// step.
const guestFlushFailStatus = "125"

// volumeOnDrive is one guest volume with the drive that holds it, or with no
// drive for a share.
type volumeOnDrive struct {
	vol   guestVolume
	drive *guestDrive
}

// volumesOnDrives pairs each of g.vols, in volume order, with its drive. A
// volume whose setting is a share has no drive, and every other volume takes
// the next entry of g.drives.volumes, which are the drives of the volumes
// that are not shares, in the same order (see checkPreparedOrder). The place
// of each pair is the volume index, so /rvm/disks and /rvm/mounts number a
// share and the volumes beside it as the guest numbers them, and a share
// never shifts a drive onto another volume's number. More guest volumes than
// a guest can have, and drives that do not match the volumes that are not
// shares one for one, are an error, because a guess could then mount one
// volume's disk at another volume's path.
func volumesOnDrives(g guestContents) ([]volumeOnDrive, error) {
	if len(g.vols) > maxVolumes {
		return nil, fmt.Errorf("%d guest volumes, over the %d a guest can have", len(g.vols), maxVolumes)
	}
	d := g.drives.volumes
	shares := 0
	for _, v := range g.vols {
		if v.Settings.Mode == volumeShare {
			shares++
		}
	}
	if len(d) != len(g.vols)-shares {
		if shares == 0 {
			return nil, fmt.Errorf("%d volume drives for %d guest volumes", len(d), len(g.vols))
		}
		return nil, fmt.Errorf("%d volume drives for %d guest volumes, %d of them shares, which have no drive", len(d), len(g.vols), shares)
	}
	pairs := make([]volumeOnDrive, len(g.vols))
	next := 0
	for n, v := range g.vols {
		pairs[n].vol = v
		if v.Settings.Mode == volumeShare {
			continue
		}
		pairs[n].drive = &d[next]
		next++
	}
	return pairs, nil
}

// mountsFile returns the guest /rvm/mounts, which stage 2 sources before it
// mounts the volumes: their number as RVM_VOLUMES, the operator's sync mount
// setting as RVM_SYNC_MOUNTS, true unless g.noVolumeSync, and, for each volume by its
// volume index, its kind as RVM_VOLn_KIND and its quoted path as
// RVM_VOLn_PATH, and for an image volume its image name as RVM_VOLn_IMAGE. A
// share has the kind share and no image. Any other volume's kind is the one
// disksFile gives the volume's drive in /rvm/disks, taken from the same entry
// of g.drives, so the two stages never disagree on which volume is an image
// that stage 2 may format. Volume drives that do not match the guest's
// volumes (see volumesOnDrives), and a drive kind other than image or block,
// are an error, because stage 2 could then treat a disk as the wrong kind.
// Stage 2 decides from the setting and from the filesystem whether an image
// mounts with sync and dirsync, because only the guest sees whether an
// image's filesystem has a journal (see guestVolumeSetup).
func mountsFile(g guestContents) (string, error) {
	pairs, err := volumesOnDrives(g)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "RVM_VOLUMES=%d\nRVM_SYNC_MOUNTS=%t\n", len(pairs), !g.noVolumeSync)
	for n, p := range pairs {
		if p.drive == nil {
			fmt.Fprintf(&b, "RVM_VOL%d_KIND=%s\nRVM_VOL%d_PATH=%s\n", n, volumeKindShare, n, shellQuote(p.vol.ContainerDir))
			continue
		}
		switch p.drive.kind {
		case driveImage:
			fmt.Fprintf(&b, "RVM_VOL%d_KIND=%s\nRVM_VOL%d_PATH=%s\nRVM_VOL%d_IMAGE=%s\n", n, p.drive.kind, n, shellQuote(p.vol.ContainerDir), n, shellQuote(p.vol.ImageName))
		case driveBlock:
			fmt.Fprintf(&b, "RVM_VOL%d_KIND=%s\nRVM_VOL%d_PATH=%s\n", n, p.drive.kind, n, shellQuote(p.vol.ContainerDir))
		default:
			return "", fmt.Errorf("drive %s holds a %q, and the guest mounts only %q and %q volume drives", volumeDriveID(n), p.drive.kind, driveImage, driveBlock)
		}
	}
	return b.String(), nil
}

// sectorBytes is the unit in which sysfs gives a block device's size.
const sectorBytes = 512

// disksFile returns the guest /rvm/disks, which stage 1 sources to find the
// guest's drives (see guestRootInit). It names every drive by its identity
// (see newGuestDrives) and its size in sectors: the guest root image as
// RVM_ROOT_ID and RVM_ROOT_SECTORS, with RVM_ROOT_INODE_RATIO, when g has one,
// the number of volumes as RVM_VOLUMES, which is always there, and each
// volume, by its volume index, as RVM_VOLn_KIND, RVM_VOLn_ID, and
// RVM_VOLn_SECTORS. A share has no drive, so it gets RVM_VOLn_KIND=share
// alone, which stage 1 passes over. The sizes are those of the files the
// hypervisor gets, as the providers opened them, and stage 1 checks each drive's against
// them. Drives may share a size, because stage 1 tells them apart by
// identity alone. Drives that would share an identity, an identity the guest
// could not match, a size that is not whole sectors, a drive without an
// identity, and volume drives that do not match the guest's volumes (see
// volumesOnDrives) are an error, because stage 1 would then refuse to boot,
// and a guess could format a volume or mount one at another's path.
func disksFile(g guestContents) (string, error) {
	var b strings.Builder
	d := g.drives
	var named []namedDriveID
	switch {
	case g.rootBytes < 0 || g.rootInodeRatio < 0:
		return "", fmt.Errorf("the guest root image of %d bytes at %d bytes per inode has a negative size", g.rootBytes, g.rootInodeRatio)
	case g.rootBytes == 0 && g.rootInodeRatio != 0:
		return "", fmt.Errorf("an inode ratio of %d bytes per inode for no guest root image", g.rootInodeRatio)
	case g.rootBytes == 0 && d.rootID != "":
		return "", fmt.Errorf("a drive identity %q for no guest root image", d.rootID)
	case g.rootBytes > 0:
		if g.rootBytes%sectorBytes != 0 {
			return "", fmt.Errorf("the guest root image of %d bytes is not a whole number of %d-byte sectors", g.rootBytes, sectorBytes)
		}
		if g.rootInodeRatio == 0 {
			return "", fmt.Errorf("the guest root image of %d bytes has no inode ratio", g.rootBytes)
		}
		named = append(named, namedDriveID{name: "the guest root image", id: d.rootID})
		fmt.Fprintf(&b, "RVM_ROOT_ID=%s\nRVM_ROOT_SECTORS=%d\nRVM_ROOT_INODE_RATIO=%d\n", d.rootID, g.rootBytes/sectorBytes, g.rootInodeRatio)
	}
	if len(d.volumes) > maxVolumes {
		return "", fmt.Errorf("%d volume drives, over the %d a guest can have", len(d.volumes), maxVolumes)
	}
	pairs, err := volumesOnDrives(g)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "RVM_VOLUMES=%d\n", len(pairs))
	for n, p := range pairs {
		if p.drive == nil {
			fmt.Fprintf(&b, "RVM_VOL%d_KIND=%s\n", n, volumeKindShare)
			continue
		}
		v := *p.drive
		drive := volumeDriveID(n)
		if v.kind != driveImage && v.kind != driveBlock {
			return "", fmt.Errorf("drive %s holds a %q, and the guest supports only %q and %q volume drives", drive, v.kind, driveImage, driveBlock)
		}
		if v.bytes <= 0 || v.bytes%sectorBytes != 0 {
			return "", fmt.Errorf("the volume image of %d bytes on drive %s is not a positive whole number of %d-byte sectors", v.bytes, drive, sectorBytes)
		}
		named = append(named, namedDriveID{name: "drive " + drive, id: v.id})
		fmt.Fprintf(&b, "RVM_VOL%d_KIND=%s\nRVM_VOL%d_ID=%s\nRVM_VOL%d_SECTORS=%d\n", n, v.kind, n, v.id, n, v.bytes/sectorBytes)
	}
	if err := checkDriveIDs(named, ""); err != nil {
		return "", err
	}
	return b.String(), nil
}

// initramfsName names the initramfs memfd. Its /proc/PID/fd link reads
// /memfd:vm-launch-initramfs (deleted).
const initramfsName = "vm-launch-initramfs"

// initramfsSeals are the seals on the initramfs memfd. Once they are set, no
// descriptor can change its contents or its size, and no seal can be added
// or removed.
const initramfsSeals = unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE | unix.F_SEAL_SEAL

// initramfsMemfdFlags are the memfd_create flags of the initramfs on every
// kernel. vm-launch adds MFD_NOEXEC_SEAL where the kernel knows it.
const initramfsMemfdFlags = unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING

// memfdCreate is unix.MemfdCreate. Specs replace it to see the flags and to
// act as an older kernel.
var memfdCreate = unix.MemfdCreate

// createInitramfsMemfd creates the initramfs memfd with MFD_NOEXEC_SEAL,
// which makes it non-executable and seals that with F_SEAL_EXEC, because
// nothing ever runs the archive. From Linux 6.3, a memfd created without
// MFD_EXEC or MFD_NOEXEC_SEAL draws a kernel warning, and vm.memfd_noexec=2
// refuses it. Older kernels reject the unknown flag with EINVAL, and only
// then does vm-launch create the memfd without it. Every other error is
// returned as it is.
func createInitramfsMemfd() (int, error) {
	fd, err := memfdCreate(initramfsName, initramfsMemfdFlags|unix.MFD_NOEXEC_SEAL)
	if errors.Is(err, unix.EINVAL) {
		fd, err = memfdCreate(initramfsName, initramfsMemfdFlags)
	}
	return fd, err
}

// guestContents is what the initramfs holds for one guest besides busybox.
type guestContents struct {
	// command is the guest command, /rvm/cmd.
	command string
	// nonce makes the console markers of stage 2 (see startTag).
	nonce string
	// nw is the guest network, which run always builds.
	nw *network
	// env is the guest environment, /rvm/env (see buildGuestEnv).
	env string
	// vols are the guest volumes in volume order, which stage 2 mounts. A
	// share has no drive, and each other volume is on the next entry of
	// drives.volumes (see volumesOnDrives).
	vols []guestVolume
	// drives are the drives the guest formats or mounts, with their
	// identities and, for the volumes, their sizes as the providers opened
	// them, for /rvm/disks (see disksFile).
	drives guestDrives
	// caBundle is the guest's CA bundle (see guestCABundle), or nil when
	// there is no certificate to trust.
	caBundle []byte
	// nofile is the command's open-files limit (see guestNofile), /rvm/limits.
	nofile nofileLimit
	// rootBytes is the size of the guest root image (see rootDiskSize), or
	// 0 when the guest root stays in RAM, and rootInodeRatio is the bytes
	// per inode of its filesystem, or 0 without one; both go in /rvm/disks.
	rootBytes      int64
	rootInodeRatio int64
	// tools are the guest filesystem tools (see openGuestTools), which stage
	// 2 needs for an image or block volume, or nil for a guest that has
	// neither. The caller closes them after the initramfs is written.
	tools *guestTools
	// noVolumeSync is set when the operator turned sync mounts off (see
	// volumeSyncMountsFlag), so that stage 2 mounts an image whose
	// filesystem has a journal without sync and dirsync. The zero value
	// keeps every image's mount synchronous.
	noVolumeSync bool
}

// The guest filesystem tools. A guest with an image or block volume gets
// four static binaries and a pinned mke2fs.conf, all below guestToolsDir.
// They are not in /bin, where stage 1 installs busybox's applets and
// formats the guest root with busybox's own mke2fs, so a stage that wants
// the e2fsprogs tools names them by these paths.
const (
	guestToolsDir     = "/rvm/tools"
	guestMke2fs       = guestToolsDir + "/mke2fs"
	guestE2fsck       = guestToolsDir + "/e2fsck"
	guestTune2fs      = guestToolsDir + "/tune2fs"
	guestExt4grow     = guestToolsDir + "/ext4grow"
	guestMke2fsConfig = guestToolsDir + "/mke2fs.conf"
)

// guestToolNames are the tools' file names, which are the same in the
// artifacts directory, where the cell's runtime config installs them side by
// side with busybox, and below guestToolsDir in the guest.
var guestToolNames = []string{"mke2fs", "e2fsck", "tune2fs", "ext4grow"}

// guestMke2fsConfText is the mke2fs.conf the guest's mke2fs reads through
// MKE2FS_CONFIG. It is the profile that the e2fsprogs 1.47.4 build of the
// guest tools carries inside mke2fs, written out here so that the filesystem
// features of a new image are the ones we measured and do not move with the
// tools. An ext4 image gets a journal, extents, flex_bg, 64bit,
// resize_inode, which reserves the descriptor room that online growth uses,
// and metadata checksums.
const guestMke2fsConfText = `[defaults]
	base_features = sparse_super,large_file,filetype,resize_inode,dir_index,ext_attr
	default_mntopts = acl,user_xattr
	enable_periodic_fsck = 0
	blocksize = 4096
	inode_size = 256
	inode_ratio = 16384

[fs_types]
	ext3 = {
		features = has_journal
	}
	ext4 = {
		features = has_journal,extent,huge_file,flex_bg,metadata_csum,metadata_csum_seed,64bit,dir_nlink,extra_isize,orphan_file
	}
	small = {
		blocksize = 1024
		inode_ratio = 4096
	}
	floppy = {
		blocksize = 1024
		inode_ratio = 8192
	}
	big = {
		inode_ratio = 32768
	}
	huge = {
		inode_ratio = 65536
	}
	news = {
		inode_ratio = 4096
	}
	largefile = {
		inode_ratio = 1048576
		blocksize = -1
	}
	largefile4 = {
		inode_ratio = 4194304
		blocksize = -1
	}
	hurd = {
		blocksize = 4096
		inode_size = 128
		warn_y2038_dates = 0
	}
`

// noGuestToolsHint ends every refusal about a guest tool, so that the line
// tells an operator what the cell lacks.
const noGuestToolsHint = "; the cell needs the guest e2fsprogs artifact (mke2fs, e2fsck, tune2fs, and ext4grow in the artifacts directory) for a guest with an image or block volume"

// guestTool is one tool, opened and checked.
type guestTool struct {
	name string
	file *os.File
	size int64
}

// guestTools are the guest filesystem tools of one launch, each held open
// from the moment openGuestTools checked it, so that the bytes that go into
// the initramfs are those of the file that passed the check.
type guestTools struct {
	tools []guestTool
}

// needsGuestTools reports whether a guest with volumes volumes, of which
// shares are served as shares, has an image or block volume. Only an image
// or a block volume is formatted, checked, or grown by the guest.
func needsGuestTools(volumes, shares int) bool { return volumes > shares }

// openGuestTools opens each of guestToolNames in the artifacts directory
// root. A tool must be a regular, executable, non-empty file that is
// root's own or reached through symbolic links that stay inside root. A
// link out of root is refused, because in the container the artifacts
// directory is the only part of the cell's disk that is there, and a link
// to anywhere else would put a file into the guest that the operator did
// not install. The error names the first tool that fails and says that the
// cell needs the guest e2fsprogs artifact. The caller closes the result.
func openGuestTools(root string) (*guestTools, error) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("guest tool: the artifacts directory %s cannot be resolved: %w%s", root, err, noGuestToolsHint)
	}
	t := &guestTools{}
	for _, name := range guestToolNames {
		tool, err := openGuestTool(root, realRoot, name)
		if err != nil {
			t.Close()
			return nil, err
		}
		t.tools = append(t.tools, tool)
	}
	return t, nil
}

// openGuestTool opens and checks the tool name in root, whose resolved path
// is realRoot.
func openGuestTool(root, realRoot, name string) (guestTool, error) {
	fail := func(format string, args ...any) (guestTool, error) {
		return guestTool{}, fmt.Errorf("guest tool %s "+format+"%s", append(append([]any{name}, args...), noGuestToolsHint)...)
	}
	p := filepath.Join(root, name)
	target, err := filepath.EvalSymlinks(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fail("is missing: %s does not exist", p)
	case err != nil:
		return fail("cannot be resolved: %v", err)
	case !strings.HasPrefix(target, realRoot+string(filepath.Separator)):
		return fail("at %s resolves to %s, which is not a file inside the artifacts directory", p, target)
	}
	// The resolved path is opened without following a link, so a link
	// that appears after the check cannot take the open elsewhere, and
	// without blocking, so that a FIFO in its place fails the type check
	// instead of hanging the launch.
	f, err := os.OpenFile(target, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fail("cannot be opened: %v", err)
	}
	info, err := f.Stat()
	switch {
	case err != nil:
		err = fmt.Errorf("guest tool %s cannot be examined: %w%s", name, err, noGuestToolsHint)
	case !info.Mode().IsRegular():
		_, err = fail("at %s is not a regular file", p)
	case info.Mode().Perm()&0o111 == 0:
		_, err = fail("at %s is not executable", p)
	case info.Size() == 0:
		_, err = fail("at %s is empty", p)
	}
	if err != nil {
		f.Close()
		return guestTool{}, err
	}
	return guestTool{name: name, file: f, size: info.Size()}, nil
}

// Close closes every tool. It is safe on nil and to call twice.
func (t *guestTools) Close() {
	if t == nil {
		return
	}
	for _, tool := range t.tools {
		tool.file.Close()
	}
	t.tools = nil
}

// archiveSteps returns the archive steps that add the tools directory, the
// tools, and mke2fs.conf.
func (t *guestTools) archiveSteps(cw *cpioWriter) []func() error {
	steps := []func() error{func() error { return cw.Dir(strings.TrimPrefix(guestToolsDir, "/"), 0o755) }}
	for _, tool := range t.tools {
		steps = append(steps, func() error {
			return cw.File(strings.TrimPrefix(guestToolsDir+"/"+tool.name, "/"), 0o755, tool.size, io.NewSectionReader(tool.file, 0, tool.size))
		})
	}
	return append(steps, func() error {
		return cw.File(strings.TrimPrefix(guestMke2fsConfig, "/"), 0o644, int64(len(guestMke2fsConfText)), strings.NewReader(guestMke2fsConfText))
	})
}

// newInitramfs builds the guest initramfs (see writeInitramfs) in a sealed
// memfd and returns it, so the archive never touches a disk. Its memory is
// charged to the container and lasts while any process holds a descriptor
// for it. The descriptor is close-on-exec: vm-launch passes it to the
// hypervisor as an extra file, which the hypervisor opens through
// /proc/self/fd, and closes its own copy once the hypervisor has started.
func newInitramfs(busyboxPath string, g guestContents) (*os.File, error) {
	fd, err := createInitramfsMemfd()
	if err != nil {
		return nil, fmt.Errorf("creating the initramfs memfd: %w", err)
	}
	f := os.NewFile(uintptr(fd), "memfd:"+initramfsName)
	if err := writeInitramfs(f, busyboxPath, g); err != nil {
		f.Close()
		return nil, err
	}
	if err := addSeals(f, initramfsSeals); err != nil {
		f.Close()
		return nil, fmt.Errorf("sealing the initramfs memfd: %w", err)
	}
	return f, nil
}

// addSeals adds seals to the memfd f.
func addSeals(f *os.File, seals int) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var sealErr error
	if err := rc.Control(func(fd uintptr) {
		_, sealErr = unix.FcntlInt(fd, unix.F_ADD_SEALS, seals)
	}); err != nil {
		return err
	}
	return sealErr
}

// writeInitramfs writes a gzip-compressed newc initramfs to dst holding a
// static busybox, the console and null device nodes, the command script at
// /rvm/cmd, the guest network's /rvm/net and /etc/resolv.conf, the guest
// environment as /rvm/env with mode 0600, the command's limits as
// /rvm/limits, the drive identities and sizes as /rvm/disks, and the two
// stages of the guest's boot that run it, /init and /rvm/init. With volumes
// it also holds /rvm/mounts, and with a CA bundle it holds that at
// /etc/ssl/certs/ca-certificates.crt. A hard open-files limit of 0 is an
// error, because it is a limit no caller can have meant: vm-launch itself
// could not run under it. So are drives that disksFile rejects.
func writeInitramfs(dst *os.File, busyboxPath string, g guestContents) error {
	if g.nw == nil {
		return errors.New("writing the initramfs: no guest network")
	}
	if g.nofile.hard == 0 {
		return errors.New("writing the initramfs: no open files limit")
	}
	busybox, err := os.Open(busyboxPath)
	if err != nil {
		return fmt.Errorf("opening busybox: %w", err)
	}
	defer busybox.Close()
	info, err := busybox.Stat()
	if err != nil {
		return fmt.Errorf("stat busybox: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("busybox %s is not a regular file", busyboxPath)
	}

	if err := writeInitramfsArchive(dst, busybox, info.Size(), g); err != nil {
		return fmt.Errorf("writing the initramfs: %w", err)
	}
	return nil
}

func writeInitramfsArchive(w io.Writer, busybox io.Reader, busyboxSize int64, g guestContents) error {
	buf := bufio.NewWriter(w)
	gz := gzip.NewWriter(buf)
	cw := newCPIOWriter(gz)
	file := func(name string, perm uint32, content string) func() error {
		return func() error { return cw.File(name, perm, int64(len(content)), strings.NewReader(content)) }
	}

	disks, err := disksFile(g)
	if err != nil {
		return err
	}
	stage2 := initScript(g.nonce, len(g.vols) > 0)
	steps := []func() error{
		func() error { return cw.Dir("bin", 0o755) },
		func() error { return cw.Dir("dev", 0o755) },
		func() error { return cw.CharDevice("dev/console", 0o600, 5, 1) },
		func() error { return cw.CharDevice("dev/null", 0o666, 1, 3) },
		func() error { return cw.Dir("etc", 0o755) },
		func() error { return cw.Dir("proc", 0o555) },
		func() error { return cw.Dir("sys", 0o555) },
		func() error { return cw.Dir("tmp", 0o1777) },
		func() error { return cw.Dir("rvm", 0o755) },
		func() error { return cw.File("bin/busybox", 0o755, busyboxSize, busybox) },
		file("rvm/cmd", 0o644, g.command),
		file("rvm/net", 0o644, netFile(g.nw)),
		file("rvm/env", 0o600, g.env),
		file("rvm/limits", 0o644, limitsFile(g.nofile)),
		file("etc/resolv.conf", 0o644, g.nw.resolvConf),
	}
	if g.nw != nil && len(g.nw.ports) > 0 {
		steps = append(steps, func() error { return cw.FIFO(strings.TrimPrefix(guestListenTick, "/"), 0o600) })
	}
	if g.tools != nil {
		steps = append(steps, g.tools.archiveSteps(cw)...)
	}
	if len(g.vols) > 0 {
		mounts, err := mountsFile(g)
		if err != nil {
			return err
		}
		steps = append(steps, file("rvm/mounts", 0o644, mounts))
	}
	if len(g.caBundle) > 0 {
		bundle := strings.TrimPrefix(guestCABundlePath, "/")
		steps = append(steps,
			func() error { return cw.Dir(path.Dir(path.Dir(bundle)), 0o755) },
			func() error { return cw.Dir(path.Dir(bundle), 0o755) },
			file(bundle, 0o644, string(g.caBundle)),
		)
	}
	steps = append(steps,
		file("rvm/disks", 0o644, disks),
		file(strings.TrimPrefix(guestStage2, "/"), 0o755, stage2),
		file("init", 0o755, guestRootInit),
		cw.Close,
		gz.Close,
		buf.Flush,
	)
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}
