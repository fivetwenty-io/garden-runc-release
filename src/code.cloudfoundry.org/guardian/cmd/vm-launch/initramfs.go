//go:build linux

package main

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

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

// Serial console markers written by the guest /init. The nonce makes them
// impossible to forge by accident from guest command output. The guest
// command runs as root and can read the nonce from /init, so it can forge
// them on purpose, which changes only what vm-launch reports for that
// command: its exit status, and whether its own port is open.
func startTag(nonce string) string  { return "RVM_START_" + nonce }
func exitTag(nonce string) string   { return "RVM_EXIT_" + nonce + "=" }
func listenTag(nonce string) string { return "RVM_LISTEN_" + nonce + "=" }

// initScript is the guest /init. It runs the command with stdin from
// /dev/null (the serial console never delivers EOF), reports its status on
// the console, and reboots: with -no-reboot (QEMU) or reboot=k (Firecracker)
// that ends the hypervisor. poweroff -f hangs Firecracker, so it is not used.
//
// Right after the mounts, /init defines rvm_fail, which every setup step
// uses. It then mounts /dev/shm, brings up lo and eth0 from /rvm/net (in
// every guest, a task's included), prepares the open-files limit from
// /rvm/limits, and checks that /rvm/env sources. A guest with a volume
// then formats the volume image when it is blank and mounts it. When a
// setup step fails, /init reboots before the start tag, so vm-launch
// reports a guest that never started its command and shows the console
// output, which ends with the failed step.
//
// The command runs in a subshell that records its pid, sets its open-files
// limit, sources /rvm/env, and then becomes the shell that runs /rvm/cmd
// with sh -c, so its status is the command's (see guestRunCommand). /init writes the exit line through its own open of
// /dev/console, because the command may have left the console that it
// shares with /init non-blocking, and through the shared console only when
// that open fails. The guest environment applies only inside that subshell,
// never to /init's own steps, such as the unquoted status in the exit line
// or the volume teardown. A guest with a port watches, while the command
// runs, whether anything listens on it (see guestListenWatch). With a
// volume, /init syncs and unmounts it after the command and before it
// reports the status.
func initScript(nonce string, volume bool) string {
	setup := guestFailFunc + guestShmSetup + guestNetworkSetup + guestLimitsSetup + guestEnvChecks
	if volume {
		setup += guestVolumeSetup
	}
	run := guestListenWatch(nonce) + guestRunCommand + "rvm_status=$?\n" + guestListenStop
	if volume {
		run += guestVolumeTeardown
	}
	exit := "echo " + exitTag(nonce) + "$rvm_status"
	run += exit + " >/dev/console || " + exit + "\n"
	return `#!/bin/busybox sh
/bin/busybox --install -s /bin
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
` + setup + `echo ` + startTag(nonce) + "\n" + run + `reboot -f
`
}

// guestFailFunc defines rvm_fail, which a setup step calls when it fails: it
// names the step on the console and reboots before the start tag.
const guestFailFunc = `rvm_fail() { echo "vm-launch guest setup: $1"; reboot -f; exit 1; }
`

// guestShmSetup mounts a tmpfs at /dev/shm with the options Garden gives a
// container's /dev/shm (noexec, nosuid, nodev, and mode 1777), so POSIX
// shared memory and semaphores work in the guest as they do in a container.
// Garden sets no size, unlike runc's own 64 MiB default, so a container's
// /dev/shm can grow to half the host's memory, bounded in practice by the
// container's memory limit. The guest's bound is its memory, so /init asks
// for half of what the guest kernel has, which is the tmpfs default spelled
// out: about 51 MiB in the smallest guest, whose kernel keeps part of its
// 128 MiB. Pages in it count as guest memory in use, as they count against a
// container's limit.
const guestShmSetup = `mkdir -p /dev/shm && mount -t tmpfs -o noexec,nosuid,nodev,mode=1777,size=50% tmpfs /dev/shm || rvm_fail "mounting /dev/shm failed"
`

// guestNetworkSetup configures the guest NIC. The virtio-net driver is built
// into the kernel and normally has eth0 ready before /init runs; the wait
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
// 1048576 by default, so /init raises it to the hard limit when that is
// higher, and it lifts fs.file-max, which the kernel sizes from guest RAM,
// to the highest value, as systemd does, so that the guest-wide count of
// open files never binds before a process limit does. A failure there only
// warns, because the command runs as root, which fs.file-max does not
// limit. /init then checks, in a subshell, that the limits apply, so that a
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

// guestListenWatch starts, in a guest with a port (RVM_PORT in /rvm/net),
// a background watcher that tells vm-launch whether anything in the guest
// listens on that port, so that vm-launch opens the container's PORT only
// while it does, as a container's port refuses connections until its app
// listens. Once a second, the watcher looks in /proc/net/tcp and
// /proc/net/tcp6 for a listening socket on the port at an address other
// than loopback, which is what a connection forwarded from the container
// reaches, and prints a listen line, the listen tag and 1 or 0, each time
// the answer changes. It starts after the start tag, so vm-launch reads
// every listen line as part of the command's run. The kernel writes an IPv4
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
// busybox a look costs about 0.09 ms of CPU for each listening socket.
// Measured over 20 seconds, an idle guest used 6 ticks of CPU, a guest with
// 201 listening sockets and 2000 connections used 62 ticks, about 3% of a
// core, and a guest with 2001 listening sockets used 372 ticks, about 19%.
//
// A look at a table fails when the table cannot be opened or yields no
// header line; the kernel allocates its buffer for a table at the first
// read, so a read that succeeds once does not fail later. A listening
// socket that the watcher finds is an answer, whatever the other table gave.
// Otherwise a look that failed keeps the last answer, so a look that fails
// never closes the port of an app that still listens. The watcher reads
// only the tables the guest kernel has, as /proc/net/tcp6 is missing from a
// kernel without IPv6.
//
// The watcher opens /dev/console for each listen line, so it writes through
// its own open file and not the one it shares with the command, which the
// command may have made non-blocking. It takes a new state only once the
// line is written, so a line that fails is written again a second later.
func guestListenWatch(nonce string) string {
	return `rvm_watch=
if [ -n "${RVM_PORT:-}" ]; then
	rvm_port_hex=$(printf '%04X' "$RVM_PORT")
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
		rvm_up=0
		while :; do
			rvm_now=0
			rvm_failed=
			for rvm_table in $rvm_tables; do
				rvm_head=
				while read -r rvm_sl rvm_local rvm_remote rvm_st rvm_rest; do
					if [ -z "$rvm_head" ]; then
						rvm_head=1
						continue
					fi
					[ "$rvm_st" = 0A ] || break
					case $rvm_local in
					*:"$rvm_port_hex") ;;
					*) continue ;;
					esac
					case ${rvm_local%:*} in
					??????7F | 00000000000000000000000001000000 | 0000000000000000FFFF0000??????7F) ;;
					*) rvm_now=1 ;;
					esac
				done 2>/dev/null <"$rvm_table"
				[ -n "$rvm_head" ] || rvm_failed=1
			done
			if [ "$rvm_now" = 0 ] && [ -n "$rvm_failed" ]; then
				rvm_now=$rvm_up
			fi
			if [ "$rvm_now" != "$rvm_up" ]; then
				echo "` + listenTag(nonce) + `$rvm_now" >/dev/console && rvm_up=$rvm_now
			fi
			rvm_pause
		done
	) </dev/null &
	rvm_watch=$!
fi
`
}

// guestListenTick is the FIFO the listen watcher waits on. The initramfs of
// a guest with a port holds it, and nothing ever writes it.
const guestListenTick = "/rvm/listen-tick"

// guestListenStop stops the listen watcher once the command has ended and
// before /init reports its status, so no listen line follows the exit line.
const guestListenStop = `if [ -n "$rvm_watch" ]; then
	kill "$rvm_watch"
	wait "$rvm_watch"
fi
`

// guestEnvChecks makes a broken /rvm/env a failed setup step, with the
// console shown, instead of a command that fails to start. It sources
// /rvm/env in a subshell, so /init itself never gets the guest environment.
const guestEnvChecks = `( . /rvm/env ) || rvm_fail "reading /rvm/env failed"
`

// guestRunCommand runs the guest command with its open-files limit and the
// guest environment, in a subshell that becomes the shell running the
// command. Only that subshell gets the limit, so /init's own steps never run
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
const guestRunCommand = "( { read -r rvm_self rvm_rest </proc/self/stat && echo \"$rvm_self\" >" + guestAppPid + "; } || echo \"vm-launch guest: recording the command's pid in " + guestAppPid + " failed; a stop request cannot reach the command\"; " +
	guestSetLimits + " && . /rvm/env && exec sh -c \"$(cat /rvm/cmd)\" ) </dev/null\n"

// guestAppPid is the file in which the command's subshell records its pid,
// which is the pid of the command's top process.
const guestAppPid = "/rvm/app-pid"

// guestVolumeDevice is the guest block device of the volume image. The guest
// boots from the initramfs and has no other drive, so the image is the first
// virtio-blk device.
const guestVolumeDevice = "/dev/vda"

// Guest scratch files of the blank check. They live under /rvm, which no
// volume path may use, so that an app's container_dir can never collide with
// them.
const (
	guestVolumeHead = "/rvm/volume-head"
	guestVolumeUsed = "/rvm/volume-used"
)

// guestVolumeSetup formats and mounts the volume image. It formats only an
// image whose first 64 KiB the guest itself reads as all zero, which is a new
// image or one whose creator died before the first boot; the host never
// tells it an image is new. A read error is a setup failure, never a blank
// image. An image that is not blank and does not mount is never formatted:
// that is a setup failure for an operator to look at. busybox mke2fs makes
// ext2, which the kernel's ext4 driver mounts. The sync and dirsync options
// put every completed write on the image before the syscall returns,
// because the hypervisors stop at once on SIGTERM, without a guest shutdown.
const guestVolumeSetup = `. /rvm/mounts
n=0
while [ ! -b "$RVM_VOLUME_DEVICE" ]; do
	n=$((n + 1))
	[ "$n" -gt 5 ] && rvm_fail "no $RVM_VOLUME_DEVICE block device for the volume"
	sleep 1
done
mkdir -p "$RVM_VOLUME_PATH" || rvm_fail "creating $RVM_VOLUME_PATH failed"
dd if="$RVM_VOLUME_DEVICE" of=` + guestVolumeHead + ` bs=4096 count=16 || rvm_fail "reading the start of $RVM_VOLUME_DEVICE failed"
tr -d '\000' <` + guestVolumeHead + ` >` + guestVolumeUsed + ` || rvm_fail "checking whether $RVM_VOLUME_DEVICE is blank failed"
rvm_blank=
[ -s ` + guestVolumeHead + ` ] && [ ! -s ` + guestVolumeUsed + ` ] && rvm_blank=1
rm -f ` + guestVolumeHead + ` ` + guestVolumeUsed + `
if [ -n "$rvm_blank" ]; then
	mke2fs -F -m 0 -L rvm-volume "$RVM_VOLUME_DEVICE" || rvm_fail "formatting the blank volume image $RVM_VOLUME_IMAGE failed"
	mount -t ext4 -o sync,dirsync,noatime,errors=remount-ro "$RVM_VOLUME_DEVICE" "$RVM_VOLUME_PATH" || rvm_fail "mounting the newly formatted volume image $RVM_VOLUME_IMAGE at $RVM_VOLUME_PATH failed"
else
	mount -t ext4 -o sync,dirsync,noatime,errors=remount-ro "$RVM_VOLUME_DEVICE" "$RVM_VOLUME_PATH" || rvm_fail "mounting the volume image $RVM_VOLUME_IMAGE at $RVM_VOLUME_PATH failed; it is not blank, so vm-launch will not format it; inspect or delete $RVM_VOLUME_IMAGE on the volume"
fi
`

// guestVolumeTeardown follows the command, once its status is kept in
// rvm_status: it flushes and unmounts the volume. A failed unmount loses
// nothing, because the mount is synchronous and sync has run, so it is
// reported and the status stays the command's.
const guestVolumeTeardown = `sync
umount "$RVM_VOLUME_PATH" 2>/dev/null || echo "vm-launch guest: unmounting $RVM_VOLUME_PATH failed; data was already synced"
`

// mountsFile returns the guest /rvm/mounts, which /init sources before it
// mounts the volume.
func mountsFile(v *guestVolume) string {
	return "RVM_VOLUME_DEVICE=" + guestVolumeDevice + "\n" +
		"RVM_VOLUME_PATH=" + shellQuote(v.ContainerDir) + "\n" +
		"RVM_VOLUME_IMAGE=" + shellQuote(v.ImageName) + "\n"
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
	// nonce makes the console markers of /init (see startTag).
	nonce string
	// nw is the guest network, which run always builds.
	nw *network
	// env is the guest environment, /rvm/env (see buildGuestEnv).
	env string
	// vol is the guest volume, or nil without one.
	vol *guestVolume
	// caBundle is the guest's CA bundle (see guestCABundle), or nil when
	// there is no certificate to trust.
	caBundle []byte
	// nofile is the command's open-files limit (see guestNofile), /rvm/limits.
	nofile nofileLimit
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
// /rvm/limits, and the /init that runs it. With a volume it also holds
// /rvm/mounts, and with a CA bundle it holds that at
// /etc/ssl/certs/ca-certificates.crt. A hard open-files limit of 0 is an
// error, because it is a limit no caller can have meant: vm-launch itself
// could not run under it.
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

	init := initScript(g.nonce, g.vol != nil)
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
	if g.nw != nil && g.nw.port > 0 {
		steps = append(steps, func() error { return cw.FIFO(strings.TrimPrefix(guestListenTick, "/"), 0o600) })
	}
	if g.vol != nil {
		steps = append(steps, file("rvm/mounts", 0o644, mountsFile(g.vol)))
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
		func() error { return cw.File("init", 0o755, int64(len(init)), strings.NewReader(init)) },
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
