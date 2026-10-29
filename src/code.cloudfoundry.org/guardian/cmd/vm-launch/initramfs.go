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
// impossible to forge by accident from guest command output.
func startTag(nonce string) string { return "RVM_START_" + nonce }
func exitTag(nonce string) string  { return "RVM_EXIT_" + nonce + "=" }

// initScript is the guest /init. It runs the command with stdin from
// /dev/null (the serial console never delivers EOF), reports its status on
// the console, and reboots: with -no-reboot (QEMU) or reboot=k (Firecracker)
// that ends the hypervisor. poweroff -f hangs Firecracker, so it is not used.
//
// Right after the mounts, /init defines rvm_fail, which every setup step
// uses. It then brings up lo and eth0 from /rvm/net and exports /rvm/env,
// for every guest, a task's included. A guest with a volume then formats the
// volume image when it is blank and mounts it, and after the command it
// syncs and unmounts it before it reports the status. When a setup step
// fails, /init reboots before the start tag, so vm-launch reports a guest
// that never started its command and shows the console output, which ends
// with the failed step.
func initScript(nonce string, volume bool) string {
	setup := guestFailFunc + guestNetworkSetup
	if volume {
		setup += guestVolumeSetup
	}
	run := "sh /rvm/cmd </dev/null\necho " + exitTag(nonce) + "$?\n"
	if volume {
		run = "sh /rvm/cmd </dev/null\n" + guestVolumeTeardown + "echo " + exitTag(nonce) + "$rvm_status\n"
	}
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
. /rvm/env
`

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

// guestVolumeTeardown follows the command: it keeps the command's status,
// flushes, and unmounts the volume. A failed unmount loses nothing, because
// the mount is synchronous and sync has run, so it is reported and the
// status stays the command's.
const guestVolumeTeardown = `rvm_status=$?
sync
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

// newInitramfs builds the guest initramfs (see writeInitramfs) in a sealed
// memfd and returns it, so the archive never touches a disk. Its memory is
// charged to the container and lasts while any process holds a descriptor
// for it. The descriptor is close-on-exec: vm-launch passes it to the
// hypervisor as an extra file, which the hypervisor opens through
// /proc/self/fd, and closes its own copy once the hypervisor has started.
func newInitramfs(busyboxPath, command, nonce string, nw *network, vol *guestVolume) (*os.File, error) {
	fd, err := createInitramfsMemfd()
	if err != nil {
		return nil, fmt.Errorf("creating the initramfs memfd: %w", err)
	}
	f := os.NewFile(uintptr(fd), "memfd:"+initramfsName)
	if err := writeInitramfs(f, busyboxPath, command, nonce, nw, vol); err != nil {
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
// /rvm/cmd, the guest network's /rvm/net, /rvm/env, and /etc/resolv.conf,
// and the /init that runs it. With a volume it also holds /rvm/mounts. nw
// is the guest network, which run always builds.
func writeInitramfs(dst *os.File, busyboxPath, command, nonce string, nw *network, vol *guestVolume) error {
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

	if err := writeInitramfsArchive(dst, busybox, info.Size(), command, nonce, nw, vol); err != nil {
		return fmt.Errorf("writing the initramfs: %w", err)
	}
	return nil
}

func writeInitramfsArchive(w io.Writer, busybox io.Reader, busyboxSize int64, command, nonce string, nw *network, vol *guestVolume) error {
	buf := bufio.NewWriter(w)
	gz := gzip.NewWriter(buf)
	cw := newCPIOWriter(gz)
	file := func(name, content string) func() error {
		return func() error { return cw.File(name, 0o644, int64(len(content)), strings.NewReader(content)) }
	}

	init := initScript(nonce, vol != nil)
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
		file("rvm/cmd", command),
		file("rvm/net", netFile(nw)),
		file("rvm/env", nw.env),
		file("etc/resolv.conf", nw.resolvConf),
	}
	if vol != nil {
		steps = append(steps, file("rvm/mounts", mountsFile(vol)))
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
