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
// A networked guest first brings up lo and eth0 from /rvm/net and exports
// /rvm/env. When that fails, /init reboots before the start tag, so
// vm-launch reports a guest that never started its command and shows the
// console output, which ends with the failed step.
func initScript(nonce string, networked bool) string {
	setup := ""
	if networked {
		setup = guestNetworkSetup
	}
	return `#!/bin/busybox sh
/bin/busybox --install -s /bin
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
` + setup + `echo ` + startTag(nonce) + `
sh /rvm/cmd </dev/null
echo ` + exitTag(nonce) + `$?
reboot -f
`
}

// guestNetworkSetup configures the guest NIC. The virtio-net driver is built
// into the kernel and normally has eth0 ready before /init runs; the wait
// covers a late probe.
const guestNetworkSetup = `rvm_fail() { echo "vm-launch guest setup: $1"; reboot -f; exit 1; }
. /rvm/net
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

// writeInitramfs writes a gzip-compressed newc initramfs to dst holding a
// static busybox, the console and null device nodes, the command script at
// /rvm/cmd, and the /init that runs it. With a network it also holds
// /rvm/net, /rvm/env, and /etc/resolv.conf.
func writeInitramfs(dst, busyboxPath, command, nonce string, nw *network) error {
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

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("creating initramfs: %w", err)
	}
	if err := writeInitramfsArchive(out, busybox, info.Size(), command, nonce, nw); err != nil {
		out.Close()
		return fmt.Errorf("writing initramfs %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("closing initramfs %s: %w", dst, err)
	}
	return nil
}

func writeInitramfsArchive(w io.Writer, busybox io.Reader, busyboxSize int64, command, nonce string, nw *network) error {
	buf := bufio.NewWriter(w)
	gz := gzip.NewWriter(buf)
	cw := newCPIOWriter(gz)
	file := func(name, content string) func() error {
		return func() error { return cw.File(name, 0o644, int64(len(content)), strings.NewReader(content)) }
	}

	init := initScript(nonce, nw != nil)
	steps := []func() error{
		func() error { return cw.Dir("bin", 0o755) },
		func() error { return cw.Dir("dev", 0o755) },
		func() error { return cw.CharDevice("dev/console", 0o600, 5, 1) },
		func() error { return cw.CharDevice("dev/null", 0o666, 1, 3) },
	}
	if nw != nil {
		steps = append(steps, func() error { return cw.Dir("etc", 0o755) })
	}
	steps = append(steps,
		func() error { return cw.Dir("proc", 0o555) },
		func() error { return cw.Dir("sys", 0o555) },
		func() error { return cw.Dir("tmp", 0o1777) },
		func() error { return cw.Dir("rvm", 0o755) },
		func() error { return cw.File("bin/busybox", 0o755, busyboxSize, busybox) },
		file("rvm/cmd", command),
	)
	if nw != nil {
		steps = append(steps, file("rvm/net", netFile(nw)), file("rvm/env", nw.env), file("etc/resolv.conf", nw.resolvConf))
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
