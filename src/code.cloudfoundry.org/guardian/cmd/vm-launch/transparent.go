//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// The transparent port proxy. A Firecracker guest is reached through
// vm-launch's port proxy, which accepts each connection in the container and
// opens another to the guest. Dialled from the container's tap address, that
// second connection would show the guest 169.254.100.1 as the peer of every
// connection, where a runc app sees its real client. With --transparent-proxy,
// which Garden passes to the vm-launch it wraps in a vm-firecracker container,
// the proxy binds each upstream socket to its client's address first, which
// IP_TRANSPARENT allows and which takes CAP_NET_RAW. Garden grants vm-launch
// that capability, in its ambient set, when the process has PORT, and routes
// the guest's replies to such sockets back to them instead of out of eth0.
// The hypervisor must never hold the capability, or any other, so vm-launch
// starts every Firecracker from an OS thread whose credentials have lost them
// all (see confineHypervisor and startConfined), with or without
// --transparent-proxy. vm-launch is also not dumpable (see markUndumpable),
// because a process of the same user without capabilities could otherwise
// write its memory through that one thread, whose credentials no longer hold
// more than its own.

// fcLink is the guest link: the guest's address, the container's tap
// address, and the two around them.
var fcLink = mustParseCIDR(fcGuestCIDR)

func mustParseCIDR(cidr string) *net.IPNet {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("parsing %q: %v", cidr, err))
	}
	return n
}

// transparentSource returns the address the transparent proxy dials the guest
// from for a client at remote: the client's IPv4 address, with port 0 so that
// the kernel picks the port. It returns nil, for a dial from the tap address,
// for a client that is not TCP over IPv4, and for one whose address a socket
// bound to it could not reach the guest from, or that would mean nothing to
// the guest: a loopback address, which the kernel never routes out of a
// device; the unspecified, a multicast, or the broadcast address; and an
// address on the guest link itself. A container IP client, such as Envoy or a
// health check dialling the container's own address, is kept, so the guest
// sees the container IP as a runc app would.
func transparentSource(remote net.Addr) *net.TCPAddr {
	tcp, ok := remote.(*net.TCPAddr)
	if !ok || tcp == nil {
		return nil
	}
	ip := tcp.IP.To4()
	switch {
	case ip == nil,
		ip.IsLoopback(),
		ip.IsUnspecified(),
		ip.IsMulticast(),
		ip.Equal(net.IPv4bcast),
		fcLink.Contains(ip):
		return nil
	}
	return &net.TCPAddr{IP: ip}
}

// transparentError is a socket that could not be prepared for a transparent
// dial. The dial that hits it is not retried, because the same option would
// fail again, and the connection is closed rather than dialled from the tap
// address, which would show the guest the wrong peer.
type transparentError struct {
	// noPort marks IP_BIND_ADDRESS_NO_PORT, which needs no capability.
	noPort bool
	err    error
}

func (e *transparentError) Error() string {
	if e.noPort {
		return "leaving the port of the socket to the guest to connect: " + e.err.Error()
	}
	return "making the socket to the guest transparent, which takes CAP_NET_RAW: " + e.err.Error()
}

func (e *transparentError) Unwrap() error { return e.err }

// prepareTransparent sets IP_TRANSPARENT on fd, which lets it bind a client's
// address that is not the container's, and IP_BIND_ADDRESS_NO_PORT, which
// makes a bind to port 0 leave the port to connect. connect then picks a port
// that is free for the whole four-tuple, so a client address is not limited to
// one upstream connection per local port, across every guest port and the
// container's own connections from the same address, and a socket in
// TIME_WAIT holds only its own four-tuple.
func prepareTransparent(fd int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		return &transparentError{err: os.NewSyscallError("setsockopt IP_TRANSPARENT", err)}
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_BIND_ADDRESS_NO_PORT, 1); err != nil {
		return &transparentError{noPort: true, err: os.NewSyscallError("setsockopt IP_BIND_ADDRESS_NO_PORT", err)}
	}
	return nil
}

// setTransparent prepares the socket of a dial with prepareTransparent. A
// dialer runs it after creating the socket and before binding it to the
// client's address, which the kernel refuses for a non-local address without
// IP_TRANSPARENT.
func setTransparent(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = prepareTransparent(int(fd))
	}); err != nil {
		return &transparentError{err: err}
	}
	return serr
}

// checkTransparentDial makes sure, before the guest boots, that vm-launch can
// prepare a socket for a transparent dial, so that a missing grant fails the
// launch rather than every connection to the guest. Specs replace it to make
// it fail.
var checkTransparentDial = func() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("creating a socket to check the transparent port proxy: %w", os.NewSyscallError("socket", err))
	}
	defer unix.Close(fd)
	return prepareTransparent(fd)
}

// transparentCheckMessage is the line vm-launch exits with when
// checkTransparentDial fails.
func transparentCheckMessage(err error) string {
	return fmt.Sprintf("the transparent port proxy cannot run: %v; Garden grants CAP_NET_RAW to the vm-launch it wraps in a vm-firecracker container when the process has PORT, and a vm-launch run another way must not be given --transparent-proxy", err)
}

// capSets are a thread's effective, permitted, and inheritable capabilities,
// one bit per capability number.
type capSets struct {
	effective, permitted, inheritable uint64
}

func capBit(c uint) uint64 { return 1 << c }

// capOps reads and changes the capabilities of the calling OS thread. Specs
// replace threadCaps, the real one, with a fake.
type capOps interface {
	get() (capSets, error)
	set(capSets) error
	clearAmbient() error
	// ambient returns the ambient set, one bit per capability. EINVAL means
	// a kernel without ambient capabilities.
	ambient() (uint64, error)
	// bounding returns the bounding set, one bit per capability.
	bounding() (uint64, error)
	dropBounding(c uint) error
	// fileCaps reports whether the file at path carries file capabilities.
	fileCaps(path string) (bool, error)
	isRoot() bool
}

// confineHypervisor takes every capability away from the calling OS thread,
// as far as a process it starts could inherit one, and refuses a hypervisor
// binary that could gain one. Firecracker needs no capability: it reaches
// /dev/kvm and tap0 through the kvm group, and every file it opens belongs to
// vm-launch's user or is readable by it. vm-launch may hold CAP_NET_RAW, which
// Garden grants for the transparent port proxy, in its ambient, inheritable,
// permitted, and effective sets, and as root it holds the container's
// capabilities. An exec keeps the ambient set, gives the inheritable set to a
// binary that has file capabilities, and gives root the bounding set. So the
// thread clears its ambient set and empties its effective, permitted, and
// inheritable sets. When it can raise CAP_SETPCAP, as root can, it first
// empties its bounding set too, and for root a bounding set that keeps any
// capability is an error. A non-root hypervisor without file capabilities
// gets nothing from its bounding set, and with no_new_privs, which Garden
// sets, it could get no more than the thread's permitted set anyway; a
// vm-launch run without no_new_privs is covered by refusing a binary with
// file capabilities. The app user's bounding set therefore keeps the
// container's capabilities, which nothing the hypervisor runs can use. Each
// change is read back, and any failure is an error, so the hypervisor never
// starts holding a capability.
func confineHypervisor(ops capOps, path string) error {
	setpcap := capBit(unix.CAP_SETPCAP)

	if err := ops.clearAmbient(); err != nil && !errors.Is(err, unix.EINVAL) {
		// EINVAL is a kernel without ambient capabilities, which leaves
		// nothing to clear.
		return fmt.Errorf("clearing the ambient capabilities: %w", err)
	}

	bounding, err := ops.bounding()
	if err != nil {
		return fmt.Errorf("reading the bounding set: %w", err)
	}
	if bounding != 0 {
		sets, err := ops.get()
		if err != nil {
			return fmt.Errorf("reading the capabilities: %w", err)
		}
		if sets.permitted&setpcap != 0 {
			if sets.effective&setpcap == 0 {
				sets.effective |= setpcap
				if err := ops.set(sets); err != nil {
					return fmt.Errorf("raising CAP_SETPCAP to empty the bounding set: %w", err)
				}
			}
			for c := uint(0); c < 64; c++ {
				if bounding&capBit(c) == 0 {
					continue
				}
				if err := ops.dropBounding(c); err != nil {
					return fmt.Errorf("dropping capability %d from the bounding set: %w", c, err)
				}
			}
		}
	}

	sets, err := ops.get()
	if err != nil {
		return fmt.Errorf("reading the capabilities: %w", err)
	}
	if sets != (capSets{}) {
		if err := ops.set(capSets{}); err != nil {
			return fmt.Errorf("dropping the capabilities: %w", err)
		}
	}

	after, err := ops.get()
	if err != nil {
		return fmt.Errorf("reading the capabilities back: %w", err)
	}
	if after != (capSets{}) {
		return fmt.Errorf("capabilities are still in the effective (%#x), permitted (%#x), or inheritable (%#x) set", after.effective, after.permitted, after.inheritable)
	}
	ambient, err := ops.ambient()
	if err != nil && !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("reading the ambient set back: %w", err)
	}
	if err == nil && ambient != 0 {
		return fmt.Errorf("capabilities are still in the ambient set (%#x)", ambient)
	}
	if ops.isRoot() {
		still, err := ops.bounding()
		if err != nil {
			return fmt.Errorf("reading the bounding set back: %w", err)
		}
		if still != 0 {
			return fmt.Errorf("vm-launch runs as root without CAP_SETPCAP, so its bounding set keeps capabilities (%#x), which a root hypervisor gets", still)
		}
	}

	hasFileCaps, err := ops.fileCaps(path)
	if err != nil {
		return fmt.Errorf("reading the file capabilities of %s: %w", path, err)
	}
	if hasFileCaps {
		return fmt.Errorf("%s has file capabilities, which could give the hypervisor capabilities", path)
	}
	return nil
}

// threadCaps is capOps for the calling OS thread. Capabilities belong to a
// thread, so the caller must hold its goroutine to its thread.
type threadCaps struct{}

func (threadCaps) get() (capSets, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return capSets{}, os.NewSyscallError("capget", err)
	}
	join := func(lo, hi uint32) uint64 { return uint64(lo) | uint64(hi)<<32 }
	return capSets{
		effective:   join(data[0].Effective, data[1].Effective),
		permitted:   join(data[0].Permitted, data[1].Permitted),
		inheritable: join(data[0].Inheritable, data[1].Inheritable),
	}, nil
}

func (threadCaps) set(s capSets) error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{
		{Effective: uint32(s.effective), Permitted: uint32(s.permitted), Inheritable: uint32(s.inheritable)},
		{Effective: uint32(s.effective >> 32), Permitted: uint32(s.permitted >> 32), Inheritable: uint32(s.inheritable >> 32)},
	}
	return os.NewSyscallError("capset", unix.Capset(&hdr, &data[0]))
}

func (threadCaps) clearAmbient() error {
	return os.NewSyscallError("prctl PR_CAP_AMBIENT_CLEAR_ALL", unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))
}

// ambient reads the ambient set of the calling thread.
func (threadCaps) ambient() (uint64, error) {
	return capBits(func(c uint) (bool, error) {
		r, err := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, uintptr(c), 0, 0)
		if err != nil {
			return false, os.NewSyscallError("prctl PR_CAP_AMBIENT_IS_SET", err)
		}
		return r == 1, nil
	})
}

// bounding reads the bounding set of the calling thread.
func (threadCaps) bounding() (uint64, error) {
	return capBits(func(c uint) (bool, error) {
		r, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0)
		if err != nil {
			return false, os.NewSyscallError("prctl PR_CAPBSET_READ", err)
		}
		return r == 1, nil
	})
}

// capBits reads one capability set, one bit per capability, with read, from
// capability 0 up to the first that the kernel does not know, for which read
// fails with EINVAL. EINVAL for capability 0 is an error: the kernel does not
// have the set at all.
func capBits(read func(c uint) (bool, error)) (uint64, error) {
	var bits uint64
	for c := uint(0); c < 64; c++ {
		set, err := read(c)
		if c > 0 && errors.Is(err, unix.EINVAL) {
			return bits, nil
		}
		if err != nil {
			return 0, err
		}
		if set {
			bits |= capBit(c)
		}
	}
	return bits, nil
}

func (threadCaps) dropBounding(c uint) error {
	return os.NewSyscallError("prctl PR_CAPBSET_DROP", unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0))
}

// fileCaps reads the security.capability attribute of path, following
// symbolic links as exec does. A file without it, or a filesystem without
// extended attributes, has no file capabilities.
func (threadCaps) fileCaps(path string) (bool, error) {
	_, err := unix.Getxattr(path, "security.capability", nil)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.ENOTSUP):
		return false, nil
	default:
		return false, os.NewSyscallError("getxattr security.capability", err)
	}
}

func (threadCaps) isRoot() bool { return unix.Geteuid() == 0 }

// hypervisorCaps is the capOps that vm-launch confines the hypervisor's
// thread with. Specs replace it with a fake.
var hypervisorCaps capOps = threadCaps{}

// confinedPrepare returns the step that runs on the hypervisor's thread
// before cmd starts: confineHypervisor for cmd's binary.
func confinedPrepare(cmd *exec.Cmd) func() error {
	return func() error { return confineHypervisor(hypervisorCaps, cmd.Path) }
}

// startConfined starts cmd from an OS thread of its own, on which prepare runs
// first, and returns release, which the caller must run once cmd has been
// reaped. The goroutine holds its thread from start to end and ends without
// releasing it, so the runtime ends the thread with it, and no other
// goroutine ever runs with the credentials prepare changed. While the
// goroutine runs, other threads keep their own credentials: the runtime
// starts every new thread from its template thread while a goroutine holds
// one. The thread waits for release because the hypervisor's parent death
// signal follows the thread that started it, and the hypervisor must get
// it only when vm-launch dies. release is safe to run more than once. When
// prepare or the start fails, the thread ends at once and release is nil.
func startConfined(cmd *exec.Cmd, prepare func() error) (release func(), err error) {
	started := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		err := prepare()
		if err != nil {
			err = fmt.Errorf("confining the hypervisor's capabilities: %w", err)
		} else {
			err = cmd.Start()
		}
		started <- err
		if err != nil {
			return
		}
		<-done
	}()
	if err := <-started; err != nil {
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }, nil
}
