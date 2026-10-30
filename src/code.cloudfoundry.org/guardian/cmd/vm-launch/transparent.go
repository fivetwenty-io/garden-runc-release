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
// that capability, in its ambient set, and routes the guest's replies to such
// sockets back to them instead of out of eth0. The hypervisor must never hold
// the capability, so vm-launch starts it from an OS thread whose credentials
// have lost it (see confineHypervisor and startConfined).

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

// transparentError is a socket that could not be made transparent. The dial
// that hits it is not retried, and the connection is closed rather than
// dialled from the tap address, which would show the guest the wrong peer.
type transparentError struct{ err error }

func (e *transparentError) Error() string {
	return "making the socket to the guest transparent, which takes CAP_NET_RAW: " + e.err.Error()
}

func (e *transparentError) Unwrap() error { return e.err }

// setTransparent sets IP_TRANSPARENT on the socket of a dial. A dialer runs
// it after creating the socket and before binding it to the client's
// address, which the kernel refuses for a non-local address without the
// option.
func setTransparent(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	}); err != nil {
		return &transparentError{err}
	}
	if serr != nil {
		return &transparentError{os.NewSyscallError("setsockopt IP_TRANSPARENT", serr)}
	}
	return nil
}

// checkTransparentDial makes sure, before the guest boots, that vm-launch can
// make a socket transparent, so that a missing grant fails the launch rather
// than every connection to the guest. Specs replace it to make it fail.
var checkTransparentDial = func() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("creating a socket to check the transparent port proxy: %w", os.NewSyscallError("socket", err))
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		return &transparentError{os.NewSyscallError("setsockopt IP_TRANSPARENT", err)}
	}
	return nil
}

// transparentCheckMessage is the line vm-launch exits with when
// checkTransparentDial fails.
func transparentCheckMessage(err error) string {
	return fmt.Sprintf("the transparent port proxy cannot run: %v; Garden grants CAP_NET_RAW to the vm-launch it wraps in a vm-firecracker container, and a vm-launch run another way must not be given --transparent-proxy", err)
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
	ambientRaised(c uint) (bool, error)
	inBounding(c uint) (bool, error)
	dropBounding(c uint) error
	// fileCaps reports whether the file at path carries file capabilities.
	fileCaps(path string) (bool, error)
	isRoot() bool
}

// confineHypervisor takes CAP_NET_RAW away from the calling OS thread, as far
// as a process it starts could inherit it, and refuses a hypervisor binary
// that could get it back. vm-launch holds the capability in its ambient,
// inheritable, permitted, and effective sets, and an exec keeps the ambient
// set and gives the inheritable set to a binary that has file capabilities.
// So the thread clears its ambient set and drops CAP_NET_RAW from its other
// three sets. It also drops the capability from its bounding set when it can
// raise CAP_SETPCAP, as root can: an exec as root gets the whole bounding
// set, so for root a bounding set that still holds CAP_NET_RAW is an error.
// A non-root hypervisor without file capabilities gets nothing from its
// bounding set, and with no_new_privs, which Garden sets, it could get no
// more than the thread's permitted set anyway; vm-launch run without it is
// covered by refusing a binary with file capabilities. Each change is read
// back, and any failure is an error, so the hypervisor never starts holding
// the capability.
func confineHypervisor(ops capOps, path string) error {
	netRaw, setpcap := uint(unix.CAP_NET_RAW), uint(unix.CAP_SETPCAP)

	if err := ops.clearAmbient(); err != nil && !errors.Is(err, unix.EINVAL) {
		// EINVAL is a kernel without ambient capabilities, which leaves
		// nothing to clear.
		return fmt.Errorf("clearing the ambient capabilities: %w", err)
	}

	bounded, err := ops.inBounding(netRaw)
	if err != nil {
		return fmt.Errorf("reading the bounding set: %w", err)
	}
	if bounded {
		sets, err := ops.get()
		if err != nil {
			return fmt.Errorf("reading the capabilities: %w", err)
		}
		if sets.permitted&capBit(setpcap) != 0 {
			if sets.effective&capBit(setpcap) == 0 {
				sets.effective |= capBit(setpcap)
				if err := ops.set(sets); err != nil {
					return fmt.Errorf("raising CAP_SETPCAP to drop CAP_NET_RAW from the bounding set: %w", err)
				}
			}
			if err := ops.dropBounding(netRaw); err != nil {
				return fmt.Errorf("dropping CAP_NET_RAW from the bounding set: %w", err)
			}
		}
	}

	sets, err := ops.get()
	if err != nil {
		return fmt.Errorf("reading the capabilities: %w", err)
	}
	if (sets.effective|sets.permitted|sets.inheritable)&capBit(netRaw) != 0 {
		sets.effective &^= capBit(netRaw)
		sets.permitted &^= capBit(netRaw)
		sets.inheritable &^= capBit(netRaw)
		if err := ops.set(sets); err != nil {
			return fmt.Errorf("dropping CAP_NET_RAW: %w", err)
		}
	}

	after, err := ops.get()
	if err != nil {
		return fmt.Errorf("reading the capabilities back: %w", err)
	}
	if (after.effective|after.permitted|after.inheritable)&capBit(netRaw) != 0 {
		return errors.New("CAP_NET_RAW is still in the effective, permitted, or inheritable set")
	}
	ambient, err := ops.ambientRaised(netRaw)
	if err != nil && !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("reading the ambient set back: %w", err)
	}
	if err == nil && ambient {
		return errors.New("CAP_NET_RAW is still in the ambient set")
	}
	if ops.isRoot() {
		still, err := ops.inBounding(netRaw)
		if err != nil {
			return fmt.Errorf("reading the bounding set back: %w", err)
		}
		if still {
			return errors.New("vm-launch runs as root without CAP_SETPCAP, so CAP_NET_RAW stays in the bounding set, which a root hypervisor gets")
		}
	}

	hasFileCaps, err := ops.fileCaps(path)
	if err != nil {
		return fmt.Errorf("reading the file capabilities of %s: %w", path, err)
	}
	if hasFileCaps {
		return fmt.Errorf("%s has file capabilities, which could give the hypervisor CAP_NET_RAW", path)
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

func (threadCaps) ambientRaised(c uint) (bool, error) {
	r, err := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, uintptr(c), 0, 0)
	if err != nil {
		return false, os.NewSyscallError("prctl PR_CAP_AMBIENT_IS_SET", err)
	}
	return r == 1, nil
}

func (threadCaps) inBounding(c uint) (bool, error) {
	r, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0)
	if err != nil {
		return false, os.NewSyscallError("prctl PR_CAPBSET_READ", err)
	}
	return r == 1, nil
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
