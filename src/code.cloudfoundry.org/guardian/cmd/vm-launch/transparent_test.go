//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/netplugin"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// helperEchoPorts makes this test binary a stand-in for a guest app: it
// listens on each of the comma-separated ports on every address, prints
// "ready", and answers each connection with the IP address of its peer.
const helperEchoPorts = "VM_LAUNCH_TEST_ECHO_PORTS"

// helperTransparentRun makes this test binary run vm-launch for
// vm-firecracker with the artifacts directory it names, the CF launcher argv,
// and --transparent-proxy when helperTransparentFlag is set.
const (
	helperTransparentRun  = "VM_LAUNCH_TEST_TRANSPARENT_RUN"
	helperTransparentFlag = "VM_LAUNCH_TEST_TRANSPARENT_FLAG"
)

// echoPeers is the helperEchoPorts process.
func echoPeers(ports string) int {
	for _, p := range strings.Split(ports, ",") {
		l, err := net.Listen("tcp4", "0.0.0.0:"+p)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				fmt.Fprintln(c, c.RemoteAddr().(*net.TCPAddr).IP.String())
				c.Close()
			}
		}()
	}
	fmt.Println("ready")
	select {}
}

const capNetRawBit = uint64(1) << unix.CAP_NET_RAW

// fakeCaps is a capOps that keeps the sets in memory and records the calls.
// Like the kernel, it refuses to drop from the bounding set without
// CAP_SETPCAP in the effective set. Each ignore field makes the matching
// change look successful without happening, and errs fails the named call.
type fakeCaps struct {
	sets        capSets
	ambient     uint64
	bounding    uint64
	root        bool
	hasFileCaps bool

	ignoreSet, ignoreClear, ignoreDrop bool
	errs                               map[string]error
	calls                              []string
}

func (f *fakeCaps) call(name string) error {
	f.calls = append(f.calls, name)
	return f.errs[name]
}

func (f *fakeCaps) get() (capSets, error) {
	if err := f.call("get"); err != nil {
		return capSets{}, err
	}
	return f.sets, nil
}

func (f *fakeCaps) set(s capSets) error {
	if err := f.call("set"); err != nil {
		return err
	}
	if !f.ignoreSet {
		f.sets = s
		// Lowering the permitted or inheritable set lowers the ambient one.
		f.ambient &= s.permitted & s.inheritable
	}
	return nil
}

func (f *fakeCaps) clearAmbient() error {
	if err := f.call("clearAmbient"); err != nil {
		return err
	}
	if !f.ignoreClear {
		f.ambient = 0
	}
	return nil
}

func (f *fakeCaps) ambientRaised(c uint) (bool, error) {
	if err := f.call("ambientRaised"); err != nil {
		return false, err
	}
	return f.ambient&capBit(c) != 0, nil
}

func (f *fakeCaps) inBounding(c uint) (bool, error) {
	if err := f.call("inBounding"); err != nil {
		return false, err
	}
	return f.bounding&capBit(c) != 0, nil
}

func (f *fakeCaps) dropBounding(c uint) error {
	if err := f.call("dropBounding"); err != nil {
		return err
	}
	if f.sets.effective&capBit(unix.CAP_SETPCAP) == 0 {
		return unix.EPERM
	}
	if !f.ignoreDrop {
		f.bounding &^= capBit(c)
	}
	return nil
}

func (f *fakeCaps) fileCaps(path string) (bool, error) {
	if err := f.call("fileCaps " + path); err != nil {
		return false, err
	}
	return f.hasFileCaps, nil
}

func (f *fakeCaps) isRoot() bool { return f.root }

func bits(caps ...int) uint64 {
	var b uint64
	for _, c := range caps {
		b |= uint64(1) << c
	}
	return b
}

// statusCaps reads the Cap* lines of a /proc status file into numbers.
func statusCaps(status string) map[string]uint64 {
	caps := map[string]uint64{}
	for _, line := range strings.Split(status, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.HasPrefix(name, "Cap") {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		Expect(err).NotTo(HaveOccurred(), line)
		caps[name] = v
	}
	return caps
}

// effectiveCap reports whether the calling thread holds capability c.
func effectiveCap(c uint) bool {
	sets, err := threadCaps{}.get()
	Expect(err).NotTo(HaveOccurred())
	return sets.effective&capBit(c) != 0
}

var _ = Describe("transparentSource", func() {
	DescribeTable("the address a client is dialled from",
		func(remote net.Addr, want string) {
			got := transparentSource(remote)
			if want == "" {
				Expect(got).To(BeNil())
				return
			}
			Expect(got).NotTo(BeNil())
			Expect(got.String()).To(Equal(want))
			Expect(got.IP).To(HaveLen(net.IPv4len))
		},
		Entry("a gorouter", &net.TCPAddr{IP: net.ParseIP("10.0.1.7"), Port: 51234}, "10.0.1.7:0"),
		Entry("a v4-mapped client", &net.TCPAddr{IP: net.ParseIP("::ffff:10.0.1.7"), Port: 1}, "10.0.1.7:0"),
		Entry("a four-byte client", &net.TCPAddr{IP: net.IPv4(192, 168, 3, 4).To4(), Port: 1}, "192.168.3.4:0"),
		Entry("the silk gateway's link-local address", &net.TCPAddr{IP: net.ParseIP("169.254.0.1"), Port: 1}, "169.254.0.1:0"),
		Entry("an address next to the guest link", &net.TCPAddr{IP: net.ParseIP("169.254.100.4"), Port: 1}, "169.254.100.4:0"),
		Entry("loopback", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}, ""),
		Entry("other loopback", &net.TCPAddr{IP: net.ParseIP("127.3.2.1"), Port: 1}, ""),
		Entry("the guest link's network", &net.TCPAddr{IP: net.ParseIP("169.254.100.0"), Port: 1}, ""),
		Entry("the tap address", &net.TCPAddr{IP: net.ParseIP(fcHostIP), Port: 1}, ""),
		Entry("the guest", &net.TCPAddr{IP: net.ParseIP(fcGuestIP), Port: 1}, ""),
		Entry("the guest link's broadcast", &net.TCPAddr{IP: net.ParseIP("169.254.100.3"), Port: 1}, ""),
		Entry("unspecified", &net.TCPAddr{IP: net.IPv4zero, Port: 1}, ""),
		Entry("multicast", &net.TCPAddr{IP: net.ParseIP("224.0.0.1"), Port: 1}, ""),
		Entry("broadcast", &net.TCPAddr{IP: net.IPv4bcast, Port: 1}, ""),
		Entry("IPv6", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}, ""),
		Entry("IPv6 loopback", &net.TCPAddr{IP: net.IPv6loopback, Port: 1}, ""),
		Entry("no IP", &net.TCPAddr{Port: 1}, ""),
		Entry("a nil TCP address", (*net.TCPAddr)(nil), ""),
		Entry("not TCP", &net.UDPAddr{IP: net.ParseIP("10.0.1.7"), Port: 1}, ""),
		Entry("nil", nil, ""),
	)

	It("covers the guest link Garden configures", func() {
		Expect(fcLink.String()).To(Equal("169.254.100.0/30"))
	})
})

var _ = Describe("the transparent dial", func() {
	var logBuf *safeBuffer

	BeforeEach(func() {
		logBuf = &safeBuffer{}
	})

	It("names the capability and keeps the cause", func() {
		err := error(&transparentError{os.NewSyscallError("setsockopt IP_TRANSPARENT", unix.EPERM)})
		Expect(err).To(MatchError("making the socket to the guest transparent, which takes CAP_NET_RAW: setsockopt IP_TRANSPARENT: operation not permitted"))
		Expect(errors.Is(err, unix.EPERM)).To(BeTrue())
	})

	It("does not retry a socket that cannot be made transparent", func() {
		upstream := listenLocal()
		p := newProxy(testDialPolicy, log.New(logBuf, "", 0), withTransparentDial())
		DeferCleanup(p.Close)
		calls := 0
		p.control = func(network, address string, c syscall.RawConn) error {
			calls++
			Expect(network).To(Equal("tcp4"))
			return &transparentError{unix.EPERM}
		}

		_, err := p.dialUpstream(upstream.Addr().String(), &net.TCPAddr{IP: net.ParseIP("10.9.8.7").To4()})
		var te *transparentError
		Expect(errors.As(err, &te)).To(BeTrue(), "%v", err)
		Expect(calls).To(Equal(1))
	})

	It("retries other dial errors of a transparent dial under the policy", func() {
		p := newProxy(dialPolicy{attemptTimeout: 200 * time.Millisecond, firstBackoff: 10 * time.Millisecond, maxBackoff: 10 * time.Millisecond, giveUp: 100 * time.Millisecond, unansweredGiveUp: 100 * time.Millisecond}, log.New(logBuf, "", 0), withTransparentDial())
		DeferCleanup(p.Close)
		calls := 0
		p.control = func(string, string, syscall.RawConn) error {
			calls++
			return nil
		}
		// Without IP_TRANSPARENT the kernel refuses to bind a non-local
		// address, which is an error the policy retries.
		_, err := p.dialUpstream(unusedAddr(), &net.TCPAddr{IP: net.ParseIP("10.9.8.7").To4()})
		Expect(err).To(HaveOccurred())
		Expect(calls).To(BeNumerically(">", 1))
	})

	It("dials a client without a transparent source plainly, without the socket hook", func() {
		upstream := listenLocal()
		serve(upstream, func(c *net.TCPConn) { fmt.Fprintln(c, c.RemoteAddr().(*net.TCPAddr).IP) })
		p := newProxy(testDialPolicy, log.New(logBuf, "", 0), withTransparentDial())
		DeferCleanup(p.Close)
		p.control = func(string, string, syscall.RawConn) error {
			defer GinkgoRecover()
			Fail("a loopback client must not get a transparent dial")
			return nil
		}
		Expect(p.Listen("127.0.0.1:0", upstream.Addr().String())).To(Succeed())

		c, err := net.Dial("tcp", p.Addr().String())
		Expect(err).NotTo(HaveOccurred())
		defer c.Close()
		line, err := bufio.NewReader(c).ReadString('\n')
		Expect(err).NotTo(HaveOccurred())
		Expect(line).To(Equal("127.0.0.1\n"))
	})

	It("sets IP_TRANSPARENT only with CAP_NET_RAW or CAP_NET_ADMIN", func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		privileged := effectiveCap(unix.CAP_NET_RAW) || effectiveCap(unix.CAP_NET_ADMIN)

		err := checkTransparentDial()
		if privileged {
			Expect(err).NotTo(HaveOccurred())
		} else {
			Expect(err).To(MatchError(ContainSubstring("setsockopt IP_TRANSPARENT: operation not permitted")))
			var te *transparentError
			Expect(errors.As(err, &te)).To(BeTrue())
		}

		var d net.Dialer
		d.Control = setTransparent
		l := listenLocal()
		c, err := d.Dial("tcp4", l.Addr().String())
		if privileged {
			Expect(err).NotTo(HaveOccurred())
			c.Close()
		} else {
			var te *transparentError
			Expect(errors.As(err, &te)).To(BeTrue(), "%v", err)
		}
	})

	// The proxy's upstream sees the client's own address: here a local,
	// non-loopback address of this host, which needs no reply routing.
	Context("with a client from a non-loopback address", func() {
		var clientIP net.IP

		BeforeEach(func() {
			addrs, err := net.InterfaceAddrs()
			Expect(err).NotTo(HaveOccurred())
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
					clientIP = n.IP.To4()
					break
				}
			}
			if clientIP == nil {
				Skip("this host has no non-loopback IPv4 address")
			}
		})

		peerThrough := func(p *tcpProxy) (string, error) {
			upstream := listenLocal()
			serve(upstream, func(c *net.TCPConn) { fmt.Fprintln(c, c.RemoteAddr().(*net.TCPAddr).IP) })
			Expect(p.Listen(net.JoinHostPort(clientIP.String(), "0"), upstream.Addr().String())).To(Succeed())
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: clientIP}}
			c, err := d.Dial("tcp4", p.Addr().String())
			Expect(err).NotTo(HaveOccurred())
			defer c.Close()
			return bufio.NewReader(c).ReadString('\n')
		}

		It("shows the upstream the client's address", func() {
			p := newProxy(testDialPolicy, log.New(logBuf, "", 0), withTransparentDial())
			DeferCleanup(p.Close)
			line, err := peerThrough(p)
			if checkTransparentDial() != nil {
				// Without the capability the connection closes instead
				// of reaching the upstream from another address.
				Expect(err).To(MatchError(io.EOF))
				Eventually(logBuf.String).Should(ContainSubstring("giving up on the guest"))
				Expect(logBuf.String()).To(ContainSubstring("which takes CAP_NET_RAW"))
				return
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(line).To(Equal(clientIP.String() + "\n"))
		})

		It("shows the upstream the proxy's own address without the option", func() {
			p := newProxy(testDialPolicy, log.New(logBuf, "", 0))
			DeferCleanup(p.Close)
			line, err := peerThrough(p)
			Expect(err).NotTo(HaveOccurred())
			Expect(line).To(Equal("127.0.0.1\n"))
		})
	})
})

var _ = Describe("confineHypervisor", func() {
	const hv = "/opt/garden-vm/artifacts/firecracker/firecracker"
	var (
		netRaw  = unix.CAP_NET_RAW
		setpcap = unix.CAP_SETPCAP
		chown   = unix.CAP_CHOWN
		kill    = unix.CAP_KILL
	)

	// gardenNonRoot is the wrapped vm-launch as the app user: CAP_NET_RAW
	// ambient, and so permitted and effective, beside the container's
	// inheritable and bounding sets.
	gardenNonRoot := func() *fakeCaps {
		return &fakeCaps{
			sets:     capSets{effective: bits(netRaw), permitted: bits(netRaw), inheritable: bits(chown, netRaw, kill)},
			ambient:  bits(netRaw),
			bounding: bits(chown, netRaw, kill, setpcap),
		}
	}
	// gardenRoot is the wrapped vm-launch as root, which holds the whole
	// bounding set, CAP_SETPCAP among it.
	gardenRoot := func() *fakeCaps {
		all := bits(chown, netRaw, kill, setpcap)
		return &fakeCaps{sets: capSets{effective: all, permitted: all, inheritable: bits(chown, netRaw, kill)}, ambient: bits(netRaw), bounding: all, root: true}
	}

	It("clears the ambient set and drops CAP_NET_RAW from the others for the app user", func() {
		f := gardenNonRoot()
		Expect(confineHypervisor(f, hv)).To(Succeed())
		Expect(f.ambient).To(BeZero())
		Expect(f.sets).To(Equal(capSets{effective: 0, permitted: 0, inheritable: bits(chown, kill)}))
		// The app user has no CAP_SETPCAP to drop it with, and a non-root
		// exec without file capabilities gets nothing from it.
		Expect(f.bounding).To(Equal(bits(chown, netRaw, kill, setpcap)))
		Expect(f.calls).NotTo(ContainElement("dropBounding"))
		Expect(f.calls).To(ContainElement("fileCaps " + hv))
		Expect(f.calls[0]).To(Equal("clearAmbient"))
	})

	It("also drops CAP_NET_RAW from the bounding set for root", func() {
		f := gardenRoot()
		Expect(confineHypervisor(f, hv)).To(Succeed())
		Expect(f.bounding).To(Equal(bits(chown, kill, setpcap)))
		Expect(f.sets).To(Equal(capSets{effective: bits(chown, kill, setpcap), permitted: bits(chown, kill, setpcap), inheritable: bits(chown, kill)}))
		Expect(f.ambient).To(BeZero())
	})

	It("raises CAP_SETPCAP from the permitted set to drop from the bounding set", func() {
		f := gardenRoot()
		f.sets.effective &^= bits(setpcap)
		Expect(confineHypervisor(f, hv)).To(Succeed())
		Expect(f.bounding).To(Equal(bits(chown, kill, setpcap)))
		Expect(f.sets.permitted & capNetRawBit).To(BeZero())
	})

	It("fails for root without CAP_SETPCAP, whose hypervisor would get the bounding set", func() {
		f := gardenRoot()
		f.sets.effective &^= bits(setpcap)
		f.sets.permitted &^= bits(setpcap)
		Expect(confineHypervisor(f, hv)).To(MatchError(ContainSubstring("runs as root without CAP_SETPCAP")))
		Expect(f.calls).NotTo(ContainElement("dropBounding"))
	})

	It("changes nothing for a process without CAP_NET_RAW", func() {
		f := &fakeCaps{sets: capSets{inheritable: bits(chown)}, bounding: bits(chown)}
		Expect(confineHypervisor(f, hv)).To(Succeed())
		Expect(f.calls).NotTo(ContainElement("set"))
		Expect(f.sets).To(Equal(capSets{inheritable: bits(chown)}))
	})

	It("tolerates a kernel without ambient capabilities", func() {
		f := gardenNonRoot()
		f.ambient = 0
		f.errs = map[string]error{"clearAmbient": unix.EINVAL, "ambientRaised": unix.EINVAL}
		Expect(confineHypervisor(f, hv)).To(Succeed())
		Expect(f.sets.inheritable & capNetRawBit).To(BeZero())
	})

	DescribeTable("fails rather than start a hypervisor that could hold CAP_NET_RAW",
		func(change func(*fakeCaps), msg string) {
			f := gardenNonRoot()
			change(f)
			Expect(confineHypervisor(f, hv)).To(MatchError(ContainSubstring(msg)))
		},
		Entry("clearing the ambient set fails", func(f *fakeCaps) { f.errs = map[string]error{"clearAmbient": unix.EPERM} }, "clearing the ambient capabilities: operation not permitted"),
		Entry("the ambient set stays", func(f *fakeCaps) { f.ignoreClear = true; f.ignoreSet = true }, "still in the effective, permitted, or inheritable set"),
		Entry("the ambient set alone stays", func(f *fakeCaps) {
			f.ignoreClear = true
			f.sets.permitted, f.sets.inheritable = 0, 0
			f.sets.effective = 0
		}, "CAP_NET_RAW is still in the ambient set"),
		Entry("the sets stay", func(f *fakeCaps) { f.ignoreSet = true }, "still in the effective, permitted, or inheritable set"),
		Entry("setting the sets fails", func(f *fakeCaps) { f.errs = map[string]error{"set": unix.EPERM} }, "dropping CAP_NET_RAW: operation not permitted"),
		Entry("reading the sets fails", func(f *fakeCaps) { f.errs = map[string]error{"get": unix.EFAULT} }, "reading the capabilities"),
		Entry("reading the bounding set fails", func(f *fakeCaps) { f.errs = map[string]error{"inBounding": unix.EINVAL} }, "reading the bounding set"),
		Entry("reading the ambient set back fails", func(f *fakeCaps) { f.errs = map[string]error{"ambientRaised": unix.EFAULT} }, "reading the ambient set back"),
		Entry("the binary has file capabilities", func(f *fakeCaps) { f.hasFileCaps = true }, hv+" has file capabilities"),
		Entry("reading the file capabilities fails", func(f *fakeCaps) { f.errs = map[string]error{"fileCaps " + hv: unix.EACCES} }, "reading the file capabilities of "+hv),
	)

	DescribeTable("fails for root when the bounding set keeps CAP_NET_RAW",
		func(change func(*fakeCaps), msg string) {
			f := gardenRoot()
			change(f)
			Expect(confineHypervisor(f, hv)).To(MatchError(ContainSubstring(msg)))
		},
		Entry("the drop fails", func(f *fakeCaps) { f.errs = map[string]error{"dropBounding": unix.EPERM} }, "dropping CAP_NET_RAW from the bounding set"),
		Entry("the drop does nothing", func(f *fakeCaps) { f.ignoreDrop = true }, "runs as root without CAP_SETPCAP"),
		Entry("raising CAP_SETPCAP fails", func(f *fakeCaps) {
			f.sets.effective &^= bits(setpcap)
			f.errs = map[string]error{"set": unix.EPERM}
		}, "raising CAP_SETPCAP"),
	)
})

var _ = Describe("threadCaps", func() {
	It("reads and writes the calling thread's sets", func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		sets, err := threadCaps{}.get()
		Expect(err).NotTo(HaveOccurred())
		Expect(threadCaps{}.set(sets)).To(Succeed())

		status, err := os.ReadFile("/proc/thread-self/status")
		Expect(err).NotTo(HaveOccurred())
		caps := statusCaps(string(status))
		Expect(sets).To(Equal(capSets{effective: caps["CapEff"], permitted: caps["CapPrm"], inheritable: caps["CapInh"]}))

		bounded, err := threadCaps{}.inBounding(unix.CAP_NET_RAW)
		Expect(err).NotTo(HaveOccurred())
		Expect(bounded).To(Equal(caps["CapBnd"]&capNetRawBit != 0))
		ambient, err := threadCaps{}.ambientRaised(unix.CAP_NET_RAW)
		Expect(err).NotTo(HaveOccurred())
		Expect(ambient).To(Equal(caps["CapAmb"]&capNetRawBit != 0))
		Expect(threadCaps{}.isRoot()).To(Equal(os.Geteuid() == 0))
	})

	It("finds file capabilities", func() {
		path := filepath.Join(GinkgoT().TempDir(), "hypervisor")
		Expect(os.WriteFile(path, []byte("x"), 0o755)).To(Succeed())
		has, err := threadCaps{}.fileCaps(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(has).To(BeFalse())
		_, err = threadCaps{}.fileCaps(filepath.Join(path, "missing"))
		Expect(err).To(MatchError(ContainSubstring("getxattr security.capability")))

		// A revision 2 security.capability value that permits CAP_NET_RAW.
		value := []byte{0, 0, 0, 2, byte(capNetRawBit & 0xff), byte(capNetRawBit >> 8 & 0xff), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		if err := unix.Setxattr(path, "security.capability", value, 0); err != nil {
			Skip("cannot set file capabilities here: " + err.Error())
		}
		has, err = threadCaps{}.fileCaps(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(has).To(BeTrue())
	})

	It("confines a real thread, leaving the others their capabilities", func() {
		before := effectiveCap(unix.CAP_NET_RAW)
		result := make(chan [2]any, 1)
		go func() {
			// The goroutine ends locked, so its changed thread ends with it.
			runtime.LockOSThread()
			err := confineHypervisor(threadCaps{}, "/bin/sh")
			status, _ := os.ReadFile("/proc/thread-self/status")
			result <- [2]any{err, string(status)}
		}()
		var r [2]any
		Eventually(result).Should(Receive(&r))
		Expect(r[0]).To(BeNil())
		caps := statusCaps(r[1].(string))
		for _, set := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb"} {
			Expect(caps[set]&capNetRawBit).To(BeZero(), set)
		}
		if os.Geteuid() == 0 {
			Expect(caps["CapBnd"] & capNetRawBit).To(BeZero())
		}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		Expect(effectiveCap(unix.CAP_NET_RAW)).To(Equal(before))
	})
})

var _ = Describe("startConfined", func() {
	It("runs prepare on the thread that starts the process", func() {
		nnp := func() int {
			r, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
			Expect(err).NotTo(HaveOccurred())
			return r
		}
		runtime.LockOSThread()
		before := nnp()
		runtime.UnlockOSThread()

		cmd := exec.Command("/bin/sh", "-c", "grep NoNewPrivs /proc/self/status")
		var out strings.Builder
		cmd.Stdout = &out
		// no_new_privs belongs to a thread, so only a process started from
		// the thread prepare ran on shows it.
		release, err := startConfined(cmd, func() error {
			return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(cmd.Wait()).To(Succeed())
		release()
		release()
		Expect(out.String()).To(MatchRegexp(`NoNewPrivs:\s+1`))

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		Expect(nnp()).To(Equal(before))
	})

	It("keeps the starting thread until release, so the parent death signal waits for vm-launch", func() {
		cmd := exec.Command("/bin/sh", "-c", "sleep 0.5")
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		release, err := startConfined(cmd, func() error { return nil })
		Expect(err).NotTo(HaveOccurred())
		defer release()
		Expect(cmd.Wait()).To(Succeed())
	})

	It("does not start the process when prepare fails", func() {
		cmd := exec.Command("/bin/true")
		release, err := startConfined(cmd, func() error { return unix.EPERM })
		Expect(err).To(MatchError("confining the hypervisor's capabilities: operation not permitted"))
		Expect(release).To(BeNil())
		Expect(cmd.Process).To(BeNil())
	})

	It("reports a process that does not start", func() {
		cmd := exec.Command(filepath.Join(GinkgoT().TempDir(), "missing"))
		release, err := startConfined(cmd, func() error { return nil })
		Expect(err).To(MatchError(ContainSubstring("no such file or directory")))
		Expect(release).To(BeNil())
	})

	It("is how the supervisor starts the hypervisor when it has prepare", func() {
		dir := GinkgoT().TempDir()
		hv := filepath.Join(dir, "hv")
		Expect(os.WriteFile(hv, []byte("#!/bin/sh\necho RVM_START_"+testNonce+"\necho RVM_EXIT_"+testNonce+"=0\n"), 0o755)).To(Succeed())
		logBuf := &safeBuffer{}
		sup := supervisor{stdout: io.Discard, logger: log.New(logBuf, "", 0), signals: make(chan os.Signal), grace: time.Second, deadline: time.Second}

		sup.prepare = func() error { return errors.New("no capabilities today") }
		_, err := sup.run(exec.Command(hv), testNonce)
		Expect(err).To(MatchError("starting hypervisor " + hv + ": confining the hypervisor's capabilities: no capabilities today"))

		prepared := false
		sup.prepare = func() error { prepared = true; return nil }
		res, err := sup.run(exec.Command(hv), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(prepared).To(BeTrue())
		Expect(res.markerFound).To(BeTrue())
	})
})

var _ = Describe("run with --transparent-proxy", func() {
	var (
		art    string
		logBuf *safeBuffer
		caps   *fakeCaps
		checks int
	)

	BeforeEach(func() {
		art = makeArtifacts()
		GinkgoT().Setenv("TMPDIR", GinkgoT().TempDir())
		logBuf = &safeBuffer{}
		caps = &fakeCaps{sets: capSets{effective: capNetRawBit, permitted: capNetRawBit, inheritable: capNetRawBit}, ambient: capNetRawBit}
		savedCaps, savedCheck := hypervisorCaps, checkTransparentDial
		hypervisorCaps = caps
		checks = 0
		checkTransparentDial = func() error { checks++; return nil }
		DeferCleanup(func() { hypervisorCaps, checkTransparentDial = savedCaps, savedCheck })
	})

	freePort := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		defer l.Close()
		return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	}

	runFC := func(flags ...string) int {
		argv := append([]string{"--backend", string(backend.VMFirecracker), "--artifacts", art}, flags...)
		argv = append(argv, "--", "/tmp/lifecycle/launcher", "app", "true", "")
		return run(argv, log.New(logBuf, "", 0))
	}

	It("exits 125 before the guest boots when a socket cannot be made transparent", func() {
		argvFile := writeFakeHypervisor(filepath.Join(art, artFirecracker), "")
		GinkgoT().Setenv("PORT", freePort())
		checkTransparentDial = func() error { return &transparentError{unix.EPERM} }
		Expect(runFC("--transparent-proxy")).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("the transparent port proxy cannot run: making the socket to the guest transparent, which takes CAP_NET_RAW: operation not permitted; Garden grants CAP_NET_RAW"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(caps.calls).To(BeEmpty())
	})

	It("confines the hypervisor's thread, and checks the dial only with ports", func() {
		writeFakeHypervisor(filepath.Join(art, artFirecracker), "")
		GinkgoT().Setenv("PORT", "")
		Expect(os.Unsetenv("PORT")).To(Succeed())
		Expect(runFC("--transparent-proxy")).To(Equal(0), logBuf.String())
		Expect(checks).To(BeZero())
		Expect(caps.calls).To(ContainElement("fileCaps " + filepath.Join(art, artFirecracker)))
		Expect(caps.ambient).To(BeZero())
		Expect(caps.sets).To(Equal(capSets{}))
	})

	It("exits 125 when the hypervisor's thread cannot be confined", func() {
		argvFile := writeFakeHypervisor(filepath.Join(art, artFirecracker), "")
		caps.hasFileCaps = true
		Expect(runFC("--transparent-proxy")).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("confining the hypervisor's capabilities: " + filepath.Join(art, artFirecracker) + " has file capabilities"))
		Expect(argvFile).NotTo(BeAnExistingFile())
	})

	It("does neither without the flag", func() {
		writeFakeHypervisor(filepath.Join(art, artFirecracker), "")
		GinkgoT().Setenv("PORT", freePort())
		Expect(runFC()).To(Equal(0), logBuf.String())
		Expect(checks).To(BeZero())
		Expect(caps.calls).To(BeEmpty())
	})
})

// The transparent proxy end to end, on a real kernel: Garden's tap setup in
// a network namespace that stands in for the container, a namespace behind
// tap0 that stands in for the guest, and one behind eth0 that stands in for
// the rest of the network. vm-launch runs in the container namespace as the
// app user, with the credentials Garden gives the wrapped vm-launch, and its
// fake Firecracker reports the guest app's listeners and records its own
// capabilities.
var _ = Describe("the transparent port proxy on a real kernel", func() {
	const (
		containerIP = "10.255.0.5"
		outsideIP   = "10.255.0.9"
		appUID      = "2000"
		portA       = 18080
		portB       = 18081
	)

	var (
		dir, bin, art, capsDir, done string
		iptables                     string
		ns                           map[string]string
		vmLaunch                     *exec.Cmd
		vmLaunchLog                  *safeBuffer
		// vmLaunchDone closes once vm-launch has been reaped, with its
		// result in vmLaunchErr.
		vmLaunchDone chan struct{}
		vmLaunchErr  error
	)

	inNS := func(name string, args ...string) (string, error) {
		out, err := exec.Command("ip", append([]string{"netns", "exec", ns[name]}, args...)...).CombinedOutput()
		return string(out), err
	}
	mustNS := func(name string, args ...string) {
		GinkgoHelper()
		out, err := inNS(name, args...)
		Expect(err).NotTo(HaveOccurred(), "%v in %s: %s", args, name, out)
	}

	BeforeEach(func() {
		if os.Geteuid() != 0 {
			Skip("network namespaces and the credentials Garden gives vm-launch need root")
		}
		for _, tool := range []string{"ip", "setpriv", "bash", "sysctl"} {
			if _, err := exec.LookPath(tool); err != nil {
				Skip(tool + " is not on PATH")
			}
		}
		iptables = "iptables-legacy"
		if _, err := exec.LookPath(iptables); err != nil {
			iptables = "iptables"
		}
		if _, err := exec.LookPath(iptables); err != nil {
			Skip("no iptables on PATH")
		}

		// Everything the app user runs or writes lives in a directory it
		// can reach.
		var err error
		dir, err = os.MkdirTemp("", "vm-launch-transparent-")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(os.RemoveAll, dir)
		Expect(os.Chmod(dir, 0o755)).To(Succeed())
		self, err := os.Executable()
		Expect(err).NotTo(HaveOccurred())
		data, err := os.ReadFile(self)
		Expect(err).NotTo(HaveOccurred())
		bin = filepath.Join(dir, "vm-launch.test")
		Expect(os.WriteFile(bin, data, 0o755)).To(Succeed())
		art = filepath.Join(dir, "art")
		for _, d := range []string{"kernel", "firecracker"} {
			Expect(os.MkdirAll(filepath.Join(art, d), 0o755)).To(Succeed())
		}
		for _, f := range []string{"kernel/vmlinux", "busybox"} {
			Expect(os.WriteFile(filepath.Join(art, f), []byte("x"), 0o644)).To(Succeed())
		}
		capsDir = filepath.Join(dir, "caps")
		Expect(os.Mkdir(capsDir, 0o777)).To(Succeed())
		Expect(os.Chmod(capsDir, 0o777)).To(Succeed())
		tmp := filepath.Join(dir, "tmp")
		Expect(os.Mkdir(tmp, 0o777)).To(Succeed())
		Expect(os.Chmod(tmp, 0o1777)).To(Succeed())
		done = filepath.Join(dir, "done")

		Expect(os.WriteFile(filepath.Join(art, artFirecracker), []byte(`#!/bin/bash
for a in "$@"; do
	case "$prev" in --config-file) initrd=$(sed -n 's/.*"initrd_path":"\([^"]*\)".*/\1/p' "$a") ;; esac
	prev=$a
done
nonce=$(gzip -dc "$initrd" | grep -a -o 'RVM_START_[0-9a-f]*' | head -n 1 | cut -d_ -f3)
grep ^Cap /proc/self/status > `+shellQuote(capsDir)+`/hypervisor
grep ^Cap /proc/$PPID/status > `+shellQuote(capsDir)+`/vm-launch
echo "RVM_START_$nonce"
echo "RVM_LISTEN_${nonce}=`+strconv.Itoa(portA)+`:1"
echo "RVM_LISTEN_${nonce}=`+strconv.Itoa(portB)+`:1"
for i in $(seq 600); do [ -e `+shellQuote(done)+` ] && break; sleep 0.05; done
echo "RVM_EXIT_$nonce=0"
`), 0o755)).To(Succeed())

		ns = map[string]string{}
		suffix := strconv.Itoa(os.Getpid())
		for _, name := range []string{"container", "guest", "outside"} {
			ns[name] = "vmlt-" + name[:1] + suffix
			if out, err := exec.Command("ip", "netns", "add", ns[name]).CombinedOutput(); err != nil {
				Skip("this system does not allow named network namespaces here: " + string(out))
			}
			nsName := ns[name]
			DeferCleanup(func() { _ = exec.Command("ip", "netns", "del", nsName).Run() })
		}
		link := func(local, localNS, peer, peerNS string) {
			GinkgoHelper()
			a, b := "vlt"+local[:1]+suffix, "vlp"+local[:1]+suffix
			out, err := exec.Command("ip", "link", "add", a, "type", "veth", "peer", "name", b).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), string(out))
			for _, step := range [][]string{
				{"link", "set", a, "netns", localNS},
				{"link", "set", b, "netns", peerNS},
				{"-n", localNS, "link", "set", a, "name", local},
				{"-n", peerNS, "link", "set", b, "name", peer},
			} {
				out, err := exec.Command("ip", step...).CombinedOutput()
				Expect(err).NotTo(HaveOccurred(), "%v: %s", step, out)
			}
		}
		link(netplugin.FirecrackerTapName, ns["container"], "eth0", ns["guest"])
		link("eth0", ns["container"], "eth0", ns["outside"])

		for _, name := range []string{"container", "guest", "outside"} {
			mustNS(name, "ip", "link", "set", "lo", "up")
		}
		mustNS("container", "ip", "addr", "add", containerIP+"/24", "dev", "eth0")
		mustNS("container", "ip", "link", "set", "eth0", "up")
		// Garden's own steps, but for creating tap0, which is a veth here
		// so that the guest's end is a namespace and not a hypervisor.
		steps := netplugin.FirecrackerTapSteps(iptables, 0, 1500, containerIP)
		Expect(steps[0].Args[:3]).To(Equal([]string{"ip", "tuntap", "add"}))
		for _, step := range steps[1:] {
			mustNS("container", step.Args...)
		}
		mustNS("guest", "ip", "addr", "add", fcGuestCIDR, "dev", "eth0")
		mustNS("guest", "ip", "link", "set", "eth0", "up")
		mustNS("guest", "ip", "route", "add", "default", "via", fcHostIP)
		mustNS("outside", "ip", "addr", "add", outsideIP+"/24", "dev", "eth0")
		mustNS("outside", "ip", "link", "set", "eth0", "up")

		guestApp := exec.Command("ip", "netns", "exec", ns["guest"], bin)
		guestApp.Env = append(os.Environ(), helperEchoPorts+"="+strconv.Itoa(portA)+","+strconv.Itoa(portB))
		guestOut, err := guestApp.StdoutPipe()
		Expect(err).NotTo(HaveOccurred())
		guestApp.Stderr = GinkgoWriter
		Expect(guestApp.Start()).To(Succeed())
		DeferCleanup(func() {
			_ = guestApp.Process.Kill()
			_ = guestApp.Wait()
		})
		ready, err := bufio.NewReader(guestOut).ReadString('\n')
		Expect(err).NotTo(HaveOccurred())
		Expect(ready).To(Equal("ready\n"))
	})

	// startVMLaunch runs vm-launch in the container namespace with setpriv
	// creds: Garden's wrapped vm-launch is the app user with the container's
	// inheritable and bounding sets, CAP_NET_RAW ambient, and no_new_privs.
	startVMLaunch := func(credentials []string, transparent bool) {
		args := append([]string{"netns", "exec", ns["container"], "setpriv"}, credentials...)
		args = append(args, "--no-new-privs", "--", bin)
		vmLaunch = exec.Command("ip", args...)
		vmLaunch.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"TMPDIR=" + filepath.Join(dir, "tmp"),
			"PORT=" + strconv.Itoa(portA),
			fmt.Sprintf(`CF_INSTANCE_PORTS=[{"internal":%d},{"internal":2222},{"internal":%d}]`, portA, portB),
			helperTransparentRun + "=" + art,
		}
		if transparent {
			vmLaunch.Env = append(vmLaunch.Env, helperTransparentFlag+"=1")
		}
		vmLaunchLog = &safeBuffer{}
		vmLaunch.Stdout = GinkgoWriter
		vmLaunch.Stderr = io.MultiWriter(vmLaunchLog, GinkgoWriter)
		Expect(vmLaunch.Start()).To(Succeed())
		vmLaunchDone = make(chan struct{})
		go func() {
			vmLaunchErr = vmLaunch.Wait()
			close(vmLaunchDone)
		}()
		DeferCleanup(func() {
			_ = os.WriteFile(done, nil, 0o644)
			select {
			case <-vmLaunchDone:
			case <-time.After(10 * time.Second):
				_ = vmLaunch.Process.Kill()
				<-vmLaunchDone
			}
		})
	}

	// launchExit waits for vm-launch and returns its exit error.
	launchExit := func() error {
		GinkgoHelper()
		Eventually(vmLaunchDone, 15*time.Second).Should(BeClosed(), func() string { return vmLaunchLog.String() })
		return vmLaunchErr
	}

	appUser := []string{"--reuid=" + appUID, "--regid=" + appUID, "--clear-groups",
		"--bounding-set=-all,+chown,+kill,+net_raw,+setpcap",
		"--inh-caps=-all,+chown,+kill,+net_raw", "--ambient-caps=+net_raw"}

	// peer connects to port at addr from the named namespace and returns
	// the address the guest app saw, once the port is open.
	peer := func(from, addr string, port int) string {
		GinkgoHelper()
		var seen string
		Eventually(func() error {
			out, err := inNS(from, "bash", "-c", fmt.Sprintf(`exec 3<>/dev/tcp/%s/%d && cat <&3`, addr, port))
			if err != nil {
				return fmt.Errorf("%v: %s", err, out)
			}
			seen = strings.TrimSpace(out)
			if seen == "" {
				return errors.New("the guest app answered nothing")
			}
			return nil
		}, 15*time.Second, 100*time.Millisecond).Should(Succeed(), func() string { return vmLaunchLog.String() })
		return seen
	}

	finish := func() {
		GinkgoHelper()
		Expect(os.WriteFile(done, nil, 0o644)).To(Succeed())
		Expect(launchExit()).To(Succeed(), vmLaunchLog.String())
	}

	readCaps := func(name string) map[string]uint64 {
		GinkgoHelper()
		status, err := os.ReadFile(filepath.Join(capsDir, name))
		Expect(err).NotTo(HaveOccurred())
		return statusCaps(string(status))
	}

	It("shows the guest each client's own address on every port, and keeps CAP_NET_RAW from the hypervisor", func() {
		startVMLaunch(appUser, true)

		Expect(peer("outside", containerIP, portA)).To(Equal(outsideIP))
		Expect(peer("outside", containerIP, portB)).To(Equal(outsideIP))
		Expect(peer("container", containerIP, portA)).To(Equal(containerIP))
		Expect(peer("container", "127.0.0.1", portA)).To(Equal(fcHostIP))
		Expect(peer("container", "127.0.0.1", portB)).To(Equal(fcHostIP))
		// Diego's SSH port is never forwarded.
		_, err := inNS("outside", "bash", "-c", fmt.Sprintf(`exec 3<>/dev/tcp/%s/2222`, containerIP))
		Expect(err).To(HaveOccurred())
		finish()

		launcher := readCaps("vm-launch")
		Expect(launcher["CapEff"] & capNetRawBit).NotTo(BeZero())
		Expect(launcher["CapAmb"] & capNetRawBit).NotTo(BeZero())
		hypervisor := readCaps("hypervisor")
		for _, set := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb"} {
			Expect(hypervisor[set]&capNetRawBit).To(BeZero(), "%s of the hypervisor: %v", set, hypervisor)
		}
		Expect(hypervisor["CapInh"]).To(Equal(bits(unix.CAP_CHOWN, unix.CAP_KILL)))
	})

	It("shows the guest the tap address without the flag, and the same credentials would leak CAP_NET_RAW then", func() {
		startVMLaunch(appUser, false)
		Expect(peer("outside", containerIP, portA)).To(Equal(fcHostIP))
		finish()
		// This is what the confinement prevents, and it shows that the
		// fake hypervisor's record reads the right bits.
		Expect(readCaps("hypervisor")["CapAmb"] & capNetRawBit).NotTo(BeZero())
	})

	It("drops CAP_NET_RAW from the hypervisor's bounding set when vm-launch runs as root", func() {
		startVMLaunch([]string{"--bounding-set=-all,+chown,+kill,+net_raw,+setpcap"}, true)
		Expect(peer("outside", containerIP, portA)).To(Equal(outsideIP))
		finish()
		hypervisor := readCaps("hypervisor")
		for _, set := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"} {
			Expect(hypervisor[set]&capNetRawBit).To(BeZero(), "%s of the hypervisor: %v", set, hypervisor)
		}
		Expect(hypervisor["CapBnd"]).To(Equal(bits(unix.CAP_CHOWN, unix.CAP_KILL, unix.CAP_SETPCAP)))
	})

	It("refuses to start the hypervisor as root without CAP_SETPCAP", func() {
		startVMLaunch([]string{"--bounding-set=-all,+chown,+kill,+net_raw"}, true)
		err := launchExit()
		var exitErr *exec.ExitError
		Expect(errors.As(err, &exitErr)).To(BeTrue(), "%v", err)
		Expect(exitErr.ExitCode()).To(Equal(exitLaunchError))
		Expect(vmLaunchLog.String()).To(ContainSubstring("runs as root without CAP_SETPCAP"))
		Expect(filepath.Join(capsDir, "hypervisor")).NotTo(BeAnExistingFile())
	})

	It("exits 125 when vm-launch lacks CAP_NET_RAW", func() {
		startVMLaunch([]string{"--reuid=" + appUID, "--regid=" + appUID, "--clear-groups", "--inh-caps=-all", "--bounding-set=-all,+chown"}, true)
		err := launchExit()
		var exitErr *exec.ExitError
		Expect(errors.As(err, &exitErr)).To(BeTrue(), "%v", err)
		Expect(exitErr.ExitCode()).To(Equal(exitLaunchError))
		Expect(vmLaunchLog.String()).To(ContainSubstring("the transparent port proxy cannot run"))
	})
})
