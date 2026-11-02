//go:build linux

package main

import (
	"errors"
	"io"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// ipv6Loopback skips the spec where the namespace has no IPv6 loopback.
func ipv6Loopback() {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		Skip("this network namespace has no IPv6 loopback: " + err.Error())
	}
	Expect(l.Close()).To(Succeed())
}

// countingOpener records its calls and fails the ones in err.
type countingOpener struct {
	opens, closes int
	openErr       error
}

func (f *countingOpener) openPort() error  { f.opens++; return f.openErr }
func (f *countingOpener) closePort() error { f.closes++; return nil }

var _ = Describe("IPv6 for the guest", func() {
	Describe("detecting the container's IPv6 address", func() {
		addrs := func(cidrs ...string) []net.Addr {
			var out []net.Addr
			for _, c := range cidrs {
				ip, n, err := net.ParseCIDR(c)
				Expect(err).NotTo(HaveOccurred())
				n.IP = ip
				out = append(out, n)
			}
			return out
		}

		It("counts a global and a unique local address", func() {
			Expect(hasGlobalIPv6(addrs("10.255.1.2/24", "2001:db8::5/64"))).To(BeTrue())
			Expect(hasGlobalIPv6(addrs("fd00:abcd::5/64"))).To(BeTrue())
		})

		It("does not count IPv4, link-local, loopback, or IPv4-mapped addresses, or no address", func() {
			Expect(hasGlobalIPv6(addrs("10.255.1.2/24"))).To(BeFalse())
			Expect(hasGlobalIPv6(addrs("fe80::1/64", "::1/128"))).To(BeFalse())
			Expect(hasGlobalIPv6(addrs("::ffff:10.0.0.1/128"))).To(BeFalse())
			Expect(hasGlobalIPv6(nil)).To(BeFalse())
		})

		It("is false for an interface that does not exist", func() {
			Expect(interfaceHasIPv6("no-such-nic0")).To(BeFalse())
		})
	})

	Describe("the network", func() {
		It("stays the IPv4 network until IPv6 is enabled", func() {
			n := taskNetwork()
			n.ports = []int{8080}
			Expect(n.listen6).To(BeFalse())
			Expect(n.address6).To(BeEmpty())
			Expect(netFile(n)).To(Equal("RVM_ADDRESS='10.0.2.15/24'\nRVM_GATEWAY='10.0.2.2'\nRVM_PORTS='8080'\n"))
			Expect(withGuestIPv6(initScript(testNonce, false), n)).To(Equal(initScript(testNonce, false)))
		})

		It("gives the QEMU guest an address and a gateway, and sends IPv6 connections to the IPv4 rule", func() {
			n := taskNetwork()
			n.enableIPv6(backend.VMQemu)
			Expect(n.listen6).To(BeTrue())
			Expect(n.address6).To(Equal("fec0::15/64"))
			Expect(n.gateway6).To(Equal("fec0::2"))
			Expect(n.listenAddr6(8080)).To(Equal("[::]:8080"))
			Expect(n.upstream6(8080)).To(Equal("127.0.0.1:8080"))
			Expect(netFile(n)).To(Equal("RVM_ADDRESS='10.0.2.15/24'\nRVM_GATEWAY='10.0.2.2'\nRVM_ADDRESS6='fec0::15/64'\nRVM_GATEWAY6='fec0::2'\n"))
		})

		It("leaves the Firecracker guest IPv4 inside and sends IPv6 connections to its IPv4 address", func() {
			n := &network{address: fcGuestCIDR, gateway: fcHostIP, ports: []int{8080}}
			before := netFile(n)
			n.enableIPv6(backend.VMFirecracker)
			Expect(n.listen6).To(BeTrue())
			Expect(n.address6).To(BeEmpty())
			Expect(n.upstream6(8080)).To(Equal("169.254.100.2:8080"))
			Expect(netFile(n)).To(Equal(before))
		})
	})

	Describe("the guest script", func() {
		It("adds the IPv6 setup right after the network setup, before the start tag", func() {
			n := taskNetwork()
			n.enableIPv6(backend.VMQemu)
			script := withGuestIPv6(initScript(testNonce, false), n)
			Expect(script).To(ContainSubstring(guestNetworkSetup + guestNetworkSetup6 + ". /rvm/limits"))
			Expect(strings.Index(script, guestNetworkSetup6)).To(BeNumerically("<", strings.Index(script, "echo RVM_START_"+testNonce)))
		})

		It("is valid shell, and configures eth0 through ip", func() {
			Expect(exec.Command("/bin/sh", "-n", "-c", guestNetworkSetup6).Run()).To(Succeed())
			Expect(guestNetworkSetup6).To(ContainSubstring(`ip -6 addr add "$RVM_ADDRESS6" dev eth0`))
			Expect(guestNetworkSetup6).To(ContainSubstring(`ip -6 route add default via "$RVM_GATEWAY6" dev eth0`))
		})

		It("only warns when the guest has no IPv6", func() {
			Expect(guestNetworkSetup6).NotTo(ContainSubstring("rvm_fail"))
			Expect(guestNetworkSetup6).To(ContainSubstring("the guest kernel has no IPv6; the guest keeps IPv4 only"))
		})
	})

	Describe("the IPv6 port listener", func() {
		It("is IPv6 only, so it never takes the IPv4 connections of the port", func() {
			ipv6Loopback()
			Expect(listenNetwork("[::]:8080")).To(Equal("tcp6"))
			Expect(listenNetwork("0.0.0.0:8080")).To(Equal("tcp"))
			Expect(listenNetwork("127.0.0.1:8080")).To(Equal("tcp"))
			Expect(listenNetwork("not an address")).To(Equal("tcp"))

			// The IPv4 side stands in for QEMU's forwarding rule.
			rule := listenLocal()
			serve(rule, echo)
			port := rule.Addr().(*net.TCPAddr).Port
			n := taskNetwork()
			n.enableIPv6(backend.VMQemu)
			proxy, err := startProxy(n.listenAddr6(port), n.upstream6(port), testDialPolicy, log.New(io.Discard, "", 0))
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(proxy.Close)

			c, err := net.Dial("tcp6", net.JoinHostPort("::1", strconv.Itoa(port)))
			Expect(err).NotTo(HaveOccurred())
			defer c.Close()
			_, err = c.Write([]byte("over ipv6"))
			Expect(err).NotTo(HaveOccurred())
			Expect(c.(*net.TCPConn).CloseWrite()).To(Succeed())
			got, err := io.ReadAll(c)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(got)).To(Equal("over ipv6"))
		})
	})

	Describe("dualPort", func() {
		var logs strings.Builder
		logger := func() *log.Logger { logs.Reset(); return log.New(&logs, "", 0) }

		It("opens and closes both", func() {
			v4, v6 := &countingOpener{}, &countingOpener{}
			d := dualPort{v4: v4, v6: v6, port: 8080, logger: logger()}
			Expect(d.openPort()).To(Succeed())
			Expect(d.closePort()).To(Succeed())
			Expect([]int{v4.opens, v4.closes, v6.opens, v6.closes}).To(Equal([]int{1, 1, 1, 1}))
		})

		It("stays open over IPv4 when IPv6 cannot open, and says so", func() {
			d := dualPort{v4: &countingOpener{}, v6: &countingOpener{openErr: errors.New("busy")}, port: 8080, logger: logger()}
			Expect(d.openPort()).To(Succeed())
			Expect(logs.String()).To(ContainSubstring("port 8080 is open over IPv4 only"))
		})

		It("fails when IPv4 cannot open, and leaves IPv6 closed", func() {
			v6 := &countingOpener{}
			d := dualPort{v4: &countingOpener{openErr: syscallInUse()}, v6: v6, port: 8080, logger: logger()}
			err := d.openPort()
			Expect(isPortConflict(err)).To(BeTrue())
			Expect(v6.opens).To(Equal(0))
		})
	})

	Describe("the IPv6 reservation", func() {
		It("holds the port against a plain IPv6 bind and not against a reusing listener", func() {
			ipv6Loopback()
			l, err := net.Listen("tcp", "127.0.0.1:0")
			Expect(err).NotTo(HaveOccurred())
			port := l.Addr().(*net.TCPAddr).Port
			Expect(l.Close()).To(Succeed())

			r, err := reservePort(port)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.reserveIPv6(port)).To(Succeed())
			Expect(r.reserveIPv6(port)).To(Succeed(), "a second call does nothing")

			// A connection is refused while nothing listens.
			_, err = net.Dial("tcp6", net.JoinHostPort("::1", strconv.Itoa(port)))
			Expect(err).To(HaveOccurred())
			// The port proxy's listener can take it over.
			ln, err := net.Listen("tcp6", net.JoinHostPort("::", strconv.Itoa(port)))
			Expect(err).NotTo(HaveOccurred())
			Expect(ln.Close()).To(Succeed())

			Expect(r.Close()).To(Succeed())
			ln, err = net.Listen("tcp6", net.JoinHostPort("::", strconv.Itoa(port)))
			Expect(err).NotTo(HaveOccurred())
			Expect(ln.Close()).To(Succeed())
		})

		It("has no IPv6 socket unless asked", func() {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			Expect(err).NotTo(HaveOccurred())
			port := l.Addr().(*net.TCPAddr).Port
			Expect(l.Close()).To(Succeed())
			r, err := reservePort(port)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.fd6).To(Equal(-1))
			Expect(r.Close()).To(Succeed())
		})
	})
})

func syscallInUse() error { return unix.EADDRINUSE }
