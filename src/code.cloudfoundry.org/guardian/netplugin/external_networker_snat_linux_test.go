package netplugin_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"code.cloudfoundry.org/commandrunner/linux_command_runner"
	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/kawasaki/kawasakifakes"
	"code.cloudfoundry.org/guardian/netplugin"
	"code.cloudfoundry.org/guardian/properties"
	"code.cloudfoundry.org/lager/v3/lagertest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// capabilityBits are the Linux capability numbers the spec needs.
const (
	capSysAdmin = 21
	capNetAdmin = 12
)

// hasCapability reports whether the process holds capability c in its
// effective set, as /proc/self/status shows it.
func hasCapability(c uint) bool {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(status), "\n") {
		if hex, ok := strings.CutPrefix(line, "CapEff:"); ok {
			effective, err := strconv.ParseUint(strings.TrimSpace(hex), 16, 64)
			return err == nil && effective&(1<<c) != 0
		}
	}
	return false
}

// The unit specs for the Firecracker tap check commands and arguments only.
// These apply the whole tap setup to a real kernel, in a network namespace of
// its own, and read the SNAT rule and the reply routing back. They run with
// each iptables flavour that is on PATH: iptables-legacy is the one Garden
// ships, and plain iptables is often the nf_tables one.
var _ = Describe("ExternalNetworker Firecracker egress on a real kernel", func() {
	for _, flavour := range []string{"iptables", "iptables-legacy"} {
		flavour := flavour
		Context("with "+flavour, func() {
			firecrackerOnRealKernel(flavour)
		})
	}
})

func firecrackerOnRealKernel(flavour string) {
	const (
		containerIP = "10.255.0.5"
		// decoyIP is a global address on eth0 that the kernel can list
		// ahead of the container IP. The rule must still use the address
		// the network plugin reported.
		decoyIP = "10.9.0.7"
	)

	var (
		pid       int
		iptables  string
		inNetns   func(args ...string) string
		plugin    netplugin.ExternalNetworker
		tapGroup  uint32 = 4242
		runnerLog        = lagertest.NewTestLogger("snat")
	)

	BeforeEach(func() {
		if os.Geteuid() != 0 {
			Skip("applying the egress rule to a real kernel needs root")
		}
		if !hasCapability(capNetAdmin) || !hasCapability(capSysAdmin) {
			Skip("applying the egress rule to a real kernel needs CAP_NET_ADMIN, and CAP_SYS_ADMIN to enter a network namespace")
		}
		if _, err := os.Stat("/dev/net/tun"); err != nil {
			Skip("this system has no /dev/net/tun, which the tap device needs")
		}
		// access(2) reports a read-only /proc/sys without writing to it.
		if err := syscall.Access("/proc/sys/net/ipv4/ip_forward", 2); err != nil {
			Skip("/proc/sys is not writable here, and the egress setup enables ip forwarding: " + err.Error())
		}
		for _, tool := range []string{"nsenter", "ip", "sysctl"} {
			if _, err := exec.LookPath(tool); err != nil {
				Skip(tool + " is not on PATH, and the egress rule is applied through it")
			}
		}
		var err error
		if iptables, err = exec.LookPath(flavour); err != nil {
			Skip(flavour + " is not on PATH")
		}

		sleeper := exec.Command("sleep", "60")
		sleeper.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
		if err := sleeper.Start(); err != nil {
			Skip("this system does not allow a new network namespace here: " + err.Error())
		}
		DeferCleanup(func() {
			_ = sleeper.Process.Kill()
			_ = sleeper.Wait()
		})
		pid = sleeper.Process.Pid

		inNetns = func(args ...string) string {
			cmd := exec.Command("nsenter", append([]string{fmt.Sprintf("--net=/proc/%d/ns/net", pid), "--"}, args...)...)
			out, err := cmd.CombinedOutput()
			ExpectWithOffset(1, err).NotTo(HaveOccurred(), "%v: %s", args, out)
			return string(out)
		}

		// A Silk-style eth0, with a link-scope address and a point to
		// point peer, plus the decoy.
		inNetns("ip", "link", "add", "eth0", "type", "veth", "peer", "name", "host0")
		inNetns("ip", "addr", "add", decoyIP+"/24", "dev", "eth0")
		inNetns("ip", "addr", "add", containerIP, "peer", "169.254.0.1/32", "scope", "link", "dev", "eth0")
		inNetns("ip", "link", "set", "eth0", "up")

		// The network plugin is a script that reports the container IP.
		pluginPath := filepath.Join(GinkgoT().TempDir(), "plugin.sh")
		reply := fmt.Sprintf(`{"Properties":{"garden.network.container-ip":%q}}`, containerIP)
		Expect(os.WriteFile(pluginPath, []byte("#!/bin/sh\ncat >/dev/null\necho '"+reply+"'\n"), 0o755)).To(Succeed())

		plugin = netplugin.New(
			linux_command_runner.New(),
			properties.NewManager(),
			net.ParseIP("1.2.3.4"),
			nil,
			nil,
			new(kawasakifakes.FakeDnsResolvConfigurer),
			pluginPath,
			nil,
			new(kawasakifakes.FakeNetworkDepot),
			netplugin.WithIPTablesBin(iptables),
			netplugin.WithTapGroup(tapGroup),
		)
	})

	It("installs a SNAT rule from the guest to the container IP the plugin reported", func() {
		spec := garden.ContainerSpec{
			Handle:     "snat-handle",
			Network:    "potato",
			Properties: garden.Properties{backend.AnnotationKey: string(backend.VMFirecracker)},
		}
		Expect(plugin.Network(runnerLog, spec, pid)).To(Succeed())

		rules := strings.Split(strings.TrimSpace(inNetns(iptables, "-t", "nat", "-S", "POSTROUTING")), "\n")
		Expect(rules).To(ContainElement(
			"-A POSTROUTING -s "+netplugin.FirecrackerGuestIP+"/32 -o eth0 -j SNAT --to-source "+containerIP),
			"iptables -t nat -S POSTROUTING showed %q", rules)
		Expect(rules).NotTo(ContainElement(ContainSubstring(decoyIP)))
		Expect(inNetns("ip", "-o", "link", "show", "dev", netplugin.FirecrackerTapName)).To(ContainSubstring("UP"))
	})

	It("drops the guest's forwarded replies, loading the conntrack direction match", func() {
		spec := garden.ContainerSpec{
			Handle:     "stray-reply-handle",
			Network:    "potato",
			Properties: garden.Properties{backend.AnnotationKey: string(backend.VMFirecracker)},
		}
		Expect(plugin.Network(runnerLog, spec, pid)).To(Succeed())

		forward := strings.Split(strings.TrimSpace(inNetns(iptables, "-S", "FORWARD")), "\n")
		Expect(forward).To(ContainElement(
			"-A FORWARD -i "+netplugin.FirecrackerTapName+" -m conntrack --ctdir REPLY -j DROP"),
			"iptables -S FORWARD showed %q", forward)
	})

	It("routes the guest's replies to transparent sockets, loading the socket match the kernel needs", func() {
		spec := garden.ContainerSpec{
			Handle:     "reply-routing-handle",
			Network:    "potato",
			Properties: garden.Properties{backend.AnnotationKey: string(backend.VMFirecracker)},
		}
		Expect(plugin.Network(runnerLog, spec, pid)).To(Succeed())

		mangle := strings.Split(strings.TrimSpace(inNetns(iptables, "-t", "mangle", "-S", "PREROUTING")), "\n")
		Expect(mangle).To(ContainElement(
			"-A PREROUTING -i "+netplugin.FirecrackerTapName+" -p tcp -m socket --transparent -j MARK --set-xmark "+netplugin.FirecrackerProxyMark+"/0xffffffff"),
			"iptables -t mangle -S PREROUTING showed %q", mangle)
		Expect(inNetns("ip", "rule", "show")).To(MatchRegexp(`(?m)^\d+:\s+from all fwmark ` + netplugin.FirecrackerProxyMark + ` lookup ` + netplugin.FirecrackerProxyRouteTable + `\s*$`))
		Expect(strings.TrimSpace(inNetns("ip", "route", "show", "table", netplugin.FirecrackerProxyRouteTable))).To(Equal("local default dev lo scope host"))
	})
}
