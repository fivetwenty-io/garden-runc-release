package netplugin_test

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"code.cloudfoundry.org/commandrunner/fake_command_runner"
	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/guardian/kawasaki"
	"code.cloudfoundry.org/guardian/kawasaki/kawasakifakes"
	"code.cloudfoundry.org/guardian/netplugin"
	"code.cloudfoundry.org/guardian/properties"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/lager/v3/lagertest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

func mustMarshalJSON(input interface{}) string {
	bytes, err := json.Marshal(input)
	Expect(err).NotTo(HaveOccurred())
	return string(bytes)
}

var _ = Describe("ExternalNetworker", func() {
	var (
		containerSpec        garden.ContainerSpec
		configStore          kawasaki.ConfigStore
		fakeCommandRunner    *fake_command_runner.FakeCommandRunner
		logger               *lagertest.TestLogger
		plugin               netplugin.ExternalNetworker
		handle               string
		resolvConfigurer     *kawasakifakes.FakeDnsResolvConfigurer
		networkDepot         *kawasakifakes.FakeNetworkDepot
		pluginOutput         string
		pluginErr            error
		pluginStderr         string
		dnsServers           = []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("9.9.9.9")}
		additionalDNSServers = []net.IP{net.ParseIP("11.11.11.11")}
		loopbackPids         []int
		loopbackErr          error
		fakeLoopback         = func(_ lager.Logger, pid int) error {
			loopbackPids = append(loopbackPids, pid)
			return loopbackErr
		}
	)

	BeforeEach(func() {
		pluginOutput = ""
		loopbackPids = nil
		loopbackErr = nil
		inputProperties := garden.Properties{
			"some-key":               "some-value",
			"some-other-key":         "some-other-value",
			"network.some-key":       "some-network-value",
			"network.some-other-key": "some-other-network-value",
		}
		fakeCommandRunner = fake_command_runner.New()
		configStore = properties.NewManager()
		handle = "some-handle"
		containerSpec = garden.ContainerSpec{
			Handle:     "some-handle",
			Network:    "potato",
			Properties: inputProperties,
		}
		logger = lagertest.NewTestLogger("test")
		externalIP := net.ParseIP("1.2.3.4")
		resolvConfigurer = new(kawasakifakes.FakeDnsResolvConfigurer)
		networkDepot = new(kawasakifakes.FakeNetworkDepot)
		plugin = netplugin.New(
			fakeCommandRunner,
			configStore,
			externalIP,
			dnsServers,
			additionalDNSServers,
			resolvConfigurer,
			"some/path",
			[]string{"arg1", "arg2", "arg3"},
			networkDepot,
			netplugin.WithLoopbackSetup(fakeLoopback),
		)

		pluginErr = nil
		pluginStderr = "some-stderr-bytes"
		fakeCommandRunner.WhenRunning(fake_command_runner.CommandSpec{
			Path: "some/path",
		}, func(cmd *exec.Cmd) error {
			cmd.Stdout.Write([]byte(pluginOutput))
			cmd.Stderr.Write([]byte(pluginStderr))
			return pluginErr
		})
	})

	Describe("Network", func() {
		It("passes the pid of the container to the external plugin's stdin", func() {
			err := plugin.Network(logger, containerSpec, 42)
			Expect(err).NotTo(HaveOccurred())

			cmd := fakeCommandRunner.ExecutedCommands()[0]
			input, err := io.ReadAll(cmd.Stdin)
			Expect(err).NotTo(HaveOccurred())

			Expect(string(input)).To(ContainSubstring("42"))
		})

		It("executes the external plugin with the correct args and input", func() {
			err := plugin.Network(logger, containerSpec, 42)
			Expect(err).NotTo(HaveOccurred())

			cmd := fakeCommandRunner.ExecutedCommands()[0]
			Expect(cmd.Path).To(Equal("some/path"))

			Expect(cmd.Args).To(Equal([]string{
				"some/path",
				"arg1",
				"arg2",
				"arg3",
				"--action", "up",
				"--handle", "some-handle",
			}))

			pluginInput, err := io.ReadAll(cmd.Stdin)
			Expect(err).NotTo(HaveOccurred())
			Expect(pluginInput).To(MatchJSON(`{
				"Pid": 42,
				"Properties": {
					"some-key": "some-network-value",
					"some-other-key": "some-other-network-value"
				}
			}`))
		})

		It("preserves filtered properties", func() {
			containerSpec.Properties["log_config"] = "some-log-config"
			err := plugin.Network(logger, containerSpec, 42)
			Expect(err).NotTo(HaveOccurred())
			cmd := fakeCommandRunner.ExecutedCommands()[0]
			pluginInput, err := io.ReadAll(cmd.Stdin)
			Expect(err).NotTo(HaveOccurred())
			Expect(pluginInput).To(MatchJSON(`{
				"Pid": 42,
				"Properties": {
					"some-key": "some-network-value",
					"some-other-key": "some-other-network-value",
					"log_config": "some-log-config"
				}
			}`))
		})

		Describe("loopback", func() {
			BeforeEach(func() {
				pluginOutput = `{"properties": {"garden.network.container-ip": "10.255.1.2"}}`
			})

			It("brings up lo in the netns of the container pid after the plugin runs", func() {
				Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())
				Expect(loopbackPids).To(Equal([]int{42}))
			})

			Context("when the plugin fails", func() {
				BeforeEach(func() {
					pluginErr = errors.New("plugin-failed")
				})

				It("does not attempt to bring up lo", func() {
					Expect(plugin.Network(logger, containerSpec, 42)).NotTo(Succeed())
					Expect(loopbackPids).To(BeEmpty())
				})
			})

			Context("when the container backend is oci-gvisor", func() {
				BeforeEach(func() {
					containerSpec.Properties[backend.AnnotationKey] = string(backend.OCIGvisor)
				})

				It("does not pass the backend property to the plugin", func() {
					Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

					pluginInput, err := io.ReadAll(fakeCommandRunner.ExecutedCommands()[0].Stdin)
					Expect(err).NotTo(HaveOccurred())
					Expect(string(pluginInput)).NotTo(ContainSubstring(backend.AnnotationKey))
				})

				Context("when bringing up lo fails", func() {
					BeforeEach(func() {
						loopbackErr = errors.New("lo-failed")
					})

					It("returns the error and logs the failure", func() {
						Expect(plugin.Network(logger, containerSpec, 42)).To(MatchError("lo-failed"))
						Expect(logger).To(gbytes.Say(`setup-loopback.*lo-failed`))
					})

					It("does not configure DNS", func() {
						Expect(plugin.Network(logger, containerSpec, 42)).NotTo(Succeed())
						Expect(resolvConfigurer.ConfigureCallCount()).To(Equal(0))
					})
				})
			})

			DescribeTable("when bringing up lo fails for a backend that does not need it",
				func(kind string) {
					if kind != "" {
						containerSpec.Properties[backend.AnnotationKey] = kind
					}
					loopbackErr = errors.New("lo-failed")

					Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())
					Expect(logger).To(gbytes.Say(`setup-loopback.*lo-failed`))
					Expect(resolvConfigurer.ConfigureCallCount()).To(Equal(1))
				},
				Entry("oci-runc", string(backend.OCIRunc)),
				Entry("vm-qemu", string(backend.VMQemu)),
				Entry("no backend", ""),
			)

			Context("when lo is required for every container", func() {
				BeforeEach(func() {
					plugin = netplugin.New(
						fakeCommandRunner,
						configStore,
						net.ParseIP("1.2.3.4"),
						dnsServers,
						additionalDNSServers,
						resolvConfigurer,
						"some/path",
						[]string{"arg1", "arg2", "arg3"},
						networkDepot,
						netplugin.WithLoopbackSetup(fakeLoopback),
						netplugin.WithLoopbackRequired(),
					)
					loopbackErr = errors.New("lo-failed")
				})

				It("fails Network when no backend is set", func() {
					Expect(plugin.Network(logger, containerSpec, 42)).To(MatchError("lo-failed"))
					Expect(resolvConfigurer.ConfigureCallCount()).To(Equal(0))
				})
			})
		})

		Describe("firecracker tap", func() {
			var procRoot string

			nsenterArgs := func(args ...string) []string {
				return append([]string{"--net=/proc/42/ns/net", "--"}, args...)
			}

			writeGIDMap := func(contents string) {
				Expect(os.MkdirAll(filepath.Join(procRoot, "42"), 0o755)).To(Succeed())
				Expect(os.WriteFile(filepath.Join(procRoot, "42", "gid_map"), []byte(contents), 0o644)).To(Succeed())
			}

			newPlugin := func(opts ...netplugin.Option) {
				plugin = netplugin.New(
					fakeCommandRunner,
					configStore,
					net.ParseIP("1.2.3.4"),
					dnsServers,
					additionalDNSServers,
					resolvConfigurer,
					"some/path",
					[]string{"arg1", "arg2", "arg3"},
					networkDepot,
					append([]netplugin.Option{netplugin.WithProcRoot(procRoot), netplugin.WithLoopbackSetup(fakeLoopback)}, opts...)...,
				)
			}

			// The one callback behind the ip link query inside the netns prints
			// eth0Link, or fails with eth0Err.
			var (
				eth0Link string
				eth0Err  error
			)
			answerEth0Link := func(link string) { eth0Link = link }

			// answerContainerIP makes the plugin's up reply report ip as the
			// container IP, or report no container IP when ip is empty.
			answerContainerIP := func(ip string) {
				if ip == "" {
					pluginOutput = `{"properties": {"foo": "bar"}}`
					return
				}
				pluginOutput = `{"properties": {"garden.network.container-ip": "` + ip + `"}}`
			}

			BeforeEach(func() {
				procRoot = GinkgoT().TempDir()
				writeGIDMap("         0 4294967294          1\n         1          1 4294967293\n")
				newPlugin(netplugin.WithTapGroup(991), netplugin.WithIPTablesBin("/var/vcap/data/gdn/assets/sbin/iptables"))
				eth0Err = nil
				fakeCommandRunner.WhenRunning(fake_command_runner.CommandSpec{
					Path: "nsenter",
					Args: nsenterArgs("ip", "-o", "link", "show", "dev", "eth0"),
				}, func(cmd *exec.Cmd) error {
					if eth0Err != nil {
						cmd.Stderr.Write([]byte("Device \"eth0\" does not exist."))
						return eth0Err
					}
					_, err := cmd.Stdout.Write([]byte(eth0Link))
					return err
				})
				answerEth0Link("2: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP mode DEFAULT group default \\    link/ether 02:42:0a:ff:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0\n")
				answerContainerIP("10.255.220.111")
			})

			Context("when the container backend is vm-firecracker", func() {
				BeforeEach(func() {
					containerSpec.Properties[backend.AnnotationKey] = string(backend.VMFirecracker)
				})

				It("creates tap0 for the group, filters the guest, then raises it, enables forwarding and translates egress to the container IP, in order", func() {
					Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

					cmds := fakeCommandRunner.ExecutedCommands()
					Expect(cmds).To(HaveLen(11))
					Expect(cmds[0].Path).To(Equal("some/path"))

					iptables := "/var/vcap/data/gdn/assets/sbin/iptables"
					var got [][]string
					for _, cmd := range cmds[1:] {
						Expect(filepath.Base(cmd.Path)).To(Equal("nsenter"))
						got = append(got, cmd.Args[1:])
					}
					Expect(got).To(Equal([][]string{
						nsenterArgs("ip", "-o", "link", "show", "dev", "eth0"),
						nsenterArgs("ip", "tuntap", "add", "dev", "tap0", "mode", "tap", "group", "991"),
						nsenterArgs("ip", "link", "set", "tap0", "mtu", "1450"),
						nsenterArgs(iptables, "-A", "FORWARD", "-i", "tap0", "!", "-s", "169.254.100.2/32", "-j", "DROP"),
						nsenterArgs(iptables, "-A", "INPUT", "-i", "tap0", "!", "-s", "169.254.100.2/32", "-j", "DROP"),
						nsenterArgs(iptables, "-A", "FORWARD", "-o", "tap0", "-m", "conntrack", "!", "--ctstate", "ESTABLISHED,RELATED", "-j", "DROP"),
						nsenterArgs("ip", "addr", "add", "169.254.100.1/30", "dev", "tap0"),
						nsenterArgs("ip", "link", "set", "tap0", "up"),
						nsenterArgs("sysctl", "-w", "net.ipv4.ip_forward=1"),
						nsenterArgs(iptables, "-t", "nat", "-A", "POSTROUTING", "-s", "169.254.100.2/32", "-o", "eth0", "-j", "SNAT", "--to-source", "10.255.220.111"),
					}))
				})

				// MASQUERADE asks the kernel for a universe scope address on eth0.
				// silk's is of link scope, so the kernel picks tap0's address
				// instead, and silk drops guest packets from 169.254.100.1.
				It("never masquerades guest egress", func() {
					Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

					for _, cmd := range fakeCommandRunner.ExecutedCommands() {
						Expect(cmd.Args).NotTo(ContainElement("MASQUERADE"))
					}
				})

				DescribeTable("translates guest egress to the container IP the plugin reported",
					func(reported string, expected string) {
						answerContainerIP(reported)
						Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

						cmds := fakeCommandRunner.ExecutedCommands()
						Expect(cmds[len(cmds)-1].Args).To(Equal(append([]string{"nsenter"}, nsenterArgs("/var/vcap/data/gdn/assets/sbin/iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "169.254.100.2/32", "-o", "eth0", "-j", "SNAT", "--to-source", expected)...)))
					},
					Entry("a dotted-quad address", "10.255.0.7", "10.255.0.7"),
					Entry("an IPv4-mapped IPv6 address, in dotted-quad form", "::ffff:10.255.0.7", "10.255.0.7"),
					Entry("a private overlay address", "10.255.34.2", "10.255.34.2"),
				)

				DescribeTable("when the plugin reports no usable IPv4 container IP",
					func(reported string, expected string) {
						answerContainerIP(reported)
						err := plugin.Network(logger, containerSpec, 42)
						Expect(err).To(MatchError(ContainSubstring("choosing the guest egress source for container netns of pid 42")))
						Expect(err).To(MatchError(ContainSubstring(expected)))
						Expect(logger).To(gbytes.Say(`setup-firecracker-tap.guest-egress-source-failed`))
						// Only the plugin ran; the netns was never touched.
						Expect(fakeCommandRunner.ExecutedCommands()).To(HaveLen(1))
						Expect(resolvConfigurer.ConfigureCallCount()).To(Equal(0))
					},
					Entry("no container IP", "", "reported no garden.network.container-ip"),
					Entry("not an address", "not-an-ip", `"not-an-ip", which is not an IPv4 address`),
					Entry("an IPv6 address", "fd00::5", `"fd00::5", which is not an IPv4 address`),
					Entry("a loopback address", "127.0.0.2", `"127.0.0.2", which is not an IPv4 address`),
					Entry("the unspecified address", "0.0.0.0", `"0.0.0.0", which is not an IPv4 address`),
					Entry("the address of tap0", "169.254.100.1", `"169.254.100.1", which is not an IPv4 address`),
					Entry("the address of the guest", "169.254.100.2", `"169.254.100.2", which is not an IPv4 address`),
					Entry("a multicast address", "224.0.0.1", `"224.0.0.1", which is not an IPv4 address`),
					Entry("the limited broadcast address", "255.255.255.255", `"255.255.255.255", which is not an IPv4 address`),
				)

				It("sets no per-device reverse path filter, which the inherited all setting would override", func() {
					Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

					for _, cmd := range fakeCommandRunner.ExecutedCommands() {
						Expect(strings.Join(cmd.Args, " ")).NotTo(ContainSubstring("rp_filter"))
					}
				})

				It("never owns tap0 by user", func() {
					Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

					for _, cmd := range fakeCommandRunner.ExecutedCommands() {
						Expect(cmd.Args).NotTo(ContainElement("user"))
					}
				})

				It("has the filters in place before the link is up and forwarding is on", func() {
					Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

					// The command each nsenter runs, after "--".
					var inNetns []string
					for _, cmd := range fakeCommandRunner.ExecutedCommands()[1:] {
						inNetns = append(inNetns, strings.Join(cmd.Args[3:], " "))
					}
					indexOf := func(command string) int {
						for i, c := range inNetns {
							if c == command {
								return i
							}
						}
						Fail("not run in the netns: " + command)
						return -1
					}

					iptables := "/var/vcap/data/gdn/assets/sbin/iptables"
					up := indexOf("ip link set tap0 up")
					forward := indexOf("sysctl -w net.ipv4.ip_forward=1")
					for _, guard := range []string{
						iptables + " -A FORWARD -i tap0 ! -s 169.254.100.2/32 -j DROP",
						iptables + " -A INPUT -i tap0 ! -s 169.254.100.2/32 -j DROP",
						iptables + " -A FORWARD -o tap0 -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP",
					} {
						Expect(indexOf(guard)).To(BeNumerically("<", up), guard)
						Expect(indexOf(guard)).To(BeNumerically("<", forward), guard)
					}
				})

				It("uses the host gid of an unprivileged mapping that does not start at 0", func() {
					writeGIDMap("0 100000 65536\n")
					Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

					Expect(fakeCommandRunner.ExecutedCommands()[2].Args).To(ContainElements("group", "100991"))
				})

				It("honours a configured tap group", func() {
					newPlugin(netplugin.WithTapGroup(1))
					Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

					Expect(fakeCommandRunner.ExecutedCommands()[2].Args).To(ContainElements("group", "1"))
				})

				It("defaults to iptables from the gdn default path", func() {
					newPlugin(netplugin.WithTapGroup(991))
					Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

					cmds := fakeCommandRunner.ExecutedCommands()
					Expect(cmds[4].Args).To(ContainElement("/sbin/iptables"))
					Expect(cmds[5].Args).To(ContainElement("/sbin/iptables"))
					Expect(cmds[6].Args).To(ContainElement("/sbin/iptables"))
					Expect(cmds[10].Args).To(ContainElement("/sbin/iptables"))
				})

				It("does not pass the backend property to the plugin", func() {
					Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

					pluginInput, err := io.ReadAll(fakeCommandRunner.ExecutedCommands()[0].Stdin)
					Expect(err).NotTo(HaveOccurred())
					Expect(string(pluginInput)).NotTo(ContainSubstring(backend.AnnotationKey))
				})

				It("keeps the tap subnet clear of the silk veth gateway", func() {
					_, tapNet, err := net.ParseCIDR(netplugin.FirecrackerTapCIDR)
					Expect(err).NotTo(HaveOccurred())
					Expect(tapNet.Contains(net.ParseIP("169.254.0.1"))).To(BeFalse())
					Expect(tapNet.Contains(net.ParseIP(netplugin.FirecrackerGuestIP))).To(BeTrue())
				})

				Context("when no tap group is configured", func() {
					BeforeEach(func() {
						newPlugin()
					})

					It("fails with a clear error before the plugin or the netns is touched", func() {
						err := plugin.Network(logger, containerSpec, 42)
						Expect(err).To(MatchError(ContainSubstring("no tap group is configured")))
						Expect(err).To(MatchError(ContainSubstring(containerSpec.Handle)))
						Expect(fakeCommandRunner.ExecutedCommands()).To(BeEmpty())
						Expect(resolvConfigurer.ConfigureCallCount()).To(Equal(0))
					})
				})

				Context("when the eth0 mtu differs", func() {
					It("uses the mtu eth0 reports", func() {
						answerEth0Link("2: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc noqueue state UP\n")
						Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

						Expect(fakeCommandRunner.ExecutedCommands()[3].Args).To(Equal(append([]string{"nsenter"}, nsenterArgs("ip", "link", "set", "tap0", "mtu", "9001")...)))
					})
				})

				DescribeTable("when the eth0 mtu cannot be used",
					func(link string, expected string) {
						answerEth0Link(link)
						err := plugin.Network(logger, containerSpec, 42)
						Expect(err).To(MatchError(ContainSubstring("reading the eth0 mtu in container netns of pid 42")))
						Expect(err).To(MatchError(ContainSubstring(expected)))
						// The plugin and the query ran; tap0 was never created.
						Expect(fakeCommandRunner.ExecutedCommands()).To(HaveLen(2))
						Expect(resolvConfigurer.ConfigureCallCount()).To(Equal(0))
					},
					Entry("no mtu in the output", "2: eth0: <BROADCAST> qdisc noqueue\n", "no mtu in"),
					Entry("empty output", "", "no mtu in"),
					Entry("mtu below the IPv4 minimum", "2: eth0: <UP> mtu 67 qdisc noqueue\n", "outside 68 to 65535"),
					Entry("mtu above what a tap accepts", "2: eth0: <UP> mtu 65536 qdisc noqueue\n", "outside 68 to 65535"),
				)

				Context("when the eth0 query fails", func() {
					BeforeEach(func() {
						eth0Err = errors.New("eth0-failed")
					})

					It("returns a wrapped error, logs stderr and creates nothing", func() {
						err := plugin.Network(logger, containerSpec, 42)
						Expect(err).To(MatchError(ContainSubstring("reading the eth0 mtu in container netns of pid 42")))
						Expect(err).To(MatchError(ContainSubstring("eth0-failed")))
						Expect(logger).To(gbytes.Say(`setup-firecracker-tap.failed.*does not exist`))
						Expect(fakeCommandRunner.ExecutedCommands()).To(HaveLen(2))
					})
				})

				Context("when the group is not mapped", func() {
					BeforeEach(func() {
						writeGIDMap("0 1000 500\n")
					})

					It("fails before changing the netns", func() {
						err := plugin.Network(logger, containerSpec, 42)
						Expect(err).To(MatchError(ContainSubstring("pid 42")))
						Expect(err).To(MatchError(ContainSubstring("container gid 991 is not mapped")))
						Expect(fakeCommandRunner.ExecutedCommands()).To(HaveLen(1))
						Expect(resolvConfigurer.ConfigureCallCount()).To(Equal(0))
					})
				})

				Context("when gid_map cannot be read", func() {
					BeforeEach(func() {
						Expect(os.RemoveAll(filepath.Join(procRoot, "42"))).To(Succeed())
					})

					It("returns an error", func() {
						err := plugin.Network(logger, containerSpec, 42)
						Expect(err).To(MatchError(ContainSubstring("resolving tap group")))
						Expect(fakeCommandRunner.ExecutedCommands()).To(HaveLen(1))
					})
				})

				Context("when a step fails", func() {
					BeforeEach(func() {
						fakeCommandRunner.WhenRunning(fake_command_runner.CommandSpec{
							Path: "nsenter",
							Args: nsenterArgs("ip", "addr", "add", "169.254.100.1/30", "dev", "tap0"),
						}, func(cmd *exec.Cmd) error {
							cmd.Stderr.Write([]byte("addr-stderr-bytes"))
							return errors.New("addr-failed")
						})
					})

					It("returns a wrapped error, logs stderr, runs no later step and skips DNS", func() {
						err := plugin.Network(logger, containerSpec, 42)
						Expect(err).To(MatchError(ContainSubstring("addressing tap0 in container netns of pid 42")))
						Expect(err).To(MatchError(ContainSubstring("addr-failed")))
						Expect(logger).To(gbytes.Say(`setup-firecracker-tap.failed.*addr-stderr-bytes`))

						Expect(fakeCommandRunner.ExecutedCommands()).To(HaveLen(8))
						Expect(resolvConfigurer.ConfigureCallCount()).To(Equal(0))
					})
				})

				DescribeTable("when a guard step fails",
					func(args []string, description string, executed int) {
						fakeCommandRunner.WhenRunning(fake_command_runner.CommandSpec{
							Path: "nsenter",
							Args: nsenterArgs(args...),
						}, func(cmd *exec.Cmd) error {
							return errors.New("guard-failed")
						})

						err := plugin.Network(logger, containerSpec, 42)
						Expect(err).To(MatchError(ContainSubstring(description + " in container netns of pid 42")))
						// Forwarding is never enabled behind a guard that did not apply.
						Expect(fakeCommandRunner.ExecutedCommands()).To(HaveLen(executed))
						for _, cmd := range fakeCommandRunner.ExecutedCommands() {
							Expect(cmd.Args).NotTo(ContainElement("net.ipv4.ip_forward=1"))
						}
					},
					Entry("spoofed source drop", []string{"/var/vcap/data/gdn/assets/sbin/iptables", "-A", "FORWARD", "-i", "tap0", "!", "-s", "169.254.100.2/32", "-j", "DROP"}, "dropping spoofed guest sources", 5),
					Entry("spoofed source drop to the container", []string{"/var/vcap/data/gdn/assets/sbin/iptables", "-A", "INPUT", "-i", "tap0", "!", "-s", "169.254.100.2/32", "-j", "DROP"}, "dropping spoofed guest sources to the container", 6),
					Entry("inbound new drop", []string{"/var/vcap/data/gdn/assets/sbin/iptables", "-A", "FORWARD", "-o", "tap0", "-m", "conntrack", "!", "--ctstate", "ESTABLISHED,RELATED", "-j", "DROP"}, "dropping connections opened towards the guest", 7),
					Entry("mtu", []string{"ip", "link", "set", "tap0", "mtu", "1450"}, "setting the mtu of tap0", 4),
				)

				Context("when the plugin fails", func() {
					BeforeEach(func() {
						pluginErr = errors.New("plugin-failed")
					})

					It("does not touch the netns", func() {
						Expect(plugin.Network(logger, containerSpec, 42)).NotTo(Succeed())
						Expect(fakeCommandRunner.ExecutedCommands()).To(HaveLen(1))
					})
				})
			})

			DescribeTable("other backends",
				func(kind string, expectedCommands int) {
					if kind != "" {
						containerSpec.Properties[backend.AnnotationKey] = kind
					}
					// None of them needs a tap group.
					newPlugin()
					Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

					cmds := fakeCommandRunner.ExecutedCommands()
					Expect(cmds).To(HaveLen(expectedCommands))
					for _, cmd := range cmds {
						Expect(cmd.Args).NotTo(ContainElement("tap0"))
					}
				},
				Entry("oci-runc", string(backend.OCIRunc), 1),
				Entry("oci-gvisor", string(backend.OCIGvisor), 1),
				Entry("vm-qemu", string(backend.VMQemu), 1),
				Entry("no backend", "", 1),
			)

			DescribeTable("HostGID",
				func(gidMap string, gid uint32, expected uint32, expectedErr string) {
					got, err := netplugin.HostGID(gidMap, gid)
					if expectedErr != "" {
						Expect(err).To(MatchError(ContainSubstring(expectedErr)))
						return
					}
					Expect(err).NotTo(HaveOccurred())
					Expect(got).To(Equal(expected))
				},
				Entry("unprivileged", "0 4294967294 1\n1 1 4294967293\n", uint32(991), uint32(991), ""),
				Entry("unprivileged, space padded as in /proc", "         0 4294967294          1\n         1          1 4294967293\n", uint32(991), uint32(991), ""),
				Entry("privileged", "0 0 4294967295\n", uint32(991), uint32(991), ""),
				Entry("offset range", "0 100000 65536", uint32(991), uint32(100991), ""),
				Entry("last gid in range", "0 5000 992", uint32(991), uint32(5991), ""),
				Entry("gid mapped by a later line", "0 100000 500\n500 200000 2000\n", uint32(991), uint32(200491), ""),
				Entry("gid just past the range", "0 100000 991", uint32(991), uint32(0), "container gid 991 is not mapped"),
				Entry("empty map", "", uint32(991), uint32(0), "container gid 991 is not mapped"),
				Entry("host id beyond the gid range", "0 4294967295 4000", uint32(991), uint32(0), "beyond the gid range"),
				Entry("wrong field count", "0 0\n", uint32(991), uint32(0), "malformed gid_map line"),
				Entry("non-numeric field", "0 zero 1\n", uint32(991), uint32(0), "malformed gid_map line"),
			)
		})

		Context("when there are NetOut rules provided", func() {
			BeforeEach(func() {
				containerSpec.NetOut = []garden.NetOutRule{
					garden.NetOutRule{
						Protocol: garden.ProtocolTCP,
						Networks: []garden.IPRange{garden.IPRangeFromIP(net.ParseIP("8.8.8.8"))},
						Ports:    []garden.PortRange{garden.PortRangeFromPort(53)},
					},
					garden.NetOutRule{
						Protocol: garden.ProtocolTCP,
						Networks: []garden.IPRange{garden.IPRangeFromIP(net.ParseIP("8.8.4.4"))},
						Ports:    []garden.PortRange{garden.PortRangeFromPort(53)},
					},
				}
			})

			It("passes them in the stdin to the network plugin", func() {
				Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

				cmd := fakeCommandRunner.ExecutedCommands()[0]
				pluginInput, err := io.ReadAll(cmd.Stdin)
				Expect(err).NotTo(HaveOccurred())
				Expect(pluginInput).To(MatchJSON(`{
				"Pid": 42,
				"Properties": {
					"some-key": "some-network-value",
					"some-other-key": "some-other-network-value"
				},
				"netout_rules": [
				  {
					  "protocol":1,
					  "networks": [{"start":"8.8.8.8","end":"8.8.8.8"}],
					  "ports": [{"start":53,"end":53}]
					},
					{
					  "protocol":1,
					  "networks":[{"start":"8.8.4.4","end":"8.8.4.4"}],
					  "ports":[{"start":53,"end":53}]
					}
				]
			}`))
			})
		})

		Context("when NetIn input is provided", func() {
			BeforeEach(func() {
				containerSpec.NetIn = []garden.NetIn{
					garden.NetIn{
						HostPort:      9999,
						ContainerPort: 8080,
					},
					garden.NetIn{
						HostPort:      9989,
						ContainerPort: 8081,
					},
				}
			})

			It("passes the input through stdin to the network plugin", func() {
				Expect(plugin.Network(logger, containerSpec, 42)).To(Succeed())

				cmd := fakeCommandRunner.ExecutedCommands()[0]
				pluginInput, err := io.ReadAll(cmd.Stdin)
				Expect(err).NotTo(HaveOccurred())

				Expect(pluginInput).To(MatchJSON(`{
				"Pid": 42,
				"Properties": {
					"some-key": "some-network-value",
					"some-other-key": "some-other-network-value"
				},
				"netin": [
					{
						"host_port": 9999,
						"container_port": 8080
					},
					{
						"host_port": 9989,
						"container_port": 8081
					}
				]
			}`))
			})
		})

		It("collects and logs the stderr from the plugin", func() {
			err := plugin.Network(logger, containerSpec, 42)
			Expect(err).NotTo(HaveOccurred())

			Expect(logger).To(gbytes.Say("result.*some-stderr-bytes"))
		})

		Context("when plugin outputs stderr", func() {
			BeforeEach(func() {
				pluginStderr = "some-stderr-bytes"
			})

			It("collects and logs the stderr from the plugin to log level info", func() {
				err := plugin.Network(logger, containerSpec, 42)
				Expect(err).NotTo(HaveOccurred())

				Expect(logger).To(gbytes.Say(`result.*"log_level":1.*some-stderr-bytes`))
			})
		})

		Context("when plugin doesn't output any stderr", func() {
			BeforeEach(func() {
				pluginStderr = ""
			})

			It("doesn't output stderr log to log level info", func() {
				err := plugin.Network(logger, containerSpec, 42)
				Expect(err).NotTo(HaveOccurred())

				Expect(logger).NotTo(gbytes.Say(`result.*"log_level":1.*some-stderr-bytes`))
			})
		})

		Describe("DNS configuration inside the container", func() {
			var cfg kawasaki.NetworkConfig

			JustBeforeEach(func() {
				var (
					log lager.Logger
					pid int
				)

				err := plugin.Network(logger, containerSpec, 42)
				Expect(err).NotTo(HaveOccurred())

				Expect(resolvConfigurer.ConfigureCallCount()).To(Equal(1))
				log, cfg, pid = resolvConfigurer.ConfigureArgsForCall(0)
				Expect(log).To(Equal(logger))
				Expect(pid).To(Equal(42))
			})

			Context("when the external plugin returns a containerIP in properties", func() {
				BeforeEach(func() {
					pluginOutput = `{
						"properties": {
							"garden.network.container-ip": "10.255.1.2"
						}
				  }`
				})

				It("is configured according to Garden defaults", func() {
					Expect(cfg).To(Equal(kawasaki.NetworkConfig{
						ContainerIP:           net.ParseIP("10.255.1.2"),
						BridgeIP:              net.ParseIP("10.255.1.2"),
						ContainerHandle:       "some-handle",
						PluginNameservers:     nil,
						OperatorNameservers:   dnsServers,
						AdditionalNameservers: additionalDNSServers,
					}))
				})
			})

			Context("when the external plugin returns a containerIP in properties and dns_servers", func() {
				Context("when 0 DNS servers are returned", func() {
					BeforeEach(func() {
						pluginOutput = `{
							"properties": {
								"garden.network.container-ip": "10.255.1.2"
							},
							"dns_servers": []
						}`
					})

					It("is configured using the returned DNS servers", func() {
						Expect(cfg).To(Equal(kawasaki.NetworkConfig{
							ContainerIP:           net.ParseIP("10.255.1.2"),
							BridgeIP:              net.ParseIP("10.255.1.2"),
							ContainerHandle:       "some-handle",
							PluginNameservers:     []net.IP{},
							OperatorNameservers:   dnsServers,
							AdditionalNameservers: additionalDNSServers,
						}))
					})
				})

				Context("when 1 DNS server is returned", func() {
					BeforeEach(func() {
						pluginOutput = `{
							"properties": {
								"garden.network.container-ip": "10.255.1.2"
							},
							"dns_servers": [
								"1.2.3.4"
							]
						}`
					})

					It("is configured using the returned DNS servers", func() {
						Expect(cfg).To(Equal(kawasaki.NetworkConfig{
							ContainerIP:           net.ParseIP("10.255.1.2"),
							BridgeIP:              net.ParseIP("10.255.1.2"),
							ContainerHandle:       "some-handle",
							PluginNameservers:     []net.IP{net.ParseIP("1.2.3.4")},
							OperatorNameservers:   dnsServers,
							AdditionalNameservers: additionalDNSServers,
						}))
					})
				})

				Context("when > 1 DNS server is returned", func() {
					BeforeEach(func() {
						pluginOutput = `{
							"properties": {
								"garden.network.container-ip": "10.255.1.2"
							},
							"dns_servers": [
								"1.2.3.4",
								"1.2.3.5"
							]
						}`
					})

					It("is configured using the returned DNS servers", func() {
						Expect(cfg).To(Equal(kawasaki.NetworkConfig{
							ContainerIP:           net.ParseIP("10.255.1.2"),
							BridgeIP:              net.ParseIP("10.255.1.2"),
							ContainerHandle:       "some-handle",
							PluginNameservers:     []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("1.2.3.5")},
							OperatorNameservers:   dnsServers,
							AdditionalNameservers: additionalDNSServers,
						}))
					})
				})
			})
		})

		Describe("Search domain configuration inside the container", func() {
			var cfg kawasaki.NetworkConfig

			BeforeEach(func() {
				pluginOutput = `{
						"properties": {
							"garden.network.container-ip": "10.255.1.2"
						}
				  }`
			})

			JustBeforeEach(func() {
				var (
					log lager.Logger
					pid int
				)

				err := plugin.Network(logger, containerSpec, 42)
				Expect(err).NotTo(HaveOccurred())

				Expect(resolvConfigurer.ConfigureCallCount()).To(Equal(1))
				log, cfg, pid = resolvConfigurer.ConfigureArgsForCall(0)
				Expect(log).To(Equal(logger))
				Expect(pid).To(Equal(42))
			})

			It("is called with an empty list of search domains", func() {
				Expect(cfg.PluginSearchDomains).To(BeEmpty())
			})

			Context("when one search domain is configured", func() {
				BeforeEach(func() {
					pluginOutput = `{
						"properties": {
							"garden.network.container-ip": "10.255.1.2"
						},
						"search_domains": ["potato"]
				  }`
				})

				It("is called with those search domains", func() {
					Expect(cfg.PluginSearchDomains).To(Equal([]string{"potato"}))
				})
			})

			Context("when two search domain are configured", func() {
				BeforeEach(func() {
					pluginOutput = `{
						"properties": {
							"garden.network.container-ip": "10.255.1.2"
						},
						"search_domains": ["potato","banana"]
				  }`
				})

				It("is called with that search domains", func() {
					Expect(cfg.PluginSearchDomains).To(Equal([]string{"potato", "banana"}))
				})
			})
		})

		Context("when the external plugin errors", func() {
			BeforeEach(func() {
				pluginErr = errors.New("external-plugin-error")
			})

			It("returns the error", func() {
				Expect(plugin.Network(logger, containerSpec, 42)).To(MatchError("external networker encountered an error running 'up' action: external-plugin-error"))
			})

			It("collects and logs the stderr from the plugin", func() {
				plugin.Network(logger, containerSpec, 42)
				Expect(logger).To(gbytes.Say("result.*error.*some-stderr-bytes"))
			})
		})

		Context("when the external plugin returns valid properties JSON", func() {
			It("persists the returned properties to the container's properties", func() {
				pluginOutput = `{"properties":{"foo":"bar","ping":"pong","garden.network.container-ip":"10.255.1.2"}}`

				err := plugin.Network(logger, containerSpec, 42)
				Expect(err).NotTo(HaveOccurred())

				persistedPropertyValue, _ := configStore.Get("some-handle", "foo")
				Expect(persistedPropertyValue).To(Equal("bar"))
			})
		})

		Context("when the external plugin returns invalid JSON", func() {
			It("returns a useful error message", func() {
				pluginOutput = "invalid-json"

				err := plugin.Network(logger, containerSpec, 42)
				Expect(err).To(MatchError(ContainSubstring("unmarshaling result from external networker")))
			})
		})

		Context("when the external network plugin returns nothing", func() {
			It("succeeds", func() {
				pluginOutput = ""

				err := plugin.Network(logger, containerSpec, 42)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when the external network plugin returns ipv6 address", func() {
			It("persists the returned ipv6 address in the container's properties", func() {
				pluginOutput = `{"properties":{"foo":"bar","ping":"pong","garden.network.container-ip":"10.255.1.2", "garden.network.container-ipv6":"2006:db8::1"}}`

				err := plugin.Network(logger, containerSpec, 42)
				Expect(err).NotTo(HaveOccurred())

				persistedPropertyValue, _ := configStore.Get("some-handle", "garden.network.container-ipv6")
				Expect(persistedPropertyValue).To(Equal("2006:db8::1"))
			})
		})
	})

	Describe("Destroy", func() {
		It("executes the external plugin with the correct args and destroys the depot", func() {
			Expect(plugin.Destroy(logger, "my-handle")).To(Succeed())

			cmd := fakeCommandRunner.ExecutedCommands()[0]
			Expect(cmd.Path).To(Equal("some/path"))

			Expect(cmd.Args).To(Equal([]string{
				"some/path",
				"arg1",
				"arg2",
				"arg3",
				"--action", "down",
				"--handle", "my-handle",
			}))

			Expect(networkDepot.DestroyCallCount()).To(Equal(1))
			actualLogger, actualHandle := networkDepot.DestroyArgsForCall(0)
			Expect(actualLogger).To(Equal(logger))
			Expect(actualHandle).To(Equal("my-handle"))
		})

		Context("when the external plugin errors", func() {
			BeforeEach(func() {
				pluginErr = errors.New("boom")
			})
			It("returns the error", func() {
				Expect(plugin.Destroy(logger, "my-handle")).To(MatchError("external networker encountered an error running 'down' action: boom"))
			})
		})

		Context("when destroying the depot fails", func() {
			It("returns the error", func() {
				networkDepot.DestroyReturns(errors.New("failed"))

				err := plugin.Destroy(logger, "my-handle")
				Expect(err).To(MatchError("failed"))
			})
		})
	})

	Describe("NetIn", func() {
		BeforeEach(func() {
			configStore.Set(handle, gardener.ContainerIPKey, "5.6.7.8")
			pluginOutput = `{
					"host_port": 1234,
					"container_port": 5555
				}`
		})

		It("executes the external plugin with the correct args and stdin", func() {
			_, _, err := plugin.NetIn(logger, handle, 22, 33)
			Expect(err).NotTo(HaveOccurred())

			cmd := fakeCommandRunner.ExecutedCommands()[0]
			Expect(cmd.Path).To(Equal("some/path"))

			Expect(cmd.Args).To(Equal([]string{
				"some/path",
				"arg1",
				"arg2",
				"arg3",
				"--action", "net-in",
				"--handle", "some-handle",
			}))

			pluginInput, err := io.ReadAll(cmd.Stdin)
			Expect(err).NotTo(HaveOccurred())
			Expect(pluginInput).To(MatchJSON(`{
				"HostIP": "1.2.3.4",
				"HostPort" : 22,
				"ContainerIP": "5.6.7.8",
				"ContainerPort": 33
			}`))
		})

		It("adds the port mapping output from the external plugin", func() {
			externalPort, containerPort, err := plugin.NetIn(logger, handle, 22, 33)
			Expect(err).NotTo(HaveOccurred())

			portMapping, ok := configStore.Get(handle, gardener.MappedPortsKey)
			Expect(ok).To(BeTrue())
			Expect(portMapping).To(MatchJSON(mustMarshalJSON([]garden.PortMapping{
				{
					HostPort:      1234,
					ContainerPort: 5555,
				},
			})))
			Expect(externalPort).To(Equal(uint32(1234)))
			Expect(containerPort).To(Equal(uint32(5555)))
		})

		Context("when the handle cannot be found in the store", func() {
			It("returns an error", func() {
				_, _, err := plugin.NetIn(logger, "some-nonexistent-handle", 22, 33)
				Expect(err).To(MatchError("cannot find container [some-nonexistent-handle]\n"))
			})
		})

		Context("when the external plugin errors", func() {
			BeforeEach(func() {
				pluginErr = errors.New("potato")
			})
			It("returns the error", func() {
				_, _, err := plugin.NetIn(logger, handle, 22, 33)
				Expect(err).To(MatchError("external networker encountered an error running 'net-in' action: potato"))
			})
		})

		Context("when adding the port mapping fails", func() {
			BeforeEach(func() {
				configStore.Set(handle, gardener.MappedPortsKey, "%%%%%%")
			})
			It("returns the error", func() {
				_, _, err := plugin.NetIn(logger, handle, 123, 543)
				Expect(err).To(MatchError(ContainSubstring("invalid character")))
			})
		})

		It("collects and logs the stderr from the plugin", func() {
			_, _, err := plugin.NetIn(logger, handle, 22, 33)
			Expect(err).NotTo(HaveOccurred())

			Expect(logger).To(gbytes.Say("result.*some-stderr-bytes"))
		})
	})

	Describe("NetOut", func() {
		var handle = "my-handle"
		var rule garden.NetOutRule

		BeforeEach(func() {
			configStore.Set(handle, gardener.ContainerIPKey, "169.254.1.2")
			rule = createRule("1.1.1.1", "2.2.2.2", 9000, 9999)
		})

		It("executes the external plugin with the correct args and input", func() {
			Expect(plugin.NetOut(logger, handle, rule)).To(Succeed())

			cmd := fakeCommandRunner.ExecutedCommands()[0]
			Expect(cmd.Path).To(Equal("some/path"))
			Expect(cmd.Args).To(Equal([]string{
				"some/path",
				"arg1",
				"arg2",
				"arg3",
				"--action", "net-out",
				"--handle", handle,
			}))

			checkPluginArgs(cmd, rule)
		})

		Context("when the handle cannot be found in the config store", func() {
			It("returns the error", func() {
				Expect(plugin.NetOut(logger, "missing-handle", rule)).To(MatchError("cannot find container [missing-handle]\n"))
			})
		})

		Context("when the external plugin errors", func() {
			BeforeEach(func() {
				pluginErr = errors.New("boom")
			})
			It("returns the error", func() {
				Expect(plugin.NetOut(logger, handle, rule)).To(MatchError("external networker encountered an error running 'net-out' action: boom"))
			})
		})

		It("collects and logs the stderr from the plugin", func() {
			Expect(plugin.NetOut(logger, handle, rule)).To(Succeed())

			Expect(logger).To(gbytes.Say("result.*some-stderr-bytes"))
		})
	})

	Describe("BulkNetOut", func() {
		var handle = "my-handle"
		var rules []garden.NetOutRule

		BeforeEach(func() {
			configStore.Set(handle, gardener.ContainerIPKey, "169.254.1.2")
			rules = []garden.NetOutRule{
				createRule("1.1.1.1", "2.2.2.2", 1111, 2222),
				createRule("3.3.3.3", "4.4.4.4", 3333, 4444),
			}
		})

		It("calls BulkNetOut passing all the rules", func() {
			Expect(plugin.BulkNetOut(logger, handle, rules)).To(Succeed())

			Expect(fakeCommandRunner.ExecutedCommands()).To(HaveLen(1))
			checkBulkPluginArgs(fakeCommandRunner.ExecutedCommands()[0], rules)
		})

		Context("when the handle cannot be found in the config store", func() {
			It("returns the error", func() {
				Expect(plugin.BulkNetOut(logger, "missing-handle", rules)).To(MatchError("cannot find container [missing-handle]\n"))
			})
		})

		Context("when the external plugin errors", func() {
			BeforeEach(func() {
				pluginErr = errors.New("boom")
			})

			It("returns the error", func() {
				Expect(plugin.BulkNetOut(logger, handle, rules)).To(MatchError("external networker encountered an error running 'bulk-net-out' action: boom"))
			})
		})

		It("collects and logs the stderr from the plugin", func() {
			Expect(plugin.BulkNetOut(logger, handle, rules)).To(Succeed())

			Expect(logger).To(gbytes.Say("result.*some-stderr-bytes"))
		})
	})

	Describe("SetupBindMounts", func() {
		It("delegates to the network depot", func() {
			networkDepot.SetupBindMountsReturns([]garden.BindMount{{SrcPath: "src"}}, nil)

			bindMounts, err := plugin.SetupBindMounts(logger, "handle", true, "rootfs/path")

			Expect(networkDepot.SetupBindMountsCallCount()).To(Equal(1))
			actualLogger, actualHandle, actualPrivileged, actualRootfsPath := networkDepot.SetupBindMountsArgsForCall(0)
			Expect(actualLogger).To(Equal(logger))
			Expect(actualHandle).To(Equal("handle"))
			Expect(actualPrivileged).To(BeTrue())
			Expect(actualRootfsPath).To(Equal("rootfs/path"))

			Expect(err).NotTo(HaveOccurred())
			Expect(bindMounts).To(HaveLen(1))
			Expect(bindMounts[0].SrcPath).To(Equal("src"))
		})

		Context("when setting up the bind mounts fails", func() {
			It("returns the error", func() {
				networkDepot.SetupBindMountsReturns(nil, errors.New("failed"))

				_, err := plugin.SetupBindMounts(logger, "handle", true, "rootfs/path")
				Expect(err).To(MatchError("failed"))
			})
		})
	})
})

func createRule(netStart, netEnd string, portStart, portEnd int) garden.NetOutRule {
	return garden.NetOutRule{
		Protocol: garden.ProtocolTCP,
		Networks: []garden.IPRange{{
			Start: net.ParseIP(netStart),
			End:   net.ParseIP(netEnd),
		}},
		Ports: []garden.PortRange{{
			Start: uint16(portStart),
			End:   uint16(portEnd),
		}},
	}
}

func checkPluginArgs(cmd *exec.Cmd, rule garden.NetOutRule) {
	pluginInput, err := io.ReadAll(cmd.Stdin)
	Expect(err).NotTo(HaveOccurred())
	r := new(netplugin.NetOutInputs)
	json.Unmarshal(pluginInput, r)
	Expect(r.NetOutRule).To(Equal(rule))
}

func checkBulkPluginArgs(cmd *exec.Cmd, rules []garden.NetOutRule) {
	pluginInput, err := io.ReadAll(cmd.Stdin)
	Expect(err).NotTo(HaveOccurred())
	r := new(netplugin.BulkNetOutInputs)
	json.Unmarshal(pluginInput, r)
	Expect(r.NetOutRules).To(Equal(rules))
}
