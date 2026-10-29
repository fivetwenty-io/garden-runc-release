//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/netplugin"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// envMap is a lookupEnv over a fixed set of variables.
func envMap(vars map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}
}

// sourceAndDumpEnv sources file in a POSIX shell (argv of the shell
// command) with an otherwise empty environment and returns the resulting
// environment, less the variables the shell sets itself.
func sourceAndDumpEnv(shell []string, file string) map[string]string {
	cmd := exec.Command(shell[0], append(shell[1:], "-c", `. "$1"; exec /usr/bin/env -0`, "sh", file)...)
	cmd.Env = []string{}
	out, err := cmd.Output()
	Expect(err).NotTo(HaveOccurred())
	env := map[string]string{}
	for _, kv := range strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00") {
		name, value, ok := strings.Cut(kv, "=")
		Expect(ok).To(BeTrue(), kv)
		env[name] = value
	}
	// The file never exports PATH (a spec checks), but busybox sh sets a
	// default one.
	for _, own := range []string{"PWD", "SHLVL", "_", "PATH"} {
		delete(env, own)
	}
	return env
}

// fixedMTU is an MTU lookup that reports mtu for every interface.
func fixedMTU(mtu int) func(string) (int, error) {
	return func(string) (int, error) { return mtu, nil }
}

// failingMTU is an MTU lookup that always fails.
func failingMTU(string) (int, error) { return 0, errors.New("no such network interface") }

func writeTempFile(name, content string) string {
	p := filepath.Join(GinkgoT().TempDir(), name)
	Expect(os.WriteFile(p, []byte(content), 0o644)).To(Succeed())
	return p
}

var _ = Describe("guest network", func() {
	var (
		logBuf *bytes.Buffer
		logger *log.Logger
	)

	BeforeEach(func() {
		logBuf = &bytes.Buffer{}
		logger = log.New(logBuf, "", 0)
	})

	It("matches the tap device garden creates for Firecracker", func() {
		Expect(fcTapName).To(Equal(netplugin.FirecrackerTapName))
		Expect(fcHostIP + "/30").To(Equal(netplugin.FirecrackerTapCIDR))
		Expect(fcGuestIP).To(Equal(netplugin.FirecrackerGuestIP))

		link := netip.MustParsePrefix(fcGuestCIDR)
		Expect(link.Contains(netip.MustParseAddr(fcHostIP))).To(BeTrue())
		Expect(link.Masked()).To(Equal(netip.MustParsePrefix(netplugin.FirecrackerTapCIDR).Masked()))
	})

	It("uses addresses inside QEMU's user-mode network", func() {
		user := netip.MustParsePrefix(qemuNetwork)
		Expect(netip.MustParsePrefix(qemuGuestCIDR).Masked()).To(Equal(user))
		for _, a := range []string{qemuGuestIP, qemuGateway, qemuDNS} {
			Expect(user.Contains(netip.MustParseAddr(a))).To(BeTrue(), a)
		}
	})

	DescribeTable("parsePort",
		func(in string, want int, ok bool) {
			got, err := parsePort(in)
			if !ok {
				Expect(err).To(MatchError(ContainSubstring("is not a TCP port number")))
				return
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(want))
		},
		Entry("CF default", "8080", 8080, true),
		Entry("lowest", "1", 1, true),
		Entry("highest", "65535", 65535, true),
		Entry("zero", "0", 0, false),
		Entry("too large", "65536", 0, false),
		Entry("empty", "", 0, false),
		Entry("negative", "-1", 0, false),
		Entry("signed", "+80", 0, false),
		Entry("trailing space", "80 ", 0, false),
		Entry("not a number", "http", 0, false),
	)

	Describe("networkFor", func() {
		const resolv = "# silk\nnameserver 169.254.0.2\nsearch service.cf.internal apps.internal\noptions ndots:1\n"

		It("gives a QEMU process without PORT the full guest network with port 0", func() {
			nw, err := networkFor(backend.VMQemu, envMap(map[string]string{"CF_INSTANCE_GUID": "g"}), writeTempFile("resolv.conf", resolv), fixedMTU(1450), logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(*nw).To(Equal(network{
				address:    "10.0.2.15/24",
				gateway:    "10.0.2.2",
				resolvConf: "search service.cf.internal apps.internal\nnameserver 10.0.2.3\n",
				env:        "export CF_INSTANCE_GUID='g'\n",
			}))
			Expect(logBuf.String()).To(BeEmpty())
		})

		It("gives a Firecracker process without PORT the full guest network with port 0", func() {
			nw, err := networkFor(backend.VMFirecracker, envMap(map[string]string{"CF_INSTANCE_GUID": "g"}), writeTempFile("resolv.conf", resolv), fixedMTU(1450), logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(*nw).To(Equal(network{
				address:    "169.254.100.2/30",
				gateway:    "169.254.100.1",
				resolvConf: "search service.cf.internal apps.internal\nnameserver 169.254.0.2\n",
				env:        "export CF_INSTANCE_GUID='g'\n",
				mtu:        1450,
			}))
			Expect(logBuf.String()).To(BeEmpty())
		})

		It("rejects a PORT that is not a port number", func() {
			_, err := networkFor(backend.VMQemu, envMap(map[string]string{"PORT": "eighty"}), "/nonexistent", fixedMTU(1450), logger)
			Expect(err).To(MatchError(`PORT "eighty" is not a TCP port number from 1 to 65535`))
		})

		It("configures the QEMU guest on the user-mode network with QEMU's DNS proxy", func() {
			nw, err := networkFor(backend.VMQemu, envMap(map[string]string{"PORT": "8080"}), writeTempFile("resolv.conf", resolv), fixedMTU(1450), logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(*nw).To(Equal(network{
				port:       8080,
				address:    "10.0.2.15/24",
				gateway:    "10.0.2.2",
				resolvConf: "search service.cf.internal apps.internal\nnameserver 10.0.2.3\n",
				env:        "export PORT='8080'\n",
			}))
			Expect(logBuf.String()).To(BeEmpty())
		})

		It("leaves the QEMU guest at the default mtu and does not look the container's up", func() {
			lookups := 0
			lookup := func(string) (int, error) { lookups++; return 1450, nil }
			nw, err := networkFor(backend.VMQemu, envMap(map[string]string{"PORT": "8080"}), writeTempFile("resolv.conf", resolv), lookup, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(nw.mtu).To(BeZero())
			Expect(lookups).To(BeZero())
		})

		It("reads the mtu of the container's eth0 for the Firecracker guest", func() {
			var asked []string
			lookup := func(name string) (int, error) { asked = append(asked, name); return 1410, nil }
			nw, err := networkFor(backend.VMFirecracker, envMap(map[string]string{"PORT": "8080"}), writeTempFile("resolv.conf", resolv), lookup, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(nw.mtu).To(Equal(1410))
			Expect(asked).To(Equal([]string{"eth0"}))
			Expect(logBuf.String()).To(BeEmpty())
		})

		It("boots the Firecracker guest at the default mtu when eth0's cannot be read", func() {
			nw, err := networkFor(backend.VMFirecracker, envMap(map[string]string{"PORT": "8080"}), writeTempFile("resolv.conf", resolv), failingMTU, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(nw.mtu).To(BeZero())
			Expect(logBuf.String()).To(ContainSubstring("reading the mtu of eth0: no such network interface; the guest keeps the default mtu"))
		})

		DescribeTable("boots the Firecracker guest at the default mtu when eth0's is unusable",
			func(mtu int) {
				nw, err := networkFor(backend.VMFirecracker, envMap(map[string]string{"PORT": "8080"}), writeTempFile("resolv.conf", resolv), fixedMTU(mtu), logger)
				Expect(err).NotTo(HaveOccurred())
				Expect(nw.mtu).To(BeZero())
				Expect(logBuf.String()).To(ContainSubstring("is outside 68 to 65535; the guest keeps the default mtu"))
			},
			Entry("zero", 0),
			Entry("below the IPv4 minimum", 67),
			Entry("above what a tap accepts", 65536),
			Entry("negative", -1),
		)

		It("accepts the lowest and highest usable mtu", func() {
			for _, mtu := range []int{68, 65535} {
				nw, err := networkFor(backend.VMFirecracker, envMap(map[string]string{"PORT": "8080"}), writeTempFile("resolv.conf", resolv), fixedMTU(mtu), logger)
				Expect(err).NotTo(HaveOccurred())
				Expect(nw.mtu).To(Equal(mtu))
			}
		})

		It("configures the Firecracker guest on the tap link with the container's nameservers", func() {
			nw, err := networkFor(backend.VMFirecracker, envMap(map[string]string{"PORT": "61000"}), writeTempFile("resolv.conf", resolv), fixedMTU(1450), logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(nw.address).To(Equal("169.254.100.2/30"))
			Expect(nw.gateway).To(Equal("169.254.100.1"))
			Expect(nw.resolvConf).To(Equal("search service.cf.internal apps.internal\nnameserver 169.254.0.2\n"))
			Expect(nw.mtu).To(Equal(1450))
			Expect(nw.upstream()).To(Equal("169.254.100.2:61000"))
			Expect(nw.listenAddr()).To(Equal("0.0.0.0:61000"))
			Expect(logBuf.String()).To(BeEmpty())
		})

		It("passes only usable nameservers to the Firecracker guest and logs the rest", func() {
			conf := writeTempFile("resolv.conf", strings.Join([]string{
				"nameserver 169.254.0.2",
				"nameserver fd00::53",
				"nameserver 127.0.0.53",
				"nameserver dns.example",
				"nameserver",
				"; nameserver 10.9.9.9",
				"nameserver 10.0.0.1",
				"nameserver 10.0.0.2",
				"nameserver 10.0.0.3",
				"search first.example",
				"domain last.example",
				"",
			}, "\n"))
			nw, err := networkFor(backend.VMFirecracker, envMap(map[string]string{"PORT": "8080"}), conf, fixedMTU(1450), logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(nw.resolvConf).To(Equal("search last.example\nnameserver 169.254.0.2\nnameserver 10.0.0.1\nnameserver 10.0.0.2\n"))
			for _, s := range []string{
				`"fd00::53" to the guest: the guest has no IPv6`,
				`"127.0.0.53" to the guest: a loopback address is the guest itself`,
				`"dns.example" to the guest: not an IP address`,
				`"10.0.0.3" to the guest: the resolver reads only 3`,
			} {
				Expect(logBuf.String()).To(ContainSubstring(s))
			}
			Expect(logBuf.String()).NotTo(ContainSubstring("10.9.9.9"))
		})

		It("boots the guest without DNS when the container has no resolv.conf", func() {
			nw, err := networkFor(backend.VMFirecracker, envMap(map[string]string{"PORT": "8080"}), "/nonexistent/resolv.conf", fixedMTU(1450), logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(nw.resolvConf).To(BeEmpty())
			Expect(logBuf.String()).To(ContainSubstring("/nonexistent/resolv.conf does not exist"))
			Expect(logBuf.String()).To(ContainSubstring("no usable nameserver"))
		})

		It("logs a resolv.conf it cannot read and keeps QEMU's DNS proxy", func() {
			nw, err := networkFor(backend.VMQemu, envMap(map[string]string{"PORT": "8080"}), GinkgoT().TempDir(), fixedMTU(1450), logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(nw.resolvConf).To(Equal("nameserver 10.0.2.3\n"))
			Expect(logBuf.String()).To(ContainSubstring("reading "))
		})

		It("rejects other backends", func() {
			_, err := networkFor(backend.OCIGvisor, envMap(map[string]string{"PORT": "8080"}), "/nonexistent", fixedMTU(1450), logger)
			Expect(err).To(MatchError(ContainSubstring("unsupported backend")))
		})
	})

	Describe("guest environment file", func() {
		hostile := map[string]string{
			"PORT":              "8080",
			"CF_INSTANCE_GUID":  `it's a "guid"`,
			"CF_INSTANCE_ADDR":  "$HOME `id` $(id) \\n \\",
			"CF_INSTANCE_PORTS": `[{"external":61000,"internal":8080}]`,
			"INSTANCE_INDEX":    "line one\nline two\n",
			"CF_INSTANCE_IP":    "",
			"INSTANCE_GUID":     "'''",
			"VCAP_SERVICES":     `{"db":[{"credentials":{"password":"secret"}}]}`,
			"VCAP_APPLICATION":  `{"name":"app"}`,
			"CF_INSTANCE_CERT":  "/etc/cf-instance-credentials/instance.crt",
			"PATH":              "/usr/bin",
		}
		allowed := map[string]string{}
		for _, name := range guestEnvVars {
			if v, ok := hostile[name]; ok {
				allowed[name] = v
			}
		}

		It("exports only the allowed variables", func() {
			file := guestEnvFile(envMap(hostile))
			for _, name := range []string{"VCAP_SERVICES", "VCAP_APPLICATION", "CF_INSTANCE_CERT", "PATH", "CF_INSTANCE_INTERNAL_IP", "secret"} {
				Expect(file).NotTo(ContainSubstring(name))
			}
			Expect(strings.HasPrefix(file, "export PORT='8080'\n")).To(BeTrue())
		})

		It("keeps every value byte for byte when a shell sources it", func() {
			path := writeTempFile("env", guestEnvFile(envMap(hostile)))
			shells := [][]string{{"/bin/sh"}}
			if bb, err := exec.LookPath("busybox"); err == nil {
				shells = append(shells, []string{bb, "sh"})
			}
			for _, shell := range shells {
				Expect(sourceAndDumpEnv(shell, path)).To(Equal(allowed), strings.Join(shell, " "))
			}
		})

		It("writes /rvm/net as shell assignments", func() {
			nw := &network{address: fcGuestCIDR, gateway: fcHostIP, mtu: 1450}
			path := writeTempFile("net", netFile(nw))
			out, err := exec.Command("/bin/sh", "-c", `. "$1"; printf '%s|%s|%s' "$RVM_ADDRESS" "$RVM_GATEWAY" "$RVM_MTU"`, "sh", path).Output()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(out)).To(Equal("169.254.100.2/30|169.254.100.1|1450"))
		})

		It("leaves RVM_MTU out of /rvm/net when the guest keeps the default mtu", func() {
			Expect(netFile(&network{address: qemuGuestCIDR, gateway: qemuGateway})).To(Equal("RVM_ADDRESS='10.0.2.15/24'\nRVM_GATEWAY='10.0.2.2'\n"))
		})
	})

	Describe("networked initramfs", func() {
		nw := &network{
			port:       8080,
			address:    qemuGuestCIDR,
			gateway:    qemuGateway,
			resolvConf: "nameserver 10.0.2.3\n",
			env:        "export PORT='8080'\n",
		}

		It("adds the network and environment files", func() {
			names, byName := archiveEntries(buildInitramfs([]byte("busybox"), "httpd -f -p $PORT", nw, nil))
			Expect(names).To(Equal([]string{"bin", "dev", "dev/console", "dev/null", "etc", "proc", "sys", "tmp", "rvm",
				"bin/busybox", "rvm/cmd", "rvm/net", "rvm/env", "etc/resolv.conf", "init", cpioTrailer}))
			Expect(string(byName["rvm/net"].data)).To(Equal("RVM_ADDRESS='10.0.2.15/24'\nRVM_GATEWAY='10.0.2.2'\n"))
			Expect(string(byName["rvm/env"].data)).To(Equal("export PORT='8080'\n"))
			Expect(string(byName["etc/resolv.conf"].data)).To(Equal("nameserver 10.0.2.3\n"))
			Expect(byName["etc/resolv.conf"].mode).To(Equal(uint32(0o100644)))
			Expect(string(byName["init"].data)).To(Equal(initScript(testNonce, false)))
		})

		It("configures the network and environment before the start tag", func() {
			script := initScript(testNonce, false)
			start := strings.Index(script, "echo RVM_START_"+testNonce)
			Expect(start).To(BeNumerically(">", 0))
			for _, step := range []string{
				". /rvm/net\n",
				"ip link set lo up",
				`ip link set eth0 mtu "$RVM_MTU"`,
				"ip link set eth0 up",
				`ip addr add "$RVM_ADDRESS" dev eth0`,
				`ip route add default via "$RVM_GATEWAY" dev eth0`,
				". /rvm/env\n",
			} {
				idx := strings.Index(script, step)
				Expect(idx).To(BeNumerically(">", 0), step)
				Expect(idx).To(BeNumerically("<", start), step)
			}
			Expect(script).To(HaveSuffix("\nsh /rvm/cmd </dev/null\necho RVM_EXIT_" + testNonce + "=$?\nreboot -f\n"))
		})

		It("sets the mtu of eth0 only when /rvm/net names one, and before it brings eth0 up", func() {
			script := initScript(testNonce, false)
			Expect(script).To(ContainSubstring("\nif [ -n \"${RVM_MTU:-}\" ]; then\n\tip link set eth0 mtu \"$RVM_MTU\" || echo \"vm-launch guest setup: setting the mtu of eth0 to $RVM_MTU failed; keeping the default mtu\"\nfi\n"))
			Expect(strings.Index(script, `mtu "$RVM_MTU"`)).To(BeNumerically("<", strings.Index(script, "ip link set eth0 up")))
		})

		It("keeps booting with the default mtu when the guest rejects the mtu, and still fails on the other network steps", func() {
			script := initScript(testNonce, false)
			Expect(script).NotTo(ContainSubstring(`mtu "$RVM_MTU" || rvm_fail`))

			// Run the real network setup with an ip that fails the mtu step only.
			dir := GinkgoT().TempDir()
			ipLog := filepath.Join(dir, "ip.log")
			fakeIP := "#!/bin/sh\necho \"$*\" >> " + shellQuote(ipLog) + "\ncase \"$*\" in *mtu*) exit 2 ;; esac\n"
			Expect(os.WriteFile(filepath.Join(dir, "ip"), []byte(fakeIP), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "net"), []byte("RVM_ADDRESS='10.0.2.15/24'\nRVM_GATEWAY='10.0.2.2'\nRVM_MTU='9001'\n"), 0o644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "env"), []byte(""), 0o644)).To(Succeed())
			Expect(os.MkdirAll(filepath.Join(dir, "sys/class/net/eth0"), 0o755)).To(Succeed())
			setup := strings.NewReplacer(
				"/rvm/net", filepath.Join(dir, "net"),
				"/rvm/env", filepath.Join(dir, "env"),
				"/sys/class/net/eth0", filepath.Join(dir, "sys/class/net/eth0"),
				"reboot -f", "echo REBOOT",
			).Replace(guestFailFunc + guestNetworkSetup)

			cmd := exec.Command("/bin/sh", "-c", setup+"echo REACHED_START")
			cmd.Env = []string{"PATH=" + dir + ":/bin:/usr/bin"}
			out, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), string(out))
			Expect(string(out)).To(ContainSubstring("setting the mtu of eth0 to 9001 failed; keeping the default mtu"))
			Expect(string(out)).To(ContainSubstring("REACHED_START"))
			Expect(string(out)).NotTo(ContainSubstring("REBOOT"))

			calls, err := os.ReadFile(ipLog)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(calls)).To(Equal("link set lo up\nlink set eth0 mtu 9001\nlink set eth0 up\naddr add 10.0.2.15/24 dev eth0\nroute add default via 10.0.2.2 dev eth0\n"))
		})

		It("gives a task the same archive and network setup as an LRP", func() {
			task := &network{address: qemuGuestCIDR, gateway: qemuGateway, resolvConf: "nameserver 10.0.2.3\n"}
			names, byName := archiveEntries(buildInitramfs([]byte("busybox"), "true", task, nil))
			lrpNames, lrp := archiveEntries(buildInitramfs([]byte("busybox"), "true", nw, nil))
			Expect(names).To(Equal(lrpNames))
			Expect(byName["init"].data).To(Equal(lrp["init"].data))
			Expect(byName["rvm/net"].data).To(Equal(lrp["rvm/net"].data))
			Expect(byName["etc/resolv.conf"].data).To(Equal(lrp["etc/resolv.conf"].data))
			Expect(byName["rvm/env"].data).To(BeEmpty())
		})

		It("defines rvm_fail before any step uses it", func() {
			for _, volume := range []bool{false, true} {
				script := initScript(testNonce, volume)
				def := strings.Index(script, "rvm_fail() {")
				Expect(def).To(BeNumerically(">", 0))
				Expect(strings.Index(script, "rvm_fail")).To(Equal(def), "volume %v", volume)
				Expect(strings.Index(script, ". /rvm/net")).To(BeNumerically(">", def))
			}
		})

		It("is valid shell", func() {
			out, err := exec.Command("/bin/sh", "-n", "-c", initScript(testNonce, false)).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), string(out))
		})
	})

	Describe("hypervisor command lines with a network", func() {
		const art = "/opt/garden-vm/artifacts"
		nw := &network{port: 8080}

		It("adds a user-mode NIC that forwards PORT to QEMU, and the same NIC without a forward for a task", func() {
			argv, err := hypervisorArgv(backend.VMQemu, art, "/unused", "/proc/self/fd/3", 128, nw, "")
			Expect(err).NotTo(HaveOccurred())
			task, err := hypervisorArgv(backend.VMQemu, art, "/unused", "/proc/self/fd/3", 128, &network{}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(argv[:len(argv)-4]).To(Equal(task[:len(task)-4]))
			Expect(argv[len(argv)-4:]).To(Equal([]string{
				"-netdev", "user,id=n0,net=10.0.2.0/24,hostfwd=tcp:0.0.0.0:8080-10.0.2.15:8080",
				"-device", "virtio-net-device,netdev=n0",
			}))
			Expect(task[len(task)-4:]).To(Equal([]string{
				"-netdev", "user,id=n0,net=10.0.2.0/24",
				"-device", "virtio-net-device,netdev=n0",
			}))
			Expect(strings.Join(task, " ")).NotTo(ContainSubstring("hostfwd"))
		})

		It("attaches the Firecracker guest of an LRP and of a task to garden's tap device", func() {
			for _, n := range []*network{nw, {}} {
				work := GinkgoT().TempDir()
				argv, err := hypervisorArgv(backend.VMFirecracker, art, work, "/proc/self/fd/3", 128, n, "")
				Expect(err).NotTo(HaveOccurred())
				Expect(argv).To(Equal([]string{art + "/firecracker/firecracker", "--no-api", "--config-file", work + "/fc.json"}))

				raw, err := os.ReadFile(filepath.Join(work, "fc.json"))
				Expect(err).NotTo(HaveOccurred())
				var cfg map[string]any
				Expect(json.Unmarshal(raw, &cfg)).To(Succeed())
				Expect(cfg["network-interfaces"]).To(Equal([]any{map[string]any{
					"iface_id":      "eth0",
					"guest_mac":     "06:00:a9:fe:64:02",
					"host_dev_name": "tap0",
				}}), "port %d", n.port)
				Expect(cfg["boot-source"]).To(HaveKeyWithValue("boot_args", "console=ttyS0 reboot=k panic=1 rdinit=/init quiet"))
			}
		})
	})
})

// makeArtifacts returns an artifacts directory with every file both backends
// need, none of them runnable. Specs replace the hypervisor with writeFakeHypervisor.
func makeArtifacts() string {
	art := GinkgoT().TempDir()
	for _, d := range []string{"kernel", "qemu/lib", "qemu/share", "firecracker"} {
		Expect(os.MkdirAll(filepath.Join(art, d), 0o755)).To(Succeed())
	}
	for _, f := range []string{"kernel/bzImage", "kernel/vmlinux", "qemu/qemu-system-x86_64-microvm", "busybox",
		"qemu/ld-linux-x86-64.so.2", "firecracker/firecracker"} {
		Expect(os.WriteFile(filepath.Join(art, f), []byte("x"), 0o644)).To(Succeed())
	}
	return art
}

// writeFakeHypervisor replaces the executable at path with a script that
// records its argv in the returned file, runs extra, and then reports guest
// status 0 under the nonce it finds in the initramfs, as /init would.
func writeFakeHypervisor(path, extra string) string {
	argvFile := path + ".argv"
	script := `#!/bin/bash
printf '%s\n' "$@" > ` + shellQuote(argvFile) + `
for a in "$@"; do
	case "$prev" in -initrd) initrd=$a ;; --config-file) initrd=$(sed -n 's/.*"initrd_path":"\([^"]*\)".*/\1/p' "$a") ;; esac
	prev=$a
done
nonce=$(gzip -dc "$initrd" | grep -a -o 'RVM_START_[0-9a-f]*' | head -n 1 | cut -d_ -f3)
` + extra + `
echo "RVM_START_$nonce"
echo "RVM_EXIT_$nonce=0"
`
	Expect(os.Remove(path)).To(Succeed())
	Expect(os.WriteFile(path, []byte(script), 0o755)).To(Succeed())
	return argvFile
}

// vmLaunchListeners is fake hypervisor shell that sets $listening to the
// inodes of the listening TCP sockets its parent, vm-launch, holds open.
const vmLaunchListeners = `listening=
for l in /proc/$PPID/fd/*; do
	t=$(readlink "$l") || continue
	case "$t" in socket:\[*\]) ;; *) continue ;; esac
	i=${t#socket:[}
	i=${i%]}
	if cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v i="$i" '$4 == "0A" && $10 == i { f = 1 } END { exit !f }'; then
		listening="$listening $i"
	fi
done
`

var _ = Describe("run with PORT", func() {
	var (
		art    string
		tmp    string
		logBuf *bytes.Buffer
	)

	BeforeEach(func() {
		art = makeArtifacts()
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		logBuf = &bytes.Buffer{}
	})

	fakeHypervisor := writeFakeHypervisor

	freePort := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}

	runVM := func(kind backend.Kind) int {
		return run([]string{"--backend", string(kind), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}, log.New(logBuf, "", 0))
	}

	It("exits 125 for a PORT that is not a port number", func() {
		GinkgoT().Setenv("PORT", "99999")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring(`PORT "99999" is not a TCP port number`))
	})

	It("gives QEMU a NIC that forwards only when PORT is set", func() {
		argvFile := fakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		GinkgoT().Setenv("PORT", "8080")
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		withPort, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(withPort)).To(ContainSubstring("\n-netdev\nuser,id=n0,net=10.0.2.0/24,hostfwd=tcp:0.0.0.0:8080-10.0.2.15:8080\n-device\nvirtio-net-device,netdev=n0\n"))

		Expect(os.Unsetenv("PORT")).To(Succeed())
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		withoutPort, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(withoutPort)).To(ContainSubstring("\n-netdev\nuser,id=n0,net=10.0.2.0/24\n-device\nvirtio-net-device,netdev=n0\n"))
		Expect(string(withoutPort)).NotTo(ContainSubstring("hostfwd"))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("gives a Firecracker task its NIC and opens no port in the container", func() {
		fcCopy := filepath.Join(art, "fc-copy.json")
		fakeHypervisor(filepath.Join(art, "firecracker/firecracker"),
			`p=; for a in "$@"; do [ "$p" = --config-file ] && cp "$a" `+shellQuote(fcCopy)+`; p=$a; done
`+vmLaunchListeners+`[ -z "$listening" ] || { echo "vm-launch listens on socket$listening" >&2; exit 1; }
`)
		Expect(runVM(backend.VMFirecracker)).To(Equal(0), logBuf.String())
		Expect(os.ReadFile(fcCopy)).To(ContainSubstring(`"network-interfaces":[{"iface_id":"eth0","guest_mac":"06:00:a9:fe:64:02","host_dev_name":"tap0"}]`))
		Expect(logBuf.String()).NotTo(ContainSubstring("listening"))
	})

	It("sees the Firecracker port proxy with the same check, so the task spec above can fail", func() {
		fakeHypervisor(filepath.Join(art, "firecracker/firecracker"),
			vmLaunchListeners+`[ -n "$listening" ] || { echo "no listener found" >&2; exit 1; }
`)
		GinkgoT().Setenv("PORT", strconv.Itoa(freePort()))
		Expect(runVM(backend.VMFirecracker)).To(Equal(0), logBuf.String())
	})

	It("listens on PORT for Firecracker before the hypervisor starts and closes it after", func() {
		port := freePort()
		// The proxy holds this connection while it waits for the guest, which
		// is unreachable here, until vm-launch closes it at guest exit.
		probe := fmt.Sprintf(`exec 3<>/dev/tcp/127.0.0.1/%d || { echo "port not bound" >&2; exit 1; }`, port)
		argvFile := fakeHypervisor(filepath.Join(art, "firecracker/firecracker"), probe)
		GinkgoT().Setenv("PORT", strconv.Itoa(port))

		Expect(runVM(backend.VMFirecracker)).To(Equal(0), logBuf.String())
		Expect(os.ReadFile(argvFile)).To(ContainSubstring("--config-file"))
		_, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		Expect(err).To(HaveOccurred())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("exits 125 when PORT is taken", func() {
		l, err := net.Listen("tcp", "0.0.0.0:0")
		Expect(err).NotTo(HaveOccurred())
		defer l.Close()
		fakeHypervisor(filepath.Join(art, "firecracker/firecracker"), "")
		GinkgoT().Setenv("PORT", strconv.Itoa(l.Addr().(*net.TCPAddr).Port))

		Expect(runVM(backend.VMFirecracker)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("listening for the guest port"))
		Expect(logBuf.String()).To(ContainSubstring(
			"port " + strconv.Itoa(l.Addr().(*net.TCPAddr).Port) + " already in use in this container; VM backends run one app process per container"))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	Describe("when QEMU cannot forward PORT", func() {
		const hostfwdError = `echo "qemu-system-x86_64: -netdev user,id=n0,net=10.0.2.0/24,hostfwd=tcp:0.0.0.0:8080-10.0.2.15:8080: Could not set up host forwarding rule 'tcp:0.0.0.0:8080-10.0.2.15:8080'" >&2; exit 1`

		It("exits 124 and names the port conflict", func() {
			fakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), hostfwdError)
			GinkgoT().Setenv("PORT", "8080")

			Expect(runVM(backend.VMQemu)).To(Equal(exitHypervisorFailed), logBuf.String())
			Expect(logBuf.String()).To(ContainSubstring("hypervisor failed with exit status 1"))
			Expect(logBuf.String()).To(ContainSubstring("port 8080 already in use in this container; VM backends run one app process per container"))
			Expect(os.ReadDir(tmp)).To(BeEmpty())
		})

		It("still names the port conflict when stderr is broken", func() {
			fakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), hostfwdError)
			GinkgoT().Setenv("PORT", "8080")

			r, w, err := os.Pipe()
			Expect(err).NotTo(HaveOccurred())
			Expect(r.Close()).To(Succeed())
			defer w.Close()
			saved := os.Stderr
			os.Stderr = w
			defer func() { os.Stderr = saved }()

			Expect(runVM(backend.VMQemu)).To(Equal(exitHypervisorFailed), logBuf.String())
			Expect(logBuf.String()).To(ContainSubstring("port 8080 already in use in this container; VM backends run one app process per container"))
			Expect(logBuf.String()).NotTo(ContainSubstring("waiting for the hypervisor"))
		})

		It("does not blame the port for another hypervisor failure", func() {
			fakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), `echo "Could not access KVM kernel module" >&2; exit 1`)
			GinkgoT().Setenv("PORT", "8080")

			Expect(runVM(backend.VMQemu)).To(Equal(exitHypervisorFailed), logBuf.String())
			Expect(logBuf.String()).NotTo(ContainSubstring("already in use"))
		})

		It("does not blame the port when the guest ran", func() {
			// The guest reports a status, so the stderr text is not about a failed launch.
			fakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), `echo "Could not set up host forwarding rule" >&2`)
			GinkgoT().Setenv("PORT", "8080")

			Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
			Expect(logBuf.String()).NotTo(ContainSubstring("already in use"))
		})

		It("says nothing about a port when the process has none", func() {
			fakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), hostfwdError)

			Expect(runVM(backend.VMQemu)).To(Equal(exitHypervisorFailed), logBuf.String())
			Expect(logBuf.String()).NotTo(ContainSubstring("already in use"))
		})
	})
})

var _ = Describe("stderrTee", func() {
	It("copies every write to both writers", func() {
		var capture, passthrough bytes.Buffer
		tee := &stderrTee{capture: &capture, passthrough: &passthrough}
		for _, chunk := range []string{"ab", "cd"} {
			n, err := tee.Write([]byte(chunk))
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(len(chunk)))
		}
		Expect(capture.String()).To(Equal("abcd"))
		Expect(passthrough.String()).To(Equal("abcd"))
	})

	It("keeps capturing and reports success when the passthrough fails", func() {
		var capture bytes.Buffer
		tee := &stderrTee{capture: &capture, passthrough: failingWriter{err: syscall.EPIPE}}
		for _, chunk := range []string{"ab", "cd"} {
			n, err := tee.Write([]byte(chunk))
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(len(chunk)))
		}
		Expect(capture.String()).To(Equal("abcd"))
	})
})

var _ = Describe("headBuffer", func() {
	It("keeps the first bytes up to its limit and accepts the rest", func() {
		b := &headBuffer{limit: 5}
		for _, chunk := range []string{"ab", "cdefg", "hij"} {
			n, err := b.Write([]byte(chunk))
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(len(chunk)))
		}
		Expect(b.String()).To(Equal("abcde"))
	})
})
