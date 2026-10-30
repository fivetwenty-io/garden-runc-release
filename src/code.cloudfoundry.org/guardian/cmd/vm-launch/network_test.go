//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

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

	Describe("guest network files", func() {
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

		It("names the port in /rvm/net for a guest with one, so the guest can watch it", func() {
			Expect(netFile(&network{port: 8080, address: qemuGuestCIDR, gateway: qemuGateway, mtu: 9001})).To(Equal("RVM_ADDRESS='10.0.2.15/24'\nRVM_GATEWAY='10.0.2.2'\nRVM_MTU='9001'\nRVM_PORT='8080'\n"))
		})
	})

	Describe("networked initramfs", func() {
		nw := &network{
			port:       8080,
			address:    qemuGuestCIDR,
			gateway:    qemuGateway,
			resolvConf: "nameserver 10.0.2.3\n",
		}

		It("adds the network and environment files", func() {
			names, byName := archiveEntries(buildInitramfsWithEnv([]byte("busybox"), "httpd -f -p $PORT", nw, "export PORT='8080'\n", nil))
			Expect(names).To(Equal([]string{"bin", "dev", "dev/console", "dev/null", "etc", "proc", "sys", "tmp", "rvm",
				"bin/busybox", "rvm/cmd", "rvm/net", "rvm/env", "rvm/limits", "etc/resolv.conf", "rvm/listen-tick", "init", cpioTrailer}))
			Expect(byName["rvm/listen-tick"].mode).To(Equal(uint32(0o010600)))
			Expect(string(byName["rvm/net"].data)).To(Equal("RVM_ADDRESS='10.0.2.15/24'\nRVM_GATEWAY='10.0.2.2'\nRVM_PORT='8080'\n"))
			Expect(string(byName["rvm/env"].data)).To(Equal("export PORT='8080'\n"))
			Expect(byName["rvm/env"].mode).To(Equal(uint32(0o100600)))
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
				"( . /rvm/env ) || rvm_fail \"reading /rvm/env failed\"\n",
			} {
				idx := strings.Index(script, step)
				Expect(idx).To(BeNumerically(">", 0), step)
				Expect(idx).To(BeNumerically("<", start), step)
			}
			Expect(script).To(HaveSuffix("\n( { read -r rvm_self rvm_rest </proc/self/stat && echo \"$rvm_self\" >/rvm/app-pid; } || echo \"vm-launch guest: recording the command's pid in /rvm/app-pid failed; a stop request cannot reach the command\"; ulimit -n \"$RVM_NOFILE_HARD\" && ulimit -S -n \"$RVM_NOFILE_SOFT\" && . /rvm/env && exec sh -c \"$(cat /rvm/cmd)\" ) </dev/null\nrvm_status=$?\n" + guestListenStop + "echo RVM_EXIT_" + testNonce + "=$rvm_status >/dev/console || echo RVM_EXIT_" + testNonce + "=$rvm_status\nreboot -f\n"))
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
			Expect(os.MkdirAll(filepath.Join(dir, "sys/class/net/eth0"), 0o755)).To(Succeed())
			setup := strings.NewReplacer(
				"/rvm/net", filepath.Join(dir, "net"),
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

		It("gives a task the same archive and network setup as an LRP, less the port and the listen watcher's FIFO", func() {
			task := &network{address: qemuGuestCIDR, gateway: qemuGateway, resolvConf: "nameserver 10.0.2.3\n"}
			names, byName := archiveEntries(buildInitramfs([]byte("busybox"), "true", task, nil))
			lrpNames, lrp := archiveEntries(buildInitramfs([]byte("busybox"), "true", nw, nil))
			Expect(lrpNames).To(Equal(slices.Insert(slices.Clone(names), slices.Index(names, "init"), "rvm/listen-tick")))
			Expect(byName["init"].data).To(Equal(lrp["init"].data))
			Expect(string(lrp["rvm/net"].data)).To(Equal(string(byName["rvm/net"].data) + "RVM_PORT='8080'\n"))
			Expect(byName["etc/resolv.conf"].data).To(Equal(lrp["etc/resolv.conf"].data))
			Expect(byName["rvm/env"].data).To(Equal(lrp["rvm/env"].data))
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

		It("adds a user-mode NIC with no forward, and for PORT a QMP monitor on the inherited socket", func() {
			argv, err := hypervisorArgv(backend.VMQemu, art, "/unused", "/proc/self/fd/3", 128, nw, "", 4)
			Expect(err).NotTo(HaveOccurred())
			task, err := hypervisorArgv(backend.VMQemu, art, "/unused", "/proc/self/fd/3", 128, &network{}, "", 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(argv[:len(argv)-4]).To(Equal(task))
			Expect(argv[len(argv)-4:]).To(Equal([]string{
				"-chardev", "socket,id=qmp0,fd=4,server=off",
				"-mon", "chardev=qmp0,mode=control",
			}))
			Expect(task[len(task)-4:]).To(Equal([]string{
				"-netdev", "user,id=n0,net=10.0.2.0/24",
				"-device", "virtio-net-device,netdev=n0",
			}))
			Expect(strings.Join(argv, " ")).NotTo(ContainSubstring("hostfwd"))
		})

		It("refuses a QMP monitor for Firecracker", func() {
			_, err := hypervisorArgv(backend.VMFirecracker, art, GinkgoT().TempDir(), "/proc/self/fd/3", 128, nw, "", 4)
			Expect(err).To(MatchError("firecracker has no QMP monitor"))
		})

		It("attaches the Firecracker guest of an LRP and of a task to garden's tap device", func() {
			for _, n := range []*network{nw, {}} {
				work := GinkgoT().TempDir()
				argv, err := hypervisorArgv(backend.VMFirecracker, art, work, "/proc/self/fd/3", 128, n, "", 0)
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

// runVMTimeout bounds one vm-launch run in the PORT specs, each of which
// takes a few seconds.
const runVMTimeout = 30 * time.Second

var _ = Describe("run with PORT", func() {
	var (
		art    string
		tmp    string
		logBuf *safeBuffer
	)

	BeforeEach(func() {
		art = makeArtifacts()
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		logBuf = &safeBuffer{}
	})

	fakeHypervisor := writeFakeHypervisor

	freePort := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}

	// runVM runs vm-launch and fails the spec when it is still running
	// after runVMTimeout, so a broken port path fails its spec instead of
	// hanging the suite.
	runVM := func(kind backend.Kind) int {
		code := make(chan int, 1)
		go func() {
			defer GinkgoRecover()
			code <- run([]string{"--backend", string(kind), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}, log.New(logBuf, "", 0))
		}()
		var c int
		Eventually(code, runVMTimeout).Should(Receive(&c), func() string {
			return "vm-launch was still running after " + runVMTimeout.String() + "; its log so far:\n" + logBuf.String()
		})
		return c
	}

	It("exits 125 for a PORT that is not a port number", func() {
		GinkgoT().Setenv("PORT", "99999")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring(`PORT "99999" is not a TCP port number`))
	})

	// portHypervisor writes a fake hypervisor that runs body between the
	// start tag and the exit tag, with these shell functions: listen 1|0
	// writes a listen line; await open|closed waits up to 10 seconds for
	// port to accept or refuse connections; qmp_send writes a line to the
	// QMP socket; qmp_recv waits up to 10 seconds for one, reads it, and
	// appends it to the returned QMP log; and qmp_reply writes a JSON object
	// as the reply to the request qmp_recv read last, with its id. A wait
	// that runs out fails the fake hypervisor, and so the spec.
	portHypervisor := func(path string, port int, body string) (argvFile, qmpLog string) {
		argvFile = path + ".argv"
		qmpLog = path + ".qmp"
		script := `#!/bin/bash
printf '%s\n' "$@" > ` + shellQuote(argvFile) + `
qmp=
for a in "$@"; do
	case "$prev" in -initrd) initrd=$a ;; --config-file) initrd=$(sed -n 's/.*"initrd_path":"\([^"]*\)".*/\1/p' "$a") ;; esac
	case "$a" in socket,id=qmp0,fd=*) qmp=${a#socket,id=qmp0,fd=}; qmp=${qmp%%,*} ;; esac
	prev=$a
done
nonce=$(gzip -dc "$initrd" | grep -a -o 'RVM_START_[0-9a-f]*' | head -n 1 | cut -d_ -f3)
port=` + strconv.Itoa(port) + `
listen() { echo "RVM_LISTEN_${nonce}=$1"; }
probe() { (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; }
await() {
	for i in $(seq 200); do
		if probe; then got=open; else got=closed; fi
		[ "$got" = "$1" ] && return 0
		sleep 0.05
	done
	echo "port $port stayed $got, want $1" >&2
	exit 1
}
qmp_send() { printf '%s\n' "$1" >&"$qmp"; }
qmp_recv() { IFS= read -r -t 10 line <&"$qmp" || { echo "no QMP request came in 10 seconds, or the QMP socket closed" >&2; exit 1; }; qid=${line##*'"id":'}; qid=${qid%\}}; printf '%s\n' "$line" >>` + shellQuote(qmpLog) + `; }
qmp_reply() { qmp_send "{\"id\": $qid, ${1#\{}"; }
echo "RVM_START_$nonce"
` + body + `
echo "RVM_EXIT_$nonce=0"
`
		Expect(os.Remove(path)).To(Succeed())
		Expect(os.WriteFile(path, []byte(script), 0o755)).To(Succeed())
		return argvFile, qmpLog
	}

	qmpGreeting := `qmp_send '{"QMP": {"version": {}, "capabilities": []}}'` + "\n"
	qmpCapabilities := `{"execute":"qmp_capabilities","id":1}`
	hostfwdAdd := func(id, port int) string {
		return fmt.Sprintf(`{"arguments":{"command-line":"hostfwd_add n0 tcp:0.0.0.0:%d-10.0.2.15:%d"},"execute":"human-monitor-command","id":%d}`, port, port, id)
	}
	hostfwdRemove := func(id, port int) string {
		return fmt.Sprintf(`{"arguments":{"command-line":"hostfwd_remove n0 tcp:0.0.0.0:%d"},"execute":"human-monitor-command","id":%d}`, port, id)
	}

	It("gives QEMU a QMP monitor and no forwarding rule for PORT, and neither without PORT", func() {
		port := freePort()
		argvFile, _ := portHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), port, "")
		GinkgoT().Setenv("PORT", strconv.Itoa(port))
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		withPort, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(withPort)).To(ContainSubstring("\n-netdev\nuser,id=n0,net=10.0.2.0/24\n-device\nvirtio-net-device,netdev=n0\n-chardev\nsocket,id=qmp0,fd=4,server=off\n-mon\nchardev=qmp0,mode=control\n"))
		Expect(string(withPort)).NotTo(ContainSubstring("hostfwd"))

		Expect(os.Unsetenv("PORT")).To(Succeed())
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		withoutPort, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(withoutPort)).To(HaveSuffix("\n-netdev\nuser,id=n0,net=10.0.2.0/24\n-device\nvirtio-net-device,netdev=n0\n"))
		Expect(string(withoutPort)).NotTo(ContainSubstring("qmp"))
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
		Expect(logBuf.String()).NotTo(ContainSubstring("listen"))
	})

	It("sees the Firecracker port proxy with the same check, so the task spec above can fail", func() {
		port := freePort()
		portHypervisor(filepath.Join(art, "firecracker/firecracker"), port, `listen 1
await open
`+vmLaunchListeners+`[ -n "$listening" ] || { echo "no listener found" >&2; exit 1; }
`)
		GinkgoT().Setenv("PORT", strconv.Itoa(port))
		Expect(runVM(backend.VMFirecracker)).To(Equal(0), logBuf.String())
	})

	It("keeps PORT closed for Firecracker until the guest listens, follows the guest after that, and closes it at exit", func() {
		port := freePort()
		argvFile, _ := portHypervisor(filepath.Join(art, "firecracker/firecracker"), port, `await closed
`+vmLaunchListeners+`[ -z "$listening" ] || { echo "vm-launch listens on socket$listening before the guest does" >&2; exit 1; }
listen 1
await open
listen 0
await closed
listen 1
await open
`)
		GinkgoT().Setenv("PORT", strconv.Itoa(port))

		Expect(runVM(backend.VMFirecracker)).To(Equal(0), logBuf.String())
		Expect(gateLoops()).To(BeZero())
		Expect(os.ReadFile(argvFile)).To(ContainSubstring("--config-file"))
		_, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		Expect(err).To(HaveOccurred())
		p := strconv.Itoa(port)
		Expect(strings.Count(logBuf.String(), "the guest listens on port "+p+"; it is open in the container\n")).To(Equal(2), logBuf.String())
		Expect(strings.Count(logBuf.String(), "the guest no longer listens on port "+p+"; it is closed in the container\n")).To(Equal(1), logBuf.String())
		Expect(logBuf.String()).To(HaveSuffix("the guest has stopped, so port " + p + " closes in the container\n"))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("logs that an open port closes before its exit line when the hypervisor stops", func() {
		port := freePort()
		p := strconv.Itoa(port)
		portHypervisor(filepath.Join(art, "firecracker/firecracker"), port, `listen 1
await open
exit 3
`)
		GinkgoT().Setenv("PORT", p)

		Expect(runVM(backend.VMFirecracker)).To(Equal(exitHypervisorFailed), logBuf.String())
		Expect(logBuf.String()).To(HaveSuffix("the guest listens on port " + p + "; it is open in the container\n" +
			"the guest has stopped, so port " + p + " closes in the container\n" +
			"hypervisor failed with exit status 3 before the guest reported a status; exiting " + strconv.Itoa(exitHypervisorFailed) + "\n"))
	})

	It("adds QEMU's forwarding rule when the guest listens and removes it when it stops", func() {
		port := freePort()
		_, qmpLog := portHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), port, qmpGreeting+`await closed
listen 1
qmp_recv
qmp_reply '{"return": {}}'
qmp_recv
qmp_send '{"timestamp": {"seconds": 1, "microseconds": 2}, "event": "NIC_RX_FILTER_CHANGED", "data": {}}'
qmp_reply '{"return": ""}'
listen 0
qmp_recv
qmp_reply '{"return": "host forwarding rule for tcp:0.0.0.0:`+strconv.Itoa(port)+` removed\r\n"}'
sleep 0.3
`)
		GinkgoT().Setenv("PORT", strconv.Itoa(port))

		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		Expect(gateLoops()).To(BeZero())
		Expect(os.ReadFile(qmpLog)).To(Equal([]byte(qmpCapabilities + "\n" + hostfwdAdd(2, port) + "\n" + hostfwdRemove(3, port) + "\n")))
		p := strconv.Itoa(port)
		Expect(logBuf.String()).To(ContainSubstring("the guest listens on port " + p + "; it is open in the container\n"))
		Expect(logBuf.String()).To(ContainSubstring("the guest no longer listens on port " + p + "; it is closed in the container\n"))
		Expect(logBuf.String()).NotTo(ContainSubstring("closes in the container"))
		Expect(logBuf.String()).NotTo(ContainSubstring("QMP"))
	})

	It("removes QEMU's forwarding rule at SIGTERM while the hypervisor still runs", func() {
		port := freePort()
		p := strconv.Itoa(port)
		// The fake QEMU ignores the SIGTERM that vm-launch passes on, so
		// only the gate's shutDown at the signal can remove the rule.
		_, qmpLog := portHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), port, `trap '' TERM
`+qmpGreeting+`listen 1
qmp_recv
qmp_reply '{"return": {}}'
qmp_recv
qmp_reply '{"return": ""}'
kill -TERM "$PPID"
qmp_recv
qmp_reply '{"return": "host forwarding rule for tcp:0.0.0.0:`+p+` removed\r\n"}'
exit 0
`)
		// vm-launch runs in a helper process, which the signal stops in
		// place of this test process.
		ctx, cancel := context.WithTimeout(context.Background(), runVMTimeout)
		defer cancel()
		var stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Env = []string{helperArtifacts + "=" + art, "PORT=" + p, "TMPDIR=" + tmp, "PATH=" + os.Getenv("PATH")}
		cmd.Stderr = &stderr
		err := cmd.Run()
		Expect(ctx.Err()).NotTo(HaveOccurred(), "vm-launch was still running after %v; its log so far:\n%s", runVMTimeout, stderr.String())
		Expect(err).To(HaveOccurred(), stderr.String())
		Expect(cmd.ProcessState.Sys().(syscall.WaitStatus).Signaled()).To(BeFalse(), stderr.String())
		Expect(cmd.ProcessState.ExitCode()).To(Equal(143), stderr.String())
		Expect(os.ReadFile(qmpLog)).To(Equal([]byte(qmpCapabilities + "\n" + hostfwdAdd(2, port) + "\n" + hostfwdRemove(3, port) + "\n")))
		// The gate logs the open while the signal comes, so either line may
		// come first. The close follows both, and is logged at shutDown, or
		// at the gate's end when QEMU exits before the gate reads the reply.
		lines := strings.SplitAfter(stderr.String(), "\n")
		opened := slices.Index(lines, "vm-launch: the guest listens on port "+p+"; it is open in the container\n")
		received := slices.Index(lines, "vm-launch: received terminated, forwarding it to the hypervisor\n")
		closed := slices.IndexFunc(lines, func(l string) bool {
			return l == "vm-launch: vm-launch is stopping; port "+p+" is closed in the container\n" ||
				l == "vm-launch: the guest has stopped, so port "+p+" closes in the container\n"
		})
		Expect([]int{opened, received, closed}).NotTo(ContainElement(-1), stderr.String())
		Expect(closed).To(BeNumerically(">", max(opened, received)), stderr.String())
		Expect(strings.Count(stderr.String(), "it is open in the container")).To(Equal(1), stderr.String())
		Expect(strings.Count(stderr.String(), "closed in the container")+strings.Count(stderr.String(), "closes in the container")).To(Equal(1), stderr.String())
		Expect(stderr.String()).To(HaveSuffix("\nvm-launch: stopped by terminated before the guest reported a status; exiting 143\n"))
	})

	It("names the port conflict when QEMU cannot add the forwarding rule, and keeps the guest running", func() {
		port := freePort()
		p := strconv.Itoa(port)
		_, qmpLog := portHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), port, qmpGreeting+`listen 1
qmp_recv
qmp_reply '{"return": {}}'
qmp_recv
qmp_reply '{"return": "Could not set up host forwarding rule '"'"'tcp:0.0.0.0:`+p+`-10.0.2.15:`+p+`'"'"'\r\n"}'
sleep 0.3
`)
		GinkgoT().Setenv("PORT", p)

		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		Expect(os.ReadFile(qmpLog)).To(Equal([]byte(qmpCapabilities + "\n" + hostfwdAdd(2, port) + "\n")))
		Expect(logBuf.String()).To(ContainSubstring("the guest listens on port " + p + ", but vm-launch could not open it in the container: QEMU could not set up the forwarding rule: Could not set up host forwarding rule 'tcp:0.0.0.0:" + p + "-10.0.2.15:" + p + "'\n"))
		Expect(logBuf.String()).To(ContainSubstring("port " + p + " already in use in this container; VM backends run one app process per container\n"))
		Expect(logBuf.String()).NotTo(ContainSubstring("it is open in the container"))
	})

	It("logs a QMP error, keeps the port closed, and opens it at the next try", func() {
		port := freePort()
		p := strconv.Itoa(port)
		_, qmpLog := portHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), port, qmpGreeting+`listen 1
qmp_recv
qmp_reply '{"return": {}}'
qmp_recv
qmp_reply '{"error": {"class": "GenericError", "desc": "no such netdev"}}'
qmp_recv
qmp_reply '{"return": "host forwarding rule for tcp:0.0.0.0:`+p+` not found\r\n"}'
qmp_recv
qmp_reply '{"return": ""}'
sleep 0.3
`)
		GinkgoT().Setenv("PORT", p)

		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		Expect(os.ReadFile(qmpLog)).To(Equal([]byte(qmpCapabilities + "\n" + hostfwdAdd(2, port) + "\n" + hostfwdRemove(3, port) + "\n" + hostfwdAdd(4, port) + "\n")))
		Expect(logBuf.String()).To(ContainSubstring("could not open it in the container: QMP human-monitor-command: GenericError: no such netdev\n"))
		Expect(logBuf.String()).To(ContainSubstring("the guest listens on port " + p + "; it is open in the container\n"))
		Expect(logBuf.String()).NotTo(ContainSubstring("already in use"))
	})

	DescribeTable("exits 125 before the hypervisor starts when another process listens on PORT",
		func(kind backend.Kind, hv string) {
			l, err := net.Listen("tcp", "0.0.0.0:0")
			Expect(err).NotTo(HaveOccurred())
			defer l.Close()
			port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
			argvFile := fakeHypervisor(filepath.Join(art, hv), "")
			GinkgoT().Setenv("PORT", port)

			Expect(runVM(kind)).To(Equal(exitLaunchError))
			Expect(logBuf.String()).To(ContainSubstring("reserving port " + port + ": bind: address already in use\n"))
			Expect(logBuf.String()).To(ContainSubstring("port " + port + " already in use in this container; VM backends run one app process per container\n"))
			Expect(argvFile).NotTo(BeAnExistingFile())
			Expect(os.ReadDir(tmp)).To(BeEmpty())
		},
		Entry("QEMU", backend.VMQemu, "qemu/ld-linux-x86-64.so.2"),
		Entry("Firecracker", backend.VMFirecracker, "firecracker/firecracker"),
	)

	DescribeTable("exits 125 before the hypervisor starts when another vm-launch holds PORT",
		func(kind backend.Kind, hv string) {
			port := freePort()
			held, err := reservePort(port)
			Expect(err).NotTo(HaveOccurred())
			defer held.Close()
			argvFile := fakeHypervisor(filepath.Join(art, hv), "")
			GinkgoT().Setenv("PORT", strconv.Itoa(port))

			Expect(runVM(kind)).To(Equal(exitLaunchError))
			Expect(logBuf.String()).To(ContainSubstring("reserving port " + strconv.Itoa(port) + ": listen unix @vm-launch-port-" + strconv.Itoa(port) + ": bind: address already in use\n"))
			Expect(logBuf.String()).To(ContainSubstring("already in use in this container"))
			Expect(argvFile).NotTo(BeAnExistingFile())
		},
		Entry("QEMU", backend.VMQemu, "qemu/ld-linux-x86-64.so.2"),
		Entry("Firecracker", backend.VMFirecracker, "firecracker/firecracker"),
	)

	It("releases PORT when it exits", func() {
		port := freePort()
		fakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		GinkgoT().Setenv("PORT", strconv.Itoa(port))
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		r, err := reservePort(port)
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Close()).To(Succeed())
	})

	It("says nothing about a port when the process has none", func() {
		fakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "echo RVM_LISTEN_${nonce}=1")
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		Expect(logBuf.String()).NotTo(ContainSubstring("port"))
	})
})
