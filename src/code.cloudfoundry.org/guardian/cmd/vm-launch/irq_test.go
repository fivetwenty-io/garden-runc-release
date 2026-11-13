//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("the guest's interrupt placement", func() {
	// guestInterrupts is /proc/interrupts of a QEMU guest whose kernel put
	// the network device (virtio0) and the console on the same vCPU, with a
	// virtio10 line to show that a device name matches whole.
	const guestInterrupts = `           CPU0       CPU1
 49:          0         25  IO-APIC  23-fasteoi   virtio0
 50:         42          0  IO-APIC  22-fasteoi   virtio1
 55:          0         80  IO-APIC   4-edge      ttyS0
 60:          0          3  IO-APIC  17-fasteoi   virtio10
NMI:          0          0   Non-maskable interrupts
`

	type fakeGuest struct {
		dir, interrupts, online, netDriver, irq string
	}

	// newFakeGuest writes /proc/interrupts, the online vCPUs, the virtio-net
	// driver's devices, and an affinity file for each interrupt in irqs, so
	// the spec never touches the host's interrupts.
	newFakeGuest := func(online string, netDevices, irqs []string) fakeGuest {
		dir := GinkgoT().TempDir()
		g := fakeGuest{
			dir:        dir,
			interrupts: filepath.Join(dir, "interrupts"),
			online:     filepath.Join(dir, "online"),
			netDriver:  filepath.Join(dir, "virtio_net"),
			irq:        filepath.Join(dir, "irq"),
		}
		Expect(os.WriteFile(g.interrupts, []byte(guestInterrupts), 0o644)).To(Succeed())
		Expect(os.WriteFile(g.online, []byte(online+"\n"), 0o644)).To(Succeed())
		Expect(os.MkdirAll(g.netDriver, 0o755)).To(Succeed())
		for _, d := range netDevices {
			Expect(os.Mkdir(filepath.Join(g.netDriver, d), 0o755)).To(Succeed())
		}
		for _, n := range irqs {
			Expect(os.MkdirAll(filepath.Join(g.irq, n), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(g.irq, n, "smp_affinity_list"), []byte("0-1\n"), 0o644)).To(Succeed())
		}
		return g
	}

	runSetup := func(shell guestShell, g fakeGuest) (string, int) {
		script := strings.NewReplacer(
			"/proc/interrupts", g.interrupts,
			"/sys/devices/system/cpu/online", g.online,
			"/sys/bus/virtio/drivers/virtio_net", g.netDriver,
			"/proc/irq/", g.irq+"/",
		).Replace(guestIRQSetup + "echo setup-done\n")
		c := exec.Command(shell.argv[0], append(shell.argv[1:], "-c", script)...)
		c.Env = []string{"PATH=" + guestBin(shell)}
		out, err := c.CombinedOutput()
		if exitErr, ok := err.(*exec.ExitError); ok {
			return string(out), exitErr.ExitCode()
		}
		Expect(err).NotTo(HaveOccurred(), "%s: %s", shell.name, out)
		return string(out), 0
	}

	affinity := func(g fakeGuest, n string) string {
		data, err := os.ReadFile(filepath.Join(g.irq, n, "smp_affinity_list"))
		Expect(err).NotTo(HaveOccurred())
		return strings.TrimSpace(string(data))
	}

	DescribeTable("pins the console to the first vCPU and the network to the last",
		func(shellOf func() guestShell) {
			shell := shellOf()
			g := newFakeGuest("0-1", []string{"virtio0"}, []string{"49", "50", "55", "60"})
			out, code := runSetup(shell, g)
			Expect(code).To(Equal(0), "%s: %s", shell.name, out)
			Expect(out).To(Equal("setup-done\n"))
			Expect(affinity(g, "55")).To(Equal("0"))
			Expect(affinity(g, "49")).To(Equal("1"))
			Expect(affinity(g, "50")).To(Equal("0-1"))
			Expect(affinity(g, "60")).To(Equal("0-1"))
		},
		shellEntries(""),
	)

	DescribeTable("matches a device's interrupt by its whole name",
		func(shellOf func() guestShell) {
			shell := shellOf()
			g := newFakeGuest("0-3", []string{"virtio1"}, []string{"49", "50", "55", "60"})
			out, code := runSetup(shell, g)
			Expect(code).To(Equal(0), "%s: %s", shell.name, out)
			Expect(affinity(g, "50")).To(Equal("3"))
			Expect(affinity(g, "60")).To(Equal("0-1"))
			Expect(affinity(g, "49")).To(Equal("0-1"))
		},
		shellEntries(""),
	)

	DescribeTable("leaves a guest with one vCPU as the kernel placed it",
		func(shellOf func() guestShell) {
			shell := shellOf()
			g := newFakeGuest("0", []string{"virtio0"}, []string{"49", "55"})
			out, code := runSetup(shell, g)
			Expect(code).To(Equal(0), "%s: %s", shell.name, out)
			Expect(out).To(Equal("setup-done\n"))
			Expect(affinity(g, "49")).To(Equal("0-1"))
			Expect(affinity(g, "55")).To(Equal("0-1"))
		},
		shellEntries(""),
	)

	DescribeTable("warns and carries on when the kernel refuses a pin",
		func(shellOf func() guestShell) {
			shell := shellOf()
			g := newFakeGuest("0-1", []string{"virtio0"}, []string{"49"})
			out, code := runSetup(shell, g)
			Expect(code).To(Equal(0), "%s: %s", shell.name, out)
			Expect(out).To(Equal("vm-launch guest setup: pinning interrupt 55 (ttyS0) to vCPU 0 failed; the kernel keeps its own placement\nsetup-done\n"))
			Expect(affinity(g, "49")).To(Equal("1"))
		},
		shellEntries(""),
	)

	It("runs in stage 2 after the limits and before the environment checks", func() {
		for _, stack := range []bool{false, true} {
			script := stage2Script(testNonce, false, stack, "", "")
			Expect(script).To(ContainSubstring(guestLimitsSetup + guestIRQSetup + guestEnvChecks))
		}
	})
})
