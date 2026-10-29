//go:build linux

package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

var _ = Describe("core dumps", func() {
	var (
		art    string
		tmp    string
		logBuf *bytes.Buffer
		before unix.Rlimit
	)

	BeforeEach(func() {
		art = makeArtifacts()
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		logBuf = &bytes.Buffer{}

		// Raise this process's core limit as far as it may, so that the run
		// has a limit to lower: root may raise the hard limit again after an
		// earlier run lowered it, and anyone may raise the soft limit to the
		// hard one.
		var lim unix.Rlimit
		Expect(unix.Getrlimit(unix.RLIMIT_CORE, &lim)).To(Succeed())
		raised := unix.Rlimit{Cur: lim.Max, Max: lim.Max}
		if os.Geteuid() == 0 {
			raised = unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
		}
		Expect(unix.Setrlimit(unix.RLIMIT_CORE, &raised)).To(Succeed())
		Expect(unix.Getrlimit(unix.RLIMIT_CORE, &before)).To(Succeed())
		if os.Geteuid() == 0 {
			Expect(before.Cur).NotTo(BeZero())
		}

		// Give this process a nonzero coredump_filter, which any user may
		// set on their own process, so that every run has a filter to clear
		// whatever ran before it. The filter is put back afterwards.
		saved, err := os.ReadFile("/proc/self/coredump_filter")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			Expect(os.WriteFile("/proc/self/coredump_filter", append([]byte("0x"), bytes.TrimSpace(saved)...), 0)).To(Succeed())
		})
		Expect(os.WriteFile("/proc/self/coredump_filter", []byte("0x33"), 0)).To(Succeed())
		Expect(ownCoreDumpFilter()).To(Equal("00000033"))
	})

	runVM := func(kind backend.Kind) int {
		return run([]string{"--backend", string(kind), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}, log.New(logBuf, "", 0))
	}

	// reportLimits is fake hypervisor shell that records its own soft and
	// hard core limits and its coredump_filter in file.
	reportLimits := func(file string) string {
		return `read -r filter < /proc/self/coredump_filter
echo "$(ulimit -S -c) $(ulimit -H -c) $filter" > ` + shellQuote(file) + "\n"
	}

	// The filter check fails for any user and in any spec order if run stops
	// clearing the filter, because every run starts from a filter of 0x33.
	// The limit check proves something only when the limit starts above
	// zero. For root it always does. For anyone else it does only when the
	// tests started with a hard limit above zero and no earlier run in this
	// process has lowered it, because nothing but root can raise it again.
	It("starts both hypervisors with a core limit of zero, soft and hard, and a coredump_filter of zero, and keeps its own at zero", func() {
		for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			// Only root may raise the hard limit again after the previous
			// run lowered it; anyone else runs the second backend at zero.
			if os.Geteuid() == 0 {
				Expect(unix.Setrlimit(unix.RLIMIT_CORE, &before)).To(Succeed())
			}
			hv := "qemu/ld-linux-x86-64.so.2"
			if kind == backend.VMFirecracker {
				hv = "firecracker/firecracker"
			}
			limits := filepath.Join(art, string(kind)+".limits")
			writeFakeHypervisor(filepath.Join(art, hv), reportLimits(limits))
			Expect(runVM(kind)).To(Equal(0), logBuf.String())
			Expect(os.ReadFile(limits)).To(Equal([]byte("0 0 00000000\n")), string(kind))

			var after unix.Rlimit
			Expect(unix.Getrlimit(unix.RLIMIT_CORE, &after)).To(Succeed())
			Expect(after).To(Equal(unix.Rlimit{Cur: 0, Max: 0}), string(kind))
			Expect(ownCoreDumpFilter()).To(Equal("00000000"), string(kind))
			Expect(os.WriteFile("/proc/self/coredump_filter", []byte("0x33"), 0)).To(Succeed())
		}
	})

	It("lowers the limit and clears the filter before it parses its arguments", func() {
		Expect(runVM("nope")).To(Equal(exitLaunchError))
		var after unix.Rlimit
		Expect(unix.Getrlimit(unix.RLIMIT_CORE, &after)).To(Succeed())
		Expect(after).To(Equal(unix.Rlimit{Cur: 0, Max: 0}))
		Expect(ownCoreDumpFilter()).To(Equal("00000000"))
	})

	It("exits 125 without starting the hypervisor when it cannot disable core dumps", func() {
		saved := disableCoreDumps
		DeferCleanup(func() { disableCoreDumps = saved })
		disableCoreDumps = func() error { return errors.New("operation not permitted") }

		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal("disabling core dumps: operation not permitted\n"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("exits 125 without starting the hypervisor when it cannot write its coredump_filter", func() {
		saved := coreDumpFilterPath
		DeferCleanup(func() { coreDumpFilterPath = saved })
		coreDumpFilterPath = filepath.Join(art, "no-such-dir", "coredump_filter")

		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal("disabling core dumps: writing " + coreDumpFilterPath + ": no such file or directory\n"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("exits 125 without starting the hypervisor when the write to its coredump_filter fails", func() {
		if _, err := os.Stat("/dev/full"); err != nil {
			Skip("this system has no /dev/full")
		}
		saved := coreDumpFilterPath
		DeferCleanup(func() { coreDumpFilterPath = saved })
		coreDumpFilterPath = "/dev/full"

		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal("disabling core dumps: writing /dev/full: no space left on device\n"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("leaves guest RAM out of QEMU's core dumps", func() {
		argv := qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, nil, "")
		machine := optionAfter(argv, "-M", "microvm")
		Expect(strings.Split(machine, ",")).To(Equal([]string{"microvm", "accel=kvm", "dump-guest-core=off"}))
	})
})

// ownCoreDumpFilter returns this process's coredump_filter as the kernel
// prints it, eight hex digits.
func ownCoreDumpFilter() string {
	raw, err := os.ReadFile("/proc/self/coredump_filter")
	Expect(err).NotTo(HaveOccurred())
	return string(bytes.TrimSpace(raw))
}
