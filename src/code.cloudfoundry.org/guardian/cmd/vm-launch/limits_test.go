//go:build linux

package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"

	"code.cloudfoundry.org/guardian/backend"
)

var _ = Describe("the guest command's open files limit", func() {
	var (
		logBuf *bytes.Buffer
		logger *log.Logger
	)

	BeforeEach(func() {
		logBuf = &bytes.Buffer{}
		logger = log.New(logBuf, "", 0)
	})

	limitOf := func(soft, hard uint64) func() (unix.Rlimit, error) {
		return func() (unix.Rlimit, error) { return unix.Rlimit{Cur: soft, Max: hard}, nil }
	}

	DescribeTable("takes vm-launch's own limit, kept within what a guest can have",
		func(soft, hard uint64, want nofileLimit, logged string) {
			got, err := guestNofile(limitOf(soft, hard), logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(want))
			if logged == "" {
				Expect(logBuf.String()).To(BeEmpty())
			} else {
				Expect(logBuf.String()).To(Equal(logged))
			}
		},
		Entry("equal limits", uint64(1024), uint64(1024), nofileLimit{soft: 1024, hard: 1024}, ""),
		Entry("a soft limit below the hard one", uint64(1024), uint64(4096), nofileLimit{soft: 1024, hard: 4096}, ""),
		Entry("a hard limit above the kernel default fs.nr_open", uint64(2000000), uint64(2000000), nofileLimit{soft: 2000000, hard: 2000000}, ""),
		Entry("the highest limit a guest can have", uint64(nrOpenMax), uint64(nrOpenMax), nofileLimit{soft: nrOpenMax, hard: nrOpenMax}, ""),
		Entry("an unlimited hard limit", uint64(1024), uint64(unix.RLIM_INFINITY), nofileLimit{soft: 1024, hard: nrOpenMax},
			"the open files limit unlimited is above the 2147483584 a guest can have; the guest command gets 2147483584\n"),
		Entry("unlimited limits", uint64(unix.RLIM_INFINITY), uint64(unix.RLIM_INFINITY), nofileLimit{soft: nrOpenMax, hard: nrOpenMax},
			"the open files limit unlimited is above the 2147483584 a guest can have; the guest command gets 2147483584\n"),
		Entry("a hard limit one above the highest", uint64(1024), uint64(nrOpenMax+1), nofileLimit{soft: 1024, hard: nrOpenMax},
			"the open files limit 2147483585 is above the 2147483584 a guest can have; the guest command gets 2147483584\n"),
		Entry("a soft limit above the hard one", uint64(8192), uint64(4096), nofileLimit{soft: 4096, hard: 4096}, ""),
	)

	It("reports a limit it cannot read", func() {
		_, err := guestNofile(func() (unix.Rlimit, error) { return unix.Rlimit{}, unix.EPERM }, logger)
		Expect(err).To(MatchError("reading the open files limit: operation not permitted"))
		Expect(errors.Is(err, unix.EPERM)).To(BeTrue())
	})

	It("reads the process's own limit", func() {
		var want unix.Rlimit
		Expect(unix.Getrlimit(unix.RLIMIT_NOFILE, &want)).To(Succeed())
		Expect(getNofile()).To(Equal(want))
	})

	It("writes the limits as /rvm/limits", func() {
		Expect(limitsFile(nofileLimit{soft: 1024, hard: nrOpenMax})).To(Equal("RVM_NOFILE_SOFT=1024\nRVM_NOFILE_HARD=2147483584\n"))
	})

	It("rejects contents without an open files limit", func() {
		bb := filepath.Join(GinkgoT().TempDir(), "busybox")
		Expect(os.WriteFile(bb, []byte("busybox"), 0o755)).To(Succeed())
		held := heldInitramfs()
		g := taskGuest("true")
		g.nofile = nofileLimit{}
		_, err := newInitramfs(bb, g)
		Expect(err).To(MatchError("writing the initramfs: no open files limit"))
		Expect(heldInitramfs()).To(Equal(held))
	})
})

var _ = Describe("the open files setup of /init", func() {
	// procLimits is the process's open-files limit, which the spec's shell
	// inherits. It skips the spec under an unlimited hard limit, which
	// guestNofile never passes on.
	procLimits := func() nofileLimit {
		var r unix.Rlimit
		Expect(unix.Getrlimit(unix.RLIMIT_NOFILE, &r)).To(Succeed())
		if r.Max == unix.RLIM_INFINITY || r.Max > nrOpenMax {
			Skip("the process's hard open files limit is above what a guest can have")
		}
		return nofileLimit{soft: r.Cur, hard: r.Max}
	}

	// realNrOpen is the host kernel's fs.nr_open, which caps what a ulimit in
	// the spec's shell can set, whatever the fake fs.nr_open says.
	realNrOpen := func() uint64 {
		data, err := os.ReadFile("/proc/sys/fs/nr_open")
		Expect(err).NotTo(HaveOccurred())
		n, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		Expect(err).NotTo(HaveOccurred())
		return n
	}

	type guestProc struct {
		dir, nrOpen, fileMax string
	}

	// newGuestProc writes fake fs.nr_open and fs.file-max files, so the spec
	// never writes the host's /proc/sys.
	newGuestProc := func(nrOpen string) guestProc {
		dir := GinkgoT().TempDir()
		p := guestProc{dir: dir, nrOpen: filepath.Join(dir, "nr_open"), fileMax: filepath.Join(dir, "file-max")}
		Expect(os.WriteFile(p.nrOpen, []byte(nrOpen+"\n"), 0o644)).To(Succeed())
		Expect(os.WriteFile(p.fileMax, []byte("12345\n"), 0o644)).To(Succeed())
		return p
	}

	// runSetup runs the open-files setup and the command line of /init in
	// shell, with n as /rvm/limits, the fake proc files of p, and a command
	// that prints the limits it got. Extra replacements come first, so they
	// win over the fake paths. It returns the output and the exit status.
	runSetup := func(shell guestShell, n nofileLimit, p guestProc, extra ...string) (string, int) {
		limits := filepath.Join(p.dir, "limits")
		Expect(os.WriteFile(limits, []byte(limitsFile(n)), 0o644)).To(Succeed())
		files := guestFiles("", "echo \"soft=$(ulimit -S -n) hard=$(ulimit -H -n)\"\n")
		paths := strings.NewReplacer(append(extra,
			"/rvm/limits", limits,
			"/proc/sys/fs/nr_open", p.nrOpen,
			"/proc/sys/fs/file-max", p.fileMax,
		)...)
		script := files.Replace(paths.Replace(guestFailFunc + guestLimitsSetup + guestRunCommand))
		bin := guestBin(shell)
		// /init reads fs.nr_open with cat, which the guest's busybox runs as
		// an applet of the same binary.
		cat := shell.argv[0]
		if shell.argv[0] == hostShell().argv[0] {
			var err error
			cat, err = exec.LookPath("cat")
			Expect(err).NotTo(HaveOccurred())
		}
		Expect(os.Symlink(cat, filepath.Join(bin, "cat"))).To(Succeed())
		c := exec.Command(shell.argv[0], append(shell.argv[1:], "-c", script)...)
		c.Env = []string{"PATH=" + bin}
		out, err := c.CombinedOutput()
		if exitErr, ok := err.(*exec.ExitError); ok {
			return string(out), exitErr.ExitCode()
		}
		Expect(err).NotTo(HaveOccurred(), "%s: %s", shell.name, out)
		return string(out), 0
	}

	readProc := func(path string) string {
		data, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		return strings.TrimSpace(string(data))
	}

	DescribeTable("gives the command the limits, soft and hard, and lifts fs.file-max",
		func(shellOf func() guestShell) {
			shell := shellOf()
			own := procLimits()
			soft := min(own.hard, 256)
			p := newGuestProc("1048576")
			out, code := runSetup(shell, nofileLimit{soft: soft, hard: own.hard}, p)
			Expect(code).To(Equal(0), "%s: %s", shell.name, out)
			Expect(out).To(Equal("soft=" + strconv.FormatUint(soft, 10) + " hard=" + strconv.FormatUint(own.hard, 10) + "\n"))
			Expect(readProc(p.fileMax)).To(Equal("9223372036854775807"))
			if own.hard <= 1048576 {
				Expect(readProc(p.nrOpen)).To(Equal("1048576"))
			}
		},
		shellEntries(""),
	)

	DescribeTable("raises fs.nr_open to a hard limit above it",
		func(shellOf func() guestShell) {
			shell := shellOf()
			own := procLimits()
			if own.hard < 2 {
				Skip("the process's hard open files limit leaves no room below it")
			}
			p := newGuestProc(strconv.FormatUint(own.hard-1, 10))
			soft := min(own.hard, 64)
			out, code := runSetup(shell, nofileLimit{soft: soft, hard: own.hard}, p)
			Expect(code).To(Equal(0), "%s: %s", shell.name, out)
			Expect(readProc(p.nrOpen)).To(Equal(strconv.FormatUint(own.hard, 10)))
			Expect(out).To(Equal("soft=" + strconv.FormatUint(soft, 10) + " hard=" + strconv.FormatUint(own.hard, 10) + "\n"))
		},
		shellEntries(""),
	)

	DescribeTable("only warns when it cannot lift fs.file-max",
		func(shellOf func() guestShell) {
			shell := shellOf()
			own := procLimits()
			p := newGuestProc("1048576")
			out, code := runSetup(shell, nofileLimit{soft: own.hard, hard: own.hard}, p,
				">/proc/sys/fs/file-max", ">"+filepath.Join(p.dir, "missing", "file-max"))
			Expect(code).To(Equal(0), "%s: %s", shell.name, out)
			Expect(out).To(ContainSubstring("vm-launch guest setup: raising fs.file-max failed; keeping the default\n"))
			Expect(out).To(HaveSuffix("soft=" + strconv.FormatUint(own.hard, 10) + " hard=" + strconv.FormatUint(own.hard, 10) + "\n"))
			Expect(out).NotTo(ContainSubstring("REBOOT"))
		},
		shellEntries(""),
	)

	DescribeTable("fails setup when it cannot read fs.nr_open",
		func(shellOf func() guestShell) {
			shell := shellOf()
			own := procLimits()
			p := newGuestProc("1048576")
			Expect(os.Remove(p.nrOpen)).To(Succeed())
			out, code := runSetup(shell, nofileLimit{soft: own.hard, hard: own.hard}, p)
			Expect(code).To(Equal(1), "%s: %s", shell.name, out)
			Expect(out).To(HaveSuffix("vm-launch guest setup: reading fs.nr_open failed\nREBOOT\n"))
			Expect(out).NotTo(ContainSubstring("soft="))
		},
		shellEntries(""),
	)

	DescribeTable("fails setup when it cannot raise fs.nr_open",
		func(shellOf func() guestShell) {
			shell := shellOf()
			own := procLimits()
			if own.hard < 2 {
				Skip("the process's hard open files limit leaves no room below it")
			}
			p := newGuestProc(strconv.FormatUint(own.hard-1, 10))
			hard := strconv.FormatUint(own.hard, 10)
			out, code := runSetup(shell, nofileLimit{soft: own.hard, hard: own.hard}, p,
				">/proc/sys/fs/nr_open", ">"+filepath.Join(p.dir, "missing", "nr_open"))
			Expect(code).To(Equal(1), "%s: %s", shell.name, out)
			Expect(out).To(HaveSuffix("vm-launch guest setup: raising fs.nr_open to " + hard + " failed\nREBOOT\n"))
			Expect(out).NotTo(ContainSubstring("soft="))
		},
		shellEntries(""),
	)

	DescribeTable("fails setup when the kernel refuses the limit",
		func(shellOf func() guestShell) {
			shell := shellOf()
			nrOpen := realNrOpen()
			if nrOpen >= nrOpenMax {
				Skip("the host's fs.nr_open allows every limit")
			}
			// The fake fs.nr_open already allows the limit, so /init leaves
			// it be, and the host kernel refuses a hard limit above its own.
			over := strconv.FormatUint(nrOpen+1, 10)
			p := newGuestProc(over)
			out, code := runSetup(shell, nofileLimit{soft: nrOpen + 1, hard: nrOpen + 1}, p)
			Expect(code).To(Equal(1), "%s: %s", shell.name, out)
			Expect(out).To(ContainSubstring("vm-launch guest setup: setting the open files limit to " + over + " soft and " + over + " hard failed\nREBOOT\n"))
			Expect(out).NotTo(ContainSubstring("soft=" + over))
		},
		shellEntries(""),
	)
})

var _ = Describe("run with an open files limit", func() {
	var (
		art     string
		scratch string
		logBuf  *bytes.Buffer
	)

	BeforeEach(func() {
		art = makeArtifacts()
		scratch = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", GinkgoT().TempDir())
		logBuf = &bytes.Buffer{}
	})

	runVM := func(kind backend.Kind) int {
		return run([]string{"--backend", string(kind), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}, log.New(logBuf, "", 0))
	}

	It("gives the guest vm-launch's own limit on both backends", func() {
		orig := getNofile
		getNofile = func() (unix.Rlimit, error) { return unix.Rlimit{Cur: 2000000, Max: 2000000}, nil }
		DeferCleanup(func() { getNofile = orig })
		for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			hv := "qemu/ld-linux-x86-64.so.2"
			if kind == backend.VMFirecracker {
				hv = "firecracker/firecracker"
			}
			initrdCopy := filepath.Join(scratch, string(kind)+".initrd")
			writeFakeHypervisor(filepath.Join(art, hv), `cat "$initrd" > `+shellQuote(initrdCopy)+"\n")
			Expect(runVM(kind)).To(Equal(0), logBuf.String())
			raw, err := os.ReadFile(initrdCopy)
			Expect(err).NotTo(HaveOccurred())
			_, byName := archiveEntries(raw)
			Expect(string(byName["rvm/limits"].data)).To(Equal("RVM_NOFILE_SOFT=2000000\nRVM_NOFILE_HARD=2000000\n"), string(kind))
			Expect(byName["rvm/limits"].mode & 0o7777).To(Equal(uint32(0o644)))
		}
	})

	It("exits 125 before the hypervisor starts when it cannot read the limit", func() {
		orig := getNofile
		getNofile = func() (unix.Rlimit, error) { return unix.Rlimit{}, unix.EFAULT }
		DeferCleanup(func() { getNofile = orig })
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("reading the open files limit: bad address"))
		Expect(argvFile).NotTo(BeAnExistingFile())
	})
})
