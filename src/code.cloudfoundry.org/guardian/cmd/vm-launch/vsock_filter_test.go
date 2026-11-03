//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// helperDenyVsock makes this test binary run "vm-launch deny-vsock" with its
// arguments, and without the mark in the command's environment. With the
// value "probe", the command gets helperVsockProbe instead. helperVsockProbe
// makes the binary report, one line each, what creating a socket in each of
// vsockProbeDomains gives, what io_uring_setup(2) gives, and how many seccomp
// filters it runs under.
const (
	helperDenyVsock  = "VM_LAUNCH_TEST_DENY_VSOCK"
	helperVsockProbe = "VM_LAUNCH_TEST_VSOCK_PROBE"
)

// vsockProbeDomains are the domains that the probe tries: AF_VSOCK, AF_VSOCK
// with high bits that the kernel drops, and three domains that stay open.
var vsockProbeDomains = []struct {
	name   string
	domain uint64
}{
	{"vsock", afVsock},
	{"vsock-high", 1<<32 | afVsock},
	{"vsock-all-high", 0xffffffff<<32 | afVsock},
	{"unix", unix.AF_UNIX},
	{"inet", unix.AF_INET},
	{"inet6", unix.AF_INET6},
}

// vsockProbe is the helperVsockProbe process. It makes the call itself, so
// that the high bits of the domain reach the kernel.
func vsockProbe() int {
	for _, d := range vsockProbeDomains {
		fd, _, errno := unix.RawSyscall(unix.SYS_SOCKET, uintptr(d.domain), unix.SOCK_STREAM, 0)
		if errno != 0 {
			fmt.Printf("%s=%s\n", d.name, unix.ErrnoName(errno))
			continue
		}
		_ = unix.Close(int(fd))
		fmt.Printf("%s=ok\n", d.name)
	}
	var params [120]byte
	fd, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params[0])), 0)
	if errno != 0 {
		fmt.Printf("io_uring=%s\n", unix.ErrnoName(errno))
	} else {
		_ = unix.Close(int(fd))
		fmt.Println("io_uring=ok")
	}
	filters, err := seccompFilters("/proc/self/status")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 99
	}
	fmt.Printf("filters=%d\n", filters)
	return 0
}

// seccompFilters reads the number of seccomp filters that a thread runs
// under from its status file.
func seccompFilters(status string) (int, error) {
	b, err := os.ReadFile(status)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Seccomp_filters:"); ok {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return 0, fmt.Errorf("%s has no Seccomp_filters line", status)
}

// denyVsockHelper is the helperDenyVsock process.
func denyVsockHelper() int {
	then := os.Getenv(helperDenyVsock)
	if err := os.Unsetenv(helperDenyVsock); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 99
	}
	if then == "probe" {
		if err := os.Setenv(helperVsockProbe, "1"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 99
		}
	}
	return runDenyVsock(os.Args[1:])
}

// probeEnv is the environment of a probe, without the deny-vsock helper's
// mark, so that the command it execs probes instead.
func probeEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, helperDenyVsock+"=") {
			env = append(env, kv)
		}
	}
	return append(env, helperVsockProbe+"=1")
}

// probeResults parses the probe's lines.
func probeResults(out string) map[string]string {
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		name, result, ok := strings.Cut(line, "=")
		if ok {
			got[name] = result
		}
	}
	return got
}

// requireKernelSpecs makes a kernel check that this environment cannot make
// fail rather than pass with a loud note. The privileged suite, whose
// container runs without a seccomp profile of its own, makes every check.
const requireKernelSpecs = "VM_LAUNCH_REQUIRE_KERNEL_SPECS"

// vacuous notes that the environment refuses what a kernel check expects
// the filter to refuse, so that the check cannot tell the filter's EPERM from
// the environment's. The filter count still shows that the filter took.
func vacuous(what string) {
	GinkgoHelper()
	msg := fmt.Sprintf("VACUOUS KERNEL CHECK: this environment already refuses %s with EPERM, so only the filter count shows that the filter took. The privileged suite checks it, and %s=1 turns this note into a failure.", what, requireKernelSpecs)
	if os.Getenv(requireKernelSpecs) != "" {
		Fail(msg)
	}
	AddReportEntry("vacuous kernel check", msg)
	fmt.Fprintln(os.Stderr, msg)
}

// unfilteredProbe returns what the probe finds without the vsock filter,
// which is what the environment the specs run in allows.
func unfilteredProbe() map[string]string {
	GinkgoHelper()
	self, err := os.Executable()
	Expect(err).NotTo(HaveOccurred())
	cmd := exec.Command(self)
	cmd.Env = probeEnv()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	Expect(err).NotTo(HaveOccurred(), stderr.String())
	got := probeResults(string(out))
	Expect(got).To(HaveKey("filters"))
	return got
}

// expectDenied checks that got is what the probe finds under the filter,
// given unfiltered, what it finds without it: one filter more, EPERM for
// AF_VSOCK whatever the high bits of the domain and for io_uring_setup(2),
// and the other domains open.
func expectDenied(got, unfiltered map[string]string) {
	GinkgoHelper()
	before, err := strconv.Atoi(unfiltered["filters"])
	Expect(err).NotTo(HaveOccurred())
	Expect(got["filters"]).To(Equal(strconv.Itoa(before+1)), "the filter did not take")
	for _, name := range []string{"vsock", "vsock-high", "vsock-all-high", "io_uring"} {
		Expect(got[name]).To(Equal("EPERM"), name)
	}
	for _, name := range []string{"unix", "inet", "inet6"} {
		Expect(got[name]).To(Equal("ok"), name)
	}
	if unfiltered["vsock"] == "EPERM" {
		vacuous("socket(AF_VSOCK)")
	}
	if unfiltered["io_uring"] == "EPERM" {
		vacuous("io_uring_setup(2)")
	}
}

// threadFilters returns the number of seccomp filters of each thread of
// this process.
func threadFilters() map[string]int {
	GinkgoHelper()
	tasks, err := os.ReadDir("/proc/self/task")
	Expect(err).NotTo(HaveOccurred())
	counts := map[string]int{}
	for _, task := range tasks {
		n, err := seccompFilters(filepath.Join("/proc/self/task", task.Name(), "status"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		Expect(err).NotTo(HaveOccurred())
		counts[task.Name()] = n
	}
	return counts
}

var _ = Describe("the vsock filter", func() {
	// seccompData lays out struct seccomp_data for bpf.VM, which loads
	// words big-endian where the kernel loads them in the machine's order,
	// so each 32-bit word is written big-endian at its offset.
	seccompData := func(arch, nr uint32, arg0 uint64) []byte {
		b := make([]byte, 64)
		binary.BigEndian.PutUint32(b[seccompDataNr:], nr)
		binary.BigEndian.PutUint32(b[seccompDataArch:], arch)
		binary.BigEndian.PutUint32(b[seccompDataArg0Low:], uint32(arg0))
		binary.BigEndian.PutUint32(b[seccompDataArg0Low+4:], uint32(arg0>>32))
		return b
	}
	const deny = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	const allow = uint32(unix.SECCOMP_RET_ALLOW)
	var vm *bpf.VM

	BeforeEach(func() {
		var err error
		vm, err = bpf.NewVM(vsockFilter())
		Expect(err).NotTo(HaveOccurred())
	})

	verdict := func(arch, nr uint32, arg0 uint64) uint32 {
		v, err := vm.Run(seccompData(arch, nr, arg0))
		Expect(err).NotTo(HaveOccurred())
		return uint32(v)
	}

	It("assembles into a program the kernel takes", func() {
		raw, err := bpf.Assemble(vsockFilter())
		Expect(err).NotTo(HaveOccurred())
		Expect(len(raw)).To(BeNumerically("<=", unix.BPF_MAXINSNS))
	})

	It("denies socket(AF_VSOCK) on every architecture it knows, whatever the high bits of the domain", func() {
		for _, a := range vsockFilterArches {
			for _, nr := range a.socket {
				for _, domain := range []uint64{afVsock, 1<<32 | afVsock, 0xffffffff<<32 | afVsock} {
					Expect(verdict(a.arch, nr, domain)).To(Equal(deny), "arch %#x call %d domain %#x", a.arch, nr, domain)
				}
			}
		}
	})

	It("allows a socket in every other domain", func() {
		for _, a := range vsockFilterArches {
			for _, nr := range a.socket {
				for domain := uint64(0); domain < 4096; domain++ {
					if domain == afVsock {
						continue
					}
					Expect(verdict(a.arch, nr, domain)).To(Equal(allow), "arch %#x call %d domain %d", a.arch, nr, domain)
					Expect(verdict(a.arch, nr, 1<<32|domain)).To(Equal(allow), "arch %#x call %d domain %#x", a.arch, nr, 1<<32|domain)
				}
			}
		}
	})

	It("denies io_uring_setup(2) on every architecture it knows, whatever its arguments", func() {
		for _, a := range vsockFilterArches {
			Expect(a.ioUringSetup).NotTo(BeEmpty())
			for _, nr := range a.ioUringSetup {
				for _, arg0 := range []uint64{0, 1, 4096, afVsock} {
					Expect(verdict(a.arch, nr, arg0)).To(Equal(deny), "arch %#x call %d", a.arch, nr)
				}
			}
		}
		Expect(verdict(nativeAuditArch(), unix.SYS_IO_URING_SETUP, 1)).To(Equal(deny))
		Expect(verdict(unix.AUDIT_ARCH_X86_64, x32SyscallBit|425, 1)).To(Equal(deny))
	})

	It("allows every other call, even with AF_VSOCK as its first argument", func() {
		for _, a := range vsockFilterArches {
			for nr := uint32(0); nr < 1024; nr++ {
				if containsNr(a.socket, nr) || containsNr(a.ioUringSetup, nr) || nr == a.socketcall && a.socketcall != 0 {
					continue
				}
				Expect(verdict(a.arch, nr, afVsock)).To(Equal(allow), "arch %#x call %d", a.arch, nr)
			}
		}
	})

	It("denies an i386 socketcall that creates a socket, and allows the rest", func() {
		Expect(verdict(unix.AUDIT_ARCH_I386, 102, sysSocketcallSocket)).To(Equal(deny))
		for call := uint64(2); call <= 20; call++ {
			Expect(verdict(unix.AUDIT_ARCH_I386, 102, call)).To(Equal(allow), "socketcall %d", call)
		}
	})

	It("knows the x86-64 numbers of socket(2), in both of its calling conventions", func() {
		Expect(verdict(unix.AUDIT_ARCH_X86_64, 41, afVsock)).To(Equal(deny))
		Expect(verdict(unix.AUDIT_ARCH_X86_64, x32SyscallBit|41, afVsock)).To(Equal(deny))
		Expect(verdict(unix.AUDIT_ARCH_X86_64, 198, afVsock)).To(Equal(allow))
		Expect(verdict(unix.AUDIT_ARCH_AARCH64, 41, afVsock)).To(Equal(allow))
	})

	It("knows this machine's number of socket(2)", func() {
		Expect(verdict(nativeAuditArch(), unix.SYS_SOCKET, afVsock)).To(Equal(deny))
	})

	It("leaves the calls of an architecture it does not know to the filters already installed", func() {
		const riscv64 = 0xc00000f3
		Expect(verdict(riscv64, 198, afVsock)).To(Equal(allow))
		Expect(verdict(riscv64, 41, afVsock)).To(Equal(allow))
	})
})

// containsNr reports whether nrs holds nr.
func containsNr(nrs []uint32, nr uint32) bool {
	for _, n := range nrs {
		if n == nr {
			return true
		}
	}
	return false
}

// nativeAuditArch is the audit architecture of this test binary.
func nativeAuditArch() uint32 {
	switch {
	case unix.SYS_SOCKET == 41:
		return unix.AUDIT_ARCH_X86_64
	case unix.SYS_SOCKET == 198:
		return unix.AUDIT_ARCH_AARCH64
	}
	Fail(fmt.Sprintf("no audit architecture for socket(2) numbered %d", unix.SYS_SOCKET))
	return 0
}

var _ = Describe("withVsockDenial", func() {
	It("leaves prepare as it is when vsock is not denied", func() {
		Expect(withVsockDenial(nil, false)).To(BeNil())
		calls := 0
		prepare := withVsockDenial(func() error { calls++; return nil }, false)
		Expect(prepare()).To(Succeed())
		Expect(calls).To(Equal(1))
	})

	It("runs prepare first and stops at its failure", func() {
		failure := errors.New("no capabilities to drop")
		Expect(withVsockDenial(func() error { return failure }, true)()).To(MatchError(failure))
	})

	It("reports a filter that did not take as a failure to deny vsock, not to confine capabilities", func() {
		cmd := exec.Command("/bin/true")
		_, err := startConfinedAs(cmd, func() error { return vsockDenialError{err: errors.New("installing the vsock filter: no")} }, "the probe")
		Expect(err).To(MatchError("denying vsock sockets to the probe: installing the vsock filter: no"))

		_, err = startConfinedAs(cmd, func() error { return errors.New("no capabilities") }, "the probe")
		Expect(err).To(MatchError("confining the probe's capabilities: no capabilities"))
	})

	It("takes --deny-child-vsock, which is off without it", func() {
		cfg, err := parseArgs([]string{"--backend", "vm-qemu", "--", "true"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.denyChildVsock).To(BeFalse())
		cfg, err = parseArgs([]string{"--backend", "vm-qemu", "--" + guestAgentFlag, "--" + denyChildVsockFlag, "--", "true"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.denyChildVsock).To(BeTrue())
		Expect(usage).To(ContainSubstring("[--" + denyChildVsockFlag + "]"))
	})
})

var _ = Describe("seccompInstalled", func() {
	It("takes a filter as installed only when the call returns 0 without an errno", func() {
		Expect(seccompInstalled(0, 0)).To(Succeed())
		Expect(seccompInstalled(0, unix.EINVAL)).To(MatchError(ContainSubstring("invalid argument")))
	})

	// With TSYNC, seccomp(2) returns the id of a thread that cannot take the
	// filter, installs it on no thread, and sets no errno.
	It("takes a thread id back from a TSYNC install as a failure", func() {
		Expect(seccompInstalled(4242, 0)).To(MatchError("installing the vsock filter: thread 4242 could not take it, so no thread has it"))
	})
})

var _ = Describe("vm-launch deny-vsock", func() {
	It("is the command that dispatch runs it under", func() {
		Expect(dispatch([]string{denyVsockCommand}, nil)).To(Equal(exitDenyVsockFailed))
	})

	It("refuses to run without -- and a command", func() {
		Expect(runDenyVsock(nil)).To(Equal(exitDenyVsockFailed))
		Expect(runDenyVsock([]string{"--"})).To(Equal(exitDenyVsockFailed))
		Expect(runDenyVsock([]string{"/bin/true"})).To(Equal(exitDenyVsockFailed))
	})

	It("exits 127, as a shell does, when there is no such command", func() {
		Expect(runDenyVsock([]string{"--", "/nonexistent/command"})).To(Equal(exitDenyVsockNoExec))
		Expect(runDenyVsock([]string{"--", "no-such-command-on-any-path"})).To(Equal(exitDenyVsockNoExec))
	})

	It("execs the command unable to create a vsock socket or an io_uring, and able to create any other socket", func() {
		unfiltered := unfilteredProbe()
		self, err := os.Executable()
		Expect(err).NotTo(HaveOccurred())
		cmd := exec.Command(self, "--", self, "probe-argument")
		cmd.Env = append(os.Environ(), helperDenyVsock+"=probe")
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		Expect(err).NotTo(HaveOccurred(), stderr.String())
		expectDenied(probeResults(string(out)), unfiltered)
	})

	It("execs the command under its name on the PATH, with the environment it was given", func() {
		cmd := exec.Command("/bin/sh", "-c", `exec "$SELF" -- sh -c 'echo "$MARK"'`)
		self, err := os.Executable()
		Expect(err).NotTo(HaveOccurred())
		cmd.Env = append(os.Environ(), helperDenyVsock+"=1", "SELF="+self, "MARK=passed through")
		out, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(out))
		Expect(string(out)).To(Equal("passed through\n"))
	})
})

var _ = Describe("a child that vm-launch starts unable to create a vsock socket", func() {
	It("gets the filter while vm-launch keeps the call", func() {
		unfiltered := unfilteredProbe()
		ownBefore := threadFilters()
		_, ownErrBefore := unix.Socket(afVsock, unix.SOCK_STREAM, 0)
		self, err := os.Executable()
		Expect(err).NotTo(HaveOccurred())
		var prepared int
		prepare := withVsockDenial(func() error { prepared++; return nil }, true)
		cmd := exec.Command(self)
		cmd.Env = probeEnv()
		var out strings.Builder
		cmd.Stdout = &out
		release, err := startConfinedAs(cmd, prepare, "the probe")
		Expect(err).NotTo(HaveOccurred())
		Expect(cmd.Wait()).To(Succeed())
		release()
		Expect(prepared).To(Equal(1))
		expectDenied(probeResults(out.String()), unfiltered)

		// The thread that started the probe has ended, and no other
		// thread of this process has the filter.
		want := 0
		for _, n := range ownBefore {
			want = n
		}
		for task, n := range threadFilters() {
			Expect(n).To(Equal(want), "thread %s", task)
		}
		for i := 0; i < 50; i++ {
			fd, err := unix.Socket(afVsock, unix.SOCK_STREAM, 0)
			if err == nil {
				Expect(unix.Close(fd)).To(Succeed())
			}
			if ownErrBefore == nil {
				Expect(err).NotTo(HaveOccurred())
			} else {
				Expect(err).To(Equal(ownErrBefore))
			}
		}
	})

	It("is the droplet build when Garden asks for that", func() {
		unfiltered := unfilteredProbe()
		self, err := os.Executable()
		Expect(err).NotTo(HaveOccurred())
		cmd := exec.Command(self)
		cmd.Env = probeEnv()
		var out strings.Builder
		cmd.Stdout = &out
		Expect(runConfined(cmd, withVsockDenial(nil, true))).To(Succeed())
		expectDenied(probeResults(out.String()), unfiltered)
	})

	It("is not a child started without the filter", func() {
		unfiltered := unfilteredProbe()
		self, err := os.Executable()
		Expect(err).NotTo(HaveOccurred())
		cmd := exec.Command(self)
		cmd.Env = probeEnv()
		var out strings.Builder
		cmd.Stdout = &out
		Expect(runConfined(cmd, withVsockDenial(nil, false))).To(Succeed())
		Expect(probeResults(out.String())).To(Equal(unfiltered))
	})
})
