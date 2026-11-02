//go:build linux && cgo && seccomp

package guardiancmd

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"code.cloudfoundry.org/guardian/rundmc/seccompvsock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// These specs load Garden's profiles the way runc loads a container's: they
// convert each with runc's specconv and install it with runc's seccomp
// package, which builds the filter with the real libseccomp and patches it
// as runc does. A child process of this test binary does the loading, and
// then reports what the kernel does with the calls the denial is about on
// this machine's own architecture. The specs then read the filter that the
// kernel holds for the child back out, with PTRACE_SECCOMP_GET_FILTER, and
// run it for x86-64, 32-bit x86, and x32 calls, which this machine may not
// be able to make.

// seccompProbeProfile makes this test binary a probe child that loads the
// named profile (see seccompProbeProfiles).
const seccompProbeProfile = "GUARDIANCMD_SECCOMP_PROBE_PROFILE"

func init() {
	which := os.Getenv(seccompProbeProfile)
	if which == "" {
		return
	}
	runtime.LockOSThread()
	os.Exit(seccompProbeChild(which))
}

// seccompProbeProfiles are the profiles that a container may run with. The
// one named "none" is no profile, which shows what the environment allows.
func seccompProbeProfiles() (map[string]*specs.LinuxSeccomp, error) {
	garden, err := buildSeccomp()
	if err != nil {
		return nil, err
	}
	return map[string]*specs.LinuxSeccomp{
		"garden":               garden,
		"unprivileged":         seccompvsock.Deny(garden),
		"privileged":           seccompvsock.Deny(nil),
		"exception":            seccompvsock.Allow(seccompvsock.Deny(garden)),
		"privileged-exception": seccompvsock.Allow(seccompvsock.Deny(nil)),
		"none":                 nil,
	}, nil
}

// seccompProbeChild loads the profile on this thread as runc's init would,
// reports its thread id and what the calls give, and waits for its stdin to
// close, so that the parent can read its filter.
func seccompProbeChild(which string) int {
	profiles, err := seccompProbeProfiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 99
	}
	profile, ok := profiles[which]
	if !ok {
		fmt.Fprintln(os.Stderr, "no profile named", which)
		return 99
	}
	tid := unix.Gettid()
	if profile != nil {
		cfg, err := specconv.SetupSeccomp(profile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 99
		}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 99
		}
		if _, err := seccomp.InitSeccomp(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 99
		}
	}
	for _, d := range []struct {
		name   string
		domain uint64
	}{{"vsock", seccompvsock.AFVsock}, {"vsock-high", 1<<32 | seccompvsock.AFVsock}, {"unix", unix.AF_UNIX}} {
		fd, _, errno := unix.RawSyscall(unix.SYS_SOCKET, uintptr(d.domain), unix.SOCK_STREAM, 0)
		if errno == 0 {
			_ = unix.Close(int(fd))
		}
		fmt.Printf("%s=%s\n", d.name, errnoName(errno))
	}
	var params [120]byte
	fd, _, errno := unix.RawSyscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params[0])), 0)
	if errno == 0 {
		_ = unix.Close(int(fd))
	}
	fmt.Printf("io_uring=%s\n", errnoName(errno))
	fmt.Printf("tid=%d\n", tid)
	_, _ = io.Copy(io.Discard, os.Stdin)
	return 0
}

func errnoName(errno unix.Errno) string {
	if errno == 0 {
		return "ok"
	}
	return unix.ErrnoName(errno)
}

// requireLibseccompSpecs makes a check that this environment cannot make
// fail rather than pass with a loud note.
const requireLibseccompSpecs = "GUARDIANCMD_REQUIRE_LIBSECCOMP_SPECS"

func libseccompVacuous(what string) {
	GinkgoHelper()
	msg := fmt.Sprintf("VACUOUS LIBSECCOMP CHECK: %s. Run the privileged suite with -tags seccomp to check it, and set %s=1 to make this note a failure.", what, requireLibseccompSpecs)
	if os.Getenv(requireLibseccompSpecs) != "" {
		Fail(msg)
	}
	AddReportEntry("vacuous libseccomp check", msg)
	fmt.Fprintln(os.Stderr, msg)
}

// loadedProfile is what a probe child found under one profile, and the
// filter the kernel held for it, which is nil when this process may not
// read it.
type loadedProfile struct {
	calls  map[string]string
	filter *bpf.VM
}

// loadProfile runs a probe child under the named profile.
func loadProfile(which string) loadedProfile {
	GinkgoHelper()
	self, err := os.Executable()
	Expect(err).NotTo(HaveOccurred())
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), seccompProbeProfile+"="+which)
	stdin, err := cmd.StdinPipe()
	Expect(err).NotTo(HaveOccurred())
	stdout, err := cmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	var stderr strings.Builder
	cmd.Stderr = &stderr
	Expect(cmd.Start()).To(Succeed())
	defer func() {
		_ = stdin.Close()
		Expect(cmd.Wait()).To(Succeed(), stderr.String())
	}()

	loaded := loadedProfile{calls: map[string]string{}}
	lines := bufio.NewScanner(stdout)
	for lines.Scan() {
		name, value, _ := strings.Cut(lines.Text(), "=")
		loaded.calls[name] = value
		if name == "tid" {
			break
		}
	}
	Expect(loaded.calls).To(HaveKey("tid"), "the probe stopped early: %s", stderr.String())
	tid, err := strconv.Atoi(loaded.calls["tid"])
	Expect(err).NotTo(HaveOccurred())
	if which != "none" {
		loaded.filter, err = readFilter(tid)
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			libseccompVacuous(fmt.Sprintf("this process may not read a filter back from the kernel (%v), so the x86-64, 32-bit x86, and x32 calls go unchecked", err))
		} else {
			Expect(err).NotTo(HaveOccurred())
		}
	}
	return loaded
}

// readFilter stops the thread tid, reads the one filter it runs under, and
// lets it go on.
func readFilter(tid int) (*bpf.VM, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.PtraceAttach(tid); err != nil {
		return nil, fmt.Errorf("attaching to %d: %w", tid, err)
	}
	defer func() { _ = unix.PtraceDetach(tid) }()
	var status unix.WaitStatus
	if _, err := unix.Wait4(tid, &status, unix.WALL, nil); err != nil {
		return nil, err
	}
	n, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_SECCOMP_GET_FILTER, uintptr(tid), 0, 0, 0, 0)
	if errno != 0 {
		return nil, fmt.Errorf("counting the filter's instructions: %w", errno)
	}
	if _, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_SECCOMP_GET_FILTER, uintptr(tid), 1, 0, 0, 0); errno != unix.ENOENT {
		return nil, fmt.Errorf("the thread runs under more than one filter: %v", errno)
	}
	raw := make([]unix.SockFilter, n)
	if _, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_SECCOMP_GET_FILTER, uintptr(tid), 0, uintptr(unsafe.Pointer(&raw[0])), 0, 0); errno != 0 {
		return nil, fmt.Errorf("reading the filter: %w", errno)
	}
	prog := make([]bpf.Instruction, 0, n)
	for _, f := range raw {
		prog = append(prog, bpf.RawInstruction{Op: f.Code, Jt: f.Jt, Jf: f.Jf, K: f.K}.Disassemble())
	}
	return bpf.NewVM(prog)
}

const (
	auditArchX86_64 = unix.AUDIT_ARCH_X86_64
	auditArchI386   = unix.AUDIT_ARCH_I386
	x32Bit          = 0x40000000
)

// verdict runs filter for one call. bpf.VM loads words big-endian, where the
// kernel loads them in the order of the machine, so each 32-bit word of
// struct seccomp_data is written big-endian at its offset, and the 64-bit
// argument as its low word and then its high word, as on x86.
func verdict(filter *bpf.VM, arch, nr uint32, arg0 uint64) uint32 {
	GinkgoHelper()
	data := make([]byte, 64)
	binary.BigEndian.PutUint32(data[0:], nr)
	binary.BigEndian.PutUint32(data[4:], arch)
	binary.BigEndian.PutUint32(data[16:], uint32(arg0))
	binary.BigEndian.PutUint32(data[20:], uint32(arg0>>32))
	v, err := filter.Run(data)
	Expect(err).NotTo(HaveOccurred())
	return uint32(v)
}

const (
	retErrnoEPERM = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	retAllow      = uint32(unix.SECCOMP_RET_ALLOW)
)

func isKill(v uint32) bool {
	return v == unix.SECCOMP_RET_KILL_THREAD || v == unix.SECCOMP_RET_KILL_PROCESS
}

var _ = Describe("Garden's profiles as runc loads them with libseccomp", Ordered, func() {
	var unfiltered map[string]string

	BeforeAll(func() {
		unfiltered = loadProfile("none").calls
	})

	// expectNativeDenial checks what the kernel did with the child's own
	// calls under a denying profile.
	expectNativeDenial := func(calls map[string]string) {
		GinkgoHelper()
		Expect(calls["vsock"]).To(Equal("EPERM"))
		Expect(calls["vsock-high"]).To(Equal("EPERM"))
		Expect(calls["io_uring"]).To(Equal("EPERM"))
		Expect(calls["unix"]).To(Equal("ok"))
		if unfiltered["vsock"] == "EPERM" {
			libseccompVacuous("this environment already refuses socket(AF_VSOCK) with EPERM, so the kernel's answer under the profile cannot show the profile's denial")
		}
	}

	expectX86Denial := func(filter *bpf.VM) {
		GinkgoHelper()
		for _, domain := range []uint64{seccompvsock.AFVsock, 1<<32 | seccompvsock.AFVsock, 0xffffffff<<32 | seccompvsock.AFVsock} {
			Expect(verdict(filter, auditArchX86_64, 41, domain)).To(Equal(retErrnoEPERM), "socket(%#x)", domain)
		}
		for _, domain := range []uint64{unix.AF_UNIX, unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK, 41, 1 << 32} {
			Expect(verdict(filter, auditArchX86_64, 41, domain)).To(Equal(retAllow), "socket(%#x)", domain)
		}
		for _, nr := range []uint32{425, 426, 427} {
			Expect(verdict(filter, auditArchX86_64, nr, 1)).To(Equal(retErrnoEPERM), "io_uring call %d", nr)
		}
		Expect(verdict(filter, auditArchX86_64, 0, 0)).To(Equal(retAllow), "read(2)")
	}

	expectNo32Bit := func(filter *bpf.VM) {
		GinkgoHelper()
		for _, call := range []struct {
			nr   uint32
			arg0 uint64
		}{{102, 1}, {359, seccompvsock.AFVsock}, {359, unix.AF_INET}, {3, 0}, {425, 1}} {
			Expect(isKill(verdict(filter, auditArchI386, call.nr, call.arg0))).To(BeTrue(), "i386 call %d(%d)", call.nr, call.arg0)
		}
		for _, call := range []struct {
			nr   uint32
			arg0 uint64
		}{{x32Bit | 41, seccompvsock.AFVsock}, {x32Bit | 41, unix.AF_INET}, {x32Bit | 0, 0}, {x32Bit | 425, 1}} {
			Expect(isKill(verdict(filter, auditArchX86_64, call.nr, call.arg0))).To(BeTrue(), "x32 call %#x(%d)", call.nr, call.arg0)
		}
	}

	for _, which := range []string{"unprivileged", "privileged"} {
		It("denies vsock and io_uring and kills 32-bit x86 and x32 calls in the "+which+" profile", func() {
			loaded := loadProfile(which)
			expectNativeDenial(loaded.calls)
			if loaded.filter != nil {
				expectX86Denial(loaded.filter)
				expectNo32Bit(loaded.filter)
			}
		})
	}

	for _, which := range []string{"exception", "privileged-exception"} {
		It("allows vsock again but keeps io_uring refused and 32-bit calls killed in the "+which+" profile", func() {
			loaded := loadProfile(which)
			Expect(loaded.calls["io_uring"]).To(Equal("EPERM"))
			Expect(loaded.calls["vsock"]).To(Equal(unfiltered["vsock"]))
			Expect(loaded.calls["unix"]).To(Equal("ok"))
			if loaded.filter != nil {
				Expect(verdict(loaded.filter, auditArchX86_64, 41, seccompvsock.AFVsock)).To(Equal(retAllow))
				Expect(verdict(loaded.filter, auditArchX86_64, 425, 1)).To(Equal(retErrnoEPERM))
				expectNo32Bit(loaded.filter)
			}
		})
	}

	It("shows, in Garden's own profile, the 32-bit socketcall(2) that the denial closes", func() {
		loaded := loadProfile("garden")
		if loaded.filter != nil {
			Expect(verdict(loaded.filter, auditArchI386, 102, 1)).To(Equal(retAllow))
			Expect(verdict(loaded.filter, auditArchX86_64, 41, seccompvsock.AFVsock)).To(Equal(retAllow))
		}
	})
})
