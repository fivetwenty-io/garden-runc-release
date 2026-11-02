//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// When the operator denies vsock sockets to container processes, Garden's
// seccomp profiles deny socket(AF_VSOCK) to every container but a vm-qemu
// container with the guest agent, whose vm-launch relays cf ssh sessions to
// the agent over vsock. The profile belongs to the whole container, so Garden
// runs every other process there through denyVsockCommand, and passes
// denyChildVsockFlag to the wrapped vm-launch, which then starts each of its
// own children under the same filter. Only vm-launch itself keeps the call.

// denyVsockCommand is the command that installs the filter and then execs
// the command after "--" (see runDenyVsock). Garden names it
// processes.VMLaunchDenyVsockCommand.
const denyVsockCommand = "deny-vsock"

// denyChildVsockFlag makes vm-launch start the hypervisor, virtiofsd, and the
// droplet build under the filter. Garden names it
// processes.VMLaunchDenyChildVsockFlag.
const denyChildVsockFlag = "deny-child-vsock"

const (
	// afVsock is AF_VSOCK, which every Linux architecture numbers 40.
	afVsock = 40

	// sysSocketcallSocket is the socketcall(2) call number of socket(2).
	sysSocketcallSocket = 1

	// The offsets in struct seccomp_data of the call number, the
	// architecture, and the low 32 bits of the first argument, which is
	// where the kernel reads an int argument from on the little-endian
	// architectures below.
	seccompDataNr       = 0
	seccompDataArch     = 4
	seccompDataArg0Low  = 16
	auditArchARM        = 0x40000028
	x32SyscallBit       = 0x40000000
	exitDenyVsockFailed = 126
	exitDenyVsockNoExec = 127
)

// vsockFilterArch is one architecture that a process on a Garden cell may
// make calls with, and the call numbers there that create a socket.
type vsockFilterArch struct {
	arch uint32
	// socket lists the numbers of socket(2), whose first argument is the
	// domain.
	socket []uint32
	// socketcall is the number of socketcall(2), or 0 where there is none.
	socketcall uint32
}

// vsockFilterArches are x86-64 with its x32 calls, i386, which an x86-64
// kernel runs 32-bit programs with, arm64, and 32-bit arm, which an arm64
// kernel may run.
var vsockFilterArches = []vsockFilterArch{
	{arch: unix.AUDIT_ARCH_X86_64, socket: []uint32{41, x32SyscallBit | 41}},
	{arch: unix.AUDIT_ARCH_I386, socket: []uint32{359}, socketcall: 102},
	{arch: unix.AUDIT_ARCH_AARCH64, socket: []uint32{198}},
	{arch: auditArchARM, socket: []uint32{281}},
}

// vsockFilter returns the classic BPF program of the seccomp filter that
// denies a socket in the AF_VSOCK domain. socket(2) fails with EPERM, as a
// call that Garden's profile refuses does, when the low 32 bits of its domain
// are AF_VSOCK, whatever the high bits hold, because the kernel reads only the
// low bits. An i386 socketcall(2) that creates a socket fails for every
// domain, because its arguments sit in memory that the filter cannot read;
// i386 programs on current kernels call socket(2) itself. Every other call,
// and every call of another architecture, goes on to the filters already
// installed.
func vsockFilter() []bpf.Instruction {
	const (
		domainLabel     = "domain"
		socketcallLabel = "socketcall"
		denyLabel       = "deny"
		allowLabel      = "allow"
	)
	type jump struct {
		at              int
		ifTrue, ifFalse string
	}
	var prog []bpf.Instruction
	var jumps []jump
	labels := map[string]int{}
	emit := func(ins bpf.Instruction) int {
		prog = append(prog, ins)
		return len(prog) - 1
	}
	jumpIf := func(val uint32, ifTrue, ifFalse string) {
		at := emit(bpf.JumpIf{Cond: bpf.JumpEqual, Val: val})
		jumps = append(jumps, jump{at: at, ifTrue: ifTrue, ifFalse: ifFalse})
	}

	emit(bpf.LoadAbsolute{Off: seccompDataArch, Size: 4})
	for i, a := range vsockFilterArches {
		next := fmt.Sprintf("arch%d", i+1)
		labels[fmt.Sprintf("arch%d", i)] = len(prog)
		jumpIf(a.arch, "", next)
		emit(bpf.LoadAbsolute{Off: seccompDataNr, Size: 4})
		for _, nr := range a.socket {
			jumpIf(nr, domainLabel, "")
		}
		if a.socketcall != 0 {
			jumpIf(a.socketcall, socketcallLabel, "")
		}
		emit(bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW})
	}
	labels[fmt.Sprintf("arch%d", len(vsockFilterArches))] = len(prog)
	emit(bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW})

	labels[domainLabel] = len(prog)
	emit(bpf.LoadAbsolute{Off: seccompDataArg0Low, Size: 4})
	jumpIf(afVsock, denyLabel, allowLabel)
	labels[socketcallLabel] = len(prog)
	emit(bpf.LoadAbsolute{Off: seccompDataArg0Low, Size: 4})
	jumpIf(sysSocketcallSocket, denyLabel, allowLabel)
	labels[denyLabel] = len(prog)
	emit(bpf.RetConstant{Val: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	labels[allowLabel] = len(prog)
	emit(bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW})

	// Every jump goes forward, as classic BPF requires.
	skip := func(from int, label string) uint8 {
		if label == "" {
			return 0
		}
		to, ok := labels[label]
		if !ok || to <= from || to-from-1 > 255 {
			panic("vsock filter: bad jump to " + label)
		}
		return uint8(to - from - 1)
	}
	for _, j := range jumps {
		ins := prog[j.at].(bpf.JumpIf)
		ins.SkipTrue = skip(j.at, j.ifTrue)
		ins.SkipFalse = skip(j.at, j.ifFalse)
		prog[j.at] = ins
	}
	return prog
}

// installVsockFilter sets no_new_privs on the calling thread, which an
// unprivileged process needs to install a filter, and installs vsockFilter
// with flags. The caller holds its OS thread. With
// unix.SECCOMP_FILTER_FLAG_TSYNC the filter covers every thread of the
// process; without it, only the calling thread and the processes it starts.
func installVsockFilter(flags uintptr) error {
	raw, err := bpf.Assemble(vsockFilter())
	if err != nil {
		return fmt.Errorf("assembling the vsock filter: %w", err)
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, ins := range raw {
		filter[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := setNoNewPrivs(); err != nil {
		return err
	}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(&prog))); errno != 0 {
		return fmt.Errorf("installing the vsock filter: %w", os.NewSyscallError("seccomp", errno))
	}
	return nil
}

// denyThreadVsock installs the filter on the calling thread alone, so that a
// process that thread starts runs under it while vm-launch keeps the call.
// startConfinedAs runs it on a thread that ends with the start.
func denyThreadVsock() error { return installVsockFilter(0) }

// withVsockDenial returns prepare followed by denyThreadVsock, or prepare
// itself when deny is false. A nil prepare stays nil when deny is false.
func withVsockDenial(prepare func() error, deny bool) func() error {
	if !deny {
		return prepare
	}
	return func() error {
		if prepare != nil {
			if err := prepare(); err != nil {
				return err
			}
		}
		return denyThreadVsock()
	}
}

// runDenyVsock runs "deny-vsock -- PATH [ARG...]": it installs the filter on
// every thread of vm-launch and then execs PATH with the arguments, the
// environment, and the working directory it was given, looking PATH up in
// the environment's PATH as the runtime would. It returns only when it
// fails: 126 when the filter or the exec fails, and 127 when there is no
// such command, as a shell does. It never runs the command without the
// filter.
func runDenyVsock(argv []string) int {
	if len(argv) < 2 || argv[0] != "--" {
		fmt.Fprintf(os.Stderr, "vm-launch: %s: usage: %s -- PATH [ARG...]\n", denyVsockCommand, denyVsockCommand)
		return exitDenyVsockFailed
	}
	argv = argv[1:]
	path, err := exec.LookPath(argv[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "vm-launch: %s: %v\n", denyVsockCommand, err)
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return exitDenyVsockNoExec
		}
		return exitDenyVsockFailed
	}
	if err := installVsockFilter(unix.SECCOMP_FILTER_FLAG_TSYNC); err != nil {
		fmt.Fprintf(os.Stderr, "vm-launch: %s: %v\n", denyVsockCommand, err)
		return exitDenyVsockFailed
	}
	err = syscall.Exec(path, argv, os.Environ())
	fmt.Fprintf(os.Stderr, "vm-launch: %s: exec %s: %v\n", denyVsockCommand, path, err)
	return exitDenyVsockFailed
}
