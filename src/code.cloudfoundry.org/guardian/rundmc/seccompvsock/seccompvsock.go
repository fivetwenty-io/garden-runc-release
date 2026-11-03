// Package seccompvsock turns the denial of vsock sockets on and off in a
// container's OCI seccomp profile.
//
// A process that may create an AF_VSOCK socket can dial the guest agent of
// every VM on the cell, so Garden denies socket(AF_VSOCK, ...) to every
// container process when the operator turns the denial on. The kernel reads
// the domain of socket(2) as an int, from the low 32 bits of the argument, so
// the rules match those 32 bits and nothing else. A domain whose high bits
// are set still creates a vsock socket, and a rule on the whole 64-bit value
// would let it through.
//
// The rules cover socket(2), and nothing in seccomp can cover socketcall(2),
// the multiplexer that 32-bit x86 programs may use instead, because its
// socket arguments sit in memory that seccomp cannot read. So a denying
// profile lists neither 32-bit x86 nor x32. A call made through an
// architecture that the profile does not list meets libseccomp's bad
// architecture action, which kills the thread, so 32-bit x86 and x32
// programs cannot run at all under it.
//
// A denying profile also refuses io_uring_setup(2), io_uring_enter(2), and
// io_uring_register(2), because an io_uring can create a socket in the kernel
// without making the socket(2) call that seccomp sees.
package seccompvsock

import (
	"slices"

	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	// AFVsock is the AF_VSOCK address family, which every Linux architecture
	// numbers 40.
	AFVsock = 40

	socketSyscall = "socket"

	// domainBits is the part of socket(2)'s domain argument that the kernel
	// reads, its low 32 bits.
	domainBits = 0xffffffff
)

// AnnotationKey is the bundle annotation that records how a container's
// processes are kept from vsock. It is set when the container is created and
// lives as long as its bundle, so it tells later execs and later runs of gdn
// what the container was created with.
const AnnotationKey = "garden.vsock-denial"

const (
	// AnnotationProfile says that the container's seccomp profile denies
	// vsock to every process in it.
	AnnotationProfile = "profile"

	// AnnotationWrapper says that the container's seccomp profile allows vsock,
	// because one process in it serves a guest agent over vsock, and that
	// every other process in it runs under vm-launch's vsock filter.
	AnnotationWrapper = "wrapper"
)

// ioUringSyscalls are the calls that set up and drive an io_uring.
var ioUringSyscalls = []string{"io_uring_setup", "io_uring_enter", "io_uring_register"}

// multiplexedArches are the architectures on which a process may create a
// socket through socketcall(2), or which a denying profile leaves out for
// another reason: x32 runs on the same kernels as 32-bit x86, and the
// kernel gives a profile that leaves both out no way in through either.
var multiplexedArches = []specs.Arch{specs.ArchX86, specs.ArchX32}

// eperm is EPERM, which every Linux architecture numbers 1, and the errno
// that a denied socket(2) returns. It is also the errno Garden's allow-list
// profile returns for every call it does not allow. The package spells it
// out because gdn also builds for Windows, which has no unix package.
const eperm uint = 1

// Deny returns a copy of profile that denies vsock. In the copy, socket(2)
// fails with EPERM for the AF_VSOCK domain and works as before for every
// other domain, the io_uring calls fail with EPERM, and 32-bit x86 and x32
// are no longer listed, so a call made through either kills the thread. It
// never modifies profile.
//
// For a nil profile, which a privileged container runs with, it returns a
// profile that allows every call but those. For an allow-list profile,
// whose default action refuses a call, it replaces each rule that allows
// socket(2) whatever its arguments with the rules that allow it for every
// domain whose low 32 bits are not AF_VSOCK, one for each bit that AF_VSOCK
// leaves clear and one for each bit it sets. A domain differs from AF_VSOCK
// in its low 32 bits exactly when one of those bits differs. The rules take
// the place of the first rule they replace, so the profile keeps its order.
// An allow-list profile loses any rule that would let an io_uring call
// through. A profile that already denies vsock comes back as an equal copy.
func Deny(profile *specs.LinuxSeccomp) *specs.LinuxSeccomp {
	if profile == nil {
		return &specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Architectures: []specs.Arch{specs.ArchX86_64},
			Syscalls:      []specs.LinuxSyscall{ioUringRule(), denyRule()},
		}
	}

	denied := copyProfile(profile)
	if Denies(profile) {
		return denied
	}
	denied.Architectures = slices.DeleteFunc(denied.Architectures, func(a specs.Arch) bool { return slices.Contains(multiplexedArches, a) })

	if profile.DefaultAction == specs.ActAllow {
		denied.Syscalls = append(withoutNames(denied.Syscalls, ioUringSyscalls, anyRule), ioUringRule())
		if admitsVsock(denied) {
			denied.Syscalls = append(denied.Syscalls, denyRule())
		}
		return denied
	}

	if refuses(profile.DefaultAction) {
		denied.Syscalls = withoutNames(denied.Syscalls, ioUringSyscalls, func(rule specs.LinuxSyscall) bool { return !refuses(rule.Action) || len(rule.Args) > 0 })
	} else {
		denied.Syscalls = append(withoutNames(denied.Syscalls, ioUringSyscalls, anyRule), ioUringRule())
	}
	if admitsVsock(denied) {
		syscalls := make([]specs.LinuxSyscall, 0, len(denied.Syscalls)+len(allowRules()))
		placed := false
		for _, rule := range denied.Syscalls {
			if !allowsAnySocket(rule) {
				syscalls = append(syscalls, rule)
				continue
			}
			if others := withoutName(rule.Names, socketSyscall); len(others) > 0 {
				rule.Names = others
				syscalls = append(syscalls, rule)
			}
			if !placed {
				syscalls = append(syscalls, allowRules()...)
				placed = true
			}
		}
		denied.Syscalls = syscalls
	}
	return denied
}

// Allow undoes the socket(2) part of Deny. It returns a copy of profile in
// which socket(2) works for every domain again, and it keeps everything
// else that Deny did: the io_uring calls stay refused and 32-bit x86 and x32
// stay unlisted, because the process that Garden gives vsock back to needs
// neither. For a profile that Deny made from an allow-list profile with a
// rule of its own for socket(2), which Garden's has, the rules come back as
// they were. It never modifies profile.
func Allow(profile *specs.LinuxSeccomp) *specs.LinuxSeccomp {
	if profile == nil {
		return nil
	}
	if profile.DefaultAction == specs.ActAllow {
		allowed := copyProfile(profile)
		allowed.Syscalls = slices.DeleteFunc(allowed.Syscalls, isDenyRule)
		return allowed
	}

	allowed := copyProfile(profile)
	syscalls := make([]specs.LinuxSyscall, 0, len(profile.Syscalls))
	placed := false
	for _, rule := range profile.Syscalls {
		if !isAllowRule(rule) {
			syscalls = append(syscalls, rule)
			continue
		}
		if !placed {
			syscalls = append(syscalls, specs.LinuxSyscall{Names: []string{socketSyscall}, Action: specs.ActAllow})
			placed = true
		}
	}
	allowed.Syscalls = syscalls
	return allowed
}

// Denies reports whether a process that runs with profile fails to create
// a socket in the AF_VSOCK domain. That takes three things. The process must
// fail to create one through socket(2), whatever the high 32 bits of the
// domain argument hold. It must fail to set up an io_uring. And the profile
// must list neither 32-bit x86 nor x32, whose programs could reach the
// socket through socketcall(2). A nil profile denies nothing.
func Denies(profile *specs.LinuxSeccomp) bool {
	if profile == nil || !refusesIOUring(profile) {
		return false
	}
	if slices.ContainsFunc(profile.Architectures, func(a specs.Arch) bool { return slices.Contains(multiplexedArches, a) }) {
		return false
	}
	return !admitsVsock(profile)
}

// refusesIOUring reports whether profile makes io_uring_setup(2) fail, the
// call without which a process has no io_uring to drive. It counts a call
// as refused only when every rule that names it refuses it whatever its
// arguments and, when no rule names it, the default action refuses it.
func refusesIOUring(profile *specs.LinuxSeccomp) bool {
	named := false
	for _, rule := range profile.Syscalls {
		if !slices.Contains(rule.Names, ioUringSyscalls[0]) {
			continue
		}
		if len(rule.Args) > 0 || !refuses(rule.Action) {
			return false
		}
		named = true
	}
	return named || refuses(profile.DefaultAction)
}

// refuses reports whether a call that meets action fails without being
// made. A trace action is not counted, because a tracer may let the call
// through.
func refuses(action specs.LinuxSeccompAction) bool {
	switch action {
	case specs.ActErrno, specs.ActKill, specs.ActKillThread, specs.ActKillProcess, specs.ActTrap:
		return true
	}
	return false
}

// vsockDomains are domain arguments that the kernel reads as AF_VSOCK: the
// family itself, and the family with high bits set, which a rule on the
// whole 64-bit argument may tell apart from it.
var vsockDomains = []uint64{AFVsock, 1<<32 | AFVsock, 0xffffffff<<32 | AFVsock}

// admitsVsock reports whether profile lets socket(2) through for any of
// vsockDomains, the way runc and libseccomp build the filter: a rule whose
// action is the default action is left out, a rule without conditions
// decides every call, and otherwise a call takes the action of the rules
// whose conditions all hold, or the default action when none hold. When
// rules that hold disagree, the call counts as admitted, so that Denies
// never claims a denial the filter might not make.
func admitsVsock(profile *specs.LinuxSeccomp) bool {
	var conditional []specs.LinuxSyscall
	for _, rule := range profile.Syscalls {
		if !slices.Contains(rule.Names, socketSyscall) || sameAction(rule.Action, rule.ErrnoRet, profile.DefaultAction, profile.DefaultErrnoRet) {
			continue
		}
		if len(rule.Args) == 0 {
			return rule.Action == specs.ActAllow
		}
		conditional = append(conditional, rule)
	}
	for _, domain := range vsockDomains {
		matched, allowed := false, false
		for _, rule := range conditional {
			if matchesDomain(rule.Args, domain) {
				matched = true
				allowed = allowed || rule.Action == specs.ActAllow
			}
		}
		if allowed || (!matched && profile.DefaultAction == specs.ActAllow) {
			return true
		}
	}
	return false
}

// sameAction reports whether two actions are one, as runc compares them: an
// errno action without an errno returns EPERM.
func sameAction(a specs.LinuxSeccompAction, aErrno *uint, b specs.LinuxSeccompAction, bErrno *uint) bool {
	if a != b {
		return false
	}
	if a != specs.ActErrno && a != specs.ActTrace {
		return true
	}
	return errnoOf(aErrno) == errnoOf(bErrno)
}

func errnoOf(errno *uint) uint {
	if errno == nil {
		return eperm
	}
	return *errno
}

// matchesDomain reports whether every condition in args that tests the
// domain, the first argument, holds for domain. A condition on another
// argument is taken to hold, because some call can meet it.
func matchesDomain(args []specs.LinuxSeccompArg, domain uint64) bool {
	for _, arg := range args {
		if arg.Index != 0 {
			continue
		}
		var holds bool
		switch arg.Op {
		case specs.OpEqualTo:
			holds = domain == arg.Value
		case specs.OpNotEqual:
			holds = domain != arg.Value
		case specs.OpLessThan:
			holds = domain < arg.Value
		case specs.OpLessEqual:
			holds = domain <= arg.Value
		case specs.OpGreaterThan:
			holds = domain > arg.Value
		case specs.OpGreaterEqual:
			holds = domain >= arg.Value
		case specs.OpMaskedEqual:
			holds = domain&arg.Value == arg.ValueTwo
		default:
			holds = true
		}
		if !holds {
			return false
		}
	}
	return true
}

// denyRule is the rule that makes socket(2) fail with EPERM for every domain
// whose low 32 bits are AF_VSOCK.
func denyRule() specs.LinuxSyscall {
	errno := eperm
	return specs.LinuxSyscall{
		Names:    []string{socketSyscall},
		Action:   specs.ActErrno,
		ErrnoRet: &errno,
		Args:     []specs.LinuxSeccompArg{{Index: 0, Value: domainBits, ValueTwo: AFVsock, Op: specs.OpMaskedEqual}},
	}
}

// allowRules are the rules that allow socket(2) for every domain whose low
// 32 bits are not AF_VSOCK. Rule i matches a domain whose bit i differs from
// that bit of AF_VSOCK.
func allowRules() []specs.LinuxSyscall {
	rules := make([]specs.LinuxSyscall, 0, 32)
	for bit := range 32 {
		mask := uint64(1) << bit
		rules = append(rules, specs.LinuxSyscall{
			Names:  []string{socketSyscall},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: mask, ValueTwo: mask &^ AFVsock, Op: specs.OpMaskedEqual}},
		})
	}
	return rules
}

// ioUringRule is the rule that makes every io_uring call fail with EPERM.
func ioUringRule() specs.LinuxSyscall {
	errno := eperm
	return specs.LinuxSyscall{
		Names:    slices.Clone(ioUringSyscalls),
		Action:   specs.ActErrno,
		ErrnoRet: &errno,
	}
}

func isDenyRule(rule specs.LinuxSyscall) bool {
	d := denyRule()
	return slices.Equal(rule.Names, d.Names) && rule.Action == d.Action && rule.ErrnoRet != nil && *rule.ErrnoRet == *d.ErrnoRet && slices.Equal(rule.Args, d.Args)
}

func isAllowRule(rule specs.LinuxSyscall) bool {
	if !slices.Equal(rule.Names, []string{socketSyscall}) || rule.Action != specs.ActAllow || rule.ErrnoRet != nil || len(rule.Args) != 1 {
		return false
	}
	return slices.ContainsFunc(allowRules(), func(r specs.LinuxSyscall) bool { return r.Args[0] == rule.Args[0] })
}

// allowsAnySocket reports whether rule allows socket(2) whatever its
// arguments.
func allowsAnySocket(rule specs.LinuxSyscall) bool {
	return rule.Action == specs.ActAllow && len(rule.Args) == 0 && slices.Contains(rule.Names, socketSyscall)
}

// withoutNames returns rules without names in each rule that pick reports,
// leaving out a rule that has no other name.
func withoutNames(rules []specs.LinuxSyscall, names []string, pick func(specs.LinuxSyscall) bool) []specs.LinuxSyscall {
	kept := make([]specs.LinuxSyscall, 0, len(rules))
	for _, rule := range rules {
		if pick(rule) {
			rule.Names = slices.DeleteFunc(rule.Names, func(n string) bool { return slices.Contains(names, n) })
			if len(rule.Names) == 0 {
				continue
			}
		}
		kept = append(kept, rule)
	}
	return kept
}

func anyRule(specs.LinuxSyscall) bool { return true }

func withoutName(names []string, name string) []string {
	var others []string
	for _, n := range names {
		if n != name {
			others = append(others, n)
		}
	}
	return others
}

// copyProfile copies profile deeply enough that changing the copy's rules,
// architectures, or flags leaves profile alone.
func copyProfile(profile *specs.LinuxSeccomp) *specs.LinuxSeccomp {
	c := *profile
	c.Architectures = slices.Clone(profile.Architectures)
	c.Flags = slices.Clone(profile.Flags)
	c.Syscalls = make([]specs.LinuxSyscall, 0, len(profile.Syscalls))
	for _, rule := range profile.Syscalls {
		rule.Names = slices.Clone(rule.Names)
		rule.Args = slices.Clone(rule.Args)
		if rule.ErrnoRet != nil {
			errno := *rule.ErrnoRet
			rule.ErrnoRet = &errno
		}
		c.Syscalls = append(c.Syscalls, rule)
	}
	return &c
}
