package seccompvsock

import (
	"encoding/json"
	"math/rand/v2"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// allowListProfile is a small profile shaped like Garden's unprivileged
// one: it refuses every call it does not name, and allows socket(2)
// whatever its arguments between two other rules.
func allowListProfile() *specs.LinuxSeccomp {
	nosys := uint(38)
	return &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"read"}, Action: specs.ActAllow},
			{Names: []string{"socket"}, Action: specs.ActAllow},
			{Names: []string{"socketcall"}, Action: specs.ActAllow},
			{Names: []string{"clone"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 0x7e020000, ValueTwo: 0, Op: specs.OpMaskedEqual}}},
			{Names: []string{"clone3"}, Action: specs.ActErrno, ErrnoRet: &nosys},
		},
	}
}

func marshal(profile *specs.LinuxSeccomp) string {
	b, err := json.Marshal(profile)
	Expect(err).NotTo(HaveOccurred())
	return string(b)
}

// allowsDomain reports whether a rule among rules allows socket(2) for
// domain, which is how libseccomp combines the conditional rules of one
// call in an allow-list filter.
func allowsDomain(rules []specs.LinuxSyscall, domain uint64) bool {
	for _, rule := range rules {
		if rule.Action == specs.ActAllow && matchesDomain(rule.Args, domain) {
			return true
		}
	}
	return false
}

// ioUringRefused is the rule that Deny adds to a profile that allows the
// io_uring calls.
func ioUringRefused() specs.LinuxSyscall {
	eperm := uint(1)
	return specs.LinuxSyscall{
		Names:    []string{"io_uring_setup", "io_uring_enter", "io_uring_register"},
		Action:   specs.ActErrno,
		ErrnoRet: &eperm,
	}
}

var _ = Describe("Deny", func() {
	It("gives a container that has no profile one that allows every call but socket(2) for AF_VSOCK and the io_uring calls, on x86_64 alone", func() {
		profile := Deny(nil)

		eperm := uint(1)
		Expect(profile).To(Equal(&specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Architectures: []specs.Arch{specs.ArchX86_64},
			Syscalls: []specs.LinuxSyscall{
				ioUringRefused(),
				{
					Names:    []string{"socket"},
					Action:   specs.ActErrno,
					ErrnoRet: &eperm,
					Args:     []specs.LinuxSeccompArg{{Index: 0, Value: 0xffffffff, ValueTwo: 40, Op: specs.OpMaskedEqual}},
				},
			},
		}))
		Expect(Denies(profile)).To(BeTrue())
	})

	It("drops 32-bit x86 and x32 from the profile's architectures, and keeps the others in order", func() {
		profile := allowListProfile()
		profile.Architectures = []specs.Arch{specs.ArchX86, specs.ArchAARCH64, specs.ArchX86_64, specs.ArchX32, specs.ArchARM}

		Expect(Deny(profile).Architectures).To(Equal([]specs.Arch{specs.ArchAARCH64, specs.ArchX86_64, specs.ArchARM}))
		Expect(Deny(allowListProfile()).Architectures).To(Equal([]specs.Arch{specs.ArchX86_64}))
	})

	It("strips the io_uring calls from the rules of an allow-list profile that allows them, and leaves its other calls alone", func() {
		profile := allowListProfile()
		profile.Syscalls = append(profile.Syscalls,
			specs.LinuxSyscall{Names: []string{"io_uring_setup", "io_uring_enter", "write"}, Action: specs.ActAllow},
			specs.LinuxSyscall{Names: []string{"io_uring_register"}, Action: specs.ActAllow},
		)
		Expect(Denies(Deny(allowListProfile()))).To(BeTrue())
		Expect(Denies(profile)).To(BeFalse())

		denied := Deny(profile)
		Expect(denied.Syscalls[len(denied.Syscalls)-1]).To(Equal(specs.LinuxSyscall{Names: []string{"write"}, Action: specs.ActAllow}))
		for _, rule := range denied.Syscalls {
			Expect(rule.Names).NotTo(ContainElements("io_uring_setup", "io_uring_enter", "io_uring_register"))
		}
		Expect(Denies(denied)).To(BeTrue())
	})

	It("replaces the io_uring rules of a profile that allows every call by default with its own", func() {
		profile := &specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Syscalls:      []specs.LinuxSyscall{{Names: []string{"io_uring_setup", "kexec_load"}, Action: specs.ActKillProcess}},
		}

		denied := Deny(profile)
		Expect(denied.Syscalls[:2]).To(Equal([]specs.LinuxSyscall{{Names: []string{"kexec_load"}, Action: specs.ActKillProcess}, ioUringRefused()}))
		Expect(Denies(denied)).To(BeTrue())
	})

	It("replaces the allow-list profile's socket(2) rule, in its place, with rules that leave out AF_VSOCK", func() {
		profile := Deny(allowListProfile())

		Expect(profile.DefaultAction).To(Equal(specs.ActErrno))
		Expect(profile.Syscalls).To(HaveLen(4 + 32))
		Expect(profile.Syscalls[0].Names).To(Equal([]string{"read"}))
		for _, rule := range profile.Syscalls[1:33] {
			Expect(rule.Names).To(Equal([]string{"socket"}))
			Expect(rule.Action).To(Equal(specs.ActAllow))
			Expect(rule.Args).To(HaveLen(1))
			Expect(rule.Args[0].Op).To(Equal(specs.OpMaskedEqual))
		}
		Expect(profile.Syscalls[33].Names).To(Equal([]string{"socketcall"}))
		Expect(profile.Syscalls[35].Names).To(Equal([]string{"clone3"}))
		Expect(profile.Architectures).To(Equal([]specs.Arch{specs.ArchX86_64}))
		Expect(Denies(profile)).To(BeTrue())
	})

	It("allows socket(2) for every domain whose low 32 bits are not AF_VSOCK, and for none whose low 32 bits are", func() {
		rules := Deny(allowListProfile()).Syscalls[1:33]

		for domain := uint64(0); domain < 1<<12; domain++ {
			Expect(allowsDomain(rules, domain)).To(Equal(domain != 40), "domain %#x", domain)
			high := domain | 1<<32
			Expect(allowsDomain(rules, high)).To(Equal(domain != 40), "domain %#x", high)
		}
		r := rand.New(rand.NewPCG(1, 2))
		for range 100000 {
			domain := r.Uint64()
			Expect(allowsDomain(rules, domain)).To(Equal(uint32(domain) != 40), "domain %#x", domain)
		}
		for _, domain := range []uint64{40, 1<<32 | 40, 0xffffffff00000028, 0x8000000000000028} {
			Expect(allowsDomain(rules, domain)).To(BeFalse(), "domain %#x", domain)
		}
		for _, domain := range []uint64{1, 2, 10, 16, 17, 41, 0x80000028, 0xffffffff, 0x100000000} {
			Expect(allowsDomain(rules, domain)).To(BeTrue(), "domain %#x", domain)
		}
	})

	It("never modifies the profile it is given", func() {
		profile := allowListProfile()
		before := marshal(profile)

		Deny(profile)
		Expect(marshal(profile)).To(Equal(before))

		allowed := Deny(nil)
		allowedBefore := marshal(allowed)
		Deny(allowed)
		Allow(allowed)
		Expect(marshal(allowed)).To(Equal(allowedBefore))
	})

	It("splits a rule that allows socket(2) along with other calls", func() {
		profile := allowListProfile()
		profile.Syscalls[1].Names = []string{"socketpair", "socket", "bind"}

		denied := Deny(profile)
		Expect(denied.Syscalls[1]).To(Equal(specs.LinuxSyscall{Names: []string{"socketpair", "bind"}, Action: specs.ActAllow}))
		Expect(denied.Syscalls[2].Names).To(Equal([]string{"socket"}))
		Expect(denied.Syscalls).To(HaveLen(5 + 32))
		Expect(Denies(denied)).To(BeTrue())
	})

	It("leaves a profile that already denies AF_VSOCK as it is", func() {
		once := Deny(allowListProfile())
		Expect(marshal(Deny(once))).To(Equal(marshal(once)))

		denyOnly := Deny(nil)
		Expect(marshal(Deny(denyOnly))).To(Equal(marshal(denyOnly)))
	})

	It("adds the denial to a profile that allows every call by default", func() {
		profile := &specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Syscalls:      []specs.LinuxSyscall{{Names: []string{"kexec_load"}, Action: specs.ActErrno}},
		}

		denied := Deny(profile)
		Expect(denied.Syscalls).To(HaveLen(3))
		Expect(denied.Syscalls[0].Names).To(Equal([]string{"kexec_load"}))
		Expect(denied.Syscalls[1]).To(Equal(ioUringRefused()))
		Expect(isDenyRule(denied.Syscalls[2])).To(BeTrue())
		Expect(Denies(denied)).To(BeTrue())

		allowed := Allow(denied)
		Expect(allowed.Syscalls).To(Equal([]specs.LinuxSyscall{profile.Syscalls[0], ioUringRefused()}))
		Expect(Denies(allowed)).To(BeFalse())
	})

	It("adds no second socket(2) rule to a profile that allows every call by default and already denies AF_VSOCK through it", func() {
		profile := &specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Syscalls:      []specs.LinuxSyscall{{Names: []string{"socket"}, Action: specs.ActErrno}},
		}

		Expect(Deny(profile).Syscalls).To(Equal([]specs.LinuxSyscall{profile.Syscalls[0], ioUringRefused()}))
	})
})

var _ = Describe("Allow", func() {
	It("undoes the socket(2) part of Deny for the allow-list profile, so that its rules are the ones it had, and keeps 32-bit x86 and x32 out", func() {
		profile := allowListProfile()
		want := allowListProfile()
		want.Architectures = []specs.Arch{specs.ArchX86_64}
		Expect(Allow(Deny(profile))).To(Equal(want))
		Expect(marshal(Allow(Deny(profile)))).To(Equal(marshal(want)))
		Expect(Denies(Allow(Deny(profile)))).To(BeFalse())
	})

	It("keeps the io_uring calls refused in the profile Deny gives a container that has none", func() {
		Expect(Allow(Deny(nil))).To(Equal(&specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Architectures: []specs.Arch{specs.ArchX86_64},
			Syscalls:      []specs.LinuxSyscall{ioUringRefused()},
		}))
		Expect(Allow(nil)).To(BeNil())
	})

	It("keeps the other rules of a profile that allows every call by default", func() {
		denied := Deny(nil)
		denied.Syscalls = append(denied.Syscalls, specs.LinuxSyscall{Names: []string{"kexec_load"}, Action: specs.ActErrno})

		Expect(Allow(denied).Syscalls).To(Equal([]specs.LinuxSyscall{ioUringRefused(), {Names: []string{"kexec_load"}, Action: specs.ActErrno}}))
	})
})

var _ = Describe("Denies", func() {
	It("is false without a profile, and for a profile that allows socket(2) whatever its arguments", func() {
		Expect(Denies(nil)).To(BeFalse())
		Expect(Denies(allowListProfile())).To(BeFalse())
	})

	It("is false for a rule that compares the whole 64-bit domain, which a domain with high bits set gets past", func() {
		profile := allowListProfile()
		profile.Syscalls[1].Args = []specs.LinuxSeccompArg{{Index: 0, Value: 40, Op: specs.OpNotEqual}}
		Expect(Denies(profile)).To(BeFalse())
	})

	It("is true for an allow-list profile that has no rule for socket(2) and lists neither 32-bit x86 nor x32", func() {
		profile := allowListProfile()
		profile.Syscalls = append(profile.Syscalls[:1], profile.Syscalls[2:]...)
		profile.Architectures = []specs.Arch{specs.ArchX86_64, specs.ArchAARCH64}
		Expect(Denies(profile)).To(BeTrue())
	})

	It("is false for a profile that lists 32-bit x86 or x32, whose programs reach the socket through socketcall(2)", func() {
		for _, arch := range []specs.Arch{specs.ArchX86, specs.ArchX32} {
			profile := Deny(allowListProfile())
			profile.Architectures = append(profile.Architectures, arch)
			Expect(Denies(profile)).To(BeFalse(), "with %s", arch)
			Expect(Denies(Deny(profile))).To(BeTrue(), "after Deny with %s", arch)
		}
	})

	It("is false for a profile that lets io_uring_setup(2) through, even only for some arguments", func() {
		profile := Deny(nil)
		profile.Syscalls = profile.Syscalls[1:]
		Expect(Denies(profile)).To(BeFalse())

		profile = Deny(nil)
		profile.Syscalls[0].Args = []specs.LinuxSeccompArg{{Index: 1, Value: 0, Op: specs.OpEqualTo}}
		Expect(Denies(profile)).To(BeFalse())

		profile = Deny(allowListProfile())
		profile.Syscalls = append(profile.Syscalls, specs.LinuxSyscall{Names: []string{"io_uring_setup"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 8, Op: specs.OpLessThan}}})
		Expect(Denies(profile)).To(BeFalse())
		Expect(Denies(Deny(profile))).To(BeTrue())

		profile = Deny(nil)
		profile.Syscalls[0].Action = specs.ActTrace
		Expect(Denies(profile)).To(BeFalse())
	})

	It("is false when a rule without conditions allows socket(2) beside the narrower ones, because it wins in libseccomp", func() {
		profile := Deny(allowListProfile())
		profile.Syscalls = append(profile.Syscalls, specs.LinuxSyscall{Names: []string{"socket"}, Action: specs.ActAllow})
		Expect(Denies(profile)).To(BeFalse())
	})

	It("is true for a default-allow profile with an errno rule for socket(2) whatever its arguments and one for io_uring_setup(2)", func() {
		profile := &specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Syscalls:      []specs.LinuxSyscall{{Names: []string{"socket", "io_uring_setup"}, Action: specs.ActErrno}},
		}
		Expect(Denies(profile)).To(BeTrue())
	})

	It("is false for a default-allow profile whose rule for socket(2) has the default action", func() {
		profile := &specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Syscalls:      []specs.LinuxSyscall{{Names: []string{"socket"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 40, Op: specs.OpEqualTo}}}},
		}
		Expect(Denies(profile)).To(BeFalse())
	})
})
