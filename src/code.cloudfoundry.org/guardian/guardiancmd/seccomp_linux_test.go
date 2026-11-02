package guardiancmd

import (
	"encoding/json"
	"os"

	"code.cloudfoundry.org/guardian/rundmc/seccompvsock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opencontainers/runtime-spec/specs-go"
)

var _ = Describe("Garden's seccomp profiles", func() {
	// unprivilegedGolden is the profile that buildSeccomp made before the
	// vsock denial existed, as JSON, on a kernel new enough to allow
	// ptrace.
	unprivilegedGolden := func() string {
		b, err := os.ReadFile("testdata/unprivileged-seccomp.json")
		Expect(err).NotTo(HaveOccurred())
		return string(b)
	}
	marshal := func(profile *specs.LinuxSeccomp) string {
		b, err := json.MarshalIndent(profile, "", "  ")
		Expect(err).NotTo(HaveOccurred())
		return string(b) + "\n"
	}

	It("builds the unprivileged profile as it was, byte for byte, which denies nothing", func() {
		unprivileged, err := buildSeccomp()
		Expect(err).NotTo(HaveOccurred())

		Expect(marshal(unprivileged)).To(Equal(unprivilegedGolden()))
		Expect(seccompvsock.Denies(unprivileged)).To(BeFalse())
	})

	It("denies vsock in the unprivileged profile by changing nothing but the socket(2) rule and the architectures", func() {
		unprivileged, err := buildSeccomp()
		Expect(err).NotTo(HaveOccurred())
		denied := seccompvsock.Deny(unprivileged)
		Expect(seccompvsock.Denies(denied)).To(BeTrue())
		Expect(denied.Architectures).To(Equal([]specs.Arch{specs.ArchX86_64}))

		allowed := seccompvsock.Allow(denied)
		Expect(seccompvsock.Denies(allowed)).To(BeFalse())
		allowed.Architectures = unprivileged.Architectures
		Expect(marshal(allowed)).To(Equal(unprivilegedGolden()))
		var socketRules int
		for _, rule := range denied.Syscalls {
			if len(rule.Names) == 1 && rule.Names[0] == "socket" {
				socketRules++
				Expect(rule.Args).To(HaveLen(1))
			}
			Expect(rule.Names).NotTo(ContainElement(HavePrefix("io_uring")))
		}
		Expect(socketRules).To(Equal(32))
	})
})
