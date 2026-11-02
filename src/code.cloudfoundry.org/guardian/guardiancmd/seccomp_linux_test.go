package guardiancmd

import (
	"encoding/json"
	"os"

	"code.cloudfoundry.org/guardian/rundmc/seccompvsock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opencontainers/runtime-spec/specs-go"
)

var _ = Describe("containerSeccomp", func() {
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

	It("leaves every profile as it was, byte for byte, when the denial is off", func() {
		unprivileged, privileged, err := containerSeccomp(false)
		Expect(err).NotTo(HaveOccurred())

		Expect(marshal(unprivileged)).To(Equal(unprivilegedGolden()))
		Expect(privileged).To(BeNil())
		Expect(seccompvsock.Denies(unprivileged)).To(BeFalse())
	})

	It("denies socket(2) for AF_VSOCK to unprivileged and privileged containers when the denial is on", func() {
		unprivileged, privileged, err := containerSeccomp(true)
		Expect(err).NotTo(HaveOccurred())

		Expect(seccompvsock.Denies(unprivileged)).To(BeTrue())
		Expect(seccompvsock.Denies(privileged)).To(BeTrue())
		Expect(privileged).To(Equal(seccompvsock.Deny(nil)))
	})

	It("changes nothing in the unprivileged profile but the socket(2) rule", func() {
		unprivileged, _, err := containerSeccomp(true)
		Expect(err).NotTo(HaveOccurred())

		Expect(marshal(seccompvsock.Allow(unprivileged))).To(Equal(unprivilegedGolden()))
		var socketRules int
		for _, rule := range unprivileged.Syscalls {
			if len(rule.Names) == 1 && rule.Names[0] == "socket" {
				socketRules++
				Expect(rule.Args).To(HaveLen(1))
			}
		}
		Expect(socketRules).To(Equal(32))
	})
})
