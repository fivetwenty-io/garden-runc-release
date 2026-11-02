package bundlerules_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opencontainers/runtime-spec/specs-go"

	"code.cloudfoundry.org/guardian/backend"
	spec "code.cloudfoundry.org/guardian/gardener/container-spec"
	"code.cloudfoundry.org/guardian/rundmc/bundlerules"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/seccompvsock"
)

var _ = Describe("VsockDenial", func() {
	var (
		deny    bool
		asked   int
		rule    bundlerules.VsockDenial
		bndl    goci.Bndl
		profile *specs.LinuxSeccomp
	)

	BeforeEach(func() {
		deny = true
		asked = 0
		rule = bundlerules.VsockDenial{Deny: func() bool {
			asked++
			return deny
		}}
		profile = allowListSeccomp()
		bndl = goci.Bundle().WithSeccomp(profile)
		bndl.Spec.Annotations = map[string]string{"existing": "annotation"}
	})

	apply := func(b goci.Bndl, s spec.DesiredContainerSpec) goci.Bndl {
		GinkgoHelper()
		out, err := rule.Apply(b, s)
		Expect(err).NotTo(HaveOccurred())
		return out
	}

	It("denies the container vsock and records it, while gdn says to deny", func() {
		out := apply(bndl, spec.DesiredContainerSpec{})
		Expect(out.Seccomp()).To(Equal(seccompvsock.Deny(allowListSeccomp())))
		Expect(out.Spec.Annotations).To(Equal(map[string]string{"existing": "annotation", seccompvsock.AnnotationKey: seccompvsock.AnnotationProfile}))
		Expect(asked).To(Equal(1))
	})

	It("gives a privileged container, which has no profile, one that denies vsock", func() {
		out := apply(goci.Bundle(), spec.DesiredContainerSpec{Privileged: true})
		Expect(seccompvsock.Denies(out.Seccomp())).To(BeTrue())
		Expect(out.Spec.Annotations).To(HaveKeyWithValue(seccompvsock.AnnotationKey, seccompvsock.AnnotationProfile))
	})

	It("does not modify the bundle it is given", func() {
		apply(bndl, spec.DesiredContainerSpec{})
		Expect(bndl.Seccomp()).To(BeIdenticalTo(profile))
		Expect(profile).To(Equal(allowListSeccomp()))
		Expect(bndl.Spec.Annotations).To(Equal(map[string]string{"existing": "annotation"}))
	})

	It("leaves the bundle as it is while gdn says not to deny, and without a gate", func() {
		deny = false
		out := apply(bndl, spec.DesiredContainerSpec{})
		Expect(out).To(Equal(bndl))

		rule = bundlerules.VsockDenial{}
		Expect(apply(bndl, spec.DesiredContainerSpec{})).To(Equal(bndl))
	})

	// A pea's spec names no execution backend, whatever its sandbox's, so
	// the execution backend rule never gives a pea vsock back, even in a
	// vm-qemu sandbox that serves the guest agent.
	It("keeps a pea, whose spec names no execution backend, denied through the execution backend rule", func() {
		vm := bundlerules.NewExecutionBackend(GinkgoT().TempDir(), "/var/vcap/packages/guardian/bin/vm-launch", 991)
		vm.GuestAgent = true
		vm.HostVhostVsock = true
		vm.VsockException = func() bool { return true }

		peaSpec := spec.DesiredContainerSpec{}
		out, err := vm.Apply(apply(bndl, peaSpec), peaSpec)
		Expect(err).NotTo(HaveOccurred())
		Expect(seccompvsock.Denies(out.Seccomp())).To(BeTrue())
		Expect(out.Spec.Annotations).To(HaveKeyWithValue(seccompvsock.AnnotationKey, seccompvsock.AnnotationProfile))
		Expect(out.Spec.Annotations).NotTo(HaveKey(backend.AnnotationKey))
		Expect(out.Devices()).To(BeEmpty())
	})
})
