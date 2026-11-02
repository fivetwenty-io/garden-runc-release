package guardiancmd

import (
	"errors"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/seccompvsock"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/lager/v3/lagertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

// fakeVsockBundles is a cell's containers, by handle.
type fakeVsockBundles struct {
	bundles  map[string]goci.Bndl
	gone     map[string]bool
	listErr  error
	infoErr  error
	listings int
}

func (f *fakeVsockBundles) ContainerHandles() ([]string, error) {
	f.listings++
	if f.listErr != nil {
		return nil, f.listErr
	}
	var handles []string
	for handle := range f.bundles {
		handles = append(handles, handle)
	}
	for handle := range f.gone {
		handles = append(handles, handle)
	}
	return handles, nil
}

func (f *fakeVsockBundles) BundleInfo(_ lager.Logger, handle string) (string, goci.Bndl, error) {
	if f.gone[handle] {
		return "", goci.Bndl{}, garden.ContainerNotFoundError{Handle: handle}
	}
	if f.infoErr != nil {
		return "", goci.Bndl{}, f.infoErr
	}
	return "/depot/" + handle, f.bundles[handle], nil
}

// fakeVsockPeaBundles also lists peas, as the containerd runtime does.
type fakeVsockPeaBundles struct {
	*fakeVsockBundles
	peas map[string]goci.Bndl
}

func (f fakeVsockPeaBundles) PeaHandles() ([]string, error) {
	var handles []string
	for handle, bndl := range f.peas {
		handles = append(handles, handle)
		f.bundles[handle] = bndl
	}
	return handles, nil
}

func vsockBundle(kind backend.Kind, denial string) goci.Bndl {
	bndl := goci.Bundle()
	bndl.Spec.Annotations = map[string]string{backend.AnnotationKey: string(kind)}
	switch denial {
	case seccompvsock.AnnotationProfile:
		bndl = bndl.WithSeccomp(seccompvsock.Deny(nil))
		bndl.Spec.Annotations[seccompvsock.AnnotationKey] = denial
	case seccompvsock.AnnotationWrapper:
		bndl = bndl.WithSeccomp(seccompvsock.Allow(seccompvsock.Deny(nil)))
		bndl.Spec.Annotations[seccompvsock.AnnotationKey] = denial
	}
	return bndl
}

var _ = Describe("vsockGate", func() {
	var (
		logger *lagertest.TestLogger
		cell   *fakeVsockBundles
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("gate")
		cell = &fakeVsockBundles{bundles: map[string]goci.Bndl{}}
	})

	gate := func(flag bool) *vsockGate {
		g := newVsockGate(logger, flag, false)
		g.watch(cell)
		return g
	}

	Context("with --deny-vsock", func() {
		It("denies every container vsock without looking at the cell", func() {
			g := gate(true)
			Expect(g.Deny()).To(BeTrue())
			Expect(cell.listings).To(Equal(0))
		})

		It("makes the guest agent exception on a cell whose every container is denied, and then stops looking", func() {
			cell.bundles["app"] = vsockBundle(backend.OCIRunc, seccompvsock.AnnotationProfile)
			cell.bundles["agent"] = vsockBundle(backend.VMQemu, seccompvsock.AnnotationWrapper)
			g := gate(true)
			Expect(g.Exception()).To(BeTrue())
			Expect(g.Exception()).To(BeTrue())
			Expect(cell.listings).To(Equal(1))
		})

		It("makes the exception on an empty cell, and skips a container that goes away while it looks", func() {
			cell.gone = map[string]bool{"destroyed": true}
			Expect(gate(true).Exception()).To(BeTrue())
		})

		It("refuses the exception while a container created without the denial runs, says which, and looks again next time", func() {
			cell.bundles["old"] = vsockBundle(backend.OCIRunc, "")
			cell.bundles["new"] = vsockBundle(backend.OCIRunc, seccompvsock.AnnotationProfile)
			g := gate(true)
			Expect(g.Exception()).To(BeFalse())
			Expect(logger).To(gbytes.Say("guest-agent-refused-while-containers-lack-vsock-denial"))
			Expect(logger.Buffer().Contents()).To(ContainSubstring(`"old"`))
			Expect(logger.Buffer().Contents()).NotTo(ContainSubstring(`"new"`))

			delete(cell.bundles, "old")
			Expect(g.Exception()).To(BeTrue())
			Expect(cell.listings).To(Equal(2))
		})

		It("counts a container whose annotation claims a denial its profile does not make as open", func() {
			bndl := vsockBundle(backend.OCIRunc, seccompvsock.AnnotationProfile)
			bndl = bndl.WithSeccomp(nil)
			cell.bundles["claims"] = bndl
			Expect(gate(true).Exception()).To(BeFalse())
		})

		It("counts a gVisor container as open whatever its annotation, because runsc ignores the profile", func() {
			cell.bundles["gvisor"] = vsockBundle(backend.OCIGvisor, seccompvsock.AnnotationProfile)
			Expect(gate(true).Exception()).To(BeFalse())
		})

		It("refuses the exception on a cell that runs every container under runsc", func() {
			g := newVsockGate(logger, true, true)
			g.watch(cell)
			Expect(g.Exception()).To(BeFalse())
			Expect(cell.listings).To(Equal(0))
		})

		It("looks at the peas too when the runtime lists them apart", func() {
			g := newVsockGate(logger, true, false)
			g.watch(fakeVsockPeaBundles{fakeVsockBundles: cell, peas: map[string]goci.Bndl{"old-pea": vsockBundle(backend.OCIRunc, "")}})
			Expect(g.Exception()).To(BeFalse())
		})

		It("refuses the exception, and looks again, when it cannot list or read the containers", func() {
			cell.listErr = errors.New("no list")
			g := gate(true)
			Expect(g.Exception()).To(BeFalse())
			cell.listErr = nil
			cell.bundles["app"] = vsockBundle(backend.OCIRunc, seccompvsock.AnnotationProfile)
			cell.infoErr = errors.New("no bundle")
			Expect(g.Exception()).To(BeFalse())
			cell.infoErr = nil
			Expect(g.Exception()).To(BeTrue())

			Expect(newVsockGate(logger, true, false).Exception()).To(BeFalse())
		})
	})

	Context("without --deny-vsock", func() {
		It("never makes the guest agent exception", func() {
			Expect(gate(false).Exception()).To(BeFalse())
			Expect(cell.listings).To(Equal(0))
		})

		It("denies nothing on a cell that serves no guest agent, and looks once", func() {
			cell.bundles["app"] = vsockBundle(backend.OCIRunc, seccompvsock.AnnotationProfile)
			cell.bundles["vm"] = vsockBundle(backend.VMQemu, "")
			g := gate(false)
			Expect(g.Deny()).To(BeFalse())
			Expect(g.Deny()).To(BeFalse())
			Expect(cell.listings).To(Equal(1))
		})

		It("keeps denying for the rest of its run when a container serves the guest agent from an earlier run", func() {
			cell.bundles["agent"] = vsockBundle(backend.VMQemu, seccompvsock.AnnotationWrapper)
			g := gate(false)
			Expect(g.Deny()).To(BeTrue())
			Expect(logger).To(gbytes.Say("vsock-denial-kept-for-guest-agent-containers"))

			delete(cell.bundles, "agent")
			Expect(g.Deny()).To(BeTrue())
			Expect(cell.listings).To(Equal(1))
		})

		It("denies, and looks again next time, when it cannot list the containers", func() {
			cell.listErr = errors.New("no list")
			g := gate(false)
			Expect(g.Deny()).To(BeTrue())
			cell.listErr = nil
			Expect(g.Deny()).To(BeFalse())
		})
	})
})
