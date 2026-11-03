package guardiancmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/rundmc/depot"
	"code.cloudfoundry.org/guardian/rundmc/execrunner"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/runrunc"
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
		g.watch(cell, nil)
		return g
	}

	Context("with --deny-vsock", func() {
		It("denies every container vsock without looking at the cell", func() {
			g := gate(true)
			Expect(g.Deny("new")).To(BeTrue())
			Expect(cell.listings).To(Equal(0))
		})

		It("makes the guest agent exception on a cell whose every container is denied, and then stops looking", func() {
			cell.bundles["app"] = vsockBundle(backend.OCIRunc, seccompvsock.AnnotationProfile)
			cell.bundles["agent"] = vsockBundle(backend.VMQemu, seccompvsock.AnnotationWrapper)
			g := gate(true)
			Expect(g.Exception("new")).To(BeTrue())
			Expect(g.Exception("newer")).To(BeTrue())
			Expect(cell.listings).To(Equal(1))
		})

		It("makes the exception on an empty cell, and skips a container that goes away while it looks", func() {
			cell.gone = map[string]bool{"destroyed": true}
			Expect(gate(true).Exception("new")).To(BeTrue())
		})

		It("does not count the container being created, which it is about to deny", func() {
			cell.bundles["new"] = vsockBundle(backend.VMQemu, "")
			Expect(gate(true).Exception("new")).To(BeTrue())
		})

		It("skips a container whose bundle has gone from the depot", func() {
			cell.bundles["half-destroyed"] = goci.Bndl{}
			cell.infoErr = fmt.Errorf("Failed to load bundle: %w", &fs.PathError{Op: "open", Path: "/depot/half-destroyed/config.json", Err: fs.ErrNotExist})
			Expect(gate(true).Exception("new")).To(BeTrue())
		})

		It("refuses the exception while a container created without the denial runs, says which, and looks again next time", func() {
			cell.bundles["old"] = vsockBundle(backend.OCIRunc, "")
			cell.bundles["denied"] = vsockBundle(backend.OCIRunc, seccompvsock.AnnotationProfile)
			g := gate(true)
			Expect(g.Exception("new")).To(BeFalse())
			Expect(logger).To(gbytes.Say("guest-agent-refused-while-containers-lack-vsock-denial"))
			Expect(logger.Buffer().Contents()).To(ContainSubstring(`"old"`))
			Expect(logger.Buffer().Contents()).NotTo(ContainSubstring(`"denied"`))

			delete(cell.bundles, "old")
			Expect(g.Exception("new")).To(BeTrue())
			Expect(cell.listings).To(Equal(2))
		})

		It("counts a container whose annotation claims a denial its profile does not make as open", func() {
			bndl := vsockBundle(backend.OCIRunc, seccompvsock.AnnotationProfile)
			bndl = bndl.WithSeccomp(nil)
			cell.bundles["claims"] = bndl
			Expect(gate(true).Exception("new")).To(BeFalse())
		})

		// gVisor's kernel has no AF_VSOCK family, so a gVisor container
		// cannot create a vsock socket whatever its profile, and the gate
		// goes by its annotation like any other container's.
		It("goes by a gVisor container's annotation like any other's", func() {
			cell.bundles["gvisor"] = vsockBundle(backend.OCIGvisor, seccompvsock.AnnotationProfile)
			Expect(gate(true).Exception("new")).To(BeTrue())

			cell.bundles["old-gvisor"] = vsockBundle(backend.OCIGvisor, "")
			Expect(gate(true).Exception("new")).To(BeFalse())
		})

		It("refuses the exception on a cell that runs every container under runsc, and says so once", func() {
			g := newVsockGate(logger, true, true)
			g.watch(cell, nil)
			Expect(g.Exception("new")).To(BeFalse())
			Expect(g.Exception("newer")).To(BeFalse())
			Expect(cell.listings).To(Equal(0))
			Expect(logger.LogMessages()).To(Equal([]string{"gate.vsock-gate.guest-agent-refused-on-gvisor-cell"}))
		})

		It("looks at the peas too when the runtime lists them apart", func() {
			g := newVsockGate(logger, true, false)
			g.watch(fakeVsockPeaBundles{fakeVsockBundles: cell, peas: map[string]goci.Bndl{"old-pea": vsockBundle(backend.OCIRunc, "")}}, nil)
			Expect(g.Exception("new")).To(BeFalse())
		})

		It("refuses the exception, logs an error that counts the failures and names the container, and looks again, when it cannot list or read the containers", func() {
			cell.listErr = errors.New("no list")
			g := gate(true)
			Expect(g.Exception("new")).To(BeFalse())
			Expect(logger).To(gbytes.Say(`guest-agent-refused-without-container-list.*"consecutive-failures":1`))
			Expect(logger.LogMessages()).To(HaveLen(1))
			Expect(logger.Logs()[0].LogLevel).To(Equal(lager.ERROR))

			cell.listErr = nil
			cell.bundles["app"] = vsockBundle(backend.OCIRunc, seccompvsock.AnnotationProfile)
			cell.infoErr = errors.New("no bundle")
			Expect(g.Exception("new")).To(BeFalse())
			Expect(logger).To(gbytes.Say(`"consecutive-failures":2,"error":"reading the bundle of app: no bundle"`))

			cell.infoErr = nil
			Expect(g.Exception("new")).To(BeTrue())
			Expect(logger).To(gbytes.Say(`container-list-recovered.*"after-failures":2`))

			Expect(newVsockGate(logger, true, false).Exception("new")).To(BeFalse())
		})

		Context("on a runc mode depot", func() {
			var (
				dir string
				g   *vsockGate
			)

			save := func(path string, bndl goci.Bndl) {
				GinkgoHelper()
				Expect(os.MkdirAll(path, 0o700)).To(Succeed())
				Expect(goci.BundleSaver{}.Save(bndl, path)).To(Succeed())
			}

			BeforeEach(func() {
				dir = GinkgoT().TempDir()
				// The networker makes the directory of the container
				// being created before anything writes its config.json.
				Expect(os.MkdirAll(filepath.Join(dir, "new-container"), 0o700)).To(Succeed())
				save(filepath.Join(dir, "app"), vsockBundle(backend.OCIRunc, seccompvsock.AnnotationProfile))
				save(filepath.Join(dir, "app", "processes", "denied-pea"), vsockBundle(backend.OCIRunc, seccompvsock.AnnotationProfile))
				Expect(os.MkdirAll(filepath.Join(dir, "app", "processes", "an-exec"), 0o700)).To(Succeed())
				Expect(os.WriteFile(filepath.Join(dir, "stray"), nil, 0o600)).To(Succeed())

				containers := depot.New(dir, &goci.BundleSaver{}, &goci.BndlLoader{})
				g = newVsockGate(logger, true, false)
				g.watch(runrunc.NewBundleManager(containers, execrunner.NewProcessDirDepot(containers)), execrunner.NewProcessDirDepot(containers))
			})

			It("skips the container being created, the exec, and the stray file, and makes the exception", func() {
				Expect(g.Exception("new-container")).To(BeTrue())
				Expect(aboveDebug(logger)).To(BeEmpty())
			})

			It("refuses the exception while a pea that runc runs lacks the denial, and names it", func() {
				save(filepath.Join(dir, "app", "processes", "old-pea"), vsockBundle(backend.OCIRunc, ""))
				Expect(g.Exception("new-container")).To(BeFalse())
				Expect(logger).To(gbytes.Say(`guest-agent-refused-while-containers-lack-vsock-denial.*"app/old-pea"`))
				Expect(logger.Buffer().Contents()).NotTo(ContainSubstring("denied-pea"))

				Expect(os.RemoveAll(filepath.Join(dir, "app", "processes", "old-pea"))).To(Succeed())
				Expect(g.Exception("new-container")).To(BeTrue())
			})

			It("without the flag, skips a bundle it cannot parse, logs it once, and still settles", func() {
				Expect(os.MkdirAll(filepath.Join(dir, "broken"), 0o700)).To(Succeed())
				Expect(os.WriteFile(filepath.Join(dir, "broken", "config.json"), []byte("{"), 0o600)).To(Succeed())
				Expect(os.MkdirAll(filepath.Join(dir, "app", "processes", "broken-pea"), 0o700)).To(Succeed())
				Expect(os.WriteFile(filepath.Join(dir, "app", "processes", "broken-pea", "config.json"), []byte(`{"ociVersion":`), 0o600)).To(Succeed())

				containers := depot.New(dir, &goci.BundleSaver{}, &goci.BndlLoader{})
				off := newVsockGate(logger, false, false)
				off.watch(runrunc.NewBundleManager(containers, execrunner.NewProcessDirDepot(containers)), execrunner.NewProcessDirDepot(containers))
				Expect(off.Deny("new-container")).To(BeFalse())
				Expect(aboveDebug(logger)).To(Equal([]string{
					"gate.vsock-gate.skipped-unreadable-bundle",
					"gate.vsock-gate.skipped-unreadable-bundle",
				}))
				Expect(logger.Buffer().Contents()).To(ContainSubstring(`"handle":"broken"`))
				Expect(logger.Buffer().Contents()).To(ContainSubstring(`"handle":"app/broken-pea"`))

				Expect(off.Deny("another-container")).To(BeFalse())
				Expect(aboveDebug(logger)).To(HaveLen(2))

				save(filepath.Join(dir, "agent"), vsockBundle(backend.VMQemu, seccompvsock.AnnotationWrapper))
				again := newVsockGate(logger, false, false)
				again.watch(runrunc.NewBundleManager(containers, execrunner.NewProcessDirDepot(containers)), execrunner.NewProcessDirDepot(containers))
				Expect(again.Deny("new-container")).To(BeTrue())
			})

			It("with the flag, refuses the guest agent while a bundle cannot be parsed", func() {
				Expect(os.MkdirAll(filepath.Join(dir, "app", "processes", "broken-pea"), 0o700)).To(Succeed())
				Expect(os.WriteFile(filepath.Join(dir, "app", "processes", "broken-pea", "config.json"), []byte("{"), 0o600)).To(Succeed())
				Expect(g.Exception("new-container")).To(BeFalse())
				Expect(logger).To(gbytes.Say(`guest-agent-refused-without-container-list.*"consecutive-failures":1,"error":"reading the bundle of pea broken-pea in app`))
			})

			It("without the flag, denies nothing and logs no error", func() {
				containers := depot.New(dir, &goci.BundleSaver{}, &goci.BndlLoader{})
				off := newVsockGate(logger, false, false)
				off.watch(runrunc.NewBundleManager(containers, execrunner.NewProcessDirDepot(containers)), execrunner.NewProcessDirDepot(containers))
				Expect(off.Deny("new-container")).To(BeFalse())
				Expect(aboveDebug(logger)).To(BeEmpty())
			})
		})
	})

	Context("without --deny-vsock", func() {
		It("never makes the guest agent exception", func() {
			Expect(gate(false).Exception("new")).To(BeFalse())
			Expect(cell.listings).To(Equal(0))
		})

		It("denies nothing on a cell that serves no guest agent, and looks once", func() {
			cell.bundles["app"] = vsockBundle(backend.OCIRunc, seccompvsock.AnnotationProfile)
			cell.bundles["vm"] = vsockBundle(backend.VMQemu, "")
			g := gate(false)
			Expect(g.Deny("new")).To(BeFalse())
			Expect(g.Deny("newer")).To(BeFalse())
			Expect(cell.listings).To(Equal(1))
		})

		It("keeps denying for the rest of its run when a container serves the guest agent from an earlier run", func() {
			cell.bundles["agent"] = vsockBundle(backend.VMQemu, seccompvsock.AnnotationWrapper)
			g := gate(false)
			Expect(g.Deny("new")).To(BeTrue())
			Expect(logger).To(gbytes.Say("vsock-denial-kept-for-guest-agent-containers"))

			delete(cell.bundles, "agent")
			Expect(g.Deny("newer")).To(BeTrue())
			Expect(cell.listings).To(Equal(1))
		})

		It("denies nothing, logs an error that counts the failures, and looks again, when it cannot list the containers", func() {
			cell.listErr = errors.New("no list")
			g := gate(false)
			Expect(g.Deny("new")).To(BeFalse())
			Expect(g.Deny("newer")).To(BeFalse())
			Expect(logger).To(gbytes.Say(`vsock-denial-not-applied-without-container-list.*"consecutive-failures":1`))
			Expect(logger).To(gbytes.Say(`vsock-denial-not-applied-without-container-list.*"consecutive-failures":2`))
			Expect(logger.Logs()[0].LogLevel).To(Equal(lager.ERROR))

			cell.listErr = nil
			cell.bundles["agent"] = vsockBundle(backend.VMQemu, seccompvsock.AnnotationWrapper)
			Expect(g.Deny("newest")).To(BeTrue())
		})
	})
})

// aboveDebug gives the messages that the gate logged above debug level,
// leaving out the depot's own lookups.
func aboveDebug(logger *lagertest.TestLogger) []string {
	var messages []string
	for _, log := range logger.Logs() {
		if log.LogLevel > lager.DEBUG {
			messages = append(messages, log.Message)
		}
	}
	return messages
}
