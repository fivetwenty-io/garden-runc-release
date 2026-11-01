package backend_test

import (
	"errors"
	"fmt"
	"testing"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestBackend(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Backend Suite")
}

var _ = Describe("Registry", func() {
	var registry *backend.Registry

	BeforeEach(func() {
		var err error
		registry, err = backend.NewRegistry(backend.VMQemu, backend.OCIGvisor)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("Resolve", func() {
		DescribeTable("selecting runc",
			func(props garden.Properties) {
				kind, err := registry.Resolve(props)
				Expect(err).NotTo(HaveOccurred())
				Expect(kind).To(Equal(backend.OCIRunc))
			},
			Entry("nil properties", nil),
			Entry("key absent", garden.Properties{"other": "x"}),
			Entry("empty value", garden.Properties{backend.AnnotationKey: ""}),
			Entry("explicit oci-runc", garden.Properties{backend.AnnotationKey: "oci-runc"}),
		)

		It("returns an allowed kind", func() {
			kind, err := registry.Resolve(garden.Properties{backend.AnnotationKey: "vm-qemu"})
			Expect(err).NotTo(HaveOccurred())
			Expect(kind).To(Equal(backend.VMQemu))
		})

		It("rejects a known kind that is not allowed", func() {
			_, err := registry.Resolve(garden.Properties{backend.AnnotationKey: "vm-firecracker"})
			Expect(err).To(MatchError(backend.ErrBackendNotEnabled))
		})

		It("rejects an unknown value", func() {
			_, err := registry.Resolve(garden.Properties{backend.AnnotationKey: "vm-bochs"})
			Expect(err).To(MatchError(backend.ErrUnknownBackend))
		})

		It("matches values exactly", func() {
			_, err := registry.Resolve(garden.Properties{backend.AnnotationKey: " vm-qemu"})
			Expect(err).To(MatchError(backend.ErrUnknownBackend))
		})

		Context("with a nil registry", func() {
			It("allows runc and absent values", func() {
				var nilRegistry *backend.Registry
				kind, err := nilRegistry.Resolve(nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(kind).To(Equal(backend.OCIRunc))
			})

			It("treats every other known kind as not enabled", func() {
				var nilRegistry *backend.Registry
				_, err := nilRegistry.Resolve(garden.Properties{backend.AnnotationKey: "oci-gvisor"})
				Expect(err).To(MatchError(backend.ErrBackendNotEnabled))
			})
		})

		Context("with an empty registry", func() {
			It("allows only runc", func() {
				empty, err := backend.NewRegistry()
				Expect(err).NotTo(HaveOccurred())
				_, err = empty.Resolve(garden.Properties{backend.AnnotationKey: "vm-qemu"})
				Expect(err).To(MatchError(backend.ErrBackendNotEnabled))
			})
		})
	})

	Describe("NewRegistry", func() {
		It("rejects an unknown kind", func() {
			_, err := backend.NewRegistry(backend.Kind("nope"))
			Expect(err).To(MatchError(backend.ErrUnknownBackend))
		})
	})

	Describe("Allowed", func() {
		It("always allows runc", func() {
			Expect(registry.Allowed(backend.OCIRunc)).To(BeTrue())
		})

		It("reflects the allowlist", func() {
			Expect(registry.Allowed(backend.VMQemu)).To(BeTrue())
			Expect(registry.Allowed(backend.VMFirecracker)).To(BeFalse())
		})
	})
})

var _ = Describe("kind helpers", func() {
	It("classifies VM kinds", func() {
		Expect(backend.IsVM(backend.VMQemu)).To(BeTrue())
		Expect(backend.IsVM(backend.VMFirecracker)).To(BeTrue())
		Expect(backend.IsVM(backend.OCIGvisor)).To(BeFalse())
		Expect(backend.IsVM(backend.OCIRunc)).To(BeFalse())
	})

	// The Diego rep keeps its own copy of this classification as isVMBackend in
	// rep/conversion_helpers.go. A new kind has to be added here, which makes
	// this a prompt to update the rep copy and its spec as well.
	It("classifies every known kind", func() {
		isVM := map[backend.Kind]bool{
			backend.OCIRunc:       false,
			backend.OCIGvisor:     false,
			backend.VMQemu:        true,
			backend.VMFirecracker: true,
		}

		kinds := backend.KnownKinds()
		Expect(kinds).To(HaveLen(len(isVM)), "a kind was added or removed; classify it here and in the Diego rep's isVMBackend")
		for _, k := range kinds {
			expected, classified := isVM[k]
			Expect(classified).To(BeTrue(), "kind %q is not classified in this spec", string(k))
			Expect(backend.IsVM(k)).To(Equal(expected), "IsVM(%q)", string(k))
		}
	})

	It("classifies gvisor", func() {
		Expect(backend.IsGvisor(backend.OCIGvisor)).To(BeTrue())
		Expect(backend.IsGvisor(backend.VMQemu)).To(BeFalse())
		Expect(backend.IsGvisor(backend.OCIRunc)).To(BeFalse())
	})
})

var _ = Describe("FromBundle", func() {
	It("returns runc when the annotation is absent", func() {
		Expect(backend.FromBundle(goci.Bundle())).To(Equal(backend.OCIRunc))
	})

	It("returns runc when the annotation is empty", func() {
		b := goci.Bundle()
		b.Spec.Annotations = map[string]string{backend.AnnotationKey: ""}
		Expect(backend.FromBundle(b)).To(Equal(backend.OCIRunc))
	})

	It("returns the annotated kind", func() {
		b := goci.Bundle()
		b.Spec.Annotations = map[string]string{backend.AnnotationKey: "vm-qemu"}
		Expect(backend.FromBundle(b)).To(Equal(backend.VMQemu))
	})
})

// Diego, Cloud Controller, and existing container bundles all spell the key
// and the backend names out, so they are a wire contract that must not change
// with the Go identifiers.
var _ = Describe("wire names", func() {
	It("uses garden.execution-backend as the property and annotation key", func() {
		Expect(backend.AnnotationKey).To(Equal("garden.execution-backend"))
	})

	It("names the backends oci-runc, oci-gvisor, vm-qemu, and vm-firecracker", func() {
		Expect(string(backend.OCIRunc)).To(Equal("oci-runc"))
		Expect(string(backend.OCIGvisor)).To(Equal("oci-gvisor"))
		Expect(string(backend.VMQemu)).To(Equal("vm-qemu"))
		Expect(string(backend.VMFirecracker)).To(Equal("vm-firecracker"))
	})

	It("resolves a property spelled out literally", func() {
		registry, err := backend.NewRegistry(backend.OCIGvisor)
		Expect(err).NotTo(HaveOccurred())

		kind, err := registry.Resolve(garden.Properties{"garden.execution-backend": "oci-gvisor"})
		Expect(err).NotTo(HaveOccurred())
		Expect(kind).To(Equal(backend.OCIGvisor))
	})

	It("reads a bundle annotation spelled out literally", func() {
		b := goci.Bundle()
		b.Spec.Annotations = map[string]string{"garden.execution-backend": "vm-firecracker"}
		Expect(backend.FromBundle(b)).To(Equal(backend.VMFirecracker))
	})
})

var _ = Describe("CheckRootFS", func() {
	DescribeTable("operator-installed images on a VM backend",
		func(kind backend.Kind, image garden.ImageRef, rootFSPath string) {
			Expect(backend.CheckRootFS(kind, garden.ContainerSpec{Image: image, RootFSPath: rootFSPath})).To(Succeed())
		},
		Entry("no image on vm-qemu", backend.VMQemu, garden.ImageRef{}, ""),
		Entry("no image on vm-firecracker", backend.VMFirecracker, garden.ImageRef{}, ""),
		Entry("a bare absolute path", backend.VMQemu, garden.ImageRef{URI: "/var/vcap/packages/cflinuxfs4/rootfs.tar"}, ""),
		Entry("a bare absolute path to a directory", backend.VMFirecracker, garden.ImageRef{URI: "/var/vcap/packages/rootfs"}, ""),
		Entry("a bare absolute path in RootFSPath", backend.VMQemu, garden.ImageRef{}, "/var/vcap/packages/cflinuxfs4/rootfs.tar"),
		Entry("a preloaded layer over an absolute path", backend.VMQemu,
			garden.ImageRef{URI: "preloaded+layer:/var/vcap/packages/cflinuxfs4/rootfs.tar?layer=https%3A%2F%2Fblobstore%2Flayer.tgz&layer_path=%2Fhome%2Fvcap&layer_digest=abc"}, ""),
		Entry("a preloaded layer with an empty authority", backend.VMFirecracker,
			garden.ImageRef{URI: "preloaded+layer:///var/vcap/packages/cflinuxfs4/rootfs.tar?layer=https://blobstore/layer.tgz&layer_path=/home/vcap"}, ""),
	)

	DescribeTable("refused schemes on a VM backend",
		func(kind backend.Kind, image garden.ImageRef, rootFSPath string, scheme string) {
			err := backend.CheckRootFS(kind, garden.ContainerSpec{Image: image, RootFSPath: rootFSPath})
			Expect(err).To(MatchError(backend.ErrRootFSNotOperatorInstalled))
			Expect(err).To(MatchError(fmt.Sprintf(
				"execution backend %s requires an operator-installed rootfs; image scheme %s is not allowed", kind, scheme)))

			var rootFSErr *backend.RootFSError
			Expect(errors.As(err, &rootFSErr)).To(BeTrue())
			Expect(rootFSErr.Backend).To(Equal(kind))
			Expect(rootFSErr.Scheme).To(Equal(scheme))
		},
		Entry("docker", backend.VMQemu, garden.ImageRef{URI: "docker:///cloudfoundry/test"}, "", "docker"),
		Entry("docker with a host", backend.VMFirecracker, garden.ImageRef{URI: "docker://registry.example.com/some/image"}, "", "docker"),
		Entry("oci", backend.VMQemu, garden.ImageRef{URI: "oci:///var/some/image"}, "", "oci"),
		Entry("raw", backend.VMQemu, garden.ImageRef{URI: "raw:///var/vcap/data/some/dir"}, "", "raw"),
		Entry("file", backend.VMQemu, garden.ImageRef{URI: "file:///var/vcap/packages/rootfs"}, "", "file"),
		Entry("an unknown scheme", backend.VMQemu, garden.ImageRef{URI: "ftp://host/rootfs"}, "", "ftp"),
		Entry("the preloaded scheme, which only Diego's rep resolves", backend.VMQemu, garden.ImageRef{URI: "preloaded:cflinuxfs4"}, "", "preloaded"),
		Entry("a refused scheme in RootFSPath", backend.VMQemu, garden.ImageRef{}, "docker:///cloudfoundry/test", "docker"),
		Entry("a refused scheme in RootFSPath next to an allowed Image URI", backend.VMQemu, garden.ImageRef{URI: "/var/vcap/packages/rootfs"}, "docker:///cloudfoundry/test", "docker"),
	)

	It("does not echo the image URI", func() {
		err := backend.CheckRootFS(backend.VMQemu, garden.ContainerSpec{
			Image: garden.ImageRef{URI: "docker://user:secret@registry.example.com/some/image"},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).NotTo(ContainSubstring("secret"))
		Expect(err.Error()).NotTo(ContainSubstring("registry.example.com"))
	})

	DescribeTable("refused shapes with no scheme to name",
		func(uri string, reason string) {
			err := backend.CheckRootFS(backend.VMQemu, garden.ContainerSpec{Image: garden.ImageRef{URI: uri}})
			Expect(err).To(MatchError(backend.ErrRootFSNotOperatorInstalled))
			Expect(err).To(MatchError(ContainSubstring("execution backend vm-qemu requires an operator-installed rootfs; " + reason)))
		},
		Entry("a relative path", "some/relative/rootfs", "the image is not an absolute path"),
		Entry("a path with a host and no scheme", "//host/rootfs", "the image is not an absolute path"),
		Entry("a preloaded layer over a named stack", "preloaded+layer:cflinuxfs4?layer=https://blobstore/layer.tgz", "the preloaded+layer image has no absolute base path"),
		Entry("a preloaded layer with a host", "preloaded+layer://host/rootfs?layer=x", "the preloaded+layer image has no absolute base path"),
		Entry("a URI that cannot be parsed", "/rootfs%zz", "the image URI cannot be parsed"),
	)

	DescribeTable("preloaded layer destinations",
		func(layerQuery string, allowed bool) {
			err := backend.CheckRootFS(backend.VMQemu, garden.ContainerSpec{
				Image: garden.ImageRef{URI: "preloaded+layer:/var/vcap/packages/cflinuxfs4/rootfs.tar?layer=https://blobstore/layer.tgz&layer_digest=abc" + layerQuery},
			})
			if allowed {
				Expect(err).NotTo(HaveOccurred())
				return
			}
			Expect(err).To(MatchError(backend.ErrRootFSNotOperatorInstalled))
			Expect(err).To(MatchError("execution backend vm-qemu requires an operator-installed rootfs; the preloaded+layer destination must be under /home/vcap"))
			Expect(err.Error()).NotTo(ContainSubstring("blobstore"))
			Expect(err.Error()).NotTo(ContainSubstring("cflinuxfs4"))
		},
		Entry("/home/vcap", "&layer_path=/home/vcap", true),
		Entry("/home/vcap/app", "&layer_path=/home/vcap/app", true),
		Entry("/", "&layer_path=/", false),
		Entry("/etc", "&layer_path=/etc", false),
		Entry("/home/vcapx", "&layer_path=/home/vcapx", false),
		Entry("/home/vcap/../../etc", "&layer_path=/home/vcap/../../etc", false),
		Entry("an empty layer_path", "&layer_path=", false),
		Entry("a missing layer_path, which the image plugin rejects", "", false),
	)

	DescribeTable("backends that accept any image",
		func(kind backend.Kind, uri string) {
			Expect(backend.CheckRootFS(kind, garden.ContainerSpec{Image: garden.ImageRef{URI: uri}})).To(Succeed())
		},
		Entry("oci-runc with docker", backend.OCIRunc, "docker:///cloudfoundry/test"),
		Entry("oci-runc with oci", backend.OCIRunc, "oci:///var/some/image"),
		Entry("oci-runc with raw", backend.OCIRunc, "raw:///var/some/dir"),
		Entry("oci-gvisor with docker", backend.OCIGvisor, "docker:///cloudfoundry/test"),
		Entry("oci-gvisor with oci", backend.OCIGvisor, "oci:///var/some/image"),
		Entry("oci-gvisor with an unparseable URI", backend.OCIGvisor, "/rootfs%zz"),
		Entry("an unset kind with docker", backend.Kind(""), "docker:///cloudfoundry/test"),
	)

	It("also checks RootFSPath for the same backend", func() {
		err := backend.CheckRootFS(backend.VMQemu, garden.ContainerSpec{RootFSPath: "oci:///var/some/image"})
		Expect(err).To(MatchError(backend.ErrRootFSNotOperatorInstalled))
	})
})

var _ = Describe("StackTarball", func() {
	DescribeTable("the tarball path a spec names",
		func(spec garden.ContainerSpec, expected string) {
			Expect(backend.StackTarball(spec)).To(Equal(expected))
		},
		Entry("a plain path", garden.ContainerSpec{Image: garden.ImageRef{URI: "/var/vcap/packages/cflinuxfs4/rootfs.tar"}},
			"/var/vcap/packages/cflinuxfs4/rootfs.tar"),
		Entry("a preloaded layer URI", garden.ContainerSpec{
			Image: garden.ImageRef{URI: "preloaded+layer:/var/vcap/packages/cflinuxfs4/rootfs.tar?layer=https%3A%2F%2Fblobstore%2Flayer.tgz&layer_path=%2Fhome%2Fvcap&layer_digest=abc"}},
			"/var/vcap/packages/cflinuxfs4/rootfs.tar"),
		Entry("RootFSPath alone", garden.ContainerSpec{RootFSPath: "/var/vcap/packages/cflinuxfs4/rootfs.tar"},
			"/var/vcap/packages/cflinuxfs4/rootfs.tar"),
		Entry("Image.URI ahead of RootFSPath", garden.ContainerSpec{
			Image: garden.ImageRef{URI: "/var/vcap/packages/a/rootfs.tar"}, RootFSPath: "/var/vcap/packages/b/rootfs.tar"},
			"/var/vcap/packages/a/rootfs.tar"),
		Entry("a docker URI", garden.ContainerSpec{Image: garden.ImageRef{URI: "docker:///cloudfoundry/test"}}, ""),
		Entry("a relative path", garden.ContainerSpec{Image: garden.ImageRef{URI: "some/relative/rootfs.tar"}}, ""),
		Entry("a preloaded layer over a named stack", garden.ContainerSpec{Image: garden.ImageRef{URI: "preloaded+layer:cflinuxfs4?layer=x"}}, ""),
		Entry("an unparseable URI", garden.ContainerSpec{Image: garden.ImageRef{URI: "/rootfs%zz"}}, ""),
		Entry("an empty spec", garden.ContainerSpec{}, ""),
	)
})
