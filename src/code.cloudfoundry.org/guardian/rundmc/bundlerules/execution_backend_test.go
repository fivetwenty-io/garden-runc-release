package bundlerules_test

import (
	"os"
	"path/filepath"

	"code.cloudfoundry.org/garden"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opencontainers/runtime-spec/specs-go"

	"code.cloudfoundry.org/guardian/backend"
	spec "code.cloudfoundry.org/guardian/gardener/container-spec"
	"code.cloudfoundry.org/guardian/rundmc/bundlerules"
	"code.cloudfoundry.org/guardian/rundmc/goci"
)

var _ = Describe("ExecutionBackendRule", func() {
	const kvmGid = 991

	unprivilegedCaps := []string{"CAP_CHOWN", "CAP_SETGID", "CAP_SETUID", "CAP_KILL"}

	var (
		artifactsDir string
		rule         bundlerules.ExecutionBackend
		inputBndl    goci.Bndl
		pristine     goci.Bndl
		desiredSpec  spec.DesiredContainerSpec
		newBndl      goci.Bndl
		applyErr     error
	)

	touch := func(rel string) {
		path := filepath.Join(artifactsDir, rel)
		Expect(os.MkdirAll(filepath.Dir(path), 0o755)).To(Succeed())
		Expect(os.WriteFile(path, []byte("x"), 0o644)).To(Succeed())
	}

	BeforeEach(func() {
		artifactsDir = GinkgoT().TempDir()
		rule = bundlerules.NewExecutionBackend(artifactsDir, "/var/vcap/packages/guardian/bin/vm-launch", kvmGid)

		inputBndl = goci.Bundle().
			WithDevices(specs.LinuxDevice{Path: "/dev/fuse", Type: "c", Major: 10, Minor: 229}).
			WithDeviceRestrictions([]specs.LinuxDeviceCgroup{{Allow: false, Access: "rwm"}}).
			WithMounts(specs.Mount{Destination: "/proc", Source: "proc", Type: "proc"}).
			WithApparmorProfile("garden-default").
			WithCapabilities(unprivilegedCaps...)
		inputBndl.Spec.Process.Capabilities.Effective = unprivilegedCaps
		inputBndl.Spec.Process.Capabilities.Ambient = []string{"CAP_SETGID"}
		inputBndl.Spec.Annotations = map[string]string{"existing": "annotation"}

		pristine = goci.Bundle().
			WithDevices(specs.LinuxDevice{Path: "/dev/fuse", Type: "c", Major: 10, Minor: 229}).
			WithDeviceRestrictions([]specs.LinuxDeviceCgroup{{Allow: false, Access: "rwm"}}).
			WithMounts(specs.Mount{Destination: "/proc", Source: "proc", Type: "proc"}).
			WithApparmorProfile("garden-default").
			WithCapabilities("CAP_CHOWN", "CAP_SETGID", "CAP_SETUID", "CAP_KILL")
		pristine.Spec.Process.Capabilities.Effective = []string{"CAP_CHOWN", "CAP_SETGID", "CAP_SETUID", "CAP_KILL"}
		pristine.Spec.Process.Capabilities.Ambient = []string{"CAP_SETGID"}
		pristine.Spec.Annotations = map[string]string{"existing": "annotation"}

		desiredSpec = spec.DesiredContainerSpec{}
	})

	JustBeforeEach(func() {
		newBndl, applyErr = rule.Apply(inputBndl, desiredSpec)
	})

	for _, kind := range []string{"", string(backend.OCIRunc)} {
		kind := kind
		When("the backend is "+`"`+kind+`"`, func() {
			BeforeEach(func() {
				desiredSpec.ExecutionBackend = kind
			})

			It("returns the bundle unchanged", func() {
				Expect(applyErr).NotTo(HaveOccurred())
				Expect(newBndl).To(Equal(pristine))
				Expect(newBndl.Spec.Annotations).NotTo(HaveKey(backend.AnnotationKey))
			})
		})
	}

	When("the backend is unknown", func() {
		BeforeEach(func() {
			desiredSpec.ExecutionBackend = "vm-bogus"
		})

		It("returns ErrUnknownBackend", func() {
			Expect(applyErr).To(MatchError(ContainSubstring("vm-bogus")))
			Expect(applyErr).To(MatchError(backend.ErrUnknownBackend))
		})
	})

	When("the backend is oci-gvisor", func() {
		BeforeEach(func() {
			desiredSpec.ExecutionBackend = string(backend.OCIGvisor)
		})

		It("only sets the annotation, keeping the existing ones", func() {
			Expect(applyErr).NotTo(HaveOccurred())
			Expect(newBndl.Spec.Annotations).To(Equal(map[string]string{
				"existing":            "annotation",
				backend.AnnotationKey: "oci-gvisor",
			}))

			expected := pristine
			expected.Spec.Annotations = newBndl.Spec.Annotations
			Expect(newBndl).To(Equal(expected))
		})

		It("does not require VM artifacts", func() {
			Expect(applyErr).NotTo(HaveOccurred())
		})

		It("leaves capabilities and NoNewPrivileges alone", func() {
			Expect(newBndl.Process().Capabilities).To(Equal(pristine.Process().Capabilities))
			Expect(newBndl.Process().NoNewPrivileges).To(BeFalse())
		})

		When("the kvm gid is not configured", func() {
			BeforeEach(func() {
				rule.KVMGid = 0
			})

			It("does not need it", func() {
				Expect(applyErr).NotTo(HaveOccurred())
			})
		})

		It("does not modify the input bundle", func() {
			Expect(inputBndl).To(Equal(pristine))
		})
	})

	When("the backend is vm-qemu", func() {
		BeforeEach(func() {
			desiredSpec.ExecutionBackend = string(backend.VMQemu)
			touch("kernel/bzImage")
			touch("qemu/qemu-system-x86_64-microvm")
			touch("qemu/ld-linux-x86-64.so.2")
			touch("busybox")
		})

		It("sets the annotation, keeping the existing ones", func() {
			Expect(applyErr).NotTo(HaveOccurred())
			Expect(newBndl.Spec.Annotations).To(Equal(map[string]string{
				"existing":            "annotation",
				backend.AnnotationKey: "vm-qemu",
			}))
			Expect(backend.FromBundle(newBndl)).To(Equal(backend.VMQemu))
		})

		It("appends /dev/kvm after the existing devices", func() {
			Expect(newBndl.Devices()).To(HaveLen(2))
			Expect(newBndl.Devices()[0].Path).To(Equal("/dev/fuse"))

			kvm := newBndl.Devices()[1]
			Expect(kvm.Path).To(Equal("/dev/kvm"))
			Expect(kvm.Type).To(Equal("c"))
			Expect(kvm.Major).To(Equal(int64(10)))
			Expect(kvm.Minor).To(Equal(int64(232)))
			Expect(*kvm.FileMode).To(Equal(os.FileMode(0o660)))
			Expect(*kvm.UID).To(Equal(uint32(0)))
			Expect(*kvm.GID).To(Equal(uint32(kvmGid)))
		})

		It("appends a cgroup allow rule for c 10:232 rwm after the existing rules", func() {
			rules := newBndl.Resources().Devices
			Expect(rules).To(HaveLen(2))
			Expect(rules[0]).To(Equal(specs.LinuxDeviceCgroup{Allow: false, Access: "rwm"}))

			major, minor := int64(10), int64(232)
			Expect(rules[1]).To(Equal(specs.LinuxDeviceCgroup{Allow: true, Type: "c", Major: &major, Minor: &minor, Access: "rwm"}))
		})

		It("appends read-only binds of the artifacts directory and vm-launch", func() {
			mounts := newBndl.Mounts()
			Expect(mounts).To(HaveLen(3))
			Expect(mounts[0].Destination).To(Equal("/proc"))
			Expect(mounts[1]).To(Equal(specs.Mount{
				Destination: "/opt/garden-vm/artifacts",
				Source:      artifactsDir,
				Type:        "bind",
				Options:     []string{"bind", "ro", "nosuid", "nodev"},
			}))
			Expect(mounts[2]).To(Equal(specs.Mount{
				Destination: "/opt/garden-vm/vm-launch",
				Source:      "/var/vcap/packages/guardian/bin/vm-launch",
				Type:        "bind",
				Options:     []string{"bind", "ro", "nosuid", "nodev"},
			}))
		})

		It("keeps the AppArmor profile, which only the wrapped vm-launch process gives up", func() {
			Expect(newBndl.Process().ApparmorProfile).To(Equal("garden-default"))
		})

		It("does not add /dev/net/tun or its cgroup rule", func() {
			for _, device := range newBndl.Devices() {
				Expect(device.Path).NotTo(Equal("/dev/net/tun"))
			}
			for _, rule := range newBndl.Resources().Devices {
				if rule.Minor != nil {
					Expect(*rule.Minor).NotTo(Equal(int64(200)))
				}
			}
		})

		It("does not modify the input bundle", func() {
			Expect(inputBndl).To(Equal(pristine))
		})

		When("the bundle has no cgroup resources yet", func() {
			BeforeEach(func() {
				inputBndl.Spec.Linux.Resources = nil
			})

			It("creates the allow rule", func() {
				Expect(newBndl.Resources().Devices).To(HaveLen(1))
			})
		})

		for _, rel := range []string{"kernel/bzImage", "qemu/qemu-system-x86_64-microvm", "qemu/ld-linux-x86-64.so.2", "busybox"} {
			rel := rel
			When(rel+" is missing", func() {
				BeforeEach(func() {
					Expect(os.Remove(filepath.Join(artifactsDir, rel))).To(Succeed())
				})

				It("returns ErrBackendUnavailable naming the path", func() {
					Expect(applyErr).To(MatchError(backend.ErrBackendUnavailable))
					Expect(applyErr).To(MatchError(ContainSubstring(filepath.Join(artifactsDir, rel))))
				})
			})
		}

		When("only the firecracker artifacts are missing", func() {
			It("still succeeds", func() {
				Expect(applyErr).NotTo(HaveOccurred())
			})
		})

		When("a required artifact is a directory", func() {
			BeforeEach(func() {
				Expect(os.Remove(filepath.Join(artifactsDir, "busybox"))).To(Succeed())
				Expect(os.Mkdir(filepath.Join(artifactsDir, "busybox"), 0o755)).To(Succeed())
			})

			It("returns ErrBackendUnavailable", func() {
				Expect(applyErr).To(MatchError(backend.ErrBackendUnavailable))
				Expect(applyErr).To(MatchError(ContainSubstring("regular file")))
			})
		})
	})

	When("the backend is vm-firecracker with a stack image directory", func() {
		BeforeEach(func() {
			desiredSpec.ExecutionBackend = string(backend.VMFirecracker)
			desiredSpec.VMStackDir = "/var/vcap/data/vm-runtime/stacks/abc"
			touch("kernel/vmlinux")
			touch("firecracker/firecracker")
			touch("busybox")
		})

		It("binds the directory read-only after the artifacts and vm-launch binds", func() {
			mounts := newBndl.Mounts()
			Expect(mounts).To(HaveLen(4))
			Expect(mounts[1].Destination).To(Equal("/opt/garden-vm/artifacts"))
			Expect(mounts[2].Destination).To(Equal("/opt/garden-vm/vm-launch"))
			Expect(mounts[3]).To(Equal(specs.Mount{
				Destination: "/opt/garden-vm/stack",
				Source:      "/var/vcap/data/vm-runtime/stacks/abc",
				Type:        "bind",
				Options:     []string{"bind", "ro", "nosuid", "nodev", "noexec"},
			}))
			Expect(bundlerules.VMStackMountPath).To(Equal("/opt/garden-vm/stack"))
		})
	})

	When("the backend is oci-gvisor with a stack image directory", func() {
		BeforeEach(func() {
			desiredSpec.ExecutionBackend = string(backend.OCIGvisor)
			desiredSpec.VMStackDir = "/var/vcap/data/vm-runtime/stacks/abc"
		})

		It("adds no mount", func() {
			Expect(applyErr).NotTo(HaveOccurred())
			Expect(newBndl.Mounts()).To(Equal(inputBndl.Mounts()))
		})
	})

	When("the backend is vm-firecracker", func() {
		BeforeEach(func() {
			desiredSpec.ExecutionBackend = string(backend.VMFirecracker)
			touch("kernel/vmlinux")
			touch("firecracker/firecracker")
			touch("busybox")
		})

		It("sets the annotation, devices, cgroup rules, and mounts", func() {
			Expect(applyErr).NotTo(HaveOccurred())
			Expect(backend.FromBundle(newBndl)).To(Equal(backend.VMFirecracker))
			Expect(newBndl.Devices()).To(HaveLen(3))
			Expect(newBndl.Devices()[1].Path).To(Equal("/dev/kvm"))
			Expect(newBndl.Resources().Devices).To(HaveLen(3))
			Expect(newBndl.Mounts()).To(HaveLen(3))
		})

		It("keeps the existing device and cgroup rule ahead of the added ones", func() {
			Expect(newBndl.Devices()[0].Path).To(Equal("/dev/fuse"))
			Expect(newBndl.Resources().Devices[0]).To(Equal(specs.LinuxDeviceCgroup{Allow: false, Access: "rwm"}))
		})

		It("appends /dev/net/tun after /dev/kvm", func() {
			tun := newBndl.Devices()[2]
			Expect(tun.Path).To(Equal("/dev/net/tun"))
			Expect(tun.Type).To(Equal("c"))
			Expect(tun.Major).To(Equal(int64(10)))
			Expect(tun.Minor).To(Equal(int64(200)))
			Expect(*tun.FileMode).To(Equal(os.FileMode(0o666)))
			Expect(*tun.UID).To(Equal(uint32(0)))
			Expect(*tun.GID).To(Equal(uint32(0)))
		})

		It("appends a cgroup allow rule for c 10:200 rwm after the kvm rule", func() {
			major, minor := int64(10), int64(200)
			Expect(newBndl.Resources().Devices[2]).To(Equal(specs.LinuxDeviceCgroup{Allow: true, Type: "c", Major: &major, Minor: &minor, Access: "rwm"}))
		})

		It("does not modify the input bundle", func() {
			Expect(inputBndl).To(Equal(pristine))
		})

		It("keeps the AppArmor profile", func() {
			Expect(newBndl.Process().ApparmorProfile).To(Equal("garden-default"))
		})

		It("gives /dev/kvm the kvm gid", func() {
			Expect(*newBndl.Devices()[1].GID).To(Equal(uint32(kvmGid)))
		})

		It("does not require the QEMU artifacts", func() {
			Expect(applyErr).NotTo(HaveOccurred())
		})

		When("the firecracker binary is missing", func() {
			BeforeEach(func() {
				Expect(os.Remove(filepath.Join(artifactsDir, "firecracker/firecracker"))).To(Succeed())
			})

			It("returns ErrBackendUnavailable naming the path", func() {
				Expect(applyErr).To(MatchError(backend.ErrBackendUnavailable))
				Expect(applyErr).To(MatchError(ContainSubstring(filepath.Join(artifactsDir, "firecracker/firecracker"))))
			})
		})

		When("the artifacts directory does not exist", func() {
			BeforeEach(func() {
				rule.ArtifactsDir = filepath.Join(artifactsDir, "nope")
			})

			It("returns ErrBackendUnavailable", func() {
				Expect(applyErr).To(MatchError(backend.ErrBackendUnavailable))
			})
		})

		When("the required artifact table is replaced", func() {
			BeforeEach(func() {
				rule.RequiredArtifacts = map[backend.Kind][]string{backend.VMFirecracker: {"custom/file"}}
			})

			It("checks the replacement list", func() {
				Expect(applyErr).To(MatchError(ContainSubstring(filepath.Join(artifactsDir, "custom/file"))))

				touch("custom/file")
				_, err := rule.Apply(inputBndl, desiredSpec)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
		kind := kind

		When("the backend is "+string(kind), func() {
			BeforeEach(func() {
				desiredSpec.ExecutionBackend = string(kind)
				for _, rel := range bundlerules.DefaultVMArtifacts[kind] {
					touch(rel)
				}
			})

			It("removes CAP_SETGID from every capability set of the bundle process", func() {
				Expect(applyErr).NotTo(HaveOccurred())
				caps := newBndl.Process().Capabilities
				Expect(caps).NotTo(BeNil())
				for _, set := range [][]string{caps.Bounding, caps.Effective, caps.Inheritable, caps.Permitted, caps.Ambient} {
					Expect(set).NotTo(ContainElement("CAP_SETGID"))
				}
				Expect(caps.Bounding).To(Equal([]string{"CAP_CHOWN", "CAP_SETUID", "CAP_KILL"}))
				Expect(caps.Effective).To(Equal([]string{"CAP_CHOWN", "CAP_SETUID", "CAP_KILL"}))
				Expect(caps.Inheritable).To(Equal([]string{"CAP_CHOWN", "CAP_SETUID", "CAP_KILL"}))
				Expect(caps.Permitted).To(Equal([]string{"CAP_CHOWN", "CAP_SETUID", "CAP_KILL"}))
				Expect(caps.Ambient).To(BeEmpty())
			})

			It("ignores bind mounts while block volumes are off, which is the default", func() {
				Expect(applyErr).NotTo(HaveOccurred())
				Expect(rule.BlockVolumes).To(BeNil())

				withDescriptor := desiredSpec
				withDescriptor.Handle = "handle-1"
				withDescriptor.BindMounts = []garden.BindMount{
					{SrcPath: "/var/vcap/data/volumes/bosh-disk/vol-1", DstPath: "/var/vcap/data/disk", Mode: garden.BindMountModeRW},
				}
				bndl, err := rule.Apply(inputBndl, withDescriptor)
				Expect(err).NotTo(HaveOccurred())
				Expect(bndl).To(Equal(newBndl))
			})

			It("sets NoNewPrivileges so a setgid binary cannot change the effective gid", func() {
				Expect(newBndl.Process().NoNewPrivileges).To(BeTrue())
			})

			It("does not modify the input bundle's capabilities", func() {
				Expect(inputBndl.Process().Capabilities).To(Equal(pristine.Process().Capabilities))
				Expect(inputBndl.Process().NoNewPrivileges).To(BeFalse())
			})

			When("the bundle process has no capabilities", func() {
				BeforeEach(func() {
					inputBndl.Spec.Process.Capabilities = nil
				})

				It("leaves them unset", func() {
					Expect(applyErr).NotTo(HaveOccurred())
					Expect(newBndl.Process().Capabilities).To(BeNil())
				})
			})

			When("the bundle has no process", func() {
				BeforeEach(func() {
					inputBndl.Spec.Process = nil
				})

				It("returns ErrBackendUnavailable", func() {
					Expect(applyErr).To(MatchError(backend.ErrBackendUnavailable))
				})
			})

			When("the kvm gid is not configured", func() {
				BeforeEach(func() {
					rule.KVMGid = 0
				})

				It("returns ErrBackendUnavailable instead of a node only root can open", func() {
					Expect(applyErr).To(MatchError(backend.ErrBackendUnavailable))
					Expect(applyErr).To(MatchError(ContainSubstring("kvm gid")))
				})
			})
		})
	}
})

var _ = Describe("the virtiofsd wrapper's path in a vm-* container", func() {
	It("sits under the artifacts mount, where the runtime config installs it", func() {
		Expect(bundlerules.VMVirtiofsdPath).To(Equal("/opt/garden-vm/artifacts/virtiofsd/virtiofsd-wrapper"))
		Expect(bundlerules.VMVirtiofsdPath).To(HavePrefix(bundlerules.VMArtifactsMountPath + "/"))
	})
})
