package processes_test

import (
	"os"
	"path/filepath"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/rundmc/bundlerules"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/processes"
	fakes "code.cloudfoundry.org/guardian/rundmc/processes/processesfakes"
	"code.cloudfoundry.org/guardian/rundmc/users"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

var _ = Describe("ProcBuilder", func() {
	var (
		envDeterminer  *fakes.FakeEnvDeterminer
		nonRootMaxCaps = []string{"CAP_FOO", "CAP_BAZ"}

		procBuilder *processes.ProcBuilder

		bndl        goci.Bndl
		processSpec garden.ProcessSpec
		user        *users.ExecUser
		tmpRootFS   string
	)

	BeforeEach(func() {
		var err error
		tmpRootFS, err = os.MkdirTemp("", "rootfs")
		Expect(err).NotTo(HaveOccurred())
		Expect(os.MkdirAll(filepath.Join(tmpRootFS, "dir"), 0755)).To(Succeed())

		envDeterminer = new(fakes.FakeEnvDeterminer)
		envDeterminer.EnvForReturns([]string{"ENV"})

		bndl = goci.Bundle().
			WithRootFS(tmpRootFS).
			WithHostname("some-hostname").
			WithUIDMappings(specs.LinuxIDMapping{
				ContainerID: 0,
				HostID:      10,
				Size:        100,
			}).
			WithGIDMappings(specs.LinuxIDMapping{
				ContainerID: 0,
				HostID:      20,
				Size:        100,
			}).
			WithProcess(specs.Process{
				ApparmorProfile: "default-profile",
			}).
			WithCapabilities("CAP_FOO", "CAP_BAR")
		processSpec = garden.ProcessSpec{
			Path: "program",
			Args: []string{"and", "args"},
			User: "Froderick",
			Dir:  "dir",
			Limits: garden.ResourceLimits{
				As:         ptr(12),
				Core:       ptr(24),
				Cpu:        ptr(36),
				Data:       ptr(99),
				Fsize:      ptr(101),
				Locks:      ptr(111),
				Memlock:    ptr(987),
				Msgqueue:   ptr(777),
				Nice:       ptr(111),
				Nofile:     ptr(222),
				Nproc:      ptr(1234),
				Rss:        ptr(888),
				Rtprio:     ptr(254),
				Sigpending: ptr(101),
				Stack:      ptr(44),
			},
		}
		user = &users.ExecUser{
			Uid:   1,
			Gid:   2,
			Sgids: []int{5, 6, 7},
		}
	})

	AfterEach(func() {
		Expect(os.RemoveAll(tmpRootFS)).To(Succeed())
	})

	Describe("the kvm gid of a vm-launch process", func() {
		const kvmGid = 108

		var (
			builderOpts  []processes.Option
			annotations  map[string]string
			marked       bool
			preparedProc *specs.Process
		)

		BeforeEach(func() {
			builderOpts = []processes.Option{processes.WithKVMGid(kvmGid)}
			annotations = map[string]string{backend.AnnotationKey: string(backend.VMQemu)}
			processSpec.Path = bundlerules.VMLaunchMountPath
			processSpec.Env = []string{"A=b"}
			marked = true
		})

		JustBeforeEach(func() {
			bndl.Spec.Annotations = annotations
			if marked {
				processSpec = processes.MarkVMLaunch(processSpec)
			}
			procBuilder = processes.NewBuilder(envDeterminer, nonRootMaxCaps, builderOpts...)
			preparedProc = procBuilder.BuildProcess(bndl, processSpec, user)
		})

		for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			kind := kind

			Context("with a "+string(kind)+" bundle", func() {
				BeforeEach(func() {
					annotations = map[string]string{backend.AnnotationKey: string(kind)}
				})

				It("appends the kvm gid after the user's own supplementary gids", func() {
					Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{5, 6, 7, kvmGid}))
				})

				Context("when the user already has the kvm gid", func() {
					BeforeEach(func() {
						user.Sgids = []int{5, kvmGid}
					})

					It("does not add it twice", func() {
						Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{5, kvmGid}))
					})
				})

				Context("when the user has no supplementary gids", func() {
					BeforeEach(func() {
						user.Sgids = nil
					})

					It("carries only the kvm gid", func() {
						Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{kvmGid}))
					})
				})

				Context("when the process is not vm-launch", func() {
					BeforeEach(func() {
						processSpec.Path = "/tmp/lifecycle/launcher"
					})

					It("leaves the gids alone", func() {
						Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{5, 6, 7}))
					})

					Context("and the user has the kvm gid as a supplementary gid", func() {
						BeforeEach(func() {
							user.Sgids = []int{5, kvmGid, 7, kvmGid}
						})

						It("removes every copy of it and keeps the other gids in order", func() {
							Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{5, 7}))
						})
					})

					Context("and a supplementary gid narrows to the kvm gid", func() {
						BeforeEach(func() {
							user.Sgids = []int{5, kvmGid + 1<<32}
						})

						It("removes it, because the runtime would receive the kvm gid", func() {
							Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{5}))
						})
					})
				})

				It("removes the provenance marker before building the environment", func() {
					Expect(envDeterminer.EnvForCallCount()).To(Equal(1))
					_, envSpec, _ := envDeterminer.EnvForArgsForCall(0)
					Expect(envSpec.Env).To(Equal([]string{"A=b"}))
				})

				Context("when vm-launch is run directly, without the containerizer's marker", func() {
					BeforeEach(func() {
						marked = false
					})

					It("gets no kvm gid", func() {
						Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{5, 6, 7}))
					})

					It("keeps the bundle's AppArmor profile", func() {
						Expect(preparedProc.ApparmorProfile).To(Equal("default-profile"))
					})

					Context("and the user has the kvm gid as a supplementary gid", func() {
						BeforeEach(func() {
							user.Sgids = []int{kvmGid, 6}
						})

						It("removes it", func() {
							Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{6}))
						})
					})
				})

				Context("when the marker carries another value", func() {
					BeforeEach(func() {
						marked = false
						processSpec.Env = append(processSpec.Env, "__GARDEN_VM_LAUNCH_WRAPPED=yes", "__GARDEN_VM_LAUNCH_WRAPPED")
					})

					It("gets no kvm gid and the variants are removed", func() {
						Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{5, 6, 7}))
						_, envSpec, _ := envDeterminer.EnvForArgsForCall(0)
						Expect(envSpec.Env).To(Equal([]string{"A=b"}))
					})

					Context("and the user has the kvm gid as a supplementary gid", func() {
						BeforeEach(func() {
							user.Sgids = []int{5, kvmGid}
						})

						It("removes it", func() {
							Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{5}))
						})
					})
				})
			})
		}

		Describe("the AppArmor profile of the wrapped vm-launch process", func() {
			// runc applies the container's profile to an exec'd process unless
			// the process names a non-empty profile, so an empty profile here
			// would leave QEMU confined.
			It("is set to unconfined in a vm-qemu bundle, so QEMU can signal its vCPU threads", func() {
				Expect(preparedProc.ApparmorProfile).To(Equal("unconfined"))
			})

			Context("in a vm-qemu bundle without an AppArmor profile", func() {
				BeforeEach(func() {
					bndl = bndl.WithApparmorProfile("")
				})

				It("names no profile, because there is nothing to lift", func() {
					Expect(preparedProc.ApparmorProfile).To(BeEmpty())
				})
			})

			Context("in a vm-firecracker bundle", func() {
				BeforeEach(func() {
					annotations = map[string]string{backend.AnnotationKey: string(backend.VMFirecracker)}
				})

				It("keeps the bundle's profile", func() {
					Expect(preparedProc.ApparmorProfile).To(Equal("default-profile"))
				})
			})

			Context("for any other process in a vm-qemu bundle", func() {
				BeforeEach(func() {
					processSpec.Path = "/tmp/lifecycle/diego-sshd"
				})

				It("keeps the bundle's profile even when marked", func() {
					Expect(preparedProc.ApparmorProfile).To(Equal("default-profile"))
				})
			})
		})

		for _, annotation := range []map[string]string{
			nil,
			{backend.AnnotationKey: string(backend.OCIRunc)},
			{backend.AnnotationKey: string(backend.OCIGvisor)},
		} {
			annotation := annotation

			Context("with a non-vm bundle annotated", func() {
				BeforeEach(func() {
					annotations = annotation
				})

				It("leaves the gids alone even for the vm-launch path", func() {
					Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{5, 6, 7}))
				})

				Context("when the user has the kvm gid as a supplementary gid", func() {
					BeforeEach(func() {
						user.Sgids = []int{5, kvmGid}
						processSpec.Path = "/tmp/lifecycle/launcher"
					})

					It("keeps it, because the container has no kvm device", func() {
						Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{5, kvmGid}))
					})
				})
			})
		}

		Context("when no kvm gid is configured", func() {
			BeforeEach(func() {
				builderOpts = nil
			})

			It("leaves the gids alone", func() {
				Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{5, 6, 7}))
			})

			Context("and an unwrapped process has gid 0 as a supplementary gid", func() {
				BeforeEach(func() {
					user.Sgids = []int{0, 5}
					processSpec.Path = "/tmp/lifecycle/launcher"
				})

				It("keeps it", func() {
					Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{0, 5}))
				})
			})
		})

		Context("when the kvm gid is configured as zero", func() {
			BeforeEach(func() {
				builderOpts = []processes.Option{processes.WithKVMGid(0)}
			})

			It("leaves the gids alone", func() {
				Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{5, 6, 7}))
			})
		})
	})

	Describe("confinement of every process in a vm-* bundle", func() {
		var (
			annotations  map[string]string
			preparedProc *specs.Process
		)

		BeforeEach(func() {
			bndl = bndl.WithCapabilities("CAP_FOO", "CAP_SETGID", "CAP_BAR")
			user.Gid = 0
			processSpec.Env = []string{"A=b", "__GARDEN_VM_LAUNCH_WRAPPED=1"}
		})

		JustBeforeEach(func() {
			bndl.Spec.Annotations = annotations
			procBuilder = processes.NewBuilder(envDeterminer, nonRootMaxCaps, processes.WithKVMGid(108))
			preparedProc = procBuilder.BuildProcess(bndl, processSpec, user)
		})

		for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			kind := kind

			Context("with a "+string(kind)+" bundle", func() {
				BeforeEach(func() {
					annotations = map[string]string{backend.AnnotationKey: string(kind)}
				})

				It("drops CAP_SETGID from every capability set, even for root", func() {
					Expect(preparedProc.Capabilities.Bounding).To(Equal([]string{"CAP_FOO", "CAP_BAR"}))
					Expect(preparedProc.Capabilities.Inheritable).To(Equal([]string{"CAP_FOO", "CAP_BAR"}))
					Expect(preparedProc.Capabilities.Permitted).To(Equal([]string{"CAP_FOO", "CAP_BAR"}))
					Expect(preparedProc.Capabilities.Effective).To(BeNil())
					Expect(preparedProc.Capabilities.Ambient).To(BeNil())
				})

				It("sets NoNewPrivileges", func() {
					Expect(preparedProc.NoNewPrivileges).To(BeTrue())
				})

				It("removes a marker from a process that is not vm-launch", func() {
					_, envSpec, _ := envDeterminer.EnvForArgsForCall(0)
					Expect(envSpec.Env).To(Equal([]string{"A=b"}))
					Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{5, 6, 7}))
				})
			})
		}

		for _, annotation := range []map[string]string{
			nil,
			{backend.AnnotationKey: string(backend.OCIRunc)},
			{backend.AnnotationKey: string(backend.OCIGvisor)},
		} {
			annotation := annotation

			Context("with a non-vm bundle", func() {
				BeforeEach(func() {
					annotations = annotation
				})

				It("keeps CAP_SETGID", func() {
					Expect(preparedProc.Capabilities.Bounding).To(Equal([]string{"CAP_FOO", "CAP_SETGID", "CAP_BAR"}))
				})

				It("passes NoNewPrivileges from the bundle", func() {
					Expect(preparedProc.NoNewPrivileges).To(BeFalse())
				})

				It("passes the environment through unchanged", func() {
					_, envSpec, _ := envDeterminer.EnvForArgsForCall(0)
					Expect(envSpec.Env).To(Equal([]string{"A=b", "__GARDEN_VM_LAUNCH_WRAPPED=1"}))
				})
			})
		}
	})

	Describe("CheckUser", func() {
		const kvmGid = 991

		var (
			builderOpts []processes.Option
			annotations map[string]string
			checkErr    error
		)

		BeforeEach(func() {
			builderOpts = []processes.Option{processes.WithKVMGid(kvmGid)}
			annotations = map[string]string{backend.AnnotationKey: string(backend.VMQemu)}
			processSpec.User = "vcap"
			user.Gid = 2000
			user.Sgids = []int{kvmGid}
		})

		JustBeforeEach(func() {
			bndl.Spec.Annotations = annotations
			procBuilder = processes.NewBuilder(envDeterminer, nonRootMaxCaps, builderOpts...)
			checkErr = procBuilder.CheckUser(bndl, processSpec, user)
		})

		for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			kind := kind

			Context("with a "+string(kind)+" bundle", func() {
				BeforeEach(func() {
					annotations = map[string]string{backend.AnnotationKey: string(kind)}
				})

				It("accepts a user that has the kvm gid only as a supplementary gid, which BuildProcess removes", func() {
					Expect(checkErr).NotTo(HaveOccurred())
				})

				Context("when the user's primary gid is the kvm gid", func() {
					BeforeEach(func() {
						user.Gid = kvmGid
					})

					It("refuses the process and names the user, the gid, and the backend", func() {
						Expect(checkErr).To(MatchError(processes.ErrKVMPrimaryGid))
						Expect(checkErr.Error()).To(ContainSubstring(`process user "vcap" resolves to gid 991 in this ` + string(kind) + ` container`))
					})

					Context("and the process is the wrapped vm-launch process", func() {
						BeforeEach(func() {
							processSpec.Path = processes.VMLaunchPath
							processSpec = processes.MarkVMLaunch(processSpec)
						})

						It("refuses it too", func() {
							Expect(checkErr).To(MatchError(processes.ErrKVMPrimaryGid))
						})
					})
				})

				Context("when the user's primary gid narrows to the kvm gid", func() {
					BeforeEach(func() {
						user.Gid = kvmGid + 1<<32
					})

					It("refuses the process, because the runtime would receive the kvm gid", func() {
						Expect(checkErr).To(MatchError(processes.ErrKVMPrimaryGid))
					})
				})
			})
		}

		for _, annotation := range []map[string]string{
			nil,
			{backend.AnnotationKey: string(backend.OCIRunc)},
			{backend.AnnotationKey: string(backend.OCIGvisor)},
		} {
			annotation := annotation

			Context("with a non-vm bundle", func() {
				BeforeEach(func() {
					annotations = annotation
					user.Gid = kvmGid
				})

				It("accepts the kvm gid as a primary gid, because the container has no kvm device", func() {
					Expect(checkErr).NotTo(HaveOccurred())
				})
			})
		}

		Context("when no kvm gid is configured", func() {
			BeforeEach(func() {
				builderOpts = nil
				user.Gid = 0
			})

			It("accepts every user, root included", func() {
				Expect(checkErr).NotTo(HaveOccurred())
			})
		})

		Context("when there is no resolved user", func() {
			BeforeEach(func() {
				user = nil
			})

			It("returns an error", func() {
				Expect(checkErr).To(MatchError("check process user: no resolved user"))
			})
		})
	})

	Describe("the kvm gid in the image's /etc/passwd and /etc/group", func() {
		const kvmGid = 991

		var (
			imageRootFS string
			lookupName  string
			lookedUp    *users.ExecUser
			checkErr    error
			prepared    *specs.Process
		)

		writeImageFile := func(name, content string) {
			Expect(os.WriteFile(filepath.Join(imageRootFS, "etc", name), []byte(content), 0644)).To(Succeed())
		}

		BeforeEach(func() {
			var err error
			imageRootFS, err = os.MkdirTemp("", "image-rootfs")
			Expect(err).NotTo(HaveOccurred())
			Expect(os.MkdirAll(filepath.Join(imageRootFS, "etc"), 0755)).To(Succeed())

			writeImageFile("passwd", "root:x:0:0:root:/root:/bin/sh\nvcap:x:2000:2000::/home/vcap:/bin/sh\n")
			writeImageFile("group", "root:x:0:\nvcap:x:2000:\nkvm:x:991:vcap\n")

			bndl.Spec.Annotations = map[string]string{backend.AnnotationKey: string(backend.VMFirecracker)}
			processSpec.User = "vcap"
			processSpec.Path = "/tmp/lifecycle/diego-sshd"
			lookupName = "vcap"
		})

		AfterEach(func() {
			Expect(os.RemoveAll(imageRootFS)).To(Succeed())
		})

		JustBeforeEach(func() {
			var err error
			lookedUp, err = users.LookupUser(imageRootFS, lookupName)
			Expect(err).NotTo(HaveOccurred())

			procBuilder = processes.NewBuilder(envDeterminer, nonRootMaxCaps, processes.WithKVMGid(kvmGid))
			checkErr = procBuilder.CheckUser(bndl, processSpec, lookedUp)
			prepared = procBuilder.BuildProcess(bndl, processSpec, lookedUp)
		})

		Context("when the image's group file makes vcap a member of the kvm group", func() {
			It("resolves the kvm gid as a supplementary gid", func() {
				Expect(lookedUp.Sgids).To(ContainElement(kvmGid))
			})

			It("accepts the user but removes the kvm gid from a process that is not the wrapped vm-launch", func() {
				Expect(checkErr).NotTo(HaveOccurred())
				Expect(prepared.User.GID).To(Equal(uint32(2000)))
				Expect(prepared.User.AdditionalGids).NotTo(ContainElement(uint32(kvmGid)))
			})

			Context("and the process is the wrapped vm-launch process", func() {
				BeforeEach(func() {
					processSpec.Path = processes.VMLaunchPath
					processSpec = processes.MarkVMLaunch(processSpec)
				})

				It("still carries the kvm gid, once", func() {
					Expect(checkErr).NotTo(HaveOccurred())
					count := 0
					for _, gid := range prepared.User.AdditionalGids {
						if gid == kvmGid {
							count++
						}
					}
					Expect(count).To(Equal(1))
				})
			})
		})

		Context("when the image's passwd file gives vcap the kvm gid as its primary gid", func() {
			BeforeEach(func() {
				writeImageFile("passwd", "root:x:0:0:root:/root:/bin/sh\nvcap:x:2000:991::/home/vcap:/bin/sh\n")
				writeImageFile("group", "root:x:0:\nvcap:x:2000:\n")
			})

			It("refuses the process", func() {
				Expect(lookedUp.Gid).To(Equal(kvmGid))
				Expect(checkErr).To(MatchError(processes.ErrKVMPrimaryGid))
			})
		})

		Context("when the process user names the kvm gid as uid:gid", func() {
			BeforeEach(func() {
				lookupName = "2000:991"
				processSpec.User = lookupName
			})

			It("refuses the process", func() {
				Expect(lookedUp.Gid).To(Equal(kvmGid))
				Expect(checkErr).To(MatchError(processes.ErrKVMPrimaryGid))
			})
		})

		Context("when the image's root user has the kvm gid as its primary gid", func() {
			BeforeEach(func() {
				writeImageFile("passwd", "root:x:0:991:root:/root:/bin/sh\n")
				lookupName = ""
				processSpec.User = ""
			})

			It("refuses a process that runs as the default user", func() {
				Expect(lookedUp.Uid).To(Equal(0))
				Expect(lookedUp.Gid).To(Equal(kvmGid))
				Expect(checkErr).To(MatchError(processes.ErrKVMPrimaryGid))
			})
		})
	})

	Describe("the vm-launch provenance marker", func() {
		It("is added once by MarkVMLaunch and found by UnmarkVMLaunch", func() {
			original := garden.ProcessSpec{Path: processes.VMLaunchPath, Env: []string{"A=b", "__GARDEN_VM_LAUNCH_WRAPPED=forged"}}

			marked := processes.MarkVMLaunch(original)
			Expect(marked.Env).To(Equal([]string{"A=b", "__GARDEN_VM_LAUNCH_WRAPPED=1"}))
			Expect(original.Env).To(Equal([]string{"A=b", "__GARDEN_VM_LAUNCH_WRAPPED=forged"}))

			unmarked, found := processes.UnmarkVMLaunch(marked)
			Expect(found).To(BeTrue())
			Expect(unmarked.Env).To(Equal([]string{"A=b"}))
			Expect(marked.Env).To(Equal([]string{"A=b", "__GARDEN_VM_LAUNCH_WRAPPED=1"}))
		})

		It("reports no marker for variants but still removes them", func() {
			spec, found := processes.UnmarkVMLaunch(garden.ProcessSpec{Env: []string{"__GARDEN_VM_LAUNCH_WRAPPED", "B=c", "__GARDEN_VM_LAUNCH_WRAPPED=0"}})
			Expect(found).To(BeFalse())
			Expect(spec.Env).To(Equal([]string{"B=c"}))
		})

		It("returns the spec as is when there is no marker", func() {
			env := []string{"A=b"}
			spec, found := processes.UnmarkVMLaunch(garden.ProcessSpec{Env: env})
			Expect(found).To(BeFalse())
			Expect(spec.Env).To(Equal(env))

			spec, found = processes.UnmarkVMLaunch(garden.ProcessSpec{})
			Expect(found).To(BeFalse())
			Expect(spec.Env).To(BeNil())
		})

		It("does not treat a similarly named variable as the marker", func() {
			spec, found := processes.UnmarkVMLaunch(garden.ProcessSpec{Env: []string{"__GARDEN_VM_LAUNCH_WRAPPED_X=1"}})
			Expect(found).To(BeFalse())
			Expect(spec.Env).To(Equal([]string{"__GARDEN_VM_LAUNCH_WRAPPED_X=1"}))
		})
	})

	Describe("WithoutCapability", func() {
		It("returns nil for nil", func() {
			Expect(processes.WithoutCapability(nil, "CAP_SETGID")).To(BeNil())
		})

		It("removes the capability from every set without touching the input", func() {
			shared := []string{"CAP_A", "CAP_SETGID"}
			caps := &specs.LinuxCapabilities{Bounding: shared, Effective: shared, Inheritable: shared, Permitted: shared, Ambient: []string{"CAP_SETGID"}}

			out := processes.WithoutCapability(caps, "CAP_SETGID")
			Expect(out).To(Equal(&specs.LinuxCapabilities{
				Bounding:    []string{"CAP_A"},
				Effective:   []string{"CAP_A"},
				Inheritable: []string{"CAP_A"},
				Permitted:   []string{"CAP_A"},
				Ambient:     []string{},
			}))
			Expect(shared).To(Equal([]string{"CAP_A", "CAP_SETGID"}))
			Expect(caps.Ambient).To(Equal([]string{"CAP_SETGID"}))
		})
	})

	Describe("the built process", func() {
		var preparedProc *specs.Process

		JustBeforeEach(func() {
			procBuilder = processes.NewBuilder(envDeterminer, nonRootMaxCaps)
			preparedProc = procBuilder.BuildProcess(bndl, processSpec, user)
		})

		It("merges the path and args to create the argv", func() {
			Expect(preparedProc.Args).To(Equal([]string{"program", "and", "args"}))
		})

		Context("when the bundle has no mappings for host root (container is privileged)", func() {
			BeforeEach(func() {
				bndl.Spec.Linux.UIDMappings = nil
				bndl.Spec.Linux.GIDMappings = nil
			})

			It("sets the rlimits correctly", func() {
				Expect(preparedProc.Rlimits).To(ConsistOf(
					specs.POSIXRlimit{Type: "RLIMIT_AS", Hard: 12, Soft: 12},
					specs.POSIXRlimit{Type: "RLIMIT_CORE", Hard: 24, Soft: 24},
					specs.POSIXRlimit{Type: "RLIMIT_CPU", Hard: 36, Soft: 36},
					specs.POSIXRlimit{Type: "RLIMIT_DATA", Hard: 99, Soft: 99},
					specs.POSIXRlimit{Type: "RLIMIT_FSIZE", Hard: 101, Soft: 101},
					specs.POSIXRlimit{Type: "RLIMIT_LOCKS", Hard: 111, Soft: 111},
					specs.POSIXRlimit{Type: "RLIMIT_MEMLOCK", Hard: 987, Soft: 987},
					specs.POSIXRlimit{Type: "RLIMIT_MSGQUEUE", Hard: 777, Soft: 777},
					specs.POSIXRlimit{Type: "RLIMIT_NICE", Hard: 111, Soft: 111},
					specs.POSIXRlimit{Type: "RLIMIT_NOFILE", Hard: 222, Soft: 222},
					specs.POSIXRlimit{Type: "RLIMIT_NPROC", Hard: 1234, Soft: 1234},
					specs.POSIXRlimit{Type: "RLIMIT_RSS", Hard: 888, Soft: 888},
					specs.POSIXRlimit{Type: "RLIMIT_RTPRIO", Hard: 254, Soft: 254},
					specs.POSIXRlimit{Type: "RLIMIT_SIGPENDING", Hard: 101, Soft: 101},
					specs.POSIXRlimit{Type: "RLIMIT_STACK", Hard: 44, Soft: 44},
				))
			})

			Context("when no TTY is specified", func() {
				It("sets terminal to false", func() {
					Expect(preparedProc.Terminal).To(BeFalse())
				})

				It("sets a default console size anyway, which will not be used", func() {
					Expect(preparedProc.ConsoleSize.Height).To(BeEquivalentTo(24))
					Expect(preparedProc.ConsoleSize.Width).To(BeEquivalentTo(80))
				})
			})

			Context("when a TTY is specified", func() {
				BeforeEach(func() {
					processSpec.TTY = &garden.TTYSpec{
						WindowSize: &garden.WindowSize{
							Columns: 25,
							Rows:    81,
						},
					}
				})

				It("sets the console size", func() {
					Expect(preparedProc.ConsoleSize.Width).To(BeEquivalentTo(25))
					Expect(preparedProc.ConsoleSize.Height).To(BeEquivalentTo(81))
				})

				It("sets terminal to false", func() {
					Expect(preparedProc.Terminal).To(BeTrue())
				})

				Context("when the user is root", func() {
					BeforeEach(func() {
						user.Uid = 0
						user.Gid = 0
					})

					It("passes the specified capabilities", func() {
						caps := []string{"CAP_FOO", "CAP_BAR"}
						Expect(preparedProc.Capabilities.Effective).To(BeEmpty())
						Expect(preparedProc.Capabilities.Bounding).To(Equal(caps))
						Expect(preparedProc.Capabilities.Inheritable).To(Equal(caps))
						Expect(preparedProc.Capabilities.Permitted).To(Equal(caps))
						Expect(preparedProc.Capabilities.Ambient).To(BeEmpty())
					})
				})

				Context("when the user is not root", func() {
					It("passes the intersection of the specified capabilites and the non-root max capabilities", func() {
						caps := []string{"CAP_FOO"}
						Expect(preparedProc.Capabilities.Effective).To(BeEmpty())
						Expect(preparedProc.Capabilities.Bounding).To(Equal(caps))
						Expect(preparedProc.Capabilities.Inheritable).To(Equal(caps))
						Expect(preparedProc.Capabilities.Permitted).To(Equal(caps))
						Expect(preparedProc.Capabilities.Ambient).To(BeEmpty())
					})
				})

				Context("when no capabilities are specified", func() {
					BeforeEach(func() {
						bndl.Spec.Process.Capabilities = nil
					})

					It("does not set the capabilities object on the process", func() {
						Expect(preparedProc.Capabilities).To(BeNil())
					})
				})

				It("passes the AppArmor profile", func() {
					Expect(preparedProc.ApparmorProfile).To(Equal("default-profile"))
				})

				It("passes NoNewPrivileges from the bundle", func() {
					Expect(preparedProc.NoNewPrivileges).To(BeFalse())
				})

				Context("when the bundle has NoNewPrivileges set", func() {
					BeforeEach(func() {
						bndl.Spec.Process.NoNewPrivileges = true
					})

					It("propagates NoNewPrivileges to the process", func() {
						Expect(preparedProc.NoNewPrivileges).To(BeTrue())
					})
				})

				It("passes the UID, GID and SGIDs", func() {
					Expect(preparedProc.User.UID).To(Equal(uint32(1)))
					Expect(preparedProc.User.GID).To(Equal(uint32(2)))
					Expect(preparedProc.User.AdditionalGids).To(Equal([]uint32{5, 6, 7}))
				})

				It("passes the username, which is used on Windows", func() {
					Expect(preparedProc.User.Username).To(Equal("Froderick"))
				})

				It("passes the working dir", func() {
					Expect(preparedProc.Cwd).To(Equal("dir"))
				})

				It("passes the environment from the EnvDeterminer", func() {
					Expect(envDeterminer.EnvForCallCount()).To(Equal(1))
					actualBndl, actualSpec, actualContainerUID := envDeterminer.EnvForArgsForCall(0)
					Expect(actualBndl).To(Equal(bndl))
					Expect(actualSpec).To(Equal(processSpec))
					Expect(actualContainerUID).To(Equal(user.Uid))
					Expect(preparedProc.Env).To(ConsistOf("ENV"))
				})
			})
		})
	})

	Describe("working directory resolution", func() {
		var (
			preparedProc *specs.Process
			tmpRootFS    string
		)

		BeforeEach(func() {
			var err error
			tmpRootFS, err = os.MkdirTemp("", "rootfs")
			Expect(err).NotTo(HaveOccurred())

			bndl = bndl.WithRootFS(tmpRootFS)
		})

		AfterEach(func() {
			Expect(os.RemoveAll(tmpRootFS)).To(Succeed())
		})

		JustBeforeEach(func() {
			procBuilder = processes.NewBuilder(envDeterminer, nonRootMaxCaps)
			preparedProc = procBuilder.BuildProcess(bndl, processSpec, user)
		})

		Context("when spec.Dir is set", func() {
			BeforeEach(func() {
				processSpec.Dir = "/app"
			})

			Context("and the directory exists", func() {
				BeforeEach(func() {
					Expect(os.MkdirAll(filepath.Join(tmpRootFS, "app"), 0755)).To(Succeed())
				})

				It("uses spec.Dir as Cwd", func() {
					Expect(preparedProc.Cwd).To(Equal("/app"))
				})
			})

			Context("and the directory does not exist", func() {
				It("falls back to '/'", func() {
					Expect(preparedProc.Cwd).To(Equal("/"))
				})
			})
		})

		Context("when spec.Dir is empty", func() {
			BeforeEach(func() {
				processSpec.Dir = ""
				user.Home = "/home/robot"
			})

			Context("and the home directory exists", func() {
				BeforeEach(func() {
					Expect(os.MkdirAll(filepath.Join(tmpRootFS, "home", "robot"), 0755)).To(Succeed())
				})

				It("uses home directory as Cwd", func() {
					Expect(preparedProc.Cwd).To(Equal("/home/robot"))
				})
			})

			Context("and the home directory does not exist", func() {
				It("falls back to '/'", func() {
					Expect(preparedProc.Cwd).To(Equal("/"))
				})
			})
		})

		Context("when both spec.Dir and home are empty", func() {
			BeforeEach(func() {
				processSpec.Dir = ""
				user.Home = ""
			})

			It("falls back to '/'", func() {
				Expect(preparedProc.Cwd).To(Equal("/"))
			})
		})
	})
})

func ptr(i uint64) *uint64 {
	return &i
}
