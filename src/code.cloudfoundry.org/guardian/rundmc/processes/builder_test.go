package processes_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
			It("is set to unconfined in a vm-qemu bundle, until a confined QEMU has been checked on a cell", func() {
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

	Describe("CAP_NET_RAW and the flag for the transparent port proxy", func() {
		var (
			annotations  map[string]string
			marked       bool
			preparedProc *specs.Process
			maxCaps      []string
			// builtEnv is the environment the env determiner builds, which
			// is what the runtime gives the process.
			builtEnv []string
		)

		launcherArgs := []string{"--backend", "vm-firecracker", "--", "/tmp/lifecycle/launcher", "app", "true", ""}

		BeforeEach(func() {
			// The caps a non-root app user gets in an unprivileged container.
			bndl = bndl.WithCapabilities("CAP_CHOWN", "CAP_NET_RAW", "CAP_SETGID", "CAP_KILL")
			maxCaps = []string{"CAP_CHOWN", "CAP_NET_RAW", "CAP_SETGID", "CAP_KILL"}
			annotations = map[string]string{backend.AnnotationKey: string(backend.VMFirecracker)}
			processSpec.Path = processes.VMLaunchPath
			processSpec.Args = launcherArgs
			processSpec.Env = []string{"A=b"}
			builtEnv = []string{"A=b", "PORT=8080", `CF_INSTANCE_PORTS=[{"internal":8080}]`}
			user.Uid, user.Gid = 2000, 2000
			marked = true
		})

		JustBeforeEach(func() {
			envDeterminer.EnvForReturns(builtEnv)
			bndl.Spec.Annotations = annotations
			if marked {
				processSpec = processes.MarkVMLaunch(processSpec)
			}
			procBuilder = processes.NewBuilder(envDeterminer, maxCaps, processes.WithKVMGid(108))
			preparedProc = procBuilder.BuildProcess(bndl, processSpec, user)
		})

		It("puts it in every set of the wrapped vm-launch in a vm-firecracker bundle, ambient and effective included", func() {
			caps := preparedProc.Capabilities
			Expect(caps.Bounding).To(Equal([]string{"CAP_CHOWN", "CAP_NET_RAW", "CAP_KILL"}))
			Expect(caps.Inheritable).To(Equal([]string{"CAP_CHOWN", "CAP_NET_RAW", "CAP_KILL"}))
			Expect(caps.Permitted).To(Equal([]string{"CAP_CHOWN", "CAP_NET_RAW", "CAP_KILL"}))
			// Effective and ambient hold nothing else, so the non-root
			// vm-launch can use CAP_NET_RAW and no other capability.
			Expect(caps.Effective).To(Equal([]string{"CAP_NET_RAW"}))
			Expect(caps.Ambient).To(Equal([]string{"CAP_NET_RAW"}))
			Expect(preparedProc.NoNewPrivileges).To(BeTrue())
		})

		It("passes the flag to that vm-launch, before its own arguments", func() {
			Expect(preparedProc.Args).To(Equal(append([]string{processes.VMLaunchPath, "--transparent-proxy"}, launcherArgs...)))
			Expect(preparedProc.Env).To(Equal(builtEnv))
		})

		// vm-launch reads an empty PORT as set, and exits because it is no
		// port, so the grant follows presence alone.
		Context("when PORT is set but empty", func() {
			BeforeEach(func() {
				builtEnv = []string{"A=b", "PORT="}
			})

			It("still grants it and passes the flag", func() {
				Expect(preparedProc.Capabilities.Ambient).To(Equal([]string{"CAP_NET_RAW"}))
				Expect(preparedProc.Args).To(ContainElement("--transparent-proxy"))
			})
		})

		It("is the capability named CAP_NET_RAW, and the flag vm-launch reads", func() {
			Expect(processes.CapNetRaw).To(Equal("CAP_NET_RAW"))
			Expect(processes.VMLaunchTransparentProxyFlag).To(Equal("--transparent-proxy"))
		})

		Context("when the container's sets lack CAP_NET_RAW", func() {
			BeforeEach(func() {
				bndl = bndl.WithCapabilities("CAP_CHOWN", "CAP_KILL")
			})

			It("adds it at the end of every set", func() {
				caps := preparedProc.Capabilities
				Expect(caps.Bounding).To(Equal([]string{"CAP_CHOWN", "CAP_KILL", "CAP_NET_RAW"}))
				Expect(caps.Inheritable).To(Equal([]string{"CAP_CHOWN", "CAP_KILL", "CAP_NET_RAW"}))
				Expect(caps.Permitted).To(Equal([]string{"CAP_CHOWN", "CAP_KILL", "CAP_NET_RAW"}))
				Expect(caps.Effective).To(Equal([]string{"CAP_NET_RAW"}))
				Expect(caps.Ambient).To(Equal([]string{"CAP_NET_RAW"}))
			})
		})

		Context("when the container has no capabilities", func() {
			BeforeEach(func() {
				bndl = bndl.WithCapabilities()
			})

			It("grants CAP_NET_RAW alone rather than the runtime's default", func() {
				Expect(preparedProc.Capabilities).To(Equal(&specs.LinuxCapabilities{
					Bounding:    []string{"CAP_NET_RAW"},
					Effective:   []string{"CAP_NET_RAW"},
					Inheritable: []string{"CAP_NET_RAW"},
					Permitted:   []string{"CAP_NET_RAW"},
					Ambient:     []string{"CAP_NET_RAW"},
				}))
			})
		})

		Context("for root", func() {
			BeforeEach(func() {
				user.Uid, user.Gid = 0, 0
			})

			It("grants it the same way, still without CAP_SETGID", func() {
				caps := preparedProc.Capabilities
				Expect(caps.Bounding).To(Equal([]string{"CAP_CHOWN", "CAP_NET_RAW", "CAP_KILL"}))
				Expect(caps.Effective).To(Equal([]string{"CAP_NET_RAW"}))
				Expect(caps.Ambient).To(Equal([]string{"CAP_NET_RAW"}))
			})
		})

		expectNoGrant := func() {
			GinkgoHelper()
			caps := preparedProc.Capabilities
			Expect(caps.Effective).To(BeNil())
			Expect(caps.Ambient).To(BeNil())
			Expect(preparedProc.Args).NotTo(ContainElement("--transparent-proxy"))
			Expect(preparedProc.Args).To(Equal(append([]string{processSpec.Path}, processSpec.Args...)))
		}

		// A task, or any other process without PORT, has nothing for the
		// proxy to forward.
		Context("for the wrapped vm-launch of a process without PORT", func() {
			BeforeEach(func() {
				builtEnv = []string{"A=b", `CF_INSTANCE_PORTS=[{"internal":8080}]`}
			})

			It("grants nothing and passes no flag", func() {
				expectNoGrant()
				Expect(preparedProc.Capabilities.Bounding).To(Equal([]string{"CAP_CHOWN", "CAP_NET_RAW", "CAP_KILL"}))
			})
		})

		Context("when only names that merely contain PORT are set", func() {
			BeforeEach(func() {
				builtEnv = []string{"PORTS=8080", "PORT_X=8080", "XPORT=8080", "CF_INSTANCE_PORT=8080"}
			})

			It("grants nothing and passes no flag", func() {
				expectNoGrant()
			})
		})

		Context("when PORT is in the spec but not in the environment the process gets", func() {
			BeforeEach(func() {
				processSpec.Env = []string{"PORT=8080"}
				builtEnv = []string{"A=b"}
			})

			It("goes by the environment the process gets, and grants nothing", func() {
				expectNoGrant()
			})
		})

		Context("for the wrapped vm-launch in a vm-qemu bundle", func() {
			BeforeEach(func() {
				annotations = map[string]string{backend.AnnotationKey: string(backend.VMQemu)}
			})

			It("grants nothing", func() {
				expectNoGrant()
				Expect(preparedProc.Capabilities.Bounding).To(Equal([]string{"CAP_CHOWN", "CAP_NET_RAW", "CAP_KILL"}))
			})
		})

		Context("for vm-launch without the containerizer's marker", func() {
			BeforeEach(func() {
				marked = false
			})

			It("grants nothing", func() {
				expectNoGrant()
			})
		})

		Context("for another process that carries the marker", func() {
			BeforeEach(func() {
				processSpec.Path = "/tmp/lifecycle/diego-sshd"
			})

			It("grants nothing", func() {
				expectNoGrant()
			})
		})

		for _, annotation := range []map[string]string{
			nil,
			{backend.AnnotationKey: string(backend.OCIRunc)},
			{backend.AnnotationKey: string(backend.OCIGvisor)},
		} {
			annotation := annotation

			Context(fmt.Sprintf("for a marked vm-launch path in a bundle annotated %v", annotation), func() {
				BeforeEach(func() {
					annotations = annotation
				})

				It("grants nothing", func() {
					expectNoGrant()
					// Outside a vm-* bundle the marker is not even removed.
					_, envSpec, _ := envDeterminer.EnvForArgsForCall(0)
					Expect(envSpec.Env).To(ContainElement("__GARDEN_VM_LAUNCH_WRAPPED=1"))
				})
			})
		}
	})

	Describe("WithCapability", func() {
		It("adds the capability to every set without touching the input", func() {
			shared := []string{"CAP_A"}
			caps := &specs.LinuxCapabilities{Bounding: shared, Effective: nil, Inheritable: shared, Permitted: shared, Ambient: []string{}}

			out := processes.WithCapability(caps, "CAP_NET_RAW")
			Expect(out).To(Equal(&specs.LinuxCapabilities{
				Bounding:    []string{"CAP_A", "CAP_NET_RAW"},
				Effective:   []string{"CAP_NET_RAW"},
				Inheritable: []string{"CAP_A", "CAP_NET_RAW"},
				Permitted:   []string{"CAP_A", "CAP_NET_RAW"},
				Ambient:     []string{"CAP_NET_RAW"},
			}))
			Expect(shared).To(Equal([]string{"CAP_A"}))
			Expect(caps.Effective).To(BeNil())
			Expect(caps.Ambient).To(BeEmpty())
		})

		It("never adds the capability twice", func() {
			caps := &specs.LinuxCapabilities{Bounding: []string{"CAP_NET_RAW", "CAP_A"}, Ambient: []string{"CAP_NET_RAW"}}
			out := processes.WithCapability(caps, "CAP_NET_RAW")
			Expect(out.Bounding).To(Equal([]string{"CAP_NET_RAW", "CAP_A"}))
			Expect(out.Ambient).To(Equal([]string{"CAP_NET_RAW"}))
		})

		It("does not share a slice with the input, even with spare capacity", func() {
			backing := make([]string, 1, 4)
			backing[0] = "CAP_A"
			caps := &specs.LinuxCapabilities{Bounding: backing}
			out := processes.WithCapability(caps, "CAP_NET_RAW")
			out.Bounding[0] = "CAP_CHANGED"
			Expect(backing[:1]).To(Equal([]string{"CAP_A"}))
			Expect(backing[:2][1]).To(BeEmpty())
		})

		It("holds the capability alone for nil", func() {
			Expect(processes.WithCapability(nil, "CAP_NET_RAW")).To(Equal(&specs.LinuxCapabilities{
				Bounding:    []string{"CAP_NET_RAW"},
				Effective:   []string{"CAP_NET_RAW"},
				Inheritable: []string{"CAP_NET_RAW"},
				Permitted:   []string{"CAP_NET_RAW"},
				Ambient:     []string{"CAP_NET_RAW"},
			}))
		})
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

	Describe("OnlyCapabilities", func() {
		It("returns empty sets, not nil, for nil", func() {
			Expect(processes.OnlyCapabilities(nil, []string{"CAP_A"})).To(Equal(&specs.LinuxCapabilities{
				Bounding:    []string{},
				Effective:   []string{},
				Inheritable: []string{},
				Permitted:   []string{},
				Ambient:     []string{},
			}))
		})

		It("keeps only the allowed capabilities in every set, in their order, without touching the input", func() {
			shared := []string{"CAP_B", "CAP_SYS_ADMIN", "CAP_A", "CAP_SYS_PTRACE"}
			caps := &specs.LinuxCapabilities{Bounding: shared, Effective: shared, Inheritable: []string{"CAP_SYS_ADMIN"}, Permitted: shared}

			out := processes.OnlyCapabilities(caps, []string{"CAP_A", "CAP_B", "CAP_C"})
			Expect(out).To(Equal(&specs.LinuxCapabilities{
				Bounding:    []string{"CAP_B", "CAP_A"},
				Effective:   []string{"CAP_B", "CAP_A"},
				Inheritable: []string{},
				Permitted:   []string{"CAP_B", "CAP_A"},
				Ambient:     nil,
			}))
			Expect(shared).To(Equal([]string{"CAP_B", "CAP_SYS_ADMIN", "CAP_A", "CAP_SYS_PTRACE"}))
			out.Bounding[0] = "CAP_X"
			Expect(shared[0]).To(Equal("CAP_B"))
		})

		It("keeps nothing when nothing is allowed", func() {
			out := processes.OnlyCapabilities(&specs.LinuxCapabilities{Bounding: []string{"CAP_A"}, Ambient: []string{"CAP_A"}}, nil)
			Expect(out.Bounding).To(BeEmpty())
			Expect(out.Bounding).NotTo(BeNil())
			Expect(out.Ambient).To(BeEmpty())
		})

		It("lets a VM sandbox's helper process keep CAP_DAC_OVERRIDE alone", func() {
			Expect(processes.VMPeaCapabilities).To(Equal([]string{"CAP_DAC_OVERRIDE"}))
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

		var cwdBuilderOpts []processes.Option

		BeforeEach(func() {
			cwdBuilderOpts = nil
		})

		JustBeforeEach(func() {
			procBuilder = processes.NewBuilder(envDeterminer, nonRootMaxCaps, cwdBuilderOpts...)
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

		Context("when the container runs under gVisor", func() {
			var outsideDir string

			BeforeEach(func() {
				bndl.Spec.Annotations = map[string]string{backend.AnnotationKey: string(backend.OCIGvisor)}
				outsideDir = GinkgoT().TempDir()
				processSpec.Dir = "/app"
			})

			Context("and the directory exists in the rootfs", func() {
				BeforeEach(func() {
					Expect(os.MkdirAll(filepath.Join(tmpRootFS, "app"), 0755)).To(Succeed())
				})

				It("uses spec.Dir as Cwd", func() {
					Expect(preparedProc.Cwd).To(Equal("/app"))
				})
			})

			Context("and the directory is a symlink to a directory in the rootfs", func() {
				BeforeEach(func() {
					Expect(os.MkdirAll(filepath.Join(tmpRootFS, "real-app"), 0755)).To(Succeed())
					Expect(os.Symlink("/real-app", filepath.Join(tmpRootFS, "app"))).To(Succeed())
				})

				It("resolves the symlink in the rootfs and uses spec.Dir as Cwd", func() {
					Expect(preparedProc.Cwd).To(Equal("/app"))
				})
			})

			Context("and the directory does not exist", func() {
				It("falls back to '/'", func() {
					Expect(preparedProc.Cwd).To(Equal("/"))
				})
			})

			Context("and the directory is an absolute symlink outside the rootfs", func() {
				BeforeEach(func() {
					Expect(os.Symlink(outsideDir, filepath.Join(tmpRootFS, "app"))).To(Succeed())
				})

				It("resolves it inside the rootfs and falls back to '/'", func() {
					Expect(preparedProc.Cwd).To(Equal("/"))
				})
			})

			Context("and the directory is a relative symlink that climbs out of the rootfs", func() {
				BeforeEach(func() {
					target := strings.Repeat("../", 32) + strings.TrimPrefix(outsideDir, "/")
					Expect(os.Symlink(target, filepath.Join(tmpRootFS, "app"))).To(Succeed())
				})

				It("resolves it inside the rootfs and falls back to '/'", func() {
					Expect(preparedProc.Cwd).To(Equal("/"))
				})
			})

			Context("and the home directory is used and exists in the rootfs", func() {
				BeforeEach(func() {
					processSpec.Dir = ""
					user.Home = "/home/robot"
					Expect(os.MkdirAll(filepath.Join(tmpRootFS, "home", "robot"), 0755)).To(Succeed())
				})

				It("uses the home directory as Cwd", func() {
					Expect(preparedProc.Cwd).To(Equal("/home/robot"))
				})
			})
		})

		Context("when the builder confines every working directory", func() {
			BeforeEach(func() {
				cwdBuilderOpts = []processes.Option{processes.WithConfinedRootDir()}
				processSpec.Dir = "/app"
			})

			Context("and the directory exists in the rootfs", func() {
				BeforeEach(func() {
					Expect(os.MkdirAll(filepath.Join(tmpRootFS, "app"), 0755)).To(Succeed())
				})

				It("uses spec.Dir as Cwd", func() {
					Expect(preparedProc.Cwd).To(Equal("/app"))
				})
			})

			Context("and the directory is an absolute symlink outside the rootfs of a runc container", func() {
				BeforeEach(func() {
					Expect(os.Symlink(GinkgoT().TempDir(), filepath.Join(tmpRootFS, "app"))).To(Succeed())
				})

				It("resolves it inside the rootfs and falls back to '/'", func() {
					Expect(preparedProc.Cwd).To(Equal("/"))
				})
			})
		})
	})
})

func ptr(i uint64) *uint64 {
	return &i
}

var _ = Describe("the volume flags of the wrapped vm-launch", func() {
	const (
		kvmGid        = 108
		virtiofsdPath = "/opt/garden-vm/artifacts/virtiofsd/virtiofsd-wrapper"
	)

	var (
		envDeterminer *fakes.FakeEnvDeterminer
		bndl          goci.Bndl
		processSpec   garden.ProcessSpec
		user          *users.ExecUser
		kind          backend.Kind
		marked        bool
		builderOpts   []processes.Option
		builtEnv      []string
	)

	launcherArgs := []string{"--backend", "vm-qemu", "--", "/tmp/lifecycle/launcher", "app", "true", ""}

	BeforeEach(func() {
		envDeterminer = new(fakes.FakeEnvDeterminer)
		builtEnv = []string{"A=b"}
		bndl = goci.Bundle().WithCapabilities("CAP_CHOWN", "CAP_KILL")
		kind = backend.VMQemu
		marked = true
		builderOpts = []processes.Option{processes.WithKVMGid(kvmGid)}
		processSpec = garden.ProcessSpec{Path: processes.VMLaunchPath, Args: launcherArgs, Env: []string{"A=b"}}
		user = &users.ExecUser{Uid: 2000, Gid: 2000}
	})

	build := func() *specs.Process {
		GinkgoHelper()
		envDeterminer.EnvForReturns(builtEnv)
		bndl.Spec.Annotations = map[string]string{backend.AnnotationKey: string(kind)}
		spec := processSpec
		if marked {
			spec = processes.MarkVMLaunch(spec)
		}
		return processes.NewBuilder(envDeterminer, []string{"CAP_CHOWN", "CAP_KILL"}, builderOpts...).BuildProcess(bndl, spec, user)
	}

	Describe("VMLaunchVolumeFlags", func() {
		DescribeTable("renders the flags for each setting",
			func(allowShares bool, path string, syncMounts bool, expected []string) {
				Expect(processes.VMLaunchVolumeFlags(allowShares, path, syncMounts)).To(Equal(expected))
			},
			Entry("the defaults pass nothing", false, virtiofsdPath, true, []string(nil)),
			Entry("shares on pass the allow flag and the path", true, virtiofsdPath, true,
				[]string{"--allow-volume-shares", "--virtiofsd-path", virtiofsdPath}),
			Entry("shares on without a path pass the allow flag alone", true, "", true,
				[]string{"--allow-volume-shares"}),
			Entry("shares off never pass the path", false, virtiofsdPath, true, []string(nil)),
			Entry("synchronous mounts off pass only that flag", false, virtiofsdPath, false,
				[]string{"--volume-sync-mounts=false"}),
			Entry("both pass all three flags in a fixed order", true, virtiofsdPath, false,
				[]string{"--allow-volume-shares", "--virtiofsd-path", virtiofsdPath, "--volume-sync-mounts=false"}),
		)

		It("names the flags vm-launch reads", func() {
			Expect(processes.VMLaunchAllowVolumeSharesFlag).To(Equal("--allow-volume-shares"))
			Expect(processes.VMLaunchVirtiofsdFlag).To(Equal("--virtiofsd-path"))
			Expect(processes.VMLaunchVolumeSyncMountsFlag).To(Equal("--volume-sync-mounts"))
		})
	})

	Context("when no flag is set", func() {
		It("builds the argv it built before: the path, then vm-launch's own arguments", func() {
			Expect(build().Args).To(Equal(append([]string{processes.VMLaunchPath}, launcherArgs...)))
		})

		It("builds the same argv when the option is given an empty list", func() {
			builderOpts = append(builderOpts, processes.WithVMLaunchFlags())
			Expect(build().Args).To(Equal(append([]string{processes.VMLaunchPath}, launcherArgs...)))
		})
	})

	Context("with shares allowed", func() {
		BeforeEach(func() {
			builderOpts = append(builderOpts, processes.WithVMLaunchFlags(processes.VMLaunchVolumeFlags(true, virtiofsdPath, true)...))
		})

		It("puts the share flags between the path and vm-launch's own arguments", func() {
			Expect(build().Args).To(Equal(append(
				[]string{processes.VMLaunchPath, "--allow-volume-shares", "--virtiofsd-path", virtiofsdPath},
				launcherArgs...)))
		})

		It("passes them to a vm-firecracker vm-launch too, which refuses a share itself", func() {
			kind = backend.VMFirecracker
			Expect(build().Args[:2]).To(Equal([]string{processes.VMLaunchPath, "--allow-volume-shares"}))
		})
	})

	Context("with synchronous mounts off", func() {
		BeforeEach(func() {
			builderOpts = append(builderOpts, processes.WithVMLaunchFlags(processes.VMLaunchVolumeFlags(false, virtiofsdPath, false)...))
		})

		It("passes --volume-sync-mounts=false alone", func() {
			Expect(build().Args).To(Equal(append(
				[]string{processes.VMLaunchPath, "--volume-sync-mounts=false"},
				launcherArgs...)))
		})
	})

	Context("with every flag set", func() {
		BeforeEach(func() {
			builderOpts = append(builderOpts, processes.WithVMLaunchFlags(processes.VMLaunchVolumeFlags(true, virtiofsdPath, false)...))
		})

		It("passes all three", func() {
			Expect(build().Args).To(Equal(append(
				[]string{processes.VMLaunchPath, "--allow-volume-shares", "--virtiofsd-path", virtiofsdPath, "--volume-sync-mounts=false"},
				launcherArgs...)))
		})

		It("puts the transparent proxy flag first for a vm-firecracker vm-launch with PORT", func() {
			kind = backend.VMFirecracker
			builtEnv = []string{"A=b", "PORT=8080"}

			Expect(build().Args).To(Equal(append(
				[]string{processes.VMLaunchPath, "--transparent-proxy", "--allow-volume-shares", "--virtiofsd-path", virtiofsdPath, "--volume-sync-mounts=false"},
				launcherArgs...)))
		})

		It("adds nothing to a vm-launch run without the containerizer's marker", func() {
			marked = false
			Expect(build().Args).To(Equal(append([]string{processes.VMLaunchPath}, launcherArgs...)))
		})

		It("adds nothing to a process other than vm-launch in a vm bundle", func() {
			processSpec = garden.ProcessSpec{Path: "/bin/ls", Args: []string{"-l"}}
			Expect(build().Args).To(Equal([]string{"/bin/ls", "-l"}))
		})

		It("adds nothing in a bundle that is not a vm one", func() {
			kind = backend.OCIRunc
			Expect(build().Args).To(Equal(append([]string{processes.VMLaunchPath}, launcherArgs...)))
		})
	})

	It("keeps its own copy of the list", func() {
		flags := []string{"--allow-volume-shares"}
		builderOpts = append(builderOpts, processes.WithVMLaunchFlags(flags...))
		flags[0] = "--changed"

		Expect(build().Args[1]).To(Equal("--allow-volume-shares"))
	})

	It("does not let one build change the next", func() {
		builderOpts = append(builderOpts, processes.WithVMLaunchFlags("--volume-sync-mounts=false"))
		first := build().Args
		second := build().Args

		Expect(second).To(Equal(first))
		Expect(second).To(Equal(append([]string{processes.VMLaunchPath, "--volume-sync-mounts=false"}, launcherArgs...)))
	})
})
