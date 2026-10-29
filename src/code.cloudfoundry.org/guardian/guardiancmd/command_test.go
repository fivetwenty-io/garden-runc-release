package guardiancmd

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"

	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/rundmc"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/runcontainerd"
	"code.cloudfoundry.org/guardian/rundmc/runcontainerd/runcontainerdfakes"
	"code.cloudfoundry.org/guardian/rundmc/rundmcfakes"
	"code.cloudfoundry.org/lager/v3/lagertest"
	flags "github.com/jessevdk/go-flags"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("execution backend flags", func() {
	var (
		cmd         *CommonCommand
		log         *lagertest.TestLogger
		launchBin   string
		originalGrp func(string) (*user.Group, error)
	)

	BeforeEach(func() {
		log = lagertest.NewTestLogger("execution-backends")
		cmd = &CommonCommand{}

		launchBin = filepath.Join(GinkgoT().TempDir(), "vm-launch")
		Expect(os.WriteFile(launchBin, []byte("#!/bin/sh\n"), 0o755)).To(Succeed())

		originalGrp = lookupKVMGroup
		lookupKVMGroup = func(name string) (*user.Group, error) {
			Expect(name).To(Equal("kvm"))
			return &user.Group{Name: name, Gid: "993"}, nil
		}
	})

	AfterEach(func() {
		lookupKVMGroup = originalGrp
	})

	Describe("flag parsing", func() {
		It("has no backend enabled and the documented defaults when no flag is given", func() {
			parsed := &CommonCommand{}
			_, err := flags.NewParser(parsed, flags.None).ParseArgs([]string{})
			if err != nil {
				// FileFlag defaults such as /sbin/iptables must exist on the
				// host; the defaults under test do not depend on them.
				Skip("host lacks a default binary: " + err.Error())
			}

			Expect(parsed.ExecutionBackends.Enabled).To(BeEmpty())
			Expect(parsed.ExecutionBackends.VMArtifactsDir).To(Equal("/var/vcap/data/vm-runtime/artifacts"))
			Expect(parsed.ExecutionBackends.VMLaunchBin).To(BeEmpty())
			Expect(parsed.ExecutionBackends.VMKVMGid).To(BeZero())
		})

		It("accepts every backend flag, with --execution-backend repeatable", func() {
			parsed := &CommonCommand{}
			_, err := flags.NewParser(parsed, flags.IgnoreUnknown).ParseArgs([]string{
				"--execution-backend", "oci-gvisor",
				"--execution-backend", "vm-qemu",
				"--vm-artifacts-dir", "/artifacts",
				"--vm-launch-bin", "/bin/vm-launch",
				"--vm-kvm-gid", "108",
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(parsed.ExecutionBackends.Enabled).To(Equal([]string{"oci-gvisor", "vm-qemu"}))
			Expect(parsed.ExecutionBackends.VMArtifactsDir).To(Equal("/artifacts"))
			Expect(parsed.ExecutionBackends.VMLaunchBin).To(Equal("/bin/vm-launch"))
			Expect(parsed.ExecutionBackends.VMKVMGid).To(BeEquivalentTo(108))
		})

		It("rejects a --vm-kvm-gid that is not a number", func() {
			parsed := &CommonCommand{}
			_, err := flags.NewParser(parsed, flags.IgnoreUnknown).ParseArgs([]string{"--vm-kvm-gid", "kvm"})
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("wireExecutionBackends", func() {
		Context("when no backend is enabled", func() {
			It("keeps the stock behaviour", func() {
				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.registry).To(BeNil())
				Expect(backends.kvmGid).To(BeZero())
			})

			It("does not inspect launch binary, artifacts dir, or kvm group", func() {
				cmd.ExecutionBackends.VMLaunchBin = "/does/not/exist"
				cmd.ExecutionBackends.VMArtifactsDir = "/does/not/exist"
				lookupKVMGroup = func(string) (*user.Group, error) {
					Fail("kvm group must not be looked up")
					return nil, nil
				}

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.registry).To(BeNil())
			})

			It("treats an explicit oci-runc as the stock behaviour", func() {
				cmd.ExecutionBackends.Enabled = []string{"oci-runc"}

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.registry).To(BeNil())
			})
		})

		Context("with an unknown backend name", func() {
			It("fails with ErrUnknownBackend naming the value", func() {
				cmd.ExecutionBackends.Enabled = []string{"oci-gvisor", "kata"}
				cmd.Containerd.Socket = "/run/containerd.sock"

				_, err := cmd.wireExecutionBackends(log)
				Expect(errors.Is(err, backend.ErrUnknownBackend)).To(BeTrue())
				Expect(err.Error()).To(ContainSubstring(`"kata"`))
			})

			It("fails on an empty name", func() {
				cmd.ExecutionBackends.Enabled = []string{""}

				_, err := cmd.wireExecutionBackends(log)
				Expect(errors.Is(err, backend.ErrUnknownBackend)).To(BeTrue())
			})
		})

		Context("with oci-gvisor", func() {
			BeforeEach(func() {
				cmd.ExecutionBackends.Enabled = []string{"oci-gvisor"}
			})

			It("fails when containerd is not configured", func() {
				_, err := cmd.wireExecutionBackends(log)
				Expect(err).To(MatchError(ContainSubstring("--containerd-socket")))
			})

			It("fails when containerd is not configured even if other backends are fine", func() {
				cmd.ExecutionBackends.Enabled = []string{"vm-qemu", "oci-gvisor"}
				cmd.ExecutionBackends.VMLaunchBin = launchBin

				_, err := cmd.wireExecutionBackends(log)
				Expect(err).To(MatchError(ContainSubstring("--containerd-socket")))
			})

			It("is enabled when containerd is configured, without needing process dispatch through containerd", func() {
				cmd.Containerd.Socket = "/run/containerd.sock"
				cmd.Containerd.UseContainerdForProcesses = false

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.registry.Allowed(backend.OCIGvisor)).To(BeTrue())
				Expect(backends.registry.Allowed(backend.VMQemu)).To(BeFalse())
				Expect(backends.kvmGid).To(BeZero())
			})

			It("does not need a launch binary or kvm group", func() {
				cmd.Containerd.Socket = "/run/containerd.sock"
				lookupKVMGroup = func(string) (*user.Group, error) {
					Fail("kvm group must not be looked up")
					return nil, nil
				}

				_, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when containerd runs every container under runsc", func() {
			BeforeEach(func() {
				cmd.Containerd.Socket = "/run/containerd.sock"
				cmd.Containerd.UseContainerdForProcesses = true
				cmd.Containerd.RuntimeType = runcontainerd.SupportedRuntimeType
				cmd.ExecutionBackends.VMLaunchBin = launchBin
			})

			for _, enabled := range [][]string{{"oci-gvisor"}, {"vm-qemu"}, {"vm-firecracker", "oci-gvisor"}} {
				It("refuses "+enabled[0]+" because per-container selection is not supported on a runsc cell", func() {
					cmd.ExecutionBackends.Enabled = enabled

					_, err := cmd.wireExecutionBackends(log)
					Expect(err).To(MatchError(ContainSubstring("--containerd-runtime-type")))
				})
			}

			It("keeps the stock behaviour when only oci-runc is named", func() {
				cmd.ExecutionBackends.Enabled = []string{"oci-runc"}

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.dispatch()).To(BeFalse())
			})

			It("reports a runsc cell", func() {
				Expect(cmd.runscCell()).To(BeTrue())
			})
		})

		Context("when the containerd runtime type is the stock one or unset", func() {
			It("does not report a runsc cell", func() {
				cmd.Containerd.Socket = "/run/containerd.sock"
				Expect(cmd.runscCell()).To(BeFalse())
				cmd.Containerd.RuntimeType = runcontainerd.StockRuntimeType
				Expect(cmd.runscCell()).To(BeFalse())
			})

			It("does not report a runsc cell without containerd", func() {
				cmd.Containerd.RuntimeType = runcontainerd.SupportedRuntimeType
				Expect(cmd.runscCell()).To(BeFalse())
			})
		})

		Context("with a vm-* backend", func() {
			BeforeEach(func() {
				cmd.ExecutionBackends.Enabled = []string{"vm-qemu", "vm-firecracker"}
				cmd.ExecutionBackends.VMLaunchBin = launchBin
			})

			It("enables both kinds and resolves the kvm gid from the host group", func() {
				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.registry.Allowed(backend.VMQemu)).To(BeTrue())
				Expect(backends.registry.Allowed(backend.VMFirecracker)).To(BeTrue())
				Expect(backends.registry.Allowed(backend.OCIGvisor)).To(BeFalse())
				Expect(backends.kvmGid).To(BeEquivalentTo(993))
			})

			It("works without containerd", func() {
				cmd.Containerd.Socket = ""

				_, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
			})

			It("prefers --vm-kvm-gid over the host group", func() {
				cmd.ExecutionBackends.VMKVMGid = 108
				lookupKVMGroup = func(string) (*user.Group, error) {
					Fail("kvm group must not be looked up when the gid is given")
					return nil, nil
				}

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.kvmGid).To(BeEquivalentTo(108))
			})

			It("does not stop gdn when the artifacts directory is missing", func() {
				cmd.ExecutionBackends.VMArtifactsDir = filepath.Join(GinkgoT().TempDir(), "missing")

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.registry.Allowed(backend.VMQemu)).To(BeTrue())
			})

			Context("when --vm-launch-bin is unusable", func() {
				It("fails when it is not set", func() {
					cmd.ExecutionBackends.VMLaunchBin = ""

					_, err := cmd.wireExecutionBackends(log)
					Expect(err).To(MatchError(ContainSubstring("--vm-launch-bin")))
				})

				It("fails when it does not exist", func() {
					cmd.ExecutionBackends.VMLaunchBin = filepath.Join(GinkgoT().TempDir(), "missing")

					_, err := cmd.wireExecutionBackends(log)
					Expect(err).To(MatchError(ContainSubstring("--vm-launch-bin")))
				})

				It("fails when it is not executable", func() {
					Expect(os.Chmod(launchBin, 0o644)).To(Succeed())

					_, err := cmd.wireExecutionBackends(log)
					Expect(err).To(MatchError(And(ContainSubstring("--vm-launch-bin"), ContainSubstring("not executable"))))
				})

				It("fails when it is a directory", func() {
					cmd.ExecutionBackends.VMLaunchBin = GinkgoT().TempDir()

					_, err := cmd.wireExecutionBackends(log)
					Expect(err).To(MatchError(ContainSubstring("not a regular file")))
				})

				It("fails even when the kvm gid cannot be resolved", func() {
					cmd.ExecutionBackends.VMLaunchBin = ""
					lookupKVMGroup = func(string) (*user.Group, error) { return nil, user.UnknownGroupError("kvm") }

					_, err := cmd.wireExecutionBackends(log)
					Expect(err).To(HaveOccurred())
				})
			})

			Context("when the kvm gid cannot be determined", func() {
				unresolvable := map[string]func(string) (*user.Group, error){
					"the kvm group is missing": func(name string) (*user.Group, error) {
						return nil, user.UnknownGroupError(name)
					},
					"the kvm group gid is not a number": func(name string) (*user.Group, error) {
						return &user.Group{Name: name, Gid: "S-1-5"}, nil
					},
					"the kvm group is gid 0": func(name string) (*user.Group, error) {
						return &user.Group{Name: name, Gid: "0"}, nil
					},
				}

				for description, lookup := range unresolvable {
					lookup := lookup

					It("leaves the vm-* kinds out and logs an error when "+description, func() {
						lookupKVMGroup = lookup

						backends, err := cmd.wireExecutionBackends(log)
						Expect(err).NotTo(HaveOccurred())
						Expect(backends.registry).To(BeNil())
						Expect(backends.kvmGid).To(BeZero())

						Expect(log.LogMessages()).To(ContainElement(HaveSuffix("execution-backends.kvm-gid-unresolved-disabling-vm-backends")))
					})
				}

				It("keeps the other enabled backends", func() {
					lookupKVMGroup = func(name string) (*user.Group, error) { return nil, user.UnknownGroupError(name) }
					cmd.ExecutionBackends.Enabled = []string{"vm-qemu", "oci-gvisor", "vm-firecracker"}
					cmd.Containerd.Socket = "/run/containerd.sock"

					backends, err := cmd.wireExecutionBackends(log)
					Expect(err).NotTo(HaveOccurred())
					Expect(backends.registry.Allowed(backend.OCIGvisor)).To(BeTrue())
					Expect(backends.registry.Allowed(backend.VMQemu)).To(BeFalse())
					Expect(backends.registry.Allowed(backend.VMFirecracker)).To(BeFalse())
					Expect(backends.kvmGid).To(BeZero())
				})
			})
		})
	})

	Describe("backend dispatch options", func() {
		gvisorBundle := func() goci.Bndl {
			bndl := goci.Bundle()
			bndl.Spec.Annotations = map[string]string{backend.AnnotationKey: string(backend.OCIGvisor)}
			return bndl
		}

		// containerizerDispatches reports whether a Containerizer built with
		// the options looks up the backend of the container it stops.
		containerizerDispatches := func(opts []rundmc.Option) bool {
			ociRuntime := new(rundmcfakes.FakeOCIRuntime)
			ociRuntime.BundleInfoReturns("", gvisorBundle(), errors.New("bundle-info-consulted"))

			containerizer := rundmc.New(
				new(rundmcfakes.FakeDepot),
				new(rundmcfakes.FakeBundleGenerator),
				ociRuntime,
				rundmc.NewNstarStreamer(ociRuntime, new(rundmcfakes.FakeNstarRunner)),
				new(rundmcfakes.FakeProcessesStopper),
				new(rundmcfakes.FakeEventStore),
				new(rundmcfakes.FakeStateStore),
				new(rundmcfakes.FakePeaCreator),
				new(rundmcfakes.FakePeaUsernameResolver),
				0,
				new(rundmcfakes.FakeRuntimeStopper),
				new(rundmcfakes.FakeCPUCgrouper),
				false,
				opts...,
			)

			err := containerizer.Stop(log, "some-handle", false)
			if ociRuntime.BundleInfoCallCount() == 0 {
				Expect(err).NotTo(HaveOccurred())
				return false
			}
			Expect(err).To(MatchError(ContainSubstring("bundle-info-consulted")))
			return true
		}

		// runContainerdDispatches reports whether a RunContainerd built with
		// the options looks up the backend of the container it reads metrics
		// from.
		runContainerdDispatches := func(opts []runcontainerd.Option) bool {
			containerManager := new(runcontainerdfakes.FakeContainerManager)
			spec := gvisorBundle().Spec
			containerManager.SpecReturns(&spec, nil)

			runContainerd := runcontainerd.New(
				containerManager,
				new(runcontainerdfakes.FakeProcessManager),
				new(runcontainerdfakes.FakeProcessBuilder),
				nil,
				new(runcontainerdfakes.FakeExecer),
				new(runcontainerdfakes.FakeStatser),
				true,
				new(runcontainerdfakes.FakeCgroupManager),
				new(runcontainerdfakes.FakeMkdirer),
				new(runcontainerdfakes.FakePeaHandlesGetter),
				false,
				new(runcontainerdfakes.FakeRuntimeStopper),
				opts...,
			)

			_, err := runContainerd.Stats(log, "some-handle")
			Expect(err).NotTo(HaveOccurred())
			return containerManager.SpecCallCount() > 0
		}

		Context("when oci-gvisor is enabled", func() {
			var backends *executionBackends

			BeforeEach(func() {
				cmd.ExecutionBackends.Enabled = []string{"oci-gvisor"}
				cmd.Containerd.Socket = "/run/containerd.sock"

				var err error
				backends, err = cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
			})

			It("passes backend dispatch to both the containerizer and the containerd runtime", func() {
				Expect(backends.dispatch()).To(BeTrue())
				Expect(backends.containerizerOptions(new(rundmcfakes.FakeOCIRuntime))).To(HaveLen(1))
				Expect(backends.runContainerdOptions(new(runcontainerdfakes.FakeStatser))).To(HaveLen(1))

				Expect(containerizerDispatches(backends.containerizerOptions(new(rundmcfakes.FakeOCIRuntime)))).To(BeTrue())
				Expect(runContainerdDispatches(backends.runContainerdOptions(new(runcontainerdfakes.FakeStatser)))).To(BeTrue())
			})

			It("configures no tap group", func() {
				_, ok := backends.tapGroup()
				Expect(ok).To(BeFalse())
			})
		})

		Context("when only vm-* backends are enabled", func() {
			It("still passes backend dispatch to both, because every non-runc kind needs it", func() {
				cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}
				cmd.ExecutionBackends.VMLaunchBin = launchBin

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())

				Expect(containerizerDispatches(backends.containerizerOptions(new(rundmcfakes.FakeOCIRuntime)))).To(BeTrue())
				Expect(runContainerdDispatches(backends.runContainerdOptions(new(runcontainerdfakes.FakeStatser)))).To(BeTrue())
			})
		})

		Context("when no backend is enabled", func() {
			It("passes neither option, so both keep their stock code paths", func() {
				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())

				Expect(backends.dispatch()).To(BeFalse())
				Expect(backends.containerizerOptions(new(rundmcfakes.FakeOCIRuntime))).To(BeEmpty())
				Expect(backends.runContainerdOptions(new(runcontainerdfakes.FakeStatser))).To(BeEmpty())

				Expect(containerizerDispatches(backends.containerizerOptions(new(rundmcfakes.FakeOCIRuntime)))).To(BeFalse())
				Expect(runContainerdDispatches(backends.runContainerdOptions(new(runcontainerdfakes.FakeStatser)))).To(BeFalse())

				_, ok := backends.tapGroup()
				Expect(ok).To(BeFalse())
			})
		})

		Context("when vm-* backends were dropped because the kvm gid is unresolved", func() {
			It("passes neither option", func() {
				cmd.ExecutionBackends.Enabled = []string{"vm-firecracker"}
				cmd.ExecutionBackends.VMLaunchBin = launchBin
				lookupKVMGroup = func(name string) (*user.Group, error) { return nil, user.UnknownGroupError(name) }

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())

				Expect(backends.containerizerOptions(new(rundmcfakes.FakeOCIRuntime))).To(BeEmpty())
				Expect(backends.runContainerdOptions(new(runcontainerdfakes.FakeStatser))).To(BeEmpty())
				_, ok := backends.tapGroup()
				Expect(ok).To(BeFalse())
			})
		})

		It("is safe to call on the nil value a CommonCommand holds before wiring", func() {
			var backends *executionBackends
			Expect(cmd.wiredBackends).To(BeNil())
			Expect(backends.dispatch()).To(BeFalse())
			Expect(backends.containerizerOptions(new(rundmcfakes.FakeOCIRuntime))).To(BeEmpty())
			Expect(backends.runContainerdOptions(new(runcontainerdfakes.FakeStatser))).To(BeEmpty())
			_, ok := backends.tapGroup()
			Expect(ok).To(BeFalse())
		})
	})

	Describe("tap group", func() {
		BeforeEach(func() {
			cmd.ExecutionBackends.VMLaunchBin = launchBin
		})

		It("is the kvm gid when vm-firecracker is enabled", func() {
			cmd.ExecutionBackends.Enabled = []string{"vm-firecracker"}

			backends, err := cmd.wireExecutionBackends(log)
			Expect(err).NotTo(HaveOccurred())

			gid, ok := backends.tapGroup()
			Expect(ok).To(BeTrue())
			Expect(gid).To(BeEquivalentTo(993))
			Expect(gid).To(Equal(backends.kvmGid))
		})

		It("follows --vm-kvm-gid", func() {
			cmd.ExecutionBackends.Enabled = []string{"vm-qemu", "vm-firecracker"}
			cmd.ExecutionBackends.VMKVMGid = 108

			backends, err := cmd.wireExecutionBackends(log)
			Expect(err).NotTo(HaveOccurred())

			gid, ok := backends.tapGroup()
			Expect(ok).To(BeTrue())
			Expect(gid).To(BeEquivalentTo(108))
		})

		It("is not configured when only vm-qemu is enabled", func() {
			cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}

			backends, err := cmd.wireExecutionBackends(log)
			Expect(err).NotTo(HaveOccurred())

			_, ok := backends.tapGroup()
			Expect(ok).To(BeFalse())
		})
	})

	Describe("createGardener", func() {
		It("gives the Gardener the registry built from the flags", func() {
			cmd.ExecutionBackends.Enabled = []string{"vm-firecracker"}
			cmd.ExecutionBackends.VMLaunchBin = launchBin
			backends, err := cmd.wireExecutionBackends(log)
			Expect(err).NotTo(HaveOccurred())

			gdnr := cmd.createGardener(&commandWiring{Logger: log, Backends: backends.registry})
			Expect(gdnr.Backends).NotTo(BeNil())
			Expect(gdnr.Backends.Allowed(backend.VMFirecracker)).To(BeTrue())
		})

		It("leaves the Gardener on oci-runc only when no backend is enabled", func() {
			backends, err := cmd.wireExecutionBackends(log)
			Expect(err).NotTo(HaveOccurred())

			gdnr := cmd.createGardener(&commandWiring{Logger: log, Backends: backends.registry})
			Expect(gdnr.Backends).To(BeNil())
		})
	})
})
