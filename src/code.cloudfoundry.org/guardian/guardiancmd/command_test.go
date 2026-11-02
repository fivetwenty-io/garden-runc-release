package guardiancmd

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/gardener/gardenerfakes"
	"code.cloudfoundry.org/guardian/rundmc"
	"code.cloudfoundry.org/guardian/rundmc/bundlerules"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/processes"
	"code.cloudfoundry.org/guardian/rundmc/runcontainerd"
	"code.cloudfoundry.org/guardian/rundmc/runcontainerd/runcontainerdfakes"
	"code.cloudfoundry.org/guardian/rundmc/rundmcfakes"
	"code.cloudfoundry.org/lager/v3/lagertest"
	flags "github.com/jessevdk/go-flags"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

// removeOnlyHost removes nodes as plain files, which is all the start-up
// sweep asks of the host.
type removeOnlyHost struct{ bundlerules.PDIHost }

func (removeOnlyHost) RemoveNode(path string, _, _ uint32) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

type failingRemoveHost struct{ bundlerules.PDIHost }

func (failingRemoveHost) RemoveNode(string, uint32, uint32) error {
	return errors.New("unlink failed")
}

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
		cmd.ExecutionBackends.VMQemuSandbox = processes.VMQemuSandboxDefault

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

	Describe("volume shares and asynchronous image mounts", func() {
		parse := func(args ...string) *CommonCommand {
			GinkgoHelper()
			parsed := &CommonCommand{}
			_, err := flags.NewParser(parsed, flags.IgnoreUnknown).ParseArgs(args)
			Expect(err).NotTo(HaveOccurred())
			return parsed
		}

		It("keeps shares off and image mounts synchronous when no flag is given", func() {
			parsed := &CommonCommand{}
			_, err := flags.NewParser(parsed, flags.None).ParseArgs([]string{})
			if err != nil {
				Skip("host lacks a default binary: " + err.Error())
			}
			Expect(parsed.ExecutionBackends.VMVolumeShares).To(BeFalse())
			Expect(parsed.ExecutionBackends.VMVolumeAsyncMounts).To(BeFalse())
		})

		It("keeps the guest at the reduced memory limit unless --vm-full-memory-limit is given", func() {
			Expect(parse().ExecutionBackends.VMFullMemoryLimit).To(BeFalse())
			Expect(parse("--vm-full-memory-limit").ExecutionBackends.VMFullMemoryLimit).To(BeTrue())
		})

		It("defaults --vm-qemu-sandbox to the seccomp sandbox and takes a custom or an empty value", func() {
			Expect(parse().ExecutionBackends.VMQemuSandbox).To(Equal(processes.VMQemuSandboxDefault))
			Expect(parse("--vm-qemu-sandbox=on,spawn=deny").ExecutionBackends.VMQemuSandbox).To(Equal("on,spawn=deny"))
			Expect(parse("--vm-qemu-sandbox=").ExecutionBackends.VMQemuSandbox).To(BeEmpty())
		})

		It("reads the sandbox value from the ini file the job renders, an empty one included", func() {
			read := func(line string) string {
				GinkgoHelper()
				ini := filepath.Join(GinkgoT().TempDir(), "config.ini")
				Expect(os.WriteFile(ini, []byte("[server]\n"+line), 0o600)).To(Succeed())
				gdn := &GdnCommand{ServerCommand: &ServerCommand{CommonCommand: &CommonCommand{}}}
				gdn.ServerCommand.ExecutionBackends.VMQemuSandbox = processes.VMQemuSandboxDefault
				parser := flags.NewParser(gdn, flags.IgnoreUnknown)
				parser.NamespaceDelimiter = "-"
				Expect(flags.NewIniParser(parser).ParseFile(ini)).To(Succeed())
				return gdn.ServerCommand.ExecutionBackends.VMQemuSandbox
			}
			Expect(read("")).To(Equal(processes.VMQemuSandboxDefault))
			Expect(read("  vm-qemu-sandbox = on,spawn=deny\n")).To(Equal("on,spawn=deny"))
			Expect(read("  vm-qemu-sandbox = \n")).To(BeEmpty())
		})

		It("turns shares on with --vm-volume-shares", func() {
			Expect(parse("--vm-volume-shares").ExecutionBackends.VMVolumeShares).To(BeTrue())
		})

		It("turns asynchronous mounts on with --vm-volume-async-mounts", func() {
			Expect(parse("--vm-volume-async-mounts").ExecutionBackends.VMVolumeAsyncMounts).To(BeTrue())
		})

		It("turns mount mirroring on with --vm-mirror-mounts and keeps it off by default", func() {
			Expect(parse().ExecutionBackends.VMMirrorMounts).To(BeFalse())
			Expect(parse("--vm-mirror-mounts").ExecutionBackends.VMMirrorMounts).To(BeTrue())
		})

		It("reads both settings from the ini file the job renders", func() {
			ini := filepath.Join(GinkgoT().TempDir(), "config.ini")
			Expect(os.WriteFile(ini, []byte("[server]\n  vm-volume-shares = true\n  vm-volume-async-mounts = true\n"), 0o600)).To(Succeed())

			gdn := &GdnCommand{ServerCommand: &ServerCommand{CommonCommand: &CommonCommand{}}}
			parser := flags.NewParser(gdn, flags.IgnoreUnknown)
			parser.NamespaceDelimiter = "-"
			Expect(flags.NewIniParser(parser).ParseFile(ini)).To(Succeed())
			Expect(gdn.ServerCommand.ExecutionBackends.VMVolumeShares).To(BeTrue())
			Expect(gdn.ServerCommand.ExecutionBackends.VMVolumeAsyncMounts).To(BeTrue())
		})

		Context("with a vm-* backend", func() {
			BeforeEach(func() {
				cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}
				cmd.ExecutionBackends.VMLaunchBin = launchBin
			})

			It("passes vm-launch no volume flag by default", func() {
				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vmLaunchFlags).To(BeEmpty())
			})

			It("passes --qemu-sandbox with a custom value", func() {
				cmd.ExecutionBackends.VMQemuSandbox = "on,spawn=deny"

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vmLaunchFlags).To(Equal([]string{"--qemu-sandbox=on,spawn=deny"}))
			})

			It("passes --qemu-sandbox= with an empty value, which turns the sandbox off", func() {
				cmd.ExecutionBackends.VMQemuSandbox = ""

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vmLaunchFlags).To(Equal([]string{"--qemu-sandbox="}))
			})

			It("passes the share flag and the wrapper's path inside the container when shares are on", func() {
				cmd.ExecutionBackends.VMVolumeShares = true

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vmLaunchFlags).To(Equal([]string{
					"--allow-volume-shares",
					"--virtiofsd-path", "/opt/garden-vm/artifacts/virtiofsd/virtiofsd-wrapper",
				}))
			})

			It("passes only --volume-sync-mounts=false when asynchronous mounts are on", func() {
				cmd.ExecutionBackends.VMVolumeAsyncMounts = true

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vmLaunchFlags).To(Equal([]string{"--volume-sync-mounts=false"}))
			})

			It("passes --guest-agent alone when the guest agent is on", func() {
				cmd.ExecutionBackends.VMGuestAgent = true

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vmLaunchFlags).To(Equal([]string{"--guest-agent"}))
			})

			It("passes no --guest-agent when the guest agent is off", func() {
				cmd.ExecutionBackends.VMGuestAgent = false
				cmd.ExecutionBackends.VMVolumeShares = true

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vmLaunchFlags).NotTo(ContainElement("--guest-agent"))
			})

			It("passes --guest-agent after the volume and CPU flags", func() {
				cmd.ExecutionBackends.VMVolumeAsyncMounts = true
				cmd.ExecutionBackends.VMMaxVCPUs = 4
				cmd.ExecutionBackends.VMGuestAgent = true

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vmLaunchFlags).To(Equal([]string{
					"--volume-sync-mounts=false",
					"--max-vcpus", "4",
					"--guest-agent",
				}))
			})

			It("passes all three flags when both settings differ from the defaults", func() {
				cmd.ExecutionBackends.VMVolumeShares = true
				cmd.ExecutionBackends.VMVolumeAsyncMounts = true

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vmLaunchFlags).To(Equal([]string{
					"--allow-volume-shares",
					"--virtiofsd-path", "/opt/garden-vm/artifacts/virtiofsd/virtiofsd-wrapper",
					"--volume-sync-mounts=false",
				}))
			})

			It("passes no vm-launch flag for the full memory limit, which the container's bundle carries, and turns the rule's raise on", func() {
				Expect(cmd.ExecutionBackends.VMFullMemoryLimit).To(BeFalse())
				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.fullMemoryLimit).To(BeFalse())

				cmd.ExecutionBackends.VMFullMemoryLimit = true
				backends, err = cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.fullMemoryLimit).To(BeTrue())
				Expect(backends.vmLaunchFlags).To(BeEmpty())
			})

			It("leaves the full memory limit off when the vm-* backends were dropped for want of a kvm gid", func() {
				cmd.ExecutionBackends.VMFullMemoryLimit = true
				lookupKVMGroup = func(name string) (*user.Group, error) { return nil, user.UnknownGroupError(name) }

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.fullMemoryLimit).To(BeFalse())
				Expect(log).To(gbytes.Say("full-memory-limit-unused-without-a-vm-backend"))
			})

			It("passes only --mirror-mounts when mirroring is on", func() {
				cmd.ExecutionBackends.VMMirrorMounts = true

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vmLaunchFlags).To(Equal([]string{"--mirror-mounts"}))
			})

			It("passes --mirror-mounts last, after the volume, sandbox, and CPU flags", func() {
				cmd.ExecutionBackends.VMVolumeShares = true
				cmd.ExecutionBackends.VMVolumeAsyncMounts = true
				cmd.ExecutionBackends.VMQemuSandbox = "on,spawn=deny"
				cmd.ExecutionBackends.VMMaxVCPUs = 4
				cmd.ExecutionBackends.VMMirrorMounts = true

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vmLaunchFlags).To(Equal([]string{
					"--allow-volume-shares",
					"--virtiofsd-path", "/opt/garden-vm/artifacts/virtiofsd/virtiofsd-wrapper",
					"--volume-sync-mounts=false",
					"--qemu-sandbox=on,spawn=deny",
					"--max-vcpus", "4",
					"--mirror-mounts",
				}))
			})

			It("passes nothing when the vm-* backends were dropped for want of a kvm gid", func() {
				cmd.ExecutionBackends.VMVolumeShares = true
				lookupKVMGroup = func(name string) (*user.Group, error) { return nil, user.UnknownGroupError(name) }

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vmLaunchFlags).To(BeEmpty())
				Expect(log).To(gbytes.Say("volume-shares-unused-without-a-vm-backend"))
			})

			It("says the guest agent is unused when the vm-* backends were dropped for want of a kvm gid", func() {
				cmd.ExecutionBackends.VMGuestAgent = true
				lookupKVMGroup = func(name string) (*user.Group, error) { return nil, user.UnknownGroupError(name) }

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vmLaunchFlags).To(BeEmpty())
				Expect(log).To(gbytes.Say("guest-agent-unused-without-a-vm-backend"))
			})
		})

		Context("with the guest agent on", func() {
			var (
				originalVsock  string
				originalDevice [2]uint32
			)

			BeforeEach(func() {
				cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}
				cmd.ExecutionBackends.VMLaunchBin = launchBin
				cmd.ExecutionBackends.VMGuestAgent = true
				originalVsock, originalDevice = hostVhostVsockPath, hostVhostVsockDevice
			})

			AfterEach(func() {
				hostVhostVsockPath, hostVhostVsockDevice = originalVsock, originalDevice
			})

			It("gives vm-qemu containers /dev/vhost-vsock when the host has the character device", func() {
				// /dev/null stands in for the device, with its own numbers.
				hostVhostVsockPath = "/dev/null"
				hostVhostVsockDevice = [2]uint32{1, 3}

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vhostVsock).To(BeTrue())
				Expect(log.LogMessages()).NotTo(ContainElement(ContainSubstring("guest-agent-vhost-vsock-unavailable")))
			})

			It("gives no container /dev/vhost-vsock and says so once when the host has no such device", func() {
				hostVhostVsockPath = filepath.Join(GinkgoT().TempDir(), "vhost-vsock")

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vhostVsock).To(BeFalse())
				Expect(backends.vmLaunchFlags).To(ContainElement("--guest-agent"))
				Expect(log).To(gbytes.Say("guest-agent-vhost-vsock-unavailable"))
				Expect(log).NotTo(gbytes.Say("guest-agent-vhost-vsock-unavailable"))
			})

			It("gives no container /dev/vhost-vsock when the host's path is not a character device", func() {
				hostVhostVsockPath = launchBin

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vhostVsock).To(BeFalse())
				Expect(log).To(gbytes.Say(`guest-agent-vhost-vsock-unavailable.*not a character device`))
			})

			It("gives no container /dev/vhost-vsock when the host's character device has other numbers", func() {
				hostVhostVsockPath = "/dev/null"

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vhostVsock).To(BeFalse())
				Expect(log).To(gbytes.Say(`guest-agent-vhost-vsock-unavailable.*device 1:3 is not vhost-vsock, which is 10:241`))
			})

			It("does not look for /dev/vhost-vsock when vm-qemu is not enabled", func() {
				cmd.ExecutionBackends.Enabled = []string{"vm-firecracker"}
				hostVhostVsockPath = filepath.Join(GinkgoT().TempDir(), "vhost-vsock")

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vhostVsock).To(BeFalse())
				Expect(log.LogMessages()).NotTo(ContainElement(ContainSubstring("guest-agent-vhost-vsock-unavailable")))
			})
		})

		It("passes nothing and says so when only oci-gvisor is enabled", func() {
			cmd.ExecutionBackends.VMVolumeShares = true
			cmd.ExecutionBackends.VMVolumeAsyncMounts = true
			cmd.ExecutionBackends.VMMirrorMounts = true
			cmd.ExecutionBackends.VMGuestAgent = true
			cmd.ExecutionBackends.Enabled = []string{"oci-gvisor"}
			cmd.Containerd.Socket = "/run/containerd.sock"

			backends, err := cmd.wireExecutionBackends(log)
			Expect(err).NotTo(HaveOccurred())
			Expect(backends.vmLaunchFlags).To(BeEmpty())
			Expect(log).To(gbytes.Say("volume-shares-unused-without-a-vm-backend"))
			Expect(log).To(gbytes.Say("volume-async-mounts-unused-without-a-vm-backend"))
			Expect(log).To(gbytes.Say("mirror-mounts-unused-without-a-vm-backend"))
			Expect(log).To(gbytes.Say("guest-agent-unused-without-a-vm-backend"))
		})

		It("passes nothing when no backend is enabled", func() {
			cmd.ExecutionBackends.VMVolumeShares = true

			backends, err := cmd.wireExecutionBackends(log)
			Expect(err).NotTo(HaveOccurred())
			Expect(backends.vmLaunchFlags).To(BeEmpty())
		})
	})

	Describe("block volumes", func() {
		It("are off unless --vm-block-volumes is given", func() {
			parsed := &CommonCommand{}
			_, err := flags.NewParser(parsed, flags.None).ParseArgs([]string{})
			if err != nil {
				Skip("host lacks a default binary: " + err.Error())
			}
			Expect(parsed.ExecutionBackends.VMBlockVolumes).To(BeFalse())

			parsed = &CommonCommand{}
			_, err = flags.NewParser(parsed, flags.IgnoreUnknown).ParseArgs([]string{"--vm-block-volumes"})
			Expect(err).NotTo(HaveOccurred())
			Expect(parsed.ExecutionBackends.VMBlockVolumes).To(BeTrue())
		})

		Context("with a vm-* backend", func() {
			BeforeEach(func() {
				cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}
				cmd.ExecutionBackends.VMLaunchBin = launchBin
			})

			It("wires no block volume step and no device releaser when the flag is off", func() {
				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.blockVolumes).To(BeNil())
				Expect(backends.containerizerOptions(new(rundmcfakes.FakeOCIRuntime))).To(HaveLen(1))
			})

			It("wires the step for the host paths and the kvm gid, and releases devices on destroy, when the flag is on", func() {
				cmd.ExecutionBackends.VMBlockVolumes = true
				cmd.Server.Tag = "ab"

				backends, err := cmd.wireExecutionBackends(log)
				if runtime.GOOS != "linux" {
					Expect(err).To(MatchError(ContainSubstring("--vm-block-volumes")))
					return
				}
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.blockVolumes).NotTo(BeNil())
				Expect(backends.blockVolumes.KVMGid).To(BeEquivalentTo(993))
				Expect(backends.blockVolumes.NodeDir).To(Equal("/dev/pdi"))
				Expect(backends.blockVolumes.ClaimDir).To(Equal("/run/garden-pdi-claims"))
				Expect(backends.blockVolumes.SysfsDir).To(Equal("/sys"))
				Expect(backends.blockVolumes.MountInfoPath).To(Equal("/proc/self/mountinfo"))
				Expect(backends.blockVolumes.Tag).To(Equal("ab"))
				Expect(backends.containerizerOptions(new(rundmcfakes.FakeOCIRuntime))).To(HaveLen(2))
			})

			It("ignores the flag when the vm-* backends were dropped for want of a kvm gid", func() {
				cmd.ExecutionBackends.VMBlockVolumes = true
				lookupKVMGroup = func(name string) (*user.Group, error) { return nil, user.UnknownGroupError(name) }

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.blockVolumes).To(BeNil())
				Expect(log).To(gbytes.Say("block-volumes-unused-without-a-vm-backend"))
			})
		})

		It("ignores the flag when only oci-gvisor is enabled", func() {
			cmd.ExecutionBackends.VMBlockVolumes = true
			cmd.ExecutionBackends.Enabled = []string{"oci-gvisor"}
			cmd.Containerd.Socket = "/run/containerd.sock"

			backends, err := cmd.wireExecutionBackends(log)
			Expect(err).NotTo(HaveOccurred())
			Expect(backends.blockVolumes).To(BeNil())
			Expect(backends.containerizerOptions(new(rundmcfakes.FakeOCIRuntime))).To(HaveLen(1))
			Expect(log).To(gbytes.Say("block-volumes-unused-without-a-vm-backend"))
		})

		It("ignores the flag when no backend is enabled", func() {
			cmd.ExecutionBackends.VMBlockVolumes = true

			backends, err := cmd.wireExecutionBackends(log)
			Expect(err).NotTo(HaveOccurred())
			Expect(backends.blockVolumes).To(BeNil())
			Expect(backends.containerizerOptions(new(rundmcfakes.FakeOCIRuntime))).To(BeEmpty())
		})

		Describe("the start-up sweep", func() {
			var (
				claimDir string
				nodeDir  string
				sweeper  blockVolumeSweeper
				handles  []string
				listErr  error
			)

			BeforeEach(func() {
				root := GinkgoT().TempDir()
				claimDir = filepath.Join(root, "claims")
				nodeDir = filepath.Join(root, "nodes")
				Expect(os.Mkdir(claimDir, 0o700)).To(Succeed())
				Expect(os.Mkdir(nodeDir, 0o755)).To(Succeed())
				Expect(os.WriteFile(filepath.Join(claimDir, "8-16"), []byte("\ngone"), 0o600)).To(Succeed())
				Expect(os.WriteFile(filepath.Join(claimDir, "8-32"), []byte("\nrunning"), 0o600)).To(Succeed())

				handles, listErr = []string{"running"}, nil
				sweeper = blockVolumeSweeper{
					log: log,
					volumes: &bundlerules.PDIDevices{
						NodeDir:  nodeDir,
						ClaimDir: claimDir,
						Host:     removeOnlyHost{},
						Logger:   log,
					},
					handles: func() ([]string, error) { return handles, listErr },
				}
			})

			It("releases the devices of containers Garden does not know and keeps the rest", func() {
				Expect(sweeper.Start()).To(Succeed())
				Expect(filepath.Join(claimDir, "8-16")).NotTo(BeAnExistingFile())
				Expect(filepath.Join(claimDir, "8-32")).To(BeARegularFile())
			})

			It("keeps the devices that a Garden with another tag claimed", func() {
				Expect(os.WriteFile(filepath.Join(claimDir, "8-48"), []byte("zz\nunknown-to-us"), 0o600)).To(Succeed())

				Expect(sweeper.Start()).To(Succeed())
				Expect(filepath.Join(claimDir, "8-16")).NotTo(BeAnExistingFile())
				Expect(filepath.Join(claimDir, "8-48")).To(BeARegularFile())
			})

			It("fails the start when the containers cannot be listed", func() {
				listErr = errors.New("containerd down")
				Expect(sweeper.Start()).To(MatchError(ContainSubstring("containerd down")))
				Expect(filepath.Join(claimDir, "8-16")).To(BeARegularFile())
			})

			It("logs a release that fails and lets Garden start", func() {
				sweeper.volumes.Host = failingRemoveHost{}

				Expect(sweeper.Start()).To(Succeed())
				Expect(filepath.Join(claimDir, "8-16")).To(BeARegularFile())
				Expect(log).To(gbytes.Say("release-unowned-block-devices-failed"))
			})
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

var _ = Describe("VM stack flags", func() {
	var (
		cmd         *CommonCommand
		log         *lagertest.TestLogger
		launchBin   string
		originalGrp func(string) (*user.Group, error)
	)

	BeforeEach(func() {
		log = lagertest.NewTestLogger("vm-stack")
		cmd = &CommonCommand{}
		cmd.ExecutionBackends.VMQemuSandbox = processes.VMQemuSandboxDefault

		launchBin = filepath.Join(GinkgoT().TempDir(), "vm-launch")
		Expect(os.WriteFile(launchBin, []byte("#!/bin/sh\n"), 0o755)).To(Succeed())

		originalGrp = lookupKVMGroup
		lookupKVMGroup = func(name string) (*user.Group, error) {
			return &user.Group{Name: name, Gid: "993"}, nil
		}
	})

	AfterEach(func() {
		lookupKVMGroup = originalGrp
	})

	Describe("flag parsing", func() {
		It("has no tarballs and the documented defaults when no flag is given", func() {
			parsed := &CommonCommand{}
			_, err := flags.NewParser(parsed, flags.None).ParseArgs([]string{})
			if err != nil {
				Skip("host lacks a default binary: " + err.Error())
			}

			Expect(parsed.ExecutionBackends.VMStackTarballs).To(BeEmpty())
			Expect(parsed.ExecutionBackends.VMStackCacheDir).To(Equal("/var/vcap/data/vm-runtime/stacks"))
			Expect(parsed.ExecutionBackends.VMStackWait).To(Equal(20 * time.Second))
			Expect(parsed.ExecutionBackends.VMDockerRootFS).To(BeEmpty())
			Expect(parsed.ExecutionBackends.VMDockerImageCacheDir).To(Equal("/var/vcap/data/vm-runtime/images"))
			Expect(parsed.ExecutionBackends.VMDockerImageCacheBytes).To(Equal(int64(10 << 30)))
		})

		It("has the guest agent off unless --vm-guest-agent is given", func() {
			parsed := &CommonCommand{}
			_, err := flags.NewParser(parsed, flags.IgnoreUnknown).ParseArgs([]string{})
			Expect(err).NotTo(HaveOccurred())
			Expect(parsed.ExecutionBackends.VMGuestAgent).To(BeFalse())

			parsed = &CommonCommand{}
			_, err = flags.NewParser(parsed, flags.IgnoreUnknown).ParseArgs([]string{"--vm-guest-agent"})
			Expect(err).NotTo(HaveOccurred())
			Expect(parsed.ExecutionBackends.VMGuestAgent).To(BeTrue())
		})

		It("parses the guest agent line that the garden job renders", func() {
			ini := filepath.Join(GinkgoT().TempDir(), "config.ini")
			Expect(os.WriteFile(ini, []byte("[server]\n  vm-guest-agent = true\n"), 0o644)).To(Succeed())

			gdn := &GdnCommand{ServerCommand: &ServerCommand{CommonCommand: &CommonCommand{}}}
			parser := flags.NewParser(gdn, flags.IgnoreUnknown)
			parser.NamespaceDelimiter = "-"
			Expect(flags.NewIniParser(parser).ParseFile(ini)).To(Succeed())

			Expect(gdn.ServerCommand.ExecutionBackends.VMGuestAgent).To(BeTrue())
		})

		It("accepts every Docker image flag", func() {
			parsed := &CommonCommand{}
			_, err := flags.NewParser(parsed, flags.IgnoreUnknown).ParseArgs([]string{
				"--vm-docker-rootfs", "/var/vcap/packages/cflinuxfs4/rootfs.tar",
				"--vm-docker-image-cache-dir", "/images",
				"--vm-docker-image-cache-bytes", "1048576",
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(parsed.ExecutionBackends.VMDockerRootFS).To(Equal("/var/vcap/packages/cflinuxfs4/rootfs.tar"))
			Expect(parsed.ExecutionBackends.VMDockerImageCacheDir).To(Equal("/images"))
			Expect(parsed.ExecutionBackends.VMDockerImageCacheBytes).To(Equal(int64(1048576)))
		})

		It("accepts every stack flag, with --vm-stack-tarball repeatable", func() {
			parsed := &CommonCommand{}
			_, err := flags.NewParser(parsed, flags.IgnoreUnknown).ParseArgs([]string{
				"--vm-stack-tarball", "/var/vcap/packages/cflinuxfs4/rootfs.tar",
				"--vm-stack-tarball", "/var/vcap/packages/cflinuxfs3/rootfs.tar",
				"--vm-stack-cache-dir", "/cache",
				"--vm-stack-wait", "5s",
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(parsed.ExecutionBackends.VMStackTarballs).To(Equal([]string{
				"/var/vcap/packages/cflinuxfs4/rootfs.tar",
				"/var/vcap/packages/cflinuxfs3/rootfs.tar",
			}))
			Expect(parsed.ExecutionBackends.VMStackCacheDir).To(Equal("/cache"))
			Expect(parsed.ExecutionBackends.VMStackWait).To(Equal(5 * time.Second))
		})

		It("parses the lines that the garden job renders", func() {
			ini := filepath.Join(GinkgoT().TempDir(), "config.ini")
			Expect(os.WriteFile(ini, []byte("[server]\n  vm-stack-tarball = /a/rootfs.tar\n  vm-stack-tarball = /b/rootfs.tar\n  vm-stack-wait = 5s\n"), 0o644)).To(Succeed())

			gdn := &GdnCommand{ServerCommand: &ServerCommand{CommonCommand: &CommonCommand{}}}
			parser := flags.NewParser(gdn, flags.IgnoreUnknown)
			parser.NamespaceDelimiter = "-"
			Expect(flags.NewIniParser(parser).ParseFile(ini)).To(Succeed())

			parsed := gdn.ServerCommand.ExecutionBackends
			Expect(parsed.VMStackTarballs).To(Equal([]string{"/a/rootfs.tar", "/b/rootfs.tar"}))
			Expect(parsed.VMStackWait).To(Equal(5 * time.Second))
		})
	})

	Describe("wireExecutionBackends", func() {
		It("leaves the stack builder nil when no tarball flag is given", func() {
			cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}
			cmd.ExecutionBackends.VMLaunchBin = launchBin

			backends, err := cmd.wireExecutionBackends(log)
			Expect(err).NotTo(HaveOccurred())
			Expect(backends.vmStacks).To(BeNil())
			Expect(cmd.createGardener(&commandWiring{Logger: log, Backends: backends.registry, VMStacks: backends.vmStacks}).VMStacks).To(BeNil())
		})

		It("builds a stack builder for a tarball flag with vm-qemu", func() {
			cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}
			cmd.ExecutionBackends.VMLaunchBin = launchBin
			cmd.ExecutionBackends.VMStackTarballs = []string{"/var/vcap/packages/cflinuxfs4/rootfs.tar"}
			cmd.ExecutionBackends.VMStackCacheDir = GinkgoT().TempDir()
			cmd.ExecutionBackends.VMStackWait = 20 * time.Second

			backends, err := cmd.wireExecutionBackends(log)
			Expect(err).NotTo(HaveOccurred())
			Expect(backends.vmStacks).NotTo(BeNil())
			gdnr := cmd.createGardener(&commandWiring{Logger: log, Backends: backends.registry, VMStacks: backends.vmStacks})
			Expect(gdnr.VMStacks).NotTo(BeNil())
		})

		It("fails with a named error for a tarball flag and no backend", func() {
			cmd.ExecutionBackends.VMStackTarballs = []string{"/var/vcap/packages/cflinuxfs4/rootfs.tar"}

			_, err := cmd.wireExecutionBackends(log)
			Expect(err).To(MatchError(ContainSubstring("--vm-stack-tarball requires a vm-* --execution-backend")))
		})

		It("fails for a tarball flag with only oci-gvisor", func() {
			cmd.ExecutionBackends.Enabled = []string{"oci-gvisor"}
			cmd.Containerd.Socket = "/run/containerd.sock"
			cmd.ExecutionBackends.VMStackTarballs = []string{"/var/vcap/packages/cflinuxfs4/rootfs.tar"}

			_, err := cmd.wireExecutionBackends(log)
			Expect(err).To(MatchError(ContainSubstring("--vm-stack-tarball requires a vm-* --execution-backend")))
		})

		It("fails for a relative tarball path", func() {
			cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}
			cmd.ExecutionBackends.VMLaunchBin = launchBin
			cmd.ExecutionBackends.VMStackTarballs = []string{"rootfs.tar"}

			_, err := cmd.wireExecutionBackends(log)
			Expect(err).To(MatchError(ContainSubstring("--vm-stack-tarball must be an absolute path")))
		})

		Describe("the Docker image guest", func() {
			BeforeEach(func() {
				cmd.ExecutionBackends.VMDockerRootFS = "/var/vcap/packages/cflinuxfs4/rootfs.tar"
				cmd.ExecutionBackends.VMDockerImageCacheDir = filepath.Join(GinkgoT().TempDir(), "images")
				cmd.ExecutionBackends.VMDockerImageCacheBytes = 10 << 30
				cmd.ExecutionBackends.VMArtifactsDir = "/var/vcap/data/vm-runtime/artifacts"
			})

			It("records the tarball with vm-qemu and builds the image builder over the volumizer", func() {
				cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}
				cmd.ExecutionBackends.VMLaunchBin = launchBin

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				Expect(backends.vmDockerRootFS).To(Equal("/var/vcap/packages/cflinuxfs4/rootfs.tar"))

				images, err := cmd.wireVMImages(log, backends, new(gardenerfakes.FakeVolumizer))
				Expect(err).NotTo(HaveOccurred())
				Expect(images).NotTo(BeNil())
				Expect(filepath.Join(cmd.ExecutionBackends.VMDockerImageCacheDir, "containers")).To(BeADirectory())

				gdnr := cmd.createGardener(&commandWiring{Logger: log, Backends: backends.registry, VMImages: images, VMDockerRootFS: backends.vmDockerRootFS})
				Expect(gdnr.VMImages).NotTo(BeNil())
				Expect(gdnr.VMDockerRootFS).To(Equal("/var/vcap/packages/cflinuxfs4/rootfs.tar"))
			})

			It("leaves the feature off when the flag is empty", func() {
				cmd.ExecutionBackends.VMDockerRootFS = ""
				cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}
				cmd.ExecutionBackends.VMLaunchBin = launchBin

				backends, err := cmd.wireExecutionBackends(log)
				Expect(err).NotTo(HaveOccurred())
				images, err := cmd.wireVMImages(log, backends, new(gardenerfakes.FakeVolumizer))
				Expect(err).NotTo(HaveOccurred())
				Expect(images).To(BeNil())

				gdnr := cmd.createGardener(&commandWiring{Logger: log, Backends: backends.registry})
				Expect(gdnr.VMImages).To(BeNil())
				Expect(gdnr.VMDockerRootFS).To(BeEmpty())
			})

			It("fails for the tarball flag with no vm-* backend", func() {
				cmd.ExecutionBackends.Enabled = []string{"oci-gvisor"}
				cmd.Containerd.Socket = "/run/containerd.sock"

				_, err := cmd.wireExecutionBackends(log)
				Expect(err).To(MatchError(ContainSubstring("--vm-docker-rootfs requires a vm-* --execution-backend")))
			})

			It("fails for a relative tarball path", func() {
				cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}
				cmd.ExecutionBackends.VMLaunchBin = launchBin
				cmd.ExecutionBackends.VMDockerRootFS = "rootfs.tar"

				_, err := cmd.wireExecutionBackends(log)
				Expect(err).To(MatchError(ContainSubstring("--vm-docker-rootfs must be an absolute path")))
			})

			It("fails for a relative cache directory", func() {
				cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}
				cmd.ExecutionBackends.VMLaunchBin = launchBin
				cmd.ExecutionBackends.VMDockerImageCacheDir = "images"

				_, err := cmd.wireExecutionBackends(log)
				Expect(err).To(MatchError(ContainSubstring("--vm-docker-image-cache-dir must be an absolute path")))
			})

			It("fails for a cache budget that holds nothing", func() {
				cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}
				cmd.ExecutionBackends.VMLaunchBin = launchBin
				cmd.ExecutionBackends.VMDockerImageCacheBytes = 0

				_, err := cmd.wireExecutionBackends(log)
				Expect(err).To(MatchError(ContainSubstring("--vm-docker-image-cache-bytes must be positive")))
			})
		})

		It("fails for a negative wait", func() {
			cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}
			cmd.ExecutionBackends.VMLaunchBin = launchBin
			cmd.ExecutionBackends.VMStackTarballs = []string{"/var/vcap/packages/cflinuxfs4/rootfs.tar"}
			cmd.ExecutionBackends.VMStackWait = -time.Second

			_, err := cmd.wireExecutionBackends(log)
			Expect(err).To(MatchError(ContainSubstring("--vm-stack-wait must not be negative")))
		})
	})

	Describe("startVMStackClean", func() {
		It("does nothing without a builder", func() {
			var backends *executionBackends
			backends.startVMStackClean()
			(&executionBackends{}).startVMStackClean()
		})

		It("cleans in the background and builds nothing", func() {
			cacheDir := GinkgoT().TempDir()
			tarball := filepath.Join(GinkgoT().TempDir(), "rootfs.tar")
			Expect(os.WriteFile(tarball, []byte("rootfs"), 0644)).To(Succeed())
			stale := filepath.Join(cacheDir, strings.Repeat("a", 64))
			Expect(os.Mkdir(stale, 0755)).To(Succeed())

			cmd.ExecutionBackends.Enabled = []string{"vm-qemu"}
			cmd.ExecutionBackends.VMLaunchBin = launchBin
			cmd.ExecutionBackends.VMStackTarballs = []string{tarball}
			cmd.ExecutionBackends.VMStackCacheDir = cacheDir

			backends, err := cmd.wireExecutionBackends(log)
			Expect(err).NotTo(HaveOccurred())

			backends.startVMStackClean()
			Eventually(log).Should(gbytes.Say("removed"))
			Expect(stale).NotTo(BeADirectory())
			entries, err := os.ReadDir(cacheDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty())
		})
	})
})
