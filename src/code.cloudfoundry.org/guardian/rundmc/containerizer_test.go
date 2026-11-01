package rundmc_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/garden/gardenfakes"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/gardener"
	specpkg "code.cloudfoundry.org/guardian/gardener/container-spec"
	"code.cloudfoundry.org/guardian/rundmc"
	"code.cloudfoundry.org/guardian/rundmc/bundlerules"
	gardencgroups "code.cloudfoundry.org/guardian/rundmc/cgroups"
	"code.cloudfoundry.org/guardian/rundmc/depot"
	"code.cloudfoundry.org/guardian/rundmc/event"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	fakes "code.cloudfoundry.org/guardian/rundmc/rundmcfakes"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/lager/v3/lagertest"
	"github.com/eapache/go-resiliency/retrier"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

var _ = Describe("Rundmc", func() {
	var (
		fakeDepot               *fakes.FakeDepot
		fakeBundleGenerator     *fakes.FakeBundleGenerator
		fakeOCIRuntime          *fakes.FakeOCIRuntime
		fakeNstarRunner         *fakes.FakeNstarRunner
		fakeProcessesStopper    *fakes.FakeProcessesStopper
		fakeEventStore          *fakes.FakeEventStore
		fakeStateStore          *fakes.FakeStateStore
		fakePeaCreator          *fakes.FakePeaCreator
		fakePeaUsernameResolver *fakes.FakePeaUsernameResolver
		fakeRuntimeStopper      *fakes.FakeRuntimeStopper
		fakeCPUCgrouper         *fakes.FakeCPUCgrouper

		logger        lager.Logger
		containerizer *rundmc.Containerizer
		bundle        goci.Bndl
	)

	newContainerizer := func(opts ...rundmc.Option) *rundmc.Containerizer {
		return rundmc.New(
			fakeDepot,
			fakeBundleGenerator,
			fakeOCIRuntime,
			rundmc.NewNstarStreamer(fakeOCIRuntime, fakeNstarRunner),
			fakeProcessesStopper,
			fakeEventStore,
			fakeStateStore,
			fakePeaCreator,
			fakePeaUsernameResolver,
			0,
			fakeRuntimeStopper,
			fakeCPUCgrouper,
			false,
			opts...,
		)
	}

	BeforeEach(func() {
		fakeDepot = new(fakes.FakeDepot)
		fakeBundleGenerator = new(fakes.FakeBundleGenerator)
		fakeOCIRuntime = new(fakes.FakeOCIRuntime)
		fakeNstarRunner = new(fakes.FakeNstarRunner)
		fakeProcessesStopper = new(fakes.FakeProcessesStopper)
		fakeEventStore = new(fakes.FakeEventStore)
		fakeStateStore = new(fakes.FakeStateStore)
		fakePeaCreator = new(fakes.FakePeaCreator)
		fakePeaUsernameResolver = new(fakes.FakePeaUsernameResolver)
		fakeRuntimeStopper = new(fakes.FakeRuntimeStopper)
		fakeCPUCgrouper = new(fakes.FakeCPUCgrouper)
		logger = lagertest.NewTestLogger("test")

		bundle = goci.Bndl{Spec: specs.Spec{Version: "test-version"}}
		fakeBundleGenerator.GenerateReturns(bundle, nil)

		containerizer = rundmc.New(
			fakeDepot,
			fakeBundleGenerator,
			fakeOCIRuntime,
			rundmc.NewNstarStreamer(fakeOCIRuntime, fakeNstarRunner),
			fakeProcessesStopper,
			fakeEventStore,
			fakeStateStore,
			fakePeaCreator,
			fakePeaUsernameResolver,
			0,
			fakeRuntimeStopper,
			fakeCPUCgrouper,
			false, // imageBackedPeas: default stock behavior
		)
	})

	Describe("Create", func() {
		It("should generate an oci bundle", func() {
			spec := specpkg.DesiredContainerSpec{
				Handle:     "exuberant!",
				BaseConfig: specs.Spec{Root: &specs.Root{}},
			}
			Expect(containerizer.Create(logger, spec)).To(Succeed())

			Expect(fakeBundleGenerator.GenerateCallCount()).To(Equal(1))

			actualSpec := fakeBundleGenerator.GenerateArgsForCall(0)
			Expect(actualSpec).To(Equal(spec))
		})

		It("should create a bad CPU cgroup", func() {
			Expect(containerizer.Create(logger, specpkg.DesiredContainerSpec{
				Handle:     "exuberant!",
				BaseConfig: specs.Spec{Root: &specs.Root{}},
			})).To(Succeed())

			Expect(fakeCPUCgrouper.PrepareCgroupsCallCount()).To(Equal(1))
			actualHandle := fakeCPUCgrouper.PrepareCgroupsArgsForCall(0)
			Expect(actualHandle).To(Equal("exuberant!"))
		})

		It("should create a container with the given id", func() {
			Expect(containerizer.Create(logger, specpkg.DesiredContainerSpec{
				Handle:     "exuberant!",
				BaseConfig: specs.Spec{Root: &specs.Root{}},
			})).To(Succeed())

			Expect(fakeOCIRuntime.CreateCallCount()).To(Equal(1))

			_, actualId, actualBundle, _ := fakeOCIRuntime.CreateArgsForCall(0)
			Expect(actualBundle).To(Equal(bundle))
			Expect(actualId).To(Equal("exuberant!"))
		})

		Context("when the bundle generation fails", func() {
			BeforeEach(func() {
				fakeBundleGenerator.GenerateReturns(goci.Bndl{}, errors.New("banana"))
			})

			It("should return an error", func() {
				Expect(containerizer.Create(logger, specpkg.DesiredContainerSpec{})).To(MatchError("banana"))
			})
		})

		Context("when creating the bad cgroup fails", func() {
			BeforeEach(func() {
				fakeCPUCgrouper.PrepareCgroupsReturns(errors.New("BOOHOO"))
			})

			It("should propagate the error", func() {
				Expect(containerizer.Create(logger, specpkg.DesiredContainerSpec{})).To(MatchError("BOOHOO"))
			})

		})
		Context("when the container creation fails", func() {
			BeforeEach(func() {
				fakeOCIRuntime.CreateReturns(errors.New("banana"))
			})

			It("should return an error", func() {
				Expect(containerizer.Create(logger, specpkg.DesiredContainerSpec{})).To(MatchError("banana"))
			})
		})
	})

	Describe("Start", func() {
		It("delegates to the runtime with the original handle", func() {
			Expect(containerizer.Start(logger, "some-handle")).To(Succeed())
			Expect(fakeOCIRuntime.StartCallCount()).To(Equal(1))
			_, id := fakeOCIRuntime.StartArgsForCall(0)
			Expect(id).To(Equal("some-handle"))
		})

		It("returns the runtime's error unchanged", func() {
			runtimeErr := errors.New("start-boom")
			fakeOCIRuntime.StartReturns(runtimeErr)
			err := containerizer.Start(logger, "some-handle")
			Expect(err).To(BeIdenticalTo(runtimeErr))
		})

		It("is not called eagerly during Create", func() {
			Expect(containerizer.Create(logger, specpkg.DesiredContainerSpec{
				Handle:     "create-only",
				BaseConfig: specs.Spec{Root: &specs.Root{}},
			})).To(Succeed())
			Expect(fakeOCIRuntime.StartCallCount()).To(Equal(0),
				"Create must not call runtime.Start; the Gardener starts the container after networking")
		})
	})

	Describe("Run", func() {
		It("should ask the execer to exec a process in the container", func() {
			_, err := containerizer.Run(logger, "some-handle", garden.ProcessSpec{Path: "hello"}, garden.ProcessIO{})
			Expect(err).NotTo(HaveOccurred())
			Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(1))

			_, id, spec, _ := fakeOCIRuntime.ExecArgsForCall(0)
			Expect(id).To(Equal("some-handle"))
			Expect(spec.Path).To(Equal("hello"))
		})

		Context("when process has no image", func() {
			It("doesn't create a pea", func() {
				_, err := containerizer.Run(logger, "some-handle", garden.ProcessSpec{Path: "hello"}, garden.ProcessIO{})
				Expect(err).NotTo(HaveOccurred())
				Expect(fakePeaCreator.CreatePeaCallCount()).To(Equal(0))
			})

			Context("when bind mounts are provided", func() {
				It("returns an error", func() {
					_, err := containerizer.Run(logger, "some-handle",
						garden.ProcessSpec{
							Path: "hello",
							BindMounts: []garden.BindMount{
								garden.BindMount{
									SrcPath: "src",
									DstPath: "dst",
								},
							},
						},
						garden.ProcessIO{})
					Expect(err).To(MatchError("Running a process with bind mounts and no image provided is not allowed"))
				})
			})
		})

		Context("when process has an image", func() {
			var (
				processSpec garden.ProcessSpec
				pio         garden.ProcessIO
			)

			BeforeEach(func() {
				processSpec = garden.ProcessSpec{Image: garden.ImageRef{URI: "some-uri"}}
				pio = garden.ProcessIO{Stdout: bytes.NewBufferString("some-idiosyncratic buffer")}
			})

			It("creates a pea", func() {
				_, err := containerizer.Run(logger, "some-handle", processSpec, pio)
				Expect(err).NotTo(HaveOccurred())
				Expect(fakePeaCreator.CreatePeaCallCount()).To(Equal(1))
				_, actualProcessSpec, actualProcessIO, actualHandle := fakePeaCreator.CreatePeaArgsForCall(0)
				Expect(actualProcessSpec).To(Equal(processSpec))
				Expect(actualHandle).To(Equal("some-handle"))
				Expect(actualProcessIO).To(Equal(pio))
			})

			It("returns process from pea creator", func() {
				fakeProcess := new(gardenfakes.FakeProcess)
				fakeProcess.IDReturns("some-id")
				fakePeaCreator.CreatePeaReturns(fakeProcess, nil)
				process, err := containerizer.Run(logger, "some-handle", processSpec, pio)
				Expect(process.ID()).To(Equal("some-id"))
				Expect(err).NotTo(HaveOccurred())
			})

			Describe("Username resolving", func() {
				Context("when user is not specified", func() {
					It("does not try to resolve the user", func() {
						_, err := containerizer.Run(logger, "some-handle", processSpec, pio)
						Expect(err).NotTo(HaveOccurred())
						Expect(fakePeaUsernameResolver.ResolveUserCallCount()).To(Equal(0))
					})
				})

				Context("when user is specified as uid:gid", func() {
					BeforeEach(func() {
						processSpec.User = "1:2"
					})

					It("does not try to resolve the user", func() {
						_, err := containerizer.Run(logger, "some-handle", processSpec, pio)
						Expect(err).NotTo(HaveOccurred())
						Expect(fakePeaUsernameResolver.ResolveUserCallCount()).To(Equal(0))
					})
				})

				Context("when user is specified as username", func() {
					BeforeEach(func() {
						processSpec.User = "foobar"
					})

					It("resolves username to uid:gid", func() {
						fakePeaUsernameResolver.ResolveUserReturns(1, 2, nil)

						_, err := containerizer.Run(logger, "some-handle", processSpec, pio)
						Expect(err).NotTo(HaveOccurred())

						Expect(fakePeaUsernameResolver.ResolveUserCallCount()).To(Equal(1))
						_, _, _, resolverInputUsername := fakePeaUsernameResolver.ResolveUserArgsForCall(0)
						Expect(resolverInputUsername).To(Equal("foobar"))

						Expect(fakePeaCreator.CreatePeaCallCount()).To(Equal(1))
						_, createdPeaProcessSpec, _, _ := fakePeaCreator.CreatePeaArgsForCall(0)
						Expect(createdPeaProcessSpec.User).To(Equal("1:2"))
					})
				})
			})
		})

		Context("when image-backed peas are enabled", func() {
			var imageBackedContainerizer *rundmc.Containerizer

			BeforeEach(func() {
				imageBackedContainerizer = rundmc.New(
					fakeDepot,
					fakeBundleGenerator,
					fakeOCIRuntime,
					rundmc.NewNstarStreamer(fakeOCIRuntime, fakeNstarRunner),
					fakeProcessesStopper,
					fakeEventStore,
					fakeStateStore,
					fakePeaCreator,
					fakePeaUsernameResolver,
					0,
					fakeRuntimeStopper,
					fakeCPUCgrouper,
					true, // imageBackedPeas
				)
			})

			It("forwards the unchanged request to the pea creator without resolving the user", func() {
				fakeProcess := new(gardenfakes.FakeProcess)
				fakePeaCreator.CreatePeaReturns(fakeProcess, nil)
				processSpec := garden.ProcessSpec{
					Path:       "/etc/cf-assets/healthcheck/healthcheck",
					User:       "vcap",
					Image:      garden.ImageRef{URI: "preloaded:cflinuxfs4"},
					BindMounts: []garden.BindMount{{SrcPath: "/host/healthcheck", DstPath: "/etc/cf-assets/healthcheck", Mode: garden.BindMountModeRO}},
				}
				pio := garden.ProcessIO{Stdin: strings.NewReader("input"), Stdout: &bytes.Buffer{}}

				returned, err := imageBackedContainerizer.Run(logger, "some-handle", processSpec, pio)
				Expect(err).NotTo(HaveOccurred())
				Expect(returned).To(BeIdenticalTo(fakeProcess))
				Expect(fakePeaCreator.CreatePeaCallCount()).To(Equal(1))
				_, forwarded, forwardedIO, handle := fakePeaCreator.CreatePeaArgsForCall(0)
				Expect(forwarded).To(Equal(processSpec))
				Expect(forwardedIO).To(Equal(pio))
				Expect(handle).To(Equal("some-handle"))
				Expect(fakePeaUsernameResolver.ResolveUserCallCount()).To(BeZero(),
					"the parent's host PID cannot see a grouped child's image")
				Expect(fakeOCIRuntime.ExecCallCount()).To(BeZero())
			})

			It("does not route non-image processes through the pea creator", func() {
				_, err := imageBackedContainerizer.Run(logger, "some-handle", garden.ProcessSpec{Path: "hello"}, garden.ProcessIO{})
				Expect(err).NotTo(HaveOccurred())
				Expect(fakePeaCreator.CreatePeaCallCount()).To(BeZero())
				Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(1))
			})
		})
	})

	Describe("Attach", func() {
		It("should ask the execer to attach a process in the container", func() {
			_, err := containerizer.Attach(logger, "some-handle", "123", garden.ProcessIO{})
			Expect(err).NotTo(HaveOccurred())
			Expect(fakeOCIRuntime.AttachCallCount()).To(Equal(1))

			_, id, processId, _ := fakeOCIRuntime.AttachArgsForCall(0)
			Expect(id).To(Equal("some-handle"))
			Expect(processId).To(Equal("123"))
		})
	})

	Describe("StreamIn", func() {
		It("should execute the NSTar command with the container PID", func() {
			fakeOCIRuntime.StateReturns(rundmc.State{
				Pid: 12,
			}, nil)

			someStream := gbytes.NewBuffer()
			Expect(containerizer.StreamIn(logger, "some-handle", garden.StreamInSpec{
				Path:      "some-path",
				User:      "some-user",
				TarStream: someStream,
			})).To(Succeed())

			_, pid, path, user, stream := fakeNstarRunner.StreamInArgsForCall(0)
			Expect(pid).To(Equal(12))
			Expect(path).To(Equal("some-path"))
			Expect(user).To(Equal("some-user"))
			Expect(stream).To(Equal(someStream))
		})

		It("returns an error if the PID cannot be found", func() {
			fakeOCIRuntime.StateReturns(rundmc.State{}, errors.New("pid not found"))
			Expect(containerizer.StreamIn(logger, "some-handle", garden.StreamInSpec{})).To(MatchError("stream-in: pid not found for container"))
		})

		It("returns the error if nstar fails", func() {
			fakeNstarRunner.StreamInReturns(errors.New("failed"))
			Expect(containerizer.StreamIn(logger, "some-handle", garden.StreamInSpec{})).To(MatchError("stream-in: nstar: failed"))
		})
	})

	Describe("StreamOut", func() {
		It("should execute the NSTar command with the container PID", func() {
			fakeOCIRuntime.StateReturns(rundmc.State{
				Pid: 12,
			}, nil)

			fakeNstarRunner.StreamOutReturns(os.Stdin, nil)

			tarStream, err := containerizer.StreamOut(logger, "some-handle", garden.StreamOutSpec{
				Path: "some-path",
				User: "some-user",
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(tarStream).To(Equal(os.Stdin))

			_, pid, path, user := fakeNstarRunner.StreamOutArgsForCall(0)
			Expect(pid).To(Equal(12))
			Expect(path).To(Equal("some-path"))
			Expect(user).To(Equal("some-user"))
		})

		It("returns an error if the PID cannot be found", func() {
			fakeOCIRuntime.StateReturns(rundmc.State{}, errors.New("pid not found"))
			tarStream, err := containerizer.StreamOut(logger, "some-handle", garden.StreamOutSpec{})

			Expect(tarStream).To(BeNil())
			Expect(err).To(MatchError("stream-out: pid not found for container"))
		})

		It("returns the error if nstar fails", func() {
			fakeNstarRunner.StreamOutReturns(nil, errors.New("failed"))
			tarStream, err := containerizer.StreamOut(logger, "some-handle", garden.StreamOutSpec{})

			Expect(tarStream).To(BeNil())
			Expect(err).To(MatchError("stream-out: nstar: failed"))
		})
	})

	Describe("Stop", func() {
		var (
			cgroupPathArg string
			exceptionsArg []int
			killArg       bool
		)

		Context("when the stop succeeds", func() {
			BeforeEach(func() {
				fakeOCIRuntime.StateReturns(rundmc.State{
					Pid: 1234,
				}, nil)

				Expect(containerizer.Stop(logger, "some-handle", true)).To(Succeed())
				Expect(fakeProcessesStopper.StopAllCallCount()).To(Equal(1))

				_, cgroupPathArg, exceptionsArg, killArg = fakeProcessesStopper.StopAllArgsForCall(0)
			})

			It("asks to stop all processes in the processes's cgroup", func() {
				Expect(cgroupPathArg).To(Equal("some-handle"))
				Expect(killArg).To(Equal(true))
			})

			It("asks to not stop the pid of the init process", func() {
				Expect(exceptionsArg).To(ConsistOf(1234))
			})

			It("transitions the stored state", func() {
				Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(1))
				handle := fakeStateStore.StoreStoppedArgsForCall(0)
				Expect(handle).To(Equal("some-handle"))
			})
		})

		Context("when stopping container processes fails", func() {
			BeforeEach(func() {
				fakeProcessesStopper.StopAllReturns(errors.New("boom"))
			})

			It("does not transition to the stopped state", func() {
				Expect(containerizer.Stop(logger, "some-handle", true)).To(MatchError(ContainSubstring("boom")))
				Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(0))
			})
		})

		Context("when getting runc's state fails", func() {
			BeforeEach(func() {
				fakeOCIRuntime.StateReturns(rundmc.State{}, errors.New("boom"))
			})

			It("does not stop the processes", func() {
				Expect(fakeProcessesStopper.StopAllCallCount()).To(Equal(0))
			})

			It("does not transition to the stopped state", func() {
				Expect(containerizer.Stop(logger, "some-handle", true)).To(MatchError(ContainSubstring("boom")))
				Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(0))
			})
		})
	})

	Describe("running the CF launcher in a vm backend container", func() {
		const (
			launcher = "/tmp/lifecycle/launcher"
			marker   = "__GARDEN_VM_LAUNCH_WRAPPED=1"
		)

		BeforeEach(func() {
			containerizer = newContainerizer(rundmc.WithBackendDispatch(rundmc.NewExecStreamer(fakeOCIRuntime)))
		})

		bundleFor := func(annotations map[string]string) goci.Bndl {
			return goci.Bndl{Spec: specs.Spec{Version: "test-version", Annotations: annotations}}
		}

		launcherSpec := func() garden.ProcessSpec {
			return garden.ProcessSpec{
				Path: launcher,
				Args: []string{"app", "echo hi", ""},
				Env:  []string{"A=b"},
				User: "vcap",
				Dir:  "/home/vcap",
			}
		}

		// The vm-launch options each backend's wrapped launcher runs with.
		// The process builder adds the transparent proxy flag for a
		// Firecracker one with PORT, so the containerizer passes none.
		wrapperOptions := map[backend.Kind][]string{
			backend.VMQemu:        {"--backend", "vm-qemu"},
			backend.VMFirecracker: {"--backend", "vm-firecracker"},
		}

		for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			kind := kind
			wrapped := func(command ...string) []string {
				return append(append(append([]string{}, wrapperOptions[kind]...), "--"), command...)
			}

			Context(fmt.Sprintf("with a %s bundle", kind), func() {
				BeforeEach(func() {
					fakeOCIRuntime.BundleInfoReturns("/bundle", bundleFor(map[string]string{backend.AnnotationKey: string(kind)}), nil)
				})

				It("wraps the launcher into vm-launch and leaves the rest of the spec alone", func() {
					_, err := containerizer.Run(logger, "some-handle", launcherSpec(), garden.ProcessIO{})
					Expect(err).NotTo(HaveOccurred())

					Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(1))
					_, id, actual, _ := fakeOCIRuntime.ExecArgsForCall(0)
					Expect(id).To(Equal("some-handle"))
					Expect(actual.Path).To(Equal(bundlerules.VMLaunchMountPath))
					Expect(actual.Args).To(Equal(wrapped(launcher, "app", "echo hi", "")))
					Expect(actual.Env).To(Equal([]string{"A=b", marker}))
					Expect(actual.User).To(Equal("vcap"))
					Expect(actual.Dir).To(Equal("/home/vcap"))
				})

				It("wraps a launcher with no arguments", func() {
					_, err := containerizer.Run(logger, "some-handle", garden.ProcessSpec{Path: launcher}, garden.ProcessIO{})
					Expect(err).NotTo(HaveOccurred())

					_, _, actual, _ := fakeOCIRuntime.ExecArgsForCall(0)
					Expect(actual.Path).To(Equal(bundlerules.VMLaunchMountPath))
					Expect(actual.Args).To(Equal(wrapped(launcher)))
				})

				It("does not modify the caller's spec", func() {
					spec := launcherSpec()
					_, err := containerizer.Run(logger, "some-handle", spec, garden.ProcessIO{})
					Expect(err).NotTo(HaveOccurred())

					Expect(spec.Path).To(Equal(launcher))
					Expect(spec.Args).To(Equal([]string{"app", "echo hi", ""}))
					Expect(spec.Env).To(Equal([]string{"A=b"}))
				})

				It("replaces a marker the client sent with exactly one of its own", func() {
					spec := launcherSpec()
					spec.Env = []string{"A=b", "__GARDEN_VM_LAUNCH_WRAPPED=forged", marker}

					_, err := containerizer.Run(logger, "some-handle", spec, garden.ProcessIO{})
					Expect(err).NotTo(HaveOccurred())

					_, _, actual, _ := fakeOCIRuntime.ExecArgsForCall(0)
					Expect(actual.Env).To(Equal([]string{"A=b", marker}))
				})

				It("strips a client marker from a direct vm-launch run, which is not wrapped", func() {
					spec := garden.ProcessSpec{Path: "/opt/garden-vm/vm-launch", Args: []string{"--backend", string(kind), "--", "/bin/sh"}, Env: []string{marker, "A=b"}}

					_, err := containerizer.Run(logger, "some-handle", spec, garden.ProcessIO{})
					Expect(err).NotTo(HaveOccurred())

					_, _, actual, _ := fakeOCIRuntime.ExecArgsForCall(0)
					Expect(actual.Path).To(Equal("/opt/garden-vm/vm-launch"))
					Expect(actual.Args).To(Equal(spec.Args))
					Expect(actual.Env).To(Equal([]string{"A=b"}))
				})

				It("strips a client marker from a pea", func() {
					spec := garden.ProcessSpec{Path: "/opt/garden-vm/vm-launch", Env: []string{marker}, Image: garden.ImageRef{URI: "some-uri"}}

					_, err := containerizer.Run(logger, "some-handle", spec, garden.ProcessIO{})
					Expect(err).NotTo(HaveOccurred())

					_, peaSpec, _, _ := fakePeaCreator.CreatePeaArgsForCall(0)
					Expect(peaSpec.Env).To(BeEmpty())
				})

				It("does not wrap other processes", func() {
					for _, path := range []string{"/bin/sh", "/tmp/lifecycle/diego-sshd", "/opt/garden-vm/vm-launch", "ls"} {
						_, err := containerizer.Run(logger, "some-handle", garden.ProcessSpec{Path: path, Args: []string{"x"}}, garden.ProcessIO{})
						Expect(err).NotTo(HaveOccurred())
					}

					Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(4))
					for i := 0; i < 4; i++ {
						_, _, actual, _ := fakeOCIRuntime.ExecArgsForCall(i)
						Expect(actual.Args).To(Equal([]string{"x"}))
					}
					_, _, first, _ := fakeOCIRuntime.ExecArgsForCall(0)
					Expect(first.Path).To(Equal("/bin/sh"))
				})

				Context("when the wrapped launcher reports a guest OOM on stderr", func() {
					const oomLine = "vm-launch: the guest ran out of memory: its kernel killed 2 processes; the guest has 128 MiB\n"

					var (
						inner  *gardenfakes.FakeProcess
						stderr *bytes.Buffer
						pio    garden.ProcessIO
						lines  []string
					)

					BeforeEach(func() {
						inner = new(gardenfakes.FakeProcess)
						stderr = new(bytes.Buffer)
						pio = garden.ProcessIO{Stderr: stderr}
						lines = []string{oomLine}

						fakeOCIRuntime.ExecStub = func(_ lager.Logger, _ string, _ garden.ProcessSpec, io garden.ProcessIO) (garden.Process, error) {
							for _, line := range lines {
								_, _ = io.Stderr.Write([]byte(line))
							}
							return inner, nil
						}
					})

					It("records Out of memory once, before Wait returns", func() {
						inner.WaitStub = func() (int, error) {
							Expect(fakeEventStore.OnEventCallCount()).To(Equal(0))
							return 137, nil
						}

						process, err := containerizer.Run(logger, "some-handle", launcherSpec(), pio)
						Expect(err).NotTo(HaveOccurred())

						status, err := process.Wait()
						Expect(err).NotTo(HaveOccurred())
						Expect(status).To(Equal(137))

						Expect(fakeEventStore.OnEventCallCount()).To(Equal(1))
						handle, message := fakeEventStore.OnEventArgsForCall(0)
						Expect(handle).To(Equal("some-handle"))
						Expect(message).To(Equal("Out of memory"))
					})

					It("records it once however often Wait is called", func() {
						process, err := containerizer.Run(logger, "some-handle", launcherSpec(), pio)
						Expect(err).NotTo(HaveOccurred())

						_, _ = process.Wait()
						_, _ = process.Wait()

						Expect(fakeEventStore.OnEventCallCount()).To(Equal(1))
					})

					It("passes the stderr bytes on unchanged", func() {
						lines = []string{"before\n", oomLine, "after"}

						_, err := containerizer.Run(logger, "some-handle", launcherSpec(), pio)
						Expect(err).NotTo(HaveOccurred())

						Expect(stderr.String()).To(Equal("before\n" + oomLine + "after"))
					})

					It("returns the inner exit status and error", func() {
						inner.WaitReturns(7, errors.New("wait-failed"))

						process, err := containerizer.Run(logger, "some-handle", launcherSpec(), pio)
						Expect(err).NotTo(HaveOccurred())

						status, err := process.Wait()
						Expect(status).To(Equal(7))
						Expect(err).To(MatchError("wait-failed"))
						Expect(fakeEventStore.OnEventCallCount()).To(Equal(1))
					})

					It("still returns the exit status when the event cannot be stored", func() {
						fakeEventStore.OnEventReturns(errors.New("store-failed"))
						inner.WaitReturns(137, nil)

						process, err := containerizer.Run(logger, "some-handle", launcherSpec(), pio)
						Expect(err).NotTo(HaveOccurred())

						status, err := process.Wait()
						Expect(err).NotTo(HaveOccurred())
						Expect(status).To(Equal(137))
					})

					It("still forwards the other process methods", func() {
						process, err := containerizer.Run(logger, "some-handle", launcherSpec(), pio)
						Expect(err).NotTo(HaveOccurred())

						inner.IDReturns("pid-1")
						Expect(process.ID()).To(Equal("pid-1"))
						Expect(process.Signal(garden.SignalTerminate)).To(Succeed())
						Expect(inner.SignalCallCount()).To(Equal(1))
					})

					It("records nothing when the line is not at the start of a stderr line", func() {
						lines = []string{"app said " + oomLine}

						process, err := containerizer.Run(logger, "some-handle", launcherSpec(), pio)
						Expect(err).NotTo(HaveOccurred())
						_, _ = process.Wait()

						Expect(fakeEventStore.OnEventCallCount()).To(Equal(0))
					})

					It("records nothing when the launcher wrote no OOM line", func() {
						lines = []string{"vm-launch: some other note\n"}

						process, err := containerizer.Run(logger, "some-handle", launcherSpec(), pio)
						Expect(err).NotTo(HaveOccurred())
						_, _ = process.Wait()

						Expect(fakeEventStore.OnEventCallCount()).To(Equal(0))
					})

					It("works when the caller gave no stderr", func() {
						process, err := containerizer.Run(logger, "some-handle", launcherSpec(), garden.ProcessIO{})
						Expect(err).NotTo(HaveOccurred())
						_, _ = process.Wait()

						Expect(fakeEventStore.OnEventCallCount()).To(Equal(1))
					})

					It("returns the runtime error when the launcher cannot start", func() {
						fakeOCIRuntime.ExecStub = nil
						fakeOCIRuntime.ExecReturns(nil, errors.New("exec-failed"))

						process, err := containerizer.Run(logger, "some-handle", launcherSpec(), pio)
						Expect(err).To(MatchError("exec-failed"))
						Expect(process).To(BeNil())
					})

					It("returns no process when the runtime returns none", func() {
						fakeOCIRuntime.ExecStub = nil
						fakeOCIRuntime.ExecReturns(nil, nil)

						process, err := containerizer.Run(logger, "some-handle", launcherSpec(), pio)
						Expect(err).NotTo(HaveOccurred())
						Expect(process).To(BeNil())
					})

					It("does not wrap a process that is not the launcher", func() {
						process, err := containerizer.Run(logger, "some-handle", garden.ProcessSpec{Path: "/bin/sh"}, pio)
						Expect(err).NotTo(HaveOccurred())
						Expect(process).To(BeIdenticalTo(inner))

						_, _ = process.Wait()
						Expect(fakeEventStore.OnEventCallCount()).To(Equal(0))
					})

					It("does not scan the stderr of a process that is not the launcher", func() {
						var gotStderr io.Writer
						fakeOCIRuntime.ExecStub = func(_ lager.Logger, _ string, _ garden.ProcessSpec, pio garden.ProcessIO) (garden.Process, error) {
							gotStderr = pio.Stderr
							return inner, nil
						}

						_, err := containerizer.Run(logger, "some-handle", garden.ProcessSpec{Path: "/opt/garden-vm/vm-launch"}, pio)
						Expect(err).NotTo(HaveOccurred())
						Expect(gotStderr).To(BeIdenticalTo(stderr))
					})
				})

				Context("when the wrapped launcher writes guest memory lines on stderr", func() {
					const (
						sampleLine = "vm-launch-metrics v1 used=300 total=1000 available=700 free=400 caches=200\n"
						otherLine  = "vm-launch-metrics v1 used=50 total=1000 available=950 free=900 caches=10\n"
					)

					var (
						inner  *gardenfakes.FakeProcess
						stderr *bytes.Buffer
						pio    garden.ProcessIO
						lines  []string
						now    time.Time
					)

					// Metrics reads the bundle's CPU shares, so the bundle needs
					// resources as well as the annotation.
					metricsBundle := func(annotations map[string]string) goci.Bndl {
						bundle := bundleFor(annotations)
						bundle.Spec.Linux = &specs.Linux{Resources: &specs.LinuxResources{}}
						return bundle
					}

					BeforeEach(func() {
						inner = new(gardenfakes.FakeProcess)
						stderr = new(bytes.Buffer)
						pio = garden.ProcessIO{Stderr: stderr}
						lines = []string{sampleLine}
						fakeOCIRuntime.BundleInfoReturns("/bundle", metricsBundle(map[string]string{backend.AnnotationKey: string(kind)}), nil)
						now = time.Unix(1000, 0)
						rundmc.SetGuestMemoryClock(containerizer, func() time.Time { return now })

						fakeOCIRuntime.StatsReturns(gardener.StatsContainerMetrics{
							CPU: garden.ContainerCPUStat{Usage: 9},
							Memory: garden.ContainerMemoryStat{
								TotalUsageTowardLimit:   800,
								TotalRss:                700,
								HierarchicalMemoryLimit: 1000,
							},
						}, nil)

						fakeOCIRuntime.ExecStub = func(_ lager.Logger, _ string, _ garden.ProcessSpec, io garden.ProcessIO) (garden.Process, error) {
							for _, line := range lines {
								_, _ = io.Stderr.Write([]byte(line))
							}
							return inner, nil
						}
					})

					run := func() garden.Process {
						process, err := containerizer.Run(logger, "some-handle", launcherSpec(), pio)
						Expect(err).NotTo(HaveOccurred())
						return process
					}

					usage := func() uint64 {
						metrics, err := containerizer.Metrics(logger, "some-handle")
						Expect(err).NotTo(HaveOccurred())
						return metrics.Memory.TotalUsageTowardLimit
					}

					It("takes the lines out of the stream and passes the rest on", func() {
						lines = []string{"before\n", sampleLine, "after"}

						run()

						Expect(stderr.String()).To(Equal("before\nafter"))
					})

					It("reports the guest's used memory and keeps the other cgroup fields", func() {
						run()

						metrics, err := containerizer.Metrics(logger, "some-handle")
						Expect(err).NotTo(HaveOccurred())
						Expect(metrics.Memory).To(Equal(garden.ContainerMemoryStat{
							TotalUsageTowardLimit:   300,
							TotalRss:                700,
							HierarchicalMemoryLimit: 1000,
						}))
						Expect(metrics.CPU.Usage).To(Equal(uint64(0)))
					})

					It("reports the newest sample", func() {
						lines = []string{sampleLine, otherLine}

						run()

						Expect(usage()).To(Equal(uint64(50)))
					})

					It("caps the figure at the cgroup's memory limit", func() {
						fakeOCIRuntime.StatsReturns(gardener.StatsContainerMetrics{
							Memory: garden.ContainerMemoryStat{TotalUsageTowardLimit: 80, HierarchicalMemoryLimit: 250},
						}, nil)

						run()

						Expect(usage()).To(Equal(uint64(250)))
					})

					It("does not cap the figure when the cgroup has no limit", func() {
						fakeOCIRuntime.StatsReturns(gardener.StatsContainerMetrics{
							Memory: garden.ContainerMemoryStat{TotalUsageTowardLimit: 80},
						}, nil)

						run()

						Expect(usage()).To(Equal(uint64(300)))
					})

					It("falls back to the cgroup figure when the sample is stale", func() {
						run()

						now = now.Add(34 * time.Second)
						Expect(usage()).To(Equal(uint64(300)))

						now = now.Add(time.Second)
						Expect(usage()).To(Equal(uint64(800)))
					})

					It("returns to the guest figure when a new sample arrives", func() {
						var stderrWriter io.Writer
						fakeOCIRuntime.ExecStub = func(_ lager.Logger, _ string, _ garden.ProcessSpec, io garden.ProcessIO) (garden.Process, error) {
							stderrWriter = io.Stderr
							_, _ = io.Stderr.Write([]byte(sampleLine))
							return inner, nil
						}
						run()

						now = now.Add(time.Minute)
						Expect(usage()).To(Equal(uint64(800)))

						_, _ = stderrWriter.Write([]byte(otherLine))
						Expect(usage()).To(Equal(uint64(50)))
					})

					It("reports the cgroup figure when the launcher wrote no sample", func() {
						lines = nil

						run()

						Expect(usage()).To(Equal(uint64(800)))
					})

					It("drops a malformed line and keeps the cgroup figure", func() {
						lines = []string{"vm-launch-metrics v1 used=1 total=0 available=0 free=0 caches=0\n"}

						run()

						Expect(stderr.Len()).To(Equal(0))
						Expect(usage()).To(Equal(uint64(800)))
					})

					It("removes the sample when its own process ends", func() {
						process := run()
						Expect(usage()).To(Equal(uint64(300)))

						_, err := process.Wait()
						Expect(err).NotTo(HaveOccurred())

						Expect(usage()).To(Equal(uint64(800)))
					})

					It("keeps a successor's sample when an earlier process ends", func() {
						first := run()

						lines = []string{otherLine}
						run()

						_, _ = first.Wait()

						Expect(usage()).To(Equal(uint64(50)))
					})

					It("releases a line cut off by the end of the stream when the process ends", func() {
						lines = []string{"vm-launch-metrics v1 used=3"}

						process := run()
						Expect(stderr.Len()).To(Equal(0))

						_, _ = process.Wait()

						Expect(stderr.String()).To(Equal("vm-launch-metrics v1 used=3"))
					})

					It("removes the sample when the container is destroyed", func() {
						run()
						Expect(usage()).To(Equal(uint64(300)))

						Expect(containerizer.Destroy(logger, "some-handle")).To(Succeed())

						Expect(usage()).To(Equal(uint64(800)))
					})

					It("keeps the samples of other containers apart", func() {
						run()

						metrics, err := containerizer.Metrics(logger, "other-handle")
						Expect(err).NotTo(HaveOccurred())
						Expect(metrics.Memory.TotalUsageTowardLimit).To(Equal(uint64(800)))
					})

					It("logs when the figure moves between the guest and the cgroup, and not otherwise", func() {
						run()

						for i := 0; i < 3; i++ {
							_ = usage()
						}
						now = now.Add(time.Minute)
						for i := 0; i < 3; i++ {
							_ = usage()
						}

						var messages []string
						for _, entry := range logger.(*lagertest.TestLogger).LogMessages() {
							if strings.Contains(entry, "vm-memory-from-") {
								messages = append(messages, entry)
							}
						}
						Expect(messages).To(HaveLen(2))
						Expect(messages[0]).To(HaveSuffix("vm-memory-from-guest"))
						Expect(messages[1]).To(HaveSuffix("vm-memory-from-cgroup"))
					})

					It("never uses the sample for a bundle that is not a VM", func() {
						run()
						fakeOCIRuntime.BundleInfoReturns("/bundle", metricsBundle(nil), nil)

						Expect(usage()).To(Equal(uint64(800)))
					})
				})

				It("does not wrap a pea that runs the launcher path", func() {
					spec := launcherSpec()
					spec.Image = garden.ImageRef{URI: "some-uri"}

					_, err := containerizer.Run(logger, "some-handle", spec, garden.ProcessIO{})
					Expect(err).NotTo(HaveOccurred())

					Expect(fakePeaCreator.CreatePeaCallCount()).To(Equal(1))
					_, peaSpec, _, _ := fakePeaCreator.CreatePeaArgsForCall(0)
					Expect(peaSpec.Path).To(Equal(launcher))
					Expect(peaSpec.Args).To(Equal([]string{"app", "echo hi", ""}))
					Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(0))
				})
			})
		}

		for _, annotations := range []map[string]string{
			nil,
			{backend.AnnotationKey: string(backend.OCIRunc)},
			{backend.AnnotationKey: string(backend.OCIGvisor)},
		} {
			annotations := annotations

			Context(fmt.Sprintf("with a non-vm bundle annotated %v", annotations), func() {
				BeforeEach(func() {
					fakeOCIRuntime.BundleInfoReturns("/bundle", bundleFor(annotations), nil)
				})

				It("passes the launcher through unchanged", func() {
					_, err := containerizer.Run(logger, "some-handle", launcherSpec(), garden.ProcessIO{})
					Expect(err).NotTo(HaveOccurred())

					_, _, actual, _ := fakeOCIRuntime.ExecArgsForCall(0)
					Expect(actual).To(Equal(launcherSpec()))
				})

				It("does not scan the stderr or wrap the process", func() {
					inner := new(gardenfakes.FakeProcess)
					stderr := new(bytes.Buffer)
					var gotStderr io.Writer
					fakeOCIRuntime.ExecStub = func(_ lager.Logger, _ string, _ garden.ProcessSpec, pio garden.ProcessIO) (garden.Process, error) {
						gotStderr = pio.Stderr
						_, _ = pio.Stderr.Write([]byte("vm-launch: the guest ran out of memory\n"))
						return inner, nil
					}

					process, err := containerizer.Run(logger, "some-handle", launcherSpec(), garden.ProcessIO{Stderr: stderr})
					Expect(err).NotTo(HaveOccurred())
					Expect(gotStderr).To(BeIdenticalTo(stderr))
					Expect(process).To(BeIdenticalTo(inner))

					_, _ = process.Wait()
					Expect(fakeEventStore.OnEventCallCount()).To(Equal(0))
				})
			})
		}

		Context("when the bundle cannot be read", func() {
			BeforeEach(func() {
				fakeOCIRuntime.BundleInfoReturns("", goci.Bndl{}, errors.New("no-bundle"))
			})

			It("fails the launcher without running it", func() {
				_, err := containerizer.Run(logger, "some-handle", launcherSpec(), garden.ProcessIO{})
				Expect(err).To(MatchError("no-bundle"))
				Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(0))
			})

			It("does not need the bundle for other processes", func() {
				_, err := containerizer.Run(logger, "some-handle", garden.ProcessSpec{Path: "hello"}, garden.ProcessIO{})
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeOCIRuntime.BundleInfoCallCount()).To(Equal(0))
			})
		})
	})

	Describe("execution backend dispatch", func() {
		var fakeTaskKiller *fakes.FakeTaskKiller

		bundleFor := func(annotations map[string]string) goci.Bndl {
			return goci.Bndl{Spec: specs.Spec{Version: "test-version", Annotations: annotations}}
		}

		BeforeEach(func() {
			fakeTaskKiller = new(fakes.FakeTaskKiller)
			containerizer = newContainerizer(
				rundmc.WithBackendDispatch(rundmc.NewExecStreamer(fakeOCIRuntime)),
				rundmc.WithTaskKiller(fakeTaskKiller, retrier.New(retrier.ConstantBackoff(2, time.Millisecond), nil)),
			)
		})

		for _, runcAnnotations := range []map[string]string{nil, {backend.AnnotationKey: string(backend.OCIRunc)}} {
			Context(fmt.Sprintf("with a runc bundle annotated %v", runcAnnotations), func() {
				BeforeEach(func() {
					fakeOCIRuntime.BundleInfoReturns("/bundle", bundleFor(runcAnnotations), nil)
					fakeOCIRuntime.StateReturns(rundmc.State{Pid: 12, Status: rundmc.RunningStatus}, nil)
				})

				It("streams in through nstar only", func() {
					stream := gbytes.NewBuffer()
					Expect(containerizer.StreamIn(logger, "some-handle", garden.StreamInSpec{Path: "p", User: "u", TarStream: stream})).To(Succeed())

					Expect(fakeNstarRunner.StreamInCallCount()).To(Equal(1))
					_, pid, path, user, actualStream := fakeNstarRunner.StreamInArgsForCall(0)
					Expect(pid).To(Equal(12))
					Expect(path).To(Equal("p"))
					Expect(user).To(Equal("u"))
					Expect(actualStream).To(Equal(stream))
					Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(0))
					_, handle := fakeOCIRuntime.BundleInfoArgsForCall(0)
					Expect(handle).To(Equal("some-handle"))
				})

				It("streams out through nstar only", func() {
					_, err := containerizer.StreamOut(logger, "some-handle", garden.StreamOutSpec{Path: "p", User: "u"})
					Expect(err).NotTo(HaveOccurred())

					Expect(fakeNstarRunner.StreamOutCallCount()).To(Equal(1))
					_, pid, path, user := fakeNstarRunner.StreamOutArgsForCall(0)
					Expect(pid).To(Equal(12))
					Expect(path).To(Equal("p"))
					Expect(user).To(Equal("u"))
					Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(0))
				})

				It("creates peas through the pea creator", func() {
					processSpec := garden.ProcessSpec{Path: "check", User: "vcap", Image: garden.ImageRef{URI: "some-uri"}}
					fakePeaUsernameResolver.ResolveUserReturns(1, 2, nil)

					_, err := containerizer.Run(logger, "some-handle", processSpec, garden.ProcessIO{})
					Expect(err).NotTo(HaveOccurred())

					Expect(fakePeaUsernameResolver.ResolveUserCallCount()).To(Equal(1))
					Expect(fakePeaCreator.CreatePeaCallCount()).To(Equal(1))
					_, peaSpec, _, handle := fakePeaCreator.CreatePeaArgsForCall(0)
					Expect(peaSpec.Image).To(Equal(garden.ImageRef{URI: "some-uri"}))
					Expect(peaSpec.User).To(Equal("1:2"))
					Expect(handle).To(Equal("some-handle"))
					Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(0))
				})

				It("stops through the cgroup stopper, sparing init", func() {
					Expect(containerizer.Stop(logger, "some-handle", false)).To(Succeed())

					Expect(fakeProcessesStopper.StopAllCallCount()).To(Equal(1))
					_, cgroupName, exceptions, kill := fakeProcessesStopper.StopAllArgsForCall(0)
					Expect(cgroupName).To(Equal("some-handle"))
					Expect(exceptions).To(ConsistOf(12))
					Expect(kill).To(BeFalse())
					Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(0))
					Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(1))
				})
			})
		}

		Context("when the bundle cannot be read", func() {
			BeforeEach(func() {
				fakeOCIRuntime.BundleInfoReturns("", goci.Bndl{}, errors.New("no-bundle"))
			})

			It("fails closed instead of assuming runc", func() {
				Expect(containerizer.StreamIn(logger, "some-handle", garden.StreamInSpec{Path: "p"})).To(MatchError("stream-in: no-bundle"))

				_, err := containerizer.StreamOut(logger, "some-handle", garden.StreamOutSpec{Path: "p"})
				Expect(err).To(MatchError("stream-out: no-bundle"))

				Expect(containerizer.Stop(logger, "some-handle", true)).To(MatchError("stop: no-bundle"))

				_, err = containerizer.Run(logger, "some-handle", garden.ProcessSpec{Image: garden.ImageRef{URI: "some-uri"}}, garden.ProcessIO{})
				Expect(err).To(MatchError("no-bundle"))

				Expect(fakeNstarRunner.StreamInCallCount()).To(Equal(0))
				Expect(fakeNstarRunner.StreamOutCallCount()).To(Equal(0))
				Expect(fakeProcessesStopper.StopAllCallCount()).To(Equal(0))
				Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(0))
				Expect(fakePeaCreator.CreatePeaCallCount()).To(Equal(0))
				Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(0))
				Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(0))
			})
		})

		Context("with a gvisor bundle", func() {
			BeforeEach(func() {
				fakeOCIRuntime.BundleInfoReturns("/bundle", bundleFor(map[string]string{backend.AnnotationKey: string(backend.OCIGvisor)}), nil)
				fakeOCIRuntime.ExecReturns(new(gardenfakes.FakeProcess), nil)
			})

			It("streams in by executing tar in the container", func() {
				Expect(containerizer.StreamIn(logger, "some-handle", garden.StreamInSpec{Path: "/dest", User: "vcap"})).To(Succeed())

				Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(2))
				_, handle, spec, _ := fakeOCIRuntime.ExecArgsForCall(1)
				Expect(handle).To(Equal("some-handle"))
				Expect(spec.Path).To(Equal("/bin/tar"))
				Expect(fakeNstarRunner.StreamInCallCount()).To(Equal(0))
				Expect(fakeOCIRuntime.StateCallCount()).To(Equal(0))
			})

			It("streams out by executing tar in the container", func() {
				_, err := containerizer.StreamOut(logger, "some-handle", garden.StreamOutSpec{Path: "/a/b"})
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(1))
				_, _, spec, _ := fakeOCIRuntime.ExecArgsForCall(0)
				Expect(spec.Path).To(Equal("/bin/tar"))
				Expect(fakeNstarRunner.StreamOutCallCount()).To(Equal(0))
			})

			It("runs a pea as a process in the sandbox, dropping its image and bind mounts", func() {
				processSpec := garden.ProcessSpec{
					ID:         "pea-id",
					Path:       "/etc/cf-assets/healthcheck/healthcheck",
					Args:       []string{"-port", "8080"},
					User:       "vcap",
					Image:      garden.ImageRef{URI: "some-uri"},
					BindMounts: []garden.BindMount{{SrcPath: "src", DstPath: "dst"}},
				}
				pio := garden.ProcessIO{Stdout: gbytes.NewBuffer()}

				_, err := containerizer.Run(logger, "some-handle", processSpec, pio)
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(1))
				_, handle, execSpec, execIO := fakeOCIRuntime.ExecArgsForCall(0)
				Expect(handle).To(Equal("some-handle"))
				Expect(execSpec.ID).To(Equal("pea-id"))
				Expect(execSpec.Path).To(Equal(processSpec.Path))
				Expect(execSpec.Args).To(Equal(processSpec.Args))
				Expect(execSpec.User).To(Equal("vcap"))
				Expect(execSpec.Image).To(Equal(garden.ImageRef{}))
				Expect(execSpec.BindMounts).To(BeNil())
				Expect(execIO).To(Equal(pio))
				Expect(fakePeaCreator.CreatePeaCallCount()).To(Equal(0))
				Expect(fakePeaUsernameResolver.ResolveUserCallCount()).To(Equal(0))
			})

			It("runs a non-pea process without consulting the bundle", func() {
				_, err := containerizer.Run(logger, "some-handle", garden.ProcessSpec{Path: "hello"}, garden.ProcessIO{})
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeOCIRuntime.BundleInfoCallCount()).To(Equal(0))
				Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(1))
			})

			Describe("Stop", func() {
				It("sends SIGTERM to the whole task and returns once it has stopped", func() {
					fakeOCIRuntime.StateReturnsOnCall(0, rundmc.State{Pid: 12, Status: rundmc.RunningStatus}, nil)
					fakeOCIRuntime.StateReturnsOnCall(1, rundmc.State{Pid: 12, Status: rundmc.StoppedStatus}, nil)

					Expect(containerizer.Stop(logger, "some-handle", false)).To(Succeed())

					Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(1))
					_, id, signal := fakeTaskKiller.KillAllArgsForCall(0)
					Expect(id).To(Equal("some-handle"))
					Expect(signal).To(Equal(syscall.SIGTERM))
					Expect(fakeProcessesStopper.StopAllCallCount()).To(Equal(0))
					Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(1))
					Expect(fakeStateStore.StoreStoppedArgsForCall(0)).To(Equal("some-handle"))
				})

				It("escalates to SIGKILL when SIGTERM does not stop the task in time", func() {
					fakeOCIRuntime.StateReturns(rundmc.State{Pid: 12, Status: rundmc.RunningStatus}, nil)
					fakeTaskKiller.KillAllStub = func(_ lager.Logger, _ string, signal syscall.Signal) error {
						if signal == syscall.SIGKILL {
							fakeOCIRuntime.StateReturns(rundmc.State{Pid: 12, Status: rundmc.StoppedStatus}, nil)
						}
						return nil
					}

					Expect(containerizer.Stop(logger, "some-handle", false)).To(Succeed())

					Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(2))
					_, _, first := fakeTaskKiller.KillAllArgsForCall(0)
					_, _, second := fakeTaskKiller.KillAllArgsForCall(1)
					Expect(first).To(Equal(syscall.SIGTERM))
					Expect(second).To(Equal(syscall.SIGKILL))
					Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(1))
				})

				It("escalates to SIGKILL when SIGTERM cannot be delivered", func() {
					fakeOCIRuntime.StateReturns(rundmc.State{Pid: 12, Status: rundmc.RunningStatus}, nil)
					fakeTaskKiller.KillAllStub = func(_ lager.Logger, _ string, signal syscall.Signal) error {
						if signal == syscall.SIGTERM {
							return errors.New("term-failed")
						}
						fakeOCIRuntime.StateReturns(rundmc.State{Pid: 12, Status: rundmc.StoppedStatus}, nil)
						return nil
					}

					Expect(containerizer.Stop(logger, "some-handle", false)).To(Succeed())
					Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(2))
				})

				It("sends only SIGKILL when kill is requested", func() {
					fakeOCIRuntime.StateReturnsOnCall(0, rundmc.State{Pid: 12, Status: rundmc.RunningStatus}, nil)
					fakeOCIRuntime.StateReturnsOnCall(1, rundmc.State{Pid: 12, Status: rundmc.StoppedStatus}, nil)

					Expect(containerizer.Stop(logger, "some-handle", true)).To(Succeed())

					Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(1))
					_, _, signal := fakeTaskKiller.KillAllArgsForCall(0)
					Expect(signal).To(Equal(syscall.SIGKILL))
				})

				It("does not signal a task that has already stopped", func() {
					fakeOCIRuntime.StateReturns(rundmc.State{Pid: 12, Status: rundmc.StoppedStatus}, nil)

					Expect(containerizer.Stop(logger, "some-handle", false)).To(Succeed())
					Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(0))
					Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(1))
				})

				for _, kill := range []bool{false, true} {
					kill := kill

					It(fmt.Sprintf("succeeds without a signal for a task that was created but never started (kill %t)", kill), func() {
						fakeOCIRuntime.StateReturns(rundmc.State{Pid: 12, Status: rundmc.CreatedStatus}, nil)
						fakeTaskKiller.KillAllReturns(errors.New("runsc cannot signal a container that has not started"))

						Expect(containerizer.Stop(logger, "some-handle", kill)).To(Succeed())
						Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(0))
						Expect(fakeProcessesStopper.StopAllCallCount()).To(Equal(0))
						Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(1))
						Expect(fakeStateStore.StoreStoppedArgsForCall(0)).To(Equal("some-handle"))
					})
				}

				It("treats a failed signal to a task that exited meanwhile as stopped", func() {
					fakeOCIRuntime.StateReturnsOnCall(0, rundmc.State{Pid: 12, Status: rundmc.RunningStatus}, nil)
					fakeOCIRuntime.StateReturnsOnCall(1, rundmc.State{Pid: 12, Status: rundmc.StoppedStatus}, nil)
					fakeTaskKiller.KillAllReturns(errors.New("process already finished"))

					Expect(containerizer.Stop(logger, "some-handle", true)).To(Succeed())
					Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(1))
				})

				It("fails without recording a stop when SIGKILL cannot be delivered", func() {
					fakeOCIRuntime.StateReturns(rundmc.State{Pid: 12, Status: rundmc.RunningStatus}, nil)
					fakeTaskKiller.KillAllReturns(errors.New("kill-failed"))

					err := containerizer.Stop(logger, "some-handle", true)
					Expect(err).To(MatchError(ContainSubstring("kill-failed")))
					Expect(err).To(MatchError(ContainSubstring("signal 9")))
					Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(0))
				})

				It("fails without recording a stop when the task survives SIGKILL", func() {
					fakeOCIRuntime.StateReturns(rundmc.State{Pid: 12, Status: rundmc.RunningStatus}, nil)

					err := containerizer.Stop(logger, "some-handle", true)
					Expect(err).To(MatchError(ContainSubstring("task still running after signal 9")))
					Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(0))
				})

				It("fails without signalling when the task state cannot be read", func() {
					fakeOCIRuntime.StateReturns(rundmc.State{}, errors.New("no-task"))

					Expect(containerizer.Stop(logger, "some-handle", false)).To(MatchError(ContainSubstring("no-task")))
					Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(0))
					Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(0))
				})

				It("fails when no task killer is configured", func() {
					containerizer = newContainerizer(rundmc.WithBackendDispatch(rundmc.NewExecStreamer(fakeOCIRuntime)))

					Expect(containerizer.Stop(logger, "some-handle", true)).To(MatchError("stop: no containerd task killer is configured to stop containers through their task"))
					Expect(fakeProcessesStopper.StopAllCallCount()).To(Equal(0))
					Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(0))
				})

				Context("with a task pid lister", func() {
					var fakePidLister *fakes.FakeTaskPidLister

					BeforeEach(func() {
						fakePidLister = new(fakes.FakeTaskPidLister)
						containerizer = newContainerizer(
							rundmc.WithBackendDispatch(rundmc.NewExecStreamer(fakeOCIRuntime)),
							rundmc.WithTaskKiller(fakeTaskKiller, retrier.New(retrier.ConstantBackoff(5, time.Millisecond), nil)),
							rundmc.WithTaskPidLister(fakePidLister),
						)
						fakeOCIRuntime.StateReturns(rundmc.State{Pid: 12, Status: rundmc.RunningStatus}, nil)
						fakeTaskKiller.KillAllStub = func(_ lager.Logger, _ string, signal syscall.Signal) error {
							if signal == syscall.SIGKILL {
								fakeOCIRuntime.StateReturns(rundmc.State{Pid: 12, Status: rundmc.StoppedStatus}, nil)
							}
							return nil
						}
					})

					It("stops waiting after SIGTERM once only init is left, then SIGKILLs init", func() {
						fakePidLister.TaskPidsReturnsOnCall(0, []uint32{1, 7, 9}, nil)
						fakePidLister.TaskPidsReturnsOnCall(1, []uint32{1}, nil)

						Expect(containerizer.Stop(logger, "some-handle", false)).To(Succeed())

						Expect(fakePidLister.TaskPidsCallCount()).To(Equal(2))
						_, id := fakePidLister.TaskPidsArgsForCall(0)
						Expect(id).To(Equal("some-handle"))
						Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(2))
						_, _, first := fakeTaskKiller.KillAllArgsForCall(0)
						_, _, second := fakeTaskKiller.KillAllArgsForCall(1)
						Expect(first).To(Equal(syscall.SIGTERM))
						Expect(second).To(Equal(syscall.SIGKILL))
						Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(1))
					})

					It("returns without SIGKILL when the task stops on SIGTERM", func() {
						fakeTaskKiller.KillAllStub = func(_ lager.Logger, _ string, _ syscall.Signal) error {
							fakeOCIRuntime.StateReturns(rundmc.State{Pid: 12, Status: rundmc.StoppedStatus}, nil)
							return nil
						}

						Expect(containerizer.Stop(logger, "some-handle", false)).To(Succeed())
						Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(1))
						Expect(fakePidLister.TaskPidsCallCount()).To(Equal(0))
					})

					It("keeps waiting the full SIGTERM budget while other processes remain", func() {
						fakePidLister.TaskPidsReturns([]uint32{1, 7}, nil)

						Expect(containerizer.Stop(logger, "some-handle", false)).To(Succeed())
						Expect(fakePidLister.TaskPidsCallCount()).To(Equal(6))
						Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(2))
					})

					It("does not take a listing error or an empty list as only init left", func() {
						fakePidLister.TaskPidsReturnsOnCall(0, nil, errors.New("list-failed"))
						fakePidLister.TaskPidsReturns([]uint32{}, nil)

						Expect(containerizer.Stop(logger, "some-handle", false)).To(Succeed())
						Expect(fakePidLister.TaskPidsCallCount()).To(Equal(6))
						Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(2))
					})

					It("is not consulted when kill is requested", func() {
						Expect(containerizer.Stop(logger, "some-handle", true)).To(Succeed())
						Expect(fakePidLister.TaskPidsCallCount()).To(Equal(0))
						Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(1))
					})

					It("still fails when init survives SIGKILL", func() {
						fakePidLister.TaskPidsReturns([]uint32{1}, nil)
						fakeTaskKiller.KillAllStub = nil
						fakeTaskKiller.KillAllReturns(nil)

						err := containerizer.Stop(logger, "some-handle", false)
						Expect(err).To(MatchError(ContainSubstring("task still running after signal 9")))
						Expect(fakeStateStore.StoreStoppedCallCount()).To(Equal(0))
					})
				})
			})
		})
	})

	Describe("without backend dispatch", func() {
		var fakeTaskKiller *fakes.FakeTaskKiller

		for _, kind := range []backend.Kind{backend.OCIGvisor, backend.VMQemu, backend.VMFirecracker} {
			kind := kind

			Context(fmt.Sprintf("even for a bundle annotated %s", kind), func() {
				BeforeEach(func() {
					fakeTaskKiller = new(fakes.FakeTaskKiller)
					containerizer = newContainerizer(rundmc.WithTaskKiller(fakeTaskKiller, retrier.New(retrier.ConstantBackoff(2, time.Millisecond), nil)))
					fakeOCIRuntime.BundleInfoReturns("/bundle", goci.Bndl{Spec: specs.Spec{Annotations: map[string]string{backend.AnnotationKey: string(kind)}}}, nil)
					fakeOCIRuntime.StateReturns(rundmc.State{Pid: 12, Status: rundmc.RunningStatus}, nil)
				})

				AfterEach(func() {
					Expect(fakeOCIRuntime.BundleInfoCallCount()).To(Equal(0))
					Expect(fakeTaskKiller.KillAllCallCount()).To(Equal(0))
				})

				It("runs the CF launcher unwrapped, passing the environment through", func() {
					spec := garden.ProcessSpec{Path: "/tmp/lifecycle/launcher", Args: []string{"app"}, Env: []string{"__GARDEN_VM_LAUNCH_WRAPPED=1"}}
					_, err := containerizer.Run(logger, "some-handle", spec, garden.ProcessIO{})
					Expect(err).NotTo(HaveOccurred())

					_, _, actual, _ := fakeOCIRuntime.ExecArgsForCall(0)
					Expect(actual).To(Equal(spec))
				})

				It("creates peas through the pea creator", func() {
					spec := garden.ProcessSpec{Path: "check", Image: garden.ImageRef{URI: "some-uri"}}
					_, err := containerizer.Run(logger, "some-handle", spec, garden.ProcessIO{})
					Expect(err).NotTo(HaveOccurred())

					Expect(fakePeaCreator.CreatePeaCallCount()).To(Equal(1))
					_, peaSpec, _, _ := fakePeaCreator.CreatePeaArgsForCall(0)
					Expect(peaSpec).To(Equal(spec))
					Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(0))
				})

				It("streams through nstar with the stock errors", func() {
					Expect(containerizer.StreamIn(logger, "some-handle", garden.StreamInSpec{Path: "p"})).To(Succeed())
					_, err := containerizer.StreamOut(logger, "some-handle", garden.StreamOutSpec{Path: "p"})
					Expect(err).NotTo(HaveOccurred())
					Expect(fakeNstarRunner.StreamInCallCount()).To(Equal(1))
					Expect(fakeNstarRunner.StreamOutCallCount()).To(Equal(1))
					Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(0))

					fakeOCIRuntime.StateReturns(rundmc.State{}, errors.New("gone"))
					Expect(containerizer.StreamIn(logger, "some-handle", garden.StreamInSpec{})).To(MatchError("stream-in: pid not found for container"))
					_, err = containerizer.StreamOut(logger, "some-handle", garden.StreamOutSpec{})
					Expect(err).To(MatchError("stream-out: pid not found for container"))
				})

				It("stops through the cgroup stopper, sparing init", func() {
					Expect(containerizer.Stop(logger, "some-handle", false)).To(Succeed())

					Expect(fakeProcessesStopper.StopAllCallCount()).To(Equal(1))
					_, _, exceptions, _ := fakeProcessesStopper.StopAllArgsForCall(0)
					Expect(exceptions).To(ConsistOf(12))
				})
			})
		}
	})

	Describe("Destroy", func() {
		It("delegates to the OCI runtime", func() {
			Expect(containerizer.Destroy(logger, "some-handle")).To(Succeed())
			Expect(fakeOCIRuntime.DeleteCallCount()).To(Equal(1))
		})

		It("destroys the bad cgroup", func() {
			Expect(containerizer.Destroy(logger, "some-handle")).To(Succeed())
			Expect(fakeCPUCgrouper.CleanupCgroupsCallCount()).To(Equal(1))
			Expect(fakeCPUCgrouper.CleanupCgroupsArgsForCall(0)).To(Equal("some-handle"))
		})

		Context("when the runtime fails to destroy", func() {
			BeforeEach(func() {
				fakeOCIRuntime.DeleteReturns(errors.New("pid not found"))
			})

			It("propagates the error back", func() {
				Expect(containerizer.Destroy(logger, "some-handle")).To(MatchError("pid not found"))
			})
		})

		Context("when deleting the bad cgroup fails", func() {
			BeforeEach(func() {
				fakeCPUCgrouper.CleanupCgroupsReturns(errors.New("POOH"))
			})

			It("propagates the error back", func() {
				Expect(containerizer.Destroy(logger, "some-handle")).To(MatchError("POOH"))
			})
		})

		Context("with a device releaser", func() {
			var fakeReleaser *fakes.FakeDeviceReleaser

			BeforeEach(func() {
				fakeReleaser = new(fakes.FakeDeviceReleaser)
				containerizer = newContainerizer(rundmc.WithDeviceReleaser(fakeReleaser))
			})

			It("releases the container's devices after the runtime deletes it", func() {
				fakeOCIRuntime.DeleteStub = func(lager.Logger, string) error {
					Expect(fakeReleaser.ReleaseCallCount()).To(BeZero())
					return nil
				}

				Expect(containerizer.Destroy(logger, "some-handle")).To(Succeed())
				Expect(fakeReleaser.ReleaseCallCount()).To(Equal(1))
				_, handle := fakeReleaser.ReleaseArgsForCall(0)
				Expect(handle).To(Equal("some-handle"))
				Expect(fakeCPUCgrouper.CleanupCgroupsCallCount()).To(Equal(1))
			})

			Context("when the runtime fails to destroy", func() {
				BeforeEach(func() {
					fakeOCIRuntime.DeleteReturns(errors.New("pid not found"))
				})

				It("keeps the devices, which the container may still hold", func() {
					Expect(containerizer.Destroy(logger, "some-handle")).To(MatchError("pid not found"))
					Expect(fakeReleaser.ReleaseCallCount()).To(BeZero())
				})
			})

			Context("when releasing fails", func() {
				BeforeEach(func() {
					fakeReleaser.ReleaseReturns(errors.New("node busy"))
				})

				It("returns the error so that the destroy is retried", func() {
					Expect(containerizer.Destroy(logger, "some-handle")).To(MatchError("node busy"))
				})
			})

			It("releases the devices only once the cgroups are gone, which shows no process is left", func() {
				fakeCPUCgrouper.CleanupCgroupsStub = func(string) error {
					Expect(fakeReleaser.ReleaseCallCount()).To(BeZero())
					return nil
				}

				Expect(containerizer.Destroy(logger, "some-handle")).To(Succeed())
				Expect(fakeReleaser.ReleaseCallCount()).To(Equal(1))
				Expect(fakeOCIRuntime.StateCallCount()).To(BeZero())
			})

			Context("when removing the cgroups fails", func() {
				BeforeEach(func() {
					fakeCPUCgrouper.CleanupCgroupsReturns(errors.New("cgroup busy"))
				})

				It("releases the devices when the runtime reports the container stopped, and still returns the error", func() {
					fakeOCIRuntime.StateReturns(rundmc.State{Status: rundmc.StoppedStatus}, nil)

					Expect(containerizer.Destroy(logger, "some-handle")).To(MatchError("cgroup busy"))
					Expect(fakeReleaser.ReleaseCallCount()).To(Equal(1))
					_, handle := fakeOCIRuntime.StateArgsForCall(0)
					Expect(handle).To(Equal("some-handle"))
				})

				It("keeps the devices when the runtime reports the container still running", func() {
					fakeOCIRuntime.StateReturns(rundmc.State{Status: rundmc.RunningStatus}, nil)

					Expect(containerizer.Destroy(logger, "some-handle")).To(MatchError("cgroup busy"))
					Expect(fakeReleaser.ReleaseCallCount()).To(BeZero())
				})

				It("keeps the devices when the runtime cannot say, and leaves them to a later destroy or the start-up sweep", func() {
					fakeOCIRuntime.StateReturns(rundmc.State{}, errors.New("runc state failed"))

					Expect(containerizer.Destroy(logger, "some-handle")).To(MatchError("cgroup busy"))
					Expect(fakeReleaser.ReleaseCallCount()).To(BeZero())
					Expect(logger).To(gbytes.Say("devices-kept"))
				})

				It("returns both errors when the release after a stopped state fails", func() {
					fakeOCIRuntime.StateReturns(rundmc.State{Status: rundmc.StoppedStatus}, nil)
					fakeReleaser.ReleaseReturns(errors.New("node busy"))

					err := containerizer.Destroy(logger, "some-handle")
					Expect(err).To(MatchError(ContainSubstring("cgroup busy")))
					Expect(err).To(MatchError(ContainSubstring("node busy")))
				})
			})
		})

		It("does not need a device releaser", func() {
			Expect(containerizer.Destroy(logger, "some-handle")).To(Succeed())
		})
	})

	Describe("RemoveBundle", func() {
		It("removes the bundle", func() {
			Expect(containerizer.RemoveBundle(logger, "some-handle")).To(Succeed())

			// TODO: this should be removed once containerd processes are on by default
			Expect(fakeDepot.DestroyCallCount()).To(Equal(1))
			_, handle := fakeDepot.DestroyArgsForCall(0)
			Expect(handle).To(Equal("some-handle"))

			Expect(fakeOCIRuntime.RemoveBundleCallCount()).To(Equal(1))
			_, handle = fakeOCIRuntime.RemoveBundleArgsForCall(0)
			Expect(handle).To(Equal("some-handle"))
		})

		Context("when removing bundle fails", func() {
			BeforeEach(func() {
				fakeOCIRuntime.RemoveBundleReturns(errors.New("destroy failed"))
			})

			It("returns an error", func() {
				Expect(containerizer.RemoveBundle(logger, "some-handle")).To(MatchError(ContainSubstring("destroy failed")))
			})
		})
	})

	Describe("Info", func() {
		var namespaces []specs.LinuxNamespace
		var resources *specs.LinuxResources

		BeforeEach(func() {
			namespaces = []specs.LinuxNamespace{}
			fakeOCIRuntime.StateReturns(rundmc.State{Pid: 42}, nil)

			var limit int64 = 10
			var shares uint64 = 20
			resources = &specs.LinuxResources{
				Memory: &specs.LinuxMemory{
					Limit: &limit,
				},
				CPU: &specs.LinuxCPU{
					Shares: &shares,
				},
			}

		})

		JustBeforeEach(func() {
			fakeOCIRuntime.BundleInfoStub = func(_ lager.Logger, handle string) (string, goci.Bndl, error) {
				if handle != "some-handle" {
					return "", goci.Bundle(), errors.New("cannot find bundle")
				}

				return "/path/to/" + handle, goci.Bndl{
					Spec: specs.Spec{
						Root: &specs.Root{},
						Linux: &specs.Linux{
							Namespaces: namespaces,
							Resources:  resources,
						},
					},
				}, nil
			}
		})

		It("should return the ActualContainerSpec with the correct bundlePath", func() {
			actualSpec, err := containerizer.Info(logger, "some-handle")
			Expect(err).NotTo(HaveOccurred())
			Expect(actualSpec.BundlePath).To(Equal("/path/to/some-handle"))
		})

		It("should return the ActualContainerSpec with the correct CPU limits", func() {
			actualSpec, err := containerizer.Info(logger, "some-handle")
			Expect(err).NotTo(HaveOccurred())
			//lint:ignore SA1019 - we still specify this to make the deprecated logic work until we get rid of the code in garden
			Expect(actualSpec.Limits.CPU.LimitInShares).To(BeEquivalentTo(20))
		})

		It("should return the ActualContainerSpec with the correct memory limits", func() {
			actualSpec, err := containerizer.Info(logger, "some-handle")
			Expect(err).NotTo(HaveOccurred())
			Expect(actualSpec.Limits.Memory.LimitInBytes).To(BeEquivalentTo(10))
		})

		It("should return the ActualContainerSpec with the correct pid", func() {
			actualSpec, err := containerizer.Info(logger, "some-handle")
			Expect(err).NotTo(HaveOccurred())
			Expect(actualSpec.Pid).To(Equal(42))
		})

		Context("when loading up the bundle info fails", func() {
			It("should return the error", func() {
				fakeOCIRuntime.BundleInfoReturns("", goci.Bndl{}, errors.New("bundle-info-error"))
				_, err := containerizer.Info(logger, "some-handle")
				Expect(err).To(MatchError("bundle-info-error"))
			})
		})

		Context("when the bundle has no resources", func() {
			BeforeEach(func() {
				resources = nil
			})

			It("doesn't fail", func() {
				actualSpec, err := containerizer.Info(logger, "some-handle")
				Expect(err).NotTo(HaveOccurred())
				Expect(actualSpec.Limits.Memory.LimitInBytes).To(BeEquivalentTo(0))
				//lint:ignore SA1019 - we still specify this to make the deprecated logic work until we get rid of the code in garden
				Expect(actualSpec.Limits.CPU.LimitInShares).To(BeEquivalentTo(0))
			})
		})

		It("should return any events from the event store", func() {
			fakeEventStore.EventsReturns([]string{
				"potato",
				"fire",
			})

			actualSpec, err := containerizer.Info(logger, "some-handle")
			Expect(err).NotTo(HaveOccurred())
			Expect(actualSpec.Events).To(Equal([]string{
				"potato",
				"fire",
			}))
		})

		It("should return the stopped state from the property manager", func() {
			fakeStateStore.IsStoppedReturns(true)

			actualSpec, err := containerizer.Info(logger, "some-handle")
			Expect(err).NotTo(HaveOccurred())
			Expect(actualSpec.Stopped).To(Equal(true))
		})

		It("should return the ActualContainerSpec with privileged by default", func() {
			actualSpec, err := containerizer.Info(logger, "some-handle")
			Expect(err).NotTo(HaveOccurred())
			Expect(actualSpec.Privileged).To(BeTrue())
		})

		Context("when namespaces contains the user namespace", func() {
			BeforeEach(func() {
				namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
			})

			It("should return the ActualContainerSpec with privileged", func() {
				actualSpec, err := containerizer.Info(logger, "some-handle")
				Expect(err).NotTo(HaveOccurred())
				Expect(actualSpec.Privileged).To(BeFalse())
			})
		})

		Context("when retrieving the State from the runtime errors", func() {
			BeforeEach(func() {
				fakeOCIRuntime.StateReturns(rundmc.State{}, errors.New("error-fetching-state"))
			})

			It("returns the error", func() {
				_, err := containerizer.Info(logger, "some-handle")
				Expect(err).To(MatchError("error-fetching-state"))
			})
		})
	})

	Describe("Metrics", func() {
		JustBeforeEach(func() {
			memoryLimit := int64(100)
			fakeOCIRuntime.BundleInfoReturns("", goci.Bndl{
				Spec: specs.Spec{
					Root: &specs.Root{},
					Linux: &specs.Linux{
						Resources: &specs.LinuxResources{
							Memory: &specs.LinuxMemory{
								Limit: &memoryLimit,
							},
						},
					},
				},
			}, nil)
		})

		It("returns the CPU metrics reported by cgrouper", func() {
			containerStats := gardener.StatsContainerMetrics{
				CPU: garden.ContainerCPUStat{
					Usage:  1,
					User:   2,
					System: 3,
				},
			}

			cpuStats := garden.ContainerCPUStat{
				Usage:  2,
				User:   4,
				System: 6,
			}

			expectedMetrics := gardener.ActualContainerMetrics{
				StatsContainerMetrics: gardener.StatsContainerMetrics{
					CPU: garden.ContainerCPUStat{
						Usage:  2,
						User:   4,
						System: 6,
					},
				},
			}
			fakeOCIRuntime.StatsReturns(containerStats, nil)
			fakeCPUCgrouper.ReadTotalCgroupUsageReturns(cpuStats, nil)
			Expect(containerizer.Metrics(logger, "foo")).To(Equal(expectedMetrics))
			handle, stats := fakeCPUCgrouper.ReadTotalCgroupUsageArgsForCall(0)
			Expect(handle).To(Equal("foo"))
			Expect(stats).To(Equal(containerStats.CPU))
		})

		Context("when cpu entitlement per share is defined", func() {
			var entitlementPerSharePercent float64

			BeforeEach(func() {
				entitlementPerSharePercent = 0.01
				containerizer = rundmc.New(
					fakeDepot,
					fakeBundleGenerator,
					fakeOCIRuntime,
					rundmc.NewNstarStreamer(fakeOCIRuntime, fakeNstarRunner),
					fakeProcessesStopper,
					fakeEventStore,
					fakeStateStore,
					fakePeaCreator,
					fakePeaUsernameResolver,
					entitlementPerSharePercent,
					fakeRuntimeStopper,
					fakeCPUCgrouper,
					false, // imageBackedPeas: default stock behavior
				)
			})

			It("return the CPU entitlement", func() {
				cpuShares := uint64(100)
				fakeOCIRuntime.BundleInfoReturns("", goci.Bundle().WithCPUShares(specs.LinuxCPU{Shares: &cpuShares}), nil)

				containerAge := time.Second * 5
				fakeOCIRuntime.StatsReturns(gardener.StatsContainerMetrics{
					Age: containerAge,
				}, nil)

				actualMetrics, err := containerizer.Metrics(logger, "foo")
				Expect(err).NotTo(HaveOccurred())
				if gardencgroups.IsCgroup2UnifiedMode() {
					expectedEntitlement := uint64(float64(cpuShares) * (entitlementPerSharePercent / 100) * float64(containerAge))
					Expect(actualMetrics.CPUEntitlement).To(BeNumerically("~", expectedEntitlement, 1_000_001))

				} else {
					expectedEntitlement := uint64(float64(cpuShares) * (entitlementPerSharePercent / 100) * float64(containerAge))
					Expect(actualMetrics.CPUEntitlement).To(Equal(expectedEntitlement))
				}
			})

			Context("when peas metrics are requested", func() {
				BeforeEach(func() {
					fakeOCIRuntime.BundleInfoReturns("", goci.Bndl{}, depot.ErrDoesNotExist)
				})

				It("does not return CPU entitlement", func() {
					actualMetrics, err := containerizer.Metrics(logger, "foo")
					Expect(err).NotTo(HaveOccurred())
					Expect(actualMetrics.CPUEntitlement).To(Equal(uint64(0)))
				})
			})
		})

		Context("when container fails to provide stats", func() {
			BeforeEach(func() {
				fakeOCIRuntime.StatsReturns(gardener.StatsContainerMetrics{}, errors.New("banana"))
			})

			It("should return the error", func() {
				_, err := containerizer.Metrics(logger, "foo")
				Expect(err).To(MatchError("banana"))
			})
		})

		Context("when the cpu cgrouper fails to provide bad cgroup usage", func() {
			BeforeEach(func() {
				fakeCPUCgrouper.ReadTotalCgroupUsageReturns(garden.ContainerCPUStat{}, errors.New("potato"))
			})

			It("should return the error", func() {
				_, err := containerizer.Metrics(logger, "foo")
				Expect(err).To(MatchError("potato"))
			})
		})

		Context("when the bad cgroup does not exist (an ancient container)", func() {
			var runtimeStats gardener.StatsContainerMetrics

			BeforeEach(func() {
				fakeCPUCgrouper.ReadTotalCgroupUsageReturns(garden.ContainerCPUStat{}, os.ErrNotExist)

				runtimeStats = gardener.StatsContainerMetrics{
					CPU: garden.ContainerCPUStat{
						Usage:  1,
						User:   2,
						System: 3,
					},
				}
				fakeOCIRuntime.StatsReturns(runtimeStats, nil)
			})

			It("returns runtime stats only", func() {
				Expect(containerizer.Metrics(logger, "foo")).To(Equal(gardener.ActualContainerMetrics{StatsContainerMetrics: runtimeStats}))
			})
		})

		Context("when the bad cgroup does not exist and error type is not recognized", func() {
			var runtimeStats gardener.StatsContainerMetrics

			BeforeEach(func() {
				err := errors.New("error while statting cgroup v2: [open group.procs: no such file or directory]")
				fakeCPUCgrouper.ReadTotalCgroupUsageReturns(garden.ContainerCPUStat{}, err)

				runtimeStats = gardener.StatsContainerMetrics{
					CPU: garden.ContainerCPUStat{
						Usage:  1,
						User:   2,
						System: 3,
					},
				}
				fakeOCIRuntime.StatsReturns(runtimeStats, nil)
			})

			It("returns runtime stats only", func() {
				Expect(containerizer.Metrics(logger, "foo")).To(Equal(gardener.ActualContainerMetrics{StatsContainerMetrics: runtimeStats}))
			})
		})
	})

	Describe("Handles", func() {
		BeforeEach(func() {
			fakeOCIRuntime.ContainerHandlesReturns([]string{"banana", "banana2"}, nil)
		})

		It("should return the handles", func() {
			Expect(containerizer.Handles()).To(ConsistOf("banana", "banana2"))
		})

		Context("when the runtime returns an error", func() {
			BeforeEach(func() {
				fakeOCIRuntime.ContainerHandlesReturns([]string{}, errors.New("handles-error"))
			})

			It("should return the error", func() {
				_, err := containerizer.Handles()
				Expect(err).To(MatchError("handles-error"))
			})
		})
	})

	Describe("WatchRuntimeEvents", func() {
		var watchErr error

		JustBeforeEach(func() {
			watchErr = containerizer.WatchRuntimeEvents(logger)
		})

		Context("when the runtime publishes an event", func() {
			BeforeEach(func() {
				events := make(chan event.Event)
				go func() {
					events <- event.Event{Message: "1"}
					events <- event.Event{Message: "2"}
				}()
				fakeOCIRuntime.EventsReturns(events, nil)
			})

			It("forwards the event to the event store", func() {
				Expect(watchErr).NotTo(HaveOccurred())
				Eventually(fakeEventStore.OnEventCallCount).Should(Equal(2))

				_, msg := fakeEventStore.OnEventArgsForCall(0)
				Expect(msg).To(Equal("1"))

				_, msg = fakeEventStore.OnEventArgsForCall(1)
				Expect(msg).To(Equal("2"))
			})
		})

		Context("when getting the events channel errors", func() {
			BeforeEach(func() {
				fakeOCIRuntime.EventsReturns(nil, errors.New("boom"))
			})

			It("errors", func() {
				Expect(watchErr).To(MatchError("boom"))
			})
		})
	})

	Describe("Shutdown", func() {
		var shutdownError error

		JustBeforeEach(func() {
			shutdownError = containerizer.Shutdown()
		})

		It("stops the runtime", func() {
			Expect(shutdownError).NotTo(HaveOccurred())
			Expect(fakeRuntimeStopper.StopCallCount()).To(Equal(1))
		})

		Context("when stopping the runtime fails", func() {
			BeforeEach(func() {
				fakeRuntimeStopper.StopReturns(errors.New("stop-rt-err"))
			})

			It("returns the error", func() {
				Expect(shutdownError).To(MatchError("stop-rt-err"))
			})
		})
	})
})
