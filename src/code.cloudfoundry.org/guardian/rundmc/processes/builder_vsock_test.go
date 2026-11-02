package processes_test

import (
	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/processes"
	fakes "code.cloudfoundry.org/guardian/rundmc/processes/processesfakes"
	"code.cloudfoundry.org/guardian/rundmc/seccompvsock"
	"code.cloudfoundry.org/guardian/rundmc/users"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

var _ = Describe("the vsock denial of the processes in a vm-* container", func() {
	var (
		envDeterminer *fakes.FakeEnvDeterminer
		profile       *specs.LinuxSeccomp
		kind          backend.Kind
		processSpec   garden.ProcessSpec
		marked        bool
		builderOpts   []processes.Option
	)

	launcherArgs := []string{"--backend", "vm-qemu", "--", "/tmp/lifecycle/launcher", "app", "true", ""}

	allowList := func() *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls:      []specs.LinuxSyscall{{Names: []string{"socket"}, Action: specs.ActAllow}},
		}
	}

	BeforeEach(func() {
		envDeterminer = new(fakes.FakeEnvDeterminer)
		envDeterminer.EnvForReturns([]string{"PATH=/usr/bin:/bin"})
		// The container that the execution backend rule lets create vsock
		// sockets: a vm-qemu container with the guest agent.
		profile = allowList()
		kind = backend.VMQemu
		marked = false
		processSpec = garden.ProcessSpec{Path: "/tmp/lifecycle/diego-sshd", Args: []string{"--address=0.0.0.0:2222"}}
		builderOpts = []processes.Option{processes.WithKVMGid(108), processes.WithVsockDenial()}
	})

	build := func() *specs.Process {
		GinkgoHelper()
		bndl := goci.Bundle().WithCapabilities("CAP_CHOWN").WithSeccomp(profile)
		bndl.Spec.Annotations = map[string]string{backend.AnnotationKey: string(kind)}
		spec := processSpec
		if marked {
			spec = processes.MarkVMLaunch(spec)
		}
		return processes.NewBuilder(envDeterminer, []string{"CAP_CHOWN"}, builderOpts...).BuildProcess(bndl, spec, &users.ExecUser{Uid: 2000, Gid: 2000})
	}

	It("names the command and the flag vm-launch reads", func() {
		Expect(processes.VMLaunchDenyVsockCommand).To(Equal("deny-vsock"))
		Expect(processes.VMLaunchDenyChildVsockFlag).To(Equal("--deny-child-vsock"))
	})

	Context("in a container whose profile lets it create vsock sockets", func() {
		It("runs every process but the wrapped vm-launch through vm-launch's deny-vsock, which execs it under a filter", func() {
			Expect(build().Args).To(Equal([]string{processes.VMLaunchPath, "deny-vsock", "--", "/tmp/lifecycle/diego-sshd", "--address=0.0.0.0:2222"}))
		})

		It("keeps a process's path as the command deny-vsock runs, so that the PATH lookup is the runtime's", func() {
			processSpec = garden.ProcessSpec{Path: "sh", Args: []string{"-c", "true"}}
			Expect(build().Args).To(Equal([]string{processes.VMLaunchPath, "deny-vsock", "--", "sh", "-c", "true"}))
		})

		It("also runs vm-launch through deny-vsock when it lacks the containerizer's marker", func() {
			processSpec = garden.ProcessSpec{Path: processes.VMLaunchPath, Args: launcherArgs}
			Expect(build().Args).To(Equal(append([]string{processes.VMLaunchPath, "deny-vsock", "--", processes.VMLaunchPath}, launcherArgs...)))
		})

		It("lets the wrapped vm-launch keep vsock, and tells it to deny vsock to its children", func() {
			marked = true
			processSpec = garden.ProcessSpec{Path: processes.VMLaunchPath, Args: launcherArgs}
			builderOpts = append(builderOpts, processes.WithVMLaunchFlags("--guest-agent"))
			Expect(build().Args).To(Equal(append([]string{processes.VMLaunchPath, "--guest-agent", "--deny-child-vsock"}, launcherArgs...)))
		})

		It("does the same for a privileged container, which has no profile", func() {
			profile = nil
			Expect(build().Args).To(Equal([]string{processes.VMLaunchPath, "deny-vsock", "--", "/tmp/lifecycle/diego-sshd", "--address=0.0.0.0:2222"}))
		})

		It("keeps the process's environment, working directory, and user", func() {
			process := build()
			Expect(process.Env).To(Equal([]string{"PATH=/usr/bin:/bin"}))
			Expect(process.User.UID).To(Equal(uint32(2000)))
			Expect(process.NoNewPrivileges).To(BeTrue())
		})
	})

	Context("in a container whose profile denies vsock already", func() {
		BeforeEach(func() {
			profile = seccompvsock.Deny(allowList())
		})

		It("runs a process as it is", func() {
			Expect(build().Args).To(Equal([]string{"/tmp/lifecycle/diego-sshd", "--address=0.0.0.0:2222"}))
		})

		It("passes the wrapped vm-launch no flag, because its children inherit the profile", func() {
			marked = true
			processSpec = garden.ProcessSpec{Path: processes.VMLaunchPath, Args: launcherArgs}
			Expect(build().Args).To(Equal(append([]string{processes.VMLaunchPath}, launcherArgs...)))
		})
	})

	It("leaves a container that is not a vm-* one alone, because vm-launch is not in it", func() {
		kind = backend.OCIRunc
		Expect(build().Args).To(Equal([]string{"/tmp/lifecycle/diego-sshd", "--address=0.0.0.0:2222"}))
		kind = backend.OCIGvisor
		Expect(build().Args).To(Equal([]string{"/tmp/lifecycle/diego-sshd", "--address=0.0.0.0:2222"}))
	})

	Context("without the option, as when the denial is off", func() {
		BeforeEach(func() {
			builderOpts = []processes.Option{processes.WithKVMGid(108)}
		})

		It("builds the argv it built before for every process", func() {
			Expect(build().Args).To(Equal([]string{"/tmp/lifecycle/diego-sshd", "--address=0.0.0.0:2222"}))

			marked = true
			processSpec = garden.ProcessSpec{Path: processes.VMLaunchPath, Args: launcherArgs}
			Expect(build().Args).To(Equal(append([]string{processes.VMLaunchPath}, launcherArgs...)))
		})
	})
})
