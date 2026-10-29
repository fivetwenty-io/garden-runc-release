package runcontainerd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"syscall"

	"code.cloudfoundry.org/guardian/rundmc"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/guardian/idmapper"
	"code.cloudfoundry.org/guardian/rundmc/event"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/users"
	"code.cloudfoundry.org/lager/v3"
	apievents "github.com/containerd/containerd/api/events"
	uuid "github.com/nu7hatch/gouuid"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

//counterfeiter:generate . ContainerManager
type ContainerManager interface {
	Create(log lager.Logger, containerID string, spec *specs.Spec, containerRootUID, containerRootGID uint32, processIO func() (io.Reader, io.Writer, io.Writer)) error
	Start(log lager.Logger, containerID string) error
	Delete(log lager.Logger, containerID string) error
	Exec(log lager.Logger, containerID, processID string, spec *specs.Process, processIO func() (io.Reader, io.Writer, io.Writer, bool)) (BackingProcess, error)
	KillAll(log lager.Logger, containerID string, signal syscall.Signal) error
	State(log lager.Logger, containerID string) (int, string, error)
	GetContainerPID(log lager.Logger, containerID string) (uint32, error)
	OOMEvents(log lager.Logger) <-chan *apievents.TaskOOM
	Spec(log lager.Logger, containerID string) (*specs.Spec, error)
	BundleIDs(filterLabels ...ContainerFilter) ([]string, error)
	RemoveBundle(lager.Logger, string) error
}

//counterfeiter:generate . RuntimeStopper
type RuntimeStopper interface {
	Stop() error
}

//counterfeiter:generate . ProcessManager
type ProcessManager interface {
	GetProcess(log lager.Logger, containerID, processID string) (BackingProcess, error)
	GetTask(log lager.Logger, id string) (BackingProcess, error)
}

//counterfeiter:generate . ProcessBuilder
type ProcessBuilder interface {
	// CheckUser reports whether spec may run as user, the user that Exec
	// resolved from the container's image, in bndl.
	CheckUser(bndl goci.Bndl, spec garden.ProcessSpec, user *users.ExecUser) error
	BuildProcess(bndl goci.Bndl, spec garden.ProcessSpec, user *users.ExecUser) *specs.Process
}

//counterfeiter:generate . Execer
type Execer interface {
	ExecWithBndl(log lager.Logger, id string, bndl goci.Bndl, spec garden.ProcessSpec, io garden.ProcessIO) (garden.Process, error)
	Attach(log lager.Logger, id string, processId string, io garden.ProcessIO) (garden.Process, error)
}

//counterfeiter:generate . Statser
type Statser interface {
	Stats(log lager.Logger, id string) (gardener.StatsContainerMetrics, error)
}

//counterfeiter:generate . Mkdirer
type Mkdirer interface {
	MkdirAs(rootFSPathFile string, uid, gid int, mode os.FileMode, recreate bool, path ...string) error
}

//counterfeiter:generate . PeaHandlesGetter
type PeaHandlesGetter interface {
	ContainerPeaHandles(log lager.Logger, sandboxHandle string) ([]string, error)
}

type ContainerFilter struct {
	Label        string
	Value        string
	ComparisonOp string
}

type RunContainerd struct {
	containerManager          ContainerManager
	processManager            ProcessManager
	processBuilder            ProcessBuilder
	execer                    Execer
	statser                   Statser
	useContainerdForProcesses bool
	userLookupper             users.UserLookupper
	cgroupManager             CgroupManager
	mkdirer                   Mkdirer
	peaHandlesGetter          PeaHandlesGetter
	cleanupProcessDirsOnWait  bool
	runtimeStopper            RuntimeStopper
	peaRunner                 *RunContainerPea
	backendDispatch           bool
	gvisorStatser             Statser
}

// Option configures a RunContainerd.
type Option func(*RunContainerd)

// WithBackendDispatch makes RunContainerd look up which execution backend a
// container uses before it executes in, attaches to, or reads metrics from
// that container. A gVisor container then always runs its processes through
// containerd and reports metrics through gvisorStatser, whatever the cell's
// defaults are. Without it every container takes the cell's paths.
func WithBackendDispatch(gvisorStatser Statser) Option {
	return func(r *RunContainerd) {
		r.backendDispatch = true
		r.gvisorStatser = gvisorStatser
	}
}

func New(containerManager ContainerManager,
	processManager ProcessManager,
	processBuilder ProcessBuilder,
	userLookupper users.UserLookupper,
	execer Execer,
	statser Statser,
	useContainerdForProcesses bool,
	cgroupManager CgroupManager,
	mkdirer Mkdirer,
	peaHandlesGetter PeaHandlesGetter,
	cleanupProcessDirsOnWait bool,
	runtimeStopper RuntimeStopper,
	opts ...Option) *RunContainerd {
	r := &RunContainerd{
		containerManager:          containerManager,
		processManager:            processManager,
		processBuilder:            processBuilder,
		execer:                    execer,
		statser:                   statser,
		useContainerdForProcesses: useContainerdForProcesses,
		userLookupper:             userLookupper,
		cgroupManager:             cgroupManager,
		mkdirer:                   mkdirer,
		peaHandlesGetter:          peaHandlesGetter,
		cleanupProcessDirsOnWait:  cleanupProcessDirsOnWait,
		runtimeStopper:            runtimeStopper,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// isGvisor reports whether backend dispatch is on and bndl selects gVisor.
func (r *RunContainerd) isGvisor(bndl goci.Bndl) bool {
	return r.backendDispatch && backend.IsGvisor(backend.FromBundle(bndl))
}

func (r *RunContainerd) Create(log lager.Logger, id string, bundle goci.Bndl, pio garden.ProcessIO) error {
	log.Debug("Annotations before update", lager.Data{"id": id, "Annotations": bundle.Spec.Annotations})
	updateAnnotationsIfNeeded(&bundle)
	log.Debug("Annotations after update", lager.Data{"id": id, "Annotations": bundle.Spec.Annotations})

	err := r.cgroupManager.SetUnifiedResources(bundle)
	if err != nil {
		log.Error("failed-to-set-unified-resources", err)
		return err
	}

	// Add cgroup bind mount for cgroups v2 (no-op on Windows and cgroups v1)
	r.cgroupManager.AddCgroupBindMount(&bundle)

	containerRootUID := idmapper.MappingList(bundle.Spec.Linux.UIDMappings).Map(0)
	containerRootGID := idmapper.MappingList(bundle.Spec.Linux.GIDMappings).Map(0)

	// #nosec G115 - the uid/gidmappings lists are capped at maxint32 by idmapper, and should never be negative
	err = r.containerManager.Create(log, id, &bundle.Spec, uint32(containerRootUID), uint32(containerRootGID), func() (io.Reader, io.Writer, io.Writer) { return pio.Stdin, pio.Stdout, pio.Stderr })
	if err != nil {
		return err
	}

	if r.useContainerdForProcesses {
		if err := r.cgroupManager.SetUseMemoryHierarchy(id); err != nil {
			if deleteErr := r.containerManager.Delete(log, id); deleteErr != nil {
				return &PeaRuntimeCleanupError{Err: errors.Join(err, deleteErr)}
			}
			return errors.Join(err, r.containerManager.RemoveBundle(log, id))
		}
	}

	return nil
}

func (r *RunContainerd) Start(log lager.Logger, id string) error {
	return r.containerManager.Start(log, id)
}

// SetPeaRunner routes Attach and restart cleanup of pea containers to the
// runner that owns their IO and shared Wait/deletion.
func (r *RunContainerd) SetPeaRunner(peaRunner *RunContainerPea) {
	r.peaRunner = peaRunner
}

func updateAnnotationsIfNeeded(bundle *goci.Bndl) {
	if _, ok := bundle.Spec.Annotations["container-type"]; !ok {
		if bundle.Spec.Annotations == nil {
			bundle.Spec.Annotations = make(map[string]string)
		}
		bundle.Spec.Annotations["container-type"] = "garden-init"
	}
}

// Exec runs a process in the container. Processes in gVisor containers always
// run through containerd, because runc cannot exec into a container that runsc
// runs. Other processes run through containerd only when
// useContainerdForProcesses is set, and through the runc execer otherwise.
func (r *RunContainerd) Exec(log lager.Logger, containerID string, gardenProcessSpec garden.ProcessSpec, gardenIO garden.ProcessIO) (garden.Process, error) {
	bundle, err := r.getBundle(log, containerID)
	if err != nil {
		return nil, err
	}

	if !r.useContainerdForProcesses && !r.isGvisor(bundle) {
		return r.execer.ExecWithBndl(log, containerID, bundle, gardenProcessSpec, gardenIO)
	}

	if bundle.Spec.Root == nil || bundle.Spec.Root.Path == "" {
		err := fmt.Errorf("container %s has no rootfs path in its spec", containerID)
		log.Error("rootfs-path-missing", err)
		return nil, err
	}
	rootfsPath := bundle.Spec.Root.Path

	resolvedUser, err := r.userLookupper.Lookup(rootfsPath, gardenProcessSpec.User)
	if err != nil {
		return nil, err
	}

	if err := r.processBuilder.CheckUser(bundle, gardenProcessSpec, resolvedUser); err != nil {
		log.Error("user-check-failed", err)
		return nil, err
	}

	hostUID := idmapper.MappingList(bundle.Spec.Linux.UIDMappings).Map(resolvedUser.Uid)
	hostGID := idmapper.MappingList(bundle.Spec.Linux.GIDMappings).Map(resolvedUser.Gid)

	if gardenProcessSpec.Dir == "" {
		gardenProcessSpec.Dir = resolvedUser.Home
	}

	err = r.mkdirer.MkdirAs(rootfsPath, hostUID, hostGID, 0755, false, gardenProcessSpec.Dir)
	if err != nil {
		log.Error("create-workdir-failed", err)
		return nil, err
	}

	if gardenProcessSpec.ID == "" {
		randomID, err := uuid.NewV4()
		if err != nil {
			return nil, err
		}
		gardenProcessSpec.ID = randomID.String()
	}

	processIO := func() (io.Reader, io.Writer, io.Writer, bool) {
		return gardenIO.Stdin, gardenIO.Stdout, gardenIO.Stderr, gardenProcessSpec.TTY != nil
	}

	ociProcessSpec := r.processBuilder.BuildProcess(bundle, gardenProcessSpec, resolvedUser)
	process, err := r.containerManager.Exec(log, containerID, gardenProcessSpec.ID, ociProcessSpec, processIO)
	if err != nil {
		if isNoSuchExecutable(err) {
			return nil, garden.ExecutableNotFoundError{Message: err.Error()}
		}
		return nil, err
	}

	return NewProcess(log, process, r.cleanupProcessDirsOnWait), nil
}

func isNoSuchExecutable(err error) bool {
	runcError := `(?:starting container process caused|unable to start container process)`
	noSuchFile := `stat .*: no such file or directory`
	executableNotFound := `executable file not found in \$PATH`
	noSuchExecutable := regexp.MustCompile(fmt.Sprintf(`%s: exec: .*: (?:%s|%s)`, runcError, noSuchFile, executableNotFound))

	return noSuchExecutable.MatchString(err.Error())
}

func (r *RunContainerd) getBundle(log lager.Logger, containerID string) (goci.Bndl, error) {
	spec, err := r.containerManager.Spec(log, containerID)
	if err != nil {
		return goci.Bndl{}, err
	}

	return goci.Bndl{Spec: *spec}, nil
}

func (r *RunContainerd) Attach(log lager.Logger, sandboxID, processID string, io garden.ProcessIO) (garden.Process, error) {
	if r.peaRunner != nil {
		spec, err := r.containerManager.Spec(log, processID)
		if err == nil && spec != nil && spec.Annotations["container-type"] == "pea" {
			if spec.Annotations["sandbox-container"] != sandboxID {
				return nil, garden.ProcessNotFoundError{ProcessID: processID}
			}
			parent, err := r.containerManager.Spec(log, sandboxID)
			if isNotFound(err) || (err == nil && parent == nil) {
				return nil, garden.ContainerNotFoundError{Handle: sandboxID}
			}
			if err != nil {
				return nil, err
			}
			return r.peaRunner.Attach(log, sandboxID, processID, io)
		}
		if err != nil && !isNotFound(err) {
			return nil, err
		}
	}
	if !r.useContainerdForProcesses {
		gvisor := false
		if r.backendDispatch {
			bundle, err := r.getBundle(log, sandboxID)
			if err != nil {
				return nil, err
			}
			gvisor = r.isGvisor(bundle)
		}
		if !gvisor {
			return r.execer.Attach(log, sandboxID, processID, io)
		}
	}

	var process BackingProcess
	var err error
	if process, err = r.processManager.GetProcess(log, sandboxID, processID); err != nil {
		if isNotFound(err) {
			return nil, garden.ProcessNotFoundError{ProcessID: processID}
		}
		return nil, err
	}
	return NewProcess(log, process, r.cleanupProcessDirsOnWait), nil
}

// WaitAndCleanPea gives restart cleanup the same Wait/deletion owner as Attach.
// Do not follow it with another image deletion.
func (r *RunContainerd) WaitAndCleanPea(log lager.Logger, id string) error {
	if r.peaRunner == nil {
		return fmt.Errorf("image-backed pea lifecycle is unavailable")
	}
	spec, err := r.containerManager.Spec(log, id)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	if spec == nil || spec.Annotations["container-type"] != "pea" || spec.Annotations["sandbox-container"] == "" {
		return fmt.Errorf("%s is not an owned image-backed pea", id)
	}
	process, err := r.peaRunner.Attach(log, spec.Annotations["sandbox-container"], id, garden.ProcessIO{})
	if err != nil {
		var noTask TaskNotFoundError
		if errors.As(err, &noTask) {
			return r.peaRunner.cleanMissingTask(log, spec.Annotations["sandbox-container"], id)
		}
		return err
	}
	_, err = process.Wait()
	return err
}

func (r *RunContainerd) Delete(log lager.Logger, id string) error {
	return r.containerManager.Delete(log, id)
}

func (r *RunContainerd) State(log lager.Logger, id string) (rundmc.State, error) {
	pid, status, err := r.containerManager.State(log, id)
	if err != nil {
		return rundmc.State{}, err
	}

	return rundmc.State{Pid: pid, Status: rundmc.Status(status)}, nil
}

// Stats reads the container's metrics. With backend dispatch, a gVisor
// container reports them through the gVisor statser, because runc knows
// nothing of containers that runsc runs. A process that has no bundle in
// containerd, such as a pea that runc runs, goes to the cell's statser.
func (r *RunContainerd) Stats(log lager.Logger, id string) (gardener.StatsContainerMetrics, error) {
	if !r.backendDispatch {
		return r.statser.Stats(log, id)
	}

	bundle, err := r.getBundle(log, id)
	if err != nil {
		if isNotFound(err) {
			return r.statser.Stats(log, id)
		}
		return gardener.StatsContainerMetrics{}, err
	}

	if r.isGvisor(bundle) {
		return r.gvisorStatser.Stats(log, id)
	}

	return r.statser.Stats(log, id)
}

// KillAll sends signal to every process in the container through containerd.
// Stopping a gVisor container uses it, because the cgroup-based stopper finds
// container processes through runc state, which runsc does not write.
func (r *RunContainerd) KillAll(log lager.Logger, id string, signal syscall.Signal) error {
	log.Debug("killing-all-processes", lager.Data{"id": id, "signal": signal.String()})
	return r.containerManager.KillAll(log, id, signal)
}

func (r *RunContainerd) Events(log lager.Logger) (<-chan event.Event, error) {
	events := make(chan event.Event)

	go func() {
		for {
			for oomEvent := range r.containerManager.OOMEvents(log) {
				events <- event.NewOOMEvent(oomEvent.ContainerID)
			}
		}
	}()

	return events, nil
}

func (r *RunContainerd) BundleInfo(log lager.Logger, handle string) (string, goci.Bndl, error) {
	containerSpec, err := r.containerManager.Spec(log, handle)
	if isNotFound(err) {
		return "", goci.Bndl{}, garden.ContainerNotFoundError{Handle: handle}
	}
	if err != nil {
		return "", goci.Bndl{}, err
	}

	return "", goci.Bndl{Spec: *containerSpec}, nil
}

func isNotFound(err error) bool {
	_, cok := err.(ContainerNotFoundError)
	_, pok := err.(ProcessNotFoundError)
	return cok || pok
}

func (r *RunContainerd) ContainerHandles() ([]string, error) {
	// We couldn't find a way to make containerd only give us the containers with no container-type label.
	// So we just get all the non-pea ones. This should be OK because even if people want to create
	// containers using containerd, but not garden, they should not use the garden namespace.
	return r.containerManager.BundleIDs(ContainerFilter{
		Label:        "container-type",
		Value:        "pea",
		ComparisonOp: "!=",
	})
}

// PeaHandles discovers retained pea metadata even when its parent is absent.
// WaitAndCleanPea validates ownership before opening IO or deleting anything.
func (r *RunContainerd) PeaHandles() ([]string, error) {
	return r.containerManager.BundleIDs(ContainerFilter{
		Label:        "container-type",
		Value:        "pea",
		ComparisonOp: "==",
	})
}

func (r *RunContainerd) ContainerPeaHandles(log lager.Logger, sandboxHandle string) ([]string, error) {
	if r.peaHandlesGetter != nil {
		return r.peaHandlesGetter.ContainerPeaHandles(log, sandboxHandle)
	}
	return r.containerManager.BundleIDs(
		ContainerFilter{
			Label:        "container-type",
			Value:        "pea",
			ComparisonOp: "==",
		},
		ContainerFilter{
			Label:        "sandbox-container",
			Value:        sandboxHandle,
			ComparisonOp: "==",
		},
	)
}

func (r *RunContainerd) RemoveBundle(log lager.Logger, handle string) error {
	return r.containerManager.RemoveBundle(log, handle)
}

func (r *RunContainerd) Stop() error {
	return r.runtimeStopper.Stop()
}
