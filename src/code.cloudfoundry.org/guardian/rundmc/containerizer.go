//lint:file-ignore SA1019 - we still specify LimitInShares to make the deprecated logic work until we get rid of the code in garden

package rundmc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/gardener"
	spec "code.cloudfoundry.org/guardian/gardener/container-spec"
	"code.cloudfoundry.org/guardian/rundmc/event"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/processes"
	"code.cloudfoundry.org/lager/v3"
	"github.com/cloudfoundry/dropsonde/metrics"
	"github.com/eapache/go-resiliency/retrier"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate . Depot
//counterfeiter:generate . OCIRuntime
//counterfeiter:generate . NstarRunner
//counterfeiter:generate . EventStore
//counterfeiter:generate . ProcessesStopper
//counterfeiter:generate . StateStore
//counterfeiter:generate . PeaCreator
//counterfeiter:generate . PeaUsernameResolver
//counterfeiter:generate . RuntimeStopper
//counterfeiter:generate . CPUCgrouper
//counterfeiter:generate . TaskKiller
//counterfeiter:generate . TaskPidLister
//counterfeiter:generate . DeviceReleaser

type Depot interface {
	Destroy(log lager.Logger, handle string) error
}

//counterfeiter:generate . BundleGenerator
type BundleGenerator interface {
	Generate(desiredContainerSpec spec.DesiredContainerSpec) (goci.Bndl, error)
}

type Status string

const RunningStatus Status = "running"
const CreatedStatus Status = "created"
const StoppedStatus Status = "stopped"

type State struct {
	Pid    int
	Status Status
}

type OCIRuntime interface {
	Create(log lager.Logger, id string, bundle goci.Bndl, io garden.ProcessIO) error
	Start(log lager.Logger, id string) error
	Exec(log lager.Logger, id string, spec garden.ProcessSpec, io garden.ProcessIO) (garden.Process, error)
	Attach(log lager.Logger, id, processId string, io garden.ProcessIO) (garden.Process, error)
	Delete(log lager.Logger, id string) error
	State(log lager.Logger, id string) (State, error)
	Stats(log lager.Logger, id string) (gardener.StatsContainerMetrics, error)
	Events(log lager.Logger) (<-chan event.Event, error)
	ContainerHandles() ([]string, error)
	ContainerPeaHandles(log lager.Logger, id string) ([]string, error)
	BundleInfo(log lager.Logger, id string) (string, goci.Bndl, error)
	RemoveBundle(log lager.Logger, id string) error
}

type PeaCreator interface {
	CreatePea(log lager.Logger, processSpec garden.ProcessSpec, pio garden.ProcessIO, sandboxHandle string) (garden.Process, error)
}

type NstarRunner interface {
	StreamIn(log lager.Logger, pid int, path string, user string, tarStream io.Reader) error
	StreamOut(log lager.Logger, pid int, path string, user string) (io.ReadCloser, error)
}

type ProcessesStopper interface {
	StopAll(log lager.Logger, cgroupName string, save []int, kill bool) error
}

type RuntimeStopper interface {
	Stop() error
}

// TaskKiller signals every process of a container's containerd task, init
// included. gVisor containers are stopped through it, because their processes
// are not visible in a host cgroup the ProcessesStopper could walk.
// Implementations return nil when the task has already exited.
type TaskKiller interface {
	KillAll(log lager.Logger, id string, signal syscall.Signal) error
}

// TaskPidLister lists the processes of a container's containerd task, init
// included. A graceful gVisor Stop uses it to see when only init is left,
// because garden-init does not exit on SIGTERM.
type TaskPidLister interface {
	TaskPids(log lager.Logger, id string) ([]uint32, error)
}

// DeviceReleaser removes the host device nodes that a container was given
// when its bundle was generated. Destroy calls Release once the runtime has
// deleted the container and its cgroups are gone, or, when removing the
// cgroups fails, once the runtime reports the container stopped. Release must
// succeed for a container that was given none and when called again.
type DeviceReleaser interface {
	Release(log lager.Logger, handle string) error
}

type EventStore interface {
	OnEvent(id string, event string) error
	Events(id string) []string
}

type StateStore interface {
	StoreStopped(handle string)
	IsStopped(handle string) bool
}

type PeaUsernameResolver interface {
	ResolveUser(log lager.Logger, handle string, image garden.ImageRef, username string) (int, int, error)
}

type CPUCgrouper interface {
	PrepareCgroups(handle string) error
	CleanupCgroups(handle string) error
	ReadTotalCgroupUsage(handle string, cpuStats garden.ContainerCPUStat) (garden.ContainerCPUStat, error)
}

// Containerizer knows how to manage a depot of container bundles
type Containerizer struct {
	depot                  Depot
	bundler                BundleGenerator
	runtime                OCIRuntime
	processesStopper       ProcessesStopper
	streamer               Streamer
	events                 EventStore
	states                 StateStore
	peaCreator             PeaCreator
	peaUsernameResolver    PeaUsernameResolver
	cpuEntitlementPerShare float64
	runtimeStopper         RuntimeStopper
	cpuCgrouper            CPUCgrouper
	imageBackedPeas        bool
	taskKiller             TaskKiller
	taskExitRetrier        *retrier.Retrier
	taskPidLister          TaskPidLister
	taskStop               bool
	backendDispatch        bool
	gvisorStreamer         Streamer
	deviceReleaser         DeviceReleaser

	// guestMemory holds the newest guest memory sample of each VM container,
	// and guestFigure remembers which containers Metrics last answered from it.
	guestMemory vmGuestMemory
	guestFigure sync.Map
}

// Option configures a Containerizer collaborator that only some deployments need.
type Option func(*Containerizer)

// WithTaskKiller lets the Containerizer stop containers through their
// containerd task. exitRetrier bounds how long Stop waits for the task to exit
// after each signal before it escalates or gives up. Without this option,
// stopping a container that needs a task stop fails.
func WithTaskKiller(killer TaskKiller, exitRetrier *retrier.Retrier) Option {
	return func(c *Containerizer) {
		c.taskKiller = killer
		c.taskExitRetrier = exitRetrier
	}
}

// WithTaskPidLister lets a graceful task stop end its SIGTERM wait as soon as
// only the init process is left, instead of waiting for the whole exit retrier.
// Without it, the wait ends only when the task has stopped.
func WithTaskPidLister(lister TaskPidLister) Option {
	return func(c *Containerizer) {
		c.taskPidLister = lister
	}
}

// WithTaskStop makes Stop stop every container through its containerd task
// instead of the ProcessesStopper, which finds processes through runc state
// that runsc does not write. Pass it when runsc is the cell's runtime.
func WithTaskStop() Option {
	return func(c *Containerizer) {
		c.taskStop = true
	}
}

// WithBackendDispatch makes the Containerizer read each container's bundle to
// route peas, tar streaming, Stop, and the CF launcher by execution backend.
// gVisor containers stream through gvisorStreamer. Without it every container
// takes the cell's paths and no bundle is read for those calls. Pass it only
// when a backend other than oci-runc is enabled.
func WithBackendDispatch(gvisorStreamer Streamer) Option {
	return func(c *Containerizer) {
		c.backendDispatch = true
		c.gvisorStreamer = gvisorStreamer
	}
}

// WithDeviceReleaser makes Destroy release the host device nodes of the
// container after the runtime has deleted it. Pass it when bundle generation
// can create such nodes.
func WithDeviceReleaser(releaser DeviceReleaser) Option {
	return func(c *Containerizer) {
		c.deviceReleaser = releaser
	}
}

func New(
	depot Depot,
	bundler BundleGenerator,
	runtime OCIRuntime,
	streamer Streamer,
	processesStopper ProcessesStopper,
	events EventStore,
	states StateStore,
	peaCreator PeaCreator,
	peaUsernameResolver PeaUsernameResolver,
	cpuEntitlementPerShare float64,
	runtimeStopper RuntimeStopper,
	cpuCgrouper CPUCgrouper,
	imageBackedPeas bool,
	opts ...Option,
) *Containerizer {
	containerizer := &Containerizer{
		depot:                  depot,
		bundler:                bundler,
		runtime:                runtime,
		streamer:               streamer,
		processesStopper:       processesStopper,
		events:                 events,
		states:                 states,
		peaCreator:             peaCreator,
		peaUsernameResolver:    peaUsernameResolver,
		cpuEntitlementPerShare: cpuEntitlementPerShare,
		runtimeStopper:         runtimeStopper,
		cpuCgrouper:            cpuCgrouper,
		imageBackedPeas:        imageBackedPeas,
	}
	for _, opt := range opts {
		opt(containerizer)
	}
	return containerizer
}

func (c *Containerizer) WatchRuntimeEvents(log lager.Logger) error {
	events, err := c.runtime.Events(log)
	if err != nil {
		return err
	}

	go func() {
		for event := range events {
			if err := c.events.OnEvent(event.ContainerID, event.Message); err != nil {
				log.Error("failed to store event", err, lager.Data{"event": event})
			}
		}
	}()

	return nil
}

// Create creates a bundle in the depot and starts its init process
func (c *Containerizer) Create(log lager.Logger, spec spec.DesiredContainerSpec) error {
	log = log.Session("containerizer-create", lager.Data{"handle": spec.Handle})

	log.Info("start")
	defer log.Info("finished")

	bundle, err := c.bundler.Generate(spec)
	if err != nil {
		log.Error("bundle-generate-failed", err)
		return err
	}

	if err := c.cpuCgrouper.PrepareCgroups(spec.Handle); err != nil {
		log.Error("prepare-cgroups-failed", err)
		return err
	}

	if err := c.runtime.Create(log, spec.Handle, bundle, garden.ProcessIO{}); err != nil {
		log.Error("runtime-create-failed", err)
		return err
	}

	return nil
}

func (c *Containerizer) Start(log lager.Logger, handle string) error {
	log = log.Session("containerizer-start", lager.Data{"handle": handle})
	return c.runtime.Start(log, handle)
}

// Run runs a process inside a running container. With imageBackedPeas, named
// pea users are resolved by PeaCreator against the pea image rather than
// through the parent's host PID, which cannot see a grouped child's rootfs.
func (c *Containerizer) Run(log lager.Logger, handle string, spec garden.ProcessSpec, io garden.ProcessIO) (garden.Process, error) {
	log = log.Session("run", lager.Data{"handle": handle, "path": spec.Path})

	log.Info("started")
	defer log.Info("finished")

	if c.backendDispatch {
		// Only wrapVMLauncher may mark a process as the wrapped vm-launch.
		spec, _ = processes.UnmarkVMLaunch(spec)
	}

	if isPea(spec) {
		if c.backendDispatch {
			gvisor, err := c.isGvisor(log, handle)
			if err != nil {
				return nil, err
			}

			if gvisor {
				return c.runPeaAsExec(log, handle, spec, io)
			}
		}

		if c.imageBackedPeas {
			return c.peaCreator.CreatePea(log, spec, io, handle)
		}

		if shouldResolveUsername(spec.User) {
			resolvedUID, resolvedGID, err := c.peaUsernameResolver.ResolveUser(log, handle, spec.Image, spec.User)
			if err != nil {
				return nil, err
			}

			spec.User = fmt.Sprintf("%d:%d", resolvedUID, resolvedGID)
		}

		return c.peaCreator.CreatePea(log, spec, io, handle)
	}

	if spec.BindMounts != nil {
		err := fmt.Errorf("Running a process with bind mounts and no image provided is not allowed")
		log.Error("invalid-spec", err)
		return nil, err
	}

	if c.backendDispatch && spec.Path == cfLauncherPath {
		wrapped, isVM, err := c.wrapVMLauncher(log, handle, spec)
		if err != nil {
			return nil, err
		}

		spec = wrapped

		if isVM {
			return c.runVMLauncher(log, handle, spec, io)
		}
	}

	return c.runtime.Exec(log, handle, spec, io)
}

// wrapVMLauncher rewrites the CF launcher process of a vm-* container so that
// it runs through vm-launch, which boots the workload inside a microVM, and
// marks it so that the process builder grants it the kvm gid. In a
// vm-firecracker container the process builder also decides, from the
// environment it builds, whether vm-launch dials each forwarded connection
// from its client's address, which takes CAP_NET_RAW (see
// processes.VMLaunchTransparentProxyFlag). Every other process, and every
// container on another backend, is returned as is. It reports whether it
// wrapped the process.
func (c *Containerizer) wrapVMLauncher(log lager.Logger, handle string, spec garden.ProcessSpec) (garden.ProcessSpec, bool, error) {
	_, bundle, err := c.runtime.BundleInfo(log, handle)
	if err != nil {
		log.Error("bundle-info-failed", err)
		return spec, false, err
	}

	kind := backend.FromBundle(bundle)
	if !backend.IsVM(kind) {
		return spec, false, nil
	}

	log.Info("vm-wrap-launcher", lager.Data{"backend": string(kind)})

	args := make([]string, 0, len(spec.Args)+4)
	args = append(args, "--backend", string(kind))
	args = append(args, "--", spec.Path)
	args = append(args, spec.Args...)

	spec.Path = processes.VMLaunchPath
	spec.Args = args

	return processes.MarkVMLaunch(spec), true, nil
}

// runPeaAsExec runs a pea's process inside the sandbox container itself. A
// gVisor sandbox cannot share its namespaces with a sibling container unless
// the cell runs runsc with grouped peas, so the pea's image and bind mounts
// are dropped and its binary must already be present in the sandbox, as the
// CF healthcheck and assets are.
func (c *Containerizer) runPeaAsExec(log lager.Logger, handle string, spec garden.ProcessSpec, io garden.ProcessIO) (garden.Process, error) {
	log.Info("gvisor-pea-as-exec", lager.Data{"image": spec.Image.URI, "bind-mounts": len(spec.BindMounts)})

	spec.Image = garden.ImageRef{}
	spec.BindMounts = nil

	return c.runtime.Exec(log, handle, spec, io)
}

const (
	// cfLauncherPath is the CF buildpack launcher, the entrypoint of every app
	// and task process Diego starts.
	cfLauncherPath = "/tmp/lifecycle/launcher"
)

func isPea(spec garden.ProcessSpec) bool {
	return spec.Image != (garden.ImageRef{})
}

func shouldResolveUsername(username string) bool {
	return username != "" && !strings.Contains(username, ":")
}

func (c *Containerizer) Attach(log lager.Logger, handle string, processID string, io garden.ProcessIO) (garden.Process, error) {
	log = log.Session("attach", lager.Data{"handle": handle, "process-id": processID})

	log.Info("started")
	defer log.Info("finished")

	return c.runtime.Attach(log, handle, processID, io)
}

// StreamIn streams files in to the container
func (c *Containerizer) StreamIn(log lager.Logger, handle string, spec garden.StreamInSpec) error {
	log = log.Session("stream-in", lager.Data{"handle": handle})
	log.Info("started")
	defer log.Info("finished")

	defer func(startedAt time.Time) {
		_ = metrics.SendValue("StreamInDuration", float64(time.Since(startedAt).Nanoseconds()), "nanos")
	}(time.Now())

	streamer, err := c.streamerFor(log, handle)
	if err != nil {
		return fmt.Errorf("stream-in: %w", err)
	}

	return streamer.StreamIn(log, handle, spec)
}

// StreamOut stream files from the container
func (c *Containerizer) StreamOut(log lager.Logger, handle string, spec garden.StreamOutSpec) (io.ReadCloser, error) {
	log = log.Session("stream-out", lager.Data{"handle": handle})

	log.Info("started")
	defer log.Info("finished")

	streamer, err := c.streamerFor(log, handle)
	if err != nil {
		return nil, fmt.Errorf("stream-out: %w", err)
	}

	return streamer.StreamOut(log, handle, spec)
}

func (c *Containerizer) streamerFor(log lager.Logger, handle string) (Streamer, error) {
	if !c.backendDispatch {
		return c.streamer, nil
	}

	gvisor, err := c.isGvisor(log, handle)
	if err != nil {
		return nil, err
	}

	if gvisor {
		return c.gvisorStreamer, nil
	}

	return c.streamer, nil
}

// isGvisor reports whether the container's bundle selects the gVisor backend.
// A bundle that cannot be read is an error rather than a runc default, because
// sending nstar or the cgroup stopper at a gVisor sandbox would act on the
// sandbox's host processes instead of the container.
func (c *Containerizer) isGvisor(log lager.Logger, handle string) (bool, error) {
	_, bundle, err := c.runtime.BundleInfo(log, handle)
	if err != nil {
		log.Error("bundle-info-failed", err)
		return false, err
	}

	return backend.IsGvisor(backend.FromBundle(bundle)), nil
}

// needsTaskStop reports whether Stop goes through the container's containerd
// task: always when the cell runs runsc, and for gVisor containers under
// backend dispatch.
func (c *Containerizer) needsTaskStop(log lager.Logger, handle string) (bool, error) {
	if c.taskStop {
		return true, nil
	}
	if !c.backendDispatch {
		return false, nil
	}
	return c.isGvisor(log, handle)
}

// Stop stops all the processes other than the init process in the container
func (c *Containerizer) Stop(log lager.Logger, handle string, kill bool) error {
	log = log.Session("stop", lager.Data{"handle": handle, "kill": kill})

	log.Info("started")
	defer log.Info("finished")

	taskStop, err := c.needsTaskStop(log, handle)
	if err != nil {
		return fmt.Errorf("stop: %w", err)
	}

	if taskStop {
		if err := c.stopTask(log, handle, kill); err != nil {
			log.Error("stop-task-failed", err)
			return fmt.Errorf("stop: %w", err)
		}

		c.states.StoreStopped(handle)
		return nil
	}

	state, err := c.runtime.State(log, handle)
	if err != nil {
		log.Error("check-pid-failed", err)
		return fmt.Errorf("stop: pid not found for container: %s", err)
	}

	if err = c.processesStopper.StopAll(log, handle, []int{state.Pid}, kill); err != nil {
		log.Error("stop-all-processes-failed", err, lager.Data{"pid": state.Pid})
		return fmt.Errorf("stop: %s", err)
	}

	c.states.StoreStopped(handle)
	return nil
}

var errNoTaskKiller = errors.New("no containerd task killer is configured to stop containers through their task")

// stopTask stops a container through its containerd task. It mirrors the
// cgroup stopper: SIGTERM and a bounded wait unless kill is set, then SIGKILL.
// Unlike the cgroup stopper it also stops the init process, because containerd
// can only signal the whole task. garden-init has no SIGTERM handler, so as the
// init of a pid namespace it ignores SIGTERM. The SIGTERM wait therefore also
// ends once init is the only process left, and SIGKILL then stops init. A task
// that is stopped, or that was created and never started, has nothing to stop,
// and stopTask returns nil without a signal.
func (c *Containerizer) stopTask(log lager.Logger, handle string, kill bool) error {
	if c.taskKiller == nil || c.taskExitRetrier == nil {
		return errNoTaskKiller
	}

	state, err := c.runtime.State(log, handle)
	if err != nil {
		log.Error("check-state-failed", err)
		return fmt.Errorf("task state not found for container: %s", err)
	}

	switch state.Status {
	case StoppedStatus:
		log.Info("task-already-stopped")
		return nil
	case CreatedStatus:
		// The task was created but never started, so no process runs in it,
		// and runsc refuses to signal such a container.
		log.Info("task-never-started")
		return nil
	}

	if !kill {
		onlyInitLeft := false
		err := c.signalTaskAndWait(log, handle, syscall.SIGTERM, func() error {
			stoppedErr := c.taskStopped(log, handle)
			if stoppedErr == nil {
				return nil
			}
			if c.onlyInitLeft(log, handle) {
				onlyInitLeft = true
				return nil
			}
			return stoppedErr
		})

		switch {
		case err != nil:
			log.Info("escalating-to-sigkill", lager.Data{"reason": err.Error()})
		case onlyInitLeft:
			log.Info("only-init-left-stopping-it")
		default:
			return nil
		}
	}

	return c.signalTaskAndWait(log, handle, syscall.SIGKILL, func() error { return c.taskStopped(log, handle) })
}

// onlyInitLeft reports whether the task's init is its only process. A listing
// error or an empty list is not proof of that, so both report false and the
// caller keeps waiting for the task to stop.
func (c *Containerizer) onlyInitLeft(log lager.Logger, handle string) bool {
	if c.taskPidLister == nil {
		return false
	}

	pids, err := c.taskPidLister.TaskPids(log, handle)
	if err != nil {
		log.Debug("list-task-pids-failed", lager.Data{"error": err.Error()})
		return false
	}

	return len(pids) == 1
}

// signalTaskAndWait signals every process of the task and then retries done
// until it returns nil or the exit retrier gives up.
func (c *Containerizer) signalTaskAndWait(log lager.Logger, handle string, signal syscall.Signal, done func() error) error {
	if err := c.taskKiller.KillAll(log, handle, signal); err != nil {
		// The task can exit between the state check and the signal.
		if c.taskStopped(log, handle) == nil {
			return nil
		}

		return fmt.Errorf("kill-all with signal %d: %w", signal, err)
	}

	if err := c.taskExitRetrier.Run(done); err != nil {
		return fmt.Errorf("task still running after signal %d: %w", signal, err)
	}

	return nil
}

func (c *Containerizer) taskStopped(log lager.Logger, handle string) error {
	state, err := c.runtime.State(log, handle)
	if err != nil {
		return err
	}

	if state.Status != StoppedStatus {
		return fmt.Errorf("task status is %q", state.Status)
	}

	return nil
}

// Destroy deletes the container and the bundle directory
func (c *Containerizer) Destroy(log lager.Logger, handle string) error {
	log = log.Session("destroy", lager.Data{"handle": handle})

	log.Info("started")
	defer log.Info("finished")

	if err := c.runtime.Delete(log, handle); err != nil {
		return err
	}

	c.guestMemory.Remove(handle)
	c.guestFigure.Delete(handle)

	// The cgroup removal fails while any process of the container is left,
	// so its success shows that nothing holds the container's devices. When
	// it fails, only a stopped state from the runtime lets the devices go. A
	// claim that is kept is released by a later destroy or by the start-up
	// sweep.
	cgErr := c.cpuCgrouper.CleanupCgroups(handle)
	if c.deviceReleaser != nil {
		if cgErr != nil && !c.reportsStopped(log, handle) {
			log.Info("devices-kept", lager.Data{"cgroup-error": cgErr.Error()})
			return cgErr
		}
		if err := c.deviceReleaser.Release(log, handle); err != nil {
			return errors.Join(cgErr, err)
		}
	}

	return cgErr
}

// reportsStopped reports whether the runtime says the container is stopped. A
// failed state lookup counts as not stopped.
func (c *Containerizer) reportsStopped(log lager.Logger, handle string) bool {
	state, err := c.runtime.State(log, handle)
	if err != nil {
		log.Info("state-unknown-after-delete", lager.Data{"error": err.Error()})
		return false
	}
	return state.Status == StoppedStatus
}

func (c *Containerizer) RemoveBundle(log lager.Logger, handle string) error {
	log = log.Session("remove-bundle", lager.Data{"handle": handle})
	// TODO: this should be removed once containerd processes are the only code path
	// and this should be managed by the network depot
	if err := c.depot.Destroy(log, handle); err != nil {
		log.Debug("failed-to-remove-bundle-dir")
	}
	return c.runtime.RemoveBundle(log, handle)
}

func (c *Containerizer) Info(log lager.Logger, handle string) (spec.ActualContainerSpec, error) {
	bundlePath, bundle, err := c.runtime.BundleInfo(log, handle)
	if err != nil {
		return spec.ActualContainerSpec{}, err
	}

	state, err := c.runtime.State(log, handle)
	if err != nil {
		return spec.ActualContainerSpec{}, err
	}

	privileged := true
	for _, ns := range bundle.Namespaces() {
		if ns.Type == specs.UserNamespace {
			privileged = false
			break
		}
	}

	var cpuShares, limitInBytes uint64
	if bundle.Resources() != nil {
		if bundle.Resources().CPU != nil {
			cpuShares = *bundle.Resources().CPU.Shares
		}
		if cpuWeight, ok := bundle.Resources().Unified["cpu.weight"]; ok {
			cpuSharesInt, err := strconv.Atoi(cpuWeight)
			if err != nil {
				return spec.ActualContainerSpec{}, err
			}
			cpuShares = uint64(cpuSharesInt)
		}
		if bundle.Resources().Memory != nil {
			// #nosec G115 - limits should never be negative
			limitInBytes = uint64(*bundle.Resources().Memory.Limit)
		}
		if memoryMax, ok := bundle.Resources().Unified["memory.max"]; ok {
			limitInBytesInt, err := strconv.Atoi(memoryMax)
			if err != nil {
				return spec.ActualContainerSpec{}, err
			}
			limitInBytes = uint64(limitInBytesInt)
		}
	} else {
		log.Debug("bundle-resources-is-nil", lager.Data{"bundle": bundle})
	}

	return spec.ActualContainerSpec{
		Pid:        state.Pid,
		BundlePath: bundlePath,
		RootFSPath: bundle.RootFS(),
		Events:     c.events.Events(handle),
		Stopped:    c.states.IsStopped(handle),
		Limits: garden.Limits{
			CPU: garden.CPULimits{
				LimitInShares: cpuShares,
			},
			Memory: garden.MemoryLimits{
				LimitInBytes: limitInBytes,
			},
		},
		Privileged: privileged,
	}, nil
}

func (c *Containerizer) Metrics(log lager.Logger, handle string) (gardener.ActualContainerMetrics, error) {
	containerMetrics, err := c.runtime.Stats(log, handle)
	if err != nil {
		return gardener.ActualContainerMetrics{}, err
	}

	totalCPUUsage, err := c.cpuCgrouper.ReadTotalCgroupUsage(handle, containerMetrics.CPU)
	if err != nil {
		if os.IsNotExist(err) || strings.Contains(err.Error(), "no such file or directory") {
			totalCPUUsage = containerMetrics.CPU
		} else {
			return gardener.ActualContainerMetrics{}, err
		}
	}

	containerMetrics.CPU = garden.ContainerCPUStat{
		Usage:  totalCPUUsage.Usage,
		User:   totalCPUUsage.User,
		System: totalCPUUsage.System,
	}

	actualContainerMetrics := gardener.ActualContainerMetrics{
		StatsContainerMetrics: containerMetrics,
	}

	_, bundle, err := c.runtime.BundleInfo(log, handle)
	if isNotFound(err) { // pea
		return actualContainerMetrics, nil
	}
	if err != nil {
		return gardener.ActualContainerMetrics{}, err
	}

	actualContainerMetrics.CPUEntitlement = calculateCPUEntitlement(getShares(bundle), c.cpuEntitlementPerShare, containerMetrics.Age)

	if backend.IsVM(backend.FromBundle(bundle)) {
		c.applyGuestMemory(log, handle, &actualContainerMetrics)
	}

	return actualContainerMetrics, nil
}

// applyGuestMemory replaces the cgroup's memory figure with the guest's used
// memory, capped at the cgroup's limit when it has one, while the container has
// a fresh sample. Without one the cgroup figure stays. It logs when the answer
// moves between the two, and at no other time.
func (c *Containerizer) applyGuestMemory(log lager.Logger, handle string, metrics *gardener.ActualContainerMetrics) {
	sample, fresh := c.guestMemory.Fresh(handle)

	if previous, loaded := c.guestFigure.Swap(handle, fresh); fresh != (loaded && previous.(bool)) {
		if fresh {
			log.Info("vm-memory-from-guest", lager.Data{"handle": handle})
		} else {
			log.Info("vm-memory-from-cgroup", lager.Data{"handle": handle})
		}
	}

	if !fresh {
		return
	}

	used := sample.Used
	if limit := metrics.Memory.HierarchicalMemoryLimit; limit > 0 && used > limit {
		used = limit
	}

	metrics.Memory.TotalUsageTowardLimit = used
}

func (c *Containerizer) Shutdown() error {
	return c.runtimeStopper.Stop()
}

func isNotFound(err error) bool {
	_, ok := err.(garden.ContainerNotFoundError)
	return ok
}

func (c *Containerizer) Handles() ([]string, error) {
	return c.runtime.ContainerHandles()
}

func calculateCPUEntitlement(shares uint64, entitlementPerShare float64, containerAge time.Duration) uint64 {
	return uint64(float64(shares) * (entitlementPerShare / 100) * float64(containerAge.Nanoseconds()))
}

func getShares(bundle goci.Bndl) uint64 {
	resources := bundle.Resources()
	if resources == nil {
		return 0
	}
	cpu := resources.CPU
	if cpu == nil {
		if cpuWeight, ok := resources.Unified["cpu.weight"]; ok {
			cpuWeightUint, err := strconv.ParseUint(cpuWeight, 10, 64)
			if err != nil {
				return 0
			}
			return ConvertCgroupV2ValueToCPUShares(cpuWeightUint)
		}

		return 0
	}
	shares := cpu.Shares
	if shares == nil {
		return 0
	}
	return *shares
}
