//go:build !windows

package nerd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/metrics"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/runcontainerd"
	"code.cloudfoundry.org/lager/v3"
	apievents "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/services/tasks/v1"
	v2types "github.com/containerd/containerd/api/types/runc/options"
	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	"github.com/containerd/containerd/v2/client"
	ctrdevents "github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/errdefs"
	"github.com/containerd/errdefs/pkg/errgrpc"
	"github.com/containerd/typeurl/v2"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type Nerd struct {
	client    *client.Client
	context   context.Context
	ioFifoDir string
	mp        *metrics.MetricsProvider

	runtimeConfigPath string
}

// Option configures a Nerd.
type Option func(*Nerd)

// WithRuntimeConfigPath sets the runtime options file that containerd passes
// to the runsc shim for gVisor containers. An empty path sends no runtime
// options, which is the default.
func WithRuntimeConfigPath(path string) Option {
	return func(n *Nerd) {
		n.runtimeConfigPath = path
	}
}

func New(client *client.Client, context context.Context, ioFifoDir string, mp *metrics.MetricsProvider, opts ...Option) *Nerd {
	n := &Nerd{
		client:    client,
		context:   context,
		ioFifoDir: ioFifoDir,
		mp:        mp,
	}
	for _, opt := range opts {
		opt(n)
	}
	return n
}

// RuntimeRunsc is the containerd runtime that runs a container under gVisor.
// containerd resolves it to the containerd-shim-runsc-v1 binary on its PATH.
const RuntimeRunsc = "io.containerd.runsc.v1"

// Create creates the container and its init task. For runc containers it also
// starts the task. For gVisor containers, selected by the execution backend
// annotation on the spec, the task is left in the Created state so that the
// network can be set up before the sandbox starts; Start starts it.
func (n *Nerd) Create(log lager.Logger, containerID string, spec *specs.Spec, hostUID, hostGID uint32, pio func() (io.Reader, io.Writer, io.Writer)) error {
	log.Debug("creating-container", lager.Data{"containerID": containerID})
	gvisor := backend.IsGvisor(backend.FromBundle(goci.Bndl{Spec: *spec}))
	containerOpts, taskOpts := createOpts(spec, gvisor, n.runtimeConfigPath, hostUID, hostGID)
	container, err := n.client.NewContainer(n.context, containerID, containerOpts...)
	if err != nil {
		return err
	}

	for key, value := range spec.Annotations {
		log.Debug("setting-label", lager.Data{"containerID": containerID, "label-key": key, "label-value": value})
		if _, err := container.SetLabels(n.context, map[string]string{key: value}); err != nil {
			return err
		}
	}

	log.Debug("creating-task", lager.Data{"containerID": containerID})
	task, err := container.NewTask(n.context, cio.NewCreator(withProcessIO(noTTYProcessIO(pio), n.ioFifoDir)), taskOpts...)
	if err != nil {
		return err
	}

	if gvisor {
		log.Debug("deferring-task-start", lager.Data{"containerID": containerID, "runtime": RuntimeRunsc})
		return nil
	}

	log.Debug("starting-task", lager.Data{"containerID": containerID})
	err = task.Start(n.context)
	if err != nil {
		return err
	}

	return task.CloseIO(n.context, client.WithStdinCloser)
}

// createOpts returns the container and task options for Create. runc
// containers get the default runtime with the runc task options. gVisor
// containers get the runsc runtime and no runc task options, because runsc
// manages its own keyring and IO ownership, and their spec loses the Windows
// section, which runsc rejects. When runtimeConfigPath is set, the runsc
// runtime gets it as the ConfigPath of its runtime options, which the stock
// shim needs to find its runsc binary and flags; otherwise it gets none.
func createOpts(spec *specs.Spec, gvisor bool, runtimeConfigPath string, hostUID, hostGID uint32) ([]client.NewContainerOpts, []client.NewTaskOpts) {
	if !gvisor {
		return []client.NewContainerOpts{client.WithSpec(spec)},
			[]client.NewTaskOpts{client.WithNoNewKeyring, WithUIDAndGID(hostUID, hostGID)}
	}

	spec.Windows = nil
	var runtimeOptions any
	if runtimeConfigPath != "" {
		runtimeOptions = &runtimeoptions.Options{ConfigPath: runtimeConfigPath}
	}
	return []client.NewContainerOpts{client.WithSpec(spec), client.WithRuntime(RuntimeRunsc, runtimeOptions)}, nil
}

// Start starts an init task that Create left in the Created state and then
// closes its stdin, as Create does for tasks it starts itself.
func (n *Nerd) Start(log lager.Logger, containerID string) error {
	_, task, err := n.loadContainerAndTask(log, containerID)
	if err != nil {
		return err
	}

	log.Debug("starting-task", lager.Data{"containerID": containerID})
	if err := task.Start(n.context); err != nil {
		return err
	}

	return task.CloseIO(n.context, client.WithStdinCloser)
}

func withProcessKillLogging(log lager.Logger, mp *metrics.MetricsProvider) func(context.Context, client.Process) error {
	return func(ctx context.Context, p client.Process) error {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		// ignore errors to wait and kill as we are forcefully killing
		// the process and don't care about the exit status
		log.Debug("with-process-kill.wait", lager.Data{"containerdProcess": p.ID(), "processID": p.Pid()})
		s, err := p.Wait(ctx)
		if err != nil {
			return err
		}
		log.Debug("with-process-kill.kill", lager.Data{"containerdProcess": p.ID(), "processID": p.Pid()})
		if err := p.Kill(ctx, syscall.SIGKILL); err != nil {
			if errdefs.IsFailedPrecondition(err) || errdefs.IsNotFound(err) {
				return nil
			}
			return err
		}
		log.Debug("with-process-kill.kill-complete", lager.Data{"containerdProcess": p.ID(), "processID": p.Pid()})
		// wait for the process to fully stop before letting the rest of the deletion complete
		select {
		case <-s:
			mp.RegisterKillableContainer(p.ID())
			break
		case <-time.After(time.Minute * 2):
			mp.RegisterUnkillableContainer(p.ID())
			return fmt.Errorf("Container still exists 2 minutes after kill -9. This container is unkillable and a VM reboot is required: containerdProcess=%s, processID=%d", p.ID(), p.Pid())
		}

		log.Debug("with-process-kill.wait-complete", lager.Data{"containerdProcess": p.ID(), "processID": p.Pid()})
		return nil
	}
}

func (n *Nerd) Delete(log lager.Logger, containerID string) error {
	container, task, err := n.loadContainerAndTask(log, containerID)
	if err != nil {
		switch err.(type) {
		case runcontainerd.ContainerNotFoundError:
			log.Debug("container-already-deleted", lager.Data{"containerID": containerID})
			return nil
		case runcontainerd.TaskNotFoundError:
			log.Debug("task-already-deleted", lager.Data{"containerID": containerID})
			return nil
		}
		return err
	}

	// The metadata was fetched by loadContainerAndTask, so this makes no call
	// to containerd.
	info, err := container.Info(n.context, client.WithoutRefreshedMetadata)
	if err != nil {
		return err
	}

	direct, err := needsDirectDelete(n.context, info.Runtime.Name, task)
	if err != nil {
		return fmt.Errorf("getting status of task %s: %w", containerID, err)
	}
	if direct {
		log.Info("deleting-created-task", lager.Data{"containerID": containerID, "runtime": info.Runtime.Name})
		return n.deleteCreatedTask(log, task)
	}

	log.Debug("deleting-task", lager.Data{"containerID": containerID})
	_, err = task.Delete(n.context, withProcessKillLogging(log, n.mp))
	return err
}

// needsDirectDelete reports whether a task cannot go through the client's
// kill-then-delete path. runsc refuses to signal a container that was created
// but never started, and the client refuses to delete a Created task with a
// non-zero pid, so a Created runsc task is deleted through the task service. A
// Created runc task is killable and keeps the usual path, and the task status
// is only fetched for runsc tasks.
func needsDirectDelete(ctx context.Context, runtime string, task client.Task) (bool, error) {
	if runtime != RuntimeRunsc {
		return false, nil
	}

	status, err := task.Status(ctx)
	if err != nil {
		return false, err
	}
	return status.Status == client.Created, nil
}

// deleteCreatedTask deletes a task through the task service, which makes the
// shim delete the never-started container. It releases the task's IO in the
// same order as the client's own Delete, and like it treats a failure to close
// the IO as non-fatal once the task is gone.
func (n *Nerd) deleteCreatedTask(log lager.Logger, task client.Task) error {
	taskIO := task.IO()
	if taskIO != nil {
		taskIO.Cancel()
		taskIO.Wait()
	}

	if _, err := n.client.TaskService().Delete(n.context, &tasks.DeleteTaskRequest{ContainerID: task.ID()}); err != nil {
		return errgrpc.ToNative(err)
	}

	if taskIO != nil {
		if err := taskIO.Close(); err != nil {
			log.Error("closing-created-task-io-failed", err, lager.Data{"containerID": task.ID()})
		}
	}
	return nil
}

func (n *Nerd) State(log lager.Logger, containerID string) (int, string, error) {
	log = log.Session("state", lager.Data{"containerID": containerID})

	_, task, err := n.loadContainerAndTask(log, containerID)
	if err != nil {
		return 0, "", err
	}

	log.Debug("getting-task-status")
	status, err := n.tryToGetStatus(log, task)
	if err != nil {
		return 0, "", err
	}

	log.Debug("task-result", lager.Data{"pid": strconv.Itoa(int(task.Pid())), "status": string(status.Status)})
	return int(task.Pid()), string(status.Status), nil
}

func (n *Nerd) tryToGetTask(log lager.Logger, container client.Container) (client.Task, error) {
	log = log.Session("try-to-get-task")

	const retries = 5
	for i := 0; i < retries; i++ {
		task, err := container.Task(n.context, cio.Load)
		if err != nil {
			if errdefs.IsNotFound(err) {
				return nil, runcontainerd.TaskNotFoundError{Handle: container.ID()}
			}
			if errors.Is(err, context.DeadlineExceeded) {
				log.Info("retrying-after-task-error", lager.Data{"retry-number": i + 1, "error": err.Error()})
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return nil, err
		}

		if task.Pid() != 0 {
			return task, nil
		}

		log.Info("retrying-after-pid-0-response", lager.Data{"retry-number": i + 1})
		time.Sleep(500 * time.Millisecond)
	}

	return nil, errors.New("failed getting task")
}

func (n *Nerd) tryToGetStatus(log lager.Logger, task client.Task) (client.Status, error) {
	log = log.Session("try-to-get-status", lager.Data{"taskID": task.ID()})

	const retries = 5
	for i := 0; i < retries; i++ {
		status, err := task.Status(n.context)
		if err != nil {
			return client.Status{}, err
		}

		if status.Status != client.Unknown {
			return status, nil
		}

		log.Info("retrying-after-status-unknown-response", lager.Data{"retry-number": i + 1})
		time.Sleep(500 * time.Millisecond)
	}

	return client.Status{}, errors.New("failed getting task status")
}

func (n *Nerd) Exec(log lager.Logger, containerID, processID string, spec *specs.Process, processIO func() (io.Reader, io.Writer, io.Writer, bool)) (runcontainerd.BackingProcess, error) {
	_, task, err := n.loadContainerAndTask(log, containerID)
	if err != nil {
		return BackingProcess{}, err
	}

	log.Debug("execing-task", lager.Data{"containerID": containerID, "processID": processID})
	process, err := task.Exec(n.context, processID, spec, cio.NewCreator(withProcessIO(processIO, n.ioFifoDir)))
	if err != nil {
		return BackingProcess{}, err
	}

	log.Debug("starting-task", lager.Data{"containerID": containerID, "processID": processID})
	if err := process.Start(n.context); err != nil {
		return BackingProcess{}, err
	}

	log.Debug("closing-stdin", lager.Data{"containerID": containerID, "processID": processID})
	go exponentialBackoffCloseIO(process, n.context, log, containerID)

	return NewBackingProcess(log, process, n.context), nil
}

func (n *Nerd) GetProcess(log lager.Logger, containerID, processID string) (runcontainerd.BackingProcess, error) {
	log.Debug("get-process", lager.Data{"containerID": containerID, "processID": processID})
	_, task, err := n.loadContainerAndTask(log, containerID)
	if err != nil {
		return BackingProcess{}, err
	}

	process, err := task.LoadProcess(n.context, processID, cio.Load)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return BackingProcess{}, runcontainerd.ProcessNotFoundError{Handle: containerID, ID: processID}
		}
		return BackingProcess{}, err
	}

	return NewBackingProcess(log, process, n.context), nil
}

func (n *Nerd) GetTask(log lager.Logger, id string) (runcontainerd.BackingProcess, error) {
	log.Debug("get-task", lager.Data{"id": id})
	_, task, err := n.loadContainerAndTask(log, id)
	if err != nil {
		return BackingProcess{}, err
	}

	return NewBackingProcess(log, task, n.context), nil
}

func exponentialBackoffCloseIO(process client.Process, ctx context.Context, log lager.Logger, containerID string) {
	duration := 3 * time.Second
	retries := 10
	for i := 0; i < retries; i++ {
		if err := process.CloseIO(ctx, client.WithStdinCloser); err != nil {
			log.Error("failed-closing-stdin", err, lager.Data{"containerID": containerID, "processID": process.ID()})
			time.Sleep(duration)
			duration *= 2
			continue
		}
		break
	}
}

func noTTYProcessIO(initProcessIO func() (io.Reader, io.Writer, io.Writer)) func() (io.Reader, io.Writer, io.Writer, bool) {
	return func() (io.Reader, io.Writer, io.Writer, bool) {
		stdin, stdout, stderr := initProcessIO()
		return stdin, stdout, stderr, false
	}
}

func withProcessIO(processIO func() (io.Reader, io.Writer, io.Writer, bool), ioFifoDir string) cio.Opt {
	return func(opt *cio.Streams) {
		stdin, stdout, stderr, hasTTY := processIO()

		cio.WithFIFODir(ioFifoDir)(opt)
		if hasTTY {
			cio.WithTerminal(opt)
			cio.WithStreams(orEmpty(stdin), orDiscard(stdout), nil)(opt)
		} else {
			cio.WithStreams(orEmpty(stdin), orDiscard(stdout), orDiscard(stderr))(opt)
		}
	}
}

func orEmpty(r io.Reader) io.Reader {
	if r != nil {
		return r
	}
	return bytes.NewBuffer(nil)
}

func orDiscard(w io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return io.Discard
}

func (n *Nerd) GetContainerPID(log lager.Logger, containerID string) (uint32, error) {
	_, task, err := n.loadContainerAndTask(log, containerID)
	if err != nil {
		return 0, err
	}

	return task.Pid(), nil
}

// KillAll sends signal to every process in the container's task, not only to
// its init process, and returns without waiting for them to exit. A task whose
// processes have all exited already is not an error. A missing container is.
func (n *Nerd) KillAll(log lager.Logger, containerID string, signal syscall.Signal) error {
	_, task, err := n.loadContainerAndTask(log, containerID)
	if err != nil {
		return err
	}

	log.Debug("killing-all-task-processes", lager.Data{"containerID": containerID, "signal": signal.String()})
	if err := task.Kill(n.context, signal, client.WithKillAll); err != nil {
		if taskAlreadyExited(err) {
			log.Debug("task-processes-already-exited", lager.Data{"containerID": containerID})
			return nil
		}
		return fmt.Errorf("killing all processes of task %s: %w", containerID, err)
	}

	return nil
}

// taskAlreadyExited reports whether a kill error means that no process was
// left to signal. Both the runc and the runsc shims report that as NotFound.
// The message check covers an error that reaches us without its NotFound code.
func taskAlreadyExited(err error) bool {
	return errdefs.IsNotFound(err) || strings.Contains(err.Error(), "process already finished")
}

// TaskMetrics returns the metrics the shim reports for the container's task,
// still encoded, together with the time containerd created the container.
func (n *Nerd) TaskMetrics(log lager.Logger, containerID string) (typeurl.Any, time.Time, error) {
	container, task, err := n.loadContainerAndTask(log, containerID)
	if err != nil {
		return nil, time.Time{}, err
	}

	log.Debug("getting-task-metrics", lager.Data{"containerID": containerID})
	metric, err := task.Metrics(n.context)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("getting metrics of task %s: %w", containerID, err)
	}
	if metric.Data == nil {
		return nil, time.Time{}, fmt.Errorf("task %s reported no metrics data", containerID)
	}

	info, err := container.Info(n.context, client.WithoutRefreshedMetadata)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("getting info of container %s: %w", containerID, err)
	}

	return metric.Data, info.CreatedAt, nil
}

func (n *Nerd) loadContainer(log lager.Logger, containerID string) (client.Container, error) {
	log.Debug("loading-container", lager.Data{"containerID": containerID})
	container, err := n.client.LoadContainer(n.context, containerID)
	if err != nil {
		if errdefs.IsNotFound(err) {
			log.Debug("container-not-found", lager.Data{"containerID": containerID})
			return nil, runcontainerd.ContainerNotFoundError{Handle: containerID}
		}
		log.Debug("loading-container-failed", lager.Data{"containerID": containerID})
		return nil, err
	}
	return container, nil
}

func (n *Nerd) loadContainers(labels ...runcontainerd.ContainerFilter) ([]client.Container, error) {
	var flattenedLabels []string
	for _, label := range labels {
		flattenedLabels = append(flattenedLabels, fmt.Sprintf("labels.\"%s\"%s%s", label.Label, label.ComparisonOp, label.Value))
	}

	return n.client.Containers(n.context, strings.Join(flattenedLabels, ","))
}

func (n *Nerd) loadContainerAndTask(log lager.Logger, containerID string) (client.Container, client.Task, error) {
	container, err := n.loadContainer(log, containerID)
	if err != nil {
		return nil, nil, err
	}

	log.Debug("loading-task", lager.Data{"containerID": containerID})
	task, err := n.tryToGetTask(log, container)
	if err != nil {
		log.Debug("loading-task-failed", lager.Data{"containerID": containerID})
		return nil, nil, err
	}

	return container, task, nil
}

func (n *Nerd) OOMEvents(log lager.Logger) <-chan *apievents.TaskOOM {
	events, errs := n.client.Subscribe(n.context, `topic=="/tasks/oom"`)
	oomEvents := make(chan *apievents.TaskOOM)

	go func() {
		for {
			select {
			case err, ok := <-errs:
				if !ok {
					log.Info("event service has been closed")
				}

				if err != nil {
					log.Error("event service received an error", err)
				}

				close(oomEvents)
				return

			case e := <-events:
				event, err := coerceEvent(e)
				if err != nil {
					log.Error("failed to coerce containerd event", err, lager.Data{"event": e})
					continue
				}

				log.Debug("received an OOM event", lager.Data{"containerID": event.ContainerID})
				oomEvents <- event
			}
		}
	}()

	return oomEvents
}

func (n *Nerd) Spec(log lager.Logger, containerID string) (*specs.Spec, error) {
	container, _, err := n.loadContainerAndTask(log, containerID)
	if err != nil {
		return nil, err
	}

	log.Debug("getting-container-spec", lager.Data{"containerID": containerID})
	return container.Spec(n.context)
}

func coerceEvent(event *ctrdevents.Envelope) (*apievents.TaskOOM, error) {
	if event.Event == nil {
		return nil, errors.New("empty event")
	}

	unmarshalledEvent, err := typeurl.UnmarshalAny(event.Event)
	if err != nil {
		return nil, err
	}

	oom, ok := unmarshalledEvent.(*apievents.TaskOOM)
	if !ok {
		return nil, errors.New("unexpected event")
	}

	return oom, nil
}

func (n *Nerd) BundleIDs(labels ...runcontainerd.ContainerFilter) ([]string, error) {
	containers, err := n.loadContainers(labels...)
	if err != nil {
		return nil, err
	}

	handles := []string{}
	for _, container := range containers {
		handles = append(handles, container.ID())
	}

	return handles, nil
}

func (n *Nerd) RemoveBundle(log lager.Logger, handle string) error {
	container, err := n.loadContainer(log, handle)
	if err == nil {
		log.Debug("deleting-container", lager.Data{"containerID": handle})
		return container.Delete(n.context)
	}

	if _, isNotFound := err.(runcontainerd.ContainerNotFoundError); isNotFound {
		log.Debug("container-already-deleted", lager.Data{"containerID": handle})
		return nil
	}

	log.Debug("loading-container-failed", lager.Data{"handle": handle})
	return err
}

func WithUIDAndGID(uid, gid uint32) client.NewTaskOpts {
	return func(ctx context.Context, c *client.Client, ti *client.TaskInfo) error {
		return updateTaskInfoCreateOptions(ti, func(opts *v2types.Options) error {
			opts.IoUid = uid
			opts.IoGid = gid
			return nil
		})
	}
}

func updateTaskInfoCreateOptions(taskInfo *client.TaskInfo, updateCreateOptions func(createOptions *v2types.Options) error) error {
	if taskInfo.Options == nil {
		taskInfo.Options = &v2types.Options{}
	}
	opts, ok := taskInfo.Options.(*v2types.Options)

	if !ok {
		return errors.New("could not cast TaskInfo Options to CreateOptions")
	}

	return updateCreateOptions(opts)
}
