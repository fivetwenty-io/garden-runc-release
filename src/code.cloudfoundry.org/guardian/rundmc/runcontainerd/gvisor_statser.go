package runcontainerd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/lager/v3"
)

const (
	// gvisorCPUCacheFor is how long a Sentry reading answers later requests
	// for the same container, so that callers who ask together share one
	// runsc call.
	gvisorCPUCacheFor = 5 * time.Second

	// gvisorCPUForgetAfter is how long a container may go unread before the
	// statser forgets its figure.
	gvisorCPUForgetAfter = time.Hour

	// gvisorCPUBackoff is how long a container whose runsc call failed goes
	// without another call, so that a wedged sandbox costs one timeout in that
	// time and not one on every request.
	gvisorCPUBackoff = 30 * time.Second

	// runscEventsTimeout bounds one runsc call. A healthy call takes tens of
	// milliseconds.
	runscEventsTimeout = 2 * time.Second

	// runscProbeTimeout bounds the start-up check of the runsc binary.
	runscProbeTimeout = 10 * time.Second

	// runscStderrLimit is how much of runsc's stderr goes into an error, so
	// that an old runsc's usage text does not fill the log.
	runscStderrLimit = 200
)

// RunscEvents prints the Sentry's usage of a gVisor container.
type RunscEvents interface {
	// SentryUsage returns the output of "runsc events --stats --sentry-usage"
	// for the container.
	SentryUsage(log lager.Logger, id string) ([]byte, error)
}

// ExecRunscEvents runs the runsc binary that the cell's gVisor runtime uses.
type ExecRunscEvents struct {
	Bin  string
	Root string
}

func (e ExecRunscEvents) SentryUsage(log lager.Logger, id string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runscEventsTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, e.Bin, "--root", e.Root, "events", "--stats", "--sentry-usage", id)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// A grandchild that holds the pipes open must not block Run after the kill.
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > runscStderrLimit {
			msg = msg[:runscStderrLimit] + "..."
		}
		return nil, fmt.Errorf("runsc events: %w: %s", err, msg)
	}

	return stdout.Bytes(), nil
}

// Probe checks that the runsc binary exists and that its events command
// accepts --sentry-usage. Garden runs it once at start-up, and leaves the
// Sentry figure off for the life of the process when it fails, so that no
// container ever switches between the Sentry's figure and the cgroup's.
func (e ExecRunscEvents) Probe() error {
	info, err := os.Stat(e.Bin)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not an executable file", e.Bin)
	}

	ctx, cancel := context.WithTimeout(context.Background(), runscProbeTimeout)
	defer cancel()

	// The help text goes to stderr and the exit status varies between
	// versions, so the output is what counts.
	out, _ := exec.CommandContext(ctx, e.Bin, "events", "--help").CombinedOutput()
	if !bytes.Contains(out, []byte("sentry-usage")) {
		return fmt.Errorf("%s events does not accept --sentry-usage", e.Bin)
	}

	return nil
}

// GVisorStatser reports a gVisor container's memory, pids, and age as its base
// statser does, and its CPU as the Sentry's own accounting of the container's
// threads, which leaves out the Sentry, the gofer, and the netstack. The base
// statser's CPU is the whole sandbox's cgroup. Once a container has had a
// Sentry reading, a runsc failure reports the held figure and never the
// cgroup's, so the figure never falls. A container that has never had a Sentry
// reading keeps the base statser's figure, unmarked, so that the cgroup reading
// follows as it does without this statser.
type GVisorStatser struct {
	base   Statser
	runsc  RunscEvents
	clock  func() time.Time
	mu     sync.Mutex
	states map[string]*gvisorCPUState
}

// gvisorCPUState is what the statser remembers of one container.
type gvisorCPUState struct {
	mu sync.Mutex

	sample   uint64
	sampleAt time.Time
	sampled  bool
	reported uint64
	failing  bool

	// lastReported is the base figure reported before the first Sentry
	// reading, which the Sentry figure must not fall below.
	lastReported uint64

	// failedAt and failErr are the last runsc failure, which answers calls
	// until the backoff ends.
	failedAt time.Time
	failErr  error

	// age is the container's age at the last read. A smaller age means that
	// the handle belongs to a new container.
	age time.Duration

	// seenAt is the time of the last read of the container. The statser's own
	// lock guards it, so that a slow runsc call never holds up the sweep.
	seenAt time.Time
}

func NewGVisorStatser(base Statser, runsc RunscEvents) *GVisorStatser {
	return &GVisorStatser{base: base, runsc: runsc, clock: time.Now, states: map[string]*gvisorCPUState{}}
}

func (s *GVisorStatser) Stats(log lager.Logger, id string) (gardener.StatsContainerMetrics, error) {
	metrics, err := s.base.Stats(log, id)
	if err != nil {
		return gardener.StatsContainerMetrics{}, err
	}

	state := s.state(id)
	state.mu.Lock()
	defer state.mu.Unlock()

	// A handle that a new container reuses starts from zero.
	if metrics.Age < state.age {
		state.sample, state.sampleAt, state.sampled = 0, time.Time{}, false
		state.reported, state.lastReported, state.failing = 0, 0, false
		state.failedAt, state.failErr = time.Time{}, nil
	}
	state.age = metrics.Age

	usage, err := s.read(log, state, id)
	if failing := err != nil; failing != state.failing {
		state.failing = failing
		if failing {
			log.Info("gvisor-cpu-from-cgroup", lager.Data{"id": id, "error": err.Error()})
		} else {
			log.Info("gvisor-cpu-from-sentry", lager.Data{"id": id})
		}
	}
	if err != nil {
		if !state.sampled {
			state.lastReported = max(state.lastReported, metrics.CPU.Usage)
			return metrics, nil
		}
		metrics.CPU = garden.ContainerCPUStat{Usage: state.reported}
		metrics.CPUFinal = true

		return metrics, nil
	}

	// The figure falls when a short-lived exec exits, because the Sentry drops
	// the CPU of a process that has no parent, and a falling figure would read
	// as a negative rate, so the reported figure waits for the count to catch up.
	// The counter never falls, so after a step from the cgroup figure it holds
	// flat until the Sentry figure catches up.
	state.reported = max(state.reported, state.lastReported, usage)

	metrics.CPU = garden.ContainerCPUStat{Usage: state.reported}
	metrics.CPUFinal = true

	return metrics, nil
}

// state returns the container's state, and forgets the states of containers
// that nobody has read for a long time.
func (s *GVisorStatser) state(id string) *gvisorCPUState {
	now := s.clock()

	s.mu.Lock()
	defer s.mu.Unlock()

	for other, state := range s.states {
		if other != id && now.Sub(state.seenAt) > gvisorCPUForgetAfter {
			delete(s.states, other)
		}
	}

	state, ok := s.states[id]
	if !ok {
		state = &gvisorCPUState{}
		s.states[id] = state
	}
	state.seenAt = now

	return state
}

// read returns the Sentry's usage of the container, from the last reading when
// it is recent. The caller holds the state's lock.
func (s *GVisorStatser) read(log lager.Logger, state *gvisorCPUState, id string) (uint64, error) {
	now := s.clock()
	if state.sampled && now.Sub(state.sampleAt) < gvisorCPUCacheFor {
		return state.sample, nil
	}

	if state.failErr != nil && now.Sub(state.failedAt) < gvisorCPUBackoff {
		return 0, state.failErr
	}

	usage, err := s.run(log, id)
	if err != nil {
		state.failedAt, state.failErr = now, err
		return 0, err
	}

	state.sample, state.sampleAt, state.sampled = usage, now, true
	state.failErr = nil

	return usage, nil
}

func (s *GVisorStatser) run(log lager.Logger, id string) (uint64, error) {
	out, err := s.runsc.SentryUsage(log.Session("gvisor-statser", lager.Data{"id": id}), id)
	if err != nil {
		return 0, err
	}

	return parseSentryUsage(out, id)
}

// parseSentryUsage returns the container's figure, in nanoseconds, from the
// output of "runsc events --stats --sentry-usage".
func parseSentryUsage(out []byte, id string) (uint64, error) {
	var result struct {
		ContainerUsage map[string]uint64 `json:"containerUsage"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return 0, fmt.Errorf("runsc events output: %w", err)
	}

	usage, ok := result.ContainerUsage[id]
	if !ok {
		return 0, errors.New("runsc events output has no usage for the container")
	}

	return usage, nil
}
