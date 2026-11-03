//go:build !windows

package runcontainerd_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/guardian/rundmc/runcontainerd"
	"code.cloudfoundry.org/guardian/rundmc/runcontainerd/runcontainerdfakes"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/lager/v3/lagertest"
)

// runscOutput is what "runsc events --stats --sentry-usage" prints for a
// sandbox with an app and a sidecar. The event's total is the sandbox cgroup's
// figure, scaled by runsc, and containerUsage is the Sentry's own accounting.
const runscOutput = `{"event":{"type":"stats","id":"app","data":{"cpu":{"usage":{"total":912000000,"kernel":0,"user":0}},"memory":{},"pids":{"current":3}}},"containerUsage":{"app":41000000,"sidecar":7000000}}` + "\n"

// fakeRunscEvents implements runcontainerd.RunscEvents for tests, with one
// answer for each call.
type fakeRunscEvents struct {
	outputs []string
	err     error
	ids     []string
}

func (f *fakeRunscEvents) SentryUsage(_ lager.Logger, id string) ([]byte, error) {
	f.ids = append(f.ids, id)
	if f.err != nil {
		return nil, f.err
	}
	out := f.outputs[min(len(f.ids), len(f.outputs))-1]
	return []byte(out), nil
}

func usageOutput(app uint64) string {
	return `{"event":{"type":"stats","id":"app","data":{"cpu":{"usage":{"total":912000000}}}},"containerUsage":{"app":` + strconv.FormatUint(app, 10) + `}}` + "\n"
}

// cgroupMetrics is what the base statser reports: the whole sandbox's CPU,
// with the memory and pids that the statser leaves alone.
func cgroupMetrics() gardener.StatsContainerMetrics {
	return gardener.StatsContainerMetrics{
		CPU:    garden.ContainerCPUStat{Usage: 912000000, User: 600000000, System: 312000000},
		Memory: garden.ContainerMemoryStat{TotalUsageTowardLimit: 4096},
		Pid:    garden.ContainerPidStat{Current: 3, Max: 100},
		Age:    90 * time.Second,
	}
}

func newGVisorStatser(runsc *fakeRunscEvents) (*runcontainerd.GVisorStatser, *runcontainerdfakes.FakeStatser) {
	base := new(runcontainerdfakes.FakeStatser)
	base.StatsReturns(cgroupMetrics(), nil)
	return runcontainerd.NewGVisorStatser(base, runsc), base
}

func TestGVisorStatser_TakesTheContainersSentryFigure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runsc := &fakeRunscEvents{outputs: []string{runscOutput}}
		statser, base := newGVisorStatser(runsc)

		got, err := statser.Stats(lagertest.NewTestLogger("test"), "app")
		if err != nil {
			t.Fatalf("Stats: %v", err)
		}

		if got.CPU != (garden.ContainerCPUStat{Usage: 41000000}) {
			t.Errorf("CPU = %+v, want only Usage 41000000 ns, the app's and not the sidecar's or the sandbox's", got.CPU)
		}
		if !got.CPUFinal {
			t.Error("CPUFinal is false, so the cgroup would replace the figure")
		}
		want := cgroupMetrics()
		if got.Memory != want.Memory || got.Pid != want.Pid || got.Age != want.Age {
			t.Errorf("memory, pids, and age = %+v %+v %v, want the base statser's", got.Memory, got.Pid, got.Age)
		}
		if base.StatsCallCount() != 1 || len(runsc.ids) != 1 || runsc.ids[0] != "app" {
			t.Errorf("base calls = %d, runsc calls = %v", base.StatsCallCount(), runsc.ids)
		}
	})
}

func TestGVisorStatser_FallsBackToTheBaseFigure(t *testing.T) {
	for name, runsc := range map[string]*fakeRunscEvents{
		"a runsc error":     {err: errors.New("exit status 1")},
		"malformed output":  {outputs: []string{"{not json"}},
		"empty output":      {outputs: []string{""}},
		"no usage map":      {outputs: []string{`{"event":{"type":"stats"}}`}},
		"another container": {outputs: []string{`{"event":{},"containerUsage":{"other":5}}`}},
		"a negative figure": {outputs: []string{`{"event":{},"containerUsage":{"app":-5}}`}},
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				statser, _ := newGVisorStatser(runsc)

				got, err := statser.Stats(lagertest.NewTestLogger("test"), "app")
				if err != nil {
					t.Fatalf("Stats: %v", err)
				}
				if got != cgroupMetrics() {
					t.Errorf("metrics = %+v, want the base statser's, unmarked", got)
				}
			})
		})
	}
}

func TestGVisorStatser_ReturnsTheBaseError(t *testing.T) {
	runsc := &fakeRunscEvents{outputs: []string{runscOutput}}
	statser, base := newGVisorStatser(runsc)
	base.StatsReturns(gardener.StatsContainerMetrics{}, errors.New("no task"))

	if _, err := statser.Stats(lagertest.NewTestLogger("test"), "app"); err == nil || err.Error() != "no task" {
		t.Errorf("err = %v, want the base statser's", err)
	}
	if len(runsc.ids) != 0 {
		t.Errorf("runsc ran %d times for a container the base statser could not read", len(runsc.ids))
	}
}

func TestGVisorStatser_NeverFalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runsc := &fakeRunscEvents{outputs: []string{usageOutput(5000), usageOutput(2000), usageOutput(9000)}}
		statser, _ := newGVisorStatser(runsc)

		var seen []uint64
		for range 3 {
			got, err := statser.Stats(lagertest.NewTestLogger("test"), "app")
			if err != nil {
				t.Fatalf("Stats: %v", err)
			}
			seen = append(seen, got.CPU.Usage)
			time.Sleep(6 * time.Second)
		}

		if seen[0] != 5000 || seen[1] != 5000 || seen[2] != 9000 {
			t.Errorf("figures = %v, want 5000, 5000 (an exited exec's CPU left the count), 9000", seen)
		}
	})
}

func TestGVisorStatser_SharesOneRunscCallBetweenCallers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runsc := &fakeRunscEvents{outputs: []string{usageOutput(5000), usageOutput(8000)}}
		statser, _ := newGVisorStatser(runsc)

		first, _ := statser.Stats(lagertest.NewTestLogger("test"), "app")
		time.Sleep(2 * time.Second)
		second, _ := statser.Stats(lagertest.NewTestLogger("test"), "app")
		if len(runsc.ids) != 1 || first.CPU.Usage != 5000 || second.CPU.Usage != 5000 {
			t.Errorf("runsc calls = %d, figures = %d and %d, want one call and 5000 twice", len(runsc.ids), first.CPU.Usage, second.CPU.Usage)
		}

		time.Sleep(4 * time.Second)
		third, _ := statser.Stats(lagertest.NewTestLogger("test"), "app")
		if len(runsc.ids) != 2 || third.CPU.Usage != 8000 {
			t.Errorf("runsc calls = %d, figure = %d, want a second call and 8000", len(runsc.ids), third.CPU.Usage)
		}
	})
}

func stats(t *testing.T, statser *runcontainerd.GVisorStatser, id string) gardener.StatsContainerMetrics {
	t.Helper()
	got, err := statser.Stats(lagertest.NewTestLogger("test"), id)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	return got
}

// A container that has had a Sentry reading never reports the cgroup's figure
// again, so the series cannot fall or spike when runsc fails and recovers.
func TestGVisorStatser_HoldsTheSentryFigureWhenRunscFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runsc := &fakeRunscEvents{outputs: []string{usageOutput(5000), "", usageOutput(3000), usageOutput(9000)}}
		statser, _ := newGVisorStatser(runsc)

		var seen []uint64
		for range 4 {
			if len(runsc.ids) == 1 {
				runsc.err = errors.New("exit status 1")
			} else {
				runsc.err = nil
			}
			got := stats(t, statser, "app")
			if !got.CPUFinal {
				t.Errorf("figure %d is not marked final, so the cgroup would replace it", len(seen))
			}
			seen = append(seen, got.CPU.Usage)
			time.Sleep(gvisorBackoff + time.Second)
		}

		if want := []uint64{5000, 5000, 5000, 9000}; !slices.Equal(seen, want) {
			t.Errorf("figures = %v, want %v", seen, want)
		}
	})
}

// A container that has never had a Sentry reading reports the base figure.
func TestGVisorStatser_ReportsTheBaseFigureUntilTheFirstSentryReading(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runsc := &fakeRunscEvents{outputs: []string{usageOutput(5000)}, err: errors.New("exit status 1")}
		statser, _ := newGVisorStatser(runsc)

		failed := stats(t, statser, "app")
		if failed.CPUFinal || failed.CPU != cgroupMetrics().CPU {
			t.Errorf("failed = %+v, want the base figure, unmarked", failed.CPU)
		}

		runsc.err = nil
		time.Sleep(gvisorBackoff + time.Second)
		recovered := stats(t, statser, "app")
		if !recovered.CPUFinal || recovered.CPU.Usage != 5000 {
			t.Errorf("recovered = %+v, want the Sentry's 5000, marked", recovered.CPU)
		}
	})
}

// gvisorBackoff matches the statser's failure backoff.
const gvisorBackoff = 30 * time.Second

func TestGVisorStatser_BacksOffFromAFailingContainer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runsc := &fakeRunscEvents{err: errors.New("exit status 1")}
		statser, _ := newGVisorStatser(runsc)

		for range 5 {
			stats(t, statser, "stuck")
			time.Sleep(5 * time.Second)
		}
		if len(runsc.ids) != 1 {
			t.Errorf("runsc calls in 25 s = %d, want 1", len(runsc.ids))
		}

		// Another container is not held back by the first one's failure.
		runsc.err = nil
		runsc.outputs = []string{usageOutput(1), usageOutput(7)}
		if got := stats(t, statser, "app"); got.CPU.Usage != 7 {
			t.Errorf("other container figure = %d, want 7", got.CPU.Usage)
		}

		time.Sleep(10 * time.Second)
		stats(t, statser, "stuck")
		if len(runsc.ids) != 3 {
			t.Errorf("runsc calls after the backoff = %d, want 3", len(runsc.ids))
		}
	})
}

// lockedRunscEvents is a fakeRunscEvents that concurrent callers may share.
type lockedRunscEvents struct {
	mu    sync.Mutex
	calls map[string]int
}

func (l *lockedRunscEvents) SentryUsage(_ lager.Logger, id string) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls[id]++
	return []byte(`{"event":{},"containerUsage":{"a":10,"b":20,"c":30}}`), nil
}

func TestGVisorStatser_ServesConcurrentCallers(t *testing.T) {
	runsc := &lockedRunscEvents{calls: map[string]int{}}
	base := new(runcontainerdfakes.FakeStatser)
	base.StatsReturns(cgroupMetrics(), nil)
	statser := runcontainerd.NewGVisorStatser(base, runsc)

	var wg sync.WaitGroup
	for i := range 60 {
		id := []string{"a", "b", "c"}[i%3]
		want := uint64(10 * (i%3 + 1))
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := statser.Stats(lagertest.NewTestLogger("test"), id)
			if err != nil || got.CPU.Usage != want || !got.CPUFinal {
				t.Errorf("%s: figure = %+v, err = %v, want %d", id, got.CPU, err, want)
			}
		}()
	}
	wg.Wait()

	for id, n := range runsc.calls {
		if n != 1 {
			t.Errorf("runsc calls for %s = %d, want 1 shared call", id, n)
		}
	}
}

func TestGVisorStatser_ForgetsContainersNobodyReads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runsc := &fakeRunscEvents{outputs: []string{
			`{"event":{},"containerUsage":{"old":5000,"other":1}}`,
			`{"event":{},"containerUsage":{"old":5000,"other":1}}`,
			`{"event":{},"containerUsage":{"old":2000,"other":1}}`,
		}}
		statser, _ := newGVisorStatser(runsc)

		stats(t, statser, "old")
		time.Sleep(61 * time.Minute)
		stats(t, statser, "other") // sweeps "old"
		if got := stats(t, statser, "old"); got.CPU.Usage != 2000 {
			t.Errorf("figure after the sweep = %d, want 2000 (the held 5000 was forgotten)", got.CPU.Usage)
		}
	})
}

func TestGVisorStatser_StartsAReusedHandleFromZero(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runsc := &fakeRunscEvents{outputs: []string{usageOutput(5000), usageOutput(2000)}}
		statser, base := newGVisorStatser(runsc)

		stats(t, statser, "app")
		time.Sleep(6 * time.Second)

		// The handle's new container is younger than the old one was.
		young := cgroupMetrics()
		young.Age = 3 * time.Second
		base.StatsReturns(young, nil)
		if got := stats(t, statser, "app"); got.CPU.Usage != 2000 {
			t.Errorf("figure for the new container = %d, want 2000", got.CPU.Usage)
		}
	})
}

func TestExecRunscEvents(t *testing.T) {
	dir := t.TempDir()
	args := filepath.Join(dir, "args")
	runsc := filepath.Join(dir, "runsc")
	script := "#!/bin/sh\necho \"$@\" > " + args + "\ncat <<'EOF'\n" + runscOutput + "EOF\n"
	if err := os.WriteFile(runsc, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	out, err := runcontainerd.ExecRunscEvents{Bin: runsc, Root: "/state/garden"}.SentryUsage(lagertest.NewTestLogger("test"), "app")
	if err != nil {
		t.Fatalf("SentryUsage: %v", err)
	}
	if string(out) != runscOutput {
		t.Errorf("output = %q", out)
	}
	gotArgs, _ := os.ReadFile(args)
	if strings.TrimSpace(string(gotArgs)) != "--root /state/garden events --stats --sentry-usage app" {
		t.Errorf("arguments = %q", gotArgs)
	}
}

func TestExecRunscEvents_ReportsAFailure(t *testing.T) {
	dir := t.TempDir()
	runsc := filepath.Join(dir, "runsc")
	if err := os.WriteFile(runsc, []byte("#!/bin/sh\necho 'cannot load container' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := runcontainerd.ExecRunscEvents{Bin: runsc, Root: "/state/garden"}.SentryUsage(lagertest.NewTestLogger("test"), "app")
	if err == nil || !strings.Contains(err.Error(), "cannot load container") {
		t.Errorf("err = %v, want runsc's message", err)
	}

	if _, err := (runcontainerd.ExecRunscEvents{Bin: filepath.Join(dir, "missing"), Root: "/r"}).SentryUsage(lagertest.NewTestLogger("test"), "app"); err == nil {
		t.Error("no error for a missing binary")
	}
}

func TestExecRunscEvents_TimesOutAndReturns(t *testing.T) {
	dir := t.TempDir()
	runsc := filepath.Join(dir, "runsc")
	// The sleep is a child of the shell and holds stdout, as a wedged
	// grandchild would.
	if err := os.WriteFile(runsc, []byte("#!/bin/sh\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err := runcontainerd.ExecRunscEvents{Bin: runsc, Root: "/r"}.SentryUsage(lagertest.NewTestLogger("test"), "app")
	if err == nil {
		t.Fatal("no error for a runsc that never answers")
	}
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Errorf("the call took %v, want about 2 s", elapsed)
	}
}

func TestExecRunscEvents_TruncatesStderr(t *testing.T) {
	dir := t.TempDir()
	runsc := filepath.Join(dir, "runsc")
	script := "#!/bin/sh\nhead -c 5000 /dev/zero | tr '\\0' 'x' >&2\nexit 1\n"
	if err := os.WriteFile(runsc, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := runcontainerd.ExecRunscEvents{Bin: runsc, Root: "/r"}.SentryUsage(lagertest.NewTestLogger("test"), "app")
	if err == nil || len(err.Error()) > 400 {
		t.Errorf("error length = %d, want a short message", len(err.Error()))
	}
}

func TestExecRunscEvents_Probe(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}

	good := write("good", "#!/bin/sh\necho 'usage: events -sentry-usage' >&2\nexit 2\n", 0o755)
	old := write("old", "#!/bin/sh\necho 'usage: events -stats' >&2\nexit 2\n", 0o755)
	plain := write("plain", "#!/bin/sh\n", 0o644)

	if err := (runcontainerd.ExecRunscEvents{Bin: good}).Probe(); err != nil {
		t.Errorf("probe of a runsc with the flag = %v", err)
	}
	for name, bin := range map[string]string{"an old runsc": old, "a file that cannot run": plain, "a missing binary": filepath.Join(dir, "missing")} {
		if err := (runcontainerd.ExecRunscEvents{Bin: bin}).Probe(); err == nil {
			t.Errorf("probe of %s passed", name)
		}
	}
}
