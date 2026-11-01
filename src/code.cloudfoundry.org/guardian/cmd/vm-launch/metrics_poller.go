//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

const (
	// metricsPollInterval is how often the poller reads the guest's newest
	// sample. The guest refreshes it every five seconds, and Garden takes a
	// sample as fresh for 35 seconds, which is three and a half intervals.
	metricsPollInterval = 10 * time.Second

	// metricsReadTimeout bounds one read, and one try to prepare the
	// source, so a source that stops answering cannot hold the poller past
	// the next tick. stop does not wait for it, because it ends the read's
	// context, and both sources give up at once when it ends.
	metricsReadTimeout = 5 * time.Second

	// metricsBreakSettle is how long the poller waits, once its source has
	// broken for good, before it logs that. A source breaks as the
	// hypervisor exits, and vm-launch stops the poller soon after, so a
	// hypervisor that simply ended gets no line about the metrics, and
	// vm-launch's own exit line says what happened.
	metricsBreakSettle = 2 * time.Second

	// metricsReadFailuresBeforeLog is how many reads in a row must fail
	// before the poller logs it. The guest answers nothing for the first
	// seconds of its boot, and a read that times out once is not news.
	metricsReadFailuresBeforeLog = 3
)

// brokenSource is implemented by an error from a guestStatsSource that will
// never succeed again, such as a monitor or an API connection that closed.
// The poller stops on such an error and does not read again.
type brokenSource interface {
	Fatal() bool
}

// isBrokenSource reports whether err means that the source has failed for
// good, as opposed to failing for this one read.
func isBrokenSource(err error) bool {
	var broken brokenSource
	if errors.As(err, &broken) && broken.Fatal() {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed)
}

// isPendingSample reports whether err means only that the guest has not
// reported its statistics yet, which is no failure at all.
func isPendingSample(err error) bool {
	return errors.Is(err, errFirecrackerStatsPending)
}

// metricsPoller reads the guest's memory from its source every interval and
// writes one line for each good sample to out, which is vm-launch's stderr.
// A sample that fails its checks is dropped, and so is a read that fails. The
// poller logs once when a run of such failures begins and once when it ends,
// so a guest that misbehaves for an hour writes two lines and not hundreds.
// A reply that the guest has not filled in yet is skipped and is not a
// failure.
type metricsPoller struct {
	source     guestStatsSource
	guestBytes uint64
	out        io.Writer
	logger     *log.Logger
	interval   time.Duration
	// breakSettle is metricsBreakSettle. Specs shorten it.
	breakSettle time.Duration

	// prepare, when set before start, readies the source before its first
	// read: it turns on QEMU's statistics, or connects to Firecracker's API.
	// The poller runs it at once when it starts, and again at each tick
	// until it succeeds. An error that is fatal stops the poller, as a read's
	// does, and any other counts as a failed read.
	prepare func(ctx context.Context) error

	// newTicker returns the channel of ticks and the function that releases
	// it. Specs replace it with ticks they send themselves.
	newTicker func(time.Duration) (<-chan time.Time, func())

	// failures counts the failed reads and dropped samples in the current
	// run, and logged records that the run's start has been logged.
	failures int
	logged   bool

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// newMetricsPoller returns a poller for a guest of guestBytes of memory. It
// writes the metrics lines to out and its own messages to logger.
func newMetricsPoller(source guestStatsSource, guestBytes uint64, out io.Writer, logger *log.Logger) *metricsPoller {
	return &metricsPoller{
		source: source, guestBytes: guestBytes, out: out, logger: logger,
		interval: metricsPollInterval, breakSettle: metricsBreakSettle,
		newTicker: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
	}
}

// start begins polling in its own goroutine. A second call does nothing.
func (p *metricsPoller) start() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return
	}
	p.started = true
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})
	ticks, release := p.newTicker(p.interval)
	go func() {
		defer close(p.done)
		defer release()
		p.run(ctx, ticks)
	}()
}

// stop ends the polling and returns once the goroutine has ended, so nothing
// is written after stop returns. It does nothing when the poller never
// started, and it is safe to call more than once.
func (p *metricsPoller) stop() {
	p.mu.Lock()
	cancel, done := p.cancel, p.done
	p.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// run prepares the source, then polls on each tick until ctx ends or the
// source breaks. A source that could not be prepared is prepared again at
// the next tick, before that tick's read.
func (p *metricsPoller) run(ctx context.Context, ticks <-chan time.Time) {
	prepared := p.prepare == nil
	if !prepared {
		var goOn bool
		if prepared, goOn = p.prepareSource(ctx); !goOn {
			return
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			if !prepared {
				var goOn bool
				if prepared, goOn = p.prepareSource(ctx); !goOn {
					return
				}
				if !prepared {
					continue
				}
			}
			if !p.poll(ctx) {
				return
			}
		}
	}
}

// prepareSource runs prepare once. It reports whether the source is ready,
// and whether the poller should go on.
func (p *metricsPoller) prepareSource(ctx context.Context) (ready, goOn bool) {
	prepareCtx, cancel := context.WithTimeout(ctx, metricsReadTimeout)
	err := p.prepare(prepareCtx)
	cancel()
	if ctx.Err() != nil {
		return false, false
	}
	if err != nil {
		return false, p.failed(ctx, err)
	}
	return true, true
}

// poll does one read. It returns false when the poller should stop.
func (p *metricsPoller) poll(ctx context.Context) bool {
	readCtx, cancel := context.WithTimeout(ctx, metricsReadTimeout)
	sample, err := p.source.Read(readCtx)
	cancel()
	if ctx.Err() != nil {
		return false
	}
	if isPendingSample(err) {
		return true
	}
	if err != nil {
		return p.failed(ctx, err)
	}
	if err := sample.check(p.guestBytes); err != nil {
		p.failures++
		if !p.logged {
			p.logged = true
			p.logger.Printf("dropping guest memory statistics that cannot be right: %v", err)
		}
		return true
	}
	if p.logged {
		p.logger.Printf("the guest memory statistics are good again, after %d failed reads", p.failures)
	}
	p.failures, p.logged = 0, false
	// A failed write goes to the same stream the logger uses, so there is
	// nowhere better to report it, and the next sample tries again.
	_, _ = io.WriteString(p.out, sample.line())
	return true
}

// failed counts err, the failure of a read or of prepare, in the current
// run, and logs when the run is long enough. It returns false when err means
// the source is broken for good, after one log line unless ctx ends within
// breakSettle.
func (p *metricsPoller) failed(ctx context.Context, err error) bool {
	if isBrokenSource(err) {
		select {
		case <-ctx.Done():
		case <-time.After(p.breakSettle):
			p.logger.Printf("stopping the guest memory metrics, as the hypervisor can no longer be read: %v", err)
		}
		return false
	}
	p.failures++
	if p.failures == metricsReadFailuresBeforeLog {
		p.logged = true
		p.logger.Printf("the guest memory statistics are unavailable, and the last %d reads failed; the latest error is: %v", p.failures, err)
	}
	return true
}
