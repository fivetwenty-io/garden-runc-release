package rundmc

import (
	"io"
	"sync"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/rundmc/event"
	"code.cloudfoundry.org/lager/v3"
)

// vmOOMLinePrefix begins the stderr line vm-launch writes when the guest
// kernel killed processes for lack of memory. cmd/vm-launch writes the line
// and pins the same text in its own specs.
const vmOOMLinePrefix = "vm-launch: the guest ran out of memory"

// oomLineScanner passes every byte through to next and remembers whether a
// line began with vmOOMLinePrefix. It keeps a match position and no data, so
// its memory does not grow with the length of a line.
type oomLineScanner struct {
	next io.Writer

	mu      sync.Mutex
	matched int // prefix bytes matched on this line, or -1 once the line cannot match
	seen    bool
}

func newOOMLineScanner(next io.Writer) *oomLineScanner {
	return &oomLineScanner{next: next}
}

func (s *oomLineScanner) Write(p []byte) (int, error) {
	s.scan(p)

	if s.next == nil {
		return len(p), nil
	}

	return s.next.Write(p)
}

func (s *oomLineScanner) scan(p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, b := range p {
		switch {
		case b == '\n':
			s.matched = 0
		case s.matched < 0 || s.matched >= len(vmOOMLinePrefix):
			// Mid-line, either past the prefix or already off it.
		case b == vmOOMLinePrefix[s.matched]:
			s.matched++
			if s.matched == len(vmOOMLinePrefix) {
				s.seen = true
			}
		default:
			s.matched = -1
		}
	}
}

// Seen reports whether any line so far began with the prefix.
func (s *oomLineScanner) Seen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.seen
}

// runVMLauncher runs the wrapped vm-launch process with a filter and a scanner
// on its stderr. The filter takes vm-launch's guest memory lines out of the
// stream and stores them for Metrics, and the scanner behind it sees the
// remaining bytes. The returned process records a guest OOM when it ends.
func (c *Containerizer) runVMLauncher(log lager.Logger, handle string, spec garden.ProcessSpec, pio garden.ProcessIO) (garden.Process, error) {
	scanner := newOOMLineScanner(pio.Stderr)

	// The process is the source of its samples, so it exists before the
	// filter that records them.
	launched := &vmLaunchProcess{log: log, handle: handle, scanner: scanner, events: c.events, memory: &c.guestMemory}
	launched.filter = newVMMetricsFilter(scanner,
		func(sample vmMemorySample) { c.guestMemory.Record(handle, launched, sample) },
		func(dropped int) {
			if dropped == 1 {
				log.Info("vm-metrics-line-dropped", lager.Data{"handle": handle})
			}
		},
	)
	pio.Stderr = launched.filter

	process, err := c.runtime.Exec(log, handle, spec, pio)
	if err != nil || process == nil {
		c.guestMemory.Forget(handle, launched)
		return process, err
	}

	launched.Process = process

	return launched, nil
}

// vmLaunchProcess is the wrapped vm-launch process. Once the process has
// ended, Wait releases what the filter still holds, removes the container's
// guest memory sample if this process wrote it, and records a guest OOM in the
// container's events if the scanner saw the report, so it is in the event
// store before the exit status travels back to the caller.
type vmLaunchProcess struct {
	garden.Process

	log     lager.Logger
	handle  string
	filter  *vmMetricsFilter
	scanner interface{ Seen() bool }
	events  EventStore
	memory  *vmGuestMemory

	once sync.Once
}

func (p *vmLaunchProcess) Wait() (int, error) {
	status, err := p.Process.Wait()

	if flushErr := p.filter.Flush(); flushErr != nil {
		p.log.Error("flush-vm-launch-stderr-failed", flushErr)
	}
	p.memory.Forget(p.handle, p)

	if p.scanner.Seen() {
		p.once.Do(func() {
			if recordErr := p.events.OnEvent(p.handle, event.NewOOMEvent(p.handle).Message); recordErr != nil {
				p.log.Error("record-guest-oom-failed", recordErr)
			}
		})
	}

	return status, err
}
