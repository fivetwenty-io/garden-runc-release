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

// runVMLauncher runs the wrapped vm-launch process with a scanner on its
// stderr, and returns a process that records a guest OOM when it ends.
func (c *Containerizer) runVMLauncher(log lager.Logger, handle string, spec garden.ProcessSpec, pio garden.ProcessIO) (garden.Process, error) {
	scanner := newOOMLineScanner(pio.Stderr)
	pio.Stderr = scanner

	process, err := c.runtime.Exec(log, handle, spec, pio)
	if err != nil || process == nil {
		return process, err
	}

	return &vmLaunchProcess{Process: process, log: log, handle: handle, scanner: scanner, events: c.events}, nil
}

// vmLaunchProcess is the wrapped vm-launch process. Once the process has
// ended, Wait records a guest OOM in the container's events if the scanner saw
// the report, so it is in the event store before the exit status travels back
// to the caller.
type vmLaunchProcess struct {
	garden.Process

	log     lager.Logger
	handle  string
	scanner interface{ Seen() bool }
	events  EventStore

	once sync.Once
}

func (p *vmLaunchProcess) Wait() (int, error) {
	status, err := p.Process.Wait()

	if p.scanner.Seen() {
		p.once.Do(func() {
			if recordErr := p.events.OnEvent(p.handle, event.NewOOMEvent(p.handle).Message); recordErr != nil {
				p.log.Error("record-guest-oom-failed", recordErr)
			}
		})
	}

	return status, err
}
