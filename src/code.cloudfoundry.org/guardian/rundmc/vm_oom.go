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

// vmHypervisorDiedPrefix begins the stderr line vm-launch writes when the
// hypervisor ended and the guest had reported no status, which is how a
// hypervisor that the container's cgroup killed for memory ends. cmd/vm-launch
// writes the line and pins the same text in its own specs.
const vmHypervisorDiedPrefix = "vm-launch: the hypervisor ended without a guest status"

// oomLineScanner passes every byte through to next and remembers whether a
// line began with prefix. It keeps a match position and no data, so its memory
// does not grow with the length of a line.
type oomLineScanner struct {
	next   io.Writer
	prefix string

	mu      sync.Mutex
	matched int // prefix bytes matched on this line, or -1 once the line cannot match
	seen    bool
}

func newOOMLineScanner(next io.Writer) *oomLineScanner {
	return newLineScanner(next, vmOOMLinePrefix)
}

func newLineScanner(next io.Writer, prefix string) *oomLineScanner {
	return &oomLineScanner{next: next, prefix: prefix}
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
		case s.matched < 0 || s.matched >= len(s.prefix):
			// Mid-line, either past the prefix or already off it.
		case b == s.prefix[s.matched]:
			s.matched++
			if s.matched == len(s.prefix) {
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
// on its stderr, and a second scanner for the line that says the hypervisor
// died. The filter takes vm-launch's guest memory lines out of the
// stream and stores them for Metrics, and the scanner behind it sees the
// remaining bytes. The returned process records a guest OOM when it ends.
func (c *Containerizer) runVMLauncher(log lager.Logger, handle string, spec garden.ProcessSpec, pio garden.ProcessIO) (garden.Process, error) {
	scanner := newOOMLineScanner(pio.Stderr)
	died := newLineScanner(scanner, vmHypervisorDiedPrefix)

	// The process is the source of its samples, so it exists before the
	// filter that records them.
	launched := &vmLaunchProcess{log: log, handle: handle, scanner: scanner, died: died, stateDir: c.vmStateDir, events: c.events, memory: &c.guestMemory, cpu: &c.guestCPU}
	launched.filter = newVMMetricsFilter(died,
		func(sample vmMemorySample) { c.guestMemory.Record(handle, launched, sample) },
		func(dropped int) {
			if dropped == 1 {
				log.Info("vm-metrics-line-dropped", lager.Data{"handle": handle})
			}
		},
	)
	launched.filter.onCPU = func(sample vmCPUSample) { c.guestCPU.Record(handle, launched, sample) }
	pio.Stderr = launched.filter

	process, err := c.runtime.Exec(log, handle, spec, pio)
	if err != nil || process == nil {
		c.guestMemory.Forget(handle, launched)
		c.guestCPU.Forget(handle, launched)
		return process, err
	}

	launched.Process = process

	return launched, nil
}

// vmLaunchProcess is the wrapped vm-launch process. Once the process has
// ended, Wait releases what the filter still holds, removes the container's
// guest memory sample if this process wrote it, and records a guest OOM in the
// container's events if the scanner saw the report, so it is in the event
// store before the exit status travels back to the caller. When vm-launch
// said that the hypervisor died without a guest status, it also logs the
// container's cgroup memory files, because the cgroup holds the cause of a
// hypervisor that its memory limit killed, and vm-launch cannot read it.
type vmLaunchProcess struct {
	garden.Process

	log     lager.Logger
	handle  string
	filter  *vmMetricsFilter
	scanner interface{ Seen() bool }
	events  EventStore
	memory  *vmGuestMemory
	cpu     *vmGuestCPU

	// died sees the hypervisor-died line, and stateDir is where runc keeps
	// the container's state.
	died     interface{ Seen() bool }
	stateDir string

	once     sync.Once
	diedOnce sync.Once
}

func (p *vmLaunchProcess) Wait() (int, error) {
	status, err := p.Process.Wait()

	if flushErr := p.filter.Flush(); flushErr != nil {
		p.log.Error("flush-vm-launch-stderr-failed", flushErr)
	}
	p.memory.Forget(p.handle, p)
	p.cpu.Forget(p.handle, p)

	if p.scanner.Seen() {
		p.once.Do(func() {
			if recordErr := p.events.OnEvent(p.handle, event.NewOOMEvent(p.handle).Message); recordErr != nil {
				p.log.Error("record-guest-oom-failed", recordErr)
			}
		})
	}

	if p.died.Seen() {
		p.diedOnce.Do(func() {
			p.log.Info("vm-hypervisor-died", lager.Data{"handle": p.handle, "exit-status": status, "cgroup": vmCgroupMemory(p.stateDir, p.handle)})
		})
	}

	return status, err
}
