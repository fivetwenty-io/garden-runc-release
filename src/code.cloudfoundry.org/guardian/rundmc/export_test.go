package rundmc

import (
	"io"
	"time"
)

// OOMLinePrefix is the prefix of the stderr line vm-launch writes after a
// guest OOM, which cmd/vm-launch pins separately.
const OOMLinePrefix = vmOOMLinePrefix

// OOMLineScanner exposes the stderr scanner to the black-box specs.
type OOMLineScanner interface {
	io.Writer
	Seen() bool
}

func NewOOMLineScanner(next io.Writer) OOMLineScanner {
	return newOOMLineScanner(next)
}

// SetGuestMemoryClock makes the container's guest memory store read now in
// place of the wall clock, so a spec can age a sample.
func SetGuestMemoryClock(c *Containerizer, now func() time.Time) {
	c.guestMemory.now = now
}

// SetGuestCPUClock makes the container's guest CPU store read now in place of
// the wall clock, so a spec can age a sample.
func SetGuestCPUClock(c *Containerizer, now func() time.Time) {
	c.guestCPU.now = now
}

// SetGuestCPUCores makes the bound on how fast a guest's CPU counter may rise
// use cores vCPUs in place of the host's.
func SetGuestCPUCores(c *Containerizer, cores int) {
	c.guestCPUCores = cores
}

// HasGuestCPUCounter says whether the container has a CPU counter.
func HasGuestCPUCounter(c *Containerizer, handle string) bool {
	_, ok := c.guestCPUCounters.Load(handle)
	return ok
}
