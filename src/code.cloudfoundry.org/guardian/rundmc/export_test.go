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
