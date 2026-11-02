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

// HypervisorDiedPrefix is the prefix of the stderr line vm-launch writes when
// the hypervisor ended without a guest status, which cmd/vm-launch pins
// separately.
const HypervisorDiedPrefix = vmHypervisorDiedPrefix

// SetVMCgroup makes the container cgroup reader read the layout of cgroup v2
// when unified is true and that of v1 otherwise. It returns a function that
// puts the real value back.
func SetVMCgroup(unified bool) func() {
	saved := vmCgroupUnified
	vmCgroupUnified = func() bool { return unified }
	return func() { vmCgroupUnified = saved }
}
