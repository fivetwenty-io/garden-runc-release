//go:build linux

package main

import (
	"context"
	"fmt"
)

// metricsLinePrefix begins every line that vm-launch writes to its stderr to
// report the guest's memory. It is not "vm-launch: ", so neither Garden's
// out-of-memory scanner nor a reader of the logs takes the line for one of
// vm-launch's own messages. Guardian's rundmc package pins the same text.
const metricsLinePrefix = "vm-launch-metrics v1 "

// guestMemorySample is one reading of the guest's balloon statistics, in bytes.
type guestMemorySample struct {
	Total, Available, Free, Caches uint64
}

// guestStatsSource reads the newest sample from the hypervisor.
type guestStatsSource interface {
	Read(ctx context.Context) (guestMemorySample, error)
}

// used returns the memory the guest uses, which is its total memory less the
// memory its kernel considers available. It is the same figure as MemTotal
// less MemAvailable in the guest's /proc/meminfo.
func (s guestMemorySample) used() uint64 {
	return s.Total - s.Available
}

// check reports why the sample cannot be right for a guest of guestBytes of
// memory, or nil when it can. The statistics come from the guest, so we trust
// nothing in them: the total must be above zero and at most the guest's size,
// and the other figures must each be at most the total.
func (s guestMemorySample) check(guestBytes uint64) error {
	switch {
	case s.Total == 0:
		return fmt.Errorf("the guest reported a total of zero bytes")
	case s.Total > guestBytes:
		return fmt.Errorf("the guest reported a total of %d bytes, above its size of %d bytes", s.Total, guestBytes)
	case s.Available > s.Total:
		return fmt.Errorf("the guest reported %d bytes available, above its total of %d bytes", s.Available, s.Total)
	case s.Free > s.Total:
		return fmt.Errorf("the guest reported %d bytes free, above its total of %d bytes", s.Free, s.Total)
	case s.Caches > s.Total:
		return fmt.Errorf("the guest reported %d bytes of caches, above its total of %d bytes", s.Caches, s.Total)
	}
	return nil
}

// line returns the sample as the line that Garden reads, newline included, so
// that one Write sends the whole line. Byte counts are decimal and the
// separators are single spaces. The line stays under 160 bytes, as every
// field is at most 20 digits.
func (s guestMemorySample) line() string {
	return fmt.Sprintf("%sused=%d total=%d available=%d free=%d caches=%d\n",
		metricsLinePrefix, s.used(), s.Total, s.Available, s.Free, s.Caches)
}
