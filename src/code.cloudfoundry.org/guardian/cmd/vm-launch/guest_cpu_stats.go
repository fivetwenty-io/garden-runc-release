//go:build linux

package main

import (
	"fmt"
	"io"
	"sync"
)

// guestClockTick is the length in nanoseconds of one tick in the guest's
// /proc/stat, which counts in USER_HZ of 100 a second on every kernel we run.
const guestClockTick = 10_000_000

// guestCPULine returns the line that Garden reads to learn the guest's CPU
// time, newline included, so that one Write sends the whole line. Both figures
// are the CPU time in nanoseconds that the guest's vCPUs together have spent
// in user mode and in system mode since the guest booted. The figures come
// from the guest, which parseCPU limits to maxTickDigits digits, so their
// conversion cannot overflow. Garden's rundmc package pins the same form.
func guestCPULine(userTicks, systemTicks uint64) string {
	return fmt.Sprintf("%scpu user=%d system=%d\n",
		metricsLinePrefix, userTicks*guestClockTick, systemTicks*guestClockTick)
}

// cpuReporter writes the guest's CPU lines to w in a goroutine of its own, so
// that a stderr that nothing reads, or that blocks, never holds up the
// goroutine that copies the guest's console to the hypervisor's output. It
// holds the newest figures only: while a write is blocked, each new report
// replaces the one waiting, since the line says how much CPU time the guest has
// used in all and a later line makes an earlier one redundant.
type cpuReporter struct {
	w      io.Writer
	latest chan [2]uint64
	done   chan struct{}
	once   sync.Once
}

func newCPUReporter(w io.Writer) *cpuReporter {
	r := &cpuReporter{w: w, latest: make(chan [2]uint64, 1), done: make(chan struct{})}
	go r.run()

	return r
}

func (r *cpuReporter) run() {
	for {
		select {
		case <-r.done:
			return
		case ticks := <-r.latest:
			_, _ = io.WriteString(r.w, guestCPULine(ticks[0], ticks[1]))
		}
	}
}

// report hands the figures to the writer and returns at once.
func (r *cpuReporter) report(userTicks, systemTicks uint64) {
	ticks := [2]uint64{userTicks, systemTicks}
	for {
		select {
		case r.latest <- ticks:
			return
		default:
		}

		select {
		case <-r.latest:
		default:
		}
	}
}

// close ends the writer goroutine. A write that is blocked stays blocked.
func (r *cpuReporter) close() {
	r.once.Do(func() { close(r.done) })
}
