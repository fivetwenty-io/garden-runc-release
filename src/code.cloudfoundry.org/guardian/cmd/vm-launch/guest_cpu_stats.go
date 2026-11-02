//go:build linux

package main

import "fmt"

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
