//go:build linux

package main

import (
	"log"
	"strconv"
	"time"
)

// stopGraceEnv names the variable that carries Diego's graceful shutdown
// interval to the process, as a whole number of seconds. That interval is the
// time between the executor's SIGTERM and its SIGKILL. The executor sets the
// variable on the process it runs. When it is unset or not usable, vm-launch
// keeps the fixed stopDeadline, which assumes Diego's default of 10 seconds.
const stopGraceEnv = "CF_VM_STOP_GRACE_SECONDS"

const (
	// stopGraceMargin is what vm-launch keeps back from Diego's interval for
	// the kernel freeing the guest's memory and for its own cleanup and exit
	// line (see stopDeadline). The guest keeps the same margin again between
	// the end of its own wind-down and the host's deadline (see
	// guestWindDown).
	stopGraceMargin = 2 * time.Second
	// minStopGrace is the shortest interval vm-launch plans around. Below it
	// the guest would have no time left to wind down once the volume teardown
	// took its share, so a shorter interval is raised to this one.
	minStopGrace = 6 * time.Second
	// maxStopGrace is the longest interval vm-launch plans around, so that a
	// mistaken value cannot leave a hung guest running for hours.
	maxStopGrace = 10 * time.Minute
)

// stopTiming returns how long the hypervisor may keep running after the first
// signal, and how long the guest's run section may wind down, for Diego's
// interval in stopGraceEnv. The host's deadline is the interval less
// stopGraceMargin, and the guest's wind-down is the deadline less
// stopGraceMargin again, which is the relation stopDeadline and guestWindDown
// have for the default interval. A value that is not a positive whole number
// of seconds is logged and ignored, and one outside minStopGrace and
// maxStopGrace is logged and moved to the nearest of the two.
func stopTiming(lookup func(string) (string, bool), logger *log.Logger) (deadline, windDown time.Duration) {
	raw, ok := lookup(stopGraceEnv)
	if !ok || raw == "" {
		return stopDeadline, guestWindDown
	}
	secs, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || secs == 0 {
		logger.Printf("ignoring %s=%q, which is not a positive whole number of seconds; the stop deadline stays at %v", stopGraceEnv, raw, stopDeadline)
		return stopDeadline, guestWindDown
	}
	grace := time.Duration(secs) * time.Second
	switch {
	case grace < minStopGrace:
		logger.Printf("%s=%d is under the %v vm-launch needs to stop a guest; using %v", stopGraceEnv, secs, minStopGrace, minStopGrace)
		grace = minStopGrace
	case grace > maxStopGrace:
		logger.Printf("%s=%d is over the %v vm-launch plans for; using %v", stopGraceEnv, secs, maxStopGrace, maxStopGrace)
		grace = maxStopGrace
	}
	deadline = grace - stopGraceMargin
	return deadline, deadline - stopGraceMargin
}
