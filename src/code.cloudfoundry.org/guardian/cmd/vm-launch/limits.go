//go:build linux

package main

import (
	"fmt"
	"log"
	"strconv"

	"golang.org/x/sys/unix"
)

// nrOpenMax is the highest fs.nr_open a 64-bit Linux kernel accepts
// (sysctl_nr_open_max), and so the highest open-files limit any process in
// the guest can have.
const nrOpenMax = 2147483584

// nofileLimit is an open-files limit, soft and hard.
type nofileLimit struct {
	soft, hard uint64
}

// getNofile reads vm-launch's RLIMIT_NOFILE. Specs replace it.
var getNofile = func() (unix.Rlimit, error) {
	var r unix.Rlimit
	err := unix.Getrlimit(unix.RLIMIT_NOFILE, &r)
	return r, err
}

// guestNofile returns the open-files limit the guest command gets, which is
// vm-launch's own RLIMIT_NOFILE: Garden gives the app process, which
// vm-launch is, the limit Diego asks for, soft and hard alike. Go raises a
// program's soft limit to its hard limit when it starts, so the soft limit
// read here is the hard one whenever the two differed. A limit above
// nrOpenMax, which only RLIM_INFINITY can be, becomes nrOpenMax, with one
// line that says so.
func guestNofile(get func() (unix.Rlimit, error), logger *log.Logger) (nofileLimit, error) {
	r, err := get()
	if err != nil {
		return nofileLimit{}, fmt.Errorf("reading the open files limit: %w", err)
	}
	limit := nofileLimit{soft: r.Cur, hard: r.Max}
	if limit.hard > nrOpenMax {
		logger.Printf("the open files limit %s is above the %d a guest can have; the guest command gets %d", formatRlimit(limit.hard), nrOpenMax, nrOpenMax)
		limit.hard = nrOpenMax
	}
	if limit.soft > limit.hard {
		limit.soft = limit.hard
	}
	return limit, nil
}

// formatRlimit formats a limit value for a log line.
func formatRlimit(v uint64) string {
	if v == unix.RLIM_INFINITY {
		return "unlimited"
	}
	return strconv.FormatUint(v, 10)
}

// limitsFile returns the guest /rvm/limits, which /init sources before it
// sets the limits of the command.
func limitsFile(n nofileLimit) string {
	return "RVM_NOFILE_SOFT=" + strconv.FormatUint(n.soft, 10) + "\n" +
		"RVM_NOFILE_HARD=" + strconv.FormatUint(n.hard, 10) + "\n"
}
