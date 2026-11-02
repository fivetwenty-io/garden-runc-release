//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// containerCgroupDir is the container's own cgroup, as a process in the
// container sees it. Under cgroup v2 the container's cgroup is the root of
// its cgroup namespace, so vm-launch reads its memory files here without any
// privilege. Specs point it elsewhere.
var containerCgroupDir = "/sys/fs/cgroup"

// cgroupEventFiles are the files that vm-launch reads, in the order it
// reports them, when the hypervisor dies without the guest reporting a
// status. memory.events holds the counts that tell an out-of-memory kill of
// the hypervisor by the container's cgroup (oom_kill) from a crash.
var cgroupEventFiles = []string{"memory.events", "memory.max", "memory.current", "memory.peak"}

// hypervisorDied reports whether r ended with the hypervisor gone and no
// reason of Diego's or the guest's for it: no status from the guest and no
// signal that vm-launch received first. It includes a hypervisor that exited
// without a status, and one that a signal killed.
func hypervisorDied(r runResult) bool {
	return !r.markerFound && r.received == 0 && r.state != nil
}

// cgroupEventsMessage returns the line vm-launch writes when the hypervisor
// died, with the container's memory events and limits on it, such as
// "memory.events=[max 3 oom 1 oom_kill 1]". The line gives an operator the
// cause of a death that the exit status alone does not, as in a hypervisor
// killed by the container's cgroup when the guest and the hypervisor outgrew
// its limit. A file that does not exist is left out, because the container is
// not on cgroup v2 or has no memory controller, and one that cannot be read
// is named with its error. The second result is false when no file could be
// read at all, so there is nothing to report.
func cgroupEventsMessage() (string, bool) {
	var parts []string
	for _, name := range cgroupEventFiles {
		raw, err := os.ReadFile(filepath.Join(containerCgroupDir, name))
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			parts = append(parts, fmt.Sprintf("%s=[unreadable: %v]", name, errnoText(err)))
		default:
			parts = append(parts, fmt.Sprintf("%s=[%s]", name, strings.Join(strings.Fields(string(raw)), " ")))
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	return "the container's cgroup after the hypervisor died: " + strings.Join(parts, " "), true
}

// errnoText returns the system error inside err, such as "permission
// denied", without the path that the os package puts in front of it.
func errnoText(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	return err.Error()
}
