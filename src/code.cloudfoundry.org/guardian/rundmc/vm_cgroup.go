package rundmc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	// vmCgroupRoot is where the host mounts the cgroup filesystem, and
	// vmCgroupUnified reports whether it is cgroup v2. Specs replace both.
	vmCgroupRoot    = "/sys/fs/cgroup"
	vmCgroupUnified = isCgroup2Unified
)

// vmCgroupMemoryFiles are the memory files that tell a hypervisor that its
// container's cgroup killed from one that crashed, in the order they are
// reported. A cgroup v2 container keeps its files under the root, and a v1
// container keeps them under the memory controller.
var (
	vmCgroupMemoryFilesV2 = []string{"memory.events", "memory.max", "memory.current", "memory.peak"}
	vmCgroupMemoryFilesV1 = []string{"memory.oom_control", "memory.limit_in_bytes", "memory.usage_in_bytes", "memory.max_usage_in_bytes", "memory.failcnt"}
)

// vmCgroupMemory returns the memory files of the cgroup at path as one line,
// such as "memory.events=[max 3 oom 1 oom_kill 1] memory.max=[1207959552]".
// A file that does not exist is left out, and one that cannot be read is
// named with its error. It returns the reason in place of the files when the
// container has no cgroup path or none of the files exist.
func vmCgroupMemory(path string) string {
	if path == "" {
		return "the bundle has no cgroup path"
	}

	dir, names := filepath.Join(vmCgroupRoot, path), vmCgroupMemoryFilesV2
	if !vmCgroupUnified() {
		dir, names = filepath.Join(vmCgroupRoot, "memory", path), vmCgroupMemoryFilesV1
	}

	var parts []string
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			parts = append(parts, fmt.Sprintf("%s=[unreadable: %v]", name, err))
		default:
			parts = append(parts, fmt.Sprintf("%s=[%s]", name, strings.Join(strings.Fields(string(raw)), " ")))
		}
	}
	if len(parts) == 0 {
		return "no memory files under " + dir
	}

	return strings.Join(parts, " ")
}
