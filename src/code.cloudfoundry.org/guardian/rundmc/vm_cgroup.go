package rundmc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// vmCgroupUnified reports whether the host runs cgroup v2. Specs replace it.
var vmCgroupUnified = isCgroup2Unified

// vmCgroupMemoryFiles are the memory files that tell a hypervisor that its
// container's cgroup killed from one that crashed, in the order they are
// reported. A cgroup v2 container keeps its files under the root, and a v1
// container keeps them under the memory controller.
var (
	vmCgroupMemoryFilesV2 = []string{"memory.events", "memory.max", "memory.current", "memory.peak"}
	vmCgroupMemoryFilesV1 = []string{"memory.oom_control", "memory.limit_in_bytes", "memory.usage_in_bytes", "memory.max_usage_in_bytes", "memory.failcnt"}
)

// vmInitCgroupName is the child cgroup that runcontainerd runs a container in
// on cgroup v2. The rundmc/cgroups package names it too, but it imports this
// package.
const vmInitCgroupName = "init"

// runcState is the part of runc's state.json that names the directories of a
// container's cgroups.
type runcState struct {
	CgroupPaths map[string]string `json:"cgroup_paths"`
}

// vmCgroupDir returns the directory of the container's memory cgroup, from the
// cgroup paths that runc saved in the container's state. Runc keeps the paths
// that are in force, so they follow the container when Garden moves it to
// another cgroup, and they carry the mount point of the controller. In
// containerd mode on cgroup v2 runc runs the container in an init child of the
// cgroup that holds its limits and its event counts, so the parent is the one
// to read.
func vmCgroupDir(stateDir, handle string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, handle, "state.json"))
	if err != nil {
		return "", err
	}

	var state runcState
	if err := json.Unmarshal(raw, &state); err != nil {
		return "", err
	}

	if vmCgroupUnified() {
		dir := state.CgroupPaths[""]
		if dir != "" && filepath.Base(dir) == vmInitCgroupName {
			dir = filepath.Dir(dir)
		}
		return dir, nil
	}
	return state.CgroupPaths["memory"], nil
}

// vmCgroupMemory returns the memory files of the container's cgroup as one
// line, such as "memory.events=[max 3 oom 1 oom_kill 1] memory.max=[1207959552]".
// A file that does not exist is left out, and one that cannot be read is
// named with its error. It returns the reason in place of the files when the
// container's state names no memory cgroup or none of the files exist.
func vmCgroupMemory(stateDir, handle string) string {
	dir, err := vmCgroupDir(stateDir, handle)
	if err != nil {
		return "the container's runc state cannot be read: " + err.Error()
	}
	if dir == "" {
		return "the container's runc state names no memory cgroup"
	}

	names := vmCgroupMemoryFilesV2
	if !vmCgroupUnified() {
		names = vmCgroupMemoryFilesV1
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
