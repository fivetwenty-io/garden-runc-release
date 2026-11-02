package rundmc

import "github.com/opencontainers/cgroups"

// isCgroup2Unified reports whether the host mounts the unified cgroup v2
// hierarchy. The rundmc/cgroups package has the same function, but it imports
// this package.
func isCgroup2Unified() bool {
	return cgroups.IsCgroup2UnifiedMode()
}
