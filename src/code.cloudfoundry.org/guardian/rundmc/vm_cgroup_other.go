//go:build !linux

package rundmc

// isCgroup2Unified is false off Linux, where a container has no cgroup.
func isCgroup2Unified() bool {
	return false
}
