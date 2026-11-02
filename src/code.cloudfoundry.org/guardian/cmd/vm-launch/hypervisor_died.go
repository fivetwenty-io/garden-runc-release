//go:build linux

package main

// hypervisorDiedPrefix is the text, after the logger's "vm-launch: ", that
// begins the line vm-launch writes when the hypervisor ended and the guest had
// reported no status. Guardian's rundmc package pins the same text with the
// "vm-launch: " in front, and on seeing it logs the container's cgroup memory
// files, which vm-launch cannot read because Garden gives the container no
// cgroup filesystem.
const hypervisorDiedPrefix = "the hypervisor ended without a guest status"

// hypervisorDied reports whether r ended with the hypervisor gone and no
// reason of Diego's or the guest's for it: no status from the guest and no
// signal that vm-launch received first. It includes a hypervisor that exited
// without a status, and one that a signal killed.
func hypervisorDied(r runResult) bool {
	return !r.markerFound && r.received == 0 && r.state != nil
}
