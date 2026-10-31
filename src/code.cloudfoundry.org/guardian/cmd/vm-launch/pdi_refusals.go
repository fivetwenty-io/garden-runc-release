//go:build linux

package main

import (
	"fmt"
	"regexp"
)

// Some mounts are refused for a reason that belongs to no provider, because
// the volume service behind them has a mode that VM backends do not attach.
// A refusal reads the mount record and answers with a line that tells the
// developer what to bind instead. The registry asks every refusal before it
// asks any provider, so the refusal also holds when a provider that matches
// the filesystem type is registered later. A refusal never appears in the
// list of supported providers, because it owns no mount.

// mountRefusal returns an error, whose text is the whole refusal line, for a
// mount vm-launch will not attach, and nil for any other mount.
type mountRefusal func(m mountRecord) error

// mountRefusals are the refusals the registry asks, in registration order.
var mountRefusals []mountRefusal

// registerMountRefusal adds r to mountRefusals. It panics on a nil refusal,
// which is a mistake in vm-launch's own code that must fail every launch.
func registerMountRefusal(r mountRefusal) {
	if r == nil {
		panic("registering a nil mount refusal")
	}
	mountRefusals = append(mountRefusals, r)
}

func init() { registerMountRefusal(refuseBoshDiskMountMode) }

// wholeDiskSource matches the kernel names of a whole block disk: a SCSI,
// IDE, virtio, or Xen disk such as /dev/sdb, /dev/vdb, or /dev/xvdf, and an
// NVMe namespace such as /dev/nvme1n1. A partition such as /dev/sdb1 or
// /dev/nvme1n1p1 ends in digits or a partition suffix and does not match.
var wholeDiskSource = regexp.MustCompile(`^/dev/(?:(?:sd|hd|vd|xvd)[a-z]+|nvme[0-9]+n[0-9]+)$`)

// refuseBoshDiskMountMode refuses a BOSH disk bound in the bosh-disk
// driver's default mount mode. The driver mounts the disk's own ext4 and the
// container sees that filesystem at its root, so the mount is ext4 or xfs
// whose source is a whole disk and whose root is "/". A VM app gets a BOSH
// disk only in block mode, where the container sees a tmpfs from "pdi:bosh-disk"
// and no filesystem on a device. JuiceFS and NFS mounts have other filesystem
// types, a block-mode descriptor is a tmpfs, a partition or a subdirectory of
// a filesystem is not a whole disk, and none of those is refused here.
func refuseBoshDiskMountMode(m mountRecord) error {
	if m.FSType != "ext4" && m.FSType != "xfs" {
		return nil
	}
	if m.Root != "/" || !wholeDiskSource.MatchString(m.Source) {
		return nil
	}
	return fmt.Errorf("volume path %s is a BOSH disk bound in the driver's mount mode (%s on the whole disk %s); VM backends attach a BOSH disk only in block mode, so bind a service instance of the bosh-disk block plan",
		quoteForLog(m.ContainerDir), m.FSType, quoteForLog(m.Source))
}
