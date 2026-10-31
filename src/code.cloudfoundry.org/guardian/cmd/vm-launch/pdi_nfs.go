//go:build linux

package main

import (
	"fmt"
	"slices"
)

// The filesystem types the NFS provider recognises, and the superblock option
// that makes a kernel NFSv4 mount safe to fence with flock. The kernel shows
// an NFSv4 mount as nfs4 and an NFSv3 mount as nfs. nfs-volume-release's
// nfsv3driver mounts the share with the kernel client when the binding gives
// no uid, and with a uid and gid mounts it at another path and runs mapfs,
// a FUSE layer, at the volume path, which a container sees as fuse.mapfs.
const (
	nfs4FSType  = "nfs4"
	nfs3FSType  = "nfs"
	mapfsFSType = "fuse.mapfs"

	// nfsLocalLockNone is the superblock option under which the Linux client
	// sends flock to the server as a whole-file lock, so the lock holds
	// across cells.
	nfsLocalLockNone = "local_lock=none"
)

func init() { registerDiskProvider(nfsProvider{}) }

// nfsProvider is the NFS volume service. Its disk is an image file in the
// volume root, which openVolumeImage creates, checks, and locks like
// JuiceFS's. It owns kernel NFSv4 mounts whose locks go to the server. An NFS
// server's quota counts allocated blocks, so a new image is allocated before
// it is sized (imageOptions.Preallocate), which fails an image the quota
// cannot hold at creation instead of inside the guest.
//
// It also claims the mounts it refuses, weakly, so that the refusal says why
// in NFS's own words: a kernel NFSv3 mount, a mapfs mount, and an NFSv4 mount
// whose locks stay on one cell. Prepare returns those refusals before it
// touches the volume.
type nfsProvider struct{}

func (nfsProvider) Name() string { return "NFS" }

// Match owns an nfs4 mount whose superblock options include local_lock=none
// strongly, and claims the nfs, nfs4 without that option, and fuse.mapfs
// types weakly, for Prepare to refuse. Types are compared as written.
func (nfsProvider) Match(m mountRecord) matchStrength {
	switch m.FSType {
	case nfs4FSType:
		if slices.Contains(m.SuperOptions, nfsLocalLockNone) {
			return strongMatch
		}
		return weakMatch
	case nfs3FSType, mapfsFSType:
		return weakMatch
	}
	return noMatch
}

func (nfsProvider) Capabilities(mountRecord) capabilities {
	return capabilities{Modes: []attachMode{attachFileImage}, Fence: fenceDistributedFlock}
}

// Prepare refuses a mount that Match claims weakly, and otherwise opens, and
// creates when missing, the instance's image with defaultImageOptions plus
// preallocation, and returns it locked. The lock lasts until Release closes
// vm-launch's copy and the hypervisor, which shares the open file, has exited.
func (nfsProvider) Prepare(req prepareRequest) (*attachment, error) {
	if req.Mode != attachFileImage {
		return nil, fmt.Errorf("the NFS volume provider attaches only in %s, not in %s", attachFileImage, req.Mode)
	}
	if err := refuseNFSMount(req.Mount); err != nil {
		return nil, err
	}
	o := defaultImageOptions
	o.Preallocate = true
	img, err := openVolumeImage(&guestVolume{
		ContainerDir: req.Mount.ContainerDir, ImageName: req.ImageName,
		MountID: req.Mount.MountID, MountIDKnown: true,
	}, o, req.Signals)
	if err != nil {
		return nil, err
	}
	return &attachment{File: img, Release: img.Close}, nil
}

// refuseNFSMount returns the refusal for an NFS mount whose locks do not hold
// across cells, or nil for a mount the NFS provider can fence. A refusal says
// what the mount is and what the operator can change: two instances on two
// cells could otherwise both hold an exclusive lock on one image, and two
// guests would write one ext4 filesystem.
func refuseNFSMount(m mountRecord) error {
	dir, fstype := quoteForLog(m.ContainerDir), quoteForLog(m.FSType)
	switch m.FSType {
	case nfs3FSType:
		return fmt.Errorf("volume path %s is a kernel NFSv3 mount (%s); VM backends support only NFSv4, because NFSv3 locks depend on lockd and on options that a binding can turn off; bind the service with version 4.1 or 4.2", dir, fstype)
	case mapfsFSType:
		return fmt.Errorf("volume path %s is a %s mount, which the NFS service makes when the binding sets uid and gid; mapfs keeps flock local to each cell, so two instances on two cells could write one image at once; bind the service without uid and gid for a VM app", dir, fstype)
	case nfs4FSType:
		if !slices.Contains(m.SuperOptions, nfsLocalLockNone) {
			return fmt.Errorf("volume path %s is an NFSv4 mount without %s, so its flock stays local to each cell and two instances on two cells could write one image at once; VM backends need an NFSv4 mount with %s", dir, nfsLocalLockNone, nfsLocalLockNone)
		}
	}
	return nil
}
