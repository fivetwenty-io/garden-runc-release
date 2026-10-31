//go:build linux

package main

import "fmt"

// juicefsFSType is the filesystem type of a JuiceFS mount. JuiceFS mounts
// itself as fuse.juicefs (juicefs cmd/mount_unix.go, and the juicefs-broker
// ctl script matches the same type in findmnt output). Cloud Controller
// removes the driver name from volume_mounts, so the type in the mount table
// is how vm-launch recognises the provider.
const juicefsFSType = "fuse.juicefs"

func init() { registerDiskProvider(juicefsProvider{}) }

// juicefsProvider is the JuiceFS volume service. Its disk is a sparse image
// file in the volume root, 1 GiB unless the app asks for another size, which
// openVolumeImage creates, checks, locks, and grows by fallocate, or by
// truncate where the volume has no fallocate. A JuiceFS flock holds across
// cells, and its quota counts file length, so an image is charged its whole
// size as soon as it is sized or grown.
//
// Driver contract. The fence is JuiceFS's flock, and it reaches the metadata
// engine, and so every cell, only when the JuiceFS client negotiates flock
// forwarding with FUSE. The provider requires a mount made without
// --no-bsd-lock, which would leave the kernel taking flock locally on each
// cell, and without --writeback or -o writeback_cache, under which FUSE
// ignores the length in an attribute reply for a regular file and the fresh
// length reads of the grow return the cell's cached length. Nothing in the
// mount table shows either setting, so there is no runtime check, and Match
// and Capabilities claim the fence on the filesystem type alone. The lab
// check confirms the mount options of our juicefs release. Unlike the NFS
// provider, which reads local_lock=none from the superblock options and
// refuses a mount without it, this asymmetry is a decision and not an
// omission.
type juicefsProvider struct{}

func (juicefsProvider) Name() string { return "JuiceFS" }

// Match owns exactly the fuse.juicefs filesystem type, compared as written.
func (juicefsProvider) Match(m mountRecord) matchStrength {
	if m.FSType == juicefsFSType {
		return strongMatch
	}
	return noMatch
}

func (juicefsProvider) Capabilities(mountRecord) capabilities {
	return capabilities{Modes: []attachMode{attachFileImage}, Fence: fenceDistributedFlock, Sharing: sharingShared}
}

// Prepare opens, and creates when missing, the instance's image with
// defaultImageOptions and the size the request asks for, grows it to that
// size, and returns it locked. The lock lasts until Release closes
// vm-launch's copy and the hypervisor, which shares the open file, has
// exited.
func (juicefsProvider) Prepare(req prepareRequest) (*attachment, error) {
	if req.Mode != attachFileImage {
		return nil, fmt.Errorf("the JuiceFS volume provider attaches only in %s, not in %s", attachFileImage, req.Mode)
	}
	opts := req.fileImageOptions(defaultImageOptions)
	img, err := openVolumeImage(&guestVolume{
		ContainerDir: req.Mount.ContainerDir, ImageName: req.ImageName,
		MountID: req.Mount.MountID, MountIDKnown: true,
	}, opts, req.Signals)
	if err != nil {
		return nil, err
	}
	return &attachment{File: img, Release: img.Close}, nil
}
