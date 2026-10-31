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
