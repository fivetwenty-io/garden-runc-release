//go:build linux

package main

import (
	"fmt"

	"code.cloudfoundry.org/guardian/backend"
)

// Share mode serves a volume's own directory to a QEMU guest over virtiofs
// instead of giving the instance an image of its own. An app asks for it with
// "mode": "share" in VM_VOLUMES (see pdi_settings.go), and three things have
// to hold before vm-launch grants it. The hypervisor must be QEMU, because
// Firecracker has no virtiofs device. The volume's provider must declare
// sharingShared, which JuiceFS and kernel NFSv4 do. And the operator must
// have turned shares on with the allowVolumeSharesFlag flag, which Garden
// renders from a job property that defaults to off. Anything else is refused
// with exit status 125 and one line, so an app that asks for a share never
// quietly gets a private disk. A volume that does not ask for a share is
// never looked at here and stays private.
//
// This file decides and records the grant. A granted volume gets no image:
// preparedVolumes.prepare skips it, virtiofsd.go starts one virtiofsd for it,
// and QEMU reaches that virtiofsd over a vhost-user socket.

// allowVolumeSharesFlag names the vm-launch flag with which the operator
// allows shares on this cell. Without it every share is refused.
const allowVolumeSharesFlag = "allow-volume-shares"

// shareTagPrefix starts the virtiofs tag of a share, which ends in the
// volume's index: rvm-vol0 for the first volume.
const shareTagPrefix = "rvm-vol"

// shareGrant is one share that grantShares allowed.
type shareGrant struct {
	// Index is the volume index: the volume's position among all of the
	// app's volumes in path order, shares and private volumes alike. It is
	// the N of RVM_VOLn and of the tag rvm-volN. A private volume beside a
	// share keeps its own index, so with a share at index 0 and an image at
	// index 1 the share's tag is rvm-vol0 and the image's drive is the
	// volume at index 1, never the first drive by position.
	Index int
	// Path is the volume's container_dir. It is both the directory that the
	// guest mounts the share at and the directory that virtiofsd serves,
	// because virtiofsd runs in the container's mount namespace, where the
	// volume is bound at that path.
	Path string
	// Mount is the record of the mount that holds Path, as
	// findVolumeProvider found it. checkShareMount compares the directory
	// with it again just before virtiofsd starts.
	Mount mountRecord
	// Tag is the virtiofs tag the guest mounts by.
	Tag string
	// Provider names the volume service behind the share.
	Provider string
}

// shareTag returns the virtiofs tag of the volume at index.
func shareTag(index int) string { return fmt.Sprintf("%s%d", shareTagPrefix, index) }

// grantShares decides every volume's share request. A volume whose
// VM_VOLUMES mode is private is skipped. For each volume that asks for a
// share, in volume order, it refuses on the first rule that fails, so an app
// is told the reason it can act on first: the backend, then the provider,
// then the operator's switch. A refusal of one volume refuses the launch,
// because the other volumes' data must not be started against a half-granted
// request. The grants it returns are in volume order; there are none when no
// volume asks for a share.
func grantShares(kind backend.Kind, operatorAllows bool, selected []selectedVolume) ([]shareGrant, error) {
	var grants []shareGrant
	for i, v := range selected {
		if v.Volume.Settings.Mode != volumeShare {
			continue
		}
		path := quoteForLog(v.Volume.ContainerDir)
		switch {
		case kind != backend.VMQemu:
			return nil, fmt.Errorf("%s %s mode %q is not available on %s, %s; shares need the %s backend",
				volumeSettingsEnv, path, modeNameShare, kind, whyNoShares(kind), backend.VMQemu)
		case v.Provider == nil || v.Provider.Capabilities(v.Mount).Sharing != sharingShared:
			return nil, fmt.Errorf("%s %s mode %q is not available for %s; only JuiceFS and NFSv4 volumes can be shared",
				volumeSettingsEnv, path, modeNameShare, describeVolume(v.Provider))
		case !operatorAllows:
			return nil, fmt.Errorf("%s %s mode %q is not allowed on this cell; the operator has not turned on volume shares",
				volumeSettingsEnv, path, modeNameShare)
		}
		grants = append(grants, shareGrant{
			Index:    i,
			Path:     v.Volume.ContainerDir,
			Mount:    v.Mount,
			Tag:      shareTag(i),
			Provider: v.Provider.Name(),
		})
	}
	return grants, nil
}

// whyNoShares says why a hypervisor cannot serve a share.
func whyNoShares(kind backend.Kind) string {
	if kind == backend.VMFirecracker {
		return "which has no virtiofs device"
	}
	return "which cannot serve a share"
}

// describeVolume names a volume by its provider for a refusal, and tolerates
// a volume with none.
func describeVolume(p diskProvider) string {
	if p == nil {
		return "a volume that no provider owns"
	}
	return "a " + p.Name() + " volume"
}
