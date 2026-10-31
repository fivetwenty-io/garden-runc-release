//go:build !linux

package bundlerules

import (
	"errors"
	"runtime"

	"code.cloudfoundry.org/lager/v3"
)

// NewPDIDevices fails off Linux, where Garden has no block nodes or device
// cgroup to give a VM container.
func NewPDIDevices(_ lager.Logger, _ uint32, _ string) (*PDIDevices, error) {
	return nil, errors.New("block volumes need Linux, and this is " + runtime.GOOS)
}

// NewPDILeftoverReleaser returns nil off Linux, because no Garden there can
// have given a device to a container, so no claim is left to release.
func NewPDILeftoverReleaser(_ lager.Logger, _ string) (*PDIDevices, error) {
	return nil, nil
}

// publishPDIClaim fails off Linux, where Garden never claims a device.
func publishPDIClaim(_, _ string, _ []byte) error {
	return errors.New("block volume claims need Linux, and this is " + runtime.GOOS)
}
