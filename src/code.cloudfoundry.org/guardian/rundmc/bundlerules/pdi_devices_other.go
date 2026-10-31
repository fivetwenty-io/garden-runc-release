//go:build !linux

package bundlerules

import (
	"errors"
	"runtime"

	"code.cloudfoundry.org/lager/v3"
)

// NewPDIDevices fails off Linux, where Garden has no block nodes or device
// cgroup to give a VM container.
func NewPDIDevices(_ lager.Logger, _ uint32) (*PDIDevices, error) {
	return nil, errors.New("block volumes need Linux, and this is " + runtime.GOOS)
}
