package processes

import "errors"

// statInRoot is used only for gVisor containers, which exist only on Linux.
func statInRoot(rootFS, path string) error {
	return errors.New("stat in root: confined lookup requires Linux")
}
