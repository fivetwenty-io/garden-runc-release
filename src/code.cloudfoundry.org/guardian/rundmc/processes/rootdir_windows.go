package processes

import "errors"

// statInRoot backs confined working directory lookups, which only Linux uses.
func statInRoot(rootFS, path string) error {
	return errors.New("stat in root: confined lookup requires Linux")
}
