package vmimage

import (
	"errors"
	"io/fs"
	"os"
)

// VM backends run only on Linux, and Garden refuses a Docker image for a VM
// container without one, so a Windows Garden never builds a VM image. These
// keep the package compiling there and fail any build that is attempted anyway.
var errNotSupported = errors.New("VM images need Linux")

func lockFile(f *os.File, wait bool) error {
	return errNotSupported
}

func idOf(info fs.FileInfo) (fileID, error) {
	return fileID{}, errNotSupported
}

func linkCount(path string) (uint64, error) {
	return 0, errNotSupported
}
