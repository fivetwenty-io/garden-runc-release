package vmstack

import (
	"errors"
	"io/fs"
	"os"
)

// VM backends run only on Linux, and Garden refuses a stack tarball without
// one, so a Windows Garden never builds a stack image. These keep the package
// compiling there and fail any build that is attempted anyway.
var errNotSupported = errors.New("VM stack images need Linux")

func lockFile(f *os.File, wait bool) error {
	return errNotSupported
}

func idOf(info fs.FileInfo) (fileID, error) {
	return fileID{}, errNotSupported
}
