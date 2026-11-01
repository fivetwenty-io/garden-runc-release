//go:build !windows

package vmstack

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive flock on f. With wait false it returns
// errLocked at once when another holder has the lock.
func lockFile(f *os.File, wait bool) error {
	how := unix.LOCK_EX
	if !wait {
		how |= unix.LOCK_NB
	}
	for {
		err := unix.Flock(int(f.Fd()), how)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return errLocked
		}
		if err != unix.EINTR {
			return err
		}
	}
}

func idOf(info fs.FileInfo) (fileID, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, fmt.Errorf("%s has no device and inode", info.Name())
	}
	return fileID{
		dev:   uint64(st.Dev),
		ino:   st.Ino,
		size:  info.Size(),
		mtime: info.ModTime().UnixNano(),
	}, nil
}
