package users

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	securejoin "github.com/cyphar/filepath-securejoin/pathrs-lite"
	"github.com/moby/sys/user"
	"golang.org/x/sys/unix"
)

// MaxImageIdentityFileSize is the largest passwd or group file that
// LookupImageUser reads. The files come from the image, so a sparse or
// endlessly growing file must not hold Guardian in the lookup.
const MaxImageIdentityFileSize int64 = 64 << 20

// ErrImageIdentityFileTooLarge is returned when an image's passwd or group
// file is larger than MaxImageIdentityFileSize.
var ErrImageIdentityFileTooLarge = errors.New("image identity file is too large")

// LookupImageUser resolves name against the passwd and group files of the
// image root filesystem at root. It reads those files the way the container
// would see them: every path component, including absolute and relative
// symlinks, resolves inside root. Each file must be a regular file and is
// opened without blocking, so a FIFO or device in the image fails the lookup
// instead of hanging it.
//
// A missing passwd file resolves "root" to uid 0, gid 0, home "/", as
// LookupUser does. A missing group file leaves the supplementary groups empty.
func LookupImageUser(root, name string) (*ExecUser, error) {
	if root == "" {
		return nil, errors.New("look up image user: image root path is empty")
	}

	rootDir, err := os.OpenFile(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("look up image user: open image root: %w", withoutPath(err))
	}
	defer rootDir.Close()

	passwd, err := openImageIdentity(rootDir, "/etc/passwd")
	passwdMissing := errors.Is(err, os.ErrNotExist)
	switch {
	case err == nil:
		defer passwd.Close()
	case passwdMissing, errors.Is(err, unix.ENOTDIR):
		// A path with a regular file where a directory belongs reads as a
		// missing file, as it does for LookupUser.
		passwd = nil
	default:
		return nil, fmt.Errorf("look up image user: %w", err)
	}

	// LookupUser answers "root" without looking at the group file when there
	// is no passwd file, so a bad group file must not matter here.
	if passwdMissing && name == "root" {
		return &ExecUser{Uid: DefaultUID, Gid: DefaultGID, Home: DefaultHome, Sgids: []int{}}, nil
	}

	group, err := openImageIdentity(rootDir, "/etc/group")
	switch {
	case err == nil:
		defer group.Close()
	case errors.Is(err, os.ErrNotExist), errors.Is(err, unix.ENOTDIR):
		group = nil
	default:
		return nil, fmt.Errorf("look up image user: %w", err)
	}

	defaultUser := &user.ExecUser{Uid: DefaultUID, Gid: DefaultGID, Home: DefaultHome}
	resolved, err := user.GetExecUser(name, defaultUser, identityReader(passwd, "/etc/passwd"), identityReader(group, "/etc/group"))
	if err != nil {
		return nil, err
	}

	return &ExecUser{Uid: resolved.Uid, Gid: resolved.Gid, Home: resolved.Home, Sgids: resolved.Sgids}, nil
}

// openImageIdentity opens path inside rootDir for reading. It returns an error
// that wraps os.ErrNotExist when the path, or the target of a symlink on it,
// does not exist inside the root.
func openImageIdentity(rootDir *os.File, path string) (*os.File, error) {
	// OpenatInRoot returns an O_PATH descriptor, so resolving the path never
	// opens the file and a FIFO cannot block here.
	handle, err := securejoin.OpenatInRoot(rootDir, path)
	if err != nil {
		return nil, fmt.Errorf("resolve %s in the container image: %w", path, withoutPath(err))
	}
	defer handle.Close()

	info, err := handle.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s in the container image: %w", path, withoutPath(err))
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s in the container image is not a regular file (type %s)", path, info.Mode().Type())
	}

	if info.Size() > MaxImageIdentityFileSize {
		return nil, fmt.Errorf("%s in the container image is %d bytes, more than %d: %w", path, info.Size(), MaxImageIdentityFileSize, ErrImageIdentityFileTooLarge)
	}

	// Reopen the inode that the handle pins rather than its path, so the file
	// read is the file that was checked. O_NONBLOCK is a second guard: the
	// inode is a regular file, on which it has no effect.
	file, err := securejoin.Reopen(handle, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("open %s in the container image: %w", path, withoutPath(err))
	}

	return file, nil
}

// identityReader returns a reader that fails once more than
// MaxImageIdentityFileSize bytes have been read, because the file can grow
// after it was checked. A nil file gives a nil reader, so GetExecUser treats
// the file as absent rather than receiving a typed nil.
func identityReader(file *os.File, path string) io.Reader {
	if file == nil {
		return nil
	}

	return newCappedReader(file, MaxImageIdentityFileSize, path)
}

func newCappedReader(r io.Reader, limit int64, path string) *cappedReader {
	return &cappedReader{r: r, limit: limit, remaining: limit, path: path}
}

type cappedReader struct {
	r         io.Reader
	limit     int64
	remaining int64
	path      string
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if c.remaining <= 0 {
		var probe [1]byte
		n, err := c.r.Read(probe[:])
		if n > 0 {
			return 0, fmt.Errorf("%s in the container image grew past %d bytes: %w", c.path, c.limit, ErrImageIdentityFileTooLarge)
		}
		return 0, err
	}

	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}

	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	return n, err
}

// withoutPath strips paths from err, because the text reaches Garden clients.
// The errno survives, so errors.Is checks for ENOENT, ENOTDIR, and ELOOP still
// work. An error without an errno becomes a generic one, since the resolver's
// own errors can carry the paths it walked.
func withoutPath(err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}

	return errors.New("path cannot be resolved inside the image root")
}
