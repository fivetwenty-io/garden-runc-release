//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The guest volume image. vm-launch creates it in the volume root,
// checks that it is a plain file the app owns, locks it, and hands the open
// file to the hypervisor. It never reads or writes the image's bytes: only
// the guest kernel parses what is in it.
const (
	// defaultImageSize is the size of a new image. An existing image keeps
	// its size; vm-launch never resizes one. A new image is sparse, but a
	// quota that counts file length, as JuiceFS does, charges all of it as
	// soon as the file is sized.
	defaultImageSize = 1 << 30

	// imageSectorSize is the unit virtio-blk exposes a drive in.
	imageSectorSize = 512

	// imageMode is the only permission set an image may have. It is created
	// with it, so the kvm group vm-launch runs with grants nothing on it.
	imageMode = 0o600

	// lockWait is how long vm-launch waits for another instance's VM to
	// release the image. It is below Diego's default 60 second start timeout,
	// so a stuck holder makes this instance crash and be retried rather than
	// time out silently.
	lockWait = 30 * time.Second
	lockPoll = 500 * time.Millisecond

	// tempPrefix and tempSuffix frame the unique name a new image has until
	// it is sized and published. A launch killed in between leaves such a
	// file behind. Nothing ever opens, trusts, or reuses a temp file, but
	// on a volume whose quota counts file length it holds up to the image
	// size of quota until an operator deletes it.
	tempPrefix = ".rvm-disk-"
	tempSuffix = ".tmp"

	// openRetries bounds retries of an openat2 that the kernel interrupted or
	// asked to repeat because of a concurrent rename.
	openRetries = 8
)

// imageOptions are the parameters of openVolumeImage. Tests shorten the
// waits and replace the mount root check, which needs a real mount.
type imageOptions struct {
	Size        int64
	LockWait    time.Duration
	LockPoll    time.Duration
	IsMountRoot func(dirfd int) (bool, error)

	// afterTempCreate, when set, runs once a new image is sized and before it
	// is published. Tests use it to act as a co-bound app would.
	afterTempCreate func(dirfd int, tempName string)

	// rename, when set, replaces renameNoReplace as the step that publishes a
	// new image. Tests use it to fail the publish while the temp file exists.
	rename func(dirfd int, oldName, newName string) error
}

var defaultImageOptions = imageOptions{
	Size:        defaultImageSize,
	LockWait:    lockWait,
	LockPoll:    lockPoll,
	IsMountRoot: statxMountRoot,
}

// Kinds of volume image failure. Every one of them stops the launch with
// exit status 125; errors.Is tells them apart.
var (
	errVolumeInUse     = errors.New("volume image in use")
	errNotMountRoot    = errors.New("volume is not a mount point")
	errImageNotRegular = errors.New("volume image is not a regular file")
	errImageOwner      = errors.New("volume image has the wrong owner")
	errImageLinks      = errors.New("volume image has more than one link")
	errImageMode       = errors.New("volume image has the wrong mode")
	errImageSize       = errors.New("volume image has an unusable size")
	errImageReplaced   = errors.New("volume image name no longer refers to the locked file")
)

// volumeError is a volume image failure with its own message. It matches
// its kind, and its cause when there is one, under errors.Is.
type volumeError struct {
	kind  error
	cause error
	msg   string
}

func (e *volumeError) Error() string { return e.msg }

func (e *volumeError) Unwrap() []error {
	if e.cause == nil {
		return []error{e.kind}
	}
	return []error{e.kind, e.cause}
}

// signalledError reports a SIGTERM or SIGINT that arrived while vm-launch
// waited for the image lock.
type signalledError struct{ Sig syscall.Signal }

func (e *signalledError) Error() string {
	return fmt.Sprintf("received %v while waiting for the volume image lock", e.Sig)
}

// openVolumeImage opens, and creates when missing, the image of v in the
// root of its volume, and returns it locked for the life of the returned
// file and of every process that inherits it.
//
// The volume path is resolved without following any symbolic link and must
// be a mount point, so that the image cannot land on the container's
// ephemeral disk or outside the volume. The image is opened beneath it on
// the same mount, again without following links, and must be a regular file
// owned by vm-launch's effective uid, with one link, mode 0600, and exactly
// Size bytes. vm-launch never repairs, resizes, or removes an image that
// fails a check. It then takes an exclusive flock, retrying every LockPoll
// for up to LockWait and giving up early when a signal arrives on sigs. Once
// it holds the lock, it checks that the name still refers to the locked file,
// which an operator or a co-bound app could have deleted or replaced during
// the wait.
//
// A missing image is created under a unique temporary name in the same
// directory, sized to Size (sparse, but a quota that counts file length
// charges all of it), synced, and only then published under its name with
// renameat2(RENAME_NOREPLACE), so the published name never refers to an
// unsized file, whatever happens to this launch. See createImage.
func openVolumeImage(v *guestVolume, o imageOptions, sigs <-chan os.Signal) (*os.File, error) {
	if err := checkImageRequest(v, o); err != nil {
		return nil, err
	}
	path := filepath.Join(v.ContainerDir, v.ImageName)

	dirfd, err := openat2Retry(unix.AT_FDCWD, v.ContainerDir, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("opening volume %s: %w%s", v.ContainerDir, err, symlinkHint(err))
	}
	defer unix.Close(dirfd)

	root, err := o.IsMountRoot(dirfd)
	switch {
	case err != nil:
		return nil, &volumeError{kind: errNotMountRoot, cause: err,
			msg: fmt.Sprintf("volume %s is not a mount point: cannot tell: %v", v.ContainerDir, err)}
	case !root:
		return nil, &volumeError{kind: errNotMountRoot,
			msg: fmt.Sprintf("volume %s is not a mount point", v.ContainerDir)}
	}

	// The umask must not take the owner's bits away from a new image: the
	// hypervisor reopens it read-write through /proc/self/fd, which checks
	// them, and a new image without them would fail every later launch.
	oldMask := unix.Umask(0o077)
	fd, err := openImageFile(dirfd, v.ImageName, path, o)
	unix.Umask(oldMask)
	if err != nil {
		return nil, err
	}
	img := os.NewFile(uintptr(fd), path)
	ok := false
	defer func() {
		if !ok {
			img.Close()
		}
	}()

	// Check before waiting, so that a bad image fails at once, and again
	// under the lock, which is what counts. A size of 0 is a bad size: an
	// image is never published unsized, so an empty file at the name was not
	// made by vm-launch.
	if err := checkOpenImage(fd, path, o.Size); err != nil {
		return nil, err
	}
	if err := lockImage(fd, path, o, sigs); err != nil {
		return nil, err
	}
	if err := checkImageName(dirfd, fd, v.ImageName, path); err != nil {
		return nil, err
	}
	if err := checkOpenImage(fd, path, o.Size); err != nil {
		return nil, err
	}
	ok = true
	return img, nil
}

// checkOpenImage runs every check an open image must pass and returns the
// first failure.
func checkOpenImage(fd int, path string, want int64) error {
	size, err := checkImage(fd, path)
	if err != nil {
		return err
	}
	return checkExistingSize(size, want, path)
}

// openImageFile returns the image name beneath dirfd, open read-write. It
// opens an existing file through the checked openat2 path, and when there is
// none, creates the image with createImage. A name that appears between the
// failed open and the publish is opened instead, and a name that vanishes
// between the publish race and that open is created again, within
// openRetries.
func openImageFile(dirfd int, name, path string, o imageOptions) (int, error) {
	var err error
	for i := 0; i < openRetries; i++ {
		var fd int
		fd, err = openExistingImage(dirfd, name)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return -1, fmt.Errorf("opening volume image %s: %w%s", path, err, symlinkHint(err))
		}
		fd, err = createImage(dirfd, name, path, o)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, errImageAppeared) {
			return -1, err
		}
	}
	return -1, fmt.Errorf("opening volume image %s: %w", path, err)
}

// imageOpenResolve and imageOpenFlags are how every image file is opened:
// beneath the volume root, on the same mount, following no link, and without
// blocking on a FIFO.
const (
	imageOpenResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS |
		unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV
	imageOpenFlags = unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
)

// openExistingImage opens name beneath dirfd without creating it.
func openExistingImage(dirfd int, name string) (int, error) {
	return openat2Retry(dirfd, name, &unix.OpenHow{Flags: imageOpenFlags, Resolve: imageOpenResolve})
}

// errImageAppeared reports that another launch, or a co-bound app, published
// the image name first. createImage has already cleaned up after itself.
var errImageAppeared = errors.New("volume image appeared while this launch created it")

// createImage makes a new image and publishes it under name. It creates a
// file with a name nothing else uses, `.rvm-disk-<random>.tmp`, in the same
// directory with O_CREAT|O_EXCL and mode 0600, sizes it to o.Size with
// ftruncate, syncs it, and moves it to name with renameat2(RENAME_NOREPLACE).
// It returns the open file, which is still the one now at name. The published
// name therefore never refers to an unsized file, and a launch killed at any
// point leaves at worst a temp file. Nothing opens, trusts, or reuses a temp
// file, but a leftover one holds up to the image size of quota on a volume
// whose quota counts file length, until an operator deletes it.
//
// When name exists already, the rename fails with EEXIST and createImage
// returns errImageAppeared, after removing its own temp file, so that the
// caller opens the existing image through the normal checked path. A
// filesystem without RENAME_NOREPLACE fails the launch rather than risk
// replacing an image.
//
// Only this launch's own temp file is ever removed, and only while its name
// still refers to the file this launch created (removeOwnTemp). The
// published name is never removed.
func createImage(dirfd int, name, path string, o imageOptions) (int, error) {
	tempName, fd, err := createTempImage(dirfd)
	if err != nil {
		return -1, fmt.Errorf("creating volume image %s: %w%s", path, err, symlinkHint(err))
	}
	discard := func() {
		removeOwnTemp(dirfd, fd, tempName)
		unix.Close(fd)
	}
	fail := func(err error) (int, error) {
		discard()
		return -1, err
	}
	if err := sizeNewImage(fd, path, o.Size); err != nil {
		return fail(err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fail(fmt.Errorf("creating volume image %s: syncing it: %w", path, err))
	}
	if o.afterTempCreate != nil {
		o.afterTempCreate(dirfd, tempName)
	}
	publish := o.rename
	if publish == nil {
		publish = renameNoReplace
	}
	switch err := publish(dirfd, tempName, name); {
	case err == nil:
		return fd, nil
	case errors.Is(err, unix.EEXIST):
		discard()
		return -1, errImageAppeared
	default:
		return fail(fmt.Errorf("creating volume image %s: publishing it: %w%s", path, err, renameHint(err)))
	}
}

// renameNoReplace moves oldName to newName in dirfd, failing with EEXIST when
// newName exists, retrying when a signal interrupted it.
func renameNoReplace(dirfd int, oldName, newName string) error {
	for {
		err := unix.Renameat2(dirfd, oldName, dirfd, newName, unix.RENAME_NOREPLACE)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// renameHint explains the errno renameat2 returns on a filesystem that does
// not support RENAME_NOREPLACE.
func renameHint(err error) string {
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
		return " (the volume does not support renameat2 with RENAME_NOREPLACE)"
	}
	return ""
}

// createTempImage creates a new empty file in dirfd under a unique temp name,
// exclusively and with mode 0600, and returns its name and open file. A
// random name that is taken is drawn again, within openRetries.
func createTempImage(dirfd int) (string, int, error) {
	var err error
	for i := 0; i < openRetries; i++ {
		var tempName string
		if tempName, err = newTempName(); err != nil {
			return "", -1, err
		}
		var fd int
		fd, err = openat2Retry(dirfd, tempName, &unix.OpenHow{
			Flags: imageOpenFlags | unix.O_CREAT | unix.O_EXCL, Mode: imageMode, Resolve: imageOpenResolve,
		})
		if err == nil {
			return tempName, fd, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", -1, err
		}
	}
	return "", -1, err
}

// newTempName returns a fresh temp file name for a new image.
func newTempName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("drawing a temp file name: %w", err)
	}
	return tempPrefix + hex.EncodeToString(b[:]) + tempSuffix, nil
}

// removeOwnTemp unlinks tempName in dirfd when it still refers to the file
// fd, which this launch created, and does nothing otherwise. The comparison
// by device and inode, without following a symbolic link, keeps it from
// removing a file that a co-bound app moved to the name in the meantime. A
// failure is ignored: the launch is already failing, and an operator can
// delete a leftover temp file.
func removeOwnTemp(dirfd, fd int, tempName string) {
	if checkImageName(dirfd, fd, tempName, tempName) != nil {
		return
	}
	_ = unix.Unlinkat(dirfd, tempName, 0)
}

// sizeNewImage truncates a file this launch created to size, which leaves it
// sparse, and confirms that the filesystem kept the size. On a volume whose
// quota counts file length, the truncate charges the whole size, so a quota
// error here is an ordinary failure to create the image. The file checked is
// still the temp file, so a failed check is reported by newImageCheckError.
func sizeNewImage(fd int, path string, size int64) error {
	if err := unix.Ftruncate(fd, size); err != nil {
		return fmt.Errorf("creating volume image %s: %w", path, err)
	}
	got, err := checkImage(fd, path)
	if err != nil {
		return newImageCheckError(path, err)
	}
	if got != size {
		return &volumeError{kind: errImageSize,
			msg: fmt.Sprintf("creating volume image %s: size is %d after sizing it to %d", path, got, size)}
	}
	return nil
}

// newImageCheckError reports a check that failed on the new temp file. The
// image name does not exist yet, so the message says that the new file failed
// and, for an owner or mode, that the volume may be forcing them, as a FUSE
// mount can. The error keeps the kind of the failed check.
func newImageCheckError(path string, err error) error {
	hint := ""
	if errors.Is(err, errImageOwner) || errors.Is(err, errImageMode) {
		hint = "; the volume may force file owners or modes"
	}
	var ve *volumeError
	if errors.As(err, &ve) {
		return &volumeError{kind: ve.kind, cause: err,
			msg: fmt.Sprintf("creating volume image %s: the new file failed a check: %v%s", path, err, hint)}
	}
	return fmt.Errorf("creating volume image %s: the new file failed a check: %w%s", path, err, hint)
}

// checkImageName checks that name in dirfd still refers to the file fd, by
// comparing device and inode without following a symbolic link at the name.
func checkImageName(dirfd, fd int, name, path string) error {
	var byName, byFD unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &byName, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &volumeError{kind: errImageReplaced, cause: err,
			msg: fmt.Sprintf("volume image %s: cannot tell whether the name still refers to the locked file: %v", path, err)}
	}
	if err := unix.Fstat(fd, &byFD); err != nil {
		return &volumeError{kind: errImageReplaced, cause: err,
			msg: fmt.Sprintf("volume image %s: fstat: %v", path, err)}
	}
	if byName.Dev != byFD.Dev || byName.Ino != byFD.Ino {
		return &volumeError{kind: errImageReplaced,
			msg: fmt.Sprintf("volume image %s: was deleted or replaced while this instance waited for its lock; start again", path)}
	}
	return nil
}

// checkExistingSize rejects an image that is not exactly want bytes, which
// vm-launch never resizes. An image of size 0 is rejected like any other
// wrong size: vm-launch publishes an image only after sizing it.
func checkExistingSize(size, want int64, path string) error {
	switch {
	case size%imageSectorSize != 0:
		return &volumeError{kind: errImageSize,
			msg: fmt.Sprintf("volume image %s: size %d is not a multiple of %d", path, size, imageSectorSize)}
	case size == want:
		return nil
	}
	return &volumeError{kind: errImageSize,
		msg: fmt.Sprintf("volume image %s: size %d, want %d; vm-launch resizes only an image it creates, so inspect or delete it", path, size, want)}
}

// checkImageRequest rejects a volume or options that openVolumeImage cannot
// use. volumeFromEnv already produces valid volumes; the volume is checked
// again because it decides which file vm-launch creates.
func checkImageRequest(v *guestVolume, o imageOptions) error {
	if v == nil {
		return errors.New("opening volume image: no volume")
	}
	if err := checkVolumeDir(v.ContainerDir); err != nil {
		return err
	}
	if n := v.ImageName; n == "" || n == "." || n == ".." || filepath.Base(n) != n {
		return fmt.Errorf("volume image name %s is not a plain file name", quoteForLog(n))
	}
	switch {
	case o.Size <= 0 || o.Size%imageSectorSize != 0:
		return fmt.Errorf("volume image size %d is not a positive multiple of %d", o.Size, imageSectorSize)
	case o.LockWait < 0:
		return fmt.Errorf("volume image lock wait %v is negative", o.LockWait)
	case o.LockPoll <= 0:
		return fmt.Errorf("volume image lock poll interval %v is not positive", o.LockPoll)
	case o.IsMountRoot == nil:
		return errors.New("volume image options have no mount root check")
	}
	return nil
}

// checkImage checks the open image fd and returns its size. It asks the
// filesystem for fresh attributes, because a FUSE volume may otherwise answer
// from a cache that another cell's write has made stale.
func checkImage(fd int, path string) (int64, error) {
	const need = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_NLINK | unix.STATX_UID | unix.STATX_SIZE
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_FORCE_SYNC, need, &st); err != nil {
		return 0, fmt.Errorf("volume image %s: statx: %w", path, err)
	}
	if st.Mask&need != need {
		return 0, fmt.Errorf("volume image %s: the filesystem did not report the image's type, mode, owner, links, and size", path)
	}
	mode := uint32(st.Mode)
	if mode&unix.S_IFMT != unix.S_IFREG {
		return 0, &volumeError{kind: errImageNotRegular,
			msg: fmt.Sprintf("volume image %s: not a regular file", path)}
	}
	if euid := os.Geteuid(); int64(st.Uid) != int64(euid) {
		return 0, &volumeError{kind: errImageOwner,
			msg: fmt.Sprintf("volume image %s: owned by uid %d, not by uid %d that runs the app", path, st.Uid, euid)}
	}
	if n := uint64(st.Nlink); n != 1 {
		return 0, &volumeError{kind: errImageLinks,
			msg: fmt.Sprintf("volume image %s: has %d links, want 1", path, n)}
	}
	if perm := mode & 0o7777; perm != imageMode {
		return 0, &volumeError{kind: errImageMode,
			msg: fmt.Sprintf("volume image %s: mode %04o, want %04o", path, perm, imageMode)}
	}
	if st.Size > 1<<62 {
		return 0, &volumeError{kind: errImageSize,
			msg: fmt.Sprintf("volume image %s: unusable size %d", path, st.Size)}
	}
	return int64(st.Size), nil
}

// lockImage takes an exclusive flock on fd. It tries again every o.LockPoll
// until o.LockWait has passed, and stops early when a signal arrives.
func lockImage(fd int, path string, o imageOptions, sigs <-chan os.Signal) error {
	deadline := time.Now().Add(o.LockWait)
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, unix.EINTR):
			continue
		case !errors.Is(err, unix.EWOULDBLOCK):
			return fmt.Errorf("locking volume image %s: %w", path, err)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return &volumeError{kind: errVolumeInUse,
				msg: fmt.Sprintf("volume image %s is in use by another instance; VM backends allow one writer per image", path)}
		}
		wait := o.LockPoll
		if remaining < wait {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case sig := <-sigs:
			timer.Stop()
			return &signalledError{Sig: syscall.Signal(signalNumber(sig))}
		case <-timer.C:
		}
	}
}

// openat2Retry calls openat2, repeating it when the kernel was interrupted
// or, under RESOLVE_BENEATH, could not rule out a concurrent rename.
func openat2Retry(dirfd int, path string, how *unix.OpenHow) (int, error) {
	var err error
	for i := 0; i < openRetries; i++ {
		var fd int
		fd, err = unix.Openat2(dirfd, path, how)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.EINTR) && !errors.Is(err, unix.EAGAIN) {
			return -1, err
		}
	}
	return -1, err
}

// symlinkHint explains the errno openat2 returns for a symbolic link.
func symlinkHint(err error) string {
	switch {
	case errors.Is(err, unix.ELOOP):
		return " (vm-launch follows no symbolic links on the volume path)"
	case errors.Is(err, unix.EXDEV):
		return " (the image must be a file in the volume root itself)"
	}
	return ""
}

// statxMountRoot reports whether dirfd is the root of a mount. A kernel that
// does not report the attribute (before Linux 5.8) is an error, so the check
// fails closed.
func statxMountRoot(dirfd int) (bool, error) {
	var stx unix.Statx_t
	if err := unix.Statx(dirfd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_TYPE, &stx); err != nil {
		return false, fmt.Errorf("statx: %w", err)
	}
	if stx.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 {
		return false, errors.New("the kernel does not report mount points through statx")
	}
	return stx.Attributes&unix.STATX_ATTR_MOUNT_ROOT != 0, nil
}

// volumeExitCode is vm-launch's exit status for a volume failure: 128+N for
// a signal during the lock wait, 125 for every other error, and 0 for none.
func volumeExitCode(err error) int {
	if err == nil {
		return 0
	}
	var sig *signalledError
	if errors.As(err, &sig) {
		return 128 + int(sig.Sig)
	}
	return exitLaunchError
}
