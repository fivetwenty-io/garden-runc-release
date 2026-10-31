//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
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
	// it is sized and published, with tempRandomBytes random bytes written as
	// hex between them. A launch killed in between leaves such a file behind.
	// Nothing ever opens, trusts, or reuses a temp file as an image. On a
	// volume whose quota counts file length it holds up to the image size of
	// quota until an operator deletes it, except on a volume that publishes by
	// link (publishLink), where the next launch removes it (sweepTempImages).
	tempPrefix      = ".rvm-disk-"
	tempSuffix      = ".tmp"
	tempRandomBytes = 8

	// openRetries bounds retries of an openat2 that the kernel interrupted or
	// asked to repeat because of a concurrent rename.
	openRetries = 8

	// zeroChunk is the size of one write when preallocation has to write
	// zeros, and syncInterval is how many bytes it writes between fsyncs.
	zeroChunk    = 1 << 20
	syncInterval = 256 << 20
)

// imageOptions are the parameters of openVolumeImage. Tests shorten the
// waits and replace the mount root check, which needs a real mount.
type imageOptions struct {
	Size        int64
	LockWait    time.Duration
	LockPoll    time.Duration
	IsMountRoot func(dirfd int) (bool, error)

	// Preallocate makes a new image allocate its whole range before it is
	// sized, for a volume whose quota counts allocated blocks, as an NFS
	// server's does. A sparse image there would pass its creation and meet
	// the quota later, inside the guest, as an I/O error. A volume whose
	// quota counts file length, as JuiceFS's does, leaves it off.
	Preallocate bool

	// fallocate, when set, replaces fallocate(2) as the step that allocates a
	// range. Tests use it to answer as an NFS 4.1 mount does.
	fallocate func(fd int, mode uint32, off, length int64) error

	// syncFile, when set, replaces fsync(2) between zero writes.
	syncFile func(fd int) error

	// afterZeroChunk, when set, runs after each chunk of zeros is written,
	// with the image's length so far. Tests use it to send a signal part way.
	afterZeroChunk func(end int64)

	// afterTempCreate, when set, runs once a new image is sized and before it
	// is published. Tests use it to act as a co-bound app would.
	afterTempCreate func(dirfd int, tempName string)

	// Publish is how a new image gets its name. The zero value, publishRename,
	// is what JuiceFS needs. The NFS provider sets publishLink.
	Publish publishStrategy

	// rename, when set, replaces renameNoReplace as the step that publishes a
	// new image under publishRename. Tests use it to fail the publish while the
	// temp file exists.
	rename func(dirfd int, oldName, newName string) error

	// link, when set, replaces linkNoReplace as the step that publishes a new
	// image under publishLink.
	link func(dirfd int, oldName, newName string) error

	// pwrite, when set, replaces pwriteFull as the step that writes one chunk
	// of zeros. Tests use it to fail a write part way through the range.
	pwrite func(fd int, b []byte, off int64) error
}

// publishStrategy is how createImage moves a finished temp file to the
// image's name without ever replacing an image another launch published.
type publishStrategy int

const (
	// publishRename moves the temp file with renameat2(RENAME_NOREPLACE), which
	// is atomic and leaves the image with one link. The Linux NFS client
	// refuses renameat2 with any flag, so a volume that is NFS cannot use it.
	publishRename publishStrategy = iota

	// publishLink gives the temp file the image's name with linkat, which
	// fails with EEXIST when the name exists on every filesystem that has hard
	// links, NFS included, and then removes the temp name. The file is closed
	// before its name is unlinked, because an NFS client turns the unlink of a
	// name that is still open into a silly rename to a hidden .nfs file. A launch killed
	// between the link and the unlink leaves a second link to a published
	// image, which sweepTempImages removes on the next launch.
	publishLink
)

// String names the strategy for a message.
func (p publishStrategy) String() string {
	switch p {
	case publishRename:
		return "rename"
	case publishLink:
		return "link"
	}
	return fmt.Sprintf("publish strategy %d", int(p))
}

// The system calls that publish and remove names, as variables so that specs
// can show which of them a strategy makes.
var (
	renameat2Call = unix.Renameat2
	linkatCall    = unix.Linkat
	unlinkatCall  = unix.Unlinkat
)

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
	errMountChanged    = errors.New("volume mount changed during start")
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

// signalledError reports a SIGTERM or SIGINT that arrived during a step
// before the guest started, such as waiting for the image lock.
type signalledError struct {
	Sig    syscall.Signal
	during string
}

func (e *signalledError) Error() string {
	return fmt.Sprintf("received %v while %s", e.Sig, e.during)
}

// openVolumeImage opens, and creates when missing, the image of v in the
// root of its volume, and returns it locked for the life of the returned
// file and of every process that inherits it.
//
// The volume path is resolved without following any symbolic link and must
// be a mount point, so that the image cannot land on the container's
// ephemeral disk or outside the volume. When v carries the ID of the mount
// that was inspected before (MountIDKnown), the directory opened here must be
// on that mount, or the launch stops: the path was resolved a second time,
// and a mount could have changed in between. The image is opened beneath it on
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
// charges all of it, and with Preallocate the whole range is allocated first),
// synced, and only then published under its name, with
// renameat2(RENAME_NOREPLACE) or, for Publish set to publishLink, with a hard
// link, so the published name never refers to an unsized file, whatever
// happens to this launch. See createImage. Under publishLink, a temp name that
// an earlier launch left behind is removed first (sweepTempImages).
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

	// The directory opened here is a second resolution of the path that was
	// inspected before. When the caller says which mount it inspected, the
	// directory must be on that mount.
	if v.MountIDKnown {
		probe, err := dirProbe(dirfd, v.ContainerDir)
		switch {
		case err != nil:
			return nil, fmt.Errorf("checking the mount of volume %s: %w", v.ContainerDir, err)
		case probe.MountID != v.MountID:
			return nil, &volumeError{kind: errMountChanged,
				msg: fmt.Sprintf("the mount of volume %s changed during start: it was mount ID %d when vm-launch inspected it and is mount ID %d now",
					v.ContainerDir, v.MountID, probe.MountID)}
		}
	}

	root, err := o.IsMountRoot(dirfd)
	switch {
	case err != nil:
		return nil, notMountRootError(v.ContainerDir, err)
	case !root:
		return nil, notMountRootError(v.ContainerDir, nil)
	}

	if o.Publish == publishLink {
		sweepTempImages(dirfd)
	}

	// The umask must not take the owner's bits away from a new image: the
	// hypervisor reopens it read-write through /proc/self/fd, which checks
	// them, and a new image without them would fail every later launch.
	oldMask := unix.Umask(0o077)
	fd, err := openImageFile(dirfd, v.ImageName, path, o, sigs)
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
// between the publish race and that open, or a temp file that a sweep removed
// during the creation, is created again, within openRetries. A signal on sigs
// stops the creation while it preallocates.
func openImageFile(dirfd int, name, path string, o imageOptions, sigs <-chan os.Signal) (int, error) {
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
		fd, err = createImage(dirfd, name, path, o, sigs)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, errImageAppeared) && !errors.Is(err, errCreateAgain) {
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

// errCreateAgain reports that the creation found its temp file or the new
// image removed by another party, which only a concurrent launch's sweep or an
// operator does. createImage has already cleaned up after itself, and the
// caller creates the image again.
var errCreateAgain = errors.New("the new volume image's temp file was removed while this launch created it")

// createImage makes a new image and publishes it under name. It creates a
// file with a name nothing else uses, `.rvm-disk-<random>.tmp`, in the same
// directory with O_CREAT|O_EXCL and mode 0600, sizes it to o.Size with
// ftruncate (after allocating the range, when o.Preallocate asks for it),
// syncs it, and moves it to name with renameat2(RENAME_NOREPLACE), or, for
// o.Publish set to publishLink, by link (createImageByLink).
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
// published name is never removed. A signal on sigs during preallocation
// removes the temp file and returns the signal's error.
func createImage(dirfd int, name, path string, o imageOptions, sigs <-chan os.Signal) (int, error) {
	if o.Publish == publishLink {
		return createImageByLink(dirfd, name, path, o, sigs)
	}
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
	if err := sizeNewImage(fd, path, o, sigs); err != nil {
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
		err := renameat2Call(dirfd, oldName, dirfd, newName, unix.RENAME_NOREPLACE)
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

// createImageByLink is createImage for a volume that cannot publish with
// renameat2(RENAME_NOREPLACE), such as a kernel NFS mount. It runs these steps
// in this order:
//
//  1. It creates the temp file with O_EXCL, takes an exclusive flock on it
//     that lasts while the file is open, and checks that the temp name still
//     refers to the file. The lock tells a concurrent launch's sweep
//     (sweepTempImages) that a live launch owns the file.
//  2. It sizes the file (after allocating the range, when o.Preallocate asks
//     for it) and syncs it.
//  3. It closes the file.
//  4. It gives the file the image's name with linkat, which fails with EEXIST
//     when another launch published first. EEXIST removes the temp name and
//     returns errImageAppeared, so the caller uses that launch's image.
//  5. It unlinks the temp name. The file is closed by now, so an NFS client
//     has no open name to turn into a silly rename.
//  6. It opens the image by its name, and returns that file.
//
// No step unlinks a name that this process still has open. A launch killed
// before step 4 leaves a temp file with one link, and one killed between
// steps 4 and 5 leaves a second link to the published image. The next launch
// removes either one (sweepTempImages), and neither is ever mistaken for the
// image: the image's own name is never unlinked, and a published image that
// has two links fails checkImage until the sweep has run.
//
// A failure in steps 1 to 3 removes the temp file, after closing it. A signal
// during preallocation does the same and returns the signal's error. A temp
// file that a concurrent sweep removed between steps 1 and 4 returns
// errCreateAgain.
func createImageByLink(dirfd int, name, path string, o imageOptions, sigs <-chan os.Signal) (int, error) {
	tempName, fd, err := createTempImage(dirfd)
	if err != nil {
		return -1, fmt.Errorf("creating volume image %s: %w%s", path, err, symlinkHint(err))
	}
	var id unix.Stat_t
	if err := unix.Fstat(fd, &id); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("creating volume image %s: fstat of the new file: %w", path, err)
	}
	// Whatever the outcome, the file is closed before its name is unlinked.
	discard := func() {
		unix.Close(fd)
		removeTempByID(dirfd, tempName, &id)
	}
	fail := func(err error) (int, error) {
		discard()
		return -1, err
	}

	switch err := lockTempImage(fd); {
	case errors.Is(err, unix.EWOULDBLOCK):
		// A sweep holds the brand new file. It is about to remove it.
		unix.Close(fd)
		return -1, errCreateAgain
	case err != nil:
		return fail(fmt.Errorf("creating volume image %s: locking the new file: %w", path, err))
	}
	if checkImageName(dirfd, fd, tempName, tempName) != nil {
		unix.Close(fd)
		return -1, errCreateAgain
	}
	if err := sizeNewImage(fd, path, o, sigs); err != nil {
		return fail(err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fail(fmt.Errorf("creating volume image %s: syncing it: %w%s", path, err, quotaHint(err)))
	}
	if o.afterTempCreate != nil {
		o.afterTempCreate(dirfd, tempName)
	}
	if err := unix.Close(fd); err != nil {
		removeTempByID(dirfd, tempName, &id)
		return -1, fmt.Errorf("creating volume image %s: closing the new file: %w%s", path, err, quotaHint(err))
	}

	publish := o.link
	if publish == nil {
		publish = linkNoReplace
	}
	switch err := publish(dirfd, tempName, name); {
	case err == nil:
	case errors.Is(err, unix.EEXIST):
		removeTempByID(dirfd, tempName, &id)
		return -1, errImageAppeared
	case errors.Is(err, unix.ENOENT):
		return -1, errCreateAgain
	default:
		removeTempByID(dirfd, tempName, &id)
		return -1, fmt.Errorf("creating volume image %s: publishing it: %w%s", path, err, linkHint(err))
	}

	if err := unlinkTempName(dirfd, tempName); err != nil {
		return -1, fmt.Errorf("creating volume image %s: published it, but could not remove its temp name %s: %w; the next launch removes it",
			path, tempName, err)
	}
	img, err := openExistingImage(dirfd, name)
	switch {
	case errors.Is(err, unix.ENOENT):
		return -1, errCreateAgain
	case err != nil:
		return -1, fmt.Errorf("opening volume image %s: %w%s", path, err, symlinkHint(err))
	}
	return img, nil
}

// lockTempImage takes an exclusive flock on the new temp file without
// waiting, repeating after an interrupt. It fails with EWOULDBLOCK when
// another open file holds the lock.
func lockTempImage(fd int) error {
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// linkNoReplace gives oldName in dirfd the name newName with linkat, failing
// with EEXIST when newName exists, retrying when a signal interrupted it.
func linkNoReplace(dirfd int, oldName, newName string) error {
	for {
		err := linkatCall(dirfd, oldName, dirfd, newName, 0)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// linkHint explains the errno linkat returns on a filesystem that does not
// support hard links.
func linkHint(err error) string {
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) {
		return " (the volume does not support hard links)"
	}
	return ""
}

// unlinkTempName unlinks the temp name tempName in dirfd, repeating after an
// interrupt. A name that is already gone counts as removed, because a
// concurrent launch's sweep removes the second link of a published image.
func unlinkTempName(dirfd int, tempName string) error {
	for {
		err := unlinkatCall(dirfd, tempName, 0)
		switch {
		case errors.Is(err, unix.EINTR):
		case err == nil, errors.Is(err, unix.ENOENT):
			return nil
		default:
			return err
		}
	}
}

// removeTempByID unlinks tempName in dirfd when it still refers to the file
// with the device and inode of id, which the caller has closed, and does
// nothing otherwise. It compares without following a symbolic link, so a file
// that another party moved to the name stays. A failure is ignored: the launch
// is already failing, or the sweep will try again.
func removeTempByID(dirfd int, tempName string, id *unix.Stat_t) {
	var byName unix.Stat_t
	if err := unix.Fstatat(dirfd, tempName, &byName, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return
	}
	if byName.Dev != id.Dev || byName.Ino != id.Ino {
		return
	}
	_ = unlinkatCall(dirfd, tempName, 0)
}

// sweepTempImages removes the temp names that earlier launches left in the
// volume root, for a volume that publishes by link. Two things need removing.
// A temp file with one link is the work of a launch that was killed before it
// published, and a temp file with two or more links is the second name of an
// image that a launch published and was killed before it removed the name.
// The second case would fail checkImage on the image until the name is gone.
//
// It touches only a name that matches tempNamePattern exactly, that is a
// regular file owned by vm-launch's effective uid, and that it opens without
// following a link. It removes a temp file with one link only when it can take
// an exclusive flock on it, because a launch that is creating an image holds
// that lock on its temp file until it has closed it (createImageByLink). The
// lock is released before the name is removed, so that an NFS client does not
// silly-rename a name that is open here, and the name is removed only while it
// still refers to the file that was checked. Removing a second name never
// removes the image, because the image keeps its own name. The sweep is best
// effort: a name it cannot open, lock, or remove stays, and the next launch
// tries again.
func sweepTempImages(dirfd int) {
	dfd, err := openat2Retry(dirfd, ".", &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: imageOpenResolve,
	})
	if err != nil {
		return
	}
	dir := os.NewFile(uintptr(dfd), "volume root")
	names, err := dir.Readdirnames(-1)
	dir.Close()
	if err != nil {
		return
	}
	for _, name := range names {
		if tempNamePattern.MatchString(name) {
			sweepTempName(dirfd, name)
		}
	}
}

// freshLinkCount returns the link count of the open file fd, asking the
// filesystem for fresh attributes, because an NFS client may otherwise answer
// from a cache that another cell's link or unlink has made stale.
func freshLinkCount(fd int) (uint32, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_FORCE_SYNC, unix.STATX_NLINK, &st); err != nil {
		return 0, err
	}
	if st.Mask&unix.STATX_NLINK == 0 {
		return 0, errors.New("the filesystem did not report the link count")
	}
	return st.Nlink, nil
}

// sweepTempName removes one temp name for sweepTempImages when it is an
// orphan or a second link, and leaves it otherwise.
func sweepTempName(dirfd int, name string) {
	fd, err := openat2Retry(dirfd, name, &unix.OpenHow{Flags: imageOpenFlags, Resolve: imageOpenResolve})
	if err != nil {
		return
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int64(st.Uid) != int64(os.Geteuid()) {
		unix.Close(fd)
		return
	}
	links, err := freshLinkCount(fd)
	if err != nil {
		unix.Close(fd)
		return
	}
	if links < 2 {
		if err := lockTempImage(fd); err != nil {
			unix.Close(fd)
			return
		}
	}
	unix.Close(fd)
	removeTempByID(dirfd, name, &st)
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
	var b [tempRandomBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("drawing a temp file name: %w", err)
	}
	return tempPrefix + hex.EncodeToString(b[:]) + tempSuffix, nil
}

// tempNamePattern matches exactly the names newTempName makes, and nothing
// else. Only a name that matches it is ever swept.
var tempNamePattern = regexp.MustCompile(`^` + regexp.QuoteMeta(tempPrefix) +
	`[0-9a-f]{` + fmt.Sprint(2*tempRandomBytes) + `}` + regexp.QuoteMeta(tempSuffix) + `$`)

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

// sizeNewImage sizes a file this launch created to o.Size and confirms that
// the filesystem kept the size. With o.Preallocate it first allocates the
// whole range (preallocateImage), so that a quota that counts allocated blocks
// refuses the image now; the truncate that follows then only sets the length.
// Without it the truncate leaves the file sparse, which on a volume whose quota
// counts file length still charges the whole size, so a quota error here is an
// ordinary failure to create the image. The file checked is still the temp
// file, so a failed check is reported by newImageCheckError. A signal during
// preallocation returns its *signalledError unwrapped.
func sizeNewImage(fd int, path string, o imageOptions, sigs <-chan os.Signal) error {
	if o.Preallocate {
		if err := preallocateImage(fd, path, 0, o.Size, o, sigs); err != nil {
			var sig *signalledError
			if errors.As(err, &sig) {
				return err
			}
			return fmt.Errorf("creating volume image %s: %w", path, err)
		}
	}
	if err := unix.Ftruncate(fd, o.Size); err != nil {
		return fmt.Errorf("creating volume image %s: %w", path, err)
	}
	got, err := checkImage(fd, path)
	if err != nil {
		return newImageCheckError(path, err)
	}
	if got != o.Size {
		return &volumeError{kind: errImageSize,
			msg: fmt.Sprintf("creating volume image %s: size is %d after sizing it to %d", path, got, o.Size)}
	}
	return nil
}

// preallocateImage allocates the range [from, to) of the open image fd, which
// must be exactly from bytes long, and leaves the image to bytes long when it
// returns without an error. It never reads the image and writes only zeros at
// or past its current end, so it cannot touch bytes the guest wrote.
//
// It first calls fallocate with mode 0 on the range. The NFS client accepts no
// other mode that allocates (it refuses FALLOC_FL_KEEP_SIZE), and a server
// with ALLOCATE refuses a range bigger than its quota. Mode 0 is safe here,
// because the range starts at the image's current end, so it only extends the
// file, as the truncate that follows does anyway. NFS 4.1 has no ALLOCATE, so
// when fallocate fails with EOPNOTSUPP it writes sequential zeroChunk chunks
// from from, which extend the image as they go, and fsyncs every syncInterval
// bytes and once at the end. glibc's posix_fallocate is not used, because its
// emulation is far slower. A signal on sigs, checked before each chunk, stops
// the writes at once, without a sync, and returns a *signalledError. A
// write or sync the quota refuses ends with that error and its hint. Either
// way the image is left part written, so the caller discards it; nothing
// resumes a part written image.
func preallocateImage(fd int, path string, from, to int64, o imageOptions, sigs <-chan os.Signal) error {
	if from < 0 || to < from || to > 1<<62 {
		return fmt.Errorf("preallocating volume image %s: the range %d to %d is not valid", path, from, to)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("preallocating volume image %s: fstat: %w", path, err)
	}
	if st.Size != from {
		return fmt.Errorf("preallocating volume image %s: the image is %d bytes, not the %d the range starts at; vm-launch writes zeros only past the current end", path, st.Size, from)
	}
	if to == from {
		return nil
	}

	call := o.fallocate
	if call == nil {
		call = func(fd int, mode uint32, off, length int64) error { return unix.Fallocate(fd, mode, off, length) }
	}
	var err error
	for {
		err = call(fd, 0, from, to-from)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	switch {
	case err == nil:
		return nil
	case !errors.Is(err, unix.EOPNOTSUPP):
		return fmt.Errorf("allocating %d bytes at offset %d: %w%s", to-from, from, err, quotaHint(err))
	}
	return writeZeros(fd, path, from, to, o, sigs)
}

// writeZeros extends the image fd from from to to with sequential writes of
// zeroChunk zero bytes, the last one shorter when the range is not a multiple
// of it. It writes at explicit offsets, so a retry never depends on the file
// position, and it syncs every syncInterval bytes. A signal returns at once,
// without a sync, because the caller discards the file.
func writeZeros(fd int, path string, from, to int64, o imageOptions, sigs <-chan os.Signal) error {
	syncFile := o.syncFile
	if syncFile == nil {
		syncFile = unix.Fsync
	}
	write := o.pwrite
	if write == nil {
		write = pwriteFull
	}
	zeros := make([]byte, zeroChunk)
	end, synced := from, from
	for end < to {
		select {
		case sig := <-sigs:
			return &signalledError{Sig: syscall.Signal(signalNumber(sig)), during: "preallocating the volume image"}
		default:
		}
		n := min(int64(len(zeros)), to-end)
		if err := write(fd, zeros[:n], end); err != nil {
			return fmt.Errorf("writing zeros at offset %d: %w%s", end, err, quotaHint(err))
		}
		end += n
		if o.afterZeroChunk != nil {
			o.afterZeroChunk(end)
		}
		if end-synced >= syncInterval {
			if err := syncFile(fd); err != nil {
				return fmt.Errorf("syncing the zeros written so far: %w%s", err, quotaHint(err))
			}
			synced = end
		}
	}
	if synced != end {
		if err := syncFile(fd); err != nil {
			return fmt.Errorf("syncing the zeros written so far: %w%s", err, quotaHint(err))
		}
	}
	return nil
}

// pwriteFull writes all of b at off, repeating after a short write or an
// interrupt. A write that makes no progress is an error.
func pwriteFull(fd int, b []byte, off int64) error {
	for len(b) > 0 {
		n, err := unix.Pwrite(fd, b, off)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case err != nil:
			return err
		case n <= 0:
			return io.ErrShortWrite
		}
		b, off = b[n:], off+int64(n)
	}
	return nil
}

// quotaHint says that a volume's quota is the cause of an out-of-space or
// over-quota errno, which is the likeliest reason a grow or an allocation
// fails on a shared volume.
func quotaHint(err error) string {
	if errors.Is(err, unix.EDQUOT) || errors.Is(err, unix.ENOSPC) {
		return " (the volume's quota refused it)"
	}
	return ""
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
	case o.Publish != publishRename && o.Publish != publishLink:
		return fmt.Errorf("volume image options have an unknown way to publish an image: %v", o.Publish)
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
			return &signalledError{Sig: syscall.Signal(signalNumber(sig)), during: "waiting for the volume image lock"}
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

// notMountRootError is the refusal of a volume directory that is not the
// root of a mount. cause is why the check could not tell, when it could not.
func notMountRootError(dir string, cause error) error {
	if cause != nil {
		return &volumeError{kind: errNotMountRoot, cause: cause,
			msg: fmt.Sprintf("volume %s is not a mount point: cannot tell: %v", dir, cause)}
	}
	return &volumeError{kind: errNotMountRoot, msg: fmt.Sprintf("volume %s is not a mount point", dir)}
}

// stepExitCode is vm-launch's exit status for a failed step before the
// guest starts, such as opening the volume image or resolving CredHub
// references: 128+N for a signal during the step, 125 for every other
// error, and 0 for none.
func stepExitCode(err error) int {
	if err == nil {
		return 0
	}
	var sig *signalledError
	if errors.As(err, &sig) {
		return 128 + int(sig.Sig)
	}
	return exitLaunchError
}
