//go:build linux

package main

import (
	"errors"
	"fmt"
	"math"

	"golang.org/x/sys/unix"
)

// The quota check of the file-image engine. A volume service bounds a volume
// with a quota, and the engine asks the filesystem for the space that is left
// before it writes anything, so that an image that cannot fit fails the start
// with one plain line instead of failing half way through its allocation.
//
// The space comes from fstatfs on the directory descriptor of the volume
// root: f_bavail times the fragment size (f_frsize, or f_bsize when the
// filesystem reports none). The lab shows what that holds on the filesystems
// a provider uses.
//
//   - A JuiceFS subdirectory mount with a directory quota reports the quota
//     as the filesystem: f_blocks is the quota, f_bavail is what is left of
//     it, and a sparse file is charged its whole length, so existing images
//     count as used. Without a quota it reports a synthetic 1 PiB. Both are
//     exact, and a quota that is short makes ftruncate fail with EDQUOT.
//   - An NFSv4 export reports its dataset quota with a 1 MiB fragment size,
//     so the fragment size and not 4096 must scale f_bavail. Space that was
//     freed shows up late, so a check right after a delete can be too strict.
//     A server that compresses zeros, or that does not reserve on ALLOCATE,
//     does not move f_bavail when the image is written, so the check there is
//     the free space at that moment and nothing more. The allocation stays the
//     authority for a refusal the check could not see.
//   - A filesystem that reports no blocks at all says nothing about its
//     space, so the check does not run on it and the allocation decides.

// quotaAdvice ends every line about a volume that lacks the space.
const quotaAdvice = "lower its size in VM_VOLUMES or move the service to a larger plan"

// Kinds of quota failure. Both stop the launch with exit status 125.
var (
	// errVolumeFull is the check's refusal: the volume has less free space
	// than the operation adds.
	errVolumeFull = errors.New("volume has too little free space")
	// errQuotaRefused is the allocation's refusal: ftruncate, fallocate, a
	// zero write, or a sync failed with EDQUOT or ENOSPC.
	errQuotaRefused = errors.New("volume quota refused the allocation")
)

// volumeSpace is the space a filesystem reports, in bytes.
type volumeSpace struct {
	free, total int64
}

// spaceOp is one creation or grow of an image, as the quota check and the
// allocation failure report it.
type spaceOp struct {
	// dirfd is the descriptor of the volume root, which fstatfs asks.
	dirfd int
	// volume and image are the quoted names in the lines.
	volume, image string
	// what is the operation in words, such as `growing image "x" from 1 GiB
	// to 2 GiB`, and need is the bytes it adds to the volume.
	what string
	need int64
}

// growOp describes the grow of an image from size to want bytes.
func growOp(t growTarget, size, want int64) spaceOp {
	return spaceOp{
		dirfd: t.dirfd, volume: t.volume, image: t.image,
		what: fmt.Sprintf("growing image %s from %s to %s", t.image, roughSize(size), exactSize(want)),
		need: want - size,
	}
}

// createOp describes the creation of an image of size bytes.
func createOp(t growTarget, size int64) spaceOp {
	return spaceOp{
		dirfd: t.dirfd, volume: t.volume, image: t.image,
		what: fmt.Sprintf("creating image %s at %s", t.image, exactSize(size)),
		need: size,
	}
}

// fragmentBytes multiplies a count of fragments by the fragment size and
// saturates at the largest int64, which no volume reaches.
func fragmentBytes(count uint64, size int64) int64 {
	if count > uint64(math.MaxInt64)/uint64(size) {
		return math.MaxInt64
	}
	return int64(count * uint64(size))
}

// readVolumeSpace asks the filesystem of the descriptor for its space. ok is
// false when the filesystem reports nothing a check can use, either because it
// has no fstatfs or because it reports no blocks, and the caller then leaves
// the decision to the allocation. A failure other than those is an error: a
// volume whose statfs fails, as a stale NFS handle does, cannot be trusted
// with an image either.
func readVolumeSpace(fd int, o imageOptions) (space volumeSpace, ok bool, err error) {
	call := o.fstatfs
	if call == nil {
		call = unix.Fstatfs
	}
	var st unix.Statfs_t
	for {
		err = call(fd, &st)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	switch {
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EOPNOTSUPP):
		return volumeSpace{}, false, nil
	case err != nil:
		return volumeSpace{}, false, err
	}
	unit := st.Frsize
	if unit <= 0 {
		unit = st.Bsize
	}
	if unit <= 0 || st.Blocks == 0 {
		return volumeSpace{}, false, nil
	}
	return volumeSpace{
		free:  fragmentBytes(st.Bavail, unit),
		total: fragmentBytes(st.Blocks, unit),
	}, true, nil
}

// String says how much of the volume is free, such as "7.5 GiB free of
// 10 GiB".
func (s volumeSpace) String() string {
	return fmt.Sprintf("%s free of %s", roughSize(s.free), roughSize(s.total))
}

// checkSpace refuses an operation that adds more bytes than the volume has
// free, before anything is written. Equality is allowed, so a 1 GiB image
// fits a fresh 1 GiB volume. An operation that adds nothing is not checked.
func (o imageOptions) checkSpace(op spaceOp) error {
	if op.need <= 0 {
		return nil
	}
	space, ok, err := readVolumeSpace(op.dirfd, o)
	switch {
	case err != nil:
		return fmt.Errorf("volume %s: %s: checking the space the volume has free: %w", op.volume, op.what, err)
	case !ok:
		return nil
	case op.need <= space.free:
		return nil
	}
	return &volumeError{kind: errVolumeFull,
		msg: fmt.Sprintf("volume %s: %s needs %s, and the volume has %s; %s",
			op.volume, op.what, exactSize(op.need), space, quotaAdvice)}
}

// isQuotaErrno reports whether err is the volume's quota or space refusing an
// allocation: EDQUOT or ENOSPC.
func isQuotaErrno(err error) bool {
	return errors.Is(err, unix.EDQUOT) || errors.Is(err, unix.ENOSPC)
}

// quotaRefusal turns an allocation failure into the quota line, which has the
// words of the check's line with the volume's refusal in place of its free
// space. It keeps cause in the chain, so errors.Is still finds EDQUOT or
// ENOSPC. stays says what the volume holds afterwards. The free space is read
// again, because the allocation and other writers have used some of it since
// the check, and is left out when the volume reports none. The reason in the
// line is the quota's errno, even when cause also holds another one, as a
// zero write that failed with EIO before a sync that failed with EDQUOT does.
func (o imageOptions) quotaRefusal(op spaceOp, cause error, stays string) error {
	reason := cause.Error()
	var errno unix.Errno
	switch {
	case errors.Is(cause, unix.EDQUOT):
		reason = unix.EDQUOT.Error()
	case errors.Is(cause, unix.ENOSPC):
		reason = unix.ENOSPC.Error()
	case errors.As(cause, &errno):
		reason = errno.Error()
	}
	msg := fmt.Sprintf("volume %s: %s needs %s, and the volume's quota refused it (%s)",
		op.volume, op.what, exactSize(op.need), reason)
	if space, ok, err := readVolumeSpace(op.dirfd, o); err == nil && ok {
		msg += fmt.Sprintf("; the volume has %s", space)
	}
	msg += "; " + quotaAdvice + "; " + stays
	return &volumeError{kind: errQuotaRefused, cause: cause, msg: msg}
}

// creationFailure reports a failed step of an image's creation. A step that
// the volume's quota refused is reported in the quota line, and the temp file
// is gone by then, so the line says no image was created. Any other failure,
// and a signal, is returned as it is.
func (o imageOptions) creationFailure(op spaceOp, err error) error {
	if isQuotaErrno(err) {
		return o.quotaRefusal(op, err, "no image was created")
	}
	return err
}
