//go:build linux

package main

import (
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The guest root image. The guest keeps its whole root, apart from the
// initramfs that lies under it, on a disk image that vm-launch creates in the
// work directory. The image is sized from the app's disk quota, so that the
// guest's own filesystem is what fills first, and is unlinked at once, so
// that nothing is left to clean up and the container's quota keeps charging
// its blocks until the hypervisor lets go of it.
const (
	rootDiskHeadroomMiB = 32
	minRootDiskMiB      = 16

	// rootDiskInodeRatio is the bytes of image for each inode that the guest
	// gives mke2fs. It doubles until the image holds at most maxRootDiskInodes
	// inodes, because mke2fs writes every inode table when it formats. Those
	// blocks count against the quota from the first second, and on Firecracker
	// each one is a first touch of guest memory, so 262144 inodes took about
	// 4.7 seconds to format where 65536 take about 1.1.
	rootDiskInodeRatio = 16384
	maxRootDiskInodes  = 65536

	// rootImageName is the root image's name while it has one.
	rootImageName = "root.img"

	bytesPerMiB = 1 << 20
)

// rootDiskSize returns the size in bytes of the guest root image, and the
// bytes per inode for its filesystem, for a container whose work directory
// is workDir. The size is the smaller of VCAP_APPLICATION limits.disk and
// the space statfs reports free in workDir, less rootDiskHeadroomMiB. The
// headroom is for other writers in the container, such as ssh sessions, so
// that the guest's filesystem fills before the quota does and the app gets
// ENOSPC rather than an I/O error. Both are cut to whole MiB. A size equal
// to volumeBytes, the volume image's, loses 1 MiB, so that the guest can
// tell the two drives apart by size.
//
// A size of 0 means the guest root stays in RAM, because limits.disk is
// missing or malformed and there is no quota to enforce; one line says so.
// Free space under minRootDiskMiB after the headroom, and a statfs that
// fails, are errors.
func rootDiskSize(workDir string, lookup func(string) (string, bool), statfs func(string, *unix.Statfs_t) error, volumeBytes int64, logger *log.Logger) (size, inodeRatio int64, err error) {
	limitMiB, err := diskLimitMiB(lookup)
	if err != nil {
		logger.Printf("%v; the disk quota does not apply to the guest root", err)
		return 0, 0, nil
	}
	var st unix.Statfs_t
	if err := statfs(workDir, &st); err != nil {
		return 0, 0, fmt.Errorf("checking the disk quota left in %s: %w", workDir, err)
	}
	quotaMiB := min(limitMiB, freeMiB(&st))
	size = (quotaMiB - rootDiskHeadroomMiB) * bytesPerMiB
	if size == volumeBytes {
		size -= bytesPerMiB
	}
	if size < minRootDiskMiB*bytesPerMiB {
		return 0, 0, fmt.Errorf("the container has %d MiB of disk quota left, and the guest root needs at least %d MiB of it, which is %d MiB plus %d MiB kept for other writers; raise the app's disk quota",
			quotaMiB, minRootDiskMiB+rootDiskHeadroomMiB, minRootDiskMiB, rootDiskHeadroomMiB)
	}
	return size, inodeRatioFor(size), nil
}

// freeMiB returns the whole MiB that an unprivileged writer can still add to
// the filesystem st describes. statfs counts blocks of f_frsize bytes, or of
// f_bsize when the filesystem leaves f_frsize unset. A count whose byte size
// overflows is capped at the largest size a file can have.
func freeMiB(st *unix.Statfs_t) int64 {
	unit := uint64(st.Frsize)
	if st.Frsize <= 0 {
		unit = uint64(st.Bsize)
	}
	if unit == 0 {
		return 0
	}
	if st.Bavail > math.MaxInt64/unit {
		return math.MaxInt64 / bytesPerMiB
	}
	return int64(st.Bavail*unit) / bytesPerMiB
}

// inodeRatioFor returns the bytes per inode for an image of size bytes:
// rootDiskInodeRatio, doubled until the image holds at most maxRootDiskInodes
// inodes.
func inodeRatioFor(size int64) int64 {
	ratio := int64(rootDiskInodeRatio)
	for size/ratio > maxRootDiskInodes {
		ratio *= 2
	}
	return ratio
}

// The file steps of createRootImage. Specs replace them.
var (
	truncateRootImage = func(f *os.File, size int64) error { return f.Truncate(size) }
	unlinkRootImage   = os.Remove
)

// createRootImage creates the guest root image in workDir, size bytes long
// and sparse, and returns it open for reading and writing. The file is
// created exclusively with mode 0600 and unlinked before it is sized, so it
// has no name once this returns and, with nothing in it yet, a launch that
// dies in between leaves an empty file at worst. The open file keeps its
// blocks, and the container's quota keeps charging them, until every holder
// closes it. The file is close-on-exec; the hypervisor gets its own copy as
// an extra file.
func createRootImage(workDir string, size int64) (*os.File, error) {
	if size <= 0 {
		return nil, fmt.Errorf("creating the guest root image in %s: the size %d is not positive", workDir, size)
	}
	path := filepath.Join(workDir, rootImageName)
	fail := func(err error) (*os.File, error) {
		return nil, fmt.Errorf("creating the guest root image in %s: %w", workDir, err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fail(err)
	}
	// An umask can take bits from the mode the file was created with.
	if err := f.Chmod(0o600); err != nil {
		// The launch is failing and removes workDir; the file is empty.
		f.Close()
		_ = unlinkRootImage(path)
		return fail(err)
	}
	if err := unlinkRootImage(path); err != nil {
		f.Close()
		return fail(err)
	}
	if err := truncateRootImage(f, size); err != nil {
		f.Close()
		return fail(fmt.Errorf("sizing it to %d bytes: %w", size, err))
	}
	return f, nil
}
