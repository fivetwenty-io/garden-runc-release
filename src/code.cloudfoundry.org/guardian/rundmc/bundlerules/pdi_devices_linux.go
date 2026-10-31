package bundlerules

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"code.cloudfoundry.org/lager/v3"
	"golang.org/x/sys/unix"
)

// NewPDIDevices returns the block volume step for the host, with the default
// node, claim, sysfs, and mount table paths. tag is the Garden's --tag value,
// or empty, and it marks the claims that this Garden may release.
func NewPDIDevices(logger lager.Logger, kvmGid uint32, tag string) (*PDIDevices, error) {
	if kvmGid == 0 {
		return nil, errors.New("block volumes need the kvm gid, which is not configured")
	}
	if strings.Contains(tag, "\n") {
		return nil, errors.New("block volumes cannot record a tag that holds a newline")
	}
	return &PDIDevices{
		KVMGid:        kvmGid,
		Tag:           tag,
		NodeDir:       DefaultPDINodeDir,
		ClaimDir:      DefaultPDIClaimDir,
		SysfsDir:      "/sys",
		MountInfoPath: "/proc/self/mountinfo",
		ClaimWait:     DefaultPDIClaimWait,
		Host:          LinuxPDIHost{},
		Logger:        logger,
	}, nil
}

// NewPDILeftoverReleaser returns a block volume step that only releases, for
// a Garden that runs with block volumes turned off. Its Claim refuses every
// descriptor, and its Release and ReleaseUnknown remove the nodes and claims
// that this Garden's tag left when it last ran with block volumes on. It
// returns nil when the claim directory does not exist, because then there is
// nothing to release.
func NewPDILeftoverReleaser(logger lager.Logger, tag string) (*PDIDevices, error) {
	if strings.Contains(tag, "\n") {
		return nil, errors.New("block volumes cannot record a tag that holds a newline")
	}
	info, err := os.Lstat(DefaultPDIClaimDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("checking for block volume claims left by an earlier run: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory (%s)", DefaultPDIClaimDir, info.Mode().Type())
	}
	return &PDIDevices{
		Tag:           tag,
		NodeDir:       DefaultPDINodeDir,
		ClaimDir:      DefaultPDIClaimDir,
		SysfsDir:      "/sys",
		MountInfoPath: "/proc/self/mountinfo",
		Host:          LinuxPDIHost{},
		Logger:        logger,
	}, nil
}

// publishPDIClaim creates the claim file name in dir holding data, and fails
// with an error wrapping os.ErrExist when name already exists. The file is
// written in full as an unnamed file and then linked to its name, which fails
// if the name exists, so no other reader and no crash ever sees a partial
// claim. The link goes through /proc/self/fd, which works without the
// CAP_DAC_READ_SEARCH that linkat with AT_EMPTY_PATH needs.
func publishPDIClaim(dir, name string, data []byte) error {
	fd, err := unix.Open(dir, unix.O_TMPFILE|unix.O_WRONLY|unix.O_CLOEXEC, 0600)
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EISDIR) {
			return fmt.Errorf("the filesystem of %s cannot make an unnamed file (O_TMPFILE), which a claim needs: %w", dir, err)
		}
		return fmt.Errorf("creating a claim in %s: %w", dir, err)
	}
	defer unix.Close(fd)

	for rest := data; len(rest) > 0; {
		n, err := unix.Write(fd, rest)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("writing a claim in %s: %w", dir, err)
		}
		rest = rest[n:]
	}
	if err := unix.Fchmod(fd, 0600); err != nil {
		return fmt.Errorf("setting the mode of a claim in %s: %w", dir, err)
	}

	final := filepath.Join(dir, name)
	if err := unix.Linkat(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", fd), unix.AT_FDCWD, final, unix.AT_SYMLINK_FOLLOW); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%s: %w", final, os.ErrExist)
		}
		return fmt.Errorf("publishing %s: %w", final, err)
	}
	return nil
}

// LinuxPDIHost performs the device step's host operations with Linux system
// calls.
type LinuxPDIHost struct{}

type linuxPDISource struct {
	fd int
}

// OpenSource opens path with O_PATH, which follows links as the bind mount
// will and opens no device, FIFO, or file for I/O.
func (LinuxPDIHost) OpenSource(path string) (PDISource, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &linuxPDISource{fd: fd}, nil
}

func (s *linuxPDISource) MountID() (uint64, error) {
	var stx unix.Statx_t
	if err := unix.Statx(s.fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_SYNC_AS_STAT, unix.STATX_MNT_ID, &stx); err != nil {
		return 0, fmt.Errorf("statx: %w", err)
	}
	if stx.Mask&unix.STATX_MNT_ID == 0 {
		return 0, errors.New("the kernel did not report a mount ID")
	}
	return stx.Mnt_id, nil
}

func (s *linuxPDISource) ReadDescriptor() (PDIDescriptorFile, error) {
	fd, err := unix.Openat(s.fd, PDIDescriptorName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return PDIDescriptorFile{}, fmt.Errorf("%s is a symbolic link", PDIDescriptorName)
		}
		return PDIDescriptorFile{}, fmt.Errorf("opening %s: %w", PDIDescriptorName, err)
	}
	f := os.NewFile(uintptr(fd), PDIDescriptorName)
	defer f.Close()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return PDIDescriptorFile{}, fmt.Errorf("fstat %s: %w", PDIDescriptorName, err)
	}
	file := PDIDescriptorFile{
		Regular: st.Mode&unix.S_IFMT == unix.S_IFREG,
		UID:     st.Uid,
		Size:    st.Size,
	}
	if !file.Regular {
		return file, nil
	}

	data, err := io.ReadAll(io.LimitReader(f, PDIDescriptorSizeLimit+1))
	if err != nil {
		return PDIDescriptorFile{}, fmt.Errorf("reading %s: %w", PDIDescriptorName, err)
	}
	file.Data = data
	return file, nil
}

func (s *linuxPDISource) Close() error {
	return unix.Close(s.fd)
}

// Mknod creates the node, sets its owner and mode explicitly so that the
// process umask does not matter, and checks the result with lstat. A node it
// created and could not finish is removed again.
func (LinuxPDIHost) Mknod(path string, major, minor, gid uint32) error {
	dev := unix.Mkdev(major, minor)
	if err := unix.Mknod(path, unix.S_IFBLK|uint32(pdiNodeMode), int(dev)); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("mknod: %w", os.ErrExist)
		}
		return fmt.Errorf("mknod: %w", err)
	}

	finish := func() error {
		if err := unix.Fchownat(unix.AT_FDCWD, path, 0, int(gid), unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("chown: %w", err)
		}
		if err := unix.Fchmodat(unix.AT_FDCWD, path, uint32(pdiNodeMode), 0); err != nil {
			return fmt.Errorf("chmod: %w", err)
		}
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return fmt.Errorf("lstat: %w", err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFBLK || st.Rdev != dev || st.Uid != 0 || st.Gid != gid || st.Mode&0o7777 != uint32(pdiNodeMode) {
			return fmt.Errorf("the node is mode %o, device %d:%d, owner %d:%d", st.Mode, unix.Major(st.Rdev), unix.Minor(st.Rdev), st.Uid, st.Gid)
		}
		return nil
	}
	if err := finish(); err != nil {
		if rmErr := unix.Unlink(path); rmErr != nil && !errors.Is(rmErr, unix.ENOENT) {
			return errors.Join(err, fmt.Errorf("removing the unfinished node: %w", rmErr))
		}
		return err
	}
	return nil
}

// Probe opens the node read-write with O_EXCL, as vm-launch will. Linux fails
// that open with EBUSY while the device is mounted anywhere or claimed by
// another exclusive opener, which includes an app that holds it. It then
// reads the device size from that descriptor, so the size belongs to the very
// device that Garden opened.
func (LinuxPDIHost) Probe(path string, major, minor uint32, size int64) error {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("exclusive open: %w", err)
	}
	defer unix.Close(fd)

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("fstat: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK || st.Rdev != unix.Mkdev(major, minor) {
		return fmt.Errorf("the node is not block device %d:%d", major, minor)
	}

	var bytes uint64
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&bytes))); errno != 0 {
		return fmt.Errorf("BLKGETSIZE64: %w", errno)
	}
	if bytes > math.MaxInt64 || int64(bytes) != size {
		return fmt.Errorf("the device is %d bytes, and the descriptor says %d", bytes, size)
	}
	return nil
}

func (LinuxPDIHost) RemoveNode(path string, major, minor uint32) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK || st.Rdev != unix.Mkdev(major, minor) {
		return fmt.Errorf("%w: it is not block device %d:%d, so Garden leaves it in place", ErrPDIForeignNode, major, minor)
	}
	if err := unix.Unlink(path); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}
