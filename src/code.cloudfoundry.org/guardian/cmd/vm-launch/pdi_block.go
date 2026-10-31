//go:build linux

package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Block mode. A volume driver in block mode never mounts the disk. It mounts
// a small tmpfs at the volume's mount point instead, with a source of "pdi:"
// and the driver's name, writes one file there that names the device, and
// remounts the tmpfs read-only. Only root on the cell can mount a filesystem,
// so an app cannot forge that source, and nothing can write through the
// read-only superblock. Garden, when the cell turns block volumes on, makes a
// device node for the disk at /dev/pdi/MAJOR-MINOR, owned root:kvm with mode
// 0660, and gives the VM container that node and a device cgroup rule for it.
//
// The block provider reads the descriptor through the volume directory,
// after it has checked that the directory is still the mount detection
// inspected, opens the node with O_RDWR|O_EXCL, and checks the device before
// the hypervisor gets it: its device number, its size from BLKGETSIZE64, and
// the ext4 superblock at byte 1024, which must have the ext4 magic, the
// descriptor's UUID, an internal journal, and no more blocks than the device
// holds. The UUID check means that a device number another disk reuses cannot
// send the guest to the wrong data. It cannot tell apart two disks cloned
// from one snapshot, which share a UUID.
// On Linux an exclusive open of a block device fails with EBUSY while the
// device is mounted or another process holds it exclusively, and while
// vm-launch holds it, a host mount of the device fails with EBUSY. vm-launch
// retries a busy device within the launch's shared lock wait, so a restart
// that overlaps the previous instance's VM on the same cell waits for it. The
// hypervisor inherits the open file, so the claim lasts until both have let
// go of it. Firecracker's identity for the drive comes from the node's own
// st_dev, st_rdev, and st_ino (see firecrackerDriveID), because the node is
// the file it opens.
//
// A device number names whichever disk has it now, so a disk that is detached
// and replaced by another under the same number would pass the node checks.
// Garden reads each disk's sequence number (diskseq, from Linux 5.15) when it
// grants the device and records it in the source of a tmpfs it mounts in the
// container (gardenDiskseqSource). vm-launch refuses a device whose
// BLKGETDISKSEQ on the exclusive descriptor differs from that record.
// The kernel gives every disk it attaches a higher number, so the check
// proves that vm-launch opened the disk Garden granted. It cannot reach a
// hypervisor that is already running when its disk is detached and another
// takes the number. That hypervisor still has the device node in the
// container, and only the kernel's exclusive hold of the new disk, by a host
// mount or another VM, stops it from opening the new disk again.

// The block-mode descriptor, which must match the bosh-disk driver's
// pkg/driver/descriptor.go in cf-bosh-disk-broker-release (DescriptorSource,
// DescriptorFileName, DescriptorVersion, and DescriptorSizeLimit).
const (
	// blockDescriptorSourcePrefix starts the source of every block-mode
	// descriptor tmpfs, and the volume service's name follows it.
	blockDescriptorSourcePrefix = "pdi:"
	// boshDiskDescriptorSource is the bosh-disk driver's source.
	boshDiskDescriptorSource = "pdi:bosh-disk"
	// blockDescriptorFileName is the one file in the tmpfs.
	blockDescriptorFileName = "device"
	// blockDescriptorVersion is the only format version vm-launch reads.
	blockDescriptorVersion = "1"
	// blockDescriptorSizeLimit bounds the file: a descriptor is always
	// shorter than this many bytes.
	blockDescriptorSizeLimit = 4096
	// blockDescriptorMode is the mode the driver gives the descriptor.
	blockDescriptorMode = 0o444

	tmpfsFSType = "tmpfs"
)

// blockNodeDir is the directory where Garden makes the device node of a
// block-mode volume, named MAJOR-MINOR.
const blockNodeDir = "/dev/pdi"

// The ext4 superblock fields the block provider checks. The superblock is
// 1024 bytes at byte 1024 of the device, little-endian.
const (
	ext4SuperblockOffset = 1024
	ext4SuperblockSize   = 1024

	ext4BlocksCountLoOffset = 0x04
	ext4LogBlockSizeOffset  = 0x18
	ext4MagicOffset         = 0x38
	ext4FeatureCompatOff    = 0x5c
	ext4FeatureIncompatOff  = 0x60
	ext4UUIDOffset          = 0x68
	ext4JournalInumOffset   = 0xe0
	ext4BlocksCountHiOffset = 0x150

	ext4Magic = 0xef53
	// ext4CompatHasJournal is COMPAT_HAS_JOURNAL.
	ext4CompatHasJournal = 0x4
	// ext4IncompatJournalDev is INCOMPAT_JOURNAL_DEV, which marks a device
	// that holds another filesystem's external journal and no filesystem.
	ext4IncompatJournalDev = 0x8
	// ext4Incompat64Bit is INCOMPAT_64BIT, without which the high word of
	// the block count is not used.
	ext4Incompat64Bit = 0x80
	// ext4MaxLogBlockSize is the largest s_log_block_size the kernel mounts:
	// a block size of 1024 << 6, or 64 KiB.
	ext4MaxLogBlockSize = 6
)

// blockBusyPoll is the first wait before vm-launch tries the exclusive open
// of a busy device again. Each wait after it doubles, up to lockPoll, so a
// device whose previous holder is about to exit is reached quickly.
const blockBusyPoll = 50 * time.Millisecond

// errBlockDeviceBusy is the kind of the refusal of a block device that is
// mounted or held open exclusively.
var errBlockDeviceBusy = errors.New("block device busy")

// blockDescriptorSources are the descriptor sources of the registered block
// providers. refuseBlockDescriptorMount refuses a "pdi:" source that is not
// one of them.
var blockDescriptorSources []string

func init() {
	registerBlockProvider(&blockProvider{
		name:    "BOSH disk",
		source:  boshDiskDescriptorSource,
		nodeDir: blockNodeDir,
		host:    linuxBlockHost{},
	})
	registerMountRefusal(refuseBlockDescriptorMount)
}

// registerBlockProvider registers p as a disk provider and records its
// descriptor source, so that a later cell-attached device that writes a
// descriptor of its own needs only another blockProvider.
func registerBlockProvider(p *blockProvider) {
	registerDiskProvider(p)
	blockDescriptorSources = append(blockDescriptorSources, p.source)
}

// blockHost is the system calls the block provider makes on the device node.
// The specs replace it to stand in for a block device without one.
type blockHost interface {
	// open opens path with flags, following no symbolic link.
	open(path string, flags int) (int, error)
	// fstat is fstat(2).
	fstat(fd int, st *unix.Stat_t) error
	// deviceBytes is the size of the open block device fd, from
	// BLKGETSIZE64.
	deviceBytes(fd int) (uint64, error)
	// diskSeq is the disk sequence number of the open block device fd, from
	// BLKGETDISKSEQ.
	diskSeq(fd int) (uint64, error)
}

// linuxBlockHost is the kernel.
type linuxBlockHost struct{}

func (linuxBlockHost) open(path string, flags int) (int, error) {
	return openat2Retry(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(flags),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
}

func (linuxBlockHost) fstat(fd int, st *unix.Stat_t) error {
	return retryEINTR(func() error { return unix.Fstat(fd, st) })
}

func (linuxBlockHost) deviceBytes(fd int) (uint64, error) {
	return ioctlBlockSize(fd)
}

func (linuxBlockHost) diskSeq(fd int) (uint64, error) {
	var seq uint64
	err := retryEINTR(func() error {
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.BLKGETDISKSEQ), uintptr(unsafe.Pointer(&seq)))
		if errno != 0 {
			return errno
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("BLKGETDISKSEQ: %w", err)
	}
	return seq, nil
}

// gardenDiskseqSource starts the source of the tmpfs that Garden mounts in a
// VM container with block volumes, and the disk sequence number of each block
// device it granted follows it, as MAJOR:MINOR=SEQ entries separated by
// commas. Only root can mount a filesystem, and the container has no
// CAP_SYS_ADMIN, so an app cannot add or change one. The environment would
// not do, because runc keeps the last of two entries with one name, and a
// process's own variables come after the bundle's.
const gardenDiskseqSource = "garden-pdi-diskseq:"

// diskseqMountInfo is the mount table that gardenDiskseq reads. The specs
// point it at a file.
var diskseqMountInfo = "/proc/self/mountinfo"

// gardenDiskseq returns the disk sequence number that Garden recorded for
// device major:minor. It is an error when no record mount is found, when
// there is more than one, when a record is malformed, and when it has no
// entry or more than one for the device.
func gardenDiskseq(major, minor uint32) (uint64, error) {
	record, err := gardenDiskseqRecord()
	if err != nil {
		return 0, err
	}
	want := strconv.FormatUint(uint64(major), 10) + ":" + strconv.FormatUint(uint64(minor), 10)
	var seq uint64
	found := false
	for _, entry := range strings.Split(record, ",") {
		numbers, value, ok := strings.Cut(entry, "=")
		if !ok {
			return 0, fmt.Errorf("%s entry %q is not MAJOR:MINOR=SEQ", gardenDiskseqSource, entry)
		}
		a, b, ok := strings.Cut(numbers, ":")
		if !ok {
			return 0, fmt.Errorf("%s entry %q is not MAJOR:MINOR=SEQ", gardenDiskseqSource, entry)
		}
		if _, err := parseDescriptorUint(a, 32); err != nil {
			return 0, fmt.Errorf("%s entry %q: major %w", gardenDiskseqSource, entry, err)
		}
		if _, err := parseDescriptorUint(b, 32); err != nil {
			return 0, fmt.Errorf("%s entry %q: minor %w", gardenDiskseqSource, entry, err)
		}
		v, err := parseDescriptorUint(value, 64)
		if err != nil {
			return 0, fmt.Errorf("%s entry %q: sequence number %w", gardenDiskseqSource, entry, err)
		}
		if v == 0 {
			return 0, fmt.Errorf("%s entry %q has sequence number 0, which no disk has", gardenDiskseqSource, entry)
		}
		if numbers != want {
			continue
		}
		if found {
			return 0, fmt.Errorf("%s names device %s more than once", gardenDiskseqSource, want)
		}
		seq, found = v, true
	}
	if !found {
		return 0, fmt.Errorf("%s has no entry for device %s, so Garden did not grant it to this container", gardenDiskseqSource, want)
	}
	return seq, nil
}

// gardenDiskseqRecord returns the entries of the one tmpfs in the mount table
// whose source starts with gardenDiskseqSource. A line that names the source
// and does not parse is refused rather than skipped.
func gardenDiskseqRecord() (string, error) {
	f, err := os.Open(diskseqMountInfo)
	if err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		return "", fmt.Errorf("reading %s to find the disks Garden granted: %w", diskseqMountInfo, err)
	}
	defer f.Close()
	var records []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, gardenDiskseqSource) {
			continue
		}
		rec, err := parseMountInfoRecord(line)
		if err != nil {
			return "", fmt.Errorf("a line of %s that names %s is malformed: %w", diskseqMountInfo, gardenDiskseqSource, err)
		}
		value, ok := strings.CutPrefix(rec.Source, gardenDiskseqSource)
		if !ok {
			continue
		}
		if rec.FSType != tmpfsFSType {
			return "", fmt.Errorf("the %s record at %s is a %s mount, and Garden makes it on tmpfs", gardenDiskseqSource, quoteForLog(rec.MountPoint), rec.FSType)
		}
		records = append(records, value)
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("reading %s to find the disks Garden granted: %w", diskseqMountInfo, err)
	}
	switch len(records) {
	case 0:
		return "", fmt.Errorf("the container has no %s mount, so this Garden did not record which disk it granted; block volumes need a Garden that records it", gardenDiskseqSource)
	case 1:
		return records[0], nil
	default:
		return "", fmt.Errorf("the container has %d %s mounts, and Garden makes one", len(records), gardenDiskseqSource)
	}
}

// ioctlBlockSize returns BLKGETSIZE64 of the block device fd.
func ioctlBlockSize(fd int) (uint64, error) {
	var size uint64
	err := retryEINTR(func() error {
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.BLKGETSIZE64), uintptr(unsafe.Pointer(&size)))
		if errno != 0 {
			return errno
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("BLKGETSIZE64: %w", err)
	}
	return size, nil
}

// blockDeviceBytes returns the size in bytes of the block device f, from
// BLKGETSIZE64. fstat gives a block device no size. A size that is zero,
// that is not a whole number of sectors, or that does not fit an int64 is an
// error, because the guest checks the drive's sector count.
func blockDeviceBytes(f *os.File) (int64, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var size uint64
	var ioctlErr error
	if err := rc.Control(func(fd uintptr) { size, ioctlErr = ioctlBlockSize(int(fd)) }); err != nil {
		return 0, err
	}
	if ioctlErr != nil {
		return 0, ioctlErr
	}
	return checkBlockSize(size)
}

// checkBlockSize returns size as an int64, or an error for a size the guest
// could not use.
func checkBlockSize(size uint64) (int64, error) {
	switch {
	case size == 0:
		return 0, errors.New("the device has no size")
	case size > 1<<63-1:
		return 0, fmt.Errorf("the device's size of %d bytes does not fit in 63 bits", size)
	case size%imageSectorSize != 0:
		return 0, fmt.Errorf("the device's size of %d bytes is not a whole number of %d-byte sectors", size, imageSectorSize)
	}
	return int64(size), nil
}

// retryEINTR runs call again while it fails with EINTR, up to openRetries
// times.
func retryEINTR(call func() error) error {
	var err error
	for i := 0; i < openRetries; i++ {
		if err = call(); !errors.Is(err, unix.EINTR) {
			return err
		}
	}
	return err
}

// blockProvider is a volume service that hands vm-launch a whole block device
// through a read-only descriptor tmpfs whose source is source. The bosh-disk
// driver's block mode is one, and a cell-attached device, such as an
// encrypted EBS volume, that writes the same descriptor would be another.
type blockProvider struct {
	name   string
	source string
	// nodeDir is where Garden makes the device nodes.
	nodeDir string
	host    blockHost
}

func (p *blockProvider) Name() string { return p.name }

// Match owns a tmpfs whose source is the provider's descriptor source, whose
// superblock is read-only, and whose root the container sees. The superblock
// rather than the per-mount flag decides, because nothing can write through a
// read-only superblock, and Garden binds the descriptor read-write.
func (p *blockProvider) Match(m mountRecord) matchStrength {
	if m.FSType == tmpfsFSType && m.Source == p.source && m.Root == "/" && slices.Contains(m.SuperOptions, "ro") {
		return strongMatch
	}
	return noMatch
}

// Capabilities says the provider attaches a whole block device, fenced by an
// exclusive open and by the volume service attaching it to one VM at a time,
// so one instance can use it.
func (p *blockProvider) Capabilities(mountRecord) capabilities {
	return capabilities{Modes: []attachMode{attachBlock}, Fence: fenceExclusiveOpen, MaxInstances: 1}
}

// refuseBlockSize refuses a size setting on a volume whose disk is attached
// in block mode. A BOSH disk is exactly as large as its plan says, so the
// app has no size to choose, and the refusal holds for any size the app
// writes, including one that happens to equal the disk's. It looks only at
// the settings and the provider, so it runs before anything is opened. A
// volume without a size, one that is not in block mode, and one without a
// provider pass.
func refuseBlockSize(v selectedVolume) error {
	if v.Provider == nil || !v.Volume.Settings.SizeSet() {
		return nil
	}
	if privateMode(v.Provider.Capabilities(v.Mount)) != attachBlock {
		return nil
	}
	return fmt.Errorf("%s %s sets a size, but it is a BOSH disk, whose size comes from its plan",
		volumeSettingsEnv, quoteForLog(v.Volume.ContainerDir))
}

// refuseBlockSizes applies refuseBlockSize to every selected volume, in
// volume order, and returns the first refusal. The launch calls it once the
// providers are known, so that no volume is opened, locked, or created
// before an app's size setting on a BOSH disk is refused.
func refuseBlockSizes(selected []selectedVolume) error {
	for _, v := range selected {
		if err := refuseBlockSize(v); err != nil {
			return err
		}
	}
	return nil
}

// Prepare refuses any mode but block mode, any instance index above 0, and a
// mount it does not own, and then opens and checks the device through
// openBlockVolume. The launch's prepare refuses an index above 0 from
// MaxInstances before it calls Prepare, and the check here backs that up.
// The attachment's Release closes vm-launch's copy of the device, and the
// exclusive claim ends once the hypervisor, which shares the open file, has
// exited too.
func (p *blockProvider) Prepare(req prepareRequest) (*attachment, error) {
	dir := quoteForLog(req.Mount.ContainerDir)
	if req.Mode != attachBlock {
		return nil, fmt.Errorf("volume path %s: the %s volume provider attaches only in %s, not in %s", dir, p.name, attachBlock, req.Mode)
	}
	if req.Index != 0 {
		return nil, instanceLimitError(p, req.Mount.ContainerDir, attachBlock, 1, req.Index)
	}
	if p.Match(req.Mount) != strongMatch {
		return nil, fmt.Errorf("the %s volume provider does not own the %s mount at volume path %s", p.name, quoteForLog(req.Mount.FSType), dir)
	}
	f, err := p.openBlockVolume(req)
	if err != nil {
		return nil, err
	}
	return &attachment{File: f, Mode: attachBlock, Release: f.Close}, nil
}

// openBlockVolume reads the descriptor of the volume in req and returns its
// device open read-write and exclusively, checked against the descriptor.
//
// The volume directory is opened without following links and must still be
// the root of the mount detection inspected, by mount ID, as openVolumeImage
// requires of an image's directory. The descriptor is read beneath that
// directory without following links or crossing a mount (readBlockDescriptor).
// The node is first opened as O_PATH and must be a block device with the
// descriptor's number. BeforeLock, when there is one, gets that O_PATH file,
// so a device an earlier volume of the launch holds is refused in the
// launch's own words before the exclusive open would fail as busy. The node
// is then opened with O_RDWR|O_EXCL|O_CLOEXEC|O_NOFOLLOW, waiting while it is
// busy (openExclusive), and the open file must be the inode checked before,
// with the descriptor's number, the descriptor's size, and an ext4
// superblock with the descriptor's UUID, a journal, and no more blocks than
// the device holds (checkExt4Superblock). Every failure closes what it
// opened.
func (p *blockProvider) openBlockVolume(req prepareRequest) (*os.File, error) {
	dir := req.Mount.ContainerDir
	qdir := quoteForLog(dir)
	dirfd, err := openat2Retry(unix.AT_FDCWD, dir, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("opening volume %s: %w%s", qdir, err, symlinkHint(err))
	}
	defer unix.Close(dirfd)

	probe, err := dirProbe(dirfd, dir)
	switch {
	case err != nil:
		return nil, fmt.Errorf("checking the mount of volume %s: %w", qdir, err)
	case probe.MountID != req.Mount.MountID:
		return nil, &volumeError{kind: errMountChanged,
			msg: fmt.Sprintf("the mount of volume %s changed during start: it was mount ID %d when vm-launch inspected it and is mount ID %d now",
				qdir, req.Mount.MountID, probe.MountID)}
	case !probe.MountRoot:
		return nil, notMountRootError(qdir, nil)
	}

	desc, err := p.readBlockDescriptor(dirfd, dir)
	if err != nil {
		return nil, err
	}
	node := p.nodeDir + "/" + strconv.FormatUint(uint64(desc.Major), 10) + "-" + strconv.FormatUint(uint64(desc.Minor), 10)
	what := fmt.Sprintf("the %s device %s (%s) for volume path %s", p.name, node, desc.DiskName, qdir)
	rdev := unix.Mkdev(desc.Major, desc.Minor)
	grantedSeq, err := gardenDiskseq(desc.Major, desc.Minor)
	if err != nil {
		return nil, fmt.Errorf("checking %s: %w", what, err)
	}

	pathFD, err := p.host.open(node, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	if err != nil {
		return nil, p.nodeOpenError(what, err)
	}
	pathFile := os.NewFile(uintptr(pathFD), node)
	defer pathFile.Close()
	var want unix.Stat_t
	if err := p.host.fstat(pathFD, &want); err != nil {
		return nil, fmt.Errorf("reading %s: fstat: %w", what, err)
	}
	if err := checkBlockNode(&want, rdev, desc, what); err != nil {
		return nil, err
	}
	if req.BeforeLock != nil {
		if err := req.BeforeLock(pathFile); err != nil {
			return nil, err
		}
	}

	fd, err := p.openExclusive(node, what, req)
	if err != nil {
		return nil, err
	}
	dev := os.NewFile(uintptr(fd), node)
	ok := false
	defer func() {
		if !ok {
			dev.Close()
		}
	}()
	var got unix.Stat_t
	if err := p.host.fstat(fd, &got); err != nil {
		return nil, fmt.Errorf("reading %s: fstat: %w", what, err)
	}
	if got.Dev != want.Dev || got.Ino != want.Ino {
		return nil, fmt.Errorf("%s was replaced while vm-launch opened it: it was inode %d on device %d and is inode %d on device %d",
			what, want.Ino, want.Dev, got.Ino, got.Dev)
	}
	if err := checkBlockNode(&got, rdev, desc, what); err != nil {
		return nil, err
	}
	seq, err := p.host.diskSeq(fd)
	if err != nil {
		return nil, fmt.Errorf("reading the disk sequence number of %s: %w", what, err)
	}
	if seq != grantedSeq {
		return nil, fmt.Errorf("%s is disk sequence number %d, and Garden granted disk sequence number %d; another disk now has the device number, and vm-launch refuses it", what, seq, grantedSeq)
	}
	raw, err := p.host.deviceBytes(fd)
	if err != nil {
		return nil, fmt.Errorf("reading the size of %s: %w", what, err)
	}
	if raw != uint64(desc.Size) {
		return nil, fmt.Errorf("%s is %d bytes, and its descriptor promises %d; vm-launch refuses a device whose size differs from its descriptor's", what, raw, desc.Size)
	}
	if _, err := checkBlockSize(raw); err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if err := checkExt4Superblock(fd, desc, what); err != nil {
		return nil, err
	}
	ok = true
	return dev, nil
}

// openExclusive opens node with O_RDWR|O_EXCL|O_CLOEXEC|O_NOFOLLOW. While the
// open fails with EBUSY, because the cell has the device mounted or another
// process, such as the hypervisor of an instance that is still stopping,
// holds it open exclusively, it tries again after blockBusyPoll, doubling
// each wait up to lockPoll. It waits up to lockWait, or for what is left of
// req.LockBudget when that is less, and the time it spends goes against the
// budget, as an image's lock wait does. A signal on req.Signals ends the wait
// with a *signalledError. Once the wait runs out, the device is refused as
// still in use, with kind errBlockDeviceBusy. Every other failure is refused
// at once, through nodeOpenError.
func (p *blockProvider) openExclusive(node, what string, req prepareRequest) (int, error) {
	began := time.Now()
	wait := lockWait
	if b := req.LockBudget; b != nil {
		wait = min(wait, b.remaining)
		defer func() { b.remaining = max(b.remaining-time.Since(began), 0) }()
	}
	deadline := began.Add(wait)
	poll := blockBusyPoll
	for {
		fd, err := p.host.open(node, unix.O_RDWR|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.EBUSY) {
			return -1, p.nodeOpenError(what, err)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return -1, &volumeError{kind: errBlockDeviceBusy, cause: err,
				msg: fmt.Sprintf("%s is still in use after vm-launch waited %s for it: the cell has it mounted, or another process, such as an earlier instance's hypervisor, holds it open exclusively; a block device takes one writer",
					what, wait.Round(100*time.Millisecond))}
		}
		timer := time.NewTimer(min(poll, remaining))
		select {
		case sig := <-req.Signals:
			timer.Stop()
			return -1, &signalledError{Sig: syscall.Signal(signalNumber(sig)), during: "waiting for the block device to be released"}
		case <-timer.C:
		}
		poll = min(2*poll, lockPoll)
	}
}

// checkBlockNode refuses a node that is not a block device with the number
// rdev that desc names.
func checkBlockNode(st *unix.Stat_t, rdev uint64, desc blockDescriptor, what string) error {
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return fmt.Errorf("%s is not a block device (file type %s); Garden makes the node a block device", what, fileTypeName(st.Mode))
	}
	if uint64(st.Rdev) != rdev {
		return fmt.Errorf("%s is device %d:%d, and its descriptor names device %d:%d", what,
			unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev)), desc.Major, desc.Minor)
	}
	return nil
}

// fileTypeName names the file type in mode for a refusal.
func fileTypeName(mode uint32) string {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return "regular file"
	case unix.S_IFDIR:
		return "directory"
	case unix.S_IFCHR:
		return "character device"
	case unix.S_IFBLK:
		return "block device"
	case unix.S_IFIFO:
		return "FIFO"
	case unix.S_IFLNK:
		return "symbolic link"
	case unix.S_IFSOCK:
		return "socket"
	}
	return fmt.Sprintf("%#o", mode&unix.S_IFMT)
}

// nodeOpenError says why vm-launch could not open the device node, in terms
// an operator can act on. openExclusive handles EBUSY, which it waits out.
func (p *blockProvider) nodeOpenError(what string, err error) error {
	switch {
	case errors.Is(err, unix.ENOENT):
		return fmt.Errorf("opening %s: the container has no such node; Garden makes it only when the cell runs Garden with --vm-block-volumes", what)
	case errors.Is(err, unix.EACCES):
		return fmt.Errorf("opening %s: %w; Garden makes the node root:kvm with mode 0660, and vm-launch needs the kvm group", what, err)
	case errors.Is(err, unix.EPERM):
		return fmt.Errorf("opening %s: %w; the container's device cgroup does not allow the device", what, err)
	case errors.Is(err, unix.ENXIO), errors.Is(err, unix.ENODEV):
		return fmt.Errorf("opening %s: %w; the disk is no longer attached to the cell", what, err)
	case errors.Is(err, unix.ELOOP):
		return fmt.Errorf("opening %s: %w; the node is a symbolic link, and vm-launch follows none", what, err)
	}
	return fmt.Errorf("opening %s: %w", what, err)
}

// readBlockDescriptor reads and parses the descriptor in the volume directory
// dirfd, whose path is dir. The file is opened beneath dirfd, without
// following links or crossing into another mount, with O_NONBLOCK so that a
// FIFO cannot hold the launch, and it must be a regular file with mode 0444,
// not owned by vm-launch's own user unless that is root, shorter than
// blockDescriptorSizeLimit, and as long as the bytes read from it. A file the
// app's user owns could be one the app wrote, so it proves nothing.
func (p *blockProvider) readBlockDescriptor(dirfd int, dir string) (blockDescriptor, error) {
	name := quoteForLog(dir + "/" + blockDescriptorFileName)
	fd, err := openat2Retry(dirfd, blockDescriptorFileName, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return blockDescriptor{}, fmt.Errorf("opening the block-mode descriptor %s: %w%s", name, err, symlinkHint(err))
	}
	f := os.NewFile(uintptr(fd), dir+"/"+blockDescriptorFileName)
	defer f.Close()
	var st unix.Stat_t
	if err := p.host.fstat(fd, &st); err != nil {
		return blockDescriptor{}, fmt.Errorf("reading the block-mode descriptor %s: fstat: %w", name, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return blockDescriptor{}, fmt.Errorf("the block-mode descriptor %s is a %s, not a regular file", name, fileTypeName(st.Mode))
	case st.Mode&0o7777 != blockDescriptorMode:
		return blockDescriptor{}, fmt.Errorf("the block-mode descriptor %s has mode %#o, and the volume driver writes it with mode %#o", name, st.Mode&0o7777, blockDescriptorMode)
	case euid() != 0 && int(st.Uid) == euid():
		return blockDescriptor{}, fmt.Errorf("the block-mode descriptor %s is owned by vm-launch's own uid %d, so it may not be the volume driver's", name, st.Uid)
	case st.Size <= 0 || st.Size >= blockDescriptorSizeLimit:
		return blockDescriptor{}, fmt.Errorf("the block-mode descriptor %s is %d bytes, and a descriptor is 1 to %d bytes", name, st.Size, blockDescriptorSizeLimit-1)
	}
	buf := make([]byte, blockDescriptorSizeLimit)
	n := 0
	for n < len(buf) {
		m, err := f.Read(buf[n:])
		n += m
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return blockDescriptor{}, fmt.Errorf("reading the block-mode descriptor %s: %w", name, err)
		}
	}
	if int64(n) != st.Size {
		return blockDescriptor{}, fmt.Errorf("the block-mode descriptor %s changed while vm-launch read it: fstat gave %d bytes and the read gave %d", name, st.Size, n)
	}
	desc, err := parseBlockDescriptor(buf[:n])
	if err != nil {
		return blockDescriptor{}, fmt.Errorf("the block-mode descriptor %s is malformed: %w", name, err)
	}
	return desc, nil
}

// euid is the effective uid, which the specs replace.
var euid = os.Geteuid

// checkExt4Superblock reads the ext4 superblock at byte 1024 of the device fd
// and refuses one without the ext4 magic, an external journal device, one
// whose UUID is all zeros or is not desc's, one without an internal journal,
// and one whose block size the kernel does not mount or whose blocks run past
// the end of the device, which is desc.Size bytes. The guest mounts the disk
// as ext4 and never formats it, and the volume driver formats it with a
// journal, so a disk without one is not the driver's. A UUID that differs is
// never printed, because the device may now be another app's disk, and
// vm-launch's lines reach the app's log. The guest's own mounts change the
// mount count, the last mount path, and the state, and never these fields, so
// the check holds across attaches.
func checkExt4Superblock(fd int, desc blockDescriptor, what string) error {
	sb := make([]byte, ext4SuperblockSize)
	n := 0
	for n < len(sb) {
		var m int
		err := retryEINTR(func() error {
			var err error
			m, err = unix.Pread(fd, sb[n:], int64(ext4SuperblockOffset+n))
			return err
		})
		if err != nil {
			return fmt.Errorf("reading the ext4 superblock of %s: %w", what, err)
		}
		if m == 0 {
			return fmt.Errorf("reading the ext4 superblock of %s: the device ends at byte %d", what, ext4SuperblockOffset+n)
		}
		n += m
	}
	le := binary.LittleEndian
	if magic := le.Uint16(sb[ext4MagicOffset:]); magic != ext4Magic {
		return fmt.Errorf("%s holds no ext4 filesystem (superblock magic %#04x, not %#04x); the volume driver formats the disk before it hands it over, and the guest never formats a block device", what, magic, ext4Magic)
	}
	incompat := le.Uint32(sb[ext4FeatureIncompatOff:])
	if incompat&ext4IncompatJournalDev != 0 {
		return fmt.Errorf("%s is an external ext4 journal device, not a filesystem", what)
	}
	uuid := formatUUID(sb[ext4UUIDOffset : ext4UUIDOffset+16])
	if uuid == zeroUUID {
		return fmt.Errorf("%s holds an ext4 filesystem whose UUID is all zeros, which cannot identify the disk, so vm-launch refuses it", what)
	}
	if uuid != desc.UUID {
		return fmt.Errorf("%s holds an ext4 filesystem whose UUID does not match the one the volume broker recorded for the disk; the device number may now belong to another disk, so vm-launch refuses it", what)
	}
	if le.Uint32(sb[ext4FeatureCompatOff:])&ext4CompatHasJournal == 0 {
		return fmt.Errorf("%s holds an ext4 filesystem without a journal; the volume driver formats a block-mode disk with one", what)
	}
	if le.Uint32(sb[ext4JournalInumOffset:]) == 0 {
		return fmt.Errorf("%s keeps its ext4 journal on another device, which the guest does not have", what)
	}
	logBlockSize := le.Uint32(sb[ext4LogBlockSizeOffset:])
	if logBlockSize > ext4MaxLogBlockSize {
		return fmt.Errorf("%s holds an ext4 superblock with s_log_block_size %d, a block size the kernel does not mount", what, logBlockSize)
	}
	blockSize := uint64(1024) << logBlockSize
	blocks := uint64(le.Uint32(sb[ext4BlocksCountLoOffset:]))
	if incompat&ext4Incompat64Bit != 0 {
		blocks |= uint64(le.Uint32(sb[ext4BlocksCountHiOffset:])) << 32
	}
	if deviceBlocks := uint64(desc.Size) / blockSize; blocks > deviceBlocks {
		return fmt.Errorf("%s holds an ext4 filesystem of %d blocks of %d bytes, and the device holds only %d such blocks; the guest cannot mount a filesystem that ends past its disk", what, blocks, blockSize, deviceBlocks)
	}
	return nil
}

// zeroUUID is the all-zero UUID, which identifies no filesystem.
const zeroUUID = "00000000-0000-0000-0000-000000000000"

// formatUUID renders 16 bytes in the lower-case 8-4-4-4-12 form.
func formatUUID(b []byte) string {
	const hexDigits = "0123456789abcdef"
	var out strings.Builder
	for i, c := range b {
		switch i {
		case 4, 6, 8, 10:
			out.WriteByte('-')
		}
		out.WriteByte(hexDigits[c>>4])
		out.WriteByte(hexDigits[c&0xf])
	}
	return out.String()
}

// refuseBlockDescriptorMount refuses a tmpfs whose source claims a
// block-mode descriptor that vm-launch must not trust or cannot read: one
// whose superblock is writable, a mount of a subdirectory of one, and one
// whose source names no registered block provider. It is registered with
// registerMountRefusal, so it comes before every provider. A mount of any
// other filesystem is left to the providers whatever its source says,
// because a FUSE filesystem such as JuiceFS names its own source and no
// block provider matches anything but tmpfs.
func refuseBlockDescriptorMount(m mountRecord) error {
	if m.FSType != tmpfsFSType || !strings.HasPrefix(m.Source, blockDescriptorSourcePrefix) {
		return nil
	}
	dir, src := quoteForLog(m.ContainerDir), quoteForLog(m.Source)
	switch {
	case !slices.Contains(m.SuperOptions, "ro"):
		return fmt.Errorf("volume path %s is a block-mode descriptor tmpfs from %s whose filesystem is writable; vm-launch reads a descriptor only from a read-only tmpfs", dir, src)
	case m.Root != "/":
		return fmt.Errorf("volume path %s shows %s of the block-mode descriptor tmpfs from %s, not its root", dir, quoteForLog(m.Root), src)
	case !slices.Contains(blockDescriptorSources, m.Source):
		return fmt.Errorf("volume path %s is a block-mode descriptor from %s, which no block provider in vm-launch reads; %s", dir, src, diskProviders.supportedLine())
	}
	return nil
}

// blockDescriptor is the content of a block-mode descriptor file.
type blockDescriptor struct {
	Major    uint32
	Minor    uint32
	Size     int64
	UUID     string
	DiskName string
}

// The descriptor's keys.
const (
	blockDescKeyVersion  = "version"
	blockDescKeyMajor    = "major"
	blockDescKeyMinor    = "minor"
	blockDescKeySize     = "size"
	blockDescKeyUUID     = "uuid"
	blockDescKeyDiskName = "disk_name"
)

var blockDescriptorKeys = []string{blockDescKeyVersion, blockDescKeyMajor, blockDescKeyMinor, blockDescKeySize, blockDescKeyUUID, blockDescKeyDiskName}

// parseBlockDescriptor reads the descriptor format and refuses anything
// else, naming the first problem it finds. It follows ParseDescriptor in the
// bosh-disk driver's pkg/driver/descriptor.go, which is the format's writer.
//
// The file is UTF-8 text with one key=value pair per line, and every line
// ends with "\n". Each of the six keys appears exactly once, in any order.
// There are no blank lines, comments, carriage returns, or other keys, and
// nothing is trimmed. Numbers are plain decimal digits with no sign and no
// leading zero.
//
//	version=1
//	major=8
//	minor=16
//	size=2147483648
//	uuid=bc20d783-6145-4623-86bb-35110042b24b
//	disk_name=bosh-disk-0123456789abcdef01
//
// major and minor fit in 32 bits, and major is not 0, which numbers the
// kernel's anonymous devices. size is from 1 to 2^63-1. uuid is the ext4
// UUID in lower-case 8-4-4-4-12 form, and not all zeros. disk_name is not empty, uses only ASCII
// letters, digits, ".", "_", and "-", does not start with "-", and is not "."
// or "..".
func parseBlockDescriptor(data []byte) (blockDescriptor, error) {
	var d blockDescriptor
	if len(data) >= blockDescriptorSizeLimit {
		return d, fmt.Errorf("descriptor is %d bytes, and it must be shorter than %d", len(data), blockDescriptorSizeLimit)
	}
	if len(data) == 0 {
		return d, errors.New("descriptor is empty")
	}
	if !utf8.Valid(data) {
		return d, errors.New("descriptor is not valid UTF-8")
	}
	if data[len(data)-1] != '\n' {
		return d, errors.New("descriptor does not end with a newline")
	}
	values := make(map[string]string, len(blockDescriptorKeys))
	for i, line := range strings.Split(string(data[:len(data)-1]), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return d, fmt.Errorf("descriptor line %d has no '='", i+1)
		}
		if !slices.Contains(blockDescriptorKeys, key) {
			return d, fmt.Errorf("descriptor line %d has unknown key %q", i+1, key)
		}
		if _, dup := values[key]; dup {
			return d, fmt.Errorf("descriptor line %d repeats key %q", i+1, key)
		}
		values[key] = value
	}
	for _, key := range blockDescriptorKeys {
		if _, ok := values[key]; !ok {
			return d, fmt.Errorf("descriptor has no %q line", key)
		}
	}
	if v := values[blockDescKeyVersion]; v != blockDescriptorVersion {
		return d, fmt.Errorf("descriptor version %q is not supported; vm-launch reads only %q", v, blockDescriptorVersion)
	}
	major, err := parseDescriptorUint(values[blockDescKeyMajor], 32)
	if err != nil {
		return d, fmt.Errorf("descriptor major: %w", err)
	}
	minor, err := parseDescriptorUint(values[blockDescKeyMinor], 32)
	if err != nil {
		return d, fmt.Errorf("descriptor minor: %w", err)
	}
	size, err := parseDescriptorUint(values[blockDescKeySize], 63)
	if err != nil {
		return d, fmt.Errorf("descriptor size: %w", err)
	}
	d = blockDescriptor{Major: uint32(major), Minor: uint32(minor), Size: int64(size), UUID: values[blockDescKeyUUID], DiskName: values[blockDescKeyDiskName]}
	switch {
	case d.Major == 0:
		return blockDescriptor{}, errors.New("descriptor major 0 numbers the kernel's anonymous devices, not a block disk")
	case d.Size <= 0:
		return blockDescriptor{}, fmt.Errorf("descriptor size %d is not a positive byte count", d.Size)
	case !validDescriptorUUID(d.UUID):
		return blockDescriptor{}, fmt.Errorf("descriptor uuid %q is not a lower-case 8-4-4-4-12 UUID", d.UUID)
	case d.UUID == zeroUUID:
		return blockDescriptor{}, errors.New("descriptor uuid is all zeros, which cannot identify a filesystem")
	}
	if err := validDescriptorDiskName(d.DiskName); err != nil {
		return blockDescriptor{}, err
	}
	return d, nil
}

// parseDescriptorUint accepts only plain ASCII digits with no leading zero
// that fit in bits.
func parseDescriptorUint(s string, bits int) (uint64, error) {
	if s == "" {
		return 0, errors.New("empty value")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%q is not a decimal number", s)
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("%q has a leading zero", s)
	}
	v, err := strconv.ParseUint(s, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("%q is out of range", s)
	}
	return v, nil
}

// validDescriptorUUID accepts the lower-case 8-4-4-4-12 form only.
func validDescriptorUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}

// validDescriptorDiskName accepts the disk names the driver writes, so no
// control, bidirectional, or zero-width character can reach a log line.
func validDescriptorDiskName(s string) error {
	if s == "" {
		return errors.New("descriptor disk_name is empty")
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("descriptor disk_name %q holds a control character", s)
		default:
			return fmt.Errorf("descriptor disk_name %q holds %q, and a disk_name may use only ASCII letters, digits, '.', '_', and '-'", s, r)
		}
	}
	if s[0] == '-' {
		return fmt.Errorf("descriptor disk_name %q starts with '-'", s)
	}
	if s == "." || s == ".." {
		return fmt.Errorf("descriptor disk_name %q is a directory name", s)
	}
	return nil
}
