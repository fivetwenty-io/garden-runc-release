package bundlerules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"code.cloudfoundry.org/garden"
	spec "code.cloudfoundry.org/guardian/gardener/container-spec"
	"code.cloudfoundry.org/lager/v3"
)

// A volume driver that serves a block device mounts a small read-only tmpfs
// whose source starts with PDISourcePrefix at the volume's mount point. The
// tmpfs holds one file, PDIDescriptorName, that names the device. A vm-*
// container whose bind mount source is such a tmpfs gets the device itself as
// a block node, so its hypervisor can hand the whole disk to the guest.
const (
	// PDISourcePrefix starts the mount source of every descriptor tmpfs. Only
	// root can mount a tmpfs, so an app cannot forge one.
	PDISourcePrefix = "pdi:"

	// PDIDescriptorName is the name of the descriptor file in the tmpfs.
	PDIDescriptorName = "device"

	// PDIDescriptorSizeLimit bounds the descriptor file, which is always
	// shorter than this many bytes.
	PDIDescriptorSizeLimit = 4096

	// DefaultPDINodeDir is the host directory for the block nodes. runc binds
	// the host node into a user-namespaced container at the same path, so this
	// is also where the node appears inside the container.
	DefaultPDINodeDir = "/dev/pdi"

	// DefaultPDIClaimDir holds one claim file per device given to a container.
	// It is on tmpfs like the nodes, so both go away together at reboot.
	DefaultPDIClaimDir = "/run/garden-pdi-claims"

	pdiNodeMode os.FileMode = 0660

	// pdiDescriptorOwner is the uid that must own a descriptor file, which is
	// root on a cell.
	pdiDescriptorOwner uint32 = 0
)

// ErrBlockVolumeRefused is wrapped by every error that refuses a container
// because of a block volume.
var ErrBlockVolumeRefused = errors.New("block volume refused")

// ErrPDIForeignNode is wrapped by the error that RemoveNode returns for a path
// that is not the block device it was asked to remove.
var ErrPDIForeignNode = errors.New("the path is not the block node Garden made")

// PDIDescriptorFile is what PDIHost read from a descriptor file.
type PDIDescriptorFile struct {
	// Regular reports whether the file is a regular file.
	Regular bool
	// UID is the file's owner.
	UID uint32
	// Size is the file's length from fstat.
	Size int64
	// Data is the file's content. It is empty unless Regular is true, and it
	// holds at most PDIDescriptorSizeLimit+1 bytes.
	Data []byte
}

// PDISource is a bind mount source opened once, so that its mount ID and its
// descriptor come from the same object.
type PDISource interface {
	// MountID returns the ID of the mount that holds the source, as the first
	// field of mountinfo gives it.
	MountID() (uint64, error)
	// ReadDescriptor reads PDIDescriptorName in the source directory without
	// following a link and without blocking on a special file.
	ReadDescriptor() (PDIDescriptorFile, error)
	Close() error
}

// PDIHost performs the host operations of the device step.
type PDIHost interface {
	// OpenSource opens a bind mount source without side effects.
	OpenSource(path string) (PDISource, error)
	// Mknod creates a block node for major:minor at path, owned by root and
	// gid with mode 0660. It returns an error wrapping os.ErrExist when path
	// already exists, and it leaves no node behind when it fails otherwise.
	Mknod(path string, major, minor, gid uint32) error
	// Probe opens the node at path with O_EXCL, checks that it is the block
	// device major:minor and that the device is size bytes long, and closes it
	// again.
	Probe(path string, major, minor uint32, size int64) error
	// RemoveNode removes the node at path when it is the block device
	// major:minor. A missing node is not an error, and a path that is anything
	// else returns an error wrapping ErrPDIForeignNode.
	RemoveNode(path string, major, minor uint32) error
}

// PDIDevices is the block volume step of the execution backend rule. For each
// bind mount of a vm-* container whose source is a descriptor tmpfs, Claim
// checks that the named device is unused on the host, creates its node, and
// records which container has it. Release removes the node and the record
// when the container is destroyed.
//
// The node and claim directories are shared by every Garden on the host. Each
// claim records the Garden's Tag, and a Garden releases only claims with its
// own tag, while it refuses a device that any Garden has claimed.
type PDIDevices struct {
	// KVMGid owns the block nodes. Only the wrapped vm-launch holds it.
	KVMGid uint32

	// Tag is the Garden's --tag value, or empty. It is written into each claim.
	Tag string

	// NodeDir holds the block nodes, named MAJOR-MINOR.
	NodeDir string

	// ClaimDir holds the claim files, named MAJOR-MINOR, each holding the tag of
	// the Garden and the handle of the container that has the device.
	ClaimDir string

	// SysfsDir is where sysfs is mounted.
	SysfsDir string

	// MountInfoPath is the mount table of Garden's mount namespace.
	MountInfoPath string

	Host   PDIHost
	Logger lager.Logger

	// mu serialises Claim's claiming, Release, and ReleaseUnknown, which would
	// otherwise read an owner and then remove a node that a new owner has taken.
	mu sync.Mutex
}

// pdiDevice is one block device that a container's descriptor names.
type pdiDevice struct {
	source string
	desc   pdiDescriptor
}

func (d pdiDevice) numbers() string {
	return fmt.Sprintf("%d:%d", d.desc.Major, d.desc.Minor)
}

func pdiName(major, minor uint32) string {
	return fmt.Sprintf("%d-%d", major, minor)
}

func (p *PDIDevices) nodePath(major, minor uint32) string {
	return filepath.Join(p.NodeDir, pdiName(major, minor))
}

func (p *PDIDevices) claimPath(major, minor uint32) string {
	return filepath.Join(p.ClaimDir, pdiName(major, minor))
}

func refuse(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrBlockVolumeRefused, fmt.Sprintf(format, args...))
}

// Claim finds the descriptor bind mounts of the container, refuses the
// container if any named device is mounted, held, busy, the wrong size, or
// already given to a container, and otherwise creates one host node per device
// and returns the nodes to add to the bundle. When it fails, it leaves no node
// or claim of its own behind.
func (p *PDIDevices) Claim(desired spec.DesiredContainerSpec) ([]deviceNode, error) {
	if len(desired.BindMounts) == 0 {
		return nil, nil
	}

	mounts, err := readPDIMountInfo(p.MountInfoPath)
	if err != nil {
		return nil, refuse("reading %s: %s", p.MountInfoPath, err)
	}

	var devices []pdiDevice
	seen := map[string]string{}
	for _, bm := range desired.BindMounts {
		desc, ok, err := p.descriptorAt(bm.SrcPath, mounts)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if bm.Mode == garden.BindMountModeRO {
			return nil, refuse("bind mount %s is a device descriptor and is read-only, and block mode needs it read-write", bm.SrcPath)
		}
		dev := pdiDevice{source: bm.SrcPath, desc: desc}
		if other, dup := seen[dev.numbers()]; dup {
			return nil, refuse("bind mounts %s and %s both name device %s", other, bm.SrcPath, dev.numbers())
		}
		seen[dev.numbers()] = bm.SrcPath
		devices = append(devices, dev)
	}
	if len(devices) == 0 {
		return nil, nil
	}
	if desired.Handle == "" {
		return nil, refuse("the container has no handle to record a device claim under")
	}

	for _, dev := range devices {
		if err := p.checkDevice(dev, mounts); err != nil {
			return nil, err
		}
	}

	if err := ensurePDIDir(p.NodeDir, 0755); err != nil {
		return nil, refuse("preparing %s: %s", p.NodeDir, err)
	}
	if err := ensurePDIDir(p.ClaimDir, 0700); err != nil {
		return nil, refuse("preparing %s: %s", p.ClaimDir, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	var claimed []pdiDevice
	nodes := make([]deviceNode, 0, len(devices))
	for _, dev := range devices {
		if err := p.claim(desired.Handle, dev); err != nil {
			p.rollback(claimed)
			return nil, err
		}
		claimed = append(claimed, dev)
		nodes = append(nodes, deviceNode{
			path:    p.nodePath(dev.desc.Major, dev.desc.Minor),
			devType: "b",
			major:   int64(dev.desc.Major),
			minor:   int64(dev.desc.Minor),
			mode:    pdiNodeMode,
			gid:     p.KVMGid,
			access:  "rw",
		})
	}

	for _, dev := range claimed {
		p.Logger.Info("pdi-device-claimed", lager.Data{
			"handle":    desired.Handle,
			"source":    dev.source,
			"device":    dev.numbers(),
			"disk-name": dev.desc.DiskName,
			"node":      p.nodePath(dev.desc.Major, dev.desc.Minor),
		})
	}
	return nodes, nil
}

// descriptorAt reports whether the bind mount source is a descriptor tmpfs
// and, if so, returns its parsed descriptor. A source that cannot be opened or
// whose mount is not in the table is refused, because it cannot be told apart
// from a descriptor.
func (p *PDIDevices) descriptorAt(source string, mounts []pdiMountEntry) (pdiDescriptor, bool, error) {
	src, err := p.Host.OpenSource(source)
	if err != nil {
		return pdiDescriptor{}, false, refuse("opening bind mount source %s: %s", source, err)
	}
	defer src.Close()

	mountID, err := src.MountID()
	if err != nil {
		return pdiDescriptor{}, false, refuse("finding the mount of %s: %s", source, err)
	}
	entry, ok := findPDIMount(mounts, mountID)
	if !ok {
		return pdiDescriptor{}, false, refuse("mount %d of %s is not in %s", mountID, source, p.MountInfoPath)
	}
	if !strings.HasPrefix(entry.source, PDISourcePrefix) {
		return pdiDescriptor{}, false, nil
	}
	if entry.fsType != "tmpfs" {
		return pdiDescriptor{}, false, refuse("%s is a %s mount from %s, and a descriptor must be on tmpfs", source, entry.fsType, entry.source)
	}
	if !entry.readOnly() {
		return pdiDescriptor{}, false, refuse("%s is a descriptor tmpfs from %s that is not read-only", source, entry.source)
	}

	file, err := src.ReadDescriptor()
	if err != nil {
		return pdiDescriptor{}, false, refuse("reading the descriptor in %s: %s", source, err)
	}
	if !file.Regular {
		return pdiDescriptor{}, false, refuse("the descriptor in %s is not a regular file", source)
	}
	if file.UID != pdiDescriptorOwner {
		return pdiDescriptor{}, false, refuse("the descriptor in %s is owned by uid %d, not %d", source, file.UID, pdiDescriptorOwner)
	}
	if file.Size >= PDIDescriptorSizeLimit || len(file.Data) >= PDIDescriptorSizeLimit {
		return pdiDescriptor{}, false, refuse("the descriptor in %s is %d bytes, and it must be shorter than %d", source, max(file.Size, int64(len(file.Data))), PDIDescriptorSizeLimit)
	}
	if int64(len(file.Data)) != file.Size {
		return pdiDescriptor{}, false, refuse("the descriptor in %s changed while it was read", source)
	}
	desc, err := parsePDIDescriptor(file.Data)
	if err != nil {
		return pdiDescriptor{}, false, refuse("the descriptor in %s: %s", source, err)
	}
	return desc, true, nil
}

// checkDevice refuses a device whose size differs from the descriptor's, or
// that is mounted on the host, either itself, through any of its partitions,
// or, for a partition, through its whole disk. The exclusive open in claim is
// the check that also sees an app's O_EXCL hold, swap, device-mapper claims,
// and mounts in other mount namespaces, which this mount table does not show.
func (p *PDIDevices) checkDevice(dev pdiDevice, mounts []pdiMountEntry) error {
	devDir := filepath.Join(p.SysfsDir, "dev", "block", dev.numbers())
	info, err := os.Stat(devDir)
	if err != nil {
		return refuse("device %s named by %s is not a block device on this host: %s", dev.numbers(), dev.source, unwrapPathError(err))
	}
	if !info.IsDir() {
		return refuse("%s is not a sysfs device directory", devDir)
	}

	sectors, err := readSysfsUint(filepath.Join(devDir, "size"))
	if err != nil {
		return refuse("reading the size of device %s: %s", dev.numbers(), err)
	}
	if sectors > uint64(1<<63-1)/512 {
		return refuse("device %s reports %d sectors, which overflows a byte count", dev.numbers(), sectors)
	}
	if size := int64(sectors) * 512; size != dev.desc.Size {
		return refuse("device %s is %d bytes, and the descriptor in %s says %d", dev.numbers(), size, dev.source, dev.desc.Size)
	}

	related, err := relatedBlockDevices(devDir)
	if err != nil {
		return refuse("listing the partitions of device %s: %s", dev.numbers(), err)
	}

	for _, numbers := range append([]string{dev.numbers()}, related...) {
		for _, m := range mounts {
			if m.devNumbers == numbers {
				return refuse("device %s (from %s) is mounted on the host at %s", numbers, dev.source, m.mountPoint)
			}
		}
	}
	return nil
}

// claim records the container as the device's owner, creates the node, and
// probes it with O_EXCL. The claim file is created exclusively, so a second
// container naming the same device is refused, whichever Garden it is in, and
// a node that Garden did not create is never adopted or removed. The caller
// holds p.mu.
func (p *PDIDevices) claim(handle string, dev pdiDevice) error {
	major, minor := dev.desc.Major, dev.desc.Minor
	claimPath := p.claimPath(major, minor)

	f, err := os.OpenFile(claimPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return p.refuseClaimed(dev, claimPath)
		}
		return refuse("claiming device %s: %s", dev.numbers(), unwrapPathError(err))
	}
	_, writeErr := f.Write(encodePDIClaim(pdiClaim{tag: p.Tag, handle: handle}))
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(claimPath)
		return refuse("recording the claim of device %s: %s", dev.numbers(), err)
	}

	nodePath := p.nodePath(major, minor)
	if err := p.Host.Mknod(nodePath, major, minor, p.KVMGid); err != nil {
		_ = os.Remove(claimPath)
		if errors.Is(err, os.ErrExist) {
			return refuse("%s already exists on the host, and Garden did not create it", nodePath)
		}
		return refuse("creating %s: %s", nodePath, err)
	}

	if err := p.Host.Probe(nodePath, major, minor, dev.desc.Size); err != nil {
		if rmErr := p.release(p.Logger, major, minor); rmErr != nil {
			p.Logger.Error("pdi-device-probe-cleanup-failed", rmErr, lager.Data{"device": dev.numbers()})
		}
		return refuse("device %s named by %s failed the exclusive probe, so it may be mounted, held, busy, or the wrong size on the host: %s", dev.numbers(), dev.source, err)
	}
	return nil
}

// refuseClaimed refuses a device whose claim file already exists.
func (p *PDIDevices) refuseClaimed(dev pdiDevice, claimPath string) error {
	data, err := os.ReadFile(claimPath)
	if err != nil {
		return refuse("device %s named by %s is already given to another container", dev.numbers(), dev.source)
	}
	c, ok := parsePDIClaim(data)
	switch {
	case !ok:
		return refuse("device %s named by %s has a claim that Garden cannot read, so it is already given to another container", dev.numbers(), dev.source)
	case c.tag != p.Tag:
		return refuse("device %s named by %s is already given to container %q of the Garden tagged %q", dev.numbers(), dev.source, c.handle, c.tag)
	default:
		return refuse("device %s named by %s is already given to container %q", dev.numbers(), dev.source, c.handle)
	}
}

// rollback releases the devices that one Claim call had already claimed. The
// caller holds p.mu.
func (p *PDIDevices) rollback(claimed []pdiDevice) {
	for _, dev := range claimed {
		if err := p.release(p.Logger, dev.desc.Major, dev.desc.Minor); err != nil {
			p.Logger.Error("pdi-device-rollback-failed", err, lager.Data{"device": dev.numbers()})
		}
	}
}

// release removes a device's node, then its claim. A claim without a node,
// which a crash between the two steps leaves, is released the same way. A path
// that is not the block node is logged and left in place, and the claim goes
// anyway, because a later claim of the device still refuses the existing path.
// The caller holds p.mu and has checked that the claim is its own.
func (p *PDIDevices) release(log lager.Logger, major, minor uint32) error {
	if err := p.Host.RemoveNode(p.nodePath(major, minor), major, minor); err != nil {
		if !errors.Is(err, ErrPDIForeignNode) {
			return fmt.Errorf("removing %s: %w", p.nodePath(major, minor), err)
		}
		log.Error("pdi-node-left-in-place", err, lager.Data{"node": p.nodePath(major, minor)})
	}
	if err := os.Remove(p.claimPath(major, minor)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing %s: %w", p.claimPath(major, minor), err)
	}
	return nil
}

// Release removes the node and claim of every device that this Garden gave to
// the container. It is safe to call for a container that has none, and more
// than once. It returns an error only for a claim that the container owns, so
// an unreadable or foreign entry in the shared claim directory, which is
// logged and left alone, never fails another container's destroy.
func (p *PDIDevices) Release(log lager.Logger, handle string) error {
	return p.releaseWhere(log, func(owner string) bool { return owner == handle })
}

// ReleaseUnknown removes the node and claim of every device that this Garden
// gave to a container not among known. Garden calls it at start-up, before it
// serves requests, to release devices that a crash left claimed by a container
// it never created. Claims of other Gardens are not touched.
func (p *PDIDevices) ReleaseUnknown(log lager.Logger, known []string) error {
	knownSet := make(map[string]struct{}, len(known))
	for _, h := range known {
		knownSet[h] = struct{}{}
	}
	return p.releaseWhere(log, func(owner string) bool {
		_, ok := knownSet[owner]
		return !ok
	})
}

// releaseWhere releases the claims with this Garden's tag whose handle match
// picks. It holds p.mu while it reads each owner and while it removes the
// node and claim, so a claim that another call has released and a new owner has
// taken is never removed on the strength of a stale read.
func (p *PDIDevices) releaseWhere(log lager.Logger, match func(handle string) bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	entries, err := os.ReadDir(p.ClaimDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Error("pdi-claim-dir-unreadable", err, lager.Data{"dir": p.ClaimDir})
		}
		return nil
	}

	var errs []error
	for _, entry := range entries {
		major, minor, ok := parsePDIName(entry.Name())
		if !ok || !entry.Type().IsRegular() {
			log.Info("pdi-claim-dir-unexpected-entry", lager.Data{"name": entry.Name()})
			continue
		}
		data, err := os.ReadFile(filepath.Join(p.ClaimDir, entry.Name()))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Error("pdi-claim-unreadable", err, lager.Data{"name": entry.Name()})
			}
			continue
		}
		c, ok := parsePDIClaim(data)
		if !ok {
			log.Info("pdi-claim-malformed", lager.Data{"name": entry.Name()})
			continue
		}
		if c.tag != p.Tag || !match(c.handle) {
			continue
		}
		if err := p.release(log, major, minor); err != nil {
			errs = append(errs, err)
			continue
		}
		log.Info("pdi-device-released", lager.Data{"handle": c.handle, "device": fmt.Sprintf("%d:%d", major, minor)})
	}
	return errors.Join(errs...)
}

// pdiClaim is the content of a claim file, which is the Garden's tag, a
// newline, and the container's handle.
type pdiClaim struct {
	tag    string
	handle string
}

func encodePDIClaim(c pdiClaim) []byte {
	return []byte(c.tag + "\n" + c.handle)
}

// parsePDIClaim reports whether data is a claim in the form encodePDIClaim
// writes.
func parsePDIClaim(data []byte) (pdiClaim, bool) {
	tag, handle, ok := strings.Cut(string(data), "\n")
	if !ok || handle == "" {
		return pdiClaim{}, false
	}
	return pdiClaim{tag: tag, handle: handle}, true
}

// parsePDIName parses a MAJOR-MINOR node or claim name in its one spelling.
func parsePDIName(name string) (uint32, uint32, bool) {
	a, b, ok := strings.Cut(name, "-")
	if !ok {
		return 0, 0, false
	}
	major, err := parsePDIDecimal(a, 32)
	if err != nil {
		return 0, 0, false
	}
	minor, err := parsePDIDecimal(b, 32)
	if err != nil {
		return 0, 0, false
	}
	return uint32(major), uint32(minor), true
}

// ensurePDIDir creates dir when it is missing and requires it to be a real
// directory rather than a link.
func ensurePDIDir(dir string, perm os.FileMode) error {
	if err := os.Mkdir(dir, perm); err != nil && !errors.Is(err, os.ErrExist) {
		return unwrapPathError(err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return unwrapPathError(err)
	}
	if !info.IsDir() {
		return fmt.Errorf("it is not a directory (%s)", info.Mode().Type())
	}
	return nil
}

// relatedBlockDevices returns the MAJOR:MINOR numbers of the partitions of the
// device in devDir and, when the device is itself a partition, of its whole
// disk.
func relatedBlockDevices(devDir string) ([]string, error) {
	var related []string

	entries, err := os.ReadDir(devDir)
	if err != nil {
		return nil, unwrapPathError(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(devDir, entry.Name())
		if _, err := os.Lstat(filepath.Join(dir, "partition")); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, unwrapPathError(err)
		}
		numbers, err := readSysfsDev(filepath.Join(dir, "dev"))
		if err != nil {
			return nil, err
		}
		related = append(related, numbers)
	}

	if _, err := os.Lstat(filepath.Join(devDir, "partition")); err == nil {
		real, err := filepath.EvalSymlinks(devDir)
		if err != nil {
			return nil, err
		}
		numbers, err := readSysfsDev(filepath.Join(filepath.Dir(real), "dev"))
		if err != nil {
			return nil, err
		}
		related = append(related, numbers)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, unwrapPathError(err)
	}

	return related, nil
}

func readSysfsUint(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, unwrapPathError(err)
	}
	v, err := strconv.ParseUint(strings.TrimSuffix(string(data), "\n"), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s holds %q, not a number", path, string(data))
	}
	return v, nil
}

// readSysfsDev reads a sysfs dev file, which holds MAJOR:MINOR.
func readSysfsDev(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", unwrapPathError(err)
	}
	s := strings.TrimSuffix(string(data), "\n")
	a, b, ok := strings.Cut(s, ":")
	if !ok {
		return "", fmt.Errorf("%s holds %q, not MAJOR:MINOR", path, s)
	}
	major, errA := parsePDIDecimal(a, 32)
	minor, errB := parsePDIDecimal(b, 32)
	if errA != nil || errB != nil {
		return "", fmt.Errorf("%s holds %q, not MAJOR:MINOR", path, s)
	}
	return fmt.Sprintf("%d:%d", major, minor), nil
}

// pdiMountEntry is the part of a mountinfo line that the device step reads.
type pdiMountEntry struct {
	id         uint64
	devNumbers string
	mountPoint string
	fsType     string
	source     string
	superOpts  string
}

// readOnly reports whether the filesystem's own options include ro. A read-only
// superblock blocks writes through every mount of the tmpfs. The per-mount
// flags are not enough. A mount that propagated into Garden's mount namespace
// before the driver's remount keeps read-write per-mount flags, and a
// per-mount ro flag leaves a read-write filesystem writable through any other
// mount of it.
func (e pdiMountEntry) readOnly() bool {
	for _, opt := range strings.Split(e.superOpts, ",") {
		if opt == "ro" {
			return true
		}
	}
	return false
}

func findPDIMount(mounts []pdiMountEntry, id uint64) (pdiMountEntry, bool) {
	for _, m := range mounts {
		if m.id == id {
			return m, true
		}
	}
	return pdiMountEntry{}, false
}

// readPDIMountInfo parses a mountinfo file. Each line is
//
//	ID PARENT MAJ:MIN ROOT MOUNTPOINT OPTIONS [OPTIONAL...] - FSTYPE SOURCE SUPEROPTIONS
//
// with spaces, tabs, newlines, and backslashes in paths written as octal
// escapes. A line that does not have this shape is an error, because the
// mounted check must not skip a mount it failed to read.
func readPDIMountInfo(path string) ([]pdiMountEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, unwrapPathError(err)
	}

	var entries []pdiMountEntry
	for n, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if len(fields) < 6 || sep < 0 || sep+3 >= len(fields) {
			return nil, fmt.Errorf("line %d is not a mountinfo line", n+1)
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d has mount ID %q", n+1, fields[0])
		}
		entries = append(entries, pdiMountEntry{
			id:         id,
			devNumbers: fields[2],
			mountPoint: unescapeMountInfo(fields[4]),
			fsType:     fields[sep+1],
			source:     unescapeMountInfo(fields[sep+2]),
			superOpts:  fields[sep+3],
		})
	}
	return entries, nil
}

// unescapeMountInfo decodes the three-digit octal escapes that the kernel
// writes for space, tab, newline, and backslash.
func unescapeMountInfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// pdiDescriptor is the content of a descriptor file.
type pdiDescriptor struct {
	Major    uint32
	Minor    uint32
	Size     int64
	UUID     string
	DiskName string
}

// The descriptor format and its parser below are a copy of ParseDescriptor in
// the bosh-disk driver, cf-bosh-disk-broker-release
// src/bosh-disk-services/pkg/driver/descriptor.go, which writes the file. Keep
// the two in step.
//
// The file is UTF-8 text with one key=value pair per line, and every line
// ends with "\n". Each of the six keys below appears exactly once, in any
// order. There are no blank lines, comments, carriage returns, or other keys,
// and nothing is trimmed. Numbers are plain decimal digits with no sign and no
// leading zero.
//
//	version=1
//	major=8
//	minor=16
//	size=2147483648
//	uuid=bc20d783-6145-4623-86bb-35110042b24b
//	disk_name=bosh-disk-0123456789abcdef01
//
// size is greater than zero. uuid is the ext4 superblock's UUID in lower-case
// 8-4-4-4-12 form. disk_name is everything after the first "=", it is not
// empty, and it holds no control characters.
const pdiDescriptorVersion = "1"

var pdiDescriptorKeys = []string{"version", "major", "minor", "size", "uuid", "disk_name"}

func parsePDIDescriptor(data []byte) (pdiDescriptor, error) {
	var d pdiDescriptor
	if len(data) >= PDIDescriptorSizeLimit {
		return d, fmt.Errorf("descriptor is %d bytes, and it must be shorter than %d", len(data), PDIDescriptorSizeLimit)
	}
	if len(data) == 0 {
		return d, fmt.Errorf("descriptor is empty")
	}
	if !utf8.Valid(data) {
		return d, fmt.Errorf("descriptor is not valid UTF-8")
	}
	if data[len(data)-1] != '\n' {
		return d, fmt.Errorf("descriptor does not end with a newline")
	}

	values := make(map[string]string, len(pdiDescriptorKeys))
	for i, line := range strings.Split(string(data[:len(data)-1]), "\n") {
		n := i + 1
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return d, fmt.Errorf("descriptor line %d has no '='", n)
		}
		known := false
		for _, k := range pdiDescriptorKeys {
			if k == key {
				known = true
				break
			}
		}
		if !known {
			return d, fmt.Errorf("descriptor line %d has unknown key %q", n, key)
		}
		if _, dup := values[key]; dup {
			return d, fmt.Errorf("descriptor line %d repeats key %q", n, key)
		}
		values[key] = value
	}
	for _, key := range pdiDescriptorKeys {
		if _, ok := values[key]; !ok {
			return d, fmt.Errorf("descriptor has no %q line", key)
		}
	}

	if v := values["version"]; v != pdiDescriptorVersion {
		return d, fmt.Errorf("descriptor version %q is not supported; this reader knows only %q", v, pdiDescriptorVersion)
	}
	major, err := parsePDIDecimal(values["major"], 32)
	if err != nil {
		return d, fmt.Errorf("descriptor major: %w", err)
	}
	minor, err := parsePDIDecimal(values["minor"], 32)
	if err != nil {
		return d, fmt.Errorf("descriptor minor: %w", err)
	}
	size, err := parsePDIDecimal(values["size"], 63)
	if err != nil {
		return d, fmt.Errorf("descriptor size: %w", err)
	}
	if size == 0 {
		return d, fmt.Errorf("descriptor size 0 is not a positive byte count")
	}
	if !validPDIUUID(values["uuid"]) {
		return d, fmt.Errorf("descriptor uuid %q is not a lower-case 8-4-4-4-12 UUID", values["uuid"])
	}
	name := values["disk_name"]
	if name == "" {
		return d, fmt.Errorf("descriptor disk_name is empty")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return d, fmt.Errorf("descriptor disk_name %q holds a control character", name)
		}
	}

	return pdiDescriptor{
		Major:    uint32(major),
		Minor:    uint32(minor),
		Size:     int64(size),
		UUID:     values["uuid"],
		DiskName: name,
	}, nil
}

// parsePDIDecimal accepts only plain ASCII digits with no leading zero, so
// each number has exactly one spelling.
func parsePDIDecimal(s string, bits int) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty value")
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

func validPDIUUID(s string) bool {
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
