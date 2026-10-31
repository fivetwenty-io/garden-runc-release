package bundlerules

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
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

	// PDIDiskseqSource starts the source of a tmpfs that Garden mounts in a VM
	// container with block volumes, at PDIDiskseqMountPath. The disk sequence
	// number of each device Garden granted follows it, as MAJOR:MINOR=SEQ
	// entries separated by commas. vm-launch checks the device it opens
	// against it, so a device number that a detach and a new attach have moved
	// to another disk is refused.
	PDIDiskseqSource = "garden-pdi-diskseq:"

	// PDIDiskseqMountPath is where the disk sequence record is mounted.
	PDIDiskseqMountPath = "/opt/garden-vm/pdi-diskseq"

	// DefaultPDIClaimWait is how long Claim waits for another container to
	// release a device before it refuses the container. It matches the time
	// vm-launch waits for a busy device.
	DefaultPDIClaimWait = 30 * time.Second

	// pdiClaimPoll and pdiClaimPollMax bound the interval at which Claim looks
	// again at a device that another container holds.
	pdiClaimPoll    = 50 * time.Millisecond
	pdiClaimPollMax = 500 * time.Millisecond

	// pdiReleaseWait bounds how long a release waits for a claim of the same
	// device that is in progress, such as one whose probe hangs.
	pdiReleaseWait = 30 * time.Second
)

// PDIDescriptorSources lists the descriptor tmpfs sources that get a device.
// A tmpfs whose source has PDISourcePrefix but is not listed is refused.
var PDIDescriptorSources = []string{"pdi:bosh-disk"}

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

	// ClaimWait is how long Claim waits for another container to release a
	// device. Zero refuses a held device at once.
	ClaimWait time.Duration

	Host   PDIHost
	Logger lager.Logger

	// busy marks each device that a call is claiming or releasing, so that
	// an owner is never read and then removed while a new owner takes the
	// device. A mark covers one device, so a probe that hangs holds back only
	// calls for the same device. busyMu guards the map alone and is never held
	// across a host call.
	busyMu sync.Mutex
	busy   map[string]chan struct{}
}

// pdiDevice is one block device that a container's descriptor names.
type pdiDevice struct {
	// source is the bind mount's host path, which goes to the log only.
	source string
	// volume is the bind mount's path in the container, which a refusal names.
	volume string
	desc   pdiDescriptor
	// diskseq is the disk sequence number of the device's disk when Garden
	// checked it.
	diskseq uint64
}

func (d pdiDevice) numbers() string {
	return fmt.Sprintf("%d:%d", d.desc.Major, d.desc.Minor)
}

func (d pdiDevice) name() string {
	return pdiName(d.desc.Major, d.desc.Minor)
}

func (d pdiDevice) logData(handle string) lager.Data {
	return lager.Data{"handle": handle, "device": d.numbers(), "source": d.source, "volume": d.volume}
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

// refuseLogged refuses the container and logs the refusal with data, which
// holds the host paths, handles, and tags that the refusal leaves out. A
// create error can reach the app's events, so a refusal names only the
// container's own volume paths and device numbers.
func (p *PDIDevices) refuseLogged(data lager.Data, format string, args ...interface{}) error {
	err := refuse(format, args...)
	p.Logger.Error("pdi-volume-refused", err, data)
	return err
}

// Claim finds the descriptor bind mounts of the container, refuses the
// container if any named device is mounted, held, busy, the wrong size, or
// still given to another container once ClaimWait has passed, and otherwise
// creates one host node per device and returns the nodes to add to the
// bundle. When it fails, it leaves no node or claim of its own behind.
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
		desc, ok, err := p.descriptorAt(bm, mounts)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		dev := pdiDevice{source: bm.SrcPath, volume: bm.DstPath, desc: desc}
		if bm.Mode == garden.BindMountModeRO {
			return nil, p.refuseLogged(dev.logData(desired.Handle), "the volume at %s is a device descriptor bind-mounted read-only, and block mode needs it read-write", bm.DstPath)
		}
		if other, dup := seen[dev.numbers()]; dup {
			return nil, p.refuseLogged(dev.logData(desired.Handle), "the volumes at %s and %s both name device %s", other, bm.DstPath, dev.numbers())
		}
		seen[dev.numbers()] = bm.DstPath
		devices = append(devices, dev)
	}
	if len(devices) == 0 {
		return nil, nil
	}
	if p.KVMGid == 0 {
		return nil, refuse("block volumes are not turned on in this Garden, so it has no kvm group to give the device node")
	}
	if desired.Handle == "" {
		return nil, refuse("the container has no handle to record a device claim under")
	}
	if strings.Contains(desired.Handle, "\n") {
		return nil, refuse("the container's handle holds a newline, which a device claim cannot record")
	}

	for i := range devices {
		seq, err := p.checkDevice(desired.Handle, devices[i], mounts)
		if err != nil {
			return nil, err
		}
		devices[i].diskseq = seq
	}

	if err := ensurePDIDir(p.NodeDir, 0755); err != nil {
		return nil, refuse("preparing %s: %s", p.NodeDir, err)
	}
	if err := ensurePDIDir(p.ClaimDir, 0700); err != nil {
		return nil, refuse("preparing %s: %s", p.ClaimDir, err)
	}

	// One wait covers every device of the container, as vm-launch's lock
	// budget covers all of a launch's volumes. Devices are claimed in order of
	// their numbers, so two containers that name the same devices never each
	// hold one while they wait for the other.
	deadline := time.Now().Add(p.ClaimWait)
	order := slices.Clone(devices)
	slices.SortFunc(order, func(a, b pdiDevice) int {
		return cmp.Or(cmp.Compare(a.desc.Major, b.desc.Major), cmp.Compare(a.desc.Minor, b.desc.Minor))
	})
	var claimed []pdiDevice
	defer func() {
		for _, dev := range claimed {
			p.unlockDevice(dev.name())
		}
	}()
	for _, dev := range order {
		if err := p.claim(desired.Handle, dev, deadline); err != nil {
			p.rollback(claimed)
			return nil, err
		}
		claimed = append(claimed, dev)
	}

	nodes := make([]deviceNode, 0, len(devices))
	for _, dev := range devices {
		nodes = append(nodes, deviceNode{
			path:    p.nodePath(dev.desc.Major, dev.desc.Minor),
			devType: "b",
			major:   int64(dev.desc.Major),
			minor:   int64(dev.desc.Minor),
			mode:    pdiNodeMode,
			gid:     p.KVMGid,
			access:  "rw",
			diskseq: dev.diskseq,
		})
	}

	for _, dev := range claimed {
		data := dev.logData(desired.Handle)
		data["node"] = p.nodePath(dev.desc.Major, dev.desc.Minor)
		data["diskseq"] = dev.diskseq
		p.Logger.Info("pdi-device-claimed", data)
	}
	return nodes, nil
}

// descriptorAt reports whether the bind mount's source is a descriptor tmpfs
// and, if so, returns its parsed descriptor. A source that cannot be opened or
// whose mount is not in the table is refused, because it cannot be told apart
// from a descriptor. A descriptor tmpfs whose source is not one of
// PDIDescriptorSources is refused too.
func (p *PDIDevices) descriptorAt(bm garden.BindMount, mounts []pdiMountEntry) (pdiDescriptor, bool, error) {
	data := lager.Data{"source": bm.SrcPath, "volume": bm.DstPath}
	src, err := p.Host.OpenSource(bm.SrcPath)
	if err != nil {
		data["detail"] = err.Error()
		return pdiDescriptor{}, false, p.refuseLogged(data, "the bind mount source of the volume at %s cannot be opened", bm.DstPath)
	}
	defer src.Close()

	mountID, err := src.MountID()
	if err != nil {
		data["detail"] = err.Error()
		return pdiDescriptor{}, false, p.refuseLogged(data, "the mount of the volume at %s cannot be found: %s", bm.DstPath, err)
	}
	entry, ok := findPDIMount(mounts, mountID)
	if !ok {
		data["mount-id"] = mountID
		return pdiDescriptor{}, false, p.refuseLogged(data, "the mount of the volume at %s is not in %s", bm.DstPath, p.MountInfoPath)
	}
	if !strings.HasPrefix(entry.source, PDISourcePrefix) {
		return pdiDescriptor{}, false, nil
	}
	data["mount-source"] = entry.source
	data["fstype"] = entry.fsType
	if !knownPDISource(entry.source) {
		return pdiDescriptor{}, false, p.refuseLogged(data, "the volume at %s is a descriptor from %q, and Garden gives a device only for %s", bm.DstPath, entry.source, strings.Join(PDIDescriptorSources, ", "))
	}
	if entry.fsType != "tmpfs" {
		return pdiDescriptor{}, false, p.refuseLogged(data, "the volume at %s is a %s mount from %s, and a descriptor must be on tmpfs", bm.DstPath, entry.fsType, entry.source)
	}
	if !entry.readOnly() {
		return pdiDescriptor{}, false, p.refuseLogged(data, "the volume at %s is a descriptor tmpfs from %s whose filesystem is not read-only", bm.DstPath, entry.source)
	}

	file, err := src.ReadDescriptor()
	if err != nil {
		return pdiDescriptor{}, false, p.refuseLogged(data, "reading the descriptor of the volume at %s: %s", bm.DstPath, err)
	}
	if !file.Regular {
		return pdiDescriptor{}, false, p.refuseLogged(data, "the descriptor of the volume at %s is not a regular file", bm.DstPath)
	}
	if file.UID != pdiDescriptorOwner {
		return pdiDescriptor{}, false, p.refuseLogged(data, "the descriptor of the volume at %s is owned by uid %d, not %d", bm.DstPath, file.UID, pdiDescriptorOwner)
	}
	if file.Size >= PDIDescriptorSizeLimit || len(file.Data) >= PDIDescriptorSizeLimit {
		return pdiDescriptor{}, false, p.refuseLogged(data, "the descriptor of the volume at %s is %d bytes, and it must be shorter than %d", bm.DstPath, max(file.Size, int64(len(file.Data))), PDIDescriptorSizeLimit)
	}
	if int64(len(file.Data)) != file.Size {
		return pdiDescriptor{}, false, p.refuseLogged(data, "the descriptor of the volume at %s changed while it was read", bm.DstPath)
	}
	desc, err := parsePDIDescriptor(file.Data)
	if err != nil {
		return pdiDescriptor{}, false, p.refuseLogged(data, "the descriptor of the volume at %s: %s", bm.DstPath, err)
	}
	return desc, true, nil
}

func knownPDISource(source string) bool {
	for _, s := range PDIDescriptorSources {
		if s == source {
			return true
		}
	}
	return false
}

// checkDevice refuses a device whose size differs from the descriptor's, or
// that is mounted on the host, either itself, through any of its partitions,
// or, for a partition, through its whole disk. It returns the disk sequence
// number of the device's disk. The exclusive open in claim is the check that
// also sees an app's O_EXCL hold, swap, device-mapper claims, and mounts in
// other mount namespaces, which this mount table does not show.
func (p *PDIDevices) checkDevice(handle string, dev pdiDevice, mounts []pdiMountEntry) (uint64, error) {
	data := dev.logData(handle)
	devDir := p.devDir(dev)
	data["sysfs"] = devDir
	info, err := os.Stat(devDir)
	if err != nil {
		data["detail"] = err.Error()
		return 0, p.refuseLogged(data, "device %s named by the volume at %s is not a block device on this host", dev.numbers(), dev.volume)
	}
	if !info.IsDir() {
		return 0, p.refuseLogged(data, "device %s named by the volume at %s has no sysfs device directory", dev.numbers(), dev.volume)
	}

	sectors, err := readSysfsUint(filepath.Join(devDir, "size"))
	if err != nil {
		return 0, refuse("reading the size of device %s: %s", dev.numbers(), err)
	}
	if sectors > uint64(1<<63-1)/512 {
		return 0, refuse("device %s reports %d sectors, which overflows a byte count", dev.numbers(), sectors)
	}
	if size := int64(sectors) * 512; size != dev.desc.Size {
		return 0, p.refuseLogged(data, "device %s is %d bytes, and the descriptor of the volume at %s says %d", dev.numbers(), size, dev.volume, dev.desc.Size)
	}

	related, err := relatedBlockDevices(devDir)
	if err != nil {
		return 0, refuse("listing the partitions of device %s: %s", dev.numbers(), err)
	}

	for _, numbers := range append([]string{dev.numbers()}, related...) {
		for _, m := range mounts {
			if m.devNumbers == numbers {
				data["mounted-device"] = numbers
				data["mount-point"] = m.mountPoint
				return 0, p.refuseLogged(data, "device %s, for the volume at %s, is mounted on the host", numbers, dev.volume)
			}
		}
	}

	seq, err := readSysfsDiskseq(devDir)
	if err != nil {
		return 0, refuse("reading the disk sequence number of device %s: %s; block volumes need Linux 5.15 or later, whose sysfs reports it", dev.numbers(), err)
	}
	return seq, nil
}

func (p *PDIDevices) devDir(dev pdiDevice) string {
	return filepath.Join(p.SysfsDir, "dev", "block", dev.numbers())
}

// claim records the container as the device's owner, creates the node, and
// probes it with O_EXCL. The claim file is published whole and exclusively,
// so a second container naming the same device finds a complete claim,
// whichever Garden it is in, and a node that Garden did not create is never
// adopted or removed. While another container holds the device, claim polls
// until deadline for the holder to release it, and then refuses the
// container. On success it returns with the device's mark held, and the
// caller ends the mark. On failure it has removed what it made and ended the
// mark.
func (p *PDIDevices) claim(handle string, dev pdiDevice, deadline time.Time) error {
	name := dev.name()
	poll := pdiClaimPoll
	for {
		if p.lockDevice(name, deadline) {
			published, err := p.publishOrInspect(handle, dev)
			if published {
				break
			}
			p.unlockDevice(name)
			if err != nil {
				return err
			}
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return p.refuseHeld(handle, dev)
		}
		time.Sleep(min(poll, remaining))
		poll = min(2*poll, pdiClaimPollMax)
	}

	err := p.finishClaim(handle, dev)
	if err != nil {
		p.unlockDevice(name)
	}
	return err
}

// publishOrInspect publishes the container's claim of the device. When a
// claim is already there, it removes that claim if it is stale (removeIfStale)
// and tries once more, and otherwise reports that the device is held. The
// caller holds the device's mark.
func (p *PDIDevices) publishOrInspect(handle string, dev pdiDevice) (bool, error) {
	data := encodePDIClaim(pdiClaim{tag: p.Tag, handle: handle, diskseq: dev.diskseq})
	for attempt := 0; attempt < 2; attempt++ {
		err := publishPDIClaim(p.ClaimDir, dev.name(), data)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return false, refuse("recording the claim of device %s: %s", dev.numbers(), err)
		}
		removed, err := p.removeIfStale(p.Logger, dev.desc.Major, dev.desc.Minor)
		if err != nil {
			p.Logger.Error("pdi-claim-stale-check-failed", err, lager.Data{"device": dev.numbers()})
		}
		if !removed {
			return false, nil
		}
	}
	return false, nil
}

// finishClaim creates and probes the node of a device whose claim the
// container has just published, and checks that the device's disk is the one
// checkDevice saw. The caller holds the device's mark.
func (p *PDIDevices) finishClaim(handle string, dev pdiDevice) error {
	major, minor := dev.desc.Major, dev.desc.Minor
	nodePath := p.nodePath(major, minor)
	data := dev.logData(handle)

	data["node"] = nodePath
	if err := p.Host.Mknod(nodePath, major, minor, p.KVMGid); err != nil {
		if rmErr := os.Remove(p.claimPath(major, minor)); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			p.Logger.Error("pdi-claim-cleanup-failed", rmErr, lager.Data{"device": dev.numbers()})
		}
		data["detail"] = err.Error()
		if errors.Is(err, os.ErrExist) {
			return p.refuseLogged(data, "the node for device %s already exists on the host, and Garden did not create it", dev.numbers())
		}
		return p.refuseLogged(data, "creating the node for device %s failed: %s", dev.numbers(), unwrapPathError(err))
	}

	if err := p.Host.Probe(nodePath, major, minor, dev.desc.Size); err != nil {
		p.cleanUpClaim(dev)
		data["detail"] = err.Error()
		return p.refuseLogged(data, "device %s for the volume at %s failed the exclusive probe: %s", dev.numbers(), dev.volume, err)
	}

	// A disk keeps its sequence number for as long as it is attached, and a
	// disk attached later gets a higher one, so the same number before and
	// after the probe means the probe opened the disk that checkDevice saw.
	after, err := readSysfsDiskseq(p.devDir(dev))
	if err != nil || after != dev.diskseq {
		p.cleanUpClaim(dev)
		data["diskseq-before"] = dev.diskseq
		data["diskseq-after"] = after
		if err != nil {
			data["detail"] = err.Error()
		}
		return p.refuseLogged(data, "device %s for the volume at %s changed while Garden checked it: another disk now has that device number", dev.numbers(), dev.volume)
	}
	return nil
}

// cleanUpClaim releases a device whose claim failed after its node was made.
// The caller holds the device's mark.
func (p *PDIDevices) cleanUpClaim(dev pdiDevice) {
	if err := p.release(p.Logger, dev.desc.Major, dev.desc.Minor); err != nil {
		p.Logger.Error("pdi-device-probe-cleanup-failed", err, lager.Data{"device": dev.numbers()})
	}
}

// refuseHeld refuses a device that another container still holds once the
// wait has run out. The refusal names only the device and the volume. The
// holder's handle and tag go to Garden's log, and so does a holder whose
// claim records another disk sequence number than the device has now, whose
// container keeps a grant for a device number that now names another disk.
func (p *PDIDevices) refuseHeld(handle string, dev pdiDevice) error {
	data := dev.logData(handle)
	data["waited"] = p.ClaimWait.String()
	raw, err := os.ReadFile(p.claimPath(dev.desc.Major, dev.desc.Minor))
	switch {
	case err != nil:
		data["holder"] = "a claim in progress in this Garden, or one released since"
	default:
		if c, ok := parsePDIClaim(raw); ok {
			data["holder-handle"] = c.handle
			data["holder-tag"] = c.tag
			data["holder-diskseq"] = c.diskseq
			if c.diskseq != 0 && c.diskseq != dev.diskseq {
				p.Logger.Error("pdi-claimed-device-replaced", errors.New("the holder's container keeps a grant for a device number that now names another disk"), lager.Data{
					"device": dev.numbers(), "holder-handle": c.handle, "holder-tag": c.tag,
					"holder-diskseq": c.diskseq, "current-diskseq": dev.diskseq,
				})
			}
		} else {
			data["holder"] = "a claim Garden cannot read, which has a node"
		}
	}
	return p.refuseLogged(data, "device %s for the volume at %s is already in use on this cell, and Garden waited %s for it to be released", dev.numbers(), dev.volume, p.ClaimWait)
}

// rollback releases the devices that one Claim call had already claimed. The
// caller holds their marks.
func (p *PDIDevices) rollback(claimed []pdiDevice) {
	for _, dev := range claimed {
		if err := p.release(p.Logger, dev.desc.Major, dev.desc.Minor); err != nil {
			p.Logger.Error("pdi-device-rollback-failed", err, lager.Data{"device": dev.numbers()})
		}
	}
}

// lockDevice marks the device named name as in use by this call, waiting
// until deadline while another call of this Garden has it marked. It reports
// false when the wait runs out. unlockDevice ends the mark.
func (p *PDIDevices) lockDevice(name string, deadline time.Time) bool {
	for {
		p.busyMu.Lock()
		if p.busy == nil {
			p.busy = map[string]chan struct{}{}
		}
		done, held := p.busy[name]
		if !held {
			p.busy[name] = make(chan struct{})
			p.busyMu.Unlock()
			return true
		}
		p.busyMu.Unlock()

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		timer := time.NewTimer(remaining)
		select {
		case <-done:
			timer.Stop()
		case <-timer.C:
			return false
		}
	}
}

func (p *PDIDevices) unlockDevice(name string) {
	p.busyMu.Lock()
	done, held := p.busy[name]
	delete(p.busy, name)
	p.busyMu.Unlock()
	if held {
		close(done)
	}
}

// release removes a device's node, then its claim. A claim without a node,
// which a crash between the two steps leaves, is released the same way. A path
// that is not the block node is logged and left in place, and the claim goes
// anyway, because a later claim of the device still refuses the existing path.
// The caller holds the device's mark and has checked that the claim is its
// own.
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

// removeIfStale removes the claim of major:minor when it is empty or cannot be
// parsed and no container can hold the device through it, and reports whether
// it removed it. Garden publishes every claim whole, before it makes the
// node, so such a claim is one that an earlier Garden, which created the file
// before writing it, left when it was killed in between. The missing node
// shows that no container was given the device through it. A malformed claim
// with a node stays, because Garden cannot tell whose it is. The claim is
// removed only while the path still holds the file that was read.
func (p *PDIDevices) removeIfStale(log lager.Logger, major, minor uint32) (bool, error) {
	path := p.claimPath(major, minor)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	defer f.Close()
	read, err := f.Stat()
	if err != nil {
		return false, err
	}
	data, err := io.ReadAll(io.LimitReader(f, pdiClaimSizeLimit))
	if err != nil {
		return false, err
	}
	if _, ok := parsePDIClaim(data); ok {
		return false, nil
	}
	if _, err := os.Lstat(p.nodePath(major, minor)); !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	now, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	if !os.SameFile(read, now) {
		return false, nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	log.Info("pdi-claim-stale-removed", lager.Data{"device": fmt.Sprintf("%d:%d", major, minor), "bytes": len(data)})
	return true, nil
}

// Release removes the node and claim of every device that this Garden gave to
// the container. It is safe to call for a container that has none, and more
// than once. It returns an error only for a claim that the container owns, so
// an unreadable or foreign entry in the shared claim directory, which is
// logged and left alone, never fails another container's destroy.
func (p *PDIDevices) Release(log lager.Logger, handle string) error {
	return p.releaseWhere(log, false, func(owner string) bool { return owner == handle })
}

// ReleaseUnknown removes the node and claim of every device that this Garden
// gave to a container not among known. Garden calls it at start-up, before it
// serves requests, to release devices that a crash left claimed by a container
// it never created, and to remove stale claims (removeIfStale). Claims of
// other Gardens are logged and not touched.
func (p *PDIDevices) ReleaseUnknown(log lager.Logger, known []string) error {
	knownSet := make(map[string]struct{}, len(known))
	for _, h := range known {
		knownSet[h] = struct{}{}
	}
	return p.releaseWhere(log, true, func(owner string) bool {
		_, ok := knownSet[owner]
		return !ok
	})
}

// releaseWhere releases the claims with this Garden's tag whose handle match
// picks. For each one it takes the device's mark, reads the owner again, and
// only then removes the node and claim, so a claim that another call has
// released and a new owner has taken is never removed on the strength of a
// stale read. A claim that names another container needs no mark, so a
// release never waits on another container's claim. sweep also removes stale
// claims and logs the claims of other tags.
func (p *PDIDevices) releaseWhere(log lager.Logger, sweep bool, match func(handle string) bool) error {
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
		c, ok, err := p.readClaim(major, minor)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Error("pdi-claim-unreadable", err, lager.Data{"name": entry.Name()})
			}
			continue
		}
		if !ok {
			if !sweep {
				log.Info("pdi-claim-malformed", lager.Data{"name": entry.Name()})
				continue
			}
			p.sweepMalformed(log, entry.Name(), major, minor)
			continue
		}
		if c.tag != p.Tag {
			if sweep {
				log.Info("pdi-claim-of-another-tag", lager.Data{"name": entry.Name(), "tag": c.tag, "handle": c.handle})
			}
			continue
		}
		if !match(c.handle) {
			continue
		}
		if err := p.releaseOwned(log, c, major, minor); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// releaseOwned releases the device major:minor whose claim read as c, after it
// has taken the device's mark and found the same owner in the claim again.
func (p *PDIDevices) releaseOwned(log lager.Logger, c pdiClaim, major, minor uint32) error {
	name := pdiName(major, minor)
	device := fmt.Sprintf("%d:%d", major, minor)
	if !p.lockDevice(name, time.Now().Add(pdiReleaseWait)) {
		return fmt.Errorf("device %s of container %q is still being claimed or released by another call after %s; destroy the container again", device, c.handle, pdiReleaseWait)
	}
	defer p.unlockDevice(name)

	again, ok, err := p.readClaim(major, minor)
	if err != nil || !ok || again.tag != c.tag || again.handle != c.handle {
		return nil
	}
	if err := p.release(log, major, minor); err != nil {
		return err
	}
	log.Info("pdi-device-released", lager.Data{"handle": c.handle, "device": device})
	return nil
}

// sweepMalformed removes a malformed claim at start-up when removeIfStale
// finds it stale, and logs it otherwise.
func (p *PDIDevices) sweepMalformed(log lager.Logger, name string, major, minor uint32) {
	if !p.lockDevice(name, time.Now().Add(pdiReleaseWait)) {
		log.Info("pdi-claim-malformed", lager.Data{"name": name})
		return
	}
	defer p.unlockDevice(name)
	removed, err := p.removeIfStale(log, major, minor)
	if err != nil {
		log.Error("pdi-claim-stale-check-failed", err, lager.Data{"name": name})
		return
	}
	if !removed {
		log.Info("pdi-claim-malformed", lager.Data{"name": name})
	}
}

// readClaim reads and parses the claim of major:minor. It reports false for a
// claim that is empty or cannot be parsed.
func (p *PDIDevices) readClaim(major, minor uint32) (pdiClaim, bool, error) {
	f, err := os.Open(p.claimPath(major, minor))
	if err != nil {
		return pdiClaim{}, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, pdiClaimSizeLimit))
	if err != nil {
		return pdiClaim{}, false, err
	}
	c, ok := parsePDIClaim(data)
	return c, ok, nil
}

// pdiClaimSizeLimit bounds how much of a claim file Garden reads. A claim is
// a tag, a handle, and a number, which is far shorter.
const pdiClaimSizeLimit = 64 << 10

// pdiClaim is the content of a claim file, which is the Garden's tag, the
// container's handle, and the disk sequence number of the device's disk, each
// followed by a newline. A claim that an earlier Garden wrote holds the tag, a
// newline, and the handle, and no sequence number, which reads as 0.
type pdiClaim struct {
	tag     string
	handle  string
	diskseq uint64
}

func encodePDIClaim(c pdiClaim) []byte {
	return []byte(c.tag + "\n" + c.handle + "\n" + strconv.FormatUint(c.diskseq, 10) + "\n")
}

// parsePDIClaim reports whether data is a claim in the form encodePDIClaim
// writes, or in the earlier form without a sequence number.
func parsePDIClaim(data []byte) (pdiClaim, bool) {
	lines := strings.Split(string(data), "\n")
	switch len(lines) {
	case 2:
		if lines[1] == "" {
			return pdiClaim{}, false
		}
		return pdiClaim{tag: lines[0], handle: lines[1]}, true
	case 4:
		if lines[1] == "" || lines[3] != "" {
			return pdiClaim{}, false
		}
		seq, err := parsePDIDecimal(lines[2], 64)
		if err != nil || seq == 0 {
			return pdiClaim{}, false
		}
		return pdiClaim{tag: lines[0], handle: lines[1], diskseq: seq}, true
	}
	return pdiClaim{}, false
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

// readSysfsDiskseq returns the disk sequence number of the disk that holds
// the device in devDir. A partition has no diskseq file of its own and shares
// its whole disk's number, as the BLKGETDISKSEQ ioctl on the partition does.
// The kernel numbers disks from 1, so 0 is an error.
func readSysfsDiskseq(devDir string) (uint64, error) {
	dir := devDir
	if _, err := os.Lstat(filepath.Join(devDir, "partition")); err == nil {
		real, err := filepath.EvalSymlinks(devDir)
		if err != nil {
			return 0, unwrapPathError(err)
		}
		dir = filepath.Dir(real)
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, unwrapPathError(err)
	}
	seq, err := readSysfsUint(filepath.Join(dir, "diskseq"))
	if err != nil {
		return 0, err
	}
	if seq == 0 {
		return 0, errors.New("the disk sequence number is 0")
	}
	return seq, nil
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
// escapes. The kernel separates the fields with one space each, and it writes
// an empty field for an empty source, so the line is split on single spaces.
// A line that does not have this shape is an error, because the mounted check
// must not skip a mount it failed to read.
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
		fields := strings.Split(line, " ")
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+3 >= len(fields) {
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
// major is not 0. size is greater than zero. uuid is the ext4 superblock's
// UUID in lower-case 8-4-4-4-12 form, and not all zeros. disk_name is
// everything after the first "=". It is not empty, it holds only ASCII
// letters, digits, '.', '_', and '-', it does not start with '-', and it is
// not "." or "..". vm-launch's copy of the parser applies the same checks.
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
	if major == 0 {
		return d, fmt.Errorf("descriptor major 0 numbers the kernel's anonymous devices, not a block disk")
	}
	if size == 0 {
		return d, fmt.Errorf("descriptor size 0 is not a positive byte count")
	}
	if !validPDIUUID(values["uuid"]) {
		return d, fmt.Errorf("descriptor uuid %q is not a lower-case 8-4-4-4-12 UUID", values["uuid"])
	}
	if values["uuid"] == pdiZeroUUID {
		return d, fmt.Errorf("descriptor uuid is all zeros, which cannot identify a filesystem")
	}
	name := values["disk_name"]
	if err := validPDIDiskName(name); err != nil {
		return d, err
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

// pdiZeroUUID is the all-zero UUID, which identifies no filesystem.
const pdiZeroUUID = "00000000-0000-0000-0000-000000000000"

// validPDIDiskName accepts the disk names the driver writes. The character
// set leaves out control, bidirectional, and zero-width characters, so a name
// reaches the log as it reads.
func validPDIDiskName(s string) error {
	if s == "" {
		return fmt.Errorf("descriptor disk_name is empty")
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
