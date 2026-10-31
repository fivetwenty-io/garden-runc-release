//go:build linux

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
)

// The persistent disk interface. A volume service reaches a VM app through a
// diskProvider compiled into vm-launch. The registry picks the provider that
// owns the volume's mount, and the provider's Prepare does all of its work
// before the hypervisor starts: it creates or checks the disk, takes its
// fence, and returns one attachment. The attachment is the only thing the
// hypervisor and guest code see, so neither learns which volume service is
// underneath. Each provider registers itself from its own init.

// mountRecord is what vm-launch learns about the mount behind a volume: the
// volume's path from the environment, and the volume's line in
// /proc/self/mountinfo, field for field. Providers decide from it.
type mountRecord struct {
	// ContainerDir is the volume's path from VCAP_SERVICES, which the guest
	// mounts at the same path. The mount it names is the one that holds this
	// directory, whose own mount point (MountPoint) may be a parent.
	ContainerDir string

	// MountID and ParentID are the mount's ID and its parent's ID.
	MountID  uint64
	ParentID uint64
	// Major and Minor are the device numbers of the filesystem.
	Major uint32
	Minor uint32
	// Root is the path within the filesystem that the mount shows, with its
	// escapes decoded. It is "/" for a mount of a whole filesystem.
	Root string
	// MountPoint is where the mount is, with its escapes decoded.
	MountPoint string
	// MountOptions are the per-mount options, such as "rw" and "nodev".
	MountOptions []string
	// OptionalFields are the tagged fields between the mount options and the
	// separator, such as "shared:5". There may be none.
	OptionalFields []string
	// FSType is the filesystem type, such as "fuse.juicefs".
	FSType string
	// Source is the mount source with its escapes decoded: a device, a
	// remote path, or a name the filesystem chose.
	Source string
	// SuperOptions are the superblock options, such as "rw" and
	// "local_lock=none".
	SuperOptions []string
}

// matchStrength is how sure a provider is that it owns a mount.
type matchStrength int

const (
	noMatch matchStrength = iota
	weakMatch
	strongMatch
)

// attachMode is how a disk reaches the guest.
type attachMode int

const (
	// attachFileImage is an image file on a mounted filesystem, which the
	// hypervisor gets as one open file and the guest formats when blank.
	attachFileImage attachMode = iota + 1
	// attachBlock is a whole block device that no host filesystem has
	// mounted, which the hypervisor gets as one open device node and the
	// guest never formats.
	attachBlock
)

func (m attachMode) String() string {
	switch m {
	case attachFileImage:
		return "file-image mode"
	case attachBlock:
		return "block mode"
	}
	return fmt.Sprintf("attach mode %d", int(m))
}

// fenceKind is how far a provider's single writer lock reaches.
type fenceKind int

const (
	// fenceDistributedFlock is a flock that holds across cells, as it does on
	// JuiceFS, so that two instances on two cells never write one disk.
	fenceDistributedFlock fenceKind = iota + 1
	// fenceExclusiveOpen is an O_EXCL open of a block device, which holds
	// against every mount and every other exclusive open on the cell, plus
	// a volume service that attaches the device to one cell at a time.
	fenceExclusiveOpen
)

// sharing says whether a provider's volumes can be served as a share.
type sharing int

const (
	// sharingPrivate is one writer per disk, which every volume gets unless
	// the app asks for a share. A provider that declares nothing, the zero
	// value, is undeclared, and grantShares refuses its shares as it refuses
	// a private provider's, so a provider is never shared by accident.
	sharingPrivate sharing = iota + 1
	// sharingShared is a volume that vm-launch offers over virtiofs on QEMU
	// when the app asks for a share and the operator allows it.
	sharingShared
)

// capabilities describes what a provider does with a mount it owns.
type capabilities struct {
	// Modes are the attach modes the provider offers.
	Modes []attachMode
	// Fence is how far the provider's lock reaches.
	Fence fenceKind
	// Sharing says whether the provider's volumes can be shared. The zero
	// value is undeclared, which grantShares treats as private.
	Sharing sharing
	// MaxInstances is how many instances of an app can use one of the
	// provider's disks at once, or 0 for no limit. A provider whose disk
	// attaches to one VM at a time says 1.
	MaxInstances int
}

// privateMode is the mode vm-launch asks a provider with capabilities c for
// when the app wants a private disk: file-image mode when the provider offers
// it, and otherwise block mode. checkCapabilities has refused a provider
// that offers neither.
func privateMode(c capabilities) attachMode {
	if !slices.Contains(c.Modes, attachFileImage) && slices.Contains(c.Modes, attachBlock) {
		return attachBlock
	}
	return attachFileImage
}

// prepareRequest is what Prepare gets for one volume.
type prepareRequest struct {
	Mount mountRecord
	// ImageName is the disk's file name in the volume root, which
	// volumesFromEnv derived from the application, process type, and
	// instance index.
	ImageName string
	// Index is the app instance's index, from CF_INSTANCE_INDEX, which a
	// provider that allows one instance checks.
	Index int
	Mode  attachMode
	// Size is the requested floor for a file image, from VM_VOLUMES: the
	// engine grows a smaller image to it and never shrinks a larger one. Zero
	// leaves the engine's default, which is 1 GiB. A block provider ignores
	// it, because a block device has the size of its plan.
	Size int64
	// Logger takes the lines a provider prints that are not errors, such as
	// the line for an image kept at a larger size than asked for. It may be
	// nil, which leaves them out.
	Logger *log.Logger
	// Signals stops a lock wait, or a grow that writes zeros, early.
	Signals <-chan os.Signal
	// LockBudget is the wait for fences that the launch's volumes share. A
	// provider that waits for a fence takes the time it waits from it, so
	// that the waits of all the volumes together stay within one limit. It
	// may be nil, which leaves the provider's own limit.
	LockBudget *lockBudget
	// BeforeLock, when set, is called with the opened and checked disk
	// before the provider takes its fence. An error from it refuses the
	// volume, and the provider must release the disk and return that error.
	// It lets vm-launch refuse a disk that an earlier volume of the launch
	// already holds, which the provider's fence would otherwise wait for.
	BeforeLock func(disk *os.File) error
}

// fileImageOptions returns base with what req sets for a file image: the
// size floor when req asks for one, the lock budget, the check before the
// lock, and the logger for the engine's lines.
func (req prepareRequest) fileImageOptions(base imageOptions) imageOptions {
	o := base
	if req.Size != 0 {
		o.Size = req.Size
	}
	o.BeforeLock = req.BeforeLock
	o.LockBudget = req.LockBudget
	if req.Logger != nil {
		o.Logf = req.Logger.Printf
	}
	return o
}

// attachment is a prepared, fenced disk. It stays fenced until Release.
type attachment struct {
	// File is the disk, open read-write, which the hypervisor reopens
	// through /proc/self/fd: an image file in file-image mode, or the
	// block device node in block mode.
	File *os.File
	// Mode is how the disk reaches the guest. A provider may leave it unset,
	// and vm-launch then records the mode it asked for; a provider that sets
	// another mode is refused.
	Mode attachMode
	// ID is the drive's identity, which newGuestDrives records once the
	// launch knows its backend and volume order: the serial vm-launch gives
	// the drive on QEMU, or the identity it predicts Firecracker gives the
	// drive. Providers leave it empty.
	ID string
	// Release drops the fence and closes File. vm-launch calls it once the
	// hypervisor has exited or never started. It never deletes the disk.
	Release func() error
}

// diskProvider is one volume service's side of the interface. A provider that
// opens an image must go through openVolumeImage, with the mount ID of its
// mountRecord in the guestVolume, so that the mount ID is rechecked against
// the directory it opens. A provider that opens a block device must go
// through openBlockVolume, which makes the same recheck on the directory that
// holds the device's descriptor before it reads the descriptor.
type diskProvider interface {
	// Name is how log lines name the provider, such as "JuiceFS".
	Name() string
	// Match says whether the provider owns the mount.
	Match(m mountRecord) matchStrength
	// Capabilities describes what the provider does with a mount it owns.
	Capabilities(m mountRecord) capabilities
	// Prepare creates or checks the disk, fences it, and returns it. Its
	// errors carry the same kinds as the image code's, so stepExitCode maps
	// a signal during the lock wait to 128+N and every other failure to 125.
	Prepare(req prepareRequest) (*attachment, error)
}

// checkAttachment refuses what a provider's Prepare returned without an
// error but without a usable disk: no attachment, no file, or no Release.
// The refusal names the provider. A half-built attachment is cleaned up with
// whichever of its parts exists, so a bad provider does not leave the disk
// fenced, and a cleanup that fails is logged.
func checkAttachment(p diskProvider, att *attachment, logger *log.Logger) error {
	var missing string
	switch {
	case att == nil:
		missing = "no attachment"
	case att.File == nil:
		missing = "no disk file"
	case att.Release == nil:
		missing = "no Release function"
	default:
		return nil
	}
	discardAttachment(att, logger)
	return fmt.Errorf("the %s volume provider prepared the disk without an error but returned %s", p.Name(), missing)
}

// discardAttachment cleans up an attachment vm-launch will not use, with
// whichever of its parts exists, and logs a cleanup that fails the way the
// release at the end of a launch is logged. A nil attachment needs nothing.
func discardAttachment(att *attachment, logger *log.Logger) {
	if att == nil {
		return
	}
	switch {
	case att.Release != nil:
		if err := att.Release(); err != nil {
			logger.Printf("releasing the volume disk: %v", err)
		}
	case att.File != nil:
		if err := att.File.Close(); err != nil {
			logger.Printf("closing the volume disk: %v", err)
		}
	}
}

// providerRegistry is the set of providers compiled into vm-launch, kept in
// name order so that every line that lists them reads the same.
type providerRegistry struct {
	providers []diskProvider
}

// diskProviders is the registry vm-launch selects from. Providers add
// themselves from their init functions through registerDiskProvider.
var diskProviders = &providerRegistry{}

// registerDiskProvider adds p to diskProviders. It panics on a nil
// provider, an empty name, or a name already registered, which are mistakes
// in vm-launch's own code that must fail every launch rather than pick a
// provider by accident.
func registerDiskProvider(p diskProvider) {
	if err := diskProviders.register(p); err != nil {
		panic(err)
	}
}

// register adds p, in name order.
func (r *providerRegistry) register(p diskProvider) error {
	if p == nil {
		return errors.New("registering a nil volume provider")
	}
	name := p.Name()
	if name == "" {
		return errors.New("registering a volume provider with no name")
	}
	i, found := slices.BinarySearchFunc(r.providers, name, func(q diskProvider, n string) int {
		return strings.Compare(q.Name(), n)
	})
	if found {
		return fmt.Errorf("registering volume provider %s twice", name)
	}
	r.providers = slices.Insert(r.providers, i, p)
	return nil
}

// supportedLine ends every refusal of a volume that no provider owns. It
// names the registered providers, so the line tells an operator what would
// have worked: "VM backends support only JuiceFS volumes today".
func (r *providerRegistry) supportedLine() string {
	names := make([]string, 0, len(r.providers))
	for _, p := range r.providers {
		names = append(names, p.Name())
	}
	return "VM backends support only " + joinNames(names, "no") + " volumes today"
}

// joinNames joins names for a line: "A", "A and B", or "A, B, and C", and
// none when there are no names.
func joinNames(names []string, none string) string {
	switch len(names) {
	case 0:
		return none
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	default:
		return strings.Join(names[:len(names)-1], ", ") + ", and " + names[len(names)-1]
	}
}

// selectProvider returns the provider that owns m. The one strong match
// wins; with no strong match, a single weak match wins. No match refuses the
// volume with a line that names the filesystem type and the registered
// providers. Two providers that match equally strongly refuse it too, with a
// line that names them, because vm-launch never guesses which service owns a
// disk. The chosen provider must offer file-image mode with a fence that
// holds across cells, or block mode with an exclusive open and one instance,
// or the volume is refused before anything is created. The
// refusals in mountRefusals come first, so a mount one of them names is
// refused with its own line whatever providers are registered.
func (r *providerRegistry) selectProvider(m mountRecord) (diskProvider, error) {
	for _, refuse := range mountRefusals {
		if err := refuse(m); err != nil {
			return nil, err
		}
	}
	var strong, weak []diskProvider
	for _, p := range r.providers {
		switch p.Match(m) {
		case strongMatch:
			strong = append(strong, p)
		case weakMatch:
			weak = append(weak, p)
		}
	}
	candidates := strong
	if len(candidates) == 0 {
		candidates = weak
	}
	switch len(candidates) {
	case 0:
		return nil, fmt.Errorf("volume path %s is a %s mount; %s", quoteForLog(m.ContainerDir), quoteForLog(m.FSType), r.supportedLine())
	case 1:
	default:
		names := make([]string, 0, len(candidates))
		for _, p := range candidates {
			names = append(names, p.Name())
		}
		return nil, fmt.Errorf("volume path %s is a %s mount, which the %s volume providers all claim; vm-launch refuses a volume whose provider it cannot tell",
			quoteForLog(m.ContainerDir), quoteForLog(m.FSType), joinNames(names, "no"))
	}
	p := candidates[0]
	if err := checkCapabilities(p, p.Capabilities(m)); err != nil {
		return nil, fmt.Errorf("volume path %s: %w", quoteForLog(m.ContainerDir), err)
	}
	return p, nil
}

// checkCapabilities refuses a provider that vm-launch cannot attach safely.
// The mode it checks is the one privateMode picks. A file-image provider's
// lock must hold across cells, and a block provider must fence with an
// exclusive open and allow one instance, because otherwise two instances
// could write one disk. A provider that offers neither mode is refused,
// because those are the modes the hypervisor code attaches, and so is a
// negative instance limit, which would read as no limit.
func checkCapabilities(p diskProvider, c capabilities) error {
	if c.MaxInstances < 0 {
		return fmt.Errorf("the %s volume provider declares an instance limit of %d; a limit is 0 for none or a positive number of instances", p.Name(), c.MaxInstances)
	}
	switch {
	case slices.Contains(c.Modes, attachFileImage):
		if c.Fence != fenceDistributedFlock {
			return fmt.Errorf("the %s volume provider declares no lock that holds across cells; VM backends allow one writer per disk", p.Name())
		}
	case slices.Contains(c.Modes, attachBlock):
		if c.Fence != fenceExclusiveOpen {
			return fmt.Errorf("the %s volume provider attaches a block device without an exclusive open; VM backends allow one writer per disk", p.Name())
		}
		if c.MaxInstances != 1 {
			return fmt.Errorf("the %s volume provider attaches a block device without limiting it to one instance; VM backends allow one writer per disk", p.Name())
		}
	default:
		return fmt.Errorf("the %s volume provider offers neither %s nor %s, the modes VM backends attach", p.Name(), attachFileImage, attachBlock)
	}
	return nil
}

// checkInstanceLimit refuses the instance index of a volume whose provider
// declares capabilities c, when c limits how many instances can use one of
// its disks and index is not below the limit. vm-launch makes the check
// itself, before Prepare, so that the limit holds whether or not a provider
// checks the index too. dir is the volume path and mode the mode vm-launch
// asks for, for the refusal.
func checkInstanceLimit(p diskProvider, c capabilities, dir string, mode attachMode, index int) error {
	if c.MaxInstances > 0 && index >= c.MaxInstances {
		return instanceLimitError(p, dir, mode, c.MaxInstances, index)
	}
	return nil
}

// instanceLimitError is the refusal of instance index of the volume at dir,
// whose provider p lets only limit instances use one disk in mode.
func instanceLimitError(p diskProvider, dir string, mode attachMode, limit, index int) error {
	if limit == 1 {
		return fmt.Errorf("volume path %s is a %s in %s, which the volume service attaches to one VM at a time, so only instance 0 can use it, and this is instance %d; scale the app to one instance or give each instance a service of its own",
			quoteForLog(dir), p.Name(), mode, index)
	}
	return fmt.Errorf("volume path %s is a %s in %s, which the volume service attaches to %d VMs at a time, so only instances 0 to %d can use it, and this is instance %d; scale the app to %d instances or give each instance a service of its own",
		quoteForLog(dir), p.Name(), mode, limit, limit-1, index, limit)
}
