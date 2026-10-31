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
)

func (m attachMode) String() string {
	switch m {
	case attachFileImage:
		return "file-image mode"
	}
	return fmt.Sprintf("attach mode %d", int(m))
}

// fenceKind is how far a provider's single writer lock reaches.
type fenceKind int

const (
	// fenceDistributedFlock is a flock that holds across cells, as it does on
	// JuiceFS, so that two instances on two cells never write one disk.
	fenceDistributedFlock fenceKind = iota + 1
)

// capabilities describes what a provider does with a mount it owns.
type capabilities struct {
	// Modes are the attach modes the provider offers.
	Modes []attachMode
	// Fence is how far the provider's lock reaches.
	Fence fenceKind
}

// prepareRequest is what Prepare gets for one volume.
type prepareRequest struct {
	Mount mountRecord
	// ImageName is the disk's file name in the volume root, which
	// volumeFromEnv derived from the application, process type, and
	// instance index.
	ImageName string
	Mode      attachMode
	// Signals stops a lock wait early.
	Signals <-chan os.Signal
}

// attachment is a prepared, fenced disk. It stays fenced until Release.
type attachment struct {
	// File is the disk, open read-write, which the hypervisor reopens
	// through /proc/self/fd.
	File *os.File
	// Release drops the fence and closes File. vm-launch calls it once the
	// hypervisor has exited or never started. It never deletes the disk.
	Release func() error
}

// diskProvider is one volume service's side of the interface.
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
			logger.Printf("releasing the volume image: %v", err)
		}
	case att.File != nil:
		if err := att.File.Close(); err != nil {
			logger.Printf("closing the volume image: %v", err)
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
// disk. The chosen provider must offer file-image mode and a fence that holds
// across cells, or the volume is refused before anything is created. The
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

// checkCapabilities refuses a provider that vm-launch cannot attach safely:
// one that offers no file-image mode, which is the only mode the hypervisor
// code attaches, or one whose lock does not hold across cells, which would
// let two instances write one disk.
func checkCapabilities(p diskProvider, c capabilities) error {
	if !slices.Contains(c.Modes, attachFileImage) {
		return fmt.Errorf("the %s volume provider offers %s, the only mode VM backends attach", p.Name(), attachFileImage)
	}
	if c.Fence != fenceDistributedFlock {
		return fmt.Errorf("the %s volume provider declares no lock that holds across cells; VM backends allow one writer per disk", p.Name())
	}
	return nil
}
