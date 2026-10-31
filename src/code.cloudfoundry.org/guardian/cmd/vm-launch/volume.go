//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// Volume discovery. Cloud Controller copies each service binding's
// volume_mounts from the broker's bind response into VCAP_SERVICES, and the
// wrapped launcher's environment reaches vm-launch untouched, so vm-launch
// learns the volume's container path from there. Garden's bind mounts carry
// no marker that tells a volume from the other bind mounts.
const (
	vcapServicesEnv    = "VCAP_SERVICES"
	vcapApplicationEnv = "VCAP_APPLICATION"
	instanceIndexEnv   = "CF_INSTANCE_INDEX"
	volumeModeReadOnly = "r"
	volumeModeRW       = "rw"

	// maxVolumes is the most volume mounts a VM app may have. Each one is a
	// drive of its own, vol0 to vol3, ahead of the guest root's drive.
	maxVolumes = 4

	// maxVolumePathLen bounds container_dir. The guest shell and the kernel
	// both handle far longer paths; the bound keeps error lines short and
	// rejects nonsense early.
	maxVolumePathLen = 1024

	// maxInstanceIndex is the highest CF_INSTANCE_INDEX vm-launch accepts.
	maxInstanceIndex = 65535

	// maxLoggedValueLen bounds how much of a rejected value an error line
	// repeats.
	maxLoggedValueLen = 64
)

// applicationIDPattern is the only application_id vm-launch puts into a file
// name: a lowercase UUID, which is what Cloud Controller issues.
var applicationIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// processTypePattern is the only process_type vm-launch puts into a file
// name. A process type comes from a Procfile or a manifest, not from Cloud
// Controller, so it is checked against a deliberately narrow set that is safe
// in a file name: lowercase letters, digits, underscores, and hyphens,
// starting with a letter or digit. CF may accept more, and a process type
// outside this set fails the launch. The instance index after it is decimal
// without a hyphen, so a name maps back to exactly one process type and
// index.
var processTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// reservedGuestDirs are guest paths /init needs for itself. A volume mounted
// on or below one of them would hide the busybox userland, the device or
// proc nodes, the resolver configuration, or the files /init runs.
var reservedGuestDirs = []string{"/bin", "/dev", "/etc", "/init", "/proc", "/rvm", "/sys"}

// guestVolume is one volume a VM app gets: the path the container sees, at
// which the guest mounts the image, and the image's file name in the volume
// root.
type guestVolume struct {
	ContainerDir string
	ImageName    string
	// Index is the instance index the image name carries, which a provider
	// that allows one instance checks.
	Index int

	// MountID is the ID of the mount that findVolumeProvider found
	// ContainerDir on. When MountIDKnown is set, openVolumeImage refuses a
	// directory that is on another mount, so the directory it opens is the
	// one that was inspected.
	MountID      uint64
	MountIDKnown bool

	// Settings are the mode and size the app chose for the volume in
	// VM_VOLUMES. The zero value is private at the default size, which is
	// what a volume gets when the app sets nothing.
	Settings volumeSettings
}

// vcapServices is the part of VCAP_SERVICES vm-launch reads: every label's
// bindings, and every binding's volume mounts. Credentials and the rest of
// each binding are never decoded.
type vcapServices map[string][]struct {
	VolumeMounts []struct {
		ContainerDir string `json:"container_dir"`
		Mode         string `json:"mode"`
	} `json:"volume_mounts"`
}

// volumesFromEnv returns the guest volumes named in VCAP_SERVICES, in
// volume order, or none when the app has none. More than maxVolumes volume
// mounts, two mounts on one path, a path on or under another volume's path,
// a mode other than rw, a container path the guest cannot use, a missing or malformed application_id or process_type in
// VCAP_APPLICATION, a bad CF_INSTANCE_INDEX, and a task are errors, so a
// misconfigured app fails to start instead of losing data to the wrong
// volume. Errors never repeat VCAP_SERVICES, which carries credentials.
// lookup reads the environment the rest of vm-launch shares (see
// lastWinsEnv), so the volumes come from the pre-resolution VCAP_SERVICES,
// which the guest also gets apart from resolved credentials. vm-launch reads
// the volumes before it resolves CredHub references, which replace
// credentials and never a volume mount.
//
// Volume order is the byte order of the container paths. It decides each
// volume's drive, file descriptor, and lock order, so it depends on nothing
// but the paths: not on the order of the labels in VCAP_SERVICES, which is a
// JSON object, and not on the order of Go's map iteration. Two instances
// with the same bindings therefore take their locks in the same order. Two
// instances whose bindings differ, for example while an app is being
// rebound, may take them in different orders, and each then holds an image
// the other wants. Neither deadlocks, because the lock wait is bounded and
// gives up and releases what the launch holds. Every volume of an instance
// gets the same image name, because each image lives in the root of its own
// volume.
//
// No volume path may be on or under another, so the guest never has to order
// its mounts, and a mount can never hide another volume.
func volumesFromEnv(lookup func(string) (string, bool)) ([]guestVolume, error) {
	raw, ok := lookup(vcapServicesEnv)
	if !ok {
		return nil, nil
	}
	var services vcapServices
	if err := json.Unmarshal([]byte(raw), &services); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			return nil, errors.New("VCAP_SERVICES is not valid JSON for service bindings: want an object of binding lists")
		}
		return nil, errors.New("VCAP_SERVICES is not valid JSON")
	}

	type mount struct{ dir, mode string }
	var mounts []mount
	for _, label := range slices.Sorted(maps.Keys(services)) {
		for _, b := range services[label] {
			for _, vm := range b.VolumeMounts {
				mounts = append(mounts, mount{dir: vm.ContainerDir, mode: vm.Mode})
			}
		}
	}
	switch {
	case len(mounts) == 0:
		return nil, nil
	case len(mounts) > maxVolumes:
		return nil, fmt.Errorf("VM backends support up to %d volume mounts; this app has %d", maxVolumes, len(mounts))
	}
	// The labels are sorted and each binding list keeps its order, so two
	// mounts on one path keep an order of their own too, and the first
	// error is the same on every start.
	slices.SortStableFunc(mounts, func(a, b mount) int { return strings.Compare(a.dir, b.dir) })

	for _, m := range mounts {
		switch m.mode {
		case volumeModeRW:
		case volumeModeReadOnly:
			return nil, fmt.Errorf("volume path %s: read-only volume mounts are not supported on VM backends", quoteForLog(m.dir))
		default:
			return nil, fmt.Errorf("volume path %s: volume mount mode %s is not supported on VM backends; want %q", quoteForLog(m.dir), quoteForLog(m.mode), volumeModeRW)
		}
		if err := checkVolumeDir(m.dir); err != nil {
			return nil, err
		}
	}
	for i := 0; i < len(mounts); {
		j := i + 1
		for j < len(mounts) && mounts[j].dir == mounts[i].dir {
			j++
		}
		if j-i > 1 {
			return nil, fmt.Errorf("volume path %s has %d volume mounts; each volume mount on a VM backend needs a path of its own", quoteForLog(mounts[i].dir), j-i)
		}
		i = j
	}
	dirs := make([]string, len(mounts))
	for i, m := range mounts {
		dirs[i] = m.dir
	}
	if err := checkNotNested(dirs); err != nil {
		return nil, err
	}

	app, err := applicationFromEnv(lookup)
	if err != nil {
		return nil, err
	}
	index, present := lookup(instanceIndexEnv)
	name, err := imageNameFor(app.ApplicationID, app.ProcessType, index, present)
	if err != nil {
		return nil, err
	}
	// imageNameFor accepted the index as canonical decimal up to
	// maxInstanceIndex, so it parses.
	n, err := strconv.ParseUint(index, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%s %s is not an instance index from 0 to %d", instanceIndexEnv, quoteForLog(index), maxInstanceIndex)
	}
	vols := make([]guestVolume, len(mounts))
	for i, m := range mounts {
		vols[i] = guestVolume{ContainerDir: m.dir, ImageName: name, Index: int(n)}
	}
	return vols, nil
}

// vcapApplication is the part of VCAP_APPLICATION vm-launch reads. Both
// fields are checked before they reach a file name.
type vcapApplication struct {
	ApplicationID string `json:"application_id"`
	ProcessType   string `json:"process_type"`
}

// applicationFromEnv decodes VCAP_APPLICATION. application_id must be a
// lowercase UUID, so that no other string reaches a file name. process_type
// is left as is, because a task has none; imageNameFor decides what to do
// with it. Errors never repeat VCAP_APPLICATION.
func applicationFromEnv(lookup func(string) (string, bool)) (vcapApplication, error) {
	raw, ok := lookup(vcapApplicationEnv)
	if !ok {
		return vcapApplication{}, fmt.Errorf("%s is not set, so the volume image cannot be named after the application", vcapApplicationEnv)
	}
	var app vcapApplication
	if err := json.Unmarshal([]byte(raw), &app); err != nil {
		return vcapApplication{}, fmt.Errorf("%s is not valid JSON for an application", vcapApplicationEnv)
	}
	if !applicationIDPattern.MatchString(app.ApplicationID) {
		return vcapApplication{}, fmt.Errorf("%s application_id is not a lowercase UUID", vcapApplicationEnv)
	}
	return app, nil
}

// imageNameFor returns the image file name of one instance of one process
// type of one application, rvm-disk-APPID-PROCESS_TYPE-INDEX.img. The process
// type keeps the web and worker processes of one app, which each number their
// instances from 0, on separate images. The application id must be a
// lowercase UUID, the process type must match processTypePattern, and the
// index must be canonical decimal, so that one instance always maps to one
// file and two applications bound to one service instance never share a file.
//
// A task has no CF_INSTANCE_INDEX and no process_type. It would have to share
// an image with an instance of the app, which the single writer lock turns
// into a crash loop for one of them, so a task that has a volume is an error.
func imageNameFor(appID, processType, index string, present bool) (string, error) {
	if !applicationIDPattern.MatchString(appID) {
		return "", fmt.Errorf("application id %s is not a lowercase UUID", quoteForLog(appID))
	}
	if !present || processType == "" {
		return "", fmt.Errorf("volumes are not supported for tasks on VM backends: this process has no %s or no process_type in %s, so it has no instance image of its own",
			instanceIndexEnv, vcapApplicationEnv)
	}
	if !processTypePattern.MatchString(processType) {
		return "", fmt.Errorf("%s process_type is not 1 to 63 lowercase letters, digits, underscores, or hyphens, starting with a letter or digit", vcapApplicationEnv)
	}
	n, err := strconv.ParseUint(index, 10, 16)
	if err != nil || n > maxInstanceIndex || strconv.FormatUint(n, 10) != index {
		return "", fmt.Errorf("%s %s is not an instance index from 0 to %d", instanceIndexEnv, quoteForLog(index), maxInstanceIndex)
	}
	return "rvm-disk-" + appID + "-" + processType + "-" + strconv.FormatUint(n, 10) + ".img", nil
}

// checkVolumeDir checks container_dir as a guest mount point: a clean
// absolute path other than /, without NUL or control characters, no longer
// than maxVolumePathLen, and outside reservedGuestDirs.
func checkVolumeDir(p string) error {
	bad := func(reason string) error {
		return fmt.Errorf("volume path %s %s", quoteForLog(p), reason)
	}
	switch {
	case p == "":
		return bad("is empty")
	case len(p) > maxVolumePathLen:
		return bad(fmt.Sprintf("is longer than %d bytes", maxVolumePathLen))
	case strings.IndexFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0:
		return bad("contains a NUL or control character")
	case !filepath.IsAbs(p):
		return bad("is not absolute")
	case filepath.Clean(p) != p:
		return bad("is not a clean path")
	case p == "/":
		return bad("is the guest root")
	}
	for _, r := range reservedGuestDirs {
		if p == r || strings.HasPrefix(p, r+"/") {
			return bad(fmt.Sprintf("is on or under %s, which the guest needs for itself", r))
		}
	}
	return nil
}

// checkNotNested refuses two volume paths of which one is on or under the
// other, compared after cleaning both. The guest would have to mount the outer
// volume first and the inner one after it, and unmount them in reverse, and a
// mount in the wrong order would hide the inner volume or leave the app
// writing to the wrong disk. Refusing the pair means the guest never orders
// its mounts. The comparison is pairwise rather than between neighbours,
// because byte order can put an unrelated path between a path and the paths
// under it: "/data-old" sorts between "/data" and "/data/inner". dirs hold at
// most maxVolumes paths.
func checkNotNested(dirs []string) error {
	for i, outer := range dirs {
		co := filepath.Clean(outer)
		for j, inner := range dirs {
			if i == j {
				continue
			}
			ci := filepath.Clean(inner)
			same := ci == co && i < j
			under := strings.HasPrefix(ci, strings.TrimSuffix(co, "/")+"/")
			if same || under {
				return fmt.Errorf("volume path %s is on or under volume path %s; VM backends need every volume path to be outside every other volume path, so give each volume a path of its own",
					quoteForLog(inner), quoteForLog(outer))
			}
		}
	}
	return nil
}

// quoteForLog quotes s for an error line, cut to maxLoggedValueLen bytes.
func quoteForLog(s string) string {
	if len(s) > maxLoggedValueLen {
		return strconv.Quote(s[:maxLoggedValueLen]) + "..."
	}
	return strconv.Quote(s)
}

// findVolumeProvider returns the provider in diskProviders that owns the
// volume at dir, and what vm-launch learned about its mount, so that a volume
// no provider supports is refused before anything boots. It asks the kernel
// (volumeProbe) for the ID of the mount that holds dir and whether dir is the
// root of that mount. A directory that is not a mount root is refused for
// every provider, before the mount table is read and before any provider's
// Prepare can run, because a volume service's disk lives in the root of its
// mount. It then finds the line with that ID in the mount table at
// mountinfo, and lets the registry select a provider from the whole record.
// A kernel that does not report the answers is a refusal, since matching by
// path could be wrong. A mount ID with no line is refused too. Every refusal
// that follows a lookup in the mount table ends by naming the registered
// providers. Errors never repeat VCAP_SERVICES.
//
// The returned record carries the mount ID, which the provider hands to
// openVolumeImage so that the directory it opens is on the mount inspected
// here.
func findVolumeProvider(mountinfo, dir string) (diskProvider, mountRecord, error) {
	probe, err := volumeProbe(dir)
	if err != nil {
		return nil, mountRecord{}, err
	}
	if !probe.MountRoot {
		return nil, mountRecord{}, notMountRootError(dir, nil)
	}
	m, err := volumeMount(mountinfo, dir, probe.MountID)
	if err != nil {
		return nil, mountRecord{}, fmt.Errorf("%w; %s", err, diskProviders.supportedLine())
	}
	p, err := diskProviders.selectProvider(m)
	if err != nil {
		return nil, mountRecord{}, err
	}
	return p, m, nil
}

// selectedVolume is a volume with the provider that owns it and the mount
// behind it, as findVolumeProviders found them.
type selectedVolume struct {
	// Index is the volume index, the volume's position among all of the
	// app's volumes in path order, shares included (see shareGrant.Index).
	Index    int
	Volume   guestVolume
	Provider diskProvider
	Mount    mountRecord
}

// findVolumeProviders runs findVolumeProvider for each of vols, in order,
// and stops at the first refusal. It also refuses two volumes whose mounts
// show the same directory of one filesystem, the same device numbers and the
// same root, because both images would then be one file, which the guest
// would mount twice. That catches two bind mounts of one directory of one
// host mount. It cannot catch two service instances of one share, because
// each service instance is a mount of its own, and a FUSE or NFS mount gets a
// device number of its own, so the two show different device numbers. Those
// two volumes reach the same image through two mounts, and the second one
// waits for the flock that the first holds, because the flock holds across
// mounts, and fails with the in-use line.
func findVolumeProviders(mountinfo string, vols []guestVolume) ([]selectedVolume, error) {
	selected := make([]selectedVolume, 0, len(vols))
	for i, v := range vols {
		p, m, err := findVolumeProvider(mountinfo, v.ContainerDir)
		if err != nil {
			return nil, err
		}
		for _, prev := range selected {
			if prev.Mount.Major == m.Major && prev.Mount.Minor == m.Minor && prev.Mount.Root == m.Root {
				return nil, fmt.Errorf("volume paths %s and %s are the same directory of one filesystem (device %d:%d, root %s), so they would share one disk; bind each volume to a directory of its own",
					quoteForLog(prev.Volume.ContainerDir), quoteForLog(v.ContainerDir), m.Major, m.Minor, quoteForLog(m.Root))
			}
		}
		selected = append(selected, selectedVolume{Index: i, Volume: v, Provider: p, Mount: m})
	}
	return selected, nil
}

// preparedVolume is a volume whose provider prepared its disk.
type preparedVolume struct {
	// Index is the volume index of the volume (see selectedVolume.Index),
	// which a share before it in path order keeps from being its position
	// among the prepared volumes.
	Index      int
	Path       string
	Attachment *attachment
	// Bytes is the size of the disk, which stage 1 checks the drive against:
	// the image's length from fstat in file-image mode, and the device's size
	// from BLKGETSIZE64 in block mode, where fstat gives no size.
	Bytes int64
	// dev and ino name the disk's inode, so that no disk is attached twice.
	dev, ino uint64
}

// preparedVolumes are the private volumes of one launch, in volume order,
// without the shares among them. Their attachments stay fenced until release.
type preparedVolumes []preparedVolume

// prepare asks v's provider for its disk, in the mode privateMode picks from
// the provider's capabilities, and adds it. A share is skipped: its provider
// is not asked, and nothing is added. A size setting on a block volume is
// refused first (refuseBlockSize), and so is an instance index at or above
// the provider's MaxInstances (checkInstanceLimit), both without calling
// Prepare. The attachment must be in that mode, and its file must be what
// the mode says: a regular file in file-image mode and a block device in
// block mode, whose size comes from the device itself.
// An attachment without a usable disk is refused and cleaned up (see
// checkAttachment), and so is a disk that an earlier volume already holds
// open. The provider gets a BeforeLock function that makes this refusal before
// the provider takes its fence, so that a disk an earlier volume holds is
// refused at once, with its own line, instead of waiting for a lock that this
// launch holds itself. The check after Prepare backs it up for a provider that
// does not call BeforeLock. A lock wait that runs out on a volume after the
// first gets a longer line, because an earlier volume of this launch may be
// the holder. The errors carry the provider's kinds, so stepExitCode maps a
// signal during a lock wait to 128+N. On an error, prepare returns what the caller
// must discard once it has logged the error, so that the error's line comes
// before the cleanup's: a provider that fails after it fenced the disk may
// hand back what it built along with the error. The volumes added before
// keep their fences, and the caller releases them too.
func (pv *preparedVolumes) prepare(v selectedVolume, signals <-chan os.Signal, budget *lockBudget, logger *log.Logger) (*attachment, error) {
	// A share has no image: its directory is served by virtiofsd (see
	// virtiofsd.go). Asking its provider for a disk would give the instance
	// a private image in place of the directory that every instance shares,
	// so the provider is never asked.
	if v.Volume.Settings.Mode == volumeShare {
		return nil, nil
	}
	caps := v.Provider.Capabilities(v.Mount)
	mode := privateMode(caps)
	if err := refuseBlockSize(v); err != nil {
		return nil, err
	}
	// v.Volume.Index is the app instance's index, which the instance limit
	// and the provider read. v.Index is the volume index (see
	// selectedVolume.Index), which is a different number.
	if err := checkInstanceLimit(v.Provider, caps, v.Volume.ContainerDir, mode, v.Volume.Index); err != nil {
		return nil, err
	}
	att, err := v.Provider.Prepare(prepareRequest{
		Mount: v.Mount, ImageName: v.Volume.ImageName, Index: v.Volume.Index, Mode: mode, Signals: signals,
		LockBudget: budget,
		BeforeLock: func(img *os.File) error {
			_, dev, ino, err := inodeOf(img, v.Volume.ContainerDir)
			if err != nil {
				return err
			}
			return pv.checkNotHeld(v.Volume.ContainerDir, dev, ino)
		},
	})
	if err != nil {
		if len(*pv) > 0 && errors.Is(err, errVolumeInUse) {
			err = &volumeError{kind: errVolumeInUse, cause: err,
				msg: err.Error() + "; with more than one volume bound, two of this app's bindings may be the same share, in which case an earlier volume of this launch holds the lock"}
		}
		return att, err
	}
	if err := checkAttachment(v.Provider, att, logger); err != nil {
		return nil, err
	}
	switch att.Mode {
	case 0:
		att.Mode = mode
	case mode:
	default:
		return att, fmt.Errorf("the %s volume provider was asked for %s for the volume at %s and prepared the disk in %s",
			v.Provider.Name(), mode, quoteForLog(v.Volume.ContainerDir), att.Mode)
	}
	info, dev, ino, err := inodeOf(att.File, v.Volume.ContainerDir)
	if err != nil {
		return att, err
	}
	size := info.Size()
	switch {
	case mode == attachBlock:
		if info.Mode().Type() != os.ModeDevice {
			return att, fmt.Errorf("the %s volume provider prepared the disk for the volume at %s in %s, but its file is not a block device", v.Provider.Name(), quoteForLog(v.Volume.ContainerDir), mode)
		}
		if size, err = blockDeviceBytes(att.File); err != nil {
			return att, fmt.Errorf("reading the size of the block device for the volume at %s: %w", quoteForLog(v.Volume.ContainerDir), err)
		}
	case !info.Mode().IsRegular():
		return att, fmt.Errorf("the %s volume provider prepared the disk for the volume at %s in %s, but its file is not a regular file", v.Provider.Name(), quoteForLog(v.Volume.ContainerDir), mode)
	}
	if err := pv.checkNotHeld(v.Volume.ContainerDir, dev, ino); err != nil {
		return att, err
	}
	*pv = append(*pv, preparedVolume{Index: v.Index, Path: v.Volume.ContainerDir, Attachment: att, Bytes: size, dev: dev, ino: ino})
	return nil, nil
}

// checkPreparedOrder refuses prepared volumes that are not the volumes of
// vols that are not shares, each with its own volume index and path, in
// volume order. The guest's /rvm/disks and /rvm/mounts pair each volume that
// is not a share with the next drive (see volumesOnDrives), and a drive's
// serial carries the volume index of its prepared volume, so a prepared
// volume out of place would put one volume's disk at another volume's path.
// prepare adds the volumes in that order, and this check keeps any other
// order from reaching the guest.
func checkPreparedOrder(vols []guestVolume, prepared preparedVolumes) error {
	next := 0
	for n, v := range vols {
		if v.Settings.Mode == volumeShare {
			continue
		}
		if next == len(prepared) {
			return fmt.Errorf("the volume at %s (volume index %d) has no prepared disk", quoteForLog(v.ContainerDir), n)
		}
		p := prepared[next]
		if p.Index != n || p.Path != v.ContainerDir {
			return fmt.Errorf("the disk prepared for the volume at %s (volume index %d) is in the place of the volume at %s (volume index %d), so the guest would mount it at the wrong path", quoteForLog(p.Path), p.Index, quoteForLog(v.ContainerDir), n)
		}
		next++
	}
	if next != len(prepared) {
		p := prepared[next]
		return fmt.Errorf("the disk prepared for the volume at %s (volume index %d) comes after the last volume that is not a share", quoteForLog(p.Path), p.Index)
	}
	return nil
}

// inodeOf returns the file info of f and the device and inode it names. dir
// is the volume path that f belongs to, for the error line.
func inodeOf(f *os.File, dir string) (os.FileInfo, uint64, uint64, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, 0, 0, fmt.Errorf("reading the disk of the volume at %s: %w", quoteForLog(dir), err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, 0, 0, fmt.Errorf("reading the inode of the disk of the volume at %s: the file system gave no inode", quoteForLog(dir))
	}
	return info, uint64(st.Dev), uint64(st.Ino), nil
}

// checkNotHeld refuses the disk with device dev and inode ino for the volume
// at dir when an earlier volume already holds it. Two volumes on one disk
// would give the guest one disk twice, whether an image or a block device.
func (pv preparedVolumes) checkNotHeld(dir string, dev, ino uint64) error {
	for _, prev := range pv {
		if prev.dev == dev && prev.ino == ino {
			return fmt.Errorf("volume paths %s and %s reach the same disk; bind each volume to a directory of its own",
				quoteForLog(prev.Path), quoteForLog(dir))
		}
	}
	return nil
}

// files returns the attachments, in volume order, for hypervisorFiles.
func (pv preparedVolumes) files() []*attachment {
	atts := make([]*attachment, len(pv))
	for i, v := range pv {
		atts[i] = v.Attachment
	}
	return atts
}

// release releases every attachment, last first, and logs each release that
// fails. vm-launch calls it once the hypervisor has exited or never started.
func (pv preparedVolumes) release(logger *log.Logger) {
	for i := len(pv) - 1; i >= 0; i-- {
		if err := pv[i].Attachment.Release(); err != nil {
			logger.Printf("releasing the volume disk: %v", err)
		}
	}
}
