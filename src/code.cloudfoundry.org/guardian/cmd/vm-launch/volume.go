//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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

// guestVolume is the one volume a VM app gets: the path the container sees,
// at which the guest mounts the image, and the image's file name in the
// volume root.
type guestVolume struct {
	ContainerDir string
	ImageName    string
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

// volumeFromEnv returns the guest volume named in VCAP_SERVICES, or nil when
// the app has none. More than one volume mount, a mode other than rw, a
// container path the guest cannot use, a missing or malformed application_id
// or process_type in VCAP_APPLICATION, a bad CF_INSTANCE_INDEX, and a task
// are errors, so a misconfigured app fails to start instead of losing data to
// the wrong volume. Errors never repeat VCAP_SERVICES, which carries
// credentials. lookup reads the environment the rest of vm-launch shares
// (see lastWinsEnv), so the volume comes from the pre-resolution
// VCAP_SERVICES, which the guest also gets apart from resolved credentials.
// vm-launch reads the volume before it resolves CredHub references, which
// replace credentials and never a volume mount.
func volumeFromEnv(lookup func(string) (string, bool)) (*guestVolume, error) {
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
	for _, bindings := range services {
		for _, b := range bindings {
			for _, vm := range b.VolumeMounts {
				mounts = append(mounts, mount{dir: vm.ContainerDir, mode: vm.Mode})
			}
		}
	}
	switch {
	case len(mounts) == 0:
		return nil, nil
	case len(mounts) > 1:
		return nil, fmt.Errorf("VM backends support one volume mount; this app has %d", len(mounts))
	}

	m := mounts[0]
	switch m.mode {
	case volumeModeRW:
	case volumeModeReadOnly:
		return nil, errors.New("read-only volume mounts are not supported on VM backends")
	default:
		return nil, fmt.Errorf("volume mount mode %s is not supported on VM backends; want %q", quoteForLog(m.mode), volumeModeRW)
	}
	if err := checkVolumeDir(m.dir); err != nil {
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
	return &guestVolume{ContainerDir: m.dir, ImageName: name}, nil
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
// for the ID of the mount that holds dir (volumeMountID), finds the line with
// that ID in the mount table at mountinfo, and lets the registry select a
// provider from the whole record. A kernel that does not report the ID is a
// refusal, since matching by path could be wrong. A mount ID with no line is
// refused too. Every refusal that follows a lookup in the mount table ends by
// naming the registered providers. Errors never repeat VCAP_SERVICES.
func findVolumeProvider(mountinfo, dir string) (diskProvider, mountRecord, error) {
	id, err := volumeMountID(dir)
	if err != nil {
		return nil, mountRecord{}, err
	}
	m, err := volumeMount(mountinfo, dir, id)
	if err != nil {
		return nil, mountRecord{}, fmt.Errorf("%w; %s", err, diskProviders.supportedLine())
	}
	p, err := diskProviders.selectProvider(m)
	if err != nil {
		return nil, mountRecord{}, err
	}
	return p, m, nil
}
