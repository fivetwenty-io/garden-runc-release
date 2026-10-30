package processes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/users"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

//counterfeiter:generate . EnvDeterminer

type EnvDeterminer interface {
	EnvFor(bndl goci.Bndl, spec garden.ProcessSpec, containerUID int) []string
}

type EnvFunc func(bndl goci.Bndl, spec garden.ProcessSpec, containerUID int) []string

func (fn EnvFunc) EnvFor(bndl goci.Bndl, spec garden.ProcessSpec, containerUID int) []string {
	return fn(bndl, spec, containerUID)
}

const (
	// VMLaunchPath is where the execution backend bundle rule binds the
	// vm-launch binary in a vm-* container.
	VMLaunchPath = "/opt/garden-vm/vm-launch"

	// vmLaunchMarkerKey names the environment entry through which the
	// containerizer tells BuildProcess that it wrapped the CF launcher into
	// vm-launch. BuildProcess removes it, so it never reaches the runtime.
	vmLaunchMarkerKey = "__GARDEN_VM_LAUNCH_WRAPPED"
	vmLaunchMarker    = vmLaunchMarkerKey + "=1"

	// CapSetGID lets a process change its group ids, including adding the kvm
	// gid with setgroups. No process of a vm-* container keeps it.
	CapSetGID = "CAP_SETGID"

	// CapSetUID lets a process change its user ids. No helper process (pea) of
	// a vm-* container keeps it.
	CapSetUID = "CAP_SETUID"

	// CapSysChroot lets a process call chroot. No helper process (pea) of a
	// vm-* container keeps it.
	CapSysChroot = "CAP_SYS_CHROOT"

	// unconfinedApparmorProfile is the AppArmor label every policy namespace
	// provides without a loaded profile. runc applies the container's profile
	// to an exec'd process unless the process names a non-empty profile of its
	// own, so lifting the profile for one process means naming this label.
	unconfinedApparmorProfile = "unconfined"
)

// ErrKVMPrimaryGid is returned by CheckUser when a process in a vm-* container
// would run with the kvm gid as its primary gid.
var ErrKVMPrimaryGid = errors.New("a process in a vm container cannot have the kvm gid as its primary gid")

// MarkVMLaunch returns a copy of spec that carries the vm-launch provenance
// marker. Only the containerizer calls it, after it has rewritten the CF
// launcher into vm-launch and after it has removed any marker the client sent.
// The caller's Env slice is not modified.
func MarkVMLaunch(spec garden.ProcessSpec) garden.ProcessSpec {
	spec, _ = UnmarkVMLaunch(spec)
	env := make([]string, 0, len(spec.Env)+1)
	env = append(env, spec.Env...)
	spec.Env = append(env, vmLaunchMarker)
	return spec
}

// UnmarkVMLaunch returns a copy of spec without any vm-launch provenance
// marker and reports whether the exact marker MarkVMLaunch adds was present.
// Every entry named after the marker is removed whatever its value, so no
// variant a client sends survives. The caller's Env slice is not modified.
func UnmarkVMLaunch(spec garden.ProcessSpec) (garden.ProcessSpec, bool) {
	named := false
	for _, entry := range spec.Env {
		if isVMLaunchMarker(entry) {
			named = true
			break
		}
	}
	if !named {
		return spec, false
	}

	marked := false
	env := make([]string, 0, len(spec.Env))
	for _, entry := range spec.Env {
		switch {
		case entry == vmLaunchMarker:
			marked = true
		case isVMLaunchMarker(entry):
		default:
			env = append(env, entry)
		}
	}
	spec.Env = env
	return spec, marked
}

func isVMLaunchMarker(entry string) bool {
	return entry == vmLaunchMarkerKey || strings.HasPrefix(entry, vmLaunchMarkerKey+"=")
}

type ProcBuilder struct {
	envDeterminer  EnvDeterminer
	nonRootMaxCaps []string
	kvmGid         uint32
	// confinedRootDir resolves every working directory inside the image
	// root, not only those of gVisor containers.
	confinedRootDir bool
}

// Option customises a ProcBuilder.
type Option func(*ProcBuilder)

// WithKVMGid sets the gid that owns /dev/kvm. BuildProcess adds it to the
// supplementary gids of the vm-launch process that the containerizer wrapped
// in a vm-* container, which is what lets that process open the kvm device
// node, removes it from every other process in a vm-* container, and CheckUser
// refuses it as a primary gid there. A gid of 0 turns all three off.
func WithKVMGid(gid uint32) Option {
	return func(p *ProcBuilder) {
		p.kvmGid = gid
	}
}

// WithConfinedRootDir makes BuildProcess resolve the working directory of
// every process inside the image root, as it does for gVisor containers. A
// cell that runs all of its containers under runsc uses it.
func WithConfinedRootDir() Option {
	return func(p *ProcBuilder) {
		p.confinedRootDir = true
	}
}

func NewBuilder(envDeterminer EnvDeterminer, nonRootMaxCaps []string, opts ...Option) *ProcBuilder {
	p := &ProcBuilder{
		envDeterminer:  envDeterminer,
		nonRootMaxCaps: nonRootMaxCaps,
	}
	for _, opt := range opts {
		opt(p)
	}

	return p
}

// CheckUser reports whether BuildProcess may run spec as user in bndl. Every
// exec path calls it once it has resolved the user from the container's image,
// and before it acts on the result. In a vm-* bundle it refuses a user whose
// primary gid is the kvm gid. BuildProcess removes the kvm gid from the
// supplementary gids of every process other than the wrapped vm-launch
// process, but it cannot replace a primary gid, and the image's /etc/passwd or
// a "uid:gid" user would otherwise let every process run as that user open
// /dev/kvm. The wrapped vm-launch process is refused too, so such an image
// fails when the app starts rather than at its first cf ssh session. A bundle
// that is not vm-*, or a builder with no kvm gid, accepts every user.
func (p *ProcBuilder) CheckUser(bndl goci.Bndl, spec garden.ProcessSpec, user *users.ExecUser) error {
	if user == nil {
		return errors.New("check process user: no resolved user")
	}

	if p.kvmGid == 0 || !backend.IsVM(backend.FromBundle(bndl)) {
		return nil
	}

	// Compare the value BuildProcess hands to the runtime, so a gid that only
	// becomes the kvm gid when narrowed to 32 bits is refused as well.
	// #nosec G115 - gids should be positive and 32bit on linux, but libcontainer uses an int for them
	if uint32(user.Gid) == p.kvmGid {
		return fmt.Errorf("%w: process user %q resolves to gid %d in this %s container", ErrKVMPrimaryGid, spec.User, p.kvmGid, backend.FromBundle(bndl))
	}

	return nil
}

// BuildProcess turns a Garden process spec into the OCI process the runtime
// executes. For a vm-* bundle it also confines every process: CAP_SETGID is
// removed from every capability set and NoNewPrivileges is set, so no process
// can acquire the kvm gid by itself, and the kvm gid is removed from the
// supplementary gids the image gives the user, so Garden does not hand it out
// either. Only the vm-launch process that carries the containerizer's
// provenance marker gets the kvm gid and, in a vm-qemu bundle, runs without
// the bundle's AppArmor profile. The marker is removed before the process is
// built. Callers check the resolved user with CheckUser first, because a kvm
// primary gid cannot be removed here.
func (p *ProcBuilder) BuildProcess(bndl goci.Bndl, spec garden.ProcessSpec, user *users.ExecUser) *specs.Process {
	kind := backend.FromBundle(bndl)
	vm := backend.IsVM(kind)

	wrapped := false
	if vm {
		spec, wrapped = UnmarkVMLaunch(spec)
		wrapped = wrapped && spec.Path == VMLaunchPath
	}

	additionalGIDs := p.supplementaryGids(user.Sgids, vm, wrapped)

	apparmorProfile := bndl.Process().ApparmorProfile
	if wrapped && kind == backend.VMQemu && apparmorProfile != "" {
		// QEMU runs unconfined. The lift dates from before the default AppArmor
		// profile allowed signals between processes in the same container,
		// which covers the SIGUSR1 QEMU uses to kick its vCPU threads. We keep
		// it until a confined QEMU has been checked on a cell. An empty profile
		// would leave the container's profile in place, so the process names
		// the unconfined label instead. QEMU inherits it, and the container's
		// other processes keep the bundle's profile. A bundle without a
		// profile has nothing to lift, and naming a label on a host without
		// AppArmor would fail the exec.
		apparmorProfile = unconfinedApparmorProfile
	}

	capabilities := p.capabilities(bndl, user.Gid)
	if vm {
		capabilities = WithoutCapability(capabilities, CapSetGID)
	}

	return &specs.Process{
		Args:        append([]string{spec.Path}, spec.Args...),
		ConsoleSize: console(spec),
		Env:         p.envDeterminer.EnvFor(bndl, spec, user.Uid),
		User: specs.User{
			// #nosec G115 - uids should be positive and 32bit on linux, but libcontainer uses an int for them
			UID: uint32(user.Uid),
			// #nosec G115 - gids should be positive and 32bit on linux, but libcontainer uses an int for them
			GID:            uint32(user.Gid),
			AdditionalGids: additionalGIDs,
			Username:       spec.User,
		},
		Cwd:             getRootDir(bndl.RootFS(), spec.Dir, user.Home, p.confinedRootDir || backend.IsGvisor(backend.FromBundle(bndl))),
		Capabilities:    capabilities,
		Rlimits:         toRlimits(spec.Limits),
		Terminal:        spec.TTY != nil,
		ApparmorProfile: apparmorProfile,
		NoNewPrivileges: bndl.Process().NoNewPrivileges || vm,
	}
}

// WithoutCapability returns a copy of caps with capability removed from every
// set. It returns nil for nil caps and never modifies caps or its slices.
func WithoutCapability(caps *specs.LinuxCapabilities, capability string) *specs.LinuxCapabilities {
	if caps == nil {
		return nil
	}

	return &specs.LinuxCapabilities{
		Bounding:    without(caps.Bounding, capability),
		Effective:   without(caps.Effective, capability),
		Inheritable: without(caps.Inheritable, capability),
		Permitted:   without(caps.Permitted, capability),
		Ambient:     without(caps.Ambient, capability),
	}
}

func without(set []string, capability string) []string {
	if set == nil {
		return nil
	}

	kept := make([]string, 0, len(set))
	for _, c := range set {
		if c != capability {
			kept = append(kept, c)
		}
	}
	return kept
}

// supplementaryGids returns the supplementary gids of a process. Outside a
// vm-* bundle, or without a kvm gid, they are the user's gids unchanged. In a
// vm-* bundle the wrapped vm-launch process gets the kvm gid appended once,
// and every other process loses it, whatever the image's /etc/group says. The
// comparison runs on the 32-bit values the runtime receives.
func (p *ProcBuilder) supplementaryGids(sgids []int, vm, wrapped bool) []uint32 {
	gids := toUint32Slice(sgids)
	if !vm || p.kvmGid == 0 {
		return gids
	}

	if wrapped {
		if !containsGid(gids, p.kvmGid) {
			gids = append(gids, p.kvmGid)
		}
		return gids
	}

	kept := make([]uint32, 0, len(gids))
	for _, g := range gids {
		if g != p.kvmGid {
			kept = append(kept, g)
		}
	}
	return kept
}

func containsGid(gids []uint32, gid uint32) bool {
	for _, g := range gids {
		if g == gid {
			return true
		}
	}

	return false
}

func (p *ProcBuilder) capabilities(bndl goci.Bndl, containerUID int) *specs.LinuxCapabilities {
	capsToSet := bndl.Capabilities()
	if containerUID != 0 {
		capsToSet = intersect(capsToSet, p.nonRootMaxCaps)
	}

	// TODO centralize knowledge of garden -> runc capability schema translation
	if len(capsToSet) > 0 {
		return &specs.LinuxCapabilities{
			Bounding:    capsToSet,
			Inheritable: capsToSet,
			Permitted:   capsToSet,
		}
	}

	return nil
}

func console(spec garden.ProcessSpec) *specs.Box {
	consoleBox := &specs.Box{
		Width:  80,
		Height: 24,
	}
	if spec.TTY != nil && spec.TTY.WindowSize != nil {
		consoleBox.Width = uint(spec.TTY.WindowSize.Columns)
		consoleBox.Height = uint(spec.TTY.WindowSize.Rows)
	}
	return consoleBox
}

func intersect(l1 []string, l2 []string) (result []string) {
	for _, a := range l1 {
		for _, b := range l2 {
			if a == b {
				result = append(result, a)
			}
		}
	}

	return result
}

func toUint32Slice(slice []int) []uint32 {
	result := []uint32{}
	for _, i := range slice {
		// #nosec G115 - uids should be positive and 32bit on linux, but libcontainer uses an int for them
		result = append(result, uint32(i))
	}
	return result
}

// getRootDir returns the working directory of a process: the spec's
// directory, else the user's home, else "/" when the chosen directory does not
// exist in the root filesystem. When confined is set, the directory is looked
// up with every symlink resolved inside rootFS, the way the container sees it.
func getRootDir(rootFS, specDir, home string, confined bool) string {
	dir := specDir
	if dir == "" {
		dir = home
	}

	if dir == "" {
		return "/"
	}

	if confined {
		if err := statInRoot(rootFS, dir); errors.Is(err, os.ErrNotExist) {
			return "/"
		}

		return dir
	}

	fullPath := filepath.Join(rootFS, dir)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return "/"
	}

	return dir
}
