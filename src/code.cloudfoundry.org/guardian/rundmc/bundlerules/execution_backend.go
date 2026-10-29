package bundlerules

import (
	"fmt"
	"os"
	"path/filepath"

	"code.cloudfoundry.org/guardian/backend"
	spec "code.cloudfoundry.org/guardian/gardener/container-spec"
	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/processes"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	// VMArtifactsMountPath is where the host artifacts directory appears inside a vm-* container.
	VMArtifactsMountPath = "/opt/garden-vm/artifacts"

	// VMLaunchMountPath is where the host vm-launch binary appears inside a vm-* container.
	VMLaunchMountPath = processes.VMLaunchPath

	// miscMajor is the character device major shared by the misc devices below.
	miscMajor int64 = 10
)

// deviceNode describes a character device node to add to a bundle together
// with the cgroup rule that allows the container to use it.
type deviceNode struct {
	path  string
	major int64
	minor int64
	mode  os.FileMode
	gid   uint32
}

var (
	// kvmNode is /dev/kvm, a misc device with a fixed minor number.
	kvmNode = deviceNode{path: "/dev/kvm", major: miscMajor, minor: 232, mode: 0660}

	// tunNode is /dev/net/tun, which Firecracker needs to attach its guest NIC to a tap device.
	// Mode 0666 matches the usual host node; opening it grants nothing without CAP_NET_ADMIN or a pre-created tap.
	// Its group stays root, because a world-accessible node does not depend on it.
	tunNode = deviceNode{path: "/dev/net/tun", major: miscMajor, minor: 200, mode: 0666}
)

// DefaultVMArtifacts lists, per VM backend, the files that must exist under
// the artifacts directory before a container may start on that backend.
var DefaultVMArtifacts = map[backend.Kind][]string{
	backend.VMQemu: {
		"kernel/bzImage",
		"qemu/qemu-system-x86_64-microvm",
		"qemu/ld-linux-x86-64.so.2",
		"busybox",
	},
	backend.VMFirecracker: {
		"kernel/vmlinux",
		"firecracker/firecracker",
		"busybox",
	},
}

// ExecutionBackend records the selected execution backend in the bundle and,
// for VM backends, grants access to /dev/kvm (plus /dev/net/tun for
// vm-firecracker), mounts the VM artifacts, and confines the container so that
// no process can give itself the kvm gid: CAP_SETGID is removed from every
// capability set of the bundle process and NoNewPrivileges is set, which stops
// setgid binaries from changing the effective gid.
type ExecutionBackend struct {
	// ArtifactsDir is the host directory holding the VM artifacts.
	ArtifactsDir string

	// LaunchBin is the host path of the vm-launch binary.
	LaunchBin string

	// RequiredArtifacts maps each VM backend to the artifact paths, relative
	// to ArtifactsDir, that must be regular files.
	RequiredArtifacts map[backend.Kind][]string

	// KVMGid is the gid that owns /dev/kvm on the host. It becomes the group
	// of the /dev/kvm node that runc creates in a privileged container, which
	// has no user namespace and so gets a fresh node rather than the host's.
	// A VM backend is unavailable while it is 0.
	KVMGid uint32
}

// NewExecutionBackend returns the rule with the default required artifact table.
func NewExecutionBackend(artifactsDir, launchBin string, kvmGid uint32) ExecutionBackend {
	return ExecutionBackend{
		ArtifactsDir:      artifactsDir,
		LaunchBin:         launchBin,
		RequiredArtifacts: DefaultVMArtifacts,
		KVMGid:            kvmGid,
	}
}

func (r ExecutionBackend) Apply(bndl goci.Bndl, spec spec.DesiredContainerSpec) (goci.Bndl, error) {
	kind := backend.Kind(spec.ExecutionBackend)
	if kind == "" || kind == backend.OCIRunc {
		return bndl, nil
	}
	if !backend.IsKnown(kind) {
		return goci.Bndl{}, fmt.Errorf("%w: %q", backend.ErrUnknownBackend, spec.ExecutionBackend)
	}

	if backend.IsVM(kind) {
		if bndl.Spec.Process == nil {
			return goci.Bndl{}, fmt.Errorf("%w: %s needs a bundle process to confine", backend.ErrBackendUnavailable, kind)
		}
		if r.KVMGid == 0 {
			return goci.Bndl{}, fmt.Errorf("%w: %s requires the kvm gid, which is not configured", backend.ErrBackendUnavailable, kind)
		}
		if err := r.checkArtifacts(kind); err != nil {
			return goci.Bndl{}, err
		}
		kvm := kvmNode
		kvm.gid = r.KVMGid
		nodes := []deviceNode{kvm}
		if kind == backend.VMFirecracker {
			nodes = append(nodes, tunNode)
		}
		bndl = withDeviceNodes(bndl, nodes...)
		bndl = bndl.WithMounts(
			specs.Mount{
				Destination: VMArtifactsMountPath,
				Source:      r.ArtifactsDir,
				Type:        "bind",
				Options:     []string{"bind", "ro", "nosuid", "nodev"},
			},
			specs.Mount{
				Destination: VMLaunchMountPath,
				Source:      r.LaunchBin,
				Type:        "bind",
				Options:     []string{"bind", "ro", "nosuid", "nodev"},
			},
		)

		// The bundle keeps its AppArmor profile. The process builder lifts it
		// for the vm-launch process of a vm-qemu container only.
		process := bndl.Process()
		process.Capabilities = processes.WithoutCapability(process.Capabilities, processes.CapSetGID)
		process.NoNewPrivileges = true
		bndl = bndl.WithProcess(process)
	}

	annotations := make(map[string]string, len(bndl.Spec.Annotations)+1)
	for k, v := range bndl.Spec.Annotations {
		annotations[k] = v
	}
	annotations[backend.AnnotationKey] = string(kind)
	bndl.Spec.Annotations = annotations

	return bndl, nil
}

func (r ExecutionBackend) checkArtifacts(kind backend.Kind) error {
	for _, rel := range r.RequiredArtifacts[kind] {
		path := filepath.Join(r.ArtifactsDir, rel)
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("%w: %s requires %s: %s", backend.ErrBackendUnavailable, kind, path, unwrapPathError(err))
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: %s requires %s to be a regular file", backend.ErrBackendUnavailable, kind, path)
		}
	}
	return nil
}

func unwrapPathError(err error) error {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err
	}
	return err
}

// withDeviceNodes appends the device nodes and their cgroup allow rules
// without disturbing the devices already in the bundle. WithDevices and
// WithDeviceRestrictions replace their slices, and the latter writes through
// the shared Resources pointer, so the bundle is rebuilt here.
func withDeviceNodes(bndl goci.Bndl, nodes ...deviceNode) goci.Bndl {
	devices := append([]specs.LinuxDevice{}, bndl.Spec.Linux.Devices...)

	var resources specs.LinuxResources
	if existing := bndl.Spec.Linux.Resources; existing != nil {
		resources = *existing
	}
	rules := append([]specs.LinuxDeviceCgroup{}, resources.Devices...)

	for _, node := range nodes {
		fileMode := node.mode
		uid, gid := uint32(0), node.gid
		devices = append(devices, specs.LinuxDevice{
			Path:     node.path,
			Type:     "c",
			Major:    node.major,
			Minor:    node.minor,
			FileMode: &fileMode,
			UID:      &uid,
			GID:      &gid,
		})

		major, minor := node.major, node.minor
		rules = append(rules, specs.LinuxDeviceCgroup{
			Allow:  true,
			Type:   "c",
			Major:  &major,
			Minor:  &minor,
			Access: "rwm",
		})
	}
	resources.Devices = rules

	linux := *bndl.Spec.Linux
	linux.Devices = devices
	linux.Resources = &resources
	bndl.Spec.Linux = &linux
	return bndl
}
