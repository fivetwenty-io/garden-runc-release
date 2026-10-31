package bundlerules

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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

// deviceNode describes a device node to add to a bundle together with the
// cgroup rule that allows the container to use it.
type deviceNode struct {
	path string
	// devType is "c" for a character device or "b" for a block device.
	devType string
	major   int64
	minor   int64
	mode    os.FileMode
	gid     uint32
	// access is the cgroup rule's access, such as "rwm".
	access string
	// diskseq is the disk sequence number of a block volume's disk, or 0.
	diskseq uint64
}

var (
	// kvmNode is /dev/kvm, a misc device with a fixed minor number.
	kvmNode = deviceNode{path: "/dev/kvm", devType: "c", major: miscMajor, minor: 232, mode: 0660, access: "rwm"}

	// tunNode is /dev/net/tun, which Firecracker needs to attach its guest NIC to a tap device.
	// Mode 0666 matches the usual host node; opening it grants nothing without CAP_NET_ADMIN or a pre-created tap.
	// Its group stays root, because a world-accessible node does not depend on it.
	tunNode = deviceNode{path: "/dev/net/tun", devType: "c", major: miscMajor, minor: 200, mode: 0666, access: "rwm"}
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
// setgid binaries from changing the effective gid. With BlockVolumes set, a VM
// container also gets the block device that each descriptor bind mount names.
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

	// BlockVolumes gives a VM container a block node and a read-write cgroup
	// rule for each device that a descriptor bind mount names. It is nil
	// unless block volumes are turned on, and then no bind mount is inspected.
	BlockVolumes *PDIDevices
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
		// Claimed last, because it creates host nodes. Nothing below can fail,
		// and a failure later in the create is cleaned up by the destroy that
		// follows it, which releases the claim.
		if r.BlockVolumes != nil {
			blockNodes, err := r.BlockVolumes.Claim(spec)
			if err != nil {
				return goci.Bndl{}, err
			}
			nodes = append(nodes, blockNodes...)
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
		if m, ok := pdiDiskseqMount(nodes); ok {
			bndl = bndl.WithMounts(m)
		}
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

// pdiDiskseqMount returns the tmpfs that records, in its source, the disk
// sequence number of each block node, and reports false when there is no block
// node. vm-launch refuses a block volume unless it finds exactly one such
// mount with the device's number. Only root can mount a filesystem, so,
// unlike an environment variable, which runc lets a process's own value
// replace, an app cannot change the record.
func pdiDiskseqMount(nodes []deviceNode) (specs.Mount, bool) {
	var entries []string
	for _, n := range nodes {
		if n.devType == "b" && n.diskseq != 0 {
			entries = append(entries, fmt.Sprintf("%d:%d=%s", n.major, n.minor, strconv.FormatUint(n.diskseq, 10)))
		}
	}
	if len(entries) == 0 {
		return specs.Mount{}, false
	}
	return specs.Mount{
		Destination: PDIDiskseqMountPath,
		Source:      PDIDiskseqSource + strings.Join(entries, ","),
		Type:        "tmpfs",
		Options:     []string{"ro", "nosuid", "nodev", "noexec", "size=4k", "mode=0555"},
	}, true
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
			Type:     node.devType,
			Major:    node.major,
			Minor:    node.minor,
			FileMode: &fileMode,
			UID:      &uid,
			GID:      &gid,
		})

		major, minor := node.major, node.minor
		rules = append(rules, specs.LinuxDeviceCgroup{
			Allow:  true,
			Type:   node.devType,
			Major:  &major,
			Minor:  &minor,
			Access: node.access,
		})
	}
	resources.Devices = rules

	linux := *bndl.Spec.Linux
	linux.Devices = devices
	linux.Resources = &resources
	bndl.Spec.Linux = &linux
	return bndl
}
