//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	"golang.org/x/sys/unix"
)

// Artifact layout below the artifacts directory. It must match
// DefaultVMArtifacts in rundmc/bundlerules/execution_backend.go.
const (
	artBusybox      = "busybox"
	artBzImage      = "kernel/bzImage"
	artVmlinux      = "kernel/vmlinux"
	artFirecracker  = "firecracker/firecracker"
	artQEMULoader   = "qemu/ld-linux-x86-64.so.2"
	artQEMUBinary   = "qemu/qemu-system-x86_64-microvm"
	artQEMULibDir   = "qemu/lib"
	artQEMUShareDir = "qemu/share"
)

// Guest shape. Every VM has one vCPU. Its memory comes from the container's
// MEMORY_LIMIT (see guestMemory).
const guestVCPUs = 1

// Guest memory sizing. The guest gets MEMORY_LIMIT less a reserve for what
// else the container holds, which is the hypervisor itself, vm-launch, the
// initramfs, sshd sessions, and the health check, clamped to a floor and a
// ceiling. The floor is the size every guest had before it was derived from
// MEMORY_LIMIT, so a container below floor plus reserve keeps that size.
const (
	guestMemoryReserveMiB = 192
	minGuestMemoryMiB     = 128
	maxGuestMemoryMiB     = 16384
)

// memoryLimitPattern is the form Cloud Controller gives MEMORY_LIMIT: whole
// megabytes with a lowercase m. Seven digits is far beyond any cell and keeps
// the arithmetic small.
var memoryLimitPattern = regexp.MustCompile(`^[1-9][0-9]{0,6}m$`)

// guestMemory returns the guest memory size in MiB from MEMORY_LIMIT. A
// missing or malformed value gives the floor, and so does a container too
// small to hold the floor and the reserve; each of those logs one line, so an
// operator who sees the hypervisor killed for memory can find the cause. The
// lines name the limit only once it has parsed as a number.
func guestMemory(lookupEnv func(string) (string, bool), logger *log.Logger) int {
	value, ok := lookupEnv("MEMORY_LIMIT")
	if !ok {
		logger.Printf("MEMORY_LIMIT is not set; the guest gets %d MiB", minGuestMemoryMiB)
		return minGuestMemoryMiB
	}
	limit, err := strconv.Atoi(strings.TrimSuffix(value, "m"))
	if !memoryLimitPattern.MatchString(value) || err != nil {
		logger.Printf("MEMORY_LIMIT is not a whole number of megabytes such as 512m; the guest gets %d MiB", minGuestMemoryMiB)
		return minGuestMemoryMiB
	}
	guest := limit - guestMemoryReserveMiB
	switch {
	case guest < minGuestMemoryMiB:
		logger.Printf("MEMORY_LIMIT %dm is below the %dm a guest of %d MiB needs with the %d MiB the container keeps for the hypervisor; the guest gets %d MiB and may be killed for memory, so give the app at least %dM",
			limit, minGuestMemoryMiB+guestMemoryReserveMiB, minGuestMemoryMiB, guestMemoryReserveMiB, minGuestMemoryMiB, minGuestMemoryMiB+guestMemoryReserveMiB)
		return minGuestMemoryMiB
	case guest > maxGuestMemoryMiB:
		logger.Printf("MEMORY_LIMIT %dm leaves more than the %d MiB a guest may have; the guest gets %d MiB", limit, maxGuestMemoryMiB, maxGuestMemoryMiB)
		return maxGuestMemoryMiB
	}
	return guest
}

// qemuMachine is QEMU's -M option: the microvm machine under KVM, with guest
// RAM left out of any core dump of QEMU.
const qemuMachine = "microvm,accel=kvm,dump-guest-core=off"

// Kernel command lines. QEMU exits on guest reboot because of -no-reboot, so
// it uses a triple-fault reboot and reboots at once on panic. Firecracker
// exits on a keyboard-controller reboot.
const (
	qemuKernelArgs        = "console=ttyS0 reboot=t panic=-1 rdinit=/init pci=off quiet"
	firecrackerKernelArgs = "console=ttyS0 reboot=k panic=1 rdinit=/init quiet"
)

type artifact struct {
	rel string
	dir bool
}

// requiredArtifacts returns the artifacts a backend needs, or an error for a
// backend vm-launch cannot run.
func requiredArtifacts(kind backend.Kind) ([]artifact, error) {
	switch kind {
	case backend.VMQemu:
		return []artifact{
			{rel: artBzImage}, {rel: artQEMULoader}, {rel: artQEMUBinary},
			{rel: artQEMULibDir, dir: true}, {rel: artQEMUShareDir, dir: true}, {rel: artBusybox},
		}, nil
	case backend.VMFirecracker:
		return []artifact{{rel: artVmlinux}, {rel: artFirecracker}, {rel: artBusybox}}, nil
	default:
		return nil, fmt.Errorf("unsupported backend %q (want %q or %q)", kind, backend.VMQemu, backend.VMFirecracker)
	}
}

// checkArtifacts reports the first missing or mistyped artifact by path.
func checkArtifacts(kind backend.Kind, root string) error {
	required, err := requiredArtifacts(kind)
	if err != nil {
		return err
	}
	for _, a := range required {
		p := filepath.Join(root, a.rel)
		info, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("artifact for %s: %w", kind, err)
		}
		if a.dir && !info.IsDir() {
			return fmt.Errorf("artifact for %s: %s is not a directory", kind, p)
		}
		if !a.dir && !info.Mode().IsRegular() {
			return fmt.Errorf("artifact for %s: %s is not a regular file", kind, p)
		}
	}
	return nil
}

// qemuArgv returns the QEMU command line for a guest of memMiB MiB. The
// microvm binary needs a newer glibc than the app rootfs has, so it runs
// through its bundled loader. dump-guest-core=off marks guest RAM as
// excluded from QEMU's core dumps.
//
// The guest gets a virtio-net NIC on QEMU's user-mode network. That needs no
// privileges, and guest egress leaves from the container's network
// namespace, so application security groups still apply. No connection
// from outside reaches the guest unless vm-launch adds a forwarding rule,
// which it does for a port, through the QMP monitor, only while the guest
// listens on it (see qmpPort). nw must be set.
//
// monitorFD, when above 0, is the inherited file descriptor of a connected
// stream socket that QEMU serves its QMP monitor on.
//
// drives are the volume drives in volume order, from hypervisorFiles, and
// the guest gets each one as a virtio-blk drive, volumeDriveID of the
// drive's volume index, after the NIC and in the same order. Each drive's
// device carries the drive's identity as its serial, which is qemuVolumeSerial
// of the volume's volume index (see newGuestDrives) and which the guest reads
// back. A share has no drive, so a drive's name counts the shares before it,
// as its serial does, and is QEMU's own name for the drive. QEMU takes each
// drive's file from the descriptor vm-launch checked and opens nothing again
// (see qemuVolumeDrive). The format is pinned
// to raw, so QEMU never probes the guest-written disk for a format header
// such as a qcow2 backing file. I/O errors, ENOSPC and EDQUOT included, reach
// the guest as errors instead of pausing the VM. QEMU's own locking is off,
// because vm-launch holds the fence that decides who writes the disk: the
// image's flock, or the device's exclusive open. Drives in neither mode are
// for hypervisorArgv to refuse; qemuArgv attaches them as images.
//
// shares are the guest's shares, in volume order: the virtiofsd socket of
// each, which QEMU connects to as a vhost-user client. A guest without a
// share gets the arguments above and nothing more. A guest with one gets its
// RAM as a shared memfd (see qemuShareArgs) and a vhost-user-fs device for
// each share, after the volume drives and before the monitor.
func qemuArgv(root, initrd string, memMiB int, nw *network, drives []volumeDrive, monitorFD int, shares ...shareSocket) []string {
	art := func(rel string) string { return filepath.Join(root, rel) }
	machine := qemuMachine
	if len(shares) > 0 {
		machine += ",memory-backend=" + qemuMemoryID
	}
	argv := []string{
		art(artQEMULoader),
		"--library-path", art(artQEMULibDir),
		art(artQEMUBinary),
		"-L", art(artQEMUShareDir),
		"-M", machine,
		"-cpu", "host",
		"-smp", strconv.Itoa(guestVCPUs),
		"-m", strconv.Itoa(memMiB),
		"-nodefaults",
		"-no-user-config",
		"-nographic",
		"-serial", "stdio",
		"-no-reboot",
		"-kernel", art(artBzImage),
		"-initrd", initrd,
		"-append", qemuKernelArgs,
	}
	argv = append(argv,
		"-netdev", "user,id="+qemuNetdevID+",net="+qemuNetwork,
		"-device", "virtio-net-device,netdev="+qemuNetdevID,
	)
	for _, d := range drives {
		argv = append(argv, qemuVolumeDrive(volumeDriveID(d.index), d)...)
	}
	argv = append(argv, qemuShareArgs(memMiB, shares)...)
	if monitorFD > 0 {
		argv = append(argv,
			"-chardev", "socket,id=qmp0,fd="+strconv.Itoa(monitorFD)+",server=off",
			"-mon", "chardev=qmp0,mode=control",
		)
	}
	return argv
}

// qemuNetdevID names the guest's user-mode network, which forwarding rules
// name too.
const qemuNetdevID = "n0"

// qemuMemoryID names the memfd that backs guest RAM when the guest has a
// share. -M names it as the machine's memory.
const qemuMemoryID = "mem0"

// qemuShareArgs returns the QEMU options that give the guest its shares, or
// nothing without one. virtiofsd reads and writes guest memory through the
// vhost-user protocol, so guest RAM has to be a file it can map: a
// memory-backend-memfd object with share=on, as large as -m, which -M
// (see qemuArgv) names as the machine's memory. Each share then gets a
// chardev on its virtiofsd socket, which QEMU connects to, and a
// vhost-user-fs-device on that chardev with the share's tag. The chardev is
// fs<N> for the share at volume index N, as the share's socket and tag
// are. QEMU reads a comma in an option value as the next key, so the socket
// path doubles any.
func qemuShareArgs(memMiB int, shares []shareSocket) []string {
	if len(shares) == 0 {
		return nil
	}
	argv := []string{"-object", "memory-backend-memfd,id=" + qemuMemoryID + ",size=" + strconv.Itoa(memMiB) + "M,share=on"}
	for _, s := range shares {
		chardev := "fs" + strconv.Itoa(s.Index)
		argv = append(argv,
			"-chardev", "socket,id="+chardev+",path="+strings.ReplaceAll(s.Path, ",", ",,"),
			"-device", "vhost-user-fs-device,chardev="+chardev+",tag="+s.Tag,
		)
	}
	return argv
}

// checkShares refuses a share list qemuShareArgs could not turn into devices
// the guest tells apart: a share with no socket path or no tag, a tag with a
// comma, which would end the option, an index below zero, and two shares at
// one volume index, which would give two chardevs one id.
func checkShares(shares []shareSocket) error {
	seen := make(map[int]bool, len(shares))
	for _, s := range shares {
		switch {
		case s.Index < 0:
			return fmt.Errorf("share %q has the volume index %d, which is below 0", s.Tag, s.Index)
		case seen[s.Index]:
			return fmt.Errorf("two shares have the volume index %d", s.Index)
		case s.Path == "":
			return fmt.Errorf("share %q has no socket path", s.Tag)
		case s.Tag == "" || strings.ContainsRune(s.Tag, ','):
			return fmt.Errorf("the share at volume index %d has the tag %q, which is empty or has a comma", s.Index, s.Tag)
		}
		seen[s.Index] = true
	}
	return nil
}

// qemuVolumeDrive returns the QEMU options that attach the volume drive d as
// the drive id. -add-fd puts the drive's inherited descriptor in a file
// descriptor set of its own, numbered as the descriptor is, and the drive
// opens /dev/fdset/N, so QEMU duplicates the descriptor vm-launch checked
// instead of opening the file again. QEMU's I/O then shares that open file:
// an image's holds the flock, and on NFS the client fails I/O through it with
// EIO once the lock is lost, and a block device's holds the exclusive claim
// and stays bound to the disk whose sequence number and UUID vm-launch read.
// A set matches an open by its access mode and by O_DIRECT, so the
// descriptor is open read-write and carries O_DIRECT exactly when the drive
// has cache=none; any other descriptor fails QEMU's start. Under -drive,
// QEMU opens the file read-only until the device attaches and then opens it
// again read-write (auto-read-only). No set holds a read-only descriptor, so
// file.auto-read-only=off makes QEMU open the file read-write, once.
//
// An image goes through QEMU's file driver with writeback caching, and its
// descriptor has no O_DIRECT. A block device goes through the host_device
// driver, because the file driver refuses block devices, with cache=none, so
// that the disk's data stays out of the container's page cache, and
// openBlockVolume sets O_DIRECT on its descriptor for that. Both name their
// driver, so QEMU never probes the path to choose one, and both keep
// discard=ignore and report I/O errors to the guest.
func qemuVolumeDrive(id string, d volumeDrive) []string {
	fd := strconv.Itoa(d.fd)
	file := qemuFDSetPath(d.fd)
	var drive string
	if d.mode == attachBlock {
		drive = "if=none,id=" + id + ",format=raw,file.driver=host_device,file.filename=" + file +
			",cache=none,aio=threads,file.locking=off,file.auto-read-only=off,werror=report,rerror=report,discard=ignore"
	} else {
		drive = "if=none,id=" + id + ",format=raw,file.driver=file,file.filename=" + file +
			",cache=writeback,aio=threads,file.locking=off,file.auto-read-only=off,werror=report,rerror=report,discard=ignore"
	}
	return []string{
		"-add-fd", "fd=" + fd + ",set=" + fd,
		"-drive", drive,
		"-device", "virtio-blk-device,drive=" + id + ",serial=" + d.id,
	}
}

// qemuReadOnlyDrive returns the QEMU options that attach the image whose
// inherited descriptor is fd as a read-only virtio-blk drive, with the drive
// id id and the serial serial. It follows qemuVolumeDrive, with the
// descriptor in a set of its own that the drive opens, so QEMU shares the
// open file vm-launch checked. The drive is read-only, so QEMU opens the
// file for reading only, and the descriptor has to be open read-only too, or
// no set matches it. A guest write is refused by the device before it
// reaches the image.
func qemuReadOnlyDrive(id, serial string, fd int) []string {
	n := strconv.Itoa(fd)
	return []string{
		"-add-fd", "fd=" + n + ",set=" + n,
		"-drive", "if=none,id=" + id + ",format=raw,file.driver=file,file.filename=" + qemuFDSetPath(fd) +
			",read-only=on,cache=writeback,aio=threads,file.locking=off,werror=report,rerror=report,discard=ignore",
		"-device", "virtio-blk-device,drive=" + id + ",serial=" + serial,
	}
}

// qemuFDSetPath is the path by which QEMU opens a duplicate of a descriptor
// in the file descriptor set set.
func qemuFDSetPath(set int) string {
	return "/dev/fdset/" + strconv.Itoa(set)
}

// volumeDrive is one volume drive as the hypervisor's arguments name it: the
// hypervisor's file descriptor for the disk, the drive's identity, how the
// disk reaches the guest, and the volume index of its volume. hypervisorFiles
// takes all four from the attachment, and an fd below firstExtraFD means the
// drive has no file. Both backends name the drive after the volume index (see
// volumeDriveID), so a share among the volumes, which has no drive, does not
// renumber the drives after it.
type volumeDrive struct {
	fd    int
	id    string
	mode  attachMode
	index int
}

// The hypervisor's inherited files. The hypervisor gets the volume disks,
// one for each volume that has a drive, the initramfs, a QEMU monitor
// socket, when there is one, and the guest root image, when there is one, as
// extra files, so the container path of a volume never reaches a QEMU option
// string or the Firecracker configuration.
//
// QEMU does its I/O on a volume disk through the descriptor it inherits,
// which shares vm-launch's checked open file (see qemuVolumeDrive).
// Firecracker opens each disk again through /proc/self/fd, and that open is
// a new open file description. For a volume image it reaches exactly the
// inode vm-launch checked, but without the flock, so on NFS Firecracker's
// I/O does not meet the client's EIO after a lost lock. For a block volume it
// finds its disk by the node's device number at the moment of the open and
// does not ask for O_EXCL, so it relies on the number still naming the disk
// vm-launch checked (see openBlockVolume). Both backends open the initramfs
// and the root image through /proc/self/fd. vm-launch made both files, holds
// no lock on them, and keeps them open, so the open reaches the inode it
// made. The root image has no path at all, because vm-launch unlinks it when
// it creates it.
//
// The volume disks take file descriptors from firstVolumeFD on, in volume
// order, so that the first one keeps 3, and the initramfs takes the next
// one: 3 without a volume, 4 with one, and 7 with four. The monitor takes the
// one after that, and the root image comes last, so that adding it moves no
// other file: 4 without a volume or a monitor, and 6 with one volume and a
// monitor.
const (
	firstExtraFD  = 3
	firstVolumeFD = firstExtraFD
	rootDriveID   = "root0"

	// stackDriveID and dropletDriveID name the read-only stack and droplet
	// drives, on QEMU and on Firecracker alike.
	stackDriveID   = "stack0"
	dropletDriveID = "droplet0"
)

// volumeDriveID names the drive of the volume with volume index i, on QEMU
// and on Firecracker alike: vol0 for the first volume. A share is a volume
// that has no drive, so with a share at index 0 the first drive is vol1.
func volumeDriveID(i int) string {
	return "vol" + strconv.Itoa(i)
}

// procSelfFD is the path a process opens its own file descriptor fd by.
func procSelfFD(fd int) string {
	return "/proc/self/fd/" + strconv.Itoa(fd)
}

// volumeDrivePath is the path Firecracker opens the volume disk at index i in
// volume order by.
func volumeDrivePath(i int) string {
	return procSelfFD(firstVolumeFD + i)
}

// hypervisorFiles returns the hypervisor's extra files in order, for
// exec.Cmd.ExtraFiles, with the descriptors and paths the hypervisor takes
// them by. vols are the volumes' attachments in volume order, after
// newGuestDrives has given each its identity, and drives holds the
// descriptor, the identity, and the mode of each, in the same order, or
// nothing without a volume. An attachment without a file, or a nil one,
// gives a drive with no file, which hypervisorArgv refuses. That drive keeps
// the attachment's volume index, so the refusal names the volume, and a nil
// attachment, which has none, gives the index -1, so the refusal names the
// drive's position instead. initrd is the
// initramfs from newInitramfs. monitor is QEMU's end of the QMP socket or nil, and
// monitorFD is its file descriptor in the hypervisor, or 0 without one. root
// is the guest root image from createRootImage or nil, and rootPath is empty
// without one.
func hypervisorFiles(vols []*attachment, initrd, monitor, root *os.File) (files []*os.File, drives []volumeDrive, initrdPath string, monitorFD int, rootPath string) {
	return hypervisorFilesWithStack(vols, initrd, monitor, root, nil)
}

// stackDriveFDs returns the file descriptors of the stack and droplet images
// in a hypervisor that gets nVols volume disks, the initramfs, a monitor
// socket when hasMonitor, and a root image when hasRoot, in that order, with
// the stack and the droplet after them.
func stackDriveFDs(nVols int, hasMonitor, hasRoot bool) (stack, droplet int) {
	n := firstExtraFD + nVols + 1
	if hasMonitor {
		n++
	}
	if hasRoot {
		n++
	}
	return n, n + 1
}

// hypervisorFilesWithStack is hypervisorFiles for a guest that also has the
// stack and droplet images in sd, which come after the root image as the last
// two files, so no other file's descriptor moves. A nil sd gives exactly what
// hypervisorFiles gives. Both files of an sd are required (see
// newGuestDrivesWithStack); a missing one is passed on as a nil file.
func hypervisorFilesWithStack(vols []*attachment, initrd, monitor, root *os.File, sd *stackDrives) (files []*os.File, drives []volumeDrive, initrdPath string, monitorFD int, rootPath string) {
	for _, att := range vols {
		if att == nil || att.File == nil {
			index := -1
			if att != nil {
				index = att.Index
			}
			files = append(files, nil)
			drives = append(drives, volumeDrive{index: index})
			continue
		}
		files = append(files, att.File)
		drives = append(drives, volumeDrive{fd: firstExtraFD + len(files) - 1, id: att.ID, mode: att.Mode, index: att.Index})
	}
	files = append(files, initrd)
	initrdPath = procSelfFD(firstExtraFD + len(files) - 1)
	if monitor != nil {
		files = append(files, monitor)
		monitorFD = firstExtraFD + len(files) - 1
	}
	if root != nil {
		files = append(files, root)
		rootPath = procSelfFD(firstExtraFD + len(files) - 1)
	}
	if sd != nil {
		files = append(files, sd.stack, sd.droplet)
	}
	return files, drives, initrdPath, monitorFD, rootPath
}

// qemuRootDrive returns the QEMU options that attach the guest root image,
// which the hypervisor opens as rootPath, with the serial qemuRootSerial as
// its identity (see newGuestDrives). The drive is raw for the reasons
// the volume's is (see qemuArgv). Unsafe caching drops the guest's flushes,
// which costs nothing because the data never outlives the VM, and
// discard=unmap turns the guest's discards into holes in the image, so that
// the blocks the guest frees go back to the container's quota. With
// detect-zeroes=unmap, which needs discard=unmap, a write of zeros becomes a
// hole too, so the zeros that mke2fs writes into every inode table at format
// time take no blocks.
func qemuRootDrive(rootPath string) []string {
	return []string{
		"-drive", "if=none,id=" + rootDriveID + ",file=" + rootPath +
			",format=raw,cache=unsafe,aio=threads,file.locking=off,werror=report,rerror=report,discard=unmap,detect-zeroes=unmap",
		"-device", "virtio-blk-device,drive=" + rootDriveID + ",serial=" + qemuRootSerial,
	}
}

type firecrackerConfig struct {
	BootSource        firecrackerBootSource         `json:"boot-source"`
	Drives            []firecrackerDrive            `json:"drives"`
	MachineConfig     firecrackerMachineConfig      `json:"machine-config"`
	NetworkInterfaces []firecrackerNetworkInterface `json:"network-interfaces,omitempty"`
	Balloon           *firecrackerBalloon           `json:"balloon,omitempty"`
}

type firecrackerBootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	InitrdPath      string `json:"initrd_path"`
	BootArgs        string `json:"boot_args"`
}

type firecrackerMachineConfig struct {
	VCPUCount  int `json:"vcpu_count"`
	MemSizeMiB int `json:"mem_size_mib"`
}

// firecrackerDrive is a Firecracker block device. Firecracker drives are
// always raw.
type firecrackerDrive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
	CacheType    string `json:"cache_type"`
	IOEngine     string `json:"io_engine"`
	Discard      bool   `json:"discard,omitempty"`
}

// Firecracker drive settings. Writeback passes guest flushes on to the
// image; the default, Unsafe, drops them. The Sync engine is the supported
// one. Neither drive is the root device, so Firecracker adds no root= to the
// kernel command line, which would also make the kernel unpack the initramfs
// into a ramfs instead of a tmpfs; the guest boots from the initramfs.
//
// The guest root image drops flushes, because its data never outlives the VM,
// and turns the guest's discards into holes in the image. Firecracker takes
// discard only with the Sync engine and exits with "Discard is not supported
// with the async IO engine" otherwise, so the engine is named even though
// Sync is what the volume has.
const (
	fcDriveCacheType     = "Writeback"
	fcDriveIOEngine      = "Sync"
	fcRootDriveCacheType = "Unsafe"
)

type firecrackerNetworkInterface struct {
	IfaceID     string `json:"iface_id"`
	GuestMAC    string `json:"guest_mac"`
	HostDevName string `json:"host_dev_name"`
}

// newFirecrackerConfig returns the --config-file content, before it is
// encoded, for a guest of memMiB MiB: a network interface on Garden's tap
// device, which Garden creates for every Firecracker container, with or
// without a port, a drive for each volume drive in drives, in volume order
// and named as on QEMU, and the guest root image as a drive after them when
// rootPath is set. Firecracker opens each volume drive by its /proc/self/fd
// path, because its drive configuration takes only a path, so it does its
// I/O through an open file of its own and not through vm-launch's checked
// one. Firecracker takes no serial, and the identity it gives
// each drive comes from the file it opens, which newGuestDrives predicts; for
// a block device that is the device node. An image and a block device get the
// same drive: Writeback, which passes the guest's flushes on, and the Sync
// engine. Firecracker opens neither with O_DIRECT, so a block device's data
// passes through the page cache and counts against the container's memory
// limit. nw must be set; the port does not change the configuration, because
// vm-launch itself, not Firecracker, forwards PORT. Every guest gets the
// balloon from newFirecrackerBalloon, which reports the guest's memory and is
// never inflated.
func newFirecrackerConfig(root, initrd string, memMiB int, nw *network, drives []volumeDrive, rootPath string) firecrackerConfig {
	return newFirecrackerConfigWithStack(root, initrd, memMiB, nw, drives, rootPath, nil)
}

// newFirecrackerConfigWithStack is newFirecrackerConfig for a guest that also
// has the stack and droplet images, as read-only drives on the descriptors
// stack and droplet, after the root image and in that order. A nil sd gives
// exactly the configuration newFirecrackerConfig gives.
func newFirecrackerConfigWithStack(root, initrd string, memMiB int, nw *network, drives []volumeDrive, rootPath string, sd *stackFDs) firecrackerConfig {
	cfg := firecrackerConfig{
		BootSource: firecrackerBootSource{
			KernelImagePath: filepath.Join(root, artVmlinux),
			InitrdPath:      initrd,
			BootArgs:        firecrackerKernelArgs,
		},
		Drives:        []firecrackerDrive{},
		MachineConfig: firecrackerMachineConfig{VCPUCount: guestVCPUs, MemSizeMiB: memMiB},
	}
	for _, d := range drives {
		cfg.Drives = append(cfg.Drives, firecrackerDrive{
			DriveID:      volumeDriveID(d.index),
			PathOnHost:   procSelfFD(d.fd),
			IsRootDevice: false,
			IsReadOnly:   false,
			CacheType:    fcDriveCacheType,
			IOEngine:     fcDriveIOEngine,
		})
	}
	if rootPath != "" {
		cfg.Drives = append(cfg.Drives, firecrackerDrive{
			DriveID:      rootDriveID,
			PathOnHost:   rootPath,
			IsRootDevice: false,
			IsReadOnly:   false,
			CacheType:    fcRootDriveCacheType,
			IOEngine:     fcDriveIOEngine,
			Discard:      true,
		})
	}
	if sd != nil {
		for _, d := range []struct {
			id string
			fd int
		}{{stackDriveID, sd.stack}, {dropletDriveID, sd.droplet}} {
			cfg.Drives = append(cfg.Drives, firecrackerDrive{
				DriveID:      d.id,
				PathOnHost:   procSelfFD(d.fd),
				IsRootDevice: false,
				IsReadOnly:   true,
				CacheType:    fcDriveCacheType,
				IOEngine:     fcDriveIOEngine,
			})
		}
	}
	cfg.NetworkInterfaces = []firecrackerNetworkInterface{{IfaceID: "eth0", GuestMAC: fcGuestMAC, HostDevName: fcTapName}}
	cfg.Balloon = newFirecrackerBalloon()
	return cfg
}

// stackFDs are the file descriptors the hypervisor gets the stack and droplet
// images on.
type stackFDs struct {
	stack, droplet int
}

// hypervisorArgv returns the command line for kind, writing any config file
// it needs into workDir. workDir holds only data files; nothing runs from it.
// memMiB is the guest memory size from guestMemory, which keeps it between
// the floor and the ceiling. nw is the guest network, which run always
// builds, and drives are the volume drives from hypervisorFiles, in volume
// order, or none without a volume. More than maxVolumes of them is an error,
// and so is a drive without a file, which the error names by its volume
// index, or by its place among drives when hypervisorFiles had no
// attachment to take an index from, a drive in neither file-image nor block
// mode, and, on QEMU, a drive whose identity the guest could not read back,
// because QEMU passes it as the serial. rootPath is the path of the guest
// root image, or empty when the guest root stays in RAM; that drive comes
// after the volumes' on both backends. monitorFD is QEMU's QMP socket (see
// qemuArgv), or 0; Firecracker has no monitor, and serves its API on
// firecrackerAPISocket of workDir instead. shares are the guest's shares,
// which only QEMU serves, so Firecracker refuses them. QEMU refuses a share
// list that checkShares rejects. Every guest gets a balloon device, which
// reports the guest's memory: on QEMU it is the last device on the command
// line, after the root, stack, and droplet drives, so no other device's
// virtio-mmio transport moves, and on Firecracker it is in the config file.
func hypervisorArgv(kind backend.Kind, root, workDir, initrd string, memMiB int, nw *network, drives []volumeDrive, rootPath string, monitorFD int, shares ...shareSocket) ([]string, error) {
	return hypervisorArgvWithStack(kind, root, workDir, initrd, memMiB, nw, drives, rootPath, monitorFD, nil, shares...)
}

// hypervisorArgvWithStack is hypervisorArgv for a guest that also has the
// stack and droplet images in sd, which hypervisorFilesWithStack passes as
// the two files after the root image. The hypervisor attaches both as
// read-only virtio-blk drives after the root image, the stack first, so no
// other drive moves. Only whether sd is nil matters here, because the
// descriptors follow from the drives, the monitor, and the root image (see
// stackDriveFDs). A nil sd gives exactly the command line or configuration
// hypervisorArgv gives.
func hypervisorArgvWithStack(kind backend.Kind, root, workDir, initrd string, memMiB int, nw *network, drives []volumeDrive, rootPath string, monitorFD int, sd *stackDrives, shares ...shareSocket) ([]string, error) {
	var fds *stackFDs
	if sd != nil {
		stack, droplet := stackDriveFDs(len(drives), monitorFD > 0, rootPath != "")
		fds = &stackFDs{stack: stack, droplet: droplet}
	}
	if len(drives) > maxVolumes {
		return nil, fmt.Errorf("%d volume drives, over the %d a guest can have", len(drives), maxVolumes)
	}
	for i, d := range drives {
		switch {
		case d.fd < firstExtraFD && d.index < 0:
			return nil, fmt.Errorf("the volume drive at place %d among the drives has no file and no volume index", i)
		case d.fd < firstExtraFD:
			return nil, fmt.Errorf("volume drive %s has no file", volumeDriveID(d.index))
		case d.mode != attachFileImage && d.mode != attachBlock:
			return nil, fmt.Errorf("volume drive %s is in %s, which VM backends do not attach as a drive", volumeDriveID(d.index), d.mode)
		case kind == backend.VMQemu && !validDriveID(d.id):
			return nil, fmt.Errorf("volume drive %s has the identity %q, which is not 1 to %d letters, digits, and hyphens, so QEMU cannot pass it as the drive's serial", volumeDriveID(d.index), d.id, virtioBlockIDBytes)
		}
	}
	if len(shares) > 0 && kind != backend.VMQemu {
		return nil, fmt.Errorf("%s cannot serve shares, which need QEMU's vhost-user-fs device", kind)
	}
	if err := checkShares(shares); err != nil {
		return nil, err
	}
	switch kind {
	case backend.VMQemu:
		argv := qemuArgv(root, initrd, memMiB, nw, drives, monitorFD, shares...)
		if rootPath != "" {
			argv = append(argv, qemuRootDrive(rootPath)...)
		}
		if fds != nil {
			argv = append(argv, qemuReadOnlyDrive(stackDriveID, qemuStackSerial, fds.stack)...)
			argv = append(argv, qemuReadOnlyDrive(dropletDriveID, qemuDropletSerial, fds.droplet)...)
		}
		return append(argv, qemuBalloonArgs()...), nil
	case backend.VMFirecracker:
		if monitorFD != 0 {
			return nil, errors.New("firecracker has no QMP monitor")
		}
		cfg, err := json.Marshal(newFirecrackerConfigWithStack(root, initrd, memMiB, nw, drives, rootPath, fds))
		if err != nil {
			return nil, fmt.Errorf("encoding firecracker config: %w", err)
		}
		cfgPath := filepath.Join(workDir, "fc.json")
		if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
			return nil, fmt.Errorf("writing firecracker config: %w", err)
		}
		return firecrackerAPIArgv(root, cfgPath, firecrackerAPISocket(workDir)), nil
	default:
		return nil, fmt.Errorf("unsupported backend %q", kind)
	}
}

// Serial filter phases.
const (
	phaseBoot = iota // before /init prints the start tag: kernel output, held for diagnostics
	phaseRun         // guest command output, streamed
	phaseDone        // exit marker seen, everything after it dropped
)

// maxBootLog bounds the pre-start console output kept for diagnostics.
const maxBootLog = 64 * 1024

// maxStatusDigits is the longest decimal exit status a shell reports (255).
const maxStatusDigits = 3

// maxPortDigits is the longest decimal TCP port number (65535).
const maxPortDigits = 5

// maxOOMDigits is the most digits an OOM count or an acknowledged push's
// sequence number may have, which keeps either far inside an int.
const maxOOMDigits = 9

// maxFrameBytes bounds a log frame on the console, from the start of its tag
// to its newline. The guest's framers put at most 960 bytes of payload in a
// frame, so a frame tag without a newline this soon is ordinary output.
const maxFrameBytes = 2 << 10

// maxLogLine bounds a log line that the filter joins from the pieces of a
// frame. The guest folds longer lines (see logTag), so a longer join only
// comes from a broken frame, and the filter passes it on as more than one
// line.
const maxLogLine = 64 << 10

// maxIndexDigits is the most digits a process index in a log frame or a
// first-exit line may have. The index is at most maxSidecars as well.
const maxIndexDigits = 2

// serialFilter turns the guest serial console into the guest command's
// output. It drops the console before the start tag and after the exit
// marker, swallows the marker, converts the console's CRLF line endings to LF,
// and records the exit status. With a listen callback, it also swallows each
// listen line the guest writes while the command runs (see
// guestListenWatch) and passes its state to the callback, which must not
// block. It swallows the guest's OOM line too (see guestOOMReport) and keeps
// its count in oomKills. With an acknowledgement callback, it swallows the
// guest's acknowledgement of each identity push (see credOKTag and
// credBadTag) and passes its sequence number to the callback, which must not
// block either. With that callback, it also swallows the line before the
// start tag with which the guest says that it takes no pushes (see
// credOffTag) and sets credOff. A listen, OOM, or acknowledgement line can follow command
// output that has no newline yet, so each is found anywhere in a line, and
// the output around it is kept as it was. It never fails a Write, so the hypervisor's output keeps draining
// when the destination breaks; the first destination error is kept in
// writeErr.
//
// With onFrames, the filter also swallows the guest's log frames (see
// logTag) and its first-exit line (see firstTag). A frame counts only at the
// start of a console line, so a tag inside a frame's payload, the exit
// marker's included, is never taken for what it says. The filter joins the
// pieces of each process's lines, writes the app's stdout lines to out, in
// order with the guest's unframed output, and the app's stderr lines to
// errOut, and passes the lines of every other process to the logs callback,
// or without one to out and errOut by stream. It passes the first-exit line
// to the firstExit callback. Neither callback may block.
type serialFilter struct {
	out        io.Writer
	errOut     io.Writer
	startTag   []byte
	exitTag    []byte
	listenTag  []byte
	oomTag     []byte
	credOKTag  []byte
	credBadTag []byte
	credOffTag []byte
	logTag     []byte
	firstTag   []byte
	listen     func(port int, up bool)
	credAck    func(seq int, ok bool)
	logs       func(index int, stream byte, line string)
	firstExit  func(index, status int)

	phase    int
	pending  []byte
	bootLog  []byte
	status   int
	oomKills int
	credOff  bool
	writeErr error

	// lineStart reports whether the console byte before pending ended a
	// line, which a log frame's tag needs at pending[0].
	lineStart bool
	// pieces holds the pieces of each process's unfinished stdout and
	// stderr lines, at 2*index and 2*index+1.
	pieces [2 * (maxSidecars + 1)][]byte
	// line is the buffer in which a joined line gets its newline for out or
	// errOut.
	line []byte

	// startSeen is closed when the start tag is parsed, before any of the
	// command's output is written.
	startSeen chan struct{}
	// running is closed at the end of the write in which the start tag was
	// parsed, after exited when that write held the exit marker too, so that
	// whoever wakes on it sees whether the guest has already reported its
	// status.
	running chan struct{}
	// exited is closed when the exit marker is parsed.
	exited chan struct{}
}

func newSerialFilter(out io.Writer, nonce string) *serialFilter {
	return &serialFilter{
		out:       out,
		startTag:  []byte(startTag(nonce)),
		exitTag:   []byte(exitTag(nonce)),
		oomTag:    []byte(oomTag(nonce)),
		startSeen: make(chan struct{}),
		running:   make(chan struct{}),
		exited:    make(chan struct{}),
	}
}

// onListen makes the filter pass listen lines to listen.
func (f *serialFilter) onListen(nonce string, listen func(port int, up bool)) {
	f.listenTag = []byte(listenTag(nonce))
	f.listen = listen
}

// onCredAck makes the filter pass the guest's acknowledgements of identity
// pushes to ack, with ok set for a push the guest installed.
func (f *serialFilter) onCredAck(nonce string, ack func(seq int, ok bool)) {
	f.credOKTag = []byte(credOKTag(nonce))
	f.credBadTag = []byte(credBadTag(nonce))
	f.credOffTag = []byte(credOffTag(nonce))
	f.credAck = ack
}

// onFrames makes the filter split the guest's log frames and swallow its
// first-exit line. errOut takes the app's stderr lines, and nil means out.
// logs, when set, takes the lines of every other process, and firstExit, when
// set, takes the first-exit line's index and status.
func (f *serialFilter) onFrames(nonce string, errOut io.Writer, logs func(index int, stream byte, line string), firstExit func(index, status int)) {
	f.logTag = []byte(logTag(nonce))
	f.firstTag = []byte(firstTag(nonce))
	f.errOut = errOut
	if errOut == nil {
		f.errOut = f.out
	}
	f.logs = logs
	f.firstExit = firstExit
}

func (f *serialFilter) Write(p []byte) (int, error) {
	if f.phase == phaseDone {
		return len(p), nil
	}
	f.pending = append(f.pending, p...)
	f.process(false)
	if f.phase != phaseBoot && !isClosed(f.running) {
		close(f.running)
	}
	return len(p), nil
}

// finish flushes held bytes at end of stream. A marker without its line
// terminator may be truncated, so it counts as output, not as a status. The
// pieces of a line whose last piece never came go out as a line of their own.
func (f *serialFilter) finish() {
	if f.phase != phaseDone {
		f.process(true)
	}
	for index := 0; index <= maxSidecars; index++ {
		f.flushPieces(index)
	}
}

func (f *serialFilter) started() bool { return f.phase != phaseBoot }

func (f *serialFilter) markerFound() bool { return f.phase == phaseDone }

func (f *serialFilter) process(eof bool) {
	if f.phase == phaseBoot {
		f.processBoot(eof)
	}
	if f.phase == phaseRun {
		f.processRun(eof)
	}
}

func (f *serialFilter) processBoot(eof bool) {
	for {
		nl := bytes.IndexByte(f.pending, '\n')
		if nl < 0 {
			break
		}
		line := f.pending[:nl+1]
		f.pending = f.pending[nl+1:]
		if bytes.Contains(line, f.startTag) {
			f.phase = phaseRun
			f.lineStart = true
			f.bootLog = nil
			close(f.startSeen)
			return
		}
		if f.credOffTag != nil && bytes.Contains(line, f.credOffTag) {
			f.credOff = true
			continue
		}
		f.keepBootLog(line)
	}
	// An overlong partial line moves to the log, except for its tail, which
	// may be the start of the tag. A line already holding the whole tag stays
	// pending until its newline, which /init writes right after the tag.
	if eof {
		f.keepBootLog(f.pending)
		f.pending = nil
	} else if keep := len(f.startTag); len(f.pending) > maxBootLog+keep && !bytes.Contains(f.pending, f.startTag) {
		f.keepBootLog(f.pending[:len(f.pending)-keep])
		f.pending = append([]byte(nil), f.pending[len(f.pending)-keep:]...)
	}
}

func (f *serialFilter) keepBootLog(b []byte) {
	f.bootLog = append(f.bootLog, b...)
	if over := len(f.bootLog) - maxBootLog; over > 0 {
		f.bootLog = append([]byte(nil), f.bootLog[over:]...)
	}
}

func (f *serialFilter) processRun(eof bool) {
	for {
		// Nearly every line is a frame once the guest frames its output, so
		// a frame at the start of pending skips the search for every tag.
		if f.logTag != nil && f.lineStart && bytes.HasPrefix(f.pending, f.logTag) {
			if !f.processFrame(0, eof) {
				return
			}
			continue
		}
		idx := bytes.Index(f.pending, f.exitTag)
		if li, kind := f.indexLine(); li >= 0 && (idx < 0 || li < idx) {
			if !f.processLine(kind, li, eof) {
				return
			}
			continue
		}
		if idx < 0 {
			break
		}
		status, ok, needMore := parseStatus(f.pending[idx+len(f.exitTag):])
		if needMore && !eof {
			f.emitPending(idx, false)
			return
		}
		if ok {
			f.emitPending(idx, true)
			f.pending = nil
			f.status = status
			f.phase = phaseDone
			close(f.exited)
			return
		}
		// Not a marker. The tag ends in its only '=', so no real tag can
		// start inside it, and scanning resumes right after it.
		f.emitPending(idx+len(f.exitTag), true)
	}
	if eof {
		f.emitPending(len(f.pending), true)
		return
	}
	hold := tagPrefixSuffix(f.pending, f.exitTag)
	for _, tag := range f.lineTags() {
		if tag != nil {
			hold = max(hold, tagPrefixSuffix(f.pending, tag))
		}
	}
	f.emitPending(len(f.pending)-hold, false)
}

// The kinds of line, other than the exit marker, that the filter swallows
// while the command runs, as indexes into lineTags.
const (
	lineOOM = iota
	lineListen
	lineCredOK
	lineCredBad
	lineLog
	lineFirst
	lineKinds
)

// lineTags returns the tag of each kind of line the filter swallows while
// the command runs, other than the exit marker, with nil for a kind it does
// not look for.
func (f *serialFilter) lineTags() [lineKinds][]byte {
	return [lineKinds][]byte{lineOOM: f.oomTag, lineListen: f.listenTag, lineCredOK: f.credOKTag, lineCredBad: f.credBadTag, lineLog: f.logTag, lineFirst: f.firstTag}
}

// indexLine returns the index in pending of the first tag of a line that the
// filter swallows, other than the exit marker, and the kind of that line, or
// -1. No two of the tags can start at the same index, because each differs
// from the others before its nonce. A log frame's tag counts only at the
// start of a line.
func (f *serialFilter) indexLine() (idx, kind int) {
	idx = -1
	for k, tag := range f.lineTags() {
		if tag == nil {
			continue
		}
		i := bytes.Index(f.pending, tag)
		if k == lineLog {
			i = f.indexFrame()
		}
		if i >= 0 && (idx < 0 || i < idx) {
			idx, kind = i, k
		}
	}
	return idx, kind
}

// indexFrame returns the index in pending of the first log tag that starts a
// line, or -1.
func (f *serialFilter) indexFrame() int {
	for from := 0; ; {
		i := bytes.Index(f.pending[from:], f.logTag)
		if i < 0 {
			return -1
		}
		i += from
		if (i == 0 && f.lineStart) || (i > 0 && f.pending[i-1] == '\n') {
			return i
		}
		from = i + len(f.logTag)
	}
}

// processLine handles the tag of a line of the given kind at pending[idx:].
func (f *serialFilter) processLine(kind, idx int, eof bool) bool {
	switch kind {
	case lineListen:
		return f.processListen(idx, eof)
	case lineOOM:
		return f.processCount(f.oomTag, idx, eof, func(kills int) { f.oomKills = kills })
	case lineCredOK:
		return f.processCount(f.credOKTag, idx, eof, func(seq int) { f.credAck(seq, true) })
	case lineCredBad:
		return f.processCount(f.credBadTag, idx, eof, func(seq int) { f.credAck(seq, false) })
	case lineLog:
		return f.processFrame(idx, eof)
	default:
		return f.processFirst(idx, eof)
	}
}

// processFrame handles the log tag at pending[idx:], which starts a line, as
// processListen handles a listen tag. A complete frame leaves the output and
// its piece goes to takePiece. A tag with anything else after it, or with no
// newline within maxFrameBytes, is output.
func (f *serialFilter) processFrame(idx int, eof bool) bool {
	if idx > 0 {
		f.emitPending(idx, true)
	}
	index, stream, last, payload, n, ok, needMore := parseFrame(f.pending[len(f.logTag):], maxFrameBytes-len(f.logTag))
	if needMore && !eof {
		return false
	}
	if !ok {
		// The tag ends in its only '=', so no tag can start inside it.
		f.emitPending(len(f.logTag), true)
		return true
	}
	f.takePiece(index, stream, last, payload)
	f.swallow(len(f.logTag) + n)
	return true
}

// processFirst handles the first-exit tag at pending[idx:] as processCount
// handles its tags. Before it passes on the line, it sends on the pieces that
// the process left unfinished, whose last piece can no longer come.
func (f *serialFilter) processFirst(idx int, eof bool) bool {
	index, status, n, ok, needMore := parseFirst(f.pending[idx+len(f.firstTag):])
	if needMore && !eof {
		f.emitPending(idx, false)
		return false
	}
	if !ok {
		// The tag ends in its only '=', so no tag can start inside it.
		f.emitPending(idx+len(f.firstTag), true)
		return true
	}
	f.emitPending(idx, true)
	f.swallow(len(f.firstTag) + n)
	f.flushPieces(index)
	if f.firstExit != nil {
		f.firstExit(index, status)
	}
	return true
}

// takePiece adds a frame's payload to the pieces of its process's line, and
// sends the line on at its last piece, or first when it would pass
// maxLogLine.
func (f *serialFilter) takePiece(index int, stream byte, last bool, payload []byte) {
	slot := 2 * index
	if stream == 'e' {
		slot++
	}
	held := f.pieces[slot]
	if len(held)+len(payload) > maxLogLine && len(held) > 0 {
		f.sendLine(index, stream, held)
		held = held[:0]
	}
	switch {
	case last && len(held) == 0:
		f.sendLine(index, stream, payload)
	case last:
		f.sendLine(index, stream, append(held, payload...))
		held = held[:0]
	default:
		held = append(held, payload...)
	}
	f.pieces[slot] = held
}

// flushPieces sends on, as lines of their own, the pieces of index's lines
// whose last piece has not come.
func (f *serialFilter) flushPieces(index int) {
	for i, stream := range []byte{'o', 'e'} {
		slot := 2*index + i
		if len(f.pieces[slot]) > 0 {
			f.sendLine(index, stream, f.pieces[slot])
		}
		f.pieces[slot] = nil
	}
}

// sendLine passes one whole line of index's stream, without its newline, to
// the logs callback, or writes it with a newline to out or errOut.
func (f *serialFilter) sendLine(index int, stream byte, line []byte) {
	if index != 0 && f.logs != nil {
		f.logs(index, stream, string(line))
		return
	}
	w := f.out
	if stream == 'e' {
		w = f.errOut
	}
	f.line = append(append(f.line[:0], line...), '\n')
	if f.writeErr != nil {
		return
	}
	if _, err := w.Write(f.line); err != nil {
		f.writeErr = err
	}
}

// swallow drops a whole control line or frame, its line ending included,
// from the start of pending, which leaves the console at the start of a line.
// It does not copy the rest of pending, so a run of frames costs no more
// than the frames themselves.
func (f *serialFilter) swallow(n int) {
	f.pending = f.pending[n:]
	f.lineStart = true
}

// processListen handles the listen tag at pending[idx:]. It reports false
// when the line is not complete yet and more input may come; the output
// before the tag is written and the tag stays pending. A complete listen
// line goes to the callback and leaves the output, its line ending
// included. Anything else after the tag is output, like the tag itself.
func (f *serialFilter) processListen(idx int, eof bool) bool {
	port, up, n, ok, needMore := parseListen(f.pending[idx+len(f.listenTag):])
	if needMore && !eof {
		f.emitPending(idx, false)
		return false
	}
	if !ok {
		// The tag ends in its only '=', and no other tag can start inside
		// it, so scanning resumes right after it.
		f.emitPending(idx+len(f.listenTag), true)
		return true
	}
	f.emitPending(idx, true)
	f.swallow(len(f.listenTag) + n)
	f.listen(port, up)
	return true
}

// processCount handles a tag at pending[idx:] whose line carries a count, the
// OOM line and both acknowledgements, as processListen handles a listen tag:
// a complete line leaves the output and its count goes to take, and anything
// else after the tag is output.
func (f *serialFilter) processCount(tag []byte, idx int, eof bool, take func(int)) bool {
	count, n, ok, needMore := parseCount(f.pending[idx+len(tag):])
	if needMore && !eof {
		f.emitPending(idx, false)
		return false
	}
	if !ok {
		// The tag ends in its only '=', so no tag can start inside it.
		f.emitPending(idx+len(tag), true)
		return true
	}
	f.emitPending(idx, true)
	f.swallow(len(tag) + n)
	take(count)
	return true
}

// emitPending writes pending[:n] as guest output with the console's CRLF
// line endings turned into LF, and keeps the rest pending. When nothing
// follows a trailing CR yet and more input may come, the CR stays pending
// until the next byte shows whether it ends a line. Cut points other than the
// end of pending always sit before 'R' or after '=', never inside a CRLF.
func (f *serialFilter) emitPending(n int, final bool) {
	if !final && n == len(f.pending) && n > 0 && f.pending[n-1] == '\r' {
		n--
	}
	out := bytes.ReplaceAll(f.pending[:n], []byte("\r\n"), []byte("\n"))
	f.pending = append([]byte(nil), f.pending[n:]...)
	if len(out) > 0 {
		f.lineStart = out[len(out)-1] == '\n'
	}
	if len(out) == 0 || f.writeErr != nil {
		return
	}
	if _, err := f.out.Write(out); err != nil {
		f.writeErr = err
	}
}

// parseStatus parses the bytes after an exit tag: 1 to 3 decimal digits
// with a value of at most 255, then LF or CRLF. needMore reports that b ends
// before that can be decided.
func parseStatus(b []byte) (status int, ok, needMore bool) {
	i := 0
	for i < len(b) && i <= maxStatusDigits && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	switch {
	case i > maxStatusDigits:
		return 0, false, false
	case i == len(b):
		return 0, false, true
	case i == 0:
		return 0, false, false
	}
	status, err := strconv.Atoi(string(b[:i]))
	if err != nil || status > 255 {
		return 0, false, false
	}
	switch {
	case b[i] == '\n':
		return status, true, false
	case b[i] != '\r':
		return 0, false, false
	case i+1 == len(b):
		return 0, false, true
	case b[i+1] == '\n':
		return status, true, false
	default:
		return 0, false, false
	}
}

// parseCount parses the bytes after an OOM or acknowledgement tag: 1 to
// maxOOMDigits decimal digits, then LF or CRLF. n is the length of what it
// parsed. needMore reports that b ends before that can be decided.
func parseCount(b []byte) (count, n int, ok, needMore bool) {
	i := 0
	for i < len(b) && i <= maxOOMDigits && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	switch {
	case i > maxOOMDigits:
		return 0, 0, false, false
	case i == len(b):
		return 0, 0, false, true
	case i == 0:
		return 0, 0, false, false
	}
	count, err := strconv.Atoi(string(b[:i]))
	if err != nil {
		return 0, 0, false, false
	}
	switch {
	case b[i] == '\n':
		return count, i + 1, true, false
	case b[i] != '\r':
		return 0, 0, false, false
	case i+1 == len(b):
		return 0, 0, false, true
	case b[i+1] == '\n':
		return count, i + 2, true, false
	default:
		return 0, 0, false, false
	}
}

// parseListen parses the bytes after a listen tag: a port of 1 to 5 decimal
// digits and a value of at most 65535, a colon, 1 or 0, then LF or CRLF. n is
// the length of what it parsed. needMore reports that b ends before that can
// be decided.
func parseListen(b []byte) (port int, up bool, n int, ok, needMore bool) {
	i := 0
	for i < len(b) && i <= maxPortDigits && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	switch {
	case i > maxPortDigits:
		return 0, false, 0, false, false
	case i == len(b):
		return 0, false, 0, false, true
	case i == 0 || b[i] != ':':
		return 0, false, 0, false, false
	}
	port, err := strconv.Atoi(string(b[:i]))
	if err != nil || port < 1 || port > 65535 {
		return 0, false, 0, false, false
	}
	b = b[i+1:]
	switch {
	case len(b) == 0:
		return 0, false, 0, false, true
	case b[0] != '0' && b[0] != '1':
		return 0, false, 0, false, false
	case len(b) == 1:
		return 0, false, 0, false, true
	case b[1] == '\n':
		return port, b[0] == '1', i + 3, true, false
	case b[1] != '\r':
		return 0, false, 0, false, false
	case len(b) == 2:
		return 0, false, 0, false, true
	case b[2] == '\n':
		return port, b[0] == '1', i + 4, true, false
	default:
		return 0, false, 0, false, false
	}
}

// parseIndex parses a process index at the start of b: 1 to maxIndexDigits
// decimal digits with a value of at most maxSidecars. i is the length of the
// digits. needMore reports that b ends before that can be decided.
func parseIndex(b []byte) (index, i int, ok, needMore bool) {
	for i < len(b) && i <= maxIndexDigits && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	switch {
	case i > maxIndexDigits:
		return 0, 0, false, false
	case i == len(b):
		return 0, 0, false, true
	case i == 0:
		return 0, 0, false, false
	}
	index, err := strconv.Atoi(string(b[:i]))
	if err != nil || index > maxSidecars {
		return 0, 0, false, false
	}
	return index, i, true, false
}

// parseFrame parses the bytes after a log tag: a process index (see
// parseIndex), o, e, O, or E, a space, and the payload, then LF or CRLF,
// with the LF among the first room bytes. stream is 'o' or 'e', and last
// reports a lowercase letter. The payload has the line ending's CR taken off,
// and it shares b's bytes. n is the length of what it parsed. needMore
// reports that b ends before that can be decided.
func parseFrame(b []byte, room int) (index int, stream byte, last bool, payload []byte, n int, ok, needMore bool) {
	index, i, ok, needMore := parseIndex(b)
	if !ok {
		return 0, 0, false, nil, 0, false, needMore
	}
	switch {
	case i == len(b):
		return 0, 0, false, nil, 0, false, true
	case b[i] == 'o' || b[i] == 'e':
		stream, last = b[i], true
	case b[i] == 'O' || b[i] == 'E':
		stream = b[i] + 'a' - 'A'
	default:
		return 0, 0, false, nil, 0, false, false
	}
	switch {
	case i+1 == len(b):
		return 0, 0, false, nil, 0, false, true
	case b[i+1] != ' ':
		return 0, 0, false, nil, 0, false, false
	}
	window := b[:min(len(b), room)]
	nl := bytes.IndexByte(window[i+2:], '\n')
	switch {
	case nl < 0 && len(b) >= room:
		return 0, 0, false, nil, 0, false, false
	case nl < 0:
		return 0, 0, false, nil, 0, false, true
	}
	payload = bytes.TrimSuffix(b[i+2:i+2+nl], []byte("\r"))
	return index, stream, last, payload, i + 2 + nl + 1, true, false
}

// parseFirst parses the bytes after a first-exit tag: a process index (see
// parseIndex), a space, and 1 to 3 decimal digits with a value of at most
// 255, then LF or CRLF. n is the length of what it parsed. needMore reports
// that b ends before that can be decided.
func parseFirst(b []byte) (index, status, n int, ok, needMore bool) {
	index, i, ok, needMore := parseIndex(b)
	if !ok {
		return 0, 0, 0, false, needMore
	}
	if b[i] != ' ' {
		return 0, 0, 0, false, false
	}
	rest := b[i+1:]
	digits := 0
	for digits < len(rest) && digits <= maxStatusDigits && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	if digits > maxStatusDigits {
		return 0, 0, 0, false, false
	}
	status, m, ok, needMore := parseCount(rest)
	if !ok || status > 255 {
		return 0, 0, 0, false, needMore
	}
	return index, status, i + 1 + m, true, false
}

// tagPrefixSuffix returns the length of the longest suffix of b that is a
// proper prefix of tag, which is the part of b that may still become a tag.
func tagPrefixSuffix(b, tag []byte) int {
	n := len(tag) - 1
	if n > len(b) {
		n = len(b)
	}
	for ; n > 0; n-- {
		if bytes.HasSuffix(b, tag[:n]) {
			return n
		}
	}
	return 0
}

// runResult is what vm-launch learned from one guest run.
type runResult struct {
	markerFound bool
	guestStatus int
	// received is the first signal vm-launch received, whether it was
	// forwarded or became a stop request, or 0.
	received syscall.Signal
	// guestOOMKills is how many processes the guest kernel killed for lack of
	// memory, as the guest reported, or 0.
	guestOOMKills int
	// state is the hypervisor's reaped state.
	state *os.ProcessState
}

// supervisor runs one hypervisor process: it reads the serial console
// through a serialFilter as fast as the guest writes it, passes the guest
// command's output on to stdout, and the app's stderr lines on to stderr,
// each through an outputQueue of its own, stops the guest
// command or forwards signals, and kills the hypervisor when it outlives
// deadline after the first signal, or grace after the guest reported its
// status without a signal (a guest that hangs on its way down must not hang
// the app process).
//
// The supervisor acts on the first signal according to what the guest has
// reported so far. While the guest's command runs, after the start tag and
// before the exit marker, the supervisor writes the stop request (see
// stopTag) once to the hypervisor's stdin, which is the guest's serial
// console, and does not forward the signal. It writes through a
// consoleWriter, which identity pushes share, so the stop request goes ahead
// of what remains of a push. The guest's stop reader then
// sends SIGTERM to the command, which may finish its work, and /init reports
// the command's status and powers off as after any other end of the command.
// Before the start tag there is no command to stop, and after the exit
// marker the guest is already on its way down, so the supervisor forwards
// the signal to the hypervisor, as it does when the stop request cannot be
// written. A later signal is forwarded too when the first one was, and
// changes nothing when a stop request was written, so it never cuts a drain
// short. No later signal moves the deadline, and nothing the guest writes
// moves it either: the supervisor never acts on stop data from the guest.
//
// While the command drains, its ports stay as the guest reports them, so a
// new connection still reaches an app that still listens, as it would in a
// container while the route goes away. The supervisor runs closePorts when
// the drain ends: when the guest reports the command's status, or when the
// deadline kills the hypervisor. A port the app stops listening on during
// the drain closes before that, on the guest's listen report. A signal that
// the supervisor forwards runs closePorts at once, because the hypervisor
// may end at once.
type supervisor struct {
	stdout io.Writer
	// stderr, when set, takes the app's stderr lines from the guest's log
	// frames (see serialFilter). Without it they go to stdout.
	stderr  io.Writer
	logger  *log.Logger
	signals <-chan os.Signal
	// grace bounds how long the hypervisor may run after the guest reported
	// its status, when no signal came first.
	grace time.Duration
	// deadline bounds how long the hypervisor may run after the first
	// signal, whatever the supervisor did with it.
	deadline time.Duration
	// closePorts, when set, runs once, when the guest is about to go: at a
	// signal the supervisor forwards, after the signal is logged and before
	// it is forwarded; when the guest reports its status after a stop
	// request; or when the deadline runs out, before the kill. vm-launch uses
	// it to stop accepting guest connections.
	closePorts func()
	// outputLimit bounds the guest output waiting for stdout (see
	// outputQueue). Zero means guestOutputLimit.
	outputLimit int
	// started, when set, runs once the hypervisor has started and before
	// anything else. vm-launch uses it to close its copies of the files the
	// hypervisor inherited.
	started func()
	// reaped, when set, runs as soon as the hypervisor has been reaped, in
	// the goroutine that reaped it, and before the supervisor flushes the
	// guest's last output. vm-launch uses it to tell the share servers at
	// once that QEMU is gone. It must not block.
	reaped func()
	// listen, when set, gets the guest's listen lines (see serialFilter). It
	// must not block.
	listen func(port int, up bool)
	// credAck, when set, gets the guest's acknowledgements of identity pushes
	// (see serialFilter). It must not block.
	credAck func(seq int, ok bool)
	// logs, when set, gets every line of the guest's sidecars, by index and
	// stream (see serialFilter). Without it they go to stdout and stderr like
	// the app's. It must not block.
	logs func(index int, stream byte, line string)
	// firstExit, when set, gets the index and status of the guest process
	// that exited first (see serialFilter). It must not block.
	firstExit func(index, status int)
	// onConsole, when set, gets the writer of the guest's console input once
	// the guest has started its command, so that vm-launch can push identity
	// frames on it. The supervisor calls it once, from its own goroutine, and
	// never when a signal came first, the guest has already reported its
	// status, or the guest said before its start tag that it takes no pushes.
	// In that last case the supervisor logs that the identity rotation is off
	// for the guest. It must not block, so it starts any work of its own in a
	// goroutine. The writer refuses pushes once the stop request is written
	// and once run returns.
	onConsole func(w *consoleWriter)
	// reported, when set, runs once the supervisor has acted on the guest's
	// status line, so a spec can send a signal that comes after it. It must
	// not block. vm-launch leaves it unset.
	reported func()
	// prepare, when set, makes the supervisor start the hypervisor from an
	// OS thread of its own, after prepare has run on it (see
	// startConfined). vm-launch uses it to start Firecracker without any
	// capability, CAP_NET_RAW, which its transparent port proxy needs,
	// among them. A failure of prepare is a failure to start the
	// hypervisor.
	prepare func() error
}

// run starts cmd and waits for it. The error is non-nil only when the
// hypervisor could not be started. cmd's stdin must be unset: run gives the
// hypervisor a pipe as its stdin, whose write end only vm-launch holds.
func (s supervisor) run(cmd *exec.Cmd, nonce string) (runResult, error) {
	if s.grace <= 0 || s.deadline <= 0 {
		return runResult{}, fmt.Errorf("the hypervisor's kill grace %v and stop deadline %v must both be positive", s.grace, s.deadline)
	}
	if cmd.Stdin != nil {
		return runResult{}, errors.New("the hypervisor's stdin is already set")
	}
	if cmd.Stdout != nil {
		return runResult{}, errors.New("the hypervisor's stdout is already set")
	}
	serial, serialOut, err := os.Pipe()
	if err != nil {
		return runResult{}, fmt.Errorf("creating serial pipe: %w", err)
	}
	defer serial.Close()
	console, consoleIn, err := os.Pipe()
	if err != nil {
		serialOut.Close()
		return runResult{}, fmt.Errorf("creating the hypervisor's stdin pipe: %w", err)
	}
	stdin := newConsoleWriter(consoleIn)
	defer stdin.close()
	growPipe(serial, s.logger)
	cmd.Stdin, cmd.Stdout = console, serialOut
	var release func()
	if s.prepare != nil {
		release, err = startConfined(cmd, s.prepare)
	} else {
		err = cmd.Start()
	}
	// Only the hypervisor keeps the read end of its stdin, so a write after
	// it has gone fails at once instead of filling the pipe; and only the
	// hypervisor keeps the write end of its stdout, so the console reaches
	// its end when the hypervisor exits.
	if cerr := console.Close(); cerr != nil {
		s.logger.Printf("closing vm-launch's copy of the hypervisor's stdin: %v", cerr)
	}
	if cerr := serialOut.Close(); cerr != nil {
		s.logger.Printf("closing vm-launch's copy of the hypervisor's stdout: %v", cerr)
	}
	if err != nil {
		return runResult{}, fmt.Errorf("starting hypervisor %s: %w", cmd.Path, err)
	}
	if release != nil {
		// run returns only once the hypervisor has been reaped, or on a
		// panic, after which vm-launch ends anyway.
		defer release()
	}
	if s.started != nil {
		s.started()
	}

	limit := s.outputLimit
	if limit <= 0 {
		limit = guestOutputLimit
	}
	output := newOutputQueue(s.stdout, limit, s.logger)
	filter := newSerialFilter(output, nonce)
	// A nil *outputQueue would make a non-nil io.Writer, so errOut stays an
	// untyped nil without stderr.
	var errOutput *outputQueue
	var errOut io.Writer
	if s.stderr != nil {
		errOutput = newOutputQueue(s.stderr, limit, s.logger)
		errOut = errOutput
	}
	filter.onFrames(nonce, errOut, s.logs, s.firstExit)
	if s.listen != nil {
		filter.onListen(nonce, s.listen)
	}
	if s.credAck != nil {
		filter.onCredAck(nonce, s.credAck)
	}
	type ended struct{ copyErr, waitErr error }
	done := make(chan ended, 1)
	go func() {
		// The filter writes to the queue, which never blocks, so this reads
		// the console as fast as the guest writes it.
		_, copyErr := io.Copy(filter, serial)
		waitErr := cmd.Wait()
		if s.reaped != nil {
			s.reaped()
		}
		done <- ended{copyErr: copyErr, waitErr: waitErr}
	}()

	var res runResult
	running, markerSeen := filter.running, filter.exited
	var kill <-chan time.Time
	var killReason string
	// signalled is set at the first signal, and asked once the stop request
	// for it is written.
	signalled, asked := false, false
	closePorts := func() {
		if s.closePorts != nil {
			s.closePorts()
			s.closePorts = nil
		}
	}
	forward := func(sig os.Signal) {
		if err := cmd.Process.Signal(sig); err != nil && !errors.Is(err, os.ErrProcessDone) {
			s.logger.Printf("forwarding %v to the hypervisor: %v", sig, err)
		}
	}
	for {
		select {
		case sig := <-s.signals:
			if signalled {
				if asked {
					s.logger.Printf("received %v again; the guest is already stopping", sig)
				} else {
					s.logger.Printf("received %v, forwarding it to the hypervisor", sig)
					forward(sig)
				}
				continue
			}
			signalled = true
			if ss, ok := sig.(syscall.Signal); ok {
				res.received = ss
			}
			// The filter closes these channels in the console goroutine, so
			// the supervisor learns the guest's progress without touching the
			// filter's state.
			reported, started := isClosed(filter.exited), isClosed(filter.startSeen)
			switch {
			case reported:
				s.logger.Printf("received %v after the guest reported its status, forwarding it to the hypervisor", sig)
			case !started:
				s.logger.Printf("received %v before the guest started its command, forwarding it to the hypervisor", sig)
			default:
				s.logger.Printf("received %v, asking the guest command to stop", sig)
			}
			if started && !reported {
				if err := stdin.stop(stopTag(nonce)); err != nil {
					s.logger.Printf("sending the stop request to the guest failed: %v; forwarding %v to the hypervisor", err, sig)
				} else {
					asked = true
				}
			}
			// The ports stay as the guest reports them while the guest
			// command drains, and close at once when the hypervisor gets the
			// signal, which may end it at once.
			if !asked {
				closePorts()
				forward(sig)
			}
			if kill == nil {
				kill = time.After(s.deadline)
				killReason = fmt.Sprintf("the guest did not stop within %v of the signal; killing the hypervisor", s.deadline)
			}
		case <-running:
			running = nil
			// The console input carries more than the stop request only
			// while the guest command runs and no signal has come, and
			// never for a guest whose console still echoes its input,
			// which would copy each pushed key into the command's output.
			// The filter set credOff in the write that closed running.
			if s.onConsole != nil && filter.credOff {
				s.logger.Println("the guest could not turn off its console's echo, so vm-launch pushes it no instance identity pairs; identity rotation is off for this guest")
			} else if s.onConsole != nil && !signalled && !isClosed(filter.exited) {
				s.onConsole(stdin)
			}
		case <-markerSeen:
			markerSeen = nil
			// After a stop request, the guest's status ends the drain.
			// Without one, the ports close when the guest ends, as they do
			// when the guest command ends of its own accord.
			if asked {
				closePorts()
			}
			if kill == nil {
				kill = time.After(s.grace)
				killReason = fmt.Sprintf("hypervisor still running %v later, killing it", s.grace)
			}
			if s.reported != nil {
				s.reported()
			}
		case <-kill:
			kill = nil
			s.logger.Print(killReason)
			closePorts()
			if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				s.logger.Printf("killing the hypervisor: %v", err)
			}
		case e := <-done:
			if e.copyErr != nil {
				s.logger.Printf("reading the guest console: %v", e.copyErr)
			}
			var exitErr *exec.ExitError
			if e.waitErr != nil && !errors.As(e.waitErr, &exitErr) {
				s.logger.Printf("waiting for the hypervisor: %v", e.waitErr)
			}
			filter.finish()
			// The queues drain side by side, so together they take no
			// longer than outputFlushTimeout.
			var flushed sync.WaitGroup
			if errOutput != nil {
				flushed.Add(1)
				go func() {
					defer flushed.Done()
					errOutput.close(outputFlushTimeout)
				}()
			}
			output.close(outputFlushTimeout)
			flushed.Wait()
			if err := output.err(); err != nil {
				s.logger.Printf("writing guest output: %v", err)
			}
			if errOutput != nil {
				if err := errOutput.err(); err != nil {
					s.logger.Printf("writing the guest's stderr output: %v", err)
				}
			}
			switch {
			case filter.started():
			case len(filter.bootLog) == 0:
				s.logger.Printf("guest never started its command and wrote no console output")
			default:
				s.logger.Printf("guest never started its command; last console output follows")
				if _, err := s.logger.Writer().Write(filter.bootLog); err != nil {
					s.logger.Printf("writing console output: %v", err)
				}
			}
			res.markerFound = filter.markerFound()
			res.guestStatus = filter.status
			res.guestOOMKills = filter.oomKills
			res.state = cmd.ProcessState
			return res, nil
		}
	}
}

// serialPipeSize is the size vm-launch asks for the serial console's pipe:
// what the guest may write while vm-launch is not scheduled before
// Firecracker, which drops what it cannot write at once, loses any of it.
const serialPipeSize = 1 << 20

// growPipe asks the kernel for a pipe of serialPipeSize behind f, and logs a
// refusal, after which the pipe keeps the size it has.
func growPipe(f *os.File, logger *log.Logger) {
	raw, err := f.SyscallConn()
	if err == nil {
		cerr := raw.Control(func(fd uintptr) {
			_, err = unix.FcntlInt(fd, unix.F_SETPIPE_SZ, serialPipeSize)
		})
		if cerr != nil {
			err = cerr
		}
	}
	if err != nil {
		logger.Printf("enlarging the serial console's pipe to %d bytes: %v", serialPipeSize, err)
	}
}

// isClosed reports whether ch, which is only ever closed, is closed.
func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// stopRequestTimeout bounds each write to the hypervisor's stdin, the stop
// request's and each chunk of an identity push's. Those writes are short and
// go into a pipe that only consoleWriter writes, so they do not block; the
// bound only keeps a hypervisor that never reads its stdin, with the pipe
// full, from holding up the supervisor.
const stopRequestTimeout = time.Second
