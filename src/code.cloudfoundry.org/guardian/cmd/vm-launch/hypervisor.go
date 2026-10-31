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
// drivePaths names the volume images in volume order, and the guest gets
// each one as a virtio-blk drive, volumeDriveID(i) for the image at index i,
// after the NIC and in the same order. Each drive's device carries the serial
// qemuVolumeSerial(i), which the guest reads as the drive's identity (see
// newGuestDrives). The format is pinned to raw, so QEMU
// never probes the guest-written image for a format header such as a qcow2
// backing file. I/O errors, ENOSPC and EDQUOT included, reach the guest as
// errors instead of pausing the VM. QEMU's own image locking is off because
// vm-launch holds the flock that decides who writes the image.
func qemuArgv(root, initrd string, memMiB int, nw *network, drivePaths []string, monitorFD int) []string {
	art := func(rel string) string { return filepath.Join(root, rel) }
	argv := []string{
		art(artQEMULoader),
		"--library-path", art(artQEMULibDir),
		art(artQEMUBinary),
		"-L", art(artQEMUShareDir),
		"-M", qemuMachine,
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
	for i, drivePath := range drivePaths {
		id := volumeDriveID(i)
		argv = append(argv,
			"-drive", "if=none,id="+id+",file="+drivePath+
				",format=raw,cache=writeback,aio=threads,file.locking=off,werror=report,rerror=report,discard=ignore",
			"-device", "virtio-blk-device,drive="+id+",serial="+qemuVolumeSerial(i),
		)
	}
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

// The hypervisor's inherited files. The hypervisor gets the volume images,
// one for each volume, the initramfs, a QEMU monitor socket, when there is
// one, and the guest root image, when there is one, as extra files, and opens
// each through /proc/self/fd. For a volume image that reopens exactly the
// inode vm-launch checked, so the container path of the volume never reaches
// a QEMU option string or the Firecracker configuration. The root image has
// no path at all, because vm-launch unlinks it when it creates it. The volume
// images take file descriptors from firstVolumeFD on, in volume order, so
// that the first one keeps 3, and the initramfs takes the next one: 3
// without a volume, 4 with one, and 7 with four. The monitor takes the one
// after that, and the root image comes last, so that adding it moves no
// other file: 4 without a volume or a monitor, and 6 with one volume and a
// monitor.
const (
	firstExtraFD  = 3
	firstVolumeFD = firstExtraFD
	rootDriveID   = "root0"
)

// volumeDriveID names the drive of the volume at index i in volume order,
// on QEMU and on Firecracker alike: vol0 for the first.
func volumeDriveID(i int) string {
	return "vol" + strconv.Itoa(i)
}

// procSelfFD is the path a process opens its own file descriptor fd by.
func procSelfFD(fd int) string {
	return "/proc/self/fd/" + strconv.Itoa(fd)
}

// volumeDrivePath is the path the hypervisor opens the volume image at index
// i in volume order by.
func volumeDrivePath(i int) string {
	return procSelfFD(firstVolumeFD + i)
}

// hypervisorFiles returns the hypervisor's extra files in order, for
// exec.Cmd.ExtraFiles, with the paths the hypervisor opens them by. imgs are
// the volume images in volume order, and drivePaths holds the path of each,
// in the same order, or nothing without a volume. initrd is the initramfs
// from newInitramfs. monitor is QEMU's end of the QMP socket or nil, and
// monitorFD is its file descriptor in the hypervisor, or 0 without one. root
// is the guest root image from createRootImage or nil, and rootPath is empty
// without one.
func hypervisorFiles(imgs []*os.File, initrd, monitor, root *os.File) (files []*os.File, drivePaths []string, initrdPath string, monitorFD int, rootPath string) {
	for _, img := range imgs {
		files = append(files, img)
		drivePaths = append(drivePaths, procSelfFD(firstExtraFD+len(files)-1))
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
	return files, drivePaths, initrdPath, monitorFD, rootPath
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
// without a port, a drive for each volume image in drivePaths, in volume
// order and named as on QEMU, and the guest root image as a drive after them
// when rootPath is set. Firecracker takes no serial, and the identity it
// gives each drive comes from the file it opens, which newGuestDrives
// predicts. nw must be set; the port does not change the
// configuration, because vm-launch itself, not Firecracker, forwards PORT.
func newFirecrackerConfig(root, initrd string, memMiB int, nw *network, drivePaths []string, rootPath string) firecrackerConfig {
	cfg := firecrackerConfig{
		BootSource: firecrackerBootSource{
			KernelImagePath: filepath.Join(root, artVmlinux),
			InitrdPath:      initrd,
			BootArgs:        firecrackerKernelArgs,
		},
		Drives:        []firecrackerDrive{},
		MachineConfig: firecrackerMachineConfig{VCPUCount: guestVCPUs, MemSizeMiB: memMiB},
	}
	for i, drivePath := range drivePaths {
		cfg.Drives = append(cfg.Drives, firecrackerDrive{
			DriveID:      volumeDriveID(i),
			PathOnHost:   drivePath,
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
	cfg.NetworkInterfaces = []firecrackerNetworkInterface{{IfaceID: "eth0", GuestMAC: fcGuestMAC, HostDevName: fcTapName}}
	return cfg
}

func firecrackerArgv(root, configPath string) []string {
	return []string{filepath.Join(root, artFirecracker), "--no-api", "--config-file", configPath}
}

// hypervisorArgv returns the command line for kind, writing any config file
// it needs into workDir. workDir holds only data files; nothing runs from it.
// memMiB is the guest memory size from guestMemory, which keeps it between
// the floor and the ceiling. nw is the guest network, which run always
// builds, and drivePaths are the paths the hypervisor opens the volume
// images by, in volume order, or none without a volume; more than maxVolumes
// of them, or an empty one, is an error. rootPath is the path of the guest
// root image, or empty when the guest root stays in RAM; that drive comes
// after the volumes' on both backends. monitorFD is QEMU's QMP socket (see
// qemuArgv), or 0; Firecracker has no monitor.
func hypervisorArgv(kind backend.Kind, root, workDir, initrd string, memMiB int, nw *network, drivePaths []string, rootPath string, monitorFD int) ([]string, error) {
	if len(drivePaths) > maxVolumes {
		return nil, fmt.Errorf("%d volume drives, over the %d a guest can have", len(drivePaths), maxVolumes)
	}
	for i, p := range drivePaths {
		if p == "" {
			return nil, fmt.Errorf("volume drive %s has no path", volumeDriveID(i))
		}
	}
	switch kind {
	case backend.VMQemu:
		argv := qemuArgv(root, initrd, memMiB, nw, drivePaths, monitorFD)
		if rootPath != "" {
			argv = append(argv, qemuRootDrive(rootPath)...)
		}
		return argv, nil
	case backend.VMFirecracker:
		if monitorFD != 0 {
			return nil, errors.New("firecracker has no QMP monitor")
		}
		cfg, err := json.Marshal(newFirecrackerConfig(root, initrd, memMiB, nw, drivePaths, rootPath))
		if err != nil {
			return nil, fmt.Errorf("encoding firecracker config: %w", err)
		}
		cfgPath := filepath.Join(workDir, "fc.json")
		if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
			return nil, fmt.Errorf("writing firecracker config: %w", err)
		}
		return firecrackerArgv(root, cfgPath), nil
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

// maxOOMDigits is the most digits an OOM count may have, which keeps the
// count far inside an int.
const maxOOMDigits = 9

// serialFilter turns the guest serial console into the guest command's
// output. It drops the console before the start tag and after the exit
// marker, swallows the marker, converts the console's CRLF line endings to LF,
// and records the exit status. With a listen callback, it also swallows each
// listen line the guest writes while the command runs (see
// guestListenWatch) and passes its state to the callback, which must not
// block. It swallows the guest's OOM line too (see guestOOMReport) and keeps
// its count in oomKills. A listen or OOM line can follow command output that
// has no newline yet, so each is found anywhere in a line, and the output
// around it is kept as it was. It never fails a Write, so the hypervisor's output keeps draining
// when the destination breaks; the first destination error is kept in
// writeErr.
type serialFilter struct {
	out       io.Writer
	startTag  []byte
	exitTag   []byte
	listenTag []byte
	oomTag    []byte
	listen    func(port int, up bool)

	phase    int
	pending  []byte
	bootLog  []byte
	status   int
	oomKills int
	writeErr error

	// startSeen is closed when the start tag is parsed, before any of the
	// command's output is written.
	startSeen chan struct{}
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
		exited:    make(chan struct{}),
	}
}

// onListen makes the filter pass listen lines to listen.
func (f *serialFilter) onListen(nonce string, listen func(port int, up bool)) {
	f.listenTag = []byte(listenTag(nonce))
	f.listen = listen
}

func (f *serialFilter) Write(p []byte) (int, error) {
	if f.phase == phaseDone {
		return len(p), nil
	}
	f.pending = append(f.pending, p...)
	f.process(false)
	return len(p), nil
}

// finish flushes held bytes at end of stream. A marker without its line
// terminator may be truncated, so it counts as output, not as a status.
func (f *serialFilter) finish() {
	if f.phase != phaseDone {
		f.process(true)
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
			f.bootLog = nil
			close(f.startSeen)
			return
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
		idx := bytes.Index(f.pending, f.exitTag)
		li := f.indexListen()
		if oi := bytes.Index(f.pending, f.oomTag); oi >= 0 && (idx < 0 || oi < idx) && (li < 0 || oi < li) {
			if !f.processOOM(oi, eof) {
				return
			}
			continue
		}
		if li >= 0 && (idx < 0 || li < idx) {
			if !f.processListen(li, eof) {
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
	hold := max(tagPrefixSuffix(f.pending, f.exitTag), tagPrefixSuffix(f.pending, f.oomTag))
	if f.listenTag != nil {
		hold = max(hold, tagPrefixSuffix(f.pending, f.listenTag))
	}
	f.emitPending(len(f.pending)-hold, false)
}

// indexListen returns the index of the first listen tag in pending, or -1.
func (f *serialFilter) indexListen() int {
	if f.listenTag == nil {
		return -1
	}
	return bytes.Index(f.pending, f.listenTag)
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
		// The tag ends in its only '=', and neither tag can start inside
		// it, so scanning resumes right after it.
		f.emitPending(idx+len(f.listenTag), true)
		return true
	}
	f.emitPending(idx, true)
	f.pending = append([]byte(nil), f.pending[len(f.listenTag)+n:]...)
	f.listen(port, up)
	return true
}

// processOOM handles the OOM tag at pending[idx:] as processListen handles a
// listen tag: a complete line leaves the output and sets oomKills, and
// anything else after the tag is output.
func (f *serialFilter) processOOM(idx int, eof bool) bool {
	kills, n, ok, needMore := parseCount(f.pending[idx+len(f.oomTag):])
	if needMore && !eof {
		f.emitPending(idx, false)
		return false
	}
	if !ok {
		// The tag ends in its only '=', so no tag can start inside it.
		f.emitPending(idx+len(f.oomTag), true)
		return true
	}
	f.emitPending(idx, true)
	f.pending = append([]byte(nil), f.pending[len(f.oomTag)+n:]...)
	f.oomKills = kills
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

// parseCount parses the bytes after an OOM tag: 1 to maxOOMDigits decimal
// digits, then LF or CRLF. n is the length of what it parsed. needMore
// reports that b ends before that can be decided.
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
// command's output on to stdout through an outputQueue, stops the guest
// command or forwards signals, and kills the hypervisor when it outlives
// deadline after the first signal, or grace after the guest reported its
// status without a signal (a guest that hangs on its way down must not hang
// the app process).
//
// The supervisor acts on the first signal according to what the guest has
// reported so far. While the guest's command runs, after the start tag and
// before the exit marker, the supervisor writes the stop request (see
// stopTag) once to the hypervisor's stdin, which is the guest's serial
// console, and does not forward the signal. The guest's stop reader then
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
	stdout  io.Writer
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
	// listen, when set, gets the guest's listen lines (see serialFilter). It
	// must not block.
	listen func(port int, up bool)
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
	defer consoleIn.Close()
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
	if s.listen != nil {
		filter.onListen(nonce, s.listen)
	}
	type ended struct{ copyErr, waitErr error }
	done := make(chan ended, 1)
	go func() {
		// The filter writes to the queue, which never blocks, so this reads
		// the console as fast as the guest writes it.
		_, copyErr := io.Copy(filter, serial)
		done <- ended{copyErr: copyErr, waitErr: cmd.Wait()}
	}()

	var res runResult
	markerSeen := filter.exited
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
				if err := requestStop(consoleIn, nonce); err != nil {
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
			output.close(outputFlushTimeout)
			if err := output.err(); err != nil {
				s.logger.Printf("writing guest output: %v", err)
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

// stopRequestTimeout bounds the write of the stop request. The request is
// one short write into a pipe that nothing else writes, so it does not
// block; the bound only keeps a hypervisor that never reads its stdin, with
// the pipe full, from holding up the supervisor.
const stopRequestTimeout = time.Second

// requestStop writes the stop request (see stopTag), one line, to the
// hypervisor's stdin w.
func requestStop(w *os.File, nonce string) error {
	if err := w.SetWriteDeadline(time.Now().Add(stopRequestTimeout)); err != nil && !errors.Is(err, os.ErrNoDeadline) {
		return err
	}
	_, err := w.WriteString(stopTag(nonce) + "\n")
	return err
}
