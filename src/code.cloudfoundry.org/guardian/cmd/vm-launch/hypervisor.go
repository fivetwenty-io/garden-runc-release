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
// With a volume, drivePath names the volume image, and the guest gets it as
// its one virtio-blk drive. The format is pinned to raw, so QEMU never probes
// the guest-written image for a format header such as a qcow2 backing file.
// I/O errors, ENOSPC and EDQUOT included, reach the guest as errors instead
// of pausing the VM. QEMU's own image locking is off because vm-launch holds
// the flock that decides who writes the image.
func qemuArgv(root, initrd string, memMiB int, nw *network, drivePath string, monitorFD int) []string {
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
	if drivePath != "" {
		argv = append(argv,
			"-drive", "if=none,id="+volumeDriveID+",file="+drivePath+
				",format=raw,cache=writeback,aio=threads,file.locking=off,werror=report,rerror=report,discard=ignore",
			"-device", "virtio-blk-device,drive="+volumeDriveID,
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

// The hypervisor's inherited files. The hypervisor gets the volume image,
// when there is one, and the initramfs as extra files, and opens each through
// /proc/self/fd. For the image that reopens exactly the inode vm-launch
// checked, so the container path of the volume never reaches a QEMU option
// string or the Firecracker configuration. The image keeps file descriptor
// volumeDriveFD, and the initramfs takes the next one: 3 without a volume
// and 4 with one. A QEMU monitor socket, when there is one, comes last.
const (
	firstExtraFD  = 3
	volumeDriveFD = firstExtraFD
	volumeDriveID = "vol0"
)

// procSelfFD is the path a process opens its own file descriptor fd by.
func procSelfFD(fd int) string {
	return "/proc/self/fd/" + strconv.Itoa(fd)
}

// volumeDrivePath is the path the hypervisor opens the volume image by.
func volumeDrivePath() string {
	return procSelfFD(volumeDriveFD)
}

// hypervisorFiles returns the hypervisor's extra files in order, for
// exec.Cmd.ExtraFiles, with the paths the hypervisor opens them by. img is
// the volume image or nil, and drivePath is empty without one. initrd is the
// initramfs from newInitramfs. monitor is QEMU's end of the QMP socket or
// nil, and monitorFD is its file descriptor in the hypervisor, or 0 without
// one.
func hypervisorFiles(img, initrd, monitor *os.File) (files []*os.File, drivePath, initrdPath string, monitorFD int) {
	if img != nil {
		files = append(files, img)
		drivePath = procSelfFD(firstExtraFD + len(files) - 1)
	}
	files = append(files, initrd)
	initrdPath = procSelfFD(firstExtraFD + len(files) - 1)
	if monitor != nil {
		files = append(files, monitor)
		monitorFD = firstExtraFD + len(files) - 1
	}
	return files, drivePath, initrdPath, monitorFD
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
}

// Firecracker drive settings. Writeback passes guest flushes on to the
// image; the default, Unsafe, drops them. The Sync engine is the supported
// one. The volume is not the root device, so Firecracker adds no root= to
// the kernel command line; the guest boots from the initramfs.
const (
	fcDriveCacheType = "Writeback"
	fcDriveIOEngine  = "Sync"
)

type firecrackerNetworkInterface struct {
	IfaceID     string `json:"iface_id"`
	GuestMAC    string `json:"guest_mac"`
	HostDevName string `json:"host_dev_name"`
}

// firecrackerConfigJSON returns the --config-file content for a guest of
// memMiB MiB: a network interface on Garden's tap device, which Garden
// creates for every Firecracker container, with or without a port, and the
// volume image as the only drive when drivePath is set. nw must be set; the
// port does not change the configuration, because vm-launch itself, not
// Firecracker, forwards PORT.
func firecrackerConfigJSON(root, initrd string, memMiB int, nw *network, drivePath string) ([]byte, error) {
	cfg := firecrackerConfig{
		BootSource: firecrackerBootSource{
			KernelImagePath: filepath.Join(root, artVmlinux),
			InitrdPath:      initrd,
			BootArgs:        firecrackerKernelArgs,
		},
		Drives:        []firecrackerDrive{},
		MachineConfig: firecrackerMachineConfig{VCPUCount: guestVCPUs, MemSizeMiB: memMiB},
	}
	if drivePath != "" {
		cfg.Drives = []firecrackerDrive{{
			DriveID:      volumeDriveID,
			PathOnHost:   drivePath,
			IsRootDevice: false,
			IsReadOnly:   false,
			CacheType:    fcDriveCacheType,
			IOEngine:     fcDriveIOEngine,
		}}
	}
	cfg.NetworkInterfaces = []firecrackerNetworkInterface{{IfaceID: "eth0", GuestMAC: fcGuestMAC, HostDevName: fcTapName}}
	return json.Marshal(cfg)
}

func firecrackerArgv(root, configPath string) []string {
	return []string{filepath.Join(root, artFirecracker), "--no-api", "--config-file", configPath}
}

// hypervisorArgv returns the command line for kind, writing any config file
// it needs into workDir. workDir holds only data files; nothing runs from it.
// memMiB is the guest memory size from guestMemory, which keeps it between
// the floor and the ceiling. nw is the guest network, which run always
// builds, and drivePath is the volume image path the hypervisor opens, or
// empty without a volume. monitorFD is QEMU's QMP socket (see qemuArgv), or 0;
// Firecracker has no monitor.
func hypervisorArgv(kind backend.Kind, root, workDir, initrd string, memMiB int, nw *network, drivePath string, monitorFD int) ([]string, error) {
	switch kind {
	case backend.VMQemu:
		return qemuArgv(root, initrd, memMiB, nw, drivePath, monitorFD), nil
	case backend.VMFirecracker:
		if monitorFD != 0 {
			return nil, errors.New("firecracker has no QMP monitor")
		}
		cfg, err := firecrackerConfigJSON(root, initrd, memMiB, nw, drivePath)
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

// serialFilter turns the guest serial console into the guest command's
// output. It drops the console before the start tag and after the exit
// marker, swallows the marker, converts the console's CRLF line endings to LF,
// and records the exit status. With a listen callback, it also swallows each
// listen line the guest writes while the command runs (see
// guestListenWatch) and passes its state to the callback, which must not
// block. A listen line can follow command output that has no newline yet,
// so it is found anywhere in a line, and the output around it is kept as it
// was. It never fails a Write, so the hypervisor's output keeps draining
// when the destination breaks; the first destination error is kept in
// writeErr.
type serialFilter struct {
	out       io.Writer
	startTag  []byte
	exitTag   []byte
	listenTag []byte
	listen    func(up bool)

	phase    int
	pending  []byte
	bootLog  []byte
	status   int
	writeErr error

	// exited is closed when the exit marker is parsed.
	exited chan struct{}
}

func newSerialFilter(out io.Writer, nonce string) *serialFilter {
	return &serialFilter{
		out:      out,
		startTag: []byte(startTag(nonce)),
		exitTag:  []byte(exitTag(nonce)),
		exited:   make(chan struct{}),
	}
}

// onListen makes the filter pass listen lines to listen.
func (f *serialFilter) onListen(nonce string, listen func(up bool)) {
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
		if li := f.indexListen(); li >= 0 && (idx < 0 || li < idx) {
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
	hold := tagPrefixSuffix(f.pending, f.exitTag)
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
	up, n, ok, needMore := parseListen(f.pending[idx+len(f.listenTag):])
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
	f.listen(up)
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

// parseListen parses the bytes after a listen tag: 1 or 0, then LF or CRLF.
// n is the length of what it parsed. needMore reports that b ends before
// that can be decided.
func parseListen(b []byte) (up bool, n int, ok, needMore bool) {
	switch {
	case len(b) == 0:
		return false, 0, false, true
	case b[0] != '0' && b[0] != '1':
		return false, 0, false, false
	case len(b) == 1:
		return false, 0, false, true
	case b[1] == '\n':
		return b[0] == '1', 2, true, false
	case b[1] != '\r':
		return false, 0, false, false
	case len(b) == 2:
		return false, 0, false, true
	case b[2] == '\n':
		return b[0] == '1', 3, true, false
	default:
		return false, 0, false, false
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
	// received is the first forwarded signal, or 0.
	received syscall.Signal
	// state is the hypervisor's reaped state.
	state *os.ProcessState
}

// supervisor runs one hypervisor process: it streams the serial console
// through a serialFilter, forwards signals, and kills the hypervisor when it
// outlives grace after a forwarded signal or after the guest reported its
// status (a guest that hangs on its way down must not hang the app process).
type supervisor struct {
	stdout  io.Writer
	logger  *log.Logger
	signals <-chan os.Signal
	grace   time.Duration
	// stopping, when set, runs once at the first signal, after the signal
	// is logged and before it is forwarded, so what stopping logs comes
	// after the signal's line. vm-launch uses it to stop accepting guest
	// connections.
	stopping func()
	// started, when set, runs once the hypervisor has started and before
	// anything else. vm-launch uses it to close its copies of the files the
	// hypervisor inherited.
	started func()
	// listen, when set, gets the guest's listen lines (see serialFilter). It
	// must not block.
	listen func(up bool)
}

// run starts cmd and waits for it. The error is non-nil only when the
// hypervisor could not be started.
func (s supervisor) run(cmd *exec.Cmd, nonce string) (runResult, error) {
	filter := newSerialFilter(s.stdout, nonce)
	if s.listen != nil {
		filter.onListen(nonce, s.listen)
	}
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return runResult{}, fmt.Errorf("creating serial pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return runResult{}, fmt.Errorf("starting hypervisor %s: %w", cmd.Path, err)
	}
	if s.started != nil {
		s.started()
	}

	type ended struct{ copyErr, waitErr error }
	done := make(chan ended, 1)
	go func() {
		_, copyErr := io.Copy(filter, pipe)
		done <- ended{copyErr: copyErr, waitErr: cmd.Wait()}
	}()

	var res runResult
	markerSeen := filter.exited
	var kill <-chan time.Time
	for {
		select {
		case sig := <-s.signals:
			if ss, ok := sig.(syscall.Signal); ok && res.received == 0 {
				res.received = ss
			}
			s.logger.Printf("received %v, forwarding it to the hypervisor", sig)
			if s.stopping != nil {
				s.stopping()
				s.stopping = nil
			}
			if err := cmd.Process.Signal(sig); err != nil && !errors.Is(err, os.ErrProcessDone) {
				s.logger.Printf("forwarding %v to the hypervisor: %v", sig, err)
			}
			if kill == nil {
				kill = time.After(s.grace)
			}
		case <-markerSeen:
			markerSeen = nil
			if kill == nil {
				kill = time.After(s.grace)
			}
		case <-kill:
			kill = nil
			s.logger.Printf("hypervisor still running %v later, killing it", s.grace)
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
			if filter.writeErr != nil {
				s.logger.Printf("writing guest output: %v", filter.writeErr)
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
			res.state = cmd.ProcessState
			return res, nil
		}
	}
}
