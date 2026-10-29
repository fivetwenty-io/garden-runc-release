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
	"strconv"
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

// Guest shape. Every VM gets the same size.
const (
	guestVCPUs     = 1
	guestMemoryMiB = 128
)

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

// qemuArgv returns the QEMU command line. The microvm binary needs a newer
// glibc than the app rootfs has, so it runs through its bundled loader.
//
// With a network, the guest gets a virtio-net NIC on QEMU's user-mode
// network, and QEMU itself listens on the container's PORT and forwards each
// connection to the guest. That needs no privileges, and guest egress leaves
// from the container's network namespace, so application security groups
// still apply.
func qemuArgv(root, initrd string, nw *network) []string {
	art := func(rel string) string { return filepath.Join(root, rel) }
	argv := []string{
		art(artQEMULoader),
		"--library-path", art(artQEMULibDir),
		art(artQEMUBinary),
		"-L", art(artQEMUShareDir),
		"-M", "microvm,accel=kvm",
		"-cpu", "host",
		"-smp", strconv.Itoa(guestVCPUs),
		"-m", strconv.Itoa(guestMemoryMiB),
		"-nodefaults",
		"-no-user-config",
		"-nographic",
		"-serial", "stdio",
		"-no-reboot",
		"-kernel", art(artBzImage),
		"-initrd", initrd,
		"-append", qemuKernelArgs,
	}
	if nw == nil {
		return argv
	}
	port := strconv.Itoa(nw.port)
	return append(argv,
		"-netdev", "user,id=n0,net="+qemuNetwork+",hostfwd=tcp:0.0.0.0:"+port+"-"+qemuGuestIP+":"+port,
		"-device", "virtio-net-device,netdev=n0",
	)
}

type firecrackerConfig struct {
	BootSource        firecrackerBootSource         `json:"boot-source"`
	Drives            []struct{}                    `json:"drives"`
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

type firecrackerNetworkInterface struct {
	IfaceID     string `json:"iface_id"`
	GuestMAC    string `json:"guest_mac"`
	HostDevName string `json:"host_dev_name"`
}

// firecrackerConfigJSON returns the --config-file content: no drives, and a
// network interface on Garden's tap device only when there is a network.
func firecrackerConfigJSON(root, initrd string, nw *network) ([]byte, error) {
	cfg := firecrackerConfig{
		BootSource: firecrackerBootSource{
			KernelImagePath: filepath.Join(root, artVmlinux),
			InitrdPath:      initrd,
			BootArgs:        firecrackerKernelArgs,
		},
		Drives:        []struct{}{},
		MachineConfig: firecrackerMachineConfig{VCPUCount: guestVCPUs, MemSizeMiB: guestMemoryMiB},
	}
	if nw != nil {
		cfg.NetworkInterfaces = []firecrackerNetworkInterface{{IfaceID: "eth0", GuestMAC: fcGuestMAC, HostDevName: fcTapName}}
	}
	return json.Marshal(cfg)
}

func firecrackerArgv(root, configPath string) []string {
	return []string{filepath.Join(root, artFirecracker), "--no-api", "--config-file", configPath}
}

// hypervisorArgv returns the command line for kind, writing any config file
// it needs into workDir. workDir holds only data files; nothing runs from it.
func hypervisorArgv(kind backend.Kind, root, workDir, initrd string, nw *network) ([]string, error) {
	switch kind {
	case backend.VMQemu:
		return qemuArgv(root, initrd, nw), nil
	case backend.VMFirecracker:
		cfg, err := firecrackerConfigJSON(root, initrd, nw)
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
// and records the exit status. It never fails a Write, so the hypervisor's
// output keeps draining when the destination breaks; the first destination
// error is kept in writeErr.
type serialFilter struct {
	out      io.Writer
	startTag []byte
	exitTag  []byte

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
	f.emitPending(len(f.pending)-tagPrefixSuffix(f.pending, f.exitTag), false)
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
	// stopping, when set, runs once at the first signal, before it is
	// forwarded. vm-launch uses it to stop accepting guest connections.
	stopping func()
}

// run starts cmd and waits for it. The error is non-nil only when the
// hypervisor could not be started.
func (s supervisor) run(cmd *exec.Cmd, nonce string) (runResult, error) {
	filter := newSerialFilter(s.stdout, nonce)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return runResult{}, fmt.Errorf("creating serial pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return runResult{}, fmt.Errorf("starting hypervisor %s: %w", cmd.Path, err)
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
			if s.stopping != nil {
				s.stopping()
				s.stopping = nil
			}
			s.logger.Printf("received %v, forwarding it to the hypervisor", sig)
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
