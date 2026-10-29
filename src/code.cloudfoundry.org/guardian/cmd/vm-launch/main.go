//go:build linux

// Command vm-launch runs one shell command inside a short-lived QEMU microvm
// or Firecracker guest and makes the command's console output and exit status
// its own. Garden runs it inside the app's container in place of the CF
// launcher, with /dev/kvm and the read-only VM artifacts mounted in.
//
// Usage:
//
//	vm-launch --backend vm-qemu|vm-firecracker [--artifacts DIR] -- PATH [ARGS...]
//
// When PATH is the CF launcher ("launcher APP-DIR START-COMMAND ..."), the
// guest runs START-COMMAND. Otherwise it runs PATH and ARGS, shell-quoted.
// The guest has a busybox userland, no disk, and none of the app's files.
//
// Without PORT in the environment, as for a task, the guest has no network
// and none of the app's environment. With PORT, as for an LRP, the guest
// gets a NIC, a default route, and DNS, its command sees PORT and the
// instance's CF_INSTANCE_* and INSTANCE_* variables, and connections to PORT
// on the container reach PORT in the guest. QEMU forwards them itself
// (user-mode networking); for Firecracker, vm-launch listens on PORT and
// proxies each connection to the guest over Garden's tap device. The
// listener is up before the guest boots, and connections that arrive early
// wait for the guest app to listen. At the first SIGTERM or SIGINT the
// listener closes; open connections close when the guest stops.
//
// The guest's console output, stdout and stderr merged, is written to stdout
// as it arrives. Kernel boot messages and the status marker are dropped.
//
// Exit status:
//
//	0-255  the guest command's exit status
//	123    the hypervisor exited cleanly, but the guest never reported a status
//	124    the hypervisor failed: it exited non-zero before the guest reported a
//	       status, as QEMU does when PORT is already in use in the container
//	125    vm-launch could not start the guest: bad arguments, a missing
//	       artifact, a temp file it could not write, a hypervisor it could not
//	       run, or (Firecracker) PORT already in use in the container
//	128+N  vm-launch received signal N (SIGTERM or SIGINT), or the hypervisor
//	       died from signal N, before the guest reported a status
//
// A guest command can exit with any of these values itself; whenever vm-launch
// picks the status, it also writes a "vm-launch:" line to stderr.
//
// A container runs one VM per port: a second vm-launch for the same PORT, such
// as a CF sidecar that gets the app's PORT, cannot listen on it and fails as
// described above, with a line that names the port conflict.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
)

const (
	exitMissingMarker    = 123
	exitHypervisorFailed = 124
	exitLaunchError      = 125
)

const defaultArtifactsDir = "/opt/garden-vm/artifacts"

// killGrace is how long the hypervisor may keep running after a forwarded
// signal or after the guest reported its status. It is shorter than garden's
// 10 second stop timeout, so vm-launch still cleans up before it is killed.
const killGrace = 5 * time.Second

const usage = "usage: vm-launch --backend vm-qemu|vm-firecracker [--artifacts DIR] -- PATH [ARGS...]\n"

type config struct {
	backend   backend.Kind
	artifacts string
	command   string
}

func main() {
	logger := log.New(os.Stderr, "vm-launch: ", 0)
	os.Exit(run(os.Args[1:], logger))
}

func run(argv []string, logger *log.Logger) int {
	// The guest's output goes to stdout, which a dying reader can break. Go
	// kills a process whose write to fd 1 or 2 hits a broken pipe, unless SIGPIPE
	// is caught or ignored. Ignoring it turns that into an EPIPE error that the
	// serial filter keeps, so the guest keeps draining and the exit status
	// stays the guest's. The hypervisor inherits the setting; QEMU and
	// Firecracker both ignore SIGPIPE themselves.
	signal.Ignore(syscall.SIGPIPE)
	defer signal.Reset(syscall.SIGPIPE)

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)

	cfg, err := parseArgs(argv)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(logger.Writer(), usage)
		return 0
	}
	if err != nil {
		logger.Print(err)
		fmt.Fprint(logger.Writer(), usage)
		return exitLaunchError
	}
	if err := checkArtifacts(cfg.backend, cfg.artifacts); err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	nw, err := networkFor(cfg.backend, os.LookupEnv, containerResolvConf, interfaceMTU, logger)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}

	workDir, err := os.MkdirTemp("", "vm-launch-")
	if err != nil {
		logger.Printf("creating work dir: %v", err)
		return exitLaunchError
	}
	defer func() {
		if err := os.RemoveAll(workDir); err != nil {
			logger.Printf("removing work dir: %v", err)
		}
	}()

	nonce, err := newNonce()
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	initrd := filepath.Join(workDir, "initrd.cpio.gz")
	if err := writeInitramfs(initrd, filepath.Join(cfg.artifacts, artBusybox), cfg.command, nonce, nw); err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	hvArgv, err := hypervisorArgv(cfg.backend, cfg.artifacts, workDir, initrd, nw)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}

	select {
	case sig := <-sigs:
		logger.Printf("received %v before the guest started", sig)
		return 128 + signalNumber(sig)
	default:
	}

	cmd := exec.Command(hvArgv[0], hvArgv[1:]...)
	cmd.Env = []string{}
	cmd.Stderr = os.Stderr
	// QEMU reports a port it cannot forward on its stderr and exits 1, so a
	// networked QEMU run keeps the start of that stream to recognise it.
	var hvStderr *headBuffer
	if nw != nil && cfg.backend == backend.VMQemu {
		hvStderr = &headBuffer{limit: maxBootLog}
		cmd.Stderr = &stderrTee{capture: hvStderr, passthrough: os.Stderr}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}

	sup := supervisor{stdout: os.Stdout, logger: logger, signals: sigs, grace: killGrace}
	if nw != nil && cfg.backend == backend.VMFirecracker {
		proxy, err := startProxy(nw.listenAddr(), nw.upstream(), upstreamDialPolicy, logger)
		if err != nil {
			logger.Print(err)
			if errors.Is(err, syscall.EADDRINUSE) {
				logger.Print(portConflictMessage(nw.port))
			}
			return exitLaunchError
		}
		defer proxy.Close()
		sup.stopping = proxy.StopAccepting
	}
	res, err := sup.run(cmd, nonce)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	code, reason := exitCode(res)
	if reason != "" {
		logger.Printf("%s; exiting %d", reason, code)
	}
	if hvStderr != nil && code == exitHypervisorFailed && strings.Contains(hvStderr.String(), qemuHostfwdFailure) {
		logger.Print(portConflictMessage(nw.port))
	}
	return code
}

// qemuHostfwdFailure starts the error QEMU prints when it cannot bind a
// hostfwd rule's listening port.
const qemuHostfwdFailure = "Could not set up host forwarding rule"

// portConflictMessage explains a PORT that the guest cannot be given: only one
// VM per container can serve it.
func portConflictMessage(port int) string {
	return fmt.Sprintf("port %d already in use in this container; VM backends run one app process per container", port)
}

// stderrTee copies the hypervisor's stderr to a capture buffer and to a
// passthrough writer. The capture side sees every byte whether or not the
// passthrough works, and a failing passthrough never reaches the copy loop
// that feeds the tee: an error there would stop the capture and make Wait
// report the copy as a failure of the hypervisor run. Stderr cannot report
// its own breakage, so the passthrough error is dropped.
type stderrTee struct {
	capture     io.Writer
	passthrough io.Writer
}

func (t *stderrTee) Write(p []byte) (int, error) {
	_, _ = t.capture.Write(p)
	_, _ = t.passthrough.Write(p)
	return len(p), nil
}

// headBuffer keeps the first limit bytes written to it and drops the rest.
type headBuffer struct {
	limit int
	buf   []byte
}

func (b *headBuffer) Write(p []byte) (int, error) {
	if room := b.limit - len(b.buf); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		b.buf = append(b.buf, p[:room]...)
	}
	return len(p), nil
}

func (b *headBuffer) String() string { return string(b.buf) }

func parseArgs(argv []string) (config, error) {
	fs := flag.NewFlagSet("vm-launch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	kind := fs.String("backend", "", "VM backend: vm-qemu or vm-firecracker")
	artifacts := fs.String("artifacts", defaultArtifactsDir, "directory holding the kernel, hypervisor, and busybox")
	if err := fs.Parse(argv); err != nil {
		return config{}, err
	}

	cfg := config{backend: backend.Kind(*kind)}
	if _, err := requiredArtifacts(cfg.backend); err != nil {
		return config{}, err
	}
	if *artifacts == "" {
		return config{}, errors.New("--artifacts must not be empty")
	}
	abs, err := filepath.Abs(*artifacts)
	if err != nil {
		return config{}, fmt.Errorf("resolving --artifacts: %w", err)
	}
	cfg.artifacts = abs

	cfg.command, err = guestCommand(fs.Args())
	if err != nil {
		return config{}, err
	}
	return cfg, nil
}

// guestCommand returns the shell command the guest runs for the wrapped
// process argv.
func guestCommand(args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("no guest command given after --")
	}
	if filepath.Base(args[0]) != "launcher" {
		return shellJoin(args), nil
	}
	// The CF launcher takes APP-DIR START-COMMAND METADATA. An empty start
	// command means "use the droplet's detected one", which lives in the
	// droplet and is not available in the guest.
	if len(args) < 3 {
		return "", fmt.Errorf("launcher argv has %d arguments, want APP-DIR START-COMMAND [METADATA]", len(args)-1)
	}
	if strings.TrimSpace(args[2]) == "" {
		return "", errors.New("empty start command: VM backends need an explicit command because the droplet's detected start command is not available in the guest")
	}
	return args[2], nil
}

// shellJoin quotes each argument for POSIX sh and joins them with spaces.
func shellJoin(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = shellQuote(a)
	}
	return strings.Join(quoted, " ")
}

func newNonce() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating marker nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func signalNumber(sig os.Signal) int {
	if s, ok := sig.(syscall.Signal); ok {
		return int(s)
	}
	return int(syscall.SIGTERM)
}

// exitCode maps a guest run to vm-launch's exit status. reason is empty when
// the status is the guest command's own.
func exitCode(r runResult) (code int, reason string) {
	switch {
	case r.markerFound:
		return r.guestStatus, ""
	case r.received != 0:
		return 128 + int(r.received), fmt.Sprintf("stopped by %v before the guest reported a status", r.received)
	case r.state == nil:
		return exitHypervisorFailed, "hypervisor state unknown"
	}
	if ws, ok := r.state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), fmt.Sprintf("hypervisor died from %v before the guest reported a status", ws.Signal())
	}
	if r.state.ExitCode() != 0 {
		return exitHypervisorFailed, fmt.Sprintf("hypervisor failed with exit status %d before the guest reported a status", r.state.ExitCode())
	}
	return exitMissingMarker, "guest ended without reporting a status"
}
