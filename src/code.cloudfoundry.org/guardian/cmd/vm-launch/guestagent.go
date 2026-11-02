//go:build linux

package main

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"golang.org/x/sys/unix"
)

// Where the initramfs holds the guest agent. The directory and both files
// belong to root and nobody else can read them, and the app root, where
// the app runs, does not reach them.
const (
	guestAgentDir    = "/rvm/agent"
	guestAgentBin    = guestAgentDir + "/vm-launch"
	guestAgentConfig = guestAgentDir + "/config"
	// guestAgentRunDir holds one directory for each session, with the
	// session's argv and environment files, while the session runs.
	guestAgentRunDir = guestAgentDir + "/run"
)

// guestAgentCommand is the first argument with which stage 2 starts
// vm-launch as the guest agent, and the second is the mode.
const guestAgentCommand = "guest-agent"

// The modes of the guest agent, one for each kind of guest. Each runs a
// session the way that guest runs its app (see newGuestAgent).
const (
	agentModeStack   = "stack"
	agentModeImage   = "image"
	agentModeBusybox = "busybox"
)

const (
	// guestAgentMaxSessions caps how many sessions and forwards the agent
	// runs at once.
	guestAgentMaxSessions = 32

	// guestAgentMaxPending caps how many connections may wait for their
	// hello at once. Any process on the cell can open a vsock connection to
	// a QEMU guest, so this is what keeps a flood of silent connections from
	// costing the guest more than a few goroutines.
	guestAgentMaxPending = 8

	// guestAgentHangupGrace is how long a session's processes get to end
	// after the hangup that follows a lost connection, before SIGKILL.
	guestAgentHangupGrace = 2 * time.Second

	// guestAgentOutputGrace is how long the agent keeps reading a session's
	// output once its process has exited, so that what the process wrote
	// last still reaches the client while a process it left behind cannot
	// hold the session open.
	guestAgentOutputGrace = 250 * time.Millisecond

	// guestAgentDialTimeout bounds a forward's connect in the guest.
	guestAgentDialTimeout = 10 * time.Second
)

// guestShells are the shells a session can run, in the order diego-sshd
// looks for them in a container. The agent runs the first that the guest's
// app root has.
var guestShells = []string{"/bin/bash", "/usr/local/bin/bash", "/bin/sh"}

// agentSignals are the signals a client may send a session's process. They
// are the signals the SSH protocol names.
var agentSignals = map[syscall.Signal]bool{
	syscall.SIGABRT: true, syscall.SIGALRM: true, syscall.SIGFPE: true, syscall.SIGHUP: true,
	syscall.SIGILL: true, syscall.SIGINT: true, syscall.SIGKILL: true, syscall.SIGPIPE: true,
	syscall.SIGQUIT: true, syscall.SIGSEGV: true, syscall.SIGTERM: true, syscall.SIGUSR1: true,
	syscall.SIGUSR2: true,
}

// guestAgentConfigFile is the agent's configuration in the initramfs: the
// boot's key, as hex, and, for the Docker image guest, the user that the
// image's processes run as.
type guestAgentConfigFile struct {
	Key string `json:"key"`
	UID uint32 `json:"uid,omitempty"`
	GID uint32 `json:"gid,omitempty"`
}

// guestAgent serves sessions and forwards in the guest.
type guestAgent struct {
	key []byte
	// root is where the agent looks for the session's shell, which is the
	// app root, or / in the busybox guest.
	root string
	// cwd is the session's working directory inside the root.
	cwd string
	// exec builds the line that runs a session in the root, as the guest
	// runs its app (see guestExec).
	exec guestExec
	// envPaths are the app's environment files, which the session sources
	// after its own, so the app's variables keep the guest's values.
	envPaths []string
	// uid and gid are the session's user, who gets the session's terminal.
	uid, gid int
	// shell runs a line as root, with -c and the line after it, in baseEnv.
	shell   []string
	baseEnv []string
	// prefix comes before every line. It sets the session's oom_score_adj
	// back to 0 from the agent's -1000, and the open-files limit, as the
	// run section does for the app.
	prefix string
	runDir string
	// ptmx and ptsDir are where the agent opens a terminal.
	ptmx, ptsDir string
	dial         func(network, address string, timeout time.Duration) (net.Conn, error)
	logger       *log.Logger

	sessions, pending chan struct{}
	seq               atomic.Uint64
}

// newGuestAgent returns the agent for mode with the key from its
// configuration file.
func newGuestAgent(mode string, cfg guestAgentConfigFile, logger *log.Logger) (*guestAgent, error) {
	key, err := hex.DecodeString(cfg.Key)
	if err != nil || len(key) != agentKeyBytes {
		return nil, errors.New("the guest agent's configuration holds no key of the right length")
	}
	a := &guestAgent{
		key:      []byte(cfg.Key),
		envPaths: []string{"/rvm/env"},
		shell:    []string{"/bin/busybox", "sh"},
		baseEnv:  []string{"PATH=/bin"},
		prefix:   "echo 0 >/proc/self/oom_score_adj && . /rvm/limits && " + guestSetLimits + " && ",
		runDir:   guestAgentRunDir,
		ptmx:     "/dev/pts/ptmx",
		ptsDir:   "/dev/pts",
		dial:     net.DialTimeout,
		logger:   logger,
		sessions: make(chan struct{}, guestAgentMaxSessions),
		pending:  make(chan struct{}, guestAgentMaxPending),
	}
	switch mode {
	case agentModeStack:
		// cf ssh lands in /home/vcap on runC, which in the stack guest
		// holds the droplet as it does there.
		a.root, a.cwd, a.exec, a.uid, a.gid = guestAppRoot, "/home/vcap", stackExec, 2000, 2000
	case agentModeImage:
		img := &guestImage{uid: cfg.UID, gid: cfg.GID}
		a.root, a.cwd, a.exec, a.uid, a.gid = guestAppRoot, "/", img.exec, int(cfg.UID), int(cfg.GID)
	case agentModeBusybox:
		a.root, a.cwd, a.exec = "/", "/", busyboxExec
	default:
		return nil, fmt.Errorf("the guest agent has no mode %q", mode)
	}
	return a, nil
}

// busyboxExec is the busybox guest's guestExec for a session, which runs
// as root in the initramfs, as that guest's command does.
func busyboxExec(p guestProcess) string {
	line := ""
	for _, env := range p.envPaths {
		line += ". " + env + " && "
	}
	return line + `eval "set -- $(` + guestRootCat + ` ` + p.argvPath + `)" && cd ` + shellQuote(p.dir) + ` && exec "$@"`
}

// runGuestAgent is vm-launch as the guest agent, which stage 2 starts in
// the background before the start tag. argv is the mode. The agent reads
// its configuration once and removes it, gives the guest and its app root a
// devpts for the sessions' terminals, and serves connections on agentPort
// until the guest stops. It writes to the console only when it cannot
// start.
func runGuestAgent(argv []string) int {
	logger := log.New(os.Stderr, "vm-launch guest agent: ", 0)
	if len(argv) != 1 {
		logger.Printf("usage: %s %s stack|image|busybox", guestAgentBin, guestAgentCommand)
		return exitLaunchError
	}
	cfg, err := readGuestAgentConfig(guestAgentConfig)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	a, err := newGuestAgent(argv[0], cfg, logger)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	appRoot := ""
	if a.root != "/" {
		appRoot = a.root
	}
	if err := mountGuestPTS(appRoot); err != nil {
		logger.Printf("%v; sessions that ask for a terminal will fail", err)
	}
	l, err := listenVsock(agentPort)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	if err := a.serve(l); err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	return 0
}

// readGuestAgentConfig reads the agent's configuration file and removes
// it, so the key stays only in the agent's memory.
func readGuestAgentConfig(path string) (guestAgentConfigFile, error) {
	var cfg guestAgentConfigFile
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("reading the guest agent's configuration: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return cfg, fmt.Errorf("removing the guest agent's configuration: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("decoding the guest agent's configuration: %w", err)
	}
	return cfg, nil
}

// mountGuestPTS mounts a devpts instance at /dev/pts and, when appRoot is
// set, binds it at /dev/pts in the app root, whose /dev is a bind of the
// guest's that does not see later mounts. Every terminal the agent opens is
// on this instance, so the session sees its terminal at the same path in
// the app root.
func mountGuestPTS(appRoot string) error {
	if err := os.MkdirAll("/dev/pts", 0o755); err != nil {
		return fmt.Errorf("creating /dev/pts: %w", err)
	}
	if err := unix.Mount("devpts", "/dev/pts", "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"); err != nil {
		return fmt.Errorf("mounting devpts at /dev/pts: %w", err)
	}
	if appRoot == "" {
		return nil
	}
	target := filepath.Join(appRoot, "dev/pts")
	if err := os.MkdirAll(target, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", target, err)
	}
	if err := unix.Mount("/dev/pts", target, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("binding /dev/pts at %s: %w", target, err)
	}
	return nil
}

// agentListener accepts the agent's connections.
type agentListener interface {
	Accept() (agentConn, error)
}

// vsockListener is a listening vsock socket. The standard library has no
// vsock support, so it accepts with the system call itself, and each
// connection becomes a non-blocking os.File, which the runtime's poller
// serves and which therefore takes read deadlines.
type vsockListener struct{ fd int }

// listenVsock listens on port for connections from the host.
func listenVsock(port uint32) (*vsockListener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening a vsock socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("binding vsock port %d: %w", port, err)
	}
	if err := unix.Listen(fd, guestAgentMaxPending); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("listening on vsock port %d: %w", port, err)
	}
	return &vsockListener{fd: fd}, nil
}

func (l *vsockListener) Accept() (agentConn, error) {
	for {
		nfd, _, err := unix.Accept4(l.fd, unix.SOCK_CLOEXEC)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.ECONNABORTED) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("accepting a vsock connection: %w", err)
		}
		if err := unix.SetNonblock(nfd, true); err != nil {
			unix.Close(nfd)
			continue
		}
		return os.NewFile(uintptr(nfd), "vsock"), nil
	}
}

// serve accepts connections until the listener fails, and handles each in
// its own goroutine.
func (a *guestAgent) serve(l agentListener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go a.handle(c)
	}
}

// handle serves one connection: the hello, the request, the go, and then
// the session or the forward. A connection that finds every hello slot
// taken is closed at once, before the agent reads a byte from it, and one
// whose hello does not hold the boot's key is closed without an answer.
// Every other refusal is an answer, which the relay never tries again.
func (a *guestAgent) handle(c agentConn) {
	defer c.Close()
	select {
	case a.pending <- struct{}{}:
	default:
		return
	}
	req, err := a.handshake(c)
	<-a.pending
	fw := &agentFrameWriter{w: c}
	refuse := func(format string, args ...any) {
		_ = fw.writeJSON(agentFrameReady, agentReady{Error: fmt.Sprintf(format, args...)})
	}
	var bad agentRequestError
	switch {
	case errors.As(err, &bad):
		refuse("%v", bad)
		return
	case err != nil:
		return
	}
	select {
	case a.sessions <- struct{}{}:
		defer func() { <-a.sessions }()
	default:
		refuse("the guest already runs %d sessions, which is as many as it allows", guestAgentMaxSessions)
		return
	}
	if req.Kind != agentKindSession && req.Kind != agentKindForward {
		refuse("the guest agent has no request of kind %q", req.Kind)
		return
	}
	if !a.awaitGo(c, fw) {
		return
	}
	if req.Kind == agentKindSession {
		a.session(c, fw, req)
	} else {
		a.forward(c, fw, req)
	}
}

// awaitGo tells the relay that the agent has accepted the request, and
// waits up to agentHelloTimeout for the relay's go. The relay never tries a
// request again once it has sent the go, and the agent starts nothing
// before it reads it, so a retry can never start a session or a forward a
// second time.
func (a *guestAgent) awaitGo(c agentConn, fw *agentFrameWriter) bool {
	if fw.write(agentFrameAccepted, nil) != nil {
		return false
	}
	if c.SetReadDeadline(time.Now().Add(agentHelloTimeout)) != nil {
		return false
	}
	if _, err := readAgentFrameOf(c, agentFrameGo); err != nil {
		return false
	}
	return c.SetReadDeadline(time.Time{}) == nil
}

// agentRequestError is a request that the agent could not read from a
// connection whose hello held the boot's key, which the agent answers.
type agentRequestError struct{ err error }

func (e agentRequestError) Error() string {
	return "the guest agent could not read the request: " + e.err.Error()
}

// handshake reads the hello and the request within agentHelloTimeout. The
// hello must be the first frame and hold the boot's key, and nothing else
// on the connection is read until it does, so a peer without the key can
// make the agent read at most agentMaxHello bytes. Once the key matches, a
// request the agent cannot read is an agentRequestError.
func (a *guestAgent) handshake(c agentConn) (agentRequest, error) {
	var req agentRequest
	if err := c.SetReadDeadline(time.Now().Add(agentHelloTimeout)); err != nil {
		return req, err
	}
	hello, err := readAgentFrameOf(c, agentFrameHello)
	if err != nil {
		return req, err
	}
	if subtle.ConstantTimeCompare(hello, a.key) != 1 {
		return req, errors.New("the hello does not hold the boot's key")
	}
	payload, err := readAgentFrameOf(c, agentFrameRequest)
	if err != nil {
		return req, agentRequestError{err}
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return req, agentRequestError{err}
	}
	return req, c.SetReadDeadline(time.Time{})
}

// readAgentFrameOf reads one frame that must be of type want, and refuses
// any other type before it reads the payload.
func readAgentFrameOf(r io.Reader, want byte) ([]byte, error) {
	var header [agentFrameHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if header[0] != want {
		return nil, fmt.Errorf("the guest agent expected a frame of type 0x%02x and got 0x%02x", want, header[0])
	}
	size := binary.BigEndian.Uint32(header[1:])
	if size > uint32(agentFrameLimit(want)) {
		return nil, fmt.Errorf("%w: type 0x%02x, %d bytes", errAgentFrameTooLarge, want, size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// findShell returns the first of guestShells that the root has as an
// executable file, resolving links inside the root, because the app's
// files are the app's and a link in them must not name a file in the
// initramfs.
func (a *guestAgent) findShell() (string, error) {
	for _, shell := range guestShells {
		p, err := securejoin.SecureJoin(a.root, shell)
		if err != nil {
			continue
		}
		info, err := os.Stat(p)
		if err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return shell, nil
		}
	}
	return "", fmt.Errorf("the guest has no shell to run the session: none of %s is an executable file", strings.Join(guestShells, ", "))
}

// agentSessionEnv is the session's own environment file, from the
// environment the shim was started with, as export lines. It leaves out
// the names that /rvm/env leaves out: names that are not shell
// identifiers, Garden's own, and the ones busybox sh sets for itself.
func agentSessionEnv(environ []string) string {
	var b strings.Builder
	for _, entry := range environ {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || !validEnvName(name) || strings.HasPrefix(name, guestEnvDeniedPrefix) || shellOwnedNames[name] {
			continue
		}
		b.WriteString("export " + name + "=" + shellQuote(value) + "\n")
	}
	return b.String()
}

// session runs the guest's shell with the request's arguments, on a
// terminal when the request asks for one and on pipes otherwise, and
// streams it to the client until it exits. A connection that ends first
// hangs the session up.
func (a *guestAgent) session(c agentConn, fw *agentFrameWriter, req agentRequest) {
	refuse := func(err error) { _ = fw.writeJSON(agentFrameReady, agentReady{Error: err.Error()}) }
	shell, err := a.findShell()
	if err != nil {
		refuse(err)
		return
	}
	dir, err := a.sessionFiles(append([]string{shell}, req.Args...), req.Env)
	if err != nil {
		refuse(err)
		return
	}
	defer os.RemoveAll(dir)
	p := guestProcess{
		argvPath: filepath.Join(dir, "argv"),
		envPaths: append([]string{filepath.Join(dir, "env")}, a.envPaths...),
		dir:      a.cwd,
	}
	args := append(append([]string(nil), a.shell[1:]...), "-c", a.prefix+a.exec(p))
	cmd := exec.Command(a.shell[0], args...)
	cmd.Env = a.baseEnv
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	var input *os.File
	var outputs []sessionOutput
	var resize func(rows, cols uint16)
	var childEnds []*os.File
	if req.TTY {
		master, slave, err := openGuestPTY(a.ptmx, a.ptsDir, a.uid, a.gid)
		if err != nil {
			refuse(err)
			return
		}
		defer master.Close()
		resize = func(rows, cols uint16) { _ = setWinsize(master, rows, cols) }
		resize(req.Rows, req.Cols)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		cmd.SysProcAttr.Setctty = true
		cmd.SysProcAttr.Ctty = 0
		input = master
		outputs = []sessionOutput{{file: master, stream: agentFrameStdout}}
		childEnds = []*os.File{slave}
	} else {
		pipes, err := sessionPipes()
		if err != nil {
			refuse(err)
			return
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = pipes[0], pipes[3], pipes[5]
		input = pipes[1]
		defer input.Close()
		outputs = []sessionOutput{{file: pipes[2], stream: agentFrameStdout}, {file: pipes[4], stream: agentFrameStderr}}
		for _, o := range outputs {
			defer o.file.Close()
		}
		childEnds = []*os.File{pipes[0], pipes[3], pipes[5]}
	}
	err = cmd.Start()
	for _, f := range childEnds {
		f.Close()
	}
	if err != nil {
		refuse(fmt.Errorf("starting the session in the guest: %w", err))
		return
	}
	pid := cmd.Process.Pid
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	if err := fw.writeJSON(agentFrameReady, agentReady{}); err != nil {
		endSession(pid, waited)
		return
	}

	var pumps sync.WaitGroup
	for _, o := range outputs {
		pumps.Add(1)
		go func(o sessionOutput) {
			defer pumps.Done()
			buf := make([]byte, agentMaxData)
			for {
				n, err := o.file.Read(buf)
				if n > 0 && fw.writeData(o.stream, buf[:n]) != nil {
					return
				}
				if err != nil {
					return
				}
			}
		}(o)
	}
	dropped := make(chan struct{})
	go func() {
		defer close(dropped)
		a.sessionInput(c, cmd.Process, input, req.TTY, resize)
	}()

	select {
	case <-waited:
	case <-dropped:
		// The client is gone, as when a terminal hangs up.
		endSession(pid, waited)
	}
	deadline := time.Now().Add(guestAgentOutputGrace)
	for _, o := range outputs {
		_ = o.file.SetReadDeadline(deadline)
	}
	pumps.Wait()
	_ = fw.writeJSON(agentFrameExit, exitOf(cmd.ProcessState))
}

// sessionOutput is one stream of a session's output and the frame type it
// goes out as.
type sessionOutput struct {
	file   *os.File
	stream byte
}

// sessionPipes returns three pipes as six files: the read and write ends
// of stdin, of stdout, and of stderr. Each read end is non-blocking, so a
// read deadline ends a pump that a process left behind holds open.
func sessionPipes() ([6]*os.File, error) {
	var files [6]*os.File
	for i := 0; i < 6; i += 2 {
		r, w, err := os.Pipe()
		if err != nil {
			for _, f := range files[:i] {
				f.Close()
			}
			return files, fmt.Errorf("creating the session's pipes: %w", err)
		}
		files[i], files[i+1] = r, w
	}
	return files, nil
}

// sessionInput passes the client's frames to the session until the
// connection ends: input, the end of input, signals for the process, and
// new terminal sizes. A frame of any other type ends the session as a lost
// connection would.
func (a *guestAgent) sessionInput(c io.Reader, proc *os.Process, input *os.File, tty bool, resize func(rows, cols uint16)) {
	inputOpen := true
	for {
		typ, payload, err := readAgentFrame(c)
		if err != nil {
			return
		}
		switch typ {
		case agentFrameStdin:
			if inputOpen {
				if _, err := input.Write(payload); err != nil {
					inputOpen = false
				}
			}
		case agentFrameStdinEnd:
			// A terminal has no end of input of its own; the shell reads
			// the end-of-file character that the user types.
			if !tty && inputOpen {
				input.Close()
				inputOpen = false
			}
		case agentFrameSignal:
			if len(payload) != 1 {
				return
			}
			if sig := syscall.Signal(payload[0]); agentSignals[sig] {
				_ = proc.Signal(sig)
			}
		case agentFrameResize:
			if len(payload) != 4 {
				return
			}
			if resize != nil {
				resize(binary.BigEndian.Uint16(payload[0:2]), binary.BigEndian.Uint16(payload[2:4]))
			}
		default:
			return
		}
	}
}

// hangUp sends SIGHUP to the process group that pid leads.
func hangUp(pid int) { _ = syscall.Kill(-pid, syscall.SIGHUP) }

// endSession hangs up the process group that pid leads and, if its process
// has not ended within guestAgentHangupGrace, kills the group. waited
// receives once the process has ended.
func endSession(pid int, waited <-chan error) {
	hangUp(pid)
	select {
	case <-waited:
	case <-time.After(guestAgentHangupGrace):
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		<-waited
	}
}

// exitOf is how the process of state ended.
func exitOf(state *os.ProcessState) agentExit {
	if state == nil {
		return agentExit{Code: exitLaunchError}
	}
	if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return agentExit{Code: 128 + int(ws.Signal()), Signal: int(ws.Signal())}
	}
	return agentExit{Code: state.ExitCode()}
}

// sessionFiles writes the session's argv and environment files, mode 0600,
// to a new directory below the agent's run directory, and returns it.
func (a *guestAgent) sessionFiles(argv, environ []string) (string, error) {
	if err := os.MkdirAll(a.runDir, 0o700); err != nil {
		return "", fmt.Errorf("creating %s: %w", a.runDir, err)
	}
	dir := filepath.Join(a.runDir, strconv.FormatUint(a.seq.Add(1), 10))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating %s: %w", dir, err)
	}
	for name, content := range map[string]string{"argv": shellJoin(argv), "env": agentSessionEnv(environ)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			os.RemoveAll(dir)
			return "", fmt.Errorf("writing the session's %s file: %w", name, err)
		}
	}
	return dir, nil
}

// openGuestPTY opens a new terminal on the devpts at ptsDir through ptmx,
// and gives its slave to uid and gid, as a login gives a user its
// terminal, so the session's user can open it again by name.
func openGuestPTY(ptmx, ptsDir string, uid, gid int) (master, slave *os.File, err error) {
	master, err = os.OpenFile(ptmx, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("opening a terminal at %s: %w", ptmx, err)
	}
	var n uint32
	var ioctlErr error
	ctlErr := control(master, func(fd int) {
		if ioctlErr = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); ioctlErr != nil {
			return
		}
		n, ioctlErr = unix.IoctlGetUint32(fd, unix.TIOCGPTN)
	})
	if err := errors.Join(ctlErr, ioctlErr); err != nil {
		master.Close()
		return nil, nil, fmt.Errorf("unlocking the terminal at %s: %w", ptmx, err)
	}
	name := filepath.Join(ptsDir, strconv.FormatUint(uint64(n), 10))
	slave, err = os.OpenFile(name, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, fmt.Errorf("opening the terminal %s: %w", name, err)
	}
	if err := slave.Chown(uid, gid); err != nil {
		master.Close()
		slave.Close()
		return nil, nil, fmt.Errorf("giving the terminal %s to %d:%d: %w", name, uid, gid, err)
	}
	return master, slave, nil
}

// setWinsize sets the terminal size of f.
func setWinsize(f *os.File, rows, cols uint16) error {
	var ioctlErr error
	err := control(f, func(fd int) {
		ioctlErr = unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols})
	})
	return errors.Join(err, ioctlErr)
}

// control runs fn with c's descriptor without making it blocking, which
// os.File's Fd would.
func control(c syscall.Conn, fn func(fd int)) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	return raw.Control(func(fd uintptr) { fn(int(fd)) })
}

// forward connects to the request's address in the guest and passes bytes
// both ways as data frames, with the end of each direction passed on
// separately, until both directions have ended.
func (a *guestAgent) forward(c agentConn, fw *agentFrameWriter, req agentRequest) {
	if req.Port < 1 || req.Port > 65535 {
		_ = fw.writeJSON(agentFrameReady, agentReady{Error: fmt.Sprintf("port %d is not a TCP port", req.Port)})
		return
	}
	host := req.Host
	if host == "" {
		host = "127.0.0.1"
	}
	target, err := a.dial("tcp", net.JoinHostPort(host, strconv.Itoa(req.Port)), guestAgentDialTimeout)
	if err != nil {
		_ = fw.writeJSON(agentFrameReady, agentReady{Error: fmt.Sprintf("connecting to %s port %d in the guest: %v", host, req.Port, err)})
		return
	}
	var closeOnce sync.Once
	abort := func() {
		closeOnce.Do(func() {
			target.Close()
			c.Close()
		})
	}
	defer abort()
	if err := fw.writeJSON(agentFrameReady, agentReady{}); err != nil {
		return
	}
	fromGuest := make(chan struct{})
	go func() {
		defer close(fromGuest)
		buf := make([]byte, agentMaxData)
		for {
			n, err := target.Read(buf)
			if n > 0 && fw.writeData(agentFrameData, buf[:n]) != nil {
				abort()
				return
			}
			if errors.Is(err, io.EOF) {
				if fw.write(agentFrameDataEnd, nil) != nil {
					abort()
				}
				return
			}
			if err != nil {
				abort()
				return
			}
		}
	}()
	if !forwardToGuest(c, target) {
		abort()
	}
	<-fromGuest
}

// forwardToGuest writes the client's data frames to target until the
// client ends its direction, and then ends target's write side. It reports
// whether the direction ended cleanly.
func forwardToGuest(c io.Reader, target net.Conn) bool {
	for {
		typ, payload, err := readAgentFrame(c)
		if err != nil {
			return false
		}
		switch typ {
		case agentFrameData:
			if _, err := target.Write(payload); err != nil {
				return false
			}
		case agentFrameDataEnd:
			if hc, ok := target.(halfCloser); ok {
				return hc.CloseWrite() == nil
			}
			return false
		default:
			return false
		}
	}
}
