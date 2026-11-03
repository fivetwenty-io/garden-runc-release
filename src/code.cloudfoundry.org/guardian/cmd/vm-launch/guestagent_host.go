//go:build linux

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"code.cloudfoundry.org/guardian/backend"
	"golang.org/x/sys/unix"
)

// guestAgentFlag names the vm-launch flag that turns the guest agent on.
// It is off by default, and Garden passes it only when the operator turns
// the agent on with a job property, which also makes Garden bind vm-launch
// over /bin/bash in the container and give a vm-qemu container
// /dev/vhost-vsock.
const guestAgentFlag = "guest-agent"

const (
	// vhostVsockDevice is the device on which vm-launch reserves a QEMU
	// guest's vsock address.
	vhostVsockDevice = "/dev/vhost-vsock"

	// vhostVsockSetGuestCID is VHOST_VSOCK_SET_GUEST_CID, _IOW(0xAF, 0x60,
	// __u64), which gives the device's guest its address. The kernel
	// refuses an address another guest on the host holds, so the ioctl is
	// the reservation.
	vhostVsockSetGuestCID = 0x4008af60

	// vsockFirstGuestCID and vsockLastGuestCID bound the addresses a guest
	// may have. 0 to 2 belong to the hypervisor, the local loopback, and
	// the host, and 0xFFFFFFFF is VMADDR_CID_ANY.
	vsockFirstGuestCID = 3
	vsockLastGuestCID  = 0xfffffffe

	// vsockCIDAttempts is how many random addresses vm-launch tries before
	// it gives up on a reservation.
	vsockCIDAttempts = 64

	// firecrackerGuestCID is the address of every Firecracker guest. Its
	// vsock device is a Unix socket on the host, so the address is never
	// shared with anything else on the cell.
	firecrackerGuestCID = 3

	// firecrackerVsockName is the name of that Unix socket in the work
	// directory.
	firecrackerVsockName = "agent.vsock"

	// agentDialTimeout bounds one connect to the agent.
	agentDialTimeout = 2 * time.Second

	// agentBootWait is how long the relay keeps trying to reach the agent
	// for one client and still lets it start the request, which covers a
	// guest that is still booting when the first cf ssh arrives.
	agentBootWait = 30 * time.Second

	// agentRelayWait is how long the relay waits for the agent for one
	// client in all, which leaves a request the agent accepts at the end
	// of agentBootWait a whole agentTryRead to start.
	agentRelayWait = agentBootWait + agentTryRead

	// agentDialRetry is how long the relay waits between two tries.
	agentDialRetry = 250 * time.Millisecond

	// agentMaxLine is the most bytes the relay's first line may have.
	agentMaxLine = 512

	// agentRelayPing is the line that asks the relay only whether this
	// guest has an agent. diego-sshd sends it before it serves scp, sftp,
	// or a forward through the guest, and serves them in the container as
	// before on any other answer.
	agentRelayPing = "ping"
)

// guestAgentBinary is the agent's binary that goes into the initramfs,
// which is vm-launch itself. Specs replace it with a build for the guest's
// architecture.
var guestAgentBinary = "/proc/self/exe"

// hostAgent is vm-launch's side of the guest agent for one launch: the
// boot's key, the vsock device the hypervisor gets, and the relay that
// clients in the container reach the agent through.
type hostAgent struct {
	key string
	// vhost and cid are QEMU's reserved vsock device and its guest's
	// address. vhost is nil once the hypervisor has its own copy.
	vhost *os.File
	cid   uint32
	// udsPath is Firecracker's vsock socket.
	udsPath string
	// off says why this launch's guest has no agent, or is empty.
	off   string
	relay *agentRelay
	bin   *os.File
}

// newHostAgent sets up the agent for a launch on kind with workDir as its
// work directory. A launch whose cell cannot give the guest a vsock device
// still runs, without the agent, and the relay tells every client why. Only
// a launch that cannot draw a key or cannot listen for clients fails.
func newHostAgent(kind backend.Kind, workDir, socket string, logger *log.Logger) (*hostAgent, error) {
	raw := make([]byte, agentKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("drawing the guest agent's key: %w", err)
	}
	a := &hostAgent{key: hex.EncodeToString(raw)}
	var dial func() (agentConn, error)
	switch kind {
	case backend.VMQemu:
		vhost, cid, err := reserveVsockCID(vhostVsockDevice)
		if err != nil {
			a.off = fmt.Sprintf("this guest has no agent for cf ssh, because %v", err)
			break
		}
		a.vhost, a.cid = vhost, cid
		dial = func() (agentConn, error) { return dialVsock(cid, agentPort, agentDialTimeout) }
	case backend.VMFirecracker:
		a.udsPath = filepath.Join(workDir, firecrackerVsockName)
		dial = func() (agentConn, error) { return dialFirecrackerVsock(a.udsPath, agentPort, agentDialTimeout) }
	default:
		return nil, fmt.Errorf("the guest agent does not support backend %q", kind)
	}
	if a.off == "" {
		bin, err := os.Open(guestAgentBinary)
		if err != nil {
			a.closeDevice()
			a.off = fmt.Sprintf("this guest has no agent for cf ssh, because opening %s failed: %v", guestAgentBinary, err)
			dial = nil
		} else {
			a.bin = bin
		}
	}
	if a.off != "" {
		logger.Print(a.off)
	}
	relay, err := newAgentRelay(socket, []byte(a.key), dial, a.off, agentRelayWait, logger)
	if err != nil {
		a.close()
		return nil, err
	}
	a.relay = relay
	return a, nil
}

// inGuest reports whether this launch's guest gets the agent.
func (a *hostAgent) inGuest() bool { return a != nil && a.bin != nil }

// guestFiles returns what the initramfs needs for the agent of the guest
// that stack describes, a nil stack being the busybox guest, or nil when
// this launch's guest has no agent.
func (a *hostAgent) guestFiles(stack *guestStack) (*guestAgentFiles, error) {
	if !a.inGuest() {
		return nil, nil
	}
	info, err := a.bin.Stat()
	if err != nil {
		return nil, fmt.Errorf("reading the size of the guest agent's binary: %w", err)
	}
	cfg := guestAgentConfigFile{Key: a.key}
	mode := agentModeBusybox
	if stack != nil {
		mode = agentModeStack
		if stack.image != nil {
			mode = agentModeImage
			cfg.UID, cfg.GID = stack.image.uid, stack.image.gid
		}
	}
	config, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	return &guestAgentFiles{bin: guestTool{name: "the guest agent", file: a.bin, size: info.Size()}, config: string(config), mode: mode}, nil
}

// hypervisor gives the hypervisor the guest's vsock device. On QEMU it
// adds the reserved device as the next of files and the -device option that
// names it, after every other device, so that no other device's slot
// moves. On Firecracker it adds the vsock section to the configuration file
// in workDir. A launch without the agent is unchanged.
func (a *hostAgent) hypervisor(kind backend.Kind, workDir string, files []*os.File, argv []string) ([]*os.File, []string, error) {
	if !a.inGuest() {
		return files, argv, nil
	}
	switch kind {
	case backend.VMQemu:
		fd := firstExtraFD + len(files)
		return append(files, a.vhost), append(argv, "-device", fmt.Sprintf("vhost-vsock-device,guest-cid=%d,vhostfd=%d", a.cid, fd)), nil
	case backend.VMFirecracker:
		return files, argv, withFirecrackerVsock(filepath.Join(workDir, "fc.json"), a.udsPath)
	}
	return files, argv, nil
}

// closeDevice closes vm-launch's copy of QEMU's vsock device, which the
// hypervisor keeps its own of once it has started. The guest's address
// stays reserved while any copy is open.
func (a *hostAgent) closeDevice() {
	if a != nil && a.vhost != nil {
		a.vhost.Close()
		a.vhost = nil
	}
}

// close stops the relay and closes everything the agent holds.
func (a *hostAgent) close() {
	if a == nil {
		return
	}
	a.closeDevice()
	if a.bin != nil {
		a.bin.Close()
		a.bin = nil
	}
	if a.relay != nil {
		a.relay.close()
	}
}

// guestAgentFiles is the agent's part of the initramfs: its binary, its
// configuration, and the mode stage 2 starts it in.
type guestAgentFiles struct {
	bin    guestTool
	config string
	mode   string
}

// reserveVsockCID opens device and gives its guest a random free address.
func reserveVsockCID(device string) (*os.File, uint32, error) {
	f, err := os.OpenFile(device, os.O_RDWR, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("opening %s failed: %w", device, err)
	}
	var buf [4]byte
	for range vsockCIDAttempts {
		if _, err := rand.Read(buf[:]); err != nil {
			f.Close()
			return nil, 0, fmt.Errorf("drawing a vsock address failed: %w", err)
		}
		cid := vsockFirstGuestCID + binary.BigEndian.Uint32(buf[:])%(vsockLastGuestCID-vsockFirstGuestCID)
		err := setVsockGuestCID(f, cid)
		if err == nil {
			return f, cid, nil
		}
		if !errors.Is(err, unix.EADDRINUSE) {
			f.Close()
			return nil, 0, fmt.Errorf("reserving a vsock address on %s failed: %w", device, err)
		}
	}
	f.Close()
	return nil, 0, fmt.Errorf("every one of %d random vsock addresses was in use", vsockCIDAttempts)
}

// setVsockGuestCID gives the guest of the vhost-vsock device f the address
// cid, and fails with EADDRINUSE when another guest on the host has it.
// Specs replace it.
var setVsockGuestCID = func(f *os.File, cid uint32) error {
	value := uint64(cid)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), vhostVsockSetGuestCID, uintptr(unsafe.Pointer(&value))); errno != 0 {
		return errno
	}
	return nil
}

// dialVsock connects to port on the guest at cid within timeout. The
// connect is non-blocking, because a blocking one that a signal interrupts
// cannot be retried, and the socket becomes a non-blocking os.File, which
// takes read deadlines.
func dialVsock(cid, port uint32, timeout time.Duration) (agentConn, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("opening a vsock socket: %w", err)
	}
	err = unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: port})
	if errors.Is(err, unix.EINPROGRESS) {
		err = awaitConnect(fd, timeout)
	}
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("connecting to vsock %d port %d: %w", cid, port, err)
	}
	return os.NewFile(uintptr(fd), "vsock"), nil
}

// awaitConnect waits for the non-blocking connect on fd to finish and
// returns its result.
func awaitConnect(fd int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return unix.ETIMEDOUT
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, err := unix.Poll(fds, int(left.Milliseconds())+1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		soErr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			return err
		}
		if soErr != 0 {
			return unix.Errno(soErr)
		}
		return nil
	}
}

// dialFirecrackerVsock connects to port in a Firecracker guest through the
// vsock device's Unix socket at path, with Firecracker's handshake: the
// client writes CONNECT and the port, and Firecracker answers OK and the
// host side's port once the guest has accepted.
func dialFirecrackerVsock(path string, port uint32, timeout time.Duration) (agentConn, error) {
	c, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return nil, err
	}
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := fmt.Fprintf(c, "CONNECT %d\n", port); err != nil {
		c.Close()
		return nil, err
	}
	line, err := readLine(c, agentMaxLine)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("reading Firecracker's answer to CONNECT %d: %w", port, err)
	}
	if !strings.HasPrefix(line, "OK ") {
		c.Close()
		return nil, fmt.Errorf("the Firecracker vsock device answered CONNECT %d with %q", port, line)
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		c.Close()
		return nil, err
	}
	return c.(*net.UnixConn), nil
}

// readLine reads one line from r a byte at a time, so that nothing after
// the newline is consumed, and returns it without the newline.
func readLine(r io.Reader, limit int) (string, error) {
	var line []byte
	var b [1]byte
	for len(line) < limit {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		if b[0] == '\n' {
			return string(line), nil
		}
		line = append(line, b[0])
	}
	return "", fmt.Errorf("the line is longer than %d bytes", limit)
}

// firecrackerVsock is the vsock section of Firecracker's configuration.
type firecrackerVsock struct {
	GuestCID uint32 `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

// withFirecrackerVsock adds the vsock device to the configuration file at
// path, with udsPath as its host side.
func withFirecrackerVsock(path, udsPath string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading firecracker config: %w", err)
	}
	var cfg firecrackerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("decoding firecracker config: %w", err)
	}
	cfg.Vsock = &firecrackerVsock{GuestCID: firecrackerGuestCID, UDSPath: udsPath}
	data, err = json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encoding firecracker config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing firecracker config: %w", err)
	}
	return nil
}

// agentRelay is where clients in the container reach the guest agent. A
// client connects to its Unix socket and writes one line: "session", after
// which the connection carries the agent's frames, "forward HOST PORT",
// after which it carries the raw bytes of a connection to that address in
// the guest, or "ping", after which it carries nothing. The relay answers
// "ok" or "error: " and the reason. Only the
// relay knows the boot's key, which it sends as the hello on every
// connection to the agent.
type agentRelay struct {
	ln   *net.UnixListener
	key  []byte
	dial func() (agentConn, error)
	// off says why there is no agent, and dial is nil while it is set.
	off    string
	wait   time.Duration
	uid    int
	logger *log.Logger

	mu     sync.Mutex
	conns  map[io.Closer]struct{}
	closed bool
	// done is closed by close, which ends every wait for the agent.
	done chan struct{}
	wg   sync.WaitGroup
}

// newAgentRelay listens at path, mode 0600, and serves clients until
// close, waiting up to wait for the agent to answer each one.
func newAgentRelay(path string, key []byte, dial func() (agentConn, error), off string, wait time.Duration, logger *log.Logger) (*agentRelay, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("removing the stale guest agent socket %s: %w", path, err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listening for the guest agent's clients at %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("making the guest agent socket %s private: %w", path, err)
	}
	r := &agentRelay{ln: ln, key: key, dial: dial, off: off, wait: wait, uid: os.Getuid(), logger: logger, conns: map[io.Closer]struct{}{}, done: make(chan struct{})}
	r.wg.Add(1)
	go r.serve()
	return r, nil
}

func (r *agentRelay) serve() {
	defer r.wg.Done()
	for {
		c, err := r.ln.AcceptUnix()
		if err != nil {
			return
		}
		if !r.track(c) {
			c.Close()
			return
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer r.untrack(c)
			r.handle(c)
		}()
	}
}

// track records c so that close can end it, and reports false once the
// relay is closed.
func (r *agentRelay) track(c io.Closer) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.conns[c] = struct{}{}
	return true
}

func (r *agentRelay) untrack(c io.Closer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.conns, c)
	c.Close()
}

// close stops listening, removes the socket, ends every connection, and
// waits for their goroutines.
func (r *agentRelay) close() {
	r.mu.Lock()
	if !r.closed {
		close(r.done)
	}
	r.closed = true
	r.ln.Close()
	for c := range r.conns {
		c.Close()
	}
	r.mu.Unlock()
	r.wg.Wait()
}

// handle serves one client.
func (r *agentRelay) handle(c *net.UnixConn) {
	answer := func(format string, args ...any) { fmt.Fprintf(c, "error: "+format+"\n", args...) }
	if err := r.checkPeer(c); err != nil {
		answer("%v", err)
		return
	}
	if err := c.SetReadDeadline(time.Now().Add(agentHelloTimeout)); err != nil {
		return
	}
	line, err := readLine(c, agentMaxLine)
	if err != nil {
		return
	}
	var forward *agentRequest
	var ping bool
	switch fields := strings.Fields(line); {
	case len(fields) == 1 && fields[0] == agentKindSession:
	case len(fields) == 3 && fields[0] == agentKindForward:
		port, err := strconv.Atoi(fields[2])
		if err != nil {
			answer("%q is not a port", fields[2])
			return
		}
		forward = &agentRequest{Kind: agentKindForward, Host: fields[1], Port: port}
	case len(fields) == 1 && fields[0] == agentRelayPing:
		ping = true
	default:
		answer("the guest agent relay takes %q, %q, or %q, not %q", agentKindSession, agentKindForward+" HOST PORT", agentRelayPing, line)
		return
	}
	if r.dial == nil {
		answer("%s", r.off)
		return
	}
	// A ping asks only whether this guest has an agent, which does not
	// change once the launch has started, so the relay answers it without
	// dialing the agent.
	if ping {
		_, _ = io.WriteString(c, "ok\n")
		return
	}
	// A session's request comes from the client, which sends it right after
	// its line, and a forward's is the relay's own.
	var request []byte
	if forward == nil {
		if request, err = readAgentFrameOf(c, agentFrameRequest); err != nil {
			answer("reading the session's request: %v", err)
			return
		}
	} else if request, err = json.Marshal(forward); err != nil {
		answer("encoding the forward's request: %v", err)
		return
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	// The shim sends nothing more until it has the relay's answer, so a
	// read that ends while the relay waits for the agent means the client
	// is gone. The relay then stops trying and closes its connection to the
	// agent, so the agent starts nothing it has not been told to, and ends
	// what it has. A byte that does arrive is the client's own, and it is
	// passed on.
	gone, early, stopWatch := watchClient(c)
	agent, ready, err := r.open(request, gone)
	if !stopWatch() {
		if agent != nil {
			r.untrack(agent)
		}
		return
	}
	if err != nil {
		answer("%v", err)
		return
	}
	defer r.untrack(agent)
	if ready.Error != "" {
		answer("%s", ready.Error)
		return
	}
	if _, err := io.WriteString(c, "ok\n"); err != nil {
		return
	}
	from := io.MultiReader(bytes.NewReader(early()), c)
	if forward != nil {
		r.forward(c, from, agent)
		return
	}
	// The client reads the agent's answer after the relay's, and then the
	// client's frames and the agent's pass through unchanged. When either
	// side ends, both connections close.
	if (&agentFrameWriter{w: c}).writeJSON(agentFrameReady, ready) != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(agent, from)
		agent.Close()
	}()
	_, _ = io.Copy(c, agent)
	c.Close()
	<-done
}

// checkPeer accepts a client running as vm-launch's own user or as root.
// Every process in the container may reach the socket's path, and this
// keeps out any that run as another user.
func (r *agentRelay) checkPeer(c *net.UnixConn) error {
	var cred *unix.Ucred
	var credErr error
	err := control(c, func(fd int) { cred, credErr = unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err := errors.Join(err, credErr); err != nil {
		return fmt.Errorf("reading the client's credentials: %w", err)
	}
	if int(cred.Uid) != r.uid && cred.Uid != 0 {
		return fmt.Errorf("uid %d may not use the guest agent", cred.Uid)
	}
	return nil
}

// watchClient reads one byte from c in the background while the relay
// waits for the agent. gone closes when that read ends, because the client
// closed its side or its connection failed. stop ends the watch and reports
// whether the client is still there, and early then returns the byte the
// client sent, if it sent one.
func watchClient(c *net.UnixConn) (gone <-chan struct{}, early func() []byte, stop func() bool) {
	ended := make(chan struct{})
	watched := make(chan struct{})
	var got []byte
	go func() {
		defer close(watched)
		var b [1]byte
		n, err := c.Read(b[:])
		if n > 0 {
			got = b[:n]
			return
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			close(ended)
		}
	}()
	stop = func() bool {
		_ = c.SetReadDeadline(time.Unix(1, 0))
		<-watched
		select {
		case <-ended:
			return false
		default:
		}
		return c.SetReadDeadline(time.Time{}) == nil
	}
	return ended, func() []byte { return got }, stop
}

// errAgentRelayClosed ends a client's wait for the agent when the relay
// closes.
var errAgentRelayClosed = errors.New("the guest agent relay closed")

// errAgentClientGone ends the wait for the agent when the client leaves.
var errAgentClientGone = errors.New("the client left before the guest agent answered")

// open connects to the agent, sends the hello and request, and returns the
// connection, which close can end, and the agent's answer. A dial that
// fails, or an agent that sends nothing before it ends the connection or
// before its read deadline passes, as one with all its handshakes pending
// does, is tried again until r.wait has passed, the relay closes, or gone
// closes.
func (r *agentRelay) open(request []byte, gone <-chan struct{}) (agentConn, agentReady, error) {
	deadline := time.Now().Add(r.wait)
	for {
		agent, ready, again, err := r.try(request, deadline, gone)
		if err == nil || !again {
			return agent, ready, err
		}
		if time.Now().After(deadline) {
			return nil, agentReady{}, fmt.Errorf("the guest agent did not answer within %v: %v", r.wait, err)
		}
		retry := time.NewTimer(agentDialRetry)
		select {
		case <-r.done:
			retry.Stop()
			return nil, agentReady{}, errAgentRelayClosed
		case <-gone:
			retry.Stop()
			return nil, agentReady{}, errAgentClientGone
		case <-retry.C:
		}
	}
}

// agentTryRead bounds each read of one try, which covers a forward's
// connect in the guest.
const agentTryRead = agentHelloTimeout + guestAgentDialTimeout

// errAgentTooLate is an accepted request that the relay does not tell the
// agent to start, because less than agentTryRead of its wait is left.
var errAgentTooLate = errors.New("the guest agent answered too late")

// try makes one connection to the agent for open, and reports with its
// error whether open may try again. The agent accepts the request first,
// and the relay then sends the go, after which the agent starts the session
// or the forward and answers. open may try again only while the agent has
// sent nothing, which is always before the go, so a request the agent
// started is never started a second time. Each read ends at the sooner of
// agentTryRead from its start and deadline. The relay sends the go only
// while a whole agentTryRead is left before deadline, so the answer to the
// go always has its full time, and a request accepted later starts
// nothing. A connection still open when gone closes is closed.
func (r *agentRelay) try(request []byte, deadline time.Time, gone <-chan struct{}) (agentConn, agentReady, bool, error) {
	var ready agentReady
	agent, err := r.dial()
	if err != nil {
		return nil, ready, true, err
	}
	if !r.track(agent) {
		agent.Close()
		return nil, ready, false, errAgentRelayClosed
	}
	tried := make(chan struct{})
	defer close(tried)
	go func() {
		select {
		case <-gone:
			agent.Close()
		case <-tried:
		}
	}()
	fail := func(again bool, err error) (agentConn, agentReady, bool, error) {
		r.untrack(agent)
		return nil, ready, again, err
	}
	readBy := func() error { return agent.SetReadDeadline(minTime(time.Now().Add(agentTryRead), deadline)) }
	fw := &agentFrameWriter{w: agent}
	if err := fw.write(agentFrameHello, r.key); err != nil {
		return fail(true, err)
	}
	if err := fw.write(agentFrameRequest, request); err != nil {
		return fail(true, err)
	}
	if err := readBy(); err != nil {
		return fail(true, err)
	}
	counted := &countingReader{r: agent}
	typ, payload, err := readAgentFrame(counted)
	if err != nil {
		return fail(counted.n == 0, fmt.Errorf("reading the guest agent's answer: %w", err))
	}
	if typ == agentFrameAccepted {
		if left := time.Until(deadline); left < agentTryRead {
			return fail(false, fmt.Errorf("%w: it accepted the request with %v of the relay's %v wait left, and starting a request may take %v", errAgentTooLate, left.Round(time.Millisecond), r.wait, agentTryRead))
		}
		if err := fw.write(agentFrameGo, nil); err != nil {
			return fail(false, fmt.Errorf("telling the guest agent to start: %w", err))
		}
		if err := readBy(); err != nil {
			return fail(false, err)
		}
		if typ, payload, err = readAgentFrame(agent); err != nil {
			return fail(false, fmt.Errorf("the guest agent accepted the request and did not answer: %w", err))
		}
	}
	if typ != agentFrameReady {
		return fail(false, fmt.Errorf("the guest agent answered with a frame of type 0x%02x", typ))
	}
	if err := json.Unmarshal(payload, &ready); err != nil {
		return fail(false, fmt.Errorf("the guest agent's answer could not be decoded: %w", err))
	}
	if err := agent.SetReadDeadline(time.Time{}); err != nil {
		return fail(false, err)
	}
	return agent, ready, false, nil
}

// minTime is the sooner of a and b.
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// forward turns the client's raw bytes, which it reads from from, into data
// frames for the agent, which has opened the forward, and the agent's data
// frames back into raw bytes on c, passing on the end of each direction.
func (r *agentRelay) forward(c *net.UnixConn, from io.Reader, agent agentConn) {
	fw := &agentFrameWriter{w: agent}
	toGuest := make(chan struct{})
	go func() {
		defer close(toGuest)
		buf := make([]byte, agentMaxData)
		for {
			n, err := from.Read(buf)
			if n > 0 && fw.writeData(agentFrameData, buf[:n]) != nil {
				agent.Close()
				return
			}
			if errors.Is(err, io.EOF) {
				if fw.write(agentFrameDataEnd, nil) != nil {
					agent.Close()
				}
				return
			}
			if err != nil {
				agent.Close()
				return
			}
		}
	}()
	for {
		typ, payload, err := readAgentFrame(agent)
		if err != nil {
			c.Close()
			break
		}
		if typ == agentFrameDataEnd {
			_ = c.CloseWrite()
			continue
		}
		if typ != agentFrameData {
			c.Close()
			break
		}
		if _, err := c.Write(payload); err != nil {
			agent.Close()
			c.Close()
			break
		}
	}
	<-toGuest
}
