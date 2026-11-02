//go:build linux

package main

import (
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

	// agentRelayWait is how long the relay keeps trying to reach the agent
	// for one client, which covers a guest that is still booting when the
	// first cf ssh arrives.
	agentRelayWait = 30 * time.Second

	// agentDialRetry is how long the relay waits between two tries.
	agentDialRetry = 250 * time.Millisecond

	// agentMaxLine is the most bytes the relay's first line may have.
	agentMaxLine = 512
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
	relay, err := newAgentRelay(socket, []byte(a.key), dial, a.off, logger)
	if err != nil {
		a.close()
		return nil, err
	}
	a.relay = relay
	return a, nil
}

// guestFiles returns what the initramfs needs for the agent of the guest
// that stack describes, a nil stack being the busybox guest, or nil when
// this launch's guest has no agent.
func (a *hostAgent) guestFiles(stack *guestStack) (*guestAgentFiles, error) {
	if a == nil || a.bin == nil {
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
	if a == nil || a.bin == nil {
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
		value := uint64(cid)
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), vhostVsockSetGuestCID, uintptr(unsafe.Pointer(&value)))
		if errno == 0 {
			return f, cid, nil
		}
		if errno != unix.EADDRINUSE {
			f.Close()
			return nil, 0, fmt.Errorf("reserving a vsock address on %s failed: %w", device, errno)
		}
	}
	f.Close()
	return nil, 0, fmt.Errorf("every one of %d random vsock addresses was in use", vsockCIDAttempts)
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
// which the connection carries the agent's frames, or "forward HOST PORT",
// after which it carries the raw bytes of a connection to that address in
// the guest. The relay answers "ok" or "error: " and the reason. Only the
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
	wg     sync.WaitGroup
}

// newAgentRelay listens at path, mode 0600, and serves clients until
// close.
func newAgentRelay(path string, key []byte, dial func() (agentConn, error), off string, logger *log.Logger) (*agentRelay, error) {
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
	r := &agentRelay{ln: ln, key: key, dial: dial, off: off, wait: agentRelayWait, uid: os.Getuid(), logger: logger, conns: map[io.Closer]struct{}{}}
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
	switch fields := strings.Fields(line); {
	case len(fields) == 1 && fields[0] == agentKindSession:
	case len(fields) == 3 && fields[0] == agentKindForward:
		port, err := strconv.Atoi(fields[2])
		if err != nil {
			answer("%q is not a port", fields[2])
			return
		}
		forward = &agentRequest{Kind: agentKindForward, Host: fields[1], Port: port}
	default:
		answer("the guest agent relay takes %q or %q, not %q", agentKindSession, agentKindForward+" HOST PORT", line)
		return
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	if r.dial == nil {
		answer("%s", r.off)
		return
	}
	agent, err := r.connect()
	if err != nil {
		answer("%v", err)
		return
	}
	if !r.track(agent) {
		agent.Close()
		return
	}
	defer r.untrack(agent)
	if forward != nil {
		r.forward(c, agent, *forward)
		return
	}
	if _, err := io.WriteString(c, "ok\n"); err != nil {
		return
	}
	// The client's frames and the agent's pass through unchanged. When
	// either side ends, both connections close.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(agent, c)
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

// connect dials the agent until it answers or r.wait has passed, and sends
// the hello.
func (r *agentRelay) connect() (agentConn, error) {
	deadline := time.Now().Add(r.wait)
	for {
		agent, err := r.dial()
		if err == nil {
			fw := &agentFrameWriter{w: agent}
			if err = fw.write(agentFrameHello, r.key); err == nil {
				return agent, nil
			}
			agent.Close()
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the guest agent did not answer within %v: %v", r.wait, err)
		}
		time.Sleep(agentDialRetry)
	}
}

// forward asks the agent for a forward to req's address and then turns the
// client's raw bytes into data frames and the agent's data frames back into
// raw bytes, passing on the end of each direction.
func (r *agentRelay) forward(c *net.UnixConn, agent agentConn, req agentRequest) {
	fw := &agentFrameWriter{w: agent}
	if err := fw.writeJSON(agentFrameRequest, req); err != nil {
		fmt.Fprintf(c, "error: asking the guest agent for the forward: %v\n", err)
		return
	}
	if err := agent.SetReadDeadline(time.Now().Add(agentHelloTimeout + guestAgentDialTimeout)); err != nil {
		return
	}
	payload, err := readAgentFrameOf(agent, agentFrameReady)
	if err != nil {
		fmt.Fprintf(c, "error: reading the guest agent's answer: %v\n", err)
		return
	}
	var ready agentReady
	if err := json.Unmarshal(payload, &ready); err != nil {
		fmt.Fprintf(c, "error: decoding the guest agent's answer: %v\n", err)
		return
	}
	if ready.Error != "" {
		fmt.Fprintf(c, "error: %s\n", ready.Error)
		return
	}
	if err := agent.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	if _, err := io.WriteString(c, "ok\n"); err != nil {
		return
	}
	toGuest := make(chan struct{})
	go func() {
		defer close(toGuest)
		buf := make([]byte, agentMaxData)
		for {
			n, err := c.Read(buf)
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
