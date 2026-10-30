//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The container's PORT opens only while the guest listens on it, as a
// container's port refuses connections until its app listens: Diego's port
// health check counts an instance as running once a connection to PORT
// succeeds, so a port that accepts before the guest app listens would pass
// the check for an app that is still booting or never listens at all.
//
// vm-launch reserves PORT when it starts (see reservePort), the guest
// reports whether anything listens on the port (see guestListenWatch), and
// a portGate opens and closes PORT to match, through a portOpener: the port
// proxy for Firecracker and a QEMU forwarding rule for QEMU.

// portOpener opens and closes the container's PORT for the guest.
type portOpener interface {
	openPort() error
	closePort() error
}

// errHostfwdFailed reports a forwarding rule QEMU could not set up, which is
// how QEMU reports a port that something else listens on.
var errHostfwdFailed = errors.New("QEMU could not set up the forwarding rule")

// isPortConflict reports whether err from openPort means that something
// else in the container listens on the port.
func isPortConflict(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, errHostfwdFailed)
}

// portGate keeps the container's PORT open while the guest listens on it,
// and closed otherwise. It acts on the guest's latest state only, one change
// at a time, in its own goroutine, so a slow change never holds up the guest
// console. A port that cannot open stays closed, with a line that says why,
// until the guest's next report that it listens.
type portGate struct {
	opener portOpener
	port   int
	logger *log.Logger

	mu   sync.Mutex
	want chan bool

	shut     chan struct{}
	shutOnce sync.Once
	ended    chan struct{}
	endOnce  sync.Once
	done     chan struct{}
}

// startPortGate returns a running gate for port, which starts closed.
func startPortGate(opener portOpener, port int, logger *log.Logger) *portGate {
	g := &portGate{
		opener: opener,
		port:   port,
		logger: logger,
		want:   make(chan bool, 1),
		shut:   make(chan struct{}),
		ended:  make(chan struct{}),
		done:   make(chan struct{}),
	}
	go g.loop()
	return g
}

// set records whether the guest listens. It never blocks: a state that the
// gate has not acted on yet is replaced by the newer one.
func (g *portGate) set(up bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.want:
	default:
	}
	// Every sender holds mu and the buffer was just emptied, so this send
	// never blocks.
	g.want <- up
}

// shutDown closes the port for good, as the guest stops: no later report
// opens it again. It returns at once.
func (g *portGate) shutDown() {
	g.shutOnce.Do(func() { close(g.shut) })
}

// end stops the gate once the hypervisor has exited and waits for it. It
// leaves the port as it is: the end of QEMU removed its forwarding rule, and
// closing the proxy closes its listener.
func (g *portGate) end() {
	g.endOnce.Do(func() { close(g.ended) })
	<-g.done
}

func (g *portGate) loop() {
	defer close(g.done)
	open, shut := false, false
	closePort := func() {
		if err := g.opener.closePort(); err != nil {
			g.logf("closing port %d in the container: %v", g.port, err)
		}
		open = false
	}
	for {
		select {
		case <-g.ended:
			return
		default:
		}
		if !shut {
			select {
			case <-g.shut:
				shut = true
				if open {
					closePort()
				}
				continue
			default:
			}
		}
		var shutCh <-chan struct{}
		if !shut {
			shutCh = g.shut
		}
		select {
		case <-g.ended:
			return
		case <-shutCh:
			// Handled at the top of the loop.
		case up := <-g.want:
			switch {
			case shut, up == open:
			case up:
				if err := g.opener.openPort(); err != nil {
					g.logf("the guest listens on port %d, but vm-launch could not open it in the container: %v", g.port, err)
					if isPortConflict(err) {
						g.logf("%s", portConflictMessage(g.port))
					}
					continue
				}
				open = true
				g.logf("the guest listens on port %d; it is open in the container", g.port)
			default:
				closePort()
				g.logf("the guest no longer listens on port %d; it is closed in the container", g.port)
			}
		}
	}
}

// logf logs a line unless the gate has ended, when a change can fail only
// because the hypervisor is gone.
func (g *portGate) logf(format string, args ...any) {
	select {
	case <-g.ended:
	default:
		g.logger.Printf(format, args...)
	}
}

// proxyPort opens the port as the listener of the Firecracker port proxy.
type proxyPort struct {
	proxy *tcpProxy
	addr  string
}

func (p proxyPort) openPort() error { return p.proxy.Listen(p.addr) }

func (p proxyPort) closePort() error {
	p.proxy.StopListening()
	return nil
}

// qmpPort opens the port as a QEMU forwarding rule from the container's
// port to the guest's, which it adds and removes through QEMU's QMP monitor.
type qmpPort struct {
	monitor *qmpMonitor
	port    int
}

// hostRule is the container side of the forwarding rule.
func (q qmpPort) hostRule() string {
	return "tcp:0.0.0.0:" + strconv.Itoa(q.port)
}

func (q qmpPort) openPort() error {
	out, err := q.monitor.humanCommand("hostfwd_add " + qemuNetdevID + " " + q.hostRule() + "-" + qemuGuestIP + ":" + strconv.Itoa(q.port))
	if err != nil {
		return err
	}
	// hostfwd_add prints nothing when it succeeds.
	if out = strings.TrimSpace(out); out != "" {
		return fmt.Errorf("%w: %s", errHostfwdFailed, out)
	}
	return nil
}

func (q qmpPort) closePort() error {
	out, err := q.monitor.humanCommand("hostfwd_remove " + qemuNetdevID + " " + q.hostRule())
	if err != nil {
		return err
	}
	// hostfwd_remove reports "host forwarding rule for RULE removed" when
	// it succeeds, and something else when it does not.
	if out = strings.TrimSpace(out); !strings.HasSuffix(out, " removed") {
		return fmt.Errorf("QEMU did not remove the forwarding rule: %s", out)
	}
	return nil
}

// qmpTimeout bounds one QMP command, from the request to the reply.
const qmpTimeout = 10 * time.Second

// qmpMonitor is a client of QEMU's QMP monitor on a connected stream socket.
// It negotiates capabilities before its first command, skips asynchronous
// events, and is used by one goroutine at a time. A command that fails on
// the socket itself, such as one that times out, leaves the monitor broken:
// a reply may still be on its way, which the next command would read as its
// own, so every later command fails with the same error.
type qmpMonitor struct {
	conn    net.Conn
	dec     *json.Decoder
	timeout time.Duration
	ready   bool
	broken  error
}

func newQMPMonitor(conn net.Conn) *qmpMonitor {
	return &qmpMonitor{conn: conn, dec: json.NewDecoder(conn), timeout: qmpTimeout}
}

// qmpMessage is any message QEMU sends on its QMP monitor: the greeting, a
// command's return or error, or an event.
type qmpMessage struct {
	QMP    json.RawMessage `json:"QMP"`
	Return json.RawMessage `json:"return"`
	Error  *qmpError       `json:"error"`
	Event  string          `json:"event"`
}

type qmpError struct {
	Class string `json:"class"`
	Desc  string `json:"desc"`
}

// humanCommand runs a human monitor command and returns its output.
func (m *qmpMonitor) humanCommand(line string) (string, error) {
	if m.broken != nil {
		return "", m.broken
	}
	if err := m.conn.SetDeadline(time.Now().Add(m.timeout)); err != nil {
		return "", m.fail(fmt.Errorf("QMP: setting a deadline: %w", err))
	}
	if !m.ready {
		msg, err := m.read()
		if err != nil {
			return "", m.fail(fmt.Errorf("QMP: reading the greeting: %w", err))
		}
		if msg.QMP == nil {
			return "", m.fail(errors.New("QMP: the first message is not a greeting"))
		}
		if _, err := m.execute("qmp_capabilities", nil); err != nil {
			return "", err
		}
		m.ready = true
	}
	ret, err := m.execute("human-monitor-command", map[string]string{"command-line": line})
	if err != nil {
		return "", err
	}
	var out string
	if err := json.Unmarshal(ret, &out); err != nil {
		return "", fmt.Errorf("QMP human-monitor-command: the return is not a string: %w", err)
	}
	return out, nil
}

// execute sends one command and returns its return value.
func (m *qmpMonitor) execute(command string, args any) (json.RawMessage, error) {
	req := map[string]any{"execute": command}
	if args != nil {
		req["arguments"] = args
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("QMP %s: encoding the request: %w", command, err)
	}
	if _, err := m.conn.Write(append(b, '\n')); err != nil {
		return nil, m.fail(fmt.Errorf("QMP %s: %w", command, err))
	}
	for {
		msg, err := m.read()
		if err != nil {
			return nil, m.fail(fmt.Errorf("QMP %s: reading the reply: %w", command, err))
		}
		switch {
		case msg.Event != "":
		case msg.Error != nil:
			return nil, fmt.Errorf("QMP %s: %s: %s", command, msg.Error.Class, msg.Error.Desc)
		case msg.Return != nil:
			return msg.Return, nil
		default:
			return nil, m.fail(fmt.Errorf("QMP %s: a reply with neither a return nor an error", command))
		}
	}
}

// fail marks the monitor broken with err and returns err.
func (m *qmpMonitor) fail(err error) error {
	m.broken = err
	return err
}

func (m *qmpMonitor) read() (qmpMessage, error) {
	var msg qmpMessage
	err := m.dec.Decode(&msg)
	return msg, err
}

// newQMPSocket returns a connected pair of stream sockets: vm-launch's end
// as a connection, and QEMU's end as a file for the hypervisor to inherit.
func newQMPSocket() (net.Conn, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("creating the QMP socket: %w", os.NewSyscallError("socketpair", err))
	}
	ours := os.NewFile(uintptr(fds[0]), "qmp")
	theirs := os.NewFile(uintptr(fds[1]), "qmp-qemu")
	conn, err := net.FileConn(ours)
	ours.Close()
	if err != nil {
		theirs.Close()
		return nil, nil, fmt.Errorf("creating the QMP socket: %w", err)
	}
	return conn, theirs, nil
}

// portReservation holds PORT from the start of vm-launch to its exit, so
// that a port the container already uses fails the launch before the guest
// boots, and nothing else takes the port while the guest is not listening.
type portReservation struct {
	lock net.Listener
	fd   int
}

// reservePort reserves port with two sockets. The first is a listener on
// the abstract Unix socket name vm-launch-port-PORT, which is unique within
// the container's network namespace, so a second vm-launch for the same
// port fails here. The second is a TCP socket bound to 0.0.0.0:PORT that
// never listens, so connections to the port are refused, as they are while
// nothing listens. It fails with an error that matches syscall.EADDRINUSE
// when another socket listens on the port. It sets SO_REUSEADDR, so the
// port proxy and QEMU, which set it too, can bind and listen on the port
// while the reservation holds it, and a plain bind cannot.
func reservePort(port int) (*portReservation, error) {
	lock, err := net.Listen("unix", "@vm-launch-port-"+strconv.Itoa(port))
	if err != nil {
		return nil, fmt.Errorf("reserving port %d: %w", port, err)
	}
	fd, err := reserveTCPPort(port)
	if err != nil {
		lock.Close()
		return nil, fmt.Errorf("reserving port %d: %w", port, err)
	}
	return &portReservation{lock: lock, fd: fd}, nil
}

func reserveTCPPort(port int) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, os.NewSyscallError("socket", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fd)
		return -1, os.NewSyscallError("setsockopt", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: port}); err != nil {
		unix.Close(fd)
		return -1, os.NewSyscallError("bind", err)
	}
	return fd, nil
}

// Close releases the port.
func (r *portReservation) Close() error {
	err := r.lock.Close()
	if cerr := unix.Close(r.fd); err == nil && cerr != nil {
		err = os.NewSyscallError("close", cerr)
	}
	return err
}
