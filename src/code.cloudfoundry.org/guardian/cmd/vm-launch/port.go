//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Each of the container's forwarded ports, PORT first, opens only while the
// guest listens on it, as a container's port refuses connections until its
// app listens: Diego's port health check counts an instance as running once
// a connection to PORT succeeds, so a port that accepts before the guest app
// listens would pass the check for an app that is still booting or never
// listens at all. A port the app never listens on stays closed.
//
// vm-launch reserves each port when it starts (see reservePort), the guest
// reports whether anything listens on each port (see guestListenWatch), and
// a portGate for each port opens and closes it to match, through a
// portOpener: a listener of the port proxy for Firecracker and a QEMU
// forwarding rule for QEMU.

// portOpener opens and closes one port of the container for the guest.
type portOpener interface {
	openPort() error
	closePort() error
}

// hostfwdFailedPrefix starts the output of hostfwd_add when QEMU could not
// bind the rule's port.
const hostfwdFailedPrefix = "Could not set up host forwarding rule"

// errHostfwdFailed reports a forwarding rule QEMU could not set up, which is
// how QEMU reports a port that something else listens on.
var errHostfwdFailed = errors.New("QEMU could not set up the forwarding rule")

// isPortConflict reports whether err from openPort means that something
// else in the container listens on the port.
func isPortConflict(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, errHostfwdFailed)
}

// portGate keeps one port of the container open while the guest listens on it,
// and closed otherwise. It acts on the guest's latest state only, one change
// at a time, in its own goroutine, so a slow change never holds up the guest
// console.
//
// A change that fails is tried again, after retry.first and then after
// twice as long each time up to retry.max, until it succeeds or the guest's
// state changes. The first failure in a row is logged, and so is a failure
// that turns a port conflict into another error or back. The gate
// tries again rather than ending the run, because a change can fail for a
// moment, as when QEMU's monitor is slow to reply, and the app in the guest
// is still healthy; a port that stays closed shows up in the health check,
// and the logged failure says why. The gate cannot tell whether a change
// that failed took effect, so it closes the port of unknown state before it
// opens it, which also clears a QEMU forwarding rule that an open which
// timed out added late.
//
// Each change that succeeds is logged, so the gate's last line says whether
// the port is open. A close at shutDown is logged as vm-launch stopping, and
// end logs that the port closes when the last line said it was open.
type portGate struct {
	opener portOpener
	port   int
	retry  backoff
	logger *log.Logger

	mu   sync.Mutex
	want chan bool

	shut     chan struct{}
	shutOnce sync.Once
	ended    chan struct{}
	endOnce  sync.Once
	done     chan struct{}

	// shownOpen is set while the gate's last line about the port said it
	// is open. Only the loop writes it, and end reads it once the loop
	// has returned.
	shownOpen bool
}

// portGates runs a portGate for each forwarded port. The gates share the
// opener's proxy or monitor, and nothing else: one port's state never
// reaches another's gate.
type portGates struct {
	// gates are in the order of the ports they were started for.
	gates  []*portGate
	byPort map[int]*portGate
}

// startPortGates returns running gates for ports, each with the opener that
// open returns for its port. Every gate starts closed.
func startPortGates(ports []int, open func(port int) portOpener, retry backoff, logger *log.Logger) *portGates {
	p := &portGates{byPort: map[int]*portGate{}}
	for _, port := range ports {
		g := startPortGate(open(port), port, retry, logger)
		p.gates = append(p.gates, g)
		p.byPort[port] = g
	}
	return p
}

// set records whether the guest listens on port, for that port's gate only.
// A port with no gate is ignored. It never blocks.
func (p *portGates) set(port int, up bool) {
	if g, ok := p.byPort[port]; ok {
		g.set(up)
	}
}

// shutDown closes every port for good, as the guest stops.
func (p *portGates) shutDown() {
	for _, g := range p.gates {
		g.shutDown()
	}
}

// end ends every gate once the hypervisor has exited, and waits for them.
func (p *portGates) end() {
	for _, g := range p.gates {
		g.end()
	}
}

// backoff is how long the gate waits before it tries a failed change again:
// first after the first failure, and twice as long after each further one,
// up to max.
type backoff struct {
	first, max time.Duration
}

// next returns the wait after a failure that followed a wait of d.
func (b backoff) next(d time.Duration) time.Duration {
	return min(2*d, b.max)
}

// gateRetry is the backoff of the gate in run. Its first wait matches the
// guest watcher's period.
var gateRetry = backoff{first: time.Second, max: 16 * time.Second}

// portState is what the gate knows of the port.
type portState int

const (
	portClosed portState = iota
	portOpen
	// portUnknown follows a change that failed, which may or may not have
	// taken effect.
	portUnknown
)

// startPortGate returns a running gate for port, which starts closed and
// tries failed changes again after the waits of retry.
func startPortGate(opener portOpener, port int, retry backoff, logger *log.Logger) *portGate {
	g := &portGate{
		opener: opener,
		port:   port,
		retry:  retry,
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
// leaves the port as it is, because the end of QEMU removed its forwarding
// rule and closing the proxy closes its listener. When the gate's last line
// said that the port is open, end logs that it closes.
func (g *portGate) end() {
	g.endOnce.Do(func() {
		close(g.ended)
		<-g.done
		if g.shownOpen {
			g.logger.Printf("the guest has stopped, so port %d closes in the container", g.port)
		}
	})
	<-g.done
}

func (g *portGate) loop() {
	defer close(g.done)
	var (
		up, shut, goal bool
		state          = portClosed
		// retry fires when a failed change is due to be tried again.
		retry <-chan time.Time
		timer *time.Timer
		wait  = g.retry.first
		// failing is set while the changes toward goal fail, and conflict
		// says whether the last of them failed on a port conflict. conflict
		// means something only while failing is set, and every failure
		// sets it along with failing, so a new goal needs no reset of it.
		failing, conflict bool
	)
	// retryNow drops the wait before the next try.
	retryNow := func() {
		if timer != nil {
			timer.Stop()
		}
		timer, retry = nil, nil
	}
	// newGoal forgets the failures of the last goal.
	newGoal := func() {
		retryNow()
		wait, failing = g.retry.first, false
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
				// A close that waits out its backoff runs at once, as
				// the guest is stopping.
				retryNow()
			default:
			}
		}
		if next := up && !shut; next != goal {
			goal = next
			newGoal()
		}
		if retry == nil && state != stateFor(goal) {
			if err := g.change(&state, goal); err != nil {
				if c := isPortConflict(err); !failing || c != conflict {
					failing, conflict = true, c
					g.logFailure(goal, err)
				}
				timer = time.NewTimer(wait)
				retry = timer.C
				wait = g.retry.next(wait)
			} else {
				// The port now matches the goal, so no change follows
				// until the goal changes, and newGoal ends the run of
				// failures then.
				switch {
				case goal:
					if g.logf("the guest listens on port %d; it is open in the container", g.port) {
						g.shownOpen = true
					}
				case shut:
					if g.logf("vm-launch is stopping; port %d is closed in the container", g.port) {
						g.shownOpen = false
					}
				default:
					if g.logf("the guest no longer listens on port %d; it is closed in the container", g.port) {
						g.shownOpen = false
					}
				}
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
		case up = <-g.want:
		case <-retry:
			timer, retry = nil, nil
		}
	}
}

func stateFor(open bool) portState {
	if open {
		return portOpen
	}
	return portClosed
}

// change opens or closes the port, closing first a port that is not known
// to be closed, and records the outcome in state.
func (g *portGate) change(state *portState, open bool) error {
	if *state != portClosed {
		if err := g.opener.closePort(); err != nil {
			*state = portUnknown
			if open {
				return fmt.Errorf("closing it after a change that failed: %w", err)
			}
			return err
		}
		*state = portClosed
	}
	if !open {
		return nil
	}
	if err := g.opener.openPort(); err != nil {
		*state = portUnknown
		return err
	}
	*state = portOpen
	return nil
}

// logFailure logs err, the failure of a change to open or close the port.
func (g *portGate) logFailure(open bool, err error) {
	if !open {
		g.logf("closing port %d in the container: %v", g.port, err)
		return
	}
	g.logf("the guest listens on port %d, but vm-launch could not open it in the container: %v", g.port, err)
	if isPortConflict(err) {
		g.logf("%s", portConflictMessage(g.port))
	}
}

// logf logs a line unless the gate has ended, when a change can fail only
// because the hypervisor is gone and end has the last word on the port. It
// reports whether it logged the line.
func (g *portGate) logf(format string, args ...any) bool {
	select {
	case <-g.ended:
		return false
	default:
		g.logger.Printf(format, args...)
		return true
	}
}

// proxyPort opens the port as the listener of the Firecracker port proxy.
type proxyPort struct {
	proxy *tcpProxy
	// addr is where the port listens in the container, and upstream the
	// guest address its connections go to.
	addr     string
	upstream string
}

func (p proxyPort) openPort() error { return p.proxy.Listen(p.addr, p.upstream) }

func (p proxyPort) closePort() error {
	p.proxy.StopListening(p.addr)
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
	// hostfwd_add prints nothing when it succeeds. Any other output, such
	// as a rule QEMU cannot parse, is not a conflict on the port.
	switch out = strings.TrimSpace(out); {
	case out == "":
		return nil
	case strings.HasPrefix(out, hostfwdFailedPrefix):
		return fmt.Errorf("%w: %s", errHostfwdFailed, out)
	default:
		return fmt.Errorf("QEMU did not add the forwarding rule: %s", out)
	}
}

// closePort removes the rule. A rule that QEMU does not have is closed
// already, and so is every rule of a QEMU whose end of the QMP socket has
// closed, which it does as it exits.
func (q qmpPort) closePort() error {
	out, err := q.monitor.humanCommand("hostfwd_remove " + qemuNetdevID + " " + q.hostRule())
	if errors.Is(err, io.EOF) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		return nil
	}
	if err != nil {
		return err
	}
	// hostfwd_remove reports "host forwarding rule for RULE removed" when
	// it removed the rule, "host forwarding rule for RULE not found" when
	// QEMU has no such rule, and something else when it failed.
	out = strings.TrimSpace(out)
	if strings.HasSuffix(out, " removed") || strings.HasSuffix(out, " not found") {
		return nil
	}
	return fmt.Errorf("QEMU did not remove the forwarding rule: %s", out)
}

// qmpTimeout bounds one QMP command, from the request to the reply.
const qmpTimeout = 10 * time.Second

// qmpMonitor is a client of QEMU's QMP monitor on a connected stream socket.
// It negotiates capabilities before its first command, skips asynchronous
// events, and runs one command at a time. It sends each command with
// an id of its own and takes as the reply only the message with that id, so
// a command that timed out leaves the monitor usable: its late reply, when
// it comes, is skipped, and a line cut off by the timeout is completed by
// the next read. A capabilities request that timed out is not sent again,
// and the next command waits for its reply first. Only a failure of the
// socket itself, an end of file or a failed write, a line that is not a QMP
// message, or an error in reply to capabilities, leaves the monitor broken,
// so every later command fails with the same error. QEMU refuses
// capabilities only when their negotiation is already complete, which
// cannot happen on a socket that only vm-launch uses, so a refusal means a
// monitor that vm-launch cannot use, and sending them again would not help.
type qmpMonitor struct {
	// mu serializes commands, which the gates of different ports send from
	// their own goroutines.
	mu      sync.Mutex
	conn    net.Conn
	r       *bufio.Reader
	timeout time.Duration

	// partial is the start of a line that a timeout cut off.
	partial []byte
	lastID  uint64
	greeted bool
	// capsID is the id of the capabilities request, once it is sent.
	capsID uint64
	ready  bool
	broken error
}

func newQMPMonitor(conn net.Conn) *qmpMonitor {
	return &qmpMonitor{conn: conn, r: bufio.NewReader(conn), timeout: qmpTimeout}
}

// qmpMessage is any message QEMU sends on its QMP monitor: the greeting, a
// command's return or error, or an event.
type qmpMessage struct {
	QMP    json.RawMessage `json:"QMP"`
	ID     *uint64         `json:"id"`
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.broken != nil {
		return "", m.broken
	}
	if err := m.conn.SetDeadline(time.Now().Add(m.timeout)); err != nil {
		return "", m.fail(fmt.Errorf("QMP: setting a deadline: %w", err))
	}
	if !m.greeted {
		msg, err := m.read()
		if err != nil {
			return "", m.readFailed(fmt.Errorf("QMP: reading the greeting: %w", err))
		}
		if msg.QMP == nil {
			return "", m.fail(errors.New("QMP: the first message is not a greeting"))
		}
		m.greeted = true
	}
	if !m.ready {
		if m.capsID == 0 {
			id, err := m.send("qmp_capabilities", nil)
			if err != nil {
				return "", err
			}
			m.capsID = id
		}
		_, err := m.await("qmp_capabilities", m.capsID)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return "", err
			}
			return "", m.fail(err)
		}
		m.ready = true
	}
	id, err := m.send("human-monitor-command", map[string]string{"command-line": line})
	if err != nil {
		return "", err
	}
	ret, err := m.await("human-monitor-command", id)
	if err != nil {
		return "", err
	}
	var out string
	if err := json.Unmarshal(ret, &out); err != nil {
		return "", fmt.Errorf("QMP human-monitor-command: the return is not a string: %w", err)
	}
	return out, nil
}

// send writes one command with a new id and returns the id.
func (m *qmpMonitor) send(command string, args any) (uint64, error) {
	m.lastID++
	req := map[string]any{"execute": command, "id": m.lastID}
	if args != nil {
		req["arguments"] = args
	}
	b, err := json.Marshal(req)
	if err != nil {
		return 0, fmt.Errorf("QMP %s: encoding the request: %w", command, err)
	}
	if _, err := m.conn.Write(append(b, '\n')); err != nil {
		// A write cut off part way would run into the next request.
		return 0, m.fail(fmt.Errorf("QMP %s: %w", command, err))
	}
	return m.lastID, nil
}

// await reads messages until the reply to the command with id and returns
// its return value. It skips events and the replies to other commands,
// which are the late replies to commands that timed out.
func (m *qmpMonitor) await(command string, id uint64) (json.RawMessage, error) {
	for {
		msg, err := m.read()
		if err != nil {
			return nil, m.readFailed(fmt.Errorf("QMP %s: reading the reply: %w", command, err))
		}
		switch {
		case msg.Event != "", msg.ID == nil || *msg.ID != id:
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

// readFailed returns err, a failure of read, and marks the monitor broken
// with it unless it is a timeout.
func (m *qmpMonitor) readFailed(err error) error {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return m.fail(err)
}

// read returns the next message. A timeout, which returns an error that
// matches os.ErrDeadlineExceeded, keeps what it read of the line for the
// next read.
func (m *qmpMonitor) read() (qmpMessage, error) {
	for {
		b, err := m.r.ReadBytes('\n')
		m.partial = append(m.partial, b...)
		if err != nil {
			return qmpMessage{}, err
		}
		line := bytes.TrimSpace(m.partial)
		m.partial = nil
		if len(line) == 0 {
			continue
		}
		var msg qmpMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			return qmpMessage{}, fmt.Errorf("a line that is not a QMP message: %w", err)
		}
		return msg, nil
	}
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
// boots, and a plain bind cannot take the port while the guest is not
// listening. A listener that sets SO_REUSEADDR can (see reservePort).
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
