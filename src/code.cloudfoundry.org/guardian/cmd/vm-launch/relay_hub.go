//go:build linux

package main

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// relaySocketPath is where the hub listens for the relays of one
	// container. Each container has its own /tmp, so the path is fixed.
	relaySocketPath = "/tmp/vm-launch-relay.sock"

	// relayMaxIndex is the most sidecars one description can give relays,
	// and so the highest index a relay can serve.
	relayMaxIndex = 8

	// relayQueueLimit bounds the bytes of one sidecar's lines that wait for
	// its relay. The serial filter never waits for a relay, so a relay that
	// attaches late or falls behind loses the oldest lines past this, and
	// never slows the console.
	relayQueueLimit = 512 << 10

	// relayHold bounds how long vm-launch waits, after a sidecar exited
	// first and the guest ended without a signal, for the signal with which
	// Diego cancels it. The signal makes vm-launch's own step count as
	// cancelled, so the description names the sidecar rather than the app.
	relayHold = 5 * time.Second

	// relayDrain bounds how long vm-launch waits, once it ends, for the
	// relays to take the lines still queued for them.
	relayDrain = 500 * time.Millisecond

	// relayHelloTimeout bounds how long a connection may take to say hello,
	// so a connection that says nothing never holds a goroutine for long.
	relayHelloTimeout = 5 * time.Second
)

// relayKeyPattern is the form of the relay key that rep puts in the
// description and in every relay's environment: 16 random bytes in hex.
var relayKeyPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// relayLine is one whole line of a sidecar's output, without its newline.
// stream is 'o' for stdout and 'e' for stderr.
type relayLine struct {
	stream byte
	text   string
}

// size is what the line counts against relayQueueLimit: its text, its
// stream prefix, and its newline.
func (l relayLine) size() int {
	return len(l.text) + 3
}

// relayQueue holds the lines of one sidecar, and its status once the guest
// reported that the sidecar exited first, until its relay takes them.
type relayQueue struct {
	index int
	// cond wakes the queue's writer. It shares the hub's mutex.
	cond  *sync.Cond
	lines []relayLine
	bytes int
	// dropped counts the lines the queue dropped since the writer last
	// reported a drop.
	dropped int
	// hasStatus is set, with status, once the guest reported that this
	// sidecar exited first. statusSent is set once the writer took it.
	hasStatus  bool
	status     int
	statusSent bool
	// conn is the attached relay's connection, or nil. A connection that
	// failed a write is broken, and its lines wait for close.
	conn   net.Conn
	broken bool
	// done is closed once the writer has ended. It is nil until a relay
	// attaches.
	done chan struct{}
}

// pending reports whether the writer has anything to send.
func (q *relayQueue) pending() bool {
	return len(q.lines) > 0 || q.dropped > 0 || (q.hasStatus && !q.statusSent)
}

// push appends a line, and drops the oldest lines when the queue would hold
// more than relayQueueLimit. A line larger than the limit on its own still
// goes in, alone.
func (q *relayQueue) push(l relayLine) {
	for len(q.lines) > 0 && q.bytes+l.size() > relayQueueLimit {
		q.bytes -= q.lines[0].size()
		q.lines[0] = relayLine{}
		q.lines = q.lines[1:]
		q.dropped++
	}
	q.lines = append(q.lines, l)
	q.bytes += l.size()
}

// relayHub serves the log relays of one app's sidecars. The serial filter
// hands it every line of sidecar i through deliver, and the guest's first
// exit through first. Neither ever blocks: each sidecar's lines wait in a
// bounded queue, and a writer goroutine for each attached relay empties its
// queue onto the relay's connection. A relay attaches with the hello line
// "hello <index> <key>", and the hub answers "ok", or "no <reason>" before it
// closes the connection. After "ok" the hub sends only "o <line>", "e
// <line>", and "x <status>" lines. Lines that no relay took by the time
// vm-launch ends go to vm-launch's own stdout and stderr, so they are never
// lost.
type relayHub struct {
	key      string
	listener *net.UnixListener
	stdout   io.Writer
	stderr   io.Writer
	logger   *log.Logger

	// wg covers the accept loop, every hello, and every writer.
	wg sync.WaitGroup

	mu sync.Mutex
	// queues holds sidecar i's queue at i-1.
	queues []*relayQueue
	// hellos holds the connections that have not said hello yet.
	hellos map[net.Conn]struct{}
	// firstIndex is the index of the process that exited first, as the
	// guest reported it, or -1.
	firstIndex int
	// stray counts the lines for an index this app has no sidecar at.
	stray int
	// closing makes every writer end once its queue is empty. closed is set
	// once close has started.
	closing bool
	closed  bool
}

// newRelayHub listens at path for the relays of count sidecars, which must
// present key, and returns the hub that serves them. A socket at path that
// this user owns is an old hub's, and is removed first. Lines no relay takes
// go to stdout and stderr when the hub closes.
func newRelayHub(path, key string, count int, stdout, stderr io.Writer, logger *log.Logger) (*relayHub, error) {
	if count < 1 || count > relayMaxIndex {
		return nil, fmt.Errorf("the log relays serve 1 to %d sidecars, not %d", relayMaxIndex, count)
	}
	if !relayKeyPattern.MatchString(key) {
		return nil, errors.New("the sidecars' relay key is not 32 lowercase hex digits")
	}
	if err := removeOldRelaySocket(path); err != nil {
		return nil, err
	}
	// Only this user may connect to the socket. The umask is the process's,
	// and nothing else in vm-launch creates a file this early.
	old := syscall.Umask(0o077)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("listening for the sidecars' log relays: %w", err)
	}

	h := &relayHub{
		key:        key,
		listener:   listener,
		stdout:     stdout,
		stderr:     stderr,
		logger:     logger,
		hellos:     make(map[net.Conn]struct{}),
		firstIndex: -1,
	}
	for i := 1; i <= count; i++ {
		h.queues = append(h.queues, &relayQueue{index: i, cond: sync.NewCond(&h.mu)})
	}
	h.wg.Add(1)
	go h.accept()
	return h, nil
}

// removeOldRelaySocket removes a socket at path that this user owns, which
// an earlier vm-launch in the container left. Anything else at path is an
// error, because listening there would fail.
func removeOldRelaySocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking for an old log relay socket: %w", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if info.Mode().Type() != fs.ModeSocket || !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s exists and is not a socket of this user, so the sidecars' log relays cannot attach", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing the old log relay socket: %w", err)
	}
	return nil
}

// accept takes connections until the listener closes, and hears each one's
// hello on a goroutine of its own.
func (h *relayHub) accept() {
	defer h.wg.Done()
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				h.logger.Printf("accepting a log relay: %v", err)
			}
			return
		}
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			_ = conn.Close()
			return
		}
		h.hellos[conn] = struct{}{}
		h.wg.Add(1)
		h.mu.Unlock()
		go h.hello(conn)
	}
}

// hello reads one connection's hello, and attaches the connection to its
// sidecar's queue or refuses it.
func (h *relayHub) hello(conn net.Conn) {
	defer h.wg.Done()
	_ = conn.SetReadDeadline(time.Now().Add(relayHelloTimeout))
	// The hello is short, so a reader of 128 bytes bounds what a connection
	// can make the hub hold.
	line, err := bufio.NewReaderSize(conn, 128).ReadSlice('\n')
	_ = conn.SetReadDeadline(time.Time{})

	h.mu.Lock()
	delete(h.hellos, conn)
	if h.closed {
		h.mu.Unlock()
		_ = conn.Close()
		return
	}
	var q *relayQueue
	reason := ""
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		reason = "a malformed hello"
	case err != nil:
		reason = "no hello"
	default:
		q, reason = h.check(strings.TrimSuffix(string(line), "\n"))
	}
	if q != nil {
		q.conn = conn
		q.done = make(chan struct{})
		h.wg.Add(1)
		h.mu.Unlock()
		go h.write(q)
		return
	}
	h.mu.Unlock()

	h.logger.Printf("refused a sidecar log relay: %s", reason)
	_ = conn.SetWriteDeadline(time.Now().Add(relayHelloTimeout))
	_, _ = io.WriteString(conn, "no "+reason+"\n")
	_ = conn.Close()
}

// check returns the queue that the hello line asks for, or the reason it
// refuses the hello. The key is checked before whether the index already
// has a relay, so a connection without the key learns nothing about the
// relays. The caller holds the mutex.
func (h *relayHub) check(line string) (*relayQueue, string) {
	fields := strings.Split(line, " ")
	if len(fields) != 3 || fields[0] != "hello" {
		return nil, "a malformed hello"
	}
	index, err := strconv.Atoi(fields[1])
	if err != nil || index < 1 || index > len(h.queues) || strconv.Itoa(index) != fields[1] {
		return nil, fmt.Sprintf("index %q is not a sidecar of this app", fields[1])
	}
	if subtle.ConstantTimeCompare([]byte(fields[2]), []byte(h.key)) != 1 {
		return nil, fmt.Sprintf("the wrong key for index %d", index)
	}
	q := h.queues[index-1]
	if q.conn != nil {
		return nil, fmt.Sprintf("index %d already has a relay", index)
	}
	return q, ""
}

// write answers the hello of q's relay and then sends q's lines, and its
// status once the guest reported one, until the hub closes. It ends after
// it sent the status, because the relay exits on it, and when a write fails,
// which leaves the lines it held at the front of the queue for close.
func (h *relayHub) write(q *relayQueue) {
	defer h.wg.Done()
	defer close(q.done)
	w := bufio.NewWriterSize(q.conn, 64<<10)
	_, _ = w.WriteString("ok\n")
	if err := w.Flush(); err != nil {
		h.breakQueue(q, nil, 0)
		return
	}
	for {
		h.mu.Lock()
		for !q.pending() && !h.closing {
			q.cond.Wait()
		}
		if !q.pending() {
			h.mu.Unlock()
			return
		}
		lines, dropped := q.lines, q.dropped
		q.lines, q.bytes, q.dropped = nil, 0, 0
		status, sendStatus := q.status, q.hasStatus && !q.statusSent
		if sendStatus {
			q.statusSent = true
		}
		h.mu.Unlock()

		if dropped > 0 {
			_, _ = fmt.Fprintf(w, "e vm-launch: dropped %d lines of this sidecar's output because its log relay fell behind\n", dropped)
		}
		for _, l := range lines {
			_ = w.WriteByte(l.stream)
			_ = w.WriteByte(' ')
			_, _ = w.WriteString(l.text)
			_ = w.WriteByte('\n')
		}
		if sendStatus {
			_, _ = fmt.Fprintf(w, "x %d\n", status)
		}
		if err := w.Flush(); err != nil {
			h.breakQueue(q, lines, dropped)
			return
		}
		if sendStatus {
			return
		}
	}
}

// breakQueue marks q's connection as broken and puts back the lines and the
// drop count of the write that failed, ahead of any that came since.
func (h *relayHub) breakQueue(q *relayQueue, lines []relayLine, dropped int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	q.broken = true
	q.lines = append(lines, q.lines...)
	q.dropped += dropped
	q.bytes = 0
	for _, l := range q.lines {
		q.bytes += l.size()
	}
}

// deliver queues one whole line, without its newline, of the output of the
// process at index, which is a sidecar's index counted from 1. stream is 'e'
// for stderr; any other value is stdout. It never blocks on a relay. It is
// the serial filter's logs callback.
func (h *relayHub) deliver(index int, stream byte, line string) {
	if stream != 'e' {
		stream = 'o'
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		h.fallback([]relayLine{{stream: stream, text: line}})
		return
	}
	defer h.mu.Unlock()
	if index < 1 || index > len(h.queues) {
		h.stray++
		return
	}
	q := h.queues[index-1]
	// The relay protocol is one line per message, so a line that holds a
	// newline goes as several.
	for {
		text, rest, more := strings.Cut(line, "\n")
		q.push(relayLine{stream: stream, text: text})
		if !more {
			break
		}
		line = rest
	}
	q.cond.Signal()
}

// first records that the guest reported index as the process that exited
// first, with status. For a sidecar, the hub queues the status behind the
// sidecar's lines, so its relay exits with it. Only the first report counts.
// It is the serial filter's firstExit callback.
func (h *relayHub) first(index, status int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.firstIndex >= 0 {
		return
	}
	h.firstIndex = index
	if index < 1 || index > len(h.queues) {
		return
	}
	q := h.queues[index-1]
	q.hasStatus, q.status = true, status
	q.cond.Signal()
}

// finish ends the hub once the guest has ended. When a sidecar exited first
// and vm-launch had received no signal, it waits up to hold for the signal
// on sigs with which Diego cancels vm-launch's step, so that the sidecar's
// relay is the step that reports the crash. It then gives the relays up to
// relayDrain to take their queued lines, and closes the hub.
func (h *relayHub) finish(received syscall.Signal, sigs <-chan os.Signal, hold time.Duration) {
	if h == nil {
		return
	}
	h.mu.Lock()
	first := h.firstIndex
	h.mu.Unlock()
	if first > 0 && received == 0 {
		t := time.NewTimer(hold)
		select {
		case <-sigs:
		case <-t.C:
			h.logger.Printf("no stop signal came within %v of sidecar %d's exit, so vm-launch exits with the guest's status", hold, first)
		}
		t.Stop()
	}

	h.mu.Lock()
	h.closing = true
	var done []chan struct{}
	for _, q := range h.queues {
		q.cond.Broadcast()
		if q.done != nil {
			done = append(done, q.done)
		}
	}
	h.mu.Unlock()
	t := time.NewTimer(relayDrain)
	defer t.Stop()
drain:
	for _, d := range done {
		select {
		case <-d:
		case <-t.C:
			break drain
		}
	}
	h.close()
}

// close stops listening, which removes the socket, closes every connection,
// and writes every line still queued to vm-launch's own stdout and stderr.
// It may be called more than once, and on a nil hub.
func (h *relayHub) close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed, h.closing = true, true
	conns := make([]net.Conn, 0, len(h.hellos)+len(h.queues))
	for c := range h.hellos {
		conns = append(conns, c)
	}
	for _, q := range h.queues {
		q.cond.Broadcast()
		if q.conn != nil {
			conns = append(conns, q.conn)
		}
	}
	h.mu.Unlock()

	_ = h.listener.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	h.wg.Wait()

	// Every goroutine has ended. The lines still queued are taken under the
	// mutex, because the serial filter may still report a first exit.
	type leftover struct {
		index, dropped int
		why            string
		lines          []relayLine
	}
	var left []leftover
	h.mu.Lock()
	for _, q := range h.queues {
		if len(q.lines) == 0 && q.dropped == 0 {
			continue
		}
		why := "fell behind"
		if q.conn == nil {
			why = "never attached"
		}
		left = append(left, leftover{index: q.index, dropped: q.dropped, why: why, lines: q.lines})
		q.lines, q.bytes, q.dropped = nil, 0, 0
	}
	stray := h.stray
	h.mu.Unlock()

	for _, l := range left {
		h.logger.Printf("sidecar %d's log relay %s, so its last %d lines follow on vm-launch's own output", l.index, l.why, len(l.lines))
		if l.dropped > 0 {
			h.logger.Printf("dropped %d lines of sidecar %d's output because its log relay %s", l.dropped, l.index, l.why)
		}
		h.fallback(l.lines)
	}
	if stray > 0 {
		h.logger.Printf("dropped %d lines for sidecar indexes this app does not have", stray)
	}
}

// fallback writes lines to vm-launch's own stdout and stderr.
func (h *relayHub) fallback(lines []relayLine) {
	for _, l := range lines {
		w := h.stdout
		if l.stream == 'e' {
			w = h.stderr
		}
		_, _ = io.WriteString(w, l.text+"\n")
	}
}
