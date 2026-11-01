//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

const (
	// relayEnv names the variable that makes a launcher process a sidecar's
	// log relay. Its value is "<index>:<key>". Rep sets it on each sidecar's
	// action, and sets it empty on the app's, so that a value from the app's
	// own environment never makes the app a relay.
	relayEnv = "CF_VM_SIDECAR_RELAY"

	// relayDialRetry is how often a relay dials the hub until a dial works.
	relayDialRetry = 100 * time.Millisecond

	// relayEndWait bounds how long a relay whose stream ended without a
	// status waits for the signal with which Diego cancels it.
	relayEndWait = 10 * time.Second
)

// relayValuePattern is the form of relayEnv's value. It is the same pattern
// Garden's containerizer matches before it runs a process as a relay.
var relayValuePattern = regexp.MustCompile(`^([1-8]):([0-9a-f]{32})$`)

// runRelay is "vm-launch relay": the process that stands in the outer
// container for one sidecar that runs in the guest. It writes the sidecar's
// lines, which it reads from the hub in vm-launch, to its own stdout and
// stderr, and exits with the sidecar's status, so the executor tags the
// lines and describes a crash as it does for a sidecar under runC.
func runRelay(argv []string) int {
	logger := log.New(os.Stderr, "vm-launch relay: ", 0)
	// The signals are caught before anything else, so a stop that comes at
	// once still ends the relay as cancelled.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)
	// A reader that goes away must not kill the relay before it has the
	// sidecar's status, so a broken pipe is an error the relay ignores.
	pipes := make(chan os.Signal, 1)
	signal.Notify(pipes, syscall.SIGPIPE)
	defer signal.Stop(pipes)

	// The environment holds the relay key, and a process that is not
	// dumpable keeps its /proc environ from every other process of the user.
	if err := markUndumpable(); err != nil {
		logger.Printf("making the relay non-dumpable: %v", err)
		return 1
	}
	if len(argv) > 0 {
		logger.Printf("the relay takes no arguments, but was given %d", len(argv))
		return 1
	}
	env := lastWinsEnv(os.Environ(), logger)
	r := relay{
		socket:  relaySocketPath,
		value:   env[relayEnv],
		stdout:  os.Stdout,
		stderr:  os.Stderr,
		logger:  logger,
		signals: sigs,
		retry:   relayDialRetry,
		endWait: relayEndWait,
	}
	return r.run()
}

// relay is one sidecar's log relay.
type relay struct {
	socket  string
	value   string
	stdout  io.Writer
	stderr  io.Writer
	logger  *log.Logger
	signals <-chan os.Signal
	retry   time.Duration
	endWait time.Duration
}

// parseRelayValue returns the index and the key in a relayEnv value.
func parseRelayValue(value string) (int, string, error) {
	m := relayValuePattern.FindStringSubmatch(value)
	if m == nil {
		return 0, "", fmt.Errorf("%s is not an index from 1 to 8 and a key of 32 lowercase hex digits", relayEnv)
	}
	index, _ := strconv.Atoi(m[1])
	return index, m[2], nil
}

// relayEventKind is what the stream reader tells the relay's main loop.
type relayEventKind int

const (
	relayAccepted relayEventKind = iota
	relayRefused
	relayStatus
	relayEnded
	relayGarbled
)

type relayEvent struct {
	kind   relayEventKind
	status int
	text   string
}

// run dials the hub, says hello, and streams until the hub sends a status
// or the stream ends. Its exit rules decide the crash description.
//
//   - A status ends the relay with that status.
//   - A signal before the hub accepted the hello ends the relay at once with
//     128 plus the signal's number.
//   - A signal after that keeps the stream open until the hub sends a status
//     or closes it, so the sidecar's last lines keep its source, and then
//     ends the relay with 128 plus the signal's number.
//   - An end of stream without a status waits up to endWait for a signal,
//     and then ends the relay with 1.
//   - A refused hello, or a line the relay cannot read, ends it with 1.
func (r relay) run() int {
	index, key, err := parseRelayValue(r.value)
	if err != nil {
		r.logger.Print(err)
		return 1
	}

	var conn net.Conn
	for {
		c, err := net.Dial("unix", r.socket)
		if err == nil {
			conn = c
			break
		}
		t := time.NewTimer(r.retry)
		select {
		case sig := <-r.signals:
			t.Stop()
			return 128 + signalNumber(sig)
		case <-t.C:
		}
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "hello %d %s\n", index, key); err != nil {
		// The hub went away between the dial and the hello, which is the
		// same as a stream that ended before it was accepted.
		return r.ended(nil)
	}
	events := make(chan relayEvent)
	quit := make(chan struct{})
	defer close(quit)
	go r.stream(conn, events, quit)

	accepted := false
	var stopped os.Signal
	for {
		select {
		case sig := <-r.signals:
			if !accepted {
				return 128 + signalNumber(sig)
			}
			if stopped == nil {
				stopped = sig
			}
		case ev := <-events:
			switch ev.kind {
			case relayAccepted:
				accepted = true
			case relayRefused:
				r.logger.Printf("vm-launch refused the log relay for sidecar %d: %s", index, ev.text)
				return 1
			case relayStatus:
				if stopped != nil {
					return 128 + signalNumber(stopped)
				}
				return ev.status
			case relayGarbled:
				if stopped != nil {
					return 128 + signalNumber(stopped)
				}
				r.logger.Printf("the log stream from vm-launch held a line the relay cannot read: %q", ev.text)
				return 1
			case relayEnded:
				return r.ended(stopped)
			}
		}
	}
}

// ended is the relay's status when the stream ended without a status. A
// signal that already came, or comes within endWait, means Diego cancelled
// the relay, most often because the app exited first.
func (r relay) ended(stopped os.Signal) int {
	if stopped != nil {
		return 128 + signalNumber(stopped)
	}
	t := time.NewTimer(r.endWait)
	defer t.Stop()
	select {
	case sig := <-r.signals:
		return 128 + signalNumber(sig)
	case <-t.C:
		r.logger.Print("the log stream from vm-launch ended without the sidecar's exit status")
		return 1
	}
}

// stream reads the hub's answer to the hello and then its lines, and sends
// what it learns on events until quit closes. It writes each line to the
// relay's stdout or stderr, and flushes them before it sends the event that
// ends the stream, so every line is out before the relay exits. Write errors
// are ignored, because the status still decides the step.
func (r relay) stream(conn net.Conn, events chan<- relayEvent, quit <-chan struct{}) {
	send := func(ev relayEvent) bool {
		select {
		case events <- ev:
			return true
		case <-quit:
			return false
		}
	}
	rd := bufio.NewReaderSize(conn, 64<<10)
	answer, err := rd.ReadString('\n')
	switch {
	case err != nil:
		send(relayEvent{kind: relayEnded})
		return
	case answer == "ok\n":
		if !send(relayEvent{kind: relayAccepted}) {
			return
		}
	case len(answer) > 3 && answer[:3] == "no ":
		send(relayEvent{kind: relayRefused, text: answer[3 : len(answer)-1]})
		return
	default:
		send(relayEvent{kind: relayGarbled, text: answer})
		return
	}

	out := bufio.NewWriterSize(r.stdout, 64<<10)
	errOut := bufio.NewWriterSize(r.stderr, 64<<10)
	flush := func() {
		_ = out.Flush()
		_ = errOut.Flush()
	}
	// last is the stream of the line before. Pending lines of the other
	// stream go out first, so the two keep the order the hub sent them in.
	last := byte(0)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			// A last piece without a newline is not a whole message.
			flush()
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				r.logger.Printf("reading the log stream from vm-launch: %v", err)
			}
			send(relayEvent{kind: relayEnded})
			return
		}
		if len(line) < 2 || line[1] != ' ' {
			flush()
			send(relayEvent{kind: relayGarbled, text: line})
			return
		}
		text := line[2:]
		switch line[0] {
		case 'o':
			if last == 'e' {
				_ = errOut.Flush()
			}
			_, _ = out.WriteString(text)
		case 'e':
			if last == 'o' {
				_ = out.Flush()
			}
			_, _ = errOut.WriteString(text)
		case 'x':
			flush()
			status, err := strconv.Atoi(text[:len(text)-1])
			if err != nil || status < 0 || status > 255 {
				send(relayEvent{kind: relayGarbled, text: line})
				return
			}
			send(relayEvent{kind: relayStatus, status: status})
			return
		default:
			flush()
			send(relayEvent{kind: relayGarbled, text: line})
			return
		}
		last = line[0]
		// Lines go out as soon as the hub has sent no more for now, so a
		// quiet sidecar's lines never wait in the relay.
		if rd.Buffered() == 0 {
			flush()
		}
	}
}
