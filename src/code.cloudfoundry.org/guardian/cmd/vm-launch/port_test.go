//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// listenRecorder records the listen states a serial filter passes on.
type listenRecorder struct {
	mu     sync.Mutex
	states []bool
}

func (r *listenRecorder) record(up bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states = append(r.states, up)
}

func (r *listenRecorder) got() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.states...)
}

// feedListen pushes chunks through a serial filter that passes listen lines
// to a recorder, finishes it, and returns the filter, its output, and the
// listen states.
func feedListen(chunks ...string) (*serialFilter, string, []bool) {
	var out bytes.Buffer
	var rec listenRecorder
	f := newSerialFilter(&out, testNonce)
	f.onListen(testNonce, rec.record)
	for _, c := range chunks {
		n, err := f.Write([]byte(c))
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(len(c)))
	}
	f.finish()
	return f, out.String(), rec.got()
}

var _ = Describe("listen lines on the serial console", func() {
	listen := "RVM_LISTEN_" + testNonce + "="

	// console is a run with listen lines at the start of a line, after
	// output with no newline yet, and malformed ones that are output.
	console := "boot " + listen + "1\r\n" +
		"RVM_START_" + testNonce + "\r\n" +
		"one\r\n" +
		listen + "1\r\n" +
		"partial" + listen + "0\r\n" +
		"rest\r\n" +
		listen + "2\r\n" +
		listen + "1x\r\n" +
		listen + "\r\n" +
		listen + "1\n" +
		"RVM_EXIT_" + testNonce + "=7\r\n" +
		listen + "0\r\n"
	wantOut := "one\npartialrest\n" + listen + "2\n" + listen + "1x\n" + listen + "\n"
	wantStates := []bool{true, false, true}

	It("passes each listen line of the run to the callback and keeps the output around it", func() {
		f, out, states := feedListen(console)
		Expect(out).To(Equal(wantOut))
		Expect(states).To(Equal(wantStates))
		Expect(f.markerFound()).To(BeTrue())
		Expect(f.status).To(Equal(7))
	})

	It("gives the same result however the console is split", func() {
		for i := 0; i <= len(console); i++ {
			_, out, states := feedListen(console[:i], console[i:])
			Expect(out).To(Equal(wantOut), "split at %d", i)
			Expect(states).To(Equal(wantStates), "split at %d", i)
		}
		chunks := make([]string, len(console))
		for i := range console {
			chunks[i] = console[i : i+1]
		}
		_, out, states := feedListen(chunks...)
		Expect(out).To(Equal(wantOut))
		Expect(states).To(Equal(wantStates))
	})

	It("treats a listen line cut off by the end of the console as output", func() {
		for _, tail := range []string{"", "1", "1\r"} {
			start := "RVM_START_" + testNonce + "\n"
			_, out, states := feedListen(start + "x" + listen + tail)
			Expect(out).To(Equal("x"+listen+tail), "tail %q", tail)
			Expect(states).To(BeEmpty(), "tail %q", tail)
		}
	})

	It("finds the exit marker right after a listen line in the same write", func() {
		f, out, states := feedListen("RVM_START_" + testNonce + "\n" + listen + "1\nRVM_EXIT_" + testNonce + "=0\n")
		Expect(out).To(BeEmpty())
		Expect(states).To(Equal([]bool{true}))
		Expect(f.status).To(Equal(0))
	})

	It("leaves listen lines in the output when nothing asked for them", func() {
		f, out := feed("RVM_START_"+testNonce+"\n", listen+"1\r\n", "RVM_EXIT_"+testNonce+"=0\n")
		Expect(out).To(Equal(listen + "1\n"))
		Expect(f.markerFound()).To(BeTrue())
	})

	DescribeTable("parses the bytes after the tag",
		func(b string, up bool, n int, ok, needMore bool) {
			gotUp, gotN, gotOK, gotMore := parseListen([]byte(b))
			Expect([]any{gotUp, gotN, gotOK, gotMore}).To(Equal([]any{up, n, ok, needMore}))
		},
		Entry("nothing yet", "", false, 0, false, true),
		Entry("a digit without its line ending", "1", false, 0, false, true),
		Entry("a CR without its LF", "0\r", false, 0, false, true),
		Entry("1 and LF", "1\nmore", true, 2, true, false),
		Entry("0 and CRLF", "0\r\nmore", false, 3, true, false),
		Entry("another digit", "2\n", false, 0, false, false),
		Entry("two digits", "10\n", false, 0, false, false),
		Entry("a CR and something else", "1\rx", false, 0, false, false),
	)
})

// fakeOpener is a portOpener that records its calls. open, when set, runs
// inside openPort and returns its error.
type fakeOpener struct {
	mu       sync.Mutex
	calls    []string
	open     func() error
	closeErr error
}

func (o *fakeOpener) openPort() error {
	o.mu.Lock()
	open := o.open
	o.mu.Unlock()
	var err error
	if open != nil {
		err = open()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, "open")
	return err
}

func (o *fakeOpener) closePort() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, "close")
	return o.closeErr
}

func (o *fakeOpener) got() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.calls...)
}

var _ = Describe("the port gate", func() {
	var (
		opener *fakeOpener
		logBuf *safeBuffer
		gate   *portGate
	)

	BeforeEach(func() {
		opener = &fakeOpener{}
		logBuf = &safeBuffer{}
	})

	start := func() {
		gate = startPortGate(opener, 8080, log.New(logBuf, "", 0))
		DeferCleanup(gate.end)
	}

	It("starts closed, opens when the guest listens, and closes when it stops", func() {
		start()
		Consistently(opener.got, 100*time.Millisecond).Should(BeEmpty())
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open"}))
		gate.set(true)
		gate.set(false)
		Eventually(opener.got).Should(Equal([]string{"open", "close"}))
		gate.set(false)
		Consistently(opener.got, 100*time.Millisecond).Should(Equal([]string{"open", "close"}))
		Expect(logBuf.String()).To(Equal("the guest listens on port 8080; it is open in the container\n" +
			"the guest no longer listens on port 8080; it is closed in the container\n"))
	})

	It("acts on the latest state only, and never blocks the guest console", func() {
		release := make(chan struct{})
		opening := make(chan struct{}, 1)
		opener.open = func() error {
			opening <- struct{}{}
			<-release
			return nil
		}
		start()
		// A spec that fails before it releases the open must not leave
		// the gate stuck in it, or the gate's cleanup never returns.
		var releaseOnce sync.Once
		DeferCleanup(func() { releaseOnce.Do(func() { close(release) }) })
		gate.set(true)
		Eventually(opening).Should(Receive())
		done := make(chan struct{})
		go func() {
			for i := 0; i < 100; i++ {
				gate.set(i%2 == 0)
			}
			gate.set(false)
			close(done)
		}()
		Eventually(done).Should(BeClosed())
		releaseOnce.Do(func() { close(release) })
		Eventually(opener.got).Should(Equal([]string{"open", "close"}))
		Consistently(opener.got, 100*time.Millisecond).Should(Equal([]string{"open", "close"}))
	})

	It("names the conflict when another process listens on the port, and tries again at the next report", func() {
		opener.open = func() error {
			return &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
		}
		start()
		gate.set(true)
		Eventually(logBuf.String).Should(ContainSubstring("port 8080 already in use in this container; VM backends run one app process per container\n"))
		Expect(logBuf.String()).To(HavePrefix("the guest listens on port 8080, but vm-launch could not open it in the container: listen tcp: bind: address already in use\n"))
		gate.set(false)
		Consistently(opener.got, 100*time.Millisecond).Should(Equal([]string{"open"}))

		opener.mu.Lock()
		opener.open = nil
		opener.mu.Unlock()
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open", "open"}))
		Eventually(logBuf.String).Should(HaveSuffix("the guest listens on port 8080; it is open in the container\n"))
	})

	It("logs a failure that is not a conflict without the conflict line", func() {
		opener.open = func() error { return errors.New("QMP human-monitor-command: GenericError: boom") }
		start()
		gate.set(true)
		Eventually(logBuf.String).Should(Equal("the guest listens on port 8080, but vm-launch could not open it in the container: QMP human-monitor-command: GenericError: boom\n"))
		Consistently(logBuf.String, 100*time.Millisecond).ShouldNot(ContainSubstring("already in use"))
	})

	It("logs a port it could not close", func() {
		opener.closeErr = errors.New("QEMU did not remove the forwarding rule: nope")
		start()
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open"}))
		gate.set(false)
		Eventually(logBuf.String).Should(ContainSubstring("closing port 8080 in the container: QEMU did not remove the forwarding rule: nope\n"))
	})

	It("closes the port for good at shutDown", func() {
		start()
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open"}))
		gate.shutDown()
		gate.shutDown()
		Eventually(opener.got).Should(Equal([]string{"open", "close"}))
		gate.set(false)
		gate.set(true)
		Consistently(opener.got, 100*time.Millisecond).Should(Equal([]string{"open", "close"}))
		Expect(logBuf.String()).To(Equal("the guest listens on port 8080; it is open in the container\n"))
	})

	It("never opens a port that was closed when shutDown came", func() {
		start()
		gate.shutDown()
		gate.set(true)
		Consistently(opener.got, 100*time.Millisecond).Should(BeEmpty())
	})

	It("leaves the port as it is at end, and is silent after it", func() {
		start()
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open"}))
		gate.end()
		gate.end()
		gate.set(false)
		gate.shutDown()
		Consistently(opener.got, 100*time.Millisecond).Should(Equal([]string{"open"}))
		Expect(logBuf.String()).To(Equal("the guest listens on port 8080; it is open in the container\n"))
	})

	It("ends while an open is in progress without logging its outcome", func() {
		release := make(chan struct{})
		opening := make(chan struct{}, 1)
		opener.open = func() error {
			opening <- struct{}{}
			<-release
			return errors.New("the hypervisor is gone")
		}
		start()
		var releaseOnce sync.Once
		DeferCleanup(func() { releaseOnce.Do(func() { close(release) }) })
		gate.set(true)
		Eventually(opening).Should(Receive())
		ended := make(chan struct{})
		go func() {
			gate.end()
			close(ended)
		}()
		Consistently(ended, 50*time.Millisecond).ShouldNot(BeClosed())
		releaseOnce.Do(func() { close(release) })
		Eventually(ended).Should(BeClosed())
		Expect(logBuf.String()).To(BeEmpty())
	})
})

// fakeQMP is QEMU's end of a QMP monitor connection, run by the spec.
type fakeQMP struct {
	conn net.Conn
	r    *bufio.Reader
}

func newFakeQMP() (*qmpMonitor, *fakeQMP) {
	ours, theirs := net.Pipe()
	DeferCleanup(ours.Close)
	DeferCleanup(theirs.Close)
	return newQMPMonitor(ours), &fakeQMP{conn: theirs, r: bufio.NewReader(theirs)}
}

func (q *fakeQMP) send(msg string) {
	_, err := q.conn.Write([]byte(msg + "\r\n"))
	Expect(err).NotTo(HaveOccurred())
}

// recv reads one request and returns it re-encoded with sorted keys.
func (q *fakeQMP) recv() string {
	line, err := q.r.ReadBytes('\n')
	Expect(err).NotTo(HaveOccurred())
	var v any
	Expect(json.Unmarshal(line, &v)).To(Succeed())
	b, err := json.Marshal(v)
	Expect(err).NotTo(HaveOccurred())
	return string(b)
}

// serve runs script in the background as QEMU's side and returns a
// channel that closes when it is done.
func (q *fakeQMP) serve(script func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer GinkgoRecover()
		defer close(done)
		script()
	}()
	return done
}

const fakeGreeting = `{"QMP": {"version": {"qemu": {"micro": 0, "minor": 2, "major": 9}, "package": ""}, "capabilities": ["oob"]}}`

func humanRequest(line string) string {
	b, err := json.Marshal(map[string]any{"execute": "human-monitor-command", "arguments": map[string]string{"command-line": line}})
	Expect(err).NotTo(HaveOccurred())
	return string(b)
}

var _ = Describe("the QMP monitor", func() {
	It("negotiates capabilities once, skips events, and returns the command output", func() {
		m, qemu := newFakeQMP()
		done := qemu.serve(func() {
			qemu.send(fakeGreeting)
			Expect(qemu.recv()).To(Equal(`{"execute":"qmp_capabilities"}`))
			qemu.send(`{"event": "RESUME", "data": {}, "timestamp": {"seconds": 1, "microseconds": 0}}`)
			qemu.send(`{"return": {}}`)
			Expect(qemu.recv()).To(Equal(humanRequest("info network")))
			qemu.send(`{"event": "NIC_RX_FILTER_CHANGED", "data": {}, "timestamp": {"seconds": 1, "microseconds": 0}}`)
			qemu.send(`{"return": "n0: user\r\n"}`)
			Expect(qemu.recv()).To(Equal(humanRequest("hostfwd_add n0 tcp:0.0.0.0:8080-10.0.2.15:8080")))
			qemu.send(`{"return": ""}`)
		})
		Expect(m.humanCommand("info network")).To(Equal("n0: user\r\n"))
		Expect(m.humanCommand("hostfwd_add n0 tcp:0.0.0.0:8080-10.0.2.15:8080")).To(Equal(""))
		Eventually(done).Should(BeClosed())
	})

	It("returns an error reply as an error and stays usable", func() {
		m, qemu := newFakeQMP()
		done := qemu.serve(func() {
			qemu.send(fakeGreeting)
			qemu.recv()
			qemu.send(`{"return": {}}`)
			qemu.recv()
			qemu.send(`{"error": {"class": "GenericError", "desc": "Invalid netdev"}}`)
			qemu.recv()
			qemu.send(`{"return": "ok"}`)
		})
		_, err := m.humanCommand("hostfwd_add x tcp:0.0.0.0:1-10.0.2.15:1")
		Expect(err).To(MatchError("QMP human-monitor-command: GenericError: Invalid netdev"))
		Expect(m.humanCommand("info network")).To(Equal("ok"))
		Eventually(done).Should(BeClosed())
	})

	It("fails for good when the first message is not a greeting", func() {
		m, qemu := newFakeQMP()
		qemu.serve(func() { qemu.send(`{"return": {}}`) })
		_, err := m.humanCommand("info network")
		Expect(err).To(MatchError("QMP: the first message is not a greeting"))
		_, again := m.humanCommand("info network")
		Expect(again).To(BeIdenticalTo(err))
	})

	It("fails for good when QEMU does not reply in time, so a late reply is never taken for the next one", func() {
		m, qemu := newFakeQMP()
		m.timeout = 100 * time.Millisecond
		done := qemu.serve(func() {
			qemu.send(fakeGreeting)
			qemu.recv()
			qemu.send(`{"return": {}}`)
			qemu.recv()
		})
		_, err := m.humanCommand("info network")
		Expect(err).To(MatchError(ContainSubstring("QMP human-monitor-command: reading the reply: ")))
		Expect(errors.Is(err, os.ErrDeadlineExceeded)).To(BeTrue(), err.Error())
		Eventually(done).Should(BeClosed())
		_, again := m.humanCommand("info network")
		Expect(again).To(BeIdenticalTo(err))
	})

	It("fails when QEMU closes its end of the QMP socket", func() {
		conn, theirs, err := newQMPSocket()
		Expect(err).NotTo(HaveOccurred())
		defer conn.Close()
		Expect(theirs.Close()).To(Succeed())
		_, err = newQMPMonitor(conn).humanCommand("info network")
		Expect(err).To(MatchError("QMP: reading the greeting: EOF"))
	})

	It("fails for a reply that is neither a return nor an error, or a return that is not text", func() {
		m, qemu := newFakeQMP()
		qemu.serve(func() {
			qemu.send(fakeGreeting)
			qemu.recv()
			qemu.send(`{"return": {}}`)
			qemu.recv()
			qemu.send(`{"id": 1}`)
		})
		_, err := m.humanCommand("info network")
		Expect(err).To(MatchError("QMP human-monitor-command: a reply with neither a return nor an error"))

		m, qemu = newFakeQMP()
		qemu.serve(func() {
			qemu.send(fakeGreeting)
			qemu.recv()
			qemu.send(`{"return": {}}`)
			qemu.recv()
			qemu.send(`{"return": {}}`)
		})
		_, err = m.humanCommand("info network")
		Expect(err).To(MatchError(ContainSubstring("QMP human-monitor-command: the return is not a string: ")))
	})

	Describe("the QEMU forwarding rule", func() {
		// ruleRun opens or closes a qmpPort for 8080 against a QEMU that
		// answers with reply, and returns the request QEMU got.
		ruleRun := func(open bool, reply string) (string, error) {
			m, qemu := newFakeQMP()
			var got string
			done := qemu.serve(func() {
				qemu.send(fakeGreeting)
				qemu.recv()
				qemu.send(`{"return": {}}`)
				got = qemu.recv()
				qemu.send(reply)
			})
			p := qmpPort{monitor: m, port: 8080}
			var err error
			if open {
				err = p.openPort()
			} else {
				err = p.closePort()
			}
			Eventually(done).Should(BeClosed())
			return got, err
		}

		It("adds a rule from the container's port to the guest's", func() {
			got, err := ruleRun(true, `{"return": ""}`)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(humanRequest("hostfwd_add n0 tcp:0.0.0.0:8080-10.0.2.15:8080")))
		})

		It("reports a rule QEMU could not set up as a port conflict", func() {
			_, err := ruleRun(true, `{"return": "Could not set up host forwarding rule 'tcp:0.0.0.0:8080-10.0.2.15:8080'\r\n"}`)
			Expect(err).To(MatchError("QEMU could not set up the forwarding rule: Could not set up host forwarding rule 'tcp:0.0.0.0:8080-10.0.2.15:8080'"))
			Expect(isPortConflict(err)).To(BeTrue())
		})

		It("removes the rule", func() {
			got, err := ruleRun(false, `{"return": "host forwarding rule for tcp:0.0.0.0:8080 removed\r\n"}`)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(humanRequest("hostfwd_remove n0 tcp:0.0.0.0:8080")))
		})

		It("fails when QEMU did not remove the rule", func() {
			_, err := ruleRun(false, `{"return": "host forwarding rule for tcp:0.0.0.0:8080 not found\r\n"}`)
			Expect(err).To(MatchError("QEMU did not remove the forwarding rule: host forwarding rule for tcp:0.0.0.0:8080 not found"))
			Expect(isPortConflict(err)).To(BeFalse())
		})
	})

	It("connects vm-launch's end of the QMP socket to the hypervisor's, which closes on exec", func() {
		conn, theirs, err := newQMPSocket()
		Expect(err).NotTo(HaveOccurred())
		defer conn.Close()
		defer theirs.Close()
		flags, err := unix.FcntlInt(theirs.Fd(), unix.F_GETFD, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(flags & unix.FD_CLOEXEC).NotTo(BeZero())

		_, err = theirs.Write([]byte("ping\n"))
		Expect(err).NotTo(HaveOccurred())
		line, err := bufio.NewReader(conn).ReadString('\n')
		Expect(err).NotTo(HaveOccurred())
		Expect(line).To(Equal("ping\n"))
		_, err = conn.Write([]byte("pong\n"))
		Expect(err).NotTo(HaveOccurred())
		buf := make([]byte, 5)
		_, err = io.ReadFull(theirs, buf)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(buf)).To(Equal("pong\n"))
	})
})

var _ = Describe("the port reservation", func() {
	// unusedPort returns a port nothing listens on.
	unusedPort := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}

	It("refuses connections to the port while it holds it, and lets the port proxy listen alongside", func() {
		port := unusedPort()
		r, err := reservePort(port)
		Expect(err).NotTo(HaveOccurred())
		defer r.Close()
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		_, err = net.Dial("tcp", addr)
		Expect(err).To(MatchError(ContainSubstring("connection refused")))

		p := newProxy(unusedAddr(), testDialPolicy, log.New(io.Discard, "", 0))
		defer p.Close()
		Expect(p.Listen("0.0.0.0:" + strconv.Itoa(port))).To(Succeed())
		c, err := net.Dial("tcp", addr)
		Expect(err).NotTo(HaveOccurred())
		c.Close()
		p.StopListening()
		_, err = net.Dial("tcp", addr)
		Expect(err).To(MatchError(ContainSubstring("connection refused")))
	})

	It("fails with EADDRINUSE when another process listens on the port", func() {
		// "tcp" listens on [::] for IPv6 and IPv4 alike, as most servers do.
		for _, network := range []string{"tcp4", "tcp"} {
			l, err := net.Listen(network, ":0")
			Expect(err).NotTo(HaveOccurred())
			port := l.Addr().(*net.TCPAddr).Port
			_, err = reservePort(port)
			l.Close()
			Expect(err).To(MatchError(ContainSubstring("reserving port "+strconv.Itoa(port)+": bind: address already in use")), network)
			Expect(errors.Is(err, syscall.EADDRINUSE)).To(BeTrue(), network)
		}
	})

	It("fails with EADDRINUSE for a second reservation of the same port, and frees the port on Close", func() {
		port := unusedPort()
		r, err := reservePort(port)
		Expect(err).NotTo(HaveOccurred())
		_, err = reservePort(port)
		Expect(err).To(MatchError("reserving port " + strconv.Itoa(port) + ": listen unix @vm-launch-port-" + strconv.Itoa(port) + ": bind: address already in use"))
		Expect(errors.Is(err, syscall.EADDRINUSE)).To(BeTrue())

		Expect(r.Close()).To(Succeed())
		again, err := reservePort(port)
		Expect(err).NotTo(HaveOccurred())
		Expect(again.Close()).To(Succeed())
		l, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(port))
		Expect(err).NotTo(HaveOccurred())
		l.Close()
	})
})

var _ = Describe("the guest listen watcher", func() {
	// procNetLine is a /proc/net/tcp or tcp6 line for a socket at local in
	// state st (0A is LISTEN).
	procNetLine := func(local, st string) string {
		return "   0: " + local + " 00000000:0000 " + st + " 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0\n"
	}
	procNetHeader := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	wildcard6 := strings.Repeat("0", 32)

	// watcherPath returns a PATH for shell holding the commands the watcher
	// runs, as /bin holds them in the guest.
	watcherPath := func(shell guestShell) string {
		if len(shell.argv) == 1 {
			return "/usr/bin:/bin"
		}
		bin := guestBin(shell)
		for _, applet := range []string{"grep", "printf", "sleep", "kill"} {
			Expect(os.Symlink(shell.argv[0], filepath.Join(bin, applet))).To(Succeed())
		}
		return bin
	}

	// noTable stands for a /proc/net table the guest kernel lacks.
	const noTable = "\x00"

	// watchRound runs one round of the watcher for port, after the shell
	// code prelude, against fake /proc/net/tcp and tcp6 contents, either of
	// which may be noTable. The watcher starts in the state wasUp, "0" or
	// "1", and watchRound returns what it printed.
	watchRound := func(shell guestShell, port int, tcp, tcp6, prelude, wasUp string) string {
		dir := GinkgoT().TempDir()
		tcpPath, tcp6Path := filepath.Join(dir, "tcp"), filepath.Join(dir, "tcp6")
		for path, table := range map[string]string{tcpPath: tcp, tcp6Path: tcp6} {
			if table != noTable {
				Expect(os.WriteFile(path, []byte(procNetHeader+table), 0o644)).To(Succeed())
			}
		}
		watch := guestListenWatch(testNonce)
		for _, s := range []string{" /proc/net/tcp /proc/net/tcp6;", "\n\t\trvm_up=0\n", "\n\t\t\tsleep 1\n"} {
			Expect(watch).To(ContainSubstring(s))
		}
		watch = strings.NewReplacer(
			" /proc/net/tcp /proc/net/tcp6;", " "+tcpPath+" "+tcp6Path+";",
			"\n\t\trvm_up=0\n", "\n\t\trvm_up="+wasUp+"\n",
			"\n\t\t\tsleep 1\n", "\n\t\t\texit 0\n",
		).Replace(watch)
		c := exec.Command(shell.argv[0], append(shell.argv[1:], "-c", prelude+watch+`wait "$rvm_watch"`+"\n")...)
		c.Env = []string{"PATH=" + watcherPath(shell), "RVM_PORT=" + strconv.Itoa(port)}
		out, err := c.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), "%s: %s", shell.name, out)
		return string(out)
	}

	// checkOnce runs one round of the watcher, from the state not
	// listening, with both tables present.
	checkOnce := func(shell guestShell, port int, tcp, tcp6 string) string {
		return watchRound(shell, port, tcp, tcp6, "", "0")
	}

	listening := "RVM_LISTEN_" + testNonce + "=1\n"

	type socketCase struct {
		port      int
		tcp, tcp6 string
		want      bool
	}
	cases := map[string]socketCase{
		"0.0.0.0":                              {port: 8080, tcp: procNetLine("00000000:1F90", "0A"), want: true},
		"a guest address":                      {port: 8080, tcp: procNetLine("0F02000A:1F90", "0A"), want: true},
		"127.0.0.1":                            {port: 8080, tcp: procNetLine("0100007F:1F90", "0A")},
		"127.1.2.3":                            {port: 8080, tcp: procNetLine("0302017F:1F90", "0A")},
		"an address ending in 7F":              {port: 8080, tcp: procNetLine("7F02000A:1F90", "0A"), want: true},
		"a socket that is not listening":       {port: 8080, tcp: procNetLine("00000000:1F90", "01")},
		"another port":                         {port: 8080, tcp: procNetLine("00000000:1F91", "0A") + procNetLine("00000000:01F9", "0A")},
		"a port of fewer than four hex digits": {port: 255, tcp: procNetLine("00000000:00FF", "0A"), want: true},
		"[::]":                                 {port: 8080, tcp6: procNetLine(wildcard6+":1F90", "0A"), want: true},
		"[::1]":                                {port: 8080, tcp6: procNetLine("00000000000000000000000001000000:1F90", "0A")},
		"[::ffff:127.0.0.1]":                   {port: 8080, tcp6: procNetLine("0000000000000000FFFF00000100007F:1F90", "0A")},
		"[::ffff:10.0.2.15]":                   {port: 8080, tcp6: procNetLine("0000000000000000FFFF00000F02000A:1F90", "0A"), want: true},
		"loopback and 0.0.0.0":                 {port: 8080, tcp: procNetLine("0100007F:1F90", "0A") + procNetLine("00000000:1F90", "0A"), want: true},
		"no sockets":                           {port: 8080},
	}

	DescribeTable("reports a listening socket on the port at any address but loopback",
		func(shellOf func() guestShell) {
			shell := shellOf()
			for name, c := range cases {
				out := checkOnce(shell, c.port, c.tcp, c.tcp6)
				if c.want {
					Expect(out).To(Equal(listening), "%s: %s", shell.name, name)
				} else {
					Expect(out).To(BeEmpty(), "%s: %s", shell.name, name)
				}
			}
		},
		shellEntries(""),
	)

	DescribeTable("reads only the tables the guest kernel has",
		func(shellOf func() guestShell) {
			shell := shellOf()
			Expect(watchRound(shell, 8080, procNetLine("00000000:1F90", "0A"), noTable, "", "0")).To(Equal(listening), shell.name)
			Expect(watchRound(shell, 8080, noTable, procNetLine(wildcard6+":1F90", "0A"), "", "0")).To(Equal(listening), shell.name)
			Expect(watchRound(shell, 8080, noTable, noTable, "", "1")).To(Equal("RVM_LISTEN_"+testNonce+"=0\n"), shell.name)
		},
		shellEntries(""),
	)

	DescribeTable("keeps its state when a grep fails instead of answering",
		func(shellOf func() guestShell) {
			shell := shellOf()
			up := procNetLine("00000000:1F90", "0A")
			// A shell function runs in place of the grep applet, and
			// "command grep" runs the applet. Status 2 is grep's error.
			for _, flags := range []string{"-hE", "-qvE"} {
				prelude := `grep() { case "$1" in ` + flags + `) return 2 ;; esac; command grep "$@"; }` + "\n"
				Expect(watchRound(shell, 8080, up, "", prelude, "1")).To(BeEmpty(), "%s: %s", shell.name, flags)
				Expect(watchRound(shell, 8080, up, "", prelude, "0")).To(BeEmpty(), "%s: %s", shell.name, flags)
			}
			Expect(watchRound(shell, 8080, "", "", "", "1")).To(Equal("RVM_LISTEN_"+testNonce+"=0\n"), shell.name)
		},
		shellEntries(""),
	)

	It("does nothing in a guest without a port", func() {
		c := exec.Command("/bin/sh", "-c", guestListenWatch(testNonce)+guestListenStop+`echo "watch=[$rvm_watch]"`)
		c.Env = []string{"PATH=/usr/bin:/bin"}
		out, err := c.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(out))
		Expect(string(out)).To(Equal("watch=[]\n"))
	})

	DescribeTable("follows real sockets and stops before /init reports the status",
		func(shellOf func() guestShell) {
			shell := shellOf()
			loopback, err := net.Listen("tcp4", "127.0.0.1:0")
			Expect(err).NotTo(HaveOccurred())
			defer loopback.Close()
			port := loopback.Addr().(*net.TCPAddr).Port

			script := guestListenWatch(testNonce) + "read rvm_go\n" + guestListenStop + "echo stopped\n"
			c := exec.Command(shell.argv[0], append(shell.argv[1:], "-c", script)...)
			c.Env = []string{"PATH=" + watcherPath(shell), "RVM_PORT=" + strconv.Itoa(port)}
			stdin, err := c.StdinPipe()
			Expect(err).NotTo(HaveOccurred())
			stdout, err := c.StdoutPipe()
			Expect(err).NotTo(HaveOccurred())
			c.Stderr = GinkgoWriter
			// The watcher is a subshell that holds the output pipes open, so
			// the cleanup kills the whole process group, not the shell
			// alone, and Wait does not wait for a watcher that never ends.
			c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			Expect(c.Start()).To(Succeed())
			DeferCleanup(func() { _ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL); _ = c.Wait() })
			lines := make(chan string, 16)
			go func() {
				defer close(lines)
				s := bufio.NewScanner(stdout)
				for s.Scan() {
					lines <- s.Text()
				}
			}()

			Consistently(lines, 1500*time.Millisecond).ShouldNot(Receive())
			wild, err := net.Listen("tcp6", "[::]:"+strconv.Itoa(port))
			Expect(err).NotTo(HaveOccurred())
			Eventually(lines, 5*time.Second).Should(Receive(Equal("RVM_LISTEN_" + testNonce + "=1")))
			Expect(wild.Close()).To(Succeed())
			Eventually(lines, 5*time.Second).Should(Receive(Equal("RVM_LISTEN_" + testNonce + "=0")))

			_, err = stdin.Write([]byte("\n"))
			Expect(err).NotTo(HaveOccurred())
			Eventually(lines, 3*time.Second).Should(Receive(Equal("stopped")))
			// The watcher's last sleep may hold the output open for up to
			// a second after the watcher itself is gone.
			Eventually(lines, 3*time.Second).Should(BeClosed())
			Expect(c.Wait()).To(Succeed())
		},
		shellEntries(""),
	)
})
