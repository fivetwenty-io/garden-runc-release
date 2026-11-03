//go:build linux

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
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
	"sync/atomic"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// testAgentKey is the boot key of the agents the specs run, as hex.
var testAgentKey = strings.Repeat("ab", agentKeyBytes)

// testAgentExec runs a session the way busyboxExec does, with the cat of
// the container the specs run in.
func testAgentExec(p guestProcess) string {
	line := ""
	for _, env := range p.envPaths {
		line += ". " + env + " && "
	}
	return line + `eval "set -- $(cat ` + p.argvPath + `)" && cd ` + shellQuote(p.dir) + ` && exec "$@"`
}

// newTestAgent returns an agent that runs sessions on the container's own
// shell as the specs' user, in a working directory of its own, with an app
// environment that sets APP_VAR.
func newTestAgent() *guestAgent {
	dir := GinkgoT().TempDir()
	appEnv := filepath.Join(dir, "app-env")
	Expect(os.WriteFile(appEnv, []byte("export APP_VAR=app\n"), 0o600)).To(Succeed())
	cwd := filepath.Join(dir, "home")
	Expect(os.Mkdir(cwd, 0o755)).To(Succeed())
	return &guestAgent{
		key:      []byte(testAgentKey),
		root:     "/",
		cwd:      cwd,
		exec:     testAgentExec,
		envPaths: []string{appEnv},
		uid:      os.Getuid(),
		gid:      os.Getgid(),
		shell:    []string{"/bin/sh"},
		baseEnv:  []string{"PATH=/usr/local/bin:/usr/bin:/bin"},
		runDir:   filepath.Join(dir, "run"),
		ptmx:     "/dev/ptmx",
		ptsDir:   "/dev/pts",
		dial:     net.DialTimeout,
		logger:   log.New(GinkgoWriter, "guest agent: ", 0),
		sessions: make(chan struct{}, guestAgentMaxSessions),
		forwards: make(chan struct{}, guestAgentMaxForwards),
		pending:  make(chan struct{}, guestAgentMaxPending),
	}
}

// agentSocketPair returns the two ends of a connected Unix stream socket.
func agentSocketPair() (*net.UnixConn, *net.UnixConn) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	Expect(err).NotTo(HaveOccurred())
	var conns [2]*net.UnixConn
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "agent-pair")
		c, err := net.FileConn(f)
		f.Close()
		Expect(err).NotTo(HaveOccurred())
		conns[i] = c.(*net.UnixConn)
	}
	return conns[0], conns[1]
}

// serveAgent hands one end of a new connection to a and returns the other
// end and a channel that closes once a is done with the connection.
func serveAgent(a *guestAgent) (*net.UnixConn, chan struct{}) {
	agentSide, client := agentSocketPair()
	DeferCleanup(func() { _ = client.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handle(agentSide)
	}()
	return client, done
}

// agentTestSession is a client's side of one session or forward.
type agentTestSession struct {
	conn           *net.UnixConn
	fw             *agentFrameWriter
	stdout, stderr *lockedBuffer
	exit           chan agentExit
	ended          chan struct{}
}

// startAgentSession connects to a, sends the hello with key and then req,
// sends the go once the agent accepts, as the relay does, and returns once
// the agent has answered. Frames that follow the answer are collected until
// the connection ends.
func startAgentSession(a *guestAgent, key string, req agentRequest) (*agentTestSession, agentReady, chan struct{}) {
	conn, done := serveAgent(a)
	s := &agentTestSession{conn: conn, fw: &agentFrameWriter{w: conn}, stdout: new(lockedBuffer), stderr: new(lockedBuffer), exit: make(chan agentExit, 1), ended: make(chan struct{})}
	Expect(s.fw.write(agentFrameHello, []byte(key))).To(Succeed())
	Expect(s.fw.writeJSON(agentFrameRequest, req)).To(Succeed())
	typ, payload, err := readAgentFrame(conn)
	Expect(err).NotTo(HaveOccurred())
	if typ == agentFrameAccepted {
		Expect(s.fw.write(agentFrameGo, nil)).To(Succeed())
		typ, payload, err = readAgentFrame(conn)
		Expect(err).NotTo(HaveOccurred())
	}
	Expect(typ).To(Equal(agentFrameReady))
	var ready agentReady
	Expect(json.Unmarshal(payload, &ready)).To(Succeed())
	go func() {
		defer GinkgoRecover()
		defer close(s.ended)
		for {
			typ, payload, err := readAgentFrame(conn)
			if err != nil {
				return
			}
			switch typ {
			case agentFrameStdout, agentFrameData:
				_, _ = s.stdout.Write(payload)
			case agentFrameStderr:
				_, _ = s.stderr.Write(payload)
			case agentFrameExit:
				var exit agentExit
				Expect(json.Unmarshal(payload, &exit)).To(Succeed())
				s.exit <- exit
			case agentFrameDataEnd:
				_, _ = s.stderr.Write([]byte("data end"))
			}
		}
	}()
	return s, ready, done
}

// awaitExit returns how the session's process ended.
func (s *agentTestSession) awaitExit() agentExit {
	var exit agentExit
	Eventually(s.exit, 10*time.Second).Should(Receive(&exit))
	return exit
}

// readyFailConn is the agent's end of a connection whose write of the Ready
// frame fails once the session's process has written its pid to pidfile, as
// when the relay goes away just after the session starts. failed receives
// the time of the failure.
type readyFailConn struct {
	*net.UnixConn
	pidfile string
	failed  chan<- time.Time
}

func (c *readyFailConn) Write(p []byte) (int, error) {
	if len(p) == 0 || p[0] != agentFrameReady {
		return c.UnixConn.Write(p)
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if b, err := os.ReadFile(c.pidfile); err == nil && bytes.HasSuffix(b, []byte("\n")) {
			break
		}
	}
	c.failed <- time.Now()
	return 0, errors.New("the relay went away")
}

// upperServer listens on a local TCP port, and for each connection reads
// until the client ends its direction, then answers with what it read in
// upper case and " bye", and closes. It returns the port.
func upperServer() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				data, _ := io.ReadAll(c)
				_, _ = c.Write([]byte(strings.ToUpper(string(data)) + " bye"))
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// closedPort returns a local TCP port that nothing listens on.
func closedPort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	port := ln.Addr().(*net.TCPAddr).Port
	Expect(ln.Close()).To(Succeed())
	return port
}

var _ = Describe("the guest agent's frames", func() {
	It("reads back each frame it writes, and splits data at the most one frame carries", func() {
		var buf bytes.Buffer
		fw := &agentFrameWriter{w: &buf}
		Expect(fw.write(agentFrameSignal, []byte{15})).To(Succeed())
		Expect(fw.writeJSON(agentFrameExit, agentExit{Code: 3})).To(Succeed())
		Expect(fw.writeData(agentFrameStdout, bytes.Repeat([]byte("x"), agentMaxData+1))).To(Succeed())
		Expect(fw.write(agentFrameStdinEnd, nil)).To(Succeed())

		typ, payload, err := readAgentFrame(&buf)
		Expect(err).NotTo(HaveOccurred())
		Expect(typ).To(Equal(agentFrameSignal))
		Expect(payload).To(Equal([]byte{15}))
		typ, payload, err = readAgentFrame(&buf)
		Expect(err).NotTo(HaveOccurred())
		Expect(typ).To(Equal(agentFrameExit))
		Expect(string(payload)).To(Equal(`{"code":3}`))
		for _, want := range []int{agentMaxData, 1} {
			typ, payload, err = readAgentFrame(&buf)
			Expect(err).NotTo(HaveOccurred())
			Expect(typ).To(Equal(agentFrameStdout))
			Expect(payload).To(HaveLen(want))
		}
		typ, payload, err = readAgentFrame(&buf)
		Expect(err).NotTo(HaveOccurred())
		Expect(typ).To(Equal(agentFrameStdinEnd))
		Expect(payload).To(BeEmpty())
		_, _, err = readAgentFrame(&buf)
		Expect(err).To(MatchError(io.EOF))
	})

	It("refuses a frame longer than its type allows before it reads the payload, and refuses unknown types", func() {
		header := func(typ byte, size uint32) []byte {
			b := []byte{typ, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(b[1:], size)
			return b
		}
		for typ, size := range map[byte]uint32{
			agentFrameHello:    agentMaxHello + 1,
			agentFrameRequest:  agentMaxRequest + 1,
			agentFrameStdin:    agentMaxData + 1,
			agentFrameSignal:   2,
			agentFrameResize:   5,
			agentFrameDataEnd:  1,
			agentFrameStdinEnd: 1,
			agentFrameAccepted: 1,
			agentFrameGo:       1,
		} {
			_, _, err := readAgentFrame(bytes.NewReader(header(typ, size)))
			Expect(err).To(MatchError(errAgentFrameTooLarge), "type 0x%02x", typ)
		}
		_, _, err := readAgentFrame(bytes.NewReader(header(0x41, 0)))
		Expect(err).To(MatchError(ContainSubstring("unknown type 0x41")))

		_, err = readAgentFrameOf(bytes.NewReader(header(agentFrameRequest, 2)), agentFrameHello)
		Expect(err).To(MatchError(ContainSubstring("expected a frame of type 0x81 and got 0x82")))
		_, err = readAgentFrameOf(bytes.NewReader(header(agentFrameHello, agentMaxHello+1)), agentFrameHello)
		Expect(err).To(MatchError(errAgentFrameTooLarge))

		fw := &agentFrameWriter{w: io.Discard}
		Expect(fw.write(agentFrameSignal, []byte{1, 2})).To(MatchError(errAgentFrameTooLarge))
		Expect(fw.write(0x41, nil)).To(MatchError(errAgentFrameTooLarge))
	})

	It("gives every frame a type above 0x80, so a text line is never one", func() {
		for typ := agentFrameHello; typ <= agentFrameGo; typ++ {
			Expect(agentFrameLimit(typ)).To(BeNumerically(">=", 0), "type 0x%02x", typ)
		}
		for typ := 0; typ < 0x80; typ++ {
			Expect(agentFrameLimit(byte(typ))).To(Equal(-1))
		}
	})
})

var _ = Describe("the guest agent", func() {
	var a *guestAgent

	BeforeEach(func() {
		a = newTestAgent()
	})

	Describe("the handshake", func() {
		expectClosed := func(conn *net.UnixConn, done chan struct{}) {
			Eventually(done, 10*time.Second).Should(BeClosed())
			Expect(conn.SetReadDeadline(time.Now().Add(5 * time.Second))).To(Succeed())
			// A connection the agent closes with bytes it never read is
			// reset rather than ended.
			_, err := conn.Read(make([]byte, 1))
			Expect(err).To(Or(MatchError(io.EOF), MatchError(syscall.ECONNRESET)))
		}

		It("closes a connection whose hello holds another key, and runs nothing", func() {
			conn, done := serveAgent(a)
			fw := &agentFrameWriter{w: conn}
			Expect(fw.write(agentFrameHello, []byte(strings.Repeat("cd", agentKeyBytes)))).To(Succeed())
			// The agent may close the connection before the request arrives.
			_ = fw.writeJSON(agentFrameRequest, agentRequest{Kind: agentKindSession, Args: []string{"-c", "true"}})
			expectClosed(conn, done)
			Expect(a.runDir).NotTo(BeADirectory())
		})

		It("closes a connection whose first frame is not the hello, or whose hello is too long, without reading on", func() {
			conn, done := serveAgent(a)
			fw := &agentFrameWriter{w: conn}
			Expect(fw.writeJSON(agentFrameRequest, agentRequest{Kind: agentKindSession})).To(Succeed())
			expectClosed(conn, done)

			conn, done = serveAgent(a)
			header := []byte{agentFrameHello, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(header[1:], 1<<20)
			_, err := conn.Write(header)
			Expect(err).NotTo(HaveOccurred())
			expectClosed(conn, done)
		})

		It("answers a request it cannot read once the hello holds the boot's key", func() {
			conn, done := serveAgent(a)
			fw := &agentFrameWriter{w: conn}
			Expect(fw.write(agentFrameHello, []byte(testAgentKey))).To(Succeed())
			Expect(fw.write(agentFrameRequest, []byte("{not json"))).To(Succeed())
			payload, err := readAgentFrameOf(conn, agentFrameReady)
			Expect(err).NotTo(HaveOccurred())
			var ready agentReady
			Expect(json.Unmarshal(payload, &ready)).To(Succeed())
			Expect(ready.Error).To(HavePrefix("the guest agent could not read the request: "))
			Eventually(done, 10*time.Second).Should(BeClosed())
			Expect(a.runDir).NotTo(BeADirectory())
		})

		It("accepts a request and starts nothing until it has the go, and nothing at all when the go never comes", func() {
			marker := filepath.Join(GinkgoT().TempDir(), "ran")
			conn, done := serveAgent(a)
			fw := &agentFrameWriter{w: conn}
			Expect(fw.write(agentFrameHello, []byte(testAgentKey))).To(Succeed())
			Expect(fw.writeJSON(agentFrameRequest, agentRequest{Kind: agentKindSession, Args: []string{"-c", "echo ran >> " + shellQuote(marker)}})).To(Succeed())
			typ, payload, err := readAgentFrame(conn)
			Expect(err).NotTo(HaveOccurred())
			Expect(typ).To(Equal(agentFrameAccepted))
			Expect(payload).To(BeEmpty())
			Consistently(func() bool { _, err := os.Stat(marker); return err == nil }, 300*time.Millisecond).Should(BeFalse())
			Expect(conn.Close()).To(Succeed())
			Eventually(done, 10*time.Second).Should(BeClosed())
			Expect(marker).NotTo(BeAnExistingFile())
			Expect(a.sessions).To(BeEmpty())
		})

		It("gives up on a request it accepted, and starts nothing, when the go has not come within agentHelloTimeout", func() {
			marker := filepath.Join(GinkgoT().TempDir(), "ran")
			conn, done := serveAgent(a)
			fw := &agentFrameWriter{w: conn}
			Expect(fw.write(agentFrameHello, []byte(testAgentKey))).To(Succeed())
			Expect(fw.writeJSON(agentFrameRequest, agentRequest{Kind: agentKindSession, Args: []string{"-c", "echo ran >> " + shellQuote(marker)}})).To(Succeed())
			Expect(readAgentFrameOf(conn, agentFrameAccepted)).To(BeEmpty())
			Consistently(done, agentHelloTimeout-time.Second).ShouldNot(BeClosed())
			Eventually(done, 5*time.Second).Should(BeClosed())
			Expect(marker).NotTo(BeAnExistingFile())
			Expect(a.sessions).To(BeEmpty())
		})

		It("closes a connection at once when as many connections as it allows already wait for their hello", func() {
			for range guestAgentMaxPending {
				a.pending <- struct{}{}
			}
			conn, done := serveAgent(a)
			expectClosed(conn, done)
		})

		It("refuses a session when it already runs as many as it allows, and a request of a kind it does not know", func() {
			for range guestAgentMaxSessions {
				a.sessions <- struct{}{}
			}
			_, ready, done := startAgentSession(a, testAgentKey, agentRequest{Kind: agentKindSession})
			Expect(ready.Error).To(Equal("the guest already runs 32 sessions, which is as many as it allows"))
			Eventually(done).Should(BeClosed())
			for range guestAgentMaxSessions {
				<-a.sessions
			}

			_, ready, done = startAgentSession(a, testAgentKey, agentRequest{Kind: "exec"})
			Expect(ready.Error).To(Equal(`the guest agent has no request of kind "exec"`))
			Eventually(done).Should(BeClosed())
			Expect(a.sessions).To(BeEmpty())
		})

		It("still runs a session when forwards take every forward slot, and still runs a forward when sessions take every session slot", func() {
			for range guestAgentMaxForwards {
				a.forwards <- struct{}{}
			}
			_, ready, done := startAgentSession(a, testAgentKey, agentRequest{Kind: agentKindForward, Host: "127.0.0.1", Port: upperServer()})
			Expect(ready.Error).To(Equal("the guest already runs 64 forwards, which is as many as it allows"))
			Eventually(done).Should(BeClosed())

			s, ready, done := startAgentSession(a, testAgentKey, agentRequest{Kind: agentKindSession, Args: []string{"-c", "echo from the guest"}})
			Expect(ready.Error).To(BeEmpty())
			Expect(s.awaitExit()).To(Equal(agentExit{Code: 0}))
			Eventually(s.ended, 10*time.Second).Should(BeClosed())
			Expect(s.stdout.String()).To(Equal("from the guest\n"))
			Eventually(done).Should(BeClosed())
			for range guestAgentMaxForwards {
				<-a.forwards
			}

			for range guestAgentMaxSessions {
				a.sessions <- struct{}{}
			}
			s, ready, done = startAgentSession(a, testAgentKey, agentRequest{Kind: agentKindForward, Host: "127.0.0.1", Port: upperServer()})
			Expect(ready.Error).To(BeEmpty())
			Expect(s.fw.writeData(agentFrameData, []byte("abc"))).To(Succeed())
			Expect(s.fw.write(agentFrameDataEnd, nil)).To(Succeed())
			Eventually(s.ended, 10*time.Second).Should(BeClosed())
			Expect(s.stdout.String()).To(Equal("ABC bye"))
			Eventually(done).Should(BeClosed())
			Expect(a.forwards).To(BeEmpty())
		})

		It("answers a ping at once, without a slot and without waiting for a go, and starts nothing", func() {
			for range guestAgentMaxSessions {
				a.sessions <- struct{}{}
			}
			for range guestAgentMaxForwards {
				a.forwards <- struct{}{}
			}
			conn, done := serveAgent(a)
			fw := &agentFrameWriter{w: conn}
			Expect(fw.write(agentFrameHello, []byte(testAgentKey))).To(Succeed())
			Expect(fw.writeJSON(agentFrameRequest, agentRequest{Kind: agentKindPing})).To(Succeed())
			payload, err := readAgentFrameOf(conn, agentFrameReady)
			Expect(err).NotTo(HaveOccurred())
			var ready agentReady
			Expect(json.Unmarshal(payload, &ready)).To(Succeed())
			Expect(ready.Error).To(BeEmpty())
			expectClosed(conn, done)
			Expect(a.runDir).NotTo(BeADirectory())
		})

		It("closes a ping whose hello holds another key without an answer", func() {
			conn, done := serveAgent(a)
			fw := &agentFrameWriter{w: conn}
			Expect(fw.write(agentFrameHello, []byte(strings.Repeat("cd", agentKeyBytes)))).To(Succeed())
			_ = fw.writeJSON(agentFrameRequest, agentRequest{Kind: agentKindPing})
			expectClosed(conn, done)
		})
	})

	Describe("a session", func() {
		It("runs the shell with the arguments in the session's environment under the app's, and streams input, output, error output, and the exit code", func() {
			s, ready, done := startAgentSession(a, testAgentKey, agentRequest{
				Kind: agentKindSession,
				Args: []string{"-c", `read line; echo "got $line"; echo "$FROM_SHIM $APP_VAR ${__GARDEN_SECRET-unset} $(pwd)"; echo oops >&2; exit 3`},
				Env:  []string{"FROM_SHIM=it's here", "APP_VAR=from the shim", "__GARDEN_SECRET=no", "BAD-NAME=no"},
			})
			Expect(ready.Error).To(BeEmpty())
			Expect(s.fw.writeData(agentFrameStdin, []byte("hello\n"))).To(Succeed())
			Expect(s.fw.write(agentFrameStdinEnd, nil)).To(Succeed())
			Expect(s.awaitExit()).To(Equal(agentExit{Code: 3}))
			Expect(s.stdout.String()).To(Equal("got hello\nit's here app unset " + a.cwd + "\n"))
			Expect(s.stderr.String()).To(Equal("oops\n"))
			Eventually(done, 5*time.Second).Should(BeClosed())
			entries, err := os.ReadDir(a.runDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty(), "the session's files go once it ends")
		})

		It("gives the process the end of its input, and passes signals to it", func() {
			s, ready, _ := startAgentSession(a, testAgentKey, agentRequest{Kind: agentKindSession, Args: []string{"-c", "cat; trap 'exit 7' TERM; echo ready; while :; do sleep 0.1; done"}})
			Expect(ready.Error).To(BeEmpty())
			Expect(s.fw.writeData(agentFrameStdin, []byte("before the end\n"))).To(Succeed())
			Expect(s.fw.write(agentFrameStdinEnd, nil)).To(Succeed())
			Eventually(s.stdout.String, 10*time.Second).Should(Equal("before the end\nready\n"))
			Expect(s.fw.write(agentFrameSignal, []byte{byte(syscall.SIGTERM)})).To(Succeed())
			Expect(s.awaitExit()).To(Equal(agentExit{Code: 7}))
		})

		It("reports the signal that ended the process", func() {
			s, ready, _ := startAgentSession(a, testAgentKey, agentRequest{Kind: agentKindSession, Args: []string{"-c", "echo ready; exec sleep 30"}})
			Expect(ready.Error).To(BeEmpty())
			Eventually(s.stdout.String, 10*time.Second).Should(Equal("ready\n"))
			Expect(s.fw.write(agentFrameSignal, []byte{byte(syscall.SIGTERM)})).To(Succeed())
			Expect(s.awaitExit()).To(Equal(agentExit{Code: 128 + int(syscall.SIGTERM), Signal: int(syscall.SIGTERM)}))
		})

		It("runs a session on a terminal of the size asked for, which the process has as its controlling terminal, and resizes it", func() {
			s, ready, _ := startAgentSession(a, testAgentKey, agentRequest{
				Kind: agentKindSession, TTY: true, Rows: 24, Cols: 80,
				Args: []string{"-c", `test -t 0 && test -t 1 && stty size && read line && stty size && echo "line $line" && exec </dev/tty && echo controlling`},
			})
			Expect(ready.Error).To(BeEmpty())
			Eventually(s.stdout.String, 10*time.Second).Should(ContainSubstring("24 80"))
			var size [4]byte
			binary.BigEndian.PutUint16(size[0:2], 50)
			binary.BigEndian.PutUint16(size[2:4], 132)
			Expect(s.fw.write(agentFrameResize, size[:])).To(Succeed())
			Expect(s.fw.writeData(agentFrameStdin, []byte("typed\r"))).To(Succeed())
			Expect(s.awaitExit()).To(Equal(agentExit{Code: 0}))
			Eventually(s.stdout.String).Should(ContainSubstring("50 132"))
			Expect(s.stdout.String()).To(ContainSubstring("line typed"))
			Expect(s.stdout.String()).To(ContainSubstring("controlling"))
		})

		It("hangs the session's process group up when the connection drops", func() {
			marker := filepath.Join(a.cwd, "hung-up")
			s, ready, done := startAgentSession(a, testAgentKey, agentRequest{Kind: agentKindSession, Args: []string{"-c", "trap 'echo hup > hung-up; exit 0' HUP; echo ready; while :; do sleep 0.1; done"}})
			Expect(ready.Error).To(BeEmpty())
			Eventually(s.stdout.String, 10*time.Second).Should(Equal("ready\n"))
			Expect(s.conn.Close()).To(Succeed())
			Eventually(done, 10*time.Second).Should(BeClosed())
			Expect(os.ReadFile(marker)).To(Equal([]byte("hup\n")))
		})

		It("kills a process that ignores the hangup once the grace has passed", func() {
			s, ready, done := startAgentSession(a, testAgentKey, agentRequest{Kind: agentKindSession, Args: []string{"-c", "trap '' HUP; echo ready; while :; do sleep 0.1; done"}})
			Expect(ready.Error).To(BeEmpty())
			Eventually(s.stdout.String, 10*time.Second).Should(Equal("ready\n"))
			Expect(s.conn.Close()).To(Succeed())
			Consistently(done, guestAgentHangupGrace-500*time.Millisecond).ShouldNot(BeClosed())
			Eventually(done, 5*time.Second).Should(BeClosed())
		})

		It("ends the session it started when it cannot write its answer, and kills one that ignores the hangup", func() {
			pidfile := filepath.Join(a.cwd, "pid")
			agentSide, client := agentSocketPair()
			DeferCleanup(func() { _ = client.Close() })
			failed := make(chan time.Time, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				a.handle(&readyFailConn{UnixConn: agentSide, pidfile: pidfile, failed: failed})
			}()
			fw := &agentFrameWriter{w: client}
			Expect(fw.write(agentFrameHello, []byte(testAgentKey))).To(Succeed())
			Expect(fw.writeJSON(agentFrameRequest, agentRequest{Kind: agentKindSession, Args: []string{"-c", "trap '' HUP; echo $$ > " + shellQuote(pidfile) + "; exec sleep 30"}})).To(Succeed())
			Expect(readAgentFrameOf(client, agentFrameAccepted)).To(BeEmpty())
			Expect(fw.write(agentFrameGo, nil)).To(Succeed())
			var at time.Time
			Eventually(failed, 10*time.Second).Should(Receive(&at))
			Eventually(done, 10*time.Second).Should(BeClosed())
			Expect(time.Since(at)).To(BeNumerically(">=", guestAgentHangupGrace))
			b, err := os.ReadFile(pidfile)
			Expect(err).NotTo(HaveOccurred())
			pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			Expect(err).NotTo(HaveOccurred())
			Expect(syscall.Kill(pid, 0)).To(MatchError(syscall.ESRCH))
			Expect(a.sessions).To(BeEmpty())
		})

		It("refuses a session when the root has no shell, and does not follow a link in the root out of it", func() {
			root := GinkgoT().TempDir()
			a.root = root
			_, ready, _ := startAgentSession(a, testAgentKey, agentRequest{Kind: agentKindSession})
			Expect(ready.Error).To(Equal("the guest has no shell to run the session: none of /bin/bash, /usr/local/bin/bash, /bin/sh is an executable file"))

			Expect(os.MkdirAll(filepath.Join(root, "bin"), 0o755)).To(Succeed())
			Expect(os.Symlink("/bin/bash", filepath.Join(root, "bin/bash"))).To(Succeed())
			_, err := a.findShell()
			Expect(err).To(HaveOccurred(), "the link resolves inside the root, where nothing is")
			Expect(os.WriteFile(filepath.Join(root, "bin/sh"), []byte("#!/bin/true\n"), 0o755)).To(Succeed())
			Expect(a.findShell()).To(Equal("/bin/sh"))
		})
	})

	Describe("a forward", func() {
		It("connects to the port in the guest and passes bytes both ways, with the end of each direction", func() {
			s, ready, done := startAgentSession(a, testAgentKey, agentRequest{Kind: agentKindForward, Port: upperServer()})
			Expect(ready.Error).To(BeEmpty())
			Expect(s.fw.writeData(agentFrameData, []byte("abc"))).To(Succeed())
			Expect(s.fw.write(agentFrameDataEnd, nil)).To(Succeed())
			Eventually(s.ended, 10*time.Second).Should(BeClosed())
			Expect(s.stdout.String()).To(Equal("ABC bye"))
			Expect(s.stderr.String()).To(Equal("data end"))
			Eventually(done).Should(BeClosed())
		})

		It("refuses a port that is not a TCP port, and says why a connect failed", func() {
			_, ready, _ := startAgentSession(a, testAgentKey, agentRequest{Kind: agentKindForward, Port: 70000})
			Expect(ready.Error).To(Equal("port 70000 is not a TCP port"))
			port := closedPort()
			_, ready, _ = startAgentSession(a, testAgentKey, agentRequest{Kind: agentKindForward, Host: "127.0.0.1", Port: port})
			Expect(ready.Error).To(HavePrefix("connecting to 127.0.0.1 port " + strconv.Itoa(port) + " in the guest: "))
		})
	})

	It("writes the session's environment as export lines, without the names /rvm/env leaves out", func() {
		Expect(agentSessionEnv([]string{"TERM=xterm", "QUOTED=it's", "__GARDEN_X=1", "BAD-NAME=1", "NOEQUALS", "SHLVL=2", "EMPTY="})).To(Equal(
			"export TERM='xterm'\nexport QUOTED='it'\\''s'\nexport EMPTY=''\n"))
	})

	It("reads its configuration once and removes it", func() {
		path := writeTempFile("agent-config", `{"key":"`+testAgentKey+`","uid":1001,"gid":1002}`)
		cfg, err := readGuestAgentConfig(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).To(Equal(guestAgentConfigFile{Key: testAgentKey, UID: 1001, GID: 1002}))
		Expect(path).NotTo(BeAnExistingFile())
		_, err = readGuestAgentConfig(path)
		Expect(err).To(MatchError(ContainSubstring("reading the guest agent's configuration")))
	})

	It("runs each kind of guest's sessions as that guest runs its app, and refuses a bad key or mode", func() {
		cfg := guestAgentConfigFile{Key: testAgentKey, UID: 1001, GID: 1002}
		stack, err := newGuestAgent(agentModeStack, cfg, log.New(GinkgoWriter, "", 0))
		Expect(err).NotTo(HaveOccurred())
		Expect([]any{stack.root, stack.cwd, stack.uid, stack.gid}).To(Equal([]any{guestAppRoot, "/home/vcap", 2000, 2000}))
		Expect(stack.envPaths).To(Equal([]string{"/rvm/env"}))
		Expect(stack.prefix).To(Equal("echo 0 >/proc/self/oom_score_adj && . /rvm/limits && " + guestSetLimits + " && "))
		p := guestProcess{argvPath: "/rvm/agent/run/1/argv", envPaths: []string{"/rvm/agent/run/1/env", "/rvm/env"}, dir: "/home/vcap"}
		Expect(stack.exec(p)).To(Equal(stackExec(p)))

		image, err := newGuestAgent(agentModeImage, cfg, log.New(GinkgoWriter, "", 0))
		Expect(err).NotTo(HaveOccurred())
		Expect([]any{image.root, image.cwd, image.uid, image.gid}).To(Equal([]any{guestAppRoot, "/", 1001, 1002}))
		Expect(image.exec(p)).To(Equal((&guestImage{uid: 1001, gid: 1002}).exec(p)))

		bb, err := newGuestAgent(agentModeBusybox, cfg, log.New(GinkgoWriter, "", 0))
		Expect(err).NotTo(HaveOccurred())
		Expect([]any{bb.root, bb.cwd, bb.uid, bb.gid}).To(Equal([]any{"/", "/", 0, 0}))
		Expect(bb.exec(p)).To(Equal(`. /rvm/agent/run/1/env && . /rvm/env && eval "set -- $(/bin/busybox cat /rvm/agent/run/1/argv)" && cd '/home/vcap' && exec "$@"`))

		_, err = newGuestAgent("vm", cfg, log.New(GinkgoWriter, "", 0))
		Expect(err).To(MatchError(`the guest agent has no mode "vm"`))
		_, err = newGuestAgent(agentModeStack, guestAgentConfigFile{Key: "abcd"}, log.New(GinkgoWriter, "", 0))
		Expect(err).To(MatchError("the guest agent's configuration holds no key of the right length"))
	})

	It("refuses to start without its mode", func() {
		Expect(dispatch([]string{guestAgentCommand}, log.New(GinkgoWriter, "", 0))).To(Equal(exitLaunchError))
	})
})

var _ = Describe("the guest agent relay", func() {
	var (
		a      *guestAgent
		path   string
		logs   *lockedBuffer
		logger *log.Logger
	)

	BeforeEach(func() {
		a = newTestAgent()
		path = filepath.Join(GinkgoT().TempDir(), "agent.sock")
		logs = new(lockedBuffer)
		logger = log.New(logs, "", 0)
	})

	dialAgent := func(a *guestAgent) func() (agentConn, error) {
		return func() (agentConn, error) {
			agentSide, relaySide := agentSocketPair()
			go a.handle(agentSide)
			return relaySide, nil
		}
	}

	startRelay := func(key string, dial func() (agentConn, error), off string) *agentRelay {
		r, err := newAgentRelay(path, []byte(key), dial, off, agentRelayWait, logger)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(r.close)
		return r
	}

	ask := func(line string) (*net.UnixConn, string) {
		c, err := net.Dial("unix", path)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = c.Close() })
		_, err = io.WriteString(c, line+"\n")
		Expect(err).NotTo(HaveOccurred())
		Expect(c.SetReadDeadline(time.Now().Add(10 * time.Second))).To(Succeed())
		answer, err := readLine(c, agentMaxLine)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.SetReadDeadline(time.Time{})).To(Succeed())
		return c.(*net.UnixConn), answer
	}

	// askSession sends a session's line and request, as the shim does, and
	// returns the client's connection and the relay's answer.
	askSession := func(args ...string) (*net.UnixConn, string) {
		c, err := net.Dial("unix", path)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = c.Close() })
		var b bytes.Buffer
		b.WriteString(agentKindSession + "\n")
		Expect((&agentFrameWriter{w: &b}).writeJSON(agentFrameRequest, agentRequest{Kind: agentKindSession, Args: args})).To(Succeed())
		_, err = c.Write(b.Bytes())
		Expect(err).NotTo(HaveOccurred())
		Expect(c.SetReadDeadline(time.Now().Add(10 * time.Second))).To(Succeed())
		answer, err := readLine(c, agentMaxLine)
		Expect(err).NotTo(HaveOccurred())
		return c.(*net.UnixConn), answer
	}

	// proxyAgent dials a through a proxy that passes the relay's bytes to
	// the agent unchanged, and hands the agent's first frame to first,
	// which decides what the relay gets of it and of what follows.
	proxyAgent := func(a *guestAgent, first func(relay, agent *net.UnixConn, typ byte, payload []byte)) func() (agentConn, error) {
		return func() (agentConn, error) {
			agentSide, agentPeer := agentSocketPair()
			go a.handle(agentSide)
			relaySide, relayPeer := agentSocketPair()
			go func() { _, _ = io.Copy(agentPeer, relayPeer) }()
			go func() {
				typ, payload, err := readAgentFrame(agentPeer)
				if err != nil {
					agentPeer.Close()
					relayPeer.Close()
					return
				}
				first(relayPeer, agentPeer, typ, payload)
			}()
			return relaySide, nil
		}
	}

	// silentAgent dials an agent that reads but never answers, and sends
	// the agent's end of each connection on peers.
	silentAgent := func(peers chan *net.UnixConn) func() (agentConn, error) {
		return func() (agentConn, error) {
			agentSide, relaySide := agentSocketPair()
			peers <- agentSide
			return relaySide, nil
		}
	}

	// readRequest reads what the relay sends a silent agent, the hello and
	// the request, and leaves a deadline on peer for the next read.
	readRequest := func(peer *net.UnixConn) {
		Expect(peer.SetReadDeadline(time.Now().Add(5 * time.Second))).To(Succeed())
		_, err := readAgentFrameOf(peer, agentFrameHello)
		Expect(err).NotTo(HaveOccurred())
		_, err = readAgentFrameOf(peer, agentFrameRequest)
		Expect(err).NotTo(HaveOccurred())
	}

	ran := func(marker string) func() string {
		return func() string {
			b, _ := os.ReadFile(marker)
			return string(b)
		}
	}

	newShim := func(stdin string, env []string, sigs chan os.Signal) (*agentShim, *lockedBuffer, *lockedBuffer) {
		in, err := os.Open(writeTempFile("stdin", stdin))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = in.Close() })
		stdout, stderr := new(lockedBuffer), new(lockedBuffer)
		return &agentShim{socket: path, wait: time.Second, stdin: in, stdout: stdout, stderr: stderr, env: env, signals: sigs}, stdout, stderr
	}

	It("listens on a socket only its own user may open, and removes a stale one first", func() {
		Expect(os.WriteFile(path, nil, 0o644)).To(Succeed())
		startRelay(testAgentKey, dialAgent(a), "")
		info, err := os.Lstat(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Type()).To(Equal(os.ModeSocket))
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))
	})

	It("tells a client why the guest has no agent", func() {
		startRelay(testAgentKey, nil, "this guest has no agent for cf ssh, because it is a spec")
		_, answer := ask(agentKindSession)
		Expect(answer).To(Equal("error: this guest has no agent for cf ssh, because it is a spec"))
	})

	It("refuses a first line it does not know and a forward whose port is not a number", func() {
		startRelay(testAgentKey, dialAgent(a), "")
		_, answer := ask("shell")
		Expect(answer).To(Equal(`error: the guest agent relay takes "session", "forward HOST PORT", or "ping", not "shell"`))
		_, answer = ask("forward 127.0.0.1 http")
		Expect(answer).To(Equal(`error: "http" is not a port`))
	})

	It("answers a ping with ok once the agent has answered it, and then closes the connection", func() {
		var dials atomic.Int32
		startRelay(testAgentKey, func() (agentConn, error) {
			dials.Add(1)
			return dialAgent(a)()
		}, "")
		c, answer := ask(agentRelayPing)
		Expect(answer).To(Equal("ok"))
		Expect(c.SetReadDeadline(time.Now().Add(5 * time.Second))).To(Succeed())
		_, err := c.Read(make([]byte, 1))
		Expect(err).To(MatchError(io.EOF))
		Expect(dials.Load()).To(Equal(int32(1)))
		Expect(a.runDir).NotTo(BeADirectory())
	})

	It("answers a ping with the reason, at once and without trying again, when the agent cannot be reached", func() {
		var dials atomic.Int32
		startRelay(testAgentKey, func() (agentConn, error) {
			dials.Add(1)
			return nil, errors.New("connecting to the guest's vsock: connection reset by peer")
		}, "")
		start := time.Now()
		_, answer := ask(agentRelayPing)
		Expect(answer).To(Equal("error: the guest agent did not answer a ping: connecting to the guest's vsock: connection reset by peer"))
		Expect(time.Since(start)).To(BeNumerically("<", agentPingWait))
		Expect(dials.Load()).To(Equal(int32(1)))
		Expect(logs.String()).To(ContainSubstring("the guest agent did not answer a ping: connecting to the guest's vsock: connection reset by peer, after "))
	})

	It("answers a ping with an error within agentPingWait when the agent never answers, and when it holds another key", func() {
		hung := make(chan *net.UnixConn, 1)
		startRelay(testAgentKey, func() (agentConn, error) {
			agentSide, relaySide := agentSocketPair()
			hung <- agentSide
			return relaySide, nil
		}, "")
		start := time.Now()
		_, answer := ask(agentRelayPing)
		Expect(answer).To(HavePrefix("error: the guest agent did not answer a ping: reading the guest agent's answer: "))
		Expect(time.Since(start)).To(BeNumerically("~", agentPingWait, time.Second))
		(<-hung).Close()

		a.key = []byte(strings.Repeat("cd", agentKeyBytes))
		path = filepath.Join(GinkgoT().TempDir(), "agent.sock")
		startRelay(testAgentKey, dialAgent(a), "")
		_, answer = ask(agentRelayPing)
		Expect(answer).To(HavePrefix("error: the guest agent did not answer a ping: "))
	})

	It("keeps the contract that diego-sshd's specs check their fake relay against", func() {
		data, err := os.ReadFile(filepath.Join("testdata", "guest-agent-relay-contract.txt"))
		Expect(err).NotTo(HaveOccurred())
		echo, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = echo.Close() })
		go func() {
			for {
				c, err := echo.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					_, _ = io.Copy(c, c)
				}()
			}
		}()
		port := strconv.Itoa(echo.Addr().(*net.TCPAddr).Port)

		dir := GinkgoT().TempDir()
		paths := map[string]string{}
		for _, state := range []string{"agent", "off", "down"} {
			path = filepath.Join(dir, state+".sock")
			paths[state] = path
			switch state {
			case "agent":
				startRelay(testAgentKey, dialAgent(a), "")
			case "off":
				startRelay(testAgentKey, nil, "this guest has no agent for cf ssh, because it is a spec")
			case "down":
				startRelay(testAgentKey, func() (agentConn, error) { return nil, errors.New("the agent is down") }, "")
			}
		}

		cases := 0
		for _, text := range strings.Split(string(data), "\n") {
			if text == "" || strings.HasPrefix(text, "#") {
				continue
			}
			fields := strings.Split(text, " | ")
			Expect(fields).To(HaveLen(4), text)
			state, line, want, after := fields[0], strings.ReplaceAll(fields[1], "PORT", port), fields[2], fields[3]
			Expect(paths).To(HaveKey(state), text)
			path = paths[state]
			c, answer := ask(line)
			switch want {
			case "ok":
				Expect(answer).To(Equal("ok"), text)
			case "error:":
				Expect(answer).To(MatchRegexp(`^error: \S`), text)
			default:
				Fail("the contract has no answer " + want)
			}
			Expect(c.SetReadDeadline(time.Now().Add(10 * time.Second))).To(Succeed())
			switch after {
			case "eof":
				_, err := c.Read(make([]byte, 1))
				Expect(err).To(MatchError(io.EOF), text)
			case "stream":
				_, err := io.WriteString(c, "through the guest")
				Expect(err).NotTo(HaveOccurred())
				Expect(c.CloseWrite()).To(Succeed())
				Expect(io.ReadAll(c)).To(Equal([]byte("through the guest")), text)
			default:
				Fail("the contract has no after " + after)
			}
			cases++
		}
		Expect(cases).To(Equal(8))
	})

	It("answers a ping with the reason when the guest has no agent", func() {
		startRelay(testAgentKey, nil, "this guest has no agent for cf ssh, because it is a spec")
		_, answer := ask(agentRelayPing)
		Expect(answer).To(Equal("error: this guest has no agent for cf ssh, because it is a spec"))
	})

	It("refuses a client that runs as another user", func() {
		if os.Getuid() == 0 {
			Skip("root may always use the relay")
		}
		r, err := newAgentRelay(path, []byte(testAgentKey), dialAgent(a), "", time.Second, logger)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(r.close)
		c, err := net.Dial("unix", path)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = c.Close() })
		Expect(r.checkPeer(c.(*net.UnixConn))).To(Succeed(), "the relay's own user")
		other := &agentRelay{uid: os.Getuid() + 1}
		Expect(other.checkPeer(c.(*net.UnixConn))).To(MatchError("uid " + strconv.Itoa(os.Getuid()) + " may not use the guest agent"))
	})

	It("keeps trying the agent while the guest boots", func() {
		var tries atomic.Int32
		dial := dialAgent(a)
		startRelay(testAgentKey, func() (agentConn, error) {
			if tries.Add(1) < 3 {
				return nil, errors.New("the guest is still booting")
			}
			return dial()
		}, "")
		shim, stdout, _ := newShim("", nil, make(chan os.Signal))
		shim.wait = 5 * time.Second
		Expect(shim.run([]string{"-c", "echo up"})).To(Equal(agentExit{Code: 0}))
		Expect(stdout.String()).To(Equal("up\n"))
		Expect(tries.Load()).To(BeNumerically("==", 3))
	})

	It("tries the agent again when it ends the connection before it answers", func() {
		var tries atomic.Int32
		dial := dialAgent(a)
		startRelay(testAgentKey, func() (agentConn, error) {
			if tries.Add(1) < 3 {
				// An agent with all its handshakes pending closes the
				// connection without an answer.
				agentSide, relaySide := agentSocketPair()
				agentSide.Close()
				return relaySide, nil
			}
			return dial()
		}, "")
		shim, stdout, _ := newShim("", nil, make(chan os.Signal))
		Expect(shim.run([]string{"-c", "echo answered"})).To(Equal(agentExit{Code: 0}))
		Expect(stdout.String()).To(Equal("answered\n"))
		Expect(tries.Load()).To(BeNumerically("==", 3))

		tries.Store(0)
		_, answer := ask("forward 127.0.0.1 " + strconv.Itoa(upperServer()))
		Expect(answer).To(Equal("ok"))
		Expect(tries.Load()).To(BeNumerically("==", 3))
	})

	It("stops waiting for the agent as soon as it closes", func() {
		var tries atomic.Int32
		r, err := newAgentRelay(path, []byte(testAgentKey), func() (agentConn, error) {
			tries.Add(1)
			return nil, errors.New("the guest is still booting")
		}, "", agentRelayWait, logger)
		Expect(err).NotTo(HaveOccurred())
		c, err := net.Dial("unix", path)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = c.Close() })
		_, err = io.WriteString(c, "forward 127.0.0.1 8080\n")
		Expect(err).NotTo(HaveOccurred())
		Eventually(tries.Load, 5*time.Second).Should(BeNumerically(">=", 2))

		start := time.Now()
		r.close()
		Expect(time.Since(start)).To(BeNumerically("<", time.Second))
		Expect(c.SetReadDeadline(time.Now().Add(5 * time.Second))).To(Succeed())
		answer, err := io.ReadAll(c)
		Expect(err).To(Or(Not(HaveOccurred()), MatchError(syscall.ECONNRESET)))
		Expect(string(answer)).To(Or(BeEmpty(), Equal("error: the guest agent relay closed\n")))
	})

	It("tries again when the agent ends the connection without a byte, even after it accepted, and runs the session once", func() {
		marker := filepath.Join(GinkgoT().TempDir(), "ran")
		var tries atomic.Int32
		dial := dialAgent(a)
		dropAccepted := proxyAgent(a, func(relay, agent *net.UnixConn, typ byte, payload []byte) {
			defer GinkgoRecover()
			Expect(typ).To(Equal(agentFrameAccepted))
			relay.Close()
			agent.Close()
		})
		startRelay(testAgentKey, func() (agentConn, error) {
			if tries.Add(1) == 1 {
				return dropAccepted()
			}
			return dial()
		}, "")
		_, answer := askSession("-c", "echo ran >> "+shellQuote(marker))
		Expect(answer).To(Equal("ok"))
		Expect(tries.Load()).To(BeNumerically("==", 2))
		Eventually(ran(marker), 10*time.Second).Should(Equal("ran\n"))
		Consistently(ran(marker), 500*time.Millisecond).Should(Equal("ran\n"))
	})

	It("passes on the bytes a forward's client sends while the relay waits for the agent, ahead of what follows", func() {
		var tries atomic.Int32
		dial := dialAgent(a)
		startRelay(testAgentKey, func() (agentConn, error) {
			// The watch on the client has the first byte by the time the
			// agent answers.
			if tries.Add(1) < 3 {
				return nil, errors.New("the guest is still booting")
			}
			return dial()
		}, "")
		c, err := net.Dial("unix", path)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = c.Close() })
		_, err = io.WriteString(c, "forward 127.0.0.1 "+strconv.Itoa(upperServer())+"\nearly ")
		Expect(err).NotTo(HaveOccurred())
		Expect(c.SetReadDeadline(time.Now().Add(10 * time.Second))).To(Succeed())
		answer, err := readLine(c, agentMaxLine)
		Expect(err).NotTo(HaveOccurred())
		Expect(answer).To(Equal("ok"))
		Expect(tries.Load()).To(BeNumerically("==", 3))
		_, err = io.WriteString(c, "data")
		Expect(err).NotTo(HaveOccurred())
		Expect(c.(*net.UnixConn).CloseWrite()).To(Succeed())
		got, err := io.ReadAll(c)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("EARLY DATA bye"))
	})

	It("never tries again once it has told the agent to start, so an agent that ends the connection then runs the session once", func() {
		marker := filepath.Join(GinkgoT().TempDir(), "ran")
		var tries atomic.Int32
		dropReady := proxyAgent(a, func(relay, agent *net.UnixConn, typ byte, payload []byte) {
			defer GinkgoRecover()
			Expect(typ).To(Equal(agentFrameAccepted))
			Expect((&agentFrameWriter{w: relay}).write(typ, payload)).To(Succeed())
			// The agent answers only once the relay's go has reached it,
			// and the connection to the relay ends before the answer does.
			typ, _, err := readAgentFrame(agent)
			Expect(err).NotTo(HaveOccurred())
			Expect(typ).To(Equal(agentFrameReady))
			relay.Close()
			_, _ = io.Copy(io.Discard, agent)
		})
		startRelay(testAgentKey, func() (agentConn, error) {
			tries.Add(1)
			return dropReady()
		}, "")
		_, answer := askSession("-c", "echo ran >> "+shellQuote(marker))
		Expect(answer).To(HavePrefix("error: the guest agent accepted the request and did not answer: "))
		Eventually(ran(marker), 10*time.Second).Should(Equal("ran\n"))
		Consistently(func() any { return []any{tries.Load(), ran(marker)()} }, time.Second).Should(Equal([]any{int32(1), "ran\n"}))
	})

	It("tells an agent that accepts with less than a try's read of the wait left nothing more, and the client that it answered too late", func() {
		marker := filepath.Join(GinkgoT().TempDir(), "ran")
		var tries atomic.Int32
		sent := make(chan byte, 8)
		// The proxy passes each frame of the relay's on to the agent and
		// notes its type, and passes the agent's bytes back unchanged.
		r, err := newAgentRelay(path, []byte(testAgentKey), func() (agentConn, error) {
			tries.Add(1)
			agentSide, agentPeer := agentSocketPair()
			go a.handle(agentSide)
			relaySide, relayPeer := agentSocketPair()
			go func() {
				defer agentPeer.Close()
				fw := &agentFrameWriter{w: agentPeer}
				for {
					typ, payload, err := readAgentFrame(relayPeer)
					if err != nil {
						return
					}
					sent <- typ
					if fw.write(typ, payload) != nil {
						return
					}
				}
			}()
			go func() {
				_, _ = io.Copy(relayPeer, agentPeer)
				relayPeer.Close()
			}()
			return relaySide, nil
		}, "", agentTryRead-time.Second, logger)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(r.close)
		_, answer := askSession("-c", "echo ran >> "+shellQuote(marker))
		Expect(answer).To(HavePrefix("error: the guest agent answered too late: "))
		Expect(tries.Load()).To(BeNumerically("==", 1))
		Expect(sent).To(Receive(Equal(agentFrameHello)))
		Expect(sent).To(Receive(Equal(agentFrameRequest)))
		Consistently(sent, time.Second).ShouldNot(Receive())
		Expect(marker).NotTo(BeAnExistingFile())
		Eventually(a.sessions).Should(BeEmpty())
	})

	It("stops waiting for the agent, and ends its connection to the agent, when the client leaves", func() {
		var tries atomic.Int32
		r, err := newAgentRelay(path, []byte(testAgentKey), func() (agentConn, error) {
			tries.Add(1)
			return nil, errors.New("the guest is still booting")
		}, "", agentRelayWait, logger)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(r.close)
		c, err := net.Dial("unix", path)
		Expect(err).NotTo(HaveOccurred())
		_, err = io.WriteString(c, "forward 127.0.0.1 8080\n")
		Expect(err).NotTo(HaveOccurred())
		Eventually(tries.Load, 5*time.Second).Should(BeNumerically(">=", 1))
		Expect(c.Close()).To(Succeed())
		Eventually(func() int32 {
			before := tries.Load()
			time.Sleep(4 * agentDialRetry)
			return tries.Load() - before
		}, 10*time.Second).Should(BeZero())
		r.close()

		peers := make(chan *net.UnixConn, 8)
		r, err = newAgentRelay(path, []byte(testAgentKey), silentAgent(peers), "", agentRelayWait, logger)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(r.close)
		c, err = net.Dial("unix", path)
		Expect(err).NotTo(HaveOccurred())
		var b bytes.Buffer
		b.WriteString(agentKindSession + "\n")
		Expect((&agentFrameWriter{w: &b}).writeJSON(agentFrameRequest, agentRequest{Kind: agentKindSession, Args: []string{"-c", "true"}})).To(Succeed())
		_, err = c.Write(b.Bytes())
		Expect(err).NotTo(HaveOccurred())
		var peer *net.UnixConn
		Eventually(peers, 5*time.Second).Should(Receive(&peer))
		DeferCleanup(func() { _ = peer.Close() })
		readRequest(peer)
		Expect(c.Close()).To(Succeed())
		start := time.Now()
		_, err = peer.Read(make([]byte, 1))
		Expect(err).To(MatchError(io.EOF))
		Expect(time.Since(start)).To(BeNumerically("<", 2*time.Second))
		Consistently(peers, time.Second).ShouldNot(Receive())
	})

	It("ends a try when the relay's wait runs out, and closes at once while a try waits for the agent", func() {
		peers := make(chan *net.UnixConn, 64)
		DeferCleanup(func() {
			for len(peers) > 0 {
				_ = (<-peers).Close()
			}
		})
		r, err := newAgentRelay(path, []byte(testAgentKey), silentAgent(peers), "", time.Second, logger)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(r.close)
		start := time.Now()
		_, answer := ask("forward 127.0.0.1 8080")
		Expect(answer).To(HavePrefix("error: the guest agent did not answer within 1s: reading the guest agent's answer: "))
		Expect(time.Since(start)).To(BeNumerically("<", 3*time.Second))
		r.close()

		r, err = newAgentRelay(path, []byte(testAgentKey), silentAgent(peers), "", agentRelayWait, logger)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(r.close)
		c, err := net.Dial("unix", path)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = c.Close() })
		_, err = io.WriteString(c, "forward 127.0.0.1 8080\n")
		Expect(err).NotTo(HaveOccurred())
		var peer *net.UnixConn
		Eventually(peers, 5*time.Second).Should(Receive(&peer))
		DeferCleanup(func() { _ = peer.Close() })
		readRequest(peer)
		start = time.Now()
		r.close()
		Expect(time.Since(start)).To(BeNumerically("<", time.Second))
		_, err = peer.Read(make([]byte, 1))
		Expect(err).To(MatchError(io.EOF))
	})

	It("runs the shim's session in the guest with its arguments, input, environment, output, and exit code", func() {
		startRelay(testAgentKey, dialAgent(a), "")
		shim, stdout, stderr := newShim("from the client\n", []string{"FROM_SHIM=1"}, make(chan os.Signal))
		exit, err := shim.run([]string{"-c", `read line; echo "$line $FROM_SHIM $APP_VAR"; echo to stderr >&2; exit 4`})
		Expect(err).NotTo(HaveOccurred())
		Expect(exit).To(Equal(agentExit{Code: 4}))
		Expect(stdout.String()).To(Equal("from the client 1 app\n"))
		Expect(stderr.String()).To(Equal("to stderr\n"))
	})

	It("passes megabytes of arbitrary bytes through the shim's session both ways unchanged, as scp and sftp need", func() {
		startRelay(testAgentKey, dialAgent(a), "")
		data := make([]byte, 4<<20)
		_, err := rand.Read(data)
		Expect(err).NotTo(HaveOccurred())
		shim, stdout, stderr := newShim(string(data), nil, make(chan os.Signal))
		exit, err := shim.run([]string{"-c", "cat > upload && cat upload && exit 3"})
		Expect(err).NotTo(HaveOccurred())
		Expect(exit).To(Equal(agentExit{Code: 3}))
		Expect(stderr.String()).To(BeEmpty())
		got := []byte(stdout.String())
		Expect(len(got)).To(Equal(len(data)))
		Expect(bytes.Equal(got, data)).To(BeTrue())
	})

	It("passes the shim's signals to the session's process", func() {
		startRelay(testAgentKey, dialAgent(a), "")
		sigs := make(chan os.Signal, 1)
		shim, stdout, _ := newShim("", nil, sigs)
		exited := make(chan agentExit, 1)
		go func() {
			defer GinkgoRecover()
			exit, err := shim.run([]string{"-c", "trap 'exit 7' TERM; echo ready; while :; do sleep 0.1; done"})
			Expect(err).NotTo(HaveOccurred())
			exited <- exit
		}()
		Eventually(stdout.String, 10*time.Second).Should(Equal("ready\n"))
		sigs <- syscall.SIGWINCH
		sigs <- syscall.SIGTERM
		Eventually(exited, 10*time.Second).Should(Receive(Equal(agentExit{Code: 7})))
	})

	It("gives the shim the relay's reason when the session cannot run, and fails when no relay answers", func() {
		startRelay(testAgentKey, nil, "this guest has no agent for cf ssh, because it is a spec")
		shim, _, _ := newShim("", nil, make(chan os.Signal))
		_, err := shim.run([]string{"-c", "true"})
		Expect(err).To(MatchError("this guest has no agent for cf ssh, because it is a spec"))

		shim.socket = filepath.Join(GinkgoT().TempDir(), "nothing.sock")
		shim.wait = 300 * time.Millisecond
		_, err = shim.run(nil)
		Expect(err).To(MatchError(ContainSubstring("did not answer within 300ms")))
	})

	It("cannot reach the agent with another boot's key", func() {
		r, err := newAgentRelay(path, []byte(strings.Repeat("cd", agentKeyBytes)), dialAgent(a), "", 500*time.Millisecond, logger)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(r.close)
		shim, _, _ := newShim("", nil, make(chan os.Signal))
		_, err = shim.run([]string{"-c", "true"})
		Expect(err).To(MatchError(HavePrefix("the guest agent did not answer within 500ms: ")))
		Expect(a.runDir).NotTo(BeADirectory())
	})

	It("forwards a client's raw bytes to a port in the guest and passes the end of each direction", func() {
		startRelay(testAgentKey, dialAgent(a), "")
		c, answer := ask("forward 127.0.0.1 " + strconv.Itoa(upperServer()))
		Expect(answer).To(Equal("ok"))
		_, err := io.WriteString(c, "through the relay")
		Expect(err).NotTo(HaveOccurred())
		Expect(c.CloseWrite()).To(Succeed())
		Expect(c.SetReadDeadline(time.Now().Add(10 * time.Second))).To(Succeed())
		Expect(io.ReadAll(c)).To(Equal([]byte("THROUGH THE RELAY bye")))
	})

	It("passes megabytes of arbitrary bytes through a forward unchanged", func() {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = ln.Close() })
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = io.Copy(c, c)
		}()
		startRelay(testAgentKey, dialAgent(a), "")
		c, answer := ask("forward 127.0.0.1 " + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
		Expect(answer).To(Equal("ok"))
		data := make([]byte, 4<<20)
		_, err = rand.Read(data)
		Expect(err).NotTo(HaveOccurred())
		go func() {
			defer GinkgoRecover()
			_, err := c.Write(data)
			Expect(err).NotTo(HaveOccurred())
			Expect(c.CloseWrite()).To(Succeed())
		}()
		Expect(c.SetReadDeadline(time.Now().Add(30 * time.Second))).To(Succeed())
		got, err := io.ReadAll(c)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(got)).To(Equal(len(data)))
		Expect(bytes.Equal(got, data)).To(BeTrue())
	})

	It("says why a forward did not connect", func() {
		startRelay(testAgentKey, dialAgent(a), "")
		port := strconv.Itoa(closedPort())
		_, answer := ask("forward 127.0.0.1 " + port)
		Expect(answer).To(HavePrefix("error: connecting to 127.0.0.1 port " + port + " in the guest: "))
	})

	It("ends its clients' connections when it closes", func() {
		r, err := newAgentRelay(path, []byte(testAgentKey), dialAgent(a), "", agentRelayWait, logger)
		Expect(err).NotTo(HaveOccurred())
		c, answer := ask("forward 127.0.0.1 " + strconv.Itoa(upperServer()))
		Expect(answer).To(Equal("ok"))
		r.close()
		Expect(c.SetReadDeadline(time.Now().Add(5 * time.Second))).To(Succeed())
		_, err = c.Read(make([]byte, 1))
		Expect(err).To(MatchError(io.EOF))
		_, err = net.Dial("unix", path)
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("the host side of the guest agent", func() {
	var dir string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
	})

	openTemp := func(name, content string) *os.File {
		f, err := os.Open(writeTempFile(name, content))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = f.Close() })
		return f
	}

	withBinary := func(path string) {
		old := guestAgentBinary
		guestAgentBinary = path
		DeferCleanup(func() { guestAgentBinary = old })
	}

	It("gives QEMU the reserved vsock device as the next descriptor, after every other device", func() {
		vhost := openTemp("vhost", "")
		a := &hostAgent{bin: openTemp("bin", "agent"), vhost: vhost, cid: 77}
		files := []*os.File{openTemp("one", ""), openTemp("two", "")}
		gotFiles, argv, err := a.hypervisor(backend.VMQemu, dir, files, []string{"qemu", "-device", "virtio-balloon-device"})
		Expect(err).NotTo(HaveOccurred())
		Expect(gotFiles).To(Equal([]*os.File{files[0], files[1], vhost}))
		Expect(argv).To(Equal([]string{"qemu", "-device", "virtio-balloon-device", "-device", "vhost-vsock-device,guest-cid=77,vhostfd=5"}))

		a.closeDevice()
		Expect(a.vhost).To(BeNil())
		_, err = vhost.Stat()
		Expect(err).To(MatchError(os.ErrClosed))
		a.closeDevice()
	})

	It("adds the vsock device to Firecracker's configuration, with its socket in the work directory", func() {
		cfgPath := filepath.Join(dir, "fc.json")
		before, err := json.Marshal(firecrackerConfig{BootSource: firecrackerBootSource{KernelImagePath: "vmlinux", InitrdPath: "initrd", BootArgs: "console=ttyS0"}})
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(cfgPath, before, 0o600)).To(Succeed())
		a := &hostAgent{bin: openTemp("bin", "agent"), udsPath: filepath.Join(dir, firecrackerVsockName)}
		files := []*os.File{openTemp("one", "")}
		gotFiles, argv, err := a.hypervisor(backend.VMFirecracker, dir, files, []string{"firecracker"})
		Expect(err).NotTo(HaveOccurred())
		Expect(gotFiles).To(Equal(files))
		Expect(argv).To(Equal([]string{"firecracker"}))
		var after map[string]any
		data, err := os.ReadFile(cfgPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(json.Unmarshal(data, &after)).To(Succeed())
		Expect(after["vsock"]).To(Equal(map[string]any{"guest_cid": float64(3), "uds_path": filepath.Join(dir, "agent.vsock")}))
		Expect(after["boot-source"]).To(HaveKeyWithValue("boot_args", "console=ttyS0"))
	})

	It("leaves the hypervisor alone when the launch has no agent", func() {
		files := []*os.File{openTemp("one", "")}
		for _, a := range []*hostAgent{nil, {vhost: openTemp("vhost", ""), off: "no agent"}} {
			gotFiles, argv, err := a.hypervisor(backend.VMQemu, dir, files, []string{"qemu"})
			Expect(err).NotTo(HaveOccurred())
			Expect(gotFiles).To(Equal(files))
			Expect(argv).To(Equal([]string{"qemu"}))
			Expect(a.guestFiles(nil)).To(BeNil())
			Expect(a.inGuest()).To(BeFalse())
		}
		var a *hostAgent
		a.closeDevice()
		a.close()
	})

	It("gives each kind of guest's agent its mode, and the Docker image guest's agent the image's user", func() {
		a := &hostAgent{key: testAgentKey, bin: openTemp("bin", "agent binary")}
		cases := []struct {
			stack  *guestStack
			mode   string
			config string
		}{
			{nil, agentModeBusybox, `{"key":"` + testAgentKey + `"}`},
			{&guestStack{}, agentModeStack, `{"key":"` + testAgentKey + `"}`},
			{&guestStack{image: &guestImage{uid: 1001, gid: 1002}}, agentModeImage, `{"key":"` + testAgentKey + `","uid":1001,"gid":1002}`},
		}
		for _, c := range cases {
			files, err := a.guestFiles(c.stack)
			Expect(err).NotTo(HaveOccurred())
			Expect(files.mode).To(Equal(c.mode))
			Expect(files.config).To(Equal(c.config))
			Expect(files.bin.file).To(Equal(a.bin))
			Expect(files.bin.size).To(Equal(int64(len("agent binary"))))
		}
	})

	It("sets a Firecracker launch up with a fresh key, the vsock socket in the work directory, and a relay", func() {
		withBinary(writeTempFile("vm-launch", "agent binary"))
		sock := filepath.Join(dir, "agent.sock")
		a, err := newHostAgent(backend.VMFirecracker, dir, sock, log.New(GinkgoWriter, "", 0))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(a.close)
		Expect(a.off).To(BeEmpty())
		Expect(a.inGuest()).To(BeTrue())
		Expect(a.key).To(MatchRegexp("^[0-9a-f]{64}$"))
		Expect(a.udsPath).To(Equal(filepath.Join(dir, "agent.vsock")))
		Expect(a.bin).NotTo(BeNil())
		Expect(sock).To(BeAnExistingFile())

		other, err := newHostAgent(backend.VMFirecracker, dir, filepath.Join(dir, "other.sock"), log.New(GinkgoWriter, "", 0))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(other.close)
		Expect(other.key).NotTo(Equal(a.key))
	})

	It("runs without the agent, and says why, when its binary cannot be opened", func() {
		withBinary(filepath.Join(dir, "missing"))
		sock := filepath.Join(dir, "agent.sock")
		logs := new(lockedBuffer)
		a, err := newHostAgent(backend.VMFirecracker, dir, sock, log.New(logs, "", 0))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(a.close)
		Expect(a.off).To(HavePrefix("this guest has no agent for cf ssh, because opening " + filepath.Join(dir, "missing") + " failed: "))
		Expect(logs.String()).To(Equal(a.off + "\n"))
		Expect(a.guestFiles(nil)).To(BeNil())
		// The launch then carries no lifecycle shell into the guest either.
		Expect(a.inGuest()).To(BeFalse())

		c, err := net.Dial("unix", sock)
		Expect(err).NotTo(HaveOccurred())
		defer c.Close()
		_, err = io.WriteString(c, "session\n")
		Expect(err).NotTo(HaveOccurred())
		Expect(readLine(c, agentMaxLine)).To(Equal("error: " + a.off))
	})

	It("refuses a backend that is not a VM, and says why a vsock device cannot be reserved", func() {
		_, err := newHostAgent(backend.Kind("garden-runc"), dir, filepath.Join(dir, "agent.sock"), log.New(GinkgoWriter, "", 0))
		Expect(err).To(MatchError(`the guest agent does not support backend "garden-runc"`))
		_, _, err = reserveVsockCID(filepath.Join(dir, "vhost-vsock"))
		Expect(err).To(MatchError(HavePrefix("opening " + filepath.Join(dir, "vhost-vsock") + " failed: ")))
	})

	It("draws another vsock address while the one it drew is in use, and gives up after a fixed number", func() {
		device := writeTempFile("vhost-vsock", "")
		old := setVsockGuestCID
		DeferCleanup(func() { setVsockGuestCID = old })
		var tried []uint32
		inUse := 2
		setVsockGuestCID = func(_ *os.File, cid uint32) error {
			tried = append(tried, cid)
			if len(tried) <= inUse {
				return unix.EADDRINUSE
			}
			return nil
		}
		f, cid, err := reserveVsockCID(device)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = f.Close() })
		Expect(tried).To(HaveLen(3))
		Expect(cid).To(Equal(tried[2]))
		for _, c := range tried {
			Expect(c).To(BeNumerically(">=", vsockFirstGuestCID))
			Expect(c).To(BeNumerically("<", vsockLastGuestCID))
		}

		tried, inUse = nil, vsockCIDAttempts
		_, _, err = reserveVsockCID(device)
		Expect(err).To(MatchError(fmt.Sprintf("every one of %d random vsock addresses was in use", vsockCIDAttempts)))
		Expect(tried).To(HaveLen(vsockCIDAttempts))

		setVsockGuestCID = func(*os.File, uint32) error { return unix.EPERM }
		_, _, err = reserveVsockCID(device)
		Expect(err).To(MatchError("reserving a vsock address on " + device + " failed: operation not permitted"))
	})

	It("connects through Firecracker's vsock socket with its CONNECT handshake", func() {
		udsPath := filepath.Join(dir, "fc.vsock")
		ln, err := net.Listen("unix", udsPath)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = ln.Close() })
		answers := make(chan string, 2)
		answers <- "OK 1073741824"
		answers <- "NOPE"
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				line, err := readLine(c, agentMaxLine)
				if err != nil || line != "CONNECT 22" {
					c.Close()
					continue
				}
				_, _ = io.WriteString(c, <-answers+"\nafter the answer")
				go func() {
					time.Sleep(time.Second)
					c.Close()
				}()
			}
		}()
		c, err := dialFirecrackerVsock(udsPath, agentPort, time.Second)
		Expect(err).NotTo(HaveOccurred())
		defer c.Close()
		got := make([]byte, len("after the answer"))
		_, err = io.ReadFull(c, got)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("after the answer"), "nothing after the answer's newline is consumed")

		_, err = dialFirecrackerVsock(udsPath, agentPort, time.Second)
		Expect(err).To(MatchError(`the Firecracker vsock device answered CONNECT 22 with "NOPE"`))
	})

	It("reads one line without what follows it, and refuses a longer one", func() {
		r := strings.NewReader("ok\nrest")
		Expect(readLine(r, 8)).To(Equal("ok"))
		rest, err := io.ReadAll(r)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(rest)).To(Equal("rest"))
		_, err = readLine(strings.NewReader("123456789\n"), 8)
		Expect(err).To(MatchError("the line is longer than 8 bytes"))
	})
})

var _ = Describe("the guest agent's shim", func() {
	It("runs as the shim only under bash's name", func() {
		for _, argv0 := range []string{"/bin/bash", "bash", "-bash", "/usr/local/bin/bash"} {
			Expect(isGuestShell(argv0)).To(BeTrue(), argv0)
		}
		for _, argv0 := range []string{"/bin/sh", "/opt/garden-vm/vm-launch", "vm-launch", "bash2", "/tmp/bash/vm-launch"} {
			Expect(isGuestShell(argv0)).To(BeFalse(), argv0)
		}
	})

	It("is off unless the launch has --guest-agent", func() {
		cfg, err := parseArgs([]string{"--backend", "vm-qemu", "--", "true"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.guestAgent).To(BeFalse())
		cfg, err = parseArgs([]string{"--backend", "vm-firecracker", "--" + guestAgentFlag, "--", "true"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.guestAgent).To(BeTrue())
		Expect(usage).To(ContainSubstring("[--guest-agent]"))
	})
})

var _ = Describe("the guest agent's initramfs", func() {
	agentFiles := func(mode string) *guestAgentFiles {
		f, err := os.Open(writeTempFile("vm-launch", "agent binary"))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = f.Close() })
		return &guestAgentFiles{bin: guestTool{name: "the guest agent", file: f, size: int64(len("agent binary"))}, config: `{"key":"k"}`, mode: mode}
	}

	archive := func(g guestContents) ([]string, map[string]cpioEntry) {
		var buf bytes.Buffer
		Expect(writeInitramfsArchive(&buf, strings.NewReader("busybox"), int64(len("busybox")), g)).To(Succeed())
		return archiveEntries(buf.Bytes())
	}

	startLine := func(mode string) string {
		return "( echo -1000 >/proc/self/oom_score_adj; exec /rvm/agent/vm-launch guest-agent " + mode + " ) </dev/null &\necho " + startTag(testNonce) + "\n"
	}

	It("starts the agent just before the start tag, and refuses a stage 2 without exactly one", func() {
		tag := "echo " + startTag(testNonce) + "\n"
		got, err := withGuestAgentStart("setup\n"+tag+"run\n", testNonce, agentModeStack)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("setup\n" + startLine(agentModeStack) + "run\n"))
		_, err = withGuestAgentStart("setup\n", testNonce, agentModeStack)
		Expect(err).To(MatchError("stage 2 has 0 start tag lines, and the guest agent starts before exactly one"))
		_, err = withGuestAgentStart(tag+tag, testNonce, agentModeStack)
		Expect(err).To(MatchError("stage 2 has 2 start tag lines, and the guest agent starts before exactly one"))
	})

	It("gives the busybox guest the agent's binary and configuration as root's alone, and starts it in busybox mode", func() {
		g := taskGuest("true")
		g.agent = agentFiles(agentModeBusybox)
		names, byName := archive(g)
		Expect(names).To(ContainElements("rvm/agent", "rvm/agent/vm-launch", "rvm/agent/config"))
		Expect(byName["rvm/agent"].mode).To(Equal(uint32(0o040700)))
		Expect(byName["rvm/agent/vm-launch"].mode).To(Equal(uint32(0o100700)))
		Expect(string(byName["rvm/agent/vm-launch"].data)).To(Equal("agent binary"))
		Expect(byName["rvm/agent/config"].mode).To(Equal(uint32(0o100600)))
		Expect(string(byName["rvm/agent/config"].data)).To(Equal(`{"key":"k"}`))
		want, err := withGuestAgentStart(initScript(testNonce, false), testNonce, agentModeBusybox)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(byName["rvm/init"].data)).To(Equal(want))
		Expect(want).To(ContainSubstring(startLine(agentModeBusybox)))
	})

	It("starts a stack guest's agent in stack mode, and the agent of the busybox guest it falls back to in busybox mode", func() {
		launcher, err := os.Open(writeTempFile("launcher", "#!/bin/sh\n"))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = launcher.Close() })
		g := taskGuest("")
		g.drives.stackID, g.drives.dropletID = qemuStackSerial, qemuDropletSerial
		g.stack = &guestStack{
			launcher: guestTool{name: "launcher", file: launcher, size: int64(len("#!/bin/sh\n"))},
			argv:     shellJoin([]string{stackLauncherPath, "/home/vcap/app", "", ""}),
			cwd:      "/home/vcap/app",
			hostname: "stack-guest-0",
			hosts:    []byte("127.0.0.1 localhost\n"),
			fallback: true,
		}
		g.agent = agentFiles(agentModeStack)
		_, byName := archive(g)
		stage2, err := withGuestAgentStart(g.stack.initScript(testNonce), testNonce, agentModeStack)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(byName["rvm/init"].data)).To(Equal(stage2))
		fallback, err := withGuestAgentStart(initScript(testNonce, false), testNonce, agentModeBusybox)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(byName[strings.TrimPrefix(guestFallbackInit, "/")].data)).To(Equal(fallback))
	})

	It("puts the lifecycle's shell beside the launcher in a stack guest that has it, and nothing there in one that does not", func() {
		launcher, err := os.Open(writeTempFile("launcher", "#!/bin/sh\n"))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = launcher.Close() })
		shell, err := os.Open(writeTempFile("shell", "the lifecycle shell"))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = shell.Close() })
		guest := func(withShell bool) guestContents {
			g := taskGuest("")
			g.drives.stackID, g.drives.dropletID = qemuStackSerial, qemuDropletSerial
			g.stack = &guestStack{
				launcher: guestTool{name: "launcher", file: launcher, size: int64(len("#!/bin/sh\n"))},
				argv:     shellJoin([]string{stackLauncherPath, "/home/vcap/app", "", ""}),
				cwd:      "/home/vcap/app",
				hostname: "stack-guest-0",
				hosts:    []byte("127.0.0.1 localhost\n"),
			}
			if withShell {
				g.stack.shell = guestTool{name: lifecycleShellName, file: shell, size: int64(len("the lifecycle shell"))}
			}
			g.agent = agentFiles(agentModeStack)
			return g
		}

		names, byName := archive(guest(true))
		Expect(names).To(ContainElement("rvm/lifecycle/shell"))
		Expect(byName["rvm/lifecycle/shell"].mode).To(Equal(uint32(0o100755)))
		Expect(string(byName["rvm/lifecycle/shell"].data)).To(Equal("the lifecycle shell"))
		Expect(byName["rvm/lifecycle/launcher"].mode).To(Equal(uint32(0o100755)))

		names, _ = archive(guest(false))
		Expect(names).To(ContainElement("rvm/lifecycle/launcher"))
		Expect(names).NotTo(ContainElement("rvm/lifecycle/shell"))
	})

	It("opens the lifecycle's shell beside the launcher, and goes without it, saying why only when it is there but unusable", func() {
		dir := GinkgoT().TempDir()
		launcher := filepath.Join(dir, "launcher")
		Expect(os.WriteFile(launcher, []byte("#!/bin/sh\n"), 0o755)).To(Succeed())
		logs := new(lockedBuffer)
		logger := log.New(logs, "", 0)

		Expect(openLifecycleShell(launcher, logger).file).To(BeNil())
		Expect(logs.String()).To(BeEmpty())

		Expect(os.WriteFile(filepath.Join(dir, lifecycleShellName), []byte("#!/bin/sh\n"), 0o644)).To(Succeed())
		Expect(openLifecycleShell(launcher, logger).file).To(BeNil())
		Expect(logs.String()).To(Equal("the guest has no lifecycle shell: guest tool shell at " + filepath.Join(dir, lifecycleShellName) + " is not executable\n"))

		Expect(os.Chmod(filepath.Join(dir, lifecycleShellName), 0o755)).To(Succeed())
		shell := openLifecycleShell(launcher, logger)
		Expect(shell.file).NotTo(BeNil())
		DeferCleanup(func() { _ = shell.file.Close() })
		Expect(shell.size).To(Equal(int64(len("#!/bin/sh\n"))))
	})

	It("leaves a guest without the agent as it was", func() {
		names, byName := archive(taskGuest("true"))
		for _, name := range names {
			Expect(name).NotTo(HavePrefix("rvm/agent"))
		}
		Expect(string(byName["rvm/init"].data)).To(Equal(initScript(testNonce, false)))
	})
})
