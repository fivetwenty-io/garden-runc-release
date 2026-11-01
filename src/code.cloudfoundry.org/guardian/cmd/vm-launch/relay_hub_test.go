//go:build linux

package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const testRelayKey = "0123456789abcdef0123456789abcdef"

// relayClient is a spec's end of a relay connection.
type relayClient struct {
	conn net.Conn
	r    *bufio.Reader
}

func dialRelay(path string, hello string) *relayClient {
	conn, err := net.Dial("unix", path)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { _ = conn.Close() })
	_, err = fmt.Fprintf(conn, "%s\n", hello)
	Expect(err).NotTo(HaveOccurred())
	return &relayClient{conn: conn, r: bufio.NewReader(conn)}
}

// line reads one line, without its newline, or fails after a few seconds.
func (c *relayClient) line() string {
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	l, err := c.r.ReadString('\n')
	Expect(err).NotTo(HaveOccurred(), "read so far: %q", l)
	return strings.TrimSuffix(l, "\n")
}

// rest reads every line until the hub closes the connection.
func (c *relayClient) rest() []string {
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var lines []string
	for {
		l, err := c.r.ReadString('\n')
		if err != nil {
			Expect(l).To(BeEmpty())
			return lines
		}
		lines = append(lines, strings.TrimSuffix(l, "\n"))
	}
}

var _ = Describe("the relay hub", func() {
	var (
		path           string
		stdout, stderr *lockedBuffer
		logs           *lockedBuffer
		logger         *log.Logger
	)

	BeforeEach(func() {
		path = filepath.Join(GinkgoT().TempDir(), "relay.sock")
		stdout, stderr, logs = new(lockedBuffer), new(lockedBuffer), new(lockedBuffer)
		logger = log.New(logs, "vm-launch: ", 0)
	})

	newHub := func(count int) *relayHub {
		h, err := newRelayHub(path, testRelayKey, count, stdout, stderr, logger)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(h.close)
		return h
	}

	hello := func(index int) string {
		return fmt.Sprintf("hello %d %s", index, testRelayKey)
	}

	Describe("creating it", func() {
		It("refuses no sidecars and more than eight", func() {
			_, err := newRelayHub(path, testRelayKey, 0, stdout, stderr, logger)
			Expect(err).To(MatchError("the log relays serve 1 to 8 sidecars, not 0"))
			_, err = newRelayHub(path, testRelayKey, 9, stdout, stderr, logger)
			Expect(err).To(MatchError("the log relays serve 1 to 8 sidecars, not 9"))
		})

		It("refuses a key that is not 32 lowercase hex digits", func() {
			for _, key := range []string{"", "abc", strings.ToUpper(testRelayKey), testRelayKey + "0"} {
				_, err := newRelayHub(path, key, 1, stdout, stderr, logger)
				Expect(err).To(MatchError("the sidecars' relay key is not 32 lowercase hex digits"))
			}
		})

		It("listens on a socket that only its user can reach", func() {
			newHub(1)
			info, err := os.Lstat(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Type()).To(Equal(os.ModeSocket))
			Expect(info.Mode().Perm() & 0o077).To(BeZero())
		})

		It("leaves the process umask as it was", func() {
			old := syscall.Umask(0o022)
			defer syscall.Umask(old)
			newHub(1)
			Expect(syscall.Umask(0o022)).To(Equal(0o022))
		})

		It("replaces an old socket of its user", func() {
			old, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			Expect(err).NotTo(HaveOccurred())
			old.SetUnlinkOnClose(false)
			Expect(old.Close()).To(Succeed())

			newHub(1)
			c := dialRelay(path, hello(1))
			Expect(c.line()).To(Equal("ok"))
		})

		It("refuses a path that holds something other than a socket", func() {
			Expect(os.WriteFile(path, nil, 0o600)).To(Succeed())
			_, err := newRelayHub(path, testRelayKey, 1, stdout, stderr, logger)
			Expect(err).To(MatchError(path + " exists and is not a socket of this user, so the sidecars' log relays cannot attach"))
		})

		It("removes the socket when it closes, and closes again without harm", func() {
			h := newHub(1)
			h.close()
			h.close()
			_, err := os.Lstat(path)
			Expect(os.IsNotExist(err)).To(BeTrue())
		})

		It("does nothing for a nil hub", func() {
			var h *relayHub
			h.close()
			h.finish(0, nil, time.Hour)
		})
	})

	Describe("a hello", func() {
		refused := func(hello, reason string) {
			c := dialRelay(path, hello)
			Expect(c.rest()).To(Equal([]string{"no " + reason}))
			Eventually(logs.String).Should(ContainSubstring("vm-launch: refused a sidecar log relay: " + reason + "\n"))
		}

		It("is refused with the wrong key", func() {
			newHub(2)
			refused("hello 1 ffffffffffffffffffffffffffffffff", "the wrong key for index 1")
		})

		It("is refused for an index the app has no sidecar at", func() {
			newHub(2)
			refused("hello 3 "+testRelayKey, `index "3" is not a sidecar of this app`)
			refused("hello 0 "+testRelayKey, `index "0" is not a sidecar of this app`)
			refused("hello 01 "+testRelayKey, `index "01" is not a sidecar of this app`)
		})

		It("is refused when it is malformed", func() {
			newHub(1)
			refused("hi 1 "+testRelayKey, "a malformed hello")
			refused("hello 1", "a malformed hello")
			refused("hello 1 "+testRelayKey+" more", "a malformed hello")
			refused(strings.Repeat("x", 200), "a malformed hello")
		})

		It("is refused for an index that already has a relay, which keeps its stream", func() {
			h := newHub(1)
			first := dialRelay(path, hello(1))
			Expect(first.line()).To(Equal("ok"))

			refused(hello(1), "index 1 already has a relay")

			h.deliver(1, 'o', "still here")
			Expect(first.line()).To(Equal("o still here"))
		})

		It("checks the key before it says that an index has a relay", func() {
			newHub(1)
			first := dialRelay(path, hello(1))
			Expect(first.line()).To(Equal("ok"))
			refused("hello 1 ffffffffffffffffffffffffffffffff", "the wrong key for index 1")
		})
	})

	Describe("the lines", func() {
		It("delivers the lines queued before the hello, in order, after ok", func() {
			h := newHub(2)
			h.deliver(2, 'o', "one")
			h.deliver(2, 'e', "two")
			h.deliver(1, 'o', "for the other sidecar")
			h.deliver(2, 'o', "")

			c := dialRelay(path, hello(2))
			Expect(c.line()).To(Equal("ok"))
			Expect(c.line()).To(Equal("o one"))
			Expect(c.line()).To(Equal("e two"))
			Expect(c.line()).To(Equal("o "))
		})

		It("delivers the lines that come after the hello", func() {
			h := newHub(1)
			c := dialRelay(path, hello(1))
			Expect(c.line()).To(Equal("ok"))
			for i := 0; i < 100; i++ {
				h.deliver(1, 'o', fmt.Sprintf("line %d", i))
			}
			for i := 0; i < 100; i++ {
				Expect(c.line()).To(Equal(fmt.Sprintf("o line %d", i)))
			}
		})

		It("sends a line that holds a newline as several", func() {
			h := newHub(1)
			h.deliver(1, 'e', "a\nb")
			c := dialRelay(path, hello(1))
			Expect(c.line()).To(Equal("ok"))
			Expect(c.line()).To(Equal("e a"))
			Expect(c.line()).To(Equal("e b"))
		})

		It("drops the oldest lines past the limit and counts them ahead of the next line", func() {
			h := newHub(1)
			text := strings.Repeat("y", 1024-3)
			fit := relayQueueLimit / 1024
			for i := 0; i < fit+90; i++ {
				h.deliver(1, 'o', fmt.Sprintf("%04d%s", i, text[4:]))
			}

			c := dialRelay(path, hello(1))
			Expect(c.line()).To(Equal("ok"))
			Expect(c.line()).To(Equal("e vm-launch: dropped 90 lines of this sidecar's output because its log relay fell behind"))
			Expect(c.line()).To(HavePrefix("o 0090"))
			for i := 91; i < fit+90; i++ {
				Expect(c.line()).To(HavePrefix(fmt.Sprintf("o %04d", i)))
			}
		})

		It("never blocks the caller on a relay that does not read", func() {
			h := newHub(1)
			c := dialRelay(path, hello(1))
			Expect(c.line()).To(Equal("ok"))

			done := make(chan struct{})
			go func() {
				defer close(done)
				big := strings.Repeat("z", 60<<10)
				for i := 0; i < 200; i++ {
					h.deliver(1, 'o', big)
				}
			}()
			Eventually(done, "5s").Should(BeClosed())
		})

		It("counts the lines for an index the app has no sidecar at", func() {
			h := newHub(1)
			h.deliver(2, 'o', "lost")
			h.deliver(0, 'o', "lost")
			h.close()
			Expect(stdout.String()).To(BeEmpty())
			Expect(logs.String()).To(ContainSubstring("vm-launch: dropped 2 lines for sidecar indexes this app does not have\n"))
		})
	})

	Describe("a first exit", func() {
		It("queues a sidecar's status behind its lines", func() {
			h := newHub(2)
			h.deliver(2, 'o', "last words")
			h.first(2, 3)
			h.first(1, 4)

			other := dialRelay(path, hello(1))
			Expect(other.line()).To(Equal("ok"))
			c := dialRelay(path, hello(2))
			Expect(c.line()).To(Equal("ok"))
			Expect(c.line()).To(Equal("o last words"))
			Expect(c.line()).To(Equal("x 3"))

			h.finish(syscall.SIGTERM, nil, time.Hour)
			Expect(other.rest()).To(BeEmpty())
			Expect(c.rest()).To(BeEmpty())
		})

		It("sends the status at once to a relay that is already attached", func() {
			h := newHub(1)
			c := dialRelay(path, hello(1))
			Expect(c.line()).To(Equal("ok"))
			h.first(1, 0)
			Expect(c.line()).To(Equal("x 0"))
		})

		It("sends no status when the app exited first", func() {
			h := newHub(1)
			c := dialRelay(path, hello(1))
			Expect(c.line()).To(Equal("ok"))
			h.deliver(1, 'o', "before")
			h.first(0, 1)
			h.first(1, 3)
			Expect(c.line()).To(Equal("o before"))

			h.finish(0, nil, time.Hour)
			Expect(c.rest()).To(BeEmpty())
		})
	})

	Describe("finishing", func() {
		It("holds up to the hold time for a signal when a sidecar exited first without one", func() {
			h := newHub(1)
			h.first(1, 3)

			start := time.Now()
			h.finish(0, make(chan os.Signal), 300*time.Millisecond)
			Expect(time.Since(start)).To(BeNumerically(">=", 300*time.Millisecond))
			Expect(logs.String()).To(ContainSubstring("vm-launch: no stop signal came within 300ms of sidecar 1's exit, so vm-launch exits with the guest's status\n"))
		})

		It("ends the hold when the signal comes", func() {
			h := newHub(1)
			h.first(1, 3)
			sigs := make(chan os.Signal, 1)
			time.AfterFunc(100*time.Millisecond, func() { sigs <- syscall.SIGTERM })

			start := time.Now()
			h.finish(0, sigs, time.Hour)
			Expect(time.Since(start)).To(BeNumerically("<", 5*time.Second))
			Expect(logs.String()).NotTo(ContainSubstring("no stop signal"))
		})

		It("does not hold when vm-launch already received a signal", func() {
			h := newHub(1)
			h.first(1, 3)
			start := time.Now()
			h.finish(syscall.SIGTERM, make(chan os.Signal), time.Hour)
			Expect(time.Since(start)).To(BeNumerically("<", 5*time.Second))
		})

		It("does not hold when the app exited first or no exit was reported", func() {
			h := newHub(1)
			h.first(0, 1)
			h.finish(0, make(chan os.Signal), time.Hour)

			h2, err := newRelayHub(path+"2", testRelayKey, 1, stdout, stderr, logger)
			Expect(err).NotTo(HaveOccurred())
			h2.finish(0, make(chan os.Signal), time.Hour)
		})

		It("delivers the status to a relay that attaches during the hold", func() {
			h := newHub(1)
			h.deliver(1, 'e', "crashing")
			h.first(1, 3)
			sigs := make(chan os.Signal, 1)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				h.finish(0, sigs, time.Hour)
			}()

			c := dialRelay(path, hello(1))
			Expect(c.line()).To(Equal("ok"))
			Expect(c.line()).To(Equal("e crashing"))
			Expect(c.line()).To(Equal("x 3"))
			sigs <- syscall.SIGTERM
			Eventually(finished, "5s").Should(BeClosed())
			Expect(stdout.String() + stderr.String()).To(BeEmpty())
		})

		It("lets an attached relay drain its queue and then closes its stream", func() {
			h := newHub(1)
			c := dialRelay(path, hello(1))
			Expect(c.line()).To(Equal("ok"))
			for i := 0; i < 1000; i++ {
				h.deliver(1, 'o', fmt.Sprintf("line %d", i))
			}
			h.finish(syscall.SIGTERM, nil, time.Hour)

			lines := c.rest()
			Expect(lines).To(HaveLen(1000))
			Expect(lines[999]).To(Equal("o line 999"))
			Expect(stdout.String()).To(BeEmpty())
			_, err := os.Lstat(path)
			Expect(os.IsNotExist(err)).To(BeTrue())
		})

		It("gives a relay that does not read only the drain time, and writes what it did not take to vm-launch's output", func() {
			h := newHub(1)
			c := dialRelay(path, hello(1))
			Expect(c.line()).To(Equal("ok"))
			big := strings.Repeat("z", 60<<10)
			for i := 0; i < 8; i++ {
				h.deliver(1, 'o', fmt.Sprintf("%d%s", i, big))
			}

			start := time.Now()
			h.finish(syscall.SIGTERM, nil, time.Hour)
			Expect(time.Since(start)).To(BeNumerically("<", relayDrain+2*time.Second))
			Expect(stdout.String()).To(ContainSubstring("7" + big + "\n"))
			Expect(logs.String()).To(MatchRegexp(`vm-launch: sidecar 1's log relay fell behind, so its last \d+ lines follow on vm-launch's own output\n`))
		})

		It("writes the lines of a relay that never attached to vm-launch's own stdout and stderr", func() {
			h := newHub(2)
			h.deliver(2, 'o', "out line")
			h.deliver(2, 'e', "err line")
			h.first(2, 3)

			h.finish(syscall.SIGTERM, nil, time.Hour)
			Expect(stdout.String()).To(Equal("out line\n"))
			Expect(stderr.String()).To(Equal("err line\n"))
			Expect(logs.String()).To(ContainSubstring("vm-launch: sidecar 2's log relay never attached, so its last 2 lines follow on vm-launch's own output\n"))
		})

		It("counts the lines a relay that never attached dropped", func() {
			h := newHub(1)
			text := strings.Repeat("y", 1024-3)
			for i := 0; i < relayQueueLimit/1024+5; i++ {
				h.deliver(1, 'o', text)
			}
			h.close()
			Expect(logs.String()).To(ContainSubstring("vm-launch: dropped 5 lines of sidecar 1's output because its log relay never attached\n"))
		})

		It("writes the lines of a relay that went away to vm-launch's own output", func() {
			h := newHub(1)
			c := dialRelay(path, hello(1))
			Expect(c.line()).To(Equal("ok"))
			Expect(c.conn.Close()).To(Succeed())
			Eventually(func() bool {
				h.deliver(1, 'o', "after the relay left")
				h.mu.Lock()
				defer h.mu.Unlock()
				return h.queues[0].broken
			}, "5s").Should(BeTrue())

			h.finish(syscall.SIGTERM, nil, time.Hour)
			Expect(stdout.String()).To(ContainSubstring("after the relay left\n"))
		})

		It("writes a line that comes after it closed to vm-launch's own output", func() {
			h := newHub(1)
			h.close()
			h.deliver(1, 'e', "late")
			Expect(stderr.String()).To(Equal("late\n"))
		})

		It("closes a connection that has not said hello", func() {
			h := newHub(1)
			conn, err := net.Dial("unix", path)
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()
			Eventually(func() int {
				h.mu.Lock()
				defer h.mu.Unlock()
				return len(h.hellos)
			}).Should(Equal(1))

			h.close()
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Read(make([]byte, 1))
			Expect(err).To(HaveOccurred())
			Expect(os.IsTimeout(err)).To(BeFalse())
		})
	})
})
