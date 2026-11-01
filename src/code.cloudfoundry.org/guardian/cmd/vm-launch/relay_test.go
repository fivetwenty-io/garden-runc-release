//go:build linux

package main

import (
	"bufio"
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

var _ = Describe("the relay", func() {
	var (
		path           string
		stdout, stderr *lockedBuffer
		hubLogs        *lockedBuffer
		sigs           chan os.Signal
		r              relay
	)

	BeforeEach(func() {
		path = filepath.Join(GinkgoT().TempDir(), "relay.sock")
		stdout, stderr, hubLogs = new(lockedBuffer), new(lockedBuffer), new(lockedBuffer)
		sigs = make(chan os.Signal, 4)
		r = relay{
			socket:  path,
			value:   "1:" + testRelayKey,
			stdout:  stdout,
			stderr:  stderr,
			logger:  log.New(stderr, "vm-launch relay: ", 0),
			signals: sigs,
			retry:   10 * time.Millisecond,
			endWait: 200 * time.Millisecond,
		}
	})

	start := func() chan int {
		code := make(chan int, 1)
		go func() { code <- r.run() }()
		return code
	}

	newHub := func(count int) *relayHub {
		h, err := newRelayHub(path, testRelayKey, count, new(lockedBuffer), new(lockedBuffer), log.New(hubLogs, "vm-launch: ", 0))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(h.close)
		return h
	}

	// attached waits until the hub has given index its relay.
	attached := func(h *relayHub, index int) {
		Eventually(func() bool {
			h.mu.Lock()
			defer h.mu.Unlock()
			return h.queues[index-1].done != nil
		}, "5s").Should(BeTrue())
	}

	// fakeHub listens at path and hands each connection, after it read the
	// hello, to serve.
	fakeHub := func(serve func(conn net.Conn, hello string)) {
		l, err := net.Listen("unix", path)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(l.Close)
		go func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				hello, _ := bufio.NewReader(conn).ReadString('\n')
				go func() {
					defer conn.Close()
					serve(conn, strings.TrimSuffix(hello, "\n"))
				}()
			}
		}()
	}

	It("refuses a value that is not an index and a key", func() {
		for _, value := range []string{"", "1", "0:" + testRelayKey, "9:" + testRelayKey, "1:" + strings.ToUpper(testRelayKey), "1:" + testRelayKey + "0", " 1:" + testRelayKey} {
			r.value = value
			stderr.buf.Reset()
			Expect(r.run()).To(Equal(1))
			Expect(stderr.String()).To(Equal("vm-launch relay: CF_VM_SIDECAR_RELAY is not an index from 1 to 8 and a key of 32 lowercase hex digits\n"))
		}
	})

	It("exits with the sidecar's status after the sidecar's lines", func() {
		h := newHub(1)
		code := start()
		attached(h, 1)
		h.deliver(1, 'o', "to stdout")
		h.deliver(1, 'e', "to stderr")
		h.deliver(1, 'o', "")
		h.first(1, 3)

		Eventually(code, "5s").Should(Receive(Equal(3)))
		Expect(stdout.String()).To(Equal("to stdout\n\n"))
		Expect(stderr.String()).To(Equal("to stderr\n"))
	})

	It("exits 0 for a status of 0", func() {
		h := newHub(1)
		h.first(1, 0)
		Eventually(start(), "5s").Should(Receive(Equal(0)))
	})

	It("serves the index in its value", func() {
		r.value = "2:" + testRelayKey
		h := newHub(2)
		code := start()
		attached(h, 2)
		h.deliver(1, 'o', "not mine")
		h.deliver(2, 'o', "mine")
		h.first(2, 5)
		Eventually(code, "5s").Should(Receive(Equal(5)))
		Expect(stdout.String()).To(Equal("mine\n"))
	})

	It("dials until the hub listens", func() {
		code := start()
		Consistently(code, "100ms").ShouldNot(Receive())

		h := newHub(1)
		h.deliver(1, 'o', "queued before the hello")
		h.first(1, 4)
		Eventually(code, "5s").Should(Receive(Equal(4)))
		Expect(stdout.String()).To(Equal("queued before the hello\n"))
	})

	It("exits at once with 128 plus the signal before it reaches the hub", func() {
		code := start()
		Consistently(code, "50ms").ShouldNot(Receive())
		sigs <- syscall.SIGTERM
		Eventually(code, "5s").Should(Receive(Equal(143)))
	})

	It("exits at once on a signal while the hub has not accepted its hello", func() {
		hellos := make(chan string, 1)
		release := make(chan struct{})
		DeferCleanup(func() { close(release) })
		fakeHub(func(conn net.Conn, hello string) {
			hellos <- hello
			<-release
		})
		code := start()
		Eventually(hellos, "5s").Should(Receive(Equal("hello 1 " + testRelayKey)))
		sigs <- syscall.SIGINT
		Eventually(code, "5s").Should(Receive(Equal(130)))
	})

	It("keeps the stream open after a signal, and then exits with 128 plus the signal", func() {
		h := newHub(1)
		code := start()
		// A line the relay wrote shows that it has the hub's ok.
		h.deliver(1, 'o', "before the stop")
		Eventually(stdout.String, "5s").Should(Equal("before the stop\n"))
		sigs <- syscall.SIGTERM
		Consistently(code, "100ms").ShouldNot(Receive())

		h.deliver(1, 'o', "during the stop")
		h.first(1, 3)
		Eventually(code, "5s").Should(Receive(Equal(143)))
		Expect(stdout.String()).To(Equal("before the stop\nduring the stop\n"))
	})

	It("exits with 128 plus the signal when the stream ends after the signal", func() {
		h := newHub(1)
		code := start()
		attached(h, 1)
		sigs <- syscall.SIGTERM
		h.deliver(1, 'e', "last")
		h.finish(syscall.SIGTERM, nil, time.Hour)
		Eventually(code, "5s").Should(Receive(Equal(143)))
		Expect(stderr.String()).To(Equal("last\n"))
	})

	It("waits for the signal when the stream ends without a status", func() {
		h := newHub(1)
		code := start()
		attached(h, 1)
		r.endWait = time.Hour
		h.close()
		Consistently(code, "100ms").ShouldNot(Receive())
		sigs <- syscall.SIGTERM
		Eventually(code, "5s").Should(Receive(Equal(143)))
		Expect(stderr.String()).To(BeEmpty())
	})

	It("exits 1 when the stream ends without a status and no signal comes", func() {
		h := newHub(1)
		code := start()
		attached(h, 1)
		h.close()
		Eventually(code, "5s").Should(Receive(Equal(1)))
		Expect(stderr.String()).To(Equal("vm-launch relay: the log stream from vm-launch ended without the sidecar's exit status\n"))
	})

	It("takes a hub that closes before it answers as a stream that ended without a status", func() {
		fakeHub(func(conn net.Conn, hello string) {})
		code := start()
		Eventually(code, "5s").Should(Receive(Equal(1)))
		Expect(stderr.String()).To(Equal("vm-launch relay: the log stream from vm-launch ended without the sidecar's exit status\n"))
	})

	It("exits 1 with the hub's reason when the hub refuses its hello", func() {
		r.value = "1:ffffffffffffffffffffffffffffffff"
		newHub(1)
		Eventually(start(), "5s").Should(Receive(Equal(1)))
		Expect(stderr.String()).To(Equal("vm-launch relay: vm-launch refused the log relay for sidecar 1: the wrong key for index 1\n"))
	})

	It("exits 1 when a second relay serves the same index", func() {
		h := newHub(1)
		first := start()
		attached(h, 1)
		Eventually(start(), "5s").Should(Receive(Equal(1)))
		Expect(stderr.String()).To(Equal("vm-launch relay: vm-launch refused the log relay for sidecar 1: index 1 already has a relay\n"))
		Consistently(first, "50ms").ShouldNot(Receive())
	})

	It("exits 1 on a line it cannot read", func() {
		for _, bad := range []string{"what\n", "ok\nq line\n", "ok\nx three\n", "ok\nx 256\n", "ok\nx -1\n", "ok\no\n"} {
			bad := bad
			p := filepath.Join(GinkgoT().TempDir(), "relay.sock")
			r.socket = p
			l, err := net.Listen("unix", p)
			Expect(err).NotTo(HaveOccurred())
			go func() {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = bufio.NewReader(conn).ReadString('\n')
				_, _ = conn.Write([]byte(bad))
				time.Sleep(time.Second)
			}()
			stderr.buf.Reset()
			Expect(r.run()).To(Equal(1), bad)
			Expect(stderr.String()).To(HavePrefix("vm-launch relay: the log stream from vm-launch held a line the relay cannot read: "), bad)
			Expect(l.Close()).To(Succeed())
		}
	})

	It("keeps the order of its stdout and stderr lines", func() {
		w := new(lockedBuffer)
		r.stdout, r.stderr = w, w
		h := newHub(1)
		for _, l := range []string{"a", "b", "c", "d"} {
			stream := byte('o')
			if l == "b" || l == "c" {
				stream = 'e'
			}
			h.deliver(1, stream, l)
		}
		h.first(1, 2)
		Eventually(start(), "5s").Should(Receive(Equal(2)))
		Expect(w.String()).To(Equal("a\nb\nc\nd\n"))
	})

	It("takes no arguments", func() {
		Expect(runRelay([]string{"extra"})).To(Equal(1))
	})
})
