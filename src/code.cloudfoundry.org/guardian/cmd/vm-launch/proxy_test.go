//go:build linux

package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// testDialPolicy retries fast so the specs stay quick.
var testDialPolicy = dialPolicy{
	attemptTimeout:   200 * time.Millisecond,
	firstBackoff:     10 * time.Millisecond,
	maxBackoff:       50 * time.Millisecond,
	giveUp:           5 * time.Second,
	unansweredGiveUp: 5 * time.Second,
}

// startProxy returns a proxy for upstream that listens on listenAddr.
func startProxy(listenAddr, upstream string, policy dialPolicy, logger *log.Logger) (*tcpProxy, error) {
	p := newProxy(policy, logger)
	if err := p.Listen(listenAddr, upstream); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// Addr is the address of the open listener, or nil when there is none.
func (p *tcpProxy) Addr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ln := range p.listeners {
		return ln.Addr()
	}
	return nil
}

// serve accepts connections on l and runs handle for each until l closes.
func serve(l net.Listener, handle func(*net.TCPConn)) {
	go func() {
		defer GinkgoRecover()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(c.(*net.TCPConn))
			}()
		}
	}()
}

func echo(c *net.TCPConn) {
	if _, err := io.Copy(c, c); err == nil {
		_ = c.CloseWrite()
	}
}

func listenLocal() net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(l.Close)
	return l
}

// unusedAddr returns a loopback address nothing listens on.
func unusedAddr() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	addr := l.Addr().String()
	Expect(l.Close()).To(Succeed())
	return addr
}

// unansweredAddr returns the address of a loopback listener whose accept
// queue is full, so the kernel drops each new SYN and a dial to it gets no
// answer.
func unansweredAddr() string {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(unix.Close, fd)
	Expect(unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})).To(Succeed())
	// A backlog of 0 holds one connection that nobody accepts.
	Expect(unix.Listen(fd, 0)).To(Succeed())
	sa, err := unix.Getsockname(fd)
	Expect(err).NotTo(HaveOccurred())
	addr := fmt.Sprintf("127.0.0.1:%d", sa.(*unix.SockaddrInet4).Port)
	queued, err := net.Dial("tcp", addr)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(queued.Close)
	_, err = net.DialTimeout("tcp", addr, 200*time.Millisecond)
	Expect(isUnanswered(err)).To(BeTrue(), "a dial to the full listener: %v", err)
	return addr
}

var _ = Describe("tcpProxy", func() {
	var (
		logBuf *safeBuffer
		logger *log.Logger
	)

	BeforeEach(func() {
		logBuf = &safeBuffer{}
		logger = log.New(logBuf, "", 0)
	})

	startTestProxy := func(upstream string, policy dialPolicy) *tcpProxy {
		p, err := startProxy("127.0.0.1:0", upstream, policy, logger)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(p.Close)
		return p
	}

	dialProxy := func(p *tcpProxy) *net.TCPConn {
		c, err := net.Dial("tcp", p.Addr().String())
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(c.Close)
		Expect(c.SetDeadline(time.Now().Add(10 * time.Second))).To(Succeed())
		return c.(*net.TCPConn)
	}

	It("carries data both ways", func() {
		up := listenLocal()
		serve(up, echo)
		c := dialProxy(startTestProxy(up.Addr().String(), testDialPolicy))

		_, err := c.Write([]byte("hello"))
		Expect(err).NotTo(HaveOccurred())
		buf := make([]byte, 5)
		_, err = io.ReadFull(c, buf)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(buf)).To(Equal("hello"))
	})

	It("passes a client half-close upstream and keeps the reply direction open", func() {
		up := listenLocal()
		serve(up, func(c *net.TCPConn) {
			n, err := io.Copy(io.Discard, c)
			if err == nil {
				fmt.Fprintf(c, "got %d bytes", n)
			}
		})
		c := dialProxy(startTestProxy(up.Addr().String(), testDialPolicy))

		_, err := c.Write(bytes.Repeat([]byte("x"), 1<<20))
		Expect(err).NotTo(HaveOccurred())
		Expect(c.CloseWrite()).To(Succeed())
		reply, err := io.ReadAll(c)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(reply)).To(Equal("got 1048576 bytes"))
	})

	It("passes an upstream half-close to the client and keeps the request direction open", func() {
		up := listenLocal()
		received := make(chan string, 1)
		serve(up, func(c *net.TCPConn) {
			if _, err := c.Write([]byte("banner")); err != nil {
				return
			}
			if err := c.CloseWrite(); err != nil {
				return
			}
			b, _ := io.ReadAll(c)
			received <- string(b)
		})
		c := dialProxy(startTestProxy(up.Addr().String(), testDialPolicy))

		banner, err := io.ReadAll(c)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(banner)).To(Equal("banner"))
		_, err = c.Write([]byte("after EOF"))
		Expect(err).NotTo(HaveOccurred())
		Expect(c.CloseWrite()).To(Succeed())
		Eventually(received).Should(Receive(Equal("after EOF")))
	})

	It("holds an early connection until the guest app listens", func() {
		addr := unusedAddr()
		c := dialProxy(startTestProxy(addr, testDialPolicy))
		_, err := c.Write([]byte("early"))
		Expect(err).NotTo(HaveOccurred())

		time.Sleep(300 * time.Millisecond)
		up, err := net.Listen("tcp", addr)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(up.Close)
		serve(up, echo)

		buf := make([]byte, 5)
		_, err = io.ReadFull(c, buf)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(buf)).To(Equal("early"))
	})

	It("gives up on a guest that never listens and closes the client", func() {
		policy := testDialPolicy
		policy.giveUp = 200 * time.Millisecond
		c := dialProxy(startTestProxy(unusedAddr(), policy))

		began := time.Now()
		_, err := io.ReadAll(c)
		Expect(err).NotTo(HaveOccurred())
		Expect(time.Since(began)).To(BeNumerically("<", 3*time.Second))
		Eventually(logBuf.String).Should(ContainSubstring("giving up on the guest at"))
	})

	It("holds a connection to a guest that stopped listening through the guest's next look, and closes it soon after", func() {
		c := dialProxy(startTestProxy(unusedAddr(), upstreamDialPolicy))

		began := time.Now()
		_, err := io.ReadAll(c)
		Expect(err).NotTo(HaveOccurred())
		Expect(time.Since(began)).To(BeNumerically(">=", time.Second))
		Expect(time.Since(began)).To(BeNumerically("<", 4*time.Second))
		Eventually(logBuf.String).Should(ContainSubstring("giving up on the guest at"))
	})

	It("waits longer for a guest that does not answer than for one that refuses, and then closes the client", func() {
		c := dialProxy(startTestProxy(unansweredAddr(), upstreamDialPolicy))

		began := time.Now()
		_, err := io.ReadAll(c)
		Expect(err).NotTo(HaveOccurred())
		Expect(time.Since(began)).To(BeNumerically(">=", 4*time.Second))
		Expect(time.Since(began)).To(BeNumerically("<", 8*time.Second))
		Eventually(logBuf.String).Should(ContainSubstring("i/o timeout"))
	})

	It("serves concurrent connections independently", func() {
		up := listenLocal()
		serve(up, echo)
		p := startTestProxy(up.Addr().String(), testDialPolicy)

		var wg sync.WaitGroup
		errs := make(chan error, 20)
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c, err := net.Dial("tcp", p.Addr().String())
				if err != nil {
					errs <- err
					return
				}
				defer c.Close()
				msg := bytes.Repeat([]byte{byte('a' + i)}, 64<<10)
				if _, err := c.Write(msg); err != nil {
					errs <- err
					return
				}
				if err := c.(*net.TCPConn).CloseWrite(); err != nil {
					errs <- err
					return
				}
				got, err := io.ReadAll(c)
				if err == nil && !bytes.Equal(got, msg) {
					err = fmt.Errorf("connection %d: got %d bytes back, want %d", i, len(got), len(msg))
				}
				if err != nil {
					errs <- err
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		Expect(errs).To(BeEmpty())
	})

	It("refuses new connections after StopAccepting and keeps open ones", func() {
		up := listenLocal()
		serve(up, echo)
		p := startTestProxy(up.Addr().String(), testDialPolicy)
		c := dialProxy(p)
		_, err := c.Write([]byte("a"))
		Expect(err).NotTo(HaveOccurred())
		_, err = io.ReadFull(c, make([]byte, 1))
		Expect(err).NotTo(HaveOccurred())

		addr := p.Addr().String()
		p.StopAccepting()
		p.StopAccepting()
		Expect(p.Addr()).To(BeNil())
		_, err = net.Dial("tcp", addr)
		Expect(err).To(MatchError(ContainSubstring("connection refused")))

		_, err = c.Write([]byte("b"))
		Expect(err).NotTo(HaveOccurred())
		buf := make([]byte, 1)
		_, err = io.ReadFull(c, buf)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(buf)).To(Equal("b"))
	})

	It("closes the listener and every connection on Close", func() {
		up := listenLocal()
		serve(up, echo)
		p := startTestProxy(up.Addr().String(), testDialPolicy)
		c := dialProxy(p)
		_, err := c.Write([]byte("a"))
		Expect(err).NotTo(HaveOccurred())
		_, err = io.ReadFull(c, make([]byte, 1))
		Expect(err).NotTo(HaveOccurred())

		addr := p.Addr().String()
		closed := make(chan struct{})
		go func() {
			p.Close()
			close(closed)
		}()
		Eventually(closed, 2*time.Second).Should(BeClosed())
		p.Close()

		_, err = c.Read(make([]byte, 1))
		Expect(err).To(HaveOccurred())
		_, err = net.Dial("tcp", addr)
		Expect(err).To(MatchError(ContainSubstring("connection refused")))
	})

	It("aborts a pending guest dial on Close without logging it", func() {
		policy := testDialPolicy
		policy.giveUp = time.Minute
		p := startTestProxy(unusedAddr(), policy)
		c := dialProxy(p)
		// The proxy accepted the connection and is retrying the dial.
		time.Sleep(100 * time.Millisecond)

		began := time.Now()
		p.Close()
		Expect(time.Since(began)).To(BeNumerically("<", time.Second))
		_, err := io.ReadAll(c)
		Expect(err).NotTo(HaveOccurred())
		Expect(logBuf.String()).NotTo(ContainSubstring("giving up"))
	})

	It("stops listening and listens again, keeping open connections in between", func() {
		up := listenLocal()
		serve(up, echo)
		p := newProxy(testDialPolicy, logger)
		DeferCleanup(p.Close)
		Expect(p.Addr()).To(BeNil())
		p.StopListening("127.0.0.1:0")

		Expect(p.Listen("127.0.0.1:0", up.Addr().String())).To(Succeed())
		Expect(p.Listen("127.0.0.1:0", up.Addr().String())).To(MatchError("the port proxy is already listening"))
		addr := p.Addr().String()
		c := dialProxy(p)
		_, err := c.Write([]byte("a"))
		Expect(err).NotTo(HaveOccurred())
		_, err = io.ReadFull(c, make([]byte, 1))
		Expect(err).NotTo(HaveOccurred())

		p.StopListening("127.0.0.1:0")
		p.StopListening("127.0.0.1:0")
		Expect(p.Addr()).To(BeNil())
		_, err = net.Dial("tcp", addr)
		Expect(err).To(MatchError(ContainSubstring("connection refused")))
		_, err = c.Write([]byte("b"))
		Expect(err).NotTo(HaveOccurred())
		buf := make([]byte, 1)
		_, err = io.ReadFull(c, buf)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(buf)).To(Equal("b"))

		Expect(p.Listen(addr, up.Addr().String())).To(Succeed())
		again := dialProxy(p)
		_, err = again.Write([]byte("c"))
		Expect(err).NotTo(HaveOccurred())
		_, err = io.ReadFull(again, buf)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(buf)).To(Equal("c"))
		Expect(logBuf.String()).To(BeEmpty())
	})

	Describe("with several listeners", func() {
		// tagged serves a one-line banner naming the upstream, then closes.
		tagged := func(name string) string {
			l := listenLocal()
			serve(l, func(c *net.TCPConn) { _, _ = c.Write([]byte(name)) })
			return l.Addr().String()
		}
		banner := func(addr string) string {
			c, err := net.Dial("tcp", addr)
			Expect(err).NotTo(HaveOccurred())
			defer c.Close()
			b, err := io.ReadAll(c)
			Expect(err).NotTo(HaveOccurred())
			return string(b)
		}
		freeAddr := func() string {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			Expect(err).NotTo(HaveOccurred())
			defer l.Close()
			return l.Addr().String()
		}

		It("sends each listener's connections to its own upstream", func() {
			first, second := tagged("first"), tagged("second")
			p := newProxy(testDialPolicy, logger)
			DeferCleanup(p.Close)
			a, b := freeAddr(), freeAddr()
			Expect(p.Listen(a, first)).To(Succeed())
			Expect(p.Listen(b, second)).To(Succeed())
			Expect(banner(a)).To(Equal("first"))
			Expect(banner(b)).To(Equal("second"))
		})

		It("stops one listener and leaves the other open", func() {
			first, second := tagged("first"), tagged("second")
			p := newProxy(testDialPolicy, logger)
			DeferCleanup(p.Close)
			a, b := freeAddr(), freeAddr()
			Expect(p.Listen(a, first)).To(Succeed())
			Expect(p.Listen(b, second)).To(Succeed())

			p.StopListening(a)
			_, err := net.Dial("tcp", a)
			Expect(err).To(MatchError(ContainSubstring("connection refused")))
			Expect(banner(b)).To(Equal("second"))

			Expect(p.Listen(a, first)).To(Succeed())
			Expect(banner(a)).To(Equal("first"))
		})

		It("stops every listener at StopAccepting", func() {
			first, second := tagged("first"), tagged("second")
			p := newProxy(testDialPolicy, logger)
			DeferCleanup(p.Close)
			a, b := freeAddr(), freeAddr()
			Expect(p.Listen(a, first)).To(Succeed())
			Expect(p.Listen(b, second)).To(Succeed())

			p.StopAccepting()
			for _, addr := range []string{a, b} {
				_, err := net.Dial("tcp", addr)
				Expect(err).To(MatchError(ContainSubstring("connection refused")))
			}
		})

		It("closes every listener at Close", func() {
			first, second := tagged("first"), tagged("second")
			p := newProxy(testDialPolicy, logger)
			a, b := freeAddr(), freeAddr()
			Expect(p.Listen(a, first)).To(Succeed())
			Expect(p.Listen(b, second)).To(Succeed())
			p.Close()
			for _, addr := range []string{a, b} {
				_, err := net.Dial("tcp", addr)
				Expect(err).To(MatchError(ContainSubstring("connection refused")))
			}
		})

		It("names the upstream in the give-up line of its own connection", func() {
			dead := unusedAddr()
			p := newProxy(dialPolicy{attemptTimeout: 50 * time.Millisecond, firstBackoff: 5 * time.Millisecond, maxBackoff: 10 * time.Millisecond, giveUp: 50 * time.Millisecond, unansweredGiveUp: 50 * time.Millisecond}, logger)
			DeferCleanup(p.Close)
			a := freeAddr()
			Expect(p.Listen(a, dead)).To(Succeed())
			c, err := net.Dial("tcp", a)
			Expect(err).NotTo(HaveOccurred())
			defer c.Close()
			_, _ = io.ReadAll(c)
			Eventually(logBuf.String).Should(ContainSubstring("giving up on the guest at " + dead))
		})
	})

	It("refuses to listen after StopAccepting or Close", func() {
		p := newProxy(testDialPolicy, logger)
		DeferCleanup(p.Close)
		p.StopAccepting()
		Expect(p.Listen("127.0.0.1:0", unusedAddr())).To(MatchError(errProxyStopped))
		Expect(p.Addr()).To(BeNil())

		closed := newProxy(testDialPolicy, logger)
		closed.Close()
		Expect(closed.Listen("127.0.0.1:0", unusedAddr())).To(MatchError(errProxyStopped))
	})

	It("fails to start when the address is taken", func() {
		taken := listenLocal()
		_, err := startProxy(taken.Addr().String(), unusedAddr(), testDialPolicy, logger)
		Expect(err).To(MatchError(ContainSubstring("listening for the guest port")))
	})
})

// safeBuffer is a bytes.Buffer for a logger shared by proxy goroutines.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
