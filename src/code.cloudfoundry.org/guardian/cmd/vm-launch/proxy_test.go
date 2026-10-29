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
)

// testDialPolicy retries fast so the specs stay quick.
var testDialPolicy = dialPolicy{
	attemptTimeout: 200 * time.Millisecond,
	firstBackoff:   10 * time.Millisecond,
	maxBackoff:     50 * time.Millisecond,
	giveUp:         5 * time.Second,
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

		p.StopAccepting()
		p.StopAccepting()
		_, err = net.Dial("tcp", p.Addr().String())
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

		closed := make(chan struct{})
		go func() {
			p.Close()
			close(closed)
		}()
		Eventually(closed, 2*time.Second).Should(BeClosed())
		p.Close()

		_, err = c.Read(make([]byte, 1))
		Expect(err).To(HaveOccurred())
		_, err = net.Dial("tcp", p.Addr().String())
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
