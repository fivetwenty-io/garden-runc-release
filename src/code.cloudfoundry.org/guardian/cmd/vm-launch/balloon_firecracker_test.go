//go:build linux

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// fakeFirecrackerAPI serves GET /balloon/statistics on a Unix socket. Each
// accepted connection is served until the client closes it, and handle
// answers every request.
type fakeFirecrackerAPI struct {
	path     string
	listener net.Listener
	accepted atomic.Int32
	requests atomic.Int32
	wg       sync.WaitGroup
	handle   func(w net.Conn, req *http.Request)
}

func newFakeFirecrackerAPI(path string, handle func(w net.Conn, req *http.Request)) *fakeFirecrackerAPI {
	l, err := net.Listen("unix", path)
	Expect(err).NotTo(HaveOccurred())
	f := &fakeFirecrackerAPI{path: path, listener: l, handle: handle}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			f.accepted.Add(1)
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				for {
					req, err := http.ReadRequest(r)
					if err != nil {
						return
					}
					f.requests.Add(1)
					f.handle(c, req)
				}
			}()
		}
	}()
	return f
}

func (f *fakeFirecrackerAPI) stop() {
	_ = f.listener.Close()
	f.wg.Wait()
}

func replyJSON(c net.Conn, status int, body string) {
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}

var _ = Describe("the firecracker balloon", func() {
	It("adds exactly the balloon entry with statistics and free page reporting", func() {
		raw, err := json.Marshal(newFirecrackerBalloon())
		Expect(err).NotTo(HaveOccurred())
		Expect(string(raw)).To(Equal(`{"amount_mib":0,"deflate_on_oom":true,"stats_polling_interval_s":5,"free_page_reporting":true}`))
	})

	It("serves the API on a socket and drops --no-api", func() {
		argv := firecrackerAPIArgv("/art", "/work/fc.json", firecrackerAPISocket("/work"))
		Expect(argv).To(Equal([]string{"/art/firecracker/firecracker", "--api-sock", "/work/fc.sock", "--config-file", "/work/fc.json"}))
	})

	Describe("the statistics source", func() {
		var (
			dir  string
			sock string
			api  *fakeFirecrackerAPI
		)

		BeforeEach(func() {
			var err error
			dir, err = os.MkdirTemp("", "fcapi")
			Expect(err).NotTo(HaveOccurred())
			sock = filepath.Join(dir, "fc.sock")
		})

		AfterEach(func() {
			if api != nil {
				api.stop()
				api = nil
			}
			_ = os.RemoveAll(dir)
		})

		const full = `{"free_memory":1000,"total_memory":4000,"available_memory":3000,"disk_caches":500,"swap_in":0}`

		It("reads the sample over one kept connection and removes the socket's path", func() {
			api = newFakeFirecrackerAPI(sock, func(c net.Conn, req *http.Request) {
				Expect(req.Method).To(Equal(http.MethodGet))
				Expect(req.URL.Path).To(Equal("/balloon/statistics"))
				replyJSON(c, 200, full)
			})

			src, err := newFirecrackerStatsSource(context.Background(), sock, time.Second)
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = src.Close() }()

			_, statErr := os.Stat(sock)
			Expect(os.IsNotExist(statErr)).To(BeTrue(), "the path should be gone once the source is connected")

			for i := 0; i < 3; i++ {
				s, err := src.Read(context.Background())
				Expect(err).NotTo(HaveOccurred())
				Expect(s).To(Equal(guestMemorySample{Total: 4000, Available: 3000, Free: 1000, Caches: 500}))
			}
			Expect(api.accepted.Load()).To(BeEquivalentTo(1))
			Expect(api.requests.Load()).To(BeEquivalentTo(3))
		})

		It("waits for the socket to appear", func() {
			started := make(chan *fakeFirecrackerAPI, 1)
			go func() {
				defer GinkgoRecover()
				time.Sleep(200 * time.Millisecond)
				started <- newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) { replyJSON(c, 200, full) })
			}()
			src, err := newFirecrackerStatsSource(context.Background(), sock, 3*time.Second)
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = src.Close() }()
			api = <-started
		})

		It("gives up when the socket never appears", func() {
			_, err := newFirecrackerStatsSource(context.Background(), sock, 150*time.Millisecond)
			Expect(err).To(MatchError(ContainSubstring("connect to the firecracker API socket")))
		})

		It("gives up early when the context ends", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			start := time.Now()
			_, err := newFirecrackerStatsSource(ctx, sock, 10*time.Second)
			Expect(err).To(MatchError(context.Canceled))
			Expect(time.Since(start)).To(BeNumerically("<", time.Second))
		})

		It("reports a reply without the guest's fields as pending and keeps the connection", func() {
			var n atomic.Int32
			api = newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) {
				if n.Add(1) == 1 {
					replyJSON(c, 200, `{"target_pages":0,"actual_pages":0,"target_mib":0,"actual_mib":0}`)
					return
				}
				replyJSON(c, 200, full)
			})
			src, err := newFirecrackerStatsSource(context.Background(), sock, time.Second)
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = src.Close() }()

			_, err = src.Read(context.Background())
			Expect(err).To(MatchError(errFirecrackerStatsPending))

			s, err := src.Read(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(s.Total).To(BeEquivalentTo(4000))
			Expect(api.accepted.Load()).To(BeEquivalentTo(1))
		})

		It("keeps zero for the optional fields a reply leaves out", func() {
			api = newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) {
				replyJSON(c, 200, `{"total_memory":4000,"available_memory":3000}`)
			})
			src, err := newFirecrackerStatsSource(context.Background(), sock, time.Second)
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = src.Close() }()
			s, err := src.Read(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(s).To(Equal(guestMemorySample{Total: 4000, Available: 3000}))
		})

		It("fails on a 400 for statistics that were not enabled and closes", func() {
			api = newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) {
				replyJSON(c, 400, `{"fault_message":"Statistics for the balloon device are not enabled"}`)
			})
			src, err := newFirecrackerStatsSource(context.Background(), sock, time.Second)
			Expect(err).NotTo(HaveOccurred())

			_, err = src.Read(context.Background())
			Expect(err).To(MatchError(ContainSubstring("status 400")))
			_, err = src.Read(context.Background())
			Expect(err).To(MatchError(ContainSubstring("closed")))
		})

		It("fails on a reply that is not JSON", func() {
			api = newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) { replyJSON(c, 200, `not json`) })
			src, err := newFirecrackerStatsSource(context.Background(), sock, time.Second)
			Expect(err).NotTo(HaveOccurred())
			_, err = src.Read(context.Background())
			Expect(err).To(MatchError(ContainSubstring("parse the balloon statistics")))
		})

		It("fails on a reply after the deadline and does not reuse the connection", func() {
			api = newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) {
				time.Sleep(500 * time.Millisecond)
				replyJSON(c, 200, full)
			})
			src, err := newFirecrackerStatsSource(context.Background(), sock, time.Second)
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err = src.Read(ctx)
			Expect(err).To(HaveOccurred())
			Expect(time.Since(start)).To(BeNumerically("<", 450*time.Millisecond))

			_, err = src.Read(context.Background())
			Expect(err).To(MatchError(ContainSubstring("closed")))
		})

		It("stops waiting for a reply when the context is cancelled", func() {
			api = newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) {
				time.Sleep(time.Second)
				replyJSON(c, 200, full)
			})
			src, err := newFirecrackerStatsSource(context.Background(), sock, time.Second)
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(100*time.Millisecond, cancel)
			start := time.Now()
			_, err = src.Read(ctx)
			Expect(err).To(HaveOccurred())
			Expect(time.Since(start)).To(BeNumerically("<", 800*time.Millisecond))
		})

		It("fails when Firecracker closes the connection", func() {
			api = newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) { _ = c.Close() })
			src, err := newFirecrackerStatsSource(context.Background(), sock, time.Second)
			Expect(err).NotTo(HaveOccurred())

			_, err = src.Read(context.Background())
			Expect(err).To(HaveOccurred())
			_, err = src.Read(context.Background())
			Expect(err).To(MatchError(ContainSubstring("closed")))
		})

		It("fails when the reply asks to close the connection", func() {
			api = newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) {
				_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(full), full)
			})
			src, err := newFirecrackerStatsSource(context.Background(), sock, time.Second)
			Expect(err).NotTo(HaveOccurred())
			_, err = src.Read(context.Background())
			Expect(err).To(MatchError(ContainSubstring("closed the API connection")))
		})

		It("closes more than once without error", func() {
			api = newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) { replyJSON(c, 200, full) })
			src, err := newFirecrackerStatsSource(context.Background(), sock, time.Second)
			Expect(err).NotTo(HaveOccurred())
			Expect(src.Close()).To(Succeed())
			Expect(src.Close()).To(Succeed())
			_, err = src.Read(context.Background())
			Expect(err).To(HaveOccurred())
			Expect(isBrokenSource(err)).To(BeTrue())
		})

		It("says a socket that never appears is fatal, and a wait that its context ended is not", func() {
			_, err := newFirecrackerStatsSource(context.Background(), sock, 150*time.Millisecond)
			Expect(isBrokenSource(err)).To(BeTrue())
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err = newFirecrackerStatsSource(ctx, sock, 10*time.Second)
			Expect(isBrokenSource(err)).To(BeFalse())
		})

		It("fails for good once a read fails, and on every read after it", func() {
			api = newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) { _ = c.Close() })
			src, err := newFirecrackerStatsSource(context.Background(), sock, time.Second)
			Expect(err).NotTo(HaveOccurred())
			_, err = src.Read(context.Background())
			Expect(isBrokenSource(err)).To(BeTrue())
			_, err = src.Read(context.Background())
			Expect(isBrokenSource(err)).To(BeTrue())
		})

		It("does not take a reply the guest has not filled in for a broken source", func() {
			Expect(isBrokenSource(errFirecrackerStatsPending)).To(BeFalse())
		})

		It("fails for good when it never connected", func() {
			_, err := (&firecrackerStatsSource{}).Read(context.Background())
			Expect(err).To(MatchError(ContainSubstring("closed")))
			Expect(isBrokenSource(err)).To(BeTrue())
		})

		It("connects a source made empty, and removes the socket's path", func() {
			api = newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) { replyJSON(c, 200, full) })
			src := &firecrackerStatsSource{}
			Expect(src.connect(context.Background(), sock, time.Second)).To(Succeed())
			defer func() { _ = src.Close() }()
			Expect(sock).NotTo(BeAnExistingFile())
			Expect(src.Read(context.Background())).To(Equal(guestMemorySample{Total: 4000, Available: 3000, Free: 1000, Caches: 500}))
		})

		It("lets a poller stop at once while Firecracker has not answered its read", func() {
			asked := make(chan struct{})
			release := make(chan struct{})
			api = newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) {
				close(asked)
				<-release
			})
			src := &firecrackerStatsSource{}
			logs, out := &syncBuffer{}, &syncBuffer{}
			ticks := make(chan time.Time)
			poller := newMetricsPoller(src, 1<<20, out, log.New(logs, "", 0))
			poller.newTicker = func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }
			poller.prepare = func(ctx context.Context) error { return src.connect(ctx, sock, time.Second) }
			poller.start()
			defer poller.stop()
			Eventually(ticks).Should(BeSent(time.Time{}))
			Eventually(asked).Should(BeClosed())
			began := time.Now()
			poller.stop()
			Expect(time.Since(began)).To(BeNumerically("<", time.Second))
			Expect(out.String()).To(BeEmpty())
			Expect(logs.String()).To(BeEmpty())
			close(release)
			Expect(src.Close()).To(Succeed())
		})
	})
})
