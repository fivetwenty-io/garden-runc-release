//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// scriptedSource answers each read with the next scripted answer, and with
// its last answer after that. It records the contexts it was read with.
type scriptedSource struct {
	mu      sync.Mutex
	answers []scriptedAnswer
	reads   int
	block   chan struct{}
}

type scriptedAnswer struct {
	sample guestMemorySample
	err    error
}

func (s *scriptedSource) Read(ctx context.Context) (guestMemorySample, error) {
	s.mu.Lock()
	i := s.reads
	if i >= len(s.answers) {
		i = len(s.answers) - 1
	}
	s.reads++
	answer := s.answers[i]
	block := s.block
	s.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return guestMemorySample{}, ctx.Err()
		}
	}
	return answer.sample, answer.err
}

func (s *scriptedSource) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// syncBuffer is a bytes.Buffer that several goroutines may use.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type fatalError struct{}

func (fatalError) Error() string { return "the monitor broke" }
func (fatalError) Fatal() bool   { return true }

var _ = Describe("the metrics poller", func() {
	const guestBytes = 322961408

	var (
		good   = guestMemorySample{Total: 322961408, Available: 250609664, Free: 250134528, Caches: 30212096}
		bad    = guestMemorySample{Total: guestBytes + 1}
		out    *syncBuffer
		logs   *syncBuffer
		ticks  chan time.Time
		source *scriptedSource
		poller *metricsPoller
	)

	build := func(answers ...scriptedAnswer) {
		source = &scriptedSource{answers: answers}
		poller = newMetricsPoller(source, guestBytes, out, log.New(logs, "vm-launch: ", 0))
		poller.newTicker = func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }
		poller.breakSettle = 10 * time.Millisecond
	}

	// tick sends one tick and waits until the poller has taken it, so the
	// poll it starts has finished when the next tick is accepted.
	tick := func() {
		GinkgoHelper()
		Eventually(ticks).Should(BeSent(time.Time{}))
	}

	BeforeEach(func() {
		out, logs = &syncBuffer{}, &syncBuffer{}
		ticks = make(chan time.Time)
	})

	AfterEach(func() { poller.stop() })

	It("polls every ten seconds", func() {
		build(scriptedAnswer{sample: good})
		Expect(poller.interval).To(Equal(10 * time.Second))
		Expect(newMetricsPoller(source, guestBytes, out, nil).interval).To(Equal(10 * time.Second))
	})

	It("writes one line for each good sample and nothing before the first tick", func() {
		build(scriptedAnswer{sample: good})
		poller.start()
		Consistently(out.String).Should(BeEmpty())
		tick()
		Eventually(out.String).Should(Equal(good.line()))
		tick()
		Eventually(out.String).Should(Equal(good.line() + good.line()))
		Expect(logs.String()).To(BeEmpty())
	})

	It("starts only once", func() {
		build(scriptedAnswer{sample: good})
		poller.start()
		poller.start()
		tick()
		Eventually(out.String).Should(Equal(good.line()))
		Consistently(source.readCount).Should(Equal(1))
	})

	It("drops a bad sample and logs once when the run begins and once when it ends", func() {
		build(scriptedAnswer{sample: bad}, scriptedAnswer{sample: bad}, scriptedAnswer{sample: bad},
			scriptedAnswer{sample: good})
		poller.start()
		for reads := 1; reads <= 3; reads++ {
			tick()
			Eventually(source.readCount).Should(Equal(reads))
		}
		tick()
		Eventually(out.String).Should(Equal(good.line()))
		lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
		Expect(lines).To(HaveLen(2))
		Expect(lines[0]).To(HavePrefix("vm-launch: dropping guest memory statistics that cannot be right: "))
		Expect(lines[1]).To(ContainSubstring("good again, after 3 failed reads"))
	})

	It("stays quiet for a few failed reads, and logs once for a run of them", func() {
		failed := scriptedAnswer{err: errors.New("the guest has not answered")}
		build(failed, failed, scriptedAnswer{sample: good}, failed, failed, failed, failed, failed, scriptedAnswer{sample: good})
		poller.start()
		for i := 0; i < 3; i++ {
			tick()
		}
		Eventually(out.String).Should(Equal(good.line()))
		Expect(logs.String()).To(BeEmpty())
		for i := 0; i < 5; i++ {
			tick()
		}
		tick()
		Eventually(out.String).Should(Equal(good.line() + good.line()))
		lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
		Expect(lines).To(HaveLen(2))
		Expect(lines[0]).To(ContainSubstring("unavailable, and the last 3 reads failed"))
		Expect(lines[0]).To(ContainSubstring("the guest has not answered"))
		Expect(lines[1]).To(ContainSubstring("good again, after 5 failed reads"))
	})

	It("does not log the end of a run it never logged", func() {
		build(scriptedAnswer{err: errors.New("timed out")}, scriptedAnswer{sample: good})
		poller.start()
		tick()
		tick()
		Eventually(out.String).Should(Equal(good.line()))
		Expect(logs.String()).To(BeEmpty())
	})

	It("keeps polling after bad samples", func() {
		build(scriptedAnswer{sample: bad}, scriptedAnswer{sample: good})
		poller.start()
		tick()
		tick()
		Eventually(out.String).Should(Equal(good.line()))
		tick()
		Eventually(out.String).Should(Equal(good.line() + good.line()))
	})

	DescribeTable("stops, with one log line, when the source is broken for good",
		func(err error) {
			build(scriptedAnswer{sample: good}, scriptedAnswer{err: err}, scriptedAnswer{sample: good})
			poller.start()
			tick()
			Eventually(out.String).Should(Equal(good.line()))
			tick()
			Eventually(logs.String).Should(ContainSubstring("stopping the guest memory metrics"))
			Consistently(ticks).ShouldNot(BeSent(time.Time{}))
			Expect(source.readCount()).To(Equal(2))
			Expect(out.String()).To(Equal(good.line()))
			Expect(strings.Count(logs.String(), "\n")).To(Equal(1))
		},
		Entry("an error that says it is fatal", fatalError{}),
		Entry("a wrapped error that says it is fatal", fmt.Errorf("qom-get: %w", fatalError{})),
		Entry("the end of the stream", io.EOF),
	)

	It("stops reading and writing when stop is called, even in the middle of a read", func() {
		build(scriptedAnswer{sample: good})
		source.block = make(chan struct{})
		poller.start()
		tick()
		Eventually(source.readCount).Should(Equal(1))
		poller.stop()
		close(source.block)
		Expect(out.String()).To(BeEmpty())
		Expect(logs.String()).To(BeEmpty())
		Consistently(ticks).ShouldNot(BeSent(time.Time{}))
	})

	It("writes nothing after stop returns", func() {
		build(scriptedAnswer{sample: good})
		poller.start()
		tick()
		Eventually(out.String).Should(Equal(good.line()))
		poller.stop()
		poller.stop()
		before := out.String()
		Consistently(ticks).ShouldNot(BeSent(time.Time{}))
		Expect(out.String()).To(Equal(before))
	})

	It("can be stopped without having started", func() {
		build(scriptedAnswer{sample: good})
		poller.stop()
	})

	It("waits two seconds before it logs a source that broke", func() {
		build(scriptedAnswer{sample: good})
		Expect(newMetricsPoller(source, guestBytes, out, nil).breakSettle).To(Equal(2 * time.Second))
	})

	It("says nothing about a broken source when it is stopped while it waits to log", func() {
		build(scriptedAnswer{err: io.EOF})
		poller.breakSettle = time.Minute
		poller.start()
		tick()
		Eventually(source.readCount).Should(Equal(1))
		began := time.Now()
		poller.stop()
		Expect(time.Since(began)).To(BeNumerically("<", time.Second))
		Expect(logs.String()).To(BeEmpty())
	})

	It("skips a reply the guest has not filled in, which neither counts as a failure nor ends a run", func() {
		pending := scriptedAnswer{err: fmt.Errorf("reading: %w", errFirecrackerStatsPending)}
		failed := scriptedAnswer{err: errors.New("timed out")}
		build(pending, pending, pending, pending, scriptedAnswer{sample: good},
			failed, failed, pending, pending, failed, scriptedAnswer{sample: good})
		poller.start()
		for i := 0; i < 5; i++ {
			tick()
		}
		Eventually(out.String).Should(Equal(good.line()))
		Expect(logs.String()).To(BeEmpty())
		for i := 0; i < 5; i++ {
			tick()
		}
		Eventually(logs.String).Should(ContainSubstring("unavailable, and the last 3 reads failed"))
		tick()
		Eventually(out.String).Should(Equal(good.line() + good.line()))
		Eventually(logs.String).Should(ContainSubstring("good again, after 3 failed reads"))
	})

	Describe("with a source to prepare", func() {
		var (
			mu       sync.Mutex
			prepares int
			answers  []error
		)

		prepareCount := func() int {
			mu.Lock()
			defer mu.Unlock()
			return prepares
		}

		buildPrepared := func(prepareAnswers ...error) {
			build(scriptedAnswer{sample: good})
			mu.Lock()
			prepares, answers = 0, prepareAnswers
			mu.Unlock()
			poller.prepare = func(ctx context.Context) error {
				mu.Lock()
				defer mu.Unlock()
				i := prepares
				if i >= len(answers) {
					i = len(answers) - 1
				}
				prepares++
				return answers[i]
			}
		}

		It("prepares the source at once when it starts, and reads only at the first tick", func() {
			buildPrepared(nil)
			poller.start()
			Eventually(prepareCount).Should(Equal(1))
			Consistently(source.readCount).Should(BeZero())
			tick()
			Eventually(out.String).Should(Equal(good.line()))
			tick()
			Eventually(out.String).Should(Equal(good.line() + good.line()))
			Expect(prepareCount()).To(Equal(1))
			Expect(logs.String()).To(BeEmpty())
		})

		It("prepares again at the next tick when preparing failed, and reads at that tick", func() {
			buildPrepared(errors.New("timed out"), nil)
			poller.start()
			Eventually(prepareCount).Should(Equal(1))
			tick()
			Eventually(out.String).Should(Equal(good.line()))
			Expect(prepareCount()).To(Equal(2))
			Expect(source.readCount()).To(Equal(1))
			Expect(logs.String()).To(BeEmpty())
		})

		It("counts each failure to prepare as a failed read", func() {
			buildPrepared(errors.New("timed out"))
			poller.start()
			tick()
			tick()
			Eventually(logs.String).Should(ContainSubstring("unavailable, and the last 3 reads failed; the latest error is: timed out"))
			Expect(source.readCount()).To(BeZero())
		})

		It("stops, with one log line, when the source cannot be prepared for good", func() {
			buildPrepared(fatalError{})
			poller.start()
			Eventually(logs.String).Should(ContainSubstring("stopping the guest memory metrics, as the hypervisor can no longer be read: the monitor broke"))
			Consistently(ticks).ShouldNot(BeSent(time.Time{}))
			Expect(source.readCount()).To(BeZero())
			Expect(strings.Count(logs.String(), "\n")).To(Equal(1))
		})

		It("stops at once when it is stopped while it prepares", func() {
			build(scriptedAnswer{sample: good})
			preparing := make(chan struct{})
			poller.prepare = func(ctx context.Context) error {
				close(preparing)
				<-ctx.Done()
				return ctx.Err()
			}
			poller.start()
			Eventually(preparing).Should(BeClosed())
			began := time.Now()
			poller.stop()
			Expect(time.Since(began)).To(BeNumerically("<", time.Second))
			Expect(logs.String()).To(BeEmpty())
			Expect(source.readCount()).To(BeZero())
		})
	})
})

var _ = Describe("the guest metrics of a run", func() {
	var (
		logs  *syncBuffer
		ticks chan time.Time
	)

	BeforeEach(func() {
		logs = &syncBuffer{}
		ticks = make(chan time.Time)
	})

	// started returns the poller of kind's guest, with ticks that the spec
	// sends, started as the supervisor's started hook starts it.
	started := func(kind backend.Kind, qmp *qmpMonitor, workDir string, memMiB int) (*metricsPoller, func()) {
		poller, closeStats := newGuestMetrics(kind, qmp, workDir, memMiB, log.New(logs, "vm-launch: ", 0))
		poller.newTicker = func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }
		poller.start()
		DeferCleanup(func() {
			poller.stop()
			closeStats()
		})
		return poller, closeStats
	}

	It("turns on QEMU's statistics at once and writes a line for each sample to the logger's writer", func() {
		m, q := newFakeQMP()
		done := q.serve(func() {
			q.send(fakeGreeting)
			Expect(q.recv()).To(Equal(capsRequest(1)))
			q.reply(`{"return": {}}`)
			Expect(q.recv()).To(Equal(qomRequest(2, "qom-set", "guest-stats-polling-interval", "5")))
			q.reply(`{"return": {}}`)
			Expect(q.recv()).To(Equal(qomRequest(3, "qom-get", "guest-stats", "")))
			q.reply(statsReply)
		})
		poller, _ := started(backend.VMQemu, m, GinkgoT().TempDir(), 512)
		Expect(poller.guestBytes).To(BeEquivalentTo(512 << 20))
		Expect(poller.interval).To(Equal(10 * time.Second))
		Eventually(ticks).Should(BeSent(time.Time{}))
		Eventually(done).Should(BeClosed())
		Eventually(logs.String).Should(Equal("vm-launch-metrics v1 used=41734144 total=322961408 available=281227264 free=250134528 caches=30212096\n"))
	})

	It("connects to Firecracker's API socket in the work directory at once, removes its path, and writes a line for each sample", func() {
		dir, err := os.MkdirTemp("", "fcapi")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(os.RemoveAll, dir)
		sock := firecrackerAPISocket(dir)
		api := newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) {
			replyJSON(c, 200, `{"free_memory":1000,"total_memory":4000,"available_memory":3000,"disk_caches":500}`)
		})
		DeferCleanup(api.stop)
		started(backend.VMFirecracker, nil, dir, 128)
		Eventually(sock).ShouldNot(BeAnExistingFile())
		Expect(api.accepted.Load()).To(BeEquivalentTo(1))
		for i := 0; i < 2; i++ {
			Eventually(ticks).Should(BeSent(time.Time{}))
		}
		line := "vm-launch-metrics v1 used=1000 total=4000 available=3000 free=1000 caches=500\n"
		Eventually(logs.String).Should(Equal(line + line))
		Expect(api.accepted.Load()).To(BeEquivalentTo(1))
	})

	It("closes the Firecracker connection once the poller has stopped", func() {
		dir, err := os.MkdirTemp("", "fcapi")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(os.RemoveAll, dir)
		sock := firecrackerAPISocket(dir)
		api := newFakeFirecrackerAPI(sock, func(c net.Conn, _ *http.Request) { replyJSON(c, 200, `{}`) })
		DeferCleanup(api.stop)
		poller, closeStats := started(backend.VMFirecracker, nil, dir, 128)
		Eventually(sock).ShouldNot(BeAnExistingFile())
		poller.stop()
		closeStats()
		_, err = poller.source.Read(context.Background())
		Expect(isBrokenSource(err)).To(BeTrue())
	})

	It("stops at once on a QEMU that never greets", func() {
		m, _ := newFakeQMP()
		poller, _ := started(backend.VMQemu, m, GinkgoT().TempDir(), 512)
		began := time.Now()
		poller.stop()
		Expect(time.Since(began)).To(BeNumerically("<", time.Second))
		Expect(logs.String()).To(BeEmpty())
	})
})
