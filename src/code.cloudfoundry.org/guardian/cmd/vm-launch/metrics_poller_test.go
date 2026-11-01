//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

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
})
