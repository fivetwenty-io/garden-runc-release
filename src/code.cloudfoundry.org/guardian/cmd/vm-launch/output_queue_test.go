//go:build linux

package main

import (
	"errors"
	"log"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// heldWriter is a stdout that takes nothing while it is held, and records
// what it took.
type heldWriter struct {
	mu      sync.Mutex
	got     []byte
	writes  int
	err     error
	entered chan struct{}
	release chan struct{}
}

func newHeldWriter() *heldWriter {
	return &heldWriter{entered: make(chan struct{}, 100), release: make(chan struct{})}
}

func (w *heldWriter) Write(p []byte) (int, error) {
	w.entered <- struct{}{}
	<-w.release
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	if w.err != nil {
		return 0, w.err
	}
	w.got = append(w.got, p...)
	return len(p), nil
}

func (w *heldWriter) taken() (string, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.got), w.writes
}

var _ = Describe("outputQueue", func() {
	var (
		w      *heldWriter
		logBuf *safeBuffer
		q      *outputQueue
	)

	BeforeEach(func() {
		w = newHeldWriter()
		logBuf = &safeBuffer{}
		q = newOutputQueue(w, 10, log.New(logBuf, "", 0))
		DeferCleanup(func() {
			select {
			case <-w.release:
			default:
				close(w.release)
			}
			q.close(time.Second)
		})
	})

	write := func(s string) {
		n, err := q.Write([]byte(s))
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(len(s)))
	}

	It("never blocks a write while stdout is held up, and drops whole writes past the limit, with one line once stdout has caught up", func() {
		write("1111")
		// The queue is writing the first output to stdout, which holds it.
		Eventually(w.entered).Should(Receive())
		began := time.Now()
		write("22222")
		write("333333") // 11 bytes would wait
		write("44444")  // exactly 10 wait
		write("5")
		Expect(time.Since(began)).To(BeNumerically("<", 100*time.Millisecond))
		Consistently(logBuf.String, 50*time.Millisecond).Should(BeEmpty())

		close(w.release)
		q.close(time.Second)
		got, writes := w.taken()
		Expect(got).To(Equal("1111" + "22222" + "44444"))
		Expect(writes).To(Equal(2))
		Expect(logBuf.String()).To(Equal("stdout did not keep up with the guest; dropped 7 bytes of the guest command's output\n"))
	})

	It("logs each run of drops once stdout has caught up with it", func() {
		write("1111")
		Eventually(w.entered).Should(Receive())
		write("12345678901")
		w.release <- struct{}{}
		Eventually(logBuf.String).Should(Equal("stdout did not keep up with the guest; dropped 11 bytes of the guest command's output\n"))
		write("2222")
		Eventually(w.entered).Should(Receive())
		write("123456789")
		write("12")
		close(w.release)
		q.close(time.Second)
		got, _ := w.taken()
		Expect(got).To(Equal("1111" + "2222" + "123456789"))
		Expect(logBuf.String()).To(Equal("stdout did not keep up with the guest; dropped 11 bytes of the guest command's output\n" +
			"stdout did not keep up with the guest; dropped 2 bytes of the guest command's output\n"))
	})

	It("waits at close for stdout to take what waits", func() {
		write("1111")
		Eventually(w.entered).Should(Receive())
		write("2222")
		go func() {
			time.Sleep(100 * time.Millisecond)
			close(w.release)
		}()
		q.close(time.Second)
		got, _ := w.taken()
		Expect(got).To(Equal("11112222"))
		Expect(logBuf.String()).To(BeEmpty())
	})

	It("gives up on stdout at the close timeout, logs what it dropped, and then writes and logs nothing more", func() {
		write("1111")
		Eventually(w.entered).Should(Receive())
		write("22222")
		write("333333")
		began := time.Now()
		q.close(100 * time.Millisecond)
		Expect(time.Since(began)).To(BeNumerically(">=", 100*time.Millisecond))
		Expect(time.Since(began)).To(BeNumerically("<", time.Second))
		// The 5 bytes waiting and the 6 dropped; the write in progress is
		// stdout's.
		Expect(logBuf.String()).To(Equal("stdout did not take the guest's last output within 100ms; dropped 11 bytes of the guest command's output\n"))
		write("late")

		close(w.release)
		Eventually(q.done).Should(BeClosed())
		got, writes := w.taken()
		Expect(got).To(Equal("1111"))
		Expect(writes).To(Equal(1))
		Expect(logBuf.String()).To(Equal("stdout did not take the guest's last output within 100ms; dropped 11 bytes of the guest command's output\n"))
	})

	It("drops what comes after close", func() {
		close(w.release)
		q.close(time.Second)
		write("late")
		Consistently(w.entered, 50*time.Millisecond).ShouldNot(Receive())
		got, _ := w.taken()
		Expect(got).To(BeEmpty())
	})

	It("keeps the first failed write to stdout, and then drops everything without counting it", func() {
		w.err = errors.New("broken pipe")
		write("1111")
		Eventually(w.entered).Should(Receive())
		write("123456789")
		write("123456789")
		close(w.release)
		Eventually(q.err).Should(MatchError("broken pipe"))
		write("2222")
		q.close(time.Second)
		_, writes := w.taken()
		Expect(writes).To(Equal(1))
		Expect(q.err()).To(MatchError("broken pipe"))
		Expect(logBuf.String()).To(BeEmpty())
	})
})
