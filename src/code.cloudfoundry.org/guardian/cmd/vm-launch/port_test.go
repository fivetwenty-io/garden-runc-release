//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// listenReport is one listen line the serial filter passed on.
type listenReport struct {
	port int
	up   bool
}

// listenRecorder records the listen reports a serial filter passes on.
type listenRecorder struct {
	mu      sync.Mutex
	reports []listenReport
}

func (r *listenRecorder) record(port int, up bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, listenReport{port, up})
}

func (r *listenRecorder) got() []listenReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]listenReport(nil), r.reports...)
}

// feedListen pushes chunks through a serial filter that passes listen lines
// to a recorder, finishes it, and returns the filter, its output, and the
// listen reports.
func feedListen(chunks ...string) (*serialFilter, string, []listenReport) {
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
	console := "boot " + listen + "8080:1\r\n" +
		"RVM_START_" + testNonce + "\r\n" +
		"one\r\n" +
		listen + "8080:1\r\n" +
		"partial" + listen + "8081:0\r\n" +
		"rest\r\n" +
		listen + "8080:2\r\n" +
		listen + "8080:1x\r\n" +
		listen + "1\r\n" +
		listen + "\r\n" +
		listen + "0:1\r\n" +
		listen + "65536:1\r\n" +
		listen + "123456:1\r\n" +
		listen + ":1\r\n" +
		listen + "80 80:1\r\n" +
		listen + "9000:1\n" +
		"RVM_EXIT_" + testNonce + "=7\r\n" +
		listen + "8080:0\r\n"
	wantOut := "one\npartialrest\n" + listen + "8080:2\n" + listen + "8080:1x\n" + listen + "1\n" + listen + "\n" +
		listen + "0:1\n" + listen + "65536:1\n" + listen + "123456:1\n" + listen + ":1\n" + listen + "80 80:1\n"
	wantReports := []listenReport{{8080, true}, {8081, false}, {9000, true}}

	It("passes each listen line of the run to the callback and keeps the output around it", func() {
		f, out, reports := feedListen(console)
		Expect(out).To(Equal(wantOut))
		Expect(reports).To(Equal(wantReports))
		Expect(f.markerFound()).To(BeTrue())
		Expect(f.status).To(Equal(7))
	})

	It("gives the same result however the console is split", func() {
		for i := 0; i <= len(console); i++ {
			_, out, reports := feedListen(console[:i], console[i:])
			Expect(out).To(Equal(wantOut), "split at %d", i)
			Expect(reports).To(Equal(wantReports), "split at %d", i)
		}
		chunks := make([]string, len(console))
		for i := range console {
			chunks[i] = console[i : i+1]
		}
		_, out, reports := feedListen(chunks...)
		Expect(out).To(Equal(wantOut))
		Expect(reports).To(Equal(wantReports))
	})

	It("treats a listen line cut off by the end of the console as output", func() {
		for _, tail := range []string{"", "8", "8080", "8080:", "8080:1", "8080:1\r"} {
			start := "RVM_START_" + testNonce + "\n"
			_, out, reports := feedListen(start + "x" + listen + tail)
			Expect(out).To(Equal("x"+listen+tail), "tail %q", tail)
			Expect(reports).To(BeEmpty(), "tail %q", tail)
		}
	})

	It("finds the exit marker right after a listen line in the same write", func() {
		f, out, reports := feedListen("RVM_START_" + testNonce + "\n" + listen + "8080:1\nRVM_EXIT_" + testNonce + "=0\n")
		Expect(out).To(BeEmpty())
		Expect(reports).To(Equal([]listenReport{{8080, true}}))
		Expect(f.status).To(Equal(0))
	})

	It("keeps the reports of different ports apart and in order", func() {
		_, out, reports := feedListen("RVM_START_"+testNonce+"\n", listen+"8081:1\n", listen+"8080:1\n", listen+"8081:0\n", listen+"8080:0\n")
		Expect(out).To(BeEmpty())
		Expect(reports).To(Equal([]listenReport{{8081, true}, {8080, true}, {8081, false}, {8080, false}}))
	})

	It("leaves listen lines in the output when nothing asked for them", func() {
		f, out := feed("RVM_START_"+testNonce+"\n", listen+"8080:1\r\n", "RVM_EXIT_"+testNonce+"=0\n")
		Expect(out).To(Equal(listen + "8080:1\n"))
		Expect(f.markerFound()).To(BeTrue())
	})

	DescribeTable("parses the bytes after the tag",
		func(b string, port int, up bool, n int, ok, needMore bool) {
			gotPort, gotUp, gotN, gotOK, gotMore := parseListen([]byte(b))
			Expect([]any{gotPort, gotUp, gotN, gotOK, gotMore}).To(Equal([]any{port, up, n, ok, needMore}))
		},
		Entry("nothing yet", "", 0, false, 0, false, true),
		Entry("a port without its colon", "8080", 0, false, 0, false, true),
		Entry("a colon without its value", "8080:", 0, false, 0, false, true),
		Entry("a value without its line ending", "8080:1", 0, false, 0, false, true),
		Entry("a CR without its LF", "8080:0\r", 0, false, 0, false, true),
		Entry("1 and LF", "8080:1\nmore", 8080, true, 7, true, false),
		Entry("0 and CRLF", "443:0\r\nmore", 443, false, 7, true, false),
		Entry("the lowest port", "1:1\n", 1, true, 4, true, false),
		Entry("the highest port", "65535:1\n", 65535, true, 8, true, false),
		Entry("port zero", "0:1\n", 0, false, 0, false, false),
		Entry("a port above 65535", "65536:1\n", 0, false, 0, false, false),
		Entry("six digits", "100000:1\n", 0, false, 0, false, false),
		Entry("six digits with a leading zero", "008080:1\n", 0, false, 0, false, false),
		Entry("five digits with a leading zero", "08080:1\n", 8080, true, 8, true, false),
		Entry("no port", ":1\n", 0, false, 0, false, false),
		Entry("a port and no colon", "8080 1\n", 0, false, 0, false, false),
		Entry("the old form without a port", "1\n", 0, false, 0, false, false),
		Entry("another digit", "8080:2\n", 0, false, 0, false, false),
		Entry("two digits", "8080:10\n", 0, false, 0, false, false),
		Entry("a CR and something else", "8080:1\rx", 0, false, 0, false, false),
	)
})

var _ = Describe("the gates of several ports", func() {
	var (
		openers map[int]*fakeOpener
		logBuf  *safeBuffer
		gates   *portGates
	)
	fastRetry := backoff{first: 5 * time.Millisecond, max: 20 * time.Millisecond}

	BeforeEach(func() {
		openers = map[int]*fakeOpener{8080: {}, 8081: {}, 9000: {}}
		logBuf = &safeBuffer{}
		gates = startPortGates([]int{8080, 8081, 9000}, func(port int) portOpener { return openers[port] }, fastRetry, log.New(logBuf, "", 0))
		DeferCleanup(gates.end)
	})

	It("starts every gate closed", func() {
		Consistently(func() int { return openers[8080].count() + openers[8081].count() + openers[9000].count() }, 100*time.Millisecond).Should(BeZero())
	})

	It("sends each report to its own port's gate only", func() {
		gates.set(8081, true)
		Eventually(openers[8081].got).Should(Equal([]string{"open"}))
		Consistently(openers[8080].got, 100*time.Millisecond).Should(BeEmpty())
		Consistently(openers[9000].got, 100*time.Millisecond).Should(BeEmpty())

		gates.set(9000, true)
		Eventually(openers[9000].got).Should(Equal([]string{"open"}))
		gates.set(8081, false)
		Eventually(openers[8081].got).Should(Equal([]string{"open", "close"}))
		Consistently(openers[9000].got, 100*time.Millisecond).Should(Equal([]string{"open"}))
		Expect(openers[8080].got()).To(BeEmpty())
	})

	It("names the port in each gate's lines", func() {
		gates.set(8081, true)
		gates.set(9000, true)
		Eventually(logBuf.String).Should(ContainSubstring("the guest listens on port 8081; it is open in the container\n"))
		Eventually(logBuf.String).Should(ContainSubstring("the guest listens on port 9000; it is open in the container\n"))
		Expect(logBuf.String()).NotTo(ContainSubstring("port 8080"))
	})

	It("ignores a report for a port that has no gate", func() {
		gates.set(8082, true)
		gates.set(0, true)
		Consistently(func() int { return openers[8080].count() + openers[8081].count() + openers[9000].count() }, 100*time.Millisecond).Should(BeZero())
	})

	It("keeps a failing port from holding up the others", func() {
		openers[8080].setOpen(func() error { return syscall.EADDRINUSE })
		gates.set(8080, true)
		gates.set(8081, true)
		Eventually(openers[8081].got).Should(Equal([]string{"open"}))
		Eventually(logBuf.String).Should(ContainSubstring("port 8080 already in use in this container"))
	})

	It("closes every open port at shutDown and opens none again", func() {
		gates.set(8080, true)
		gates.set(9000, true)
		Eventually(openers[8080].got).Should(Equal([]string{"open"}))
		Eventually(openers[9000].got).Should(Equal([]string{"open"}))

		gates.shutDown()
		Eventually(openers[8080].got).Should(Equal([]string{"open", "close"}))
		Eventually(openers[9000].got).Should(Equal([]string{"open", "close"}))
		gates.set(8081, true)
		gates.set(8080, true)
		Consistently(openers[8081].got, 100*time.Millisecond).Should(BeEmpty())
		Expect(openers[8080].got()).To(Equal([]string{"open", "close"}))
	})

	It("ends every gate and says which ports were open", func() {
		gates.set(8080, true)
		gates.set(9000, true)
		Eventually(openers[8080].got).Should(Equal([]string{"open"}))
		Eventually(openers[9000].got).Should(Equal([]string{"open"}))
		gates.end()
		Expect(gateLoops()).To(BeZero())
		Expect(logBuf.String()).To(ContainSubstring("the guest has stopped, so port 8080 closes in the container\n"))
		Expect(logBuf.String()).To(ContainSubstring("the guest has stopped, so port 9000 closes in the container\n"))
		Expect(logBuf.String()).NotTo(ContainSubstring("port 8081 closes"))
	})
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

// setOpen sets open.
func (o *fakeOpener) setOpen(open func() error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.open = open
}

// setCloseErr sets closeErr.
func (o *fakeOpener) setCloseErr(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closeErr = err
}

// count returns the number of calls.
func (o *fakeOpener) count() int {
	return len(o.got())
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

// gateLoops counts the port gates running in this process. run ends its
// gate before it returns, so after run there are none.
func gateLoops() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), ".(*portGate).loop(")
		}
		buf = make([]byte, 2*len(buf))
	}
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

	// fastRetry tries a failed change again within a few milliseconds.
	fastRetry := backoff{first: 5 * time.Millisecond, max: 20 * time.Millisecond}

	startWith := func(retry backoff) {
		gate = startPortGate(opener, 8080, retry, log.New(logBuf, "", 0))
		DeferCleanup(gate.end)
	}
	start := func() { startWith(fastRetry) }

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

	It("names the conflict once when another process listens on the port, and opens the port once it is free", func() {
		opener.open = func() error {
			return &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
		}
		start()
		gate.set(true)
		// Each try after the first closes the port of unknown state
		// before it opens it.
		Eventually(opener.count).Should(BeNumerically(">=", 7))
		Expect(opener.got()[:7]).To(Equal([]string{"open", "close", "open", "close", "open", "close", "open"}))
		Expect(logBuf.String()).To(Equal("the guest listens on port 8080, but vm-launch could not open it in the container: listen tcp: bind: address already in use\n" +
			"port 8080 already in use in this container; VM backends run one app process per container\n"))

		opener.setOpen(nil)
		Eventually(logBuf.String).Should(HaveSuffix("the guest listens on port 8080; it is open in the container\n"))
		Expect(strings.Count(logBuf.String(), "already in use")).To(Equal(2), logBuf.String())
		n := opener.count()
		Consistently(opener.count, 100*time.Millisecond).Should(Equal(n))
	})

	It("logs a failure that is not a conflict once, without the conflict line", func() {
		opener.open = func() error { return errors.New("QMP human-monitor-command: GenericError: boom") }
		start()
		gate.set(true)
		line := "the guest listens on port 8080, but vm-launch could not open it in the container: QMP human-monitor-command: GenericError: boom\n"
		Eventually(logBuf.String).Should(Equal(line))
		Eventually(opener.count).Should(BeNumerically(">=", 5))
		Expect(logBuf.String()).To(Equal(line))
	})

	It("logs a port it could not close once, and tries again until it closes", func() {
		opener.closeErr = errors.New("QEMU did not remove the forwarding rule: nope")
		start()
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open"}))
		gate.set(false)
		Eventually(opener.count).Should(BeNumerically(">=", 4))
		Expect(opener.got()[1:]).To(HaveEach("close"))
		Expect(logBuf.String()).To(Equal("the guest listens on port 8080; it is open in the container\n" +
			"closing port 8080 in the container: QEMU did not remove the forwarding rule: nope\n"))

		opener.setCloseErr(nil)
		Eventually(logBuf.String).Should(HaveSuffix("the guest no longer listens on port 8080; it is closed in the container\n"))
		n := opener.count()
		Consistently(opener.count, 100*time.Millisecond).Should(Equal(n))
		Expect(strings.Count(logBuf.String(), "closing port")).To(Equal(1), logBuf.String())
	})

	It("waits before it tries again, and acts at once when the guest's state changes", func() {
		opener.open = func() error { return errors.New("boom") }
		startWith(backoff{first: time.Hour, max: time.Hour})
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open"}))
		Consistently(opener.got, 100*time.Millisecond).Should(Equal([]string{"open"}))
		gate.set(false)
		Eventually(opener.got).Should(Equal([]string{"open", "close"}))
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open", "close", "open"}))
		// A new state starts a new run of failures, whose first is logged.
		// The gate logs a failure after the call that failed returns.
		failed := "the guest listens on port 8080, but vm-launch could not open it in the container: boom\n"
		Eventually(logBuf.String).Should(Equal(failed + "the guest no longer listens on port 8080; it is closed in the container\n" + failed))
	})

	It("logs a failed close that follows a failed open, as a new run of failures", func() {
		opener.open = func() error { return errors.New("boom") }
		opener.closeErr = errors.New("nope")
		startWith(backoff{first: time.Hour, max: time.Hour})
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open"}))
		gate.set(false)
		Eventually(opener.got).Should(Equal([]string{"open", "close"}))
		Eventually(logBuf.String).Should(Equal("the guest listens on port 8080, but vm-launch could not open it in the container: boom\n" +
			"closing port 8080 in the container: nope\n"))
	})

	It("keeps its wait when the guest reports the same state again", func() {
		opener.open = func() error { return errors.New("boom") }
		startWith(backoff{first: time.Hour, max: time.Hour})
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open"}))
		for i := 0; i < 10; i++ {
			gate.set(true)
			time.Sleep(10 * time.Millisecond)
		}
		Consistently(opener.got, 100*time.Millisecond).Should(Equal([]string{"open"}))
	})

	It("logs a failure again when it turns into a port conflict, or out of one", func() {
		var (
			mu    sync.Mutex
			tries int
		)
		conflict := &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
		opener.open = func() error {
			mu.Lock()
			defer mu.Unlock()
			tries++
			switch {
			case tries == 1:
				return errors.New("boom")
			case tries <= 4:
				return conflict
			default:
				return errors.New("bang")
			}
		}
		start()
		gate.set(true)
		failed := "the guest listens on port 8080, but vm-launch could not open it in the container: "
		Eventually(opener.count).Should(BeNumerically(">=", 13))
		Expect(logBuf.String()).To(Equal(failed + "boom\n" +
			failed + "listen tcp: bind: address already in use\n" +
			"port 8080 already in use in this container; VM backends run one app process per container\n" +
			failed + "bang\n"))
	})

	It("doubles its wait after each failure, up to the maximum", func() {
		b := backoff{first: time.Second, max: 5 * time.Second}
		var waits []time.Duration
		for w := b.first; len(waits) < 5; w = b.next(w) {
			waits = append(waits, w)
		}
		Expect(waits).To(Equal([]time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}))
	})

	It("keeps trying to close the port at shutDown until it closes", func() {
		opener.closeErr = errors.New("nope")
		start()
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open"}))
		gate.shutDown()
		Eventually(opener.count).Should(BeNumerically(">=", 4))
		opener.setCloseErr(nil)
		Eventually(func() bool {
			n := opener.count()
			time.Sleep(50 * time.Millisecond)
			return opener.count() == n
		}).Should(BeTrue())
		n := opener.count()
		gate.set(true)
		Consistently(opener.count, 100*time.Millisecond).Should(Equal(n))
		Expect(opener.got()[1:]).To(HaveEach("close"))
		Expect(logBuf.String()).To(Equal("the guest listens on port 8080; it is open in the container\n" +
			"closing port 8080 in the container: nope\n" +
			"vm-launch is stopping; port 8080 is closed in the container\n"))
	})

	It("tries a close that waits out its backoff at once at shutDown", func() {
		startWith(backoff{first: time.Hour, max: time.Hour})
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open"}))
		opener.setCloseErr(errors.New("nope"))
		gate.set(false)
		Eventually(opener.got).Should(Equal([]string{"open", "close"}))
		Consistently(opener.got, 100*time.Millisecond).Should(Equal([]string{"open", "close"}))
		opener.setCloseErr(nil)
		gate.shutDown()
		Eventually(opener.got).Should(Equal([]string{"open", "close", "close"}))
		Eventually(logBuf.String).Should(Equal("the guest listens on port 8080; it is open in the container\n" +
			"closing port 8080 in the container: nope\n" +
			"vm-launch is stopping; port 8080 is closed in the container\n"))
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
		Expect(logBuf.String()).To(Equal("the guest listens on port 8080; it is open in the container\n" +
			"vm-launch is stopping; port 8080 is closed in the container\n"))
	})

	It("never opens a port that was closed when shutDown came", func() {
		start()
		gate.shutDown()
		gate.set(true)
		Consistently(opener.got, 100*time.Millisecond).Should(BeEmpty())
	})

	It("leaves the port as it is at end, says that an open port closes, and is silent after it", func() {
		start()
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open"}))
		Expect(gateLoops()).To(Equal(1))
		gate.end()
		Expect(gateLoops()).To(BeZero())
		gate.end()
		gate.set(false)
		gate.shutDown()
		Consistently(opener.got, 100*time.Millisecond).Should(Equal([]string{"open"}))
		Expect(logBuf.String()).To(Equal("the guest listens on port 8080; it is open in the container\n" +
			"the guest has stopped, so port 8080 closes in the container\n"))
	})

	It("says nothing at end when its last line said that the port is closed", func() {
		start()
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open"}))
		gate.set(false)
		Eventually(logBuf.String).Should(HaveSuffix("it is closed in the container\n"))
		gate.end()
		Expect(logBuf.String()).To(Equal("the guest listens on port 8080; it is open in the container\n" +
			"the guest no longer listens on port 8080; it is closed in the container\n"))
	})

	DescribeTable("ends while an open is in progress without logging its outcome",
		func(fails bool) {
			release := make(chan struct{})
			opening := make(chan struct{}, 1)
			opener.open = func() error {
				opening <- struct{}{}
				<-release
				if fails {
					return errors.New("the hypervisor is gone")
				}
				return nil
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
			// The open finishes only once end has closed the gate's ended
			// channel, which is what makes the gate drop its log line.
			Eventually(gate.ended).Should(BeClosed())
			Consistently(ended, 50*time.Millisecond).ShouldNot(BeClosed())
			releaseOnce.Do(func() { close(release) })
			Eventually(ended).Should(BeClosed())
			// An open that went through and was never shown as open leaves
			// nothing for end to say closes.
			Expect(logBuf.String()).To(BeEmpty())
		},
		Entry("an open that fails", true),
		Entry("an open that succeeds", false),
	)

	It("does not say at end that a port closes when its close was logged at shutDown", func() {
		start()
		gate.set(true)
		Eventually(opener.got).Should(Equal([]string{"open"}))
		gate.shutDown()
		Eventually(logBuf.String).Should(HaveSuffix("vm-launch is stopping; port 8080 is closed in the container\n"))
		gate.end()
		Expect(opener.got()).To(Equal([]string{"open", "close"}))
		Expect(logBuf.String()).To(Equal("the guest listens on port 8080; it is open in the container\n" +
			"vm-launch is stopping; port 8080 is closed in the container\n"))
	})
})

// fakeQMP is QEMU's end of a QMP monitor connection, run by the spec.
type fakeQMP struct {
	conn net.Conn
	r    *bufio.Reader
	// id is the id of the last request recv read.
	id json.RawMessage
}

// newFakeQMP returns a monitor on a QMP socket and the fake QEMU on its
// other end. The socket buffers, as QEMU's does, so either side can write
// while the other is writing too.
func newFakeQMP() (*qmpMonitor, *fakeQMP) {
	ours, theirsFile, err := newQMPSocket()
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(ours.Close)
	theirs, err := net.FileConn(theirsFile)
	Expect(err).NotTo(HaveOccurred())
	Expect(theirsFile.Close()).To(Succeed())
	DeferCleanup(theirs.Close)
	return newQMPMonitor(ours), &fakeQMP{conn: theirs, r: bufio.NewReader(theirs)}
}

func (q *fakeQMP) send(msg string) {
	_, err := q.conn.Write([]byte(msg + "\r\n"))
	Expect(err).NotTo(HaveOccurred())
}

// reply sends msg, a JSON object, as the reply to the last request.
func (q *fakeQMP) reply(msg string) {
	q.replyTo(q.id, msg)
}

// replyTo sends msg, a JSON object, with id.
func (q *fakeQMP) replyTo(id json.RawMessage, msg string) {
	var v map[string]json.RawMessage
	Expect(json.Unmarshal([]byte(msg), &v)).To(Succeed())
	v["id"] = id
	b, err := json.Marshal(v)
	Expect(err).NotTo(HaveOccurred())
	q.send(string(b))
}

// recv reads one request, keeps its id for reply, and returns it
// re-encoded with sorted keys.
func (q *fakeQMP) recv() string {
	line, err := q.r.ReadBytes('\n')
	Expect(err).NotTo(HaveOccurred())
	var v map[string]json.RawMessage
	Expect(json.Unmarshal(line, &v)).To(Succeed())
	q.id = v["id"]
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

// capsRequest is the capabilities request with id.
func capsRequest(id int) string {
	return `{"execute":"qmp_capabilities","id":` + strconv.Itoa(id) + `}`
}

// humanRequest is the human monitor command line with id.
func humanRequest(id int, line string) string {
	b, err := json.Marshal(map[string]any{"execute": "human-monitor-command", "arguments": map[string]string{"command-line": line}, "id": id})
	Expect(err).NotTo(HaveOccurred())
	return string(b)
}

var _ = Describe("the QMP monitor", func() {
	It("negotiates capabilities once, skips events, and returns the command output", func() {
		m, qemu := newFakeQMP()
		done := qemu.serve(func() {
			qemu.send(fakeGreeting)
			Expect(qemu.recv()).To(Equal(capsRequest(1)))
			qemu.send(`{"event": "RESUME", "data": {}, "timestamp": {"seconds": 1, "microseconds": 0}}`)
			qemu.reply(`{"return": {}}`)
			Expect(qemu.recv()).To(Equal(humanRequest(2, "info network")))
			qemu.send(`{"event": "NIC_RX_FILTER_CHANGED", "data": {}, "timestamp": {"seconds": 1, "microseconds": 0}}`)
			qemu.reply(`{"return": "n0: user\r\n"}`)
			Expect(qemu.recv()).To(Equal(humanRequest(3, "hostfwd_add n0 tcp:0.0.0.0:8080-10.0.2.15:8080")))
			qemu.reply(`{"return": ""}`)
		})
		Expect(m.humanCommand("info network")).To(Equal("n0: user\r\n"))
		Expect(m.humanCommand("hostfwd_add n0 tcp:0.0.0.0:8080-10.0.2.15:8080")).To(Equal(""))
		Eventually(done).Should(BeClosed())
	})

	It("runs the commands of several goroutines one at a time, each getting its own reply", func() {
		m, qemu := newFakeQMP()
		const callers, each = 4, 10
		done := qemu.serve(func() {
			qemu.send(fakeGreeting)
			qemu.recv()
			qemu.reply(`{"return": {}}`)
			for i := 0; i < callers*each; i++ {
				var req struct {
					Arguments struct {
						CommandLine string `json:"command-line"`
					} `json:"arguments"`
				}
				Expect(json.Unmarshal([]byte(qemu.recv()), &req)).To(Succeed())
				reply, err := json.Marshal(req.Arguments.CommandLine)
				Expect(err).NotTo(HaveOccurred())
				qemu.reply(`{"return": ` + string(reply) + `}`)
			}
		})
		var wg sync.WaitGroup
		for c := 0; c < callers; c++ {
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				for i := 0; i < each; i++ {
					line := fmt.Sprintf("caller %d command %d", c, i)
					Expect(m.humanCommand(line)).To(Equal(line))
				}
			}()
		}
		wg.Wait()
		Eventually(done).Should(BeClosed())
	})

	It("returns an error reply as an error and stays usable", func() {
		m, qemu := newFakeQMP()
		done := qemu.serve(func() {
			qemu.send(fakeGreeting)
			qemu.recv()
			qemu.reply(`{"return": {}}`)
			qemu.recv()
			qemu.reply(`{"error": {"class": "GenericError", "desc": "Invalid netdev"}}`)
			qemu.recv()
			qemu.reply(`{"return": "ok"}`)
		})
		_, err := m.humanCommand("hostfwd_add x tcp:0.0.0.0:1-10.0.2.15:1")
		Expect(err).To(MatchError("QMP human-monitor-command: GenericError: Invalid netdev"))
		Expect(m.humanCommand("info network")).To(Equal("ok"))
		Eventually(done).Should(BeClosed())
	})

	It("fails for good when QEMU refuses capabilities, and sends nothing more", func() {
		m, qemu := newFakeQMP()
		done := qemu.serve(func() {
			qemu.send(fakeGreeting)
			Expect(qemu.recv()).To(Equal(capsRequest(1)))
			qemu.reply(`{"error": {"class": "CommandNotFound", "desc": "Capabilities negotiation is already complete, command ignored"}}`)
		})
		_, err := m.humanCommand("info network")
		Expect(err).To(MatchError("QMP qmp_capabilities: CommandNotFound: Capabilities negotiation is already complete, command ignored"))
		Eventually(done).Should(BeClosed())
		_, again := m.humanCommand("info network")
		Expect(again).To(BeIdenticalTo(err))
		// The second command returned without a write, so whatever it
		// had sent would already be waiting.
		Expect(qemu.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))).To(Succeed())
		_, rerr := qemu.r.ReadByte()
		Expect(rerr).To(MatchError(os.ErrDeadlineExceeded))
	})

	It("fails for good when the first message is not a greeting", func() {
		m, qemu := newFakeQMP()
		qemu.serve(func() { qemu.send(`{"return": {}}`) })
		_, err := m.humanCommand("info network")
		Expect(err).To(MatchError("QMP: the first message is not a greeting"))
		_, again := m.humanCommand("info network")
		Expect(again).To(BeIdenticalTo(err))
	})

	It("skips the late reply to a command that timed out, so the next command gets its own", func() {
		m, qemu := newFakeQMP()
		m.timeout = 100 * time.Millisecond
		late := make(chan struct{})
		done := qemu.serve(func() {
			qemu.send(fakeGreeting)
			qemu.recv()
			qemu.reply(`{"return": {}}`)
			Expect(qemu.recv()).To(Equal(humanRequest(2, "hostfwd_add n0 tcp:0.0.0.0:8080-10.0.2.15:8080")))
			<-late
			qemu.reply(`{"error": {"class": "GenericError", "desc": "late"}}`)
			qemu.reply(`{"return": "late too"}`)
			Expect(qemu.recv()).To(Equal(humanRequest(3, "hostfwd_remove n0 tcp:0.0.0.0:8080")))
			qemu.reply(`{"return": "removed"}`)
		})
		_, err := m.humanCommand("hostfwd_add n0 tcp:0.0.0.0:8080-10.0.2.15:8080")
		Expect(err).To(MatchError(ContainSubstring("QMP human-monitor-command: reading the reply: ")))
		Expect(errors.Is(err, os.ErrDeadlineExceeded)).To(BeTrue(), err.Error())
		close(late)
		Expect(m.humanCommand("hostfwd_remove n0 tcp:0.0.0.0:8080")).To(Equal("removed"))
		Eventually(done).Should(BeClosed())
	})

	It("waits for the reply to a capabilities request that timed out instead of sending it again", func() {
		m, qemu := newFakeQMP()
		m.timeout = 100 * time.Millisecond
		late := make(chan struct{})
		done := qemu.serve(func() {
			qemu.send(fakeGreeting)
			Expect(qemu.recv()).To(Equal(capsRequest(1)))
			<-late
			qemu.reply(`{"return": {}}`)
			Expect(qemu.recv()).To(Equal(humanRequest(2, "info network")))
			qemu.reply(`{"return": "ok"}`)
		})
		_, err := m.humanCommand("info network")
		Expect(err).To(MatchError(ContainSubstring("QMP qmp_capabilities: reading the reply: ")))
		Expect(errors.Is(err, os.ErrDeadlineExceeded)).To(BeTrue(), err.Error())
		close(late)
		Expect(m.humanCommand("info network")).To(Equal("ok"))
		Eventually(done).Should(BeClosed())
	})

	It("reads a line that a timeout cut off, and a greeting that came late, in the next command", func() {
		m, qemu := newFakeQMP()
		m.timeout = 100 * time.Millisecond
		next := make(chan struct{})
		done := qemu.serve(func() {
			_, err := qemu.conn.Write([]byte(fakeGreeting[:20]))
			Expect(err).NotTo(HaveOccurred())
			<-next
			qemu.send(fakeGreeting[20:])
			qemu.recv()
			qemu.reply(`{"return": {}}`)
			Expect(qemu.recv()).To(Equal(humanRequest(2, "info network")))
			_, err = qemu.conn.Write([]byte(`{"id": 2, "return": `))
			Expect(err).NotTo(HaveOccurred())
			<-next
			qemu.send(`"ok"}`)
			Expect(qemu.recv()).To(Equal(humanRequest(3, "info network")))
			qemu.reply(`{"return": "again"}`)
		})
		_, err := m.humanCommand("info network")
		Expect(err).To(MatchError(ContainSubstring("QMP: reading the greeting: ")))
		Expect(errors.Is(err, os.ErrDeadlineExceeded)).To(BeTrue(), err.Error())
		next <- struct{}{}
		_, err = m.humanCommand("info network")
		Expect(err).To(MatchError(ContainSubstring("QMP human-monitor-command: reading the reply: ")))
		Expect(errors.Is(err, os.ErrDeadlineExceeded)).To(BeTrue(), err.Error())
		next <- struct{}{}
		// The rest of the cut-off reply, to command 2, is skipped.
		Expect(m.humanCommand("info network")).To(Equal("again"))
		Eventually(done).Should(BeClosed())
	})

	It("fails for good when QEMU closes its end of the QMP socket", func() {
		conn, theirs, err := newQMPSocket()
		Expect(err).NotTo(HaveOccurred())
		defer conn.Close()
		Expect(theirs.Close()).To(Succeed())
		m := newQMPMonitor(conn)
		_, err = m.humanCommand("info network")
		Expect(err).To(MatchError("QMP: reading the greeting: EOF"))
		_, again := m.humanCommand("info network")
		Expect(again).To(BeIdenticalTo(err))
	})

	It("fails for good on a line that is not a QMP message", func() {
		m, qemu := newFakeQMP()
		qemu.serve(func() {
			qemu.send(fakeGreeting)
			qemu.recv()
			qemu.send(`{"return": {}, "id": 1`)
		})
		_, err := m.humanCommand("info network")
		Expect(err).To(MatchError(HavePrefix("QMP qmp_capabilities: reading the reply: a line that is not a QMP message: ")))
		_, again := m.humanCommand("info network")
		Expect(again).To(BeIdenticalTo(err))
	})

	It("fails for a reply that is neither a return nor an error, or a return that is not text", func() {
		m, qemu := newFakeQMP()
		qemu.serve(func() {
			qemu.send(fakeGreeting)
			qemu.recv()
			qemu.reply(`{"return": {}}`)
			qemu.recv()
			qemu.reply(`{}`)
		})
		_, err := m.humanCommand("info network")
		Expect(err).To(MatchError("QMP human-monitor-command: a reply with neither a return nor an error"))

		m, qemu = newFakeQMP()
		qemu.serve(func() {
			qemu.send(fakeGreeting)
			qemu.recv()
			qemu.reply(`{"return": {}}`)
			qemu.recv()
			qemu.reply(`{"return": {}}`)
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
				qemu.reply(`{"return": {}}`)
				got = qemu.recv()
				qemu.reply(reply)
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
			Expect(got).To(Equal(humanRequest(2, "hostfwd_add n0 tcp:0.0.0.0:8080-10.0.2.15:8080")))
		})

		It("reports a rule QEMU could not set up as a port conflict", func() {
			_, err := ruleRun(true, `{"return": "Could not set up host forwarding rule 'tcp:0.0.0.0:8080-10.0.2.15:8080'\r\n"}`)
			Expect(err).To(MatchError("QEMU could not set up the forwarding rule: Could not set up host forwarding rule 'tcp:0.0.0.0:8080-10.0.2.15:8080'"))
			Expect(isPortConflict(err)).To(BeTrue())
		})

		It("reports other output of hostfwd_add as a failure that is not a conflict", func() {
			_, err := ruleRun(true, `{"return": "Invalid host forwarding rule 'tcp:0.0.0.0:8080-10.0.2.15:8080' (Bad host port)\r\n"}`)
			Expect(err).To(MatchError("QEMU did not add the forwarding rule: Invalid host forwarding rule 'tcp:0.0.0.0:8080-10.0.2.15:8080' (Bad host port)"))
			Expect(isPortConflict(err)).To(BeFalse())
		})

		It("removes the rule", func() {
			got, err := ruleRun(false, `{"return": "host forwarding rule for tcp:0.0.0.0:8080 removed\r\n"}`)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(humanRequest(2, "hostfwd_remove n0 tcp:0.0.0.0:8080")))
		})

		It("counts a rule that QEMU does not have as removed", func() {
			_, err := ruleRun(false, `{"return": "host forwarding rule for tcp:0.0.0.0:8080 not found\r\n"}`)
			Expect(err).NotTo(HaveOccurred())
		})

		It("fails when QEMU did not remove the rule", func() {
			_, err := ruleRun(false, `{"return": "invalid format\r\n"}`)
			Expect(err).To(MatchError("QEMU did not remove the forwarding rule: invalid format"))
			Expect(isPortConflict(err)).To(BeFalse())
		})

		It("counts every rule of a QEMU that closed its QMP socket as removed, and cannot add one", func() {
			conn, theirs, err := newQMPSocket()
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()
			Expect(theirs.Close()).To(Succeed())
			p := qmpPort{monitor: newQMPMonitor(conn), port: 8080}
			Expect(p.closePort()).To(Succeed())
			Expect(p.openPort()).To(MatchError("QMP: reading the greeting: EOF"))
			Expect(p.closePort()).To(Succeed())

			// A QEMU that exits after the greeting, with a request unread.
			conn, theirs, err = newQMPSocket()
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()
			_, err = theirs.Write([]byte(fakeGreeting + "\r\n"))
			Expect(err).NotTo(HaveOccurred())
			p = qmpPort{monitor: newQMPMonitor(conn), port: 8080}
			go func() {
				defer GinkgoRecover()
				buf := make([]byte, 1)
				_, err := theirs.Read(buf)
				Expect(err).NotTo(HaveOccurred())
				Expect(theirs.Close()).To(Succeed())
			}()
			Expect(p.closePort()).To(Succeed())
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

		p := newProxy(testDialPolicy, log.New(io.Discard, "", 0))
		defer p.Close()
		Expect(p.Listen("0.0.0.0:"+strconv.Itoa(port), unusedAddr())).To(Succeed())
		c, err := net.Dial("tcp", addr)
		Expect(err).NotTo(HaveOccurred())
		c.Close()
		p.StopListening("0.0.0.0:" + strconv.Itoa(port))
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
	// may run, as /bin holds them in the guest.
	watcherPath := func(shell guestShell) string {
		if len(shell.argv) == 1 {
			return "/usr/bin:/bin"
		}
		bin := guestBin(shell)
		for _, applet := range []string{"printf", "kill"} {
			Expect(os.Symlink(shell.argv[0], filepath.Join(bin, applet))).To(Succeed())
		}
		return bin
	}

	// watcherTimeout bounds a watcher that a spec runs to its end. A round
	// takes milliseconds, so a watcher that runs this long hangs.
	const watcherTimeout = 10 * time.Second

	// runBounded runs name with args and env, in a process group of its
	// own, and returns its combined output and error. A command that is
	// still running after watcherTimeout fails the spec with what it
	// printed so far, and its whole process group is killed, because the
	// watcher is a subshell that can outlive its parent and hold the output
	// pipe open. The group is killed when the command returns too, so a
	// child the shell leaves behind does not outlive it.
	runBounded := func(name string, args, env []string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), watcherTimeout)
		defer cancel()
		c := exec.CommandContext(ctx, name, args...)
		c.Env = env
		c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
		c.WaitDelay = time.Second
		out, err := c.CombinedOutput()
		// Nothing is left to wait for, so ESRCH, from a group with no
		// process in it, is the usual answer and not an error.
		_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		if ctx.Err() != nil {
			Fail(fmt.Sprintf("%s was still running after %v; it printed so far:\n%s", filepath.Base(name), watcherTimeout, out))
		}
		return out, err
	}

	// newTick returns a FIFO for the watcher to wait on, in a directory
	// that any user can reach.
	newTick := func() string {
		dir, err := os.MkdirTemp("", "vm-launch-tick-")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(os.RemoveAll, dir)
		Expect(os.Chmod(dir, 0o755)).To(Succeed())
		tick := filepath.Join(dir, "tick")
		Expect(unix.Mkfifo(tick, 0o666)).To(Succeed())
		Expect(os.Chmod(tick, 0o666)).To(Succeed())
		return tick
	}

	// watchOnStdout is the watcher with its listen lines on stdout in
	// place of the console, waiting on the FIFO tick.
	watchOnStdout := func(tick string) string {
		watch := guestListenWatch(testNonce)
		Expect(watch).To(ContainSubstring(" >/dev/console "))
		Expect(strings.Count(watch, guestListenTick)).To(Equal(2))
		return strings.NewReplacer(" >/dev/console ", " ", guestListenTick, tick).Replace(watch)
	}

	// noTable stands for a /proc/net table the guest kernel lacks, and
	// unreadable for one that the watcher cannot read.
	const (
		noTable    = "\x00"
		unreadable = "\x01"
	)

	// watchPorts runs the watcher for ports, after the shell code prelude,
	// against fake /proc/net/tcp and tcp6 contents, either of which may be
	// noTable or unreadable, with its listen lines on stdout. The watcher
	// starts in the state that exactly the ports of was are up, and calls
	// rvm_round_end in place of its pause, which ends it after one round
	// unless prelude defines it again. watchPorts returns what the watcher
	// printed.
	watchPorts := func(shell guestShell, ports []int, tcp, tcp6, prelude string, was []int) string {
		dir := GinkgoT().TempDir()
		tcpPath, tcp6Path := filepath.Join(dir, "tcp"), filepath.Join(dir, "tcp6")
		for path, table := range map[string]string{tcpPath: tcp, tcp6Path: tcp6} {
			switch table {
			case noTable:
			case unreadable:
				// A directory opens, and every read of it fails.
				Expect(os.Mkdir(path, 0o755)).To(Succeed())
			default:
				Expect(os.WriteFile(path, []byte(procNetHeader+table), 0o644)).To(Succeed())
			}
		}
		upSet := " "
		for _, p := range was {
			upSet += fmt.Sprintf("%04X ", p)
		}
		watch := watchOnStdout(newTick())
		const startState = "\n\t\trvm_upset=\" \"\n"
		for _, s := range []string{" /proc/net/tcp /proc/net/tcp6;", startState, "\n\t\t\trvm_pause\n"} {
			Expect(watch).To(ContainSubstring(s))
		}
		watch = strings.NewReplacer(
			" /proc/net/tcp /proc/net/tcp6;", " "+tcpPath+" "+tcp6Path+";",
			startState, "\n\t\trvm_upset=\""+upSet+"\"\n",
			"\n\t\t\trvm_pause\n", "\n\t\t\trvm_round_end\n",
		).Replace(watch)
		script := "rvm_round_end() { exit 0; }\n" + prelude + watch + `wait "$rvm_watch"` + "\n"
		list := make([]string, len(ports))
		for i, p := range ports {
			list[i] = strconv.Itoa(p)
		}
		out, err := runBounded(shell.argv[0], append(shell.argv[1:], "-c", script),
			[]string{"PATH=" + watcherPath(shell), "RVM_PORTS=" + strings.Join(list, " ")})
		Expect(err).NotTo(HaveOccurred(), "%s: %s", shell.name, out)
		return string(out)
	}

	// watchRound runs the watcher for one port, which was up before the
	// round when wasUp is "1".
	watchRound := func(shell guestShell, port int, tcp, tcp6, prelude, wasUp string) string {
		var was []int
		if wasUp == "1" {
			was = []int{port}
		}
		return watchPorts(shell, []int{port}, tcp, tcp6, prelude, was)
	}

	// checkOnce runs one round of the watcher, from the state not
	// listening, with both tables present.
	checkOnce := func(shell guestShell, port int, tcp, tcp6 string) string {
		return watchRound(shell, port, tcp, tcp6, "", "0")
	}

	// listenLine is the line the watcher prints when port goes up or down.
	listenLine := func(port int, up bool) string {
		state := "0"
		if up {
			state = "1"
		}
		return "RVM_LISTEN_" + testNonce + "=" + strconv.Itoa(port) + ":" + state + "\n"
	}
	listening, notListening := listenLine(8080, true), listenLine(8080, false)

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
		"other listeners first":                {port: 8080, tcp: procNetLine("00000000:0016", "0A") + procNetLine("0100007F:1F90", "0A") + procNetLine("00000000:1F90", "0A"), want: true},
		"no sockets":                           {port: 8080},
	}

	DescribeTable("reports a listening socket on the port at any address but loopback",
		func(shellOf func() guestShell) {
			shell := shellOf()
			for name, c := range cases {
				out := checkOnce(shell, c.port, c.tcp, c.tcp6)
				if c.want {
					Expect(out).To(Equal(listenLine(c.port, true)), "%s: %s", shell.name, name)
				} else {
					Expect(out).To(BeEmpty(), "%s: %s", shell.name, name)
				}
			}
		},
		shellEntries(""),
	)

	DescribeTable("reports each port on its own, from one pass over the tables",
		func(shellOf func() guestShell) {
			shell := shellOf()
			ports := []int{8080, 8081, 9000}
			a, b := procNetLine("00000000:1F90", "0A"), procNetLine("00000000:1F91", "0A")
			loopback9000 := procNetLine("0100007F:2328", "0A")
			// Only 8080 listens: 8081 and 9000 stay down and say nothing.
			Expect(watchPorts(shell, ports, a, "", "", nil)).To(Equal(listenLine(8080, true)), shell.name)
			// Both 8080 and 8081 listen, and 9000 listens on loopback only.
			Expect(watchPorts(shell, ports, a+b+loopback9000, "", "", nil)).To(Equal(listenLine(8080, true)+listenLine(8081, true)), shell.name)
			// A port that is up and still listens says nothing, and one that
			// stopped says so alone.
			Expect(watchPorts(shell, ports, a, "", "", []int{8080, 8081})).To(Equal(listenLine(8081, false)), shell.name)
			Expect(watchPorts(shell, ports, a+b, "", "", []int{8080, 8081})).To(BeEmpty(), shell.name)
			// A port in the second table counts too.
			Expect(watchPorts(shell, ports, a, procNetLine(wildcard6+":2328", "0A"), "", []int{8080})).To(Equal(listenLine(9000, true)), shell.name)
			// Every port that was up goes down when nothing listens.
			Expect(watchPorts(shell, ports, "", "", "", []int{8080, 9000})).To(Equal(listenLine(8080, false)+listenLine(9000, false)), shell.name)
		},
		shellEntries(""),
	)

	DescribeTable("keeps the last answer of every port when a look fails",
		func(shellOf func() guestShell) {
			shell := shellOf()
			ports := []int{8080, 8081}
			a := procNetLine("00000000:1F90", "0A")
			Expect(watchPorts(shell, ports, unreadable, "", "", []int{8080, 8081})).To(BeEmpty(), shell.name)
			// A port found in the look that worked is up, and the one that
			// the failed table might have held keeps its answer.
			Expect(watchPorts(shell, ports, unreadable, "", "", []int{8081})).To(BeEmpty(), shell.name)
			Expect(watchPorts(shell, ports, a, unreadable, "", []int{8081})).To(Equal(listenLine(8080, true)), shell.name)
		},
		shellEntries(""),
	)

	DescribeTable("repeats the listen line of one port that failed to write without touching another",
		func(shellOf func() guestShell) {
			shell := shellOf()
			ports := []int{8080, 8081}
			both := procNetLine("00000000:1F90", "0A") + procNetLine("00000000:1F91", "0A")
			// The write of the 8080 line fails: echo is a function that
			// fails for that line only, so 8080 stays down and the 8081
			// line still goes out.
			prelude := `echo() { case "$*" in *=8080:*) return 1 ;; esac; printf '%s\n' "$*"; }` + "\n"
			Expect(watchPorts(shell, ports, both, "", prelude, nil)).To(Equal(listenLine(8081, true)), shell.name)
		},
		shellEntries(""),
	)

	DescribeTable("reads a table only up to its first socket that is not listening, as the kernel lists listening sockets first",
		func(shellOf func() guestShell) {
			shell := shellOf()
			connection := procNetLine("0F02000A:1F90", "01")
			Expect(watchRound(shell, 8080, connection+procNetLine("00000000:1F90", "0A"), "", "", "0")).To(BeEmpty(), shell.name)
			Expect(watchRound(shell, 8080, procNetLine("00000000:1F90", "0A")+connection, "", "", "0")).To(Equal(listening), shell.name)
		},
		shellEntries(""),
	)

	DescribeTable("reads only the tables the guest kernel has",
		func(shellOf func() guestShell) {
			shell := shellOf()
			Expect(watchRound(shell, 8080, procNetLine("00000000:1F90", "0A"), noTable, "", "0")).To(Equal(listening), shell.name)
			Expect(watchRound(shell, 8080, noTable, procNetLine(wildcard6+":1F90", "0A"), "", "0")).To(Equal(listening), shell.name)
			Expect(watchRound(shell, 8080, noTable, noTable, "", "1")).To(Equal(notListening), shell.name)
		},
		shellEntries(""),
	)

	DescribeTable("keeps its state when it cannot read a table, unless the other table has a listener",
		func(shellOf func() guestShell) {
			shell := shellOf()
			up := procNetLine("00000000:1F90", "0A")
			for _, wasUp := range []string{"0", "1"} {
				Expect(watchRound(shell, 8080, unreadable, "", "", wasUp)).To(BeEmpty(), "%s: was %s", shell.name, wasUp)
				Expect(watchRound(shell, 8080, "", unreadable, "", wasUp)).To(BeEmpty(), "%s: was %s", shell.name, wasUp)
			}
			Expect(watchRound(shell, 8080, unreadable, procNetLine(wildcard6+":1F90", "0A"), "", "0")).To(Equal(listening), shell.name)
			Expect(watchRound(shell, 8080, up, unreadable, "", "0")).To(Equal(listening), shell.name)
			Expect(watchRound(shell, 8080, "", "", "", "1")).To(Equal(notListening), shell.name)
		},
		shellEntries(""),
	)

	DescribeTable("writes a listen line that failed again in the next round",
		func(shellOf func() guestShell) {
			shell := shellOf()
			prelude := `rvm_round_end() { [ -n "${rvm_again:-}" ] && exit 0; rvm_again=1; }
echo() { if [ -z "${rvm_failed_once:-}" ]; then rvm_failed_once=1; return 1; fi; command echo "$@"; }
`
			Expect(watchRound(shell, 8080, procNetLine("00000000:1F90", "0A"), "", prelude, "0")).To(Equal(listening), shell.name)
		},
		shellEntries(""),
	)

	It("does nothing in a guest without a port", func() {
		out, err := runBounded("/bin/sh", []string{"-c", guestListenWatch(testNonce) + guestListenStop + `echo "watch=[$rvm_watch]"`},
			[]string{"PATH=/usr/bin:/bin"})
		Expect(err).NotTo(HaveOccurred(), string(out))
		Expect(string(out)).To(Equal("watch=[]\n"))
	})

	// A shell that exits normally can leave a background child behind. The
	// group kill covers that child as well as the one a timeout abandons, so
	// no spec leaks a process even when its script is wrong.
	DescribeTable("kills a background child that outlives the shell, whether or not it holds the output pipe",
		func(redirect string) {
			out, err := runBounded("/bin/sh", []string{"-c", "sleep 60 " + redirect + " & echo $!"},
				[]string{"PATH=/usr/bin:/bin"})
			if redirect != "" {
				Expect(err).NotTo(HaveOccurred(), string(out))
			}
			pid, convErr := strconv.Atoi(strings.TrimSpace(string(out)))
			Expect(convErr).NotTo(HaveOccurred(), string(out))
			Expect(pid).To(BeNumerically(">", 1))

			// A killed child that nothing has reaped yet is a zombie, which
			// still has a /proc entry but is no longer running.
			running := func() bool {
				stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
				if err != nil {
					return false
				}
				state := stat[bytes.LastIndexByte(stat, ')')+2]
				return state != 'Z' && state != 'X'
			}
			DeferCleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
			Eventually(running, 5*time.Second, 20*time.Millisecond).Should(BeFalse(), "the sleep the shell left behind is still running")
		},
		Entry("with the child holding the output pipe", ""),
		Entry("with the child's output redirected", ">/dev/null 2>&1"),
	)

	// The other specs of the watcher replace its pause, so none of them
	// shows that the watcher waits between its looks. A watcher that did not
	// would look at both tables in a tight loop for the life of the VM and
	// still report every change correctly.
	DescribeTable("waits about a second in each pause, with the FIFO and without it",
		func(withFIFO bool) {
			shell := guestBusyboxShell()
			tick := filepath.Join(GinkgoT().TempDir(), "no-tick")
			if withFIFO {
				tick = newTick()
			}
			// The watcher's own text from the choice of the pause up to
			// the start of its loop, run as the watcher runs it, in a
			// subshell with its stdin on /dev/null.
			watch := watchOnStdout(tick)
			from, to := strings.Index(watch, "\t\tif [ -p "), strings.Index(watch, "\n\t\trvm_upset=\" \"\n")
			Expect(from).To(BeNumerically(">=", 0), watch)
			Expect(to).To(BeNumerically(">", from), watch)
			script := "(\n" + watch[from:to] + `
		if [ -p /proc/self/fd/3 ]; then echo fifo=open; else echo fifo=none; fi
		rvm_pause
		rvm_pause
		echo paused
) </dev/null
`
			began := time.Now()
			out, err := runBounded(shell.argv[0], append(shell.argv[1:], "-c", script),
				[]string{"PATH=" + watcherPath(shell)})
			elapsed := time.Since(began)
			Expect(err).NotTo(HaveOccurred(), string(out))
			want := "fifo=none\npaused\n"
			if withFIFO {
				want = "fifo=open\npaused\n"
			}
			Expect(string(out)).To(Equal(want))
			Expect(elapsed).To(BeNumerically(">=", 1800*time.Millisecond), "two pauses took %v", elapsed)
		},
		Entry("waits on the FIFO", true),
		Entry("waits with sleep when the guest has no FIFO", false),
	)

	// startWatcher starts script in shell, with the watcher's port and its
	// own process group, and returns the command, a pipe to its stdin, and
	// its stdout lines. A cleanup kills the whole process group, because
	// the watcher is a subshell that holds the output pipes open, and Wait
	// would wait for a watcher that never ends.
	startWatcher := func(shell guestShell, port int, script string, attr *syscall.SysProcAttr) (*exec.Cmd, io.Writer, *safeBuffer, <-chan string) {
		c := exec.Command(shell.argv[0], append(shell.argv[1:], "-c", script)...)
		c.Env = []string{"PATH=" + watcherPath(shell), "RVM_PORTS=" + strconv.Itoa(port)}
		stdin, err := c.StdinPipe()
		Expect(err).NotTo(HaveOccurred())
		stdout, err := c.StdoutPipe()
		Expect(err).NotTo(HaveOccurred())
		stderr := &safeBuffer{}
		c.Stderr = io.MultiWriter(stderr, GinkgoWriter)
		attr.Setpgid = true
		c.SysProcAttr = attr
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
		return c, stdin, stderr, lines
	}

	// loopbackPort returns a port with a listener on 127.0.0.1, which the
	// watcher does not count, and on which followListener can listen at
	// [::]. A port that is free on 127.0.0.1 can still be taken for IPv6,
	// as by a socket in TIME_WAIT on [::1], so it tries other ports.
	loopbackPort := func() int {
		for try := 0; try < 20; try++ {
			loopback, err := net.Listen("tcp4", "127.0.0.1:0")
			Expect(err).NotTo(HaveOccurred())
			port := loopback.Addr().(*net.TCPAddr).Port
			wild, err := net.Listen("tcp6", "[::]:"+strconv.Itoa(port))
			if err == nil {
				Expect(wild.Close()).To(Succeed())
				DeferCleanup(loopback.Close)
				return port
			}
			Expect(loopback.Close()).To(Succeed())
		}
		Fail("found no port free on both 127.0.0.1 and [::] in 20 tries")
		return 0
	}

	// followListener opens and closes a listener on [::]:port and expects
	// the watcher's lines for each.
	followListener := func(port int, lines <-chan string) {
		Consistently(lines, 1500*time.Millisecond).ShouldNot(Receive())
		wild, err := net.Listen("tcp6", "[::]:"+strconv.Itoa(port))
		Expect(err).NotTo(HaveOccurred())
		Eventually(lines, 5*time.Second).Should(Receive(Equal("RVM_LISTEN_" + testNonce + "=" + strconv.Itoa(port) + ":1")))
		Expect(wild.Close()).To(Succeed())
		Eventually(lines, 5*time.Second).Should(Receive(Equal("RVM_LISTEN_" + testNonce + "=" + strconv.Itoa(port) + ":0")))
	}

	DescribeTable("follows real sockets, among connections, and stops before /init reports the status",
		func(shellOf func() guestShell) {
			shell := shellOf()
			port := loopbackPort()
			// Connections in both tables, which the kernel lists after
			// the listening sockets.
			for _, network := range []string{"tcp4", "tcp6"} {
				l, err := net.Listen(network, "localhost:0")
				if err != nil {
					continue
				}
				DeferCleanup(l.Close)
				c, err := net.Dial(network, l.Addr().String())
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(c.Close)
			}
			// /bin/sh has no read with a timeout, so it gets no FIFO and
			// waits with sleep, as the guest would without one.
			tick := filepath.Join(GinkgoT().TempDir(), "no-tick")
			if len(shell.argv) > 1 {
				tick = newTick()
			}
			script := watchOnStdout(tick) + "read rvm_go\n" + guestListenStop + "echo stopped\n"
			c, stdin, _, lines := startWatcher(shell, port, script, &syscall.SysProcAttr{})

			followListener(port, lines)

			_, err := stdin.Write([]byte("\n"))
			Expect(err).NotTo(HaveOccurred())
			Eventually(lines, 3*time.Second).Should(Receive(Equal("stopped")))
			// With sleep, the watcher's last sleep may hold the output
			// open for up to a second after the watcher itself is gone.
			Eventually(lines, 3*time.Second).Should(BeClosed())
			Expect(c.Wait()).To(Succeed())
		},
		shellEntries(""),
	)

	It("goes on in the guest's busybox sh when no process can fork", func() {
		shell := guestBusyboxShell()
		port := loopbackPort()
		// The shell forks once more after the watcher stops, which fails
		// and ends it with status 2, to show that the limit holds.
		script := watchOnStdout(newTick()) + `echo "watcher=$rvm_watch"
read rvm_go
` + guestListenStop + `echo stopped
( : )
echo forked
`
		// RLIMIT_NPROC binds a user without CAP_SYS_RESOURCE, so as root
		// the shell runs as nobody.
		attr := &syscall.SysProcAttr{}
		if os.Getuid() == 0 {
			attr.Credential = &syscall.Credential{Uid: 65534, Gid: 65534}
		}
		c, stdin, stderr, lines := startWatcher(shell, port, script, attr)
		var watcher int
		Eventually(lines, 5*time.Second).Should(Receive(WithTransform(func(l string) bool {
			n, err := strconv.Atoi(strings.TrimPrefix(l, "watcher="))
			watcher = n
			return err == nil
		}, BeTrue())))
		// Each process of the user counts against a limit of one, so
		// neither shell can fork from here on.
		for _, pid := range []int{c.Process.Pid, watcher} {
			Expect(unix.Prlimit(pid, unix.RLIMIT_NPROC, &unix.Rlimit{Cur: 1, Max: 1}, nil)).To(Succeed())
		}

		followListener(port, lines)

		_, err := stdin.Write([]byte("\n"))
		Expect(err).NotTo(HaveOccurred())
		Eventually(lines, 3*time.Second).Should(Receive(Equal("stopped")))
		Eventually(lines, 3*time.Second).Should(BeClosed())
		err = c.Wait()
		Expect(err).To(HaveOccurred(), stderr.String())
		Expect(c.ProcessState.ExitCode()).To(Equal(2), stderr.String())
		Expect(stderr.String()).To(ContainSubstring("can't fork"))
		Expect(strings.Count(stderr.String(), "can't fork")).To(Equal(1), stderr.String())
	})
})
