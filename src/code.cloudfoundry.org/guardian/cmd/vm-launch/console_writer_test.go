//go:build linux

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// consoleRead is one read from the console pipe and when it returned.
type consoleRead struct {
	at   time.Time
	data []byte
}

// consoleReader reads the read end of a console pipe, once started, until
// the end of the stream, and records each read.
type consoleReader struct {
	r     *os.File
	mu    sync.Mutex
	reads []consoleRead
	done  chan struct{}
}

func newConsoleReader(r *os.File) *consoleReader {
	return &consoleReader{r: r, done: make(chan struct{})}
}

func (c *consoleReader) start() {
	go func() {
		defer close(c.done)
		buf := make([]byte, 1<<16)
		for {
			n, err := c.r.Read(buf)
			if n > 0 {
				c.mu.Lock()
				c.reads = append(c.reads, consoleRead{at: time.Now(), data: append([]byte(nil), buf[:n]...)})
				c.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
}

func (c *consoleReader) got() []consoleRead {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]consoleRead(nil), c.reads...)
}

func (c *consoleReader) bytes() []byte {
	var b []byte
	for _, r := range c.got() {
		b = append(b, r.data...)
	}
	return b
}

// consolePipe returns a console writer on a new pipe, and a reader of the
// pipe that has not started yet. Both ends close when the spec ends.
func consolePipe() (*consoleWriter, *consoleReader) {
	r, wf, err := os.Pipe()
	Expect(err).NotTo(HaveOccurred())
	w := newConsoleWriter(wf)
	DeferCleanup(func() {
		_ = w.close()
		_ = r.Close()
	})
	return w, newConsoleReader(r)
}

// pushLines returns n lines that pack two to a chunk: each is 127 bytes, and
// 128 with its newline.
func pushLines(n int) []string {
	lines := make([]string, n)
	for i := range lines {
		head := fmt.Sprintf("RVM_CRED_%s=crt %04d ", testNonce, i)
		lines[i] = head + strings.Repeat("A", 127-len(head))
	}
	return lines
}

func joinLines(lines []string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

// pipeHolds returns how many unread bytes the pipe behind r holds (TIOCINQ
// is FIONREAD on Linux).
// It goes through SyscallConn, because Fd would make the pipe blocking.
func pipeHolds(r *os.File) int {
	raw, err := r.SyscallConn()
	Expect(err).NotTo(HaveOccurred())
	var n int
	Expect(raw.Control(func(fd uintptr) { n, err = unix.IoctlGetInt(int(fd), unix.TIOCINQ) })).To(Succeed())
	Expect(err).NotTo(HaveOccurred())
	return n
}

var _ = Describe("the console writer", func() {
	stopLine := stopTag(testNonce) + "\n"

	It("writes the stop request byte for byte as one line", func() {
		w, rd := consolePipe()
		rd.start()
		Expect(w.stop(stopTag(testNonce))).To(Succeed())
		Expect(w.close()).To(Succeed())
		Eventually(rd.done, 5*time.Second).Should(BeClosed())
		Expect(string(rd.bytes())).To(Equal(stopLine))
	})

	It("pushes whole lines in chunks of at most 256 bytes, 100 ms apart", func() {
		w, rd := consolePipe()
		rd.start()
		lines := append(pushLines(39), "RVM_CRED_"+testNonce+"=end 1")
		began := time.Now()
		Expect(w.push(lines)).To(Succeed())
		Expect(time.Since(began)).To(BeNumerically(">=", 19*consolePace))
		Expect(w.close()).To(Succeed())
		Eventually(rd.done, 5*time.Second).Should(BeClosed())

		reads := rd.got()
		Expect(rd.bytes()).To(Equal(joinLines(lines)))
		// Each chunk is one atomic write, so with the pause between them
		// each read returns one chunk.
		Expect(reads).To(HaveLen(20))
		for i, r := range reads {
			Expect(len(r.data)).To(BeNumerically("<=", consoleChunk), "chunk %d", i)
			Expect(r.data).To(HaveSuffix("\n"), "chunk %d", i)
			if i > 0 {
				Expect(r.at.Sub(reads[i-1].at)).To(BeNumerically(">=", consolePace-20*time.Millisecond), "chunk %d", i)
			}
		}
	})

	It("lets a stop that comes during a 20-chunk push reach the pipe after at most one more chunk", func() {
		w, rd := consolePipe()
		rd.start()
		lines := pushLines(40)
		pushed := make(chan error, 1)
		go func() { pushed <- w.push(lines) }()
		Eventually(func() int { return len(rd.bytes()) }, 5*time.Second, time.Millisecond).Should(BeNumerically(">=", 3*consoleChunk))
		seen := len(rd.bytes())
		began := time.Now()
		Expect(w.stop(stopTag(testNonce))).To(Succeed())
		Expect(time.Since(began)).To(BeNumerically("<", consolePace))
		Eventually(pushed, consolePace).Should(Receive(MatchError(errConsoleStopped)))
		Expect(w.close()).To(Succeed())
		Eventually(rd.done, 5*time.Second).Should(BeClosed())

		got := rd.bytes()
		Expect(got).To(HaveSuffix(stopLine))
		before := got[:len(got)-len(stopLine)]
		// The push wrote only whole chunks, which hold whole lines, so the
		// stop request starts a line of its own.
		Expect(len(before) % consoleChunk).To(BeZero())
		Expect(len(before)).To(BeNumerically("<=", seen+consoleChunk))
		Expect(joinLines(lines)).To(HavePrefix(string(before)))
	})

	It("cuts short a chunk that waits on a full pipe and writes none of it", func() {
		w, rd := consolePipe()
		w.pace = 0
		// The push is far bigger than the pipe, and nothing reads the pipe
		// yet, so the push waits in a write once the pipe is full.
		lines := pushLines(2000)
		pushed := make(chan error, 1)
		go func() { pushed <- w.push(lines) }()
		// The pipe is full once what it holds stops growing.
		held := 0
		Eventually(func() bool {
			was := held
			held = pipeHolds(rd.r)
			return held > 0 && held == was
		}, 5*time.Second, 50*time.Millisecond).Should(BeTrue())
		Consistently(func() int { return pipeHolds(rd.r) }, 200*time.Millisecond, 10*time.Millisecond).Should(Equal(held))
		Expect(pushed).NotTo(Receive())

		stopped := make(chan error, 1)
		go func() { stopped <- w.stop(stopTag(testNonce)) }()
		Eventually(pushed, time.Second).Should(Receive(MatchError(errConsoleStopped)))
		// The stop request waits for room in the pipe, which the reader
		// now makes.
		rd.start()
		Eventually(stopped, time.Second).Should(Receive(BeNil()))
		Expect(w.close()).To(Succeed())
		Eventually(rd.done, 5*time.Second).Should(BeClosed())

		got := rd.bytes()
		Expect(len(got)).To(Equal(held + len(stopLine)))
		Expect(string(got[held:])).To(Equal(stopLine))
		Expect(joinLines(lines)).To(HavePrefix(string(got[:held])))
	})

	It("fails every push at once after a stop, and writes nothing more", func() {
		w, rd := consolePipe()
		rd.start()
		Expect(w.stop(stopTag(testNonce))).To(Succeed())
		began := time.Now()
		Expect(w.push(pushLines(4))).To(MatchError(errConsoleStopped))
		Expect(w.push(pushLines(1))).To(MatchError(errConsoleStopped))
		Expect(time.Since(began)).To(BeNumerically("<", consolePace))
		Expect(w.stop(stopTag(testNonce))).To(MatchError(errConsoleStopped))
		Expect(w.close()).To(Succeed())
		Eventually(rd.done, 5*time.Second).Should(BeClosed())
		Expect(string(rd.bytes())).To(Equal(stopLine))
	})

	It("fails every push and the stop request once it is closed", func() {
		w, _ := consolePipe()
		Expect(w.close()).To(Succeed())
		Expect(w.push(pushLines(1))).To(MatchError(errConsoleStopped))
		Expect(w.stop(stopTag(testNonce))).To(MatchError(errConsoleStopped))
	})

	It("ends a push that pauses between chunks at once when it is closed", func() {
		w, rd := consolePipe()
		rd.start()
		pushed := make(chan error, 1)
		go func() { pushed <- w.push(pushLines(40)) }()
		Eventually(func() int { return len(rd.bytes()) }, 5*time.Second, time.Millisecond).Should(BeNumerically(">=", consoleChunk))
		Expect(w.close()).To(Succeed())
		Eventually(pushed, consolePace/2).Should(Receive(MatchError(errConsoleStopped)))
	})

	It("refuses a line that holds a line break or does not fit a chunk, before it writes anything", func() {
		w, rd := consolePipe()
		rd.start()
		Expect(w.push([]string{"one", "two\nthree"})).To(MatchError("console line 1 holds a line break"))
		Expect(w.push([]string{"one\r"})).To(MatchError("console line 0 holds a line break"))
		Expect(w.push([]string{"one", strings.Repeat("x", consoleChunk)})).To(MatchError("console line 1 is 256 bytes, and a chunk holds at most 256 with the newline"))
		Expect(w.push([]string{strings.Repeat("x", consoleChunk-1)})).To(Succeed())
		Expect(w.push(nil)).To(Succeed())
		Expect(w.close()).To(Succeed())
		Eventually(rd.done, 5*time.Second).Should(BeClosed())
		Expect(string(rd.bytes())).To(Equal(strings.Repeat("x", consoleChunk-1) + "\n"))
	})

	It("reports a write that fails, other than for a stop", func() {
		w, rd := consolePipe()
		Expect(rd.r.Close()).To(Succeed())
		Expect(w.push(pushLines(1))).To(MatchError(ContainSubstring("broken pipe")))
		Expect(w.stop(stopTag(testNonce))).To(MatchError(ContainSubstring("broken pipe")))
	})
})

// ackReport is one acknowledgement that a serial filter reported.
type ackReport struct {
	seq int
	ok  bool
}

// feedCredAck pushes chunks through a serial filter that passes
// acknowledgements to a recorder, finishes it, and returns the filter, its
// output, and the acknowledgements.
func feedCredAck(chunks ...string) (*serialFilter, string, []ackReport) {
	var out bytes.Buffer
	var acks []ackReport
	f := newSerialFilter(&out, testNonce)
	f.onCredAck(testNonce, func(seq int, ok bool) { acks = append(acks, ackReport{seq, ok}) })
	for _, c := range chunks {
		n, err := f.Write([]byte(c))
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(len(c)))
	}
	f.finish()
	return f, out.String(), acks
}

var _ = Describe("identity acknowledgements on the serial console", func() {
	okTag := credOKTag(testNonce)
	badTag := credBadTag(testNonce)
	start := "RVM_START_" + testNonce + "\r\n"
	marker := "RVM_EXIT_" + testNonce + "=0\r\n"

	// console has acknowledgements before the start tag, at the start of a
	// line, after output with no newline yet, and after the exit marker, and
	// malformed ones that are output.
	console := okTag + "1\r\n" +
		start +
		"one\r\n" +
		okTag + "1\r\n" +
		"partial" + badTag + "2\r\n" +
		"rest\r\n" +
		okTag + "\r\n" +
		badTag + "\r\n" +
		okTag + "x\r\n" +
		badTag + "3x\r\n" +
		okTag + "1234567890\r\n" +
		okTag + "\n" +
		badTag + "7\n" +
		okTag + "12\r\n" +
		marker +
		okTag + "13\r\n"
	wantOut := "one\npartialrest\n" + okTag + "\n" + badTag + "\n" + okTag + "x\n" + badTag + "3x\n" + okTag + "1234567890\n" + okTag + "\n"
	wantAcks := []ackReport{{1, true}, {2, false}, {7, false}, {12, true}}

	It("swallows each acknowledgement of the run, reports it, and keeps the output around it", func() {
		f, out, acks := feedCredAck(console)
		Expect(out).To(Equal(wantOut))
		Expect(acks).To(Equal(wantAcks))
		Expect(f.markerFound()).To(BeTrue())
	})

	It("gives the same result however the console is split", func() {
		for i := 0; i <= len(console); i++ {
			_, out, acks := feedCredAck(console[:i], console[i:])
			Expect(out).To(Equal(wantOut), "split at %d", i)
			Expect(acks).To(Equal(wantAcks), "split at %d", i)
		}
		chunks := make([]string, len(console))
		for i := range console {
			chunks[i] = console[i : i+1]
		}
		_, out, acks := feedCredAck(chunks...)
		Expect(out).To(Equal(wantOut))
		Expect(acks).To(Equal(wantAcks))
	})

	It("passes a line that holds only the tag through as output", func() {
		for _, tag := range []string{okTag, badTag} {
			_, out, acks := feedCredAck(start + tag + "\r\n" + "x" + tag + "\r\n" + marker)
			Expect(out).To(Equal(tag + "\nx" + tag + "\n"))
			Expect(acks).To(BeEmpty())
		}
	})

	It("treats an acknowledgement cut off by the end of the console as output", func() {
		for _, tail := range []string{"", "4", "42", "42\r"} {
			_, out, acks := feedCredAck(start + "x" + okTag + tail)
			Expect(out).To(Equal("x"+okTag+tail), "tail %q", tail)
			Expect(acks).To(BeEmpty(), "tail %q", tail)
		}
	})

	It("handles acknowledgements, listen lines, and OOM lines in one write, in any order", func() {
		var out bytes.Buffer
		var acks []ackReport
		var ports []int
		f := newSerialFilter(&out, testNonce)
		f.onListen(testNonce, func(port int, up bool) { ports = append(ports, port) })
		f.onCredAck(testNonce, func(seq int, ok bool) { acks = append(acks, ackReport{seq, ok}) })
		_, _ = f.Write([]byte(start + "a\r\n" + badTag + "4\r\n" + listenTag(testNonce) + "8080:1\r\n" + okTag + "5\r\n" +
			oomTagLine("2") + "\r\n" + "b" + okTag + "6\r\n" + marker))
		f.finish()
		Expect(out.String()).To(Equal("a\nb"))
		Expect(acks).To(Equal([]ackReport{{4, false}, {5, true}, {6, true}}))
		Expect(ports).To(Equal([]int{8080}))
		Expect(f.oomKills).To(Equal(2))
		Expect(f.status).To(Equal(0))
	})

	It("passes acknowledgements through as output when nothing asked for them", func() {
		var out bytes.Buffer
		f := newSerialFilter(&out, testNonce)
		_, _ = io.WriteString(f, start+okTag+"1\r\n"+badTag+"2\r\n"+marker)
		f.finish()
		Expect(out.String()).To(Equal(okTag + "1\n" + badTag + "2\n"))
	})

	It("swallows the guest's word, before the start tag, that it takes no pushes, and sets credOff, only when it reports acknowledgements", func() {
		boot := "boot noise\r\n" + credOffTag(testNonce) + "\r\n"
		var out bytes.Buffer
		f := newSerialFilter(&out, testNonce)
		f.onCredAck(testNonce, func(int, bool) {})
		_, _ = io.WriteString(f, boot)
		Expect(f.credOff).To(BeTrue())
		Expect(string(f.bootLog)).To(Equal("boot noise\r\n"))
		_, _ = io.WriteString(f, start+"a\r\n"+marker)
		f.finish()
		Expect(out.String()).To(Equal("a\n"))

		var plainOut bytes.Buffer
		plain := newSerialFilter(&plainOut, testNonce)
		_, _ = io.WriteString(plain, boot)
		Expect(plain.credOff).To(BeFalse())
		Expect(string(plain.bootLog)).To(Equal(boot))
	})

	It("takes the word only before the start tag, and passes it on as output after it", func() {
		var out bytes.Buffer
		f := newSerialFilter(&out, testNonce)
		f.onCredAck(testNonce, func(int, bool) {})
		_, _ = io.WriteString(f, start+credOffTag(testNonce)+"\r\n"+marker)
		f.finish()
		Expect(f.credOff).To(BeFalse())
		Expect(out.String()).To(Equal(credOffTag(testNonce) + "\n"))
	})
})
