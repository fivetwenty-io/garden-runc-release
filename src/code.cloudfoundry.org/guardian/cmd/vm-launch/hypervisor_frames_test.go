//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// frame is one log frame as the guest's framers write it on the console.
func frame(index int, stream byte, payload string) string {
	return fmt.Sprintf("%s%d%c %s\r\n", logTag(testNonce), index, stream, payload)
}

// firstLine is the guest's first-exit line.
func firstLine(index, status int) string {
	return fmt.Sprintf("%s%d %d\r\n", firstTag(testNonce), index, status)
}

// logLine is one line that the filter passed to its logs callback.
type logLine struct {
	index  int
	stream byte
	line   string
}

// frameRecorder records what the filter passes to its callbacks, from
// whichever goroutine calls them.
type frameRecorder struct {
	mu     sync.Mutex
	lines  []logLine
	firsts [][2]int
	// events holds both kinds in the order they came.
	events []string
}

func (r *frameRecorder) logs(index int, stream byte, line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, logLine{index, stream, line})
	r.events = append(r.events, fmt.Sprintf("%d%c %s", index, stream, line))
}

func (r *frameRecorder) first(index, status int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.firsts = append(r.firsts, [2]int{index, status})
	r.events = append(r.events, fmt.Sprintf("first %d %d", index, status))
}

func (r *frameRecorder) got() ([]logLine, [][2]int, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]logLine(nil), r.lines...), append([][2]int(nil), r.firsts...), append([]string(nil), r.events...)
}

// framesFed is what feedFrames saw come out of the filter.
type framesFed struct {
	f      *serialFilter
	out    string
	errOut string
	lines  []logLine
	firsts [][2]int
	events []string
}

// feedFrames pushes chunks through a serial filter that splits frames into
// its own stdout and stderr and a recorder's callbacks, and finishes it.
func feedFrames(chunks ...string) framesFed {
	var out, errOut bytes.Buffer
	var rec frameRecorder
	f := newSerialFilter(&out, testNonce)
	f.onFrames(testNonce, &errOut, rec.logs, rec.first)
	for _, c := range chunks {
		n, err := f.Write([]byte(c))
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(len(c)))
	}
	f.finish()
	lines, firsts, events := rec.got()
	return framesFed{f: f, out: out.String(), errOut: errOut.String(), lines: lines, firsts: firsts, events: events}
}

var _ = Describe("serialFilter with log frames", func() {
	start := "RVM_START_" + testNonce + "\r\n"
	marker := func(rc int) string { return fmt.Sprintf("RVM_EXIT_%s=%d\r\n", testNonce, rc) }

	stream := start +
		"unframed before\r\n" +
		frame(0, 'o', "app out") +
		frame(1, 'O', "side ") +
		frame(0, 'e', "app err") +
		frame(2, 'e', "other err") +
		frame(1, 'O', "out in ") +
		frame(0, 'E', "app ") +
		frame(1, 'o', "pieces") +
		frame(0, 'e', "err joined") +
		"unframed after\r\n" +
		frame(1, 'e', "side "+exitTag(testNonce)+"3") +
		firstLine(1, 3) +
		marker(3) +
		frame(1, 'o', "after the marker")
	wantOut := "unframed before\napp out\nunframed after\n"
	wantErr := "app err\napp err joined\n"
	wantLines := []logLine{
		{2, 'e', "other err"},
		{1, 'o', "side out in pieces"},
		{1, 'e', "side " + exitTag(testNonce) + "3"},
	}

	check := func(got framesFed, why string) {
		Expect(got.out).To(Equal(wantOut), why)
		Expect(got.errOut).To(Equal(wantErr), why)
		Expect(got.lines).To(Equal(wantLines), why)
		Expect(got.firsts).To(Equal([][2]int{{1, 3}}), why)
		Expect(got.f.markerFound()).To(BeTrue(), why)
		Expect(got.f.status).To(Equal(3), why)
	}

	It("routes the app's streams to out and errOut, joins pieces, and passes the sidecars' lines and the first exit to the callbacks", func() {
		check(feedFrames(stream), "whole")
	})

	It("gives the same result for every two-way split of the stream", func() {
		for i := 0; i <= len(stream); i++ {
			check(feedFrames(stream[:i], stream[i:]), fmt.Sprintf("split at %d", i))
		}
	})

	It("gives the same result when fed one byte at a time", func() {
		chunks := make([]string, len(stream))
		for i := range stream {
			chunks[i] = stream[i : i+1]
		}
		check(feedFrames(chunks...), "byte by byte")
	})

	It("never takes an exit tag inside a frame's payload for the marker", func() {
		got := feedFrames(start, frame(1, 'o', marker(9)[:len(marker(9))-2]), frame(0, 'o', "RVM_EXIT_"+testNonce+"=8"), marker(0))
		Expect(got.f.status).To(Equal(0))
		Expect(got.lines).To(Equal([]logLine{{1, 'o', "RVM_EXIT_" + testNonce + "=9"}}))
		Expect(got.out).To(Equal("RVM_EXIT_" + testNonce + "=8\n"))
	})

	It("never takes a first-exit tag inside a frame's payload for the line", func() {
		got := feedFrames(start, frame(1, 'o', strings.TrimSuffix(firstLine(2, 7), "\r\n")))
		Expect(got.firsts).To(BeEmpty())
		Expect(got.lines).To(Equal([]logLine{{1, 'o', strings.TrimSuffix(firstLine(2, 7), "\r\n")}}))
	})

	It("passes the first exit on after the process's last frames and sends its unfinished pieces first", func() {
		got := feedFrames(start, frame(1, 'o', "last"), frame(1, 'E', "cut "), frame(1, 'E', "off"), frame(2, 'O', "kept"), firstLine(1, 0), frame(2, 'o', " whole"))
		Expect(got.events).To(Equal([]string{"1o last", "1e cut off", "first 1 0", "2o kept whole"}))
	})

	It("finds a first-exit line after output that has no newline yet", func() {
		got := feedFrames(start, "partial"+firstLine(4, 255), "rest\r\n")
		Expect(got.firsts).To(Equal([][2]int{{4, 255}}))
		Expect(got.out).To(Equal("partialrest\n"))
	})

	It("keeps empty lines and the CRs that a line carried itself", func() {
		got := feedFrames(start, frame(0, 'o', ""), frame(0, 'o', "dos\r"), frame(1, 'e', ""), logTag(testNonce)+"0o lf only\n")
		Expect(got.out).To(Equal("\ndos\r\nlf only\n"))
		Expect(got.lines).To(Equal([]logLine{{1, 'e', ""}}))
	})

	It("sends a line's unfinished pieces on at the end of the stream", func() {
		got := feedFrames(start, frame(0, 'O', "app half"), frame(3, 'E', "side half"))
		Expect(got.out).To(Equal("app half\n"))
		Expect(got.lines).To(Equal([]logLine{{3, 'e', "side half"}}))
		Expect(got.f.markerFound()).To(BeFalse())
	})

	It("passes a join past maxLogLine on as more than one line", func() {
		piece := strings.Repeat("x", 960)
		var chunks []string
		chunks = append(chunks, start)
		pieces := maxLogLine/len(piece) + 2
		for i := 0; i < pieces-1; i++ {
			chunks = append(chunks, frame(1, 'O', piece))
		}
		chunks = append(chunks, frame(1, 'o', piece))
		got := feedFrames(chunks...)
		Expect(got.lines).To(HaveLen(2))
		Expect(len(got.lines[0].line)).To(BeNumerically("<=", maxLogLine))
		Expect(len(got.lines[0].line) + len(got.lines[1].line)).To(Equal(pieces * len(piece)))
	})

	It("takes a frame only at the start of a console line", func() {
		got := feedFrames(start, "prefix "+frame(1, 'o', "not a frame"), "no newline yet", frame(1, 'o', "mid-line either"))
		Expect(got.lines).To(BeEmpty())
		Expect(got.out).To(Equal("prefix " + logTag(testNonce) + "1o not a frame\nno newline yet" + logTag(testNonce) + "1o mid-line either\n"))
	})

	It("takes a frame right after a swallowed control line that followed unfinished output", func() {
		got := feedFrames(start, "partial"+oomTag(testNonce)+"2\r\n"+frame(1, 'o', "framed"))
		Expect(got.f.oomKills).To(Equal(2))
		Expect(got.out).To(Equal("partial"))
		Expect(got.lines).To(Equal([]logLine{{1, 'o', "framed"}}))
	})

	It("ignores frames with another nonce", func() {
		other := "RVM_LOG_aaaaaaaaaaaaaaaa=1o hidden\r\n"
		got := feedFrames(start, other)
		Expect(got.out).To(Equal("RVM_LOG_aaaaaaaaaaaaaaaa=1o hidden\n"))
		Expect(got.lines).To(BeEmpty())
	})

	DescribeTable("passes malformed frames through as output",
		func(rest string) {
			got := feedFrames(start, logTag(testNonce)+rest)
			Expect(got.out).To(Equal(logTag(testNonce) + strings.ReplaceAll(rest, "\r\n", "\n")))
			Expect(got.errOut).To(BeEmpty())
			Expect(got.lines).To(BeEmpty())
		},
		Entry("an index past maxSidecars", "9o x\r\n"),
		Entry("three index digits", "100o x\r\n"),
		Entry("no index", "o x\r\n"),
		Entry("an unknown stream letter", "1x x\r\n"),
		Entry("no space after the stream", "1ox\r\n"),
		Entry("nothing after the stream", "1o\r\n"),
		Entry("no newline at the end of the stream", "1o x"),
		Entry("no newline within maxFrameBytes", "1o "+strings.Repeat("y", maxFrameBytes)+"\r\n"),
	)

	It("finds a real frame after a malformed one", func() {
		got := feedFrames(start, logTag(testNonce)+"1x\r\n"+frame(1, 'o', "real"))
		Expect(got.out).To(Equal(logTag(testNonce) + "1x\n"))
		Expect(got.lines).To(Equal([]logLine{{1, 'o', "real"}}))
	})

	It("takes a frame whose newline comes just inside maxFrameBytes", func() {
		payload := strings.Repeat("y", maxFrameBytes-len(logTag(testNonce))-len("1o \r\n"))
		got := feedFrames(start, frame(1, 'o', payload))
		Expect(got.lines).To(Equal([]logLine{{1, 'o', payload}}))
		Expect(got.out).To(BeEmpty())
	})

	DescribeTable("passes malformed first-exit lines through as output",
		func(rest string) {
			got := feedFrames(start, firstTag(testNonce)+rest)
			Expect(got.out).To(Equal(firstTag(testNonce) + strings.ReplaceAll(rest, "\r\n", "\n")))
			Expect(got.firsts).To(BeEmpty())
		},
		Entry("a status above 255", "1 256\r\n"),
		Entry("four status digits", "1 0003\r\n"),
		Entry("an index past maxSidecars", "9 1\r\n"),
		Entry("no space", "1x1\r\n"),
		Entry("no status", "1 \r\n"),
		Entry("letters", "1 2a\r\n"),
		Entry("no newline at the end of the stream", "1 2"),
	)

	It("keeps the boot log free of frame handling before the start tag", func() {
		got := feedFrames(frame(1, 'o', "early"), start, frame(1, 'o', "late"))
		Expect(string(got.f.bootLog)).To(BeEmpty())
		Expect(got.lines).To(Equal([]logLine{{1, 'o', "late"}}))
	})

	It("keeps the listen and acknowledgement lines working beside frames", func() {
		var out, errOut bytes.Buffer
		var rec frameRecorder
		var listens []listenReport
		var acks []ackReport
		f := newSerialFilter(&out, testNonce)
		f.onListen(testNonce, func(port int, up bool) { listens = append(listens, listenReport{port, up}) })
		f.onCredAck(testNonce, func(seq int, ok bool) { acks = append(acks, ackReport{seq, ok}) })
		f.onFrames(testNonce, &errOut, rec.logs, rec.first)
		_, _ = f.Write([]byte(start + frame(1, 'o', "a") + listenTag(testNonce) + "8080:1\r\n" + frame(0, 'e', "b") +
			credOKTag(testNonce) + "7\r\n" + frame(1, 'O', "c") + credBadTag(testNonce) + "8\r\n" + frame(1, 'o', "d") + marker(0)))
		f.finish()
		lines, _, _ := rec.got()
		Expect(lines).To(Equal([]logLine{{1, 'o', "a"}, {1, 'o', "cd"}}))
		Expect(errOut.String()).To(Equal("b\n"))
		Expect(out.String()).To(BeEmpty())
		Expect(listens).To(Equal([]listenReport{{8080, true}}))
		Expect(acks).To(Equal([]ackReport{{7, true}, {8, false}}))
		Expect(f.status).To(Equal(0))
	})

	Context("without callbacks", func() {
		It("writes every process's lines to out and errOut by stream and swallows the first exit", func() {
			var out, errOut bytes.Buffer
			f := newSerialFilter(&out, testNonce)
			f.onFrames(testNonce, &errOut, nil, nil)
			_, _ = f.Write([]byte(start + frame(0, 'o', "app") + frame(1, 'O', "side ") + frame(1, 'o', "out") + frame(2, 'e', "side err") + firstLine(2, 4) + marker(4)))
			f.finish()
			Expect(out.String()).To(Equal("app\nside out\n"))
			Expect(errOut.String()).To(Equal("side err\n"))
			Expect(f.status).To(Equal(4))
		})

		It("writes stderr lines to out when there is no errOut", func() {
			var out bytes.Buffer
			f := newSerialFilter(&out, testNonce)
			f.onFrames(testNonce, nil, nil, nil)
			_, _ = f.Write([]byte(start + frame(0, 'o', "one") + frame(0, 'e', "two") + frame(1, 'e', "three") + marker(0)))
			f.finish()
			Expect(out.String()).To(Equal("one\ntwo\nthree\n"))
		})
	})

	It("leaves frames alone without onFrames", func() {
		f, out := feed(start, frame(1, 'o', "raw"), firstLine(1, 2))
		Expect(out).To(Equal(logTag(testNonce) + "1o raw\n" + firstTag(testNonce) + "1 2\n"))
		Expect(f.markerFound()).To(BeFalse())
	})

	It("keeps draining when errOut fails", func() {
		var rec frameRecorder
		f := newSerialFilter(failingWriter{errors.New("broken pipe")}, testNonce)
		f.onFrames(testNonce, failingWriter{errors.New("broken stderr")}, rec.logs, rec.first)
		n, err := f.Write([]byte(start + frame(0, 'e', "lost") + frame(1, 'o', "kept") + firstLine(1, 6) + marker(6)))
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(BeNumerically(">", 0))
		Expect(f.writeErr).To(MatchError("broken stderr"))
		lines, firsts, _ := rec.got()
		Expect(lines).To(Equal([]logLine{{1, 'o', "kept"}}))
		Expect(firsts).To(Equal([][2]int{{1, 6}}))
		Expect(f.status).To(Equal(6))
	})
})

var _ = Describe("the supervisor with log frames", func() {
	var (
		out, errOut *safeBuffer
		logBuf      *safeBuffer
		rec         *frameRecorder
		sup         supervisor
	)

	BeforeEach(func() {
		out, errOut, logBuf = &safeBuffer{}, &safeBuffer{}, &safeBuffer{}
		rec = &frameRecorder{}
		sup = supervisor{stdout: out, logger: log.New(logBuf, "", 0), signals: make(chan os.Signal, 1), grace: 200 * time.Millisecond, deadline: 200 * time.Millisecond}
	})

	fakeHypervisor := func(script string) *exec.Cmd {
		return exec.Command("/bin/sh", "-c", script)
	}
	startLine := `printf 'boot noise\r\nRVM_START_` + testNonce + `\r\n'; `
	printFrames := func(frames ...string) string {
		return `printf '%s' '` + strings.Join(frames, "") + `'; `
	}

	It("writes the app's stderr lines to stderr and passes the sidecars' lines and the first exit on", func(ctx SpecContext) {
		sup.stderr, sup.logs, sup.firstExit = errOut, rec.logs, rec.first
		res, err := sup.run(fakeHypervisor(startLine+printFrames(frame(0, 'o', "app out"), frame(0, 'e', "app err"), frame(1, 'O', "side "), frame(1, 'o', "out"), frame(1, 'e', "side err"), firstLine(1, 3), "RVM_EXIT_"+testNonce+"=3\r\n")), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(3))
		Expect(out.String()).To(Equal("app out\n"))
		Expect(errOut.String()).To(Equal("app err\n"))
		_, _, events := rec.got()
		Expect(events).To(Equal([]string{"1o side out", "1e side err", "first 1 3"}))
		Expect(logBuf.String()).To(BeEmpty())
	}, SpecTimeout(time.Minute))

	It("writes every line to stdout as before without stderr or callbacks", func(ctx SpecContext) {
		res, err := sup.run(fakeHypervisor(startLine+printFrames(frame(0, 'o', "app out"), frame(0, 'e', "app err"), frame(1, 'e', "side err"), firstLine(1, 3), "RVM_EXIT_"+testNonce+"=3\r\n")), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(3))
		Expect(out.String()).To(Equal("app out\napp err\nside err\n"))
		Expect(logBuf.String()).To(BeEmpty())
	}, SpecTimeout(time.Minute))

	It("drains a flood of frames while stdout and stderr take nothing, so the console never blocks", func(ctx SpecContext) {
		const frames = 60000
		release := make(chan struct{})
		stuck := writerFunc(func(p []byte) (int, error) {
			<-release
			return len(p), nil
		})
		defer close(release)
		sup.stdout, sup.stderr, sup.logs, sup.firstExit = stuck, stuck, rec.logs, rec.first
		// Each frame is about 40 bytes, so the flood is more than twice the
		// serial pipe, which the guest could not get through if the filter
		// blocked.
		script := startLine + `awk 'BEGIN { for (i = 0; i < ` + fmt.Sprint(frames) + `; i++) {
			printf "` + logTag(testNonce) + `%d%s line %d\r\n", i % 3, (i % 2 ? "e" : "o"), i
		}
		printf "` + firstTag(testNonce) + `2 9\r\nRVM_EXIT_` + testNonce + `=9\r\n" }'`
		began := time.Now()
		res, err := sup.run(fakeHypervisor(script), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(9))
		// Both queues give up on their writers side by side.
		Expect(time.Since(began)).To(BeNumerically("<", 10*time.Second))
		lines, firsts, _ := rec.got()
		Expect(lines).To(HaveLen(2 * frames / 3))
		Expect(firsts).To(Equal([][2]int{{2, 9}}))
		Expect(logBuf.String()).To(ContainSubstring("dropped"))
	}, SpecTimeout(time.Minute))
})
