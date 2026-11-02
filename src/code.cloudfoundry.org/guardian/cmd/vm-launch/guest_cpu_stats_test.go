//go:build linux

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("the guest CPU line", func() {
	It("pins the tag and the line that guardian reads", func() {
		Expect(cpuTag(testNonce)).To(Equal("RVM_CPU_0123456789abcdef="))
		Expect(guestCPULine(3, 1)).To(Equal("vm-launch-metrics v1 cpu user=30000000 system=10000000\n"))
		Expect(guestCPULine(0, 0)).To(Equal("vm-launch-metrics v1 cpu user=0 system=0\n"))
	})

	It("converts the largest figure the filter takes without overflowing", func() {
		largest := uint64(1)
		for range maxTickDigits {
			largest *= 10
		}
		largest--

		Expect(guestCPULine(largest, largest)).To(Equal("vm-launch-metrics v1 cpu user=999999999990000000 system=999999999990000000\n"))
	})
})

var _ = Describe("parsing a guest CPU line", func() {
	DescribeTable("reads the figures after the tag",
		func(input string, user, system uint64, n int) {
			gotUser, gotSystem, gotN, ok, needMore := parseCPU([]byte(input))
			Expect(ok).To(BeTrue())
			Expect(needMore).To(BeFalse())
			Expect(gotUser).To(Equal(user))
			Expect(gotSystem).To(Equal(system))
			Expect(gotN).To(Equal(n))
		},
		Entry("with an LF", "123:45\nrest", uint64(123), uint64(45), 7),
		Entry("with a CRLF", "123:45\r\nrest", uint64(123), uint64(45), 8),
		Entry("with zeros", "0:0\n", uint64(0), uint64(0), 4),
		Entry("with the most digits", "99999999999:99999999999\n", uint64(99999999999), uint64(99999999999), 24),
	)

	DescribeTable("asks for more when the line may still complete",
		func(input string) {
			_, _, _, ok, needMore := parseCPU([]byte(input))
			Expect(ok).To(BeFalse())
			Expect(needMore).To(BeTrue())
		},
		Entry("nothing yet", ""),
		Entry("digits only", "123"),
		Entry("the colon", "123:"),
		Entry("part of the second figure", "123:4"),
		Entry("a CR", "123:45\r"),
	)

	DescribeTable("refuses what cannot be a CPU line",
		func(input string) {
			_, _, _, ok, needMore := parseCPU([]byte(input))
			Expect(ok).To(BeFalse())
			Expect(needMore).To(BeFalse())
		},
		Entry("no first figure", ":1\n"),
		Entry("no second figure", "1:\n"),
		Entry("no colon", "1 2\n"),
		Entry("a sign", "+1:2\n"),
		Entry("a letter", "1:2x\n"),
		Entry("a CR without an LF", "1:2\rx"),
		Entry("a first figure of 12 digits", "123456789012:1\n"),
		Entry("a second figure of 12 digits", "1:123456789012\n"),
		Entry("a third figure", "1:2:3\n"),
	)
})

var _ = Describe("the serial filter with CPU lines", func() {
	const (
		start  = "RVM_START_" + testNonce + "\r\n"
		marker = "RVM_EXIT_" + testNonce + "=0\r\n"
	)

	type reading struct{ user, system uint64 }

	feed := func(chunks ...string) (string, []reading, *serialFilter) {
		var out bytes.Buffer
		var got []reading
		f := newSerialFilter(&out, testNonce)
		f.onCPU(func(user, system uint64) { got = append(got, reading{user, system}) })
		for _, c := range chunks {
			_, _ = f.Write([]byte(c))
		}
		f.finish()
		return out.String(), got, f
	}

	line := cpuTag(testNonce) + "700:300\r\n"

	It("swallows a CPU line while the command runs and passes its figures on", func() {
		out, got, f := feed(start, "a\r\n", line, "b\r\n", marker)

		Expect(out).To(Equal("a\nb\n"))
		Expect(got).To(Equal([]reading{{700, 300}}))
		Expect(f.status).To(Equal(0))
	})

	It("takes the line split at every offset", func() {
		stream := start + "a\r\n" + line + "b\r\n" + marker
		for cut := 0; cut <= len(stream); cut++ {
			out, got, f := feed(stream[:cut], stream[cut:])

			Expect(out).To(Equal("a\nb\n"), "cut at %d", cut)
			Expect(got).To(Equal([]reading{{700, 300}}), "cut at %d", cut)
			Expect(f.markerFound()).To(BeTrue(), "cut at %d", cut)
		}
	})

	It("takes the line one byte at a time", func() {
		stream := start + "a\r\n" + line + "b\r\n" + marker
		chunks := make([]string, len(stream))
		for i := range stream {
			chunks[i] = stream[i : i+1]
		}

		out, got, _ := feed(chunks...)

		Expect(out).To(Equal("a\nb\n"))
		Expect(got).To(Equal([]reading{{700, 300}}))
	})

	It("keeps the output around a line that follows output with no newline", func() {
		out, got, _ := feed(start, "partial", line, "rest\r\n", marker)

		Expect(out).To(Equal("partialrest\n"))
		Expect(got).To(Equal([]reading{{700, 300}}))
	})

	It("takes every line in order", func() {
		_, got, _ := feed(start, cpuTag(testNonce)+"1:1\r\n", cpuTag(testNonce)+"2:1\r\n", cpuTag(testNonce)+"3:2\r\n", marker)

		Expect(got).To(Equal([]reading{{1, 1}, {2, 1}, {3, 2}}))
	})

	It("passes a malformed line on as output and reports nothing", func() {
		bad := cpuTag(testNonce) + "7x:3\r\n"

		out, got, _ := feed(start, bad, marker)

		Expect(out).To(Equal(bad[:len(bad)-2] + "\n"))
		Expect(got).To(BeEmpty())
	})

	It("takes no CPU line before the start tag or after the exit marker", func() {
		out, got, _ := feed(line, start, "a\r\n", marker, line)

		Expect(out).To(Equal("a\n"))
		Expect(got).To(BeEmpty())
	})

	It("swallows the line when the filter has no CPU callback", func() {
		var out bytes.Buffer
		f := newSerialFilter(&out, testNonce)
		for _, c := range []string{start, "a\r\n", line, "b\r\n", marker} {
			_, _ = f.Write([]byte(c))
		}
		f.finish()

		Expect(out.String()).To(Equal("a\nb\n"))
	})

	It("takes a CPU line next to a listen line and an OOM line", func() {
		var out bytes.Buffer
		var got []reading
		var ups []bool
		f := newSerialFilter(&out, testNonce)
		f.onCPU(func(user, system uint64) { got = append(got, reading{user, system}) })
		f.onListen(testNonce, func(port int, up bool) { ups = append(ups, up) })
		for _, c := range []string{start, line, listenTag(testNonce) + "8080:1\r\n", oomTagLine("2") + "\r\n", line, marker} {
			_, _ = f.Write([]byte(c))
		}
		f.finish()

		Expect(out.String()).To(BeEmpty())
		Expect(got).To(Equal([]reading{{700, 300}, {700, 300}}))
		Expect(ups).To(Equal([]bool{true}))
		Expect(f.oomKills).To(Equal(2))
	})
})

var _ = Describe("the guest CPU watcher", func() {
	It("starts after the start tag and stops before the report of the status", func() {
		for _, volume := range []bool{false, true} {
			script := initScript(testNonce, volume)
			watch, stop := guestCPUWatch(testNonce), guestCPUStop

			Expect(strings.Count(script, watch)).To(Equal(1), "volume=%v", volume)
			Expect(strings.Count(script, stop)).To(Equal(1), "volume=%v", volume)
			Expect(strings.Index(script, watch)).To(BeNumerically(">", strings.Index(script, "echo RVM_START_")), "volume=%v", volume)
			Expect(strings.Index(script, stop)).To(BeNumerically(">", strings.Index(script, guestRunStatus)), "volume=%v", volume)
			Expect(strings.Index(script, stop)).To(BeNumerically("<", strings.Index(script, "echo RVM_EXIT_")), "volume=%v", volume)
		}
	})

	It("runs in a stack guest with a run section too", func() {
		script := stage2Script(testNonce, false, true, "", "echo section\n")

		Expect(script).To(ContainSubstring(guestCPUWatch(testNonce)))
		Expect(script).To(ContainSubstring(guestCPUStop))
	})

	// watchWith runs the watcher in shell against a /proc/stat that holds
	// stat, with its loop cut to one round, and returns what it wrote on the
	// console.
	watchWith := func(shell guestShell, stat, tick string) string {
		dir := GinkgoT().TempDir()
		proc := filepath.Join(dir, "stat")
		Expect(os.WriteFile(proc, []byte(stat), 0o644)).To(Succeed())
		con := filepath.Join(dir, "console")
		watch := guestCPUWatch(testNonce)
		Expect(strings.Count(watch, "/proc/stat")).To(Equal(1))
		Expect(strings.Count(watch, ">/dev/console")).To(Equal(1))
		Expect(strings.Count(watch, "\t\trvm_cpupause\n")).To(Equal(1))
		watch = strings.Replace(watch, "/proc/stat", proc, 1)
		watch = strings.Replace(watch, ">/dev/console", ">"+con, 1)
		watch = strings.ReplaceAll(watch, guestCPUTick, tick)
		watch = strings.Replace(watch, "\t\trvm_cpupause\n", "\t\texit 0\n", 1)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var errOut bytes.Buffer
		cmd := exec.CommandContext(ctx, shell.argv[0], append(shell.argv[1:], "-c", watch+"wait \"$rvm_cpuwatch\"\n")...)
		cmd.Stderr = &errOut
		Expect(cmd.Run()).To(Succeed(), errOut.String())
		Expect(errOut.String()).To(BeEmpty())

		raw, err := os.ReadFile(con)
		if os.IsNotExist(err) {
			return ""
		}
		Expect(err).NotTo(HaveOccurred())
		return string(raw)
	}

	DescribeTable("writes user and system ticks from the total line of /proc/stat",
		func(shellOf func() guestShell, stat, want string) {
			Expect(watchWith(shellOf(), stat, filepath.Join(GinkgoT().TempDir(), "tick"))).To(Equal(want))
		},
		shellEntries("two vCPUs", "cpu  1000 20 300 99000 50 6 4 7 0 0\ncpu0 500 10 150 49500 25 3 2 3 0 0\ncpu1 500 10 150 49500 25 3 2 3 0 0\nintr 1\n", cpuTag(testNonce)+"1020:310\n"),
		shellEntries("an idle guest", "cpu  0 0 0 5000 0 0 0 0 0 0\n", cpuTag(testNonce)+"0:0\n"),
		shellEntries("a line with the older, shorter set of columns", "cpu  10 0 5 100 0 0 0\n", cpuTag(testNonce)+"10:5\n"),
		shellEntries("a line that stops before the interrupt columns", "cpu  10 0 5\n", cpuTag(testNonce)+"10:5\n"),
	)

	It("reports in a guest where the FIFO cannot be made, waiting with sleep", func() {
		stat := "cpu  10 0 5 100 0 0 0\n"
		missing := filepath.Join(GinkgoT().TempDir(), "no", "such", "dir", "tick")
		for _, shell := range []guestShell{hostShell(), guestBusyboxShell()} {
			watch := guestCPUWatch(testNonce)
			Expect(watch).To(ContainSubstring("rvm_cpupause() { sleep 5; }"))
			Expect(watchWith(shell, stat, missing)).To(Equal(cpuTag(testNonce) + "10:5\n"))
		}
	})

	It("runs no process between its lines", func() {
		watch := guestCPUWatch(testNonce)
		loop := watch[strings.Index(watch, "while :;"):]
		Expect(loop).NotTo(ContainSubstring("sleep"))
		Expect(loop).To(ContainSubstring("rvm_cpupause"))
	})

	DescribeTable("writes nothing when /proc/stat does not hold numbers",
		func(shellOf func() guestShell, stat string) {
			Expect(watchWith(shellOf(), stat, filepath.Join(GinkgoT().TempDir(), "tick"))).To(BeEmpty())
		},
		shellEntries("a figure that is not a number", "cpu  10 0 x 100 0 0 0\n"),
		shellEntries("a negative figure", "cpu  -10 0 5 100 0 0 0\n"),
		shellEntries("an empty file", ""),
	)

	DescribeTable("is ended by the stop",
		func(shellOf func() guestShell) {
			shell := shellOf()
			dir := GinkgoT().TempDir()
			proc := filepath.Join(dir, "stat")
			Expect(os.WriteFile(proc, []byte("cpu  1 0 1 1 0 0 0\n"), 0o644)).To(Succeed())
			watch := strings.Replace(guestCPUWatch(testNonce), "/proc/stat", proc, 1)
			watch = strings.Replace(watch, ">/dev/console", ">"+filepath.Join(dir, "console"), 1)
			watch = strings.ReplaceAll(watch, guestCPUTick, filepath.Join(dir, "tick"))

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, shell.argv[0], append(shell.argv[1:], "-c", watch+guestCPUStop+"echo stopped\n")...)
			out, err := cmd.Output()

			Expect(ctx.Err()).NotTo(HaveOccurred(), "the stop did not end the watcher")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(out)).To(Equal("stopped\n"))
		},
		Entry("in /bin/sh", hostShell),
		Entry("in the guest's busybox sh", guestBusyboxShell),
	)
})

// gateWriter blocks every Write until release is closed, and keeps what it
// was given.
type gateWriter struct {
	release chan struct{}
	mu      sync.Mutex
	got     []string
}

func (g *gateWriter) Write(p []byte) (int, error) {
	<-g.release
	g.mu.Lock()
	defer g.mu.Unlock()
	g.got = append(g.got, string(p))

	return len(p), nil
}

func (g *gateWriter) lines() []string {
	g.mu.Lock()
	defer g.mu.Unlock()

	return append([]string(nil), g.got...)
}

var _ io.Writer = (*gateWriter)(nil)

var _ = Describe("the CPU reporter", func() {
	It("writes the line", func() {
		gate := &gateWriter{release: make(chan struct{})}
		close(gate.release)
		r := newCPUReporter(gate)
		defer r.close()

		r.report(7, 3)

		Eventually(gate.lines).Should(Equal([]string{guestCPULine(7, 3)}))
	})

	It("does not block the caller while the writer is blocked, and delivers the newest figures afterwards", func() {
		gate := &gateWriter{release: make(chan struct{})}
		r := newCPUReporter(gate)
		defer r.close()

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			for i := uint64(1); i <= 1000; i++ {
				r.report(i, i)
			}
		}()
		Eventually(done, 5*time.Second).Should(BeClosed())

		close(gate.release)

		Eventually(func() string {
			lines := gate.lines()
			if len(lines) == 0 {
				return ""
			}

			return lines[len(lines)-1]
		}).Should(Equal(guestCPULine(1000, 1000)))
		Expect(len(gate.lines())).To(BeNumerically("<=", 3))
	})

	It("keeps the console copy moving when the hypervisor's console runs through a filter that has a blocked CPU callback", func() {
		gate := &gateWriter{release: make(chan struct{})}
		defer close(gate.release)
		r := newCPUReporter(gate)
		defer r.close()

		var out bytes.Buffer
		f := newSerialFilter(&out, testNonce)
		f.onCPU(r.report)
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			_, _ = f.Write([]byte("RVM_START_" + testNonce + "\r\n"))
			for i := 0; i < 50; i++ {
				_, _ = f.Write([]byte(cpuTag(testNonce) + "1:1\r\nhello\r\n"))
			}
			f.finish()
		}()

		Eventually(done, 5*time.Second).Should(BeClosed())
		Expect(strings.Count(out.String(), "hello")).To(Equal(50))
	})
})
