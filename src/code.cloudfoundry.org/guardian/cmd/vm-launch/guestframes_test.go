//go:build linux

package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// frameEvent is one call of the serial filter's logs or firstExit callback.
type frameEvent struct {
	index  int
	stream byte
	line   string
	first  bool
	status int
}

// splitSection passes out, the console output of a run section, through a
// serial filter that splits frames, as vm-launch reads the console, after a
// start tag and before an exit marker. It returns what the filter wrote to
// its output and to its stderr, and the calls of its callbacks in order.
func splitSection(out string) (stdout, stderr string, events []frameEvent) {
	var o, e bytes.Buffer
	f := newSerialFilter(&o, testNonce)
	f.onFrames(testNonce, &e,
		func(index int, stream byte, line string) {
			events = append(events, frameEvent{index: index, stream: stream, line: line})
		},
		func(index, status int) {
			events = append(events, frameEvent{index: index, first: true, status: status})
		})
	_, err := f.Write([]byte("boot\n" + startTag(testNonce) + "\n" + out + exitTag(testNonce) + "0\n"))
	Expect(err).NotTo(HaveOccurred())
	f.finish()
	Expect(f.markerFound()).To(BeTrue(), out)
	return o.String(), e.String(), events
}

// streamLines returns the lines of events that process index wrote to
// stream.
func streamLines(events []frameEvent, index int, stream byte) []string {
	lines := []string{}
	for _, ev := range events {
		if !ev.first && ev.index == index && ev.stream == stream {
			lines = append(lines, ev.line)
		}
	}
	return lines
}

// fdScript has the process write, to fds in its directory, a line for each
// of its open file descriptors with the number and what it names. The
// listing comes from the shell's own pid, and the file appears whole.
const fdScript = `rvm_l=; for f in /proc/$$/fd/*; do rvm_l="$rvm_l${f##*/} $(/bin/readlink "$f")
"; done; printf '%s' "$rvm_l" >fds.tmp && mv fds.tmp fds; `

// parseFds parses the file that fdScript writes into a map from each
// descriptor's number to what it names.
func parseFds(text string) map[string]string {
	fds := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		fd, target, ok := strings.Cut(line, " ")
		Expect(ok).To(BeTrue(), text)
		fds[fd] = target
	}
	return fds
}

// startFramer runs rvm_frame for process 1's stdout with the busybox of
// sectionBusybox, under a UTF-8 locale, and returns the pipe to its
// standard input and its output so far.
func startFramer(nonce string) (io.WriteCloser, *safeBuffer, *exec.Cmd) {
	bb := sectionBusybox()
	script := strings.ReplaceAll(guestFrameFunc(nonce), "/bin/busybox ", bb+" ") + "rvm_frame 1 o\n"
	cmd := exec.Command(bb, "sh", "-c", script)
	cmd.Env = append(os.Environ(), "LANG=C.UTF-8", "LC_ALL=C.UTF-8")
	in, err := cmd.StdinPipe()
	Expect(err).NotTo(HaveOccurred())
	out := &safeBuffer{}
	cmd.Stdout = out
	cmd.Stderr = GinkgoWriter
	Expect(cmd.Start()).To(Succeed())
	DeferCleanup(func() {
		_ = in.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return in, out, cmd
}

// framerPid returns the pid of the framer's shell for process 1 under
// nonce, which it finds by the tag in its environment.
func framerPid(nonce string) string {
	want := "RVM_TAG=" + logTag(nonce) + "1"
	var pid string
	Eventually(func() string {
		environs, _ := filepath.Glob("/proc/[0-9]*/environ")
		for _, environ := range environs {
			raw, err := os.ReadFile(environ)
			if err == nil && slices.Contains(strings.Split(string(raw), "\x00"), want) {
				pid = filepath.Base(filepath.Dir(environ))
			}
		}
		return pid
	}, 10*time.Second, 10*time.Millisecond).ShouldNot(BeEmpty())
	return pid
}

// peakKiB returns the most resident memory that process pid has used, in
// KiB.
func peakKiB(pid string) int {
	status, err := os.ReadFile(filepath.Join("/proc", pid, "status"))
	Expect(err).NotTo(HaveOccurred())
	for _, line := range strings.Split(string(status), "\n") {
		if rest, ok := strings.CutPrefix(line, "VmHWM:"); ok {
			kib, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(rest), " kB"))
			Expect(err).NotTo(HaveOccurred())
			return kib
		}
	}
	Fail("no VmHWM in the status of " + pid)
	return 0
}

var _ = Describe("the run section's log frames", func() {
	appEnv := "export A=app\n"

	DescribeTable("frames each process's stdout and stderr on the console, a 100 KiB line in pieces that the host joins up to its bound, and names the first exit after the last frame of the process that exited",
		func(shellOf func() guestShell) {
			shell := shellOf()
			long := strings.Repeat("0123456789abcdef", 6400)
			sidecar := `until [ -s ../p0/start ]; do sleep 0.05; done; echo side-out; echo side-err >&2; cat long; i=0; while [ "$i" -lt 200 ]; do echo "line $i"; i=$((i + 1)); done; printf 'tail-without-newline'; exit 3`
			procs := sectionProcs(GinkgoT().TempDir(), []string{`echo app-out; echo app-err >&2; ` + termScript(143), sidecar}, appEnv)
			Expect(os.WriteFile(filepath.Join(procs[1].dir, "long"), []byte(long+"\n"), 0o600)).To(Succeed())
			r := startSection(shell, procs, false, testIdentityPair{}, nil)
			out := r.finish(10 * time.Second)

			stdout, stderr, events := splitSection(out)
			Expect(stdout).To(Equal("app-out\nvm-launch guest: sidecar 1 exited with status 3; stopping the app\nstatus=3\n"), shell.name)
			Expect(stderr).To(Equal("app-err\n"), shell.name)
			// The host joins the pieces of a line up to maxLogLine, so the
			// line arrives as the whole pieces that fit and then the rest.
			joined := maxLogLine / guestFramePayload * guestFramePayload
			wantOut := []string{"side-out", long[:joined], long[joined:]}
			for i := 0; i < 200; i++ {
				wantOut = append(wantOut, "line "+strconv.Itoa(i))
			}
			wantOut = append(wantOut, "tail-without-newline")
			Expect(streamLines(events, 1, 'o')).To(Equal(wantOut))
			Expect(streamLines(events, 1, 'e')).To(Equal([]string{"side-err"}))
			Expect(events[len(events)-1]).To(Equal(frameEvent{index: 1, first: true, status: 3}))
			for _, ev := range events[:len(events)-1] {
				Expect(ev.first).To(BeFalse(), "%+v", ev)
			}

			pieces := 0
			for _, line := range strings.Split(out, "\n") {
				if !strings.Contains(line, testNonce) {
					continue
				}
				if strings.HasPrefix(line, firstTag(testNonce)) {
					Expect(line).To(Equal(firstTag(testNonce) + "1 3"))
					continue
				}
				Expect(line).To(HavePrefix(logTag(testNonce)))
				_, payload, _ := strings.Cut(line, " ")
				Expect(len(payload)).To(BeNumerically("<=", guestFramePayload))
				if strings.HasPrefix(line, logTag(testNonce)+"1O ") {
					pieces++
				}
			}
			Expect(pieces).To(Equal(len(long) / guestFramePayload))
		},
		shellEntries(""),
	)

	DescribeTable("keeps the console, the section's text, the other processes' FIFOs, and the frame tag away from every process",
		func(shellOf func() guestShell) {
			shell := shellOf()
			procs := sectionProcs(GinkgoT().TempDir(), []string{fdScript + termScript(143), fdScript + `until [ -e go ]; do sleep 0.05; done; exit 0`}, appEnv)
			r := startSection(shell, procs, false, testIdentityPair{}, nil)
			for i := range procs {
				processFile(procs, i, "fds")
			}

			info, err := os.Stat(r.logDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o700)))
			for _, p := range procs {
				for _, stream := range []string{"out", "err"} {
					info, err := os.Stat(filepath.Join(r.logDir, strconv.Itoa(p.index)+"."+stream))
					Expect(err).NotTo(HaveOccurred())
					Expect(info.Mode() & os.ModeNamedPipe).NotTo(BeZero())
					Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))
				}
			}

			group := groupProcesses(r.cmd.Process.Pid)
			Expect(group).NotTo(ContainSubstring(testNonce))
			framers := 0
			for _, line := range strings.Split(strings.TrimSpace(group), "\n") {
				pid, cmdline, _ := strings.Cut(line, " ")
				if !strings.HasSuffix(cmdline, " rvm_frame o") && !strings.HasSuffix(cmdline, " rvm_frame e") {
					continue
				}
				framers++
				environ, err := os.ReadFile(filepath.Join("/proc", pid, "environ"))
				Expect(err).NotTo(HaveOccurred())
				Expect(strings.Split(string(environ), "\x00")).To(ContainElement(MatchRegexp(`^RVM_TAG=` + logTag(testNonce) + `[01]$`)))
				Expect(strings.Split(string(environ), "\x00")).To(ContainElement("LC_ALL=C"))
			}
			Expect(framers).To(Equal(2*len(procs)), group)

			for i, p := range procs {
				fds := parseFds(processFile(procs, i, "fds"))
				own := filepath.Join(r.logDir, strconv.Itoa(p.index))
				Expect(fds).To(HaveKeyWithValue("0", "/dev/null"), "process %d", i)
				Expect(fds).To(HaveKeyWithValue("1", own+".out"), "process %d", i)
				Expect(fds).To(HaveKeyWithValue("2", own+".err"), "process %d", i)
				for fd, target := range fds {
					Expect(target).NotTo(BeElementOf(r.out, r.consolePath, r.events, r.script, r.acks), "process %d fd %s", i, fd)
					if strings.HasPrefix(target, r.logDir+"/") {
						Expect(target).To(BeElementOf(own+".out", own+".err"), "process %d fd %s", i, fd)
					}
				}
			}

			Expect(os.WriteFile(filepath.Join(procs[1].dir, "go"), nil, 0o600)).To(Succeed())
			Expect(r.finish(10*time.Second)).To(Equal(firstTag(testNonce)+"1 0\nvm-launch guest: sidecar 1 exited with status 0; stopping the app\nstatus=0\n"), shell.name)
		},
		shellEntries(""),
	)

	DescribeTable("reports an exit within half a second when a descendant still holds the process's FIFO, and frames what the descendant writes later",
		func(shellOf func() guestShell) {
			shell := shellOf()
			procs := sectionProcs(GinkgoT().TempDir(), []string{termScript(143), `( sleep 1.5; echo late-line ) & echo early-line; exit 3`}, appEnv)
			r := startSection(shell, procs, false, testIdentityPair{}, nil)
			out := r.finish(10 * time.Second)
			Expect(out).To(Equal(logTag(testNonce)+"1o early-line\n"+firstTag(testNonce)+"1 3\nvm-launch guest: sidecar 1 exited with status 3; stopping the app\nstatus=3\n"), shell.name)
			Eventually(r.output, 5*time.Second, 10*time.Millisecond).Should(Equal(out + logTag(testNonce) + "1o late-line\n"))
		},
		shellEntries(""),
	)

	It("passes the frame tag to the framer's shell only in its environment, with LC_ALL=C, has the framers set -1000, bounds the drain, and starts each process on its own FIFOs", func() {
		procs := sectionProcs(GinkgoT().TempDir(), []string{"exit 0", "exit 0"}, appEnv)
		section := guestRunSection(testNonce, procs, true, stubGuestExec)
		Expect(strings.Count(section, logTag(testNonce))).To(Equal(1))
		Expect(section).To(ContainSubstring(`/bin/busybox tr -d '\000' | LC_ALL=C RVM_TAG='` + logTag(testNonce) + `'"$1" /bin/busybox sh -c '`))
		Expect(section).To(ContainSubstring("rvm_frame() {\n\techo -1000 >/proc/self/oom_score_adj\n"))
		Expect(section).To(ContainSubstring("\twhile [ \"$rvm_n\" -lt 10 ] && { rvm_live \"$1\" || rvm_live \"$2\"; }; do\n\t\tsleep 0.05\n"))
		for _, p := range procs {
			idx, out, errs := strconv.Itoa(p.index), guestLogFIFO(p.index, "out"), guestLogFIFO(p.index, "err")
			Expect(strings.Count(section, "\trvm_frame "+idx+" o <"+out+" 3>&- 4>&- &\n\trvm_out=$!\n\trvm_frame "+idx+" e <"+errs+" 3>&- 4>&- &\n")).To(Equal(1))
			Expect(strings.Count(section, "\t\tcommand exec >"+out+" 2>"+errs+" 3>&- 4>&- || {")).To(Equal(1))
			Expect(strings.Count(section, "\trvm_s=$?\n\trvm_drain \"$rvm_out\" \"$rvm_err\"\n\techo \"exit "+idx+" $rvm_s\" >&4\n")).To(Equal(1))
		}
	})

	It("keeps a frame of the most payload inside one write of 1 KiB and the host's bound, with the console's CRLF", func() {
		nonce, err := newNonce()
		Expect(err).NotTo(HaveOccurred())
		frame := len(logTag(nonce)) + maxIndexDigits + len("o ") + guestFramePayload + len("\r\n")
		Expect(frame).To(BeNumerically("<=", 1<<10))
		Expect(frame).To(BeNumerically("<=", maxFrameBytes))
		Expect(guestFrameFunc(nonce)).To(ContainSubstring("read -r -n " + strconv.Itoa(guestFramePayload) + " rvm_l;"))
		Expect(guestFrameFunc(nonce)).To(ContainSubstring(`[ "${#rvm_l}" -eq ` + strconv.Itoa(guestFramePayload) + ` ]`))
	})

	It("frames each piece of a line that has not ended as soon as it comes, and holds no more than one piece of it", func() {
		nonce, err := newNonce()
		Expect(err).NotTo(HaveOccurred())
		in, out, cmd := startFramer(nonce)
		more, last := logTag(nonce)+"1O ", logTag(nonce)+"1o "

		first := strings.Repeat("a", guestFramePayload)
		_, err = in.Write([]byte(first))
		Expect(err).NotTo(HaveOccurred())
		Eventually(out.String, 10*time.Second, 10*time.Millisecond).Should(Equal(more + first + "\n"))
		pid := framerPid(nonce)
		before := peakKiB(pid)

		// 4096 more pieces, about 4 MiB, still with no newline.
		rest := strings.Repeat("0123456789abcdef", 4096*guestFramePayload/16)
		written := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			_, err := in.Write([]byte(rest))
			written <- err
		}()
		Eventually(func() int { return strings.Count(out.String(), more) }, time.Minute, 50*time.Millisecond).Should(Equal(1 + 4096))
		Expect(<-written).To(Succeed())
		Expect(out.String()).NotTo(ContainSubstring(last))
		Expect(peakKiB(pid)-before).To(BeNumerically("<", 512), "the framer's peak grew from %d KiB", before)

		_, err = in.Write([]byte("tail\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(in.Close()).To(Succeed())
		Expect(cmd.Wait()).To(Succeed())
		lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
		Expect(lines).To(HaveLen(1 + 4096 + 1))
		Expect(lines[len(lines)-1]).To(Equal(last + "tail"))
		joined := ""
		for _, line := range lines[:len(lines)-1] {
			Expect(line).To(HavePrefix(more))
			joined += strings.TrimPrefix(line, more)
		}
		Expect(joined).To(Equal(first + rest))
	})

	It("counts bytes under a UTF-8 locale, ends a line of exactly one piece with an empty last piece, drops NUL bytes, and ends the stream's last line without a newline", func() {
		nonce, err := newNonce()
		Expect(err).NotTo(HaveOccurred())
		in, out, cmd := startFramer(nonce)
		more, last := logTag(nonce)+"1O ", logTag(nonce)+"1o "
		accents := strings.Repeat("\u00e9", 500)
		exact := strings.Repeat("x", guestFramePayload)
		unended := strings.Repeat("y", guestFramePayload)
		_, err = in.Write([]byte(accents + "\n" + exact + "\n" + "a\x00b\n" + unended))
		Expect(err).NotTo(HaveOccurred())
		Expect(in.Close()).To(Succeed())
		Expect(cmd.Wait()).To(Succeed())
		Expect(out.String()).To(Equal(
			more + accents[:guestFramePayload] + "\n" + last + accents[guestFramePayload:] + "\n" +
				more + exact + "\n" + last + "\n" +
				last + "ab\n" +
				more + unended + "\n" + last + "\n"))
	})
})
