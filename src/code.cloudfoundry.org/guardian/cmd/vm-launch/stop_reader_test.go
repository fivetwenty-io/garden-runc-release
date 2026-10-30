//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// stopReaderAt is the stop reader of /init with console in place of the
// guest's console and oomFile in place of its own oom_score_adj, so a spec
// can run it as any user.
func stopReaderAt(console, oomFile string) string {
	reader := guestStopReader(testNonce)
	Expect(strings.Count(reader, "</dev/console")).To(Equal(1))
	Expect(strings.Count(reader, "/proc/self/oom_score_adj")).To(Equal(1))
	reader = strings.Replace(reader, "</dev/console", "<"+console, 1)
	return strings.Replace(reader, "/proc/self/oom_score_adj", oomFile, 1)
}

// readerRun is the stop reader of /init running in a real shell, with a
// FIFO as the console that the spec writes console input to.
type readerRun struct {
	cmd     *exec.Cmd
	out     string
	oom     string
	appPid  string
	console *os.File
	done    chan error
}

// startReaderRun runs, in shell, the stop reader and then, when command is
// set, the command line of /init with command as /rvm/cmd, the reader stop,
// and a line with the command's status. Without a command it waits for the
// reader and says when the reader has ended. Its output goes to a file; the
// shell leads a process group of its own, which the spec kills at its end.
func startReaderRun(shell guestShell, command *string) *readerRun {
	return startReaderRunOn(shell, command, false)
}

// startReaderRunOn is startReaderRun, with /dev/null as the console when
// ended is set, so the reader's first read finds the end of its input.
func startReaderRunOn(shell guestShell, command *string, ended bool) *readerRun {
	dir := GinkgoT().TempDir()
	cmdText := ""
	if command != nil {
		cmdText = *command
	}
	paths := guestFiles("", cmdText)
	r := &readerRun{
		out:    filepath.Join(dir, "out"),
		oom:    filepath.Join(dir, "oom_score_adj"),
		appPid: paths.Replace(guestAppPid),
		done:   make(chan error, 1),
	}
	fifo := os.DevNull
	if !ended {
		fifo = filepath.Join(dir, "console")
		Expect(syscall.Mkfifo(fifo, 0o600)).To(Succeed())
		// Held open for reading and writing, so the reader's open never
		// waits and its reads never see EOF, as on a serial console.
		console, err := os.OpenFile(fifo, os.O_RDWR, 0)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(console.Close)
		r.console = console
	}

	body := "wait \"$rvm_reader\"\necho reader-done\n"
	if command != nil {
		body = guestRunCommand + guestRunStatus + guestStopReaderStop + "echo \"status=$rvm_status\"\n"
	}
	limits := "RVM_NOFILE_SOFT=$(ulimit -S -n)\nRVM_NOFILE_HARD=$(ulimit -H -n)\n"
	script := paths.Replace(guestFailFunc + limits + stopReaderAt(fifo, r.oom) + body)

	out, err := os.Create(r.out)
	Expect(err).NotTo(HaveOccurred())
	defer out.Close()
	r.cmd = exec.Command(shell.argv[0], append(shell.argv[1:], "-c", script)...)
	r.cmd.Env = []string{"PATH=" + guestBin(shell)}
	r.cmd.Stdout = out
	r.cmd.Stderr = out
	r.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	Expect(r.cmd.Start()).To(Succeed())
	pgid := r.cmd.Process.Pid
	go func() { r.done <- r.cmd.Wait() }()
	DeferCleanup(func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) })
	return r
}

// output returns what the run has printed so far.
func (r *readerRun) output() string {
	out, err := os.ReadFile(r.out)
	Expect(err).NotTo(HaveOccurred())
	return string(out)
}

// waitFor waits until the run has printed text.
func (r *readerRun) waitFor(text string) {
	Eventually(r.output, 10*time.Second, 10*time.Millisecond).Should(ContainSubstring(text))
}

// write writes console input to the reader.
func (r *readerRun) write(input string) {
	_, err := r.console.WriteString(input)
	Expect(err).NotTo(HaveOccurred())
}

// finish waits up to 10 s for the shell to exit and returns its output.
// Nothing of the run may outlive the shell: the command, the reader, and
// the reader's sleep all run in its process group.
func (r *readerRun) finish() string {
	select {
	case err := <-r.done:
		Expect(err).NotTo(HaveOccurred(), r.output())
	case <-time.After(10 * time.Second):
		Fail("the run did not end within 10s:\n" + r.output())
	}
	out := r.output()
	// The reader's last sleep, if a kill caught it in its poll, ends within
	// 50 ms; nothing else may be left.
	Eventually(func() error { return syscall.Kill(-r.cmd.Process.Pid, 0) }, 2*time.Second, 10*time.Millisecond).
		Should(MatchError(syscall.ESRCH), "a process of the run outlived it:\n"+out)
	return out
}

// strPtr returns a pointer to s.
func strPtr(s string) *string { return &s }

var _ = Describe("the stop reader", func() {
	stopLine := stopTag(testNonce) + "\n"

	DescribeTable("sends SIGTERM to the command on the stop request, and the command's own status is kept",
		func(shellOf func() guestShell) {
			shell := shellOf()
			r := startReaderRun(shell, strPtr(`trap 'echo got-term; exit 0' TERM; echo ready; while :; do sleep 0.05; done`))
			r.waitFor("ready\n")
			r.write("noise line\n" + stopLine)
			Expect(r.finish()).To(Equal("ready\ngot-term\nstatus=0\n"), shell.name)
			oom, err := os.ReadFile(r.oom)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(oom)).To(Equal("-1000\n"))
		},
		shellEntries(""),
	)

	DescribeTable("ends a command that keeps the default action of SIGTERM",
		func(shellOf func() guestShell) {
			shell := shellOf()
			r := startReaderRun(shell, strPtr(`echo ready; exec sleep 600`))
			r.waitFor("ready\n")
			r.write(stopLine)
			Expect(r.finish()).To(Equal("ready\nstatus=143\n"), shell.name)
		},
		shellEntries(""),
	)

	It("ends a simple command that sh -c runs as the top process, and leaves nothing of it behind, in the guest's busybox sh", func() {
		shell := guestBusyboxShell()
		// No exec: busybox's sh -c becomes the last simple command itself,
		// so SIGTERM reaches sleep and no shell is left waiting for it.
		r := startReaderRun(shell, strPtr(`echo ready; sleep 600`))
		r.waitFor("ready\n")
		r.write(stopLine)
		Expect(r.finish()).To(Equal("ready\nstatus=143\n"))
	})

	DescribeTable("is stopped once the command has ended without a request",
		func(shellOf func() guestShell) {
			shell := shellOf()
			r := startReaderRun(shell, strPtr(`echo ran; exit 7`))
			Expect(r.finish()).To(Equal("ran\nstatus=7\n"), shell.name)
		},
		shellEntries(""),
	)

	DescribeTable("never stops the command when the console ends without a request",
		func(shellOf func() guestShell) {
			shell := shellOf()
			// Long enough for a reader that went on after the end of its
			// input to find the pid and signal the command.
			r := startReaderRunOn(shell, strPtr(`trap 'echo got-term' TERM; echo ready; sleep 0.5; echo finished`), true)
			Expect(r.finish()).To(Equal("ready\nfinished\nstatus=0\n"), shell.name)
		},
		shellEntries(""),
	)

	DescribeTable("never stops the command on a line that is not the request",
		func(shellOf func() guestShell) {
			shell := shellOf()
			gate := filepath.Join(GinkgoT().TempDir(), "go")
			r := startReaderRun(shell, strPtr(`echo ready; until [ -e '`+gate+`' ]; do sleep 0.02; done; echo finished`))
			r.waitFor("ready\n")
			for _, line := range []string{
				"RVM_STOP_fedcba9876543210",
				"RVM_STOP_",
				"RVM_STOP",
				"x" + stopTag(testNonce),
				stopTag(testNonce) + "x",
				" " + stopTag(testNonce),
				stopTag(testNonce) + " ",
				stopTag(testNonce) + "\\",
				stopTag(testNonce)[:len(stopTag(testNonce))-1],
				"$(echo " + stopTag(testNonce) + ")",
				"",
			} {
				r.write(line + "\n")
			}
			// Long enough for a reader that matched to have acted.
			time.Sleep(300 * time.Millisecond)
			Expect(r.output()).To(Equal("ready\n"))
			Expect(os.WriteFile(gate, nil, 0o600)).To(Succeed())
			Expect(r.finish()).To(Equal("ready\nfinished\nstatus=0\n"), shell.name)
		},
		shellEntries(""),
	)

	DescribeTable("acts on a request that comes before the command has recorded its pid, once the pid is there",
		func(shellOf func() guestShell) {
			shell := shellOf()
			r := startReaderRun(shell, nil)
			r.write(stopLine)
			// The reader polls for the pid file now; the process it is
			// to signal comes later.
			time.Sleep(200 * time.Millisecond)
			Expect(r.output()).To(BeEmpty())
			helper := exec.Command("sleep", "600")
			Expect(helper.Start()).To(Succeed())
			DeferCleanup(func() { _ = helper.Process.Kill() })
			// A partly written pid file reads as no pid; the reader keeps
			// polling until the whole line is there.
			Expect(os.WriteFile(r.appPid, nil, 0o600)).To(Succeed())
			time.Sleep(100 * time.Millisecond)
			Expect(os.WriteFile(r.appPid, []byte(strconv.Itoa(helper.Process.Pid)+"\n"), 0o600)).To(Succeed())
			waited := make(chan error, 1)
			go func() { waited <- helper.Wait() }()
			var err error
			select {
			case err = <-waited:
			case <-time.After(10 * time.Second):
				Fail("the reader did not signal the process in the pid file within 10s:\n" + r.output())
			}
			var exitErr *exec.ExitError
			Expect(errors.As(err, &exitErr)).To(BeTrue(), "%v", err)
			status := exitErr.Sys().(syscall.WaitStatus)
			Expect(status.Signaled()).To(BeTrue())
			Expect(status.Signal()).To(Equal(syscall.SIGTERM))
			Expect(r.finish()).To(Equal("reader-done\n"), shell.name)
		},
		shellEntries(""),
	)

	DescribeTable("acts on the first request only",
		func(shellOf func() guestShell) {
			shell := shellOf()
			gate := filepath.Join(GinkgoT().TempDir(), "go")
			// A second TERM, if one came, would print second-term.
			r := startReaderRun(shell, strPtr(`trap 'echo got-term; trap "echo second-term" TERM' TERM; echo ready; until [ -e '`+gate+`' ]; do sleep 0.02; done; exit 0`))
			r.waitFor("ready\n")
			r.write(stopLine + stopLine)
			r.waitFor("got-term\n")
			time.Sleep(300 * time.Millisecond)
			Expect(r.output()).To(Equal("ready\ngot-term\n"))
			Expect(os.WriteFile(gate, nil, 0o600)).To(Succeed())
			Expect(r.finish()).To(Equal("ready\ngot-term\nstatus=0\n"), shell.name)
		},
		shellEntries(""),
	)

	It("is in /init after every setup step and before the start tag, and is stopped right after the command, before anything else", func() {
		for _, volume := range []bool{false, true} {
			script := initScript(testNonce, volume)
			Expect(strings.Count(script, guestConsoleSetup)).To(Equal(1))
			Expect(strings.Count(script, guestStopReader(testNonce))).To(Equal(1))
			Expect(strings.Count(script, guestStopReaderStop)).To(Equal(1))
			Expect(script).To(ContainSubstring(guestFailFunc+guestConsoleSetup), "echo goes off right after rvm_fail is defined")
			lastSetup := guestEnvChecks
			if volume {
				lastSetup = guestVolumeSetup
			}
			Expect(script).To(ContainSubstring(lastSetup+guestStopReader(testNonce)+"echo "+startTag(testNonce)+"\n"), "volume=%v", volume)
			Expect(script).To(ContainSubstring(guestRunCommand+guestRunStatus+guestStopReaderStop+guestListenStop), "volume=%v", volume)
			if volume {
				Expect(strings.Index(script, guestStopReaderStop)).To(BeNumerically("<", strings.Index(script, guestVolumeTeardown)))
			}
		}
	})
})
