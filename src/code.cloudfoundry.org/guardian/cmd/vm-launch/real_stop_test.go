//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// triggerWriter passes guest output to w and calls fire once, from the
// console goroutine, when the output so far holds text.
type triggerWriter struct {
	w    *safeBuffer
	text string
	fire func()
	once sync.Once
}

func (t *triggerWriter) Write(p []byte) (int, error) {
	n, err := t.w.Write(p)
	if strings.Contains(t.w.String(), t.text) {
		t.once.Do(t.fire)
	}
	return n, err
}

// realStop is one supervised run of a real guest that a spec stopped.
type realStop struct {
	res       runResult
	out       string
	log       string
	signalled time.Time
	ended     time.Time
}

// superviseRealStop boots a guest that runs command under TCG through the
// supervisor, as vm-launch runs QEMU, with QEMU's stdin the supervisor's
// pipe and the real stop deadline. Once the command's output holds ready,
// it sends the supervisor SIGTERM, and then each of later, after the time
// that its entry waits. With ready empty, the signal comes as soon as QEMU
// runs, before the guest has started its command.
func superviseRealStop(command, ready string, later ...laterSignal) realStop {
	art := realArtifacts()
	qemu := realQEMU()
	requireMicrovm(qemu)
	g := taskGuest(command)
	withRealRoot(&g)
	f, err := newInitramfs(guestBusybox(), g)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(f.Close)

	var r realStop
	bootWithRetry(func() bool {
		files, _, initrdPath, _, rootPath := hypervisorFiles(nil, withUserspaceMark(f), nil, realRootImage())
		consoleLog := filepath.Join(GinkgoT().TempDir(), "console.log")
		argv := consoleLogArgv(markedArgv(tcgArgv(qemu, withRealRootDrive(qemuArgv(art, initrdPath, minGuestMemoryMiB, g.nw, nil, 0), rootPath))), consoleLog)
		cmd := newHypervisorCmd(argv, files)
		stderr := &safeBuffer{}
		cmd.Stderr = stderr
		out, logBuf := &safeBuffer{}, &safeBuffer{}
		console := newBootWriter(realBootMark)
		stopTail := make(chan struct{})
		tailed := tailFile(consoleLog, console, stopTail)

		signals := make(chan os.Signal, 1+len(later))
		var signalled time.Time
		fire := func() {
			signalled = time.Now()
			signals <- syscall.SIGTERM
			go func() {
				for _, l := range later {
					time.Sleep(l.after)
					signals <- l.sig
				}
			}()
		}
		var qemuProc *os.Process
		running := make(chan struct{})
		sup := supervisor{
			stdout:   &triggerWriter{w: out, text: ready, fire: fire},
			logger:   log.New(logBuf, "", 0),
			signals:  signals,
			grace:    killGrace,
			deadline: stopDeadline,
			started: func() {
				qemuProc = cmd.Process
				close(running)
				if ready == "" {
					fire()
				}
			},
		}
		if ready == "" {
			sup.stdout = out
		}
		kill := func() {
			select {
			case <-running:
				_ = qemuProc.Kill()
			default:
			}
		}
		exited := make(chan struct{})
		var res runResult
		var runErr error
		go func() {
			defer close(exited)
			res, runErr = sup.run(cmd, testNonce)
		}()
		details := func() string {
			return "stderr: " + stderr.String() + "\nconsole: " + console.String() + "\nlog: " + logBuf.String()
		}
		booted := ready == "" || awaitRealGuest(kill, console, exited, details)
		<-exited
		ended := time.Now()
		close(stopTail)
		<-tailed
		if !booted {
			return false
		}
		Expect(runErr).NotTo(HaveOccurred())
		if ready != "" {
			Expect(console.String()).To(ContainSubstring(realBootMark), "QEMU exited before the guest started userspace\n%s", details())
		}
		GinkgoWriter.Printf("%s\n", details())
		r = realStop{res: res, out: out.String(), log: logBuf.String(), signalled: signalled, ended: ended}
		return true
	})
	return r
}

// laterSignal is a signal that superviseRealStop sends after the first.
type laterSignal struct {
	after time.Duration
	sig   os.Signal
}

var _ = Describe("stopping a guest against a real QEMU", func() {
	// drainingApp traps SIGTERM, takes 2 seconds to finish its work, and
	// exits 0.
	const drainingApp = `trap 'echo got-term; sleep 2; echo drained; exit 0' TERM
echo ready
while :; do sleep 1; done`

	It("lets a command that traps SIGTERM drain, and reports its status", func() {
		r := superviseRealStop(drainingApp, "ready\n")
		Expect(codeOf(r.res)).To(Equal(0), r.log)
		Expect(r.out).To(Equal("ready\ngot-term\ndrained\n"))
		Expect(r.ended.Sub(r.signalled)).To(BeNumerically(">=", 2*time.Second))
		Expect(r.ended.Sub(r.signalled)).To(BeNumerically("<", stopDeadline))
		Expect(r.log).To(Equal("received terminated, asking the guest command to stop\n"))
	})

	It("keeps the stop request and its nonce out of the command's output, with the console's echo off", func() {
		r := superviseRealStop(drainingApp, "ready\n")
		Expect(codeOf(r.res)).To(Equal(0), r.log)
		Expect(r.out).NotTo(ContainSubstring("RVM_STOP_"))
		Expect(r.out).NotTo(ContainSubstring(testNonce))
		Expect(r.out).NotTo(ContainSubstring("Terminated"))
	})

	It("ends a simple command, which sh -c runs as the top process, with SIGTERM", func() {
		r := superviseRealStop("echo ready\nsleep 600", "ready\n")
		Expect(r.res.markerFound).To(BeTrue(), r.log)
		Expect(codeOf(r.res)).To(Equal(143))
		Expect(r.out).To(Equal("ready\n"))
		Expect(r.ended.Sub(r.signalled)).To(BeNumerically("<", stopDeadline))
	})

	It("kills QEMU at the deadline when the command ignores SIGTERM", func() {
		r := superviseRealStop("trap '' TERM\necho ready\nsleep 600", "ready\n")
		Expect(r.res.markerFound).To(BeFalse(), r.out)
		Expect(codeOf(r.res)).To(Equal(143))
		Expect(r.ended.Sub(r.signalled)).To(BeNumerically(">=", stopDeadline))
		Expect(r.ended.Sub(r.signalled)).To(BeNumerically("<", stopDeadline+3*time.Second))
		Expect(r.log).To(Equal("received terminated, asking the guest command to stop\n" +
			fmt.Sprintf("the guest did not stop within %v of the signal; killing the hypervisor\n", stopDeadline)))
	})

	It("lets the command drain through a second signal, which changes nothing", func() {
		r := superviseRealStop(drainingApp, "ready\n", laterSignal{after: 500 * time.Millisecond, sig: syscall.SIGINT})
		Expect(codeOf(r.res)).To(Equal(0), r.log)
		Expect(r.out).To(Equal("ready\ngot-term\ndrained\n"))
		Expect(r.log).To(Equal("received terminated, asking the guest command to stop\n" +
			"received interrupt again; the guest is already stopping\n"))
	})

	It("forwards a signal that comes before the guest started its command, which ends QEMU", func() {
		r := superviseRealStop("echo never", "")
		Expect(r.res.markerFound).To(BeFalse())
		Expect(codeOf(r.res)).To(Equal(143))
		Expect(r.out).To(BeEmpty())
		Expect(r.ended.Sub(r.signalled)).To(BeNumerically("<", stopDeadline))
		Expect(r.log).To(HavePrefix("received terminated before the guest started its command, forwarding it to the hypervisor\n"))
	})
})
