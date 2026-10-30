//go:build linux

package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// appendTo appends s to the file at path, creating it if need be.
func appendTo(path, s string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	Expect(err).NotTo(HaveOccurred())
	_, err = f.WriteString(s)
	Expect(err).NotTo(HaveOccurred())
	Expect(f.Close()).To(Succeed())
}

// waitForFile waits up to 10 s for path to exist.
func waitForFile(path string) {
	Eventually(path, 10*time.Second, 5*time.Millisecond).Should(BeAnExistingFile())
}

// openFDs returns the number of this process's open file descriptors.
func openFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	Expect(err).NotTo(HaveOccurred())
	return len(entries)
}

var _ = Describe("the supervisor's stop path", func() {
	var (
		out     *safeBuffer
		logBuf  *safeBuffer
		signals chan os.Signal
		sup     supervisor
		dir     string
		stdin   string
	)

	BeforeEach(func() {
		out = &safeBuffer{}
		logBuf = &safeBuffer{}
		signals = make(chan os.Signal, 2)
		sup = supervisor{stdout: out, logger: log.New(logBuf, "", 0), signals: signals, grace: 5 * time.Second, deadline: 5 * time.Second}
		dir = GinkgoT().TempDir()
		// stdin is where a fake hypervisor records the console input it read.
		stdin = filepath.Join(dir, "stdin")
	})

	// fakeHypervisor stands in for QEMU or Firecracker: a shell that writes
	// console bytes to stdout and may read the console input from stdin.
	fakeHypervisor := func(script string) *exec.Cmd {
		return exec.Command("/bin/sh", "-c", script)
	}
	startLine := `printf 'boot noise\r\nRVM_START_` + testNonce + `\r\n'; `
	exitLine := func(status string) string { return `printf 'RVM_EXIT_` + testNonce + `=` + status + `\r\n'; ` }
	// readRequest reads one line of console input and records it in stdin.
	readRequest := func() string { return `IFS= read -r line; printf '%s\n' "$line" >>'` + stdin + `'; ` }
	stopLine := stopTag(testNonce) + "\n"
	// onForwardedTERM is a trap that records a forwarded SIGTERM in stdin,
	// then copies to stdin whatever console input is waiting, and exits 0.
	onForwardedTERM := func() string {
		return `STDIN='` + stdin + `'; trap 'echo forwarded >>"$STDIN"; timeout 0.3 cat >>"$STDIN"; exit 0' TERM; `
	}

	It("asks the running guest command to stop, forwards nothing, and exits with the command's status", func(ctx SpecContext) {
		sup.closePorts = func() { sup.logger.Print("closing the ports") }
		sup.stdout = &signalOnWrite{w: out, signals: signals, sig: syscall.SIGTERM}
		// A forwarded signal would end the fake hypervisor with 99.
		res, err := sup.run(fakeHypervisor(`trap 'exit 99' TERM INT; `+startLine+`echo ready; `+readRequest()+`echo drained; `+exitLine("0")), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(0), logBuf.String())
		Expect(res.received).To(Equal(syscall.SIGTERM))
		Expect(out.String()).To(Equal("ready\ndrained\n"))
		Expect(os.ReadFile(stdin)).To(Equal([]byte(stopLine)))
		// The ports close when the guest reports its status, not at the signal.
		Expect(logBuf.String()).To(Equal("received terminated, asking the guest command to stop\nclosing the ports\n"))
	}, SpecTimeout(time.Minute))

	It("takes SIGINT the same way, so the guest gets the same stop request", func(ctx SpecContext) {
		sup.stdout = &signalOnWrite{w: out, signals: signals, sig: syscall.SIGINT}
		res, err := sup.run(fakeHypervisor(`trap 'exit 99' TERM INT; `+startLine+`echo ready; `+readRequest()+exitLine("0")), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(0), logBuf.String())
		Expect(os.ReadFile(stdin)).To(Equal([]byte(stopLine)))
		Expect(logBuf.String()).To(Equal("received interrupt, asking the guest command to stop\n"))
	}, SpecTimeout(time.Minute))

	It("forwards a signal that comes before the guest started its command, and writes no stop request", func(ctx SpecContext) {
		trapped := filepath.Join(dir, "trapped")
		sup.started = func() {
			defer GinkgoRecover()
			waitForFile(trapped)
			signals <- syscall.SIGTERM
		}
		// The ports close before the hypervisor gets the signal.
		sup.closePorts = func() { appendTo(stdin, "closed the ports\n") }
		// A stop request would show in stdin after the forwarded signal.
		res, err := sup.run(fakeHypervisor(onForwardedTERM()+`printf 'boot noise\r\n'; : >'`+trapped+`'; while :; do sleep 0.02; done`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.ReadFile(stdin)).To(Equal([]byte("closed the ports\nforwarded\n")))
		Expect(codeOf(res)).To(Equal(143))
		Expect(logBuf.String()).To(Equal("received terminated before the guest started its command, forwarding it to the hypervisor\n" +
			"guest never started its command; last console output follows\nboot noise\r\n"))
	}, SpecTimeout(time.Minute))

	It("forwards a signal that comes after the guest reported its status, and writes no stop request", func(ctx SpecContext) {
		// The supervisor has acted on the marker before the signal comes.
		sup.reported = func() { signals <- syscall.SIGTERM }
		// The ports stay up at the marker, which came without a signal, and
		// close before the hypervisor gets the signal.
		sup.closePorts = func() { appendTo(stdin, "closed the ports\n") }
		began := time.Now()
		res, err := sup.run(fakeHypervisor(onForwardedTERM()+startLine+exitLine("5")+`while :; do sleep 0.02; done`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(time.Since(began)).To(BeNumerically("<", sup.grace))
		Expect(codeOf(res)).To(Equal(5))
		Expect(os.ReadFile(stdin)).To(Equal([]byte("closed the ports\nforwarded\n")))
		Expect(logBuf.String()).To(Equal("received terminated after the guest reported its status, forwarding it to the hypervisor\n"))
	}, SpecTimeout(time.Minute))

	It("forwards the signal at once when the stop request cannot be written, and closes the ports first", func(ctx SpecContext) {
		sup.closePorts = func() { sup.logger.Print("closing the ports") }
		sup.stdout = &signalOnWrite{w: out, signals: signals, sig: syscall.SIGTERM}
		began := time.Now()
		// The fake hypervisor closes its stdin, the one read end of the pipe.
		res, err := sup.run(fakeHypervisor(`exec 0<&-; `+startLine+`echo ready; exec sleep 60`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(time.Since(began)).To(BeNumerically("<", sup.deadline))
		Expect(codeOf(res)).To(Equal(143))
		Expect(logBuf.String()).To(MatchRegexp(`^received terminated, asking the guest command to stop\nsending the stop request to the guest failed: write \S+: broken pipe; forwarding terminated to the hypervisor\nclosing the ports\n$`))
	}, SpecTimeout(time.Minute))

	It("kills the hypervisor at the deadline when the guest command does not stop, and closes the ports first", func(ctx SpecContext) {
		sup.deadline = 500 * time.Millisecond
		sup.closePorts = func() { sup.logger.Print("closing the ports") }
		var signalled time.Time
		sup.stdout = writerFunc(func(p []byte) (int, error) {
			if signalled.IsZero() {
				signalled = time.Now()
				signals <- syscall.SIGTERM
			}
			return out.Write(p)
		})
		res, err := sup.run(fakeHypervisor(`trap '' TERM INT; `+startLine+`echo ready; `+readRequest()+`exec sleep 60`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(time.Since(signalled)).To(BeNumerically(">=", sup.deadline))
		Expect(time.Since(signalled)).To(BeNumerically("<", 5*time.Second))
		Expect(codeOf(res)).To(Equal(143))
		Expect(os.ReadFile(stdin)).To(Equal([]byte(stopLine)))
		Expect(logBuf.String()).To(Equal("received terminated, asking the guest command to stop\n" +
			"the guest did not stop within 500ms of the signal; killing the hypervisor\n" +
			"closing the ports\n"))
	}, SpecTimeout(time.Minute))

	It("writes one stop request for repeated signals, and keeps the deadline of the first", func(ctx SpecContext) {
		sup.deadline = 1500 * time.Millisecond
		calls := 0
		sup.closePorts = func() { calls++ }
		var signalled time.Time
		sup.stdout = writerFunc(func(p []byte) (int, error) {
			if signalled.IsZero() {
				signalled = time.Now()
				signals <- syscall.SIGTERM
				go func() {
					time.Sleep(500 * time.Millisecond)
					signals <- syscall.SIGINT
				}()
			}
			return out.Write(p)
		})
		// After the request, the fake hypervisor copies any further console
		// input to stdin until it is killed, and records a forwarded SIGINT
		// there too.
		res, err := sup.run(fakeHypervisor(`trap '' TERM; trap 'echo int >>'"'`+stdin+`'" INT; `+startLine+`echo ready; `+readRequest()+`cat >>'`+stdin+`' & while :; do sleep 0.02; done`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		elapsed := time.Since(signalled)
		// A deadline that the second signal had moved would end at 2s.
		Expect(elapsed).To(BeNumerically(">=", sup.deadline))
		Expect(elapsed).To(BeNumerically("<", 1900*time.Millisecond))
		Expect(calls).To(Equal(1))
		Expect(res.received).To(Equal(syscall.SIGTERM))
		Expect(codeOf(res)).To(Equal(143))
		Expect(os.ReadFile(stdin)).To(Equal([]byte(stopLine)))
		Expect(logBuf.String()).To(Equal("received terminated, asking the guest command to stop\n" +
			"received interrupt again; the guest is already stopping\n" +
			"the guest did not stop within 1.5s of the signal; killing the hypervisor\n"))
	}, SpecTimeout(time.Minute))

	It("closes the ports when the guest reports its status during the stop, and keeps the deadline of the signal when the guest then hangs", func(ctx SpecContext) {
		sup.deadline = time.Second
		sup.closePorts = func() { sup.logger.Print("closing the ports") }
		var signalled time.Time
		sup.stdout = writerFunc(func(p []byte) (int, error) {
			if signalled.IsZero() {
				signalled = time.Now()
				signals <- syscall.SIGTERM
			}
			return out.Write(p)
		})
		res, err := sup.run(fakeHypervisor(`trap '' TERM INT; `+startLine+`echo ready; `+readRequest()+`sleep 0.3; `+exitLine("0")+`exec sleep 60`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		elapsed := time.Since(signalled)
		// The grace after the marker would end at 5.3s.
		Expect(elapsed).To(BeNumerically(">=", sup.deadline))
		Expect(elapsed).To(BeNumerically("<", 3*time.Second))
		Expect(codeOf(res)).To(Equal(0))
		Expect(logBuf.String()).To(Equal("received terminated, asking the guest command to stop\n" +
			"closing the ports\n" +
			"the guest did not stop within 1s of the signal; killing the hypervisor\n"))
	}, SpecTimeout(time.Minute))

	It("forwards a repeated signal when it forwarded the first", func(ctx SpecContext) {
		sup.deadline = 300 * time.Millisecond
		trapped := filepath.Join(dir, "trapped")
		sup.started = func() {
			defer GinkgoRecover()
			waitForFile(trapped)
			signals <- syscall.SIGTERM
			signals <- syscall.SIGINT
		}
		res, err := sup.run(fakeHypervisor(`trap 'echo term >>'"'`+stdin+`'" TERM; trap 'echo int >>'"'`+stdin+`'" INT; : >'`+trapped+`'; while :; do sleep 0.02; done`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.received).To(Equal(syscall.SIGTERM))
		Expect(codeOf(res)).To(Equal(143))
		// The shell may run the two traps in either order.
		Expect(os.ReadFile(stdin)).To(Or(Equal([]byte("term\nint\n")), Equal([]byte("int\nterm\n"))))
		Expect(logBuf.String()).To(Equal("received terminated before the guest started its command, forwarding it to the hypervisor\n" +
			"received interrupt, forwarding it to the hypervisor\n" +
			"the guest did not stop within 300ms of the signal; killing the hypervisor\n" +
			"guest never started its command and wrote no console output\n"))
	}, SpecTimeout(time.Minute))

	It("never acts on stop data that the guest writes", func(ctx SpecContext) {
		sup.closePorts = func() { sup.logger.Print("closing the ports") }
		res, err := sup.run(fakeHypervisor(startLine+`printf '`+stopTag(testNonce)+`\r\n`+stopTag(testNonce)+`=0\r\nreceived terminated\r\n'; sleep 0.3; `+exitLine("3")), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(3))
		Expect(res.received).To(BeZero())
		Expect(out.String()).To(Equal(stopLine + stopTag(testNonce) + "=0\nreceived terminated\n"))
		Expect(logBuf.String()).To(BeEmpty())
	}, SpecTimeout(time.Minute))

	It("leaves no descriptor of its own open once it has returned", func(ctx SpecContext) {
		before := openFDs()
		sup.stdout = &signalOnWrite{w: out, signals: signals, sig: syscall.SIGTERM}
		res, err := sup.run(fakeHypervisor(startLine+`echo ready; `+readRequest()+exitLine("0")), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(0))
		Expect(openFDs()).To(Equal(before))

		_, err = sup.run(exec.Command("/nonexistent/qemu"), testNonce)
		Expect(err).To(HaveOccurred())
		Expect(openFDs()).To(Equal(before))
	}, SpecTimeout(time.Minute))

	It("keeps each port as the guest reports it while the guest command drains, and closes the rest when the guest reports its status", func(ctx SpecContext) {
		openers := map[int]*fakeOpener{8080: {}, 8081: {}}
		gates := startPortGates([]int{8080, 8081}, func(port int) portOpener { return openers[port] }, backoff{first: 5 * time.Millisecond, max: 20 * time.Millisecond}, sup.logger)
		DeferCleanup(gates.end)
		sup.closePorts = gates.shutDown
		sup.listen = gates.set
		checked := filepath.Join(dir, "checked")
		sent := false
		sup.stdout = writerFunc(func(p []byte) (int, error) {
			if !sent {
				sent = true
				defer GinkgoRecover()
				Eventually(openers[8080].got, 10*time.Second, 5*time.Millisecond).Should(Equal([]string{"open"}))
				Eventually(openers[8081].got, 10*time.Second, 5*time.Millisecond).Should(Equal([]string{"open"}))
				signals <- syscall.SIGTERM
				go func() {
					defer GinkgoRecover()
					// The port the app closed during the drain closes at
					// once, while the other one stays open.
					Eventually(openers[8080].got, 10*time.Second, 5*time.Millisecond).Should(Equal([]string{"open", "close"}))
					Consistently(openers[8081].got, 200*time.Millisecond, 5*time.Millisecond).Should(Equal([]string{"open"}))
					Expect(os.WriteFile(checked, nil, 0o600)).To(Succeed())
				}()
			}
			return out.Write(p)
		})
		listen := func(port, up string) string {
			return `printf 'RVM_LISTEN_` + testNonce + `=` + port + `:` + up + `\r\n'; `
		}
		res, err := sup.run(fakeHypervisor(startLine+listen("8080", "1")+listen("8081", "1")+`echo ready; `+readRequest()+listen("8080", "0")+`while [ ! -e '`+checked+`' ]; do sleep 0.02; done; `+exitLine("0")+`sleep 0.3`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(checked).To(BeAnExistingFile())
		Expect(openers[8081].got()).To(Equal([]string{"open", "close"}))
		gates.end()
		Expect(codeOf(res)).To(Equal(0), logBuf.String())
		Expect(out.String()).To(Equal("ready\n"))
		Expect(openers[8080].got()).To(Equal([]string{"open", "close"}))
		Expect(openers[8081].got()).To(Equal([]string{"open", "close"}))
		// Each port has a goroutine of its own, so the two ports open in
		// either order.
		lines := strings.Split(strings.TrimSuffix(logBuf.String(), "\n"), "\n")
		Expect(lines).To(HaveLen(5), logBuf.String())
		Expect(lines[:2]).To(ConsistOf("the guest listens on port 8080; it is open in the container",
			"the guest listens on port 8081; it is open in the container"))
		Expect(lines[2:]).To(Equal([]string{"received terminated, asking the guest command to stop",
			"the guest no longer listens on port 8080; it is closed in the container",
			"vm-launch is stopping; port 8081 is closed in the container"}))
	}, SpecTimeout(time.Minute))

	It("never opens a port again for a listen report once it has closed the ports", func(ctx SpecContext) {
		openers := map[int]*fakeOpener{8080: {}}
		gates := startPortGates([]int{8080}, func(port int) portOpener { return openers[port] }, backoff{first: 5 * time.Millisecond, max: 20 * time.Millisecond}, sup.logger)
		DeferCleanup(gates.end)
		closed := filepath.Join(dir, "closed")
		trapped := filepath.Join(dir, "trapped")
		sup.closePorts = func() {
			gates.shutDown()
			Expect(os.WriteFile(closed, nil, 0o600)).To(Succeed())
		}
		sup.listen = gates.set
		sup.started = func() {
			defer GinkgoRecover()
			waitForFile(trapped)
			signals <- syscall.SIGTERM
		}
		listen := `printf 'RVM_LISTEN_` + testNonce + `=8080:1\r\n'; `
		// The forwarded signal closes the ports before the guest has
		// started, and the guest, which ignores it, then reports the port
		// up again and again.
		res, err := sup.run(fakeHypervisor(`trap '' TERM; : >'`+trapped+`'; while [ ! -e '`+closed+`' ]; do sleep 0.02; done; `+startLine+`for i in 1 2 3 4 5; do `+listen+`sleep 0.05; done; `+exitLine("0")), testNonce)
		Expect(err).NotTo(HaveOccurred())
		gates.end()
		Expect(res.markerFound).To(BeTrue())
		Expect(openers[8080].got()).To(BeEmpty())
	}, SpecTimeout(time.Minute))

	DescribeTable("refuses a kill grace or stop deadline that is not positive, before it starts anything",
		func(grace, deadline time.Duration) {
			sup.grace, sup.deadline = grace, deadline
			ran := filepath.Join(dir, "ran")
			_, err := sup.run(fakeHypervisor(`: >'`+ran+`'`), testNonce)
			Expect(err).To(MatchError(ContainSubstring("must both be positive")))
			Consistently(ran, 100*time.Millisecond).ShouldNot(BeAnExistingFile())
		},
		Entry("no deadline", time.Second, time.Duration(0)),
		Entry("no grace", time.Duration(0), time.Second),
		Entry("a negative deadline", time.Second, -time.Second),
	)

	It("refuses a hypervisor command whose stdin is already set", func(ctx SpecContext) {
		cmd := fakeHypervisor(`exit 0`)
		cmd.Stdin = strings.NewReader("")
		_, err := sup.run(cmd, testNonce)
		Expect(err).To(MatchError("the hypervisor's stdin is already set"))
		Expect(cmd.Process).To(BeNil())
	}, SpecTimeout(time.Minute))
})

var _ = Describe("run at a stop signal", func() {
	// stopHelper runs vm-launch in a helper process with a fake QEMU that
	// prints the start tag, then ready, and then runs guest, a bash script
	// that may use $nonce. Once ready shows, it sends the helper SIGTERM,
	// and it returns the helper's exit status, stdout, and stderr, and the
	// time from the signal to the helper's exit.
	stopHelper := func(guest string) (int, string, string, time.Duration) {
		art := makeArtifacts()
		script := `#!/bin/bash
for a in "$@"; do
	case "$prev" in -initrd) initrd=$a ;; esac
	prev=$a
done
nonce=$(gzip -dc "$initrd" | grep -a -o 'RVM_START_[0-9a-f]*' | head -n 1 | cut -d_ -f3)
echo "RVM_START_$nonce"
echo ready
` + guest
		loader := filepath.Join(art, "qemu/ld-linux-x86-64.so.2")
		Expect(os.Remove(loader)).To(Succeed())
		Expect(os.WriteFile(loader, []byte(script), 0o755)).To(Succeed())

		var stdout, stderr safeBuffer
		cmd := exec.Command(os.Args[0])
		cmd.Env = []string{helperArtifacts + "=" + art, "TMPDIR=" + GinkgoT().TempDir(), "PATH=" + os.Getenv("PATH")}
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		Expect(cmd.Start()).To(Succeed())
		done := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(done)
		}()
		DeferCleanup(func() { _ = cmd.Process.Kill() })
		// vm-launch catches SIGTERM before it starts the hypervisor.
		Eventually(stdout.String, 20*time.Second, 10*time.Millisecond).Should(Equal("ready\n"))
		Expect(cmd.Process.Signal(syscall.SIGTERM)).To(Succeed())
		signalled := time.Now()
		Eventually(done, 30*time.Second).Should(BeClosed(), stderr.String())
		elapsed := time.Since(signalled)
		Expect(cmd.ProcessState.Sys().(syscall.WaitStatus).Signaled()).To(BeFalse(), stderr.String())
		return cmd.ProcessState.ExitCode(), stdout.String(), stderr.String(), elapsed
	}

	It("lets the guest command drain and exits 0 with it", func(ctx SpecContext) {
		code, stdout, stderr, _ := stopHelper(`trap 'echo "the signal was forwarded" >&2; exit 99' TERM INT
IFS= read -r line
[ "$line" = "RVM_STOP_$nonce" ] && echo "got the stop request"
echo "RVM_EXIT_$nonce=0"
`)
		Expect(code).To(Equal(0), stderr)
		Expect(stdout).To(Equal("ready\ngot the stop request\n"))
		Expect(stderr).To(ContainSubstring("vm-launch: received terminated, asking the guest command to stop\n"))
		Expect(stderr).NotTo(ContainSubstring("forwarded"))
	}, SpecTimeout(time.Minute))

	It("kills a hypervisor whose guest has not stopped 8 seconds after the signal, and exits 143", func(ctx SpecContext) {
		code, stdout, stderr, elapsed := stopHelper(`trap '' TERM INT
IFS= read -r line
exec sleep 60
`)
		Expect(code).To(Equal(143), stderr)
		Expect(stdout).To(Equal("ready\n"))
		Expect(elapsed).To(BeNumerically(">=", 8*time.Second))
		Expect(elapsed).To(BeNumerically("<", 11*time.Second))
		Expect(stderr).To(ContainSubstring("vm-launch: received terminated, asking the guest command to stop\n" +
			"vm-launch: the guest did not stop within 8s of the signal; killing the hypervisor\n"))
		Expect(stderr).To(HaveSuffix("vm-launch: stopped by terminated before the guest reported a status; exiting 143\n"))
	}, SpecTimeout(time.Minute))
})
