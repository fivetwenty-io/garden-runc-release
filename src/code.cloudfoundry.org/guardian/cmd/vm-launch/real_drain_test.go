//go:build linux

package main

import (
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// timedProbe records each state that a portProbe look finds, with its time.
type timedProbe struct {
	mu   sync.Mutex
	seen []timedState
}

type timedState struct {
	at    time.Time
	state string
}

func (p *timedProbe) observe(addr string) string {
	look := &portProbe{}
	look.observe(addr)
	state := look.got()[0]
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, timedState{at: time.Now(), state: state})
	return state
}

// after returns the states found after t, with runs of the same state
// counted once.
func (p *timedProbe) after(t time.Time) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var states []string
	for _, s := range p.seen {
		if s.at.After(t) && (len(states) == 0 || states[len(states)-1] != s.state) {
			states = append(states, s.state)
		}
	}
	return states
}

var _ = Describe("draining a guest's port against a real QEMU", func() {
	It("still serves new connections on PORT while the stopped app drains, and refuses them once the app closes its listener", func() {
		art := realArtifacts()
		qemu := realQEMU()
		requireMicrovm(qemu)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		port := l.Addr().(*net.TCPAddr).Port
		Expect(l.Close()).To(Succeed())
		p := strconv.Itoa(port)
		reservation, err := reservePort(port)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(reservation.Close)

		nw := taskNetwork()
		nw.ports = []int{port}
		// The app serves PORT and, at SIGTERM, keeps serving it for a few
		// seconds, as an app does while gorouter unregisters its route,
		// then closes its listener and finishes its work.
		g := taskGuest(`mkdir -p /tmp/www && echo hello >/tmp/www/index.html
httpd -f -p ` + p + ` -h /tmp/www &
h=$!
trap 'echo draining; sleep 3; kill $h; wait $h; echo closed; sleep 2; echo drained; exit 0' TERM
echo ready
while :; do sleep 0.1; done`)
		g.nw = nw
		withRealRoot(&g)
		f, err := newInitramfs(guestBusybox(), g)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)

		var (
			res       runResult
			runErr    error
			out       *safeBuffer
			logBuf    *safeBuffer
			probe     *timedProbe
			signalled time.Time
		)
		bootWithRetry(func() bool {
			monitor, qemuEnd, err := newQMPSocket()
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(monitor.Close)
			DeferCleanup(func() { _ = qemuEnd.Close() })
			files, _, initrdPath, monitorFD, rootPath := hypervisorFiles(nil, withUserspaceMark(f), qemuEnd, realRootImage())
			consoleLog := filepath.Join(GinkgoT().TempDir(), "console.log")
			argv := consoleLogArgv(markedArgv(tcgArgv(qemu, withRealRootDrive(qemuArgv(art, initrdPath, minGuestMemoryMiB, nw, "", monitorFD), rootPath))), consoleLog)
			cmd := newHypervisorCmd(argv, files)
			stderr := &safeBuffer{}
			cmd.Stderr = stderr

			logBuf = &safeBuffer{}
			gates := startPortGates([]int{port}, func(int) portOpener {
				return qmpPort{monitor: newQMPMonitor(monitor), port: port}
			}, gateRetry, log.New(logBuf, "", 0))
			out = &safeBuffer{}
			console := newBootWriter(realBootMark)
			stopTail := make(chan struct{})
			tailed := tailFile(consoleLog, console, stopTail)
			signals := make(chan os.Signal, 1)
			var qemuProc *os.Process
			running := make(chan struct{})
			sup := supervisor{
				stdout:   out,
				logger:   log.New(logBuf, "", 0),
				signals:  signals,
				grace:    killGrace,
				deadline: stopDeadline,
				started: func() {
					_ = qemuEnd.Close()
					qemuProc = cmd.Process
					close(running)
				},
				closePorts: gates.shutDown,
				listen:     gates.set,
			}
			kill := func() {
				select {
				case <-running:
					_ = qemuProc.Kill()
				default:
				}
			}

			// The probe sends SIGTERM once the app serves PORT, and looks
			// at the port until the run ends.
			probe = &timedProbe{}
			signalled = time.Time{}
			stopProbe := make(chan struct{})
			probed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(probed)
				for {
					if probe.observe(net.JoinHostPort("127.0.0.1", p)) == "serves" && signalled.IsZero() {
						signalled = time.Now()
						signals <- syscall.SIGTERM
					}
					select {
					case <-stopProbe:
						return
					case <-time.After(100 * time.Millisecond):
					}
				}
			}()
			var stopOnce sync.Once
			stop := func() {
				stopOnce.Do(func() {
					close(stopProbe)
					<-probed
					gates.end()
					close(stopTail)
					<-tailed
				})
			}
			DeferCleanup(stop)

			exited := make(chan struct{})
			go func() {
				defer close(exited)
				res, runErr = sup.run(cmd, testNonce)
			}()
			details := func() string {
				return "stderr: " + stderr.String() + "\nconsole: " + console.String() + "\nlog: " + logBuf.String() + "\noutput: " + out.String()
			}
			booted := awaitRealGuest(kill, console, exited, details)
			stop()
			if booted {
				Expect(console.String()).To(ContainSubstring(realBootMark), "QEMU exited before the guest started userspace\n%s", details())
			}
			GinkgoWriter.Printf("%s\n", details())
			return booted
		})

		Expect(runErr).NotTo(HaveOccurred())
		Expect(signalled.IsZero()).To(BeFalse(), "the app never served PORT\n%s", logBuf.String())
		code, reason := exitCode(res)
		Expect(code).To(Equal(0), "%s\n%s\n%s", reason, logBuf.String(), out.String())
		// The guest's sh prints "Terminated" for a child that the stop's
		// SIGTERM or the app's kill ends, depending on what runs at the time.
		var said []string
		for _, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
			if line != "Terminated" {
				said = append(said, line)
			}
		}
		Expect(said).To(Equal([]string{"ready", "draining", "closed", "drained"}), out.String())

		// A connection made a second into the drain, well after the stop
		// request reached the guest, still reached the app; and once the
		// app closed its listener, the port refused connections.
		// A connection may open and find nothing in the moment between the
		// app closing its listener and the watcher's next look.
		states := probe.after(signalled.Add(time.Second))
		GinkgoWriter.Printf("port %s went %q after the first second of the drain\n", p, states)
		var served []string
		for _, s := range states {
			if s != "accepts" && (len(served) == 0 || served[len(served)-1] != s) {
				served = append(served, s)
			}
		}
		Expect(served).To(Equal([]string{"serves", "closed"}), "%q", states)
		Expect(logBuf.String()).To(Equal("the guest listens on port " + p + "; it is open in the container\n" +
			"received terminated, asking the guest command to stop\n" +
			"the guest no longer listens on port " + p + "; it is closed in the container\n"))
	})
})
