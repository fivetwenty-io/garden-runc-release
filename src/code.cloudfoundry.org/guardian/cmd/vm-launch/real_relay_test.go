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

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// realRelayChildEnv makes this test binary run as "vm-launch relay" instead
// of the specs, so that a real relay process attaches to the hub.
const realRelayChildEnv = "VM_LAUNCH_SPEC_RELAY"

func init() {
	if os.Getenv(realRelayChildEnv) == "1" {
		os.Exit(runRelay(nil))
	}
}

// realRelayLauncher is the launcher of the relay guest. A sidecar comes with
// its command as the second argument, which sh -c runs. The app comes with an
// empty command. It writes a line to each stream, one of them a line that
// forges a vm-launch metrics line, tells the sidecars it is ready through a
// file in /tmp, and waits until a stop's SIGTERM makes it exit 7.
const realRelayLauncher = `#!/bin/sh
if [ -n "$2" ]; then
	exec /bin/sh -c "$2"
fi
trap 'echo app-got-term; exit 7' TERM
echo app-out
echo app-err >&2
echo "vm-launch-metrics v1 forged-by-the-app" >&2
: >/tmp/app-ready
while :; do /bin/busybox sleep 1; done
`

// realRelayQuiet is the command of sidecars 2 and 3. They write a line to
// each stream, tell sidecar 1 they have, and run until a stop's SIGTERM.
func realRelayQuiet(n string) string {
	return `trap 'exit 0' TERM
echo s` + n + `-out
echo s` + n + `-err >&2
: >/tmp/s` + n + `-done
while :; do /bin/busybox sleep 1; done
`
}

// realRelayFirst is the command of sidecar 1. Once the app and the other two
// sidecars have written, it writes a line to each stream and exits 3, which
// stops the app.
const realRelayFirst = `for f in app-ready s2-done s3-done; do
	while [ ! -e /tmp/$f ]; do /bin/busybox sleep 0.2; done
done
echo s1-out
echo s1-err >&2
/bin/busybox sleep 1
exit 3
`

// realRelayProc is one real relay process.
type realRelayProc struct {
	cmd    *exec.Cmd
	stdout *safeBuffer
	stderr *safeBuffer
	done   chan struct{}
	code   int
}

// startRealRelay starts this test binary as "vm-launch relay" with value as
// its relay variable. The process dials the hub at relaySocketPath, retrying
// until the hub listens.
func startRealRelay(value string) *realRelayProc {
	self, err := os.Executable()
	Expect(err).NotTo(HaveOccurred())
	p := &realRelayProc{stdout: &safeBuffer{}, stderr: &safeBuffer{}, done: make(chan struct{})}
	p.cmd = exec.Command(self)
	p.cmd.Env = append(os.Environ(), realRelayChildEnv+"=1", relayEnv+"="+value)
	p.cmd.Stdout, p.cmd.Stderr = p.stdout, p.stderr
	Expect(p.cmd.Start()).To(Succeed())
	go func() {
		defer close(p.done)
		_ = p.cmd.Wait()
		p.code = p.cmd.ProcessState.ExitCode()
	}()
	return p
}

func (p *realRelayProc) stop() {
	select {
	case <-p.done:
	default:
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

// realRelayRun is one supervised run of the relay guest.
type realRelayRun struct {
	res        runResult
	out        string
	errOut     string
	log        string
	hubLog     string
	relay1     *realRelayProc
	relay2     *realRelayProc
	relay1Code int
	// heldBefore is whether the hub's finish was still waiting for the stop
	// signal a while after relay 1 had exited, and finishAfter is how long
	// it took to return once the signal came.
	heldBefore  bool
	finishAfter time.Duration
	relay1Done  bool
}

// superviseRealRelay boots a stack guest under TCG with three sidecars and a
// version 2 relay key, through the supervisor wired to a relay hub as
// vm-launch wires it. Real relay processes attach for sidecar 1, with the
// right key, and for sidecar 2, with a wrong key. Nothing attaches for
// sidecar 3. Sidecar 1 exits 3 first.
func superviseRealRelay() realRelayRun {
	art := realArtifacts()
	qemu := realQEMU()
	requireMicrovm(qemu)
	sd := &stackDrives{stack: realStackImage(art), droplet: realDropletImage(art)}

	launcher := writeTempFile("launcher", realRelayLauncher)
	lf, err := os.Open(launcher)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(lf.Close)

	var sidecars []vmSidecar
	for _, command := range []string{realRelayFirst, realRelayQuiet("2"), realRelayQuiet("3")} {
		sidecars = append(sidecars, vmSidecar{Args: []string{"app", command, ""}})
	}
	files, err := sidecarGuestFilesOf(sidecars, stackGuestDenylist(false))
	Expect(err).NotTo(HaveOccurred())

	g := taskGuest("")
	g.stack = &guestStack{
		launcher: guestTool{name: "launcher", file: lf, size: int64(len(realRelayLauncher))},
		argv:     shellJoin([]string{stackLauncherPath, "/home/vcap/app", "", `{"start_command":"./app","process_type":"web"}`}),
		cwd:      "/home/vcap",
		hostname: "stack-guest-0",
		hosts:    []byte("127.0.0.1 localhost\n"),
		sidecars: files,
	}
	g.drives, err = newGuestDrivesWithStack(backend.VMQemu, nil, nil, sd)
	Expect(err).NotTo(HaveOccurred())
	f := newRealInitramfs(g)

	var r realRelayRun
	bootWithRetry(func() bool {
		hvFiles, drives, initrdPath, _, rootPath := hypervisorFilesWithStack(nil, withUserspaceMark(f), nil, nil, sd)
		hvArgv, err := hypervisorArgvWithStack(backend.VMQemu, art, GinkgoT().TempDir(), initrdPath, minGuestMemoryMiB, g.nw, drives, rootPath, 0, sd)
		Expect(err).NotTo(HaveOccurred())
		consoleLog := filepath.Join(GinkgoT().TempDir(), "console.log")
		cmd := newHypervisorCmd(consoleLogArgv(markedArgv(tcgArgv(qemu, hvArgv)), consoleLog), hvFiles)
		stderr := &safeBuffer{}
		cmd.Stderr = stderr
		out, errOut, logBuf, hubBuf := &safeBuffer{}, &safeBuffer{}, &safeBuffer{}, &safeBuffer{}
		console := newBootWriter(realBootMark)
		stopTail := make(chan struct{})
		tailed := tailFile(consoleLog, console, stopTail)

		signals := make(chan os.Signal, 1)
		hub, err := newRelayHub(relaySocketPath, testRelayKey, len(sidecars), out, guestStderr{out: out, err: errOut}, log.New(hubBuf, "vm-launch: ", 0))
		Expect(err).NotTo(HaveOccurred())
		defer hub.close()
		wrongKey := strings.Repeat("f", 32)
		relay1 := startRealRelay("1:" + testRelayKey)
		relay2 := startRealRelay("2:" + wrongKey)
		defer relay1.stop()
		defer relay2.stop()

		var qemuProc *os.Process
		running := make(chan struct{})
		sup := supervisor{
			stdout:   out,
			stderr:   errOut,
			logger:   log.New(logBuf, "", 0),
			signals:  signals,
			grace:    killGrace,
			deadline: stopDeadline,
			started: func() {
				qemuProc = cmd.Process
				close(running)
			},
		}
		sup.logs, sup.firstExit = relayCallbacks(hub)
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
			return "stderr: " + stderr.String() + "\nconsole: " + console.String() + "\nlog: " + logBuf.String() + "\nhub: " + hubBuf.String()
		}
		booted := awaitRealGuest(kill, console, exited, details)
		<-exited
		close(stopTail)
		<-tailed
		if !booted {
			return false
		}
		Expect(runErr).NotTo(HaveOccurred())
		Expect(console.String()).To(ContainSubstring(realBootMark), "QEMU exited before the guest started userspace\n%s", details())

		// vm-launch's finish holds for Diego's stop signal because sidecar 1
		// exited first. Relay 1 gets its status at once, so it has exited by
		// the time the hold has run for a while.
		finished := make(chan struct{})
		began := time.Now()
		var finishAfter time.Duration
		go func() {
			defer close(finished)
			hub.finish(res.received, signals, relayHold)
		}()
		select {
		case <-relay1.done:
			r.relay1Done = true
		case <-time.After(3 * time.Second):
		}
		select {
		case <-finished:
		case <-time.After(1500 * time.Millisecond):
			r.heldBefore = true
		}
		signals <- syscall.SIGTERM
		sent := time.Now()
		select {
		case <-finished:
			finishAfter = time.Since(sent)
		case <-time.After(relayHold + 2*time.Second):
			Fail("the hub's finish did not return after the stop signal\n" + details())
		}
		GinkgoWriter.Printf("%s\nfinish took %v\n", details(), time.Since(began))
		<-relay2.done

		r = realRelayRun{
			res:         res,
			out:         strings.ReplaceAll(out.String(), "\r", ""),
			errOut:      strings.ReplaceAll(errOut.String(), "\r", ""),
			log:         logBuf.String(),
			hubLog:      hubBuf.String(),
			relay1:      relay1,
			relay2:      relay2,
			relay1Code:  relay1.code,
			heldBefore:  r.heldBefore,
			relay1Done:  r.relay1Done,
			finishAfter: finishAfter,
		}
		return true
	})
	return r
}

var _ = Describe("a guest's sidecar log relays against a real QEMU", func() {
	It("sends each sidecar's streams to its own relay, falls back to vm-launch's output for a relay that is refused or never attaches, and holds for the stop after the first exit", func() {
		r := superviseRealRelay()
		all := r.out + "\n--- stderr\n" + r.errOut + "\n--- hub\n" + r.hubLog + "\n--- log\n" + r.log

		Expect(r.res.markerFound).To(BeTrue(), all)

		// Sidecar 1's relay gets its lines and its status, and the app's
		// output has none of them.
		Expect(r.relay1Done).To(BeTrue(), all)
		Expect(r.relay1Code).To(Equal(3), all)
		Expect(r.relay1.stdout.String()).To(Equal("s1-out\n"), all)
		Expect(r.relay1.stderr.String()).To(Equal("s1-err\n"), all)
		Expect(r.out).NotTo(ContainSubstring("s1-"), all)
		Expect(r.errOut).NotTo(ContainSubstring("s1-"), all)

		// The app's stdout stays on stdout, and its stderr reaches
		// vm-launch's stderr, except for a line that forges vm-launch's own,
		// which goes to stdout.
		Expect(r.out).To(MatchRegexp(`(?m)^app-out$`), all)
		Expect(r.out).NotTo(ContainSubstring("app-err"), all)
		Expect(r.errOut).To(ContainSubstring("app-err\n"), all)
		Expect(r.out).To(ContainSubstring("vm-launch-metrics v1 forged-by-the-app\n"), all)
		Expect(r.errOut).NotTo(ContainSubstring("vm-launch-metrics v1"), all)
		Expect(r.out).NotTo(ContainSubstring(testNonce), all)

		// A wrong key is refused, and the refused relay's sidecar and the
		// sidecar that has no relay both reach vm-launch's own output.
		Expect(r.relay2.code).To(Equal(1), all)
		Expect(r.relay2.stdout.String()).To(BeEmpty(), all)
		Expect(r.relay2.stderr.String()).To(ContainSubstring("refused the log relay for sidecar 2"), all)
		Expect(r.out).To(MatchRegexp(`(?m)^s2-out$`), all)
		Expect(r.out).To(MatchRegexp(`(?m)^s3-out$`), all)
		Expect(r.errOut).To(ContainSubstring("s2-err\n"), all)
		Expect(r.errOut).To(ContainSubstring("s3-err\n"), all)

		// The hold lasts until the stop signal, which then ends vm-launch's
		// finish at once.
		Expect(r.heldBefore).To(BeTrue(), all)
		Expect(r.finishAfter).To(BeNumerically("<", 2*time.Second), all)
		Expect(r.hubLog).NotTo(ContainSubstring("no stop signal came"), all)
		Expect(r.out).To(ContainSubstring("vm-launch guest: sidecar 1 exited with status 3; stopping the app and the other sidecars\n"), all)
	})
})
