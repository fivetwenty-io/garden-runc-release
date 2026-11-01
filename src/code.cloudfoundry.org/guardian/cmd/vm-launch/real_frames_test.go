//go:build linux

package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// realFramesLauncher is the launcher of the framed-output guest. A sidecar
// comes with its command as the second argument, which sh -c runs. The app
// comes with an empty command, and it then writes a line to each stream,
// lists what its open file descriptors name, tries to open the console and
// the serial port for reading, tells the sidecar it is ready through a file
// in /tmp, and waits until a stop's SIGTERM makes it exit 7.
const realFramesLauncher = `#!/bin/sh
if [ -n "$2" ]; then
	exec /bin/sh -c "$2"
fi
trap 'echo app-got-term; exit 7' TERM
echo app-out
echo app-err >&2
for f in /proc/$$/fd/*; do
	echo "app-fd=${f##*/} $(/bin/busybox readlink "$f")"
done
for d in /dev/console /dev/ttyS0; do
	if (exec 9<"$d") 2>/dev/null; then echo "app-read=$d opened"; else echo "app-read=$d denied"; fi
done
echo app-ready
: >/tmp/app-ready
while :; do /bin/busybox sleep 1; done
`

// realFramesSidecar is the sidecar's command. Once the app is ready, it
// writes a line to each stream and a line of 3000 bytes, which the guest
// frames in four pieces, and exits 3, which stops the app.
const realFramesSidecar = `while [ ! -e /tmp/app-ready ]; do /bin/busybox sleep 0.2; done
echo side-out
long=; i=0; while [ "$i" -lt 300 ]; do long="${long}0123456789"; i=$((i + 1)); done; echo "$long"
echo side-err >&2
exit 3
`

// realFramesRun is one supervised run of the framed-output guest.
type realFramesRun struct {
	res     runResult
	out     string
	errOut  string
	console string
	log     string
	events  []frameEvent
}

// superviseRealFrames boots a stack guest under TCG through the supervisor,
// as vm-launch runs QEMU, with realFramesLauncher as its launcher and one
// sidecar that runs realFramesSidecar. The supervisor takes the app's
// stderr, the sidecar's lines, and the first exit apart from its stdout.
func superviseRealFrames() realFramesRun {
	art := realArtifacts()
	qemu := realQEMU()
	requireMicrovm(qemu)
	sd := &stackDrives{stack: realStackImage(art), droplet: realDropletImage(art)}

	launcher := writeTempFile("launcher", realFramesLauncher)
	lf, err := os.Open(launcher)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(lf.Close)
	g := taskGuest("")
	g.stack = &guestStack{
		launcher: guestTool{name: "launcher", file: lf, size: int64(len(realFramesLauncher))},
		argv:     shellJoin([]string{stackLauncherPath, "/home/vcap/app", "", `{"start_command":"./app","process_type":"web"}`}),
		cwd:      "/home/vcap",
		hostname: "stack-guest-0",
		hosts:    []byte("127.0.0.1 localhost\n"),
		sidecars: realSidecarFiles(realFramesSidecar),
	}
	g.drives, err = newGuestDrivesWithStack(backend.VMQemu, nil, nil, sd)
	Expect(err).NotTo(HaveOccurred())
	f := newRealInitramfs(g)

	var r realFramesRun
	bootWithRetry(func() bool {
		files, drives, initrdPath, _, rootPath := hypervisorFilesWithStack(nil, withUserspaceMark(f), nil, nil, sd)
		hvArgv, err := hypervisorArgvWithStack(backend.VMQemu, art, GinkgoT().TempDir(), initrdPath, minGuestMemoryMiB, g.nw, drives, rootPath, 0, sd)
		Expect(err).NotTo(HaveOccurred())
		consoleLog := filepath.Join(GinkgoT().TempDir(), "console.log")
		cmd := newHypervisorCmd(consoleLogArgv(markedArgv(tcgArgv(qemu, hvArgv)), consoleLog), files)
		stderr := &safeBuffer{}
		cmd.Stderr = stderr
		out, errOut, logBuf := &safeBuffer{}, &safeBuffer{}, &safeBuffer{}
		console := newBootWriter(realBootMark)
		stopTail := make(chan struct{})
		tailed := tailFile(consoleLog, console, stopTail)

		var mu sync.Mutex
		var events []frameEvent
		var qemuProc *os.Process
		running := make(chan struct{})
		sup := supervisor{
			stdout:   out,
			stderr:   errOut,
			logger:   log.New(logBuf, "", 0),
			signals:  make(chan os.Signal, 1),
			grace:    killGrace,
			deadline: stopDeadline,
			started: func() {
				qemuProc = cmd.Process
				close(running)
			},
			logs: func(index int, stream byte, line string) {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, frameEvent{index: index, stream: stream, line: line})
			},
			firstExit: func(index, status int) {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, frameEvent{index: index, first: true, status: status})
			},
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
		booted := awaitRealGuest(kill, console, exited, details)
		<-exited
		close(stopTail)
		<-tailed
		if !booted {
			return false
		}
		Expect(runErr).NotTo(HaveOccurred())
		Expect(console.String()).To(ContainSubstring(realBootMark), "QEMU exited before the guest started userspace\n%s", details())
		GinkgoWriter.Printf("%s\n", details())
		mu.Lock()
		defer mu.Unlock()
		r = realFramesRun{
			res:     res,
			out:     strings.ReplaceAll(out.String(), "\r", ""),
			errOut:  strings.ReplaceAll(errOut.String(), "\r", ""),
			console: console.String(),
			log:     logBuf.String(),
			events:  events,
		}
		return true
	})
	return r
}

var _ = Describe("a stack guest's framed output against a real QEMU", func() {
	It("frames the app's and the sidecar's streams apart, joins a line of several pieces, keeps the console from the app, and names the sidecar's exit before it stops the app", func() {
		r := superviseRealFrames()
		out := r.out

		Expect(r.res.markerFound).To(BeTrue(), r.log)
		Expect(codeOf(r.res)).To(Equal(3), out)

		Expect(out).To(MatchRegexp(`(?m)^app-out$`), out)
		Expect(out).NotTo(ContainSubstring("app-err"), out)
		Expect(r.errOut).To(Equal("app-err\n"), out)
		Expect(out).NotTo(ContainSubstring("side-out"), out)
		Expect(out).NotTo(ContainSubstring("side-err"), out)
		Expect(out).NotTo(ContainSubstring(testNonce), out)
		Expect(out).To(ContainSubstring("vm-launch guest: sidecar 1 exited with status 3; stopping the app\n"), out)
		Expect(out).To(MatchRegexp(`(?m)^app-got-term$`), out)

		Expect(streamLines(r.events, 1, 'o')).To(Equal([]string{"side-out", strings.Repeat("0123456789", 300)}), out)
		Expect(streamLines(r.events, 1, 'e')).To(Equal([]string{"side-err"}), out)
		Expect(r.events).To(HaveLen(4), out)
		Expect(r.events[3]).To(Equal(frameEvent{index: 1, first: true, status: 3}), out)
		Expect(r.console).To(ContainSubstring(logTag(testNonce)+"1O "), "the 3000-byte line came in one frame")

		// The app's descriptors name /dev/null and its own log FIFOs, and
		// none names the console, the serial port, or the section's files.
		fds := map[string]string{}
		for _, line := range strings.Split(out, "\n") {
			if fd, ok := strings.CutPrefix(line, "app-fd="); ok {
				n, target, _ := strings.Cut(fd, " ")
				fds[n] = target
			}
		}
		Expect(fds).To(HaveKeyWithValue("0", "/dev/null"), out)
		Expect(fds).To(HaveKeyWithValue("1", HaveSuffix("/rvm/log/0.out")), out)
		Expect(fds).To(HaveKeyWithValue("2", HaveSuffix("/rvm/log/0.err")), out)
		for n, target := range fds {
			Expect(target).NotTo(Or(ContainSubstring("console"), ContainSubstring("ttyS"), ContainSubstring("/rvm/events"), ContainSubstring("/rvm/init"), ContainSubstring("/rvm/log/1.")), "fd %s\n%s", n, out)
		}
		Expect(out).To(MatchRegexp(`(?m)^app-read=/dev/console denied$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-read=/dev/ttyS0 denied$`), out)
	})
})
