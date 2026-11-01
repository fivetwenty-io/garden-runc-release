//go:build linux

package main

import (
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// realSidecarLauncher is the launcher of the sidecar guest's app. It reports
// who it runs as, where, and the identity pair it finds, and then checks the
// certificate each second and prints the pair again once a push has replaced
// it. A stop's SIGTERM makes it exit 7, after the sleep it waits on ends.
// The test stack has no sleep applet of its own, so the launcher runs
// busybox's through the binary.
const realSidecarLauncher = `#!/bin/sh
trap 'echo app-got-term; exit 7' TERM
creds=/etc/cf-instance-credentials
echo "app-id=$(id)"
echo "app-$(grep NoNewPrivs /proc/self/status | tr -d '[:space:]')"
echo "app-cwd=$(pwd)"
echo "app-creds=$(stat -c '%n %a %u' $creds/instance.crt $creds/instance.key | tr '\n' ' ')"
echo app-pair-begin
cat $creds/instance.crt $creds/instance.key
echo app-pair-end
first=$(cat $creds/instance.crt)
while :; do
	if [ "$(cat $creds/instance.crt)" != "$first" ]; then
		echo app-renewed-begin
		cat $creds/instance.crt $creds/instance.key
		echo app-renewed-end
		first=$(cat $creds/instance.crt)
	fi
	/bin/busybox sleep 1
done
`

// realSidecarScript is the sidecar's own script, which sh -c runs from the
// stack. It reports who it runs as, where, and the variable its own
// environment sets, and a stop's SIGTERM makes it exit 0.
const realSidecarScript = `trap 'echo sidecar-got-term; exit 0' TERM
echo "sidecar-id=$(id)"
echo "sidecar-$(grep NoNewPrivs /proc/self/status | tr -d '[:space:]')"
echo "sidecar-cwd=$(pwd)"
echo "sidecar-mark=$SIDECAR_MARK"
echo sidecar-ready
while :; do /bin/busybox sleep 1; done
`

// allWriter passes guest output to w and calls fire once, from the console
// goroutine, when the output so far holds every one of texts.
type allWriter struct {
	w     *safeBuffer
	texts []string
	fire  func()
	once  sync.Once
}

func (a *allWriter) Write(p []byte) (int, error) {
	n, err := a.w.Write(p)
	out := a.w.String()
	for _, text := range a.texts {
		if !strings.Contains(out, text) {
			return n, err
		}
	}
	a.once.Do(a.fire)
	return n, err
}

// realCredAck is one acknowledgement of an identity push.
type realCredAck struct {
	seq int
	ok  bool
}

// realSidecarRun is one supervised run of a real stack guest with a sidecar
// that a spec stopped.
type realSidecarRun struct {
	realStop
	acks    []realCredAck
	pushErr error
}

// superviseRealSidecar boots a stack guest under TCG through the
// supervisor, as vm-launch runs QEMU, with realSidecarLauncher as its app,
// one sidecar that runs realSidecarScript, and initial as the identity pair
// in its initramfs. Once the guest has started its command, it pushes next
// as push number 1. Once the output shows that the sidecar is ready and that
// the app has seen the pushed pair, it sends the supervisor SIGTERM.
func superviseRealSidecar(initial, next testIdentityPair) realSidecarRun {
	art := realArtifacts()
	qemu := realQEMU()
	requireMicrovm(qemu)
	sd := &stackDrives{stack: realStackImage(art), droplet: realDropletImage(art)}

	launcher := writeTempFile("launcher", realSidecarLauncher)
	lf, err := os.Open(launcher)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(lf.Close)
	g := taskGuest("")
	g.stack = &guestStack{
		launcher: guestTool{name: "launcher", file: lf, size: int64(len(realSidecarLauncher))},
		argv:     shellJoin([]string{stackLauncherPath, "/home/vcap/app", "", `{"start_command":"./app","process_type":"web"}`}),
		cwd:      "/home/vcap",
		hostname: "stack-guest-0",
		hosts:    []byte("127.0.0.1 localhost\n"),
		sidecars: []guestSidecar{{
			argv: shellJoin([]string{"/bin/sh", "-c", realSidecarScript}),
			env:  "export SIDECAR_MARK='from the sidecar env'\n",
		}},
		identity: &instanceIdentity{cert: initial.crt, key: initial.key},
	}
	g.drives, err = newGuestDrivesWithStack(backend.VMQemu, nil, nil, sd)
	Expect(err).NotTo(HaveOccurred())
	f := newRealInitramfs(g)

	var r realSidecarRun
	bootWithRetry(func() bool {
		files, drives, initrdPath, _, rootPath := hypervisorFilesWithStack(nil, withUserspaceMark(f), nil, nil, sd)
		hvArgv, err := hypervisorArgvWithStack(backend.VMQemu, art, GinkgoT().TempDir(), initrdPath, minGuestMemoryMiB, g.nw, drives, rootPath, 0, sd)
		Expect(err).NotTo(HaveOccurred())
		consoleLog := filepath.Join(GinkgoT().TempDir(), "console.log")
		cmd := newHypervisorCmd(consoleLogArgv(markedArgv(tcgArgv(qemu, hvArgv)), consoleLog), files)
		stderr := &safeBuffer{}
		cmd.Stderr = stderr
		out, logBuf := &safeBuffer{}, &safeBuffer{}
		console := newBootWriter(realBootMark)
		stopTail := make(chan struct{})
		tailed := tailFile(consoleLog, console, stopTail)

		signals := make(chan os.Signal, 1)
		var signalled time.Time
		fire := func() {
			signalled = time.Now()
			signals <- syscall.SIGTERM
		}
		var mu sync.Mutex
		var acks []realCredAck
		pushed := make(chan error, 1)
		var qemuProc *os.Process
		running := make(chan struct{})
		sup := supervisor{
			stdout:   &allWriter{w: out, texts: []string{"sidecar-ready\n", "app-renewed-end\n"}, fire: fire},
			logger:   log.New(logBuf, "", 0),
			signals:  signals,
			grace:    killGrace,
			deadline: stopDeadline,
			started: func() {
				qemuProc = cmd.Process
				close(running)
			},
			credAck: func(seq int, ok bool) {
				mu.Lock()
				defer mu.Unlock()
				acks = append(acks, realCredAck{seq: seq, ok: ok})
			},
			onConsole: func(w *consoleWriter) {
				go func() {
					pushed <- w.push(credFrames(testNonce, 1, &instanceIdentity{cert: next.crt, key: next.key}))
				}()
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
		ended := time.Now()
		close(stopTail)
		<-tailed
		if !booted {
			return false
		}
		Expect(runErr).NotTo(HaveOccurred())
		Expect(console.String()).To(ContainSubstring(realBootMark), "QEMU exited before the guest started userspace\n%s", details())
		GinkgoWriter.Printf("%s\n", details())
		var pushErr error
		select {
		case pushErr = <-pushed:
		default:
			Fail("the identity push never finished\n" + details())
		}
		mu.Lock()
		defer mu.Unlock()
		r = realSidecarRun{
			realStop: realStop{res: res, out: strings.ReplaceAll(out.String(), "\r", ""), log: logBuf.String(), signalled: signalled, ended: ended},
			acks:     acks,
			pushErr:  pushErr,
		}
		return true
	})
	return r
}

// pairBetween returns the text of out between the lines begin and end.
func pairBetween(out, begin, end string) string {
	m := regexp.MustCompile(`(?s)` + begin + `\n(.*?)` + end + `\n`).FindStringSubmatch(out)
	Expect(m).NotTo(BeNil(), out)
	return m[1]
}

var _ = Describe("a stack guest with a sidecar and an instance identity against a real QEMU", func() {
	var initial, next testIdentityPair

	BeforeEach(func() {
		initial = newTestIdentityPair(1, "ec")
		next = newTestIdentityPair(2, "rsa")
	})

	It("runs the sidecar from the stack as vcap in the app's working directory, installs and replaces the pair at /etc/cf-instance-credentials, and stops both within the guest's timeout", func() {
		r := superviseRealSidecar(initial, next)
		out := r.out

		Expect(out).To(MatchRegexp(`(?m)^app-id=uid=2000\(vcap\) gid=2000\(vcap\) groups=2000\(vcap\)$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-NoNewPrivs:1$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-cwd=/home/vcap$`), out)
		Expect(out).To(MatchRegexp(`(?m)^sidecar-id=uid=2000\(vcap\) gid=2000\(vcap\) groups=2000\(vcap\)$`), out)
		Expect(out).To(MatchRegexp(`(?m)^sidecar-NoNewPrivs:1$`), out)
		Expect(out).To(MatchRegexp(`(?m)^sidecar-cwd=/home/vcap$`), out)
		Expect(out).To(MatchRegexp(`(?m)^sidecar-mark=from the sidecar env$`), out)

		Expect(out).To(MatchRegexp(`(?m)^app-creds=/etc/cf-instance-credentials/instance.crt 644 0 /etc/cf-instance-credentials/instance.key 644 0 $`), out)
		Expect(pairBetween(out, "app-pair-begin", "app-pair-end")).To(Equal(string(initial.crt) + string(initial.key)))
		Expect(r.pushErr).NotTo(HaveOccurred())
		Expect(r.acks).To(Equal([]realCredAck{{seq: 1, ok: true}}))
		Expect(pairBetween(out, "app-renewed-begin", "app-renewed-end")).To(Equal(string(next.crt) + string(next.key)))

		Expect(r.res.markerFound).To(BeTrue(), r.log)
		Expect(codeOf(r.res)).To(Equal(7), out)
		Expect(out).To(MatchRegexp(`(?m)^app-got-term$`), out)
		Expect(out).To(MatchRegexp(`(?m)^sidecar-got-term$`), out)
		Expect(out).NotTo(ContainSubstring("did not all exit within"))
		Expect(r.ended.Sub(r.signalled)).To(BeNumerically("<", stopDeadline))
		Expect(r.log).To(Equal("received terminated, asking the guest command to stop\n"))
	})
})
