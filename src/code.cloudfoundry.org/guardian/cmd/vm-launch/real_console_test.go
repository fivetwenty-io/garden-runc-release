//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// realConsoleForgeries are the guest's status lines and the host's stop
// request, with the nonce as the shell variable n, which the console guest's
// app writes to its stdout as though it were the guest.
func realConsoleForgeries() []string {
	return []string{
		exitTag("$n") + "0",
		listenTag("$n") + "8080:1",
		oomTag("$n") + "3",
		firstTag("$n") + "1 9",
		logTag("$n") + "1o forged",
		credOKTag("$n") + "1",
		credBadTag("$n") + "2",
		stopTag("$n"),
	}
}

// realConsoleLauncher is the launcher of the console guest, a stack guest
// with neither sidecars nor an instance identity. The app gets the nonce in
// two halves as its second and third arguments, so that no single argument
// holds it. It lists what its open file descriptors name and what those of
// every process it can see name, tries to open the console, the serial
// ports, its terminal, and the kernel log for reading and for writing, and
// prints the command line and the environment of every process whose files
// it can read, the kernel's command line, and how many lines of the kernel's
// log it can read and how many of them hold the nonce. It reports each file
// outside /proc, /sys, and /dev that holds the nonce, writes every forgery from
// realConsoleForgeries to its stdout and the exit marker to its stderr, and
// waits until a stop's SIGTERM makes it exit 7.
func realConsoleLauncher() string {
	var forgeries strings.Builder
	for _, line := range realConsoleForgeries() {
		forgeries.WriteString("echo \"" + line + "\"\n")
	}
	return `#!/bin/sh
trap 'echo app-got-term; exit 7' TERM
n="$2$3"
for f in /proc/$$/fd/*; do
	echo "app-fd=${f##*/} $(/bin/busybox readlink "$f")"
done
for f in /proc/[0-9]*/fd/*; do
	t=$(/bin/busybox readlink "$f" 2>/dev/null) && echo "app-pfd=$f $t"
done
for d in /dev/console /dev/ttyS0 /dev/ttyS1 /dev/tty /dev/kmsg; do
	if (exec 9<"$d") 2>/dev/null; then echo "app-read=$d opened"; else echo "app-read=$d denied"; fi
	if (exec 9>"$d") 2>/dev/null; then echo "app-write=$d opened"; else echo "app-write=$d denied"; fi
done
for p in /proc/[0-9]*; do
	if c=$(tr '\000' ' ' 2>/dev/null <"$p/cmdline"); then echo "app-proc=${p##*/} cmd=$c"; fi
	if e=$(tr '\000' ' ' 2>/dev/null <"$p/environ"); then echo "app-proc=${p##*/} env=$e"; fi
done
echo "app-kernel=$(cat /proc/cmdline)"
echo "app-dmesg=$(/bin/busybox dmesg | /bin/busybox wc -l) $(/bin/busybox dmesg | grep -cF "$n")"
for d in /*; do
	case "$d" in
	/proc | /sys | /dev) ;;
	*) grep -rlF "$n" "$d" 2>/dev/null | while read -r f; do echo "app-holds=$f"; done ;;
	esac
done
` + forgeries.String() + `echo "` + exitTag("$n") + `0" >&2
echo app-ready
while :; do /bin/busybox sleep 1; done
`
}

// realConsoleRun is one supervised run of the console guest.
type realConsoleRun struct {
	nonce   string
	res     runResult
	out     string
	errOut  string
	console string
	log     string
	events  []frameEvent
	listens []string
	acks    []realCredAck
}

// superviseRealConsole boots the console guest under TCG through the
// supervisor, as vm-launch runs QEMU, with every callback that takes a
// status line from the console set, so that a forgery the filter took for
// the guest's would show. Once the app is ready, it sends the supervisor
// SIGTERM. The guest gets a random nonce, as vm-launch makes one, because the
// suite's fixed one is a run of hex digits that the stack's binaries hold.
func superviseRealConsole() realConsoleRun {
	nonce, err := newNonce()
	Expect(err).NotTo(HaveOccurred())
	art := realArtifacts()
	qemu := realQEMU()
	requireMicrovm(qemu)
	sd := &stackDrives{stack: realStackImage(art), droplet: realDropletImage(art)}

	script := realConsoleLauncher()
	launcher := writeTempFile("launcher", script)
	lf, err := os.Open(launcher)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(lf.Close)
	g := taskGuest("")
	g.nonce = nonce
	g.stack = &guestStack{
		launcher: guestTool{name: "launcher", file: lf, size: int64(len(script))},
		argv:     shellJoin([]string{stackLauncherPath, "/home/vcap/app", nonce[:len(nonce)/2], nonce[len(nonce)/2:]}),
		cwd:      "/home/vcap",
		hostname: "stack-guest-0",
		hosts:    []byte("127.0.0.1 localhost\n"),
	}
	g.drives, err = newGuestDrivesWithStack(backend.VMQemu, nil, nil, sd)
	Expect(err).NotTo(HaveOccurred())
	f := newRealInitramfs(g)

	var r realConsoleRun
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

		signals := make(chan os.Signal, 1)
		var mu sync.Mutex
		var events []frameEvent
		var listens []string
		var acks []realCredAck
		var qemuProc *os.Process
		running := make(chan struct{})
		sup := supervisor{
			stdout:   &allWriter{w: out, texts: []string{"app-ready\n"}, fire: func() { signals <- syscall.SIGTERM }},
			stderr:   errOut,
			logger:   log.New(logBuf, "", 0),
			signals:  signals,
			grace:    killGrace,
			deadline: stopDeadline,
			started: func() {
				qemuProc = cmd.Process
				close(running)
			},
			listen: func(port int, up bool) {
				mu.Lock()
				defer mu.Unlock()
				listens = append(listens, fmt.Sprintf("%d %t", port, up))
			},
			credAck: func(seq int, ok bool) {
				mu.Lock()
				defer mu.Unlock()
				acks = append(acks, realCredAck{seq: seq, ok: ok})
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
			res, runErr = sup.run(cmd, nonce)
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
		r = realConsoleRun{
			nonce:   nonce,
			res:     res,
			out:     strings.ReplaceAll(out.String(), "\r", ""),
			errOut:  strings.ReplaceAll(errOut.String(), "\r", ""),
			console: console.String(),
			log:     logBuf.String(),
			events:  events,
			listens: listens,
			acks:    acks,
		}
		return true
	})
	return r
}

var _ = Describe("a stack guest's console against a real QEMU", func() {
	It("keeps the console and the nonce from an app without sidecars or an identity, and takes none of the status lines the app forges for the guest's", func() {
		r := superviseRealConsole()
		out := r.out

		// The forgeries changed nothing. The app's exit status is the one
		// the stop's SIGTERM gave it, the guest's kernel killed nothing, no
		// port came up, no identity push was acknowledged, and the guest
		// reports no process's first exit, as it reports none once the host
		// has asked it to stop.
		Expect(r.res.markerFound).To(BeTrue(), r.log)
		Expect(r.res.received).To(Equal(syscall.SIGTERM), out)
		Expect(codeOf(r.res)).To(Equal(7), out)
		Expect(r.res.guestOOMKills).To(BeZero(), out)
		Expect(r.listens).To(BeEmpty(), out)
		Expect(r.acks).To(BeEmpty(), out)
		Expect(r.events).To(BeEmpty(), out)
		Expect(out).To(MatchRegexp(`(?m)^app-ready$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-got-term$`), out)

		// Each forgery came out as a line of the app's own output, word
		// for word, and the forged exit marker on its stderr too.
		for _, forged := range realConsoleForgeries() {
			line := strings.Replace(forged, "$n", r.nonce, 1)
			Expect(out).To(MatchRegexp(`(?m)^`+regexp.QuoteMeta(line)+`$`), out)
		}
		Expect(r.errOut).To(Equal(exitTag(r.nonce)+"0\n"), out)

		// The app's descriptors name /dev/null and its own log FIFOs, and no
		// descriptor it can see names the console, the serial port, or the
		// guest's own files.
		fds := map[string]string{}
		for _, line := range strings.Split(out, "\n") {
			if fd, ok := strings.CutPrefix(line, "app-fd="); ok {
				n, target, _ := strings.Cut(fd, " ")
				fds[n] = target
			}
			if pfd, ok := strings.CutPrefix(line, "app-pfd="); ok {
				Expect(pfd).NotTo(Or(ContainSubstring("console"), ContainSubstring("ttyS"), ContainSubstring("/rvm/events"), ContainSubstring("/rvm/init")), out)
				Expect(pfd).NotTo(HavePrefix("/proc/1/"), out)
			}
		}
		Expect(fds).To(HaveKeyWithValue("0", "/dev/null"), out)
		Expect(fds).To(HaveKeyWithValue("1", HaveSuffix("/rvm/log/0.out")), out)
		Expect(fds).To(HaveKeyWithValue("2", HaveSuffix("/rvm/log/0.err")), out)
		for _, d := range []string{"/dev/console", "/dev/ttyS0", "/dev/ttyS1", "/dev/tty", "/dev/kmsg"} {
			if d != "/dev/kmsg" {
				Expect(out).To(MatchRegexp(`(?m)^app-read=`+regexp.QuoteMeta(d)+` denied$`), out)
			}
			Expect(out).To(MatchRegexp(`(?m)^app-write=`+regexp.QuoteMeta(d)+` denied$`), out)
		}

		// The app reads the command line of the guest's init, so the scan
		// reached the processes that run as root, and no command line, no
		// environment it can read, no file it can read, not the kernel's
		// command line, and no line of the kernel's log, which any process
		// may read, holds the nonce.
		Expect(out).To(MatchRegexp(`(?m)^app-proc=1 cmd=`), out)
		Expect(out).NotTo(MatchRegexp(`(?m)^app-proc=1 env=`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-kernel=.*console=ttyS0`), out)
		Expect(out).NotTo(ContainSubstring("app-holds="), out)
		Expect(out).To(MatchRegexp(`(?m)^app-dmesg=[1-9][0-9]* 0$`), out)
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "app-proc=") || strings.HasPrefix(line, "app-kernel=") || strings.HasPrefix(line, "app-pfd=") {
				Expect(line).NotTo(ContainSubstring(r.nonce), out)
			}
		}
		// The framers' scripts name RVM_TAG, but no environment the app
		// can read holds it.
		Expect(out).NotTo(MatchRegexp(`(?m)^app-proc=[0-9]+ env=.*RVM_TAG`), out)
	})
})
