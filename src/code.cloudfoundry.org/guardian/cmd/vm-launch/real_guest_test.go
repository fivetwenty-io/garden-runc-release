//go:build linux

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// bootRealGuest boots a guest with contents g, the guest's busybox, and the
// real kernel under TCG, as vm-launch would with QEMU, and returns the
// console output. It fails the spec unless QEMU exits 0, and skips it
// where the real kernel, the guest's busybox, or an x86 QEMU is missing.
func bootRealGuest(g guestContents) string {
	art := realArtifacts()
	qemu := realQEMU()
	requireMicrovm(qemu)
	f, err := newInitramfs(guestBusybox(), g)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(f.Close)
	files, _, initrdPath, _ := hypervisorFiles(nil, withUserspaceMark(f), nil)
	argv := markedArgv(tcgArgv(qemu, qemuArgv(art, initrdPath, minGuestMemoryMiB, g.nw, "", 0)))
	code, stdout, stderr := bootRealQEMU(argv, files)
	Expect(code).To(Equal(0), "QEMU failed: %s\n%s", stderr, stdout)
	Expect(stdout).To(ContainSubstring(startTag(testNonce)), stdout)
	return stdout
}

// A real guest under TCG boots in a few seconds, but now and then, on a
// loaded host, its kernel cannot calibrate the TSC against the microvm's
// timers and spins before it reaches userspace. Nothing inside the guest
// ends that, so the specs that boot a real guest kill a QEMU whose kernel
// has not started userspace after realBootTimeout and boot again, up to
// realBootAttempts times. Userspace starts with a test /init that prints
// realBootMark before it runs vm-launch's /init (see withUserspaceMark), so
// a hang in vm-launch's /init is never retried: a guest that printed the
// mark and still runs after realRunTimeout fails its spec, with QEMU killed.
// Each retry is a report entry, so a passing run shows it too, and the
// suite fails a boot once it has retried realBootRetries of them, because
// that many retries is a host too loaded to test on or a kernel that hangs.
const (
	realBootTimeout  = 90 * time.Second
	realBootAttempts = 3
	realBootRetries  = 3
	realRunTimeout   = 2 * time.Minute
	realBootMark     = "RVM_TEST_USERSPACE"
	realTestInit     = "rvm-test-init"
)

// realBootRetried counts the boots that the suite has retried.
var realBootRetried atomic.Int32

// withUserspaceMark returns a copy of the initramfs f, in a sealed memfd
// as vm-launch passes it, with an archive appended that adds
// /rvm-test-init, which prints realBootMark and then runs vm-launch's /init
// as the same process, the guest's init. The kernel unpacks each archive
// of a concatenated initramfs in turn.
func withUserspaceMark(f *os.File) *os.File {
	info, err := f.Stat()
	Expect(err).NotTo(HaveOccurred())
	fd, err := createInitramfsMemfd()
	Expect(err).NotTo(HaveOccurred())
	marked := os.NewFile(uintptr(fd), "memfd:"+initramfsName+"-marked")
	DeferCleanup(marked.Close)
	_, err = io.Copy(marked, io.NewSectionReader(f, 0, info.Size()))
	Expect(err).NotTo(HaveOccurred())
	script := "#!/bin/busybox sh\necho " + realBootMark + "\nexec /init\n"
	gz := gzip.NewWriter(marked)
	cw := newCPIOWriter(gz)
	Expect(cw.File(realTestInit, 0o755, int64(len(script)), strings.NewReader(script))).To(Succeed())
	Expect(cw.Close()).To(Succeed())
	Expect(gz.Close()).To(Succeed())
	Expect(addSeals(marked, initramfsSeals)).To(Succeed())
	return marked
}

// markedArgv returns QEMU's argv with the kernel starting /rvm-test-init in
// place of /init (see withUserspaceMark).
func markedArgv(argv []string) []string {
	out := slices.Clone(argv)
	n := 0
	for i, a := range out {
		if strings.Contains(a, "rdinit=/init") {
			out[i] = strings.Replace(a, "rdinit=/init", "rdinit=/"+realTestInit, 1)
			n++
		}
	}
	Expect(n).To(Equal(1), "no single rdinit=/init in %q", argv)
	return out
}

// bootWriter collects a real guest's console output and closes booted
// once the output holds mark.
type bootWriter struct {
	mark   string
	booted chan struct{}

	mu   sync.Mutex
	buf  bytes.Buffer
	seen bool
}

func newBootWriter(mark string) *bootWriter {
	return &bootWriter{mark: mark, booted: make(chan struct{})}
}

func (w *bootWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if !w.seen && bytes.Contains(w.buf.Bytes(), []byte(w.mark)) {
		w.seen = true
		close(w.booted)
	}
	return len(p), nil
}

func (w *bootWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// consoleLogArgv returns QEMU's argv with the serial console also logged
// to path, for a spec whose console goes through a serialFilter, which
// drops the output before the start tag and with it realBootMark.
func consoleLogArgv(argv []string, path string) []string {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == "-serial" && argv[i+1] == "stdio" {
			return slices.Concat(argv[:i], []string{"-chardev", "stdio,id=rvmcon,logfile=" + path, "-serial", "chardev:rvmcon"}, argv[i+2:])
		}
	}
	Fail(fmt.Sprintf("no -serial stdio in %q", argv))
	return nil
}

// tailFile copies what is written to path into w, from a goroutine, until
// stop closes, and returns a channel that closes once it has stopped. It
// reads the file once more after stop closes, so w then holds all that the
// file held. A path that does not exist yet is tried again.
func tailFile(path string, w io.Writer, stop <-chan struct{}) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer GinkgoRecover()
		defer close(done)
		var off int64
		for {
			stopping := false
			select {
			case <-stop:
				stopping = true
			default:
			}
			f, err := os.Open(path)
			switch {
			case err == nil:
				n, err := io.Copy(w, io.NewSectionReader(f, off, 1<<62))
				off += n
				Expect(f.Close()).To(Succeed())
				Expect(err).NotTo(HaveOccurred())
			case !errors.Is(err, os.ErrNotExist):
				Expect(err).NotTo(HaveOccurred())
			}
			if stopping {
				return
			}
			select {
			case <-stop:
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()
	return done
}

// awaitRealGuest waits for a real guest whose console output w collects
// until exited closes, which it does once QEMU has been reaped. It returns
// false, with QEMU killed by kill and reaped, when the guest did not boot
// in realBootTimeout, and adds a report entry that says so. It fails the
// spec, with QEMU killed and reaped, when the guest still runs
// realRunTimeout after it booted. details describes the run for either.
func awaitRealGuest(kill func(), w *bootWriter, exited <-chan struct{}, details func() string) bool {
	select {
	case <-w.booted:
	case <-exited:
		return true
	case <-time.After(realBootTimeout):
		kill()
		<-exited
		AddReportEntry("real QEMU boot retry", fmt.Sprintf("the guest did not print %s in %v, so QEMU was killed\n%s", w.mark, realBootTimeout, details()))
		return false
	}
	select {
	case <-exited:
	case <-time.After(realRunTimeout):
		kill()
		<-exited
		Fail(fmt.Sprintf("the guest still ran %v after it booted, so QEMU was killed\n%s", realRunTimeout, details()))
	}
	return true
}

// bootWithRetry calls boot, which reports whether its guest booted, until
// one does. It fails the spec after realBootAttempts guests that did not,
// or when the suite has already retried realBootRetries boots.
func bootWithRetry(boot func() bool) {
	for attempt := 1; !boot(); attempt++ {
		if attempt == realBootAttempts {
			Fail(fmt.Sprintf("none of %d guests booted in %v", realBootAttempts, realBootTimeout))
		}
		if n := realBootRetried.Add(1); n > realBootRetries {
			Fail(fmt.Sprintf("the suite has retried %d real QEMU boots, more than the %d a healthy host needs", n, realBootRetries))
		}
	}
}

// bootRealQEMU runs QEMU with argv and files under bootWithRetry, and
// returns the exit status, the console output, and stderr of the QEMU
// whose guest booted. argv must start /rvm-test-init (see markedArgv), and
// the initrd among files must hold it (see withUserspaceMark).
func bootRealQEMU(argv []string, files []*os.File) (code int, stdout, stderr string) {
	Expect(argv).To(ContainElement(ContainSubstring("rdinit=/"+realTestInit)), "the guest would never print %s", realBootMark)
	bootWithRetry(func() bool {
		cmd := newHypervisorCmd(argv, files)
		out := newBootWriter(realBootMark)
		errOut := &safeBuffer{}
		cmd.Stdout, cmd.Stderr = out, errOut
		Expect(cmd.Start()).To(Succeed())
		exited := make(chan struct{})
		var waitErr error
		go func() {
			waitErr = cmd.Wait()
			close(exited)
		}()
		details := func() string { return "stderr: " + errOut.String() + "\nconsole:\n" + out.String() }
		if !awaitRealGuest(func() { _ = cmd.Process.Kill() }, out, exited, details) {
			return false
		}
		Expect(out.String()).To(ContainSubstring(realBootMark), "QEMU exited before the guest started userspace\n%s", details())
		var exitErr *exec.ExitError
		switch {
		case waitErr == nil:
			code = 0
		case errors.As(waitErr, &exitErr):
			code = exitErr.ExitCode()
		default:
			Expect(waitErr).NotTo(HaveOccurred())
		}
		stdout, stderr = out.String(), errOut.String()
		return true
	})
	return code, stdout, stderr
}

var _ = Describe("the guest userland against a real QEMU", func() {
	It("gives the command the CA bundle at the standard path, with SSL_CERT_FILE naming it", func() {
		dir := GinkgoT().TempDir()
		rootfs := filepath.Join(dir, "ca-certificates.crt")
		Expect(os.WriteFile(rootfs, []byte(newFixtureCert("rootfs").pem), 0o644)).To(Succeed())
		certDir := filepath.Join(dir, "system")
		Expect(os.Mkdir(certDir, 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(certDir, "trusted-ca-1.crt"), []byte(newFixtureCert("system").pem), 0o644)).To(Succeed())
		logger := log.New(GinkgoWriter, "", 0)
		bundle, err := guestCABundle([]string{rootfs}, lookupIn(map[string]string{systemCertPathEnv: certDir}), logger)
		Expect(err).NotTo(HaveOccurred())
		envFile, err := buildGuestEnv(map[string]string{sslCertFileEnv: guestCABundlePath}, minGuestMemoryMiB, logger)
		Expect(err).NotTo(HaveOccurred())
		sum := sha256.Sum256(bundle)

		g := taskGuest(`echo "certs=$(grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt) file=$SSL_CERT_FILE"
sha256sum /etc/ssl/certs/ca-certificates.crt
ls -ld /etc/ssl/certs/ca-certificates.crt`)
		g.env = envFile
		g.caBundle = bundle
		out := bootRealGuest(g)
		Expect(out).To(ContainSubstring("certs=2 file=" + guestCABundlePath))
		Expect(out).To(ContainSubstring(hex.EncodeToString(sum[:]) + "  " + guestCABundlePath))
		Expect(out).To(MatchRegexp(`-rw-r--r-- +1 0 +0 .*` + guestCABundlePath))
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})

	It("gives the command the container's open files limit above the kernel's default fs.nr_open", func() {
		g := taskGuest(`echo "soft=$(ulimit -S -n) hard=$(ulimit -H -n) nr_open=$(cat /proc/sys/fs/nr_open) file_max=$(cat /proc/sys/fs/file-max)"
echo "init=$(sed -n 's/^Max open files *\([0-9]*\) *\([0-9]*\).*/\1 \2/p' /proc/1/limits)"`)
		g.nofile = nofileLimit{soft: 1500000, hard: 2000000}
		out := bootRealGuest(g)
		Expect(out).To(ContainSubstring("soft=1500000 hard=2000000 nr_open=2000000 file_max=9223372036854775807"))
		// /init keeps the kernel's own limit; only the command gets the
		// container's.
		Expect(out).To(MatchRegexp(`init=\d+ \d+`))
		Expect(out).NotTo(ContainSubstring("init=1500000 2000000"))
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})

	It("turns off console echo and starts the stop reader, which runs beside the command with the oom killer kept off it", func() {
		out := bootRealGuest(taskGuest(`echo "echo_off=$(stty -a </dev/console | tr ' ;' '\n\n' | grep -cx -- -echo)"
echo "oom_protected=$(grep -lx -- -1000 /proc/[0-9]*/oom_score_adj 2>/dev/null | wc -l)"
echo "app=$(cat /rvm/app-pid) self=$$"`))
		Expect(out).NotTo(ContainSubstring("turning off console echo failed"))
		Expect(out).To(MatchRegexp(`(?m)^echo_off=1\r?$`))
		// The stop reader is the one process that the oom killer never picks.
		Expect(out).To(MatchRegexp(`(?m)^oom_protected=1\r?$`))
		m := regexp.MustCompile(`(?m)^app=(\d+) self=(\d+)\r?$`).FindStringSubmatch(out)
		Expect(m).NotTo(BeNil(), out)
		Expect(m[1]).To(Equal(m[2]), "the recorded pid is the command's shell")
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})

	It("gives the command a /dev/shm tmpfs of half the guest's memory, mounted as Garden mounts it", func() {
		out := bootRealGuest(taskGuest(`grep ' /dev/shm ' /proc/mounts
ls -ld /dev/shm
echo "memtotal=$(sed -n 's/^MemTotal: *\([0-9]*\) kB$/\1/p' /proc/meminfo)"
echo "shm_kib=$(df -k /dev/shm | sed -n '2s/^[^ ]*  *\([0-9]*\) .*/\1/p')"
echo shared >/dev/shm/probe && echo "wrote=$(cat /dev/shm/probe)"
cp /bin/busybox /dev/shm/bb && chmod 755 /dev/shm/bb
/dev/shm/bb true && echo exec=allowed || echo exec=denied`))
		m := regexp.MustCompile(`(?m)^tmpfs /dev/shm tmpfs (\S+) 0 0\r?$`).FindStringSubmatch(out)
		Expect(m).NotTo(BeNil(), out)
		opts := strings.Split(m[1], ",")
		Expect(opts).To(ContainElements("rw", "nosuid", "nodev", "noexec"), out)
		// The kernel leaves mode=1777 out of the options, because it is the
		// tmpfs default, so the mode is checked on the directory.
		Expect(out).To(MatchRegexp(`(?m)^drwxrwxrwt +\d+ 0 +0 .* /dev/shm\r?$`))
		// The kernel also leaves the size out when it equals the tmpfs
		// default of half the memory at the time it shows the options, which
		// moves as the kernel frees boot memory, so the size comes from df.
		kib := func(name string) uint64 {
			m := regexp.MustCompile(name + `=(\d+)`).FindStringSubmatch(out)
			Expect(m).NotTo(BeNil(), out)
			n, err := strconv.ParseUint(m[1], 10, 64)
			Expect(err).NotTo(HaveOccurred())
			return n
		}
		sizeKiB, memKiB := kib("shm_kib"), kib("memtotal")
		// tmpfs takes half of the guest's pages, so the size is within a
		// page of half of MemTotal.
		Expect(sizeKiB).To(BeNumerically("~", memKiB/2, 4), out)
		Expect(sizeKiB).To(BeNumerically("<=", minGuestMemoryMiB*1024/2), out)
		Expect(out).To(ContainSubstring("wrote=shared"))
		Expect(out).To(ContainSubstring("exec=denied"))
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})
})

var _ = Describe("a real guest that runs out of memory", func() {
	It("reports how many processes its kernel killed, and then the command's status", func() {
		// tail keeps a whole line, and a stream of zeros has no newline, so
		// it outgrows a guest of minGuestMemoryMiB and the kernel kills it.
		out := bootRealGuest(taskGuest(`head -c 400m /dev/zero | tail`))

		m := regexp.MustCompile(`(?m)^` + oomTag(testNonce) + `([0-9]+)\r?$`).FindStringSubmatch(out)
		Expect(m).NotTo(BeNil(), out)
		kills, err := strconv.Atoi(m[1])
		Expect(err).NotTo(HaveOccurred())
		Expect(kills).To(BeNumerically(">=", 1), out)
		AddReportEntry("guest oom kills", kills)
		Expect(strings.Count(out, oomTag(testNonce))).To(Equal(1), out)
		Expect(strings.Index(out, oomTag(testNonce))).To(BeNumerically("<", strings.Index(out, exitTag(testNonce)+"137")), out)

		// The same stream, through the filter, gives the count and the status
		// and leaves the guest's own kernel message in the output.
		var filtered bytes.Buffer
		f := newSerialFilter(&filtered, testNonce)
		_, _ = f.Write([]byte(out))
		f.finish()
		Expect(f.oomKills).To(Equal(kills))
		Expect(f.status).To(Equal(137))
		Expect(filtered.String()).NotTo(ContainSubstring(oomTag(testNonce)))
	})

	It("reports nothing for a command that does not run out of memory", func() {
		out := bootRealGuest(taskGuest(`echo fine`))
		Expect(out).NotTo(ContainSubstring(oomTag(testNonce)))
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})
})

// portProbe records what a connection to a port finds, over time: "closed"
// when the connection is refused, "serves" when an HTTP request through it
// gets an HTTP reply, and "accepts" when the connection opens but no reply
// comes, which is a forwarding rule with nothing behind it. Runs of the same
// state count once.
type portProbe struct {
	mu     sync.Mutex
	states []string
}

func (p *portProbe) observe(addr string) {
	state := "closed"
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		state = "accepts"
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err == nil {
			head := make([]byte, 7)
			if _, err := io.ReadFull(c, head); err == nil && string(head) == "HTTP/1." {
				state = "serves"
			}
		}
		c.Close()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.states) == 0 || p.states[len(p.states)-1] != state {
		p.states = append(p.states, state)
	}
}

func (p *portProbe) got() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.states...)
}

var _ = Describe("the port gate against a real QEMU", func() {
	It("keeps PORT closed until the guest listens on it, forwards it while it does, and closes it after", func() {
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
		// The guest boots, waits, serves PORT for a while, and stops
		// serving it well before it exits.
		g := taskGuest(`mkdir -p /tmp/www && echo hello >/tmp/www/index.html
sleep 4
httpd -f -p ` + p + ` -h /tmp/www &
h=$!
sleep 8
kill $h
wait $h
sleep 6
echo served`)
		g.nw = nw
		f, err := newInitramfs(guestBusybox(), g)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)

		type result struct {
			res runResult
			err error
		}
		var (
			r      result
			out    *safeBuffer
			stderr *safeBuffer
			logBuf *safeBuffer
			states []string
		)
		bootWithRetry(func() bool {
			monitor, qemuEnd, err := newQMPSocket()
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(monitor.Close)
			// The supervisor closes vm-launch's copy of QEMU's end once
			// QEMU has it; this closes it when QEMU never started.
			DeferCleanup(func() { _ = qemuEnd.Close() })
			files, _, initrdPath, monitorFD := hypervisorFiles(nil, withUserspaceMark(f), qemuEnd)
			consoleLog := filepath.Join(GinkgoT().TempDir(), "console.log")
			argv := consoleLogArgv(markedArgv(tcgArgv(qemu, qemuArgv(art, initrdPath, minGuestMemoryMiB, nw, "", monitorFD))), consoleLog)
			cmd := newHypervisorCmd(argv, files)
			stderr = &safeBuffer{}
			cmd.Stderr = stderr

			logBuf = &safeBuffer{}
			gate := startPortGate(qmpPort{monitor: newQMPMonitor(monitor), port: port}, port, gateRetry, log.New(logBuf, "", 0))
			out = &safeBuffer{}
			console := newBootWriter(realBootMark)
			stopTail := make(chan struct{})
			tailed := tailFile(consoleLog, console, stopTail)
			// started runs in the supervisor's goroutine once QEMU runs,
			// and hands its process to kill.
			var qemuProc *os.Process
			running := make(chan struct{})
			sup := supervisor{
				stdout:   out,
				logger:   log.New(logBuf, "", 0),
				signals:  make(chan os.Signal),
				grace:    killGrace,
				deadline: stopDeadline,
				started: func() {
					_ = qemuEnd.Close()
					qemuProc = cmd.Process
					close(running)
				},
				listen: func(_ int, up bool) { gate.set(up) },
			}
			kill := func() {
				select {
				case <-running:
					_ = qemuProc.Kill()
				default:
				}
			}

			probe := &portProbe{}
			stopProbe := make(chan struct{})
			probed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(probed)
				for {
					probe.observe(net.JoinHostPort("127.0.0.1", p))
					select {
					case <-stopProbe:
						return
					case <-time.After(100 * time.Millisecond):
					}
				}
			}()
			// stop ends the gate, the probe, and the console tail, once,
			// whether the spec gets past this attempt or fails in it.
			var stopOnce sync.Once
			stop := func() {
				stopOnce.Do(func() {
					gate.end()
					close(stopProbe)
					<-probed
					close(stopTail)
					<-tailed
				})
			}
			DeferCleanup(stop)

			exited := make(chan struct{})
			go func() {
				defer close(exited)
				res, err := sup.run(cmd, testNonce)
				r = result{res, err}
			}()
			details := func() string {
				return "stderr: " + stderr.String() + "\nconsole: " + console.String() + "\nlog: " + logBuf.String() + fmt.Sprintf("\nport %s went %q", p, probe.got())
			}
			booted := awaitRealGuest(kill, console, exited, details)
			stop()
			if booted {
				Expect(console.String()).To(ContainSubstring(realBootMark), "QEMU exited before the guest started userspace\n%s", details())
			}
			states = probe.got()
			return booted
		})

		Expect(r.err).NotTo(HaveOccurred())
		code, reason := exitCode(r.res)
		Expect(code).To(Equal(0), "%s\n%s\n%s", reason, stderr.String(), out.String())
		Expect(out.String()).To(ContainSubstring("served"))
		Expect(out.String()).NotTo(ContainSubstring("RVM_LISTEN_"))

		// A connection may open and find nothing in the moment between the
		// guest's server stopping and the watcher's next look; it may never
		// open before the guest listens.
		GinkgoWriter.Printf("port %s went %q\n", p, states)
		Expect(states[0]).To(Equal("closed"), "%q", states)
		served := []string{}
		for _, s := range states {
			if s != "accepts" {
				served = append(served, s)
			}
		}
		Expect(served).To(Equal([]string{"closed", "serves", "closed"}), "%q\n%s", states, logBuf.String())
		Expect(states[:slices.Index(states, "serves")]).NotTo(ContainElement("accepts"), "%q", states)
		Expect(logBuf.String()).To(Equal("the guest listens on port " + p + "; it is open in the container\n" +
			"the guest no longer listens on port " + p + "; it is closed in the container\n"))
	})
})
