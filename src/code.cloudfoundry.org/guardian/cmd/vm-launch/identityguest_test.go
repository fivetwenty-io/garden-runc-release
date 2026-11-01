//go:build linux

package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// guestToolsBin returns a directory holding sh for shell and the tools that
// the run section and the control reader run, to be the whole PATH of a
// guest run, as /bin is in the guest. The guest's busybox runs each tool as
// an applet of the same binary; /bin/sh gets the host's.
func guestToolsBin(shell guestShell) string {
	bin := filepath.Join(GinkgoT().TempDir(), "bin")
	Expect(os.Mkdir(bin, 0o755)).To(Succeed())
	Expect(os.Symlink(shell.argv[0], filepath.Join(bin, "sh"))).To(Succeed())
	for _, tool := range []string{"cat", "sleep", "sha256sum", "cp", "chmod", "mv", "mkdir", "mkfifo"} {
		path := shell.argv[0]
		if shell.argv[0] == hostShell().argv[0] {
			var err error
			path, err = exec.LookPath(tool)
			Expect(err).NotTo(HaveOccurred())
		}
		Expect(os.Symlink(path, filepath.Join(bin, tool))).To(Succeed())
	}
	return bin
}

// testIdentityPair is a certificate chain and its key in PEM, as Diego
// writes them.
type testIdentityPair struct{ crt, key []byte }

var (
	testRSAKeyOnce sync.Once
	testRSAKey     *rsa.PrivateKey
)

// newTestIdentityPair returns a pair whose certificate file holds a leaf
// and its issuer, as Diego's does, and whose key is in the PEM form that
// format names: "rsa" for PKCS #1, as Diego writes it, "ec" for SEC 1, and
// "pkcs8" for PKCS #8.
func newTestIdentityPair(serial int64, format string) testIdentityPair {
	var signer crypto.Signer
	var keyPEM []byte
	switch format {
	case "rsa":
		testRSAKeyOnce.Do(func() {
			var err error
			testRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
		})
		signer = testRSAKey
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testRSAKey)})
	case "ec", "pkcs8":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		signer = key
		if format == "ec" {
			der, err := x509.MarshalECPrivateKey(key)
			Expect(err).NotTo(HaveOccurred())
			keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		} else {
			der, err := x509.MarshalPKCS8PrivateKey(key)
			Expect(err).NotTo(HaveOccurred())
			keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		}
	default:
		Fail("unknown key format " + format)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: fmt.Sprintf("instance %d", serial)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	Expect(err).NotTo(HaveOccurred())
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return testIdentityPair{crt: append(append([]byte{}, leaf...), leaf...), key: keyPEM}
}

// testPushFrames returns the console lines of push seq of a pair, without
// line endings, in the form vm-launch writes them: the files' lines, and an
// end line whose digest is of the files as the guest rebuilds them.
func testPushFrames(seq int, crt, key []byte) []string {
	split := func(b []byte) []string { return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") }
	crtLines, keyLines := split(crt), split(key)
	sum := sha256.Sum256([]byte(strings.Join(crtLines, "\n") + "\n" + strings.Join(keyLines, "\n") + "\n"))
	prefix := credTag(testNonce)
	frames := []string{fmt.Sprintf("%sbegin %d", prefix, seq)}
	for _, line := range crtLines {
		frames = append(frames, prefix+"crt "+line)
	}
	for _, line := range keyLines {
		frames = append(frames, prefix+"key "+line)
	}
	return append(frames, fmt.Sprintf("%send %d %d %d %s", prefix, seq, len(crtLines), len(keyLines), hex.EncodeToString(sum[:])))
}

// consoleInput joins console lines into what vm-launch writes.
func consoleInput(lines []string) string { return strings.Join(lines, "\n") + "\n" }

// controlRun is a control reader running in a real shell, with a FIFO as
// the console that the spec writes console input to, and with every guest
// path it uses in a scratch directory.
type controlRun struct {
	cmd     *exec.Cmd
	out     string
	acks    string
	oom     string
	next    string
	cred    string
	events  string
	mvLog   string
	console *os.File
	done    chan error
}

// startControlRun runs guestControlReader for pidFiles in shell and waits
// for it, then says that it has ended. With events set, the run has a FIFO
// at the place of guestEvents, which the spec reads with eventLines. The
// script's mv logs each of its calls, so the spec can see the order of the
// renames.
func startControlRun(shell guestShell, pidFiles []string, identity, events bool) *controlRun {
	dir := GinkgoT().TempDir()
	r := &controlRun{
		out:    filepath.Join(dir, "out"),
		acks:   filepath.Join(dir, "acks"),
		oom:    filepath.Join(dir, "oom_score_adj"),
		next:   filepath.Join(dir, "next"),
		cred:   filepath.Join(dir, "cred"),
		events: filepath.Join(dir, "events"),
		mvLog:  filepath.Join(dir, "mv.log"),
		done:   make(chan error, 1),
	}
	Expect(os.Mkdir(r.next, 0o700)).To(Succeed())
	Expect(os.Mkdir(r.cred, 0o755)).To(Succeed())
	if events {
		Expect(syscall.Mkfifo(r.events, 0o600)).To(Succeed())
	}
	fifo := filepath.Join(dir, "console")
	Expect(syscall.Mkfifo(fifo, 0o600)).To(Succeed())
	// Held open for reading and writing, so the reader's open never waits
	// and its reads never see EOF, as on a serial console.
	console, err := os.OpenFile(fifo, os.O_RDWR, 0)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { _ = console.Close() })
	r.console = console

	reader := guestControlReader(testNonce, pidFiles, identity)
	Expect(strings.Count(reader, "</dev/console")).To(Equal(1))
	reader = strings.NewReplacer(
		"</dev/console", "<"+fifo,
		">/dev/console", ">>"+r.acks,
		"/proc/self/oom_score_adj", r.oom,
		guestIdentityNext, r.next,
		guestCredDir, r.cred,
		guestEvents, r.events,
	).Replace(reader)
	script := `mv() { echo "mv $*" >>` + r.mvLog + `; command mv "$@"; }
` + reader + `wait "$rvm_reader"
echo reader-done
`
	out, err := os.Create(r.out)
	Expect(err).NotTo(HaveOccurred())
	defer out.Close()
	r.cmd = exec.Command(shell.argv[0], append(shell.argv[1:], "-c", script)...)
	r.cmd.Env = []string{"PATH=" + guestToolsBin(shell)}
	r.cmd.Stdout = out
	r.cmd.Stderr = out
	r.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	Expect(r.cmd.Start()).To(Succeed())
	pgid := r.cmd.Process.Pid
	go func() { r.done <- r.cmd.Wait() }()
	DeferCleanup(func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) })
	return r
}

// write writes console input to the reader.
func (r *controlRun) write(input string) {
	_, err := r.console.WriteString(input)
	Expect(err).NotTo(HaveOccurred())
}

// output returns what the run has printed so far.
func (r *controlRun) output() string {
	out, err := os.ReadFile(r.out)
	Expect(err).NotTo(HaveOccurred())
	return string(out)
}

// answers returns the answer lines the reader has written to the console.
func (r *controlRun) answers() string {
	out, err := os.ReadFile(r.acks)
	if os.IsNotExist(err) {
		return ""
	}
	Expect(err).NotTo(HaveOccurred())
	return string(out)
}

// renames returns the mv calls the reader has made.
func (r *controlRun) renames() []string {
	out, err := os.ReadFile(r.mvLog)
	if os.IsNotExist(err) {
		return nil
	}
	Expect(err).NotTo(HaveOccurred())
	return strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
}

// finish waits up to 10 s for the shell to exit and returns its output.
// Nothing of the run may outlive the shell.
func (r *controlRun) finish() string {
	select {
	case err := <-r.done:
		Expect(err).NotTo(HaveOccurred(), r.output())
	case <-time.After(10 * time.Second):
		Fail("the run did not end within 10s:\n" + r.output())
	}
	out := r.output()
	Eventually(func() error { return syscall.Kill(-r.cmd.Process.Pid, 0) }, 2*time.Second, 10*time.Millisecond).
		Should(MatchError(syscall.ESRCH), "a process of the run outlived it:\n"+out)
	return out
}

// eventLines returns a channel that receives each line written to the
// run's events FIFO, which the spec holds open for reading and writing.
func (r *controlRun) eventLines() <-chan string {
	f, err := os.OpenFile(r.events, os.O_RDWR, 0)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(f.Close)
	lines := make(chan string, 16)
	go func() {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	return lines
}

// pidTarget is a process that a pid file names, for a stop to signal.
type pidTarget struct {
	cmd     *exec.Cmd
	pidFile string
	exited  chan error
}

// startPidTarget starts a process that runs until a signal ends it, and
// returns it with the path of its pid file, which it writes only when
// record is set.
func startPidTarget(record bool) *pidTarget {
	t := &pidTarget{
		cmd:     exec.Command("sleep", "600"),
		pidFile: filepath.Join(GinkgoT().TempDir(), "pid"),
		exited:  make(chan error, 1),
	}
	Expect(t.cmd.Start()).To(Succeed())
	DeferCleanup(func() { _ = t.cmd.Process.Kill() })
	go func() { t.exited <- t.cmd.Wait() }()
	if record {
		t.record()
	}
	return t
}

// record writes the process's pid file.
func (t *pidTarget) record() {
	Expect(os.WriteFile(t.pidFile, []byte(fmt.Sprintf("%d\n", t.cmd.Process.Pid)), 0o600)).To(Succeed())
}

// terminated reports whether SIGTERM ended the process, without waiting
// when it still runs.
func (t *pidTarget) terminated() bool {
	select {
	case err := <-t.exited:
		t.exited <- err
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				return ws.Signal() == syscall.SIGTERM
			}
		}
		Fail(fmt.Sprintf("the process ended without SIGTERM: %v", err))
	default:
	}
	return false
}

// expectInstalled checks that the run's tmpfs holds exactly pair, with mode
// 0644, and nothing else.
func expectInstalled(r *controlRun, pair testIdentityPair) {
	entries, err := os.ReadDir(r.cred)
	Expect(err).NotTo(HaveOccurred())
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	Expect(names).To(ConsistOf("instance.crt", "instance.key"))
	for name, want := range map[string][]byte{"instance.crt": pair.crt, "instance.key": pair.key} {
		path := filepath.Join(r.cred, name)
		got, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(string(want)), name)
		info, err := os.Stat(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o644)), name)
	}
}

var _ = Describe("the control reader", func() {
	stopLine := stopTag(testNonce) + "\n"
	ok := func(seq int) string { return fmt.Sprintf("%s%d\n", credOKTag(testNonce), seq) }
	bad := func(seq int) string { return fmt.Sprintf("%s%d\n", credBadTag(testNonce), seq) }

	DescribeTable("installs each complete push, answers every end line, renames the key before the certificate, and signals the app on the stop",
		func(shellOf func() guestShell) {
			shell := shellOf()
			app := startPidTarget(true)
			r := startControlRun(shell, []string{app.pidFile}, true, false)
			first, second := newTestIdentityPair(1, "rsa"), newTestIdentityPair(3, "pkcs8")
			other := newTestIdentityPair(2, "ec")

			r.write(consoleInput(testPushFrames(1, first.crt, first.key)))
			Eventually(r.answers, 10*time.Second, 10*time.Millisecond).Should(Equal(ok(1)))
			expectInstalled(r, first)

			// A push with one certificate line dropped.
			dropped := testPushFrames(2, other.crt, other.key)
			dropped = append(dropped[:3], dropped[4:]...)
			// A push with one character of the key changed, so only the
			// checksum tells.
			changed := testPushFrames(3, other.crt, other.key)
			line := []byte(changed[len(changed)-3])
			at := len(credTag(testNonce) + "key ")
			line[at] ^= 1
			changed[len(changed)-3] = string(line)
			// A certificate without its first boundary, whose counts and
			// checksum are its own.
			unbounded := []byte(strings.SplitN(string(other.crt), "\n", 2)[1])
			// An end line without a frame, and a frame that a new begin
			// line interrupts.
			input := append(append(append(dropped, changed...), testPushFrames(4, unbounded, other.key)...),
				credTag(testNonce)+"end 5 1 1 "+strings.Repeat("0", 64))
			input = append(input, testPushFrames(6, other.crt, other.key)[:5]...)
			input = append(input, testPushFrames(7, second.crt, second.key)...)
			r.write(consoleInput(input))
			Eventually(r.answers, 10*time.Second, 10*time.Millisecond).Should(Equal(ok(1)+bad(2)+bad(3)+bad(4)+bad(5)+ok(7)), shell.name)
			expectInstalled(r, second)
			Expect(r.renames()).To(Equal([]string{
				"mv -f " + r.cred + "/instance.key.tmp " + r.cred + "/instance.key",
				"mv -f " + r.cred + "/instance.crt.tmp " + r.cred + "/instance.crt",
				"mv -f " + r.cred + "/instance.key.tmp " + r.cred + "/instance.key",
				"mv -f " + r.cred + "/instance.crt.tmp " + r.cred + "/instance.crt",
			}))
			Expect(app.terminated()).To(BeFalse())

			r.write(stopLine)
			Expect(r.finish()).To(Equal("reader-done\n"), shell.name)
			Eventually(app.terminated, 5*time.Second, 10*time.Millisecond).Should(BeTrue())
			oom, err := os.ReadFile(r.oom)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(oom)).To(Equal("-1000\n"))
		},
		shellEntries(""),
	)

	DescribeTable("discards a frame that the stop request interrupts",
		func(shellOf func() guestShell) {
			shell := shellOf()
			app := startPidTarget(true)
			r := startControlRun(shell, []string{app.pidFile}, true, false)
			pair := newTestIdentityPair(1, "ec")
			frames := testPushFrames(1, pair.crt, pair.key)
			r.write(consoleInput(frames[:len(frames)-1]) + stopLine + consoleInput(frames[len(frames)-1:]))
			Expect(r.finish()).To(Equal("reader-done\n"), shell.name)
			Eventually(app.terminated, 5*time.Second, 10*time.Millisecond).Should(BeTrue())
			Expect(r.answers()).To(BeEmpty())
			entries, err := os.ReadDir(r.cred)
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty())
		},
		shellEntries(""),
	)

	DescribeTable("writes stop to the events FIFO and then signals each pid file as soon as it holds a pid",
		func(shellOf func() guestShell) {
			shell := shellOf()
			app, early, late := startPidTarget(true), startPidTarget(true), startPidTarget(false)
			r := startControlRun(shell, []string{app.pidFile, late.pidFile, early.pidFile}, false, true)
			events := r.eventLines()
			r.write(stopLine)
			Eventually(events, 5*time.Second).Should(Receive(Equal("stop")))
			Eventually(app.terminated, 5*time.Second, 10*time.Millisecond).Should(BeTrue())
			Eventually(early.terminated, 5*time.Second, 10*time.Millisecond).Should(BeTrue())
			Consistently(late.terminated, 300*time.Millisecond, 10*time.Millisecond).Should(BeFalse())
			late.record()
			Eventually(late.terminated, 5*time.Second, 10*time.Millisecond).Should(BeTrue())
			Expect(r.finish()).To(Equal("reader-done\n"), shell.name)
			Consistently(events, 100*time.Millisecond).ShouldNot(Receive())
		},
		shellEntries(""),
	)

	Describe("with only the app's pid file and no identity", func() {
		It("is the stop reader with the events FIFO and no frames", func() {
			reader := guestControlReader(testNonce, []string{guestAppPid}, false)
			Expect(reader).NotTo(ContainSubstring("RVM_CRED"))
			Expect(reader).NotTo(ContainSubstring(">/dev/console"))
			Expect(reader).To(HavePrefix("(\n\techo -1000 >/proc/self/oom_score_adj\n"))
			Expect(reader).To(HaveSuffix(") </dev/null &\nrvm_reader=$!\n"))
		})

		// Each run feeds the reader near misses of the request and frame
		// lines, and then either the request or the end of the console, and
		// the two readers must leave the app and print alike.
		DescribeTable("signals exactly as the stop reader does",
			func(shellOf func() guestShell, stop bool) {
				shell := shellOf()
				pair := newTestIdentityPair(1, "ec")
				noise := []string{
					stopTag(testNonce) + " ",
					" " + stopTag(testNonce),
					stopTag(testNonce) + `\`,
					stopTag(testNonce) + "x",
					"stop",
				}
				noise = append(noise, testPushFrames(1, pair.crt, pair.key)...)
				expectApp := func(app *pidTarget) {
					if stop {
						Eventually(app.terminated, 5*time.Second, 10*time.Millisecond).Should(BeTrue())
					} else {
						Consistently(app.terminated, 200*time.Millisecond, 10*time.Millisecond).Should(BeFalse())
					}
				}

				app := startPidTarget(true)
				r := startControlRun(shell, []string{app.pidFile}, false, false)
				r.write(consoleInput(noise))
				Consistently(app.terminated, 200*time.Millisecond, 10*time.Millisecond).Should(BeFalse())
				if stop {
					r.write(stopLine)
				} else {
					Expect(r.console.Close()).To(Succeed())
				}
				controlOut := r.finish()
				expectApp(app)
				Expect(r.answers()).To(BeEmpty())
				entries, err := os.ReadDir(r.cred)
				Expect(err).NotTo(HaveOccurred())
				Expect(entries).To(BeEmpty())

				stopApp := startPidTarget(true)
				stopOut := runStopReaderLike(shell, stopApp, noise, stop)
				expectApp(stopApp)
				Expect(controlOut).To(Equal(stopOut))
				Expect(controlOut).To(Equal("reader-done\n"))
			},
			append(shellEntries("on the request", true), shellEntries("when the console ends without a request", false)...),
		)
	})
})

// runStopReaderLike runs guestStopReader as startControlRun runs the
// control reader, with the pid file of app as the app's, feeds it lines,
// checks that app still runs, and then writes the request when stop is set
// or ends the console otherwise. It returns the run's output once the run
// has ended.
func runStopReaderLike(shell guestShell, app *pidTarget, lines []string, stop bool) string {
	dir := GinkgoT().TempDir()
	fifo := filepath.Join(dir, "console")
	Expect(syscall.Mkfifo(fifo, 0o600)).To(Succeed())
	console, err := os.OpenFile(fifo, os.O_RDWR, 0)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { _ = console.Close() })
	reader := strings.NewReplacer(
		"</dev/console", "<"+fifo,
		"/proc/self/oom_score_adj", filepath.Join(dir, "oom_score_adj"),
		guestAppPid, app.pidFile,
	).Replace(guestStopReader(testNonce))
	out, err := os.Create(filepath.Join(dir, "out"))
	Expect(err).NotTo(HaveOccurred())
	defer out.Close()
	cmd := exec.Command(shell.argv[0], append(shell.argv[1:], "-c", reader+"wait \"$rvm_reader\"\necho reader-done\n")...)
	cmd.Env = []string{"PATH=" + guestToolsBin(shell)}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	Expect(cmd.Start()).To(Succeed())
	pgid := cmd.Process.Pid
	DeferCleanup(func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) })
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	_, err = console.WriteString(consoleInput(lines))
	Expect(err).NotTo(HaveOccurred())
	Consistently(app.terminated, 200*time.Millisecond, 10*time.Millisecond).Should(BeFalse())
	if stop {
		_, err = console.WriteString(stopTag(testNonce) + "\n")
		Expect(err).NotTo(HaveOccurred())
	} else {
		Expect(console.Close()).To(Succeed())
	}
	Eventually(done, 10*time.Second).Should(Receive(BeNil()))
	text, err := os.ReadFile(filepath.Join(dir, "out"))
	Expect(err).NotTo(HaveOccurred())
	return string(text)
}

// setupPrepare changes the app root or the boot pair before an identity
// setup run.
type setupPrepare func(root, crtPath, keyPath string)

var _ = Describe("the identity setup of the run section", func() {
	// identitySetupRun runs guestIdentitySetup in shell with the app root at
	// root, the boot pair at the given paths, and a mount that logs its
	// arguments and fails when mountFails is set, and returns its output,
	// the mount log, and the directory that stands for guestIdentityNext.
	identitySetupRun := func(shell guestShell, root, crtPath, keyPath string, mountFails bool) (out, mounts, next string) {
		dir := GinkgoT().TempDir()
		next = filepath.Join(dir, "identity", "next")
		mountLog := filepath.Join(dir, "mount.log")
		mountStatus := "0"
		if mountFails {
			mountStatus = "32"
		}
		script := strings.NewReplacer(
			guestAppRootEtc, filepath.Join(root, "etc"),
			guestIdentityCert, crtPath,
			guestIdentityKey, keyPath,
			guestIdentityNext, next,
			"reboot -nf", "echo REBOOT",
		).Replace(guestFailFunc + `mount() { echo "mount $*" >>` + mountLog + `; return ` + mountStatus + `; }
` + guestIdentitySetup + "echo setup-done\n")
		cmd := exec.Command(shell.argv[0], append(shell.argv[1:], "-c", script)...)
		cmd.Env = []string{"PATH=" + guestToolsBin(shell)}
		text, _ := cmd.CombinedOutput()
		log, err := os.ReadFile(mountLog)
		if !os.IsNotExist(err) {
			Expect(err).NotTo(HaveOccurred())
		}
		return string(text), string(log), next
	}
	bootPair := func() (crtPath, keyPath string, pair testIdentityPair) {
		dir := GinkgoT().TempDir()
		pair = newTestIdentityPair(1, "ec")
		crtPath, keyPath = filepath.Join(dir, "instance.crt"), filepath.Join(dir, "instance.key")
		Expect(os.WriteFile(crtPath, pair.crt, 0o600)).To(Succeed())
		Expect(os.WriteFile(keyPath, pair.key, 0o600)).To(Succeed())
		return crtPath, keyPath, pair
	}
	expectPair := func(credDir string, pair testIdentityPair) {
		for name, want := range map[string][]byte{"instance.crt": pair.crt, "instance.key": pair.key} {
			got, err := os.ReadFile(filepath.Join(credDir, name))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(got)).To(Equal(string(want)), name)
			info, err := os.Stat(filepath.Join(credDir, name))
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o644)), name)
		}
	}

	DescribeTable("mounts the tmpfs and installs the boot pair there with mode 0644, also in a root that already has the directory",
		func(shellOf func() guestShell, existing bool) {
			shell := shellOf()
			root := GinkgoT().TempDir()
			credDir := filepath.Join(root, "etc", "cf-instance-credentials")
			if existing {
				Expect(os.MkdirAll(credDir, 0o755)).To(Succeed())
			}
			crtPath, keyPath, pair := bootPair()
			out, mounts, next := identitySetupRun(shell, root, crtPath, keyPath, false)
			Expect(out).To(Equal("setup-done\n"), shell.name)
			Expect(mounts).To(Equal("mount -t tmpfs -o mode=0755,size=1m,nosuid,nodev,noexec tmpfs " + credDir + "\n"))
			expectPair(credDir, pair)
			info, err := os.Stat(next)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.IsDir()).To(BeTrue())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o700)))
		},
		append(shellEntries("in a root without the directory", false), shellEntries("in a root with the directory", true)...),
	)

	DescribeTable("fails the boot with a named step",
		func(shellOf func() guestShell, prepare setupPrepare, mountFails bool, step string, mounted bool) {
			shell := shellOf()
			root := GinkgoT().TempDir()
			crtPath, keyPath, _ := bootPair()
			if prepare != nil {
				prepare(root, crtPath, keyPath)
			}
			out, mounts, _ := identitySetupRun(shell, root, crtPath, keyPath, mountFails)
			Expect(out).To(HaveSuffix("vm-launch guest setup: "+step+"\nREBOOT\n"), shell.name)
			Expect(out).NotTo(ContainSubstring("setup-done"))
			Expect(mounts != "").To(Equal(mounted))
		},
		append(append(append(
			shellEntries("when the mount fails", setupPrepare(nil), true, "mounting a tmpfs at /etc/cf-instance-credentials in the app root failed", true),
			shellEntries("when /etc is a symbolic link", setupPrepare(func(root, _, _ string) {
				Expect(os.Symlink(GinkgoT().TempDir(), filepath.Join(root, "etc"))).To(Succeed())
			}), false, "the app root's /etc or /etc/cf-instance-credentials is a symbolic link, so the instance identity cannot be installed there", false)...),
			shellEntries("when /etc/cf-instance-credentials is a symbolic link", setupPrepare(func(root, _, _ string) {
				Expect(os.Mkdir(filepath.Join(root, "etc"), 0o755)).To(Succeed())
				Expect(os.Symlink(GinkgoT().TempDir(), filepath.Join(root, "etc", "cf-instance-credentials"))).To(Succeed())
			}), false, "the app root's /etc or /etc/cf-instance-credentials is a symbolic link, so the instance identity cannot be installed there", false)...),
			shellEntries("when the key is missing", setupPrepare(func(_, _, keyPath string) {
				Expect(os.Remove(keyPath)).To(Succeed())
			}), false, "copying the instance identity key into the app root failed", true)...),
	)
})
