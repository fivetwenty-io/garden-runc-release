//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

var _ = Describe("the supervisor and the mirrored files' console", func() {
	var (
		out     *safeBuffer
		logBuf  *safeBuffer
		signals chan os.Signal
		sup     supervisor
		dir     string
		stdin   string
		calls   chan *consoleWriter
	)

	BeforeEach(func() {
		out = &safeBuffer{}
		logBuf = &safeBuffer{}
		signals = make(chan os.Signal, 2)
		sup = supervisor{stdout: out, logger: log.New(logBuf, "", 0), signals: signals, grace: 5 * time.Second, deadline: 5 * time.Second}
		dir = GinkgoT().TempDir()
		// stdin is where a fake hypervisor records the console input it read.
		stdin = filepath.Join(dir, "stdin")
		calls = make(chan *consoleWriter, 2)
		sup.fileAck = func(int, bool) {}
		sup.mirrored = true
		sup.onFileConsole = func(w *consoleWriter) { calls <- w }
	})

	// fakeHypervisor stands in for QEMU or Firecracker, as it does in the
	// specs of the stop path.
	fakeHypervisor := func(script string) *exec.Cmd {
		return exec.Command("/bin/sh", "-c", script)
	}
	say := func(line string) string { return `printf '` + line + `\r\n'; ` }
	startLine := say("boot noise") + say("RVM_START_"+testNonce)
	exitLine := say("RVM_EXIT_" + testNonce + "=0")
	// readRequest reads one line of console input and records it in stdin.
	readRequest := func() string { return `IFS= read -r line; printf '%s\n' "$line" >>'` + stdin + `'; ` }
	noPushes := "the guest did not say that it takes pushes of mirrored files, so vm-launch pushes it no changes to them; the guest keeps the copies it booted with\n"

	It("gives the console writer to onFileConsole once a guest that said it takes file pushes starts its command", func(ctx SpecContext) {
		push := fileTag(testNonce) + "begin 1 1"
		sup.onFileConsole = func(w *consoleWriter) {
			calls <- w
			go func() { _ = w.push([]string{push}) }()
		}
		res, err := sup.run(fakeHypervisor(say(fileOnTag(testNonce))+startLine+readRequest()+`echo ready; sleep 0.3; `+exitLine), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(0), logBuf.String())
		Expect(calls).To(HaveLen(1))
		Expect(os.ReadFile(stdin)).To(Equal([]byte(push + "\n")))
		Expect(out.String()).To(Equal("ready\n"))
		Expect(logBuf.String()).To(BeEmpty())
	}, SpecTimeout(time.Minute))

	It("never calls onFileConsole, and logs it, when the guest never said that it takes file pushes", func(ctx SpecContext) {
		res, err := sup.run(fakeHypervisor(startLine+`echo ready; sleep 0.3; `+exitLine), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(0), logBuf.String())
		Expect(calls).To(BeEmpty())
		Expect(logBuf.String()).To(Equal(noPushes))
	}, SpecTimeout(time.Minute))

	It("never calls onFileConsole, and logs it, when the guest also said that it could not turn off its echo", func(ctx SpecContext) {
		sup.credAck = func(int, bool) {}
		res, err := sup.run(fakeHypervisor(say(fileOnTag(testNonce))+say(credOffTag(testNonce))+startLine+`echo ready; sleep 0.3; `+exitLine), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(0), logBuf.String())
		Expect(calls).To(BeEmpty())
		Expect(logBuf.String()).To(Equal(noPushes))
	}, SpecTimeout(time.Minute))

	It("never calls onFileConsole when a signal comes before the guest starts its command", func(ctx SpecContext) {
		closed := filepath.Join(dir, "closed")
		trapped := filepath.Join(dir, "trapped")
		sup.closePorts = func() { Expect(os.WriteFile(closed, nil, 0o600)).To(Succeed()) }
		sup.started = func() {
			defer GinkgoRecover()
			waitForFile(trapped)
			signals <- syscall.SIGTERM
		}
		// The guest ignores the forwarded signal and starts its command once
		// the supervisor has acted on it.
		res, err := sup.run(fakeHypervisor(`trap '' TERM; `+say(fileOnTag(testNonce))+`: >'`+trapped+`'; while [ ! -e '`+closed+`' ]; do sleep 0.02; done; `+startLine+`echo ready; sleep 0.3; `+exitLine), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.markerFound).To(BeTrue())
		Expect(out.String()).To(Equal("ready\n"))
		Expect(calls).To(BeEmpty())
	}, SpecTimeout(time.Minute))

	It("never calls onFileConsole, and logs why, when the guest fell back to the busybox guest and removed its mirrored mounts", func(ctx SpecContext) {
		res, err := sup.run(fakeHypervisor(say("busybox guest: no stack")+say(mirrorOffTag(testNonce))+startLine+`echo ready; sleep 0.3; `+exitLine), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(0), logBuf.String())
		Expect(calls).To(BeEmpty())
		Expect(out.String()).To(Equal("ready\n"))
		Expect(logBuf.String()).To(Equal("the guest fell back to the busybox guest, which runs its command as root, so it removed the container's mirrored mounts before it ran it\n"))
	}, SpecTimeout(time.Minute))

	It("logs the fallback for a guest whose mirror has no watched files", func(ctx SpecContext) {
		sup.onFileConsole, sup.fileAck = nil, nil
		res, err := sup.run(fakeHypervisor(say(mirrorOffTag(testNonce))+startLine+`sleep 0.3; `+exitLine), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(0), logBuf.String())
		Expect(logBuf.String()).To(Equal("the guest fell back to the busybox guest, which runs its command as root, so it removed the container's mirrored mounts before it ran it\n"))
	}, SpecTimeout(time.Minute))
})

var _ = Describe("identity and file pushes on one console", func() {
	It("keeps every line whole and each push's lines in order when the two push at once", func() {
		w, rd := consolePipe()
		rd.start()
		creds := pushLines(12)
		data := bytes.Repeat([]byte("0123456789abcdef"), 120)
		files := mirrorFrames(testNonce, 1, 1, data, 0o644)
		Expect(len(files)).To(BeNumerically(">", 4), "the file push takes several chunks")

		errs := make(chan error, 2)
		go func() { errs <- w.push(creds) }()
		go func() { errs <- w.push(files) }()
		Eventually(errs, 10*time.Second).Should(Receive(BeNil()))
		Eventually(errs, 10*time.Second).Should(Receive(BeNil()))
		Expect(w.close()).To(Succeed())
		Eventually(rd.done, 5*time.Second).Should(BeClosed())

		got := strings.Split(strings.TrimSuffix(string(rd.bytes()), "\n"), "\n")
		Expect(got).To(HaveLen(len(creds) + len(files)))
		var gotCreds, gotFiles []string
		for _, line := range got {
			switch {
			case strings.HasPrefix(line, "RVM_CRED_"+testNonce+"="):
				gotCreds = append(gotCreds, line)
			case strings.HasPrefix(line, fileTag(testNonce)):
				gotFiles = append(gotFiles, line)
			default:
				Fail("a line that is neither push's: " + line)
			}
		}
		Expect(gotCreds).To(Equal(creds))
		Expect(gotFiles).To(Equal(files))

		// The guest's file reader takes only its own lines, so the file
		// decodes to its bytes and digest.
		var enc strings.Builder
		for _, f := range gotFiles[1 : len(gotFiles)-1] {
			enc.WriteString(strings.TrimPrefix(f, fileTag(testNonce)+"data "))
		}
		decoded, err := base64.StdEncoding.DecodeString(enc.String())
		Expect(err).NotTo(HaveOccurred())
		Expect(decoded).To(Equal(data))
		sum := sha256.Sum256(decoded)
		Expect(gotFiles[len(gotFiles)-1]).To(HaveSuffix(" " + hex.EncodeToString(sum[:])))
	})
})
