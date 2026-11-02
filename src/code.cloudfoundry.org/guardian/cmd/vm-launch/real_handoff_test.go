//go:build linux

package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("handing a volume image over against a real QEMU", func() {
	const dataDir = "/home/vcap/data"
	// handoffApp leaves a mark on the volume, says it is ready, and drains
	// on SIGTERM.
	const handoffApp = `echo kept-by-the-holder >` + dataDir + `/mark
trap 'echo got-term; exit 0' TERM
echo ready
while :; do sleep 1; done`

	It("stops the guest through its teardown for a replacement of the same process, which locks the image once QEMU has exited", func() {
		art := realArtifacts()
		qemu := realQEMU()
		requireMicrovm(qemu)
		holderID := handoffIdentity{ProcessID: handoffProcessID, Token: holderToken}
		waiterID := handoffIdentity{ProcessID: handoffProcessID, Token: waiterToken}

		var (
			res     runResult
			out     string
			supLog  string
			asked   time.Time
			closing time.Time
			waited  <-chan waitedImage
			waitLog *safeBuffer
			reqPath string
		)
		bootWithRetry(func() bool {
			dir := GinkgoT().TempDir()
			vol := guestVolume{ContainerDir: dir, ImageName: handoffImageName}
			reqPath = filepath.Join(dir, handoffRequestName(handoffImageName))
			open := func(id handoffIdentity, wait time.Duration, logf func(string, ...any)) (*os.File, error) {
				return openVolumeImage(&vol, imageOptions{Size: defaultImageSize, LockWait: wait, LockPoll: lockPoll,
					IsMountRoot: alwaysMountRoot, Handoff: &id, Logf: logf}, nil)
			}
			img, err := open(holderID, time.Second, nil)
			Expect(err).NotTo(HaveOccurred())
			watch, err := openHandoffWatch(dir, mountIDOf(dir), handoffImageName, holderID)
			Expect(err).NotTo(HaveOccurred())
			defer watch.Close()

			g := taskGuest(handoffApp)
			g.vols = []guestVolume{{ContainerDir: dataDir, ImageName: handoffImageName}}
			g.drives.volumes = qemuImageDrives(defaultImageSize)
			withRealRoot(&g)
			f := newRealInitramfs(g)
			files, drivePaths, initrdPath, _, rootPath := hypervisorFiles(imageAttachments(img), withUserspaceMark(f), nil, realRootImage())
			consoleLog := filepath.Join(GinkgoT().TempDir(), "console.log")
			argv := consoleLogArgv(markedArgv(tcgArgv(qemu, withRealRootDrive(qemuArgv(art, initrdPath, minGuestMemoryMiB, g.nw, drivePaths, 0), rootPath))), consoleLog)
			cmd := newHypervisorCmd(argv, files)
			stderr := &safeBuffer{}
			cmd.Stderr = stderr
			stdout, logBuf := &safeBuffer{}, &safeBuffer{}
			console := newBootWriter(realBootMark)
			stopTail := make(chan struct{})
			tailed := tailFile(consoleLog, console, stopTail)

			// The replacement starts its wait, with the wait vm-launch gives
			// it, once the holder's command runs.
			waitLog = &safeBuffer{}
			ch := make(chan waitedImage, 1)
			waited = ch
			ready := func() {
				asked = time.Now()
				go func() {
					w, err := open(waiterID, lockWait, log.New(waitLog, "", 0).Printf)
					ch <- waitedImage{img: w, err: err, at: time.Now()}
				}()
			}
			watcher := startHandoffWatcher([]*handoffWatch{watch}, handoffPoll, 0)
			var qemuProc *os.Process
			running := make(chan struct{})
			sup := supervisor{
				stdout:   &triggerWriter{w: stdout, text: "ready\n", fire: ready},
				logger:   log.New(logBuf, "", 0),
				signals:  make(chan os.Signal, 1),
				handoff:  watcher.requests(),
				grace:    killGrace,
				deadline: stopDeadline,
				started: func() {
					qemuProc = cmd.Process
					close(running)
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
			watcher.stop()
			// vm-launch's release closes its copy of the image once run has
			// returned, and the lock goes with it.
			closing = time.Now()
			Expect(img.Close()).To(Succeed())
			close(stopTail)
			<-tailed
			if !booted {
				// A replacement that started its wait takes the image now
				// and lets it go, so the next boot starts clean.
				if !asked.IsZero() {
					if w := <-ch; w.img != nil {
						w.img.Close()
					}
					asked = time.Time{}
				}
				return false
			}
			Expect(runErr).NotTo(HaveOccurred())
			GinkgoWriter.Printf("%s\n", details())
			out, supLog = stdout.String(), logBuf.String()
			return true
		})

		Expect(asked.IsZero()).To(BeFalse(), "the guest command never said it was ready\n%s", supLog)
		var w waitedImage
		Eventually(waited, lockWait).Should(Receive(&w))
		Expect(w.err).NotTo(HaveOccurred(), "the replacement did not lock the image\n%s", waitLog.String())
		DeferCleanup(w.img.Close)
		GinkgoWriter.Printf("the replacement locked the image %v after it began to wait\n", w.at.Sub(asked))

		Expect(supLog).To(ContainSubstring("another instance of this process is waiting for volume image "), supLog)
		Expect(supLog).To(ContainSubstring(", so vm-launch asks the guest command to stop and hands the volumes over once the guest has stopped\n"), supLog)
		Expect(supLog).NotTo(ContainSubstring("killing the hypervisor"), supLog)
		Expect(res.handedOff).To(BeTrue())
		Expect(codeOf(res)).To(Equal(0), supLog)
		Expect(out).To(Equal("ready\ngot-term\n"))
		Expect(waitLog.String()).To(ContainSubstring("asking the instance that holds it to hand it over"))

		// The replacement locked the image only after QEMU had exited and
		// the holder's copy began to close, and well within its wait.
		Expect(w.at).To(BeTemporally(">=", closing))
		Expect(w.at.Sub(asked)).To(BeNumerically("<", lockWait*2/3))
		fs := readExtImage(w.img)
		Expect(fs.clean()).To(BeTrue(), "the guest did not unmount the image before it stopped")
		Expect(imageHolds(w.img, "kept-by-the-holder")).To(BeTrue(), "the holder's mark is not on the image")
		_, err := os.Lstat(reqPath)
		Expect(os.IsNotExist(err)).To(BeTrue(), "the replacement left its request")
	})
})

// waitedImage is how a replacement's wait for an image ended, and when.
type waitedImage struct {
	img *os.File
	err error
	at  time.Time
}
