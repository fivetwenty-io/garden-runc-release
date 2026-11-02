//go:build linux

package main

import (
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// The process and the tokens of the instances in the handoff specs.
const (
	handoffProcessID   = "4d6c1a6e-0a3b-4f53-9d2c-1f0e2b3c4d5e"
	otherProcessID     = "9a0e5f61-1bde-4a45-8bb6-4f65ee45614c"
	holderToken        = "00112233445566778899aabbccddeeff"
	waiterToken        = "ffeeddccbbaa99887766554433221100"
	secondWaiterToken  = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	handoffImageName   = "rvm-disk-0.img"
	handoffSpecPoll    = 50 * time.Millisecond
	handoffSpecTimeout = time.Minute
)

// openDirFD opens dir as an O_PATH directory for the rest of the spec.
func openDirFD(dir string) int {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { unix.Close(fd) })
	return fd
}

// found returns the request a read or a parse gave, which it must have given.
func found(r handoffRequest, ok bool) handoffRequest {
	ExpectWithOffset(1, ok).To(BeTrue(), "no request was found")
	return r
}

// mountIDOf is the ID of the mount dir is on, as openHandoffWatch reads it.
func mountIDOf(dir string) uint64 {
	p, err := dirProbe(openDirFD(dir), dir)
	Expect(err).NotTo(HaveOccurred())
	return p.MountID
}

var _ = Describe("handoff requests", func() {
	It("writes one line that parses back to the request", func() {
		r := handoffRequest{ProcessID: handoffProcessID, Token: waiterToken, Seq: 42}
		Expect(r.line()).To(Equal("rvm-handoff 1 " + handoffProcessID + " " + waiterToken + " 42\n"))
		Expect(found(parseHandoffRequest([]byte(r.line())))).To(Equal(r))
	})

	DescribeTable("refuses text that is not exactly one request",
		func(text string) {
			_, ok := parseHandoffRequest([]byte(text))
			Expect(ok).To(BeFalse())
		},
		Entry("empty", ""),
		Entry("without its newline", "rvm-handoff 1 "+handoffProcessID+" "+waiterToken+" 1"),
		Entry("with two lines", "rvm-handoff 1 "+handoffProcessID+" "+waiterToken+" 1\nrvm-handoff 1 "+handoffProcessID+" "+waiterToken+" 2\n"),
		Entry("with a carriage return", "rvm-handoff 1 "+handoffProcessID+" "+waiterToken+" 1\r\n"),
		Entry("of another version", "rvm-handoff 2 "+handoffProcessID+" "+waiterToken+" 1\n"),
		Entry("of another kind", "rvm-handover 1 "+handoffProcessID+" "+waiterToken+" 1\n"),
		Entry("with a process that is not a lowercase UUID", "rvm-handoff 1 "+strings.ToUpper(handoffProcessID)+" "+waiterToken+" 1\n"),
		Entry("with a short token", "rvm-handoff 1 "+handoffProcessID+" "+waiterToken[:30]+" 1\n"),
		Entry("with a sequence number that is not canonical", "rvm-handoff 1 "+handoffProcessID+" "+waiterToken+" 01\n"),
		Entry("with a negative sequence number", "rvm-handoff 1 "+handoffProcessID+" "+waiterToken+" -1\n"),
		Entry("with an extra field", "rvm-handoff 1 "+handoffProcessID+" "+waiterToken+" 1 x\n"),
		Entry("with two spaces", "rvm-handoff 1  "+handoffProcessID+" "+waiterToken+" 1\n"),
	)

	It("draws one token for the whole launch", func() {
		a, err := launchHandoffToken()
		Expect(err).NotTo(HaveOccurred())
		b, err := launchHandoffToken()
		Expect(err).NotTo(HaveOccurred())
		Expect(a).To(MatchRegexp(`^[0-9a-f]{32}$`))
		Expect(b).To(Equal(a))
		c, err := newHandoffToken()
		Expect(err).NotTo(HaveOccurred())
		Expect(c).NotTo(Equal(a))
	})

	Describe("on disk", func() {
		var (
			dir   string
			dirfd int
			name  string
		)

		BeforeEach(func() {
			requireOpenat2()
			dir = GinkgoT().TempDir()
			dirfd = openDirFD(dir)
			name = handoffRequestName(handoffImageName)
		})

		It("names the request after the image, apart from the image's temp files", func() {
			Expect(name).To(Equal(".rvm-handoff-rvm-disk-0.img"))
			Expect(tempNamePattern.MatchString(name)).To(BeFalse())
		})

		It("writes the request by rename, with mode 0600, and leaves no temp file", func() {
			r := handoffRequest{ProcessID: handoffProcessID, Token: waiterToken, Seq: 1}
			Expect(writeHandoffRequest(dirfd, name, r)).To(Succeed())
			r.Seq = 2
			Expect(writeHandoffRequest(dirfd, name, r)).To(Succeed())
			Expect(found(readHandoffRequest(dirfd, name))).To(Equal(r))
			info, err := os.Lstat(filepath.Join(dir, name))
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode()).To(Equal(os.FileMode(0o600)))
			entries, err := os.ReadDir(dir)
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(1))
		})

		It("reads no request from a missing name, a link, a directory, a large file, or a file that does not parse", func() {
			_, ok := readHandoffRequest(dirfd, name)
			Expect(ok).To(BeFalse())

			r := handoffRequest{ProcessID: handoffProcessID, Token: waiterToken, Seq: 1}
			target := filepath.Join(dir, "target")
			Expect(os.WriteFile(target, []byte(r.line()), 0o600)).To(Succeed())
			Expect(os.Symlink("target", filepath.Join(dir, name))).To(Succeed())
			_, ok = readHandoffRequest(dirfd, name)
			Expect(ok).To(BeFalse(), "a symbolic link was followed")
			Expect(os.Remove(filepath.Join(dir, name))).To(Succeed())

			Expect(os.Mkdir(filepath.Join(dir, name), 0o700)).To(Succeed())
			_, ok = readHandoffRequest(dirfd, name)
			Expect(ok).To(BeFalse())
			Expect(os.Remove(filepath.Join(dir, name))).To(Succeed())

			Expect(os.WriteFile(filepath.Join(dir, name), []byte(r.line()+strings.Repeat(" ", maxHandoffRequest)), 0o600)).To(Succeed())
			_, ok = readHandoffRequest(dirfd, name)
			Expect(ok).To(BeFalse())

			Expect(os.WriteFile(filepath.Join(dir, name), []byte("hand it over\n"), 0o600)).To(Succeed())
			_, ok = readHandoffRequest(dirfd, name)
			Expect(ok).To(BeFalse())
		})

		It("reads no request from a file another user owns", func() {
			if os.Geteuid() != 0 {
				Skip("only root can give a file to another user")
			}
			r := handoffRequest{ProcessID: handoffProcessID, Token: waiterToken, Seq: 1}
			Expect(writeHandoffRequest(dirfd, name, r)).To(Succeed())
			Expect(os.Chown(filepath.Join(dir, name), 1234, 1234)).To(Succeed())
			_, ok := readHandoffRequest(dirfd, name)
			Expect(ok).To(BeFalse())
		})

		It("reports a request it cannot write and removes the temp file", func() {
			r := handoffRequest{ProcessID: handoffProcessID, Token: waiterToken, Seq: 1}
			Expect(os.Mkdir(filepath.Join(dir, name), 0o700)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, name, "keep"), nil, 0o600)).To(Succeed())
			err := writeHandoffRequest(dirfd, name, r)
			Expect(err).To(MatchError(ContainSubstring("renaming")))
			entries, err := os.ReadDir(dir)
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(1))
		})

		Describe("the waiting side", func() {
			var (
				logBuf *safeBuffer
				asker  *handoffRequester
			)

			BeforeEach(func() {
				logBuf = &safeBuffer{}
				asker = newHandoffRequester(dirfd, handoffImageName, "/data/"+handoffImageName,
					handoffIdentity{ProcessID: handoffProcessID, Token: waiterToken}, log.New(logBuf, "", 0).Printf)
			})

			It("writes at most one request each refresh, with a rising sequence number, and logs only the first", func() {
				asker.refresh()
				asker.refresh()
				Expect(found(readHandoffRequest(dirfd, name))).To(Equal(handoffRequest{ProcessID: handoffProcessID, Token: waiterToken, Seq: 1}))
				time.Sleep(handoffRefresh)
				asker.refresh()
				Expect(found(readHandoffRequest(dirfd, name))).To(Equal(handoffRequest{ProcessID: handoffProcessID, Token: waiterToken, Seq: 2}))
				Expect(logBuf.String()).To(Equal("volume image /data/rvm-disk-0.img is locked; asking the instance that holds it to hand it over, which it does when it is an earlier instance of this process\n"))
			})

			It("removes its own request and leaves another's", func() {
				asker.refresh()
				asker.withdraw()
				_, err := os.Lstat(filepath.Join(dir, name))
				Expect(errors.Is(err, os.ErrNotExist)).To(BeTrue(), "the request is still there")

				other := handoffRequest{ProcessID: handoffProcessID, Token: secondWaiterToken, Seq: 9}
				Expect(writeHandoffRequest(dirfd, name, other)).To(Succeed())
				asker.withdraw()
				Expect(found(readHandoffRequest(dirfd, name))).To(Equal(other))
			})

			It("removes nothing when it never wrote a request", func() {
				other := handoffRequest{ProcessID: handoffProcessID, Token: waiterToken, Seq: 9}
				Expect(writeHandoffRequest(dirfd, name, other)).To(Succeed())
				asker.withdraw()
				Expect(found(readHandoffRequest(dirfd, name))).To(Equal(other))
			})

			It("logs one line when it cannot write the request and keeps waiting", func() {
				Expect(os.Mkdir(filepath.Join(dir, name), 0o700)).To(Succeed())
				Expect(os.WriteFile(filepath.Join(dir, name, "keep"), nil, 0o600)).To(Succeed())
				asker.refresh()
				time.Sleep(handoffRefresh)
				asker.refresh()
				Expect(logBuf.String()).To(HavePrefix("asking the instance that holds volume image /data/rvm-disk-0.img to hand it over: renaming "))
				Expect(strings.Count(logBuf.String(), "\n")).To(Equal(1))
				Expect(logBuf.String()).To(HaveSuffix("; this instance waits for the lock without asking\n"))
			})

			It("does nothing as a nil requester", func() {
				var none *handoffRequester
				none.refresh()
				none.withdraw()
				_, ok := readHandoffRequest(dirfd, name)
				Expect(ok).To(BeFalse())
			})
		})

		Describe("the holding side", func() {
			var watch *handoffWatch

			BeforeEach(func() {
				var err error
				watch, err = openHandoffWatch(dir, mountIDOf(dir), handoffImageName, handoffIdentity{ProcessID: handoffProcessID, Token: holderToken})
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(watch.Close)
			})

			It("refuses a volume root on another mount or behind a symbolic link", func() {
				_, err := openHandoffWatch(dir, mountIDOf(dir)+1, handoffImageName, handoffIdentity{})
				Expect(err).To(MatchError(ContainSubstring("the mount of volume " + dir + " changed")))
				link := filepath.Join(GinkgoT().TempDir(), "link")
				Expect(os.Symlink(dir, link)).To(Succeed())
				_, err = openHandoffWatch(link, mountIDOf(dir), handoffImageName, handoffIdentity{})
				Expect(err).To(MatchError(ContainSubstring("follows no symbolic links")))
			})

			It("reads a request from its own process and none from another process or with its own token", func() {
				r := handoffRequest{ProcessID: handoffProcessID, Token: waiterToken, Seq: 3}
				Expect(writeHandoffRequest(dirfd, name, r)).To(Succeed())
				Expect(found(watch.read())).To(Equal(r))
				Expect(writeHandoffRequest(dirfd, name, handoffRequest{ProcessID: otherProcessID, Token: waiterToken, Seq: 4})).To(Succeed())
				_, ok := watch.read()
				Expect(ok).To(BeFalse())
				Expect(writeHandoffRequest(dirfd, name, handoffRequest{ProcessID: handoffProcessID, Token: holderToken, Seq: 5})).To(Succeed())
				_, ok = watch.read()
				Expect(ok).To(BeFalse())
			})

			Describe("the watcher", func() {
				var watcher *handoffWatcher

				BeforeEach(func() {
					watcher = startHandoffWatcher([]*handoffWatch{watch}, handoffSpecPoll)
					DeferCleanup(watcher.stop)
				})

				write := func(token string, seq uint64) {
					Expect(writeHandoffRequest(dirfd, name, handoffRequest{ProcessID: handoffProcessID, Token: token, Seq: seq})).To(Succeed())
				}

				It("offers a line once two reads find the same requester's sequence number risen", func() {
					write(waiterToken, 1)
					time.Sleep(3 * handoffSpecPoll)
					Consistently(watcher.requests(), 3*handoffSpecPoll).ShouldNot(Receive())
					write(waiterToken, 2)
					Eventually(watcher.requests(), time.Second).Should(Receive(Equal("another instance of this process is waiting for volume image " + filepath.Join(dir, handoffImageName))))
				})

				It("never offers a line for a request that stops changing", func() {
					write(waiterToken, 7)
					Consistently(watcher.requests(), 10*handoffSpecPoll).ShouldNot(Receive())
				})

				It("never offers a line when the token changes, which is a new requester seen once", func() {
					write(waiterToken, 1)
					time.Sleep(3 * handoffSpecPoll)
					write(secondWaiterToken, 2)
					Consistently(watcher.requests(), 6*handoffSpecPoll).ShouldNot(Receive())
				})

				It("reads again when nobody takes its line, and offers it only for a requester that is still alive", func() {
					write(waiterToken, 1)
					time.Sleep(3 * handoffSpecPoll)
					write(waiterToken, 2)
					// Nobody takes the line for several polls, so the watcher has
					// read the request again and needs it to rise once more.
					time.Sleep(6 * handoffSpecPoll)
					Consistently(watcher.requests(), 4*handoffSpecPoll).ShouldNot(Receive())
					write(waiterToken, 3)
					Eventually(watcher.requests(), time.Second).Should(Receive())
				})

				It("stops after it has given its line, and stop can be called again", func() {
					write(waiterToken, 1)
					time.Sleep(3 * handoffSpecPoll)
					write(waiterToken, 2)
					Eventually(watcher.requests(), time.Second).Should(Receive())
					Eventually(watcher.finished).Should(BeClosed())
					watcher.stop()
					watcher.stop()
				})
			})
		})
	})

	It("starts no watcher for no watches, and a nil watcher offers nothing", func() {
		w := startHandoffWatcher(nil, handoffSpecPoll)
		Expect(w).To(BeNil())
		Expect(w.requests()).To(BeNil())
		w.stop()
	})
})

var _ = Describe("the handoff identity of a volume", func() {
	blockCaps := capabilities{Modes: []attachMode{attachBlock}, Fence: fenceExclusiveOpen, MaxInstances: 1}
	logger := log.New(io.Discard, "", 0)
	vol := func(processID string) selectedVolume {
		return selectedVolume{Volume: guestVolume{ContainerDir: "/data", ImageName: handoffImageName, ProcessID: processID}}
	}

	It("is the process and the launch's token for a file image under a distributed flock", func() {
		token, err := launchHandoffToken()
		Expect(err).NotTo(HaveOccurred())
		Expect(handoffIdentityFor(vol(handoffProcessID), fileImageCaps, attachFileImage, logger)).To(Equal(&handoffIdentity{ProcessID: handoffProcessID, Token: token}))
	})

	It("is nil for a block volume, a process without a process_id, and another fence", func() {
		Expect(handoffIdentityFor(vol(handoffProcessID), blockCaps, attachBlock, logger)).To(BeNil())
		Expect(handoffIdentityFor(vol(""), fileImageCaps, attachFileImage, logger)).To(BeNil())
		Expect(handoffIdentityFor(vol(handoffProcessID), capabilities{Modes: []attachMode{attachFileImage}, Fence: fenceExclusiveOpen}, attachFileImage, logger)).To(BeNil())
	})

	It("takes the process_id from VCAP_APPLICATION only when it is a lowercase UUID", func() {
		app := `{"application_id":"` + testAppID + `","process_type":"web","process_id":"%s"}`
		for id, want := range map[string]string{handoffProcessID: handoffProcessID, strings.ToUpper(handoffProcessID): "", "web": "", "": ""} {
			env := map[string]string{
				vcapServicesEnv:    vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw")}}),
				vcapApplicationEnv: strings.Replace(app, "%s", id, 1),
				instanceIndexEnv:   "0",
			}
			vols, err := volumesFromEnv(envMap(env))
			Expect(err).NotTo(HaveOccurred())
			Expect(vols).To(HaveLen(1))
			Expect(vols[0].ProcessID).To(Equal(want), id)
		}
	})

	It("reaches the provider through prepare, which watches the volume root once the disk is held", func() {
		requireOpenat2()
		dir := GinkgoT().TempDir()
		var got *handoffIdentity
		p := fake("JuiceFS-like")
		p.prepare = func(req prepareRequest) (*attachment, error) {
			got = req.Handoff
			img, err := os.OpenFile(filepath.Join(dir, handoffImageName), os.O_RDWR|os.O_CREATE, 0o600)
			Expect(err).NotTo(HaveOccurred())
			return &attachment{File: img, Release: img.Close}, nil
		}
		var pv preparedVolumes
		v := selectedVolume{Volume: guestVolume{ContainerDir: dir, ImageName: handoffImageName, ProcessID: handoffProcessID},
			Provider: p, Mount: mountRecord{ContainerDir: dir, MountID: mountIDOf(dir)}}
		leftover, err := pv.prepare(v, nil, nil, logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(leftover).To(BeNil())
		DeferCleanup(func() { pv.release(logger) })
		Expect(got).NotTo(BeNil())
		Expect(got.ProcessID).To(Equal(handoffProcessID))
		Expect(pv.handoffWatches()).To(HaveLen(1))
		Expect(pv.handoffWatches()[0].path).To(Equal(filepath.Join(dir, handoffImageName)))
	})

	It("keeps the disk without a watch when the volume root cannot be opened again", func() {
		requireOpenat2()
		dir := GinkgoT().TempDir()
		logBuf := &safeBuffer{}
		p := fake("JuiceFS-like")
		p.prepare = func(req prepareRequest) (*attachment, error) {
			img, err := os.OpenFile(filepath.Join(dir, handoffImageName), os.O_RDWR|os.O_CREATE, 0o600)
			Expect(err).NotTo(HaveOccurred())
			return &attachment{File: img, Release: img.Close}, nil
		}
		var pv preparedVolumes
		v := selectedVolume{Volume: guestVolume{ContainerDir: dir, ImageName: handoffImageName, ProcessID: handoffProcessID},
			Provider: p, Mount: mountRecord{ContainerDir: dir, MountID: mountIDOf(dir) + 1}}
		_, err := pv.prepare(v, nil, nil, log.New(logBuf, "", 0))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { pv.release(log.New(io.Discard, "", 0)) })
		Expect(pv).To(HaveLen(1))
		Expect(pv.handoffWatches()).To(BeEmpty())
		Expect(logBuf.String()).To(ContainSubstring("watching for handoff requests: the mount of volume " + dir + " changed"))
		Expect(logBuf.String()).To(HaveSuffix("; this instance keeps the volume image until it is stopped\n"))
	})
})

var _ = Describe("the supervisor's handoff", func() {
	var (
		out     *safeBuffer
		logBuf  *safeBuffer
		signals chan os.Signal
		handoff chan string
		sup     supervisor
		dir     string
		stdin   string
	)

	BeforeEach(func() {
		out, logBuf = &safeBuffer{}, &safeBuffer{}
		signals = make(chan os.Signal, 2)
		handoff = make(chan string)
		sup = supervisor{stdout: out, logger: log.New(logBuf, "", 0), signals: signals, handoff: handoff, grace: 5 * time.Second, deadline: 5 * time.Second}
		dir = GinkgoT().TempDir()
		stdin = filepath.Join(dir, "stdin")
	})

	startLine := `printf 'boot noise\r\nRVM_START_` + testNonce + `\r\n'; `
	exitLine := func(status string) string { return `printf 'RVM_EXIT_` + testNonce + `=` + status + `\r\n'; ` }
	readRequest := func() string { return `IFS= read -r line; printf '%s\n' "$line" >>'` + stdin + `'; ` }
	stopLine := stopTag(testNonce) + "\n"
	const reason = "another instance of this process is waiting for volume image /data/rvm-disk-0.img"
	handoffLine := reason + ", so vm-launch asks the guest command to stop and hands the volumes over once the guest has stopped\n"

	// offer gives the supervisor the line for up to d and reports whether it
	// took it, as the watcher does.
	offer := func(d time.Duration) bool {
		select {
		case handoff <- reason:
			return true
		case <-time.After(d):
			return false
		}
	}

	It("asks the running guest command to stop, forwards nothing, and exits with the command's status", func(ctx SpecContext) {
		sup.closePorts = func() { sup.logger.Print("closing the ports") }
		sup.stdout = writerFunc(func(p []byte) (int, error) {
			if strings.Contains(string(p), "ready") {
				go func() { Expect(offer(5 * time.Second)).To(BeTrue()) }()
			}
			return out.Write(p)
		})
		res, err := sup.run(exec.Command("/bin/sh", "-c", `trap 'exit 99' TERM INT; `+startLine+`echo ready; `+readRequest()+`echo drained; `+exitLine("0")), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(0), logBuf.String())
		Expect(res.handedOff).To(BeTrue())
		Expect(res.received).To(Equal(syscall.SIGTERM))
		Expect(out.String()).To(Equal("ready\ndrained\n"))
		Expect(os.ReadFile(stdin)).To(Equal([]byte(stopLine)))
		Expect(logBuf.String()).To(Equal(handoffLine + "closing the ports\n"))
	}, SpecTimeout(handoffSpecTimeout))

	It("takes no line before the guest starts its command, and takes the next one once it runs", func(ctx SpecContext) {
		gate := filepath.Join(dir, "gate")
		sup.started = func() {
			go func() {
				defer GinkgoRecover()
				Expect(offer(300*time.Millisecond)).To(BeFalse(), "the supervisor took a line before the guest started its command")
				appendTo(gate, "go\n")
				Expect(offer(5 * time.Second)).To(BeTrue())
			}()
		}
		res, err := sup.run(exec.Command("/bin/sh", "-c", `trap 'exit 99' TERM INT; while [ ! -e '`+gate+`' ]; do sleep 0.02; done; `+startLine+readRequest()+exitLine("0")), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(0), logBuf.String())
		Expect(res.handedOff).To(BeTrue())
		Expect(os.ReadFile(stdin)).To(Equal([]byte(stopLine)))
	}, SpecTimeout(handoffSpecTimeout))

	It("takes no line once the guest has reported its status", func(ctx SpecContext) {
		sup.grace = 500 * time.Millisecond
		taken := make(chan bool, 1)
		sup.reported = func() { go func() { taken <- offer(300 * time.Millisecond) }() }
		res, err := sup.run(exec.Command("/bin/sh", "-c", startLine+exitLine("3")+`while :; do sleep 0.02; done`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(<-taken).To(BeFalse())
		Expect(codeOf(res)).To(Equal(3))
		Expect(res.handedOff).To(BeFalse())
		Expect(logBuf.String()).NotTo(ContainSubstring(reason))
	}, SpecTimeout(handoffSpecTimeout))

	It("takes no line once a signal has asked the guest to stop, and writes one stop request", func(ctx SpecContext) {
		taken := make(chan bool, 1)
		sup.stdout = writerFunc(func(p []byte) (int, error) {
			if strings.Contains(string(p), "ready") {
				signals <- syscall.SIGTERM
			}
			if strings.Contains(string(p), "asked") {
				go func() { taken <- offer(300 * time.Millisecond) }()
			}
			return out.Write(p)
		})
		res, err := sup.run(exec.Command("/bin/sh", "-c", startLine+`echo ready; `+readRequest()+`echo asked; sleep 0.6; `+exitLine("0")), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(<-taken).To(BeFalse())
		Expect(res.handedOff).To(BeFalse())
		Expect(os.ReadFile(stdin)).To(Equal([]byte(stopLine)))
		Expect(logBuf.String()).To(Equal("received terminated, asking the guest command to stop\n"))
	}, SpecTimeout(handoffSpecTimeout))

	It("treats a later signal as one that comes while the guest stops", func(ctx SpecContext) {
		sup.stdout = writerFunc(func(p []byte) (int, error) {
			if strings.Contains(string(p), "ready") {
				go func() { Expect(offer(5 * time.Second)).To(BeTrue()) }()
			}
			if strings.Contains(string(p), "asked") {
				signals <- syscall.SIGTERM
			}
			return out.Write(p)
		})
		res, err := sup.run(exec.Command("/bin/sh", "-c", `trap 'exit 99' TERM INT; `+startLine+`echo ready; `+readRequest()+`echo asked; sleep 0.3; `+exitLine("0")), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(0))
		Expect(os.ReadFile(stdin)).To(Equal([]byte(stopLine)))
		Expect(logBuf.String()).To(Equal(handoffLine + "received terminated again; the guest is already stopping\n"))
	}, SpecTimeout(handoffSpecTimeout))

	It("kills the hypervisor at the deadline when the guest command does not stop, and exits as after SIGTERM", func(ctx SpecContext) {
		sup.deadline = 300 * time.Millisecond
		sup.stdout = writerFunc(func(p []byte) (int, error) {
			if strings.Contains(string(p), "ready") {
				go func() { Expect(offer(5 * time.Second)).To(BeTrue()) }()
			}
			return out.Write(p)
		})
		res, err := sup.run(exec.Command("/bin/sh", "-c", startLine+`echo ready; `+readRequest()+`while :; do sleep 0.02; done`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		code, why := exitCode(res)
		Expect(code).To(Equal(143))
		Expect(why).To(Equal("stopped to hand the volumes to another instance before the guest reported a status"))
		Expect(logBuf.String()).To(Equal(handoffLine + "the guest did not stop within 300ms of the handoff request; killing the hypervisor\n"))
	}, SpecTimeout(handoffSpecTimeout))
})

// The orders in which two instances of one process can meet one image. Each
// instance opens the image through openVolumeImage with real flocks, the
// holder's guest is a fake hypervisor under the supervisor, and the holder
// reads its requests through a real watcher. In every order, the waiter's
// lock succeeds only after the holder's copy of the image began to close.
var _ = Describe("the volume handoff between two instances", func() {
	var (
		dir     string
		mountID uint64
		logBuf  *safeBuffer
		reqPath string
	)

	BeforeEach(func() {
		requireOpenat2()
		dir = GinkgoT().TempDir()
		mountID = mountIDOf(dir)
		logBuf = &safeBuffer{}
		reqPath = filepath.Join(dir, handoffRequestName(handoffImageName))
		// The two instances are two processes on a cell, and here they share
		// one umask, which openVolumeImage sets to 0o077 and restores around
		// its create. Two opens at once could restore each other's mask and
		// leave 0o077 for the specs after these, so the mask is 0o077 for the
		// whole spec and goes back once it ends.
		old := unix.Umask(0o077)
		DeferCleanup(func() { unix.Umask(old) })
	})

	identity := func(processID, token string) handoffIdentity {
		return handoffIdentity{ProcessID: processID, Token: token}
	}
	open := func(id handoffIdentity, wait time.Duration) (*os.File, error) {
		o := imageOptions{Size: defaultImageSize, LockWait: wait, LockPoll: 20 * time.Millisecond, IsMountRoot: alwaysMountRoot,
			Handoff: &id, Logf: log.New(logBuf, "", 0).Printf}
		return openVolumeImage(&guestVolume{ContainerDir: dir, ImageName: handoffImageName}, o, nil)
	}

	wait := func(id handoffIdentity, d time.Duration) <-chan waitedImage {
		ch := make(chan waitedImage, 1)
		go func() {
			img, err := open(id, d)
			ch <- waitedImage{img: img, err: err, at: time.Now()}
		}()
		return ch
	}
	take := func(ch <-chan waitedImage) waitedImage {
		var w waitedImage
		Eventually(ch, 20*time.Second).Should(Receive(&w))
		if w.img != nil {
			DeferCleanup(w.img.Close)
		}
		return w
	}
	waitForRequest := func() {
		Eventually(func() error { _, err := os.Lstat(reqPath); return err }, 5*time.Second, 10*time.Millisecond).Should(Succeed())
	}
	requestGone := func() bool {
		_, err := os.Lstat(reqPath)
		return errors.Is(err, os.ErrNotExist)
	}

	// held is a holder's run: what the supervisor returned, its log, and
	// when its copy of the image began to close.
	type held struct {
		res     runResult
		log     string
		closing time.Time
	}
	// runHolder runs script as the holder's guest under the supervisor, with
	// the requests of img read every handoffSpecPoll, and closes img once the
	// supervisor has returned, as vm-launch's release does. edit, when set,
	// changes the supervisor first.
	runHolder := func(img *os.File, id handoffIdentity, script string, edit func(*supervisor)) held {
		watch, err := openHandoffWatch(dir, mountID, handoffImageName, id)
		Expect(err).NotTo(HaveOccurred())
		defer watch.Close()
		watcher := startHandoffWatcher([]*handoffWatch{watch}, handoffSpecPoll)
		holderLog := &safeBuffer{}
		sup := supervisor{stdout: &safeBuffer{}, logger: log.New(holderLog, "", 0), signals: make(chan os.Signal, 2),
			handoff: watcher.requests(), grace: 5 * time.Second, deadline: 5 * time.Second}
		if edit != nil {
			edit(&sup)
		}
		res, err := sup.run(exec.Command("/bin/sh", "-c", script), testNonce)
		watcher.stop()
		Expect(err).NotTo(HaveOccurred())
		closing := time.Now()
		Expect(img.Close()).To(Succeed())
		return held{res: res, log: holderLog.String(), closing: closing}
	}
	startLine := `printf 'RVM_START_` + testNonce + `\r\n'; `
	exitLine := func(status string) string { return `printf 'RVM_EXIT_` + testNonce + `=` + status + `\r\n'; ` }
	// untilStopped is a guest command that runs until the stop request comes,
	// and a forwarded signal ends the fake hypervisor with 99.
	untilStopped := `trap 'exit 99' TERM INT; ` + startLine + `IFS= read -r line; ` + exitLine("0")
	handoffLine := "another instance of this process is waiting for volume image " + filepath.Join("%s", handoffImageName) +
		", so vm-launch asks the guest command to stop and hands the volumes over once the guest has stopped\n"

	It("hands the image over when the replacement waits while the holder's command runs", func(ctx SpecContext) {
		holder, err := open(identity(handoffProcessID, holderToken), time.Second)
		Expect(err).NotTo(HaveOccurred())
		waiter := wait(identity(handoffProcessID, waiterToken), 20*time.Second)
		h := runHolder(holder, identity(handoffProcessID, holderToken), untilStopped, nil)
		w := take(waiter)
		Expect(w.err).NotTo(HaveOccurred())
		Expect(w.at).To(BeTemporally(">=", h.closing))
		Expect(h.res.handedOff).To(BeTrue())
		Expect(codeOf(h.res)).To(Equal(0))
		Expect(h.log).To(Equal(strings.Replace(handoffLine, "%s", dir, 1)))
		Expect(requestGone()).To(BeTrue(), "the replacement left its request")
		Expect(logBuf.String()).To(ContainSubstring("asking the instance that holds it to hand it over"))
	}, SpecTimeout(handoffSpecTimeout))

	It("hands the image over to one of two instances that start at once, and the first to lock it holds it", func(ctx SpecContext) {
		a := wait(identity(handoffProcessID, holderToken), 20*time.Second)
		b := wait(identity(handoffProcessID, waiterToken), 20*time.Second)
		var first waitedImage
		var second <-chan waitedImage
		var firstID handoffIdentity
		select {
		case first = <-a:
			second, firstID = b, identity(handoffProcessID, holderToken)
		case first = <-b:
			second, firstID = a, identity(handoffProcessID, waiterToken)
		case <-time.After(10 * time.Second):
			Fail("neither instance locked the image")
		}
		Expect(first.err).NotTo(HaveOccurred())
		h := runHolder(first.img, firstID, untilStopped, nil)
		w := take(second)
		Expect(w.err).NotTo(HaveOccurred())
		Expect(w.at).To(BeTemporally(">=", h.closing))
		Expect(h.res.handedOff).To(BeTrue())
	}, SpecTimeout(handoffSpecTimeout))

	It("waits for the holder's command to start before it stops the guest for a request that came during the boot", func(ctx SpecContext) {
		holder, err := open(identity(handoffProcessID, holderToken), time.Second)
		Expect(err).NotTo(HaveOccurred())
		waiter := wait(identity(handoffProcessID, waiterToken), 20*time.Second)
		// The boot outlasts several reads that find the requester alive.
		boot := `trap 'exit 99' TERM INT; while [ ! -e '` + reqPath + `' ]; do sleep 0.02; done; sleep 2.5; `
		h := runHolder(holder, identity(handoffProcessID, holderToken), boot+untilStopped, nil)
		w := take(waiter)
		Expect(w.err).NotTo(HaveOccurred())
		Expect(w.at).To(BeTemporally(">=", h.closing))
		Expect(h.res.handedOff).To(BeTrue())
		Expect(codeOf(h.res)).To(Equal(0), "the supervisor forwarded a signal to a guest that had not started its command\n%s", h.log)
	}, SpecTimeout(handoffSpecTimeout))

	It("lets a signal stop the holder while the replacement waits, and stops the guest once", func(ctx SpecContext) {
		holder, err := open(identity(handoffProcessID, holderToken), time.Second)
		Expect(err).NotTo(HaveOccurred())
		waiter := wait(identity(handoffProcessID, waiterToken), 20*time.Second)
		waitForRequest()
		var sigs chan os.Signal
		// The guest takes the stop request, then outlasts several reads that
		// find the requester alive before it reports its status.
		script := `trap 'exit 99' TERM INT; ` + startLine + `echo ready; IFS= read -r line; echo "$line"; sleep 2.5; ` + exitLine("0")
		h := runHolder(holder, identity(handoffProcessID, holderToken), script, func(s *supervisor) {
			sigs = make(chan os.Signal, 2)
			s.signals = sigs
			s.stdout = &signalOnWrite{w: &safeBuffer{}, signals: sigs, sig: syscall.SIGTERM}
		})
		w := take(waiter)
		Expect(w.err).NotTo(HaveOccurred())
		Expect(w.at).To(BeTemporally(">=", h.closing))
		Expect(h.res.handedOff).To(BeFalse())
		Expect(h.res.received).To(Equal(syscall.SIGTERM))
		Expect(codeOf(h.res)).To(Equal(0))
		Expect(h.log).To(Equal("received terminated, asking the guest command to stop\n"))
	}, SpecTimeout(handoffSpecTimeout))

	It("gives the image to the replacement when the holder crashes", func(ctx SpecContext) {
		holder, err := open(identity(handoffProcessID, holderToken), time.Second)
		Expect(err).NotTo(HaveOccurred())
		waiter := wait(identity(handoffProcessID, waiterToken), 20*time.Second)
		waitForRequest()
		time.Sleep(300 * time.Millisecond)
		Consistently(waiter, 300*time.Millisecond).ShouldNot(Receive(), "the replacement locked an image that the holder holds")
		closing := time.Now()
		Expect(holder.Close()).To(Succeed())
		w := take(waiter)
		Expect(w.err).NotTo(HaveOccurred())
		Expect(w.at).To(BeTemporally(">=", closing))
		Expect(requestGone()).To(BeTrue())
	}, SpecTimeout(handoffSpecTimeout))

	It("never stops a holder for a replacement that gave up, and the replacement takes its request back", func(ctx SpecContext) {
		holder, err := open(identity(handoffProcessID, holderToken), time.Second)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(holder.Close)
		_, err = open(identity(handoffProcessID, waiterToken), 300*time.Millisecond)
		Expect(err).To(MatchError(errVolumeInUse))
		Expect(requestGone()).To(BeTrue())
		watch, err := openHandoffWatch(dir, mountID, handoffImageName, identity(handoffProcessID, holderToken))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(watch.Close)
		watcher := startHandoffWatcher([]*handoffWatch{watch}, handoffSpecPoll)
		DeferCleanup(watcher.stop)
		Consistently(watcher.requests(), 2*handoffRefresh+500*time.Millisecond).ShouldNot(Receive())
	}, SpecTimeout(handoffSpecTimeout))

	It("never stops a holder for a request that a departed launch left behind", func(ctx SpecContext) {
		holder, err := open(identity(handoffProcessID, holderToken), time.Second)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(holder.Close)
		Expect(writeHandoffRequest(openDirFD(dir), handoffRequestName(handoffImageName), handoffRequest{ProcessID: handoffProcessID, Token: waiterToken, Seq: 7})).To(Succeed())
		watch, err := openHandoffWatch(dir, mountID, handoffImageName, identity(handoffProcessID, holderToken))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(watch.Close)
		watcher := startHandoffWatcher([]*handoffWatch{watch}, handoffSpecPoll)
		DeferCleanup(watcher.stop)
		Consistently(watcher.requests(), 2*handoffRefresh+500*time.Millisecond).ShouldNot(Receive())
	}, SpecTimeout(handoffSpecTimeout))

	DescribeTable("never stops a holder for a waiter it must not hand the image to, which waits out its lock wait",
		func(ctx SpecContext, processID, token string) {
			holder, err := open(identity(handoffProcessID, holderToken), time.Second)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(holder.Close)
			watch, err := openHandoffWatch(dir, mountID, handoffImageName, identity(handoffProcessID, holderToken))
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(watch.Close)
			watcher := startHandoffWatcher([]*handoffWatch{watch}, handoffSpecPoll)
			DeferCleanup(watcher.stop)
			waiter := wait(identity(processID, token), 2*handoffRefresh+500*time.Millisecond)
			Consistently(watcher.requests(), 2*handoffRefresh).ShouldNot(Receive())
			w := take(waiter)
			Expect(w.err).To(MatchError(errVolumeInUse))
		},
		Entry("an instance of another process, as in a rolling deployment", otherProcessID, waiterToken),
		Entry("a request with the holder's own token", handoffProcessID, holderToken),
	)

	It("gives the image to one of two replacements, and the other waits until that one lets go", func(ctx SpecContext) {
		holder, err := open(identity(handoffProcessID, holderToken), time.Second)
		Expect(err).NotTo(HaveOccurred())
		a := wait(identity(handoffProcessID, waiterToken), 30*time.Second)
		b := wait(identity(handoffProcessID, secondWaiterToken), 30*time.Second)
		h := runHolder(holder, identity(handoffProcessID, holderToken), untilStopped, nil)
		var first waitedImage
		var second <-chan waitedImage
		select {
		case first = <-a:
			second = b
		case first = <-b:
			second = a
		case <-time.After(20 * time.Second):
			Fail("neither replacement locked the image")
		}
		Expect(first.err).NotTo(HaveOccurred())
		Expect(first.at).To(BeTemporally(">=", h.closing))
		Consistently(second, time.Second).ShouldNot(Receive(), "two replacements locked one image")
		closing := time.Now()
		Expect(first.img.Close()).To(Succeed())
		w := take(second)
		Expect(w.err).NotTo(HaveOccurred())
		Expect(w.at).To(BeTemporally(">=", closing))
	}, SpecTimeout(handoffSpecTimeout))

	It("takes no request once the holder's guest has reported its status", func(ctx SpecContext) {
		holder, err := open(identity(handoffProcessID, holderToken), time.Second)
		Expect(err).NotTo(HaveOccurred())
		waiter := wait(identity(handoffProcessID, waiterToken), 20*time.Second)
		waitForRequest()
		// The hypervisor outlives the status line by several live reads.
		script := startLine + exitLine("4") + `while :; do sleep 0.02; done`
		h := runHolder(holder, identity(handoffProcessID, holderToken), script, func(s *supervisor) { s.grace = 2500 * time.Millisecond })
		w := take(waiter)
		Expect(w.err).NotTo(HaveOccurred())
		Expect(w.at).To(BeTemporally(">=", h.closing))
		Expect(h.res.handedOff).To(BeFalse())
		Expect(codeOf(h.res)).To(Equal(4))
		Expect(h.log).NotTo(ContainSubstring("another instance"))
	}, SpecTimeout(handoffSpecTimeout))
})
