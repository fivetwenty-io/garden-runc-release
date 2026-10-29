//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// fdThreeChecks is fake hypervisor shell that fails unless its file
// descriptor 3 is the image at img and is locked, checked the way a
// hypervisor uses it: a new open of /proc/self/fd/3, which cannot take the
// flock that vm-launch's open file holds.
func fdThreeChecks(img string) string {
	return `[ -f /proc/self/fd/3 ] || { echo "fd 3 is not a regular file" >&2; exit 1; }
[ "$(stat -L -c %d:%i /proc/self/fd/3)" = "$(stat -c %d:%i ` + shellQuote(img) + `)" ] || { echo "fd 3 is not the image" >&2; exit 1; }
exec 4<>/proc/self/fd/3 || { echo "cannot reopen /proc/self/fd/3" >&2; exit 1; }
if flock -n 4; then echo "the image is not locked" >&2; exit 1; fi
exec 4>&-
`
}

// noFDThree fails when the fake hypervisor's fd 3 is a volume image. Under
// qemu-user emulation the emulator itself may hold fd 3, so the check names
// the image rather than demanding that fd 3 be closed.
const noFDThree = `case "$(readlink /proc/self/fd/3 2>/dev/null)" in *rvm-disk-*) echo "fd 3 is a volume image without a volume" >&2; exit 1 ;; esac
`

var _ = Describe("volumeExitCode", func() {
	It("maps a signal during the lock wait to 128+N", func() {
		Expect(volumeExitCode(&signalledError{Sig: syscall.SIGTERM})).To(Equal(143))
		Expect(volumeExitCode(&signalledError{Sig: syscall.SIGINT})).To(Equal(130))
		Expect(volumeExitCode(fmt.Errorf("wrapped: %w", &signalledError{Sig: syscall.SIGTERM}))).To(Equal(143))
	})

	It("maps every other volume failure to 125", func() {
		for _, kind := range []error{errVolumeInUse, errNotMountRoot, errImageNotRegular, errImageOwner, errImageLinks, errImageMode, errImageSize, errImageReplaced} {
			err := &volumeError{kind: kind, msg: "x"}
			Expect(errors.Is(err, kind)).To(BeTrue())
			Expect(volumeExitCode(err)).To(Equal(exitLaunchError), kind.Error())
		}
		Expect(volumeExitCode(syscall.ELOOP)).To(Equal(exitLaunchError))
		Expect(volumeExitCode(errors.New("VCAP_SERVICES is not valid JSON"))).To(Equal(exitLaunchError))
		Expect(volumeExitCode(nil)).To(Equal(0))
	})

	It("matches both the kind and the cause of a volume error", func() {
		err := &volumeError{kind: errNotMountRoot, cause: syscall.ENOSYS, msg: "x"}
		Expect(errors.Is(err, errNotMountRoot)).To(BeTrue())
		Expect(errors.Is(err, syscall.ENOSYS)).To(BeTrue())
	})
})

var _ = Describe("newHypervisorCmd", func() {
	It("keeps the hypervisor's environment empty, its stderr vm-launch's, and kills it with vm-launch", func() {
		cmd := newHypervisorCmd([]string{"/bin/true", "a"}, nil)
		Expect(cmd.Args).To(Equal([]string{"/bin/true", "a"}))
		Expect(cmd.Env).To(Equal([]string{}))
		Expect(cmd.Stderr).To(BeIdenticalTo(os.Stderr))
		Expect(cmd.SysProcAttr.Pdeathsig).To(Equal(syscall.SIGKILL))
		Expect(cmd.ExtraFiles).To(BeNil())
	})

	It("passes an image as the child's file descriptor 3", func() {
		f, err := os.Open(os.DevNull)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		cmd := newHypervisorCmd([]string{"/bin/true"}, f)
		Expect(cmd.ExtraFiles).To(HaveLen(1))
		Expect(cmd.ExtraFiles[0]).To(BeIdenticalTo(f))
	})

	Describe("with a real image", func() {
		var (
			dir string
			img string
			f   *os.File
		)

		BeforeEach(func() {
			requireOpenat2()
			dir = GinkgoT().TempDir()
			img = filepath.Join(dir, "rvm-disk-0.img")
			var err error
			f, err = openVolumeImage(&guestVolume{ContainerDir: dir, ImageName: "rvm-disk-0.img"},
				imageOptions{Size: defaultImageSize, LockWait: 0, LockPoll: time.Millisecond, IsMountRoot: alwaysMountRoot}, nil)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = f.Close() })
		})

		script := func(body string) string {
			p := filepath.Join(GinkgoT().TempDir(), "hypervisor")
			Expect(os.WriteFile(p, []byte("#!/bin/bash\n"+body), 0o755)).To(Succeed())
			return p
		}

		It("lets the supervised hypervisor open the locked image through /proc/self/fd/3", func() {
			var out, logBuf bytes.Buffer
			sup := supervisor{stdout: &out, logger: log.New(&logBuf, "", 0), signals: make(chan os.Signal), grace: time.Second}
			cmd := newHypervisorCmd([]string{script(fdThreeChecks(img) +
				"printf 'RVM_START_" + testNonce + "\\nvolume ok\\nRVM_EXIT_" + testNonce + "=0\\n'\n")}, f)
			res, err := sup.run(cmd, testNonce)
			Expect(err).NotTo(HaveOccurred())
			Expect(codeOf(res)).To(Equal(0), logBuf.String())
			Expect(out.String()).To(Equal("volume ok\n"))
		})

		It("keeps the image locked while the hypervisor lives, after vm-launch closes its copy", func() {
			cmd := newHypervisorCmd([]string{script("exec sleep 60\n")}, f)
			Expect(cmd.Start()).To(Succeed())
			Expect(f.Close()).To(Succeed())
			Expect(lockedElsewhere(img)).To(BeTrue())

			Expect(cmd.Process.Kill()).To(Succeed())
			_ = cmd.Wait()
			Expect(lockedElsewhere(img)).To(BeFalse())
		})
	})
})

var _ = Describe("run with a volume", func() {
	var (
		art    string
		tmp    string
		volDir string
		img    string
		logBuf *bytes.Buffer
	)

	BeforeEach(func() {
		art = makeArtifacts()
		volDir = GinkgoT().TempDir()
		img = filepath.Join(volDir, "rvm-disk-"+testAppID+"-web-2.img")
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		GinkgoT().Setenv("CF_INSTANCE_INDEX", "2")
		GinkgoT().Setenv("VCAP_APPLICATION", vcapApp)
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"juicefs": {mountJSON(volDir, "rw")}}))
		logBuf = &bytes.Buffer{}

		saved := defaultImageOptions
		DeferCleanup(func() { defaultImageOptions = saved })
		defaultImageOptions.IsMountRoot = alwaysMountRoot
		defaultImageOptions.LockWait = 300 * time.Millisecond
		defaultImageOptions.LockPoll = 20 * time.Millisecond
	})

	runVM := func(kind backend.Kind) int {
		return run([]string{"--backend", string(kind), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}, log.New(logBuf, "", 0))
	}

	noWorkDirs := func() {
		entries, err := os.ReadDir(tmp)
		Expect(err).NotTo(HaveOccurred())
		for _, e := range entries {
			Expect(e.Name()).NotTo(HavePrefix("vm-launch-"))
		}
	}

	It("exits 125 for two volume mounts before it creates anything", func() {
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"juicefs": {mountJSON(volDir, "rw")}, "nfs": {mountJSON("/other", "rw")}}))
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("VM backends support one volume mount; this app has 2"))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(os.ReadDir(volDir)).To(BeEmpty())
		Expect(argvFile).NotTo(BeAnExistingFile())
	})

	It("exits 125 for VCAP_SERVICES that is not JSON and never prints it", func() {
		GinkgoT().Setenv("VCAP_SERVICES", `{"juicefs":[{"credentials":{"password":"`+secretSentinel+`"}`)
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("VCAP_SERVICES is not valid JSON"))
		Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("exits 125 for a bad CF_INSTANCE_INDEX", func() {
		GinkgoT().Setenv("CF_INSTANCE_INDEX", "02")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring(`CF_INSTANCE_INDEX "02" is not an instance index`))
		Expect(os.ReadDir(volDir)).To(BeEmpty())
	})

	It("exits 125 for a task with a volume, says why, and creates nothing", func() {
		for name, set := range map[string]func(){
			"no CF_INSTANCE_INDEX": func() { os.Unsetenv("CF_INSTANCE_INDEX") },
			"no process_type":      func() { GinkgoT().Setenv("VCAP_APPLICATION", `{"application_id":"`+testAppID+`"}`) },
		} {
			logBuf.Reset()
			GinkgoT().Setenv("CF_INSTANCE_INDEX", "2")
			set()
			Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError), name)
			Expect(logBuf.String()).To(ContainSubstring("volumes are not supported for tasks on VM backends"), name)
			Expect(os.ReadDir(volDir)).To(BeEmpty(), name)
			Expect(os.ReadDir(tmp)).To(BeEmpty(), name)
		}
	})

	It("exits 125 for a bad process_type and never prints VCAP_APPLICATION", func() {
		GinkgoT().Setenv("VCAP_APPLICATION", `{"application_id":"`+testAppID+`","process_type":"../`+secretSentinel+`"}`)
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("process_type"))
		Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel))
		Expect(os.ReadDir(volDir)).To(BeEmpty())
	})

	It("exits 125 for a missing or malformed application_id and never prints VCAP_APPLICATION", func() {
		for _, app := range []string{`{"application_id":"../` + testAppID + `","name":"` + secretSentinel + `"}`, `{"name":"` + secretSentinel + `"}`, `x` + secretSentinel} {
			logBuf.Reset()
			GinkgoT().Setenv("VCAP_APPLICATION", app)
			Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
			Expect(logBuf.String()).To(ContainSubstring("VCAP_APPLICATION"))
			Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel))
			Expect(os.ReadDir(volDir)).To(BeEmpty())
			Expect(os.ReadDir(tmp)).To(BeEmpty())
		}
	})

	It("gives QEMU the locked image as fd 3 and a raw drive, without the volume path in its argv", func() {
		requireOpenat2()
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), fdThreeChecks(img)+
			`gzip -dc "$initrd" | grep -a -q -F `+shellQuote("RVM_VOLUME_PATH="+shellQuote(volDir))+` || { echo "no /rvm/mounts" >&2; exit 1; }
`)
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())

		argv, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(argv)).To(HaveSuffix("\n" + strings.Join(goldenQEMUDrive, "\n") + "\n"))
		Expect(string(argv)).NotTo(ContainSubstring(volDir))

		Expect(statOf(img).Size).To(Equal(int64(defaultImageSize)))
		Expect(lockedElsewhere(img)).To(BeFalse(), "the lock ends with the run")
		noWorkDirs()
	})

	It("gives Firecracker the locked image as its one drive", func() {
		requireOpenat2()
		fcCopy := filepath.Join(GinkgoT().TempDir(), "fc.json")
		writeFakeHypervisor(filepath.Join(art, "firecracker/firecracker"), fdThreeChecks(img)+
			`p=; for a in "$@"; do [ "$p" = --config-file ] && cp "$a" `+shellQuote(fcCopy)+`; p=$a; done
`)
		Expect(runVM(backend.VMFirecracker)).To(Equal(0), logBuf.String())

		cfg, err := os.ReadFile(fcCopy)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(cfg)).To(ContainSubstring(goldenFCDrive))
		Expect(string(cfg)).NotTo(ContainSubstring(volDir))
		noWorkDirs()
	})

	It("adds no drive and no fd 3 when VCAP_SERVICES has no volume mount", func() {
		GinkgoT().Setenv("VCAP_SERVICES", `{"p-mysql":[{"credentials":{"password":"`+secretSentinel+`"}}]}`)
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), noFDThree)
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		argv, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(argv)).NotTo(ContainSubstring("-drive"))
		Expect(os.ReadDir(volDir)).To(BeEmpty())
	})

	It("exits 125 after the wait when another instance holds the image, without starting the hypervisor", func() {
		requireOpenat2()
		writeImage(img, defaultImageSize, nil)
		holder, err := os.OpenFile(img, os.O_RDWR, 0)
		Expect(err).NotTo(HaveOccurred())
		defer holder.Close()
		Expect(syscall.Flock(int(holder.Fd()), syscall.LOCK_EX)).To(Succeed())
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")

		began := time.Now()
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(time.Since(began)).To(BeNumerically(">=", 300*time.Millisecond))
		Expect(logBuf.String()).To(ContainSubstring("volume image " + img + " is in use by another instance; VM backends allow one writer per image"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		noWorkDirs()
	})

	It("exits 125 for a symbolic link at the image name and leaves its target alone", func() {
		requireOpenat2()
		target := filepath.Join(GinkgoT().TempDir(), "passwd")
		Expect(os.WriteFile(target, []byte("root:x:0:0\n"), 0o644)).To(Succeed())
		Expect(os.Symlink(target, img)).To(Succeed())

		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("opening volume image " + img + ": too many levels of symbolic links"))
		Expect(os.ReadFile(target)).To(Equal([]byte("root:x:0:0\n")))
	})

	It("exits 124 when the hypervisor rejects the drive", func() {
		requireOpenat2()
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), `echo "qemu: Could not open '/proc/self/fd/3'" >&2; exit 1`)
		Expect(runVM(backend.VMQemu)).To(Equal(exitHypervisorFailed))
		Expect(logBuf.String()).To(ContainSubstring("hypervisor failed with exit status 1"))
	})

	It("exits 123 with the console tail when the guest cannot mount the volume", func() {
		requireOpenat2()
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"),
			`echo "vm-launch guest setup: mounting the volume image rvm-disk-2.img at /data failed; it is not blank"; exit 0`)
		Expect(runVM(backend.VMQemu)).To(Equal(exitMissingMarker))
		Expect(logBuf.String()).To(ContainSubstring("guest never started its command; last console output follows"))
		Expect(logBuf.String()).To(ContainSubstring("vm-launch guest setup: mounting the volume image rvm-disk-2.img at /data failed"))
		Expect(lockedElsewhere(img)).To(BeFalse())
	})
})
