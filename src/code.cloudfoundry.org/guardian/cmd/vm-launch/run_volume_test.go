//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
// flock that vm-launch's open file holds. The reopen uses fd 20, above every
// file vm-launch passes, because fd 4 is the initramfs when there is one
// volume and fd 9 is the root image when there are four.
func fdThreeChecks(img string) string {
	return imageAtFD("3", img)
}

// imageAtFD is fdThreeChecks for file descriptor fd.
func imageAtFD(fd, img string) string {
	return `[ -f /proc/self/fd/` + fd + ` ] || { echo "fd ` + fd + ` is not a regular file" >&2; exit 1; }
[ "$(stat -L -c %d:%i /proc/self/fd/` + fd + `)" = "$(stat -c %d:%i ` + shellQuote(img) + `)" ] || { echo "fd ` + fd + ` is not the image ` + img + `" >&2; exit 1; }
exec 20<>/proc/self/fd/` + fd + ` || { echo "cannot reopen /proc/self/fd/` + fd + `" >&2; exit 1; }
if flock -n 20; then echo "the image on fd ` + fd + ` is not locked" >&2; exit 1; fi
exec 20>&-
`
}

// noFDThree fails when the fake hypervisor's fd 3 is a volume image. Under
// qemu-user emulation the emulator itself may hold fd 3, so the check names
// the image rather than demanding that fd 3 be closed.
const noFDThree = `case "$(readlink /proc/self/fd/3 2>/dev/null)" in *rvm-disk-*) echo "fd 3 is a volume image without a volume" >&2; exit 1 ;; esac
`

var _ = Describe("stepExitCode", func() {
	It("maps a signal during the lock wait to 128+N", func() {
		Expect(stepExitCode(&signalledError{Sig: syscall.SIGTERM})).To(Equal(143))
		Expect(stepExitCode(&signalledError{Sig: syscall.SIGINT})).To(Equal(130))
		Expect(stepExitCode(fmt.Errorf("wrapped: %w", &signalledError{Sig: syscall.SIGTERM}))).To(Equal(143))
	})

	It("maps every other volume failure to 125", func() {
		for _, kind := range []error{errVolumeInUse, errNotMountRoot, errMountChanged, errImageNotRegular, errImageOwner, errImageLinks, errImageMode, errImageSize, errImageReplaced} {
			err := &volumeError{kind: kind, msg: "x"}
			Expect(errors.Is(err, kind)).To(BeTrue())
			Expect(stepExitCode(err)).To(Equal(exitLaunchError), kind.Error())
		}
		Expect(stepExitCode(syscall.ELOOP)).To(Equal(exitLaunchError))
		Expect(stepExitCode(errors.New("VCAP_SERVICES is not valid JSON"))).To(Equal(exitLaunchError))
		Expect(stepExitCode(nil)).To(Equal(0))
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

	It("passes the extra files in order, from the child's file descriptor 3", func() {
		f, err := os.Open(os.DevNull)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		g, err := os.Open(os.DevNull)
		Expect(err).NotTo(HaveOccurred())
		defer g.Close()
		cmd := newHypervisorCmd([]string{"/bin/true"}, []*os.File{f, g})
		Expect(cmd.ExtraFiles).To(HaveLen(2))
		Expect(cmd.ExtraFiles[0]).To(BeIdenticalTo(f))
		Expect(cmd.ExtraFiles[1]).To(BeIdenticalTo(g))
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
			sup := supervisor{stdout: &out, logger: log.New(&logBuf, "", 0), signals: make(chan os.Signal), grace: time.Second, deadline: time.Second}
			cmd := newHypervisorCmd([]string{script(fdThreeChecks(img) +
				"printf 'RVM_START_" + testNonce + "\\nvolume ok\\nRVM_EXIT_" + testNonce + "=0\\n'\n")}, []*os.File{f})
			res, err := sup.run(cmd, testNonce)
			Expect(err).NotTo(HaveOccurred())
			Expect(codeOf(res)).To(Equal(0), logBuf.String())
			Expect(out.String()).To(Equal("volume ok\n"))
		})

		It("keeps the image locked while the hypervisor lives, after vm-launch closes its copy", func() {
			cmd := newHypervisorCmd([]string{script("exec sleep 60\n")}, []*os.File{f})
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

		// setMountInfo makes the mount table show one mount, outside the
		// TMPDIR the specs check for leftovers.
		setMountInfo func(point, fstype string)
	)

	BeforeEach(func() {
		art = makeArtifacts()
		volDir = GinkgoT().TempDir()
		infoDir := GinkgoT().TempDir()
		setMountInfo = func(point, fstype string) {
			mountInfoPath = filepath.Join(infoDir, "mountinfo")
			Expect(os.WriteFile(mountInfoPath, []byte(mountinfoLine(40, point, fstype)), 0o644)).To(Succeed())
		}
		img = filepath.Join(volDir, "rvm-disk-"+testAppID+"-web-2.img")
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		GinkgoT().Setenv("CF_INSTANCE_INDEX", "2")
		GinkgoT().Setenv("VCAP_APPLICATION", vcapApp)
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"juicefs": {mountJSON(volDir, "rw")}}))
		logBuf = &bytes.Buffer{}

		DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)
		setMountInfo(volDir, "fuse.juicefs")

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

	It("exits 125 for a volume path under another volume path before it creates anything", func() {
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"juicefs": {mountJSON("/data/inner", "rw"), mountJSON("/data", "rw")}}))
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal(`volume path "/data/inner" is on or under volume path "/data"; VM backends need every volume path to be outside every other volume path, so give each volume a path of its own` + "\n"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(volDir)).To(BeEmpty())
		noWorkDirs()
	})

	It("exits 125 for a volume path and the same path with a trailing slash before it creates anything", func() {
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"juicefs": {mountJSON("/data", "rw"), mountJSON("/data/", "rw")}}))
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal(`volume path "/data/" is not a clean path` + "\n"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		noWorkDirs()
	})

	It("exits 125 for five volume mounts before it creates anything", func() {
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"juicefs": {mountJSON(volDir, "rw"), mountJSON("/a", "rw")}, "nfs": {mountJSON("/b", "rw"), mountJSON("/c", "rw"), mountJSON("/d", "rw")}}))
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal("VM backends support up to 4 volume mounts; this app has 5\n"))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(os.ReadDir(volDir)).To(BeEmpty())
		Expect(argvFile).NotTo(BeAnExistingFile())
	})

	It("exits 125 for two volume mounts on one path before it creates anything", func() {
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"juicefs": {mountJSON(volDir, "rw")}, "nfs": {mountJSON(volDir, "rw")}}))
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal("volume path " + quoteForLog(volDir) + " has 2 volume mounts; each volume mount on a VM backend needs a path of its own\n"))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(os.ReadDir(volDir)).To(BeEmpty())
		Expect(argvFile).NotTo(BeAnExistingFile())
	})

	It("exits 125 before it creates anything when the volume is not a JuiceFS mount", func() {
		for _, fstype := range []string{"cifs", "ext4"} {
			setMountInfo(volDir, fstype)
			logBuf.Reset()
			argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
			Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError), fstype)
			Expect(logBuf.String()).To(ContainSubstring(strconv.Quote(fstype)))
			Expect(logBuf.String()).To(ContainSubstring("VM backends support only BOSH disk, JuiceFS, and NFS volumes today"))
			Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel))
			Expect(os.ReadDir(tmp)).To(BeEmpty())
			Expect(os.ReadDir(volDir)).To(BeEmpty())
			Expect(argvFile).NotTo(BeAnExistingFile())
		}
	})

	It("exits 125 when the volume path has no mount entry", func() {
		setMountInfo("/elsewhere", "fuse.juicefs")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("has no mount entry"))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("does not read the mount table for an app with no volume", func() {
		GinkgoT().Setenv("VCAP_SERVICES", `{}`)
		mountInfoPath = filepath.Join(volDir, "absent")
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), noFDThree)
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
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
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), fdThreeChecks(img)+initramfsAt("4")+initramfsReleased+noFilesUnder(tmp)+
			`gzip -dc "$initrd" | grep -a -q -F `+shellQuote("RVM_VOL0_PATH="+shellQuote(volDir))+` || { echo "no /rvm/mounts" >&2; exit 1; }
`)
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())

		argv, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(argv)).To(HaveSuffix("\n" + strings.Join(concat(goldenQEMUDrive, goldenQEMUMonitor("5"), goldenQEMUBalloon), "\n") + "\n"))
		Expect(string(argv)).To(ContainSubstring("\n-initrd\n/proc/self/fd/4\n"))
		Expect(string(argv)).NotTo(ContainSubstring(volDir))

		Expect(statOf(img).Size).To(Equal(int64(defaultImageSize)))
		Expect(lockedElsewhere(img)).To(BeFalse(), "the lock ends with the run")
		noWorkDirs()
	})

	It("names the guest root image and the volume image in /rvm/disks by identity, with the sizes of the drives the hypervisor gets, even when the two sizes are equal", func() {
		requireOpenat2()
		// With room in the work directory, this quota makes the root image
		// exactly the volume image's size, which the guest's lookup by
		// identity allows.
		limit := defaultImageSize/bytesPerMiB + rootDiskHeadroomMiB
		GinkgoT().Setenv("VCAP_APPLICATION", `{"application_id":"`+testAppID+`","process_type":"web","name":"app","limits":{"disk":`+strconv.Itoa(limit)+`}}`)
		initrdCopy := filepath.Join(GinkgoT().TempDir(), "initrd")
		sizesFile := filepath.Join(GinkgoT().TempDir(), "sizes")
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), fdThreeChecks(img)+initramfsAt("4")+
			`cp "$initrd" `+shellQuote(initrdCopy)+` || exit 1
stat -L -c %s /proc/self/fd/3 /proc/self/fd/6 >`+shellQuote(sizesFile)+` || exit 1
`)
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())

		raw, err := os.ReadFile(sizesFile)
		Expect(err).NotTo(HaveOccurred())
		sizes := strings.Fields(string(raw))
		Expect(sizes).To(HaveLen(2))
		Expect(sizes[0]).To(Equal(strconv.Itoa(defaultImageSize)))
		root, err := strconv.ParseInt(sizes[1], 10, 64)
		Expect(err).NotTo(HaveOccurred())
		var st syscall.Statfs_t
		Expect(syscall.Statfs(tmp, &st)).To(Succeed())
		if int64(st.Bavail)*st.Bsize/bytesPerMiB >= int64(limit) {
			Expect(root).To(Equal(int64(defaultImageSize)))
		}

		initrd, err := os.ReadFile(initrdCopy)
		Expect(err).NotTo(HaveOccurred())
		_, byName := archiveEntries(initrd)
		Expect(string(byName["rvm/disks"].data)).To(Equal(fmt.Sprintf("RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=%d\nRVM_ROOT_INODE_RATIO=%d\nRVM_VOLUMES=1\nRVM_VOL0_KIND=image\nRVM_VOL0_ID=rvm-vol0\nRVM_VOL0_SECTORS=%d\n",
			root/512, inodeRatioFor(root), defaultImageSize/512)))
		Expect(string(byName["rvm/mounts"].data)).NotTo(ContainSubstring("RVM_VOLUME_DEVICE"))
		noWorkDirs()
	})

	It("gives Firecracker the locked image as its one drive", func() {
		requireOpenat2()
		fcCopy := filepath.Join(GinkgoT().TempDir(), "fc.json")
		writeFakeHypervisor(filepath.Join(art, "firecracker/firecracker"), fdThreeChecks(img)+initramfsAt("4")+initramfsReleased+noFilesUnder(tmp)+
			`p=; for a in "$@"; do [ "$p" = --config-file ] && cp "$a" `+shellQuote(fcCopy)+`; p=$a; done
`)
		Expect(runVM(backend.VMFirecracker)).To(Equal(0), logBuf.String())

		cfg, err := os.ReadFile(fcCopy)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(cfg)).To(ContainSubstring(goldenFCDrive))
		Expect(string(cfg)).To(ContainSubstring(`"initrd_path":"/proc/self/fd/4"`))
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

var _ = Describe("run with several volumes", func() {
	const imageName = "rvm-disk-" + testAppID + "-web-2.img"
	var (
		art     string
		tmp     string
		scratch string
		infoDir string
		logBuf  *bytes.Buffer

		// dirs are the volume directories in volume order, and imgs the
		// image each one gets.
		dirs []string
		imgs []string
	)

	// setMountInfo makes the mount table the given lines, outside the TMPDIR
	// the specs check for leftovers.
	setMountInfo := func(lines ...string) {
		mountInfoPath = filepath.Join(infoDir, "mountinfo")
		Expect(os.WriteFile(mountInfoPath, []byte(strings.Join(lines, "")), 0o644)).To(Succeed())
	}

	// bindWith binds n volume directories, each the root of a mount of its
	// own that mountLine describes, with the labels and the mounts in
	// VCAP_SERVICES in the opposite order to the paths. With an odd n all the
	// mounts are in one binding under label.
	bindWith := func(n int, label string, mountLine func(id int, dir string) string) {
		dirs, imgs = nil, nil
		var table []string
		labels := map[string][]string{}
		var oneBinding []string
		for i := range n {
			d := filepath.Join(scratch, "vol"+strconv.Itoa(i))
			Expect(os.Mkdir(d, 0o755)).To(Succeed())
			dirs = append(dirs, d)
			imgs = append(imgs, filepath.Join(d, imageName))
			table = append(table, mountLine(40+i, d))
			labels["l"+strconv.Itoa(n-i)] = []string{mountJSON(d, "rw")}
			oneBinding = append([]string{mountJSON(d, "rw")}, oneBinding...)
		}
		setMountInfo(table...)
		if n%2 == 0 {
			GinkgoT().Setenv("VCAP_SERVICES", vcapWith(labels))
		} else {
			GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{label: oneBinding}))
		}
	}

	// bind binds n volume directories, each the root of a JuiceFS mount of
	// its own.
	bind := func(n int) {
		bindWith(n, "juicefs", func(id int, d string) string { return mountinfoLine(id, d, "fuse.juicefs") })
	}

	// bindNFS binds n volume directories, each the root of a kernel NFSv4
	// mount of its own with local_lock=none, and makes the mount ID probe
	// answer for them, since the directories are not mounts.
	bindNFS := func(n int) {
		bindWith(n, "nfs", func(id int, d string) string {
			return nfsMountinfoLine(id, d, "nfs4", "10.0.0.5:/export"+strconv.Itoa(id), labNFSOptions)
		})
		DeferCleanup(func(saved func(int, string) (mountProbe, error)) { dirProbe = saved }, dirProbe)
		dirProbe = func(_ int, dir string) (mountProbe, error) {
			i := slices.Index(dirs, dir)
			if i < 0 {
				return mountProbe{}, fmt.Errorf("no volume directory %s", dir)
			}
			return mountProbe{MountID: uint64(40 + i), MountRoot: true}, nil
		}
	}

	BeforeEach(func() {
		art = makeArtifacts()
		scratch = GinkgoT().TempDir()
		infoDir = GinkgoT().TempDir()
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		GinkgoT().Setenv("CF_INSTANCE_INDEX", "2")
		GinkgoT().Setenv("VCAP_APPLICATION", vcapApp)
		logBuf = &bytes.Buffer{}
		DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)

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

	// diskFile returns a new disk of size bytes for a fake provider, outside
	// TMPDIR.
	diskFile := func(size int64) *os.File {
		f, err := os.CreateTemp(scratch, "disk")
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Truncate(size)).To(Succeed())
		return f
	}

	It("gives QEMU each locked image on its own file descriptor, in the order of the paths, and the initramfs after them", func() {
		requireOpenat2()
		bind(4)
		var checks string
		for i, img := range imgs {
			checks += imageAtFD(strconv.Itoa(3+i), img)
		}
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), checks+initramfsAt("7")+initramfsReleased+noFilesUnder(tmp))
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())

		argv, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		drives := concat(goldenQEMUVolumeDrive(0, "3"), goldenQEMUVolumeDrive(1, "4"), goldenQEMUVolumeDrive(2, "5"), goldenQEMUVolumeDrive(3, "6"), goldenQEMUMonitor("8"), goldenQEMUBalloon)
		Expect(string(argv)).To(HaveSuffix("\n" + strings.Join(drives, "\n") + "\n"))
		Expect(string(argv)).To(ContainSubstring("\n-initrd\n/proc/self/fd/7\n"))
		for i, img := range imgs {
			Expect(string(argv)).NotTo(ContainSubstring(dirs[i]))
			Expect(statOf(img).Size).To(Equal(int64(defaultImageSize)))
			Expect(lockedElsewhere(img)).To(BeFalse(), "the lock on %s ends with the run", img)
		}
		noWorkDirs()
	})

	It("gives four NFS volumes what four JuiceFS volumes get: each image on its own descriptor, in the order of the paths, locked until the run ends", func() {
		requireOpenat2()
		bindNFS(4)
		// The NFS provider allocates the whole image, so the images are small.
		const size = 4 << 20
		defaultImageOptions.Size = size
		var checks string
		for i, img := range imgs {
			checks += imageAtFD(strconv.Itoa(3+i), img)
		}
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), checks+initramfsAt("7")+initramfsReleased+noFilesUnder(tmp))
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())

		argv, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		drives := concat(goldenQEMUVolumeDrive(0, "3"), goldenQEMUVolumeDrive(1, "4"), goldenQEMUVolumeDrive(2, "5"), goldenQEMUVolumeDrive(3, "6"), goldenQEMUMonitor("8"), goldenQEMUBalloon)
		Expect(string(argv)).To(HaveSuffix("\n" + strings.Join(drives, "\n") + "\n"))
		for i, img := range imgs {
			Expect(string(argv)).NotTo(ContainSubstring(dirs[i]))
			Expect(statOf(img).Size).To(Equal(int64(size)))
			Expect(lockedElsewhere(img)).To(BeFalse(), "the lock on %s ends with the run", img)
			entries, err := os.ReadDir(dirs[i])
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(1), "no temp name stays beside the image")
		}
		noWorkDirs()
	})

	It("gives each provider its own volume when one is JuiceFS and one is NFS, with the duplicate check and the shared lock wait for both", func() {
		bind(2)
		setMountInfo(mountinfoLine(40, dirs[0], "fuse.juicefs"),
			nfsMountinfoLine(41, dirs[1], "nfs4", "10.0.0.5:/export", labNFSOptions))
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{
			"nfs":     {mountJSON(dirs[1], "rw")},
			"juicefs": {mountJSON(dirs[0], "rw")},
		}))
		type call struct {
			provider    string
			dir         string
			before      bool
			budget      *lockBudget
			noDuplicate bool
		}
		var calls []call
		var released []string
		prepare := func(name string) func(prepareRequest) (*attachment, error) {
			return func(r prepareRequest) (*attachment, error) {
				c := call{provider: name, dir: r.Mount.ContainerDir, before: r.BeforeLock != nil, budget: r.LockBudget}
				Expect(r.ImageName).To(Equal(imageName))
				Expect(r.Mode).To(Equal(attachFileImage))
				f := diskFile(defaultImageSize)
				if r.BeforeLock != nil {
					// A provider that calls BeforeLock before it locks sees the
					// duplicate check pass for a disk of its own.
					c.noDuplicate = r.BeforeLock(f) == nil
				}
				calls = append(calls, c)
				return &attachment{File: f, Release: func() error { released = append(released, name); return f.Close() }}, nil
			}
		}
		juice, nfs := fake("JuiceFS", "fuse.juicefs", strongMatch), fake("NFS", "nfs4", strongMatch)
		juice.prepare, nfs.prepare = prepare("JuiceFS"), prepare("NFS")
		withProviders(juice, nfs)
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())

		Expect(calls).To(HaveLen(2))
		Expect(calls[0].provider).To(Equal("JuiceFS"))
		Expect(calls[0].dir).To(Equal(dirs[0]))
		Expect(calls[1].provider).To(Equal("NFS"))
		Expect(calls[1].dir).To(Equal(dirs[1]))
		for _, c := range calls {
			Expect(c.before).To(BeTrue(), "%s got BeforeLock", c.provider)
			Expect(c.noDuplicate).To(BeTrue(), "%s: its own disk is not a duplicate", c.provider)
			Expect(c.budget).NotTo(BeNil(), "%s got the shared lock budget", c.provider)
		}
		Expect(calls[1].budget).To(BeIdenticalTo(calls[0].budget), "one lock wait for both volumes")
		Expect(released).To(Equal([]string{"NFS", "JuiceFS"}))
		argv, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(argv)).To(ContainSubstring(strings.Join(concat(goldenQEMUVolumeDrive(0, "3"), goldenQEMUVolumeDrive(1, "4")), "\n")))
	})

	It("gives Firecracker each locked image as a drive of its own, in the order of the paths", func() {
		requireOpenat2()
		bind(2)
		fcCopy := filepath.Join(scratch, "fc.json")
		writeFakeHypervisor(filepath.Join(art, "firecracker/firecracker"), imageAtFD("3", imgs[0])+imageAtFD("4", imgs[1])+initramfsAt("5")+initramfsReleased+noFilesUnder(tmp)+
			`p=; for a in "$@"; do [ "$p" = --config-file ] && cp "$a" `+shellQuote(fcCopy)+`; p=$a; done
`)
		Expect(runVM(backend.VMFirecracker)).To(Equal(0), logBuf.String())

		cfg, err := os.ReadFile(fcCopy)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(cfg)).To(ContainSubstring(`"drives":[` + goldenFCVolumeDrive(0, "3") + `,` + goldenFCVolumeDrive(1, "4") + `]`))
		Expect(string(cfg)).To(ContainSubstring(`"initrd_path":"/proc/self/fd/5"`))
		for _, d := range dirs {
			Expect(string(cfg)).NotTo(ContainSubstring(d))
		}
		noWorkDirs()
	})

	It("tells the guest every volume's path, image, identity, and size, in the order of the paths", func() {
		requireOpenat2()
		bind(3)
		initrdCopy := filepath.Join(scratch, "initrd")
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), initramfsAt("6")+`cp "$initrd" `+shellQuote(initrdCopy)+" || exit 1\n")
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		initrd, err := os.ReadFile(initrdCopy)
		Expect(err).NotTo(HaveOccurred())
		_, byName := archiveEntries(initrd)
		sectors := defaultImageSize / 512
		Expect(string(byName["rvm/disks"].data)).To(HaveSuffix(fmt.Sprintf("RVM_VOLUMES=3\n"+
			"RVM_VOL0_KIND=image\nRVM_VOL0_ID=rvm-vol0\nRVM_VOL0_SECTORS=%d\n"+
			"RVM_VOL1_KIND=image\nRVM_VOL1_ID=rvm-vol1\nRVM_VOL1_SECTORS=%d\n"+
			"RVM_VOL2_KIND=image\nRVM_VOL2_ID=rvm-vol2\nRVM_VOL2_SECTORS=%d\n", sectors, sectors, sectors)))
		Expect(string(byName["rvm/disks"].data)).NotTo(ContainSubstring("RVM_VOLUME_"))
		Expect(string(byName["rvm/mounts"].data)).To(Equal("RVM_VOLUMES=3\nRVM_SYNC_MOUNTS=true\n" +
			"RVM_VOL0_KIND=image\nRVM_VOL0_PATH=" + shellQuote(dirs[0]) + "\nRVM_VOL0_IMAGE=" + shellQuote(imageName) + "\n" +
			"RVM_VOL1_KIND=image\nRVM_VOL1_PATH=" + shellQuote(dirs[1]) + "\nRVM_VOL1_IMAGE=" + shellQuote(imageName) + "\n" +
			"RVM_VOL2_KIND=image\nRVM_VOL2_PATH=" + shellQuote(dirs[2]) + "\nRVM_VOL2_IMAGE=" + shellQuote(imageName) + "\n"))
	})

	It("tells the guest that the operator turned sync mounts off with --volume-sync-mounts=false, and that they are on otherwise", func() {
		requireOpenat2()
		bind(1)
		initrdCopy := filepath.Join(scratch, "initrd")
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), initramfsAt("4")+`cp "$initrd" `+shellQuote(initrdCopy)+" || exit 1\n")
		mounts := func(flags ...string) string {
			GinkgoHelper()
			Expect(os.RemoveAll(initrdCopy)).To(Succeed())
			argv := append(append([]string{"--backend", string(backend.VMQemu), "--artifacts", art}, flags...), "--", "/tmp/lifecycle/launcher", "app", "true", "")
			Expect(run(argv, log.New(logBuf, "", 0))).To(Equal(0), logBuf.String())
			initrd, err := os.ReadFile(initrdCopy)
			Expect(err).NotTo(HaveOccurred())
			_, byName := archiveEntries(initrd)
			return string(byName["rvm/mounts"].data)
		}
		want := "RVM_VOLUMES=1\nRVM_SYNC_MOUNTS=%s\nRVM_VOL0_KIND=image\nRVM_VOL0_PATH=" + shellQuote(dirs[0]) + "\nRVM_VOL0_IMAGE=" + shellQuote(imageName) + "\n"
		Expect(mounts()).To(Equal(fmt.Sprintf(want, "true")))
		Expect(mounts("--" + volumeSyncMountsFlag + "=false")).To(Equal(fmt.Sprintf(want, "false")))
		Expect(mounts("--" + volumeSyncMountsFlag + "=true")).To(Equal(fmt.Sprintf(want, "true")))
		Expect(mounts("--" + volumeSyncMountsFlag)).To(Equal(fmt.Sprintf(want, "true")))
		noWorkDirs()
	})

	It("prepares the volumes in the order of the paths and, when one fails, releases every one it prepared, last first, after the failure's line", func() {
		for failAt := range 4 {
			for name, failure := range map[string]struct {
				err  error
				code int
			}{
				"an ordinary error": {errors.New("the fake disk failed"), exitLaunchError},
				"a signal":          {&signalledError{Sig: syscall.SIGTERM, during: "waiting for the fake disk"}, 128 + int(syscall.SIGTERM)},
			} {
				bind(4)
				var prepared, released []string
				p := fake("Fake", "fuse.juicefs", strongMatch)
				p.prepare = func(r prepareRequest) (*attachment, error) {
					Expect(r.ImageName).To(Equal(imageName))
					Expect(r.Mode).To(Equal(attachFileImage))
					dir := r.Mount.ContainerDir
					prepared = append(prepared, dir)
					if len(prepared) == failAt+1 {
						return nil, failure.err
					}
					f := diskFile(defaultImageSize)
					return &attachment{File: f, Release: func() error {
						released = append(released, dir)
						Expect(f.Close()).To(Succeed())
						return errors.New("the fence of " + filepath.Base(dir) + " would not let go")
					}}, nil
				}
				withProviders(p)
				logBuf.Reset()
				argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
				Expect(runVM(backend.VMQemu)).To(Equal(failure.code), "%s at volume %d", name, failAt)
				Expect(prepared).To(Equal(dirs[:failAt+1]), "%s at volume %d", name, failAt)
				want := slices.Clone(dirs[:failAt])
				slices.Reverse(want)
				Expect(slices.Equal(released, want)).To(BeTrue(), "%s at volume %d released %q, want %q", name, failAt, released, want)
				lines := failure.err.Error() + "\n"
				if _, ok := failure.err.(*signalledError); ok {
					lines = "received terminated while waiting for the fake disk\n"
				}
				for _, d := range want {
					lines += "releasing the volume disk: the fence of " + filepath.Base(d) + " would not let go\n"
				}
				Expect(logBuf.String()).To(HaveSuffix(lines), "%s at volume %d", name, failAt)
				Expect(argvFile).NotTo(BeAnExistingFile())
				Expect(os.ReadDir(tmp)).To(BeEmpty())
				Expect(os.RemoveAll(scratch)).To(Succeed())
				Expect(os.Mkdir(scratch, 0o755)).To(Succeed())
			}
		}
	})

	It("releases the volumes prepared before an unusable attachment, and cleans up the unusable one", func() {
		bind(3)
		var released []string
		var half *os.File
		p := fake("Fake", "fuse.juicefs", strongMatch)
		p.prepare = func(r prepareRequest) (*attachment, error) {
			dir := r.Mount.ContainerDir
			f := diskFile(defaultImageSize)
			if dir == dirs[2] {
				half = f
				return &attachment{File: f}, nil
			}
			return &attachment{File: f, Release: func() error { released = append(released, dir); return f.Close() }}, nil
		}
		withProviders(p)
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(HaveSuffix("the Fake volume provider prepared the disk without an error but returned no Release function\n"))
		Expect(released).To(Equal([]string{dirs[1], dirs[0]}))
		Expect(half.Close()).NotTo(Succeed(), "the unusable attachment's file was closed")
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	// sameImageLine is the refusal of two volumes that reach one image.
	sameImageLine := func() string {
		return "volume paths " + quoteForLog(dirs[0]) + " and " + quoteForLog(dirs[1]) + " reach the same disk; bind each volume to a directory of its own\n"
	}

	It("refuses at once, without a lock wait, two volumes whose images are one file when the provider takes the lock", func() {
		requireOpenat2()
		bind(2)
		// The wait is long enough that waiting for the lock would fail the
		// spec on time, and the provider takes a real flock, as JuiceFS does:
		// both volumes open the one image in dirs[0], so the second one's
		// flock would conflict with the first one's.
		defaultImageOptions.LockWait = 20 * time.Second
		var released []string
		p := fake("Fake", "fuse.juicefs", strongMatch)
		p.prepare = func(r prepareRequest) (*attachment, error) {
			opts := defaultImageOptions
			opts.BeforeLock = r.BeforeLock
			opts.LockBudget = r.LockBudget
			dir := r.Mount.ContainerDir
			f, err := openVolumeImage(&guestVolume{ContainerDir: dirs[0], ImageName: r.ImageName}, opts, r.Signals)
			if err != nil {
				return nil, err
			}
			return &attachment{File: f, Release: func() error { released = append(released, dir); return f.Close() }}, nil
		}
		withProviders(p)
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		began := time.Now()
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(time.Since(began)).To(BeNumerically("<", 5*time.Second), "the duplicate did not wait for the lock")
		Expect(logBuf.String()).To(HaveSuffix(sameImageLine()))
		Expect(logBuf.String()).NotTo(ContainSubstring("in use by another instance"))
		Expect(released).To(Equal([]string{dirs[0]}))
		Expect(lockedElsewhere(imgs[0])).To(BeFalse(), "the lock ended with the run")
		Expect(argvFile).NotTo(BeAnExistingFile())
		noWorkDirs()
	})

	It("still refuses two volumes whose disks are one file when the provider calls no BeforeLock, and releases both", func() {
		bind(2)
		shared := diskFile(defaultImageSize)
		Expect(shared.Close()).To(Succeed())
		var released []string
		p := fake("Fake", "fuse.juicefs", strongMatch)
		p.prepare = func(r prepareRequest) (*attachment, error) {
			dir := r.Mount.ContainerDir
			f, err := os.OpenFile(shared.Name(), os.O_RDWR, 0)
			Expect(err).NotTo(HaveOccurred())
			return &attachment{File: f, Release: func() error { released = append(released, dir); return f.Close() }}, nil
		}
		withProviders(p)
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(HaveSuffix(sameImageLine()))
		Expect(released).To(Equal([]string{dirs[1], dirs[0]}))
		Expect(argvFile).NotTo(BeAnExistingFile())
	})

	It("refuses a duplicate across a JuiceFS and an NFS volume before either provider waits for a lock", func() {
		bind(2)
		setMountInfo(mountinfoLine(40, dirs[0], "fuse.juicefs"),
			nfsMountinfoLine(41, dirs[1], "nfs4", "10.0.0.5:/export", labNFSOptions))
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{
			"nfs":     {mountJSON(dirs[1], "rw")},
			"juicefs": {mountJSON(dirs[0], "rw")},
		}))
		shared := diskFile(defaultImageSize)
		Expect(shared.Close()).To(Succeed())
		var released []string
		prepare := func(name string) func(prepareRequest) (*attachment, error) {
			return func(r prepareRequest) (*attachment, error) {
				f, err := os.OpenFile(shared.Name(), os.O_RDWR, 0)
				Expect(err).NotTo(HaveOccurred())
				if err := r.BeforeLock(f); err != nil {
					Expect(f.Close()).To(Succeed())
					return nil, err
				}
				return &attachment{File: f, Release: func() error { released = append(released, name); return f.Close() }}, nil
			}
		}
		juice, nfs := fake("JuiceFS", "fuse.juicefs", strongMatch), fake("NFS", "nfs4", strongMatch)
		juice.prepare, nfs.prepare = prepare("JuiceFS"), prepare("NFS")
		withProviders(juice, nfs)
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(HaveSuffix(sameImageLine()))
		Expect(released).To(Equal([]string{"JuiceFS"}))
		Expect(argvFile).NotTo(BeAnExistingFile())
		noWorkDirs()
	})

	It("boots volume images of different sizes, naming each drive's own size in /rvm/disks, and releases them all", func() {
		bind(3)
		var released []string
		p := fake("Fake", "fuse.juicefs", strongMatch)
		p.prepare = func(r prepareRequest) (*attachment, error) {
			dir := r.Mount.ContainerDir
			size := int64(defaultImageSize)
			if dir == dirs[2] {
				size = 2 * defaultImageSize
			}
			f := diskFile(size)
			return &attachment{File: f, Release: func() error { released = append(released, dir); return f.Close() }}, nil
		}
		withProviders(p)
		initrdCopy := filepath.Join(scratch, "initrd")
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), initramfsAt("6")+`cp "$initrd" `+shellQuote(initrdCopy)+" || exit 1\n")
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		initrd, err := os.ReadFile(initrdCopy)
		Expect(err).NotTo(HaveOccurred())
		_, byName := archiveEntries(initrd)
		Expect(string(byName["rvm/disks"].data)).To(HaveSuffix(fmt.Sprintf("RVM_VOL0_SECTORS=%d\n", defaultImageSize/512) +
			"RVM_VOL1_KIND=image\nRVM_VOL1_ID=rvm-vol1\n" + fmt.Sprintf("RVM_VOL1_SECTORS=%d\n", defaultImageSize/512) +
			"RVM_VOL2_KIND=image\nRVM_VOL2_ID=rvm-vol2\n" + fmt.Sprintf("RVM_VOL2_SECTORS=%d\n", 2*defaultImageSize/512)))
		Expect(released).To(Equal([]string{dirs[2], dirs[1], dirs[0]}))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("releases every volume after the hypervisor exits, last first", func() {
		bind(3)
		hypervisorDone := filepath.Join(scratch, "hypervisor-done")
		var released []string
		p := fake("Fake", "fuse.juicefs", strongMatch)
		p.prepare = func(r prepareRequest) (*attachment, error) {
			dir := r.Mount.ContainerDir
			f := diskFile(defaultImageSize)
			return &attachment{File: f, Release: func() error {
				Expect(hypervisorDone).To(BeAnExistingFile(), "Release runs after the hypervisor")
				released = append(released, dir)
				return f.Close()
			}}, nil
		}
		withProviders(p)
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), `: >`+shellQuote(hypervisorDone)+"\n")
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		Expect(released).To(Equal([]string{dirs[2], dirs[1], dirs[0]}))
	})

	It("checks every volume's mount before it prepares any, and creates nothing when a later one is refused", func() {
		requireOpenat2()
		bind(3)
		setMountInfo(mountinfoLine(40, dirs[0], "fuse.juicefs"), mountinfoLine(41, dirs[1], "fuse.juicefs"), mountinfoLine(42, dirs[2], "cifs"))
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(HaveSuffix("volume path " + quoteForLog(dirs[2]) + ` is a "cifs" mount; VM backends support only BOSH disk, JuiceFS, and NFS volumes today` + "\n"))
		for _, d := range dirs {
			Expect(os.ReadDir(d)).To(BeEmpty())
		}
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(argvFile).NotTo(BeAnExistingFile())
	})

	It("refuses two volumes that show one directory of one filesystem before it creates anything", func() {
		requireOpenat2()
		bind(2)
		// Two mounts of one JuiceFS directory, as two service instances that
		// name one share would give: one device and one root.
		setMountInfo("40 29 0:52 /share "+dirs[0]+" rw,relatime shared:40 - fuse.juicefs JuiceFS:vol rw\n",
			"41 29 0:52 /share "+dirs[1]+" rw,relatime shared:41 - fuse.juicefs JuiceFS:vol rw\n")
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(HaveSuffix("volume paths " + quoteForLog(dirs[0]) + " and " + quoteForLog(dirs[1]) +
			` are the same directory of one filesystem (device 0:52, root "/share"), so they would share one disk; bind each volume to a directory of its own` + "\n"))
		for _, d := range dirs {
			Expect(os.ReadDir(d)).To(BeEmpty())
		}
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(argvFile).NotTo(BeAnExistingFile())
	})

	It("starts two volumes on one filesystem when each shows a directory of its own", func() {
		requireOpenat2()
		bind(2)
		setMountInfo("40 29 0:52 /a "+dirs[0]+" rw,relatime shared:40 - fuse.juicefs JuiceFS:vol rw\n",
			"41 29 0:52 /b "+dirs[1]+" rw,relatime shared:41 - fuse.juicefs JuiceFS:vol rw\n")
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), imageAtFD("3", imgs[0])+imageAtFD("4", imgs[1]))
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
	})

	It("exits 125 after the wait when another instance holds a later volume's image, and lets go of the earlier ones", func() {
		requireOpenat2()
		bind(2)
		writeImage(imgs[1], defaultImageSize, nil)
		holder, err := os.OpenFile(imgs[1], os.O_RDWR, 0)
		Expect(err).NotTo(HaveOccurred())
		defer holder.Close()
		Expect(syscall.Flock(int(holder.Fd()), syscall.LOCK_EX)).To(Succeed())
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")

		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("volume image " + imgs[1] + " is in use by another instance; VM backends allow one writer per image"))
		Expect(logBuf.String()).To(ContainSubstring("; with more than one volume bound, two of this app's bindings may be the same share, in which case an earlier volume of this launch holds the lock\n"))
		Expect(statOf(imgs[0]).Size).To(Equal(int64(defaultImageSize)))
		Expect(lockedElsewhere(imgs[0])).To(BeFalse(), "the first volume's lock ended")
		Expect(argvFile).NotTo(BeAnExistingFile())
		noWorkDirs()
	})

	It("gives all the volumes one lock wait together, so that waits on several contended volumes do not add up", func() {
		requireOpenat2()
		bind(3)
		for _, img := range imgs[1:] {
			writeImage(img, defaultImageSize, nil)
		}
		holders := make([]*os.File, 2)
		for i, img := range imgs[1:] {
			h, err := os.OpenFile(img, os.O_RDWR, 0)
			Expect(err).NotTo(HaveOccurred())
			defer h.Close()
			Expect(syscall.Flock(int(h.Fd()), syscall.LOCK_EX)).To(Succeed())
			holders[i] = h
		}
		// The second volume's holder lets go after 600 ms. Each volume would
		// get the full second on a wait of its own, so the third volume would
		// fail at about 1.6 s. With one wait for the launch, it fails at about
		// 1 s.
		defaultImageOptions.LockWait = time.Second
		go func() {
			defer GinkgoRecover()
			time.Sleep(600 * time.Millisecond)
			Expect(holders[0].Close()).To(Succeed())
		}()
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")

		began := time.Now()
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		took := time.Since(began)
		Expect(took).To(BeNumerically(">=", time.Second), "the third volume waited out what was left")
		Expect(took).To(BeNumerically("<", 1400*time.Millisecond), "the waits did not add up")
		Expect(logBuf.String()).To(ContainSubstring("volume image " + imgs[2] + " is in use by another instance"))
		Expect(lockedElsewhere(imgs[0])).To(BeFalse(), "the first volume's lock ended")
		Expect(lockedElsewhere(imgs[1])).To(BeFalse(), "the second volume's lock ended")
		Expect(argvFile).NotTo(BeAnExistingFile())
		noWorkDirs()
	})
})
