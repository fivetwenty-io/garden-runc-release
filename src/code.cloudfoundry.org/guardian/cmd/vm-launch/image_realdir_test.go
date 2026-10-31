//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// These specs run the image engine and the NFS provider on a directory that
// the caller names, so that they can be pointed at a real NFS mount. They are
// skipped unless VM_LAUNCH_TEST_IMAGE_DIR names an existing directory, and
// only the tests read these variables, never vm-launch.
//
//	VM_LAUNCH_TEST_IMAGE_DIR  a directory on the volume to test. Each spec
//	                          makes its own vm-launch-test-* subdirectory in it
//	                          and removes it afterwards.
//	VM_LAUNCH_TEST_IMAGE_MIB  the size of the images the specs create, in MiB.
//	                          The default is 64.
//	VM_LAUNCH_TEST_IMAGE_EXPECT_QUOTA_REFUSAL
//	                          set to 1 with an image size above the volume's
//	                          free space, to run the spec that expects the
//	                          quota to refuse the image.
const (
	imageDirEnv = "VM_LAUNCH_TEST_IMAGE_DIR"
	imageMiBEnv = "VM_LAUNCH_TEST_IMAGE_MIB"

	defaultTestImageMiB = 64
)

var _ = Describe("an image on the directory named by "+imageDirEnv, func() {
	var (
		dir  string
		size int64
		img  string
		name = "rvm-disk-0.img"
	)

	BeforeEach(func() {
		base := os.Getenv(imageDirEnv)
		if base == "" {
			Skip("set " + imageDirEnv + " to a directory on the volume to run these specs")
		}
		requireOpenat2()
		fi, err := os.Stat(base)
		Expect(err).NotTo(HaveOccurred(), "%s=%s", imageDirEnv, base)
		Expect(fi.IsDir()).To(BeTrue(), "%s=%s is not a directory", imageDirEnv, base)

		size = defaultTestImageMiB << 20
		if v := os.Getenv(imageMiBEnv); v != "" {
			mib, err := strconv.ParseInt(v, 10, 32)
			Expect(err).NotTo(HaveOccurred(), "%s=%s", imageMiBEnv, v)
			Expect(mib).To(BeNumerically(">", 0), "%s=%s", imageMiBEnv, v)
			size = mib << 20
		}

		dir, err = os.MkdirTemp(base, "vm-launch-test-")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			if err := os.RemoveAll(dir); err != nil {
				GinkgoWriter.Printf("removing %s: %v\n", dir, err)
			}
		})
		img = filepath.Join(dir, name)

		// The real kernel answers the mount questions, and the directory is
		// treated as the volume root even when it is a subdirectory of the
		// mount, so that the specs need no mount of their own.
		savedProbe, savedDirProbe, savedDefaults := volumeProbe, dirProbe, defaultImageOptions
		DeferCleanup(func() { volumeProbe, dirProbe, defaultImageOptions = savedProbe, savedDirProbe, savedDefaults })
		volumeProbe, dirProbe = probeVolume, probeMountFD
		defaultImageOptions.IsMountRoot = alwaysMountRoot
		defaultImageOptions.Size = size
		defaultImageOptions.LockWait = 2 * time.Second
		defaultImageOptions.LockPoll = 50 * time.Millisecond
	})

	// noSillyRenames fails when the directory holds a hidden .nfs file, which an
	// NFS client makes when a name is unlinked while it is open.
	noSillyRenames := func() {
		entries, err := os.ReadDir(dir)
		Expect(err).NotTo(HaveOccurred())
		for _, e := range entries {
			Expect(e.Name()).NotTo(HavePrefix(".nfs"), "an open name was unlinked")
		}
	}

	nfsRequest := func() prepareRequest {
		probe, err := probeVolume(dir)
		Expect(err).NotTo(HaveOccurred())
		return prepareRequest{
			Mount: mountRecord{ContainerDir: dir, MountID: probe.MountID, FSType: nfs4FSType,
				SuperOptions: []string{nfsLocalLockNone}},
			ImageName: name, Mode: attachFileImage,
		}
	}

	It("reports what this volume does with the system calls the image engine makes", func() {
		probe := filepath.Join(dir, "probe")
		f, err := os.OpenFile(probe, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()

		GinkgoWriter.Printf("fallocate mode 0, 1 MiB past the end: %v\n", unix.Fallocate(int(f.Fd()), 0, 0, 1<<20))
		GinkgoWriter.Printf("fallocate FALLOC_FL_KEEP_SIZE, 1 MiB past the end: %v\n", unix.Fallocate(int(f.Fd()), unix.FALLOC_FL_KEEP_SIZE, 1<<20, 1<<20))
		other := filepath.Join(dir, "other")
		Expect(os.WriteFile(other, nil, 0o600)).To(Succeed())
		GinkgoWriter.Printf("renameat2 RENAME_NOREPLACE onto an existing name: %v\n", unix.Renameat2(unix.AT_FDCWD, probe, unix.AT_FDCWD, other, unix.RENAME_NOREPLACE))
		third := filepath.Join(dir, "third")
		GinkgoWriter.Printf("renameat2 RENAME_NOREPLACE onto a free name: %v\n", unix.Renameat2(unix.AT_FDCWD, other, unix.AT_FDCWD, third, unix.RENAME_NOREPLACE))

		// What the link publish relies on: linkat fails with EEXIST when the
		// name exists, and succeeds when it does not.
		fresh := filepath.Join(dir, "fresh")
		Expect(os.WriteFile(fresh, nil, 0o600)).To(Succeed())
		Expect(unix.Linkat(unix.AT_FDCWD, fresh, unix.AT_FDCWD, third, 0)).To(MatchError(unix.EEXIST), "linkat onto an existing name")
		fourth := filepath.Join(dir, "fourth")
		Expect(unix.Linkat(unix.AT_FDCWD, fresh, unix.AT_FDCWD, fourth, 0)).To(Succeed(), "linkat onto a free name")
		var st unix.Stat_t
		Expect(unix.Stat(fresh, &st)).To(Succeed())
		Expect(int(st.Nlink)).To(Equal(2))
		Expect(os.Remove(fourth)).To(Succeed())
	})

	It("selects the NFS provider for the directory when it is the root of a kernel NFSv4 mount with local_lock=none", func() {
		probe, err := probeVolume(dir)
		Expect(err).NotTo(HaveOccurred())
		base := filepath.Dir(dir)
		baseProbe, err := probeVolume(base)
		Expect(err).NotTo(HaveOccurred())
		if !baseProbe.MountRoot {
			GinkgoWriter.Printf("%s is not the root of a mount, so the provider selection is not tried; point %s at the mount's root directory to try it\n", base, imageDirEnv)
			return
		}
		Expect(baseProbe.MountID).To(Equal(probe.MountID))
		p, rec, err := findVolumeProvider("/proc/self/mountinfo", base)
		GinkgoWriter.Printf("mount record: %+v\nselected: %v, error: %v\n", rec, p, err)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Name()).To(Equal("NFS"), "the mount is %s with options %s", rec.FSType, strings.Join(rec.SuperOptions, ","))
	})

	It("creates, locks, and reopens an image through the NFS provider, leaving one name and no silly rename", func() {
		var calls []string
		defaultImageOptions.fallocate = func(fd int, mode uint32, off, length int64) error {
			err := unix.Fallocate(fd, mode, off, length)
			calls = append(calls, "fallocate mode "+strconv.Itoa(int(mode))+": "+errText(err))
			return err
		}
		att, err := nfsProvider{}.Prepare(nfsRequest())
		Expect(err).NotTo(HaveOccurred())
		released := false
		release := func() {
			if !released {
				released = true
				Expect(att.Release()).To(Succeed())
			}
		}
		DeferCleanup(release)
		GinkgoWriter.Printf("allocation: %s\n", strings.Join(calls, "; "))

		st := statOf(img)
		GinkgoWriter.Printf("image: size %d, blocks %d (%d bytes), mode %04o, uid %d, gid %d, links %d\n",
			st.Size, st.Blocks, st.Blocks*512, st.Mode&0o7777, st.Uid, st.Gid, st.Nlink)
		Expect(st.Size).To(Equal(size))
		Expect(int(st.Nlink)).To(Equal(1))
		Expect(st.Mode & 0o7777).To(Equal(uint32(0o600)))
		Expect(int(st.Uid)).To(Equal(os.Geteuid()))
		Expect(tempFiles(dir)).To(BeEmpty())
		noSillyRenames()
		Expect(lockedElsewhere(img)).To(BeTrue(), "the image is locked while the attachment is held")

		_, err = att.File.WriteAt([]byte("kept"), 0)
		Expect(err).NotTo(HaveOccurred())
		release()
		Expect(lockedElsewhere(img)).To(BeFalse(), "Release drops the lock")

		again, err := nfsProvider{}.Prepare(nfsRequest())
		Expect(err).NotTo(HaveOccurred(), "the second launch reopens the image as it is")
		DeferCleanup(again.Release)
		Expect(statOf(img).Ino).To(Equal(st.Ino))
		Expect(os.ReadFile(img)).To(HavePrefix("kept"))
		noSillyRenames()
	})

	It("lets launches race on one new image and ends with one image of one link", func() {
		dirfd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { unix.Close(dirfd) })
		o := defaultImageOptions
		o.Preallocate = true
		o.Publish = publishLink

		const launches = 4
		var wg sync.WaitGroup
		results := make([]error, launches)
		for i := 0; i < launches; i++ {
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				fd, err := openImageFile(dirfd, name, img, o, nil)
				if err == nil {
					unix.Close(fd)
				}
				results[i] = err
			}()
		}
		wg.Wait()
		for i, err := range results {
			Expect(err).NotTo(HaveOccurred(), "launch %d", i)
		}
		sweepTempImages(dirfd)

		Expect(tempFiles(dir)).To(BeEmpty())
		noSillyRenames()
		st := statOf(img)
		Expect(int(st.Nlink)).To(Equal(1))
		Expect(st.Size).To(Equal(size))
	})

	It("removes a temp name that a killed launch left, an orphan or a second name of the image, and keeps the image", func() {
		orphan := filepath.Join(dir, ".rvm-disk-0123456789abcdef.tmp")
		writeImage(orphan, size, []byte("orphan"))
		writeImage(img, size, []byte("image"))
		second := filepath.Join(dir, ".rvm-disk-fedcba9876543210.tmp")
		Expect(os.Link(img, second)).To(Succeed())
		before := statOf(img)

		att, err := nfsProvider{}.Prepare(nfsRequest())
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(att.Release)

		Expect(tempFiles(dir)).To(BeEmpty())
		noSillyRenames()
		after := statOf(img)
		Expect(after.Ino).To(Equal(before.Ino))
		Expect(int(after.Nlink)).To(Equal(1))
		Expect(os.ReadFile(img)).To(HavePrefix("image"))
	})

	It("refuses a quota that cannot hold the image, leaving nothing behind, when the volume has one", func() {
		if os.Getenv("VM_LAUNCH_TEST_IMAGE_EXPECT_QUOTA_REFUSAL") == "" {
			Skip("set VM_LAUNCH_TEST_IMAGE_EXPECT_QUOTA_REFUSAL=1 and VM_LAUNCH_TEST_IMAGE_MIB to more than the volume's free space to run this spec")
		}
		_, err := nfsProvider{}.Prepare(nfsRequest())
		GinkgoWriter.Printf("error: %v\n", err)
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EDQUOT)).To(BeTrue(), "%v", err)
		Expect(err.Error()).To(HaveSuffix("(the volume's quota refused it)"))
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		entries, rerr := os.ReadDir(dir)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty())
	})
})

// errText is err's text, or "ok" for no error.
func errText(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}
