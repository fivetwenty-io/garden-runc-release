//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// requireOpenat2 skips a spec on a kernel or emulator without openat2.
func requireOpenat2() {
	fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC})
	if errors.Is(err, unix.ENOSYS) {
		Skip("openat2 is not available here; run these specs on a native linux kernel 5.6 or later")
	}
	Expect(err).NotTo(HaveOccurred())
	Expect(unix.Close(fd)).To(Succeed())
}

func alwaysMountRoot(int) (bool, error) { return true, nil }

// lockedElsewhere reports whether a new open file description of path
// cannot take an exclusive flock, which means another one holds it.
func lockedElsewhere(path string) bool {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	Expect(err).NotTo(HaveOccurred())
	defer f.Close()
	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return false
	}
	Expect(err).To(MatchError(unix.EWOULDBLOCK))
	return true
}

func statOf(path string) *syscall.Stat_t {
	var st syscall.Stat_t
	Expect(syscall.Lstat(path, &st)).To(Succeed())
	return &st
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// tempFiles lists the temp files of unpublished images in dir.
func tempFiles(dir string) []string {
	matches, err := filepath.Glob(filepath.Join(dir, ".rvm-disk-*.tmp"))
	Expect(err).NotTo(HaveOccurred())
	return matches
}

// writeImage creates path with mode 0600 holding size bytes, data first.
func writeImage(path string, size int64, data []byte) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	Expect(err).NotTo(HaveOccurred())
	Expect(f.Chmod(0o600)).To(Succeed())
	_, err = f.WriteAt(data, 0)
	Expect(err).NotTo(HaveOccurred())
	Expect(f.Truncate(size)).To(Succeed())
	Expect(f.Close()).To(Succeed())
}

// ageTemp sets the modification time of path to well beyond tempOrphanAge ago,
// as a temp file that a killed launch left has.
func ageTemp(path string) {
	old := time.Now().Add(-2 * tempOrphanAge)
	Expect(os.Chtimes(path, old, old)).To(Succeed())
}

// watchOpens reports, through the function it returns, the names in dir that
// any process opened since the call, as inotify saw them. The function may be
// called once.
func watchOpens(dir string) func() []string {
	ifd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	Expect(err).NotTo(HaveOccurred())
	_, err = unix.InotifyAddWatch(ifd, dir, unix.IN_OPEN)
	Expect(err).NotTo(HaveOccurred())
	return func() []string {
		defer unix.Close(ifd)
		var names []string
		buf := make([]byte, 64<<10)
		for {
			n, err := unix.Read(ifd, buf)
			if errors.Is(err, unix.EAGAIN) {
				return names
			}
			Expect(err).NotTo(HaveOccurred())
			for off := 0; off+unix.SizeofInotifyEvent <= n; {
				ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
				nameBytes := buf[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+int(ev.Len)]
				if name := string(bytes.TrimRight(nameBytes, "\x00")); name != "" {
					names = append(names, name)
				}
				off += unix.SizeofInotifyEvent + int(ev.Len)
			}
		}
	}
}

var _ = Describe("openVolumeImage", func() {
	var (
		dir  string
		vol  *guestVolume
		img  string
		opts imageOptions
	)

	BeforeEach(func() {
		requireOpenat2()
		dir = GinkgoT().TempDir()
		vol = &guestVolume{ContainerDir: dir, ImageName: "rvm-disk-0.img"}
		img = filepath.Join(dir, "rvm-disk-0.img")
		opts = imageOptions{Size: defaultImageSize, LockWait: 200 * time.Millisecond, LockPoll: 20 * time.Millisecond, IsMountRoot: alwaysMountRoot}
	})

	open := func() (*os.File, error) { return openVolumeImage(vol, opts, nil) }

	It("defaults to a fixed sparse 1 GiB image, a 30 second wait, and the statx mount root check", func() {
		Expect(defaultImageOptions.Size).To(Equal(int64(1 << 30)))
		Expect(defaultImageOptions.LockWait).To(Equal(30 * time.Second))
		Expect(defaultImageOptions.LockPoll).To(Equal(500 * time.Millisecond))
		Expect(defaultImageOptions.IsMountRoot).NotTo(BeNil())
	})

	It("creates a sparse 1 GiB image with mode 0600 owned by the caller, whatever the umask", func() {
		old := unix.Umask(0o277)
		f, err := open()
		Expect(unix.Umask(old)).To(Equal(0o277), "the umask is restored")
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(f.Name()).To(Equal(img))

		st := statOf(img)
		Expect(st.Size).To(Equal(int64(1 << 30)))
		Expect(st.Blocks*512).To(BeNumerically("<", 1<<20), "the image must be sparse")
		Expect(st.Mode & 0o7777).To(Equal(uint32(0o600)))
		Expect(st.Mode & syscall.S_IFMT).To(Equal(uint32(syscall.S_IFREG)))
		Expect(int(st.Uid)).To(Equal(os.Geteuid()))
	})

	It("returns the image locked, close-on-exec, and unlocked once closed", func() {
		f, err := open()
		Expect(err).NotTo(HaveOccurred())
		Expect(lockedElsewhere(img)).To(BeTrue())

		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(flags & unix.FD_CLOEXEC).NotTo(BeZero())

		Expect(f.Close()).To(Succeed())
		Expect(lockedElsewhere(img)).To(BeFalse())
	})

	It("reopens an existing image without touching its size or bytes", func() {
		f, err := open()
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Close()).To(Succeed())

		// Guest data that looks like a qcow2 header with a backing file: the
		// host side must leave it alone.
		header := append([]byte("QFI\xfb\x00\x00\x00\x03"), []byte("backing_file=/etc/passwd")...)
		w, err := os.OpenFile(img, os.O_RDWR, 0)
		Expect(err).NotTo(HaveOccurred())
		_, err = w.WriteAt(header, 0)
		Expect(err).NotTo(HaveOccurred())
		_, err = w.WriteAt([]byte("tail"), (1<<30)-4)
		Expect(err).NotTo(HaveOccurred())
		Expect(w.Close()).To(Succeed())

		f, err = open()
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Close()).To(Succeed())

		Expect(statOf(img).Size).To(Equal(int64(1 << 30)))
		r, err := os.Open(img)
		Expect(err).NotTo(HaveOccurred())
		defer r.Close()
		got := make([]byte, len(header))
		_, err = r.ReadAt(got, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(header))
		tail := make([]byte, 4)
		_, err = r.ReadAt(tail, (1<<30)-4)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(tail)).To(Equal("tail"))
	})

	It("fails closed on an empty image a dead creator left behind, and leaves it alone", func() {
		writeImage(img, 0, nil)
		_, err := open()
		Expect(errors.Is(err, errImageSize)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError("volume image " + img + ": size 0, want 1073741824; vm-launch resizes only an image it creates, so inspect or delete it"))
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		Expect(statOf(img).Size).To(BeZero())
		Expect(lockedElsewhere(img)).To(BeFalse(), "a rejected image is closed")
	})

	It("never shrinks or grows an existing image whose size is not the fixed size", func() {
		for _, size := range []int64{64 << 20, 2 << 30} {
			Expect(os.Remove(img) == nil || !fileExists(img)).To(BeTrue())
			writeImage(img, size, []byte("data"))
			_, err := open()
			Expect(errors.Is(err, errImageSize)).To(BeTrue(), "%d: %v", size, err)
			Expect(err).To(MatchError(ContainSubstring(": size " + strconv.FormatInt(size, 10) + ", want 1073741824; vm-launch resizes only an image it creates")))
			Expect(statOf(img).Size).To(Equal(size))
			Expect(os.ReadFile(img)).To(HavePrefix("data"))
		}
	})

	It("rejects an empty image at once, without waiting for the lock", func() {
		writeImage(img, 0, nil)
		holder, err := os.OpenFile(img, os.O_RDWR, 0)
		Expect(err).NotTo(HaveOccurred())
		defer holder.Close()
		Expect(unix.Flock(int(holder.Fd()), unix.LOCK_EX)).To(Succeed())
		opts.LockWait = 10 * time.Second
		began := time.Now()
		_, err = open()
		Expect(time.Since(began)).To(BeNumerically("<", time.Second))
		Expect(errors.Is(err, errImageSize)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError(ContainSubstring("size 0, want 1073741824")))
	})

	It("opens an image that exists without touching it, and creates one that does not", func() {
		writeImage(img, 8<<20, []byte("keep"))
		dirfd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		Expect(err).NotTo(HaveOccurred())
		defer unix.Close(dirfd)
		fd, err := openImageFile(dirfd, "rvm-disk-0.img", img, opts, nil)
		Expect(err).NotTo(HaveOccurred())
		defer unix.Close(fd)
		Expect(statOf(img).Size).To(Equal(int64(8 << 20)))
		Expect(os.ReadFile(img)).To(HavePrefix("keep"))

		fd2, err := openImageFile(dirfd, "rvm-disk-new.img", filepath.Join(dir, "rvm-disk-new.img"), opts, nil)
		Expect(err).NotTo(HaveOccurred())
		defer unix.Close(fd2)
		Expect(statOf(filepath.Join(dir, "rvm-disk-new.img")).Size).To(Equal(int64(defaultImageSize)))
	})

	It("rejects an image whose size is not a whole number of sectors", func() {
		writeImage(img, 1000, []byte("data"))
		_, err := open()
		Expect(errors.Is(err, errImageSize)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError("volume image " + img + ": size 1000 is not a multiple of 512"))
		Expect(statOf(img).Size).To(Equal(int64(1000)))
		Expect(lockedElsewhere(img)).To(BeFalse(), "a rejected image is closed")
	})

	It("rejects a symbolic link at the image name and leaves its target alone", func() {
		target := filepath.Join(GinkgoT().TempDir(), "passwd")
		Expect(os.WriteFile(target, []byte("root:x:0:0\n"), 0o644)).To(Succeed())
		Expect(os.Symlink(target, img)).To(Succeed())

		_, err := open()
		Expect(errors.Is(err, unix.ELOOP)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError(ContainSubstring("opening volume image " + img)))
		Expect(err).To(MatchError(ContainSubstring("follows no symbolic links")))

		Expect(os.ReadFile(target)).To(Equal([]byte("root:x:0:0\n")))
		Expect(statOf(target).Mode & 0o7777).To(Equal(uint32(0o644)))
	})

	It("rejects a dangling symbolic link at the image name without creating its target", func() {
		target := filepath.Join(GinkgoT().TempDir(), "planted")
		Expect(os.Symlink(target, img)).To(Succeed())
		_, err := open()
		Expect(errors.Is(err, unix.ELOOP)).To(BeTrue(), "%v", err)
		Expect(target).NotTo(BeAnExistingFile())
	})

	It("rejects a container_dir that is a symbolic link, or that has one in any component", func() {
		real := filepath.Join(dir, "real")
		Expect(os.MkdirAll(filepath.Join(real, "sub"), 0o755)).To(Succeed())
		Expect(os.Symlink(real, filepath.Join(dir, "link"))).To(Succeed())

		for _, p := range []string{filepath.Join(dir, "link"), filepath.Join(dir, "link", "sub")} {
			v := &guestVolume{ContainerDir: p, ImageName: "rvm-disk-0.img"}
			_, err := openVolumeImage(v, opts, nil)
			Expect(errors.Is(err, unix.ELOOP)).To(BeTrue(), "%s: %v", p, err)
			Expect(err).To(MatchError(ContainSubstring("opening volume " + p)))
		}
		Expect(filepath.Join(real, "rvm-disk-0.img")).NotTo(BeAnExistingFile())
		Expect(filepath.Join(real, "sub", "rvm-disk-0.img")).NotTo(BeAnExistingFile())
	})

	It("rejects a missing container_dir and one that is not a directory", func() {
		missing := &guestVolume{ContainerDir: filepath.Join(dir, "missing"), ImageName: "rvm-disk-0.img"}
		_, err := openVolumeImage(missing, opts, nil)
		Expect(errors.Is(err, unix.ENOENT)).To(BeTrue(), "%v", err)

		file := filepath.Join(dir, "file")
		Expect(os.WriteFile(file, nil, 0o600)).To(Succeed())
		_, err = openVolumeImage(&guestVolume{ContainerDir: file, ImageName: "rvm-disk-0.img"}, opts, nil)
		Expect(errors.Is(err, unix.ENOTDIR)).To(BeTrue(), "%v", err)
	})

	It("rejects a FIFO at the image name without hanging", func() {
		Expect(unix.Mkfifo(img, 0o600)).To(Succeed())
		done := make(chan error, 1)
		go func() {
			_, err := open()
			done <- err
		}()
		var err error
		Eventually(done, 5*time.Second).Should(Receive(&err))
		Expect(errors.Is(err, errImageNotRegular)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError("volume image " + img + ": not a regular file"))
	})

	It("rejects a directory at the image name", func() {
		Expect(os.Mkdir(img, 0o700)).To(Succeed())
		_, err := open()
		Expect(errors.Is(err, unix.EISDIR)).To(BeTrue(), "%v", err)
	})

	It("rejects an image with a second hard link", func() {
		f, err := open()
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Close()).To(Succeed())
		Expect(os.Link(img, filepath.Join(dir, "rvm-disk-1.img"))).To(Succeed())

		_, err = open()
		Expect(errors.Is(err, errImageLinks)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError("volume image " + img + ": has 2 links, want 1"))
	})

	It("rejects an image with another mode and does not repair it", func() {
		writeImage(img, 1<<20, nil)
		Expect(os.Chmod(img, 0o644)).To(Succeed())
		_, err := open()
		Expect(errors.Is(err, errImageMode)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError("volume image " + img + ": mode 0644, want 0600"))
		Expect(statOf(img).Mode & 0o7777).To(Equal(uint32(0o644)))

		Expect(syscall.Chmod(img, 0o4600)).To(Succeed())
		Expect(statOf(img).Mode & 0o7777).To(Equal(uint32(0o4600)))
		_, err = open()
		Expect(errors.Is(err, errImageMode)).To(BeTrue(), "%v", err)
	})

	It("rejects an image another uid owns and does not repair it", func() {
		if os.Geteuid() != 0 {
			Skip("changing a file's owner needs root")
		}
		writeImage(img, 1<<20, nil)
		Expect(os.Chown(img, 1234, 1234)).To(Succeed())
		_, err := open()
		Expect(errors.Is(err, errImageOwner)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError("volume image " + img + ": owned by uid 1234, not by uid 0 that runs the app"))
		Expect(statOf(img).Uid).To(Equal(uint32(1234)))
	})

	It("rejects a volume that is not a mount point, with the real statx check", func() {
		sub := filepath.Join(dir, "sub")
		Expect(os.Mkdir(sub, 0o755)).To(Succeed())
		opts.IsMountRoot = statxMountRoot
		_, err := openVolumeImage(&guestVolume{ContainerDir: sub, ImageName: "rvm-disk-0.img"}, opts, nil)
		Expect(errors.Is(err, errNotMountRoot)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError("volume " + sub + " is not a mount point"))
		Expect(filepath.Join(sub, "rvm-disk-0.img")).NotTo(BeAnExistingFile())
	})

	It("recognises a real mount point with statx", func() {
		fd, err := unix.Open("/proc", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		Expect(err).NotTo(HaveOccurred())
		defer unix.Close(fd)
		root, err := statxMountRoot(fd)
		Expect(err).NotTo(HaveOccurred())
		Expect(root).To(BeTrue())

		sub, err := unix.Open("/proc/self", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		Expect(err).NotTo(HaveOccurred())
		defer unix.Close(sub)
		root, err = statxMountRoot(sub)
		Expect(err).NotTo(HaveOccurred())
		Expect(root).To(BeFalse())
	})

	It("fails closed when the mount point check cannot tell", func() {
		opts.IsMountRoot = func(int) (bool, error) { return false, errors.New("no STATX_ATTR_MOUNT_ROOT") }
		_, err := open()
		Expect(errors.Is(err, errNotMountRoot)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError(ContainSubstring("is not a mount point: cannot tell: no STATX_ATTR_MOUNT_ROOT")))
		Expect(img).NotTo(BeAnExistingFile())
	})

	Describe("the mount that was inspected", func() {
		var asked []string

		BeforeEach(func() {
			asked = nil
			vol.MountID, vol.MountIDKnown = 40, true
			dirProbe = func(fd int, name string) (mountProbe, error) {
				target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
				Expect(err).NotTo(HaveOccurred())
				Expect(target).To(Equal(dir), "the descriptor is the volume directory")
				asked = append(asked, name)
				return mountProbe{MountID: 40, MountRoot: true}, nil
			}
		})

		It("opens the image when the directory is on that mount", func() {
			f, err := open()
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			Expect(asked).To(Equal([]string{dir}))
		})

		It("refuses a directory that is on another mount, with one line, and creates nothing", func() {
			dirProbe = func(int, string) (mountProbe, error) { return mountProbe{MountID: 41, MountRoot: true}, nil }
			_, err := open()
			Expect(errors.Is(err, errMountChanged)).To(BeTrue(), "%v", err)
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			Expect(err).To(MatchError("the mount of volume " + dir + " changed during start: it was mount ID 40 when vm-launch inspected it and is mount ID 41 now"))
			Expect(err.Error()).NotTo(ContainSubstring("\n"))
			Expect(os.ReadDir(dir)).To(BeEmpty())
		})

		It("refuses when the mount cannot be read, and creates nothing", func() {
			dirProbe = func(int, string) (mountProbe, error) { return mountProbe{}, errors.New("no mount ID here") }
			_, err := open()
			Expect(err).To(MatchError("checking the mount of volume " + dir + ": no mount ID here"))
			Expect(os.ReadDir(dir)).To(BeEmpty())
		})

		It("asks before the mount root check and before it creates anything", func() {
			dirProbe = func(int, string) (mountProbe, error) { return mountProbe{MountID: 41}, nil }
			opts.IsMountRoot = func(int) (bool, error) { Fail("the mount root check ran first"); return true, nil }
			_, err := open()
			Expect(errors.Is(err, errMountChanged)).To(BeTrue(), "%v", err)
		})

		It("keeps the mount root check as a second line of defence", func() {
			opts.IsMountRoot = func(int) (bool, error) { return false, nil }
			_, err := open()
			Expect(errors.Is(err, errNotMountRoot)).To(BeTrue(), "%v", err)
			Expect(os.ReadDir(dir)).To(BeEmpty())
		})

		It("does not ask when the caller names no mount", func() {
			vol.MountID, vol.MountIDKnown = 0, false
			dirProbe = func(int, string) (mountProbe, error) { Fail("the mount was asked"); return mountProbe{}, nil }
			f, err := open()
			Expect(err).NotTo(HaveOccurred())
			f.Close()
		})
	})

	It("reports an image it cannot size, removes its temp file, and creates the image on the next launch", func() {
		opts.Size = 1 << 62
		_, err := open()
		if err == nil {
			Skip("this filesystem accepts a 4 EiB file, so sizing cannot fail here")
		}
		Expect(err).To(MatchError(ContainSubstring("creating volume image " + img)))
		Expect(img).NotTo(BeAnExistingFile(), "the published name never refers to an unsized file")
		Expect(tempFiles(dir)).To(BeEmpty())

		opts.Size = defaultImageSize
		f, err := open()
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Close()).To(Succeed())
		Expect(statOf(img).Size).To(Equal(int64(defaultImageSize)))
	})

	Describe("publishing a new image", func() {
		var dirfd int

		BeforeEach(func() {
			var err error
			dirfd, err = unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { unix.Close(dirfd) })
		})

		It("creates the image under a temp name and leaves only the final name behind", func() {
			var seen []string
			var tempSize int64
			var tempMode uint32
			opts.afterTempCreate = func(_ int, tempName string) {
				seen = append(seen, tempName)
				st := statOf(filepath.Join(dir, tempName))
				tempSize, tempMode = st.Size, st.Mode&0o7777
				Expect(fileExists(img)).To(BeFalse(), "the final name is not published before the file is sized")
			}
			f, err := open()
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()

			Expect(seen).To(HaveLen(1))
			Expect(seen[0]).To(MatchRegexp(`^\.rvm-disk-[0-9a-f]{16}\.tmp$`))
			Expect(tempSize).To(Equal(int64(defaultImageSize)), "the file is sized before it is published")
			Expect(tempMode).To(Equal(uint32(0o600)))
			Expect(tempFiles(dir)).To(BeEmpty())
			Expect(statOf(img).Size).To(Equal(int64(defaultImageSize)))

			var byFD syscall.Stat_t
			Expect(syscall.Fstat(int(f.Fd()), &byFD)).To(Succeed())
			Expect(statOf(img).Ino).To(Equal(byFD.Ino), "the returned file is the published one")
		})

		It("uses a different temp name for every launch", func() {
			names := map[string]bool{}
			opts.afterTempCreate = func(_ int, tempName string) { names[tempName] = true }
			for i := 0; i < 3; i++ {
				f, err := open()
				Expect(err).NotTo(HaveOccurred())
				Expect(f.Close()).To(Succeed())
				Expect(os.Remove(img)).To(Succeed())
			}
			Expect(names).To(HaveLen(3))
		})

		It("opens the image that appeared first when the name is taken at publish time, and removes its own temp file", func() {
			opts.afterTempCreate = func(_ int, _ string) {
				writeImage(img, defaultImageSize, []byte("first"))
			}
			f, err := open()
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			Expect(tempFiles(dir)).To(BeEmpty())
			got := make([]byte, 5)
			_, err = f.ReadAt(got, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(got)).To(Equal("first"), "the existing image is used, not replaced")
			Expect(lockedElsewhere(img)).To(BeTrue())
		})

		It("checks an image that appeared first like any other, and fails closed on a wrong one", func() {
			opts.afterTempCreate = func(_ int, _ string) {
				writeImage(img, 4096, []byte("planted"))
			}
			_, err := open()
			Expect(errors.Is(err, errImageSize)).To(BeTrue(), "%v", err)
			Expect(tempFiles(dir)).To(BeEmpty())
			Expect(os.ReadFile(img)).To(HavePrefix("planted"))
		})

		It("never publishes over a symbolic link planted at the name", func() {
			target := filepath.Join(GinkgoT().TempDir(), "passwd")
			Expect(os.WriteFile(target, []byte("root:x:0:0\n"), 0o644)).To(Succeed())
			opts.afterTempCreate = func(_ int, _ string) { Expect(os.Symlink(target, img)).To(Succeed()) }
			_, err := open()
			Expect(errors.Is(err, unix.ELOOP)).To(BeTrue(), "%v", err)
			Expect(os.ReadFile(target)).To(Equal([]byte("root:x:0:0\n")))
			link, err := os.Readlink(img)
			Expect(err).NotTo(HaveOccurred())
			Expect(link).To(Equal(target), "the planted link is left alone")
			Expect(tempFiles(dir)).To(BeEmpty())
		})

		It("fails closed when the temp file is swapped for another file before it is published", func() {
			opts.afterTempCreate = func(_ int, tempName string) {
				swapped := filepath.Join(dir, tempName)
				Expect(os.Remove(swapped)).To(Succeed())
				writeImage(swapped, defaultImageSize, []byte("other"))
			}
			_, err := open()
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, errImageReplaced) || errors.Is(err, errImageLinks)).To(BeTrue(), "%v", err)
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			Expect(os.ReadFile(img)).To(HavePrefix("other"), "the file that took the name is left alone")
		})

		It("leaves a temp file from a killed launch alone, and never trusts or reuses it", func() {
			leftover := filepath.Join(dir, ".rvm-disk-0123456789abcdef.tmp")
			writeImage(leftover, 0, []byte("stale"))
			f, err := open()
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			Expect(statOf(leftover).Size).To(BeZero())
			Expect(statOf(img).Ino).NotTo(Equal(statOf(leftover).Ino))
			Expect(statOf(img).Size).To(Equal(int64(defaultImageSize)))
		})

		It("does not use a temp file that a launch left as the image, even one with the final name's size", func() {
			leftover := filepath.Join(dir, ".rvm-disk-fedcba9876543210.tmp")
			writeImage(leftover, defaultImageSize, []byte("stale"))
			f, err := open()
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			got := make([]byte, 5)
			_, err = f.ReadAt(got, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).NotTo(Equal([]byte("stale")))
		})

		It("fails with 125 and a publish message when the rename fails for a reason other than the name existing", func() {
			opts.afterTempCreate = func(dirfd int, tempName string) {
				Expect(unix.Unlinkat(dirfd, tempName, 0)).To(Succeed())
			}
			_, err := open()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("publishing it"))
			Expect(err.Error()).NotTo(ContainSubstring("appeared"))
			Expect(errors.Is(err, errImageAppeared)).To(BeFalse())
			Expect(errors.Is(err, unix.ENOENT)).To(BeTrue(), "%v", err)
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			Expect(fileExists(img)).To(BeFalse())
		})

		It("removes its temp file and adds the RENAME_NOREPLACE hint when the volume cannot publish the image", func() {
			opts.rename = func(_ int, _, _ string) error {
				Expect(tempFiles(dir)).To(HaveLen(1), "the temp file exists when the publish fails")
				return unix.EINVAL
			}
			_, err := open()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("publishing it"))
			Expect(err.Error()).To(ContainSubstring("does not support renameat2 with RENAME_NOREPLACE"))
			Expect(errors.Is(err, unix.EINVAL)).To(BeTrue(), "%v", err)
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			Expect(fileExists(img)).To(BeFalse())
			Expect(tempFiles(dir)).To(BeEmpty())
		})

		DescribeTable("renameHint",
			func(err error, want string) { Expect(renameHint(err)).To(Equal(want)) },
			Entry("EINVAL", unix.EINVAL, " (the volume does not support renameat2 with RENAME_NOREPLACE)"),
			Entry("ENOSYS", unix.ENOSYS, " (the volume does not support renameat2 with RENAME_NOREPLACE)"),
			Entry("a wrapped EINVAL", fmt.Errorf("rename: %w", unix.EINVAL), " (the volume does not support renameat2 with RENAME_NOREPLACE)"),
			Entry("ENOENT", unix.ENOENT, ""),
			Entry("EDQUOT", unix.EDQUOT, ""),
		)

		Describe("sizeNewImage", func() {
			It("names the image path and keeps the kind when a check fails on the new file", func() {
				name, fd, err := createTempImage(dirfd)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() { unix.Close(fd); _ = unix.Unlinkat(dirfd, name, 0) })
				Expect(unix.Fchmod(fd, 0o644)).To(Succeed())

				err = sizeNewImage(fd, img, imageOptions{Size: defaultImageSize}, nil)
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, errImageMode)).To(BeTrue(), "%v", err)
				Expect(err.Error()).To(HavePrefix("creating volume image " + img + ": the new file failed a check"))
				Expect(err.Error()).To(ContainSubstring("the volume may force file owners or modes"))
				Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			})

			It("leaves out the owner and mode hint for a check that is not about them", func() {
				name, fd, err := createTempImage(dirfd)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() { unix.Close(fd); _ = unix.Unlinkat(dirfd, name, 0) })
				Expect(unix.Linkat(dirfd, name, dirfd, "second-link", 0)).To(Succeed())
				DeferCleanup(func() { _ = unix.Unlinkat(dirfd, "second-link", 0) })

				err = sizeNewImage(fd, img, imageOptions{Size: defaultImageSize}, nil)
				Expect(errors.Is(err, errImageLinks)).To(BeTrue(), "%v", err)
				Expect(err.Error()).NotTo(ContainSubstring("force file owners"))
			})
		})

		Describe("removeOwnTemp", func() {
			newTemp := func() (string, int) {
				name, fd, err := createTempImage(dirfd)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() { unix.Close(fd) })
				return name, fd
			}

			It("unlinks the temp file while the name still refers to it", func() {
				name, fd := newTemp()
				Expect(fileExists(filepath.Join(dir, name))).To(BeTrue())
				removeOwnTemp(dirfd, fd, name)
				Expect(fileExists(filepath.Join(dir, name))).To(BeFalse())
			})

			It("leaves a file another party moved to the temp name", func() {
				name, fd := newTemp()
				p := filepath.Join(dir, name)
				Expect(os.Remove(p)).To(Succeed())
				writeImage(p, 4096, []byte("theirs"))
				removeOwnTemp(dirfd, fd, name)
				Expect(os.ReadFile(p)).To(HavePrefix("theirs"))
			})

			It("leaves a symbolic link at the temp name and its target alone", func() {
				name, fd := newTemp()
				p := filepath.Join(dir, name)
				target := filepath.Join(GinkgoT().TempDir(), "target")
				Expect(os.WriteFile(target, []byte("keep"), 0o600)).To(Succeed())
				Expect(os.Remove(p)).To(Succeed())
				Expect(os.Symlink(target, p)).To(Succeed())
				removeOwnTemp(dirfd, fd, name)
				Expect(os.Readlink(p)).To(Equal(target))
				Expect(os.ReadFile(target)).To(Equal([]byte("keep")))
			})

			It("does nothing when the name is gone", func() {
				name, fd := newTemp()
				Expect(os.Remove(filepath.Join(dir, name))).To(Succeed())
				removeOwnTemp(dirfd, fd, name)
			})

			It("never touches the published image name", func() {
				writeImage(img, defaultImageSize, []byte("data"))
				_, fd := newTemp()
				removeOwnTemp(dirfd, fd, "rvm-disk-0.img")
				Expect(os.ReadFile(img)).To(HavePrefix("data"))
			})
		})
	})

	Describe("the single writer lock", func() {
		It("makes a second instance give up after the wait", func() {
			first, err := open()
			Expect(err).NotTo(HaveOccurred())
			defer first.Close()

			began := time.Now()
			_, err = open()
			Expect(time.Since(began)).To(BeNumerically(">=", opts.LockWait))
			Expect(errors.Is(err, errVolumeInUse)).To(BeTrue(), "%v", err)
			Expect(err).To(MatchError("volume image " + img + " is in use by another instance; VM backends allow one writer per image"))
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		})

		It("fails at once with no wait", func() {
			first, err := open()
			Expect(err).NotTo(HaveOccurred())
			defer first.Close()
			opts.LockWait = 0
			began := time.Now()
			_, err = open()
			Expect(errors.Is(err, errVolumeInUse)).To(BeTrue(), "%v", err)
			Expect(time.Since(began)).To(BeNumerically("<", time.Second))
		})

		It("goes ahead once the holder lets go within the wait", func() {
			writeImage(img, defaultImageSize, nil)
			holder, err := os.OpenFile(img, os.O_RDWR, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(unix.Flock(int(holder.Fd()), unix.LOCK_EX)).To(Succeed())
			go func() {
				defer GinkgoRecover()
				time.Sleep(100 * time.Millisecond)
				Expect(holder.Close()).To(Succeed())
			}()

			opts.LockWait = 5 * time.Second
			began := time.Now()
			f, err := open()
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			Expect(time.Since(began)).To(BeNumerically(">=", 100*time.Millisecond))
			Expect(time.Since(began)).To(BeNumerically("<", 5*time.Second))
			Expect(lockedElsewhere(img)).To(BeTrue())
		})

		It("stops waiting at a signal", func() {
			first, err := open()
			Expect(err).NotTo(HaveOccurred())
			defer first.Close()

			sigs := make(chan os.Signal, 1)
			go func() {
				time.Sleep(50 * time.Millisecond)
				sigs <- syscall.SIGTERM
			}()
			opts.LockWait = 10 * time.Second
			began := time.Now()
			_, err = openVolumeImage(vol, opts, sigs)
			Expect(time.Since(began)).To(BeNumerically("<", 5*time.Second))
			var sigErr *signalledError
			Expect(errors.As(err, &sigErr)).To(BeTrue(), "%v", err)
			Expect(sigErr.Sig).To(Equal(syscall.SIGTERM))
			Expect(err).To(MatchError("received terminated while waiting for the volume image lock"))
			Expect(stepExitCode(err)).To(Equal(143))
		})

		It("fails closed when the name is replaced by another file during the wait", func() {
			writeImage(img, defaultImageSize, nil)
			holder, err := os.OpenFile(img, os.O_RDWR, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(unix.Flock(int(holder.Fd()), unix.LOCK_EX)).To(Succeed())
			replacement := filepath.Join(dir, "replacement")
			writeImage(replacement, defaultImageSize, []byte("other"))
			name := img
			go func() {
				defer GinkgoRecover()
				time.Sleep(100 * time.Millisecond)
				Expect(os.Rename(replacement, name)).To(Succeed())
				Expect(holder.Close()).To(Succeed())
			}()

			opts.LockWait = 5 * time.Second
			_, err = open()
			Expect(errors.Is(err, errImageReplaced)).To(BeTrue(), "%v", err)
			Expect(err).To(MatchError("volume image " + img + ": was deleted or replaced while this instance waited for its lock; start again"))
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			Expect(os.ReadFile(img)).To(HavePrefix("other"), "the replacement is left alone")
		})

		It("fails closed when the name is deleted during the wait", func() {
			writeImage(img, defaultImageSize, nil)
			holder, err := os.OpenFile(img, os.O_RDWR, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(unix.Flock(int(holder.Fd()), unix.LOCK_EX)).To(Succeed())
			name := img
			go func() {
				defer GinkgoRecover()
				time.Sleep(100 * time.Millisecond)
				Expect(os.Remove(name)).To(Succeed())
				Expect(holder.Close()).To(Succeed())
			}()

			opts.LockWait = 5 * time.Second
			_, err = open()
			Expect(errors.Is(err, errImageReplaced)).To(BeTrue(), "%v", err)
			Expect(errors.Is(err, unix.ENOENT)).To(BeTrue(), "%v", err)
			Expect(img).NotTo(BeAnExistingFile(), "vm-launch does not create it again")
		})

		It("checks the image before it waits", func() {
			writeImage(img, 1000, nil)
			holder, err := os.OpenFile(img, os.O_RDWR, 0)
			Expect(err).NotTo(HaveOccurred())
			defer holder.Close()
			Expect(unix.Flock(int(holder.Fd()), unix.LOCK_EX)).To(Succeed())

			opts.LockWait = 10 * time.Second
			began := time.Now()
			_, err = open()
			Expect(errors.Is(err, errImageSize)).To(BeTrue(), "%v", err)
			Expect(time.Since(began)).To(BeNumerically("<", time.Second))
		})
	})

	DescribeTable("rejects requests it cannot serve",
		func(mutate func(*guestVolume, *imageOptions), msg string) {
			v := *vol
			o := opts
			mutate(&v, &o)
			_, err := openVolumeImage(&v, o, nil)
			Expect(err).To(MatchError(ContainSubstring(msg)))
			Expect(img).NotTo(BeAnExistingFile())
		},
		Entry("a relative volume path", func(v *guestVolume, _ *imageOptions) { v.ContainerDir = "data" }, "is not absolute"),
		Entry("an image name with a slash", func(v *guestVolume, _ *imageOptions) { v.ImageName = "x/rvm-disk-0.img" }, "is not a plain file name"),
		Entry("a dot dot image name", func(v *guestVolume, _ *imageOptions) { v.ImageName = ".." }, "is not a plain file name"),
		Entry("an empty image name", func(v *guestVolume, _ *imageOptions) { v.ImageName = "" }, "is not a plain file name"),
		Entry("a size that is not whole sectors", func(_ *guestVolume, o *imageOptions) { o.Size = 1000 }, "not a positive multiple of 512"),
		Entry("no size", func(_ *guestVolume, o *imageOptions) { o.Size = 0 }, "not a positive multiple of 512"),
		Entry("a negative wait", func(_ *guestVolume, o *imageOptions) { o.LockWait = -1 }, "is negative"),
		Entry("no poll interval", func(_ *guestVolume, o *imageOptions) { o.LockPoll = 0 }, "is not positive"),
		Entry("no mount root check", func(_ *guestVolume, o *imageOptions) { o.IsMountRoot = nil }, "no mount root check"),
	)

	It("rejects a nil volume", func() {
		_, err := openVolumeImage(nil, opts, nil)
		Expect(err).To(MatchError(ContainSubstring("no volume")))
	})
})

var _ = Describe("preallocateImage", func() {
	var (
		dir  string
		path string
		f    *os.File
		opts imageOptions
		// Each fallocate call and each chunk of zeros the spec saw.
		calls  []fallocateCall
		chunks []int64
		syncs  int
	)

	// newFile makes an image of size bytes whose first bytes are data.
	newFile := func(size int64, data string) {
		var err error
		f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { f.Close() })
		_, err = f.WriteAt([]byte(data), 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Truncate(size)).To(Succeed())
	}
	preallocate := func(from, to int64, sigs <-chan os.Signal) error {
		return preallocateImage(int(f.Fd()), path, from, to, opts, sigs)
	}
	// unsupported answers fallocate as an NFS 4.1 mount does.
	unsupported := func(fd int, mode uint32, off, length int64) error {
		calls = append(calls, fallocateCall{mode, off, length})
		return unix.EOPNOTSUPP
	}
	sizeOf := func() int64 {
		st, err := f.Stat()
		Expect(err).NotTo(HaveOccurred())
		return st.Size()
	}

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		path = filepath.Join(dir, "image")
		calls, chunks, syncs = nil, nil, 0
		opts = imageOptions{
			afterZeroChunk: func(end int64) { chunks = append(chunks, end) },
			syncFile:       func(int) error { syncs++; return nil },
		}
	})

	Describe("on a filesystem that allocates", func() {
		It("calls fallocate with mode 0 on the new range only, never with KEEP_SIZE", func() {
			newFile(0, "")
			var refused error
			opts.fallocate = func(fd int, mode uint32, off, length int64) error {
				calls = append(calls, fallocateCall{mode, off, length})
				refused = unix.Fallocate(fd, mode, off, length)
				return refused
			}
			err := preallocate(0, 4<<20, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(calls).To(Equal([]fallocateCall{{0, 0, 4 << 20}}))
			Expect(calls[0].mode & unix.FALLOC_FL_KEEP_SIZE).To(BeZero())
			if errors.Is(refused, unix.EOPNOTSUPP) {
				Skip("this filesystem has no fallocate, so the zero write fallback ran; the specs for it are in the next group")
			}
			Expect(sizeOf()).To(Equal(int64(4<<20)), "mode 0 extends the file past its old end")
			Expect(chunks).To(BeEmpty(), "no zeros are written")
			Expect(syncs).To(BeZero())
		})

		It("allocates the blocks of the range when the filesystem supports it", func() {
			newFile(0, "")
			var refused error
			opts.fallocate = func(fd int, mode uint32, off, length int64) error {
				refused = unix.Fallocate(fd, mode, off, length)
				return refused
			}
			Expect(preallocate(0, 4<<20, nil)).To(Succeed())
			if errors.Is(refused, unix.EOPNOTSUPP) {
				Skip("this filesystem has no fallocate, so the zero write fallback ran; the specs for it are in the next group")
			}
			Expect(refused).NotTo(HaveOccurred())
			st := statOf(path)
			Expect(st.Size).To(Equal(int64(4 << 20)))
			Expect(st.Blocks * 512).To(BeNumerically(">=", 4<<20))
		})

		It("starts the range where the image ends and leaves its bytes alone", func() {
			newFile(1<<20, "keep")
			opts.fallocate = func(fd int, mode uint32, off, length int64) error {
				calls = append(calls, fallocateCall{mode, off, length})
				return nil
			}
			Expect(preallocate(1<<20, 3<<20, nil)).To(Succeed())
			Expect(calls).To(Equal([]fallocateCall{{0, 1 << 20, 2 << 20}}))
			Expect(os.ReadFile(path)).To(HavePrefix("keep"))
		})

		It("tries again after an interrupt", func() {
			newFile(0, "")
			opts.fallocate = func(fd int, mode uint32, off, length int64) error {
				calls = append(calls, fallocateCall{mode, off, length})
				if len(calls) < 3 {
					return unix.EINTR
				}
				return nil
			}
			Expect(preallocate(0, 1<<20, nil)).To(Succeed())
			Expect(calls).To(HaveLen(3))
			Expect(chunks).To(BeEmpty())
		})

		It("does nothing for an empty range", func() {
			newFile(1<<20, "")
			opts.fallocate = func(int, uint32, int64, int64) error { Fail("fallocate was called"); return nil }
			Expect(preallocate(1<<20, 1<<20, nil)).To(Succeed())
			Expect(chunks).To(BeEmpty())
		})

		DescribeTable("fails on any other error and writes no zeros",
			func(errno error, hint string) {
				newFile(0, "")
				opts.fallocate = func(fd int, mode uint32, off, length int64) error { return errno }
				err := preallocate(0, 4<<20, nil)
				Expect(errors.Is(err, errno)).To(BeTrue(), "%v", err)
				Expect(err).To(MatchError("allocating 4194304 bytes at offset 0: " + errno.Error() + hint))
				Expect(chunks).To(BeEmpty())
				Expect(sizeOf()).To(BeZero())
			},
			Entry("ENOSPC", unix.ENOSPC, " (the volume's quota refused it)"),
			Entry("EDQUOT", unix.EDQUOT, " (the volume's quota refused it)"),
			Entry("EIO", unix.EIO, ""),
			Entry("ENOSYS, which is not the NFS 4.1 answer", unix.ENOSYS, ""),
			Entry("EINVAL", unix.EINVAL, ""),
		)
	})

	Describe("when fallocate returns EOPNOTSUPP", func() {
		BeforeEach(func() { opts.fallocate = unsupported })

		It("writes zeros in 1 MiB chunks from the end, the last one short, and syncs once", func() {
			newFile(0, "")
			Expect(preallocate(0, 5<<19, nil)).To(Succeed()) // 2.5 MiB
			Expect(calls).To(HaveLen(1), "fallocate is tried once, for the whole range")
			Expect(chunks).To(Equal([]int64{1 << 20, 2 << 20, 5 << 19}))
			Expect(syncs).To(Equal(1))
			Expect(sizeOf()).To(Equal(int64(5 << 19)))
			data, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(bytes.Count(data, []byte{0})).To(Equal(5 << 19))
			Expect(statOf(path).Blocks*512).To(BeNumerically(">=", 5<<19), "zeros are written, not left sparse")
		})

		It("writes only past the current end and keeps the bytes before it", func() {
			newFile(1<<20, "keep")
			Expect(preallocate(1<<20, 3<<20, nil)).To(Succeed())
			Expect(chunks).To(Equal([]int64{2 << 20, 3 << 20}))
			data, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(data).To(HaveLen(3 << 20))
			Expect(data[:4]).To(Equal([]byte("keep")))
			Expect(bytes.Count(data[4:], []byte{0})).To(Equal(3<<20 - 4))
		})

		It("syncs every 256 MiB and once more at the end", func() {
			newFile(0, "")
			Expect(preallocate(0, 300<<20, nil)).To(Succeed())
			Expect(syncs).To(Equal(2))
			Expect(sizeOf()).To(Equal(int64(300 << 20)))
		})

		It("syncs once when the range is exactly one sync interval", func() {
			newFile(0, "")
			Expect(preallocate(0, 256<<20, nil)).To(Succeed())
			Expect(syncs).To(Equal(1))
		})

		It("stops at a signal at once, without a sync, and leaves the part written file for the caller to discard", func() {
			newFile(0, "")
			sigs := make(chan os.Signal, 1)
			opts.afterZeroChunk = func(end int64) {
				chunks = append(chunks, end)
				if end == 2<<20 {
					sigs <- syscall.SIGTERM
				}
			}
			err := preallocate(0, 5<<20, sigs)
			var sig *signalledError
			Expect(errors.As(err, &sig)).To(BeTrue(), "%v", err)
			Expect(sig.Sig).To(Equal(syscall.SIGTERM))
			Expect(err).To(MatchError("received terminated while preallocating the volume image"))
			Expect(stepExitCode(err)).To(Equal(128 + int(syscall.SIGTERM)))
			Expect(chunks).To(Equal([]int64{1 << 20, 2 << 20}))
			Expect(syncs).To(BeZero(), "a signal does not sync a file that is about to be deleted")
			Expect(sizeOf()).To(Equal(int64(2 << 20)))
		})

		It("exits 128 plus the signal even when a sync would have failed", func() {
			newFile(0, "")
			opts.syncFile = func(int) error { Fail("fsync was called after a signal"); return unix.EIO }
			sigs := make(chan os.Signal, 1)
			sigs <- syscall.SIGTERM
			err := preallocate(0, 2<<20, sigs)
			Expect(stepExitCode(err)).To(Equal(128 + int(syscall.SIGTERM)))
		})

		It("checks for a signal before the first chunk", func() {
			newFile(0, "")
			sigs := make(chan os.Signal, 1)
			sigs <- syscall.SIGINT
			err := preallocate(0, 5<<20, sigs)
			Expect(stepExitCode(err)).To(Equal(128 + int(syscall.SIGINT)))
			Expect(chunks).To(BeEmpty())
			Expect(sizeOf()).To(BeZero())
		})

		It("reports a write to a descriptor that cannot be written and does not sync", func() {
			newFile(0, "")
			// A descriptor that cannot be written fails the first chunk.
			ro, err := os.Open(path)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { ro.Close() })
			err = preallocateImage(int(ro.Fd()), path, 0, 2<<20, opts, nil)
			Expect(errors.Is(err, unix.EBADF)).To(BeTrue(), "%v", err)
			Expect(err).To(MatchError("writing zeros at offset 0: bad file descriptor"))
			Expect(chunks).To(BeEmpty())
			Expect(syncs).To(BeZero())
		})

		It("reports a write the quota refuses in the middle of the range, with the quota's words, and does not sync", func() {
			newFile(0, "")
			var writes []int64
			opts.pwrite = func(fd int, b []byte, off int64) error {
				writes = append(writes, off)
				if len(writes) == 3 {
					return unix.EDQUOT
				}
				return pwriteFull(fd, b, off)
			}
			err := preallocate(0, 5<<20, nil)
			Expect(errors.Is(err, unix.EDQUOT)).To(BeTrue(), "%v", err)
			Expect(err).To(MatchError("writing zeros at offset 2097152: disk quota exceeded (the volume's quota refused it)"))
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			Expect(writes).To(Equal([]int64{0, 1 << 20, 2 << 20}))
			Expect(chunks).To(Equal([]int64{1 << 20, 2 << 20}), "the failed chunk is not counted")
			Expect(syncs).To(BeZero())
			Expect(sizeOf()).To(Equal(int64(2<<20)), "the two chunks before the failure stay")
		})

		It("adds the quota's words to an ENOSPC write error, and none to another one", func() {
			for i, c := range []struct {
				errno error
				want  string
			}{
				{unix.ENOSPC, "writing zeros at offset 0: no space left on device (the volume's quota refused it)"},
				{unix.EIO, "writing zeros at offset 0: input/output error"},
			} {
				errno, want := c.errno, c.want
				each := filepath.Join(dir, "each-"+strconv.Itoa(i))
				g, err := os.OpenFile(each, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
				Expect(err).NotTo(HaveOccurred())
				opts.pwrite = func(int, []byte, int64) error { return errno }
				err = preallocateImage(int(g.Fd()), each, 0, 2<<20, opts, nil)
				g.Close()
				Expect(err).To(MatchError(want))
			}
		})

		It("fails when a sync fails, in the loop and at the end", func() {
			newFile(0, "")
			opts.syncFile = func(int) error { return unix.EDQUOT }
			err := preallocate(0, 2<<20, nil)
			Expect(err).To(MatchError("syncing the zeros written so far: disk quota exceeded (the volume's quota refused it)"))
			Expect(errors.Is(err, unix.EDQUOT)).To(BeTrue())

			err = preallocate(2<<20, 300<<20, nil)
			Expect(errors.Is(err, unix.EDQUOT)).To(BeTrue(), "%v", err)
			Expect(sizeOf()).To(Equal(int64(2<<20+256<<20)), "the loop stopped at the first sync")
		})
	})

	It("refuses an image that is not as long as the range starts, and touches nothing", func() {
		newFile(1<<20, "keep")
		opts.fallocate = func(int, uint32, int64, int64) error { Fail("fallocate was called"); return nil }
		err := preallocate(512, 3<<20, nil)
		Expect(err).To(MatchError("preallocating volume image " + path + ": the image is 1048576 bytes, not the 512 the range starts at; vm-launch writes zeros only past the current end"))
		Expect(sizeOf()).To(Equal(int64(1 << 20)))
		Expect(os.ReadFile(path)).To(HavePrefix("keep"))
	})

	DescribeTable("refuses a range that is not valid",
		func(from, to int64) {
			newFile(0, "")
			err := preallocate(from, to, nil)
			Expect(err).To(MatchError(fmt.Sprintf("preallocating volume image %s: the range %d to %d is not valid", path, from, to)))
		},
		Entry("a negative start", int64(-1), int64(512)),
		Entry("an end before the start", int64(1024), int64(512)),
		Entry("an end past 2^62", int64(0), int64(1<<62+1)),
	)

	It("reports an image it cannot stat", func() {
		newFile(0, "")
		Expect(preallocateImage(-1, path, 0, 512, opts, nil)).To(MatchError(ContainSubstring("fstat: bad file descriptor")))
	})
})

// fallocateCall is one call the preallocation specs saw.
type fallocateCall struct {
	mode        uint32
	off, length int64
}

var _ = Describe("creating an image with preallocation", func() {
	var (
		dir  string
		vol  *guestVolume
		img  string
		opts imageOptions
	)

	BeforeEach(func() {
		requireOpenat2()
		dir = GinkgoT().TempDir()
		vol = &guestVolume{ContainerDir: dir, ImageName: "rvm-disk-0.img"}
		img = filepath.Join(dir, "rvm-disk-0.img")
		opts = imageOptions{Size: 4 << 20, LockWait: 200 * time.Millisecond, LockPoll: 20 * time.Millisecond,
			IsMountRoot: alwaysMountRoot, Preallocate: true}
	})

	It("leaves preallocation off for the default options, as JuiceFS needs", func() {
		Expect(defaultImageOptions.Preallocate).To(BeFalse())
	})

	It("allocates the range, sets the length, and publishes an image of exactly its size", func() {
		var calls []fallocateCall
		var refused error
		opts.fallocate = func(fd int, mode uint32, off, length int64) error {
			calls = append(calls, fallocateCall{mode, off, length})
			refused = unix.Fallocate(fd, mode, off, length)
			return refused
		}
		f, err := openVolumeImage(vol, opts, nil)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(calls).To(Equal([]fallocateCall{{0, 0, 4 << 20}}))
		if errors.Is(refused, unix.EOPNOTSUPP) {
			Skip("this filesystem has no fallocate, so the zero write fallback ran; the next spec covers it")
		}
		st := statOf(img)
		Expect(st.Size).To(Equal(int64(4 << 20)))
		Expect(st.Blocks * 512).To(BeNumerically(">=", 4<<20))
		Expect(st.Mode & 0o7777).To(Equal(uint32(0o600)))
		Expect(tempFiles(dir)).To(BeEmpty())
		Expect(lockedElsewhere(img)).To(BeTrue())
	})

	It("writes the zeros itself when the filesystem has no ALLOCATE, and publishes the same image", func() {
		var chunks []int64
		opts.fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
		opts.afterZeroChunk = func(end int64) { chunks = append(chunks, end) }
		f, err := openVolumeImage(vol, opts, nil)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(chunks).To(Equal([]int64{1 << 20, 2 << 20, 3 << 20, 4 << 20}))
		st := statOf(img)
		Expect(st.Size).To(Equal(int64(4 << 20)))
		Expect(st.Blocks * 512).To(BeNumerically(">=", 4<<20))
		Expect(tempFiles(dir)).To(BeEmpty())
	})

	It("does not preallocate when the option is off", func() {
		opts.Preallocate = false
		opts.fallocate = func(int, uint32, int64, int64) error { Fail("fallocate was called"); return nil }
		f, err := openVolumeImage(vol, opts, nil)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(statOf(img).Blocks * 512).To(BeNumerically("<", 1<<20))
	})

	It("stops at a signal while it writes zeros, exits 128 plus the signal, and leaves no image or temp file", func() {
		opts.fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
		sigs := make(chan os.Signal, 1)
		opts.afterZeroChunk = func(end int64) {
			if end == 2<<20 {
				sigs <- syscall.SIGTERM
			}
		}
		_, err := openVolumeImage(vol, opts, sigs)
		Expect(stepExitCode(err)).To(Equal(128 + int(syscall.SIGTERM)))
		Expect(err).To(MatchError("received terminated while preallocating the volume image"))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("exits 125 with the quota's words and leaves nothing behind when the allocation is refused", func() {
		opts.fallocate = func(int, uint32, int64, int64) error { return unix.ENOSPC }
		_, err := openVolumeImage(vol, opts, nil)
		Expect(errors.Is(err, unix.ENOSPC)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError("creating volume image " + img + ": allocating 4194304 bytes at offset 0: no space left on device (the volume's quota refused it)"))
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("leaves the temp file and image name clear when the final sync of the zeros fails", func() {
		opts.fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
		opts.syncFile = func(int) error { return unix.EDQUOT }
		_, err := openVolumeImage(vol, opts, nil)
		Expect(errors.Is(err, unix.EDQUOT)).To(BeTrue(), "%v", err)
		Expect(err.Error()).To(HavePrefix("creating volume image " + img + ": syncing the zeros written so far"))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("leaves the temp file and image name clear, with the quota's words, when a zero write fails part way", func() {
		opts.fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
		writes := 0
		opts.pwrite = func(fd int, b []byte, off int64) error {
			writes++
			if writes == 3 {
				return unix.EDQUOT
			}
			return pwriteFull(fd, b, off)
		}
		_, err := openVolumeImage(vol, opts, nil)
		Expect(errors.Is(err, unix.EDQUOT)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError("creating volume image " + img + ": writing zeros at offset 2097152: disk quota exceeded (the volume's quota refused it)"))
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		Expect(writes).To(Equal(3), "no write follows the failed one")
		Expect(os.ReadDir(dir)).To(BeEmpty(), "the part written temp file is removed and no image is published")
	})

	It("keeps an existing image as it is and does not preallocate it", func() {
		writeImage(img, 4<<20, []byte("keep"))
		opts.fallocate = func(int, uint32, int64, int64) error { Fail("fallocate was called"); return nil }
		f, err := openVolumeImage(vol, opts, nil)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(os.ReadFile(img)).To(HavePrefix("keep"))
	})
})

// openPaths lists the paths of the files this process has open, as the kernel
// shows them in /proc/self/fd.
func openPaths() []string {
	entries, err := os.ReadDir("/proc/self/fd")
	Expect(err).NotTo(HaveOccurred())
	var paths []string
	for _, e := range entries {
		if target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil {
			paths = append(paths, target)
		}
	}
	return paths
}

var _ = Describe("publishing a new image by link", func() {
	var (
		dir  string
		real string
		vol  *guestVolume
		img  string
		opts imageOptions
		// The names every unlink the specs saw was asked to remove.
		unlinked []string
		// The flags of every renameat2 call the specs saw.
		renames []uint
		// hooks guards the two lists above, which the race specs fill from
		// several goroutines.
		hooks sync.Mutex
	)

	BeforeEach(func() {
		requireOpenat2()
		dir = GinkgoT().TempDir()
		var err error
		real, err = filepath.EvalSymlinks(dir)
		Expect(err).NotTo(HaveOccurred())
		vol = &guestVolume{ContainerDir: dir, ImageName: "rvm-disk-0.img"}
		img = filepath.Join(dir, "rvm-disk-0.img")
		opts = imageOptions{Size: 1 << 20, LockWait: 200 * time.Millisecond, LockPoll: 20 * time.Millisecond,
			IsMountRoot: alwaysMountRoot, Publish: publishLink}
		unlinked, renames = nil, nil

		savedRename, savedLink, savedUnlink, savedFstatat := renameat2Call, linkatCall, unlinkatCall, fstatatCall
		DeferCleanup(func() {
			renameat2Call, linkatCall, unlinkatCall, fstatatCall = savedRename, savedLink, savedUnlink, savedFstatat
		})
		// Any renameat2 with a flag fails as it does on a kernel NFS mount.
		renameat2Call = func(olddirfd int, oldpath string, newdirfd int, newpath string, flags uint) error {
			hooks.Lock()
			renames = append(renames, flags)
			hooks.Unlock()
			if flags != 0 {
				return unix.EINVAL
			}
			return unix.Renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
		}
		// No name is unlinked while this process still has it open, which on
		// an NFS client would turn the unlink into a silly rename.
		unlinkatCall = func(dirfd int, name string, flags int) error {
			hooks.Lock()
			unlinked = append(unlinked, name)
			hooks.Unlock()
			Expect(openPaths()).NotTo(ContainElement(filepath.Join(real, name)), "%s was open when it was unlinked", name)
			return unix.Unlinkat(dirfd, name, flags)
		}
	})

	open := func() (*os.File, error) { return openVolumeImage(vol, opts, nil) }

	It("publishes an image of the right size with one link and mode 0600, and never calls renameat2", func() {
		var tempName string
		opts.afterTempCreate = func(_ int, name string) { tempName = name }
		f, err := open()
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()

		Expect(f.Name()).To(Equal(img))
		st := statOf(img)
		Expect(st.Size).To(Equal(int64(1 << 20)))
		Expect(int(st.Nlink)).To(Equal(1))
		Expect(st.Mode & 0o7777).To(Equal(uint32(0o600)))
		Expect(int(st.Uid)).To(Equal(os.Geteuid()))
		Expect(renames).To(BeEmpty(), "the link publish makes no renameat2 call, with or without a flag")
		Expect(unlinked).To(Equal([]string{tempName}), "only the temp name is unlinked")
		Expect(tempFiles(dir)).To(BeEmpty())
		Expect(lockedElsewhere(img)).To(BeTrue())

		var byFD syscall.Stat_t
		Expect(syscall.Fstat(int(f.Fd()), &byFD)).To(Succeed())
		Expect(statOf(img).Ino).To(Equal(byFD.Ino), "the returned file is the published one")
	})

	It("gives the temp file the image's name with linkat and flags 0", func() {
		var calls []string
		linkatCall = func(olddirfd int, oldpath string, newdirfd int, newpath string, flags int) error {
			calls = append(calls, fmt.Sprintf("%s>%s flags=%d same=%t", oldpath, newpath, flags, olddirfd == newdirfd))
			return unix.Linkat(olddirfd, oldpath, newdirfd, newpath, flags)
		}
		var tempName string
		opts.afterTempCreate = func(_ int, name string) { tempName = name }
		f, err := open()
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(calls).To(Equal([]string{tempName + ">rvm-disk-0.img flags=0 same=true"}))
	})

	It("holds the lock on the temp file while it creates it, and has closed it before the link", func() {
		var linkAt []string
		opts.afterTempCreate = func(_ int, name string) {
			Expect(lockedElsewhere(filepath.Join(dir, name))).To(BeTrue(), "a sweep must find the temp file of a live launch locked")
		}
		opts.link = func(dirfd int, oldName, newName string) error {
			linkAt = openPaths()
			return linkNoReplace(dirfd, oldName, newName)
		}
		f, err := open()
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		for _, p := range linkAt {
			Expect(filepath.Base(p)).NotTo(MatchRegexp(`^\.rvm-disk-[0-9a-f]{16}\.tmp`), "the temp file is closed before it is linked")
		}
	})

	It("opens the image that another launch published first, removes its own temp file, and replaces nothing", func() {
		opts.afterTempCreate = func(_ int, _ string) { writeImage(img, 1<<20, []byte("first")) }
		f, err := open()
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(tempFiles(dir)).To(BeEmpty())
		got := make([]byte, 5)
		_, err = f.ReadAt(got, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("first"))
		Expect(int(statOf(img).Nlink)).To(Equal(1))
		Expect(renames).To(BeEmpty())
	})

	It("checks an image that appeared first like any other, and fails closed on a wrong one", func() {
		opts.afterTempCreate = func(_ int, _ string) { writeImage(img, 4096, []byte("planted")) }
		_, err := open()
		Expect(errors.Is(err, errImageSize)).To(BeTrue(), "%v", err)
		Expect(tempFiles(dir)).To(BeEmpty())
		Expect(os.ReadFile(img)).To(HavePrefix("planted"))
	})

	It("never publishes over a symbolic link planted at the name", func() {
		target := filepath.Join(GinkgoT().TempDir(), "passwd")
		Expect(os.WriteFile(target, []byte("root:x:0:0\n"), 0o644)).To(Succeed())
		opts.afterTempCreate = func(_ int, _ string) { Expect(os.Symlink(target, img)).To(Succeed()) }
		_, err := open()
		Expect(errors.Is(err, unix.ELOOP)).To(BeTrue(), "%v", err)
		Expect(os.ReadFile(target)).To(Equal([]byte("root:x:0:0\n")))
		Expect(os.Readlink(img)).To(Equal(target))
		Expect(tempFiles(dir)).To(BeEmpty())
	})

	It("removes its temp file and says the volume has no hard links when the link is refused", func() {
		opts.link = func(int, string, string) error {
			Expect(tempFiles(dir)).To(HaveLen(1), "the temp file exists when the link fails")
			return unix.EPERM
		}
		_, err := open()
		Expect(errors.Is(err, unix.EPERM)).To(BeTrue(), "%v", err)
		Expect(err.Error()).To(ContainSubstring("publishing it"))
		Expect(err.Error()).To(HaveSuffix("(the volume does not support hard links)"))
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("removes its temp file and adds no hint for a link error that is not about hard links", func() {
		opts.link = func(int, string, string) error { return unix.EDQUOT }
		_, err := open()
		Expect(errors.Is(err, unix.EDQUOT)).To(BeTrue(), "%v", err)
		Expect(err.Error()).NotTo(ContainSubstring("hard links"))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("creates the image again when a sweep removes the temp file before the link", func() {
		first := true
		opts.afterTempCreate = func(dirfd int, name string) {
			if first {
				first = false
				Expect(unix.Unlinkat(dirfd, name, 0)).To(Succeed())
			}
		}
		f, err := open()
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(int(statOf(img).Nlink)).To(Equal(1))
		Expect(statOf(img).Size).To(Equal(int64(1 << 20)))
		Expect(tempFiles(dir)).To(BeEmpty())
	})

	It("gives up after the retries when a temp file keeps vanishing, and publishes nothing", func() {
		opts.afterTempCreate = func(dirfd int, name string) { Expect(unix.Unlinkat(dirfd, name, 0)).To(Succeed()) }
		_, err := open()
		Expect(errors.Is(err, errCreateAgain)).To(BeTrue(), "%v", err)
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("stops at a signal while it writes zeros, closes the file before it unlinks the name, and leaves nothing", func() {
		opts.Preallocate = true
		opts.Size = 4 << 20
		opts.fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
		sigs := make(chan os.Signal, 1)
		opts.afterZeroChunk = func(end int64) {
			if end == 2<<20 {
				sigs <- syscall.SIGTERM
			}
		}
		_, err := openVolumeImage(vol, opts, sigs)
		Expect(stepExitCode(err)).To(Equal(128 + int(syscall.SIGTERM)))
		Expect(unlinked).To(HaveLen(1), "the temp name was unlinked, after its file was closed")
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("exits 125 with the quota's words and leaves nothing when the allocation is refused", func() {
		opts.Preallocate = true
		opts.fallocate = func(int, uint32, int64, int64) error { return unix.ENOSPC }
		_, err := open()
		Expect(errors.Is(err, unix.ENOSPC)).To(BeTrue(), "%v", err)
		Expect(err.Error()).To(HaveSuffix("(the volume's quota refused it)"))
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("exits 125 with the quota's words and leaves nothing when the final sync is refused", func() {
		opts.Preallocate = true
		opts.fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
		opts.syncFile = func(int) error { return unix.EDQUOT }
		_, err := open()
		Expect(errors.Is(err, unix.EDQUOT)).To(BeTrue(), "%v", err)
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("reports an image it published but could not remove the temp name of, and the next launch finishes the job", func() {
		failing := true
		unlinkatCall = func(dirfd int, name string, flags int) error {
			if failing && tempNamePattern.MatchString(name) {
				return unix.EIO
			}
			return unix.Unlinkat(dirfd, name, flags)
		}
		_, err := open()
		Expect(errors.Is(err, unix.EIO)).To(BeTrue(), "%v", err)
		Expect(err.Error()).To(ContainSubstring("published it, but could not remove its temp name"))
		Expect(err.Error()).To(ContainSubstring("the next launch removes it"))
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		Expect(int(statOf(img).Nlink)).To(Equal(2), "the image has a second name until the sweep")
		Expect(tempFiles(dir)).To(HaveLen(1))

		failing = false
		f, err := open()
		Expect(err).NotTo(HaveOccurred(), "the sweep removes the second name before the image is checked")
		defer f.Close()
		Expect(int(statOf(img).Nlink)).To(Equal(1))
		Expect(tempFiles(dir)).To(BeEmpty())
	})

	It("lets launches race on one new image, with sweeps running, and ends with one image of one link", func() {
		dirfd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { unix.Close(dirfd) })
		opts.Preallocate = true
		opts.fallocate = func(fd int, mode uint32, off, length int64) error { return unix.Fallocate(fd, mode, off, length) }
		// The recording hooks stay in place, so every unlink in the race fails
		// the spec if any file of this process has the name open. The temp
		// names are all new, so the sweeps may not open them.
		opened := watchOpens(dir)

		const launches = 6
		var wg sync.WaitGroup
		results := make([]error, launches)
		for i := 0; i < launches; i++ {
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				fd, err := openImageFile(dirfd, "rvm-disk-0.img", img, opts, nil)
				if err == nil {
					unix.Close(fd)
				}
				results[i] = err
			}()
		}
		stop := make(chan struct{})
		var sweeps sync.WaitGroup
		sweeps.Add(1)
		go func() {
			defer GinkgoRecover()
			defer sweeps.Done()
			for {
				select {
				case <-stop:
					return
				default:
					sweepTempImages(dirfd)
					time.Sleep(time.Millisecond)
				}
			}
		}()
		wg.Wait()
		close(stop)
		sweeps.Wait()

		for i, err := range results {
			Expect(err).NotTo(HaveOccurred(), "launch %d", i)
		}
		opens := map[string]int{}
		for _, n := range opened() {
			if tempNamePattern.MatchString(n) {
				opens[n]++
			}
		}
		Expect(opens).NotTo(BeEmpty())
		for n, count := range opens {
			Expect(count).To(Equal(1), "%s was opened by more than the launch that made it", n)
		}
		sweepTempImages(dirfd)
		entries, err := os.ReadDir(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1))
		st := statOf(img)
		Expect(int(st.Nlink)).To(Equal(1))
		Expect(st.Size).To(Equal(int64(1 << 20)))
	})

	DescribeTable("fails with the cause, and does not create the image again, when it cannot tell whether the temp name is its file",
		func(cause unix.Errno) {
			checks := 0
			fstatatCall = func(dirfd int, name string, st *unix.Stat_t, flags int) error {
				if tempNamePattern.MatchString(name) {
					checks++
					return cause
				}
				return unix.Fstatat(dirfd, name, st, flags)
			}
			_, err := open()
			Expect(errors.Is(err, cause)).To(BeTrue(), "%v", err)
			Expect(errors.Is(err, errCreateAgain)).To(BeFalse(), "%v", err)
			Expect(err.Error()).To(ContainSubstring("checking the new file's temp name"))
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			Expect(checks).To(Equal(1), "one attempt, not eight")
			Expect(os.ReadDir(dir)).To(BeEmpty(), "the temp file is removed")
		},
		Entry("a stale handle", unix.ESTALE),
		Entry("an I/O error", unix.EIO),
		Entry("a permission error", unix.EACCES),
	)

	It("creates the image again when the temp name is gone at the check", func() {
		first := true
		fstatatCall = func(dirfd int, name string, st *unix.Stat_t, flags int) error {
			if first && tempNamePattern.MatchString(name) {
				first = false
				Expect(unix.Unlinkat(dirfd, name, 0)).To(Succeed())
			}
			return unix.Fstatat(dirfd, name, st, flags)
		}
		f, err := open()
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(first).To(BeFalse())
		Expect(int(statOf(img).Nlink)).To(Equal(1))
		Expect(tempFiles(dir)).To(BeEmpty())
	})

	It("creates the image again when another file has taken the temp name, and leaves that file alone", func() {
		var theirs string
		fstatatCall = func(dirfd int, name string, st *unix.Stat_t, flags int) error {
			if theirs == "" && tempNamePattern.MatchString(name) {
				theirs = filepath.Join(dir, name)
				Expect(unix.Unlinkat(dirfd, name, 0)).To(Succeed())
				writeImage(theirs, 4096, []byte("theirs"))
			}
			return unix.Fstatat(dirfd, name, st, flags)
		}
		f, err := open()
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(os.ReadFile(theirs)).To(HavePrefix("theirs"))
		Expect(int(statOf(img).Nlink)).To(Equal(1))
	})

	Describe("when it cannot read the identity of the new file", func() {
		BeforeEach(func() {
			opts.identify = func(int) (unix.Statx_t, error) { return unix.Statx_t{}, unix.EIO }
		})

		It("closes the file, removes the temp name, and fails with the cause", func() {
			_, err := open()
			Expect(errors.Is(err, unix.EIO)).To(BeTrue(), "%v", err)
			Expect(err.Error()).To(ContainSubstring("fstat of the new file"))
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			Expect(unlinked).To(HaveLen(1), "the temp name was unlinked, after its file was closed")
			Expect(os.ReadDir(dir)).To(BeEmpty())
		})

		It("leaves the temp name alone when it is not the empty file this launch created", func() {
			var theirs string
			opts.identify = func(fd int) (unix.Statx_t, error) {
				var err error
				theirs, err = os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
				Expect(err).NotTo(HaveOccurred())
				Expect(os.Remove(theirs)).To(Succeed())
				writeImage(theirs, 4096, []byte("theirs"))
				return unix.Statx_t{}, unix.EIO
			}
			_, err := open()
			Expect(errors.Is(err, unix.EIO)).To(BeTrue(), "%v", err)
			Expect(os.ReadFile(theirs)).To(HavePrefix("theirs"))
			Expect(unlinked).To(BeEmpty())
		})
	})

	Describe("after it published the image", func() {
		// The unlink leaves the temp name in place, as an NFS client does when
		// another process of the cell has the name open, and the name goes
		// after the delay, or never when the delay is negative.
		leaveSecondLink := func(delay time.Duration) {
			unlinkatCall = func(dirfd int, name string, flags int) error {
				if !tempNamePattern.MatchString(name) {
					return unix.Unlinkat(dirfd, name, flags)
				}
				if delay >= 0 {
					p := filepath.Join(dir, name)
					time.AfterFunc(delay, func() { _ = unix.Unlink(p) })
				}
				return nil
			}
		}

		It("waits for the second link to go and then opens the image", func() {
			leaveSecondLink(35 * time.Millisecond)
			opts.settleInterval = 10 * time.Millisecond
			f, err := open()
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			Expect(int(statOf(img).Nlink)).To(Equal(1))
			Expect(tempFiles(dir)).To(BeEmpty())
		})

		It("refuses the image with its link count when the second link stays, after a bounded wait", func() {
			leaveSecondLink(-1)
			opts.settleInterval = 5 * time.Millisecond
			start := time.Now()
			_, err := open()
			Expect(errors.Is(err, errImageLinks)).To(BeTrue(), "%v", err)
			Expect(err.Error()).To(ContainSubstring("has 2 links, want 1"))
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			Expect(time.Since(start)).To(BeNumerically("<", 5*time.Second))
			Expect(int(statOf(img).Nlink)).To(Equal(2), "the image is left as it is")
		})

		It("stops waiting at a signal", func() {
			leaveSecondLink(-1)
			opts.settleInterval = time.Minute
			sigs := make(chan os.Signal, 1)
			sigs <- syscall.SIGTERM
			_, err := openVolumeImage(vol, opts, sigs)
			Expect(stepExitCode(err)).To(Equal(128 + int(syscall.SIGTERM)))
		})

		It("does not wait for an image that another launch published, which has two links", func() {
			opts.settleInterval = time.Minute
			opts.afterTempCreate = func(_ int, _ string) {
				writeImage(img, 1<<20, nil)
				Expect(os.Link(img, filepath.Join(dir, "elsewhere"))).To(Succeed())
			}
			start := time.Now()
			_, err := open()
			Expect(errors.Is(err, errImageLinks)).To(BeTrue(), "%v", err)
			Expect(time.Since(start)).To(BeNumerically("<", 5*time.Second))
		})
	})

	Describe("sweepTempImages", func() {
		var dirfd int

		BeforeEach(func() {
			var err error
			dirfd, err = unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { unix.Close(dirfd) })
		})

		const (
			orphan = ".rvm-disk-0123456789abcdef.tmp"
			second = ".rvm-disk-fedcba9876543210.tmp"
		)

		It("removes a temp file of a launch that was killed before it published", func() {
			writeImage(filepath.Join(dir, orphan), 1<<20, []byte("orphan"))
			ageTemp(filepath.Join(dir, orphan))
			sweepTempImages(dirfd)
			Expect(fileExists(filepath.Join(dir, orphan))).To(BeFalse())
		})

		It("leaves a temp file with one link that changed within the orphan age, without opening it", func() {
			p := filepath.Join(dir, orphan)
			writeImage(p, 1<<20, []byte("live"))
			recent := time.Now().Add(-tempOrphanAge + 20*time.Second)
			Expect(os.Chtimes(p, recent, recent)).To(Succeed())
			opened := watchOpens(dir)

			sweepTempImages(dirfd)

			Expect(opened()).NotTo(ContainElement(orphan), "a young temp name is a live launch's, and a launch unlinks it")
			Expect(os.ReadFile(p)).To(HavePrefix("live"))
		})

		It("leaves a temp file whose modification time is in the future", func() {
			p := filepath.Join(dir, orphan)
			writeImage(p, 1<<20, []byte("skewed"))
			future := time.Now().Add(time.Hour)
			Expect(os.Chtimes(p, future, future)).To(Succeed())
			sweepTempImages(dirfd)
			Expect(os.ReadFile(p)).To(HavePrefix("skewed"))
		})

		It("removes an old temp file after it opened the name for the lock only", func() {
			p := filepath.Join(dir, orphan)
			writeImage(p, 1<<20, []byte("orphan"))
			ageTemp(p)
			opened := watchOpens(dir)
			sweepTempImages(dirfd)
			Expect(opened()).To(Equal([]string{orphan}), "one open, to try the lock")
			Expect(fileExists(p)).To(BeFalse())
		})

		It("removes the second name of a published image and leaves the image whole", func() {
			writeImage(img, 1<<20, []byte("image"))
			Expect(os.Link(img, filepath.Join(dir, second))).To(Succeed())
			before := statOf(img)
			opened := watchOpens(dir)

			sweepTempImages(dirfd)

			Expect(opened()).NotTo(ContainElement(second), "a second name is removed without being opened")
			Expect(fileExists(filepath.Join(dir, second))).To(BeFalse())
			after := statOf(img)
			Expect(after.Ino).To(Equal(before.Ino))
			Expect(int(after.Nlink)).To(Equal(1))
			Expect(after.Size).To(Equal(int64(1 << 20)))
			Expect(os.ReadFile(img)).To(HavePrefix("image"))
		})

		It("never touches the published image when only its temp name is an orphan", func() {
			writeImage(img, 1<<20, []byte("image"))
			writeImage(filepath.Join(dir, orphan), 1<<20, []byte("orphan"))
			ageTemp(filepath.Join(dir, orphan))
			before := statOf(img)
			sweepTempImages(dirfd)
			Expect(statOf(img).Ino).To(Equal(before.Ino))
			Expect(os.ReadFile(img)).To(HavePrefix("image"))
			Expect(fileExists(filepath.Join(dir, orphan))).To(BeFalse())
		})

		It("leaves a temp file that a live launch has locked, and removes it once the lock is gone", func() {
			p := filepath.Join(dir, orphan)
			writeImage(p, 1<<20, []byte("live"))
			ageTemp(p)
			holder, err := os.OpenFile(p, os.O_RDWR, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(unix.Flock(int(holder.Fd()), unix.LOCK_EX)).To(Succeed())

			sweepTempImages(dirfd)
			Expect(os.ReadFile(p)).To(HavePrefix("live"))

			Expect(holder.Close()).To(Succeed())
			sweepTempImages(dirfd)
			Expect(fileExists(p)).To(BeFalse())
		})

		It("closes a name before it unlinks it", func() {
			writeImage(filepath.Join(dir, orphan), 1<<20, nil)
			ageTemp(filepath.Join(dir, orphan))
			writeImage(img, 1<<20, nil)
			Expect(os.Link(img, filepath.Join(dir, second))).To(Succeed())
			sweepTempImages(dirfd)
			Expect(unlinked).To(ConsistOf(orphan, second), "the unlink spec of this group fails the run when a name was open")
		})

		DescribeTable("leaves a name that is not exactly a temp name",
			func(name string) {
				p := filepath.Join(dir, name)
				writeImage(p, 4096, []byte("keep"))
				ageTemp(p)
				sweepTempImages(dirfd)
				Expect(os.ReadFile(p)).To(HavePrefix("keep"))
			},
			Entry("a short random part", ".rvm-disk-0123456789abcde.tmp"),
			Entry("a long random part", ".rvm-disk-0123456789abcdef0.tmp"),
			Entry("upper case hex", ".rvm-disk-0123456789ABCDEF.tmp"),
			Entry("a non hex letter", ".rvm-disk-0123456789abcdeg.tmp"),
			Entry("no leading dot", "rvm-disk-0123456789abcdef.tmp"),
			Entry("another suffix", ".rvm-disk-0123456789abcdef.tmp.bak"),
			Entry("a prefix before it", "x.rvm-disk-0123456789abcdef.tmp"),
			Entry("an image name", "rvm-disk-0.img"),
			Entry("an image name with the temp prefix", ".rvm-disk-app-web-0.img"),
			Entry("an NFS silly rename", ".nfs0000000000000001"),
			Entry("a glob like name", ".rvm-disk-*.tmp"),
		)

		It("leaves a symbolic link with a temp name and its target alone", func() {
			target := filepath.Join(GinkgoT().TempDir(), "target")
			Expect(os.WriteFile(target, []byte("keep"), 0o600)).To(Succeed())
			Expect(os.Symlink(target, filepath.Join(dir, orphan))).To(Succeed())
			sweepTempImages(dirfd)
			Expect(os.Readlink(filepath.Join(dir, orphan))).To(Equal(target))
			Expect(os.ReadFile(target)).To(Equal([]byte("keep")))
		})

		It("leaves a directory with a temp name, with what is in it", func() {
			d := filepath.Join(dir, orphan)
			Expect(os.Mkdir(d, 0o700)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(d, "inner"), []byte("keep"), 0o600)).To(Succeed())
			sweepTempImages(dirfd)
			Expect(os.ReadFile(filepath.Join(d, "inner"))).To(Equal([]byte("keep")))
		})

		It("leaves a temp file that another user owns", func() {
			if os.Geteuid() != 0 {
				Skip("changing a file's owner needs root")
			}
			p := filepath.Join(dir, orphan)
			writeImage(p, 4096, []byte("theirs"))
			ageTemp(p)
			Expect(os.Chown(p, 12345, 12345)).To(Succeed())
			sweepTempImages(dirfd)
			Expect(os.ReadFile(p)).To(HavePrefix("theirs"))
		})

		It("does nothing for an empty directory or one it cannot list", func() {
			sweepTempImages(dirfd)
			sweepTempImages(-1)
		})

		It("is not run for the rename publish, which leaves a temp file from a killed launch alone", func() {
			p := filepath.Join(dir, orphan)
			writeImage(p, 4096, []byte("stale"))
			ageTemp(p)
			opts.Publish = publishRename
			renameat2Call = unix.Renameat2
			f, err := open()
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			Expect(os.ReadFile(p)).To(HavePrefix("stale"))
		})

		It("is run by a launch, so that a leftover temp file does not outlive the next one", func() {
			p := filepath.Join(dir, orphan)
			writeImage(p, 1<<20, []byte("stale"))
			ageTemp(p)
			f, err := open()
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			Expect(fileExists(p)).To(BeFalse())
		})
	})

	DescribeTable("checkImageRequest accepts the two publish strategies and no other",
		func(p publishStrategy, ok bool) {
			o := opts
			o.Publish = p
			err := checkImageRequest(vol, o)
			if ok {
				Expect(err).NotTo(HaveOccurred())
			} else {
				Expect(err).To(MatchError(ContainSubstring("unknown way to publish an image")))
			}
		},
		Entry("rename", publishRename, true),
		Entry("link", publishLink, true),
		Entry("a value that is neither", publishStrategy(7), false),
		Entry("a negative value", publishStrategy(-1), false),
	)

	It("names the strategies", func() {
		Expect(publishRename.String()).To(Equal("rename"))
		Expect(publishLink.String()).To(Equal("link"))
		Expect(publishStrategy(7).String()).To(Equal("publish strategy 7"))
	})

	It("leaves the default options on the rename publish, as JuiceFS needs", func() {
		Expect(defaultImageOptions.Publish).To(Equal(publishRename))
	})
})
