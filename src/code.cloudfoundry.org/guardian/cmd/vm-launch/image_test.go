//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

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
		Expect(volumeExitCode(err)).To(Equal(exitLaunchError))
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
		fd, err := openImageFile(dirfd, "rvm-disk-0.img", img, opts)
		Expect(err).NotTo(HaveOccurred())
		defer unix.Close(fd)
		Expect(statOf(img).Size).To(Equal(int64(8 << 20)))
		Expect(os.ReadFile(img)).To(HavePrefix("keep"))

		fd2, err := openImageFile(dirfd, "rvm-disk-new.img", filepath.Join(dir, "rvm-disk-new.img"), opts)
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
			Expect(volumeExitCode(err)).To(Equal(exitLaunchError))
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
			Expect(volumeExitCode(err)).To(Equal(exitLaunchError))
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
			Expect(volumeExitCode(err)).To(Equal(143))
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
			Expect(volumeExitCode(err)).To(Equal(exitLaunchError))
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
