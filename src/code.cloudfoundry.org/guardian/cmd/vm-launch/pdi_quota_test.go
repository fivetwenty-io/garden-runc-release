//go:build linux

package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// fakeStatfs answers fstatfs with the numbers given.
func fakeStatfs(frsize, bsize int64, blocks, bavail uint64) func(int, *unix.Statfs_t) error {
	return func(_ int, st *unix.Statfs_t) error {
		*st = unix.Statfs_t{Frsize: frsize, Bsize: bsize, Blocks: blocks, Bfree: bavail, Bavail: bavail}
		return nil
	}
}

// fakeVolume answers fstatfs as a volume with free of total bytes does, in
// 4096 byte fragments.
func fakeVolume(free, total int64) func(int, *unix.Statfs_t) error {
	return fakeStatfs(4096, 4096, uint64(total/4096), uint64(free/4096))
}

var _ = Describe("reading the space a volume has free", func() {
	read := func(call func(int, *unix.Statfs_t) error) (volumeSpace, bool, error) {
		return readVolumeSpace(-1, imageOptions{fstatfs: call})
	}

	It("multiplies f_bavail by f_frsize, which is 1 MiB on the lab's NFS export and not f_bsize", func() {
		// The numbers the lab's NFSv4 mount reported: 51160 MiB, 50875 MiB free.
		space, ok, err := read(fakeStatfs(1<<20, 4096, 51160, 50875))
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(space).To(Equal(volumeSpace{free: 50875 << 20, total: 51160 << 20}))
	})

	It("reads a JuiceFS directory quota as the volume: 1 GiB with 924 MiB left", func() {
		// 262144 blocks of 4096 bytes in all and 236544 free, as the lab's
		// JuiceFS subdirectory mount reported after a 100 MiB write.
		space, ok, err := read(fakeStatfs(4096, 4096, 262144, 236544))
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(space).To(Equal(volumeSpace{free: 924 << 20, total: 1 << 30}))
	})

	It("reads the 1 PiB that JuiceFS reports with no quota", func() {
		space, ok, err := read(fakeStatfs(4096, 4096, 274877906944, 274877906923))
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(space.total).To(Equal(int64(1 << 50)))
		Expect(space.free).To(BeNumerically("<", space.total))
	})

	It("uses f_bsize when the filesystem reports no f_frsize", func() {
		space, ok, err := read(fakeStatfs(0, 1024, 100, 40))
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(space).To(Equal(volumeSpace{free: 40 << 10, total: 100 << 10}))
	})

	DescribeTable("says nothing a check can use for a volume that reports no space",
		func(call func(int, *unix.Statfs_t) error) {
			_, ok, err := read(call)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeFalse())
		},
		Entry("no blocks", fakeStatfs(4096, 4096, 0, 0)),
		Entry("no fragment size at all", fakeStatfs(0, 0, 100, 40)),
		Entry("a negative fragment size", fakeStatfs(-1, -1, 100, 40)),
		Entry("no fstatfs", func(int, *unix.Statfs_t) error { return unix.ENOSYS }),
		Entry("an fstatfs the filesystem does not support", func(int, *unix.Statfs_t) error { return unix.EOPNOTSUPP }),
	)

	It("stops at the largest size instead of overflowing", func() {
		space, ok, err := read(fakeStatfs(1<<40, 1<<40, math.MaxUint64, math.MaxUint64))
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(space).To(Equal(volumeSpace{free: math.MaxInt64, total: math.MaxInt64}))
	})

	It("repeats an fstatfs that a signal interrupted", func() {
		calls := 0
		space, ok, err := read(func(fd int, st *unix.Statfs_t) error {
			calls++
			if calls < 3 {
				return unix.EINTR
			}
			return fakeVolume(1<<20, 2<<20)(fd, st)
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(calls).To(Equal(3))
		Expect(space.free).To(Equal(int64(1 << 20)))
	})

	It("returns any other failure of fstatfs", func() {
		_, _, err := read(func(int, *unix.Statfs_t) error { return unix.ESTALE })
		Expect(errors.Is(err, unix.ESTALE)).To(BeTrue(), "%v", err)
	})

	It("asks the real filesystem of a directory and finds some space free", func() {
		dir, err := os.Open(GinkgoT().TempDir())
		Expect(err).NotTo(HaveOccurred())
		defer dir.Close()
		space, ok, err := readVolumeSpace(int(dir.Fd()), imageOptions{})
		Expect(err).NotTo(HaveOccurred())
		if !ok {
			Skip("this filesystem reports no space")
		}
		Expect(space.free).To(BeNumerically(">", 0))
		Expect(space.total).To(BeNumerically(">=", space.free))
	})

	It("reads the space in the words of a log line", func() {
		Expect(volumeSpace{free: 7<<30 + 1<<29, total: 10 << 30}.String()).To(Equal("7.5 GiB free of 10 GiB"))
	})

	It("recognises the two errors a quota or a full volume gives", func() {
		Expect(isQuotaErrno(unix.EDQUOT)).To(BeTrue())
		Expect(isQuotaErrno(unix.ENOSPC)).To(BeTrue())
		Expect(isQuotaErrno(errors.Join(errors.New("write"), unix.EDQUOT))).To(BeTrue())
		Expect(isQuotaErrno(unix.EIO)).To(BeFalse())
		Expect(isQuotaErrno(unix.EFBIG)).To(BeFalse())
		Expect(isQuotaErrno(nil)).To(BeFalse())
	})
})

var _ = Describe("the quota check of the image engine", func() {
	var (
		dir     string
		vol     *guestVolume
		img     string
		vq      string
		opts    imageOptions
		lines   []string
		truncs  []int64
		fallocs []int64
		// noFallocate is set when the test filesystem refused fallocate,
		// so the grow without preallocation fell back to a truncate.
		noFallocate bool
	)

	const (
		gib = int64(1) << 30
		mib = int64(1) << 20
	)

	// volume makes the volume answer fstatfs with free of total bytes.
	volume := func(free, total int64) { opts.fstatfs = fakeVolume(free, total) }
	// trackAllocations counts the calls that would write to the image.
	trackAllocations := func() {
		opts.truncate = func(fd int, size int64) error {
			truncs = append(truncs, size)
			return unix.Ftruncate(fd, size)
		}
		opts.fallocate = func(fd int, mode uint32, off, length int64) error {
			fallocs = append(fallocs, off, length)
			err := unix.Fallocate(fd, mode, off, length)
			noFallocate = errors.Is(err, unix.EOPNOTSUPP)
			return err
		}
	}
	// grewBy checks that a grow without preallocation called fallocate mode
	// 0 on the length bytes from off, and truncated only where the test
	// filesystem had no fallocate.
	grewBy := func(off, length int64) {
		GinkgoHelper()
		Expect(fallocs).To(Equal([]int64{off, length}))
		if noFallocate {
			Expect(truncs).To(Equal([]int64{off + length}))
		} else {
			Expect(truncs).To(BeEmpty())
		}
	}
	open := func() (*os.File, error) { return openVolumeImage(vol, opts, nil) }
	openOK := func() {
		GinkgoHelper()
		f, err := open()
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Close()).To(Succeed())
	}
	sizeOf := func() int64 {
		fi, err := os.Stat(img)
		Expect(err).NotTo(HaveOccurred())
		return fi.Size()
	}

	BeforeEach(func() {
		requireOpenat2()
		dir = GinkgoT().TempDir()
		vol = &guestVolume{ContainerDir: dir, ImageName: "rvm-disk-0.img"}
		img = filepath.Join(dir, "rvm-disk-0.img")
		vq = quoteForLog(dir)
		lines, truncs, fallocs, noFallocate = nil, nil, nil, false
		opts = imageOptions{Size: 8 << 20, LockWait: 200 * time.Millisecond, LockPoll: 20 * time.Millisecond,
			IsMountRoot: alwaysMountRoot, creationStep: 1 << 20,
			Logf: func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }}
	})

	Describe("refusing a creation", func() {
		It("exits 125 before it writes anything when the volume cannot hold the image, and creates nothing", func() {
			opts.Size = 20 * gib
			volume(7*gib+gib/2, 10*gib)
			trackAllocations()
			_, err := open()
			Expect(err).To(MatchError("volume " + vq + `: creating image "rvm-disk-0.img" at 20 GiB needs 20 GiB, and the volume has 7.5 GiB free of 10 GiB; ` + quotaAdvice))
			Expect(errors.Is(err, errVolumeFull)).To(BeTrue(), "%v", err)
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			Expect(os.ReadDir(dir)).To(BeEmpty(), "no image and no temp file")
			Expect(truncs).To(BeEmpty())
			Expect(fallocs).To(BeEmpty())
			Expect(lines).To(BeEmpty())
		})

		It("asks about the directory of the volume root, which is the descriptor the engine detected the mount with", func() {
			opts.Size = 20 * gib
			var modes []uint32
			opts.fstatfs = func(fd int, st *unix.Statfs_t) error {
				var stat unix.Stat_t
				if err := unix.Fstat(fd, &stat); err != nil {
					return err
				}
				modes = append(modes, stat.Mode&unix.S_IFMT)
				return fakeVolume(gib, 10*gib)(fd, st)
			}
			_, err := open()
			Expect(errors.Is(err, errVolumeFull)).To(BeTrue(), "%v", err)
			Expect(modes).To(Equal([]uint32{unix.S_IFDIR}))
		})

		It("counts the whole image, because a new image grows to its full size under the lock", func() {
			opts.Size = 8 << 20
			volume(8*mib-4096, 16*mib)
			_, err := open()
			Expect(err).To(MatchError(ContainSubstring("needs 8 MiB, and the volume has 7.9 MiB free of 16 MiB")))
			Expect(os.ReadDir(dir)).To(BeEmpty())
		})

		It("allows a creation that needs exactly the free space", func() {
			volume(8*mib, 16*mib)
			openOK()
			Expect(sizeOf()).To(Equal(8 * mib))
		})

		It("refuses one more fragment than the volume has free", func() {
			opts.Size = 64 << 20
			volume(64*mib-4096, 128*mib)
			_, err := open()
			Expect(errors.Is(err, errVolumeFull)).To(BeTrue(), "%v", err)
		})
	})

	Describe("refusing a grow", func() {
		It("exits 125 with the line the design gives, before it writes anything, and keeps the image as it was", func() {
			writeImage(img, gib, []byte("guest data"))
			opts.Size = 20 * gib
			volume(7*gib+gib/2, 10*gib)
			trackAllocations()
			_, err := open()
			Expect(err).To(MatchError("volume " + vq + `: growing image "rvm-disk-0.img" from 1 GiB to 20 GiB needs 19 GiB, and the volume has 7.5 GiB free of 10 GiB; ` + quotaAdvice))
			Expect(errors.Is(err, errVolumeFull)).To(BeTrue(), "%v", err)
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			Expect(sizeOf()).To(Equal(gib))
			Expect(truncs).To(BeEmpty())
			Expect(fallocs).To(BeEmpty())
			Expect(lines).To(BeEmpty(), "a refused grow prints no growing line")
			Expect(lockedElsewhere(img)).To(BeFalse(), "a refused grow closes the image")
		})

		It("counts only the bytes the grow adds, not the whole image", func() {
			// The image is 7 MiB of the 8 MiB asked for. Only 1 MiB is added,
			// and the volume has 1 MiB free, so it fits although 8 MiB do not.
			writeImage(img, 7*mib, nil)
			volume(mib, 100*mib)
			trackAllocations()
			openOK()
			Expect(sizeOf()).To(Equal(8 * mib))
			grewBy(7*mib, mib)
		})

		It("refuses a grow that needs one fragment more than the free space", func() {
			writeImage(img, 7*mib, nil)
			volume(mib-4096, 100*mib)
			_, err := open()
			Expect(err).To(MatchError(ContainSubstring("from 7 MiB to 8 MiB needs 1 MiB, and the volume has 1020 KiB free of 100 MiB")))
			Expect(sizeOf()).To(Equal(7 * mib))
		})

		It("refuses the part of a grow that is left after the creation step has been written", func() {
			// The volume has room for the 1 MiB creation step but not the
			// rest, so the creation passes its own check at the full size
			// only if the volume holds it all. Here it holds all 8 MiB at
			// creation, then loses 6 MiB to another writer before the grow.
			volume(8*mib, 100*mib)
			inner := opts.fstatfs
			calls := 0
			opts.fstatfs = func(fd int, st *unix.Statfs_t) error {
				calls++
				if calls > 1 {
					return fakeVolume(5*mib, 100*mib)(fd, st)
				}
				return inner(fd, st)
			}
			_, err := open()
			Expect(err).To(MatchError(ContainSubstring("growing image \"rvm-disk-0.img\" from 1 MiB to 8 MiB needs 7 MiB, and the volume has 5 MiB free of 100 MiB")))
			Expect(sizeOf()).To(Equal(mib), "the image is published at the creation step and stays there")
			Expect(tempFiles(dir)).To(BeEmpty())
		})

		It("does not check an image that is large enough, or one that is larger than asked for", func() {
			opts.fstatfs = func(int, *unix.Statfs_t) error { Fail("the volume was asked"); return nil }
			writeImage(img, 8*mib, nil)
			openOK()
			Expect(os.Remove(img)).To(Succeed())
			writeImage(img, 16*mib, nil)
			openOK()
			Expect(sizeOf()).To(Equal(16 * mib))
		})

		It("allows a grow that fits, and grows the image", func() {
			writeImage(img, 2*mib, []byte("guest data"))
			volume(6*mib, 10*mib)
			trackAllocations()
			openOK()
			Expect(sizeOf()).To(Equal(8 * mib))
			grewBy(2*mib, 6*mib)
			Expect(lines).To(Equal([]string{`volume ` + vq + `: growing image "rvm-disk-0.img" from 2 MiB to 8 MiB`}))
		})

		It("scales a grow by the fragment size, as on the lab's NFS export", func() {
			writeImage(img, 2*mib, nil)
			// 5 MiB free in 1 MiB fragments, and the grow adds 6 MiB.
			opts.fstatfs = fakeStatfs(1<<20, 1<<20, 10, 5)
			_, err := open()
			Expect(err).To(MatchError(ContainSubstring("needs 6 MiB, and the volume has 5 MiB free of 10 MiB")))
			opts.fstatfs = fakeStatfs(1<<20, 1<<20, 10, 6)
			openOK()
			Expect(sizeOf()).To(Equal(8 * mib))
		})

		It("continues a grow that a signal stopped, counting only what is left", func() {
			opts.Preallocate = true
			opts.fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
			writeImage(img, 4*mib, nil)
			// The zeros up to 4 MiB are written and are no longer free.
			volume(4*mib, 10*mib)
			openOK()
			Expect(sizeOf()).To(Equal(8 * mib))
		})
	})

	Describe("a volume whose space cannot be read", func() {
		It("leaves the decision to the allocation when the volume reports no blocks", func() {
			writeImage(img, 2*mib, nil)
			opts.fstatfs = fakeStatfs(4096, 4096, 0, 0)
			openOK()
			Expect(sizeOf()).To(Equal(8 * mib))
		})

		It("leaves the decision to the allocation when the filesystem has no fstatfs", func() {
			writeImage(img, 2*mib, nil)
			opts.fstatfs = func(int, *unix.Statfs_t) error { return unix.ENOSYS }
			openOK()
			Expect(sizeOf()).To(Equal(8 * mib))
		})

		It("refuses the launch with the error when fstatfs fails for another reason, and writes nothing", func() {
			writeImage(img, 2*mib, nil)
			opts.fstatfs = func(int, *unix.Statfs_t) error { return unix.ESTALE }
			trackAllocations()
			_, err := open()
			Expect(errors.Is(err, unix.ESTALE)).To(BeTrue(), "%v", err)
			Expect(err).To(MatchError("volume " + vq + `: growing image "rvm-disk-0.img" from 2 MiB to 8 MiB: checking the space the volume has free: stale file handle`))
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			Expect(truncs).To(BeEmpty())
			Expect(sizeOf()).To(Equal(2 * mib))
		})

		It("refuses a creation the same way, and leaves nothing behind", func() {
			opts.fstatfs = func(int, *unix.Statfs_t) error { return unix.EIO }
			_, err := open()
			Expect(errors.Is(err, unix.EIO)).To(BeTrue(), "%v", err)
			Expect(err).To(MatchError(ContainSubstring(`creating image "rvm-disk-0.img" at 8 MiB: checking the space the volume has free`)))
			Expect(os.ReadDir(dir)).To(BeEmpty())
		})
	})

	Describe("an allocation the quota refuses after the check passed", func() {
		type allocator struct {
			name  string
			setup func(errno error)
			// stays is the length the image keeps.
			stays int64
		}
		allocators := func() []allocator {
			return []allocator{
				{"fallocate, as on JuiceFS", func(errno error) {
					opts.fallocate = func(int, uint32, int64, int64) error { return errno }
				}, 2 * mib},
				{"ftruncate, as on a JuiceFS volume without fallocate", func(errno error) {
					opts.fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
					opts.truncate = func(int, int64) error { return errno }
				}, 2 * mib},
				{"fallocate, as on NFS 4.2", func(errno error) {
					opts.Preallocate = true
					opts.fallocate = func(int, uint32, int64, int64) error { return errno }
				}, 2 * mib},
				{"a zero write, as on NFS 4.1", func(errno error) {
					opts.Preallocate = true
					opts.fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
					opts.pwrite = func(fd int, b []byte, off int64) error {
						if off >= 4*mib {
							return errno
						}
						return pwriteFull(fd, b, off)
					}
				}, 4 * mib},
			}
		}

		for _, errno := range []unix.Errno{unix.EDQUOT, unix.ENOSPC} {
			for _, a := range allocators() {
				errno, a := errno, a
				It("reports "+errno.Error()+" from "+a.name+" in the words of the check, and the image keeps the length it reached", func() {
					writeImage(img, 2*mib, []byte("guest data"))
					volume(7*gib+gib/2, 10*gib)
					a.setup(errno)
					_, err := open()
					Expect(errors.Is(err, errno)).To(BeTrue(), "%v", err)
					Expect(errors.Is(err, errQuotaRefused)).To(BeTrue(), "%v", err)
					Expect(err).To(MatchError("volume " + vq + `: growing image "rvm-disk-0.img" from 2 MiB to 8 MiB needs 6 MiB, and the volume's quota refused it (` + errno.Error() + `); the volume has 7.5 GiB free of 10 GiB; ` + quotaAdvice + "; the image stays at " + roughSize(a.stays)))
					Expect(stepExitCode(err)).To(Equal(exitLaunchError))
					Expect(sizeOf()).To(Equal(a.stays))
					Expect(lockedElsewhere(img)).To(BeFalse(), "a failed grow closes the image")

					// The volume has room now. A later start resumes.
					opts.truncate, opts.fallocate, opts.pwrite = nil, nil, nil
					opts.Preallocate = false
					volume(gib, 10*gib)
					openOK()
					Expect(sizeOf()).To(Equal(8 * mib))
				})
			}
		}

		It("leaves out the free space when the volume cannot be asked again", func() {
			writeImage(img, 2*mib, nil)
			good := fakeVolume(gib, 10*gib)
			calls := 0
			opts.fstatfs = func(fd int, st *unix.Statfs_t) error {
				calls++
				if calls > 1 {
					return unix.ESTALE
				}
				return good(fd, st)
			}
			opts.fallocate = func(int, uint32, int64, int64) error { return unix.EDQUOT }
			_, err := open()
			Expect(err).To(MatchError("volume " + vq + `: growing image "rvm-disk-0.img" from 2 MiB to 8 MiB needs 6 MiB, and the volume's quota refused it (disk quota exceeded); ` + quotaAdvice + "; the image stays at 2 MiB"))
		})

		It("reports a quota that refuses the sync of a grow in the same words", func() {
			opts.Preallocate = true
			opts.fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
			opts.syncFile = func(int) error { return unix.EDQUOT }
			writeImage(img, 2*mib, nil)
			volume(gib, 10*gib)
			_, err := open()
			Expect(errors.Is(err, unix.EDQUOT)).To(BeTrue(), "%v", err)
			Expect(err.Error()).To(HavePrefix("volume " + vq + `: growing image "rvm-disk-0.img" from 2 MiB to 8 MiB needs 6 MiB, and the volume's quota refused it (disk quota exceeded)`))
			Expect(err.Error()).To(HaveSuffix("; the image stays at 2 MiB"), "the zeros that did not sync are cut")
			Expect(sizeOf()).To(Equal(2 * mib))
		})

		It("reports a refused allocation of a new image in the same words, and leaves no image or temp file", func() {
			opts.Size = 4 * mib
			opts.Preallocate = true
			opts.fallocate = func(int, uint32, int64, int64) error { return unix.EDQUOT }
			volume(gib, 10*gib)
			_, err := open()
			Expect(err).To(MatchError("volume " + vq + `: creating image "rvm-disk-0.img" at 4 MiB needs 4 MiB, and the volume's quota refused it (disk quota exceeded); the volume has 1 GiB free of 10 GiB; ` + quotaAdvice + "; no image was created"))
			Expect(os.ReadDir(dir)).To(BeEmpty())
		})

		It("reports a refused creation by link in the same words", func() {
			opts.Size = 4 * mib
			opts.Preallocate = true
			opts.Publish = publishLink
			opts.fallocate = func(int, uint32, int64, int64) error { return unix.ENOSPC }
			volume(gib, 10*gib)
			_, err := open()
			Expect(errors.Is(err, unix.ENOSPC)).To(BeTrue(), "%v", err)
			Expect(err.Error()).To(ContainSubstring(`creating image "rvm-disk-0.img" at 4 MiB needs 4 MiB, and the volume's quota refused it (no space left on device)`))
			Expect(os.ReadDir(dir)).To(BeEmpty())
		})

		It("gives another allocation failure its own words, without the quota's", func() {
			writeImage(img, 2*mib, nil)
			volume(gib, 10*gib)
			opts.fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
			opts.truncate = func(int, int64) error { return unix.EIO }
			_, err := open()
			Expect(err).To(MatchError("volume " + vq + `: growing image "rvm-disk-0.img" from 2 MiB to 8 MiB: truncating it to 8388608 bytes: input/output error; the image stays at 2 MiB`))
			Expect(errors.Is(err, errQuotaRefused)).To(BeFalse())
		})

		It("exits with the signal's status and not the quota's when a signal stops a grow", func() {
			opts.Preallocate = true
			opts.fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
			sigs := make(chan os.Signal, 1)
			opts.afterZeroChunk = func(end int64) {
				if end == 4*mib {
					sigs <- syscall.SIGTERM
				}
			}
			writeImage(img, 2*mib, nil)
			volume(gib, 10*gib)
			_, err := openVolumeImage(vol, opts, sigs)
			Expect(stepExitCode(err)).To(Equal(128 + int(syscall.SIGTERM)))
			Expect(errors.Is(err, errQuotaRefused)).To(BeFalse())
		})
	})
})
