//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

const (
	testMiB = 1 << 20
	testGiB = 1 << 30
)

// vcapWithDisk is a VCAP_APPLICATION environment whose limits.disk is
// diskMiB, next to the other limits Diego sets.
func vcapWithDisk(diskMiB string) func(string) (string, bool) {
	return envMap(map[string]string{vcapApplicationEnv: `{"limits":{"disk":` + diskMiB + `,"fds":16384,"mem":512},"name":"app"}`})
}

// freeBlocks is a statfs that reports blocks free blocks of 4096 bytes each, and
// records the directory it was asked about in asked.
func freeBlocks(blocks uint64, asked *string) func(string, *unix.Statfs_t) error {
	return func(dir string, st *unix.Statfs_t) error {
		*asked = dir
		*st = unix.Statfs_t{Bsize: 4096, Frsize: 4096, Blocks: blocks * 2, Bfree: blocks, Bavail: blocks}
		return nil
	}
}

// statfsFreeMiB is a statfs that reports exactly free MiB free.
func statfsFreeMiB(free uint64) func(string, *unix.Statfs_t) error {
	var asked string
	return freeBlocks(free*testMiB/4096, &asked)
}

var _ = Describe("the guest root image size", func() {
	var (
		logBuf *bytes.Buffer
		logger *log.Logger
	)

	BeforeEach(func() {
		logBuf = &bytes.Buffer{}
		logger = log.New(logBuf, "", 0)
	})

	sized := func(diskMiB string, free uint64, volume int64) (int64, int64, error) {
		return rootDiskSize("/work", vcapWithDisk(diskMiB), statfsFreeMiB(free), volume, logger)
	}

	DescribeTable("takes the smaller of the disk limit and the free space, less 32 MiB",
		func(diskMiB string, free uint64, wantMiB int64) {
			size, ratio, err := sized(diskMiB, free, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(size).To(Equal(wantMiB * testMiB))
			Expect(ratio).To(Equal(inodeRatioFor(wantMiB * testMiB)))
			Expect(logBuf.String()).To(BeEmpty())
		},
		Entry("a limit under the free space", "512", uint64(10000), int64(480)),
		Entry("free space under the limit", "4096", uint64(300), int64(268)),
		Entry("a limit equal to the free space", "300", uint64(300), int64(268)),
		Entry("the smallest root, 16 MiB after the headroom", "48", uint64(1000), int64(16)),
		Entry("free space at the smallest root", "1000", uint64(48), int64(16)),
		Entry("a limit just over the volume image's size", "1057", uint64(5000), int64(1025)),
		Entry("a limit of 100 MiB", "100", uint64(5000), int64(68)),
	)

	It("cuts the free space to whole MiB", func() {
		var asked string
		// 300 MiB and 700 KiB.
		size, _, err := rootDiskSize("/work", vcapWithDisk("4096"), freeBlocks((300*testMiB+700*1024)/4096, &asked), 0, logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(size).To(Equal(int64(268 * testMiB)))
		Expect(size % 4096).To(BeZero())
	})

	It("asks statfs about the work directory", func() {
		var asked string
		_, _, err := rootDiskSize("/work/vm-launch-123", vcapWithDisk("512"), freeBlocks(1<<20, &asked), 0, logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(asked).To(Equal("/work/vm-launch-123"))
	})

	Describe("the free space statfs reports", func() {
		freeOf := func(st unix.Statfs_t) func(string, *unix.Statfs_t) error {
			return func(_ string, got *unix.Statfs_t) error {
				*got = st
				return nil
			}
		}
		sizeFor := func(st unix.Statfs_t) (int64, error) {
			size, _, err := rootDiskSize("/work", vcapWithDisk("100000"), freeOf(st), 0, logger)
			return size, err
		}

		It("counts what an unprivileged writer can use, not what root can", func() {
			size, err := sizeFor(unix.Statfs_t{Bsize: 4096, Frsize: 4096, Bfree: 1 << 20, Bavail: 100 * testMiB / 4096})
			Expect(err).NotTo(HaveOccurred())
			Expect(size).To(Equal(int64(68 * testMiB)))
		})

		It("counts blocks of the fragment size when the filesystem sets one", func() {
			size, err := sizeFor(unix.Statfs_t{Bsize: 4096, Frsize: 1024, Bavail: 100 * 1024})
			Expect(err).NotTo(HaveOccurred())
			Expect(size).To(Equal(int64(68 * testMiB)))
		})

		It("counts blocks of the block size when the fragment size is unset", func() {
			size, err := sizeFor(unix.Statfs_t{Bsize: 65536, Bavail: 100 * 16})
			Expect(err).NotTo(HaveOccurred())
			Expect(size).To(Equal(int64(68 * testMiB)))
		})

		It("does not overflow on a free count too large to hold in bytes", func() {
			size, err := sizeFor(unix.Statfs_t{Bsize: 4096, Frsize: 4096, Bavail: math.MaxUint64})
			Expect(err).NotTo(HaveOccurred())
			Expect(size).To(Equal(int64(100000-32) * testMiB))
		})

		It("sees no free space when the block size is unset", func() {
			_, err := sizeFor(unix.Statfs_t{Bavail: 1 << 30})
			Expect(err).To(MatchError(ContainSubstring("the container has 0 MiB of disk quota left")))
		})
	})

	Describe("the volume image", func() {
		It("takes 1 MiB off a root that would be the volume's size, so the drives differ by size", func() {
			size, _, err := sized("1056", 5000, testGiB)
			Expect(err).NotTo(HaveOccurred())
			Expect(size).To(Equal(int64(testGiB - testMiB)))
		})

		It("leaves a root of any other size alone", func() {
			for limit, want := range map[string]int64{"1055": 1023, "1057": 1025} {
				size, _, err := sized(limit, 5000, testGiB)
				Expect(err).NotTo(HaveOccurred())
				Expect(size).To(Equal(want * testMiB))
			}
		})

		It("leaves a root of the volume's size alone when there is no volume", func() {
			size, _, err := sized("1056", 5000, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(size).To(Equal(int64(testGiB)))
		})

		It("nudges away from whatever size the volume image has", func() {
			size, _, err := sized("96", 5000, 64*testMiB)
			Expect(err).NotTo(HaveOccurred())
			Expect(size).To(Equal(int64(63 * testMiB)))
		})

		It("measures the nudged size against the smallest root", func() {
			_, _, err := sized("48", 5000, 16*testMiB)
			Expect(err).To(MatchError(ContainSubstring("the app's disk limit is 48 MiB")))
		})
	})

	Describe("a quota that is too small", func() {
		const (
			needs = ", and the guest root needs at least 48 MiB of it, which is 16 MiB plus 32 MiB kept for other writers; raise the app's disk quota"
			// wantLeft is the line when the free space is the smaller number,
			// and wantLimit when the app's disk limit is.
			wantLeft  = "the container has %d MiB of disk quota left" + needs
			wantLimit = "the app's disk limit is %d MiB" + needs
		)

		DescribeTable("exits with the quota line, naming the MiB left when the free space is smaller and the limit when it is",
			func(diskMiB string, free uint64, want string, leftMiB int) {
				size, ratio, err := sized(diskMiB, free, 0)
				Expect(err).To(MatchError(fmt.Sprintf(want, leftMiB)))
				Expect(size).To(BeZero())
				Expect(ratio).To(BeZero())
				Expect(logBuf.String()).To(BeEmpty())
			},
			Entry("a limit one MiB short", "47", uint64(1000), wantLimit, 47),
			Entry("free space one MiB short", "1000", uint64(47), wantLeft, 47),
			Entry("exactly the headroom", "32", uint64(1000), wantLimit, 32),
			Entry("less than the headroom", "10", uint64(1000), wantLimit, 10),
			Entry("one MiB", "1", uint64(1000), wantLimit, 1),
			Entry("no free space", "1000", uint64(0), wantLeft, 0),
			Entry("a limit equal to the free space", "40", uint64(40), wantLimit, 40),
		)

		It("names the smaller of the limit and the free space", func() {
			_, _, err := sized("40", 30, 0)
			Expect(err).To(MatchError(fmt.Sprintf(wantLeft, 30)))
		})

		It("counts the free MiB it was cut to, not a fraction", func() {
			var asked string
			_, _, err := rootDiskSize("/work", vcapWithDisk("1000"), freeBlocks((47*testMiB+testMiB-4096)/4096, &asked), 0, logger)
			Expect(err).To(MatchError(fmt.Sprintf(wantLeft, 47)))
		})
	})

	Describe("a missing or malformed limits.disk", func() {
		never := func(string, *unix.Statfs_t) error {
			Fail("statfs ran with no quota to check")
			return nil
		}

		DescribeTable("keeps the RAM root with one line and no error",
			func(env map[string]string, logged string) {
				size, ratio, err := rootDiskSize("/work", envMap(env), never, 0, logger)
				Expect(err).NotTo(HaveOccurred())
				Expect(size).To(BeZero())
				Expect(ratio).To(BeZero())
				Expect(logBuf.String()).To(Equal(logged + "; the disk quota does not apply to the guest root\n"))
			},
			Entry("no VCAP_APPLICATION", map[string]string{}, "VCAP_APPLICATION is not set"),
			Entry("no limits", map[string]string{vcapApplicationEnv: `{"name":"app"}`}, "VCAP_APPLICATION has no limits.disk"),
			Entry("no disk limit", map[string]string{vcapApplicationEnv: `{"limits":{"mem":512}}`}, "VCAP_APPLICATION has no limits.disk"),
			Entry("a limit that is not a number", map[string]string{vcapApplicationEnv: `{"limits":{"disk":"a lot"}}`}, "VCAP_APPLICATION limits.disk is not a positive whole number of MiB"),
			Entry("a limit of zero", map[string]string{vcapApplicationEnv: `{"limits":{"disk":0}}`}, "VCAP_APPLICATION limits.disk is not a positive whole number of MiB"),
			Entry("VCAP_APPLICATION that is not JSON", map[string]string{vcapApplicationEnv: `not json`}, "VCAP_APPLICATION is not a JSON object"),
		)

		It("checks the limit before it asks statfs, so a bad limit never fails on statfs", func() {
			size, _, err := rootDiskSize("/work", envMap(map[string]string{}), func(string, *unix.Statfs_t) error {
				return errors.New("statfs broke")
			}, 0, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(size).To(BeZero())
		})
	})

	Describe("a statfs that fails", func() {
		It("is an error that names the directory and wraps the cause", func() {
			size, ratio, err := rootDiskSize("/work/vm-launch-1", vcapWithDisk("512"), func(string, *unix.Statfs_t) error {
				return syscall.ENOENT
			}, 0, logger)
			Expect(err).To(MatchError("checking the disk quota left in /work/vm-launch-1: no such file or directory"))
			Expect(errors.Is(err, syscall.ENOENT)).To(BeTrue())
			Expect(size).To(BeZero())
			Expect(ratio).To(BeZero())
			Expect(logBuf.String()).To(BeEmpty())
		})
	})

	Describe("the inode ratio", func() {
		DescribeTable("is 16384 bytes per inode, doubled until the image holds at most 65536 inodes",
			func(size int64, want int64) {
				Expect(inodeRatioFor(size)).To(Equal(want))
			},
			Entry("16 MiB", int64(16*testMiB), int64(16384)),
			Entry("1 GiB, 65536 inodes", int64(testGiB), int64(16384)),
			Entry("1 GiB and 1 MiB", int64(testGiB+testMiB), int64(32768)),
			Entry("4 GiB", int64(4*testGiB), int64(65536)),
			Entry("16 GiB", int64(16*testGiB), int64(262144)),
			Entry("64 GiB", int64(64*testGiB), int64(1048576)),
			Entry("1 TiB", int64(1024*testGiB), int64(16777216)),
		)

		It("never lets an image hold more than 65536 inodes, and never doubles more than it must", func() {
			for _, size := range []int64{16 * testMiB, 100 * testMiB, testGiB, 3 * testGiB, 4 * testGiB, 5 * testGiB, 8 * testGiB, 9 * testGiB, 100 * testGiB, 4096 * testGiB} {
				ratio := inodeRatioFor(size)
				Expect(size/ratio).To(BeNumerically("<=", 65536), "size %d", size)
				if ratio > 16384 {
					Expect(size/(ratio/2)).To(BeNumerically(">", 65536), "size %d", size)
				}
			}
		})

		It("comes with the size from rootDiskSize", func() {
			size, ratio, err := sized("16416", 100000, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(size).To(Equal(int64(16 * testGiB)))
			Expect(ratio).To(Equal(int64(262144)))
		})
	})
})

var _ = Describe("the filesystem of the guest root image", func() {
	// devs is a stat that reports the device of each path in devs, and fails
	// for a path it does not list.
	devs := func(devs map[string]uint64) func(string, *unix.Stat_t) error {
		return func(path string, st *unix.Stat_t) error {
			dev, ok := devs[path]
			if !ok {
				return &os.PathError{Op: "stat", Path: path, Err: syscall.ENOENT}
			}
			*st = unix.Stat_t{Dev: dev}
			return nil
		}
	}

	It("accepts a work directory on the filesystem of the container's root directory", func() {
		Expect(checkRootImageDir("/tmp/vm-launch-1", devs(map[string]uint64{"/tmp/vm-launch-1": 42, "/": 42}))).To(Succeed())
	})

	It("rejects a work directory on another filesystem, naming it, before an image is created", func() {
		err := checkRootImageDir("/dev/shm/vm-launch-1", devs(map[string]uint64{"/dev/shm/vm-launch-1": 7, "/": 42}))
		Expect(err).To(MatchError("the work directory /dev/shm/vm-launch-1 is not on the container's root filesystem, whose disk quota the guest root is sized from; unset TMPDIR or point it at a directory on the root filesystem"))
	})

	It("fails when it cannot stat the work directory or the root directory", func() {
		err := checkRootImageDir("/work", devs(map[string]uint64{"/": 42}))
		Expect(err).To(MatchError(ContainSubstring("checking the filesystem of the work directory /work: ")))
		Expect(err).To(MatchError(ContainSubstring("no such file or directory")))

		err = checkRootImageDir("/work", devs(map[string]uint64{"/work": 42}))
		Expect(err).To(MatchError(ContainSubstring("checking the filesystem of the container's root directory: ")))
	})
})

var _ = Describe("creating the guest root image", func() {
	var (
		dir          string
		restoreSteps func()
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		oldTruncate, oldUnlink := truncateRootImage, unlinkRootImage
		restoreSteps = func() { truncateRootImage, unlinkRootImage = oldTruncate, oldUnlink }
	})

	AfterEach(func() { restoreSteps() })

	names := func() []string {
		entries, err := os.ReadDir(dir)
		Expect(err).NotTo(HaveOccurred())
		var got []string
		for _, e := range entries {
			got = append(got, e.Name())
		}
		return got
	}

	statFile := func(f *os.File) *syscall.Stat_t {
		var st syscall.Stat_t
		Expect(syscall.Fstat(int(f.Fd()), &st)).To(Succeed())
		return &st
	}

	It("returns an open file of exactly the size, with no name and no link", func() {
		f, err := createRootImage(dir, 256*testMiB)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()

		st := statFile(f)
		Expect(st.Size).To(Equal(int64(256 * testMiB)))
		Expect(st.Nlink).To(BeZero(), "the image must be unlinked")
		Expect(names()).To(BeEmpty())
	})

	It("is sparse, so only the blocks the guest writes count against the quota", func() {
		f, err := createRootImage(dir, 256*testMiB)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(statFile(f).Blocks * 512).To(BeNumerically("<", testMiB))

		_, err = f.WriteAt([]byte("tail"), 256*testMiB-4)
		Expect(err).NotTo(HaveOccurred())
		Expect(statFile(f).Blocks*512).To(BeNumerically("<", testMiB), "a write at the end allocates its own block only")
		Expect(statFile(f).Size).To(Equal(int64(256 * testMiB)))
	})

	It("is readable and writable, and holds what is written", func() {
		f, err := createRootImage(dir, 64*testMiB)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()

		_, err = f.WriteAt([]byte("guest bytes"), 1234)
		Expect(err).NotTo(HaveOccurred())
		got := make([]byte, 11)
		_, err = f.ReadAt(got, 1234)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("guest bytes"))
		zero := make([]byte, 4)
		_, err = f.ReadAt(zero, 64*testMiB-4)
		Expect(err).NotTo(HaveOccurred())
		Expect(zero).To(Equal(make([]byte, 4)))
	})

	It("has mode 0600 whatever the umask", func() {
		for _, mask := range []int{0o022, 0o277, 0o000} {
			old := unix.Umask(mask)
			f, err := createRootImage(dir, 16*testMiB)
			Expect(unix.Umask(old)).To(Equal(mask), "the umask is restored")
			Expect(err).NotTo(HaveOccurred())
			Expect(statFile(f).Mode&0o7777).To(Equal(uint32(0o600)), "umask %04o", mask)
			Expect(f.Close()).To(Succeed())
		}
	})

	It("is close-on-exec, so no child inherits it by accident", func() {
		f, err := createRootImage(dir, 16*testMiB)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()

		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(flags & unix.FD_CLOEXEC).To(Equal(unix.FD_CLOEXEC))
	})

	It("gives each call its own file, even in one directory", func() {
		a, err := createRootImage(dir, 16*testMiB)
		Expect(err).NotTo(HaveOccurred())
		defer a.Close()
		b, err := createRootImage(dir, 16*testMiB)
		Expect(err).NotTo(HaveOccurred())
		defer b.Close()

		_, err = a.WriteAt([]byte("a"), 0)
		Expect(err).NotTo(HaveOccurred())
		got := make([]byte, 1)
		_, err = b.ReadAt(got, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal([]byte{0}))
	})

	It("unlinks the file before it sizes it", func() {
		var namesWhenSized []string
		truncateRootImage = func(f *os.File, size int64) error {
			namesWhenSized = names()
			return f.Truncate(size)
		}
		f, err := createRootImage(dir, 16*testMiB)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(namesWhenSized).To(BeEmpty())
	})

	It("sizes the file with the size it was given", func() {
		var sized int64
		truncateRootImage = func(f *os.File, size int64) error {
			sized = size
			return f.Truncate(size)
		}
		f, err := createRootImage(dir, 20*testMiB)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(sized).To(Equal(int64(20 * testMiB)))
	})

	Describe("failures", func() {
		const prefix = "creating the guest root image in "

		It("fails in a directory that does not exist", func() {
			missing := filepath.Join(dir, "gone")
			f, err := createRootImage(missing, 16*testMiB)
			Expect(f).To(BeNil())
			Expect(err).To(MatchError(HavePrefix(prefix + missing + ": ")))
			Expect(errors.Is(err, os.ErrNotExist)).To(BeTrue())
		})

		It("refuses a name that is taken, and leaves that file as it is", func() {
			taken := filepath.Join(dir, rootImageName)
			Expect(os.WriteFile(taken, []byte("not ours"), 0o600)).To(Succeed())

			f, err := createRootImage(dir, 16*testMiB)
			Expect(f).To(BeNil())
			Expect(err).To(MatchError(HavePrefix(prefix + dir + ": ")))
			Expect(errors.Is(err, os.ErrExist)).To(BeTrue())
			Expect(os.ReadFile(taken)).To(Equal([]byte("not ours")))
		})

		DescribeTable("refuses a size that is not positive, before it creates anything",
			func(size int64, why string) {
				f, err := createRootImage(dir, size)
				Expect(f).To(BeNil())
				Expect(err).To(MatchError(prefix + dir + ": " + why))
				Expect(names()).To(BeEmpty())
			},
			Entry("zero", int64(0), "the size 0 is not positive"),
			Entry("negative", int64(-4096), "the size -4096 is not positive"),
		)

		It("closes the file and leaves nothing when the size is refused", func() {
			var created *os.File
			truncateRootImage = func(f *os.File, size int64) error {
				created = f
				return syscall.EFBIG
			}
			before := openFDs()
			f, err := createRootImage(dir, 16*testMiB)
			Expect(f).To(BeNil())
			Expect(err).To(MatchError(prefix + dir + ": sizing it to 16777216 bytes: file too large"))
			Expect(errors.Is(err, syscall.EFBIG)).To(BeTrue())
			Expect(names()).To(BeEmpty())
			_, statErr := created.Stat()
			Expect(errors.Is(statErr, os.ErrClosed)).To(BeTrue(), "the file must be closed")
			Expect(openFDs()).To(Equal(before))
		})

		It("closes the file and reports it when the file cannot be unlinked", func() {
			var created *os.File
			unlinkRootImage = func(path string) error {
				Expect(path).To(Equal(filepath.Join(dir, rootImageName)))
				return syscall.EPERM
			}
			truncateRootImage = func(f *os.File, size int64) error {
				created = f
				Fail("sized a file that could not be unlinked")
				return nil
			}
			before := openFDs()
			f, err := createRootImage(dir, 16*testMiB)
			Expect(f).To(BeNil())
			Expect(openFDs()).To(Equal(before), "the file must be closed")
			Expect(err).To(MatchError(prefix + dir + ": operation not permitted"))
			Expect(errors.Is(err, syscall.EPERM)).To(BeTrue())
			Expect(created).To(BeNil())
			Expect(names()).To(ConsistOf(rootImageName), "nothing here removed the file")

			// Only the injected unlink failed; the file is empty and ours.
			Expect(os.Remove(filepath.Join(dir, rootImageName))).To(Succeed())
		})
	})
})
