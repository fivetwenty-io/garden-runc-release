//go:build linux

package main

import (
	"errors"
	"os"
	"slices"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// Every spec starts with a root image that takes direct I/O, so that the
// QEMU command lines run gives are the same on every host, whatever file
// system the spec's temporary directory is on. The specs below that probe a
// real image restore the real probe themselves.
var _ = BeforeEach(func() {
	saved := rootDirectIO
	DeferCleanup(func() { rootDirectIO = saved })
	rootDirectIO = func(*os.File) error { return nil }
})

var _ = Describe("withDirectRootDrive", func() {
	It("switches only the root drive to direct I/O and keeps the guest's flushes dropped", func() {
		argv := concat(goldenQEMUBase, goldenQEMUDrive, goldenQEMURootDrive("5"), goldenQEMUBalloon)
		before := slices.Clone(argv)
		Expect(withDirectRootDrive(argv)).To(Equal(concat(goldenQEMUBase, goldenQEMUDrive, goldenQEMUDirectRootDrive("5"), goldenQEMUBalloon)))
		Expect(argv).To(Equal(before))
	})

	It("leaves a command line without a root drive as it is", func() {
		argv := concat(goldenQEMUBase, goldenQEMUDrive, goldenQEMUBalloon)
		Expect(withDirectRootDrive(argv)).To(Equal(argv))
	})

	It("gives the root drive the caching that qemuRootDrive names", func() {
		Expect(withDirectRootDrive(qemuRootDrive("/proc/self/fd/4"))).To(Equal(goldenQEMUDirectRootDrive("4")))
	})
})

var _ = Describe("probeDirectIO", func() {
	It("opens a root image again for direct I/O and leaves the image open", func() {
		root, err := createRootImage(GinkgoT().TempDir(), 1<<20)
		Expect(err).NotTo(HaveOccurred())
		defer root.Close()
		err = probeDirectIO(root)
		if errors.Is(err, unix.EINVAL) {
			Skip("the spec's temporary directory is on a file system without direct I/O")
		}
		Expect(err).NotTo(HaveOccurred())
		_, err = root.WriteAt([]byte("still open"), 0)
		Expect(err).NotTo(HaveOccurred())
	})

	It("returns the error of a file that cannot be opened for direct I/O", func() {
		dir, err := os.Open(GinkgoT().TempDir())
		Expect(err).NotTo(HaveOccurred())
		defer dir.Close()
		err = probeDirectIO(dir)
		Expect(err).To(MatchError(ContainSubstring("opening the guest root image for direct I/O")))
		Expect(errors.Is(err, unix.EISDIR)).To(BeTrue())
	})
})
