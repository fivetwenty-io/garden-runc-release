//go:build linux

package main

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// writeSuperblock writes a file that holds just enough of a squashfs
// superblock for openStackImage: the magic and the compressor id.
func writeSuperblock(path string, magic uint32, compressor uint16) {
	sb := make([]byte, 96)
	binary.LittleEndian.PutUint32(sb, magic)
	binary.LittleEndian.PutUint16(sb[squashfsCompressorOffset:], compressor)
	Expect(os.WriteFile(path, sb, 0o444)).To(Succeed())
}

var _ = Describe("openStackImage", func() {
	var dir, saved string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		saved = stackImagePath
		stackImagePath = filepath.Join(dir, "rootfs.squashfs")
	})

	AfterEach(func() {
		stackImagePath = saved
	})

	It("names the production path by default", func() {
		Expect(saved).To(Equal("/opt/garden-vm/stack/rootfs.squashfs"))
	})

	It("returns an open, read-only file for an lz4 squashfs", func() {
		writeSuperblock(stackImagePath, squashfsMagic, squashfsCompressorLZ4)

		f, reason := openStackImage()
		Expect(reason).To(BeEmpty())
		Expect(f).NotTo(BeNil())
		defer f.Close()
		_, err := f.Write([]byte("x"))
		Expect(err).To(HaveOccurred())
	})

	It("refuses a missing file", func() {
		f, reason := openStackImage()
		Expect(f).To(BeNil())
		Expect(reason).To(ContainSubstring("cannot be opened"))
	})

	It("refuses a directory", func() {
		Expect(os.Mkdir(stackImagePath, 0o755)).To(Succeed())

		f, reason := openStackImage()
		Expect(f).To(BeNil())
		Expect(reason).To(ContainSubstring("not a regular file"))
	})

	It("refuses a file that is too short", func() {
		Expect(os.WriteFile(stackImagePath, []byte("hsqs"), 0o444)).To(Succeed())

		f, reason := openStackImage()
		Expect(f).To(BeNil())
		Expect(reason).To(ContainSubstring("too short"))
	})

	It("refuses the wrong magic", func() {
		writeSuperblock(stackImagePath, 0x464c457f, squashfsCompressorLZ4)

		f, reason := openStackImage()
		Expect(f).To(BeNil())
		Expect(reason).To(ContainSubstring("not a squashfs"))
	})

	It("refuses a gzip squashfs", func() {
		writeSuperblock(stackImagePath, squashfsMagic, 1)

		f, reason := openStackImage()
		Expect(f).To(BeNil())
		Expect(reason).To(ContainSubstring("compressor 1"))
		Expect(reason).To(ContainSubstring("lz4"))
	})

	Describe("with images from the real QEMU artifacts mksquashfs", func() {
		var art, tree string

		BeforeEach(func() {
			art = squashTool("mksquashfs")
			tree = GinkgoT().TempDir()
			writeHomeTree(tree)
		})

		build := func(comp string) {
			out, err := exec.Command(filepath.Join(art, "mksquashfs"), tree, stackImagePath,
				"-noappend", "-comp", comp, "-no-progress", "-quiet").CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), string(out))
		}

		It("accepts an lz4 image", func() {
			build("lz4")

			f, reason := openStackImage()
			Expect(reason).To(BeEmpty())
			Expect(f).NotTo(BeNil())
			defer f.Close()
		})

		It("refuses a gzip image", func() {
			build("gzip")

			f, reason := openStackImage()
			Expect(f).To(BeNil())
			Expect(reason).To(ContainSubstring("compressor 1"))
		})
	})
})
