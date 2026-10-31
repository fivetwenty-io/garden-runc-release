//go:build linux

package main

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The fields of the ext2 superblock, which starts 1024 bytes into the
// filesystem, that the volume specs read and change, as offsets into the
// superblock.
const (
	extSuperblockOffset = 1024
	extSuperblockBytes  = 1024

	extBlocksCountLo   = 0x04
	extFreeBlocksLo    = 0x0c
	extLogBlockSize    = 0x18
	extFirstDataBlock  = 0x14
	extState           = 0x3a
	extInodeSize       = 0x58
	extFeatureCompat   = 0x5c
	extFeatureIncompat = 0x60
	extFeatureROCompat = 0x64
	extUUID            = 0x68
	extDescSize        = 0xfe
	extBlocksCountHi   = 0x150
	extFreeBlocksHi    = 0x158
	extChecksumSeed    = 0x270
	extChecksum        = 0x3fc

	extStateValid = 0x1

	extCompatHasJournal     = 0x4
	extCompatResizeInode    = 0x10
	extIncompatExtents      = 0x40
	extIncompat64Bit        = 0x80
	extIncompatFlexBG       = 0x200
	extIncompatCsumSeed     = 0x2000
	extROCompatMetadataCsum = 0x400
)

// extRootInode is the root directory's inode number, and its inode is the
// second in the first group's inode table.
const extRootInode = 2

// The fields of an ext2 inode that the specs change.
const (
	extInodeMode       = 0x00
	extInodeLinks      = 0x1a
	extInodeGeneration = 0x64
	extInodeChecksumLo = 0x7c
	extInodeExtraIsize = 0x80
	extInodeChecksumHi = 0x82
)

// castagnoli is the CRC32C table of ext4's metadata checksums.
var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// ext4CRC32C continues the CRC32C crc over p as ext4 computes its
// checksums, without the inversions of the standard CRC.
func ext4CRC32C(crc uint32, p []byte) uint32 { return ^crc32.Update(^crc, castagnoli, p) }

// extImage is the ext2, ext3, or ext4 filesystem in a host image file, read
// and changed from the host while no guest runs on it.
type extImage struct {
	f  *os.File
	sb []byte
}

// readExtImage reads the superblock of the filesystem in f.
func readExtImage(f *os.File) *extImage {
	GinkgoHelper()
	sb := make([]byte, extSuperblockBytes)
	_, err := f.ReadAt(sb, extSuperblockOffset)
	Expect(err).NotTo(HaveOccurred())
	Expect(binary.LittleEndian.Uint16(sb[0x38:])).To(Equal(uint16(0xef53)), "the image holds no ext filesystem")
	return &extImage{f: f, sb: sb}
}

func (e *extImage) u16(off int) uint32 { return uint32(binary.LittleEndian.Uint16(e.sb[off:])) }
func (e *extImage) u32(off int) uint32 { return binary.LittleEndian.Uint32(e.sb[off:]) }

// hasJournal reports whether the filesystem has an internal journal.
func (e *extImage) hasJournal() bool { return e.u32(extFeatureCompat)&extCompatHasJournal != 0 }

// checksummed reports whether the filesystem's metadata carry checksums,
// which every change from the host must then recompute.
func (e *extImage) checksummed() bool {
	return e.u32(extFeatureROCompat)&extROCompatMetadataCsum != 0
}

// blockSize returns the filesystem's block size in bytes.
func (e *extImage) blockSize() int64 { return int64(1024) << e.u32(extLogBlockSize) }

// blocks returns the filesystem's block count, with its high half when
// the filesystem is 64-bit.
func (e *extImage) blocks() int64 {
	n := int64(e.u32(extBlocksCountLo))
	if e.u32(extFeatureIncompat)&extIncompat64Bit != 0 {
		n |= int64(e.u32(extBlocksCountHi)) << 32
	}
	return n
}

// freeBlocks returns the free block count the superblock records, which
// e2fsck brings up to date.
func (e *extImage) freeBlocks() int64 {
	n := int64(e.u32(extFreeBlocksLo))
	if e.u32(extFeatureIncompat)&extIncompat64Bit != 0 {
		n |= int64(e.u32(extFreeBlocksHi)) << 32
	}
	return n
}

// uuid returns the filesystem's UUID, which a new format would change.
func (e *extImage) uuid() string { return string(e.sb[extUUID : extUUID+16]) }

// clean reports whether the superblock marks the filesystem cleanly
// unmounted.
func (e *extImage) clean() bool { return e.u16(extState)&extStateValid != 0 }

// markUnclean clears the clean flag, as a guest that stopped without
// unmounting the filesystem leaves it, so that e2fsck -p checks it in full.
func (e *extImage) markUnclean() {
	GinkgoHelper()
	binary.LittleEndian.PutUint16(e.sb[extState:], uint16(e.u16(extState)&^extStateValid))
	if e.checksummed() {
		binary.LittleEndian.PutUint32(e.sb[extChecksum:], ext4CRC32C(^uint32(0), e.sb[:extChecksum]))
	}
	_, err := e.f.WriteAt(e.sb, extSuperblockOffset)
	Expect(err).NotTo(HaveOccurred())
}

// rootInode returns the root directory's inode and its offset in the image.
func (e *extImage) rootInode() ([]byte, int64) {
	GinkgoHelper()
	blockSize := int64(1024) << e.u32(extLogBlockSize)
	descSize := 32
	if e.u32(extFeatureIncompat)&extIncompat64Bit != 0 {
		descSize = int(e.u16(extDescSize))
	}
	desc := make([]byte, descSize)
	_, err := e.f.ReadAt(desc, (int64(e.u32(extFirstDataBlock))+1)*blockSize)
	Expect(err).NotTo(HaveOccurred())
	table := int64(binary.LittleEndian.Uint32(desc[8:]))
	if descSize >= 64 {
		table |= int64(binary.LittleEndian.Uint32(desc[0x28:])) << 32
	}
	inodeSize := int64(e.u16(extInodeSize))
	off := table*blockSize + (extRootInode-1)*inodeSize
	inode := make([]byte, inodeSize)
	_, err = e.f.ReadAt(inode, off)
	Expect(err).NotTo(HaveOccurred())
	return inode, off
}

// rootLinks returns the root directory's link count.
func (e *extImage) rootLinks() uint16 {
	inode, _ := e.rootInode()
	return binary.LittleEndian.Uint16(inode[extInodeLinks:])
}

// editRoot changes the root directory's inode with edit and writes it back
// with its checksum recomputed, so that e2fsck sees the change itself and
// not a checksum error.
func (e *extImage) editRoot(edit func(inode []byte)) {
	GinkgoHelper()
	inode, off := e.rootInode()
	edit(inode)
	if e.checksummed() {
		seed := e.u32(extChecksumSeed)
		if e.u32(extFeatureIncompat)&extIncompatCsumSeed == 0 {
			seed = ext4CRC32C(^uint32(0), e.sb[extUUID:extUUID+16])
		}
		hi := len(inode) > 128 && binary.LittleEndian.Uint16(inode[extInodeExtraIsize:]) >= extInodeChecksumHi+2-128
		binary.LittleEndian.PutUint16(inode[extInodeChecksumLo:], 0)
		if hi {
			binary.LittleEndian.PutUint16(inode[extInodeChecksumHi:], 0)
		}
		var number [4]byte
		binary.LittleEndian.PutUint32(number[:], extRootInode)
		sum := ext4CRC32C(ext4CRC32C(ext4CRC32C(seed, number[:]), inode[extInodeGeneration:extInodeGeneration+4]), inode)
		binary.LittleEndian.PutUint16(inode[extInodeChecksumLo:], uint16(sum))
		if hi {
			binary.LittleEndian.PutUint16(inode[extInodeChecksumHi:], uint16(sum>>16))
		}
	}
	_, err := e.f.WriteAt(inode, off)
	Expect(err).NotTo(HaveOccurred())
}

// hostBlocks returns the bytes the host file f holds blocks for.
func hostBlocks(f *os.File) int64 {
	GinkgoHelper()
	info, err := f.Stat()
	Expect(err).NotTo(HaveOccurred())
	st, ok := info.Sys().(*syscall.Stat_t)
	Expect(ok).To(BeTrue())
	return st.Blocks * 512
}

// legacyImage returns a volume image of size bytes that holds the ext2
// filesystem an rvm.6 guest made on a blank image, with the guest's own
// busybox mke2fs and its arguments of that release.
func legacyImage(size int64) *os.File {
	GinkgoHelper()
	f := openSizedFile(size)
	out, err := exec.Command(guestBusybox(), "mke2fs", "-F", "-m", "0", "-L", "rvm-volume", f.Name()).CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), string(out))
	img := readExtImage(f)
	Expect(img.hasJournal()).To(BeFalse(), "busybox mke2fs made a journal")
	return f
}

// volumeMounts returns, for each mount= line of mountsCommand in out, the
// ext4 mount options of the path it names.
func volumeMounts(out string) map[string][]string {
	GinkgoHelper()
	got := map[string][]string{}
	for _, m := range regexp.MustCompile(`(?m)^mount=(\S+) (\S*)\r?$`).FindAllStringSubmatch(out, -1) {
		Expect(got).NotTo(HaveKey(m[1]), out)
		Expect(m[2]).NotTo(BeEmpty(), "%s is not an ext4 mount\n%s", m[1], out)
		got[m[1]] = strings.Split(m[2], ",")
	}
	return got
}

// mountsCommand prints a mount= line with the ext4 mount options of each
// of paths.
func mountsCommand(paths ...string) string {
	return `for p in ` + strings.Join(paths, " ") + `; do
	echo "mount=$p $(grep " $p ext4 " /proc/mounts | cut -d ' ' -f 4)"
done
`
}

var _ = Describe("volume images against a real QEMU", func() {
	const dataDir = "/home/vcap/data"

	// imageGuest returns a guest that runs command with a root image and an
	// image volume at each of dirs, in volume order, of the sizes given.
	imageGuest := func(command string, dirs []string, sizes ...int64) guestContents {
		Expect(dirs).To(HaveLen(len(sizes)))
		g := taskGuest(command)
		for _, d := range dirs {
			g.vols = append(g.vols, guestVolume{ContainerDir: d, ImageName: "volume.img"})
		}
		g.drives.volumes = qemuImageDrives(sizes...)
		withRealRoot(&g)
		return g
	}
	// bootData boots a guest that runs command with img as its one volume
	// at dataDir, and returns the console output, which a failed setup
	// leaves without the start tag.
	bootData := func(img *os.File, command string) string {
		info, err := img.Stat()
		Expect(err).NotTo(HaveOccurred())
		return bootRealGuestEdited(imageGuest(command, []string{dataDir}, info.Size()), []*os.File{img}, realRootImage(), nil)
	}
	// markData boots a guest that leaves text in a file on img and expects
	// the boot to go through.
	markData := func(img *os.File, text string) {
		out := bootData(img, "echo "+text+" >"+dataDir+"/mark")
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
	}

	It("formats a new image as a journalled ext4 without writing the image's size, mounts it with sync and noinit_itable, and preens it at the next boot", func() {
		img := openSizedFile(defaultImageSize)
		if hostBlocks(img) != 0 {
			Skip("the file system under the temporary directory does not keep a truncated file sparse")
		}
		out := bootData(img, mountsCommand(dataDir)+"echo kept >"+dataDir+"/mark\n")
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
		Expect(out).NotTo(ContainSubstring("e2fsck"), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		options := volumeMounts(out)[dataDir]
		Expect(options).To(ContainElements("sync", "dirsync", "noatime", "noinit_itable"), out)

		fs := readExtImage(img)
		Expect(extLabel(img)).To(Equal("rvm-volume"))
		Expect(fs.hasJournal()).To(BeTrue(), "the new image has no journal")
		Expect(fs.u32(extFeatureCompat) & extCompatResizeInode).NotTo(BeZero())
		for _, feature := range []uint32{extIncompatExtents, extIncompat64Bit, extIncompatFlexBG} {
			Expect(fs.u32(extFeatureIncompat)&feature).NotTo(BeZero(), "incompat feature %#x", feature)
		}
		Expect(fs.checksummed()).To(BeTrue())
		Expect(int64(1024) << fs.u32(extLogBlockSize)).To(Equal(int64(4096)))
		// The journal of a 1 GiB ext4 is 32 MiB, and the inode tables take
		// 16 MiB, so an image that holds less than 16 MiB had neither
		// written in zeros, by mke2fs or by the kernel after the mount.
		GinkgoWriter.Printf("the new 1 GiB image holds %d KiB on the host\n", hostBlocks(img)/1024)
		Expect(hostBlocks(img)).To(BeNumerically("<", 16<<20), "the format or the mount wrote the journal or the inode tables")
		uuid := fs.uuid()

		// The next boot checks the image, finds it clean, and mounts it as
		// it was.
		out = bootData(img, `echo "mark=$(cat `+dataDir+`/mark)"`)
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
		Expect(out).To(MatchRegexp(`(?m)^rvm-volume: clean, [0-9]+/[0-9]+ files, [0-9]+/[0-9]+ blocks\r?$`), out)
		Expect(out).To(MatchRegexp(`(?m)^mark=kept\r?$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		Expect(readExtImage(img).uuid()).To(Equal(uuid), "the image was formatted again")
	})

	DescribeTable("repairs an image with an error that e2fsck -p fixes, and mounts it with its files",
		func(newImage func() *os.File) {
			img := newImage()
			markData(img, "before-the-repair")
			fs := readExtImage(img)
			uuid := fs.uuid()
			Expect(fs.rootLinks()).To(Equal(uint16(3)), "a root with lost+found and no other directory")
			fs.editRoot(func(inode []byte) { binary.LittleEndian.PutUint16(inode[extInodeLinks:], 7) })
			fs.markUnclean()

			out := bootData(img, `echo "mark=$(cat `+dataDir+`/mark)"`)
			Expect(out).To(MatchRegexp(`(?m)^rvm-volume was not cleanly unmounted, check forced\.\r?$`), out)
			Expect(out).To(MatchRegexp(`(?m)^rvm-volume: Inode 2 ref count is 7, should be 3\.  FIXED\.\r?$`), out)
			Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
			Expect(out).To(MatchRegexp(`(?m)^mark=before-the-repair\r?$`), out)
			Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)

			fs = readExtImage(img)
			Expect(fs.rootLinks()).To(Equal(uint16(3)), "the repair is not on the image")
			Expect(fs.clean()).To(BeTrue(), "the image was not left clean")
			Expect(fs.uuid()).To(Equal(uuid), "the image was formatted again")
		},
		Entry("a journalled ext4 image that a guest formatted", func() *os.File { return openSizedFile(defaultImageSize) }),
		Entry("an ext2 image from rvm.6", func() *os.File { return legacyImage(defaultImageSize) }),
	)

	// refusedImage boots a guest on img and expects stage 2 to fail the boot
	// because e2fsck -p exits with status before the command starts: with
	// the line for errors it left, from 4 to 7, or with the line for a check
	// that could not run, from 8 on.
	refusedImage := func(img *os.File, status int) string {
		out := bootData(img, "echo command-ran")
		line := "the volume image volume.img has errors that e2fsck -p can't repair; inspect it on the volume (e2fsck -p exited " + strconv.Itoa(status) + " for " + dataDir + ", and vm-launch never formats an image that is not blank)"
		if status >= 8 {
			line = "e2fsck -p for the volume image volume.img at " + dataDir + " exited " + strconv.Itoa(status) + ", which means it could not check the image, not that the image has errors it can't repair (the check adds 8 for an operational error, 16 for a usage error, 32 for a cancelled check, 128 for a library error, and 4 for errors it left); inspect it on the volume, and vm-launch never formats an image that is not blank"
		}
		Expect(out).To(MatchRegexp(`(?m)^`+regexp.QuoteMeta("vm-launch guest setup: "+line)+`\r?$`), out)
		Expect(out).NotTo(ContainSubstring(startTag(testNonce)), out)
		Expect(out).NotTo(ContainSubstring("command-ran"), out)
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup: mounting"), out)
		return out
	}

	DescribeTable("fails the boot on an image whose filesystem e2fsck -p can't repair, and never formats it",
		func(newImage func() *os.File) {
			img := newImage()
			markData(img, "kept-through-the-failure")
			fs := readExtImage(img)
			uuid := fs.uuid()
			fs.editRoot(func(inode []byte) { binary.LittleEndian.PutUint16(inode[extInodeMode:], syscall.S_IFREG|0o644) })
			fs.markUnclean()

			out := refusedImage(img, 4)
			Expect(out).To(MatchRegexp(`(?m)^rvm-volume: Root inode is not a directory\.`), out)
			Expect(out).To(MatchRegexp(`(?m)^rvm-volume: UNEXPECTED INCONSISTENCY; RUN fsck MANUALLY\.`), out)
			fs = readExtImage(img)
			Expect(fs.uuid()).To(Equal(uuid), "the image was formatted")
			Expect(extLabel(img)).To(Equal("rvm-volume"))
			Expect(imageHolds(img, "kept-through-the-failure")).To(BeTrue(), "the file's data is gone from the image")
		},
		Entry("a journalled ext4 image that a guest formatted", func() *os.File { return openSizedFile(defaultImageSize) }),
		Entry("an ext2 image from rvm.6", func() *os.File { return legacyImage(defaultImageSize) }),
	)

	It("fails the boot on an image that is not blank and holds no filesystem, and leaves every byte of it", func() {
		img := openSizedFile(defaultImageSize)
		// The bytes go inside the first 64 KiB, which is what the blank
		// check reads.
		_, err := img.WriteAt([]byte("not a filesystem, and not blank either"), 8<<10)
		Expect(err).NotTo(HaveOccurred())
		before := imageDigest(img)
		out := refusedImage(img, 8)
		Expect(out).To(ContainSubstring("Bad magic number in super-block"), out)
		Expect(imageDigest(img)).To(Equal(before), "the guest wrote to the image")
		Expect(extLabel(img)).To(BeEmpty())
	})

	// growTo makes the host file img size bytes long, as a larger disk_mb
	// leaves a volume's image.
	growTo := func(img *os.File, size int64) {
		GinkgoHelper()
		Expect(img.Truncate(size)).To(Succeed())
	}
	// grewLine matches the line ext4grow prints when it grows the volume.
	const grewLine = `(?m)^ext4grow: grew ` + dataDir + ` to fill /dev/vd[a-z]+, from [0-9]+ to [0-9]+ usable blocks of [0-9]+ bytes\r?$`

	It("grows a 1 GiB journalled image to 2 GiB online after its preen, with its files, and leaves it alone at the next boot", func() {
		img := openSizedFile(defaultImageSize)
		markData(img, "kept-through-the-grow")
		fs := readExtImage(img)
		uuid := fs.uuid()
		Expect(fs.hasJournal()).To(BeTrue())
		Expect(fs.blocks() * fs.blockSize()).To(Equal(int64(defaultImageSize)))

		growTo(img, 2*defaultImageSize)
		out := bootData(img, `echo "mark=$(cat `+dataDir+`/mark)"; df -k `+dataDir+` | sed -n 's/^[^ ]* *\([0-9]*\) .*/size=\1/p'`)
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
		Expect(out).To(MatchRegexp(`(?m)^rvm-volume: clean, `), out)
		Expect(out).To(MatchRegexp(grewLine), out)
		Expect(out).To(MatchRegexp(`(?m)^mark=kept-through-the-grow\r?$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		// The command already sees the grown filesystem.
		m := regexp.MustCompile(`(?m)^size=([0-9]+)\r?$`).FindStringSubmatch(out)
		Expect(m).NotTo(BeNil(), out)
		kib, err := strconv.ParseInt(m[1], 10, 64)
		Expect(err).NotTo(HaveOccurred())
		Expect(kib).To(BeNumerically(">", int64(defaultImageSize)/1024), out)

		fs = readExtImage(img)
		Expect(fs.uuid()).To(Equal(uuid), "the image was formatted again")
		Expect(fs.blocks() * fs.blockSize()).To(Equal(int64(2 * defaultImageSize)))
		Expect(imageHolds(img, "kept-through-the-grow")).To(BeTrue())

		// The image fills its device now, so the next boot preens it and
		// runs no ext4grow.
		out = bootData(img, `echo "mark=$(cat `+dataDir+`/mark)"`)
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
		Expect(out).NotTo(ContainSubstring("ext4grow"), out)
		Expect(out).To(MatchRegexp(`(?m)^mark=kept-through-the-grow\r?$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		Expect(readExtImage(img).blocks()).To(Equal(fs.blocks()))
	})

	It("gives a legacy ext2 image with files a 4 MiB journal before it grows it, and keeps its files", func() {
		img := legacyImage(defaultImageSize)
		markData(img, "kept-through-the-journal")
		fs := readExtImage(img)
		uuid, blocks := fs.uuid(), fs.blocks()
		Expect(fs.hasJournal()).To(BeFalse())

		growTo(img, 2*defaultImageSize)
		out := bootData(img, `echo "mark=$(cat `+dataDir+`/mark)"`)
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
		Expect(out).NotTo(ContainSubstring("mounts at its old size"), out)
		Expect(out).To(MatchRegexp(grewLine), out)
		Expect(out).To(MatchRegexp(`(?m)^mark=kept-through-the-journal\r?$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)

		fs = readExtImage(img)
		Expect(fs.uuid()).To(Equal(uuid), "the image was formatted again")
		Expect(fs.hasJournal()).To(BeTrue(), "the legacy image got no journal")
		devBlocks := int64(2*defaultImageSize) / fs.blockSize()
		GinkgoWriter.Printf("the legacy image grew from %d to %d blocks of %d bytes on a device of %d\n", blocks, fs.blocks(), fs.blockSize(), devBlocks)
		Expect(fs.blocks()).To(BeNumerically(">", blocks))
		Expect(fs.blocks()).To(BeNumerically("<=", devBlocks))
		Expect(imageHolds(img, "kept-through-the-journal")).To(BeTrue())
	})

	It("mounts a full legacy image at its old size without a journal and asks for 4 MiB, and grows it once the app frees the space", func() {
		const size = 16 << 20
		img := legacyImage(size)
		markData(img, "kept-while-full")
		// The guest fills the image; dd stops when the filesystem is full.
		out := bootData(img, "dd if=/dev/zero of="+dataDir+"/fill bs=64k 2>/dev/null; sync -f "+dataDir+"; echo filled")
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
		Expect(out).To(MatchRegexp(`(?m)^filled\r?$`), out)
		fs := readExtImage(img)
		uuid, blocks := fs.uuid(), fs.blocks()
		Expect(fs.hasJournal()).To(BeFalse())

		Expect(fs.freeBlocks()*fs.blockSize()).To(BeNumerically("<", 4<<20), "the fill left 4 MiB free")

		growTo(img, 2*size)
		out = bootData(img, `echo "mark=$(cat `+dataDir+`/mark)"; rm `+dataDir+`/fill`)
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
		Expect(out).To(MatchRegexp(`(?m)^vm-launch guest: the volume image volume\.img at `+dataDir+` has no journal and only [0-9]+ KiB free, and it needs 4 MiB free for the journal it must have before it grows, so it mounts at its old size of `+strconv.FormatInt(blocks, 10)+` blocks of [0-9]+ bytes; free 4 MiB in `+dataDir+` and restart the app to grow it\r?$`), out)
		Expect(out).NotTo(ContainSubstring("ext4grow"), out)
		Expect(out).To(MatchRegexp(`(?m)^mark=kept-while-full\r?$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		fs = readExtImage(img)
		Expect(fs.uuid()).To(Equal(uuid))
		Expect(fs.hasJournal()).To(BeFalse())
		Expect(fs.blocks()).To(Equal(blocks), "the full image grew")

		// The app freed the space, so the next boot adds the journal and
		// grows the image.
		out = bootData(img, `echo "mark=$(cat `+dataDir+`/mark)"`)
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
		Expect(out).To(MatchRegexp(grewLine), out)
		Expect(out).To(MatchRegexp(`(?m)^mark=kept-while-full\r?$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		fs = readExtImage(img)
		Expect(fs.hasJournal()).To(BeTrue())
		Expect(fs.blocks()).To(BeNumerically(">", blocks))
		Expect(fs.blocks()).To(BeNumerically("<=", int64(2*size)/fs.blockSize()))
	})

	It("grows a block volume online when its disk is bigger, without formatting or checking it", func() {
		const size = 64 << 20
		img := openSizedFile(size)
		markData(img, "kept-on-the-block-volume")
		fs := readExtImage(img)
		uuid, blocks := fs.uuid(), fs.blocks()

		growTo(img, 2*size)
		g := imageGuest(`echo "mark=$(cat `+dataDir+`/mark)"`, []string{dataDir}, 2*size)
		g.drives.volumes[0].kind = driveBlock
		out := bootRealGuestEdited(g, []*os.File{img}, realRootImage(), nil)
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
		Expect(out).NotTo(ContainSubstring("rvm-volume: clean"), out)
		Expect(out).To(MatchRegexp(grewLine), out)
		Expect(out).To(MatchRegexp(`(?m)^mark=kept-on-the-block-volume\r?$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		fs = readExtImage(img)
		Expect(fs.uuid()).To(Equal(uuid), "the block volume was formatted")
		Expect(fs.blocks()).To(BeNumerically(">", blocks))
		Expect(fs.blocks() * fs.blockSize()).To(Equal(int64(2 * size)))
	})

	It("fails the boot on an image whose filesystem is larger than its device, before the preen, and never mounts it", func() {
		img := openSizedFile(defaultImageSize)
		markData(img, "kept-on-a-shrunk-device")
		fs := readExtImage(img)
		growTo(img, defaultImageSize/2)
		before := imageDigest(img)
		out := bootData(img, "echo command-ran")
		Expect(out).To(MatchRegexp(`(?m)^vm-launch guest setup: the filesystem on the volume image volume\.img at `+dataDir+` has `+strconv.FormatInt(fs.blocks(), 10)+` blocks of 4096 bytes, more than the `+strconv.FormatInt(fs.blocks()/2, 10)+` its device holds, so the device was shrunk or holds another filesystem's data; vm-launch never mounts a filesystem larger than its device; inspect it on the volume\r?$`), out)
		Expect(out).NotTo(ContainSubstring("rvm-volume: clean"), out)
		Expect(out).NotTo(ContainSubstring(startTag(testNonce)), out)
		Expect(out).NotTo(ContainSubstring("command-ran"), out)
		Expect(imageDigest(img)).To(Equal(before), "the guest wrote to the image")
	})

	It("fails the boot on an image whose first 64 KiB are zero but which keeps a backup superblock, and never formats it", func() {
		img := openSizedFile(defaultImageSize)
		markData(img, "kept-behind-a-zeroed-head")
		fs := readExtImage(img)
		Expect(fs.blockSize()).To(Equal(int64(4096)))
		_, err := img.WriteAt(make([]byte, 64<<10), 0)
		Expect(err).NotTo(HaveOccurred())
		before := imageDigest(img)

		out := bootData(img, "echo command-ran")
		Expect(out).To(MatchRegexp(`(?m)^vm-launch guest setup: the volume image volume\.img for `+dataDir+` reads as zero in its first 64 KiB but holds the magic of an ext2, ext3, or ext4 superblock at byte 134217728, where a backup superblock is kept, so it looks like a damaged filesystem, and vm-launch never formats it; if the volume never held data, an interrupted first format can cause this, and deleting volume\.img on the volume lets the next start create it fresh; otherwise repair it by hand on the volume with e2fsck -b from a backup superblock \(e2fsck -b 32768 -B 4096 for 4096-byte blocks\)\r?$`), out)
		Expect(out).NotTo(ContainSubstring(startTag(testNonce)), out)
		Expect(out).NotTo(ContainSubstring("command-ran"), out)
		Expect(imageDigest(img)).To(Equal(before), "the guest wrote to the image")
		Expect(imageHolds(img, "kept-behind-a-zeroed-head")).To(BeTrue())
	})

	DescribeTable("fails the boot on a filesystem too small for a backup superblock whose first 64 KiB are zero but which is still there, also once the host grew its image, and never formats it",
		func(small, grown int64) {
			img := openSizedFile(small)
			markData(img, "kept-in-a-small-image")
			fs := readExtImage(img)
			Expect(fs.blockSize()).To(Equal(int64(4096)))
			Expect(fs.blocks()).To(BeNumerically("<=", 32768), "mke2fs made a second block group, which holds a backup superblock")
			_, err := img.WriteAt(make([]byte, 64<<10), 0)
			Expect(err).NotTo(HaveOccurred())
			size := small
			if grown > 0 {
				// The host grows the file before the boot, as a larger
				// size in the volume's settings does, and the guest has not
				// yet grown the filesystem, so it still has one group.
				growTo(img, grown)
				size = grown
			}
			before := imageDigest(img)

			out := bootData(img, "echo command-ran")
			read := min(size, int64(256<<20))
			Expect(out).To(MatchRegexp(`(?m)^`+regexp.QuoteMeta("vm-launch guest setup: the volume image volume.img for "+dataDir+" reads as zero in its first 64 KiB but not in all of its first "+strconv.FormatInt(read, 10)+" bytes, and a filesystem that vm-launch made on an image no larger than that, which the host may have grown since, may have no backup superblock that would tell a damaged filesystem from a new image, so it looks like a damaged filesystem, and vm-launch never formats it; if the volume never held data, an interrupted first format can cause this, and deleting volume.img on the volume lets the next start create it fresh; otherwise repair it by hand on the volume, where e2fsck -b needs a backup superblock that a filesystem this small may not have")+`\r?$`), out)
			Expect(out).NotTo(ContainSubstring(startTag(testNonce)), out)
			Expect(out).NotTo(ContainSubstring("command-ran"), out)
			Expect(imageDigest(img)).To(Equal(before), "the guest wrote to the image")
			Expect(imageHolds(img, "kept-in-a-small-image")).To(BeTrue())
		},
		Entry("of 64 MiB", int64(64<<20), int64(0)),
		Entry("of 64 MiB that the host grew to 1 GiB before the boot", int64(64<<20), int64(1<<30)),
	)

	It("stops a process the command left behind that ignores SIGTERM before it flushes and unmounts the volume, and keeps what both wrote", func() {
		img := openSizedFile(defaultImageSize)
		// The writer ignores SIGTERM and keeps its file open on the volume,
		// so only the teardown's SIGKILL lets the volume unmount.
		command := "( trap '' TERM; exec 3>>" + dataDir + "/left; while :; do echo left-behind-writer >&3; sleep 0.1; done ) &\n" +
			"sleep 0.5\necho kept-past-the-teardown >" + dataDir + "/mark\n"
		out := bootData(img, command)
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
		Expect(out).To(MatchRegexp(`(?m)^vm-launch guest: processes the command left were still running 2 seconds after SIGTERM, so the guest sends them SIGKILL before it flushes the volumes\r?$`), out)
		Expect(out).NotTo(ContainSubstring("second after SIGKILL"), out)
		Expect(out).NotTo(ContainSubstring("unmounting"), out)
		Expect(out).NotTo(ContainSubstring("flushing"), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		Expect(imageHolds(img, "kept-past-the-teardown")).To(BeTrue())
		Expect(imageHolds(img, "left-behind-writer")).To(BeTrue())
		fs := readExtImage(img)
		Expect(fs.clean()).To(BeTrue(), "the image was not unmounted cleanly")
	})

	It("finds no process left in a guest whose command left none, so the teardown neither waits nor reports one", func() {
		img := openSizedFile(defaultImageSize)
		out := bootData(img, "echo kept-without-a-wait >"+dataDir+"/mark")
		Expect(out).NotTo(ContainSubstring("SIGTERM"), out)
		Expect(out).NotTo(ContainSubstring("SIGKILL"), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		Expect(imageHolds(img, "kept-without-a-wait")).To(BeTrue())
	})

	It("drops sync and dirsync only from the images with a journal when the operator turns sync mounts off", func() {
		dirs := []string{"/home/vcap/new", "/home/vcap/legacy", "/home/vcap/small"}
		const smallImage = 4 << 20
		newImg, legacy, small := openSizedFile(defaultImageSize), legacyImage(defaultImageSize), openSizedFile(smallImage)
		vols := []*os.File{newImg, legacy, small}
		guest := func(noSync bool) guestContents {
			g := imageGuest(mountsCommand(dirs...), dirs, defaultImageSize, defaultImageSize, smallImage)
			g.noVolumeSync = noSync
			return g
		}

		out := bootRealGuestWith(guest(true), vols, realRootImage())
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
		Expect(out).NotTo(ContainSubstring("reading the filesystem features"), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		// The new 1 GiB image gets a journal, and a 4 MiB one is too small
		// for one, so it keeps sync and dirsync as the rvm.6 image does.
		Expect(readExtImage(newImg).hasJournal()).To(BeTrue())
		Expect(readExtImage(legacy).hasJournal()).To(BeFalse())
		Expect(readExtImage(small).hasJournal()).To(BeFalse())
		mounts := volumeMounts(out)
		Expect(mounts).To(HaveLen(3), out)
		Expect(mounts[dirs[0]]).NotTo(ContainElement("sync"), out)
		Expect(mounts[dirs[0]]).NotTo(ContainElement("dirsync"), out)
		Expect(mounts[dirs[0]]).To(ContainElements("noatime", "noinit_itable"), out)
		for _, d := range dirs[1:] {
			Expect(mounts[d]).To(ContainElements("sync", "dirsync", "noatime", "noinit_itable"), "%s\n%s", d, out)
		}

		// With the default, every image keeps sync and dirsync, the
		// journalled one included.
		out = bootRealGuestWith(guest(false), vols, realRootImage())
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
		mounts = volumeMounts(out)
		Expect(mounts).To(HaveLen(3), out)
		for _, d := range dirs {
			Expect(mounts[d]).To(ContainElements("sync", "dirsync", "noatime", "noinit_itable"), "%s\n%s", d, out)
		}
	})
})
