//go:build linux

package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// The descriptor the specs start from, as the bosh-disk driver writes it.
const (
	testBlockMajor = 8
	testBlockMinor = 16
	testBlockSize  = 4 << 20
	testBlockUUID  = "bc20d783-6145-4623-86bb-35110042b24b"
	testBlockDisk  = "bosh-disk-0123456789abcdef01"
	// testBlockMountID is the descriptor tmpfs's mount ID in the fake specs.
	testBlockMountID = 50
	// overflowUID is the uid a file owned outside the container's user
	// namespace shows inside it.
	overflowUID = 65534
)

// blockDescriptorText is a descriptor in the driver's format.
func blockDescriptorText(major, minor uint32, size int64, uuid, disk string) string {
	return fmt.Sprintf("version=1\nmajor=%d\nminor=%d\nsize=%d\nuuid=%s\ndisk_name=%s\n", major, minor, size, uuid, disk)
}

// testDescriptorText is the descriptor of the specs' disk.
func testDescriptorText() string {
	return blockDescriptorText(testBlockMajor, testBlockMinor, testBlockSize, testBlockUUID, testBlockDisk)
}

// ext4Superblock describes the fields of an ext4 superblock that
// checkExt4Superblock reads.
type ext4Superblock struct {
	magic       uint16
	compat      uint32
	incompat    uint32
	uuid        string
	journalInum uint32
}

// goodSuperblock is the superblock of an ext4 filesystem with an internal
// journal and the specs' UUID.
func goodSuperblock() ext4Superblock {
	return ext4Superblock{magic: ext4Magic, compat: ext4CompatHasJournal, uuid: testBlockUUID, journalInum: 8}
}

// diskBytes returns n bytes of a disk with sb at byte 1024.
func (sb ext4Superblock) diskBytes(n int) []byte {
	disk := make([]byte, n)
	raw := disk[ext4SuperblockOffset : ext4SuperblockOffset+ext4SuperblockSize]
	le := binary.LittleEndian
	le.PutUint16(raw[ext4MagicOffset:], sb.magic)
	le.PutUint32(raw[ext4FeatureCompatOff:], sb.compat)
	le.PutUint32(raw[ext4FeatureIncompatOff:], sb.incompat)
	u, err := hex.DecodeString(strings.ReplaceAll(sb.uuid, "-", ""))
	Expect(err).NotTo(HaveOccurred())
	Expect(u).To(HaveLen(16))
	copy(raw[ext4UUIDOffset:], u)
	le.PutUint32(raw[ext4JournalInumOffset:], sb.journalInum)
	return disk
}

// fakeBlockHost stands in for the kernel's view of the device node. The
// nodes are regular files holding a disk's first bytes, and fstat reports
// them as the block device rdev. Every other file it is asked about, which is
// the descriptor, is reported as owned by descUID.
type fakeBlockHost struct {
	rdev     uint64
	nodeType uint32
	descUID  uint32
	size     uint64
	sizeErr  error
	// openErr, when set, answers an open before the file is opened.
	openErr func(path string, flags int) error
	// replace makes the exclusive open report another inode.
	replace bool
	// nodes holds the flags of every node file descriptor it opened.
	nodes map[int]int
	opens []int
}

func newFakeBlockHost() *fakeBlockHost {
	return &fakeBlockHost{
		rdev:     unix.Mkdev(testBlockMajor, testBlockMinor),
		nodeType: unix.S_IFBLK,
		descUID:  overflowUID,
		size:     testBlockSize,
		nodes:    map[int]int{},
	}
}

func (h *fakeBlockHost) open(path string, flags int) (int, error) {
	h.opens = append(h.opens, flags)
	if h.openErr != nil {
		if err := h.openErr(path, flags); err != nil {
			return -1, err
		}
	}
	fd, err := linuxBlockHost{}.open(path, flags&^unix.O_EXCL)
	if err != nil {
		return -1, err
	}
	h.nodes[fd] = flags
	return fd, nil
}

func (h *fakeBlockHost) fstat(fd int, st *unix.Stat_t) error {
	if err := unix.Fstat(fd, st); err != nil {
		return err
	}
	flags, node := h.nodes[fd]
	if !node {
		st.Uid = h.descUID
		return nil
	}
	st.Mode = h.nodeType | 0o660
	st.Rdev = h.rdev
	if h.replace && flags&unix.O_EXCL != 0 {
		st.Ino++
	}
	return nil
}

func (h *fakeBlockHost) deviceBytes(int) (uint64, error) {
	return h.size, h.sizeErr
}

// blockFixture is a volume directory with a descriptor and a node directory
// with the node the descriptor names, for one blockProvider.
type blockFixture struct {
	dir, nodeDir, node string
	host               *fakeBlockHost
	provider           *blockProvider
}

func newBlockFixture() *blockFixture {
	requireOpenat2()
	f := &blockFixture{dir: GinkgoT().TempDir(), nodeDir: GinkgoT().TempDir(), host: newFakeBlockHost()}
	f.node = filepath.Join(f.nodeDir, strconv.Itoa(testBlockMajor)+"-"+strconv.Itoa(testBlockMinor))
	f.writeDescriptor(testDescriptorText())
	f.writeNode(goodSuperblock())
	f.provider = &blockProvider{name: "BOSH disk", source: boshDiskDescriptorSource, nodeDir: f.nodeDir, host: f.host}
	saved := dirProbe
	DeferCleanup(func() { dirProbe = saved })
	dirProbe = func(int, string) (mountProbe, error) {
		return mountProbe{MountID: testBlockMountID, MountRoot: true}, nil
	}
	return f
}

func (f *blockFixture) writeDescriptor(text string) {
	p := filepath.Join(f.dir, blockDescriptorFileName)
	_ = os.Chmod(p, 0o644)
	Expect(os.WriteFile(p, []byte(text), 0o644)).To(Succeed())
	Expect(os.Chmod(p, blockDescriptorMode)).To(Succeed())
}

func (f *blockFixture) writeNode(sb ext4Superblock) {
	Expect(os.WriteFile(f.node, sb.diskBytes(8192), 0o660)).To(Succeed())
}

func (f *blockFixture) request() prepareRequest {
	return prepareRequest{
		Mount: mountRecord{ContainerDir: f.dir, MountID: testBlockMountID, Root: "/", FSType: "tmpfs",
			Source: boshDiskDescriptorSource, SuperOptions: []string{"ro"}},
		Mode: attachBlock,
	}
}

// prepareRefused runs Prepare, expects it to fail, and checks that it closed
// every file it opened.
func (f *blockFixture) prepareRefused(req prepareRequest) error {
	before := openFDs()
	att, err := f.provider.Prepare(req)
	Expect(err).To(HaveOccurred())
	Expect(att).To(BeNil())
	Expect(openFDs()).To(Equal(before), "Prepare left a file open after %v", err)
	return err
}

func (f *blockFixture) what() string {
	return fmt.Sprintf("the BOSH disk device %s (%s) for volume path %q", f.node, testBlockDisk, f.dir)
}

var _ = DescribeTable("parseBlockDescriptor accepts the driver's format",
	func(text string, want blockDescriptor) {
		got, err := parseBlockDescriptor([]byte(text))
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(want))
	},
	Entry("in the driver's order", testDescriptorText(),
		blockDescriptor{Major: 8, Minor: 16, Size: testBlockSize, UUID: testBlockUUID, DiskName: testBlockDisk}),
	Entry("in any order", "disk_name=d\nuuid="+testBlockUUID+"\nsize=1\nminor=0\nmajor=259\nversion=1\n",
		blockDescriptor{Major: 259, Minor: 0, Size: 1, UUID: testBlockUUID, DiskName: "d"}),
	Entry("at the largest numbers", blockDescriptorText(4294967295, 4294967295, 9223372036854775807, testBlockUUID, "a.b_c-D9"),
		blockDescriptor{Major: 4294967295, Minor: 4294967295, Size: 9223372036854775807, UUID: testBlockUUID, DiskName: "a.b_c-D9"}),
)

var _ = DescribeTable("parseBlockDescriptor refuses anything else",
	func(text, msg string) {
		_, err := parseBlockDescriptor([]byte(text))
		Expect(err).To(MatchError(msg))
	},
	Entry("an empty file", "", "descriptor is empty"),
	Entry("a file of the size limit", strings.Repeat("x", 4095)+"\n", "descriptor is 4096 bytes, and it must be shorter than 4096"),
	Entry("invalid UTF-8", "version=1\xff\n", "descriptor is not valid UTF-8"),
	Entry("no final newline", strings.TrimSuffix(testDescriptorText(), "\n"), "descriptor does not end with a newline"),
	Entry("a blank line", "version=1\n\n", "descriptor line 2 has no '='"),
	Entry("a carriage return", strings.Replace(testDescriptorText(), "version=1\n", "version=1\r\n", 1), `descriptor version "1\r" is not supported; vm-launch reads only "1"`),
	Entry("an unknown key", testDescriptorText()+"extra=1\n", `descriptor line 7 has unknown key "extra"`),
	Entry("a key with spaces", strings.Replace(testDescriptorText(), "major=", " major=", 1), `descriptor line 2 has unknown key " major"`),
	Entry("a repeated key", testDescriptorText()+"major=8\n", `descriptor line 7 repeats key "major"`),
	Entry("a missing key", strings.Replace(testDescriptorText(), "disk_name="+testBlockDisk+"\n", "", 1), `descriptor has no "disk_name" line`),
	Entry("another version", strings.Replace(testDescriptorText(), "version=1", "version=2", 1), `descriptor version "2" is not supported; vm-launch reads only "1"`),
	Entry("a signed number", strings.Replace(testDescriptorText(), "major=8", "major=+8", 1), `descriptor major: "+8" is not a decimal number`),
	Entry("a leading zero", strings.Replace(testDescriptorText(), "minor=16", "minor=016", 1), `descriptor minor: "016" has a leading zero`),
	Entry("an empty number", strings.Replace(testDescriptorText(), "minor=16", "minor=", 1), "descriptor minor: empty value"),
	Entry("a trailing space", strings.Replace(testDescriptorText(), "minor=16", "minor=16 ", 1), `descriptor minor: "16 " is not a decimal number`),
	Entry("a major over 32 bits", strings.Replace(testDescriptorText(), "major=8", "major=4294967296", 1), `descriptor major: "4294967296" is out of range`),
	Entry("a size over 63 bits", strings.Replace(testDescriptorText(), "size=4194304", "size=9223372036854775808", 1), `descriptor size: "9223372036854775808" is out of range`),
	Entry("major 0", strings.Replace(testDescriptorText(), "major=8", "major=0", 1), "descriptor major 0 numbers the kernel's anonymous devices, not a block disk"),
	Entry("size 0", strings.Replace(testDescriptorText(), "size=4194304", "size=0", 1), "descriptor size 0 is not a positive byte count"),
	Entry("an upper-case UUID", strings.Replace(testDescriptorText(), testBlockUUID, strings.ToUpper(testBlockUUID), 1), `descriptor uuid "BC20D783-6145-4623-86BB-35110042B24B" is not a lower-case 8-4-4-4-12 UUID`),
	Entry("a UUID without dashes", strings.Replace(testDescriptorText(), testBlockUUID, strings.ReplaceAll(testBlockUUID, "-", ""), 1), `descriptor uuid "bc20d7836145462386bb35110042b24b" is not a lower-case 8-4-4-4-12 UUID`),
	Entry("an empty disk name", strings.Replace(testDescriptorText(), "disk_name="+testBlockDisk, "disk_name=", 1), "descriptor disk_name is empty"),
	Entry("a disk name with a slash", strings.Replace(testDescriptorText(), "disk_name="+testBlockDisk, "disk_name=a/b", 1), `descriptor disk_name "a/b" holds '/', and a disk_name may use only ASCII letters, digits, '.', '_', and '-'`),
	Entry("a disk name with a control character", strings.Replace(testDescriptorText(), "disk_name="+testBlockDisk, "disk_name=a\tb", 1), `descriptor disk_name "a\tb" holds a control character`),
	Entry("a disk name with a bidirectional mark", strings.Replace(testDescriptorText(), "disk_name="+testBlockDisk, "disk_name=a\u202eb", 1), "descriptor disk_name \"a\\u202eb\" holds '\\u202e', and a disk_name may use only ASCII letters, digits, '.', '_', and '-'"),
	Entry("a disk name that starts with a dash", strings.Replace(testDescriptorText(), "disk_name="+testBlockDisk, "disk_name=-rf", 1), `descriptor disk_name "-rf" starts with '-'`),
	Entry("a disk name of two dots", strings.Replace(testDescriptorText(), "disk_name="+testBlockDisk, "disk_name=..", 1), `descriptor disk_name ".." is a directory name`),
)

var _ = Describe("the block provider", func() {
	descriptorLine := func(source, superOptions, root string) string {
		return fmt.Sprintf("50 30 0:50 %s /data rw,nodev,nosuid,noexec,relatime shared:50 - tmpfs %s %s\n", root, source, superOptions)
	}

	It("is registered as BOSH disk, ahead of JuiceFS and NFS in the supported line, with its source and refusal", func() {
		Expect(providerNamesOf(diskProviders)).To(ContainElement("BOSH disk"))
		Expect(blockDescriptorSources).To(Equal([]string{"pdi:bosh-disk"}))
		Expect(diskProviders.supportedLine()).To(Equal("VM backends support only BOSH disk, JuiceFS, and NFS volumes today"))
	})

	It("declares block mode, fenced by an exclusive open, for one instance", func() {
		p := &blockProvider{name: "BOSH disk", source: boshDiskDescriptorSource}
		c := p.Capabilities(mountRecord{})
		Expect(c).To(Equal(capabilities{Modes: []attachMode{attachBlock}, Fence: fenceExclusiveOpen, MaxInstances: 1}))
		Expect(privateMode(c)).To(Equal(attachBlock))
		Expect(checkCapabilities(p, c)).To(Succeed())
	})

	It("refuses a block provider without an exclusive open or without a limit of one instance", func() {
		p := &blockProvider{name: "Raw"}
		Expect(checkCapabilities(p, capabilities{Modes: []attachMode{attachBlock}, Fence: fenceDistributedFlock, MaxInstances: 1})).To(
			MatchError("the Raw volume provider attaches a block device without an exclusive open; VM backends allow one writer per disk"))
		Expect(checkCapabilities(p, capabilities{Modes: []attachMode{attachBlock}, Fence: fenceExclusiveOpen})).To(
			MatchError("the Raw volume provider attaches a block device without limiting it to one instance; VM backends allow one writer per disk"))
		Expect(checkCapabilities(p, capabilities{Modes: []attachMode{attachBlock}, Fence: fenceExclusiveOpen, MaxInstances: 2})).To(
			MatchError("the Raw volume provider attaches a block device without limiting it to one instance; VM backends allow one writer per disk"))
	})

	It("matches only the root of a read-only tmpfs with its source", func() {
		p := &blockProvider{name: "BOSH disk", source: boshDiskDescriptorSource}
		good := mountRecord{FSType: "tmpfs", Source: "pdi:bosh-disk", Root: "/", SuperOptions: []string{"ro", "size=16k", "mode=755"}}
		Expect(p.Match(good)).To(Equal(strongMatch))
		for name, m := range map[string]mountRecord{
			"a writable tmpfs":   {FSType: "tmpfs", Source: "pdi:bosh-disk", Root: "/", SuperOptions: []string{"rw"}},
			"another source":     {FSType: "tmpfs", Source: "pdi:other", Root: "/", SuperOptions: []string{"ro"}},
			"a subdirectory":     {FSType: "tmpfs", Source: "pdi:bosh-disk", Root: "/sub", SuperOptions: []string{"ro"}},
			"a FUSE filesystem":  {FSType: "fuse.juicefs", Source: "pdi:bosh-disk", Root: "/", SuperOptions: []string{"ro"}},
			"a source in caps":   {FSType: "tmpfs", Source: "PDI:BOSH-DISK", Root: "/", SuperOptions: []string{"ro"}},
			"an option like ro":  {FSType: "tmpfs", Source: "pdi:bosh-disk", Root: "/", SuperOptions: []string{"rw", "nro"}},
			"no super options":   {FSType: "tmpfs", Source: "pdi:bosh-disk", Root: "/"},
			"an empty fs record": {},
		} {
			Expect(p.Match(m)).To(Equal(noMatch), name)
		}
	})

	It("selects the BOSH disk provider for the driver's read-only descriptor tmpfs", func() {
		p, m, err := findIn(writeTempFile("mountinfo", descriptorLine("pdi:bosh-disk", "ro,size=16k,mode=755", "/")), "/data")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Name()).To(Equal("BOSH disk"))
		Expect(m.Source).To(Equal("pdi:bosh-disk"))
	})

	DescribeTable("refuses a descriptor tmpfs it must not trust, in its own words, before any provider",
		func(line, msg string) {
			_, m, err := findIn(writeTempFile("mountinfo", line), "/data")
			Expect(m).To(Equal(mountRecord{}))
			Expect(err).To(MatchError(msg))
		},
		Entry("a writable superblock", descriptorLine("pdi:bosh-disk", "rw,size=16k", "/"),
			`volume path "/data" is a block-mode descriptor tmpfs from "pdi:bosh-disk" whose filesystem is writable; vm-launch reads a descriptor only from a read-only tmpfs`),
		Entry("a subdirectory of the tmpfs", descriptorLine("pdi:bosh-disk", "ro", "/sub"),
			`volume path "/data" shows "/sub" of the block-mode descriptor tmpfs from "pdi:bosh-disk", not its root`),
		Entry("a source no provider reads", descriptorLine("pdi:ebs", "ro", "/"),
			`volume path "/data" is a block-mode descriptor from "pdi:ebs", which no block provider in vm-launch reads; VM backends support only BOSH disk, JuiceFS, and NFS volumes today`),
	)

	It("leaves a mount of another filesystem with a block-mode source to the providers", func() {
		Expect(refuseBlockDescriptorMount(mountRecord{FSType: "fuse.juicefs", Source: "pdi:bosh-disk", Root: "/", SuperOptions: []string{"rw"}})).To(Succeed())
		Expect(refuseBlockDescriptorMount(mountRecord{FSType: "tmpfs", Source: "tmpfs", Root: "/", SuperOptions: []string{"rw"}})).To(Succeed())
		_, _, err := findIn(writeTempFile("mountinfo", "50 30 0:50 / /data rw shared:50 - ext4 pdi:bosh-disk ro\n"), "/data")
		Expect(err).To(MatchError(`volume path "/data" is a "ext4" mount; VM backends support only BOSH disk, JuiceFS, and NFS volumes today`))
	})

	It("quotes and bounds the values it names", func() {
		err := refuseBlockDescriptorMount(mountRecord{ContainerDir: "/da\nta", FSType: "tmpfs", Source: "pdi:\x1b[31m" + strings.Repeat("x", 4*maxLoggedValueLen), Root: "/", SuperOptions: []string{"ro"}})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).NotTo(ContainSubstring("\n"))
		Expect(err.Error()).NotTo(ContainSubstring("\x1b"))
		Expect(len(err.Error())).To(BeNumerically("<", 3*maxLoggedValueLen+400))
	})

	Describe("Prepare", func() {
		var f *blockFixture

		BeforeEach(func() { f = newBlockFixture() })

		It("opens the node read-write and exclusively, after an O_PATH look, and returns it in block mode", func() {
			var looked *os.File
			req := f.request()
			req.BeforeLock = func(disk *os.File) error {
				looked = disk
				_, err := unix.FcntlInt(disk.Fd(), unix.F_GETFL, 0)
				Expect(err).NotTo(HaveOccurred())
				return nil
			}
			att, err := f.provider.Prepare(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(att.Mode).To(Equal(attachBlock))
			Expect(att.File.Name()).To(Equal(f.node))
			Expect(looked).NotTo(BeNil())
			Expect(looked.Name()).To(Equal(f.node))
			Expect(f.host.opens).To(Equal([]int{
				unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
				unix.O_RDWR | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW,
			}))
			flags, err := unix.FcntlInt(att.File.Fd(), unix.F_GETFL, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(flags & unix.O_ACCMODE).To(Equal(unix.O_RDWR))
			Expect(att.Release()).To(Succeed())
		})

		It("accepts a descriptor that root owns, as the driver writes it, when vm-launch is not root", func() {
			saved := euid
			DeferCleanup(func() { euid = saved })
			euid = func() int { return 1000 }
			f.host.descUID = 0
			att, err := f.provider.Prepare(f.request())
			Expect(err).NotTo(HaveOccurred())
			Expect(att.Release()).To(Succeed())
		})

		It("refuses any mode but block mode, without opening anything", func() {
			req := f.request()
			req.Mode = attachFileImage
			Expect(f.prepareRefused(req)).To(MatchError("the BOSH disk volume provider attaches only in block mode, not in file-image mode"))
			Expect(f.host.opens).To(BeEmpty())
		})

		It("refuses an instance after the first, since the volume service attaches the disk to one VM", func() {
			req := f.request()
			req.Index = 2
			err := f.prepareRefused(req)
			Expect(err).To(MatchError(ContainSubstring(fmt.Sprintf("volume path %q is a BOSH disk in block mode, which the volume service attaches to one VM at a time, so only instance 0 can use it, and this is instance 2", f.dir))))
			Expect(f.host.opens).To(BeEmpty())
		})

		It("refuses a mount it does not own", func() {
			req := f.request()
			req.Mount.SuperOptions = []string{"rw"}
			Expect(f.prepareRefused(req)).To(MatchError(fmt.Sprintf(`the BOSH disk volume provider does not own the "tmpfs" mount at volume path %q`, f.dir)))
		})

		It("refuses a directory that is no longer the mount detection inspected", func() {
			dirProbe = func(int, string) (mountProbe, error) { return mountProbe{MountID: 51, MountRoot: true}, nil }
			err := f.prepareRefused(f.request())
			Expect(errors.Is(err, errMountChanged)).To(BeTrue())
			Expect(err).To(MatchError(fmt.Sprintf("the mount of volume %q changed during start: it was mount ID 50 when vm-launch inspected it and is mount ID 51 now", f.dir)))
			Expect(f.host.opens).To(BeEmpty())
		})

		It("refuses a directory that is not the root of its mount, and one it cannot check", func() {
			dirProbe = func(int, string) (mountProbe, error) { return mountProbe{MountID: testBlockMountID}, nil }
			Expect(errors.Is(f.prepareRefused(f.request()), errNotMountRoot)).To(BeTrue())
			dirProbe = func(int, string) (mountProbe, error) { return mountProbe{}, errors.New("no statx") }
			Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("checking the mount of volume %q: no statx", f.dir)))
		})

		It("refuses a volume directory that is a symbolic link", func() {
			link := filepath.Join(GinkgoT().TempDir(), "link")
			Expect(os.Symlink(f.dir, link)).To(Succeed())
			req := f.request()
			req.Mount.ContainerDir = link
			Expect(f.prepareRefused(req)).To(MatchError(ContainSubstring(fmt.Sprintf("opening volume %q: ", link))))
		})

		Describe("the descriptor file", func() {
			descriptor := func() string { return filepath.Join(f.dir, blockDescriptorFileName) }

			It("is refused when it is missing", func() {
				Expect(os.Remove(descriptor())).To(Succeed())
				Expect(f.prepareRefused(f.request())).To(MatchError(ContainSubstring(fmt.Sprintf("opening the block-mode descriptor %q: no such file or directory", descriptor()))))
			})

			It("is refused when it is a symbolic link, even to a good descriptor", func() {
				good := filepath.Join(f.dir, "good")
				Expect(os.Rename(descriptor(), good)).To(Succeed())
				Expect(os.Symlink(good, descriptor())).To(Succeed())
				Expect(f.prepareRefused(f.request())).To(MatchError(ContainSubstring(fmt.Sprintf("opening the block-mode descriptor %q: ", descriptor()))))
			})

			It("is refused when it is a FIFO, without waiting for a writer", func() {
				Expect(os.Remove(descriptor())).To(Succeed())
				Expect(unix.Mkfifo(descriptor(), 0o444)).To(Succeed())
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("the block-mode descriptor %q is a FIFO, not a regular file", descriptor())))
			})

			It("is refused when it is a directory", func() {
				Expect(os.Remove(descriptor())).To(Succeed())
				Expect(os.Mkdir(descriptor(), 0o555)).To(Succeed())
				Expect(f.prepareRefused(f.request())).To(MatchError(ContainSubstring(fmt.Sprintf("the block-mode descriptor %q is a directory, not a regular file", descriptor()))))
			})

			It("is refused without the driver's mode", func() {
				Expect(os.Chmod(descriptor(), 0o644)).To(Succeed())
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("the block-mode descriptor %q has mode 0644, and the volume driver writes it with mode 0444", descriptor())))
			})

			It("is refused when vm-launch's own user owns it, unless that user is root", func() {
				saved := euid
				DeferCleanup(func() { euid = saved })
				euid = func() int { return 1000 }
				f.host.descUID = 1000
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("the block-mode descriptor %q is owned by vm-launch's own uid 1000, so it may not be the volume driver's", descriptor())))

				euid = func() int { return 0 }
				f.host.descUID = 0
				att, err := f.provider.Prepare(f.request())
				Expect(err).NotTo(HaveOccurred())
				Expect(att.Release()).To(Succeed())
			})

			It("is refused when it is empty or as long as the limit", func() {
				f.writeDescriptor("")
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("the block-mode descriptor %q is 0 bytes, and a descriptor is 1 to 4095 bytes", descriptor())))
				f.writeDescriptor(strings.Repeat("x", blockDescriptorSizeLimit))
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("the block-mode descriptor %q is 4096 bytes, and a descriptor is 1 to 4095 bytes", descriptor())))
			})

			It("is refused when it is malformed, naming the problem", func() {
				f.writeDescriptor(strings.Replace(testDescriptorText(), "version=1", "version=2", 1))
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf(`the block-mode descriptor %q is malformed: descriptor version "2" is not supported; vm-launch reads only "1"`, descriptor())))
			})
		})

		Describe("the device node", func() {
			It("is refused when Garden made no node, naming the cell setting", func() {
				Expect(os.Remove(f.node)).To(Succeed())
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("opening %s: the container has no such node; Garden makes it only when the cell runs Garden with --vm-block-volumes", f.what())))
			})

			It("is refused when it is a symbolic link", func() {
				Expect(os.Rename(f.node, f.node+".real")).To(Succeed())
				Expect(os.Symlink(f.node+".real", f.node)).To(Succeed())
				Expect(f.prepareRefused(f.request())).To(MatchError(HavePrefix(fmt.Sprintf("opening %s: ", f.what()))))
			})

			DescribeTable("says why the exclusive open failed",
				func(errno syscall.Errno, msg string) {
					f.host.openErr = func(_ string, flags int) error {
						if flags&unix.O_EXCL != 0 {
							return errno
						}
						return nil
					}
					err := f.prepareRefused(f.request())
					Expect(err).To(MatchError(fmt.Sprintf(msg, f.what())))
					Expect(errors.Is(err, errno)).To(BeTrue())
					Expect(errors.Is(err, errBlockDeviceBusy)).To(Equal(errno == unix.EBUSY))
				},
				Entry("mounted or held", unix.EBUSY, "%s is busy: the cell has it mounted, or another process holds it open exclusively, so vm-launch will not attach it; a block device takes one writer"),
				Entry("not in the kvm group", unix.EACCES, "opening %s: permission denied; Garden makes the node root:kvm with mode 0660, and vm-launch needs the kvm group"),
				Entry("not in the device cgroup", unix.EPERM, "opening %s: operation not permitted; the container's device cgroup does not allow the device"),
				Entry("detached", unix.ENXIO, "opening %s: no such device or address; the disk is no longer attached to the cell"),
				Entry("gone", unix.ENODEV, "opening %s: no such device; the disk is no longer attached to the cell"),
				Entry("another error", unix.EIO, "opening %s: input/output error"),
			)

			It("hands BeforeLock the node before the exclusive open, and returns its error with nothing open", func() {
				req := f.request()
				req.BeforeLock = func(*os.File) error { return errors.New("held by an earlier volume") }
				Expect(f.prepareRefused(req)).To(MatchError("held by an earlier volume"))
				Expect(f.host.opens).To(HaveLen(1))
			})

			It("is refused when it is not a block device", func() {
				f.host.nodeType = unix.S_IFCHR
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("%s is not a block device (file type character device); Garden makes the node a block device", f.what())))
				Expect(f.host.opens).To(HaveLen(1))
			})

			It("is refused when it is another device number than the descriptor's", func() {
				f.host.rdev = unix.Mkdev(7, 3)
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("%s is device 7:3, and its descriptor names device 8:16", f.what())))
			})

			It("is refused when the exclusive open reaches another inode", func() {
				f.host.replace = true
				Expect(f.prepareRefused(f.request())).To(MatchError(ContainSubstring(fmt.Sprintf("%s was replaced while vm-launch opened it", f.what()))))
			})
		})

		Describe("the device", func() {
			It("is refused when its size differs from the descriptor's", func() {
				f.host.size = testBlockSize + 512
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("%s is 4194816 bytes, and its descriptor promises 4194304; vm-launch refuses a device whose size differs from its descriptor's", f.what())))
			})

			It("is refused when its size cannot be read", func() {
				f.host.sizeErr = errors.New("BLKGETSIZE64: inappropriate ioctl for device")
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("reading the size of %s: BLKGETSIZE64: inappropriate ioctl for device", f.what())))
			})

			It("is refused when its size is not whole sectors, even when the descriptor agrees", func() {
				f.writeDescriptor(blockDescriptorText(testBlockMajor, testBlockMinor, testBlockSize+1, testBlockUUID, testBlockDisk))
				f.host.size = testBlockSize + 1
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("%s: the device's size of 4194305 bytes is not a whole number of 512-byte sectors", f.what())))
			})

			DescribeTable("is refused unless its superblock is the descriptor's journaled ext4",
				func(edit func(*ext4Superblock), msg string) {
					sb := goodSuperblock()
					edit(&sb)
					f.writeNode(sb)
					Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf(msg, f.what())))
				},
				Entry("no ext4 magic", func(sb *ext4Superblock) { sb.magic = 0x1234 },
					"%s holds no ext4 filesystem (superblock magic 0x1234, not 0xef53); the volume driver formats the disk before it hands it over, and the guest never formats a block device"),
				Entry("an external journal device", func(sb *ext4Superblock) { sb.incompat = ext4IncompatJournalDev },
					"%s is an external ext4 journal device, not a filesystem"),
				Entry("another UUID", func(sb *ext4Superblock) { sb.uuid = "00000000-1111-2222-3333-444444444444" },
					"%s holds the ext4 filesystem 00000000-1111-2222-3333-444444444444, and its descriptor names "+testBlockUUID+"; the device number may now belong to another disk, so vm-launch refuses it"),
				Entry("no journal", func(sb *ext4Superblock) { sb.compat = 0 },
					"%s holds an ext4 filesystem without a journal; the volume driver formats a block-mode disk with one"),
				Entry("a journal on another device", func(sb *ext4Superblock) { sb.journalInum = 0 },
					"%s keeps its ext4 journal on another device, which the guest does not have"),
			)

			It("is refused when it ends before the superblock does", func() {
				Expect(os.Truncate(f.node, ext4SuperblockOffset+100)).To(Succeed())
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("reading the ext4 superblock of %s: the device ends at byte 1124", f.what())))
			})
		})
	})

	It("formats a UUID in lower-case 8-4-4-4-12 form", func() {
		b, err := hex.DecodeString("bc20d7836145462386bb35110042b24b")
		Expect(err).NotTo(HaveOccurred())
		Expect(formatUUID(b)).To(Equal(testBlockUUID))
	})

	It("refuses a block device size the guest could not use", func() {
		_, err := checkBlockSize(0)
		Expect(err).To(MatchError("the device has no size"))
		_, err = checkBlockSize(1 << 63)
		Expect(err).To(MatchError("the device's size of 9223372036854775808 bytes does not fit in 63 bits"))
		_, err = checkBlockSize(1000)
		Expect(err).To(MatchError("the device's size of 1000 bytes is not a whole number of 512-byte sectors"))
		Expect(checkBlockSize(1 << 30)).To(Equal(int64(1 << 30)))
	})

	It("reads no size from a file that is not a block device", func() {
		f, err := os.Open(os.DevNull)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		_, err = blockDeviceBytes(f)
		Expect(err).To(MatchError(ContainSubstring("BLKGETSIZE64: ")))
	})
})

var _ = Describe("block drives in the hypervisor arguments", func() {
	task := &network{}
	blockDrive := volumeDrive{path: volumeDrivePath(0), id: qemuVolumeSerial(0), mode: attachBlock}

	It("gives QEMU a block device through host_device with cache=none, and keeps the serial", func() {
		argv, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", goldenVolumeInitrd, goldenMemMiB, task, []volumeDrive{blockDrive}, "", 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal(concat(withInitrd(goldenQEMUBase, goldenVolumeInitrd), goldenQEMUTaskNetdev, []string{
			"-drive", "if=none,id=vol0,format=raw,file.driver=host_device,file.filename=/proc/self/fd/3,cache=none,aio=threads,file.locking=off,werror=report,rerror=report,discard=ignore",
			"-device", "virtio-blk-device,drive=vol0,serial=rvm-vol0",
		})))
	})

	It("gives Firecracker a block device the same drive an image gets", func() {
		Expect(fcConfigJSON(goldenVolumeInitrd, goldenMemMiB, task, []volumeDrive{blockDrive}, "")).To(Equal(fcConfigJSON(goldenVolumeInitrd, goldenMemMiB, task, drivePathsFor(1), "")))
	})

	It("mixes block and image drives in volume order", func() {
		drives := []volumeDrive{drivePathsFor(1)[0], {path: volumeDrivePath(1), id: qemuVolumeSerial(1), mode: attachBlock}}
		argv := qemuArgv(goldenArt, procSelfFD(5), goldenMemMiB, task, drives, 0)
		Expect(optionAfter(argv, "-drive", "id=vol0")).To(ContainSubstring(",file=/proc/self/fd/3,format=raw,cache=writeback,"))
		Expect(optionAfter(argv, "-drive", "id=vol1")).To(ContainSubstring(",file.driver=host_device,file.filename=/proc/self/fd/4,cache=none,"))
	})

	It("takes each drive's path, identity, and mode from its attachment", func() {
		img, err := os.Open(os.DevNull)
		Expect(err).NotTo(HaveOccurred())
		defer img.Close()
		files, drives, _, _, _ := hypervisorFiles([]*attachment{{File: img, Mode: attachBlock, ID: "12345"}}, img, nil, nil)
		Expect(files).To(HaveLen(2))
		Expect(drives).To(Equal([]volumeDrive{{path: "/proc/self/fd/3", id: "12345", mode: attachBlock}}))
	})

	It("refuses a drive in neither mode, and on QEMU a drive whose identity cannot be a serial", func() {
		for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			_, err := hypervisorArgv(kind, goldenArt, GinkgoT().TempDir(), goldenVolumeInitrd, goldenMemMiB, task, []volumeDrive{{path: volumeDrivePath(0), id: "rvm-vol0"}}, "", 0)
			Expect(err).To(MatchError(ContainSubstring("volume drive vol0 is in ")), string(kind))
		}
		_, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", goldenVolumeInitrd, goldenMemMiB, task, []volumeDrive{{path: volumeDrivePath(0), id: "a,b", mode: attachBlock}}, "", 0)
		Expect(err).To(MatchError(`volume drive vol0 has the identity "a,b", which is not 1 to 20 letters, digits, and hyphens, so QEMU cannot pass it as the drive's serial`))
		_, err = hypervisorArgv(backend.VMQemu, goldenArt, "/unused", goldenVolumeInitrd, goldenMemMiB, task, []volumeDrive{{path: volumeDrivePath(0), mode: attachBlock}}, "", 0)
		Expect(err).To(MatchError(ContainSubstring(`volume drive vol0 has the identity ""`)))
	})

	It("gives a block attachment the block drive kind and puts the identity on the attachment", func() {
		img := openSizedFile(1 << 20)
		pv := preparedVolumes{{Path: "/data", Attachment: &attachment{File: img, Mode: attachBlock, Release: func() error { return nil }}, Bytes: 1 << 20}}
		drives, err := newGuestDrives(backend.VMQemu, pv, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(drives.volumes).To(Equal([]guestDrive{{id: "rvm-vol0", kind: driveBlock, bytes: 1 << 20}}))
		Expect(pv[0].Attachment.ID).To(Equal("rvm-vol0"))
		disks, err := disksFile(guestContents{vol: &guestVolume{ContainerDir: "/data"}, drives: drives})
		Expect(err).NotTo(HaveOccurred())
		Expect(disks).To(ContainSubstring("RVM_VOL0_KIND=block\n"))
	})
})

// loopDevicesEnv turns on the specs that attach loop devices, which need root
// in a privileged container with e2fsprogs.
const loopDevicesEnv = "VM_LAUNCH_TEST_LOOP_DEVICES"

// loopDisk is an ext4 filesystem on a loop device over a sparse file, with a
// device node for it in a directory of its own, as Garden makes it.
type loopDisk struct {
	dev          string
	major, minor uint32
	uuid         string
	size         int64
	nodeDir      string
	node         string
}

// requireLoopDevices skips the spec unless loop device specs are on and
// possible here.
func requireLoopDevices() {
	if os.Getenv(loopDevicesEnv) != "1" {
		Skip("set " + loopDevicesEnv + "=1 as root in a privileged container to run the loop device specs")
	}
	if os.Geteuid() != 0 {
		Skip("loop devices need root")
	}
	for _, tool := range []string{"losetup", "mkfs.ext4", "mount", "umount"} {
		if _, err := exec.LookPath(tool); err != nil {
			Skip(tool + " is not installed")
		}
	}
	requireOpenat2()
}

func runTool(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "%s %v: %s", name, args, out)
	return strings.TrimSpace(string(out))
}

// newLoopDisk formats a sparse file of size bytes with mkfs options and a
// UUID of its own, attaches it to a free loop device, which the spec's
// cleanup detaches, and makes the device node nodeDir/MAJOR-MINOR. The UUID
// is chosen here rather than read back with blkid, because blkid's cache
// keeps the UUID of the last filesystem it saw on a reused loop device.
func newLoopDisk(size int64, mkfsArgs ...string) *loopDisk {
	backing := filepath.Join(GinkgoT().TempDir(), "disk.img")
	Expect(os.WriteFile(backing, nil, 0o600)).To(Succeed())
	Expect(os.Truncate(backing, size)).To(Succeed())
	raw := make([]byte, 16)
	_, err := rand.Read(raw)
	Expect(err).NotTo(HaveOccurred())
	raw[6], raw[8] = raw[6]&0x0f|0x40, raw[8]&0x3f|0x80
	uuid := formatUUID(raw)
	runTool("mkfs.ext4", append(append([]string{"-q", "-F", "-U", uuid}, mkfsArgs...), backing)...)
	dev := runTool("losetup", "--find", "--show", backing)
	DeferCleanup(func() { runTool("losetup", "--detach", dev) })
	var st unix.Stat_t
	Expect(unix.Stat(dev, &st)).To(Succeed())
	d := &loopDisk{dev: dev, major: unix.Major(st.Rdev), minor: unix.Minor(st.Rdev), uuid: uuid, size: size, nodeDir: GinkgoT().TempDir()}
	d.node = filepath.Join(d.nodeDir, fmt.Sprintf("%d-%d", d.major, d.minor))
	Expect(unix.Mknod(d.node, unix.S_IFBLK|0o660, int(st.Rdev))).To(Succeed())
	return d
}

// descriptorMount mounts a tmpfs with the driver's source and options at a
// new directory, writes text as its descriptor with the driver's mode, and
// remounts it read-only, as the driver does. The spec's cleanup unmounts it.
func descriptorMount(text string) string {
	dir := GinkgoT().TempDir()
	runTool("mount", "-t", "tmpfs", "-o", "size=16k,mode=0755,nodev,nosuid,noexec", boshDiskDescriptorSource, dir)
	DeferCleanup(func() { runTool("umount", dir) })
	Expect(os.WriteFile(filepath.Join(dir, blockDescriptorFileName), []byte(text), blockDescriptorMode)).To(Succeed())
	Expect(os.Chmod(filepath.Join(dir, blockDescriptorFileName), blockDescriptorMode)).To(Succeed())
	runTool("mount", "-o", "remount,ro", dir)
	return dir
}

var _ = Describe("the block provider on a loop device", func() {
	var disk *loopDisk

	BeforeEach(func() {
		requireLoopDevices()
		volumeProbe, dirProbe = probeVolume, probeMountFD
		disk = newLoopDisk(64 << 20)
	})

	descriptorFor := func(d *loopDisk) string {
		return blockDescriptorText(d.major, d.minor, d.size, d.uuid, testBlockDisk)
	}
	providerFor := func(d *loopDisk) *blockProvider {
		return &blockProvider{name: "BOSH disk", source: boshDiskDescriptorSource, nodeDir: d.nodeDir, host: linuxBlockHost{}}
	}
	// prepareAt finds the provider of the descriptor at dir through the
	// kernel's mount table, as vm-launch does, and prepares the disk with the
	// provider for d.
	prepareAt := func(d *loopDisk, dir string) (*attachment, error) {
		p, m, err := findVolumeProvider("/proc/self/mountinfo", dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Name()).To(Equal("BOSH disk"))
		return providerFor(d).Prepare(prepareRequest{Mount: m, Mode: attachBlock})
	}
	what := func(d *loopDisk, dir string) string {
		return fmt.Sprintf("the BOSH disk device %s (%s) for volume path %q", d.node, testBlockDisk, dir)
	}

	It("attaches the device exclusively, and a mount of it fails while vm-launch holds it", func() {
		dir := descriptorMount(descriptorFor(disk))
		att, err := prepareAt(disk, dir)
		Expect(err).NotTo(HaveOccurred())
		released := false
		DeferCleanup(func() {
			if !released {
				Expect(att.Release()).To(Succeed())
			}
		})
		Expect(att.Mode).To(Equal(attachBlock))
		Expect(blockDeviceBytes(att.File)).To(Equal(disk.size))

		mnt := GinkgoT().TempDir()
		out, err := exec.Command("mount", "-t", "ext4", disk.dev, mnt).CombinedOutput()
		if err == nil {
			runTool("umount", mnt)
		}
		Expect(err).To(HaveOccurred(), "the cell mounted the disk vm-launch holds: %s", out)

		Expect(att.Release()).To(Succeed())
		released = true
		runTool("mount", "-t", "ext4", disk.dev, mnt)
		runTool("umount", mnt)
	})

	It("refuses the device while the cell has it mounted", func() {
		dir := descriptorMount(descriptorFor(disk))
		mnt := GinkgoT().TempDir()
		runTool("mount", "-t", "ext4", disk.dev, mnt)
		DeferCleanup(func() { runTool("umount", mnt) })
		_, err := prepareAt(disk, dir)
		Expect(errors.Is(err, errBlockDeviceBusy)).To(BeTrue(), "%v", err)
		Expect(errors.Is(err, unix.EBUSY)).To(BeTrue())
		Expect(err).To(MatchError(HavePrefix(what(disk, dir) + " is busy")))
	})

	It("refuses the device while another process holds it open exclusively", func() {
		dir := descriptorMount(descriptorFor(disk))
		holder, err := unix.Open(disk.dev, unix.O_RDONLY|unix.O_EXCL|unix.O_CLOEXEC, 0)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { unix.Close(holder) })
		_, err = prepareAt(disk, dir)
		Expect(errors.Is(err, errBlockDeviceBusy)).To(BeTrue(), "%v", err)
	})

	It("refuses a node whose device is not the descriptor's", func() {
		other := newLoopDisk(64 << 20)
		// The node has the descriptor's name and the other disk's number.
		Expect(os.Remove(disk.node)).To(Succeed())
		Expect(unix.Mknod(disk.node, unix.S_IFBLK|0o660, int(unix.Mkdev(other.major, other.minor)))).To(Succeed())
		dir := descriptorMount(descriptorFor(disk))
		_, err := prepareAt(disk, dir)
		Expect(err).To(MatchError(fmt.Sprintf("%s is device %d:%d, and its descriptor names device %d:%d", what(disk, dir), other.major, other.minor, disk.major, disk.minor)))
	})

	It("refuses a device whose size is not the descriptor's", func() {
		dir := descriptorMount(blockDescriptorText(disk.major, disk.minor, disk.size*2, disk.uuid, testBlockDisk))
		_, err := prepareAt(disk, dir)
		Expect(err).To(MatchError(fmt.Sprintf("%s is %d bytes, and its descriptor promises %d; vm-launch refuses a device whose size differs from its descriptor's", what(disk, dir), disk.size, disk.size*2)))
	})

	It("refuses a device whose filesystem is not the descriptor's", func() {
		dir := descriptorMount(blockDescriptorText(disk.major, disk.minor, disk.size, "00000000-1111-2222-3333-444444444444", testBlockDisk))
		_, err := prepareAt(disk, dir)
		Expect(err).To(MatchError(ContainSubstring(fmt.Sprintf("%s holds the ext4 filesystem %s, and its descriptor names 00000000-1111-2222-3333-444444444444", what(disk, dir), disk.uuid))))
	})

	It("refuses an ext4 filesystem without a journal", func() {
		bare := newLoopDisk(64<<20, "-O", "^has_journal")
		dir := descriptorMount(descriptorFor(bare))
		_, err := prepareAt(bare, dir)
		Expect(err).To(MatchError(what(bare, dir) + " holds an ext4 filesystem without a journal; the volume driver formats a block-mode disk with one"))
	})

	It("predicts the Firecracker drive identity from the node's own numbers", func() {
		dir := descriptorMount(descriptorFor(disk))
		att, err := prepareAt(disk, dir)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(att.Release)
		var st syscall.Stat_t
		Expect(syscall.Stat(disk.node, &st)).To(Succeed())
		want := statID(&st)
		if len(want) > virtioBlockIDBytes {
			want = want[:virtioBlockIDBytes]
		}
		drives, err := newGuestDrives(backend.VMFirecracker, preparedVolumes{{Path: dir, Attachment: att, Bytes: disk.size}}, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(drives.volumes).To(Equal([]guestDrive{{id: want, kind: driveBlock, bytes: disk.size}}))
		Expect(att.ID).To(Equal(want))
		Expect(uint64(st.Rdev)).To(Equal(unix.Mkdev(disk.major, disk.minor)))
	})

	It("prepares the volume in block mode through the launch's prepare, with the device's own size", func() {
		dir := descriptorMount(descriptorFor(disk))
		p, m, err := findVolumeProvider("/proc/self/mountinfo", dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Name()).To(Equal("BOSH disk"))
		bp := p.(*blockProvider)
		saved := bp.nodeDir
		DeferCleanup(func() { bp.nodeDir = saved })
		bp.nodeDir = disk.nodeDir

		var pv preparedVolumes
		DeferCleanup(func() { pv.release(log.New(io.Discard, "", 0)) })
		leftover, err := pv.prepare(selectedVolume{Volume: guestVolume{ContainerDir: dir, Index: 0}, Provider: p, Mount: m}, nil, nil, log.New(io.Discard, "", 0))
		Expect(err).NotTo(HaveOccurred())
		Expect(leftover).To(BeNil())
		Expect(pv).To(HaveLen(1))
		Expect(pv[0].Bytes).To(Equal(disk.size))
		Expect(pv[0].Attachment.Mode).To(Equal(attachBlock))

		_, err = pv.prepare(selectedVolume{Volume: guestVolume{ContainerDir: dir, Index: 0}, Provider: p, Mount: m}, nil, nil, log.New(io.Discard, "", 0))
		Expect(err).To(MatchError(fmt.Sprintf("volume paths %q and %q reach the same disk image; bind each volume to a directory of its own", dir, dir)))

		drives, err := newGuestDrives(backend.VMQemu, pv, nil)
		Expect(err).NotTo(HaveOccurred())
		_, hv, _, _, _ := hypervisorFiles(pv.files(), pv[0].Attachment.File, nil, nil)
		Expect(hv).To(Equal([]volumeDrive{{path: "/proc/self/fd/3", id: drives.volumes[0].id, mode: attachBlock}}))
	})
})
