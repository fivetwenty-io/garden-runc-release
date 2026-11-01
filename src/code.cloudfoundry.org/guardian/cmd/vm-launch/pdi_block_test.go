//go:build linux

package main

import (
	"bytes"
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
	"time"

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
	// testBlockDiskseq is the fake disk's sequence number, which Garden
	// records in the fake specs' environment.
	testBlockDiskseq = 42
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
	magic        uint16
	compat       uint32
	incompat     uint32
	uuid         string
	journalInum  uint32
	logBlockSize uint32
	blocksLo     uint32
	blocksHi     uint32
}

// goodSuperblock is the superblock of an ext4 filesystem with an internal
// journal and the specs' UUID, of 4096-byte blocks that fill the specs' disk.
func goodSuperblock() ext4Superblock {
	return ext4Superblock{magic: ext4Magic, compat: ext4CompatHasJournal, uuid: testBlockUUID, journalInum: 8,
		logBlockSize: 2, blocksLo: testBlockSize / 4096}
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
	le.PutUint32(raw[ext4LogBlockSizeOffset:], sb.logBlockSize)
	le.PutUint32(raw[ext4BlocksCountLoOffset:], sb.blocksLo)
	le.PutUint32(raw[ext4BlocksCountHiOffset:], sb.blocksHi)
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
	seq      uint64
	seqErr   error
	// direct holds each file descriptor setDirect was asked about, and
	// directErr, when set, is its answer. The fake sets no flag, because
	// the nodes are regular files on a filesystem that may refuse O_DIRECT.
	direct    []int
	directErr error
	// openErr, when set, answers an open before the file is opened.
	openErr func(path string, flags int) error
	// replace makes the exclusive open report another inode.
	replace bool
	// nodes holds every node file descriptor it opened, with the inode it
	// opened, so that a later file the kernel gives the same number, after
	// the provider closed the node, is not taken for the node.
	nodes map[int]fakeNodeFD
	opens []int
}

// fakeNodeFD is a node file descriptor the fake host opened.
type fakeNodeFD struct {
	flags    int
	dev, ino uint64
}

func newFakeBlockHost() *fakeBlockHost {
	return &fakeBlockHost{
		rdev:     unix.Mkdev(testBlockMajor, testBlockMinor),
		nodeType: unix.S_IFBLK,
		descUID:  overflowUID,
		size:     testBlockSize,
		seq:      testBlockDiskseq,
		nodes:    map[int]fakeNodeFD{},
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
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, err
	}
	h.nodes[fd] = fakeNodeFD{flags: flags, dev: st.Dev, ino: st.Ino}
	return fd, nil
}

func (h *fakeBlockHost) fstat(fd int, st *unix.Stat_t) error {
	if err := unix.Fstat(fd, st); err != nil {
		return err
	}
	node, ok := h.nodes[fd]
	if ok && (node.dev != st.Dev || node.ino != st.Ino) {
		// The node was closed, and fd now names another file.
		delete(h.nodes, fd)
		ok = false
	}
	if !ok {
		st.Uid = h.descUID
		return nil
	}
	st.Mode = h.nodeType | 0o660
	st.Rdev = h.rdev
	if h.replace && node.flags&unix.O_EXCL != 0 {
		st.Ino++
	}
	return nil
}

// busyFor makes the first n exclusive opens fail with EBUSY, as they do while
// another process holds the device, and counts the exclusive opens.
func (h *fakeBlockHost) busyFor(n int) *int {
	tries := new(int)
	h.openErr = func(_ string, flags int) error {
		if flags&unix.O_EXCL == 0 {
			return nil
		}
		*tries++
		if *tries <= n {
			return unix.EBUSY
		}
		return nil
	}
	return tries
}

func (h *fakeBlockHost) deviceBytes(int) (uint64, error) {
	return h.size, h.sizeErr
}

func (h *fakeBlockHost) diskSeq(int) (uint64, error) {
	return h.seq, h.seqErr
}

func (h *fakeBlockHost) setDirect(fd int) error {
	h.direct = append(h.direct, fd)
	return h.directErr
}

// setDiskseqTable makes gardenDiskseq read a mount table with lines until the
// spec ends.
func setDiskseqTable(lines ...string) {
	path := filepath.Join(GinkgoT().TempDir(), "mountinfo")
	table := "22 1 0:21 / / rw,relatime - overlay overlay rw\n"
	for _, line := range lines {
		table += line + "\n"
	}
	Expect(os.WriteFile(path, []byte(table), 0o644)).To(Succeed())
	saved := diskseqMountInfo
	DeferCleanup(func() { diskseqMountInfo = saved })
	diskseqMountInfo = path
}

// diskseqLine is a mount table line for a record tmpfs with source
// gardenDiskseqSource followed by entries, as Garden mounts it.
func diskseqLine(id int, entries string) string {
	return fmt.Sprintf("%d 22 0:%d / /opt/garden-vm/pdi-diskseq ro,nosuid,nodev,noexec - tmpfs %s%s ro,size=4k", id, id, gardenDiskseqSource, entries)
}

// setDiskseqRecords makes gardenDiskseq find one record tmpfs per entry list.
func setDiskseqRecords(records ...string) {
	var lines []string
	for i, r := range records {
		lines = append(lines, diskseqLine(60+i, r))
	}
	setDiskseqTable(lines...)
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
	setDiskseqRecords(fmt.Sprintf("%d:%d=%d", testBlockMajor, testBlockMinor, testBlockDiskseq))
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
	Entry("an all-zero UUID", strings.Replace(testDescriptorText(), testBlockUUID, "00000000-0000-0000-0000-000000000000", 1), "descriptor uuid is all zeros, which cannot identify a filesystem"),
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
			Expect(f.host.direct).To(Equal([]int{int(att.File.Fd())}), "the exclusive file gets O_DIRECT, for QEMU's cache=none")
			Expect(att.Release()).To(Succeed())
		})

		It("is refused, with nothing left open, when the exclusive file cannot take O_DIRECT", func() {
			f.host.directErr = errors.New("F_SETFL O_DIRECT: invalid argument")
			Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("turning on direct I/O for %s, which QEMU attaches with cache=none: F_SETFL O_DIRECT: invalid argument", f.what())))
			Expect(f.host.direct).To(HaveLen(1))
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
			Expect(f.prepareRefused(req)).To(MatchError(fmt.Sprintf("volume path %q: the BOSH disk volume provider attaches only in block mode, not in file-image mode", f.dir)))
			Expect(f.host.opens).To(BeEmpty())
		})

		It("refuses an instance after the first, since the volume service attaches the disk to one VM", func() {
			req := f.request()
			req.Index = 2
			err := f.prepareRefused(req)
			Expect(err).To(MatchError(fmt.Sprintf("volume path %q is a BOSH disk in block mode, which the volume service attaches to one VM at a time, so only instance 0 can use it, and this is instance 2; scale the app to one instance or give each instance a service of its own", f.dir)))
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

			It("names the cell setting when Garden made neither the node nor the record, as it does with block volumes off", func() {
				Expect(os.Remove(f.node)).To(Succeed())
				setDiskseqTable()
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("opening %s: the container has no such node; Garden makes it only when the cell runs Garden with --vm-block-volumes", f.what())))
				Expect(f.host.opens).To(Equal([]int{unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC}))
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
					Expect(errors.Is(err, errBlockDeviceBusy)).To(BeFalse())
					Expect(f.host.opens).To(HaveLen(2), "an exclusive open that fails for any reason but EBUSY is not tried again")
				},
				Entry("not in the kvm group", unix.EACCES, "opening %s: permission denied; Garden makes the node root:kvm with mode 0660, and vm-launch needs the kvm group"),
				Entry("not in the device cgroup", unix.EPERM, "opening %s: operation not permitted; the container's device cgroup does not allow the device"),
				Entry("detached", unix.ENXIO, "opening %s: no such device or address; the disk is no longer attached to the cell"),
				Entry("gone", unix.ENODEV, "opening %s: no such device; the disk is no longer attached to the cell"),
				Entry("another error", unix.EIO, "opening %s: input/output error"),
			)

			Describe("while the device is busy", func() {
				It("tries the exclusive open again until the holder lets go, and takes the time from the launch's budget", func() {
					tries := f.host.busyFor(3)
					budget := newLockBudget(10 * time.Second)
					req := f.request()
					req.LockBudget = budget
					began := time.Now()
					att, err := f.provider.Prepare(req)
					Expect(err).NotTo(HaveOccurred())
					DeferCleanup(att.Release)
					Expect(*tries).To(Equal(4))
					// The waits are 50, 100, and 200 milliseconds.
					Expect(time.Since(began)).To(BeNumerically(">=", 350*time.Millisecond))
					Expect(budget.remaining).To(BeNumerically("<=", 10*time.Second-350*time.Millisecond))
					Expect(budget.remaining).To(BeNumerically(">", 5*time.Second))
				})

				It("refuses the device as still in use once the budget runs out, with nothing left open", func() {
					tries := f.host.busyFor(1 << 30)
					budget := newLockBudget(300 * time.Millisecond)
					req := f.request()
					req.LockBudget = budget
					began := time.Now()
					err := f.prepareRefused(req)
					Expect(time.Since(began)).To(BeNumerically(">=", 300*time.Millisecond))
					Expect(err).To(MatchError(fmt.Sprintf("%s is still in use after vm-launch waited 300ms for it: the cell has it mounted, or another process, such as an earlier instance's hypervisor, holds it open exclusively; a block device takes one writer", f.what())))
					Expect(errors.Is(err, errBlockDeviceBusy)).To(BeTrue())
					Expect(errors.Is(err, unix.EBUSY)).To(BeTrue())
					Expect(stepExitCode(err)).To(Equal(exitLaunchError))
					Expect(budget.remaining).To(BeZero())
					Expect(*tries).To(BeNumerically(">", 1))
				})

				It("tries once and refuses at once when an earlier volume used up the budget", func() {
					tries := f.host.busyFor(1 << 30)
					req := f.request()
					req.LockBudget = newLockBudget(0)
					err := f.prepareRefused(req)
					Expect(err).To(MatchError(HavePrefix(f.what() + " is still in use after vm-launch waited 0s for it: ")))
					Expect(*tries).To(Equal(1))
				})

				It("stops waiting when a signal arrives, and exits as the signal says", func() {
					f.host.busyFor(1 << 30)
					sigs := make(chan os.Signal, 1)
					sigs <- syscall.SIGTERM
					req := f.request()
					req.LockBudget = newLockBudget(10 * time.Second)
					req.Signals = sigs
					began := time.Now()
					err := f.prepareRefused(req)
					Expect(time.Since(began)).To(BeNumerically("<", 5*time.Second))
					var sig *signalledError
					Expect(errors.As(err, &sig)).To(BeTrue(), "%v", err)
					Expect(err).To(MatchError("received terminated while waiting for the block device to be released"))
					Expect(stepExitCode(err)).To(Equal(128 + int(syscall.SIGTERM)))
				})
			})

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

			It("is refused when it is another disk than the one Garden granted", func() {
				f.host.seq = testBlockDiskseq + 1
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("%s is disk sequence number 43, and Garden granted disk sequence number 42; another disk now has the device number, and vm-launch refuses it", f.what())))
			})

			It("is refused when its disk sequence number cannot be read", func() {
				f.host.seqErr = errors.New("BLKGETDISKSEQ: inappropriate ioctl for device")
				Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("reading the disk sequence number of %s: BLKGETDISKSEQ: inappropriate ioctl for device", f.what())))
			})

			It("passes with Garden's entries for other devices beside its own", func() {
				setDiskseqRecords("8:32=7,8:16=42,253:0=9")
				att, err := f.provider.Prepare(f.request())
				Expect(err).NotTo(HaveOccurred())
				Expect(att.Release()).To(Succeed())
			})

			DescribeTable("is refused, after the look at the node and before the exclusive open, unless Garden recorded the disk once",
				func(lines []string, msg string) {
					setDiskseqTable(lines...)
					Expect(f.prepareRefused(f.request())).To(MatchError(fmt.Sprintf("checking %s: %s", f.what(), msg)))
					Expect(f.host.opens).To(Equal([]int{unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC}))
				},
				Entry("without the record", nil, "the container has no garden-pdi-diskseq: mount, so this Garden did not record which disk it granted; block volumes need a Garden that records it"),
				Entry("with two records", []string{diskseqLine(60, "8:16=42"), diskseqLine(61, "8:16=42")}, "the container has 2 garden-pdi-diskseq: mounts, and Garden makes one"),
				Entry("with a record that is not on tmpfs", []string{"60 22 0:60 / /opt/garden-vm/pdi-diskseq ro - ext4 garden-pdi-diskseq:8:16=42 ro"}, `the garden-pdi-diskseq: record at "/opt/garden-vm/pdi-diskseq" is a ext4 mount, and Garden makes it on tmpfs`),
				Entry("without the device", []string{diskseqLine(60, "8:32=42")}, "garden-pdi-diskseq: has no entry for device 8:16, so Garden did not grant it to this container"),
				Entry("empty", []string{diskseqLine(60, "")}, `garden-pdi-diskseq: entry "" is not MAJOR:MINOR=SEQ`),
				Entry("without a sequence number", []string{diskseqLine(60, "8:16")}, `garden-pdi-diskseq: entry "8:16" is not MAJOR:MINOR=SEQ`),
				Entry("without a minor", []string{diskseqLine(60, "8=42")}, `garden-pdi-diskseq: entry "8=42" is not MAJOR:MINOR=SEQ`),
				Entry("with a signed major", []string{diskseqLine(60, "+8:16=42")}, `garden-pdi-diskseq: entry "+8:16=42": major "+8" is not a decimal number`),
				Entry("with a padded minor", []string{diskseqLine(60, "8:016=42")}, `garden-pdi-diskseq: entry "8:016=42": minor "016" has a leading zero`),
				Entry("with a sequence number that overflows", []string{diskseqLine(60, "8:16=18446744073709551616")}, `garden-pdi-diskseq: entry "8:16=18446744073709551616": sequence number "18446744073709551616" is out of range`),
				Entry("with sequence number 0", []string{diskseqLine(60, "8:16=0")}, `garden-pdi-diskseq: entry "8:16=0" has sequence number 0, which no disk has`),
				Entry("with a malformed entry for another device", []string{diskseqLine(60, "8:16=42,8:32=x")}, `garden-pdi-diskseq: entry "8:32=x": sequence number "x" is not a decimal number`),
				Entry("naming the device twice", []string{diskseqLine(60, "8:16=42,8:16=43")}, "garden-pdi-diskseq: names device 8:16 more than once"),
			)

			It("is refused, before the exclusive open, when a line that names the record does not parse", func() {
				setDiskseqTable("60 22 0:60 / /opt/garden-vm/pdi-diskseq ro tmpfs garden-pdi-diskseq:8:16=42 ro")
				Expect(f.prepareRefused(f.request())).To(MatchError(HavePrefix(fmt.Sprintf("checking %s: a line of %s that names garden-pdi-diskseq: is malformed: ", f.what(), diskseqMountInfo))))
				Expect(f.host.opens).To(Equal([]int{unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC}))
			})

			It("ignores a mount whose path, not its source, holds the record's prefix", func() {
				setDiskseqTable(diskseqLine(60, "8:16=42"), "61 22 0:61 / /data/garden-pdi-diskseq:8:16=1 rw - tmpfs tmpfs rw")
				att, err := f.provider.Prepare(f.request())
				Expect(err).NotTo(HaveOccurred())
				Expect(att.Release()).To(Succeed())
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
				Entry("another UUID, which the line does not repeat", func(sb *ext4Superblock) { sb.uuid = "00000000-1111-2222-3333-444444444444" },
					"%s holds an ext4 filesystem whose UUID does not match the one the volume broker recorded for the disk; the device number may now belong to another disk, so vm-launch refuses it"),
				Entry("an all-zero UUID", func(sb *ext4Superblock) { sb.uuid = "00000000-0000-0000-0000-000000000000" },
					"%s holds an ext4 filesystem whose UUID is all zeros, which cannot identify the disk, so vm-launch refuses it"),
				Entry("no journal", func(sb *ext4Superblock) { sb.compat = 0 },
					"%s holds an ext4 filesystem without a journal; the volume driver formats a block-mode disk with one"),
				Entry("a journal on another device", func(sb *ext4Superblock) { sb.journalInum = 0 },
					"%s keeps its ext4 journal on another device, which the guest does not have"),
				Entry("a block size the kernel does not mount", func(sb *ext4Superblock) { sb.logBlockSize = 7 },
					"%s holds an ext4 superblock with s_log_block_size 7, a block size the kernel does not mount"),
				Entry("a filesystem one block larger than the device", func(sb *ext4Superblock) { sb.blocksLo++ },
					"%s holds an ext4 filesystem of 1025 blocks of 4096 bytes, and the device holds only 1024 such blocks; the guest cannot mount a filesystem that ends past its disk"),
				Entry("a 64-bit filesystem whose high block count runs past the device", func(sb *ext4Superblock) {
					sb.incompat, sb.blocksHi = ext4Incompat64Bit, 1
				}, "%s holds an ext4 filesystem of 4294968320 blocks of 4096 bytes, and the device holds only 1024 such blocks; the guest cannot mount a filesystem that ends past its disk"),
				Entry("1 KiB blocks past the device", func(sb *ext4Superblock) { sb.logBlockSize, sb.blocksLo = 0, 4097 },
					"%s holds an ext4 filesystem of 4097 blocks of 1024 bytes, and the device holds only 4096 such blocks; the guest cannot mount a filesystem that ends past its disk"),
			)

			DescribeTable("accepts a filesystem that fits the device",
				func(edit func(*ext4Superblock)) {
					sb := goodSuperblock()
					edit(&sb)
					f.writeNode(sb)
					att, err := f.provider.Prepare(f.request())
					Expect(err).NotTo(HaveOccurred())
					Expect(att.Release()).To(Succeed())
				},
				Entry("that fills it", func(*ext4Superblock) {}),
				Entry("that is smaller", func(sb *ext4Superblock) { sb.blocksLo = 512 }),
				Entry("with 64 KiB blocks", func(sb *ext4Superblock) { sb.logBlockSize, sb.blocksLo = 6, 64 }),
				Entry("whose unused high block count is set without the 64-bit feature", func(sb *ext4Superblock) { sb.blocksHi = 1 }),
				Entry("of 64 bits whose high block count is 0", func(sb *ext4Superblock) { sb.incompat = ext4Incompat64Bit }),
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
	blockDrive := volumeDrive{fd: firstVolumeFD, id: qemuVolumeSerial(0), mode: attachBlock}

	It("gives QEMU a block device from its file descriptor set through host_device with cache=none, and keeps the serial", func() {
		argv, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", goldenVolumeInitrd, goldenMemMiB, task, []volumeDrive{blockDrive}, "", 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal(concat(withInitrd(goldenQEMUBase, goldenVolumeInitrd), goldenQEMUTaskNetdev, []string{
			"-add-fd", "fd=3,set=3",
			"-drive", "if=none,id=vol0,format=raw,file.driver=host_device,file.filename=/dev/fdset/3,cache=none,aio=threads,file.locking=off,file.auto-read-only=off,werror=report,rerror=report,discard=ignore",
			"-device", "virtio-blk-device,drive=vol0,serial=rvm-vol0",
		}, goldenQEMUBalloon)))
	})

	It("gives Firecracker a block device the same drive an image gets", func() {
		Expect(fcConfigJSON(goldenVolumeInitrd, goldenMemMiB, task, []volumeDrive{blockDrive}, "")).To(Equal(fcConfigJSON(goldenVolumeInitrd, goldenMemMiB, task, drivePathsFor(1), "")))
	})

	It("mixes block and image drives in volume order", func() {
		drives := []volumeDrive{drivePathsFor(1)[0], {fd: firstVolumeFD + 1, id: qemuVolumeSerial(1), mode: attachBlock, index: 1}}
		argv := qemuArgv(goldenArt, procSelfFD(5), goldenMemMiB, task, drives, 0)
		Expect(optionAfter(argv, "-drive", "id=vol0")).To(ContainSubstring(",file.driver=file,file.filename=/dev/fdset/3,cache=writeback,"))
		Expect(optionAfter(argv, "-drive", "id=vol1")).To(ContainSubstring(",file.driver=host_device,file.filename=/dev/fdset/4,cache=none,"))
		Expect(optionAfter(argv, "-add-fd", "fd=4,")).To(Equal("fd=4,set=4"))
	})

	It("takes each drive's file descriptor, identity, and mode from its attachment", func() {
		img, err := os.Open(os.DevNull)
		Expect(err).NotTo(HaveOccurred())
		defer img.Close()
		files, drives, _, _, _ := hypervisorFiles([]*attachment{{File: img, Mode: attachBlock, ID: "12345"}}, img, nil, nil)
		Expect(files).To(HaveLen(2))
		Expect(drives).To(Equal([]volumeDrive{{fd: 3, id: "12345", mode: attachBlock}}))
	})

	It("refuses a drive in neither mode, and on QEMU a drive whose identity cannot be a serial", func() {
		for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			_, err := hypervisorArgv(kind, goldenArt, GinkgoT().TempDir(), goldenVolumeInitrd, goldenMemMiB, task, []volumeDrive{{fd: firstVolumeFD, id: "rvm-vol0"}}, "", 0)
			Expect(err).To(MatchError(ContainSubstring("volume drive vol0 is in ")), string(kind))
		}
		_, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", goldenVolumeInitrd, goldenMemMiB, task, []volumeDrive{{fd: firstVolumeFD, id: "a,b", mode: attachBlock}}, "", 0)
		Expect(err).To(MatchError(`volume drive vol0 has the identity "a,b", which is not 1 to 20 letters, digits, and hyphens, so QEMU cannot pass it as the drive's serial`))
		_, err = hypervisorArgv(backend.VMQemu, goldenArt, "/unused", goldenVolumeInitrd, goldenMemMiB, task, []volumeDrive{{fd: firstVolumeFD, mode: attachBlock}}, "", 0)
		Expect(err).To(MatchError(ContainSubstring(`volume drive vol0 has the identity ""`)))
	})

	DescribeTable("predicts Firecracker's identity for a block drive from fixed node numbers",
		func(st syscall.Stat_t, want string) {
			withDriveStats(st)
			pv := preparedVolumes{{Path: "/data", Attachment: &attachment{File: openSizedFile(1 << 20), Mode: attachBlock, Release: func() error { return nil }}, Bytes: 1 << 20}}
			drives, err := newGuestDrives(backend.VMFirecracker, pv, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(drives.volumes).To(Equal([]guestDrive{{id: want, kind: driveBlock, bytes: 1 << 20}}))
			Expect(pv[0].Attachment.ID).To(Equal(want))
		},
		// Firecracker's build_disk_image_id formats st_dev, st_rdev, and st_ino
		// as "{}{}{}" and keeps the first 20 bytes. st_rdev is glibc's
		// makedev encoding: 8:16 is 16 | 8<<8 = 2064, and 259:300 is
		// 44 | 259<<8 | 256<<12 = 1114924. A /dev on devtmpfs 0:6 has st_dev 6,
		// and one on a container's tmpfs 0:312 has st_dev 56 | 256<<12 = 1048632.
		Entry("of /dev/sdb on the host's devtmpfs", syscall.Stat_t{Dev: 6, Rdev: 2064, Ino: 301}, "62064301"),
		Entry("of an NVMe partition in a container's /dev, cut to 20 bytes", syscall.Stat_t{Dev: 1048632, Rdev: 1114924, Ino: 1234567}, "10486321114924123456"),
	)

	It("encodes device numbers as glibc's makedev does, which Firecracker's stat reports", func() {
		Expect(unix.Mkdev(8, 16)).To(Equal(uint64(2064)))
		Expect(unix.Mkdev(259, 300)).To(Equal(uint64(1114924)))
		Expect(unix.Mkdev(0, 312)).To(Equal(uint64(1048632)))
	})

	It("gives a block attachment the block drive kind and puts the identity on the attachment", func() {
		img := openSizedFile(1 << 20)
		pv := preparedVolumes{{Path: "/data", Attachment: &attachment{File: img, Mode: attachBlock, Release: func() error { return nil }}, Bytes: 1 << 20}}
		drives, err := newGuestDrives(backend.VMQemu, pv, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(drives.volumes).To(Equal([]guestDrive{{id: "rvm-vol0", kind: driveBlock, bytes: 1 << 20}}))
		Expect(pv[0].Attachment.ID).To(Equal("rvm-vol0"))
		disks, err := disksFile(guestContents{vols: []guestVolume{{ContainerDir: "/data"}}, drives: drives})
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

// sysfsDiskseq returns the disk sequence number of d from sysfs.
func sysfsDiskseq(d *loopDisk) uint64 {
	raw, err := os.ReadFile(fmt.Sprintf("/sys/dev/block/%d:%d/diskseq", d.major, d.minor))
	Expect(err).NotTo(HaveOccurred(), "block volumes need a kernel with diskseq, Linux 5.15 or later")
	seq, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	Expect(err).NotTo(HaveOccurred())
	return seq
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

	// grant mounts the record tmpfs of the disks, as Garden does when it grants
	// them, and unmounts the one an earlier grant in the spec mounted, so the
	// kernel's mount table always holds one.
	var unmountGrant func()
	grantRecord := func(entries string) {
		if unmountGrant != nil {
			unmountGrant()
		}
		dir := GinkgoT().TempDir()
		runTool("mount", "-t", "tmpfs", "-o", "ro,size=4k,nodev,nosuid,noexec", gardenDiskseqSource+entries, dir)
		mounted := true
		unmountGrant = func() {
			if mounted {
				runTool("umount", dir)
				mounted = false
			}
		}
		DeferCleanup(unmountGrant)
	}
	grant := func(disks ...*loopDisk) {
		var entries []string
		for _, d := range disks {
			entries = append(entries, fmt.Sprintf("%d:%d=%d", d.major, d.minor, sysfsDiskseq(d)))
		}
		grantRecord(strings.Join(entries, ","))
	}

	BeforeEach(func() {
		requireLoopDevices()
		volumeProbe, dirProbe = probeVolume, probeMountFD
		disk = newLoopDisk(64 << 20)
		grant(disk)
	})

	descriptorFor := func(d *loopDisk) string {
		return blockDescriptorText(d.major, d.minor, d.size, d.uuid, testBlockDisk)
	}
	providerFor := func(d *loopDisk) *blockProvider {
		return &blockProvider{name: "BOSH disk", source: boshDiskDescriptorSource, nodeDir: d.nodeDir, host: linuxBlockHost{}}
	}
	// prepareWithin finds the provider of the descriptor at dir through the
	// kernel's mount table, as vm-launch does, and prepares the disk with the
	// provider for d, waiting up to wait for a busy device.
	prepareWithin := func(d *loopDisk, dir string, wait time.Duration) (*attachment, error) {
		p, m, err := findVolumeProvider("/proc/self/mountinfo", dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Name()).To(Equal("BOSH disk"))
		return providerFor(d).Prepare(prepareRequest{Mount: m, Mode: attachBlock, LockBudget: newLockBudget(wait)})
	}
	// prepareAt prepares the disk with a short wait for a busy device.
	prepareAt := func(d *loopDisk, dir string) (*attachment, error) {
		return prepareWithin(d, dir, 300*time.Millisecond)
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
		flags, err := unix.FcntlInt(att.File.Fd(), unix.F_GETFL, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(flags & unix.O_ACCMODE).To(Equal(unix.O_RDWR))
		Expect(flags&unix.O_DIRECT).NotTo(BeZero(), "the device carries O_DIRECT, which QEMU's cache=none drive asks its file descriptor set for")

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
		Expect(err).To(MatchError(HavePrefix(what(disk, dir) + " is still in use after vm-launch waited 300ms for it")))
	})

	It("refuses the device while another process holds it open exclusively", func() {
		dir := descriptorMount(descriptorFor(disk))
		holder, err := unix.Open(disk.dev, unix.O_RDONLY|unix.O_EXCL|unix.O_CLOEXEC, 0)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { unix.Close(holder) })
		_, err = prepareAt(disk, dir)
		Expect(errors.Is(err, errBlockDeviceBusy)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError(HavePrefix(what(disk, dir) + " is still in use after vm-launch waited 300ms for it")))
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
		Expect(err).To(MatchError(what(disk, dir) + " holds an ext4 filesystem whose UUID does not match the one the volume broker recorded for the disk; the device number may now belong to another disk, so vm-launch refuses it"))
		Expect(err.Error()).NotTo(ContainSubstring(disk.uuid))
	})

	It("refuses a disk that is not the one Garden granted, which the kernel numbers anew", func() {
		seq := sysfsDiskseq(disk)
		grantRecord(fmt.Sprintf("%d:%d=%d", disk.major, disk.minor, seq+1))
		dir := descriptorMount(descriptorFor(disk))
		_, err := prepareAt(disk, dir)
		Expect(err).To(MatchError(fmt.Sprintf("%s is disk sequence number %d, and Garden granted disk sequence number %d; another disk now has the device number, and vm-launch refuses it", what(disk, dir), seq, seq+1)))
	})

	It("refuses an ext4 filesystem without a journal", func() {
		bare := newLoopDisk(64<<20, "-O", "^has_journal")
		grant(bare)
		dir := descriptorMount(descriptorFor(bare))
		_, err := prepareAt(bare, dir)
		Expect(err).To(MatchError(what(bare, dir) + " holds an ext4 filesystem without a journal; the volume driver formats a block-mode disk with one"))
	})

	It("waits for another process's exclusive hold to end, and then attaches the device", func() {
		dir := descriptorMount(descriptorFor(disk))
		holder, err := unix.Open(disk.dev, unix.O_RDONLY|unix.O_EXCL|unix.O_CLOEXEC, 0)
		Expect(err).NotTo(HaveOccurred())
		released := make(chan struct{})
		go func() {
			defer close(released)
			time.Sleep(300 * time.Millisecond)
			unix.Close(holder)
		}()
		DeferCleanup(func() { <-released })
		att, err := prepareWithin(disk, dir, 10*time.Second)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(att.Release)
		Expect(att.Mode).To(Equal(attachBlock))
		Eventually(released).Should(BeClosed())
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
		Expect(err).To(MatchError(fmt.Sprintf("volume paths %q and %q reach the same disk; bind each volume to a directory of its own", dir, dir)))

		drives, err := newGuestDrives(backend.VMQemu, pv, nil)
		Expect(err).NotTo(HaveOccurred())
		_, hv, _, _, _ := hypervisorFiles(pv.files(), pv[0].Attachment.File, nil, nil)
		Expect(hv).To(Equal([]volumeDrive{{fd: 3, id: drives.volumes[0].id, mode: attachBlock}}))
	})
})

var _ = Describe("the launch's prepare of a volume", func() {
	blockCaps := capabilities{Modes: []attachMode{attachBlock}, Fence: fenceExclusiveOpen, MaxInstances: 1}
	discard := log.New(io.Discard, "", 0)
	volumeAt := func(p diskProvider, index int) selectedVolume {
		return selectedVolume{Volume: guestVolume{ContainerDir: "/data", Index: index}, Provider: p, Mount: mountRecord{ContainerDir: "/data", FSType: "fuse.fake"}}
	}

	Describe("the provider's instance limit", func() {
		var (
			p      *fakeDiskProvider
			called int
		)

		BeforeEach(func() {
			called = 0
			p = fake("Fake", "fuse.fake", strongMatch)
			p.prepare = func(prepareRequest) (*attachment, error) {
				called++
				return nil, errors.New("the fake provider was asked to prepare the disk")
			}
		})

		DescribeTable("refuses an instance at or above the limit before the provider's Prepare runs",
			func(caps capabilities, index int, msg string) {
				p.caps = caps
				var pv preparedVolumes
				att, err := pv.prepare(volumeAt(p, index), nil, nil, discard)
				Expect(err).To(MatchError(msg))
				Expect(att).To(BeNil())
				Expect(pv).To(BeEmpty())
				Expect(called).To(BeZero())
				Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			},
			Entry("a block provider of one instance, at instance 1", blockCaps, 1,
				`volume path "/data" is a Fake in block mode, which the volume service attaches to one VM at a time, so only instance 0 can use it, and this is instance 1; scale the app to one instance or give each instance a service of its own`),
			Entry("a block provider of one instance, at the highest index", blockCaps, maxInstanceIndex,
				`volume path "/data" is a Fake in block mode, which the volume service attaches to one VM at a time, so only instance 0 can use it, and this is instance 65535; scale the app to one instance or give each instance a service of its own`),
			Entry("a file-image provider of two instances, at instance 2",
				capabilities{Modes: []attachMode{attachFileImage}, Fence: fenceDistributedFlock, MaxInstances: 2}, 2,
				`volume path "/data" is a Fake in file-image mode, which the volume service attaches to 2 VMs at a time, so only instances 0 to 1 can use it, and this is instance 2; scale the app to 2 instances or give each instance a service of its own`),
		)

		DescribeTable("hands an instance under the limit, or any instance without a limit, to the provider",
			func(caps capabilities, index int) {
				p.caps = caps
				var pv preparedVolumes
				_, err := pv.prepare(volumeAt(p, index), nil, nil, discard)
				Expect(err).To(MatchError("the fake provider was asked to prepare the disk"))
				Expect(called).To(Equal(1))
			},
			Entry("instance 0 of a block provider of one instance", blockCaps, 0),
			Entry("instance 1 of a provider of two instances", capabilities{Modes: []attachMode{attachFileImage}, Fence: fenceDistributedFlock, MaxInstances: 2}, 1),
			Entry("instance 5 of a provider without a limit", fileImageCaps, 5),
		)

		It("refuses a provider that declares a negative limit when it is selected", func() {
			Expect(checkCapabilities(p, capabilities{Modes: []attachMode{attachFileImage}, Fence: fenceDistributedFlock, MaxInstances: -1})).To(
				MatchError("the Fake volume provider declares an instance limit of -1; a limit is 0 for none or a positive number of instances"))
		})
	})

	// The refusals of a disk that does not match the mode it was prepared in
	// hand the attachment back, so that the caller releases it after the
	// refusal's line.
	DescribeTable("refuses an attachment whose mode or file is not what it asked for, and hands it back to be released",
		func(caps capabilities, mode attachMode, open func() *os.File, msg string) {
			released := 0
			file := open()
			p := fake("Fake", "fuse.fake", strongMatch)
			p.caps = caps
			want := &attachment{File: file, Mode: mode, Release: func() error { released++; return nil }}
			p.prepare = func(prepareRequest) (*attachment, error) { return want, nil }
			var pv preparedVolumes
			att, err := pv.prepare(volumeAt(p, 0), nil, nil, discard)
			Expect(err).To(MatchError(msg))
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			Expect(att).To(BeIdenticalTo(want))
			Expect(pv).To(BeEmpty())
			Expect(released).To(BeZero(), "prepare released the disk before the refusal's line")
			discardAttachment(att, discard)
			Expect(released).To(Equal(1))
		},
		Entry("a block-mode disk from a provider asked for file-image mode", fileImageCaps, attachBlock,
			func() *os.File { return openSizedFile(1 << 20) },
			`the Fake volume provider was asked for file-image mode for the volume at "/data" and prepared the disk in block mode`),
		Entry("a file-image disk from a provider asked for block mode", blockCaps, attachFileImage,
			func() *os.File { return openSizedFile(1 << 20) },
			`the Fake volume provider was asked for block mode for the volume at "/data" and prepared the disk in file-image mode`),
		Entry("a regular file in block mode", blockCaps, attachBlock,
			func() *os.File { return openSizedFile(1 << 20) },
			`the Fake volume provider prepared the disk for the volume at "/data" in block mode, but its file is not a block device`),
		Entry("a character device in block mode", blockCaps, attachBlock,
			func() *os.File { return openDevNull() },
			`the Fake volume provider prepared the disk for the volume at "/data" in block mode, but its file is not a block device`),
		Entry("a directory in file-image mode", fileImageCaps, attachFileImage,
			func() *os.File {
				d, err := os.Open(GinkgoT().TempDir())
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(d.Close)
				return d
			},
			`the Fake volume provider prepared the disk for the volume at "/data" in file-image mode, but its file is not a regular file`),
		Entry("a character device in file-image mode", fileImageCaps, attachFileImage,
			func() *os.File { return openDevNull() },
			`the Fake volume provider prepared the disk for the volume at "/data" in file-image mode, but its file is not a regular file`),
	)

	It("records the mode it asked for when the provider leaves it unset", func() {
		p := fake("Fake", "fuse.fake", strongMatch)
		file := openSizedFile(1 << 20)
		p.prepare = func(prepareRequest) (*attachment, error) {
			return &attachment{File: file, Release: func() error { return nil }}, nil
		}
		var pv preparedVolumes
		att, err := pv.prepare(volumeAt(p, 0), nil, nil, discard)
		Expect(err).NotTo(HaveOccurred())
		Expect(att).To(BeNil())
		Expect(pv).To(HaveLen(1))
		Expect(pv[0].Attachment.Mode).To(Equal(attachFileImage))
		Expect(pv[0].Bytes).To(Equal(int64(1 << 20)))
	})
})

var _ = Describe("a size setting on a BOSH disk", func() {
	blockCaps := capabilities{Modes: []attachMode{attachBlock}, Fence: fenceExclusiveOpen, MaxInstances: 1}
	discard := log.New(io.Discard, "", 0)
	sizedVolume := func(p diskProvider, size int64, index int) selectedVolume {
		return selectedVolume{
			Volume:   guestVolume{ContainerDir: "/disk", Index: index, Settings: volumeSettings{SizeBytes: size}},
			Provider: p,
			Mount:    mountRecord{ContainerDir: "/disk", FSType: "tmpfs"},
		}
	}
	const planLine = `VM_VOLUMES "/disk" sets a size, but it is a BOSH disk, whose size comes from its plan`

	DescribeTable("is refused with the plan line, whatever its value",
		func(size int64) {
			Expect(refuseBlockSize(sizedVolume(&blockProvider{name: "BOSH disk"}, size, 0))).To(MatchError(planLine))
		},
		Entry("the smallest size an app may ask for", int64(minVolumeSize)),
		Entry("the default image size, which an explicit size can equal", int64(defaultImageSize)),
		Entry("the size of the test disk, which an explicit size can equal", int64(testBlockSize)),
		Entry("a large size", int64(20<<30)),
		Entry("the largest size", int64(maxVolumeSize)),
	)

	It("lets a block volume without a size pass", func() {
		Expect(refuseBlockSize(sizedVolume(&blockProvider{name: "BOSH disk"}, 0, 0))).To(Succeed())
	})

	It("leaves a size on a volume that is not in block mode to the file-image path", func() {
		Expect(refuseBlockSize(sizedVolume(juicefsProvider{}, 1<<30, 0))).To(Succeed())
		Expect(refuseBlockSize(sizedVolume(nfsProvider{}, 1<<30, 0))).To(Succeed())
	})

	It("passes a volume that has no provider", func() {
		Expect(refuseBlockSize(sizedVolume(nil, 1<<30, 0))).To(Succeed())
	})

	It("names the path of the first block volume with a size, in volume order", func() {
		block := &blockProvider{name: "BOSH disk"}
		first := sizedVolume(block, 1<<30, 0)
		first.Volume.ContainerDir = "/first"
		second := sizedVolume(block, 2<<30, 0)
		second.Volume.ContainerDir = "/second"
		plain := sizedVolume(block, 0, 0)
		plain.Volume.ContainerDir = "/plain"
		image := sizedVolume(juicefsProvider{}, 1<<30, 0)
		image.Volume.ContainerDir = "/image"
		Expect(refuseBlockSizes([]selectedVolume{image, plain, first, second})).To(MatchError(
			`VM_VOLUMES "/first" sets a size, but it is a BOSH disk, whose size comes from its plan`))
		Expect(refuseBlockSizes([]selectedVolume{image, plain})).To(Succeed())
		Expect(refuseBlockSizes(nil)).To(Succeed())
	})

	Describe("in the launch's prepare of the volume", func() {
		var (
			p      *fakeDiskProvider
			called int
		)

		BeforeEach(func() {
			called = 0
			p = fake("Fake", "fuse.fake", strongMatch)
			p.caps = blockCaps
			p.prepare = func(prepareRequest) (*attachment, error) {
				called++
				return nil, errors.New("the fake provider was asked to prepare the disk")
			}
		})

		It("refuses a size before the provider's Prepare runs, and before an instance limit", func() {
			var pv preparedVolumes
			att, err := pv.prepare(sizedVolume(p, 1<<30, 1), nil, nil, discard)
			Expect(err).To(MatchError(planLine))
			Expect(att).To(BeNil())
			Expect(pv).To(BeEmpty())
			Expect(called).To(BeZero())
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		})

		It("hands a volume without a size to the provider", func() {
			var pv preparedVolumes
			_, err := pv.prepare(sizedVolume(p, 0, 0), nil, nil, discard)
			Expect(err).To(MatchError("the fake provider was asked to prepare the disk"))
			Expect(called).To(Equal(1))
		})

		It("hands a size on a file-image volume to the provider", func() {
			p.caps = fileImageCaps
			var pv preparedVolumes
			_, err := pv.prepare(sizedVolume(p, 1<<30, 0), nil, nil, discard)
			Expect(err).To(MatchError("the fake provider was asked to prepare the disk"))
			Expect(called).To(Equal(1))
		})
	})

	Describe("at launch", func() {
		var (
			art    string
			tmp    string
			volDir string
			logBuf *bytes.Buffer
			p      *fakeDiskProvider
			called int
		)

		BeforeEach(func() {
			art = makeArtifacts()
			volDir = GinkgoT().TempDir()
			infoDir := GinkgoT().TempDir()
			tmp = GinkgoT().TempDir()
			GinkgoT().Setenv("TMPDIR", tmp)
			GinkgoT().Setenv("CF_INSTANCE_INDEX", "0")
			GinkgoT().Setenv("VCAP_APPLICATION", vcapApp)
			GinkgoT().Setenv("VCAP_SERVICES", `{"disk":[{"name":"b","credentials":{"password":"`+secretSentinel+`"},"volume_mounts":[`+mountJSON(volDir, "rw")+`]}]}`)
			DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)
			mountInfoPath = filepath.Join(infoDir, "mountinfo")
			Expect(os.WriteFile(mountInfoPath, []byte(mountinfoLine(40, volDir, "fuse.fake")), 0o644)).To(Succeed())
			logBuf = &bytes.Buffer{}

			saved := defaultImageOptions
			DeferCleanup(func() { defaultImageOptions = saved })
			defaultImageOptions.IsMountRoot = alwaysMountRoot

			called = 0
			p = fake("Fake", "fuse.fake", strongMatch)
			p.caps = blockCaps
			p.prepare = func(prepareRequest) (*attachment, error) {
				called++
				return nil, errors.New("the fake provider was asked to prepare the disk")
			}
			withProviders(p)
		})

		launch := func(volumes string) int {
			GinkgoT().Setenv("VM_VOLUMES", strings.ReplaceAll(volumes, "$DIR", volDir))
			logBuf.Reset()
			argv := []string{"--backend", "vm-qemu", "--allow-volume-shares", "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}
			return run(argv, log.New(logBuf, "", 0))
		}

		DescribeTable("exits 125 with exactly one line before it opens or creates anything",
			func(size, line string) {
				argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
				Expect(launch(`{"$DIR":{` + size + `}}`)).To(Equal(exitLaunchError))
				Expect(logBuf.String()).To(Equal(strings.ReplaceAll(line, "$DIR", quoteForLog(volDir)) + "\n"))
				Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel))
				Expect(called).To(BeZero())
				Expect(argvFile).NotTo(BeAnExistingFile())
				Expect(os.ReadDir(tmp)).To(BeEmpty())
				Expect(os.ReadDir(volDir)).To(BeEmpty())
			},
			Entry("a size of 20G", `"size":"20G"`, `VM_VOLUMES $DIR sets a size, but it is a BOSH disk, whose size comes from its plan`),
			Entry("the smallest size", `"size":"64M"`, `VM_VOLUMES $DIR sets a size, but it is a BOSH disk, whose size comes from its plan`),
			Entry("the default image size written out", `"size":"1G"`, `VM_VOLUMES $DIR sets a size, but it is a BOSH disk, whose size comes from its plan`),
			Entry("a size with the private mode written out", `"mode":"private","size":"4G"`, `VM_VOLUMES $DIR sets a size, but it is a BOSH disk, whose size comes from its plan`),
			Entry("a size with mode share, which the share line refuses first", `"mode":"share","size":"1G"`,
				`VM_VOLUMES $DIR sets a size, but a share has no image; its space is the volume's own quota`),
		)

		DescribeTable("lets a block volume without a size reach the provider",
			func(volumes string) {
				Expect(launch(volumes)).To(Equal(exitLaunchError))
				Expect(logBuf.String()).To(ContainSubstring("the fake provider was asked to prepare the disk"))
				Expect(logBuf.String()).NotTo(ContainSubstring("sets a size"))
				Expect(called).To(Equal(1))
			},
			Entry("no VM_VOLUMES", ""),
			Entry("an empty object", "{}"),
			Entry("an entry without settings", "{\"$DIR\":{}}"),
			Entry("mode private", "{\"$DIR\":{\"mode\":\"private\"}}"),
		)
	})
})

// openDevNull opens the null device read-write, which is a character device,
// for the rest of the spec.
func openDevNull() *os.File {
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(f.Close)
	return f
}
