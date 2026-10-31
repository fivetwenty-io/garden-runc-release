//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// noSuchMountID is a mount ID no fake mount table uses.
const noSuchMountID = uint64(1) << 62

// mountIDByPath returns a volumeMountID that answers as a kernel would for a
// directory that is the mount point of a line in the mount table at table():
// the ID of the last such line. Most specs describe a volume by its path in a
// fake table, and this is how they reach its line by ID. A directory with no
// such line, or a table that cannot be read, gets an ID no line has.
func mountIDByPath(table func() string) func(string) (uint64, error) {
	return func(dir string) (uint64, error) {
		data, err := os.ReadFile(table())
		if err != nil {
			return noSuchMountID, nil
		}
		id := noSuchMountID
		for _, line := range strings.Split(string(data), "\n") {
			if rec, err := parseMountInfoRecord(line); err == nil && rec.MountPoint == dir {
				id = rec.MountID
			}
		}
		return id, nil
	}
}

// findIn is findVolumeProvider with the kernel's answer taken from the mount
// table at info, by the dir's path.
func findIn(info, dir string) (diskProvider, mountRecord, error) {
	saved := volumeMountID
	defer func() { volumeMountID = saved }()
	volumeMountID = mountIDByPath(func() string { return info })
	return findVolumeProvider(info, dir)
}

// findWithID is findVolumeProvider with the kernel answering id for any
// directory.
func findWithID(info, dir string, id uint64) (diskProvider, mountRecord, error) {
	saved := volumeMountID
	defer func() { volumeMountID = saved }()
	volumeMountID = func(string) (uint64, error) { return id, nil }
	return findVolumeProvider(info, dir)
}

// Every spec starts with a kernel that finds a volume by its mount point in
// the mount table at mountInfoPath, so the specs that write a one-line table
// for a volume directory need not know a mount ID.
var _ = BeforeEach(func() {
	savedID, savedStatx := volumeMountID, statxCall
	DeferCleanup(func() { volumeMountID, statxCall = savedID, savedStatx })
	volumeMountID = mountIDByPath(func() string { return mountInfoPath })
})

var _ = DescribeTable("parseMountInfoRecord",
	func(line string, want mountRecord) {
		got, err := parseMountInfoRecord(line)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(want))
	},
	Entry("a line with optional fields",
		"36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 shared:2 - ext3 /dev/root rw,errors=continue",
		mountRecord{MountID: 36, ParentID: 35, Major: 98, Minor: 0, Root: "/mnt1", MountPoint: "/mnt2",
			MountOptions: []string{"rw", "noatime"}, OptionalFields: []string{"master:1", "shared:2"},
			FSType: "ext3", Source: "/dev/root", SuperOptions: []string{"rw", "errors=continue"}}),
	Entry("a line with no optional fields",
		"41 30 0:41 / /data rw - fuse.juicefs JuiceFS:vol rw,user_id=0,group_id=0",
		mountRecord{MountID: 41, ParentID: 30, Major: 0, Minor: 41, Root: "/", MountPoint: "/data",
			MountOptions: []string{"rw"}, FSType: "fuse.juicefs", Source: "JuiceFS:vol",
			SuperOptions: []string{"rw", "user_id=0", "group_id=0"}}),
	Entry("a space escape in the mount point",
		`41 30 0:41 / /my\040data rw - fuse.juicefs v rw`,
		mountRecord{MountID: 41, ParentID: 30, Minor: 41, Root: "/", MountPoint: "/my data", MountOptions: []string{"rw"},
			FSType: "fuse.juicefs", Source: "v", SuperOptions: []string{"rw"}}),
	Entry("tab, newline, and backslash escapes in the root, mount point, and source",
		`41 30 0:41 /a\011b\012c\134d /m\134\040 rw shared:1 - nfs4 10.0.0.1:/ex\040port rw,vers=4.2,local_lock=none`,
		mountRecord{MountID: 41, ParentID: 30, Minor: 41, Root: "/a\tb\nc\\d", MountPoint: `/m\ `, MountOptions: []string{"rw"},
			OptionalFields: []string{"shared:1"}, FSType: "nfs4", Source: "10.0.0.1:/ex port",
			SuperOptions: []string{"rw", "vers=4.2", "local_lock=none"}}),
	Entry("an escape that is not an octal byte stays as written",
		`41 30 0:41 /a\04 /b\9zz\400 rw - tmpfs none rw`,
		mountRecord{MountID: 41, ParentID: 30, Minor: 41, Root: `/a\04`, MountPoint: `/b\9zz\400`, MountOptions: []string{"rw"},
			FSType: "tmpfs", Source: "none", SuperOptions: []string{"rw"}}),
	Entry("a mount point that is a lone dash",
		"41 30 0:41 / - rw shared:1 - ext4 /dev/vda1 rw",
		mountRecord{MountID: 41, ParentID: 30, Minor: 41, Root: "/", MountPoint: "-", MountOptions: []string{"rw"},
			OptionalFields: []string{"shared:1"}, FSType: "ext4", Source: "/dev/vda1", SuperOptions: []string{"rw"}}),
	Entry("a source of a dash, as FUSE and NFS often show",
		"41 30 0:41 / /data rw - fuse.juicefs - rw",
		mountRecord{MountID: 41, ParentID: 30, Minor: 41, Root: "/", MountPoint: "/data", MountOptions: []string{"rw"},
			FSType: "fuse.juicefs", Source: "-", SuperOptions: []string{"rw"}}),
	Entry("large mount and device numbers",
		"4294967 4294966 259:4294967295 / /d rw - xfs /dev/nvme0n1p1 rw",
		mountRecord{MountID: 4294967, ParentID: 4294966, Major: 259, Minor: 4294967295, Root: "/", MountPoint: "/d",
			MountOptions: []string{"rw"}, FSType: "xfs", Source: "/dev/nvme0n1p1", SuperOptions: []string{"rw"}}),
)

var _ = DescribeTable("parseMountInfoRecord refuses a malformed line",
	func(line, reason string) {
		_, err := parseMountInfoRecord(line)
		Expect(err).To(MatchError(ContainSubstring(reason)))
	},
	Entry("an empty line", "", "want at least 10 fields, have 0"),
	Entry("too few fields", "41 30 0:41 / /data rw - fuse.juicefs", "want at least 10 fields, have 8"),
	Entry("no separator", "41 30 0:41 / /data rw shared:1 fuse.juicefs src rw", "no - separator"),
	Entry("a separator and no filesystem type", "41 30 0:41 / /data rw shared:1 shared:2 shared:3 -", "have 0 fields"),
	Entry("a filesystem type and no source", "41 30 0:41 / /data rw shared:1 shared:2 - ext4", "have 1 fields"),
	Entry("no superblock options", "41 30 0:41 / /data rw shared:1 shared:2 shared:3 - ext4 /dev/sda", "have 2 fields"),
	Entry("fields after the superblock options", "41 30 0:41 / /data rw - ext4 /dev/sda rw extra", "have 4 fields"),
	Entry("a mount ID that is not a number", "x1 30 0:41 / /data rw - ext4 /dev/sda rw", `mount ID "x1" is not a number`),
	Entry("a negative mount ID", "-1 30 0:41 / /data rw - ext4 /dev/sda rw", `mount ID "-1" is not a number`),
	Entry("a parent ID that is not a number", "41 p 0:41 / /data rw - ext4 /dev/sda rw", `parent ID "p" is not a number`),
	Entry("a device with no colon", "41 30 041 / /data rw - ext4 /dev/sda rw", `device "041" is not major:minor`),
	Entry("a device that is not numbers", "41 30 a:b / /data rw - ext4 /dev/sda rw", `device "a:b" is not major:minor`),
	Entry("a device number above 32 bits", "41 30 0:4294967296 / /data rw - ext4 /dev/sda rw", `device "0:4294967296" is not major:minor`),
	Entry("a mount ID above 64 bits", "99999999999999999999 30 0:41 / /data rw - ext4 /dev/sda rw", "is not a number"),
)

var _ = Describe("selecting the volume's mountinfo line by mount ID", func() {
	table := func(lines ...string) string { return writeTempFile("mountinfo", strings.Join(lines, "\n")+"\n") }

	// Two mounts at /data: the JuiceFS volume the kernel put the directory
	// on, and a later mount over the same mount point.
	const (
		volume  = "41 30 0:41 / /data rw,nosuid shared:5 - fuse.juicefs JuiceFS:vol rw,user_id=0\n"
		shadow  = "60 30 0:60 / /data rw - ext4 /dev/vdb rw\n"
		otherFS = "30 1 0:30 / / rw - overlay overlay rw\n"
	)

	It("takes the line with the mount ID where a path match takes the last line at the mount point", func() {
		info := writeTempFile("mountinfo", otherFS+volume+shadow)

		p, m, err := findWithID(info, "/data", 41)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Name()).To(Equal("JuiceFS"))
		Expect(m).To(Equal(mountRecord{ContainerDir: "/data", MountID: 41, ParentID: 30, Minor: 41, Root: "/", MountPoint: "/data",
			MountOptions: []string{"rw", "nosuid"}, OptionalFields: []string{"shared:5"}, FSType: "fuse.juicefs",
			Source: "JuiceFS:vol", SuperOptions: []string{"rw", "user_id=0"}}))

		// The path match that this replaces sees the later line.
		_, m, err = findIn(info, "/data")
		Expect(err).To(MatchError(ContainSubstring(`"ext4"`)))
		Expect(m).To(Equal(mountRecord{}))

		_, _, err = findWithID(info, "/data", 60)
		Expect(err).To(MatchError(ContainSubstring(`is a "ext4" mount`)))
	})

	It("takes the same line whatever the order of the two", func() {
		_, m, err := findWithID(writeTempFile("mountinfo", otherFS+shadow+volume), "/data", 41)
		Expect(err).NotTo(HaveOccurred())
		Expect(m.FSType).To(Equal("fuse.juicefs"))
	})

	It("takes the mount that holds the directory, even when the directory is not its mount point", func() {
		_, m, err := findWithID(table(otherFS, volume), "/data/vol", 41)
		Expect(err).NotTo(HaveOccurred())
		Expect(m.ContainerDir).To(Equal("/data/vol"))
		Expect(m.MountPoint).To(Equal("/data"))
	})

	It("finds a mount whose mount point has escapes by its ID", func() {
		_, m, err := findWithID(table(`41 30 0:41 / /my\040data rw - fuse.juicefs v rw`), "/my data", 41)
		Expect(err).NotTo(HaveOccurred())
		Expect(m.MountPoint).To(Equal("/my data"))
	})

	It("refuses an ID with no line, whatever mounts share its path, and names the providers", func() {
		_, _, err := findWithID(table(otherFS, volume, shadow), "/data", 99)
		Expect(err).To(MatchError(ContainSubstring(`volume path "/data" has no mount entry for its mount ID 99 in `)))
		Expect(err).To(MatchError(HaveSuffix("; VM backends support only JuiceFS volumes today")))
	})

	It("does not take a line whose ID only starts with the ID", func() {
		_, _, err := findWithID(table(`410 30 0:41 / /data rw - fuse.juicefs v rw`, `4 30 0:41 / /data rw - fuse.juicefs v rw`), "/data", 41)
		Expect(err).To(MatchError(ContainSubstring("has no mount entry for its mount ID 41")))
	})

	It("refuses a mount ID that is on two lines", func() {
		_, _, err := findWithID(table(volume, strings.TrimSuffix(volume, "\n")), "/data", 41)
		Expect(err).To(MatchError(ContainSubstring("mount ID 41 of volume path \"/data\" is on 2 lines in ")))
	})

	It("refuses a malformed line with the ID, and ignores malformed lines with other IDs", func() {
		_, _, err := findWithID(table("garbage", "41 30 0:41 / /data rw - fuse.juicefs", otherFS), "/data", 41)
		Expect(err).To(MatchError(ContainSubstring("the line for mount ID 41 in ")))
		Expect(err).To(MatchError(ContainSubstring("is malformed: want at least 10 fields, have 8")))
		Expect(err).To(MatchError(HaveSuffix("; VM backends support only JuiceFS volumes today")))

		_, m, err := findWithID(table("garbage", "42 30 0:41", volume, "43 x"), "/data", 41)
		Expect(err).NotTo(HaveOccurred())
		Expect(m.MountID).To(Equal(uint64(41)))
	})

	It("takes the one good line when a malformed line has the same ID", func() {
		_, m, err := findWithID(table("41 broken", volume), "/data", 41)
		Expect(err).NotTo(HaveOccurred())
		Expect(m.FSType).To(Equal("fuse.juicefs"))
	})

	It("refuses a mount table that cannot be read, with the cause", func() {
		_, _, err := findWithID(filepath.Join(GinkgoT().TempDir(), "absent"), "/data", 41)
		Expect(errors.Is(err, unix.ENOENT)).To(BeTrue())
		Expect(err).To(MatchError(ContainSubstring(`to find the filesystem of volume path "/data": no such file or directory; VM backends`)))
	})

	It("does not read the mount table when the kernel gives no mount ID", func() {
		saved := volumeMountID
		DeferCleanup(func() { volumeMountID = saved })
		volumeMountID = func(string) (uint64, error) { return 0, errors.New("no mount ID here") }
		_, _, err := findVolumeProvider(filepath.Join(GinkgoT().TempDir(), "absent"), "/data")
		Expect(err).To(MatchError("no mount ID here"))
	})
})

var _ = Describe("statxMountID", func() {
	BeforeEach(requireOpenat2)

	It("asks statx on the open directory, with an empty path, for the mount ID", func() {
		dir := GinkgoT().TempDir()
		var gotPath string
		var gotFlags, gotMask int
		statxCall = func(fd int, path string, flags int, mask int, st *unix.Statx_t) error {
			gotPath, gotFlags, gotMask = path, flags, mask
			// The descriptor is the directory, open without a name.
			target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
			Expect(err).NotTo(HaveOccurred())
			Expect(target).To(Equal(dir))
			st.Mask, st.Mnt_id = unix.STATX_MNT_ID|unix.STATX_TYPE, 77
			return nil
		}
		id, err := statxMountID(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(id).To(Equal(uint64(77)))
		Expect(gotPath).To(BeEmpty())
		Expect(gotFlags).To(Equal(unix.AT_EMPTY_PATH))
		Expect(gotMask).To(Equal(unix.STATX_MNT_ID))
	})

	It("refuses a kernel that does not report the mount ID in the mask", func() {
		statxCall = func(_ int, _ string, _ int, _ int, st *unix.Statx_t) error {
			st.Mask, st.Mnt_id = unix.STATX_TYPE, 77
			return nil
		}
		id, err := statxMountID(GinkgoT().TempDir())
		Expect(id).To(BeZero())
		Expect(err).To(MatchError(ContainSubstring("the kernel did not report a mount ID through statx for volume ")))
		Expect(err).To(MatchError(ContainSubstring("STATX_MNT_ID needs Linux 5.8 or later")))
	})

	It("refuses through findVolumeProvider before it reads the mount table", func() {
		statxCall = func(_ int, _ string, _ int, _ int, st *unix.Statx_t) error { return nil }
		volumeMountID = statxMountID
		dir := GinkgoT().TempDir()
		_, _, err := findVolumeProvider(filepath.Join(GinkgoT().TempDir(), "absent"), dir)
		Expect(err).To(MatchError(ContainSubstring("the kernel did not report a mount ID")))
		Expect(err.Error()).NotTo(ContainSubstring("VM backends support only"))
		Expect(err.Error()).NotTo(ContainSubstring("reading"))
	})

	It("keeps a statx failure's cause", func() {
		statxCall = func(int, string, int, int, *unix.Statx_t) error { return unix.ENOSYS }
		_, err := statxMountID(GinkgoT().TempDir())
		Expect(errors.Is(err, unix.ENOSYS)).To(BeTrue())
		Expect(err).To(MatchError(ContainSubstring("reading the mount ID of volume ")))
	})

	It("repeats statx when it is interrupted, and gives up when it keeps being interrupted", func() {
		calls := 0
		statxCall = func(_ int, _ string, _ int, _ int, st *unix.Statx_t) error {
			calls++
			if calls < 3 {
				return unix.EINTR
			}
			st.Mask, st.Mnt_id = unix.STATX_MNT_ID, 5
			return nil
		}
		id, err := statxMountID(GinkgoT().TempDir())
		Expect(err).NotTo(HaveOccurred())
		Expect(id).To(Equal(uint64(5)))

		statxCall = func(int, string, int, int, *unix.Statx_t) error { return unix.EINTR }
		_, err = statxMountID(GinkgoT().TempDir())
		Expect(errors.Is(err, unix.EINTR)).To(BeTrue())
	})

	It("refuses a path that is missing, a file, or a symbolic link, without asking statx", func() {
		statxCall = func(int, string, int, int, *unix.Statx_t) error {
			Fail("statx was called")
			return nil
		}
		dir := GinkgoT().TempDir()
		file := filepath.Join(dir, "file")
		Expect(os.WriteFile(file, nil, 0o600)).To(Succeed())
		link := filepath.Join(dir, "link")
		Expect(os.Symlink(dir, link)).To(Succeed())

		_, err := statxMountID(filepath.Join(dir, "absent"))
		Expect(errors.Is(err, unix.ENOENT)).To(BeTrue())
		_, err = statxMountID(file)
		Expect(errors.Is(err, unix.ENOTDIR)).To(BeTrue())
		// The last component is a link: O_DIRECTORY with O_NOFOLLOW refuses it.
		_, err = statxMountID(link)
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP)).To(BeTrue(), err.Error())
		// A link on the way is refused with the hint.
		Expect(os.Mkdir(filepath.Join(dir, "x"), 0o700)).To(Succeed())
		_, err = statxMountID(filepath.Join(link, "x"))
		Expect(errors.Is(err, unix.ELOOP)).To(BeTrue())
		Expect(err).To(MatchError(ContainSubstring("follows no symbolic links")))
	})
})

var _ = Describe("the real kernel's mount ID and the real mount table", func() {
	BeforeEach(requireOpenat2)

	realTable := "/proc/self/mountinfo"

	It("parses every line of the real mount table", func() {
		data, err := os.ReadFile(realTable)
		Expect(err).NotTo(HaveOccurred())
		lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
		Expect(lines).NotTo(BeEmpty())
		seen := map[uint64]bool{}
		for _, line := range lines {
			rec, err := parseMountInfoRecord(line)
			Expect(err).NotTo(HaveOccurred(), line)
			Expect(rec.FSType).NotTo(BeEmpty(), line)
			Expect(rec.MountPoint).To(HavePrefix("/"), line)
			Expect(seen[rec.MountID]).To(BeFalse(), "mount IDs are unique: "+line)
			seen[rec.MountID] = true
		}
	})

	It("finds the line of /proc by the ID statx gives", func() {
		volumeMountID = statxMountID
		id, err := statxMountID("/proc")
		Expect(err).NotTo(HaveOccurred())
		m, err := volumeMount(realTable, "/proc", id)
		Expect(err).NotTo(HaveOccurred())
		Expect(m.MountID).To(Equal(id))
		Expect(m.MountPoint).To(Equal("/proc"))
		Expect(m.FSType).To(Equal("proc"))
		Expect(m.ContainerDir).To(Equal("/proc"))
	})

	It("finds the line that holds a temporary directory", func() {
		dir := GinkgoT().TempDir()
		id, err := statxMountID(dir)
		Expect(err).NotTo(HaveOccurred())
		m, err := volumeMount(realTable, dir, id)
		Expect(err).NotTo(HaveOccurred())
		Expect(m.MountID).To(Equal(id))
		Expect(m.FSType).NotTo(BeEmpty())
		Expect(m.MountPoint == "/" || strings.HasPrefix(dir, m.MountPoint+"/")).To(BeTrue(), "%q is not under %q", dir, m.MountPoint)
	})

	It("takes the top of two stacked mounts, which share a mount point in the real table", func() {
		dir := GinkgoT().TempDir()
		for i := 0; i < 2; i++ {
			if err := unix.Mount("pdi-test", dir, "tmpfs", 0, "size=1m"); err != nil {
				if i == 1 {
					Expect(unix.Unmount(dir, 0)).To(Succeed())
				}
				if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
					Skip("mounting needs CAP_SYS_ADMIN; run these specs privileged")
				}
				Expect(err).NotTo(HaveOccurred())
			}
		}
		DeferCleanup(func() {
			Expect(unix.Unmount(dir, 0)).To(Succeed())
			Expect(unix.Unmount(dir, 0)).To(Succeed())
		})
		id, err := statxMountID(dir)
		Expect(err).NotTo(HaveOccurred())

		data, err := os.ReadFile(realTable)
		Expect(err).NotTo(HaveOccurred())
		var ids []uint64
		for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
			if rec, err := parseMountInfoRecord(line); err == nil && rec.MountPoint == dir {
				ids = append(ids, rec.MountID)
			}
		}
		Expect(ids).To(HaveLen(2))
		Expect(id).To(Equal(ids[1]), "the kernel reports the mount on top")

		m, err := volumeMount(realTable, dir, id)
		Expect(err).NotTo(HaveOccurred())
		Expect(m.MountID).To(Equal(id))
		Expect(m.ParentID).To(Equal(ids[0]), "the top mount sits on the first")
		Expect(m.FSType).To(Equal("tmpfs"))
		Expect(m.Source).To(Equal("pdi-test"))
	})

	It("tells a subdirectory of a mount from the mount point by the same ID", func() {
		dir := GinkgoT().TempDir()
		sub := filepath.Join(dir, "sub")
		Expect(os.Mkdir(sub, 0o700)).To(Succeed())
		a, err := statxMountID(dir)
		Expect(err).NotTo(HaveOccurred())
		b, err := statxMountID(sub)
		Expect(err).NotTo(HaveOccurred())
		Expect(b).To(Equal(a))
	})
})
