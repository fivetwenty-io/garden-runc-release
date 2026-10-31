//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// guestDisksCommand prints a disk= line for each virtio block device the
// guest has: its name, its size in sectors, and the label in its ext2
// superblock, which is empty for a disk that holds none.
const guestDisksCommand = `for rvm_d in /sys/block/vd*; do
	[ -e "$rvm_d/size" ] || continue
	rvm_n=${rvm_d##*/}
	echo "disk=$rvm_n:$(cat "$rvm_d/size"):$(dd if=/dev/$rvm_n bs=1 skip=` + extLabelOffsetText + ` count=16 2>/dev/null | tr -d '\000')"
done
`

// The ext2 superblock starts 1024 bytes into the filesystem and keeps the
// volume label, 16 bytes, 120 bytes into the superblock.
const (
	extLabelOffset     = 1024 + 120
	extLabelOffsetText = "1144"
	extLabelBytes      = 16
)

// guestDisks returns the disk= lines of guestDisksCommand in out, as each
// device's label keyed by its size in sectors.
func guestDisks(out string) map[int64]string {
	disks := map[int64]string{}
	for _, m := range regexp.MustCompile(`(?m)^disk=vd[a-z]+:([0-9]+):([^\r\n]*)\r?$`).FindAllStringSubmatch(out, -1) {
		size, err := strconv.ParseInt(m[1], 10, 64)
		Expect(err).NotTo(HaveOccurred())
		Expect(disks).NotTo(HaveKey(size), "two disks of %d sectors\n%s", size, out)
		disks[size] = m[2]
	}
	return disks
}

// extLabel returns the label of the ext2 filesystem that f holds, or "" when
// f holds none.
func extLabel(f *os.File) string {
	b := make([]byte, extLabelBytes)
	_, err := f.ReadAt(b, extLabelOffset)
	Expect(err).NotTo(HaveOccurred())
	return string(bytes.TrimRight(b, "\x00"))
}

// allocatedBytes returns the bytes that the host file f holds blocks for, as
// st_blocks counts them, which is what the container's quota charges.
func allocatedBytes(f *os.File) int64 {
	info, err := f.Stat()
	Expect(err).NotTo(HaveOccurred())
	st, ok := info.Sys().(*syscall.Stat_t)
	Expect(ok).To(BeTrue())
	Expect(info.Size()).To(Equal(int64(realRootBytes)), "the root image changed size")
	return st.Blocks * 512
}

// requireHolePunching skips the spec where the file system under the spec's
// temporary files cannot punch holes, because the host file could not shrink
// there whatever the guest and QEMU do.
func requireHolePunching() {
	f, err := os.CreateTemp(GinkgoT().TempDir(), "holes")
	Expect(err).NotTo(HaveOccurred())
	defer f.Close()
	Expect(f.Truncate(1 << 20)).To(Succeed())
	if err := syscall.Fallocate(int(f.Fd()), 0x3 /* PUNCH_HOLE|KEEP_SIZE */, 0, 1<<20); err != nil {
		Skip("the file system under the temporary directory cannot punch holes: " + err.Error())
	}
}

// guestBytes reads the value of the key= line in out, a count of bytes the
// guest printed, as MiB.
func guestBytes(out, key string) int64 {
	m := regexp.MustCompile(`(?m)^` + key + `=([0-9]+)\r?$`).FindStringSubmatch(out)
	Expect(m).NotTo(BeNil(), "no %s= line in\n%s", key, out)
	n, err := strconv.ParseInt(m[1], 10, 64)
	Expect(err).NotTo(HaveOccurred())
	return n
}

// fillRootCommand fills the guest's root with dd, through /tmp, /, and /var
// in turn, the last of them asked for far more than the root image holds. It
// prints each dd's status, the bytes in the files it wrote as written=, and
// the status of a later 8 MiB write to each of the first two places. dd's own
// messages go to the console. The data is not zeros, because the root drive
// turns a write of zeros into a hole in the image.
const fillRootCommand = `mkdir -p /var
tr '\000' x </dev/zero | dd of=/tmp/a bs=1M count=16 iflag=fullblock 2>&1; echo "dd-tmp=$?"
tr '\000' x </dev/zero | dd of=/b bs=1M count=16 iflag=fullblock 2>&1; echo "dd-root=$?"
tr '\000' x </dev/zero | dd of=/var/c bs=1M count=200 iflag=fullblock 2>&1; echo "dd-var=$?"
tr '\000' x </dev/zero | dd of=/tmp/d bs=1M count=8 iflag=fullblock 2>&1; echo "dd-after-tmp=$?"
tr '\000' x </dev/zero | dd of=/e bs=1M count=8 iflag=fullblock 2>&1; echo "dd-after-root=$?"
echo "written=$(( $(wc -c </tmp/a) + $(wc -c </b) + $(wc -c </var/c) ))"
sync
`

var _ = Describe("the guest root against a real QEMU", func() {
	It("boots through the overlay root, with the initramfs below and the root image above, and runs the command in it", func() {
		g := taskGuest(`grep ' / ' /proc/mounts
echo hello >/written && echo "written=$(cat /written)"
df -k / | tail -n 1
` + guestDisksCommand)
		withRealRoot(&g)
		root := realRootImage()
		out := bootRealGuestWith(g, nil, root)

		Expect(out).To(MatchRegexp(`(?m)^overlay / overlay \S*lowerdir=/,upperdir=/rvm/disk/upper,workdir=/rvm/disk/work`), out)
		Expect(out).To(ContainSubstring("written=hello"), out)
		// The overlay's free space is the root image's.
		m := regexp.MustCompile(`(?m)^overlay\s+([0-9]+)\s`).FindStringSubmatch(out)
		Expect(m).NotTo(BeNil(), out)
		kib, err := strconv.ParseInt(m[1], 10, 64)
		Expect(err).NotTo(HaveOccurred())
		Expect(kib).To(BeNumerically(">", realRootBytes/1024/2), out)
		Expect(kib).To(BeNumerically("<=", realRootBytes/1024), out)
		Expect(guestDisks(out)).To(Equal(map[int64]string{realRootBytes / sectorBytes: "rvm-root"}), out)
		Expect(extLabel(root)).To(Equal("rvm-root"))
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})

	It("keeps the guest root in RAM for a guest with no root image", func() {
		out := bootRealGuestWith(taskGuest(`grep ' / ' /proc/mounts
echo "disks=$(ls /sys/block | grep -c '^vd')"
`), nil, nil)
		Expect(out).To(MatchRegexp(`(?m)^\S+ / rootfs `), out)
		Expect(out).NotTo(MatchRegexp(`(?m)^overlay / `), out)
		Expect(out).To(ContainSubstring("disks=0"), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})

	It("formats the root image and never the volume image, which keeps its data across boots", func() {
		volPath := filepath.Join(GinkgoT().TempDir(), "volume.img")
		vol, err := os.OpenFile(volPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(vol.Close)
		Expect(vol.Truncate(defaultImageSize)).To(Succeed())
		withVolume := func(command string) guestContents {
			g := taskGuest(command)
			g.vols, g.drives.volumes = []guestVolume{{ContainerDir: "/home/vcap/data", ImageName: "volume.img"}}, qemuImageDrives(defaultImageSize)
			withRealRoot(&g)
			return g
		}
		disks := map[int64]string{realRootBytes / sectorBytes: "rvm-root", defaultImageSize / sectorBytes: "rvm-volume"}

		root := realRootImage()
		out := bootRealGuestWith(withVolume(`echo kept-from-the-first-boot >/home/vcap/data/kept
echo kept-in-root >/root-only
grep ' /home/vcap/data ' /proc/mounts
`+guestDisksCommand), []*os.File{vol}, root)
		Expect(out).To(MatchRegexp(`(?m)^/dev/vd[a-z]+ /home/vcap/data ext4 `), out)
		Expect(guestDisks(out)).To(Equal(disks), out)
		Expect(extLabel(root)).To(Equal("rvm-root"))
		Expect(extLabel(vol)).To(Equal("rvm-volume"))

		// A second boot gets a new blank root image, as every launch does,
		// and the volume as the first boot left it.
		root = realRootImage()
		out = bootRealGuestWith(withVolume(`echo "volume=$(cat /home/vcap/data/kept)"
echo "root=$(cat /root-only 2>/dev/null || echo gone)"
`+guestDisksCommand), []*os.File{vol}, root)
		Expect(out).To(ContainSubstring("volume=kept-from-the-first-boot"), out)
		Expect(out).To(ContainSubstring("root=gone"), out)
		Expect(guestDisks(out)).To(Equal(disks), out)
		Expect(extLabel(vol)).To(Equal("rvm-volume"))
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})

	Describe("the root image's quota", func() {
		It("fails a write past the image's capacity with ENOSPC wherever it goes, and never grows the image", func() {
			g := taskGuest(fillRootCommand + "df -k / | tail -n 1\necho \"overlayfs-lines=$(dmesg 2>&1 | grep -c overlayfs)\"\necho \"kmsg=$(dmesg 2>&1 | wc -l)\"\n")
			withRealRoot(&g)
			root := realRootImage()
			out := bootRealGuestWith(g, nil, root)

			Expect(out).To(MatchRegexp(`(?m)^dd-tmp=0\r?$`), out)
			Expect(out).To(MatchRegexp(`(?m)^dd-root=0\r?$`), out)
			Expect(out).To(MatchRegexp(`(?m)^dd-var=1\r?$`), out)
			Expect(out).To(MatchRegexp(`(?m)^dd: error writing '/var/c': No space left on device\r?$`), out)
			Expect(out).To(MatchRegexp(`(?m)^dd-after-tmp=1\r?$`), out)
			Expect(out).To(MatchRegexp(`(?m)^dd-after-root=1\r?$`), out)
			Expect(out).NotTo(ContainSubstring("Input/output error"), out)

			// The 64 MiB image holds a little less than 64 MiB of file data.
			written := guestBytes(out, "written")
			Expect(written).To(BeNumerically(">", 32<<20+1), out)
			Expect(written).To(BeNumerically("<", realRootBytes), out)
			Expect(written).To(BeNumerically(">", realRootBytes-8<<20), "ENOSPC came more than 8 MiB short of the image's size\n"+out)

			// Nothing grew the image, and the host holds blocks for what the
			// guest wrote.
			Expect(allocatedBytes(root)).To(BeNumerically(">=", written), out)

			// No overlayfs warning, which would mean the upper layer lacks
			// d_type or xattrs, and the kernel log was readable to say so.
			Expect(guestBytes(out, "kmsg")).To(BeNumerically(">", 0), out)
			Expect(out).To(MatchRegexp(`(?m)^overlayfs-lines=0\r?$`), "grep counted overlayfs lines in the kernel log\n"+out)
			Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
		})

		It("reports the command's exit status when the command fills the root first", func() {
			g := taskGuest(fillRootCommand + "exit 7\n")
			withRealRoot(&g)
			out := bootRealGuestWith(g, nil, realRootImage())

			Expect(out).To(MatchRegexp(`(?m)^dd-var=1\r?$`), out)
			Expect(out).To(ContainSubstring("No space left on device"), out)
			Expect(out).To(ContainSubstring(exitTag(testNonce) + "7"))
		})

		It("returns the space of files the guest deletes to the host, which discard makes happen", func() {
			requireHolePunching()
			const fileMiB = 32
			write := "tr '\\000' x </dev/zero | dd of=/tmp/big bs=1M count=32 iflag=fullblock 2>&1; echo \"dd=$?\"\nsync\n"

			kept := realRootImage()
			out := bootRealGuestWith(withRealRootGuest(write), nil, kept)
			Expect(out).To(MatchRegexp(`(?m)^dd=0\r?$`), out)
			Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))

			deleted := realRootImage()
			out = bootRealGuestWith(withRealRootGuest(write+"rm /tmp/big\nsync\nsleep 1\nsync\n"), nil, deleted)
			Expect(out).To(MatchRegexp(`(?m)^dd=0\r?$`), out)
			Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))

			keptBytes, deletedBytes := allocatedBytes(kept), allocatedBytes(deleted)
			GinkgoWriter.Printf("allocated with the file kept: %d KiB, after the guest deleted it: %d KiB\n", keptBytes/1024, deletedBytes/1024)
			// The image that kept the file holds its blocks, and the file's
			// blocks are most of what the other image gave back.
			Expect(keptBytes).To(BeNumerically(">=", fileMiB<<20), "the host holds no blocks for the file the guest wrote")
			Expect(keptBytes-deletedBytes).To(BeNumerically(">=", fileMiB<<20*3/4), "discard returned less than three quarters of the file's blocks")
			// What is left is the file system's metadata and the guest's
			// small files, an eighth of the image at most.
			Expect(deletedBytes).To(BeNumerically("<", realRootBytes/8))
		})
	})

	// A guest that has written much to its root and not synced it must still
	// stop at once. The root drive is throttled to writeBackMiBPerSecond, and
	// the guest is told to keep its dirty pages, so that a reboot which syncs
	// the whole guest first, as reboot -f does, would take longer than the
	// time the hypervisor gets after the command ends (see killGrace), while
	// reboot -nf does not wait for the root at all.
	It("stops the hypervisor soon after the command ends, though the guest holds much unwritten data for its root", func() {
		const (
			dirtyMiB              = 24
			writeBackMiBPerSecond = 1
			// bound is well under killGrace, and under the 24 seconds that
			// writing the data back would take.
			bound = 3 * time.Second
		)
		Expect(bound).To(BeNumerically("<", killGrace))
		g := withRealRootGuest(`echo 90 >/proc/sys/vm/dirty_ratio
echo 90 >/proc/sys/vm/dirty_background_ratio
echo 360000 >/proc/sys/vm/dirty_expire_centisecs
tr '\000' x </dev/zero | head -c ` + strconv.Itoa(dirtyMiB<<20) + ` >/tmp/dirty
echo "dirty-kib=$(sed -n 's/^Dirty: *\([0-9]*\) kB.*/\1/p' /proc/meminfo)"
echo writes-done
`)
		art := realArtifacts()
		qemu := realQEMU()
		requireMicrovm(qemu)
		f, err := newInitramfs(guestBusybox(), g)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		files, drivePath, initrdPath, _, rootPath := hypervisorFiles(nil, withUserspaceMark(f), nil, realRootImage())
		argv := withRealRootDrive(qemuArgv(art, initrdPath, minGuestMemoryMiB, g.nw, drivePath, 0), rootPath)
		throttled := 0
		for i, a := range argv {
			if strings.HasPrefix(a, "if=none,id="+rootDriveID+",") {
				argv[i] = a + ",throttling.bps-write=" + strconv.Itoa(writeBackMiBPerSecond<<20)
				throttled++
			}
		}
		Expect(throttled).To(Equal(1))

		code, stdout, stderr, after := bootRealQEMUStamped(markedArgv(tcgArgv(qemu, argv)), files, "writes-done")
		Expect(code).To(Equal(0), "QEMU failed: %s\n%s", stderr, stdout)
		Expect(stdout).To(ContainSubstring(exitTag(testNonce) + "0"))
		GinkgoWriter.Printf("QEMU exited %v after the command's last output\n", after)
		// The guest had the data in memory when the command ended.
		Expect(guestBytes(stdout, "dirty-kib")).To(BeNumerically(">", (dirtyMiB-8)<<10), stdout)
		Expect(after).To(BeNumerically("<", bound), "QEMU took %v to exit after the command ended\n%s", after, stdout)
	})

	It("flushes the volume with sync -f, which the guest's busybox runs on a volume mount", func() {
		volPath := filepath.Join(GinkgoT().TempDir(), "volume.img")
		vol, err := os.OpenFile(volPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(vol.Close)
		Expect(vol.Truncate(defaultImageSize)).To(Succeed())
		g := taskGuest(`echo flushed >/home/vcap/data/f
sync -f /home/vcap/data
echo "sync-f-volume=$?"
`)
		g.vols, g.drives.volumes = []guestVolume{{ContainerDir: "/home/vcap/data", ImageName: "volume.img"}}, qemuImageDrives(defaultImageSize)
		withRealRoot(&g)
		out := bootRealGuestWith(g, []*os.File{vol}, realRootImage())

		Expect(out).To(MatchRegexp(`(?m)^sync-f-volume=0\r?$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out)
	})
})

// withRealRootGuest returns a guest that runs command on a real root image.
func withRealRootGuest(command string) guestContents {
	g := taskGuest(command)
	withRealRoot(&g)
	return g
}
