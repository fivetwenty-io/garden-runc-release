//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

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
			g.vol = &guestVolume{ContainerDir: "/home/vcap/data", ImageName: "volume.img"}
			withRealRoot(&g)
			return g
		}
		disks := map[int64]string{realRootBytes / sectorBytes: "rvm-root", defaultImageSize / sectorBytes: "rvm-volume"}

		root := realRootImage()
		out := bootRealGuestWith(withVolume(`echo kept-from-the-first-boot >/home/vcap/data/kept
echo kept-in-root >/root-only
grep ' /home/vcap/data ' /proc/mounts
`+guestDisksCommand), vol, root)
		Expect(out).To(MatchRegexp(`(?m)^/dev/vd[a-z]+ /home/vcap/data ext4 `), out)
		Expect(guestDisks(out)).To(Equal(disks), out)
		Expect(extLabel(root)).To(Equal("rvm-root"))
		Expect(extLabel(vol)).To(Equal("rvm-volume"))

		// A second boot gets a new blank root image, as every launch does,
		// and the volume as the first boot left it.
		root = realRootImage()
		out = bootRealGuestWith(withVolume(`echo "volume=$(cat /home/vcap/data/kept)"
echo "root=$(cat /root-only 2>/dev/null || echo gone)"
`+guestDisksCommand), vol, root)
		Expect(out).To(ContainSubstring("volume=kept-from-the-first-boot"), out)
		Expect(out).To(ContainSubstring("root=gone"), out)
		Expect(guestDisks(out)).To(Equal(disks), out)
		Expect(extLabel(vol)).To(Equal("rvm-volume"))
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})
})
