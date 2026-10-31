//go:build linux

package main

import (
	"os"
	"os/exec"
	"strconv"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("volumes numbered by volume index beside a share", func() {
	share := func(dir string) guestVolume {
		return guestVolume{ContainerDir: dir, Settings: volumeSettings{Mode: volumeShare}}
	}
	sectors := strconv.Itoa(defaultImageSize / sectorBytes)

	It("gives each share its own number in /rvm/mounts and /rvm/disks, with no drive, and each other volume the next drive", func() {
		g := taskGuest("true")
		g.vols = []guestVolume{
			{ContainerDir: "/data", ImageName: "a.img"},
			share("/shared"),
			{ContainerDir: "/disk", ImageName: "b.img"},
			share("/more shared"),
		}
		g.drives.volumes = []guestDrive{
			{id: qemuVolumeSerial(0), kind: driveImage, bytes: defaultImageSize},
			{id: qemuVolumeSerial(2), kind: driveBlock, bytes: defaultImageSize},
		}
		mounts, err := mountsFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(mounts).To(Equal("RVM_VOLUMES=4\n" +
			"RVM_VOL0_KIND=image\nRVM_VOL0_PATH='/data'\nRVM_VOL0_IMAGE='a.img'\n" +
			"RVM_VOL1_KIND=share\nRVM_VOL1_PATH='/shared'\n" +
			"RVM_VOL2_KIND=block\nRVM_VOL2_PATH='/disk'\n" +
			"RVM_VOL3_KIND=share\nRVM_VOL3_PATH='/more shared'\n"))
		disks, err := disksFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(disks).To(Equal("RVM_VOLUMES=4\n" +
			"RVM_VOL0_KIND=image\nRVM_VOL0_ID=rvm-vol0\nRVM_VOL0_SECTORS=" + sectors + "\n" +
			"RVM_VOL1_KIND=share\n" +
			"RVM_VOL2_KIND=block\nRVM_VOL2_ID=rvm-vol2\nRVM_VOL2_SECTORS=" + sectors + "\n" +
			"RVM_VOL3_KIND=share\n"))

		// Both files source back as the guest reads them, and a share has no
		// identity, size, or image for stage 1 or stage 2 to act on.
		out, err := exec.Command("/bin/sh", "-c", `. "$1"; . "$2"; printf '%s|' "$RVM_VOLUMES" "$RVM_VOL1_KIND" "$RVM_VOL1_PATH" "${RVM_VOL1_ID-unset}" "${RVM_VOL1_SECTORS-unset}" "${RVM_VOL1_IMAGE-unset}" "$RVM_VOL2_ID" "$RVM_VOL3_PATH"`,
			"sh", writeTempFile("mounts", mounts), writeTempFile("disks", disks)).Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(out)).To(Equal("4|share|/shared|unset|unset|unset|rvm-vol2|/more shared|"))
	})

	It("gives a guest whose only volume is a share the share and no drive", func() {
		g := taskGuest("true")
		g.vols = []guestVolume{share("/shared")}
		mounts, err := mountsFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(mounts).To(Equal("RVM_VOLUMES=1\nRVM_VOL0_KIND=share\nRVM_VOL0_PATH='/shared'\n"))
		disks, err := disksFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(disks).To(Equal("RVM_VOLUMES=1\nRVM_VOL0_KIND=share\n"))
	})

	DescribeTable("refuses drives that do not match the volumes that are not shares, so no initramfs is built",
		func(drives []guestDrive, want string) {
			g := taskGuest("true")
			g.vols = []guestVolume{share("/shared"), {ContainerDir: "/data", ImageName: "a.img"}}
			g.drives.volumes = drives
			_, err := mountsFile(g)
			Expect(err).To(MatchError(want))
			_, err = disksFile(g)
			Expect(err).To(MatchError(want))
		},
		Entry("with no drive for the volume beside the share", nil,
			"0 volume drives for 2 guest volumes, 1 of them shares, which have no drive"),
		Entry("with a drive for the share as well", qemuImageDrives(defaultImageSize, defaultImageSize),
			"2 volume drives for 2 guest volumes, 1 of them shares, which have no drive"),
	)

	It("refuses a drive of the share kind, naming it by the volume index of the volume it would hold", func() {
		g := taskGuest("true")
		g.vols = []guestVolume{share("/shared"), {ContainerDir: "/data", ImageName: "a.img"}}
		g.drives.volumes = []guestDrive{{id: qemuVolumeSerial(1), kind: volumeKindShare, bytes: defaultImageSize}}
		_, err := mountsFile(g)
		Expect(err).To(MatchError(`drive vol1 holds a "share", and the guest mounts only "image" and "block" volume drives`))
		_, err = disksFile(g)
		Expect(err).To(MatchError(`drive vol1 holds a "share", and the guest supports only "image" and "block" volume drives`))
	})

	It("refuses more guest volumes than a guest can have, shares included", func() {
		g := taskGuest("true")
		for i := 0; i <= maxVolumes; i++ {
			g.vols = append(g.vols, share("/shared"+strconv.Itoa(i)))
		}
		_, err := mountsFile(g)
		Expect(err).To(MatchError("5 guest volumes, over the 4 a guest can have"))
		_, err = disksFile(g)
		Expect(err).To(MatchError("5 guest volumes, over the 4 a guest can have"))
	})

	It("gives a QEMU drive the serial of its volume index, past the shares before it", func() {
		pv := preparedFiles(openSizedFile(1<<20), openSizedFile(2<<20))
		pv[0].Index, pv[1].Index = 1, 3
		drives, err := newGuestDrives(backend.VMQemu, pv, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(drives.volumes).To(Equal([]guestDrive{
			{id: "rvm-vol1", kind: driveImage, bytes: 1 << 20},
			{id: "rvm-vol3", kind: driveImage, bytes: 2 << 20},
		}))
		Expect(pv[0].Attachment.ID).To(Equal("rvm-vol1"))
		Expect(pv[1].Attachment.ID).To(Equal("rvm-vol3"))
	})

	DescribeTable("refuses volumes whose volume indexes do not rise, and leaves the attachments unchanged",
		func(indexes []int, want string) {
			files := make([]*os.File, len(indexes))
			for i := range files {
				files[i] = openSizedFile(1 << 20)
			}
			pv := preparedFiles(files...)
			for i, n := range indexes {
				pv[i].Index = n
			}
			_, err := newGuestDrives(backend.VMQemu, pv, nil)
			Expect(err).To(MatchError(want))
			for _, v := range pv {
				Expect(v.Attachment.ID).To(BeEmpty())
			}
		},
		Entry("a negative index", []int{-1}, `the volume at "/data0" has the volume index -1, which does not follow the volume before it in volume order`),
		Entry("an index used twice", []int{1, 1}, `the volume at "/data1" has the volume index 1, which does not follow the volume before it in volume order`),
		Entry("an index that falls", []int{2, 1}, `the volume at "/data1" has the volume index 1, which does not follow the volume before it in volume order`),
	)

	Describe("checkPreparedOrder", func() {
		data := guestVolume{ContainerDir: "/data"}
		logs := guestVolume{ContainerDir: "/logs"}
		prepared := func(entries ...preparedVolume) preparedVolumes { return entries }

		It("accepts the volumes that are not shares, each at its volume index, in volume order", func() {
			Expect(checkPreparedOrder(nil, nil)).To(Succeed())
			Expect(checkPreparedOrder([]guestVolume{share("/shared")}, nil)).To(Succeed())
			Expect(checkPreparedOrder([]guestVolume{data, logs}, prepared(preparedVolume{Index: 0, Path: "/data"}, preparedVolume{Index: 1, Path: "/logs"}))).To(Succeed())
			Expect(checkPreparedOrder([]guestVolume{share("/a"), data, share("/b"), logs}, prepared(preparedVolume{Index: 1, Path: "/data"}, preparedVolume{Index: 3, Path: "/logs"}))).To(Succeed())
		})

		DescribeTable("refuses prepared disks that do not line up with the volumes",
			func(vols []guestVolume, pv preparedVolumes, want string) {
				Expect(checkPreparedOrder(vols, pv)).To(MatchError(want))
			},
			Entry("a volume with no disk", []guestVolume{data, logs}, prepared(preparedVolume{Index: 0, Path: "/data"}),
				`the volume at "/logs" (volume index 1) has no prepared disk`),
			Entry("a disk for the share", []guestVolume{share("/shared"), data}, prepared(preparedVolume{Index: 0, Path: "/shared"}, preparedVolume{Index: 1, Path: "/data"}),
				`the disk prepared for the volume at "/shared" (volume index 0) is in the place of the volume at "/data" (volume index 1), so the guest would mount it at the wrong path`),
			Entry("a disk numbered by its place among the disks", []guestVolume{share("/shared"), data}, prepared(preparedVolume{Index: 0, Path: "/data"}),
				`the disk prepared for the volume at "/data" (volume index 0) is in the place of the volume at "/data" (volume index 1), so the guest would mount it at the wrong path`),
			Entry("two disks in the wrong order", []guestVolume{data, logs}, prepared(preparedVolume{Index: 1, Path: "/logs"}, preparedVolume{Index: 0, Path: "/data"}),
				`the disk prepared for the volume at "/logs" (volume index 1) is in the place of the volume at "/data" (volume index 0), so the guest would mount it at the wrong path`),
			Entry("a disk past the last volume", []guestVolume{data}, prepared(preparedVolume{Index: 0, Path: "/data"}, preparedVolume{Index: 1, Path: "/logs"}),
				`the disk prepared for the volume at "/logs" (volume index 1) comes after the last volume that is not a share`),
		)
	})
})
