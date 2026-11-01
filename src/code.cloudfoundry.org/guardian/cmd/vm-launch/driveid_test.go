//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
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
)

// qemuImageDrives returns volume image drives of the given sizes, in volume
// order, with the serials QEMU gives them.
func qemuImageDrives(sizes ...int64) []guestDrive {
	drives := make([]guestDrive, len(sizes))
	for i, size := range sizes {
		drives[i] = guestDrive{id: qemuVolumeSerial(i), kind: driveImage, bytes: size}
	}
	return drives
}

// openSizedFile returns a new open sparse file of size bytes, closed when the
// spec ends.
func openSizedFile(size int64) *os.File {
	f, err := os.CreateTemp(GinkgoT().TempDir(), "drive")
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(f.Close)
	Expect(f.Truncate(size)).To(Succeed())
	return f
}

// preparedFiles returns prepared volumes at /data0, /data1, and so on, one for
// each file, as prepare would leave them.
func preparedFiles(files ...*os.File) preparedVolumes {
	var pv preparedVolumes
	for i, f := range files {
		info, err := f.Stat()
		Expect(err).NotTo(HaveOccurred())
		pv = append(pv, preparedVolume{Index: i, Path: "/data" + strconv.Itoa(i), Attachment: &attachment{File: f, Mode: attachFileImage, Release: func() error { return nil }}, Bytes: info.Size()})
	}
	return pv
}

// statID is the identity Firecracker derives from the numbers of a file's
// stat, before the cut to 20 bytes.
func statID(st *syscall.Stat_t) string {
	return strconv.FormatUint(uint64(st.Dev), 10) + strconv.FormatUint(uint64(st.Rdev), 10) + strconv.FormatUint(uint64(st.Ino), 10)
}

// withDriveStats makes driveFileStat give the numbers in stats, in turn, for
// the rest of the spec.
func withDriveStats(stats ...syscall.Stat_t) {
	saved := driveFileStat
	DeferCleanup(func() { driveFileStat = saved })
	next := 0
	driveFileStat = func(*os.File) (*syscall.Stat_t, error) {
		Expect(next).To(BeNumerically("<", len(stats)), "more drives than stats")
		st := stats[next]
		next++
		return &st, nil
	}
}

var _ = Describe("the QEMU serials", func() {
	It("names the root rvm-root and the volume at index N rvm-volN", func() {
		Expect(qemuRootSerial).To(Equal("rvm-root"))
		for i := range maxVolumes {
			Expect(qemuVolumeSerial(i)).To(Equal("rvm-vol" + strconv.Itoa(i)))
		}
	})

	It("gives every drive a guest can have a valid serial of its own", func() {
		named := []namedDriveID{{name: "root", id: qemuRootSerial}}
		for i := range maxVolumes {
			named = append(named, namedDriveID{name: volumeDriveID(i), id: qemuVolumeSerial(i)})
		}
		Expect(checkDriveIDs(named, "")).To(Succeed())
	})

	It("puts each serial on the device of its own drive, in the QEMU command line and in the identities alike", func() {
		for n := 0; n <= maxVolumes; n++ {
			files := make([]*os.File, n)
			for i := range files {
				files[i] = openSizedFile(int64(i+1) << 20)
			}
			drives, err := newGuestDrives(backend.VMQemu, preparedFiles(files...), openSizedFile(8<<20))
			Expect(err).NotTo(HaveOccurred())
			argv, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", procSelfFD(3+n), goldenMemMiB, taskNetwork(), drivePathsFor(n), procSelfFD(4+n), 0)
			Expect(err).NotTo(HaveOccurred())
			for i, d := range drives.volumes {
				Expect(optionAfter(argv, "-device", "drive="+volumeDriveID(i)+",")).To(Equal("virtio-blk-device,drive=" + volumeDriveID(i) + ",serial=" + d.id))
			}
			Expect(rootDeviceOption(argv)).To(Equal("virtio-blk-device,drive=root0,serial=" + drives.rootID))
			Expect(strings.Count(strings.Join(argv, " "), "serial=")).To(Equal(n + 1))
		}
	})
})

var _ = Describe("firecrackerDriveID", func() {
	It("runs the device, device type, and inode numbers of the open file together", func() {
		f := openSizedFile(1 << 20)
		var st syscall.Stat_t
		Expect(syscall.Stat(f.Name(), &st)).To(Succeed())
		id, err := firecrackerDriveID(f)
		Expect(err).NotTo(HaveOccurred())
		Expect(id).To(Equal(statID(&st)))
		Expect(st.Rdev).To(BeZero(), "a regular file has no device type")
	})

	It("follows the open file, not its name, so a file renamed or unlinked after the open keeps its identity", func() {
		f := openSizedFile(1 << 20)
		before, err := firecrackerDriveID(f)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.Remove(f.Name())).To(Succeed())
		Expect(os.WriteFile(f.Name(), []byte("another file"), 0o600)).To(Succeed())
		after, err := firecrackerDriveID(f)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
	})

	DescribeTable("gives what Firecracker v1.17.0 gives the guest",
		func(st syscall.Stat_t, want string) {
			withDriveStats(st)
			id, err := firecrackerDriveID(os.Stdin)
			Expect(err).NotTo(HaveOccurred())
			Expect(id).To(Equal(want))
		},
		// The lab cell's loop device node and image file, whose identities the
		// guest read back on four boots.
		Entry("a block device node on devtmpfs", syscall.Stat_t{Dev: 7, Rdev: 1794, Ino: 3911}, "717943911"),
		Entry("an image on the cell's data disk", syscall.Stat_t{Dev: 64772, Rdev: 0, Ino: 1831457}, "6477201831457"),
		Entry("numbers of all zero", syscall.Stat_t{}, "000"),
		Entry("exactly 20 digits", syscall.Stat_t{Dev: 1234567890, Rdev: 0, Ino: 123456789}, "12345678900123456789"),
		Entry("more than 20 digits, of which the first 20 count", syscall.Stat_t{Dev: 18446744073709551615, Rdev: 18446744073709551615, Ino: 18446744073709551615},
			"18446744073709551615"),
		Entry("a long inode cut short", syscall.Stat_t{Dev: 64772, Rdev: 0, Ino: 98765432109876543}, "64772098765432109876"),
	)

	It("fails without an open file", func() {
		_, err := firecrackerDriveID(nil)
		Expect(err).To(MatchError("no open file"))
	})

	It("passes on a stat that fails", func() {
		saved := driveFileStat
		DeferCleanup(func() { driveFileStat = saved })
		driveFileStat = func(*os.File) (*syscall.Stat_t, error) { return nil, syscall.EIO }
		_, err := firecrackerDriveID(os.Stdin)
		Expect(errors.Is(err, syscall.EIO)).To(BeTrue(), "%v", err)
	})

	It("fails on a closed file", func() {
		f, err := os.CreateTemp(GinkgoT().TempDir(), "drive")
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Close()).To(Succeed())
		_, err = firecrackerDriveID(f)
		Expect(errors.Is(err, os.ErrClosed)).To(BeTrue(), "%v", err)
	})
})

var _ = Describe("newGuestDrives", func() {
	It("gives QEMU's drives their serials, the volumes in volume order with their sizes", func() {
		vols := preparedFiles(openSizedFile(1<<20), openSizedFile(2<<20))
		drives, err := newGuestDrives(backend.VMQemu, vols, openSizedFile(8<<20))
		Expect(err).NotTo(HaveOccurred())
		Expect(drives).To(Equal(guestDrives{rootID: "rvm-root", volumes: []guestDrive{
			{id: "rvm-vol0", kind: driveImage, bytes: 1 << 20},
			{id: "rvm-vol1", kind: driveImage, bytes: 2 << 20},
		}}))
	})

	It("gives no root identity without a root image, and no drives without volumes", func() {
		drives, err := newGuestDrives(backend.VMQemu, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(drives).To(Equal(guestDrives{}))
		drives, err = newGuestDrives(backend.VMFirecracker, preparedFiles(openSizedFile(1<<20)), nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(drives.rootID).To(BeEmpty())
		Expect(drives.volumes).To(HaveLen(1))
	})

	It("predicts Firecracker's identity of every drive from the file the hypervisor gets", func() {
		files := []*os.File{openSizedFile(1 << 20), openSizedFile(2 << 20), openSizedFile(3 << 20), openSizedFile(4 << 20)}
		root := openSizedFile(8 << 20)
		drives, err := newGuestDrives(backend.VMFirecracker, preparedFiles(files...), root)
		Expect(err).NotTo(HaveOccurred())
		want := func(f *os.File) string {
			var st syscall.Stat_t
			Expect(syscall.Fstat(int(f.Fd()), &st)).To(Succeed())
			id := statID(&st)
			return id[:min(len(id), virtioBlockIDBytes)]
		}
		Expect(drives.volumes).To(HaveLen(4))
		for i, f := range files {
			Expect(drives.volumes[i]).To(Equal(guestDrive{id: want(f), kind: driveImage, bytes: int64(i+1) << 20}))
		}
		Expect(drives.rootID).To(Equal(want(root)))
	})

	It("refuses two Firecracker drives that would share an identity, naming both", func() {
		withDriveStats(syscall.Stat_t{Dev: 1, Ino: 23}, syscall.Stat_t{Dev: 1, Ino: 23})
		_, err := newGuestDrives(backend.VMFirecracker, preparedFiles(openSizedFile(1<<20), openSizedFile(1<<20)), nil)
		Expect(err).To(MatchError(`the volume at "/data0" and the volume at "/data1" would both have the drive identity "1023" on vm-firecracker, so the guest could not tell them apart`))
	})

	It("refuses a volume and the root whose numbers differ but run together into one identity", func() {
		// 12, 0, 3 and 1, 20, 3 both read 1203.
		withDriveStats(syscall.Stat_t{Dev: 12, Ino: 3}, syscall.Stat_t{Dev: 1, Rdev: 20, Ino: 3})
		_, err := newGuestDrives(backend.VMFirecracker, preparedFiles(openSizedFile(1<<20)), openSizedFile(8<<20))
		Expect(err).To(MatchError(`the volume at "/data0" and the guest root image would both have the drive identity "1203" on vm-firecracker, so the guest could not tell them apart`))
	})

	It("refuses two drives whose identities differ only past the cut", func() {
		withDriveStats(syscall.Stat_t{Dev: 64772, Ino: 9876543210987654321}, syscall.Stat_t{Dev: 64772, Ino: 9876543210987654322})
		_, err := newGuestDrives(backend.VMFirecracker, preparedFiles(openSizedFile(1<<20), openSizedFile(1<<20)), nil)
		Expect(err).To(MatchError(`the volume at "/data0" and the volume at "/data1" would both have the drive identity "64772098765432109876" on vm-firecracker, so the guest could not tell them apart`))
	})

	It("passes on a stat that fails, naming the drive", func() {
		saved := driveFileStat
		DeferCleanup(func() { driveFileStat = saved })
		driveFileStat = func(*os.File) (*syscall.Stat_t, error) { return nil, syscall.EIO }
		_, err := newGuestDrives(backend.VMFirecracker, preparedFiles(openSizedFile(1<<20)), nil)
		Expect(err).To(MatchError(`predicting the vm-firecracker drive identity of the volume at "/data0": ` + syscall.EIO.Error()))
		Expect(errors.Is(err, syscall.EIO)).To(BeTrue())
		_, err = newGuestDrives(backend.VMFirecracker, nil, openSizedFile(8<<20))
		Expect(err).To(MatchError(`predicting the vm-firecracker drive identity of the guest root image: ` + syscall.EIO.Error()))
	})

	Describe("with the stack and droplet images", func() {
		It("gives QEMU's stack and droplet their serials after the volumes and the root", func() {
			sd := &stackDrives{stack: openSizedFile(1 << 20), droplet: openSizedFile(2 << 20)}
			drives, err := newGuestDrivesWithStack(backend.VMQemu, preparedFiles(openSizedFile(1<<20)), openSizedFile(8<<20), sd)
			Expect(err).NotTo(HaveOccurred())
			Expect(drives).To(Equal(guestDrives{
				rootID:    "rvm-root",
				volumes:   qemuImageDrives(1 << 20),
				stackID:   "rvm-stack",
				dropletID: "rvm-droplet",
			}))
		})

		It("predicts Firecracker's identity of each from its open file", func() {
			sd := &stackDrives{stack: openSizedFile(1 << 20), droplet: openSizedFile(2 << 20)}
			drives, err := newGuestDrivesWithStack(backend.VMFirecracker, nil, openSizedFile(8<<20), sd)
			Expect(err).NotTo(HaveOccurred())
			want := func(f *os.File) string {
				id, err := firecrackerDriveID(f)
				Expect(err).NotTo(HaveOccurred())
				return id
			}
			Expect(drives.stackID).To(Equal(want(sd.stack)))
			Expect(drives.dropletID).To(Equal(want(sd.droplet)))
			Expect(drives.stackID).NotTo(Equal(drives.dropletID))
		})

		It("gives the same result as newGuestDrives for a nil stackDrives", func() {
			for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
				vols := preparedFiles(openSizedFile(1 << 20))
				root := openSizedFile(8 << 20)
				plain, err := newGuestDrives(kind, vols, root)
				Expect(err).NotTo(HaveOccurred())
				with, err := newGuestDrivesWithStack(kind, vols, root, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(with).To(Equal(plain))
				Expect(with.stackID).To(BeEmpty())
				Expect(with.dropletID).To(BeEmpty())
			}
		})

		It("refuses a stack that shares an identity with a volume, naming both", func() {
			withDriveStats(syscall.Stat_t{Dev: 1, Ino: 23}, syscall.Stat_t{Dev: 1, Ino: 23}, syscall.Stat_t{Dev: 1, Ino: 24})
			sd := &stackDrives{stack: openSizedFile(1 << 20), droplet: openSizedFile(1 << 20)}
			_, err := newGuestDrivesWithStack(backend.VMFirecracker, preparedFiles(openSizedFile(1<<20)), nil, sd)
			Expect(err).To(MatchError(`the volume at "/data0" and the stack image would both have the drive identity "1023" on vm-firecracker, so the guest could not tell them apart`))
		})

		It("refuses a droplet that shares an identity with the stack, naming both", func() {
			withDriveStats(syscall.Stat_t{Dev: 1, Ino: 23}, syscall.Stat_t{Dev: 1, Ino: 23})
			sd := &stackDrives{stack: openSizedFile(1 << 20), droplet: openSizedFile(1 << 20)}
			_, err := newGuestDrivesWithStack(backend.VMFirecracker, nil, nil, sd)
			Expect(err).To(MatchError(`the stack image and the droplet image would both have the drive identity "1023" on vm-firecracker, so the guest could not tell them apart`))
		})

		It("refuses a stack or a droplet without an open file", func() {
			_, err := newGuestDrivesWithStack(backend.VMQemu, nil, nil, &stackDrives{droplet: openSizedFile(1 << 20)})
			Expect(err).To(MatchError("the stack image has no open disk to identify"))
			_, err = newGuestDrivesWithStack(backend.VMQemu, nil, nil, &stackDrives{stack: openSizedFile(1 << 20)})
			Expect(err).To(MatchError("the droplet image has no open disk to identify"))
		})

		It("passes on a stat that fails, naming the drive", func() {
			saved := driveFileStat
			DeferCleanup(func() { driveFileStat = saved })
			driveFileStat = func(*os.File) (*syscall.Stat_t, error) { return nil, syscall.EIO }
			sd := &stackDrives{stack: openSizedFile(1 << 20), droplet: openSizedFile(1 << 20)}
			_, err := newGuestDrivesWithStack(backend.VMFirecracker, nil, nil, sd)
			Expect(err).To(MatchError(`predicting the vm-firecracker drive identity of the stack image: ` + syscall.EIO.Error()))
		})

		It("names valid serials", func() {
			Expect(checkDriveIDs([]namedDriveID{{name: "stack", id: qemuStackSerial}, {name: "droplet", id: qemuDropletSerial}}, "")).To(Succeed())
		})
	})

	It("refuses a volume without an open disk", func() {
		_, err := newGuestDrives(backend.VMQemu, preparedVolumes{{Path: "/data"}}, nil)
		Expect(err).To(MatchError(`the volume at "/data" has no open disk to identify`))
		_, err = newGuestDrives(backend.VMFirecracker, preparedVolumes{{Path: "/data", Attachment: &attachment{}}}, nil)
		Expect(err).To(MatchError(`the volume at "/data" has no open disk to identify`))
	})

	It("refuses more volumes than a guest can have", func() {
		files := make([]*os.File, maxVolumes+1)
		for i := range files {
			files[i] = openSizedFile(1 << 20)
		}
		_, err := newGuestDrives(backend.VMQemu, preparedFiles(files...), nil)
		Expect(err).To(MatchError("5 volume drives, over the 4 a guest can have"))
	})

	It("refuses a backend that is not a VM", func() {
		_, err := newGuestDrives(backend.OCIRunc, nil, nil)
		Expect(err).To(MatchError(fmt.Sprintf("unsupported backend %q for drive identities", backend.OCIRunc)))
	})
})

var _ = Describe("checkDriveIDs", func() {
	DescribeTable("refuses an identity the guest could not read back or match",
		func(id, want string) {
			Expect(checkDriveIDs([]namedDriveID{{name: "drive vol0", id: id}}, "")).To(MatchError(want))
		},
		Entry("an empty one", "", "drive vol0 has no drive identity, so the guest could not find it"),
		Entry("one of 21 bytes", "123456789012345678901",
			`the drive identity "123456789012345678901" of drive vol0 is not 1 to 20 letters, digits, and hyphens, so the guest could not match it`),
		Entry("one with a comma, which would end a QEMU option", "rvm,vol0",
			`the drive identity "rvm,vol0" of drive vol0 is not 1 to 20 letters, digits, and hyphens, so the guest could not match it`),
		Entry("one with a space", "rvm vol0", `the drive identity "rvm vol0" of drive vol0 is not 1 to 20 letters, digits, and hyphens, so the guest could not match it`),
		Entry("one with a quote", "rvm'vol0", `the drive identity "rvm'vol0" of drive vol0 is not 1 to 20 letters, digits, and hyphens, so the guest could not match it`),
		Entry("one with a newline", "rvm\nvol0", `the drive identity "rvm\nvol0" of drive vol0 is not 1 to 20 letters, digits, and hyphens, so the guest could not match it`),
		Entry("one with a shell expansion", "$(reboot)", `the drive identity "$(reboot)" of drive vol0 is not 1 to 20 letters, digits, and hyphens, so the guest could not match it`),
		Entry("one with a byte outside ASCII", "rvm-volé", `the drive identity "rvm-volé" of drive vol0 is not 1 to 20 letters, digits, and hyphens, so the guest could not match it`),
	)

	It("accepts identities of 1 and of 20 bytes in letters, digits, and hyphens", func() {
		Expect(checkDriveIDs([]namedDriveID{{name: "a", id: "x"}, {name: "b", id: "Az09-zZ-12345678901"}, {name: "c", id: "12345678901234567890"}}, "")).To(Succeed())
		Expect(checkDriveIDs(nil, "")).To(Succeed())
	})

	It("refuses the second drive that shares an identity, naming the first", func() {
		err := checkDriveIDs([]namedDriveID{{name: "a", id: "rvm-vol0"}, {name: "b", id: "rvm-vol1"}, {name: "c", id: "rvm-vol0"}}, " on vm-qemu")
		Expect(err).To(MatchError(`a and c would both have the drive identity "rvm-vol0" on vm-qemu, so the guest could not tell them apart`))
	})
})

var _ = Describe("the drive identities in /rvm/disks", func() {
	// vols returns n guest volumes, one for each volume drive.
	vols := func(n int) []guestVolume {
		var vs []guestVolume
		for i := range n {
			vs = append(vs, guestVolume{ContainerDir: "/data" + strconv.Itoa(i), ImageName: "rvm-disk-0.img"})
		}
		return vs
	}

	guest := func(rootID string, drives ...guestDrive) guestContents {
		g := taskGuest("true")
		g.rootBytes, g.rootInodeRatio = 64*bytesPerMiB, 16384
		g.drives = guestDrives{rootID: rootID, volumes: drives}
		g.vols = vols(len(drives))
		return g
	}

	It("names the root and every volume, in volume order, by identity, kind, and size, and sources in the guest's shell", func() {
		g := guest("rvm-root", qemuImageDrives(defaultImageSize, 2*defaultImageSize, defaultImageSize)...)
		got, err := disksFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=131072\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUMES=3\n" +
			"RVM_VOL0_KIND=image\nRVM_VOL0_ID=rvm-vol0\nRVM_VOL0_SECTORS=2097152\n" +
			"RVM_VOL1_KIND=image\nRVM_VOL1_ID=rvm-vol1\nRVM_VOL1_SECTORS=4194304\n" +
			"RVM_VOL2_KIND=image\nRVM_VOL2_ID=rvm-vol2\nRVM_VOL2_SECTORS=2097152\n"))

		out, err := exec.Command("/bin/sh", "-c", `set -eu; . "$1"; printf '%s|' "$RVM_ROOT_ID" "$RVM_VOLUMES" "$RVM_VOL0_ID" "$RVM_VOL1_KIND" "$RVM_VOL1_SECTORS" "$RVM_VOL2_ID"`, "sh", writeTempFile("disks", got)).CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(out))
		Expect(string(out)).To(Equal("rvm-root|3|rvm-vol0|image|4194304|rvm-vol2|"))
	})

	It("names Firecracker's predicted identities as they are", func() {
		g := guest("6477201831457", guestDrive{id: "717943911", kind: driveImage, bytes: defaultImageSize})
		got, err := disksFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("RVM_ROOT_ID=6477201831457\nRVM_ROOT_SECTORS=131072\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUMES=1\n" +
			"RVM_VOL0_KIND=image\nRVM_VOL0_ID=717943911\nRVM_VOL0_SECTORS=2097152\n"))
	})

	It("names four volumes without a root", func() {
		g := guest("", qemuImageDrives(defaultImageSize, defaultImageSize, defaultImageSize, defaultImageSize)...)
		g.rootBytes, g.rootInodeRatio = 0, 0
		got, err := disksFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HavePrefix("RVM_VOLUMES=4\nRVM_VOL0_KIND=image\n"))
		Expect(got).To(ContainSubstring("RVM_VOL3_ID=rvm-vol3\nRVM_VOL3_SECTORS=2097152\n"))
		Expect(strings.Count(got, "_KIND=")).To(Equal(4))
	})

	It("names a volume of the root's size, and volumes of one size, since the guest tells drives apart by identity alone", func() {
		g := guest("rvm-root", qemuImageDrives(64*bytesPerMiB, 64*bytesPerMiB)...)
		got, err := disksFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=131072\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUMES=2\n" +
			"RVM_VOL0_KIND=image\nRVM_VOL0_ID=rvm-vol0\nRVM_VOL0_SECTORS=131072\n" +
			"RVM_VOL1_KIND=image\nRVM_VOL1_ID=rvm-vol1\nRVM_VOL1_SECTORS=131072\n"))
	})

	DescribeTable("refuses drives the guest could not find or tell apart, so no initramfs is built",
		func(g guestContents, want string) {
			_, err := disksFile(g)
			Expect(err).To(MatchError(want))

			bb := filepath.Join(GinkgoT().TempDir(), "busybox")
			Expect(os.WriteFile(bb, []byte("busybox"), 0o755)).To(Succeed())
			held := heldInitramfs()
			_, err = newInitramfs(bb, g)
			Expect(err).To(MatchError("writing the initramfs: " + want))
			Expect(heldInitramfs()).To(Equal(held))
		},
		Entry("a root image without an identity", guest(""), "the guest root image has no drive identity, so the guest could not find it"),
		Entry("a root identity without a root image", func() guestContents {
			g := guest("rvm-root")
			g.rootBytes, g.rootInodeRatio = 0, 0
			return g
		}(), `a drive identity "rvm-root" for no guest root image`),
		Entry("a volume without an identity", guest("rvm-root", guestDrive{kind: driveImage, bytes: defaultImageSize}), "drive vol0 has no drive identity, so the guest could not find it"),
		Entry("a volume whose identity the guest could not match", guest("rvm-root", guestDrive{id: "vol 0", kind: driveImage, bytes: defaultImageSize}),
			`the drive identity "vol 0" of drive vol0 is not 1 to 20 letters, digits, and hyphens, so the guest could not match it`),
		Entry("two volumes of one identity", guest("rvm-root", guestDrive{id: "rvm-vol0", kind: driveImage, bytes: defaultImageSize}, guestDrive{id: "rvm-vol0", kind: driveImage, bytes: defaultImageSize}),
			`drive vol0 and drive vol1 would both have the drive identity "rvm-vol0", so the guest could not tell them apart`),
		Entry("a volume with the root's identity", guest("7123", guestDrive{id: "7123", kind: driveImage, bytes: defaultImageSize}),
			`the guest root image and drive vol0 would both have the drive identity "7123", so the guest could not tell them apart`),
		Entry("a volume of a kind the guest does not support", guest("rvm-root", guestDrive{id: "rvm-vol0", kind: "share", bytes: defaultImageSize}),
			`drive vol0 holds a "share", and the guest supports only "image" and "block" volume drives`),
		Entry("a later volume that is not whole sectors", guest("rvm-root", qemuImageDrives(defaultImageSize, defaultImageSize+1)...),
			"the volume image of 1073741825 bytes on drive vol1 is not a positive whole number of 512-byte sectors"),
		Entry("more volumes than a guest can have", guest("rvm-root", qemuImageDrives(1<<30, 1<<30, 1<<30, 1<<30, 1<<30)...),
			"5 volume drives, over the 4 a guest can have"),
		Entry("volume drives for a guest without a volume", func() guestContents {
			g := guest("rvm-root", qemuImageDrives(defaultImageSize)...)
			g.vols = nil
			return g
		}(), "1 volume drives for 0 guest volumes"),
		Entry("a guest volume without a volume drive", func() guestContents {
			g := guest("rvm-root")
			g.vols = vols(1)
			return g
		}(), "0 volume drives for 1 guest volumes"),
		Entry("fewer volume drives than guest volumes", func() guestContents {
			g := guest("rvm-root", qemuImageDrives(defaultImageSize, defaultImageSize)...)
			g.vols = vols(3)
			return g
		}(), "2 volume drives for 3 guest volumes"),
	)
})

var _ = Describe("run with drives that would share an identity", func() {
	var (
		art    string
		tmp    string
		volDir string
		img    string
		logBuf *bytes.Buffer
	)

	BeforeEach(func() {
		requireOpenat2()
		art = makeArtifacts()
		volDir = GinkgoT().TempDir()
		img = filepath.Join(volDir, "rvm-disk-"+testAppID+"-web-2.img")
		tmp = GinkgoT().TempDir()
		DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)
		mountInfoPath = writeTempFile("mountinfo", mountinfoLine(40, volDir, "fuse.juicefs"))
		GinkgoT().Setenv("TMPDIR", tmp)
		GinkgoT().Setenv("CF_INSTANCE_INDEX", "2")
		// A guest of 320 MiB, which logs no line about its memory.
		GinkgoT().Setenv("MEMORY_LIMIT", "512m")
		GinkgoT().Setenv("VCAP_APPLICATION", `{"application_id":"`+testAppID+`","process_type":"web","name":"app","limits":{"disk":64}}`)
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"juicefs": {mountJSON(volDir, "rw")}}))
		logBuf = &bytes.Buffer{}

		saved := defaultImageOptions
		DeferCleanup(func() { defaultImageOptions = saved })
		defaultImageOptions.IsMountRoot = alwaysMountRoot
		defaultImageOptions.LockWait = 300 * time.Millisecond
		defaultImageOptions.LockPoll = 20 * time.Millisecond
	})

	It("exits 125 on Firecracker before the hypervisor starts, and lets go of the volume", func() {
		withDriveStats(syscall.Stat_t{Dev: 1, Ino: 23}, syscall.Stat_t{Dev: 1, Ino: 23})
		argvFile := writeFakeHypervisor(filepath.Join(art, "firecracker/firecracker"), "")
		code := run([]string{"--backend", string(backend.VMFirecracker), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}, log.New(logBuf, "", 0))
		Expect(code).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal(`the volume at ` + strconv.Quote(volDir) + ` and the guest root image would both have the drive identity "1023" on vm-firecracker, so the guest could not tell them apart` + "\n"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(lockedElsewhere(img)).To(BeFalse(), "the lock ends with the run")
		entries, err := os.ReadDir(tmp)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty())
	})
})
