//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// guestBusyboxEnv names the busybox binary that the VM guests run, for the
// specs that need the guest's own shell. That binary comes from Ubuntu's
// busybox-static 1:1.37.0-7ubuntu1 amd64 package, and guestBusyboxSHA256 is
// its sha256.
const (
	guestBusyboxEnv    = "VM_LAUNCH_GUEST_BUSYBOX"
	guestBusyboxSHA256 = "df12634c17fcdca839ae5dc47d7627b7558511f7645de7c99ccf097a0f28ed5b"
)

// guestBusybox returns the path guestBusyboxEnv names, or skips the spec
// when it is unset. The skip names the variable, and Ginkgo lists it in a
// verbose run, but it does not fail the run, so a release check must set the
// variable and confirm that these specs ran. No other shell can stand in,
// because the host's /bin/sh may be dash, which lacks the `read -t` and
// `read -u` that the watcher's pause uses. Without the variable, the golden
// /init text spec alone guards the pause, and the spec that times two pauses
// does not run. A file that is not the guest's busybox fails the spec,
// because another build behaves differently: Debian's and busybox.net's
// builds import environment names that the guest's build drops.
func guestBusybox() string {
	path := os.Getenv(guestBusyboxEnv)
	if path == "" {
		Skip(guestBusyboxEnv + " is not set; point it at the guest's busybox, from Ubuntu's busybox-static 1:1.37.0-7ubuntu1 amd64 package (sha256 " + guestBusyboxSHA256 + "), to run this check against the guest's shell")
	}
	raw, err := os.ReadFile(path)
	Expect(err).NotTo(HaveOccurred(), "reading %s %s", guestBusyboxEnv, path)
	sum := sha256.Sum256(raw)
	Expect(hex.EncodeToString(sum[:])).To(Equal(guestBusyboxSHA256), "%s names %s, which is not the guest's busybox", guestBusyboxEnv, path)
	return path
}

var _ = Describe("stage 1's tools in the guest's busybox", func() {
	// scanDrives is what stage 1 sets up for rvm_scan from a /rvm/disks
	// that names a 64 MiB root and a 1 GiB volume by their QEMU serials.
	const scanDrives = "rvm_drives=\"root vol0\"\n" +
		"rvm_want_root=rvm-root rvm_sectors_root=131072 rvm_label_root=\"guest root drive\"\n" +
		"rvm_want_vol0=rvm-vol0 rvm_sectors_vol0=2097152 rvm_label_vol0=\"volume drive vol0\"\n"

	// stackScanDrives adds to scanDrives the stack and droplet drives, which
	// have no size, as stage 1 of a guest with a stack sets them up.
	const stackScanDrives = scanDrives + "rvm_drives=\"$rvm_drives stack droplet\"\n" +
		"rvm_want_stack=rvm-stack rvm_sectors_stack= rvm_label_stack=\"stack image drive\"\n" +
		"rvm_want_droplet=rvm-droplet rvm_sectors_droplet= rvm_label_droplet=\"droplet image drive\"\n"

	// run runs script in the guest's busybox, with rvm_fail's reboot
	// replaced by a line that says so, and returns what it printed and its
	// exit status.
	run := func(script string) (string, int) {
		out, err := exec.Command(guestBusybox(), "sh", "-c", strings.Replace(guestFailFunc, "reboot -nf", "echo REBOOT", 1)+script).CombinedOutput()
		if err != nil {
			exitErr, ok := err.(*exec.ExitError)
			Expect(ok).To(BeTrue(), "%v: %s", err, out)
			return string(out), exitErr.ExitCode()
		}
		return string(out), 0
	}

	// onTree points the drive search text at the sysfs tree sys and at the
	// device files in dev in place of /dev.
	onTree := func(text, sys, dev string) string {
		return strings.NewReplacer("/sys/block/", sys+"/", "/dev/${rvm_b", dev+"/${rvm_b").Replace(text)
	}

	// scanWith runs rvm_scan from diskFunc once in the guest's busybox for
	// drives, against the sysfs tree sys, with the device files in dev in
	// place of /dev, and returns what it printed and set, and its exit
	// status.
	scanWith := func(diskFunc, drives, sys, dev string) (string, int) {
		return run(onTree(diskFunc, sys, dev) + drives +
			`rvm_scan; echo "status=$? root=${rvm_dev_root:-} vol0=${rvm_dev_vol0:-}${rvm_want_stack:+ stack=$rvm_dev_stack droplet=$rvm_dev_droplet} missing=$rvm_missing"`)
	}

	// scan is scanWith for the rvm.6 guest's rvm_scan and drives.
	scan := func(sys, dev string) (string, int) { return scanWith(guestDiskFunc, scanDrives, sys, dev) }

	// sysDisk adds the block device name to the sysfs tree sys with the
	// identity serial, written without a newline as virtio_blk gives it,
	// and size sectors.
	sysDisk := func(sys, name, serial, sectors string) {
		Expect(os.MkdirAll(filepath.Join(sys, name), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(sys, name, "serial"), []byte(serial), 0o444)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(sys, name, "size"), []byte(sectors+"\n"), 0o444)).To(Succeed())
	}

	// blockNodes returns a directory that holds a block device node for each
	// of names, or skips the spec where the process may not create them.
	blockNodes := func(names ...string) string {
		dev := GinkgoT().TempDir()
		for _, name := range names {
			if err := unix.Mknod(filepath.Join(dev, name), unix.S_IFBLK|0o600, int(unix.Mkdev(7, 0))); err != nil {
				Skip("this process cannot create a block device node: " + err.Error())
			}
		}
		return dev
	}

	It("finds each drive by the serial its device has, in either device order, and looks at vd devices only", func() {
		dev := blockNodes("vda", "vdb")
		for _, order := range [][2]string{{"rvm-vol0", "rvm-root"}, {"rvm-root", "rvm-vol0"}} {
			sys := GinkgoT().TempDir()
			sizes := map[string]string{"rvm-root": "131072", "rvm-vol0": "2097152"}
			sysDisk(sys, "vda", order[0], sizes[order[0]])
			sysDisk(sys, "vdb", order[1], sizes[order[1]])
			// A loop device with the root's identity is no vd device.
			sysDisk(sys, "loop0", "rvm-root", "131072")
			at := map[string]string{order[0]: dev + "/vda", order[1]: dev + "/vdb"}
			out, code := scan(sys, dev)
			Expect(code).To(Equal(0), out)
			Expect(out).To(Equal("status=0 root=" + at["rvm-root"] + " vol0=" + at["rvm-vol0"] + " missing=\n"))
		}
	})

	It("does not take a drive as found until its device node is a block device", func() {
		sys := GinkgoT().TempDir()
		sysDisk(sys, "vda", "rvm-vol0", "2097152")
		sysDisk(sys, "vdb", "rvm-root", "131072")

		missing := GinkgoT().TempDir()
		want := "status=1 root=" + missing + "/vdb vol0=" + missing + "/vda missing=no device node " + missing + "/vda yet for the volume drive vol0, and no device node " + missing + "/vdb yet for the guest root drive\n"
		out, _ := scan(sys, missing)
		Expect(out).To(Equal(want))

		// A regular file is no block device.
		for _, name := range []string{"vda", "vdb"} {
			Expect(os.WriteFile(filepath.Join(missing, name), nil, 0o600)).To(Succeed())
		}
		out, _ = scan(sys, missing)
		Expect(out).To(Equal(want))

		dev := blockNodes("vda", "vdb")
		out, code := scan(sys, dev)
		Expect(code).To(Equal(0), out)
		Expect(out).To(Equal("status=0 root=" + dev + "/vdb vol0=" + dev + "/vda missing=\n"))
	})

	It("checks again when a serial cannot be read, and says which device and drive it waits for", func() {
		sys := GinkgoT().TempDir()
		sysDisk(sys, "vda", "rvm-vol0", "2097152")
		sysDisk(sys, "vdb", "rvm-root", "131072")
		// vdb's serial is a directory, which no user can read as a file.
		serial := filepath.Join(sys, "vdb", "serial")
		Expect(os.Remove(serial)).To(Succeed())
		Expect(os.Mkdir(serial, 0o755)).To(Succeed())
		dev := blockNodes("vda", "vdb")
		out, _ := scan(sys, dev)
		Expect(out).To(Equal("status=1 root= vol0=" + dev + "/vda missing=no readable identity yet on the block device " + dev + "/vdb, and no block device with the identity rvm-root for the guest root drive\n"))
	})

	DescribeTable("fails the boot at once on a device no drive owns, two devices of one drive, or a drive of another size",
		func(serials [3]string, sizes [3]string, line string) {
			sys := GinkgoT().TempDir()
			for i, name := range []string{"vda", "vdb", "vdc"} {
				if serials[i] != "-" {
					sysDisk(sys, name, serials[i], sizes[i])
				}
			}
			// The device directory is the real /dev, so the lines name
			// the devices as the guest does; every case fails before any
			// device node is looked at.
			out, code := scan(sys, "/dev")
			Expect(code).To(Equal(1), out)
			Expect(out).To(Equal("vm-launch guest setup: " + line + "\nREBOOT\n"))
		},
		Entry("a device with an identity no drive has", [3]string{"rvm-root", "rvm-vol0", "rvm-vol1"}, [3]string{"131072", "2097152", "2097152"},
			"the block device /dev/vdc has the identity rvm-vol1, which /rvm/disks gives no drive, so the guest will not boot with it"),
		Entry("a device without an identity", [3]string{"", "rvm-root", "rvm-vol0"}, [3]string{"2097152", "131072", "2097152"},
			"the block device /dev/vda has no identity, so it is no drive /rvm/disks names, and the guest will not boot with it"),
		Entry("an identity that differs from a drive's by a space", [3]string{"rvm-root ", "rvm-vol0", "-"}, [3]string{"131072", "2097152", ""},
			"the block device /dev/vda has the identity rvm-root , which /rvm/disks gives no drive, so the guest will not boot with it"),
		Entry("two devices with the root's identity", [3]string{"rvm-root", "rvm-root", "rvm-vol0"}, [3]string{"131072", "131072", "2097152"},
			"two block devices, /dev/vda and /dev/vdb, have the identity rvm-root of the guest root drive, so the guest cannot tell which one it is"),
		Entry("a root of the volume's size", [3]string{"rvm-root", "rvm-vol0", "-"}, [3]string{"2097152", "2097152", ""},
			"the guest root drive /dev/vda has 2097152 sectors, and /rvm/disks gives it 131072, so the guest will not use it"),
	)

	It("finds the rvm.6 drives alone with the stack guest's rvm_scan as the rvm.6 guest's finds them", func() {
		dev := blockNodes("vda", "vdb")
		sys := GinkgoT().TempDir()
		sysDisk(sys, "vda", "rvm-vol0", "2097152")
		sysDisk(sys, "vdb", "rvm-root", "131072")
		want := "status=0 root=" + dev + "/vdb vol0=" + dev + "/vda missing=\n"
		for _, diskFunc := range []string{guestDiskFunc, guestStackDiskFunc} {
			out, code := scanWith(diskFunc, scanDrives, sys, dev)
			Expect(code).To(Equal(0), out)
			Expect(out).To(Equal(want))
		}
	})

	It("finds the stack and droplet drives by their serials whatever their sizes, and still checks the sizes of the root and the volume", func() {
		dev := blockNodes("vda", "vdb", "vdc", "vdd")
		sys := GinkgoT().TempDir()
		sysDisk(sys, "vda", "rvm-droplet", "8")
		sysDisk(sys, "vdb", "rvm-root", "131072")
		sysDisk(sys, "vdc", "rvm-stack", "1234567")
		sysDisk(sys, "vdd", "rvm-vol0", "2097152")
		out, code := scanWith(guestStackDiskFunc, stackScanDrives, sys, dev)
		Expect(code).To(Equal(0), out)
		Expect(out).To(Equal("status=0 root=" + dev + "/vdb vol0=" + dev + "/vdd stack=" + dev + "/vdc droplet=" + dev + "/vda missing=\n"))

		Expect(os.WriteFile(filepath.Join(sys, "vdb", "size"), []byte("131080\n"), 0o444)).To(Succeed())
		out, code = scanWith(guestStackDiskFunc, stackScanDrives, sys, dev)
		Expect(code).To(Equal(1), out)
		Expect(out).To(Equal("vm-launch guest setup: the guest root drive " + dev + "/vdb has 131080 sectors, and /rvm/disks gives it 131072, so the guest will not use it\nREBOOT\n"))
	})

	It("waits for a stack drive that has not appeared and names it", func() {
		dev := blockNodes("vda", "vdb", "vdc")
		sys := GinkgoT().TempDir()
		sysDisk(sys, "vda", "rvm-root", "131072")
		sysDisk(sys, "vdb", "rvm-vol0", "2097152")
		sysDisk(sys, "vdc", "rvm-droplet", "8")
		out, code := scanWith(guestStackDiskFunc, stackScanDrives, sys, dev)
		Expect(code).To(Equal(0), out)
		Expect(out).To(Equal("status=1 root=" + dev + "/vda vol0=" + dev + "/vdb stack= droplet=" + dev + "/vdc missing=no block device with the identity rvm-stack for the stack image drive\n"))
	})

	DescribeTable("fails the boot of a guest with a stack at once on a device no drive owns or two devices of one drive",
		func(drives string, serials []string, line string) {
			// The root and the volume have their own sizes, and every other
			// device has one that no drive's size check would take.
			sizes := map[string]string{"rvm-root": "131072", "rvm-vol0": "2097152"}
			sys := GinkgoT().TempDir()
			for i, serial := range serials {
				size, ok := sizes[serial]
				if !ok {
					size = "8"
				}
				sysDisk(sys, "vd"+string(rune('a'+i)), serial, size)
			}
			out, code := scanWith(guestStackDiskFunc, drives, sys, "/dev")
			Expect(code).To(Equal(1), out)
			Expect(out).To(Equal("vm-launch guest setup: " + line + "\nREBOOT\n"))
		},
		Entry("an unnamed drive besides the rvm.6 drives", scanDrives, []string{"rvm-root", "rvm-vol0", "rvm-stack"},
			"the block device /dev/vdc has the identity rvm-stack, which /rvm/disks gives no drive, so the guest will not boot with it"),
		Entry("an unnamed drive besides the stack and droplet drives", stackScanDrives, []string{"rvm-root", "rvm-vol0", "rvm-stack", "rvm-droplet", "rvm-vol1"},
			"the block device /dev/vde has the identity rvm-vol1, which /rvm/disks gives no drive, so the guest will not boot with it"),
		Entry("a device without an identity besides the stack and droplet drives", stackScanDrives, []string{"rvm-stack", ""},
			"the block device /dev/vdb has no identity, so it is no drive /rvm/disks names, and the guest will not boot with it"),
		Entry("two devices with the stack's identity", stackScanDrives, []string{"rvm-stack", "rvm-stack"},
			"two block devices, /dev/vda and /dev/vdb, have the identity rvm-stack of the stack image drive, so the guest cannot tell which one it is"),
	)

	// stackFind runs the stack guest's whole drive search in the guest's
	// busybox for the /rvm/disks text disks, against the sysfs tree sys and
	// the device files in dev, and returns what it printed and its exit
	// status. It prints the devices it leaves and its positional arguments.
	stackFind := func(disks, sys, dev string) (string, int) {
		find := strings.Replace(onTree(guestStackDiskFind, sys, dev), ". /rvm/disks\n", ". "+shellQuote(writeTempFile("disks", disks))+"\n", 1)
		return run(find + `echo "root=$rvm_root stack=$rvm_stack droplet=$rvm_droplet args=$#:$*"`)
	}

	It("reads the stack and droplet identities from /rvm/disks and leaves their devices for the app root's mounts", func() {
		dev := blockNodes("vda", "vdb", "vdc")
		sys := GinkgoT().TempDir()
		sysDisk(sys, "vda", "rvm-stack", "40")
		sysDisk(sys, "vdb", "rvm-root", "131072")
		sysDisk(sys, "vdc", "rvm-droplet", "8")
		out, code := stackFind("RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=131072\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUMES=0\nRVM_STACK_ID=rvm-stack\nRVM_DROPLET_ID=rvm-droplet\n", sys, dev)
		Expect(code).To(Equal(0), out)
		Expect(out).To(Equal("root=" + dev + "/vdb stack=" + dev + "/vda droplet=" + dev + "/vdc args=0:\n"))

		// Without a root disk, the app root's upper layer is in RAM.
		Expect(os.RemoveAll(filepath.Join(sys, "vdb"))).To(Succeed())
		out, code = stackFind("RVM_VOLUMES=0\nRVM_STACK_ID=rvm-stack\nRVM_DROPLET_ID=rvm-droplet\n", sys, dev)
		Expect(code).To(Equal(0), out)
		Expect(out).To(Equal("root= stack=" + dev + "/vda droplet=" + dev + "/vdc args=0:\n"))
	})

	DescribeTable("fails the boot of a guest with a stack before it looks at a device when /rvm/disks cannot name the stack and droplet drives",
		func(disks, line string) {
			out, code := stackFind(disks, GinkgoT().TempDir(), "/dev")
			Expect(code).To(Equal(1), out)
			Expect(out).To(Equal("vm-launch guest setup: " + line + "\nREBOOT\n"))
		},
		Entry("no stack identity", "RVM_VOLUMES=0\nRVM_DROPLET_ID=rvm-droplet\n",
			"the stack image drive's identity in /rvm/disks is not 1 to 20 letters, digits, and hyphens"),
		Entry("no droplet identity", "RVM_VOLUMES=0\nRVM_STACK_ID=rvm-stack\n",
			"the droplet image drive's identity in /rvm/disks is not 1 to 20 letters, digits, and hyphens"),
		Entry("a droplet identity the guest cannot match", "RVM_VOLUMES=0\nRVM_STACK_ID=rvm-stack\nRVM_DROPLET_ID='rvm droplet'\n",
			"the droplet image drive's identity in /rvm/disks is not 1 to 20 letters, digits, and hyphens"),
		Entry("the stack with the root's identity", "RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=131072\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUMES=0\nRVM_STACK_ID=rvm-root\nRVM_DROPLET_ID=rvm-droplet\n",
			"the guest root drive and the stack image drive have the one identity rvm-root in /rvm/disks, so the guest cannot tell them apart"),
		Entry("the droplet with a volume's identity", "RVM_VOLUMES=1\nRVM_VOL0_KIND=image\nRVM_VOL0_ID=rvm-vol0\nRVM_VOL0_SECTORS=2097152\nRVM_STACK_ID=rvm-stack\nRVM_DROPLET_ID=rvm-vol0\n",
			"the volume drive vol0 and the droplet image drive have the one identity rvm-vol0 in /rvm/disks, so the guest cannot tell them apart"),
		Entry("the droplet with the stack's identity", "RVM_VOLUMES=0\nRVM_STACK_ID=rvm-stack\nRVM_DROPLET_ID=rvm-stack\n",
			"the stack image drive and the droplet image drive have the one identity rvm-stack in /rvm/disks, so the guest cannot tell them apart"),
	)

	// The ext2 superblock starts 1024 bytes into the filesystem and keeps the
	// size of an inode, 2 bytes, 88 bytes into the superblock.
	inodeSize := func(image string) int {
		f, err := os.Open(image)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		b := make([]byte, 2)
		_, err = f.ReadAt(b, 1024+88)
		Expect(err).NotTo(HaveOccurred())
		return int(b[0]) | int(b[1])<<8
	}

	It("formats a small image with 256-byte inodes when mke2fs is given -I 256, and with 128-byte ones when it is not", func() {
		bb := guestBusybox()
		for args, want := range map[string]int{"-I 256": 256, "": 128} {
			image := filepath.Join(GinkgoT().TempDir(), "root.img")
			Expect(os.WriteFile(image, nil, 0o600)).To(Succeed())
			Expect(os.Truncate(image, 64<<20)).To(Succeed())
			argv := append([]string{"mke2fs", "-F", "-b", "4096", "-m", "0"}, strings.Fields(args)...)
			argv = append(argv, "-i", strconv.FormatInt(inodeRatioFor(64<<20), 10), "-L", "rvm-root", image)
			out, err := exec.Command(bb, argv...).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), string(out))
			Expect(inodeSize(image)).To(Equal(want), "mke2fs %q: %s", args, out)
		}
	})

	// backupCheck runs stage 2's backup superblock check in the guest's
	// busybox, with its dd, od, and cmp, against image as the volume's
	// device, and returns what it printed.
	backupCheck := func(image string) string {
		bb := guestBusybox()
		info, err := os.Stat(image)
		Expect(err).NotTo(HaveOccurred())
		dir := GinkgoT().TempDir()
		bin := filepath.Join(dir, "bin")
		Expect(os.Mkdir(bin, 0o755)).To(Succeed())
		for _, applet := range []string{"dd", "od", "rm", "cmp"} {
			Expect(os.Symlink(bb, filepath.Join(bin, applet))).To(Succeed())
		}
		script := strings.Replace(guestFailFunc, "reboot -nf", "echo REBOOT", 1) +
			"rvm_vdev=" + shellQuote(image) + " rvm_vimage=rvm-disk-0.img rvm_vname='the volume image rvm-disk-0.img' rvm_vpath=/home/vcap/data rvm_vsectors=" + strconv.FormatInt(info.Size()/512, 10) + "\n" +
			strings.ReplaceAll(guestVolumeBackupCheck, guestVolumeBackup, shellQuote(filepath.Join(dir, "volume-backup"))) +
			"echo BLANK\n"
		cmd := exec.Command(bb, "sh", "-c", script)
		cmd.Env = []string{"PATH=" + bin}
		// The check fails the boot through rvm_fail, which exits non-zero
		// after the line and the stand-in for its reboot.
		out, err := cmd.CombinedOutput()
		if err != nil {
			_, ok := err.(*exec.ExitError)
			Expect(ok).To(BeTrue(), "%v: %s", err, out)
			Expect(string(out)).To(HaveSuffix("\nREBOOT\n"))
			return string(out)
		}
		Expect(filepath.Join(dir, "volume-backup")).NotTo(BeAnExistingFile())
		return string(out)
	}

	DescribeTable("finds the backup superblock that busybox mke2fs writes for each block size once the image's first 64 KiB are zeroed, and none in an image of zeros",
		func(blockSize, groupBlock int, size int64) {
			bb := guestBusybox()
			image := filepath.Join(GinkgoT().TempDir(), "rvm-disk-0.img")
			Expect(os.WriteFile(image, nil, 0o600)).To(Succeed())
			Expect(os.Truncate(image, size)).To(Succeed())
			Expect(backupCheck(image)).To(Equal("BLANK\n"))

			out, err := exec.Command(bb, "mke2fs", "-F", "-b", strconv.Itoa(blockSize), "-L", "rvm-volume", image).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), string(out))
			f, err := os.OpenFile(image, os.O_RDWR, 0)
			Expect(err).NotTo(HaveOccurred())
			_, err = f.WriteAt(make([]byte, 64<<10), 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(f.Close()).To(Succeed())
			at := groupBlock * blockSize
			Expect(backupCheck(image)).To(Equal("vm-launch guest setup: the volume image rvm-disk-0.img for /home/vcap/data reads as zero in its first 64 KiB but holds the magic of an ext2, ext3, or ext4 superblock at byte " + strconv.Itoa(at) + ", where a backup superblock is kept, so it looks like a damaged filesystem, and vm-launch never formats it; if the volume never held data, an interrupted first format can cause this, and deleting rvm-disk-0.img on the volume lets the next start create it fresh; otherwise repair it by hand on the volume with e2fsck -b from a backup superblock (e2fsck -b " + strconv.Itoa(groupBlock) + " -B " + strconv.Itoa(blockSize) + " for " + strconv.Itoa(blockSize) + "-byte blocks)\nREBOOT\n"))
		},
		Entry("1024-byte blocks", 1024, 8193, int64(64<<20)),
		Entry("2048-byte blocks", 2048, 16384, int64(128<<20)),
		Entry("4096-byte blocks", 4096, 32768, int64(256<<20)),
	)

	// zeroLine is the line for an image whose first 64 KiB read as zero but
	// whose first n bytes do not.
	zeroLine := func(n int64) string {
		return "vm-launch guest setup: the volume image rvm-disk-0.img for /home/vcap/data reads as zero in its first 64 KiB but not in all of its first " + strconv.FormatInt(n, 10) + " bytes, and a filesystem that vm-launch made on an image no larger than that, which the host may have grown since, may have no backup superblock that would tell a damaged filesystem from a new image, so it looks like a damaged filesystem, and vm-launch never formats it; if the volume never held data, an interrupted first format can cause this, and deleting rvm-disk-0.img on the volume lets the next start create it fresh; otherwise repair it by hand on the volume, where e2fsck -b needs a backup superblock that a filesystem this small may not have\nREBOOT\n"
	}

	DescribeTable("refuses a filesystem with 4096-byte blocks too small for a backup superblock once its first 64 KiB are zeroed, also once the host grew its image, and formats one that reads as zero",
		func(grown, read int64) {
			bb := guestBusybox()
			image := filepath.Join(GinkgoT().TempDir(), "rvm-disk-0.img")
			Expect(os.WriteFile(image, nil, 0o600)).To(Succeed())
			Expect(os.Truncate(image, 64<<20)).To(Succeed())
			Expect(backupCheck(image)).To(Equal("BLANK\n"))

			out, err := exec.Command(bb, "mke2fs", "-F", "-b", "4096", "-L", "rvm-volume", image).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), string(out))
			f, err := os.OpenFile(image, os.O_RDWR, 0)
			Expect(err).NotTo(HaveOccurred())
			_, err = f.WriteAt(make([]byte, 64<<10), 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(f.Close()).To(Succeed())
			if grown > 0 {
				Expect(os.Truncate(image, grown)).To(Succeed())
			}
			Expect(backupCheck(image)).To(Equal(zeroLine(read)))
		},
		Entry("at 64 MiB", int64(0), int64(64<<20)),
		Entry("grown to 1 GiB, where the read stops at 256 MiB", int64(1<<30), int64(256<<20)),
	)

	It("compares the first n bytes of a file with /dev/zero with cmp -s -n, exiting 0 when they match, 1 when they differ, and 2 when it cannot read", func() {
		bb := guestBusybox()
		dir := GinkgoT().TempDir()
		image := filepath.Join(dir, "image")
		Expect(os.WriteFile(image, append(make([]byte, 4096), 1), 0o600)).To(Succeed())
		for n, want := range map[string]int{"4096": 0, "4097": 1} {
			err := exec.Command(bb, "cmp", "-s", "-n", n, image, "/dev/zero").Run()
			if want == 0 {
				Expect(err).NotTo(HaveOccurred(), n)
				continue
			}
			var exit *exec.ExitError
			Expect(errors.As(err, &exit)).To(BeTrue(), "%s: %v", n, err)
			Expect(exit.ExitCode()).To(Equal(want), n)
		}
		err := exec.Command(bb, "cmp", "-s", "-n", "1", filepath.Join(dir, "missing"), "/dev/zero").Run()
		var exit *exec.ExitError
		Expect(errors.As(err, &exit)).To(BeTrue(), "%v", err)
		Expect(exit.ExitCode()).To(Equal(2))
	})

	It("reads no backup superblock place past the end of a small image", func() {
		image := filepath.Join(GinkgoT().TempDir(), "rvm-disk-0.img")
		Expect(os.WriteFile(image, make([]byte, 8193*1024+1023), 0o600)).To(Succeed())
		Expect(backupCheck(image)).To(Equal("BLANK\n"))
	})

	It("syncs the filesystem of a directory with sync -f, and fails for a path that is missing", func() {
		bb := guestBusybox()
		dir := GinkgoT().TempDir()
		out, err := exec.Command(bb, "sync", "-f", dir).CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(out))
		Expect(out).To(BeEmpty())
		out, err = exec.Command(bb, "sync", "-f", filepath.Join(dir, "missing")).CombinedOutput()
		Expect(err).To(HaveOccurred(), string(out))
	})
})
