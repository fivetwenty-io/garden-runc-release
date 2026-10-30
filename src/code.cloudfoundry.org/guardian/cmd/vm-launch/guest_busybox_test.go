//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
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
	// diskSearch runs rvm_disk in the guest's busybox against the sysfs
	// tree sys for a size of sectors, with the device files in dev in place
	// of /dev, and returns what it printed and set.
	diskSearch := func(sys, dev, sectors string) string {
		script := strings.Replace(guestFailFunc, "reboot -nf", "echo REBOOT", 1) + strings.ReplaceAll(guestDiskFunc, "/dev/", dev+"/") +
			`rvm_disk "$1" "$2" "guest root"; echo "status=$? dev=$rvm_dev"`
		out, err := exec.Command(guestBusybox(), "sh", "-c", script, "sh", sys, sectors).CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(out))
		return string(out)
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

	It("finds the one device of a size, finds none for a size no device has, and skips a size it cannot read", func() {
		sys := GinkgoT().TempDir()
		for name, size := range map[string]string{"vda": "2097152\n", "vdb": "131072\n", "loop0": "131072\n"} {
			Expect(os.MkdirAll(filepath.Join(sys, name), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(sys, name, "size"), []byte(size), 0o444)).To(Succeed())
		}
		dev := blockNodes("vda", "vdb", "vdc", "vdd")
		// vdc's size is a directory, which no user can read as a file, and
		// vdd has none.
		Expect(os.MkdirAll(filepath.Join(sys, "vdc", "size"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(sys, "vdd"), 0o755)).To(Succeed())

		Expect(diskSearch(sys, dev, "131072")).To(Equal("status=0 dev=" + dev + "/vdb\n"))
		Expect(diskSearch(sys, dev, "2097152")).To(Equal("status=0 dev=" + dev + "/vda\n"))
		Expect(diskSearch(sys, dev, "4096")).To(Equal("status=1 dev=\n"))
		Expect(diskSearch(filepath.Join(sys, "none"), dev, "131072")).To(Equal("status=1 dev=\n"))
	})

	It("does not find a device that sysfs lists until its device node is a block device", func() {
		sys := GinkgoT().TempDir()
		Expect(os.MkdirAll(filepath.Join(sys, "vdb"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(sys, "vdb", "size"), []byte("131072\n"), 0o444)).To(Succeed())

		missing := GinkgoT().TempDir()
		Expect(diskSearch(sys, missing, "131072")).To(Equal("status=1 dev=" + missing + "/vdb\n"))

		// A regular file or a character device is no block device.
		Expect(os.WriteFile(filepath.Join(missing, "vdb"), nil, 0o600)).To(Succeed())
		Expect(diskSearch(sys, missing, "131072")).To(Equal("status=1 dev=" + missing + "/vdb\n"))

		dev := blockNodes("vdb")
		Expect(diskSearch(sys, dev, "131072")).To(Equal("status=0 dev=" + dev + "/vdb\n"))
	})

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

	It("fails the boot when two devices have the size", func() {
		sys := GinkgoT().TempDir()
		for _, name := range []string{"vda", "vdb"} {
			Expect(os.MkdirAll(filepath.Join(sys, name), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(sys, name, "size"), []byte("131072\n"), 0o444)).To(Succeed())
		}
		script := strings.Replace(guestFailFunc, "reboot -nf", "echo REBOOT", 1) + guestDiskFunc + `rvm_disk "$1" 131072 "guest root"; echo "returned"`
		out, err := exec.Command(guestBusybox(), "sh", "-c", script, "sh", sys).CombinedOutput()
		Expect(err).To(HaveOccurred())
		Expect(string(out)).To(Equal("vm-launch guest setup: two block devices, /dev/vda and /dev/vdb, have the size of the guest root, so the guest cannot tell which one it is\nREBOOT\n"))
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
