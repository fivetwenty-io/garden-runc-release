//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
	// tree sys for a size of sectors, and returns what it printed and set.
	diskSearch := func(sys, sectors string) string {
		script := strings.Replace(guestFailFunc, "reboot -f", "echo REBOOT", 1) + guestDiskFunc +
			`rvm_disk "$1" "$2" "guest root"; echo "status=$? dev=$rvm_dev"`
		out, err := exec.Command(guestBusybox(), "sh", "-c", script, "sh", sys, sectors).CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(out))
		return string(out)
	}

	It("finds the one device of a size, finds none for a size no device has, and skips a size it cannot read", func() {
		sys := GinkgoT().TempDir()
		for name, size := range map[string]string{"vda": "2097152\n", "vdb": "131072\n", "loop0": "131072\n"} {
			Expect(os.MkdirAll(filepath.Join(sys, name), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(sys, name, "size"), []byte(size), 0o444)).To(Succeed())
		}
		// vdc's size is a directory, which no user can read as a file, and
		// vdd has none.
		Expect(os.MkdirAll(filepath.Join(sys, "vdc", "size"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(sys, "vdd"), 0o755)).To(Succeed())

		Expect(diskSearch(sys, "131072")).To(Equal("status=0 dev=/dev/vdb\n"))
		Expect(diskSearch(sys, "2097152")).To(Equal("status=0 dev=/dev/vda\n"))
		Expect(diskSearch(sys, "4096")).To(Equal("status=1 dev=\n"))
		Expect(diskSearch(filepath.Join(sys, "none"), "131072")).To(Equal("status=1 dev=\n"))
	})

	It("fails the boot when two devices have the size", func() {
		sys := GinkgoT().TempDir()
		for _, name := range []string{"vda", "vdb"} {
			Expect(os.MkdirAll(filepath.Join(sys, name), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(sys, name, "size"), []byte("131072\n"), 0o444)).To(Succeed())
		}
		script := strings.Replace(guestFailFunc, "reboot -f", "echo REBOOT", 1) + guestDiskFunc + `rvm_disk "$1" 131072 "guest root"; echo "returned"`
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
