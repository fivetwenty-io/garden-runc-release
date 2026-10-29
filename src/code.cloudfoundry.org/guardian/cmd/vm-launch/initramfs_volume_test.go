//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The /init scripts of cf68f18, from before volume support, for testNonce.
// A guest without a volume must keep getting exactly these.
const (
	goldenInitPlain = "#!/bin/busybox sh\n/bin/busybox --install -s /bin\nexport PATH=/bin\nmount -t proc proc /proc\nmount -t sysfs sys /sys\nmount -t devtmpfs dev /dev 2>/dev/null\necho RVM_START_0123456789abcdef\nsh /rvm/cmd </dev/null\necho RVM_EXIT_0123456789abcdef=$?\nreboot -f\n"

	goldenInitNet = "#!/bin/busybox sh\n/bin/busybox --install -s /bin\nexport PATH=/bin\nmount -t proc proc /proc\nmount -t sysfs sys /sys\nmount -t devtmpfs dev /dev 2>/dev/null\nrvm_fail() { echo \"vm-launch guest setup: $1\"; reboot -f; exit 1; }\n. /rvm/net\nip link set lo up || rvm_fail \"bringing up lo failed\"\nn=0\nwhile [ ! -e /sys/class/net/eth0 ]; do\n\tn=$((n + 1))\n\t[ \"$n\" -gt 5 ] && rvm_fail \"no eth0 network device\"\n\tsleep 1\ndone\nif [ -n \"${RVM_MTU:-}\" ]; then\n\tip link set eth0 mtu \"$RVM_MTU\" || echo \"vm-launch guest setup: setting the mtu of eth0 to $RVM_MTU failed; keeping the default mtu\"\nfi\nip link set eth0 up || rvm_fail \"bringing up eth0 failed\"\nip addr add \"$RVM_ADDRESS\" dev eth0 || rvm_fail \"adding $RVM_ADDRESS to eth0 failed\"\nip route add default via \"$RVM_GATEWAY\" dev eth0 || rvm_fail \"adding the default route via $RVM_GATEWAY failed\"\n. /rvm/env\necho RVM_START_0123456789abcdef\nsh /rvm/cmd </dev/null\necho RVM_EXIT_0123456789abcdef=$?\nreboot -f\n"
)

func archiveEntries(path string) ([]string, map[string]cpioEntry) {
	raw, err := os.ReadFile(path)
	Expect(err).NotTo(HaveOccurred())
	var names []string
	byName := map[string]cpioEntry{}
	for _, e := range readNewc(gunzip(raw)) {
		names = append(names, e.name)
		byName[e.name] = e
	}
	return names, byName
}

var _ = Describe("guest volume initramfs", func() {
	vol := &guestVolume{ContainerDir: "/data/it's $here", ImageName: "rvm-disk-3.img"}
	nw := &network{port: 8080, address: qemuGuestCIDR, gateway: qemuGateway, resolvConf: "nameserver 10.0.2.3\n", env: "export PORT='8080'\n"}

	writeArchive := func(nw *network, vol *guestVolume) string {
		dir := GinkgoT().TempDir()
		bb := filepath.Join(dir, "busybox")
		Expect(os.WriteFile(bb, []byte("busybox"), 0o755)).To(Succeed())
		out := filepath.Join(dir, "initrd.cpio.gz")
		Expect(writeInitramfs(out, bb, "true", testNonce, nw, vol)).To(Succeed())
		return out
	}

	It("keeps the /init of a guest without a volume byte for byte", func() {
		Expect(initScript(testNonce, false, false)).To(Equal(goldenInitPlain))
		Expect(initScript(testNonce, true, false)).To(Equal(goldenInitNet))

		_, plain := archiveEntries(writeArchive(nil, nil))
		Expect(string(plain["init"].data)).To(Equal(goldenInitPlain))
		_, networked := archiveEntries(writeArchive(nw, nil))
		Expect(string(networked["init"].data)).To(Equal(goldenInitNet))
	})

	It("adds /rvm/mounts with the device, the quoted path, and the image name", func() {
		names, byName := archiveEntries(writeArchive(nil, vol))
		Expect(names).To(Equal([]string{"bin", "dev", "dev/console", "dev/null", "proc", "sys", "tmp", "rvm",
			"bin/busybox", "rvm/cmd", "rvm/mounts", "init", cpioTrailer}))
		Expect(string(byName["rvm/mounts"].data)).To(Equal(
			"RVM_VOLUME_DEVICE=/dev/vda\nRVM_VOLUME_PATH='/data/it'\\''s $here'\nRVM_VOLUME_IMAGE='rvm-disk-3.img'\n"))
		Expect(byName["rvm/mounts"].mode).To(Equal(uint32(0o100644)))
		Expect(string(byName["init"].data)).To(Equal(initScript(testNonce, false, true)))

		path := writeTempFile("mounts", mountsFile(vol))
		out, err := exec.Command("/bin/sh", "-c", `. "$1"; printf '%s|%s|%s' "$RVM_VOLUME_DEVICE" "$RVM_VOLUME_PATH" "$RVM_VOLUME_IMAGE"`, "sh", path).Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(out)).To(Equal("/dev/vda|/data/it's $here|rvm-disk-3.img"))
	})

	It("adds /rvm/mounts after the network files of a networked guest", func() {
		names, byName := archiveEntries(writeArchive(nw, vol))
		Expect(names).To(Equal([]string{"bin", "dev", "dev/console", "dev/null", "etc", "proc", "sys", "tmp", "rvm",
			"bin/busybox", "rvm/cmd", "rvm/net", "rvm/env", "etc/resolv.conf", "rvm/mounts", "init", cpioTrailer}))
		Expect(string(byName["init"].data)).To(Equal(initScript(testNonce, true, true)))
	})

	It("mounts the volume before the start tag and unmounts it after the command, before the exit tag", func() {
		for _, networked := range []bool{false, true} {
			script := initScript(testNonce, networked, true)
			start := strings.Index(script, "\necho RVM_START_"+testNonce+"\n")
			Expect(start).To(BeNumerically(">", 0))
			Expect(strings.Count(script, "rvm_fail() {")).To(Equal(1))
			Expect(strings.Index(script, "rvm_fail() {")).To(BeNumerically("<", strings.Index(script, "rvm_fail \"")))

			setup := strings.Index(script, guestVolumeSetup)
			Expect(setup).To(BeNumerically(">", 0))
			Expect(setup + len(guestVolumeSetup)).To(BeNumerically("<=", start+1))
			if networked {
				Expect(strings.Index(script, ". /rvm/env\n")).To(BeNumerically("<", strings.Index(script, ". /rvm/mounts\n")))
			}
			Expect(script).To(HaveSuffix("\necho RVM_START_" + testNonce + "\nsh /rvm/cmd </dev/null\n" + guestVolumeTeardown +
				"echo RVM_EXIT_" + testNonce + "=$rvm_status\nreboot -f\n"))
		}
	})

	It("formats only after a blank check, and mounts synchronously with the ext4 driver", func() {
		Expect(guestVolumeSetup).To(ContainSubstring(`dd if="$RVM_VOLUME_DEVICE" of=/rvm/volume-head bs=4096 count=16 || rvm_fail`))
		Expect(guestVolumeSetup).To(ContainSubstring(`mke2fs -F -m 0 -L rvm-volume "$RVM_VOLUME_DEVICE"`))
		Expect(guestVolumeSetup).To(ContainSubstring(`mount -t ext4 -o sync,dirsync,noatime,errors=remount-ro "$RVM_VOLUME_DEVICE" "$RVM_VOLUME_PATH"`))
		Expect(strings.Count(guestVolumeSetup, "mke2fs")).To(Equal(1))
	})

	It("keeps its scratch files under /rvm, where no volume path can reach them", func() {
		Expect(guestVolumeHead).To(Equal("/rvm/volume-head"))
		Expect(guestVolumeUsed).To(Equal("/rvm/volume-used"))
		Expect(guestVolumeSetup).NotTo(ContainSubstring("/tmp/"))
		for _, p := range []string{guestVolumeHead, guestVolumeUsed} {
			Expect(checkVolumeDir(p)).To(MatchError(ContainSubstring("on or under /rvm")))
		}
	})

	It("is valid shell with and without a network and a volume", func() {
		for _, networked := range []bool{false, true} {
			for _, volume := range []bool{false, true} {
				out, err := exec.Command("/bin/sh", "-n", "-c", initScript(testNonce, networked, volume)).CombinedOutput()
				Expect(err).NotTo(HaveOccurred(), "networked=%v volume=%v: %s", networked, volume, out)
			}
		}
	})

	Describe("running the volume setup", func() {
		type setupRun struct {
			out   string
			calls string
		}

		var (
			dir     string
			bin     string
			callLog string
			device  string
			mnt     string
		)

		BeforeEach(func() {
			dir = GinkgoT().TempDir()
			bin = filepath.Join(dir, "bin")
			Expect(os.Mkdir(bin, 0o755)).To(Succeed())
			callLog = filepath.Join(dir, "calls")
			device = filepath.Join(dir, "vda")
			mnt = filepath.Join(dir, "mnt", "da'ta")

			// Each stub records its argv. dd writes what DD_MODE says to its
			// of= file; the others exit with their *_RC.
			stub := func(name, body string) {
				script := "#!/bin/sh\necho \"" + name + " $*\" >> " + shellQuote(callLog) + "\n" + body + "\n"
				Expect(os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755)).To(Succeed())
			}
			stub("dd", `for a; do case $a in of=*) of=${a#of=} ;; esac; done
case "$DD_MODE" in
zeros) head -c 65536 /dev/zero > "$of" ;;
data) { head -c 1024 /dev/zero; printf 'E'; head -c 64511 /dev/zero; } > "$of" ;;
empty) : > "$of" ;;
fail) echo "dd: can't open device" >&2; exit 1 ;;
esac`)
			stub("mke2fs", `exit "${MKE2FS_RC:-0}"`)
			stub("mount", `exit "${MOUNT_RC:-0}"`)
			stub("sleep", `exit 0`)
			stub("sync", `exit 0`)
			stub("umount", `exit "${UMOUNT_RC:-0}"`)

			// The real /rvm/mounts names /dev/vda; this one points the device
			// at a test file and the path at a test mount point.
			Expect(os.WriteFile(filepath.Join(dir, "mounts"), []byte("RVM_VOLUME_DEVICE="+shellQuote(device)+"\nRVM_VOLUME_PATH="+shellQuote(mnt)+"\nRVM_VOLUME_IMAGE='rvm-disk-0.img'\n"), 0o644)).To(Succeed())
		})

		// run executes rvm_fail and the volume setup under /bin/sh, with the
		// guest paths moved into the test directory, a regular file standing
		// in for the block device, and reboot replaced by a marker.
		run := func(env ...string) setupRun {
			script := strings.NewReplacer(
				"/rvm/mounts", filepath.Join(dir, "mounts"),
				"/rvm/volume-", filepath.Join(dir, "volume-"),
				`[ ! -b "$RVM_VOLUME_DEVICE" ]`, `[ ! -e "$RVM_VOLUME_DEVICE" ]`,
				"reboot -f", "echo REBOOT",
			).Replace(guestFailFunc+guestVolumeSetup) + "echo REACHED_START\n"
			Expect(script).NotTo(ContainSubstring(guestVolumeHead))
			Expect(script).NotTo(ContainSubstring(guestVolumeUsed))
			Expect(script).NotTo(ContainSubstring("-b \""))

			cmd := exec.Command("/bin/sh", "-c", script)
			cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin"}, env...)
			out, _ := cmd.CombinedOutput()
			calls, err := os.ReadFile(callLog)
			if os.IsNotExist(err) {
				err = nil
			}
			Expect(err).NotTo(HaveOccurred())
			return setupRun{out: string(out), calls: string(calls)}
		}

		// The stubs' expected argv lines, built once BeforeEach set the paths.
		var mountCall, ddCall string
		BeforeEach(func() {
			mountCall = "mount -t ext4 -o sync,dirsync,noatime,errors=remount-ro " + device + " " + mnt + "\n"
			ddCall = "dd if=" + device + " of=" + filepath.Join(dir, "volume-head") + " bs=4096 count=16\n"
		})

		BeforeEach(func() {
			Expect(os.WriteFile(device, nil, 0o600)).To(Succeed())
		})

		It("formats and mounts a blank image", func() {
			r := run("DD_MODE=zeros")
			Expect(r.out).To(ContainSubstring("REACHED_START"))
			Expect(r.out).NotTo(ContainSubstring("REBOOT"))
			Expect(r.calls).To(Equal(ddCall + "mke2fs -F -m 0 -L rvm-volume " + device + "\n" + mountCall))
			Expect(mnt).To(BeADirectory())
			Expect(filepath.Join(dir, "volume-head")).NotTo(BeAnExistingFile())
			Expect(filepath.Join(dir, "volume-used")).NotTo(BeAnExistingFile())
		})

		It("mounts an image with data without formatting it", func() {
			r := run("DD_MODE=data")
			Expect(r.out).To(ContainSubstring("REACHED_START"))
			Expect(r.calls).To(Equal(ddCall + mountCall))
		})

		It("never formats an image with data that does not mount", func() {
			r := run("DD_MODE=data", "MOUNT_RC=32")
			Expect(r.out).To(ContainSubstring("vm-launch guest setup: mounting the volume image rvm-disk-0.img at " + mnt + " failed; it is not blank, so vm-launch will not format it; inspect or delete rvm-disk-0.img on the volume"))
			Expect(r.out).To(ContainSubstring("REBOOT"))
			Expect(r.out).NotTo(ContainSubstring("REACHED_START"))
			Expect(r.calls).NotTo(ContainSubstring("mke2fs"))
		})

		It("treats a read error as a failure, never as a blank image", func() {
			r := run("DD_MODE=fail")
			Expect(r.out).To(ContainSubstring("vm-launch guest setup: reading the start of " + device + " failed"))
			Expect(r.out).To(ContainSubstring("REBOOT"))
			Expect(r.calls).To(Equal(ddCall))
		})

		It("does not format an image it read nothing from", func() {
			r := run("DD_MODE=empty", "MOUNT_RC=32")
			Expect(r.calls).NotTo(ContainSubstring("mke2fs"))
			Expect(r.out).To(ContainSubstring("it is not blank, so vm-launch will not format it"))
		})

		It("fails when formatting fails", func() {
			r := run("DD_MODE=zeros", "MKE2FS_RC=1")
			Expect(r.out).To(ContainSubstring("vm-launch guest setup: formatting the blank volume image rvm-disk-0.img failed"))
			Expect(r.out).NotTo(ContainSubstring("REACHED_START"))
			Expect(r.calls).NotTo(ContainSubstring("mount -t"))
		})

		It("fails when a newly formatted image does not mount", func() {
			r := run("DD_MODE=zeros", "MOUNT_RC=32")
			Expect(r.out).To(ContainSubstring("vm-launch guest setup: mounting the newly formatted volume image rvm-disk-0.img at " + mnt + " failed"))
			Expect(r.out).NotTo(ContainSubstring("REACHED_START"))
		})

		It("fails after six checks when the block device never appears", func() {
			Expect(os.Remove(device)).To(Succeed())
			r := run("DD_MODE=zeros")
			Expect(r.out).To(ContainSubstring("vm-launch guest setup: no " + device + " block device for the volume"))
			Expect(r.out).To(ContainSubstring("REBOOT"))
			Expect(r.calls).To(Equal(strings.Repeat("sleep 1\n", 5)))
		})

		It("fails when the mount point cannot be made", func() {
			Expect(os.WriteFile(filepath.Join(dir, "mnt"), nil, 0o600)).To(Succeed())
			r := run("DD_MODE=zeros")
			Expect(r.out).To(ContainSubstring("vm-launch guest setup: creating " + mnt + " failed"))
			Expect(r.calls).NotTo(ContainSubstring("dd "))
		})

		Describe("the teardown", func() {
			teardown := func(status string, env ...string) setupRun {
				script := ". " + shellQuote(filepath.Join(dir, "mounts")) + "\n(exit " + status + ")\n" + guestVolumeTeardown + "echo \"status=$rvm_status\"\n"
				cmd := exec.Command("/bin/sh", "-c", script)
				cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin"}, env...)
				out, err := cmd.CombinedOutput()
				Expect(err).NotTo(HaveOccurred(), string(out))
				calls, err := os.ReadFile(callLog)
				Expect(err).NotTo(HaveOccurred())
				return setupRun{out: string(out), calls: string(calls)}
			}

			It("syncs, unmounts, and keeps the command's status", func() {
				r := teardown("7")
				Expect(r.out).To(Equal("status=7\n"))
				Expect(r.calls).To(Equal("sync \numount " + mnt + "\n"))
			})

			It("reports a failed unmount and still keeps the command's status", func() {
				r := teardown("0", "UMOUNT_RC=1")
				Expect(r.out).To(Equal("vm-launch guest: unmounting " + mnt + " failed; data was already synced\nstatus=0\n"))
			})
		})
	})
})
