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

// The /init script of a guest without a volume, for testNonce, which every
// guest gets, a task's included. It brings up the network, checks that the
// guest environment sources, and runs the command in a subshell with the guest
// environment. A guest without a volume must keep getting exactly this.
const (
	goldenInitNet = "#!/bin/busybox sh\n/bin/busybox --install -s /bin\nexport PATH=/bin\nmount -t proc proc /proc\nmount -t sysfs sys /sys\nmount -t devtmpfs dev /dev 2>/dev/null\nrvm_fail() { echo \"vm-launch guest setup: $1\"; reboot -f; exit 1; }\nmkdir -p /dev/shm && mount -t tmpfs -o noexec,nosuid,nodev,mode=1777,size=50% tmpfs /dev/shm || rvm_fail \"mounting /dev/shm failed\"\n. /rvm/net\nip link set lo up || rvm_fail \"bringing up lo failed\"\nn=0\nwhile [ ! -e /sys/class/net/eth0 ]; do\n\tn=$((n + 1))\n\t[ \"$n\" -gt 5 ] && rvm_fail \"no eth0 network device\"\n\tsleep 1\ndone\nif [ -n \"${RVM_MTU:-}\" ]; then\n\tip link set eth0 mtu \"$RVM_MTU\" || echo \"vm-launch guest setup: setting the mtu of eth0 to $RVM_MTU failed; keeping the default mtu\"\nfi\nip link set eth0 up || rvm_fail \"bringing up eth0 failed\"\nip addr add \"$RVM_ADDRESS\" dev eth0 || rvm_fail \"adding $RVM_ADDRESS to eth0 failed\"\nip route add default via \"$RVM_GATEWAY\" dev eth0 || rvm_fail \"adding the default route via $RVM_GATEWAY failed\"\n. /rvm/limits\necho 9223372036854775807 >/proc/sys/fs/file-max || echo \"vm-launch guest setup: raising fs.file-max failed; keeping the default\"\nrvm_nr_open=$(cat /proc/sys/fs/nr_open) || rvm_fail \"reading fs.nr_open failed\"\nif [ \"$rvm_nr_open\" -lt \"$RVM_NOFILE_HARD\" ]; then\n\techo \"$RVM_NOFILE_HARD\" >/proc/sys/fs/nr_open || rvm_fail \"raising fs.nr_open to $RVM_NOFILE_HARD failed\"\nfi\n( ulimit -n \"$RVM_NOFILE_HARD\" && ulimit -S -n \"$RVM_NOFILE_SOFT\" ) || rvm_fail \"setting the open files limit to $RVM_NOFILE_SOFT soft and $RVM_NOFILE_HARD hard failed\"\n( . /rvm/env ) || rvm_fail \"reading /rvm/env failed\"\necho RVM_START_0123456789abcdef\nrvm_watch=\nif [ -n \"${RVM_PORT:-}\" ]; then\n\trvm_port_hex=$(printf '%04X' \"$RVM_PORT\")\n\trvm_tables=\n\tfor rvm_table in /proc/net/tcp /proc/net/tcp6; do\n\t\t[ -e \"$rvm_table\" ] && rvm_tables=\"$rvm_tables $rvm_table\"\n\tdone\n\t(\n\t\tif [ -p /rvm/listen-tick ] && command exec 3<>/rvm/listen-tick; then\n\t\t\trvm_pause() { read -t 1 -u 3 rvm_tick; }\n\t\telse\n\t\t\trvm_pause() { sleep 1; }\n\t\tfi\n\t\trvm_up=0\n\t\twhile :; do\n\t\t\trvm_now=0\n\t\t\trvm_failed=\n\t\t\tfor rvm_table in $rvm_tables; do\n\t\t\t\trvm_head=\n\t\t\t\twhile read -r rvm_sl rvm_local rvm_remote rvm_st rvm_rest; do\n\t\t\t\t\tif [ -z \"$rvm_head\" ]; then\n\t\t\t\t\t\trvm_head=1\n\t\t\t\t\t\tcontinue\n\t\t\t\t\tfi\n\t\t\t\t\t[ \"$rvm_st\" = 0A ] || break\n\t\t\t\t\tcase $rvm_local in\n\t\t\t\t\t*:\"$rvm_port_hex\") ;;\n\t\t\t\t\t*) continue ;;\n\t\t\t\t\tesac\n\t\t\t\t\tcase ${rvm_local%:*} in\n\t\t\t\t\t??????7F | 00000000000000000000000001000000 | 0000000000000000FFFF0000??????7F) ;;\n\t\t\t\t\t*) rvm_now=1 ;;\n\t\t\t\t\tesac\n\t\t\t\tdone 2>/dev/null <\"$rvm_table\"\n\t\t\t\t[ -n \"$rvm_head\" ] || rvm_failed=1\n\t\t\tdone\n\t\t\tif [ \"$rvm_now\" = 0 ] && [ -n \"$rvm_failed\" ]; then\n\t\t\t\trvm_now=$rvm_up\n\t\t\tfi\n\t\t\tif [ \"$rvm_now\" != \"$rvm_up\" ]; then\n\t\t\t\techo \"RVM_LISTEN_0123456789abcdef=$rvm_now\" >/dev/console && rvm_up=$rvm_now\n\t\t\tfi\n\t\t\trvm_pause\n\t\tdone\n\t) </dev/null &\n\trvm_watch=$!\nfi\n( ulimit -n \"$RVM_NOFILE_HARD\" && ulimit -S -n \"$RVM_NOFILE_SOFT\" && . /rvm/env && exec sh /rvm/cmd ) </dev/null\nrvm_status=$?\nif [ -n \"$rvm_watch\" ]; then\n\tkill \"$rvm_watch\"\n\twait \"$rvm_watch\"\nfi\necho RVM_EXIT_0123456789abcdef=$rvm_status >/dev/console || echo RVM_EXIT_0123456789abcdef=$rvm_status\nreboot -f\n"
)

// archiveEntries parses a gzip newc archive into its entry names, in order,
// and its entries by name.
func archiveEntries(raw []byte) ([]string, map[string]cpioEntry) {
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
	nw := &network{port: 8080, address: qemuGuestCIDR, gateway: qemuGateway, resolvConf: "nameserver 10.0.2.3\n"}
	task := taskNetwork()

	writeArchive := func(nw *network, vol *guestVolume) []byte {
		return buildInitramfs([]byte("busybox"), "true", nw, vol)
	}

	It("keeps the /init of a guest without a volume byte for byte", func() {
		Expect(initScript(testNonce, false)).To(Equal(goldenInitNet))

		for _, n := range []*network{task, nw} {
			_, byName := archiveEntries(writeArchive(n, nil))
			Expect(string(byName["init"].data)).To(Equal(goldenInitNet), "port %d", n.port)
		}
	})

	It("adds /rvm/mounts with the device, the quoted path, and the image name", func() {
		names, byName := archiveEntries(writeArchive(task, vol))
		Expect(names).To(Equal([]string{"bin", "dev", "dev/console", "dev/null", "etc", "proc", "sys", "tmp", "rvm",
			"bin/busybox", "rvm/cmd", "rvm/net", "rvm/env", "rvm/limits", "etc/resolv.conf", "rvm/mounts", "init", cpioTrailer}))
		Expect(string(byName["rvm/mounts"].data)).To(Equal(
			"RVM_VOLUME_DEVICE=/dev/vda\nRVM_VOLUME_PATH='/data/it'\\''s $here'\nRVM_VOLUME_IMAGE='rvm-disk-3.img'\n"))
		Expect(byName["rvm/mounts"].mode).To(Equal(uint32(0o100644)))
		Expect(string(byName["init"].data)).To(Equal(initScript(testNonce, true)))

		path := writeTempFile("mounts", mountsFile(vol))
		out, err := exec.Command("/bin/sh", "-c", `. "$1"; printf '%s|%s|%s' "$RVM_VOLUME_DEVICE" "$RVM_VOLUME_PATH" "$RVM_VOLUME_IMAGE"`, "sh", path).Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(out)).To(Equal("/dev/vda|/data/it's $here|rvm-disk-3.img"))
	})

	It("adds /rvm/mounts after the network files of an LRP", func() {
		names, byName := archiveEntries(writeArchive(nw, vol))
		Expect(names).To(Equal([]string{"bin", "dev", "dev/console", "dev/null", "etc", "proc", "sys", "tmp", "rvm",
			"bin/busybox", "rvm/cmd", "rvm/net", "rvm/env", "rvm/limits", "etc/resolv.conf", "rvm/listen-tick", "rvm/mounts", "init", cpioTrailer}))
		Expect(string(byName["init"].data)).To(Equal(initScript(testNonce, true)))
	})

	It("mounts /dev/shm as a setup step, before the network and the start tag", func() {
		for _, volume := range []bool{false, true} {
			script := initScript(testNonce, volume)
			shm := strings.Index(script, guestShmSetup)
			Expect(shm).To(BeNumerically(">", strings.Index(script, "rvm_fail() {")), "volume %v", volume)
			Expect(shm).To(BeNumerically("<", strings.Index(script, ". /rvm/net\n")), "volume %v", volume)
			Expect(strings.Count(script, "/dev/shm")).To(Equal(strings.Count(guestShmSetup, "/dev/shm")), "volume %v", volume)
		}
	})

	It("mounts the volume before the start tag and unmounts it after the command, before the exit tag", func() {
		script := initScript(testNonce, true)
		start := strings.Index(script, "\necho RVM_START_"+testNonce+"\n")
		Expect(start).To(BeNumerically(">", 0))
		Expect(strings.Count(script, "rvm_fail() {")).To(Equal(1))
		Expect(strings.Index(script, "rvm_fail() {")).To(BeNumerically("<", strings.Index(script, "rvm_fail \"")))

		setup := strings.Index(script, guestVolumeSetup)
		Expect(setup).To(BeNumerically(">", 0))
		Expect(setup + len(guestVolumeSetup)).To(BeNumerically("<=", start+1))
		Expect(strings.Index(script, guestEnvChecks)).To(BeNumerically("<", strings.Index(script, ". /rvm/mounts\n")))
		Expect(script).To(HaveSuffix("\necho RVM_START_" + testNonce + "\n" + guestListenWatch(testNonce) +
			"( ulimit -n \"$RVM_NOFILE_HARD\" && ulimit -S -n \"$RVM_NOFILE_SOFT\" && . /rvm/env && exec sh /rvm/cmd ) </dev/null\nrvm_status=$?\n" +
			guestListenStop + guestVolumeTeardown + "echo RVM_EXIT_" + testNonce + "=$rvm_status >/dev/console || echo RVM_EXIT_" + testNonce + "=$rvm_status\nreboot -f\n"))
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

	It("is valid shell with and without a volume", func() {
		for _, volume := range []bool{false, true} {
			out, err := exec.Command("/bin/sh", "-n", "-c", initScript(testNonce, volume)).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), "volume=%v: %s", volume, out)
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
				script := ". " + shellQuote(filepath.Join(dir, "mounts")) + "\n(exit " + status + ")\nrvm_status=$?\n" + guestVolumeTeardown + "echo \"status=$rvm_status\"\n"
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
