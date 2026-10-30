//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The /rvm/init script, stage 2 of the guest's boot, of a guest without a
// volume, for testNonce, which every guest gets, a task's included. It brings
// up the network, checks that the guest environment sources, and runs the
// command in a subshell with the guest environment. A guest without a volume
// must keep getting exactly this.
const (
	goldenInitNet = "#!/bin/busybox sh\nexport PATH=/bin\nrvm_fail() { echo \"vm-launch guest setup: $1\"; reboot -f; exit 1; }\nstty -echo </dev/console || echo \"vm-launch guest setup: turning off console echo failed; a stop request will appear in the output\"\nmkdir -p /dev/shm && mount -t tmpfs -o noexec,nosuid,nodev,mode=1777,size=50% tmpfs /dev/shm || rvm_fail \"mounting /dev/shm failed\"\n. /rvm/net\nip link set lo up || rvm_fail \"bringing up lo failed\"\nn=0\nwhile [ ! -e /sys/class/net/eth0 ]; do\n\tn=$((n + 1))\n\t[ \"$n\" -gt 5 ] && rvm_fail \"no eth0 network device\"\n\tsleep 1\ndone\nif [ -n \"${RVM_MTU:-}\" ]; then\n\tip link set eth0 mtu \"$RVM_MTU\" || echo \"vm-launch guest setup: setting the mtu of eth0 to $RVM_MTU failed; keeping the default mtu\"\nfi\nip link set eth0 up || rvm_fail \"bringing up eth0 failed\"\nip addr add \"$RVM_ADDRESS\" dev eth0 || rvm_fail \"adding $RVM_ADDRESS to eth0 failed\"\nip route add default via \"$RVM_GATEWAY\" dev eth0 || rvm_fail \"adding the default route via $RVM_GATEWAY failed\"\n. /rvm/limits\necho 9223372036854775807 >/proc/sys/fs/file-max || echo \"vm-launch guest setup: raising fs.file-max failed; keeping the default\"\nrvm_nr_open=$(cat /proc/sys/fs/nr_open) || rvm_fail \"reading fs.nr_open failed\"\nif [ \"$rvm_nr_open\" -lt \"$RVM_NOFILE_HARD\" ]; then\n\techo \"$RVM_NOFILE_HARD\" >/proc/sys/fs/nr_open || rvm_fail \"raising fs.nr_open to $RVM_NOFILE_HARD failed\"\nfi\n( ulimit -n \"$RVM_NOFILE_HARD\" && ulimit -S -n \"$RVM_NOFILE_SOFT\" ) || rvm_fail \"setting the open files limit to $RVM_NOFILE_SOFT soft and $RVM_NOFILE_HARD hard failed\"\n( . /rvm/env ) || rvm_fail \"reading /rvm/env failed\"\n(\n\techo -1000 >/proc/self/oom_score_adj\n\trvm_stop=\n\twhile IFS= read -r rvm_line; do\n\t\tif [ \"$rvm_line\" = \"RVM_STOP_0123456789abcdef\" ]; then\n\t\t\trvm_stop=1\n\t\t\tbreak\n\t\tfi\n\tdone </dev/console\n\t[ -n \"$rvm_stop\" ] || exit 0\n\tuntil read -r rvm_app 2>/dev/null </rvm/app-pid && [ -n \"$rvm_app\" ]; do\n\t\tsleep 0.05\n\tdone\n\tkill -TERM \"$rvm_app\"\n) </dev/null &\nrvm_reader=$!\necho RVM_START_0123456789abcdef\nrvm_watch=\nif [ -n \"${RVM_PORTS:-}\" ]; then\n\trvm_ports=\n\trvm_hexes=\" \"\n\tfor rvm_dec in $RVM_PORTS; do\n\t\trvm_hex=$(printf '%04X' \"$rvm_dec\")\n\t\trvm_ports=\"$rvm_ports $rvm_dec:$rvm_hex\"\n\t\trvm_hexes=\"$rvm_hexes$rvm_hex \"\n\tdone\n\trvm_tables=\n\tfor rvm_table in /proc/net/tcp /proc/net/tcp6; do\n\t\t[ -e \"$rvm_table\" ] && rvm_tables=\"$rvm_tables $rvm_table\"\n\tdone\n\t(\n\t\tif [ -p /rvm/listen-tick ] && command exec 3<>/rvm/listen-tick; then\n\t\t\trvm_pause() { read -t 1 -u 3 rvm_tick; }\n\t\telse\n\t\t\trvm_pause() { sleep 1; }\n\t\tfi\n\t\trvm_upset=\" \"\n\t\trvm_look=0\n\t\twhile :; do\n\t\t\trvm_seen=\" \"\n\t\t\trvm_failed=\n\t\t\tfor rvm_table in $rvm_tables; do\n\t\t\t\trvm_head=\n\t\t\t\twhile read -r rvm_sl rvm_local rvm_remote rvm_st rvm_rest; do\n\t\t\t\t\tif [ -z \"$rvm_head\" ]; then\n\t\t\t\t\t\trvm_head=1\n\t\t\t\t\t\tcontinue\n\t\t\t\t\tfi\n\t\t\t\t\t[ \"$rvm_st\" = 0A ] || break\n\t\t\t\t\tcase \"$rvm_hexes\" in\n\t\t\t\t\t*\" ${rvm_local##*:} \"*) ;;\n\t\t\t\t\t*) continue ;;\n\t\t\t\t\tesac\n\t\t\t\t\tcase ${rvm_local%:*} in\n\t\t\t\t\t??????7F | 00000000000000000000000001000000 | 0000000000000000FFFF0000??????7F) ;;\n\t\t\t\t\t*) rvm_seen=\"$rvm_seen${rvm_local##*:} \" ;;\n\t\t\t\t\tesac\n\t\t\t\tdone 2>/dev/null <\"$rvm_table\"\n\t\t\t\t[ -n \"$rvm_head\" ] || rvm_failed=1\n\t\t\tdone\n\t\t\trvm_look=$((rvm_look + 1))\n\t\t\trvm_all=\n\t\t\tif [ \"$rvm_look\" -ge 5 ]; then\n\t\t\t\trvm_all=1\n\t\t\t\trvm_look=0\n\t\t\tfi\n\t\t\trvm_nextup=\" \"\n\t\t\tfor rvm_pp in $rvm_ports; do\n\t\t\t\trvm_hex=${rvm_pp#*:}\n\t\t\t\tcase \"$rvm_seen\" in\n\t\t\t\t*\" $rvm_hex \"*) rvm_now=1 ;;\n\t\t\t\t*) rvm_now=0 ;;\n\t\t\t\tesac\n\t\t\t\tcase \"$rvm_upset\" in\n\t\t\t\t*\" $rvm_hex \"*) rvm_was=1 ;;\n\t\t\t\t*) rvm_was=0 ;;\n\t\t\t\tesac\n\t\t\t\tif [ \"$rvm_now\" = 0 ] && [ -n \"$rvm_failed\" ]; then\n\t\t\t\t\trvm_now=$rvm_was\n\t\t\t\tfi\n\t\t\t\tif [ \"$rvm_now\" != \"$rvm_was\" ] || [ -n \"$rvm_all\" ]; then\n\t\t\t\t\techo \"RVM_LISTEN_0123456789abcdef=${rvm_pp%:*}:$rvm_now\" >/dev/console && rvm_was=$rvm_now\n\t\t\t\tfi\n\t\t\t\tif [ \"$rvm_was\" = 1 ]; then\n\t\t\t\t\trvm_nextup=\"$rvm_nextup$rvm_hex \"\n\t\t\t\tfi\n\t\t\tdone\n\t\t\trvm_upset=$rvm_nextup\n\t\t\trvm_pause\n\t\tdone\n\t) </dev/null &\n\trvm_watch=$!\nfi\ncommand exec 3>&2 2>/dev/null\n( command exec 2>&3 3>&-; { read -r rvm_self rvm_rest </proc/self/stat && echo \"$rvm_self\" >/rvm/app-pid; } || echo \"vm-launch guest: recording the command's pid in /rvm/app-pid failed; a stop request cannot reach the command\"; ulimit -n \"$RVM_NOFILE_HARD\" && ulimit -S -n \"$RVM_NOFILE_SOFT\" && . /rvm/env && exec sh -c \"$(cat /rvm/cmd)\" ) </dev/null\nrvm_status=$?\ncommand exec 2>&3 3>&-\nkill \"$rvm_reader\" 2>/dev/null\nwait \"$rvm_reader\" 2>/dev/null\nif [ -n \"$rvm_watch\" ]; then\n\tkill \"$rvm_watch\"\n\twait \"$rvm_watch\"\nfi\nrvm_oom=0\nwhile read -r rvm_key rvm_val; do\n\tif [ \"$rvm_key\" = oom_kill ]; then\n\t\trvm_oom=$rvm_val\n\t\tbreak\n\tfi\ndone 2>/dev/null </proc/vmstat\ncase \"$rvm_oom\" in\n'' | *[!0-9]* | 0 | 0[0-9]*) ;;\n*) echo RVM_OOM_0123456789abcdef=$rvm_oom >/dev/console || echo RVM_OOM_0123456789abcdef=$rvm_oom;;\nesac\necho RVM_EXIT_0123456789abcdef=$rvm_status >/dev/console || echo RVM_EXIT_0123456789abcdef=$rvm_status\nreboot -f\n"
)

// goldenRootInit is the /init script, stage 1 of the guest's boot, of every
// guest. It finds the drives by size, formats a blank guest root disk and
// enters the overlay root on it when /rvm/disks names one, and runs stage 2
// with the volume's device.
const goldenRootInit = `#!/bin/busybox sh
/bin/busybox --install -s /bin
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
rvm_fail() { echo "vm-launch guest setup: $1"; reboot -f; exit 1; }
rvm_number() { case "$1" in '' | 0* | *[!0-9]*) return 1 ;; esac; }
rvm_disk() {
	rvm_dev=
	for rvm_b in "$1"/vd*; do
		[ -r "$rvm_b/size" ] && read -r rvm_s 2>/dev/null <"$rvm_b/size" && [ "$rvm_s" = "$2" ] || continue
		[ -z "$rvm_dev" ] || rvm_fail "two block devices, $rvm_dev and /dev/${rvm_b##*/}, have the size of the $3, so the guest cannot tell which one it is"
		rvm_dev=/dev/${rvm_b##*/}
	done
	[ -n "$rvm_dev" ]
}
. /rvm/disks
if [ -n "${RVM_ROOT_SECTORS:-}" ]; then
	rvm_number "$RVM_ROOT_SECTORS" && rvm_number "${RVM_ROOT_INODE_RATIO:-}" || rvm_fail "the guest root size or inode ratio in /rvm/disks is not a positive number"
	[ "$RVM_ROOT_SECTORS" != "${RVM_VOLUME_SECTORS:-}" ] || rvm_fail "the guest root and the volume have the same size, so the guest cannot tell them apart"
fi
if [ -n "${RVM_VOLUME_SECTORS:-}" ]; then
	rvm_number "$RVM_VOLUME_SECTORS" || rvm_fail "the volume size in /rvm/disks is not a positive number"
fi
rvm_root=
rvm_volume=
n=0
until { [ -z "${RVM_ROOT_SECTORS:-}" ] || { rvm_disk /sys/block "$RVM_ROOT_SECTORS" "guest root" && rvm_root=$rvm_dev; }; } &&
	{ [ -z "${RVM_VOLUME_SECTORS:-}" ] || { rvm_disk /sys/block "$RVM_VOLUME_SECTORS" volume && rvm_volume=$rvm_dev; }; }; do
	n=$((n + 1))
	[ "$n" -gt 5 ] && rvm_fail "no block device of the expected size for the guest root or the volume"
	sleep 1
done
if [ -n "$rvm_root" ]; then
	dd if="$rvm_root" of=/rvm/root-head bs=4096 count=16 || rvm_fail "reading the start of the guest root disk $rvm_root failed"
	tr -d '\000' </rvm/root-head >/rvm/root-used || rvm_fail "checking whether the guest root disk $rvm_root is blank failed"
	rvm_blank=
	[ -s /rvm/root-head ] && [ ! -s /rvm/root-used ] && rvm_blank=1
	rm -f /rvm/root-head /rvm/root-used
	[ -n "$rvm_blank" ] || rvm_fail "the guest root disk $rvm_root is not blank, so vm-launch will not format it"
	mke2fs -F -b 4096 -m 0 -i "$RVM_ROOT_INODE_RATIO" -L rvm-root "$rvm_root" || rvm_fail "formatting the guest root disk $rvm_root failed"
	mkdir -p /rvm/disk /rvm/root || rvm_fail "creating the guest root mount points failed"
	mount -t ext4 -o noatime,discard,errors=continue "$rvm_root" /rvm/disk || rvm_fail "mounting the guest root disk $rvm_root failed"
	mkdir /rvm/disk/upper /rvm/disk/work || rvm_fail "creating the overlay directories failed"
	mount -t overlay -o lowerdir=/,upperdir=/rvm/disk/upper,workdir=/rvm/disk/work overlay /rvm/root || rvm_fail "mounting the overlay root failed; the guest kernel needs overlayfs"
	for rvm_m in proc sys dev; do
		mount -o move "/$rvm_m" "/rvm/root/$rvm_m" || rvm_fail "moving /$rvm_m into the overlay root failed"
	done
	cd /rvm/root && mount -o move . / || rvm_fail "moving the overlay root onto / failed"
	exec chroot . /bin/sh /rvm/init "$rvm_volume"
	rvm_fail "entering the overlay root failed"
fi
exec /bin/sh /rvm/init "$rvm_volume"
`

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
	nw := &network{ports: []int{8080}, address: qemuGuestCIDR, gateway: qemuGateway, resolvConf: "nameserver 10.0.2.3\n"}
	task := taskNetwork()

	writeArchive := func(nw *network, vol *guestVolume) []byte {
		return buildInitramfs([]byte("busybox"), "true", nw, vol)
	}

	It("keeps stage 2 of a guest without a volume byte for byte, and gives every guest the same stage 1", func() {
		Expect(initScript(testNonce, false)).To(Equal(goldenInitNet))
		Expect(guestRootInit).To(Equal(goldenRootInit))

		for _, n := range []*network{task, nw} {
			for _, v := range []*guestVolume{nil, vol} {
				_, byName := archiveEntries(writeArchive(n, v))
				Expect(string(byName["init"].data)).To(Equal(goldenRootInit), "ports %v, volume %v", n.ports, v != nil)
				Expect(byName["init"].mode).To(Equal(uint32(0o100755)))
				if v == nil {
					Expect(string(byName["rvm/init"].data)).To(Equal(goldenInitNet), "ports %v", n.ports)
				}
			}
		}
	})

	It("adds /rvm/mounts with the quoted path and the image name, and the volume's size to /rvm/disks", func() {
		names, byName := archiveEntries(writeArchive(task, vol))
		Expect(names).To(Equal([]string{"bin", "dev", "dev/console", "dev/null", "etc", "proc", "sys", "tmp", "rvm",
			"bin/busybox", "rvm/cmd", "rvm/net", "rvm/env", "rvm/limits", "etc/resolv.conf", "rvm/mounts", "rvm/disks", "rvm/init", "init", cpioTrailer}))
		Expect(string(byName["rvm/mounts"].data)).To(Equal(
			"RVM_VOLUME_PATH='/data/it'\\''s $here'\nRVM_VOLUME_IMAGE='rvm-disk-3.img'\n"))
		Expect(byName["rvm/mounts"].mode).To(Equal(uint32(0o100644)))
		Expect(string(byName["rvm/disks"].data)).To(Equal("RVM_VOLUME_SECTORS=2097152\n"))
		Expect(string(byName["rvm/init"].data)).To(Equal(initScript(testNonce, true)))

		path := writeTempFile("mounts", mountsFile(vol))
		out, err := exec.Command("/bin/sh", "-c", `. "$1"; printf '%s|%s|%s' "${RVM_VOLUME_DEVICE-unset}" "$RVM_VOLUME_PATH" "$RVM_VOLUME_IMAGE"`, "sh", path).Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(out)).To(Equal("unset|/data/it's $here|rvm-disk-3.img"))
	})

	It("adds /rvm/mounts after the network files of an LRP", func() {
		names, byName := archiveEntries(writeArchive(nw, vol))
		Expect(names).To(Equal([]string{"bin", "dev", "dev/console", "dev/null", "etc", "proc", "sys", "tmp", "rvm",
			"bin/busybox", "rvm/cmd", "rvm/net", "rvm/env", "rvm/limits", "etc/resolv.conf", "rvm/listen-tick", "rvm/mounts", "rvm/disks", "rvm/init", "init", cpioTrailer}))
		Expect(string(byName["rvm/init"].data)).To(Equal(initScript(testNonce, true)))
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
			"command exec 3>&2 2>/dev/null\n( command exec 2>&3 3>&-; { read -r rvm_self rvm_rest </proc/self/stat && echo \"$rvm_self\" >/rvm/app-pid; } || echo \"vm-launch guest: recording the command's pid in /rvm/app-pid failed; a stop request cannot reach the command\"; ulimit -n \"$RVM_NOFILE_HARD\" && ulimit -S -n \"$RVM_NOFILE_SOFT\" && . /rvm/env && exec sh -c \"$(cat /rvm/cmd)\" ) </dev/null\nrvm_status=$?\ncommand exec 2>&3 3>&-\n" +
			guestStopReaderStop + guestListenStop + guestOOMReport(testNonce) + guestVolumeTeardown + "echo RVM_EXIT_" + testNonce + "=$rvm_status >/dev/console || echo RVM_EXIT_" + testNonce + "=$rvm_status\nreboot -f\n"))
	})

	It("formats only after a blank check, and mounts synchronously with the ext4 driver", func() {
		Expect(guestVolumeSetup).To(HavePrefix(". /rvm/mounts\nRVM_VOLUME_DEVICE=${1:-}\n"))
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

	It("is valid shell with and without a volume, in both stages", func() {
		for _, volume := range []bool{false, true} {
			out, err := exec.Command("/bin/sh", "-n", "-c", initScript(testNonce, volume)).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), "volume=%v: %s", volume, out)
		}
		out, err := exec.Command("/bin/sh", "-n", "-c", guestRootInit).CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), "stage 1: %s", out)
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

			// This /rvm/mounts points the path at a test mount point. The
			// device is the argument stage 1 passes, here a test file.
			Expect(os.WriteFile(filepath.Join(dir, "mounts"), []byte("RVM_VOLUME_PATH="+shellQuote(mnt)+"\nRVM_VOLUME_IMAGE='rvm-disk-0.img'\n"), 0o644)).To(Succeed())
		})

		// runWith executes rvm_fail and the volume setup under /bin/sh, with
		// arg as stage 2's argument, the guest paths moved into the test
		// directory, a regular file standing in for the block device, and
		// reboot replaced by a marker.
		runWith := func(arg string, env ...string) setupRun {
			script := strings.NewReplacer(
				"/rvm/mounts", filepath.Join(dir, "mounts"),
				"/rvm/volume-", filepath.Join(dir, "volume-"),
				`[ -b "$RVM_VOLUME_DEVICE" ]`, `[ -f "$RVM_VOLUME_DEVICE" ]`,
				"reboot -f", "echo REBOOT",
			).Replace(guestFailFunc+guestVolumeSetup) + "echo REACHED_START\n"
			Expect(script).NotTo(ContainSubstring(guestVolumeHead))
			Expect(script).NotTo(ContainSubstring(guestVolumeUsed))
			Expect(script).NotTo(ContainSubstring("-b \""))

			cmd := exec.Command("/bin/sh", "-c", script, "sh", arg)
			cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin"}, env...)
			out, _ := cmd.CombinedOutput()
			calls, err := os.ReadFile(callLog)
			if os.IsNotExist(err) {
				err = nil
			}
			Expect(err).NotTo(HaveOccurred())
			return setupRun{out: string(out), calls: string(calls)}
		}
		run := func(env ...string) setupRun { return runWith(device, env...) }

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

		It("fails at once, touching nothing, when stage 1 passed no device or one that is missing", func() {
			for _, arg := range []string{"", filepath.Join(dir, "vdz")} {
				r := runWith(arg, "DD_MODE=zeros")
				Expect(r.out).To(Equal("vm-launch guest setup: no block device for the volume image rvm-disk-0.img\nREBOOT\n"), "argument %q", arg)
				Expect(r.calls).To(BeEmpty(), "argument %q", arg)
				Expect(mnt).NotTo(BeAnExistingFile())
			}
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

			It("syncs the volume's filesystem only, unmounts it, and keeps the command's status", func() {
				r := teardown("7")
				Expect(r.out).To(Equal("status=7\n"))
				Expect(r.calls).To(Equal("sync -f " + mnt + "\numount " + mnt + "\n"))
			})

			It("reports a failed unmount and still keeps the command's status", func() {
				r := teardown("0", "UMOUNT_RC=1")
				Expect(r.out).To(Equal("vm-launch guest: unmounting " + mnt + " failed; data was already synced\nstatus=0\n"))
			})
		})
	})
})

var _ = Describe("the command's subshell in /init", func() {
	// runCommandLine runs the command line of /init in shell, with cmd as
	// /rvm/cmd, the limits the shell already has, and pidFile as the pid
	// file, or the spec's own one when pidFile is empty. It returns the
	// console output, the exit status, and the pid file's path.
	runCommandLine := func(shell guestShell, cmd, pidFile string) (string, int, string) {
		paths := guestFiles(noGuestEnv, cmd)
		script := paths.Replace(guestRunCommand + guestRunStatus)
		if pidFile != "" {
			script = strings.NewReplacer(paths.Replace(guestAppPid), pidFile).Replace(script)
		} else {
			pidFile = paths.Replace(guestAppPid)
		}
		Expect(pidFile).NotTo(Equal(guestAppPid))
		limits := "RVM_NOFILE_SOFT=$(ulimit -S -n)\nRVM_NOFILE_HARD=$(ulimit -H -n)\n"
		// After the command, /init has its standard error back and no fd 3
		// to write to. (Under an emulator such as Rosetta, a process can
		// hold read-only descriptors of its own there.)
		after := "{ echo init-fd3-open >&3; } 2>/dev/null\necho init-stderr >&2\necho \"status=$rvm_status\"\n"
		c := exec.Command(shell.argv[0], append(shell.argv[1:], "-c", limits+script+after)...)
		c.Env = []string{"PATH=" + guestBin(shell)}
		out, err := c.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), "%s: %s", shell.name, out)
		m := regexp.MustCompile(`\ninit-stderr\nstatus=(\d+)\n$|^init-stderr\nstatus=(\d+)\n$`).FindStringSubmatch(string(out))
		if m != nil && m[1] == "" {
			m[1] = m[2]
		}
		Expect(m).NotTo(BeNil(), "%s: %s", shell.name, out)
		code, err := strconv.Atoi(m[1])
		Expect(err).NotTo(HaveOccurred())
		return strings.TrimSuffix(string(out), strings.TrimPrefix(m[0], "\n")), code, pidFile
	}

	readPid := func(path string) string {
		raw, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(raw)).To(MatchRegexp(`^[1-9][0-9]*\n$`))
		return strings.TrimSpace(string(raw))
	}

	DescribeTable("records the pid of the shell that runs the command",
		func(shellOf func() guestShell) {
			shell := shellOf()
			// $$ in sh -c is the pid of that shell, which the subshell
			// became with exec.
			out, code, pidFile := runCommandLine(shell, "echo \"shell=$$\"\nexit 9\n", "")
			Expect(code).To(Equal(9), "%s: %s", shell.name, out)
			Expect(out).To(Equal("shell=" + readPid(pidFile) + "\n"))
		},
		shellEntries(""),
	)

	DescribeTable("runs /rvm/cmd as one sh -c argument, byte for byte, with sh as $0",
		func(shellOf func() guestShell) {
			shell := shellOf()
			cmd := "printf '[%s]\\n' \"a  b\" '$HOME' '`x`' \"$0\"\n\necho second line\nexit 4\n\n\n"
			out, code, _ := runCommandLine(shell, cmd, "")
			Expect(code).To(Equal(4), "%s: %s", shell.name, out)
			Expect(out).To(Equal("[a  b]\n[$HOME]\n[`x`]\n[sh]\nsecond line\n"))
		},
		shellEntries(""),
	)

	DescribeTable("gives the command /init's standard error and no fd 3",
		func(shellOf func() guestShell) {
			shell := shellOf()
			// /init's standard error stays open on fd 3 while the command
			// runs, so a write there would show in the output.
			out, code, _ := runCommandLine(shell, "echo to-stderr >&2\n{ echo fd3-open >&3; } 2>/dev/null\necho done\n", "")
			Expect(code).To(Equal(0), "%s: %s", shell.name, out)
			Expect(out).To(Equal("to-stderr\ndone\n"))
		},
		shellEntries(""),
	)

	DescribeTable("keeps the shell's report of a command that a signal ended out of the output",
		func(shellOf func() guestShell) {
			shell := shellOf()
			out, code, _ := runCommandLine(shell, "echo before\nkill -TERM $$\n", "")
			Expect(code).To(Equal(143), "%s: %s", shell.name, out)
			Expect(out).To(Equal("before\n"))
		},
		shellEntries(""),
	)

	DescribeTable("still runs the command, and says so, when the pid cannot be recorded",
		func(shellOf func() guestShell) {
			shell := shellOf()
			missing := filepath.Join(GinkgoT().TempDir(), "missing", "app-pid")
			out, code, _ := runCommandLine(shell, "echo ran\nexit 6\n", missing)
			Expect(code).To(Equal(6), "%s: %s", shell.name, out)
			Expect(out).To(ContainSubstring("vm-launch guest: recording the command's pid in " + missing + " failed; a stop request cannot reach the command\n"))
			Expect(out).To(HaveSuffix("ran\n"))
			Expect(missing).NotTo(BeAnExistingFile())
		},
		shellEntries(""),
	)

	// statPid returns the pid at the start of the /proc/PID/stat line that
	// the command printed.
	statPid := func(out string) string {
		m := regexp.MustCompile(`^([1-9][0-9]*) \(`).FindStringSubmatch(out)
		Expect(m).NotTo(BeNil(), out)
		return m[1]
	}

	It("makes a simple command the top process in the guest's busybox, and a pipeline keeps the shell", func() {
		shell := guestBusyboxShell()
		out, code, pidFile := runCommandLine(shell, "cat /proc/self/stat\n", "")
		Expect(code).To(Equal(0), out)
		Expect(statPid(out)).To(Equal(readPid(pidFile)), "the simple command is not the process whose pid /init recorded")

		// The control shows that the probe tells the two shapes apart.
		out, code, pidFile = runCommandLine(shell, "cat /proc/self/stat | cat\n", "")
		Expect(code).To(Equal(0), out)
		Expect(statPid(out)).NotTo(Equal(readPid(pidFile)))
	})
})

var _ = Describe("the guest's /rvm/disks", func() {
	vol := &guestVolume{ContainerDir: "/data", ImageName: "rvm-disk-0.img"}
	const rootBytes = 64 * bytesPerMiB

	DescribeTable("names each drive the guest has by its size in sectors",
		func(rootBytes, ratio int64, vol *guestVolume, want string) {
			g := taskGuest("true")
			g.rootBytes, g.rootInodeRatio, g.vol = rootBytes, ratio, vol
			got, err := disksFile(g)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(want))

			out, err := exec.Command("/bin/sh", "-c", `. "$1"; printf '%s|%s|%s' "${RVM_ROOT_SECTORS-unset}" "${RVM_ROOT_INODE_RATIO-unset}" "${RVM_VOLUME_SECTORS-unset}"`, "sh", writeTempFile("disks", got)).Output()
			Expect(err).NotTo(HaveOccurred())
			fields := strings.Split(string(out), "|")
			Expect(fields).To(HaveLen(3))
			if rootBytes > 0 {
				Expect(fields[:2]).To(Equal([]string{strconv.FormatInt(rootBytes/512, 10), strconv.FormatInt(ratio, 10)}))
			} else {
				Expect(fields[:2]).To(Equal([]string{"unset", "unset"}))
			}
			if vol != nil {
				Expect(fields[2]).To(Equal("2097152"))
			} else {
				Expect(fields[2]).To(Equal("unset"))
			}
		},
		Entry("no root disk and no volume", int64(0), int64(0), nil, ""),
		Entry("a root disk", int64(rootBytes), int64(16384), nil, "RVM_ROOT_SECTORS=131072\nRVM_ROOT_INODE_RATIO=16384\n"),
		Entry("a volume", int64(0), int64(0), vol, "RVM_VOLUME_SECTORS=2097152\n"),
		Entry("both", int64(rootBytes), int64(16384), vol, "RVM_ROOT_SECTORS=131072\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUME_SECTORS=2097152\n"),
		Entry("a root disk 1 MiB under the volume's size, as rootDiskSize makes it", int64(defaultImageSize-bytesPerMiB), int64(16384), vol,
			"RVM_ROOT_SECTORS=2095104\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUME_SECTORS=2097152\n"),
		Entry("a root disk of the volume's size without a volume", int64(defaultImageSize), int64(16384), nil, "RVM_ROOT_SECTORS=2097152\nRVM_ROOT_INODE_RATIO=16384\n"),
	)

	DescribeTable("rejects sizes that would leave the guest to guess, so no initramfs is built",
		func(rootBytes, ratio int64, vol *guestVolume, want string) {
			g := taskGuest("true")
			g.rootBytes, g.rootInodeRatio, g.vol = rootBytes, ratio, vol
			_, err := disksFile(g)
			Expect(err).To(MatchError(want))

			bb := filepath.Join(GinkgoT().TempDir(), "busybox")
			Expect(os.WriteFile(bb, []byte("busybox"), 0o755)).To(Succeed())
			held := heldInitramfs()
			_, err = newInitramfs(bb, g)
			Expect(err).To(MatchError("writing the initramfs: " + want))
			Expect(heldInitramfs()).To(Equal(held))
		},
		Entry("a root disk of the volume's size", int64(defaultImageSize), int64(16384), vol,
			"the guest root image and the volume image are both 1073741824 bytes, so the guest could not tell them apart"),
		Entry("a root disk of part of a sector", int64(rootBytes+100), int64(16384), nil,
			"the guest root image of 67108964 bytes is not a whole number of 512-byte sectors"),
		Entry("a root disk without an inode ratio", int64(rootBytes), int64(0), vol, "the guest root image of 67108864 bytes has no inode ratio"),
		Entry("an inode ratio without a root disk", int64(0), int64(16384), nil, "an inode ratio of 16384 bytes per inode for no guest root image"),
		Entry("a negative size", int64(-512), int64(16384), nil, "the guest root image of -512 bytes at 16384 bytes per inode has a negative size"),
		Entry("a negative inode ratio", int64(rootBytes), int64(-1), nil, "the guest root image of 67108864 bytes at -1 bytes per inode has a negative size"),
	)
})

// stage1Head is what stage 1 runs before rvm_fail: busybox's applets and the
// three mounts, which a run outside a guest leaves out.
const stage1Head = "#!/bin/busybox sh\n/bin/busybox --install -s /bin\nexport PATH=/bin\nmount -t proc proc /proc\nmount -t sysfs sys /sys\nmount -t devtmpfs dev /dev 2>/dev/null\n"

var _ = Describe("stage 1 of the guest's boot", func() {
	// Sizes in sectors: the volume image's, which is fixed, and a guest root
	// image of 64 MiB.
	const (
		volumeSectors = "2097152"
		rootSectors   = "131072"
		rootRatio     = "16384"
		bothDisks     = "RVM_ROOT_SECTORS=" + rootSectors + "\nRVM_ROOT_INODE_RATIO=" + rootRatio + "\nRVM_VOLUME_SECTORS=" + volumeSectors + "\n"
	)

	type stage1Run struct {
		out   string
		calls string
		code  int
	}

	var (
		dir     string
		bin     string
		callLog string
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		bin = filepath.Join(dir, "bin")
		callLog = filepath.Join(dir, "calls")
		for _, d := range []string{bin, filepath.Join(dir, "sys", "block"), filepath.Join(dir, "dev")} {
			Expect(os.MkdirAll(d, 0o755)).To(Succeed())
		}
		// Each stub records its argv; mke2fs exits MKE2FS_RC, and mount fails
		// for the filesystem type MOUNT_FAIL names. chroot also records the
		// directory it would enter. The runs call the stubs by path, because
		// the guest's busybox runs its own applets before anything on PATH.
		stub := func(name, body string) {
			script := "#!/bin/sh\necho \"" + name + " $*\" >> " + shellQuote(callLog) + "\n" + body + "\n"
			Expect(os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755)).To(Succeed())
		}
		stub("mke2fs", `exit "${MKE2FS_RC:-0}"`)
		stub("mount", `[ -n "${MOUNT_FAIL:-}" ] && [ "$2" = "$MOUNT_FAIL" ] && exit 32
exit 0`)
		stub("sleep", `exit 0`)
		stub("chroot", `echo "chroot in $(pwd -P)" >> `+shellQuote(callLog))
		stub("stage2", `exit 0`)
	})

	// disk adds the block device name to the fake sysfs with size sectors
	// and, unless content is nil, its device file with content.
	disk := func(name, sectors string, content []byte) {
		Expect(os.MkdirAll(filepath.Join(dir, "sys", "block", name), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "sys", "block", name, "size"), []byte(sectors+"\n"), 0o444)).To(Succeed())
		if content != nil {
			Expect(os.WriteFile(filepath.Join(dir, "dev", name), content, 0o600)).To(Succeed())
		}
	}
	dev := func(name string) string { return filepath.Join(dir, "dev", name) }

	// reset takes the test directory back to no devices, no calls, and no
	// mount points, keeping the stubs.
	reset := func() {
		for _, p := range []string{callLog, filepath.Join(dir, "disk"), filepath.Join(dir, "root"), filepath.Join(dir, "sys"), filepath.Join(dir, "dev")} {
			Expect(os.RemoveAll(p)).To(Succeed())
		}
		Expect(os.MkdirAll(filepath.Join(dir, "sys", "block"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(dir, "dev"), 0o755)).To(Succeed())
	}

	// blank is the start of a new image, and formatted that of a volume
	// that holds an ext2 filesystem, whose superblock magic sits 56 bytes
	// into the superblock at 1024.
	blank := make([]byte, 128<<10)
	formatted := make([]byte, 128<<10)
	formatted[1024+56], formatted[1024+57] = 0x53, 0xef

	// run executes stage 1 from rvm_fail on in shell, with disks as
	// /rvm/disks, the guest paths moved into the test directory, the
	// commands that would change the host stubbed, and reboot replaced by
	// a marker. dd, tr, rm, and mkdir are the real ones.
	run := func(shell guestShell, disks string, env ...string) stage1Run {
		Expect(os.WriteFile(filepath.Join(dir, "disks"), []byte(disks), 0o644)).To(Succeed())
		Expect(guestRootInit).To(HavePrefix(stage1Head))
		script := strings.NewReplacer(
			"/rvm/disks", filepath.Join(dir, "disks"),
			"/rvm/root-", filepath.Join(dir, "root-"),
			"/rvm/disk", filepath.Join(dir, "disk"),
			"/rvm/root", filepath.Join(dir, "root"),
			"/sys/block", filepath.Join(dir, "sys", "block"),
			"/dev/${rvm_b##*/}", filepath.Join(dir, "dev")+"/${rvm_b##*/}",
			"mke2fs -F", filepath.Join(bin, "mke2fs")+" -F",
			"mount -", filepath.Join(bin, "mount")+" -",
			"sleep 1", filepath.Join(bin, "sleep")+" 1",
			"exec chroot", "exec "+filepath.Join(bin, "chroot"),
			"exec /bin/sh", "exec "+filepath.Join(bin, "stage2"),
			"reboot -f", "echo REBOOT",
		).Replace(strings.TrimPrefix(guestRootInit, stage1Head))
		Expect(strings.ReplaceAll(script, guestStage2, "")).NotTo(ContainSubstring("/rvm/"))
		Expect(script).NotTo(ContainSubstring(" /sys/"))

		c := exec.Command(shell.argv[0], append(shell.argv[1:], "-c", script)...)
		c.Env = append([]string{"PATH=/usr/bin:/bin"}, env...)
		out, err := c.CombinedOutput()
		code := 0
		if err != nil {
			var exitErr *exec.ExitError
			Expect(errors.As(err, &exitErr)).To(BeTrue(), "%s: %v", shell.name, err)
			code = exitErr.ExitCode()
		}
		calls, err := os.ReadFile(callLog)
		if os.IsNotExist(err) {
			err = nil
		}
		Expect(err).NotTo(HaveOccurred())
		return stage1Run{out: string(out), calls: string(calls), code: code}
	}

	// failed expects r to have ended in rvm_fail with line, after nothing
	// but the calls in calls.
	failed := func(r stage1Run, line, calls string) {
		GinkgoHelper()
		Expect(r.out).To(HaveSuffix("vm-launch guest setup: "+line+"\nREBOOT\n"), r.out)
		Expect(r.code).To(Equal(1), r.out)
		Expect(r.calls).To(Equal(calls), r.out)
	}

	// entered is what the stubs record for a root disk at root that stage
	// 1 formats and enters, passing volume to stage 2.
	entered := func(root, volume string) string {
		d := filepath.Join(dir, "disk")
		r := filepath.Join(dir, "root")
		real, err := filepath.EvalSymlinks(dir)
		Expect(err).NotTo(HaveOccurred())
		return "mke2fs -F -b 4096 -m 0 -i " + rootRatio + " -L rvm-root " + root + "\n" +
			"mount -t ext4 -o noatime,discard,errors=continue " + root + " " + d + "\n" +
			"mount -t overlay -o lowerdir=/,upperdir=" + d + "/upper,workdir=" + d + "/work overlay " + r + "\n" +
			"mount -o move /proc " + r + "/proc\n" +
			"mount -o move /sys " + r + "/sys\n" +
			"mount -o move /dev " + r + "/dev\n" +
			"mount -o move . /\n" +
			"chroot . /bin/sh /rvm/init " + volume + "\n" +
			"chroot in " + filepath.Join(real, "root") + "\n"
	}

	DescribeTable("formats the one device of the root's size and hands the volume's device to stage 2, in either device order",
		func(shellOf func() guestShell) {
			shell := shellOf()
			for _, order := range [][2]string{{"vda", "vdb"}, {"vdb", "vda"}} {
				volume, root := order[0], order[1]
				reset()
				disk(volume, volumeSectors, formatted)
				disk(root, rootSectors, blank)

				r := run(shell, bothDisks)
				Expect(r.code).To(Equal(0), "%s, root %s: %s", shell.name, root, r.out)
				Expect(r.out).NotTo(ContainSubstring("vm-launch guest setup"))
				Expect(r.calls).To(Equal(entered(dev(root), dev(volume))), "%s, root %s", shell.name, root)
				Expect(r.calls).NotTo(ContainSubstring("mke2fs -F -b 4096 -m 0 -i " + rootRatio + " -L rvm-root " + dev(volume)))
				Expect(os.ReadFile(dev(volume))).To(Equal(formatted), "the volume is never written")
				Expect(filepath.Join(dir, "disk", "upper")).To(BeADirectory())
				Expect(filepath.Join(dir, "disk", "work")).To(BeADirectory())
				Expect(filepath.Join(dir, "root-head")).NotTo(BeAnExistingFile())
				Expect(filepath.Join(dir, "root-used")).NotTo(BeAnExistingFile())
			}
		},
		shellEntries(""),
	)

	DescribeTable("keeps the RAM root and formats nothing when /rvm/disks names no root disk",
		func(shellOf func() guestShell) {
			shell := shellOf()
			disk("vda", volumeSectors, formatted)
			r := run(shell, "RVM_VOLUME_SECTORS="+volumeSectors+"\n")
			Expect(r.code).To(Equal(0), r.out)
			Expect(r.calls).To(Equal("stage2 /rvm/init " + dev("vda") + "\n"))
			Expect(filepath.Join(dir, "disk")).NotTo(BeAnExistingFile())
			Expect(os.ReadFile(dev("vda"))).To(Equal(formatted))

			Expect(os.Remove(callLog)).To(Succeed())
			r = run(shell, "")
			Expect(r.code).To(Equal(0), r.out)
			Expect(r.calls).To(Equal("stage2 /rvm/init \n"))
		},
		shellEntries(""),
	)

	DescribeTable("never formats the volume: it fails before touching any device when the sizes cannot tell the drives apart",
		func(shellOf func() guestShell) {
			shell := shellOf()
			disk("vda", volumeSectors, formatted)
			r := run(shell, "RVM_ROOT_SECTORS="+volumeSectors+"\nRVM_ROOT_INODE_RATIO="+rootRatio+"\nRVM_VOLUME_SECTORS="+volumeSectors+"\n")
			failed(r, "the guest root and the volume have the same size, so the guest cannot tell them apart", "")
			Expect(os.ReadFile(dev("vda"))).To(Equal(formatted))
		},
		shellEntries(""),
	)

	DescribeTable("never formats the volume: it fails when two devices have the root's size",
		func(shellOf func() guestShell) {
			shell := shellOf()
			disk("vda", rootSectors, formatted)
			disk("vdb", rootSectors, blank)
			disk("vdc", volumeSectors, formatted)
			r := run(shell, bothDisks)
			failed(r, "two block devices, "+dev("vda")+" and "+dev("vdb")+", have the size of the guest root, so the guest cannot tell which one it is", "")
			Expect(os.ReadFile(dev("vda"))).To(Equal(formatted))
		},
		shellEntries(""),
	)

	DescribeTable("never formats the volume: it fails when the device of the root's size is not blank",
		func(shellOf func() guestShell) {
			shell := shellOf()
			// A volume that stood where the root disk should be, as when a
			// host passed the wrong file.
			disk("vda", rootSectors, formatted)
			disk("vdb", volumeSectors, blank)
			r := run(shell, bothDisks)
			failed(r, "the guest root disk "+dev("vda")+" is not blank, so vm-launch will not format it", "")
			Expect(os.ReadFile(dev("vda"))).To(Equal(formatted))
			Expect(filepath.Join(dir, "root-head")).NotTo(BeAnExistingFile())
		},
		shellEntries(""),
	)

	DescribeTable("fails rather than guess when /rvm/disks gives a size that is not a sector count",
		func(shellOf func() guestShell) {
			shell := shellOf()
			disk("vda", volumeSectors, formatted)
			disk("vdb", rootSectors, blank)
			// The harness moves /rvm/disks into dir, and the messages name it.
			disksPath := filepath.Join(dir, "disks")
			rootLine := "the guest root size or inode ratio in " + disksPath + " is not a positive number"
			volumeLine := "the volume size in " + disksPath + " is not a positive number"
			for disks, line := range map[string]string{
				"RVM_ROOT_SECTORS=" + rootSectors + "\n":                                                                 rootLine,
				"RVM_ROOT_SECTORS=" + rootSectors + "\nRVM_ROOT_INODE_RATIO=\n":                                          rootLine,
				"RVM_ROOT_SECTORS=0" + rootSectors + "\nRVM_ROOT_INODE_RATIO=" + rootRatio + "\n":                        rootLine,
				"RVM_ROOT_SECTORS='" + rootSectors + " '\nRVM_ROOT_INODE_RATIO=" + rootRatio + "\n":                      rootLine,
				"RVM_ROOT_SECTORS=-1\nRVM_ROOT_INODE_RATIO=" + rootRatio + "\n":                                          rootLine,
				"RVM_ROOT_SECTORS=" + rootSectors + "\nRVM_ROOT_INODE_RATIO=16k\n":                                       rootLine,
				"RVM_ROOT_SECTORS=" + rootSectors + "\nRVM_ROOT_INODE_RATIO=0\n":                                         rootLine,
				"RVM_VOLUME_SECTORS=1GiB\n":                                                                              volumeLine,
				"RVM_VOLUME_SECTORS=0\n":                                                                                 volumeLine,
				"RVM_ROOT_SECTORS=" + rootSectors + "\nRVM_ROOT_INODE_RATIO=" + rootRatio + "\nRVM_VOLUME_SECTORS='*'\n": volumeLine,
			} {
				Expect(os.RemoveAll(callLog)).To(Succeed())
				r := run(shell, disks)
				Expect(r.out).To(HaveSuffix("vm-launch guest setup: "+line+"\nREBOOT\n"), "%s: %q", shell.name, disks)
				Expect(r.calls).To(BeEmpty(), "%s: %q", shell.name, disks)
			}
		},
		shellEntries(""),
	)

	DescribeTable("fails after six checks, before it formats anything, when a drive never appears",
		func(shellOf func() guestShell) {
			shell := shellOf()
			for _, present := range []struct{ name, sectors string }{{"vda", volumeSectors}, {"vda", rootSectors}} {
				reset()
				disk(present.name, present.sectors, blank)
				r := run(shell, bothDisks)
				failed(r, "no block device of the expected size for the guest root or the volume", strings.Repeat("sleep 1\n", 5))
			}
		},
		shellEntries(""),
	)

	DescribeTable("skips a device whose size cannot be read",
		func(shellOf func() guestShell) {
			shell := shellOf()
			// vda has no size file and vdb's is a directory, which every
			// user, root included, fails to read.
			Expect(os.MkdirAll(filepath.Join(dir, "sys", "block", "vda"), 0o755)).To(Succeed())
			Expect(os.MkdirAll(filepath.Join(dir, "sys", "block", "vdb", "size"), 0o755)).To(Succeed())
			disk("vdc", rootSectors, blank)
			disk("vdd", volumeSectors, formatted)
			r := run(shell, bothDisks)
			Expect(r.code).To(Equal(0), r.out)
			Expect(r.calls).To(Equal(entered(dev("vdc"), dev("vdd"))))
		},
		shellEntries(""),
	)

	It("treats a read error, or a root disk it read nothing from, as a failure, never as a blank disk", func() {
		shell := hostShell()
		disk("vda", volumeSectors, formatted)
		// vdb is in sysfs and has no device file, so dd cannot open it.
		disk("vdb", rootSectors, nil)
		failed(run(shell, bothDisks), "reading the start of the guest root disk "+dev("vdb")+" failed", "")

		Expect(os.WriteFile(dev("vdb"), nil, 0o600)).To(Succeed())
		failed(run(shell, bothDisks), "the guest root disk "+dev("vdb")+" is not blank, so vm-launch will not format it", "")
	})

	It("names the step that failed, and stops there", func() {
		shell := hostShell()
		disk("vda", volumeSectors, formatted)
		disk("vdb", rootSectors, blank)
		root := dev("vdb")
		mke2fs := "mke2fs -F -b 4096 -m 0 -i " + rootRatio + " -L rvm-root " + root + "\n"
		ext4 := "mount -t ext4 -o noatime,discard,errors=continue " + root + " " + filepath.Join(dir, "disk") + "\n"

		failed(run(shell, bothDisks, "MKE2FS_RC=1"), "formatting the guest root disk "+root+" failed", mke2fs)

		Expect(os.Remove(callLog)).To(Succeed())
		failed(run(shell, bothDisks, "MOUNT_FAIL=ext4"), "mounting the guest root disk "+root+" failed", mke2fs+ext4)

		Expect(os.Remove(callLog)).To(Succeed())
		Expect(os.RemoveAll(filepath.Join(dir, "disk"))).To(Succeed())
		r := run(shell, bothDisks, "MOUNT_FAIL=overlay")
		Expect(r.out).To(HaveSuffix("vm-launch guest setup: mounting the overlay root failed; the guest kernel needs overlayfs\nREBOOT\n"))
		Expect(r.calls).NotTo(ContainSubstring("move"))
		Expect(r.calls).NotTo(ContainSubstring("chroot"))

		Expect(os.Remove(callLog)).To(Succeed())
		Expect(os.RemoveAll(filepath.Join(dir, "disk"))).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "disk"), nil, 0o600)).To(Succeed())
		failed(run(shell, bothDisks), "creating the guest root mount points failed", mke2fs)
	})
})
