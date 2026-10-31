//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// The /rvm/init script, stage 2 of the guest's boot, of a guest without a
// volume, for testNonce, which every guest gets, a task's included. It brings
// up the network, checks that the guest environment sources, and runs the
// command in a subshell with the guest environment. A guest without a volume
// must keep getting exactly this.
const (
	goldenInitNet = "#!/bin/busybox sh\nexport PATH=/bin\nrvm_fail() { echo \"vm-launch guest setup: $1\"; reboot -nf; exit 1; }\nstty -echo </dev/console || echo \"vm-launch guest setup: turning off console echo failed; a stop request will appear in the output\"\nmkdir -p /dev/shm && mount -t tmpfs -o noexec,nosuid,nodev,mode=1777,size=50% tmpfs /dev/shm || rvm_fail \"mounting /dev/shm failed\"\n. /rvm/net\nip link set lo up || rvm_fail \"bringing up lo failed\"\nn=0\nwhile [ ! -e /sys/class/net/eth0 ]; do\n\tn=$((n + 1))\n\t[ \"$n\" -gt 5 ] && rvm_fail \"no eth0 network device\"\n\tsleep 1\ndone\nif [ -n \"${RVM_MTU:-}\" ]; then\n\tip link set eth0 mtu \"$RVM_MTU\" || echo \"vm-launch guest setup: setting the mtu of eth0 to $RVM_MTU failed; keeping the default mtu\"\nfi\nip link set eth0 up || rvm_fail \"bringing up eth0 failed\"\nip addr add \"$RVM_ADDRESS\" dev eth0 || rvm_fail \"adding $RVM_ADDRESS to eth0 failed\"\nip route add default via \"$RVM_GATEWAY\" dev eth0 || rvm_fail \"adding the default route via $RVM_GATEWAY failed\"\n. /rvm/limits\necho 9223372036854775807 >/proc/sys/fs/file-max || echo \"vm-launch guest setup: raising fs.file-max failed; keeping the default\"\nrvm_nr_open=$(cat /proc/sys/fs/nr_open) || rvm_fail \"reading fs.nr_open failed\"\nif [ \"$rvm_nr_open\" -lt \"$RVM_NOFILE_HARD\" ]; then\n\techo \"$RVM_NOFILE_HARD\" >/proc/sys/fs/nr_open || rvm_fail \"raising fs.nr_open to $RVM_NOFILE_HARD failed\"\nfi\n( ulimit -n \"$RVM_NOFILE_HARD\" && ulimit -S -n \"$RVM_NOFILE_SOFT\" ) || rvm_fail \"setting the open files limit to $RVM_NOFILE_SOFT soft and $RVM_NOFILE_HARD hard failed\"\n( . /rvm/env ) || rvm_fail \"reading /rvm/env failed\"\n(\n\techo -1000 >/proc/self/oom_score_adj\n\trvm_stop=\n\twhile IFS= read -r rvm_line; do\n\t\tif [ \"$rvm_line\" = \"RVM_STOP_0123456789abcdef\" ]; then\n\t\t\trvm_stop=1\n\t\t\tbreak\n\t\tfi\n\tdone </dev/console\n\t[ -n \"$rvm_stop\" ] || exit 0\n\tuntil read -r rvm_app 2>/dev/null </rvm/app-pid && [ -n \"$rvm_app\" ]; do\n\t\tsleep 0.05\n\tdone\n\tkill -TERM \"$rvm_app\"\n) </dev/null &\nrvm_reader=$!\necho RVM_START_0123456789abcdef\nrvm_watch=\nif [ -n \"${RVM_PORTS:-}\" ]; then\n\trvm_ports=\n\trvm_hexes=\" \"\n\tfor rvm_dec in $RVM_PORTS; do\n\t\trvm_hex=$(printf '%04X' \"$rvm_dec\")\n\t\trvm_ports=\"$rvm_ports $rvm_dec:$rvm_hex\"\n\t\trvm_hexes=\"$rvm_hexes$rvm_hex \"\n\tdone\n\trvm_tables=\n\tfor rvm_table in /proc/net/tcp /proc/net/tcp6; do\n\t\t[ -e \"$rvm_table\" ] && rvm_tables=\"$rvm_tables $rvm_table\"\n\tdone\n\t(\n\t\tif [ -p /rvm/listen-tick ] && command exec 3<>/rvm/listen-tick; then\n\t\t\trvm_pause() { read -t 1 -u 3 rvm_tick; }\n\t\telse\n\t\t\trvm_pause() { sleep 1; }\n\t\tfi\n\t\trvm_upset=\" \"\n\t\trvm_look=0\n\t\twhile :; do\n\t\t\trvm_seen=\" \"\n\t\t\trvm_failed=\n\t\t\tfor rvm_table in $rvm_tables; do\n\t\t\t\trvm_head=\n\t\t\t\twhile read -r rvm_sl rvm_local rvm_remote rvm_st rvm_rest; do\n\t\t\t\t\tif [ -z \"$rvm_head\" ]; then\n\t\t\t\t\t\trvm_head=1\n\t\t\t\t\t\tcontinue\n\t\t\t\t\tfi\n\t\t\t\t\t[ \"$rvm_st\" = 0A ] || break\n\t\t\t\t\tcase \"$rvm_hexes\" in\n\t\t\t\t\t*\" ${rvm_local##*:} \"*) ;;\n\t\t\t\t\t*) continue ;;\n\t\t\t\t\tesac\n\t\t\t\t\tcase ${rvm_local%:*} in\n\t\t\t\t\t??????7F | 00000000000000000000000001000000 | 0000000000000000FFFF0000??????7F) ;;\n\t\t\t\t\t*) rvm_seen=\"$rvm_seen${rvm_local##*:} \" ;;\n\t\t\t\t\tesac\n\t\t\t\tdone 2>/dev/null <\"$rvm_table\"\n\t\t\t\t[ -n \"$rvm_head\" ] || rvm_failed=1\n\t\t\tdone\n\t\t\trvm_look=$((rvm_look + 1))\n\t\t\trvm_all=\n\t\t\tif [ \"$rvm_look\" -ge 5 ]; then\n\t\t\t\trvm_all=1\n\t\t\t\trvm_look=0\n\t\t\tfi\n\t\t\trvm_nextup=\" \"\n\t\t\tfor rvm_pp in $rvm_ports; do\n\t\t\t\trvm_hex=${rvm_pp#*:}\n\t\t\t\tcase \"$rvm_seen\" in\n\t\t\t\t*\" $rvm_hex \"*) rvm_now=1 ;;\n\t\t\t\t*) rvm_now=0 ;;\n\t\t\t\tesac\n\t\t\t\tcase \"$rvm_upset\" in\n\t\t\t\t*\" $rvm_hex \"*) rvm_was=1 ;;\n\t\t\t\t*) rvm_was=0 ;;\n\t\t\t\tesac\n\t\t\t\tif [ \"$rvm_now\" = 0 ] && [ -n \"$rvm_failed\" ]; then\n\t\t\t\t\trvm_now=$rvm_was\n\t\t\t\tfi\n\t\t\t\tif [ \"$rvm_now\" != \"$rvm_was\" ] || [ -n \"$rvm_all\" ]; then\n\t\t\t\t\techo \"RVM_LISTEN_0123456789abcdef=${rvm_pp%:*}:$rvm_now\" >/dev/console && rvm_was=$rvm_now\n\t\t\t\tfi\n\t\t\t\tif [ \"$rvm_was\" = 1 ]; then\n\t\t\t\t\trvm_nextup=\"$rvm_nextup$rvm_hex \"\n\t\t\t\tfi\n\t\t\tdone\n\t\t\trvm_upset=$rvm_nextup\n\t\t\trvm_pause\n\t\tdone\n\t) </dev/null &\n\trvm_watch=$!\nfi\ncommand exec 3>&2 2>/dev/null\n( command exec 2>&3 3>&-; { read -r rvm_self rvm_rest </proc/self/stat && echo \"$rvm_self\" >/rvm/app-pid; } || echo \"vm-launch guest: recording the command's pid in /rvm/app-pid failed; a stop request cannot reach the command\"; ulimit -n \"$RVM_NOFILE_HARD\" && ulimit -S -n \"$RVM_NOFILE_SOFT\" && . /rvm/env && exec sh -c \"$(cat /rvm/cmd)\" ) </dev/null\nrvm_status=$?\ncommand exec 2>&3 3>&-\nkill \"$rvm_reader\" 2>/dev/null\nwait \"$rvm_reader\" 2>/dev/null\nif [ -n \"$rvm_watch\" ]; then\n\tkill \"$rvm_watch\"\n\twait \"$rvm_watch\"\nfi\nrvm_oom=0\nwhile read -r rvm_key rvm_val; do\n\tif [ \"$rvm_key\" = oom_kill ]; then\n\t\trvm_oom=$rvm_val\n\t\tbreak\n\tfi\ndone 2>/dev/null </proc/vmstat\ncase \"$rvm_oom\" in\n'' | *[!0-9]* | 0 | 0[0-9]*) ;;\n*) echo RVM_OOM_0123456789abcdef=$rvm_oom >/dev/console || echo RVM_OOM_0123456789abcdef=$rvm_oom;;\nesac\necho RVM_EXIT_0123456789abcdef=$rvm_status >/dev/console || echo RVM_EXIT_0123456789abcdef=$rvm_status\nreboot -nf\n"
)

// goldenRootInit is the /init script, stage 1 of the guest's boot, of every
// guest. It finds the drives by identity and checks their sizes, formats a
// blank guest root disk and enters the overlay root on it when /rvm/disks
// names one, and runs stage 2 with each volume's device.
const goldenRootInit = `#!/bin/busybox sh
/bin/busybox --install -s /bin
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
rvm_devtmpfs=
mount -t devtmpfs dev /dev 2>/dev/null && rvm_devtmpfs=1
rvm_fail() { echo "vm-launch guest setup: $1"; reboot -nf; exit 1; }
rvm_number() { case "$1" in '' | 0* | *[!0-9]*) return 1 ;; esac; }
rvm_ident() {
	case "$1" in '' | *[!A-Za-z0-9-]*) return 1 ;; esac
	[ "${#1}" -le 20 ]
}
rvm_scan() {
	rvm_missing=
	for rvm_d in $rvm_drives; do
		eval "rvm_dev_$rvm_d="
	done
	for rvm_b in /sys/block/vd*; do
		[ -e "$rvm_b" ] || continue
		rvm_n=/dev/${rvm_b##*/}
		if ! rvm_id=$(cat "$rvm_b/serial" 2>/dev/null); then
			rvm_missing="${rvm_missing:+$rvm_missing, and }no readable identity yet on the block device $rvm_n"
			continue
		fi
		[ -n "$rvm_id" ] || rvm_fail "the block device $rvm_n has no identity, so it is no drive /rvm/disks names, and the guest will not boot with it"
		rvm_m=
		for rvm_d in $rvm_drives; do
			eval "rvm_w=\$rvm_want_$rvm_d"
			if [ "$rvm_w" = "$rvm_id" ]; then
				rvm_m=$rvm_d
				break
			fi
		done
		[ -n "$rvm_m" ] || rvm_fail "the block device $rvm_n has the identity $rvm_id, which /rvm/disks gives no drive, so the guest will not boot with it"
		eval "rvm_o=\$rvm_dev_$rvm_m rvm_l=\$rvm_label_$rvm_m rvm_w=\$rvm_sectors_$rvm_m"
		[ -z "$rvm_o" ] || rvm_fail "two block devices, $rvm_o and $rvm_n, have the identity $rvm_id of the $rvm_l, so the guest cannot tell which one it is"
		eval "rvm_dev_$rvm_m=\$rvm_n"
		if [ -r "$rvm_b/size" ] && read -r rvm_s 2>/dev/null <"$rvm_b/size"; then
			[ "$rvm_s" = "$rvm_w" ] || rvm_fail "the $rvm_l $rvm_n has $rvm_s sectors, and /rvm/disks gives it $rvm_w, so the guest will not use it"
			[ -b "$rvm_n" ] || rvm_missing="${rvm_missing:+$rvm_missing, and }no device node $rvm_n yet for the $rvm_l"
		else
			rvm_missing="${rvm_missing:+$rvm_missing, and }no readable size yet for the $rvm_l on $rvm_n"
		fi
	done
	for rvm_d in $rvm_drives; do
		eval "rvm_o=\$rvm_dev_$rvm_d rvm_l=\$rvm_label_$rvm_d rvm_w=\$rvm_want_$rvm_d"
		[ -n "$rvm_o" ] || rvm_missing="${rvm_missing:+$rvm_missing, and }no block device with the identity $rvm_w for the $rvm_l"
	done
	[ -z "$rvm_missing" ]
}
. /rvm/disks
rvm_drives=
rvm_dev_root=
if [ -n "${RVM_ROOT_ID:-}${RVM_ROOT_SECTORS:-}" ]; then
	rvm_number "${RVM_ROOT_SECTORS:-}" && rvm_number "${RVM_ROOT_INODE_RATIO:-}" || rvm_fail "the guest root size or inode ratio in /rvm/disks is not a positive number"
	rvm_ident "${RVM_ROOT_ID:-}" || rvm_fail "the guest root drive's identity in /rvm/disks is not 1 to 20 letters, digits, and hyphens"
	rvm_drives=root
	rvm_want_root=$RVM_ROOT_ID
	rvm_sectors_root=$RVM_ROOT_SECTORS
	rvm_label_root="guest root drive"
fi
case "${RVM_VOLUMES:-}" in
[0-4]) ;;
*) rvm_fail "the volume count in /rvm/disks is not a number from 0 to 4" ;;
esac
rvm_i=0
while [ "$rvm_i" -lt "$RVM_VOLUMES" ]; do
	rvm_l="volume drive vol$rvm_i"
	eval "rvm_k=\${RVM_VOL${rvm_i}_KIND:-} rvm_w=\${RVM_VOL${rvm_i}_ID:-} rvm_s=\${RVM_VOL${rvm_i}_SECTORS:-}"
	case "$rvm_k" in
	image | block) ;;
	share)
		[ -z "$rvm_w$rvm_s" ] || rvm_fail "the volume vol$rvm_i in /rvm/disks is a share, which has no drive, yet it has a drive identity or size"
		eval "rvm_dev_vol$rvm_i="
		rvm_i=$((rvm_i + 1))
		continue
		;;
	'') rvm_fail "the $rvm_l in /rvm/disks has no kind" ;;
	*) rvm_fail "the $rvm_l in /rvm/disks has the kind $rvm_k, which the guest does not know" ;;
	esac
	rvm_ident "$rvm_w" || rvm_fail "the $rvm_l's identity in /rvm/disks is not 1 to 20 letters, digits, and hyphens"
	rvm_number "$rvm_s" || rvm_fail "the $rvm_l's size in /rvm/disks is not a positive number"
	for rvm_d in $rvm_drives; do
		eval "rvm_o=\$rvm_want_$rvm_d rvm_ol=\$rvm_label_$rvm_d"
		[ "$rvm_o" != "$rvm_w" ] || rvm_fail "the $rvm_ol and the $rvm_l have the one identity $rvm_w in /rvm/disks, so the guest cannot tell them apart"
	done
	eval "rvm_want_vol$rvm_i=\$rvm_w rvm_sectors_vol$rvm_i=\$rvm_s rvm_label_vol$rvm_i=\$rvm_l"
	rvm_drives="$rvm_drives vol$rvm_i"
	rvm_i=$((rvm_i + 1))
done
n=0
until rvm_scan; do
	n=$((n + 1))
	[ "$n" -gt 5 ] && rvm_fail "$rvm_missing"
	sleep 1
done
rvm_root=${rvm_dev_root:-}
set --
rvm_i=0
while [ "$rvm_i" -lt "$RVM_VOLUMES" ]; do
	eval "set -- \"\$@\" \"\$rvm_dev_vol$rvm_i\""
	rvm_i=$((rvm_i + 1))
done
if [ -n "$rvm_root" ]; then
	[ -n "$rvm_devtmpfs" ] || rvm_fail "mounting devtmpfs at /dev failed"
	dd if="$rvm_root" of=/rvm/root-head bs=4096 count=16 || rvm_fail "reading the start of the guest root disk $rvm_root failed"
	tr -d '\000' </rvm/root-head >/rvm/root-used || rvm_fail "checking whether the guest root disk $rvm_root is blank failed"
	rvm_blank=
	[ -s /rvm/root-head ] && [ ! -s /rvm/root-used ] && rvm_blank=1
	rm -f /rvm/root-head /rvm/root-used
	[ -n "$rvm_blank" ] || rvm_fail "the guest root disk $rvm_root is not blank, so vm-launch will not format it"
	mke2fs -F -b 4096 -m 0 -I 256 -i "$RVM_ROOT_INODE_RATIO" -L rvm-root "$rvm_root" || rvm_fail "formatting the guest root disk $rvm_root failed"
	mkdir -p /rvm/disk /rvm/root || rvm_fail "creating the guest root mount points failed"
	mount -t ext4 -o noatime,discard,errors=continue "$rvm_root" /rvm/disk || rvm_fail "mounting the guest root disk $rvm_root failed"
	mkdir /rvm/disk/upper /rvm/disk/work || rvm_fail "creating the overlay directories failed"
	mount -t overlay -o lowerdir=/,upperdir=/rvm/disk/upper,workdir=/rvm/disk/work overlay /rvm/root || rvm_fail "mounting the overlay root failed; the guest kernel needs overlayfs"
	[ -x /rvm/root/bin/sh ] || rvm_fail "the overlay root has no /bin/sh to run stage 2"
	[ -r /rvm/root/rvm/init ] || rvm_fail "the overlay root has no /rvm/init"
	for rvm_m in proc sys dev; do
		mount -o move "/$rvm_m" "/rvm/root/$rvm_m" || rvm_fail "moving /$rvm_m into the overlay root failed"
	done
	cd /rvm/root && mount -o move . / || rvm_fail "moving the overlay root onto / failed"
	exec chroot . /bin/sh /rvm/init "$@"
fi
exec /bin/sh /rvm/init "$@"
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

	It("writes the numbers stage 1 compares in the text it gives the guest's shell", func() {
		Expect(virtioBlockIDBytesText).To(Equal(strconv.Itoa(virtioBlockIDBytes)))
		Expect(maxVolumesText).To(Equal(strconv.Itoa(maxVolumes)))
		Expect(maxVolumesText).To(HaveLen(1), "stage 1 matches the volume count with a one-digit pattern")
	})

	It("adds /rvm/mounts with the count, the kind, the quoted path, and the image name, and the volume's drive to /rvm/disks", func() {
		names, byName := archiveEntries(writeArchive(task, vol))
		Expect(names).To(Equal([]string{"bin", "dev", "dev/console", "dev/null", "etc", "proc", "sys", "tmp", "rvm",
			"bin/busybox", "rvm/cmd", "rvm/net", "rvm/env", "rvm/limits", "etc/resolv.conf", "rvm/mounts", "rvm/disks", "rvm/init", "init", cpioTrailer}))
		Expect(string(byName["rvm/mounts"].data)).To(Equal(
			"RVM_VOLUMES=1\nRVM_SYNC_MOUNTS=true\nRVM_VOL0_KIND=image\nRVM_VOL0_PATH='/data/it'\\''s $here'\nRVM_VOL0_IMAGE='rvm-disk-3.img'\n"))
		Expect(byName["rvm/mounts"].mode).To(Equal(uint32(0o100644)))
		Expect(string(byName["rvm/disks"].data)).To(Equal("RVM_VOLUMES=1\nRVM_VOL0_KIND=image\nRVM_VOL0_ID=rvm-vol0\nRVM_VOL0_SECTORS=2097152\n"))
		Expect(string(byName["rvm/init"].data)).To(Equal(initScript(testNonce, true)))
	})

	It("names every volume in /rvm/mounts by its index, in volume order, with its drive's kind, so that each sources back as it was", func() {
		g := taskGuest("true")
		g.vols = []guestVolume{*vol, {ContainerDir: "/home/vcap/logs", ImageName: "rvm-disk-3.img"}, {ContainerDir: "/x y", ImageName: "z"}}
		g.drives.volumes = qemuImageDrives(defaultImageSize, defaultImageSize, defaultImageSize)
		g.drives.volumes[1].kind = driveBlock
		got, err := mountsFile(g)
		Expect(err).NotTo(HaveOccurred())
		// A block volume has no image file, so /rvm/mounts names none for it.
		Expect(got).To(Equal("RVM_VOLUMES=3\nRVM_SYNC_MOUNTS=true\n" +
			"RVM_VOL0_KIND=image\nRVM_VOL0_PATH='/data/it'\\''s $here'\nRVM_VOL0_IMAGE='rvm-disk-3.img'\n" +
			"RVM_VOL1_KIND=block\nRVM_VOL1_PATH='/home/vcap/logs'\n" +
			"RVM_VOL2_KIND=image\nRVM_VOL2_PATH='/x y'\nRVM_VOL2_IMAGE='z'\n"))
		out, err := exec.Command("/bin/sh", "-c", `. "$1"; printf '%s|' "${RVM_VOLUME_PATH-unset}" "$RVM_VOLUMES" "$RVM_SYNC_MOUNTS" "$RVM_VOL0_KIND" "$RVM_VOL0_PATH" "$RVM_VOL0_IMAGE" "$RVM_VOL1_KIND" "$RVM_VOL1_PATH" "${RVM_VOL1_IMAGE-unset}" "$RVM_VOL2_PATH" "$RVM_VOL2_IMAGE"`, "sh", writeTempFile("mounts", got)).Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(out)).To(Equal("unset|3|true|image|/data/it's $here|rvm-disk-3.img|block|/home/vcap/logs|unset|/x y|z|"))

		// /rvm/disks gives each drive the same kind, from the same entry.
		disks, err := disksFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(disks).To(ContainSubstring("RVM_VOL0_KIND=image\n"))
		Expect(disks).To(ContainSubstring("RVM_VOL1_KIND=block\n"))
		Expect(disks).To(ContainSubstring("RVM_VOL2_KIND=image\n"))
	})

	It("refuses volume drives that do not match the volumes one for one, or a kind stage 2 cannot mount, so no initramfs is built", func() {
		g := taskGuest("true")
		g.vols = []guestVolume{*vol, {ContainerDir: "/home/vcap/logs", ImageName: "rvm-disk-3.img"}}
		g.drives.volumes = qemuImageDrives(defaultImageSize)
		_, err := mountsFile(g)
		Expect(err).To(MatchError("1 volume drives for 2 guest volumes"))

		g.drives.volumes = qemuImageDrives(defaultImageSize, defaultImageSize)
		for _, kind := range []driveKind{"", volumeKindShare, "plain"} {
			g.drives.volumes[1].kind = kind
			_, err = mountsFile(g)
			Expect(err).To(MatchError(fmt.Sprintf(`drive vol1 holds a %q, and the guest mounts only "image" and "block" volume drives`, kind)), "kind %q", kind)
		}
	})

	It("records in /rvm/mounts whether the operator keeps image mounts synchronous, which they are unless it says otherwise", func() {
		g := taskGuest("true")
		g.vols = []guestVolume{*vol, {ContainerDir: "/disk", ImageName: "unused"}}
		g.drives.volumes = qemuImageDrives(defaultImageSize, defaultImageSize)
		g.drives.volumes[1].kind = driveBlock
		got, err := mountsFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HavePrefix("RVM_VOLUMES=2\nRVM_SYNC_MOUNTS=true\nRVM_VOL0_KIND=image\n"))
		Expect(strings.Count(got, "RVM_SYNC_MOUNTS")).To(Equal(1))

		g.noVolumeSync = true
		off, err := mountsFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(off).To(Equal(strings.Replace(got, "RVM_SYNC_MOUNTS=true\n", "RVM_SYNC_MOUNTS=false\n", 1)))
		var archive bytes.Buffer
		Expect(writeInitramfsArchive(&archive, strings.NewReader("busybox"), int64(len("busybox")), g)).To(Succeed())
		_, byName := archiveEntries(archive.Bytes())
		Expect(string(byName["rvm/mounts"].data)).To(Equal(off))
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

	It("mounts the volumes before the start tag and unmounts them after the command, before the exit tag", func() {
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
			guestStopReaderStop + guestListenStop + guestOOMReport(testNonce) + guestVolumeTeardown + "echo RVM_EXIT_" + testNonce + "=$rvm_status >/dev/console || echo RVM_EXIT_" + testNonce + "=$rvm_status\nreboot -nf\n"))
	})

	It("formats only after a blank check, with the shipped mke2fs and its pinned configuration, and preens every other image", func() {
		Expect(guestVolumeSetup).To(HavePrefix(". /rvm/mounts\n"))
		Expect(guestVolumeSetup).To(ContainSubstring(`dd if="$rvm_vdev" of=/rvm/volume-head bs=4096 count=16 || rvm_fail`))
		Expect(guestVolumeSetup).To(ContainSubstring("\n\t\t\tMKE2FS_CONFIG=/rvm/tools/mke2fs.conf /rvm/tools/mke2fs -t ext4 -F -b 4096 -m 0 -L rvm-volume -E lazy_itable_init=1,lazy_journal_init=1,nodiscard,assume_storage_prezeroed=1 \"$rvm_vdev\" || rvm_fail"))
		Expect(guestVolumeSetup).To(ContainSubstring("\n\t\t\t/rvm/tools/e2fsck -p \"$rvm_vdev\" || rvm_vrc=$?\n"))
		Expect(guestVolumeSetup).To(ContainSubstring(`mount -t ext4 -o "$rvm_vopts" "$rvm_vdev" "$rvm_vpath"`))
		Expect(guestVolumeSetup).To(ContainSubstring("rvm_vopts=sync,dirsync,noatime,noinit_itable,errors=remount-ro\n"))
		Expect(guestVolumeSetup).To(ContainSubstring(`*" has_journal "*) rvm_vjournal=yes ;;`))
		Expect(guestVolumeSetup).To(ContainSubstring("\tyes) rvm_vopts=noatime,noinit_itable,errors=remount-ro ;;\n"))
		// Every e2fsprogs tool runs by its full path, never as a busybox
		// applet, and nothing runs e2fsck in a mode that answers yes. The
		// lines stage 2 prints are in double quotes and may name a tool.
		commands := regexp.MustCompile(`"[^"]*"`).ReplaceAllString(guestVolumeSetup, `""`)
		for _, tool := range []string{"mke2fs", "e2fsck", "tune2fs", "ext4grow", "resize2fs"} {
			Expect(strings.Count(commands, tool)).To(Equal(strings.Count(commands, guestToolsDir+"/"+tool)), "%s runs without its path", tool)
		}
		Expect(strings.Count(commands, guestMke2fs+" -")).To(Equal(1))
		// e2fsck runs only as e2fsck -p and e2fsck -f -p, tune2fs only to
		// read the superblock and to add the legacy image's journal, and
		// ext4grow only on the mounted volume.
		for tool, forms := range map[string][]string{
			guestE2fsck:   {` -p "$rvm_vdev" || rvm_vrc=$?`, ` -f -p "$rvm_vdev" || rvm_vrc=$?`},
			guestTune2fs:  {` -l "$rvm_vdev" >` + guestVolumeSuper + ` 2>/dev/null`, ` -O has_journal -J size=4 "$rvm_vdev"; then`},
			guestExt4grow: {` "$rvm_vdev" "$rvm_vpath" || echo`},
		} {
			n := 0
			for _, form := range forms {
				c := strings.Count(guestVolumeSetup, tool+form)
				Expect(c).To(BeNumerically(">", 0), "%s%s", tool, form)
				n += c
			}
			// The lists of the tools that an arm checks for name them too.
			listed := strings.Count(strings.Join(regexp.MustCompile(`for rvm_vtool in [^;]*;`).FindAllString(commands, -1), ""), tool)
			Expect(strings.Count(commands, tool)-listed).To(Equal(n), "%s runs in another form", tool)
		}
		Expect(strings.Count(guestVolumeSetup, guestTune2fs+" -l")).To(Equal(1), "the superblock is read in one place")
		Expect(strings.Count(guestVolumeSetup, guestTune2fs+" -O")).To(Equal(1))
		Expect(strings.Count(guestVolumeSetup, guestExt4grow+" ")).To(Equal(1))
		Expect(guestLegacyJournalMiB).To(Equal("4"))
		Expect(guestLegacyJournalBytesText).To(Equal(strconv.Itoa(4 << 20)))
		Expect(guestLegacyJournalSlack).To(Equal("32"))
		Expect(sectorBytesText).To(Equal(strconv.Itoa(sectorBytes)))
		Expect(guestVolumeSetup).NotTo(ContainSubstring("-y"))
		Expect(guestVolumeSetup).NotTo(ContainSubstring("resize2fs"))
		Expect(guestMke2fs).To(Equal("/rvm/tools/mke2fs"))
		Expect(guestMke2fsConfig).To(Equal("/rvm/tools/mke2fs.conf"))
	})

	// volumeArm returns the text of the arm of stage 2's kind case for kind,
	// from its pattern to its ;;.
	volumeArm := func(kind string) string {
		GinkgoHelper()
		start := strings.Index(guestVolumeSetup, "\n\t"+kind+")\n")
		Expect(start).To(BeNumerically(">", 0), "no arm for %s", kind)
		end := strings.Index(guestVolumeSetup[start:], "\n\t\t;;\n")
		Expect(end).To(BeNumerically(">", 0), "no end for the %s arm", kind)
		return guestVolumeSetup[start : start+end]
	}

	It("can format only in the image arm of its kind case, and never reads, formats, or mounts a block volume synchronously", func() {
		image := volumeArm(string(driveImage))
		block := volumeArm(string(driveBlock))
		share := volumeArm(volumeKindShare)
		for _, risky := range []string{"mke2fs", "e2fsck", "-O has_journal", "MKE2FS_CONFIG", "dd ", "rvm_blank", guestVolumeHead, guestVolumeBackup, "rvm_vopts", "$RVM_SYNC_MOUNTS"} {
			Expect(image).To(ContainSubstring(risky))
			Expect(strings.Count(guestVolumeSetup, risky)).To(Equal(strings.Count(image, risky)), "%s outside the image arm", risky)
			Expect(block).NotTo(ContainSubstring(risky))
			Expect(share).NotTo(ContainSubstring(risky))
		}
		// A block volume's superblock is only read, and its filesystem only
		// grown online once it is mounted, by the helpers the image arm
		// shares, which only read the device.
		Expect(block).To(ContainSubstring("\n\t\trvm_vsuper || rvm_fail"))
		Expect(block).To(ContainSubstring("\n\t\trvm_vfits\n"))
		Expect(block).To(HaveSuffix("\n\t\trvm_vgrow_now"))
		Expect(image).To(HaveSuffix("\n\t\trvm_vgrow_now"))
		for _, risky := range []string{"mke2fs", "e2fsck", "-O", "dd ", "mount -t"} {
			Expect(guestVolumeFuncs).NotTo(ContainSubstring(risky))
		}
		Expect(share).NotTo(ContainSubstring("rvm_vgrow"))
		Expect(block).To(ContainSubstring(`mount -t ext4 -o noatime,errors=remount-ro "$rvm_vdev" "$rvm_vpath" || rvm_fail`))
		Expect(block).NotTo(ContainSubstring("sync"))
		Expect(block).NotTo(ContainSubstring("image"))
		// The share arm mounts by tag, as virtiofs, with no device and no
		// options, and never touches a filesystem tool or a sync option.
		Expect(share).To(ContainSubstring(`mount -t virtiofs rvm-vol"$rvm_vi" "$rvm_vpath" || rvm_fail`))
		Expect(strings.Count(share, "mount -t")).To(Equal(1))
		Expect(share).NotTo(ContainSubstring("ext4"))
		Expect(share).NotTo(ContainSubstring(" -o "))
		Expect(share).NotTo(ContainSubstring("sync"))
		Expect(share).NotTo(ContainSubstring("$rvm_vdev\" \"$rvm_vpath"))
		// The kinds come from the drive kinds, so a renamed kind cannot leave
		// an arm behind.
		Expect(string(driveImage)).To(Equal("image"))
		Expect(string(driveBlock)).To(Equal("block"))
		Expect(volumeKindShare).To(Equal("share"))
	})

	It("keeps its scratch files under /rvm, where no volume path can reach them", func() {
		Expect(guestVolumeHead).To(Equal("/rvm/volume-head"))
		Expect(guestVolumeUsed).To(Equal("/rvm/volume-used"))
		Expect(guestVolumeBackup).To(Equal("/rvm/volume-backup"))
		Expect(guestVolumeSuper).To(Equal("/rvm/volume-super"))
		Expect(guestVolumeSetup).NotTo(ContainSubstring("/tmp/"))
		for _, p := range []string{guestVolumeHead, guestVolumeUsed, guestVolumeBackup, guestVolumeSuper} {
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
			tools   string
			sys     string
			callLog string
			device  string
			mnt     string
		)

		// setSectors gives the device dev its size in 512-byte sectors in
		// the test /sys/block, as the text sysfs gives, which stage 2 reads.
		setSectors := func(dev, sectors string) {
			GinkgoHelper()
			at := filepath.Join(sys, filepath.Base(dev))
			Expect(os.MkdirAll(at, 0o755)).To(Succeed())
			// The file is read-only, as in sysfs, so a spec that resizes the
			// device replaces it, which a user other than root must do.
			Expect(os.RemoveAll(filepath.Join(at, "size"))).To(Succeed())
			Expect(os.WriteFile(filepath.Join(at, "size"), []byte(sectors), 0o444)).To(Succeed())
		}

		// writeKindsSync writes the test /rvm/mounts, as mountsFile writes
		// it, for mounts, the paths of the volumes in volume order, each of
		// the kind at its place in kinds and each image with its own image
		// name, with sync mounts turned off when noSync is set.
		writeKindsSync := func(kinds []driveKind, noSync bool, mounts ...string) {
			GinkgoHelper()
			Expect(kinds).To(HaveLen(len(mounts)))
			g := taskGuest("true")
			g.noVolumeSync = noSync
			for i, m := range mounts {
				g.vols = append(g.vols, guestVolume{ContainerDir: m, ImageName: "rvm-disk-" + strconv.Itoa(i) + ".img"})
				g.drives.volumes = append(g.drives.volumes, guestDrive{id: qemuVolumeSerial(i), kind: kinds[i], bytes: defaultImageSize})
			}
			content, err := mountsFile(g)
			Expect(err).NotTo(HaveOccurred())
			Expect(os.WriteFile(filepath.Join(dir, "mounts"), []byte(content), 0o644)).To(Succeed())
		}
		// writeKinds is writeKindsSync with sync mounts kept on.
		writeKinds := func(kinds []driveKind, mounts ...string) {
			GinkgoHelper()
			writeKindsSync(kinds, false, mounts...)
		}
		// writeMounts writes the test /rvm/mounts for image volumes at
		// mounts.
		writeMounts := func(mounts ...string) {
			GinkgoHelper()
			kinds := make([]driveKind, len(mounts))
			for i := range kinds {
				kinds[i] = driveImage
			}
			writeKinds(kinds, mounts...)
		}

		// backupPlaces are where stage 2 looks for a backup superblock, in
		// the order it looks.
		backupPlaces := []int64{8193 * 1024, 8193*1024 + 1024, 16384 * 2048, 16384*2048 + 1024, 32768 * 4096, 32768*4096 + 1024}

		BeforeEach(func() {
			dir = GinkgoT().TempDir()
			bin = filepath.Join(dir, "bin")
			Expect(os.Mkdir(bin, 0o755)).To(Succeed())
			tools = filepath.Join(dir, "tools")
			Expect(os.Mkdir(tools, 0o755)).To(Succeed())
			sys = filepath.Join(dir, "sys")
			Expect(os.Mkdir(sys, 0o755)).To(Succeed())
			callLog = filepath.Join(dir, "calls")
			device = filepath.Join(dir, "vda")
			mnt = filepath.Join(dir, "mnt", "da'ta")

			// Each stub records its argv. e2fsck exits with E2FSCK_RC, and
			// e2fsck -f with E2FSCK_F_RC the first time and E2FSCK_F2_RC
			// after that. dd writes what DD_MODE says to its
			// of= file, or, for the device named in DD_DATA_IF, data, and a
			// dd with skip=, which reads a backup superblock's place, reads
			// the test device itself with the real dd, unless DD_SKIP_FAIL
			// is set; the others exit with their *_RC, and mount fails for
			// the mount point MOUNT_FAIL_AT names. The guest filesystem
			// tools are in their own directory, which stands in for
			// /rvm/tools: mke2fs also records the configuration it was
			// given. tune2fs -l prints a superblock of TUNE2FS_BLOCKS blocks
			// of TUNE2FS_BSIZE bytes, TUNE2FS_FREE of them free, which is a
			// 1 GiB filesystem with 4096-byte blocks by default, and
			// TUNE2FS_FEATURES as the filesystem's features, or no feature
			// line with TUNE2FS_NO_FEATURES. With TUNE2FS_FAIL_FIRST, its
			// first -l fails. tune2fs -O exits with TUNE2FS_O_RC and, when
			// that is 0 and TUNE2FS_O_NOJOURNAL is unset, adds has_journal
			// to the features of every later -l.
			stubIn := func(at, name, body string) {
				script := "#!/bin/sh\necho \"" + name + " $*\" >> " + shellQuote(callLog) + "\n" + body + "\n"
				Expect(os.WriteFile(filepath.Join(at, name), []byte(script), 0o755)).To(Succeed())
			}
			stub := func(name, body string) { stubIn(bin, name, body) }
			stubIn(tools, "mke2fs", `echo "MKE2FS_CONFIG=${MKE2FS_CONFIG-unset}" >> `+shellQuote(callLog)+`
exit "${MKE2FS_RC:-0}"`)
			stubIn(tools, "e2fsck", `echo "rvm-volume: clean, 11/65536 files, 4127/262144 blocks"
rc=${E2FSCK_RC:-0}
if [ "$1" = -f ]; then
	full=`+shellQuote(filepath.Join(dir, "e2fsck-full-ran"))+`
	rc=${E2FSCK_F_RC:-0}
	[ ! -e "$full" ] || rc=${E2FSCK_F2_RC:-0}
	: >"$full"
fi
exit "$rc"`)
			stubIn(tools, "tune2fs", `echo "tune2fs 1.47.4 (6-Mar-2025)" >&2
journal=`+shellQuote(filepath.Join(dir, "journalled"))+`
if [ "$1" = -O ]; then
	[ "${TUNE2FS_O_RC:-0}" = 0 ] || exit "$TUNE2FS_O_RC"
	echo "Creating journal inode: done"
	[ -n "${TUNE2FS_O_NOJOURNAL:-}" ] || : >"$journal"
	exit 0
fi
first=`+shellQuote(filepath.Join(dir, "tune2fs-ran"))+`
if [ -n "${TUNE2FS_FAIL_FIRST:-}" ] && [ ! -e "$first" ]; then
	: >"$first"
	exit 1
fi
[ "${TUNE2FS_RC:-0}" = 0 ] || exit "$TUNE2FS_RC"
features=${TUNE2FS_FEATURES-has_journal ext_attr resize_inode dir_index filetype extent 64bit}
[ -e "$journal" ] && features="has_journal $features"
echo "Filesystem volume name:   rvm-volume"
[ -n "${TUNE2FS_NO_FEATURES:-}" ] || echo "Filesystem features:      $features"
echo "Filesystem flags:         signed_directory_hash "
echo "Block count:              ${TUNE2FS_BLOCKS-262144}"
echo "Reserved block count:     0"
echo "Free blocks:              ${TUNE2FS_FREE-200000}"
echo "Free inodes:              65525"
echo "Block size:               ${TUNE2FS_BSIZE-4096}"`)
			stubIn(tools, "ext4grow", `echo "ext4grow: grew $2 to fill $1"
exit "${EXT4GROW_RC:-0}"`)
			Expect(os.WriteFile(filepath.Join(tools, "mke2fs.conf"), []byte(guestMke2fsConfText), 0o644)).To(Succeed())
			stub("dd", `skip=
for a; do case $a in of=*) of=${a#of=} ;; if=*) in=${a#if=} ;; skip=*) skip=1 ;; esac; done
if [ -n "$skip" ]; then
	[ -z "${DD_SKIP_FAIL:-}" ] || { echo "dd: can't read device" >&2; exit 1; }
	exec /bin/dd "$@" 2>/dev/null
fi
mode=$DD_MODE
[ -n "${DD_DATA_IF:-}" ] && [ "$in" = "$DD_DATA_IF" ] && mode=data
case "$mode" in
zeros) head -c 65536 /dev/zero > "$of" ;;
data) { head -c 1024 /dev/zero; printf 'E'; head -c 64511 /dev/zero; } > "$of" ;;
empty) : > "$of" ;;
fail) echo "dd: can't open device" >&2; exit 1 ;;
esac`)
			stub("mount", `for a; do last=$a; done
[ -n "${MOUNT_FAIL_AT:-}" ] && [ "$last" = "$MOUNT_FAIL_AT" ] && exit 32
exit "${MOUNT_RC:-0}"`)
			stub("sleep", `exit 0`)
			stub("sync", `exit 0`)
			stub("umount", `exit "${UMOUNT_RC:-0}"`)

			// This /rvm/mounts points the path at a test mount point. The
			// device is the argument stage 1 passes, here a test file, and
			// each of the devices the specs use is 1 GiB in /sys/block.
			writeMounts(mnt)
			for _, name := range []string{"vda", "vdb", "vdc", "vdd"} {
				setSectors(name, "2097152\n")
			}
		})

		// runIn executes rvm_fail and the volume setup in shell, with args
		// as stage 2's arguments, the guest paths moved into the test
		// directory, a regular file standing in for each block device, the
		// commands that would change the host called as the stubs by path,
		// because the guest's busybox runs its own applets before anything
		// on PATH, and reboot replaced by a marker.
		runIn := func(shell guestShell, args []string, env ...string) setupRun {
			script := strings.NewReplacer(
				"/rvm/mounts", filepath.Join(dir, "mounts"),
				"/rvm/volume-", filepath.Join(dir, "volume-"),
				guestToolsDir+"/", tools+"/",
				"/sys/block/", sys+"/",
				`[ -b "$rvm_vdev" ]`, `[ -f "$rvm_vdev" ]`,
				"dd if=", filepath.Join(bin, "dd")+" if=",
				"mount -t", filepath.Join(bin, "mount")+" -t",
				"reboot -nf", "echo REBOOT",
			).Replace(guestFailFunc+guestVolumeSetup) + "echo REACHED_START\n"
			Expect(script).NotTo(ContainSubstring(guestVolumeHead))
			Expect(script).NotTo(ContainSubstring(guestVolumeUsed))
			Expect(script).NotTo(ContainSubstring(guestToolsDir))
			Expect(script).NotTo(ContainSubstring("/sys/block/"))
			Expect(script).NotTo(ContainSubstring("-b \""))
			Expect(strings.Count(script, filepath.Join(bin, "mount")+" -t")).To(Equal(strings.Count(guestVolumeSetup, "mount -t")))

			cmd := exec.Command(shell.argv[0], append(append(slices.Clone(shell.argv[1:]), "-c", script, "sh"), args...)...)
			cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin"}, env...)
			out, _ := cmd.CombinedOutput()
			calls, err := os.ReadFile(callLog)
			if os.IsNotExist(err) {
				err = nil
			}
			Expect(err).NotTo(HaveOccurred())
			return setupRun{out: string(out), calls: string(calls)}
		}
		runWith := func(args []string, env ...string) setupRun { return runIn(hostShell(), args, env...) }
		run := func(env ...string) setupRun { return runWith([]string{device}, env...) }

		// The stubs' expected argv lines, built once BeforeEach set the paths.
		mountCall := func(device, mnt string) string {
			return "mount -t ext4 -o sync,dirsync,noatime,noinit_itable,errors=remount-ro " + device + " " + mnt + "\n"
		}
		asyncMountCall := func(device, mnt string) string {
			return "mount -t ext4 -o noatime,noinit_itable,errors=remount-ro " + device + " " + mnt + "\n"
		}
		mkfsCall := func(device string) string {
			return "mke2fs -t ext4 -F -b 4096 -m 0 -L rvm-volume -E lazy_itable_init=1,lazy_journal_init=1,nodiscard,assume_storage_prezeroed=1 " + device + "\n" +
				"MKE2FS_CONFIG=" + filepath.Join(tools, "mke2fs.conf") + "\n"
		}
		fsckCall := func(device string) string { return "e2fsck -p " + device + "\n" }
		tune2fsCall := func(device string) string { return "tune2fs -l " + device + "\n" }
		ddCall := func(device string) string {
			return "dd if=" + device + " of=" + filepath.Join(dir, "volume-head") + " bs=4096 count=16\n"
		}
		// backupCall is the dd that reads the two bytes of the magic of a
		// superblock that starts at the byte at of device.
		backupCall := func(device string, at int64) string {
			return "dd if=" + device + " of=" + filepath.Join(dir, "volume-backup") + " bs=2 skip=" + strconv.FormatInt((at+56)/2, 10) + " count=1\n"
		}
		// blankCalls are the reads of an image whose first 64 KiB are zero:
		// the start, and the magic of a backup superblock at the start of
		// block group 1 and 1024 bytes in, for 1024-, 2048-, and 4096-byte
		// blocks, all of which a 1 GiB device holds.
		blankCalls := func(device string) string {
			calls := ddCall(device)
			for _, at := range backupPlaces {
				calls += backupCall(device, at)
			}
			return calls
		}
		// preenCalls are the calls for an image with data up to its mount:
		// the start, the superblock, the preen, and the superblock again.
		preenCalls := func(device string) string {
			return ddCall(device) + tune2fsCall(device) + fsckCall(device) + tune2fsCall(device)
		}
		growCall := func(device, mnt string) string { return "ext4grow " + device + " " + mnt + "\n" }

		BeforeEach(func() {
			Expect(os.WriteFile(device, nil, 0o600)).To(Succeed())
		})

		It("formats and mounts a blank image", func() {
			r := run("DD_MODE=zeros")
			Expect(r.out).To(ContainSubstring("REACHED_START"))
			Expect(r.out).NotTo(ContainSubstring("REBOOT"))
			Expect(r.calls).To(Equal(blankCalls(device) + mkfsCall(device) + mountCall(device, mnt)))
			Expect(mnt).To(BeADirectory())
			Expect(filepath.Join(dir, "volume-head")).NotTo(BeAnExistingFile())
			Expect(filepath.Join(dir, "volume-used")).NotTo(BeAnExistingFile())
		})

		It("preens an image with data with e2fsck -p and mounts it without formatting it", func() {
			r := run("DD_MODE=data")
			Expect(r.out).To(Equal("rvm-volume: clean, 11/65536 files, 4127/262144 blocks\nREACHED_START\n"))
			Expect(r.calls).To(Equal(preenCalls(device) + mountCall(device, mnt)))
		})

		It("mounts every volume on the device stage 1 passed in its place, in volume order, and formats only the blank ones", func() {
			devices := []string{filepath.Join(dir, "vdc"), filepath.Join(dir, "vda"), filepath.Join(dir, "vdb")}
			mounts := []string{filepath.Join(dir, "data"), filepath.Join(dir, "logs"), filepath.Join(dir, "cache dir")}
			for _, d := range devices {
				Expect(os.WriteFile(d, nil, 0o600)).To(Succeed())
			}
			writeMounts(mounts...)
			r := runWith(devices, "DD_MODE=zeros", "DD_DATA_IF="+devices[1])
			Expect(r.out).To(Equal("rvm-volume: clean, 11/65536 files, 4127/262144 blocks\nREACHED_START\n"))
			Expect(r.calls).To(Equal(
				blankCalls(devices[0]) + mkfsCall(devices[0]) + mountCall(devices[0], mounts[0]) +
					preenCalls(devices[1]) + mountCall(devices[1], mounts[1]) +
					blankCalls(devices[2]) + mkfsCall(devices[2]) + mountCall(devices[2], mounts[2])))
			for _, m := range mounts {
				Expect(m).To(BeADirectory())
			}
		})

		It("stops at the first volume whose setup fails, naming its image and path, and touches no later one", func() {
			devices := []string{filepath.Join(dir, "vda"), filepath.Join(dir, "vdb"), filepath.Join(dir, "vdc")}
			mounts := []string{filepath.Join(dir, "data"), filepath.Join(dir, "logs"), filepath.Join(dir, "cache")}
			for _, d := range devices {
				Expect(os.WriteFile(d, nil, 0o600)).To(Succeed())
			}
			writeMounts(mounts...)
			r := runWith(devices, "DD_MODE=data", "MOUNT_FAIL_AT="+mounts[1])
			clean := "rvm-volume: clean, 11/65536 files, 4127/262144 blocks\n"
			Expect(r.out).To(Equal(clean + clean + "vm-launch guest setup: mounting the volume image rvm-disk-1.img at " + mounts[1] + " failed; it is not blank, so vm-launch will not format it; inspect or delete rvm-disk-1.img on the volume\nREBOOT\n"))
			Expect(r.calls).To(Equal(preenCalls(devices[0]) + mountCall(devices[0], mounts[0]) + preenCalls(devices[1]) + mountCall(devices[1], mounts[1])))
			Expect(mounts[2]).NotTo(BeAnExistingFile())
		})

		It("fails at once, touching nothing, when stage 1 passed another number of devices than /rvm/mounts has volumes", func() {
			writeMounts(mnt, filepath.Join(dir, "logs"))
			for _, args := range [][]string{nil, {device}, {device, device, device}} {
				r := runWith(args, "DD_MODE=zeros")
				Expect(r.out).To(Equal(fmt.Sprintf("vm-launch guest setup: stage 1 passed %d volume devices for the 2 volumes in %s\nREBOOT\n", len(args), filepath.Join(dir, "mounts"))), "arguments %q", args)
				Expect(r.calls).To(BeEmpty())
				Expect(mnt).NotTo(BeAnExistingFile())
			}
		})

		It("fails at once, touching nothing, when /rvm/mounts has no volume count it can use, no sync mount setting it knows, or no path for a volume", func() {
			mounts := filepath.Join(dir, "mounts")
			const volume = "RVM_VOL0_KIND=image\nRVM_VOL0_PATH=/x\nRVM_VOL0_IMAGE=a\n"
			for content, line := range map[string]string{
				"":                "the volume count in " + mounts + " is not a number from 1 to 4",
				"RVM_VOLUMES=0\n": "the volume count in " + mounts + " is not a number from 1 to 4",
				"RVM_VOLUMES=5\n": "the volume count in " + mounts + " is not a number from 1 to 4",
				"RVM_VOLUMES=x\n": "the volume count in " + mounts + " is not a number from 1 to 4",
				"RVM_VOLUMES=1\nRVM_SYNC_MOUNTS=true\nRVM_VOL0_IMAGE=a\n": mounts + " gives volume 0 no path",
				"RVM_VOLUMES=1\n" + volume:                                "the sync mount setting in " + mounts + " is not true or false",
				"RVM_VOLUMES=1\nRVM_SYNC_MOUNTS=\n" + volume:              "the sync mount setting in " + mounts + " is not true or false",
				"RVM_VOLUMES=1\nRVM_SYNC_MOUNTS=yes\n" + volume:           "the sync mount setting in " + mounts + " is not true or false",
				"RVM_VOLUMES=1\nRVM_SYNC_MOUNTS=False\n" + volume:         "the sync mount setting in " + mounts + " is not true or false",
				"RVM_VOLUMES=1\nRVM_SYNC_MOUNTS=0\n" + volume:             "the sync mount setting in " + mounts + " is not true or false",
			} {
				Expect(os.WriteFile(mounts, []byte(content), 0o644)).To(Succeed())
				r := run("DD_MODE=zeros")
				Expect(r.out).To(Equal("vm-launch guest setup: "+line+"\nREBOOT\n"), "%q", content)
				Expect(r.calls).To(BeEmpty())
			}
		})

		It("never formats an image with data that does not mount", func() {
			r := run("DD_MODE=data", "MOUNT_RC=32")
			Expect(r.out).To(ContainSubstring("vm-launch guest setup: mounting the volume image rvm-disk-0.img at " + mnt + " failed; it is not blank, so vm-launch will not format it; inspect or delete rvm-disk-0.img on the volume"))
			Expect(r.calls).To(Equal(preenCalls(device) + mountCall(device, mnt)))
			Expect(r.out).To(ContainSubstring("REBOOT"))
			Expect(r.out).NotTo(ContainSubstring("REACHED_START"))
			Expect(r.calls).NotTo(ContainSubstring("mke2fs"))
		})

		It("treats a read error as a failure, never as a blank image", func() {
			r := run("DD_MODE=fail")
			Expect(r.out).To(ContainSubstring("vm-launch guest setup: reading the start of " + device + " failed"))
			Expect(r.out).To(ContainSubstring("REBOOT"))
			Expect(r.calls).To(Equal(ddCall(device)))
		})

		It("does not format an image it read nothing from", func() {
			r := run("DD_MODE=empty", "MOUNT_RC=32")
			Expect(r.calls).NotTo(ContainSubstring("mke2fs"))
			Expect(r.out).To(ContainSubstring("it is not blank, so vm-launch will not format it"))
		})

		It("fails when formatting fails", func() {
			r := run("DD_MODE=zeros", "MKE2FS_RC=1")
			Expect(r.out).To(ContainSubstring("vm-launch guest setup: formatting the blank volume image rvm-disk-0.img for " + mnt + " failed"))
			Expect(r.out).NotTo(ContainSubstring("REACHED_START"))
			Expect(r.calls).To(Equal(blankCalls(device) + mkfsCall(device)))
		})

		It("fails when a newly formatted image does not mount", func() {
			r := run("DD_MODE=zeros", "MOUNT_RC=32")
			Expect(r.out).To(ContainSubstring("vm-launch guest setup: mounting the newly formatted volume image rvm-disk-0.img at " + mnt + " failed"))
			Expect(r.out).NotTo(ContainSubstring("REACHED_START"))
		})

		It("fails at once, touching nothing, when stage 1 passed an empty device or one that is missing", func() {
			for _, arg := range []string{"", filepath.Join(dir, "vdz")} {
				r := runWith([]string{arg}, "DD_MODE=zeros")
				Expect(r.out).To(Equal("vm-launch guest setup: no block device for the volume image rvm-disk-0.img at "+mnt+"\nREBOOT\n"), "argument %q", arg)
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

		// cleanLine is what the e2fsck stub prints, as e2fsck -p does for a
		// clean filesystem.
		const cleanLine = "rvm-volume: clean, 11/65536 files, 4127/262144 blocks\n"

		DescribeTable("goes on after a preen whose exit status is below 4, and says so when e2fsck asks for a reboot, because the image is not mounted yet",
			func(shellOf func() guestShell) {
				shell := shellOf()
				for _, rc := range []int{0, 1, 2, 3} {
					Expect(os.RemoveAll(callLog)).To(Succeed())
					r := runIn(shell, []string{device}, "DD_MODE=data", "E2FSCK_RC="+strconv.Itoa(rc))
					want := cleanLine
					if rc&2 != 0 {
						want += "vm-launch guest: e2fsck -p repaired the volume image rvm-disk-0.img and asked for a reboot, which only a mounted filesystem needs; the image is not mounted yet, so the guest goes on\n"
					}
					Expect(r.out).To(Equal(want+"REACHED_START\n"), "%s, e2fsck status %d", shell.name, rc)
					Expect(r.calls).To(Equal(preenCalls(device)+mountCall(device, mnt)), "%s, e2fsck status %d", shell.name, rc)
				}
			},
			shellEntries(""),
		)

		DescribeTable("fails the boot when the preen exits 4 or more, naming the image, and never formats or mounts it",
			func(shellOf func() guestShell) {
				shell := shellOf()
				// 4 is errors left uncorrected, 8 an operational error, 16 a
				// usage error, 32 a cancelled check, and 128 a library error,
				// and e2fsck adds them up.
				for _, rc := range []int{4, 5, 6, 7, 8, 12, 16, 32, 128} {
					Expect(os.RemoveAll(callLog)).To(Succeed())
					r := runIn(shell, []string{device}, "DD_MODE=data", "E2FSCK_RC="+strconv.Itoa(rc))
					Expect(r.out).To(Equal(cleanLine+"vm-launch guest setup: the volume image rvm-disk-0.img has errors that e2fsck -p can't repair; inspect it on the volume (e2fsck -p exited "+strconv.Itoa(rc)+" for "+mnt+", and vm-launch never formats an image that is not blank)\nREBOOT\n"), "%s, e2fsck status %d", shell.name, rc)
					Expect(r.calls).To(Equal(ddCall(device)+tune2fsCall(device)+fsckCall(device)), "%s, e2fsck status %d", shell.name, rc)
				}
			},
			shellEntries(""),
		)

		DescribeTable("fails the boot before it reads the image when a guest filesystem tool is missing, and never falls back to another mke2fs",
			func(shellOf func() guestShell) {
				shell := shellOf()
				for _, name := range []string{"mke2fs", "e2fsck", "tune2fs", "ext4grow"} {
					for _, how := range []string{"missing", "not executable", "a directory"} {
						Expect(os.RemoveAll(callLog)).To(Succeed())
						Expect(os.RemoveAll(mnt)).To(Succeed())
						tool := filepath.Join(tools, name)
						saved, err := os.ReadFile(tool)
						Expect(err).NotTo(HaveOccurred())
						Expect(os.Remove(tool)).To(Succeed())
						switch how {
						case "not executable":
							Expect(os.WriteFile(tool, saved, 0o644)).To(Succeed())
						case "a directory":
							Expect(os.Mkdir(tool, 0o755)).To(Succeed())
						}
						// A busybox-like mke2fs on PATH must never stand in.
						Expect(os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\necho \"path "+name+" $*\" >> "+shellQuote(callLog)+"\n"), 0o755)).To(Succeed())
						for _, mode := range []string{"zeros", "data"} {
							r := runIn(shell, []string{device}, "DD_MODE="+mode)
							Expect(r.out).To(Equal("vm-launch guest setup: the guest has no "+tool+" for the volume image rvm-disk-0.img at "+mnt+", and it never formats or checks a volume image with another tool\nREBOOT\n"), "%s, %s %s, %s image", shell.name, name, how, mode)
							Expect(r.calls).To(BeEmpty(), "%s, %s %s", shell.name, name, how)
							Expect(mnt).NotTo(BeAnExistingFile())
						}
						Expect(os.RemoveAll(tool)).To(Succeed())
						Expect(os.WriteFile(tool, saved, 0o755)).To(Succeed())
						Expect(os.Remove(filepath.Join(bin, name))).To(Succeed())
					}
				}

				conf := filepath.Join(tools, "mke2fs.conf")
				Expect(os.Remove(conf)).To(Succeed())
				r := runIn(shell, []string{device}, "DD_MODE=zeros")
				Expect(r.out).To(Equal("vm-launch guest setup: the guest has no "+conf+" for the volume image rvm-disk-0.img at "+mnt+"\nREBOOT\n"), "%s", shell.name)
				Expect(r.calls).To(BeEmpty(), "%s", shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("drops sync and dirsync only from an image whose filesystem has a journal when the operator turned sync mounts off",
			func(shellOf func() guestShell, mode string, env []string, wantSync bool, line string) {
				shell := shellOf()
				writeKindsSync([]driveKind{driveImage}, true, mnt)
				r := runIn(shell, []string{device}, append([]string{"DD_MODE=" + mode}, env...)...)
				// An image with data has its superblock read before and after
				// its preen whatever the setting, and a blank image only when
				// sync mounts are off, after its format.
				prepare, offRead := preenCalls(device), ""
				out := cleanLine
				if mode == "zeros" {
					prepare, offRead, out = blankCalls(device)+mkfsCall(device), tune2fsCall(device), ""
				}
				if line != "" {
					out += "vm-launch guest: reading the filesystem features of the volume image rvm-disk-0.img failed, so it mounts with sync and dirsync\n"
				}
				Expect(r.out).To(Equal(out+"REACHED_START\n"), "%s", shell.name)
				mount := asyncMountCall(device, mnt)
				if wantSync {
					mount = mountCall(device, mnt)
				}
				Expect(r.calls).To(Equal(prepare+offRead+mount), "%s", shell.name)

				// With sync mounts on, which is the default, the mount keeps
				// sync and dirsync whatever the features, and a blank image's
				// superblock is not read.
				Expect(os.Remove(callLog)).To(Succeed())
				writeKinds([]driveKind{driveImage}, mnt)
				r = runIn(shell, []string{device}, append([]string{"DD_MODE=" + mode}, env...)...)
				Expect(r.calls).To(Equal(prepare+mountCall(device, mnt)), "%s", shell.name)
			},
			shellEntries("a preened journalled image", "data", []string{}, false, ""),
			shellEntries("a journalled image whose feature list ends in has_journal", "data", []string{"TUNE2FS_FEATURES=ext_attr dir_index filetype has_journal"}, false, ""),
			shellEntries("a newly formatted journalled image", "zeros", []string{}, false, ""),
			shellEntries("a legacy ext2 image", "data", []string{"TUNE2FS_FEATURES=dir_index filetype sparse_super"}, true, ""),
			shellEntries("a new image too small for a journal", "zeros", []string{"TUNE2FS_FEATURES=ext_attr resize_inode dir_index filetype extent 64bit flex_bg"}, true, ""),
			shellEntries("an image with an external journal device feature only", "data", []string{"TUNE2FS_FEATURES=journal_dev filetype"}, true, ""),
			shellEntries("an image with no features", "data", []string{"TUNE2FS_FEATURES="}, true, "unread"),
			shellEntries("a newly formatted image whose features tune2fs cannot read", "zeros", []string{"TUNE2FS_RC=1"}, true, "unread"),
			shellEntries("an image for which tune2fs prints no feature line", "data", []string{"TUNE2FS_NO_FEATURES=1"}, true, "unread"),
		)

		DescribeTable("leaves a block volume's mount and checks alone when the operator turned sync mounts off",
			func(shellOf func() guestShell) {
				shell := shellOf()
				writeKindsSync([]driveKind{driveBlock}, true, mnt)
				zeroDevice := make([]byte, 128<<10)
				Expect(os.WriteFile(device, zeroDevice, 0o600)).To(Succeed())
				r := runIn(shell, []string{device}, "DD_MODE=data")
				Expect(r.out).To(Equal("REACHED_START\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(tune2fsCall(device)+"mount -t ext4 -o noatime,errors=remount-ro "+device+" "+mnt+"\n"), "%s", shell.name)
			},
			shellEntries(""),
		)

		// blockMountCall is the stub's argv line for a block volume's mount.
		blockMountCall := func(device, mnt string) string {
			return "mount -t ext4 -o noatime,errors=remount-ro " + device + " " + mnt + "\n"
		}
		// zeroDevice makes device a blank disk, as a block device whose first
		// 64 KiB read as zero would be, and returns its content.
		zeroDevice := func(device string) []byte {
			blank := make([]byte, 128<<10)
			Expect(os.WriteFile(device, blank, 0o600)).To(Succeed())
			return blank
		}

		DescribeTable("never formats a blank block volume, and fails the boot with a line that names the volume's disk",
			func(shellOf func() guestShell) {
				shell := shellOf()
				writeKinds([]driveKind{driveBlock}, mnt)
				blank := zeroDevice(device)
				// tune2fs finds no superblock on a blank disk, as it does in
				// a guest, and the boot fails before the mount.
				r := runIn(shell, []string{device}, "DD_MODE=zeros", "TUNE2FS_RC=1")
				Expect(r.out).To(Equal("vm-launch guest setup: reading the filesystem on volume 0's disk " + device + " for " + mnt + " with tune2fs -l failed; vm-launch never formats a block volume, so the guest will not boot with it\nREBOOT\n"))
				Expect(r.calls).To(Equal(tune2fsCall(device)), "%s", shell.name)
				Expect(os.ReadFile(device)).To(Equal(blank))
				Expect(filepath.Join(dir, "volume-head")).NotTo(BeAnExistingFile())

				// A disk whose superblock reads but that does not mount fails
				// the boot with the same words.
				Expect(os.Remove(callLog)).To(Succeed())
				r = runIn(shell, []string{device}, "DD_MODE=zeros", "MOUNT_RC=32")
				Expect(r.out).To(Equal("vm-launch guest setup: mounting volume 0's disk " + device + " at " + mnt + " failed; vm-launch never formats a block volume, so the guest will not boot with it\nREBOOT\n"))
				Expect(r.calls).To(Equal(tune2fsCall(device)+blockMountCall(device, mnt)), "%s", shell.name)
				Expect(os.ReadFile(device)).To(Equal(blank))
			},
			shellEntries(""),
		)

		DescribeTable("mounts a block volume as ext4 with noatime and errors=remount-ro, without sync or dirsync",
			func(shellOf func() guestShell) {
				shell := shellOf()
				writeKinds([]driveKind{driveBlock}, mnt)
				zeroDevice(device)
				r := runIn(shell, []string{device}, "DD_MODE=zeros")
				Expect(r.out).To(Equal("REACHED_START\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(tune2fsCall(device)+blockMountCall(device, mnt)), "%s", shell.name)
				Expect(r.calls).NotTo(ContainSubstring("sync"))
				Expect(mnt).To(BeADirectory())
			},
			shellEntries(""),
		)

		DescribeTable("fails at once, touching nothing, on a block volume without a device, and names the volume's disk",
			func(shellOf func() guestShell) {
				shell := shellOf()
				writeKinds([]driveKind{driveBlock}, mnt)
				for _, arg := range []string{"", filepath.Join(dir, "vdz")} {
					r := runIn(shell, []string{arg}, "DD_MODE=zeros")
					Expect(r.out).To(Equal("vm-launch guest setup: no block device for volume 0's disk at "+mnt+"\nREBOOT\n"), "%s, argument %q", shell.name, arg)
					Expect(r.calls).To(BeEmpty(), "%s, argument %q", shell.name, arg)
					Expect(mnt).NotTo(BeAnExistingFile())
				}
			},
			shellEntries(""),
		)

		DescribeTable("mounts image and block volumes in volume order, and formats only the blank images",
			func(shellOf func() guestShell) {
				shell := shellOf()
				devices := []string{filepath.Join(dir, "vdc"), filepath.Join(dir, "vda"), filepath.Join(dir, "vdb")}
				mounts := []string{filepath.Join(dir, "data"), filepath.Join(dir, "disk"), filepath.Join(dir, "cache dir")}
				for _, d := range devices {
					zeroDevice(d)
				}
				writeKinds([]driveKind{driveImage, driveBlock, driveImage}, mounts...)
				r := runIn(shell, devices, "DD_MODE=zeros")
				Expect(r.out).To(Equal("REACHED_START\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(
					blankCalls(devices[0])+mkfsCall(devices[0])+mountCall(devices[0], mounts[0])+
						tune2fsCall(devices[1])+blockMountCall(devices[1], mounts[1])+
						blankCalls(devices[2])+mkfsCall(devices[2])+mountCall(devices[2], mounts[2])), "%s", shell.name)
			},
			shellEntries(""),
		)

		// twoGiB is a 2 GiB device in sectors, twice the size of the
		// filesystem the tune2fs stub gives by default.
		const twoGiB = "4194304\n"
		// legacyFeatures are the features of an rvm.6 image, which busybox
		// mke2fs made without a journal.
		const legacyFeatures = "TUNE2FS_FEATURES=dir_index filetype sparse_super"
		// legacyCalls are the calls for a legacy image that grows, from
		// its full check to the read of its superblock with the journal.
		legacyCalls := func(device string) string {
			return "e2fsck -f -p " + device + "\n" + tune2fsCall(device) + "tune2fs -O has_journal -J size=4 " + device + "\n" + tune2fsCall(device)
		}
		// tune2fsBanner is the version line tune2fs prints on stderr,
		// which reaches the console when it adds a journal.
		const tune2fsBanner = "tune2fs 1.47.4 (6-Mar-2025)\n"
		growLine := func(device, mnt string) string { return "ext4grow: grew " + mnt + " to fill " + device + "\n" }

		DescribeTable("grows a journalled image online after its mount when its device holds more blocks than its filesystem, and leaves one that its filesystem fills",
			func(shellOf func() guestShell) {
				shell := shellOf()
				setSectors(device, twoGiB)
				r := runIn(shell, []string{device}, "DD_MODE=data")
				Expect(r.out).To(Equal(cleanLine+growLine(device, mnt)+"REACHED_START\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(preenCalls(device)+mountCall(device, mnt)+growCall(device, mnt)), "%s", shell.name)

				// With sync mounts off, a journalled image grows as well,
				// without sync and dirsync.
				Expect(os.Remove(callLog)).To(Succeed())
				writeKindsSync([]driveKind{driveImage}, true, mnt)
				r = runIn(shell, []string{device}, "DD_MODE=data")
				Expect(r.calls).To(Equal(preenCalls(device)+asyncMountCall(device, mnt)+growCall(device, mnt)), "%s", shell.name)

				// A device a few sectors bigger holds no whole block more,
				// and a device the filesystem fills has nothing to grow into.
				writeKinds([]driveKind{driveImage}, mnt)
				for _, sectors := range []string{"2097159\n", "2097152\n", "2097152"} {
					Expect(os.Remove(callLog)).To(Succeed())
					setSectors(device, sectors)
					r = runIn(shell, []string{device}, "DD_MODE=data")
					Expect(r.out).To(Equal(cleanLine+"REACHED_START\n"), "%s, %q sectors", shell.name, sectors)
					Expect(r.calls).To(Equal(preenCalls(device)+mountCall(device, mnt)), "%s, %q sectors", shell.name, sectors)
				}
			},
			shellEntries(""),
		)

		DescribeTable("grows a block volume online after its mount when its disk holds more blocks than its filesystem, and never formats, checks, or gives it a journal",
			func(shellOf func() guestShell) {
				shell := shellOf()
				writeKinds([]driveKind{driveBlock}, mnt)
				setSectors(device, twoGiB)
				r := runIn(shell, []string{device}, "DD_MODE=zeros")
				Expect(r.out).To(Equal(growLine(device, mnt)+"REACHED_START\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(tune2fsCall(device)+blockMountCall(device, mnt)+growCall(device, mnt)), "%s", shell.name)

				// A disk without a journal, which the volume driver never
				// hands over, or whose features do not read, mounts at its
				// old size.
				for env, line := range map[string]string{
					"TUNE2FS_FEATURES=dir_index filetype": "",
					"TUNE2FS_NO_FEATURES=1":               "",
					"TUNE2FS_FEATURES=":                   "",
				} {
					Expect(line).To(BeEmpty())
					Expect(os.Remove(callLog)).To(Succeed())
					r = runIn(shell, []string{device}, "DD_MODE=zeros", env)
					Expect(r.out).To(Equal("vm-launch guest: volume 0's disk "+device+" has no journal that tune2fs -l shows, so it mounts at its old size of 262144 blocks of 4096 bytes and does not grow\nREACHED_START\n"), "%s, %s", shell.name, env)
					Expect(r.calls).To(Equal(tune2fsCall(device)+blockMountCall(device, mnt)), "%s, %s", shell.name, env)
				}
			},
			shellEntries(""),
		)

		DescribeTable("keeps an image or a block volume mounted at its old size and goes on when ext4grow fails, with a line that names the volume",
			func(shellOf func() guestShell, kind driveKind) {
				shell := shellOf()
				writeKinds([]driveKind{kind}, mnt)
				setSectors(device, twoGiB)
				r := runIn(shell, []string{device}, "DD_MODE=data", "EXT4GROW_RC=1")
				name, prepare, mount := "the volume image rvm-disk-0.img", preenCalls(device), mountCall(device, mnt)
				out := cleanLine
				if kind == driveBlock {
					name, prepare, mount, out = "volume 0's disk "+device, tune2fsCall(device), blockMountCall(device, mnt), ""
				}
				Expect(r.out).To(Equal(out+growLine(device, mnt)+"vm-launch guest: growing "+name+" at "+mnt+" from 262144 to 524288 blocks of 4096 bytes failed, so it stays at its old size; its data is intact\nREACHED_START\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(prepare+mount+growCall(device, mnt)), "%s", shell.name)
			},
			shellEntries("an image", driveImage),
			shellEntries("a block volume", driveBlock),
		)

		DescribeTable("fails the boot on a filesystem larger than its device before anything writes to it or mounts it",
			func(shellOf func() guestShell, kind driveKind) {
				shell := shellOf()
				writeKinds([]driveKind{kind}, mnt)
				name, calls := "the volume image rvm-disk-0.img", ddCall(device)+tune2fsCall(device)
				if kind == driveBlock {
					name, calls = "volume 0's disk "+device, tune2fsCall(device)
				}
				line := "vm-launch guest setup: the filesystem on " + name + " at " + mnt + " has 262145 blocks of 4096 bytes, more than the 262144 its device holds, so the device was shrunk or holds another filesystem's data; vm-launch never mounts a filesystem larger than its device; inspect it on the volume\nREBOOT\n"
				r := runIn(shell, []string{device}, "DD_MODE=data", "TUNE2FS_BLOCKS=262145")
				Expect(r.out).To(Equal(line), "%s", shell.name)
				Expect(r.calls).To(Equal(calls), "%s", shell.name)

				// A 1024-byte block on a device that ends half a block early
				// is past the device too.
				Expect(os.Remove(callLog)).To(Succeed())
				setSectors(device, "2097151\n")
				r = runIn(shell, []string{device}, "DD_MODE=data", "TUNE2FS_BLOCKS=1048576", "TUNE2FS_BSIZE=1024")
				Expect(r.out).To(Equal(strings.NewReplacer("262145 blocks of 4096", "1048576 blocks of 1024", "the 262144", "the 1048575").Replace(line)), "%s", shell.name)
				Expect(r.calls).To(Equal(calls), "%s", shell.name)
			},
			shellEntries("an image", driveImage),
			shellEntries("a block volume", driveBlock),
		)

		DescribeTable("leaves an image's superblock that does not read before the preen to the preen, and fails the boot when it does not read after it",
			func(shellOf func() guestShell) {
				shell := shellOf()
				r := runIn(shell, []string{device}, "DD_MODE=data", "TUNE2FS_FAIL_FIRST=1")
				Expect(r.out).To(Equal(cleanLine+"REACHED_START\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(preenCalls(device)+mountCall(device, mnt)), "%s", shell.name)

				// The check after the preen still finds a filesystem larger
				// than its device.
				Expect(os.Remove(callLog)).To(Succeed())
				Expect(os.Remove(filepath.Join(dir, "tune2fs-ran"))).To(Succeed())
				r = runIn(shell, []string{device}, "DD_MODE=data", "TUNE2FS_FAIL_FIRST=1", "TUNE2FS_BLOCKS=300000")
				Expect(r.out).To(HavePrefix(cleanLine+"vm-launch guest setup: the filesystem on the volume image rvm-disk-0.img at "+mnt+" has 300000 blocks of 4096 bytes, more than the 262144 its device holds"), "%s", shell.name)
				Expect(r.calls).To(Equal(preenCalls(device)), "%s", shell.name)

				for _, env := range [][]string{
					{"TUNE2FS_RC=1"},
					{"TUNE2FS_BLOCKS="},
					{"TUNE2FS_BLOCKS=0"},
					{"TUNE2FS_BLOCKS=0262144"},
					{"TUNE2FS_BLOCKS=26214x"},
					{"TUNE2FS_BLOCKS=-1"},
					{"TUNE2FS_BSIZE="},
					{"TUNE2FS_BSIZE=1000"},
					{"TUNE2FS_BSIZE=0"},
				} {
					Expect(os.Remove(callLog)).To(Succeed())
					r = runIn(shell, []string{device}, append([]string{"DD_MODE=data"}, env...)...)
					Expect(r.out).To(Equal(cleanLine+"vm-launch guest setup: reading the superblock of the volume image rvm-disk-0.img for "+mnt+" with tune2fs -l failed after its preen, so the guest cannot tell whether it fits its device; inspect it on the volume\nREBOOT\n"), "%s, %q", shell.name, env)
					Expect(r.calls).To(Equal(preenCalls(device)), "%s, %q", shell.name, env)
				}
			},
			shellEntries(""),
		)

		DescribeTable("fails the boot at once, touching nothing, when the device's size in /sys/block does not read as a number",
			func(shellOf func() guestShell, kind driveKind) {
				shell := shellOf()
				writeKinds([]driveKind{kind}, mnt)
				name := "the volume image rvm-disk-0.img"
				if kind == driveBlock {
					name = "volume 0's disk " + device
				}
				size := filepath.Join(sys, "vda", "size")
				for _, content := range []string{"missing", "", "\n", "0\n", "-1\n", "12a\n", "02097152\n"} {
					Expect(os.RemoveAll(size)).To(Succeed())
					if content != "missing" {
						Expect(os.WriteFile(size, []byte(content), 0o444)).To(Succeed())
					}
					r := runIn(shell, []string{device}, "DD_MODE=data")
					Expect(r.out).To(Equal("vm-launch guest setup: reading the size of "+device+" for "+name+" at "+mnt+" from /sys/block failed\nREBOOT\n"), "%s, %q", shell.name, content)
					Expect(r.calls).To(BeEmpty(), "%s, %q", shell.name, content)
				}
			},
			shellEntries("an image", driveImage),
			shellEntries("a block volume", driveBlock),
		)

		DescribeTable("gives a legacy image without a journal a 4 MiB journal after a full check, and only then grows it",
			func(shellOf func() guestShell) {
				shell := shellOf()
				setSectors(device, twoGiB)
				r := runIn(shell, []string{device}, "DD_MODE=data", legacyFeatures)
				Expect(r.out).To(Equal(cleanLine+cleanLine+tune2fsBanner+"Creating journal inode: done\n"+growLine(device, mnt)+"REACHED_START\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(preenCalls(device)+legacyCalls(device)+mountCall(device, mnt)+growCall(device, mnt)), "%s", shell.name)

				// The image has a journal now, so with sync mounts off it
				// mounts without sync and dirsync.
				for _, name := range []string{"journalled", "e2fsck-full-ran"} {
					Expect(os.Remove(filepath.Join(dir, name))).To(Succeed())
				}
				Expect(os.Remove(callLog)).To(Succeed())
				writeKindsSync([]driveKind{driveImage}, true, mnt)
				r = runIn(shell, []string{device}, "DD_MODE=data", legacyFeatures)
				Expect(r.calls).To(Equal(preenCalls(device)+legacyCalls(device)+asyncMountCall(device, mnt)+growCall(device, mnt)), "%s", shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("leaves a legacy image that does not need to grow as it is apart from the preen",
			func(shellOf func() guestShell) {
				shell := shellOf()
				for _, sectors := range []string{"2097152\n", "2097159\n"} {
					Expect(os.RemoveAll(callLog)).To(Succeed())
					setSectors(device, sectors)
					r := runIn(shell, []string{device}, "DD_MODE=data", legacyFeatures)
					Expect(r.out).To(Equal(cleanLine+"REACHED_START\n"), "%s, %q", shell.name, sectors)
					Expect(r.calls).To(Equal(preenCalls(device)+mountCall(device, mnt)), "%s, %q", shell.name, sectors)
				}
			},
			shellEntries(""),
		)

		DescribeTable("mounts a legacy image at its old size without a journal and asks the app to free 4 MiB when it has less free, and does not fail the boot",
			func(shellOf func() guestShell, blockSize, blocks, enough int) {
				shell := shellOf()
				setSectors(device, twoGiB)
				size := []string{"TUNE2FS_BSIZE=" + strconv.Itoa(blockSize), "TUNE2FS_BLOCKS=" + strconv.Itoa(blocks)}
				short := enough - 1
				r := runIn(shell, []string{device}, append([]string{"DD_MODE=data", legacyFeatures, "TUNE2FS_FREE=" + strconv.Itoa(short)}, size...)...)
				Expect(r.out).To(Equal(cleanLine+cleanLine+"vm-launch guest: the volume image rvm-disk-0.img at "+mnt+" has no journal and only "+strconv.Itoa(short*blockSize/1024)+" KiB free, and it needs 4 MiB free for the journal it must have before it grows, so it mounts at its old size of "+strconv.Itoa(blocks)+" blocks of "+strconv.Itoa(blockSize)+" bytes; free 4 MiB in "+mnt+" and restart the app to grow it\nREACHED_START\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(preenCalls(device)+"e2fsck -f -p "+device+"\n"+tune2fsCall(device)+mountCall(device, mnt)), "%s", shell.name)

				// One more free block is enough.
				Expect(os.Remove(callLog)).To(Succeed())
				Expect(os.Remove(filepath.Join(dir, "e2fsck-full-ran"))).To(Succeed())
				r = runIn(shell, []string{device}, append([]string{"DD_MODE=data", legacyFeatures, "TUNE2FS_FREE=" + strconv.Itoa(enough)}, size...)...)
				Expect(r.calls).To(Equal(preenCalls(device)+legacyCalls(device)+mountCall(device, mnt)+growCall(device, mnt)), "%s", shell.name)
			},
			// 4 MiB of journal and 32 blocks more.
			shellEntries("4096-byte blocks", 4096, 262144, 1024+32),
			shellEntries("2048-byte blocks", 2048, 524288, 2048+32),
			shellEntries("1024-byte blocks", 1024, 1048576, 4096+32),
		)

		DescribeTable("fails the boot when the full check of a legacy image that would grow exits 4 or more, before it gets a journal",
			func(shellOf func() guestShell) {
				shell := shellOf()
				setSectors(device, twoGiB)
				for _, rc := range []int{4, 8, 12} {
					Expect(os.RemoveAll(callLog)).To(Succeed())
					Expect(os.RemoveAll(filepath.Join(dir, "e2fsck-full-ran"))).To(Succeed())
					r := runIn(shell, []string{device}, "DD_MODE=data", legacyFeatures, "E2FSCK_F_RC="+strconv.Itoa(rc))
					Expect(r.out).To(Equal(cleanLine+cleanLine+"vm-launch guest setup: the volume image rvm-disk-0.img has errors that e2fsck -f -p can't repair; inspect it on the volume (e2fsck -f -p exited "+strconv.Itoa(rc)+" for "+mnt+" before the image got the journal it needs to grow, and vm-launch never formats an image that is not blank)\nREBOOT\n"), "%s, %d", shell.name, rc)
					Expect(r.calls).To(Equal(preenCalls(device)+"e2fsck -f -p "+device+"\n"), "%s, %d", shell.name, rc)
				}
			},
			shellEntries(""),
		)

		DescribeTable("checks a legacy image again and mounts it at its old size when tune2fs cannot add its journal, and fails the boot when that check exits 4 or more",
			func(shellOf func() guestShell) {
				shell := shellOf()
				setSectors(device, twoGiB)
				failed := preenCalls(device) + "e2fsck -f -p " + device + "\n" + tune2fsCall(device) + "tune2fs -O has_journal -J size=4 " + device + "\n" + "e2fsck -f -p " + device + "\n"
				r := runIn(shell, []string{device}, "DD_MODE=data", legacyFeatures, "TUNE2FS_O_RC=1")
				Expect(r.out).To(Equal(cleanLine+cleanLine+tune2fsBanner+cleanLine+"vm-launch guest: adding a 4 MiB journal to the volume image rvm-disk-0.img failed, so it mounts at its old size of 262144 blocks of 4096 bytes; its data is intact\nREACHED_START\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(failed+tune2fsCall(device)+mountCall(device, mnt)), "%s", shell.name)

				Expect(os.Remove(callLog)).To(Succeed())
				Expect(os.Remove(filepath.Join(dir, "e2fsck-full-ran"))).To(Succeed())
				r = runIn(shell, []string{device}, "DD_MODE=data", legacyFeatures, "TUNE2FS_O_RC=1", "E2FSCK_F2_RC=4")
				Expect(r.out).To(Equal(cleanLine+cleanLine+tune2fsBanner+cleanLine+"vm-launch guest setup: the volume image rvm-disk-0.img has errors that e2fsck -f -p can't repair after adding a journal to it failed; inspect it on the volume (e2fsck -f -p exited 4 for "+mnt+", and vm-launch never formats an image that is not blank)\nREBOOT\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(failed), "%s", shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("mounts a legacy image at its old size when tune2fs reports success but the image still has no journal, or when its features do not read",
			func(shellOf func() guestShell) {
				shell := shellOf()
				setSectors(device, twoGiB)
				r := runIn(shell, []string{device}, "DD_MODE=data", legacyFeatures, "TUNE2FS_O_NOJOURNAL=1")
				Expect(r.out).To(Equal(cleanLine+cleanLine+tune2fsBanner+"Creating journal inode: done\nvm-launch guest: tune2fs gave the volume image rvm-disk-0.img no journal, so it mounts at its old size of 262144 blocks of 4096 bytes\nREACHED_START\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(preenCalls(device)+legacyCalls(device)+mountCall(device, mnt)), "%s", shell.name)

				for _, env := range []string{"TUNE2FS_NO_FEATURES=1", "TUNE2FS_FEATURES="} {
					Expect(os.Remove(callLog)).To(Succeed())
					r = runIn(shell, []string{device}, "DD_MODE=data", env)
					Expect(r.out).To(Equal(cleanLine+"vm-launch guest: tune2fs -l gives no filesystem features for the volume image rvm-disk-0.img, so the guest cannot tell whether it has the journal it needs to grow, and it mounts at its old size of 262144 blocks of 4096 bytes\nREACHED_START\n"), "%s, %s", shell.name, env)
					Expect(r.calls).To(Equal(preenCalls(device)+mountCall(device, mnt)), "%s, %s", shell.name, env)
				}
			},
			shellEntries(""),
		)

		// sparseDevice makes device a sparse 1 GiB file of zeros, with the
		// bytes b at the byte at when b is not empty.
		sparseDevice := func(at int64, b []byte) {
			GinkgoHelper()
			f, err := os.OpenFile(device, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			Expect(f.Truncate(1 << 30)).To(Succeed())
			if len(b) > 0 {
				_, err = f.WriteAt(b, at)
				Expect(err).NotTo(HaveOccurred())
			}
		}

		DescribeTable("never formats an image whose first 64 KiB are zero but which holds a backup superblock's magic, and fails the boot as a damaged filesystem",
			func(shellOf func() guestShell, place int, groupBlock, blockSize int) {
				shell := shellOf()
				at := backupPlaces[place]
				sparseDevice(at+56, []byte{0x53, 0xef})
				r := runIn(shell, []string{device}, "DD_MODE=zeros")
				Expect(r.out).To(Equal(fmt.Sprintf("vm-launch guest setup: the volume image rvm-disk-0.img for %s reads as zero in its first 64 KiB but holds the magic of an ext2, ext3, or ext4 superblock at byte %d, where a backup superblock is kept, so it looks like a damaged filesystem, and vm-launch never formats it; repair it by hand on the volume with e2fsck -b from a backup superblock (e2fsck -b %d -B %d for %d-byte blocks)\nREBOOT\n", mnt, at, groupBlock, blockSize, blockSize)), "%s", shell.name)
				calls := ddCall(device)
				for _, p := range backupPlaces[:place+1] {
					calls += backupCall(device, p)
				}
				Expect(r.calls).To(Equal(calls), "%s", shell.name)
				Expect(r.calls).NotTo(ContainSubstring("mke2fs"))
				Expect(r.calls).NotTo(ContainSubstring("mount"))
			},
			shellEntries("at block 8193 of 1024 bytes", 0, 8193, 1024),
			shellEntries("1024 bytes into block 8193 of 1024 bytes", 1, 8193, 1024),
			shellEntries("at block 16384 of 2048 bytes", 2, 16384, 2048),
			shellEntries("1024 bytes into block 16384 of 2048 bytes", 3, 16384, 2048),
			shellEntries("at block 32768 of 4096 bytes", 4, 32768, 4096),
			shellEntries("1024 bytes into block 32768 of 4096 bytes", 5, 32768, 4096),
		)

		DescribeTable("formats an image whose first 64 KiB are zero when no backup superblock's magic is where one would be",
			func(shellOf func() guestShell) {
				shell := shellOf()
				// The magic in the other byte order, the magic one byte off,
				// and other data at the magic's place are no superblock.
				for _, c := range []struct {
					at int64
					b  []byte
				}{{0, nil}, {backupPlaces[4] + 56, []byte{0xef, 0x53}}, {backupPlaces[4] + 57, []byte{0x53, 0xef}}, {backupPlaces[0] + 56, []byte{0x53, 0x00}}, {backupPlaces[2] + 100, []byte{0x53, 0xef}}} {
					Expect(os.RemoveAll(callLog)).To(Succeed())
					sparseDevice(c.at, c.b)
					r := runIn(shell, []string{device}, "DD_MODE=zeros")
					Expect(r.out).To(Equal("REACHED_START\n"), "%s, %d", shell.name, c.at)
					Expect(r.calls).To(Equal(blankCalls(device)+mkfsCall(device)+mountCall(device, mnt)), "%s, %d", shell.name, c.at)
				}
			},
			shellEntries(""),
		)

		DescribeTable("looks for a backup superblock only where the image holds all of one",
			func(shellOf func() guestShell) {
				shell := shellOf()
				// A 1024-byte superblock at byte at needs a device of at
				// least at+1024 bytes, which is (at+1024)/512 sectors.
				for _, c := range []struct {
					sectors int64
					places  int
				}{{128, 0}, {(backupPlaces[0] + 1024) / 512, 1}, {(backupPlaces[0]+1024)/512 - 1, 0}, {(backupPlaces[1] + 1024) / 512, 2}, {32 << 11, 2}, {(backupPlaces[3] + 1024) / 512, 4}, {(backupPlaces[5]+1024)/512 - 1, 5}, {(backupPlaces[5] + 1024) / 512, 6}} {
					Expect(os.RemoveAll(callLog)).To(Succeed())
					setSectors(device, strconv.FormatInt(c.sectors, 10)+"\n")
					r := runIn(shell, []string{device}, "DD_MODE=zeros")
					Expect(r.out).To(Equal("REACHED_START\n"), "%s, %d sectors", shell.name, c.sectors)
					calls := ddCall(device)
					for _, p := range backupPlaces[:c.places] {
						calls += backupCall(device, p)
					}
					Expect(r.calls).To(Equal(calls+mkfsCall(device)+mountCall(device, mnt)), "%s, %d sectors", shell.name, c.sectors)
				}
			},
			shellEntries(""),
		)

		DescribeTable("treats a failed read of a backup superblock's place as a failure, never as a blank image",
			func(shellOf func() guestShell) {
				shell := shellOf()
				r := runIn(shell, []string{device}, "DD_MODE=zeros", "DD_SKIP_FAIL=1")
				Expect(r.out).To(Equal("vm-launch guest setup: reading "+device+" at byte 8389632, where a backup superblock would be, failed\nREBOOT\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(ddCall(device)+backupCall(device, backupPlaces[0])), "%s", shell.name)
			},
			shellEntries(""),
		)

		// shareCall is the stub's argv line for a share's mount.
		shareCall := func(index int, mnt string) string {
			return "mount -t virtiofs rvm-vol" + strconv.Itoa(index) + " " + mnt + "\n"
		}

		DescribeTable("mounts a share by its volume index's tag beside the other volumes, and refuses a device for it",
			func(shellOf func() guestShell) {
				shell := shellOf()
				mounts := []string{filepath.Join(dir, "data"), filepath.Join(dir, "shared dir"), filepath.Join(dir, "logs")}
				devices := []string{filepath.Join(dir, "vda"), "", filepath.Join(dir, "vdb")}
				zeroDevice(devices[0])
				zeroDevice(devices[2])
				Expect(os.WriteFile(filepath.Join(dir, "mounts"), []byte("RVM_VOLUMES=3\nRVM_SYNC_MOUNTS=true\n"+
					"RVM_VOL0_KIND=image\nRVM_VOL0_PATH="+shellQuote(mounts[0])+"\nRVM_VOL0_IMAGE=a.img\n"+
					"RVM_VOL1_KIND=share\nRVM_VOL1_PATH="+shellQuote(mounts[1])+"\n"+
					"RVM_VOL2_KIND=block\nRVM_VOL2_PATH="+shellQuote(mounts[2])+"\n"), 0o644)).To(Succeed())
				r := runIn(shell, devices, "DD_MODE=data")
				Expect(r.out).To(Equal("rvm-volume: clean, 11/65536 files, 4127/262144 blocks\nREACHED_START\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(preenCalls(devices[0])+mountCall(devices[0], mounts[0])+shareCall(1, mounts[1])+tune2fsCall(devices[2])+blockMountCall(devices[2], mounts[2])), "%s", shell.name)
				Expect(mounts[1]).To(BeADirectory())

				Expect(os.Remove(callLog)).To(Succeed())
				devices[1] = devices[2]
				r = runIn(shell, devices, "DD_MODE=data")
				Expect(r.out).To(Equal("rvm-volume: clean, 11/65536 files, 4127/262144 blocks\nvm-launch guest setup: stage 1 passed the device "+devices[2]+" for the share at "+mounts[1]+", which has no drive\nREBOOT\n"), "%s", shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("mounts a guest that holds only a share, at the tag of its own index, with no tool and no drive",
			func(shellOf func() guestShell) {
				shell := shellOf()
				shared := filepath.Join(dir, "a b", "it's")
				Expect(os.WriteFile(filepath.Join(dir, "mounts"), []byte("RVM_VOLUMES=1\nRVM_SYNC_MOUNTS=true\nRVM_VOL0_KIND=share\nRVM_VOL0_PATH="+shellQuote(shared)+"\n"), 0o644)).To(Succeed())
				r := runIn(shell, []string{""})
				Expect(r.out).To(Equal("REACHED_START\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(shareCall(0, shared)), "%s", shell.name)
				Expect(shared).To(BeADirectory())
			},
			shellEntries(""),
		)

		DescribeTable("fails the boot with a line that names the path when a share does not mount, and goes no further",
			func(shellOf func() guestShell) {
				shell := shellOf()
				mounts := []string{filepath.Join(dir, "shared"), filepath.Join(dir, "later")}
				Expect(os.WriteFile(filepath.Join(dir, "mounts"), []byte("RVM_VOLUMES=2\nRVM_SYNC_MOUNTS=true\n"+
					"RVM_VOL0_KIND=share\nRVM_VOL0_PATH="+shellQuote(mounts[0])+"\n"+
					"RVM_VOL1_KIND=share\nRVM_VOL1_PATH="+shellQuote(mounts[1])+"\n"), 0o644)).To(Succeed())
				r := runIn(shell, []string{"", ""}, "MOUNT_RC=32")
				Expect(r.out).To(Equal("vm-launch guest setup: mounting the share rvm-vol0 at "+mounts[0]+" failed; the hypervisor must give the guest a virtiofs device with that tag\nREBOOT\n"), "%s", shell.name)
				Expect(r.calls).To(Equal(shareCall(0, mounts[0])), "%s", shell.name)
				Expect(mounts[1]).NotTo(BeAnExistingFile())
			},
			shellEntries(""),
		)

		DescribeTable("fails the boot with a line that names the path when the mount point of a share cannot be made",
			func(shellOf func() guestShell) {
				shell := shellOf()
				blocker := filepath.Join(dir, "file")
				Expect(os.WriteFile(blocker, nil, 0o600)).To(Succeed())
				shared := filepath.Join(blocker, "shared")
				Expect(os.WriteFile(filepath.Join(dir, "mounts"), []byte("RVM_VOLUMES=1\nRVM_SYNC_MOUNTS=true\nRVM_VOL0_KIND=share\nRVM_VOL0_PATH="+shellQuote(shared)+"\n"), 0o644)).To(Succeed())
				r := runIn(shell, []string{""})
				Expect(r.out).To(HaveSuffix("vm-launch guest setup: creating "+shared+" failed\nREBOOT\n"), "%s", shell.name)
				Expect(r.calls).To(BeEmpty(), "%s", shell.name)
			},
			shellEntries(""),
		)

		DescribeTable("fails at once, touching nothing, on a volume without a kind or with a kind it does not know",
			func(shellOf func() guestShell) {
				shell := shellOf()
				zeroDevice(device)
				for kind, line := range map[string]string{
					"":      "/rvm/mounts gives the volume at " + mnt + " no kind",
					"plain": "/rvm/mounts gives the volume at " + mnt + " the kind plain, which the guest does not know",
					"Image": "/rvm/mounts gives the volume at " + mnt + " the kind Image, which the guest does not know",
				} {
					Expect(os.WriteFile(filepath.Join(dir, "mounts"), []byte("RVM_VOLUMES=1\nRVM_SYNC_MOUNTS=true\nRVM_VOL0_KIND="+kind+"\nRVM_VOL0_PATH="+shellQuote(mnt)+"\nRVM_VOL0_IMAGE=a.img\n"), 0o644)).To(Succeed())
					r := runIn(shell, []string{device}, "DD_MODE=zeros")
					Expect(r.out).To(Equal(strings.ReplaceAll("vm-launch guest setup: "+line+"\nREBOOT\n", "/rvm/mounts", filepath.Join(dir, "mounts"))), "%s, kind %q", shell.name, kind)
					Expect(r.calls).To(BeEmpty(), "%s, kind %q", shell.name, kind)
				}
			},
			shellEntries(""),
		)

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

			It("syncs and unmounts every volume, last first", func() {
				mounts := []string{filepath.Join(dir, "data"), filepath.Join(dir, "logs"), filepath.Join(dir, "cache dir")}
				writeMounts(mounts...)
				r := teardown("3")
				Expect(r.out).To(Equal("status=3\n"))
				Expect(r.calls).To(Equal("sync -f " + mounts[2] + "\numount " + mounts[2] + "\n" +
					"sync -f " + mounts[1] + "\numount " + mounts[1] + "\n" +
					"sync -f " + mounts[0] + "\numount " + mounts[0] + "\n"))
			})

			It("syncs and unmounts a block volume and a share as it does an image, last first", func() {
				mounts := []string{filepath.Join(dir, "data"), filepath.Join(dir, "shared"), filepath.Join(dir, "disk")}
				Expect(os.WriteFile(filepath.Join(dir, "mounts"), []byte("RVM_VOLUMES=3\n"+
					"RVM_VOL0_KIND=image\nRVM_VOL0_PATH="+shellQuote(mounts[0])+"\nRVM_VOL0_IMAGE=a.img\n"+
					"RVM_VOL1_KIND=share\nRVM_VOL1_PATH="+shellQuote(mounts[1])+"\n"+
					"RVM_VOL2_KIND=block\nRVM_VOL2_PATH="+shellQuote(mounts[2])+"\n"), 0o644)).To(Succeed())
				r := teardown("5")
				Expect(r.out).To(Equal("status=5\n"))
				Expect(r.calls).To(Equal("sync -f " + mounts[2] + "\numount " + mounts[2] + "\n" +
					"sync -f " + mounts[1] + "\numount " + mounts[1] + "\n" +
					"sync -f " + mounts[0] + "\numount " + mounts[0] + "\n"))
			})

			It("flushes a share before it unmounts it, and reports a share that will not unmount", func() {
				shared := filepath.Join(dir, "shared")
				Expect(os.WriteFile(filepath.Join(dir, "mounts"), []byte("RVM_VOLUMES=1\nRVM_VOL0_KIND=share\nRVM_VOL0_PATH="+shellQuote(shared)+"\n"), 0o644)).To(Succeed())
				r := teardown("4")
				Expect(r.out).To(Equal("status=4\n"))
				Expect(r.calls).To(Equal("sync -f " + shared + "\numount " + shared + "\n"))

				Expect(os.Remove(callLog)).To(Succeed())
				r = teardown("4", "UMOUNT_RC=1")
				Expect(r.out).To(Equal("vm-launch guest: unmounting " + shared + " failed; data was already synced\nstatus=4\n"))
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
	// goldenVol0Disks is what /rvm/disks names a 1 GiB first volume by on
	// QEMU.
	const goldenVol0Disks = "RVM_VOL0_KIND=image\nRVM_VOL0_ID=rvm-vol0\nRVM_VOL0_SECTORS=2097152\n"

	// guestWith returns a task guest with a root disk of rootBytes at ratio
	// bytes per inode, when rootBytes is not 0, and vol on a 1 GiB image,
	// when vol is not nil, both with their QEMU serials.
	guestWith := func(rootBytes, ratio int64, vol *guestVolume) guestContents {
		g := taskGuest("true")
		g.rootBytes, g.rootInodeRatio = rootBytes, ratio
		if rootBytes > 0 {
			g.drives.rootID = qemuRootSerial
		}
		if vol != nil {
			g.vols, g.drives.volumes = []guestVolume{*vol}, qemuImageDrives(defaultImageSize)
		}
		return g
	}

	DescribeTable("names each drive the guest has by its identity and its size in sectors",
		func(rootBytes, ratio int64, vol *guestVolume, want string) {
			got, err := disksFile(guestWith(rootBytes, ratio, vol))
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(want))

			out, err := exec.Command("/bin/sh", "-c", `. "$1"; printf '%s|%s|%s|%s' "${RVM_ROOT_SECTORS-unset}" "${RVM_ROOT_INODE_RATIO-unset}" "${RVM_VOL0_SECTORS-unset}" "${RVM_VOLUME_SECTORS-unset}"`, "sh", writeTempFile("disks", got)).Output()
			Expect(err).NotTo(HaveOccurred())
			fields := strings.Split(string(out), "|")
			Expect(fields).To(HaveLen(4))
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
			Expect(fields[3]).To(Equal("unset"), "the guest finds the volume by its identity, not by a size")
		},
		Entry("no root disk and no volume", int64(0), int64(0), nil, "RVM_VOLUMES=0\n"),
		Entry("a root disk", int64(rootBytes), int64(16384), nil, "RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=131072\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUMES=0\n"),
		Entry("a volume", int64(0), int64(0), vol, "RVM_VOLUMES=1\n"+goldenVol0Disks),
		Entry("both", int64(rootBytes), int64(16384), vol, "RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=131072\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUMES=1\n"+goldenVol0Disks),
		Entry("a root disk of the volume's size, since the guest tells the drives apart by identity", int64(defaultImageSize), int64(16384), vol,
			"RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=2097152\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUMES=1\n"+goldenVol0Disks),
		Entry("a root disk larger than the volume", int64(2*defaultImageSize), int64(16384), vol,
			"RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=4194304\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUMES=1\n"+goldenVol0Disks),
		Entry("a root disk of the volume's size without a volume", int64(defaultImageSize), int64(16384), nil, "RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=2097152\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUMES=0\n"),
	)

	DescribeTable("rejects a root disk the guest could not format as asked, so no initramfs is built",
		func(rootBytes, ratio int64, vol *guestVolume, want string) {
			g := guestWith(rootBytes, ratio, vol)
			_, err := disksFile(g)
			Expect(err).To(MatchError(want))

			bb := filepath.Join(GinkgoT().TempDir(), "busybox")
			Expect(os.WriteFile(bb, []byte("busybox"), 0o755)).To(Succeed())
			held := heldInitramfs()
			_, err = newInitramfs(bb, g)
			Expect(err).To(MatchError("writing the initramfs: " + want))
			Expect(heldInitramfs()).To(Equal(held))
		},
		Entry("a root disk of part of a sector", int64(rootBytes+100), int64(16384), nil,
			"the guest root image of 67108964 bytes is not a whole number of 512-byte sectors"),
		Entry("a root disk without an inode ratio", int64(rootBytes), int64(0), vol, "the guest root image of 67108864 bytes has no inode ratio"),
		Entry("an inode ratio without a root disk", int64(0), int64(16384), nil, "an inode ratio of 16384 bytes per inode for no guest root image"),
		Entry("a negative size", int64(-512), int64(16384), nil, "the guest root image of -512 bytes at 16384 bytes per inode has a negative size"),
		Entry("a negative inode ratio", int64(rootBytes), int64(-1), nil, "the guest root image of 67108864 bytes at -1 bytes per inode has a negative size"),
	)

	It("names the size of the volume image it was given, not the size of a new one", func() {
		g := guestWith(defaultImageSize, 16384, vol)
		g.drives.volumes = qemuImageDrives(2 * defaultImageSize)
		got, err := disksFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=2097152\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUMES=1\nRVM_VOL0_KIND=image\nRVM_VOL0_ID=rvm-vol0\nRVM_VOL0_SECTORS=4194304\n"))
	})

	DescribeTable("rejects a volume image whose size is not a whole number of sectors",
		func(volumeBytes int64) {
			g := guestWith(0, 0, vol)
			g.drives.volumes = qemuImageDrives(volumeBytes)
			_, err := disksFile(g)
			Expect(err).To(MatchError(fmt.Sprintf("the volume image of %d bytes on drive vol0 is not a positive whole number of 512-byte sectors", volumeBytes)))
		},
		Entry("an unset size", int64(0)),
		Entry("a negative size", int64(-512)),
		Entry("part of a sector", int64(defaultImageSize+1)),
	)
})

// stage1Head is what stage 1 runs before rvm_fail: busybox's applets and the
// three mounts, which a run outside a guest leaves out. The runs set
// rvm_devtmpfs themselves, as the devtmpfs mount does.
const stage1Head = "#!/bin/busybox sh\n/bin/busybox --install -s /bin\nexport PATH=/bin\nmount -t proc proc /proc\nmount -t sysfs sys /sys\nrvm_devtmpfs=\nmount -t devtmpfs dev /dev 2>/dev/null && rvm_devtmpfs=1\n"

var _ = Describe("stage 1 of the guest's boot", func() {
	// Sizes in sectors: the volume image's, which is 1 GiB, and a guest root
	// image of 64 MiB.
	const (
		volumeSectors = "2097152"
		rootSectors   = "131072"
		rootRatio     = "16384"
	)

	// rootEntry is what /rvm/disks names a guest root drive by, with the
	// identity id and a size of sectors, and volEntry the same for the
	// image volume at index i.
	rootEntry := func(id, sectors string) string {
		return "RVM_ROOT_ID=" + id + "\nRVM_ROOT_SECTORS=" + sectors + "\nRVM_ROOT_INODE_RATIO=" + rootRatio + "\n"
	}
	volEntry := func(i int, id, sectors string) string {
		n := strconv.Itoa(i)
		return "RVM_VOL" + n + "_KIND=image\nRVM_VOL" + n + "_ID=" + id + "\nRVM_VOL" + n + "_SECTORS=" + sectors + "\n"
	}
	// bothDisks names a 64 MiB root and one 1 GiB volume by their QEMU
	// serials.
	bothDisks := rootEntry("rvm-root", rootSectors) + "RVM_VOLUMES=1\n" + volEntry(0, "rvm-vol0", volumeSectors)

	type stage1Run struct {
		out   string
		calls string
		code  int
	}

	var (
		dir     string
		bin     string
		callLog string
		late    string
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		bin = filepath.Join(dir, "bin")
		callLog = filepath.Join(dir, "calls")
		late = filepath.Join(dir, "late")
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
		// The first sleep runs the script in late, once, as a late probe
		// would make a device, its device file, or its identity appear.
		stub("sleep", `if [ -f `+shellQuote(late)+` ]; then
	mv `+shellQuote(late)+` `+shellQuote(late+".ran")+` && sh `+shellQuote(late+".ran")+`
fi
exit 0`)
		stub("chroot", `echo "chroot in $(pwd -P)" >> `+shellQuote(callLog))
		stub("stage2", `exit 0`)
	})

	// sysBlock is the fake sysfs directory of the block device name.
	sysBlock := func(name string) string { return filepath.Join(dir, "sys", "block", name) }
	dev := func(name string) string { return filepath.Join(dir, "dev", name) }

	// disk adds the block device name to the fake sysfs with the identity
	// serial, written without a newline as virtio_blk gives it, and size
	// sectors, and, unless content is nil, its device file with content.
	disk := func(name, serial, sectors string, content []byte) {
		Expect(os.MkdirAll(sysBlock(name), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(sysBlock(name), "serial"), []byte(serial), 0o444)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(sysBlock(name), "size"), []byte(sectors+"\n"), 0o444)).To(Succeed())
		if content != nil {
			Expect(os.WriteFile(dev(name), content, 0o600)).To(Succeed())
		}
	}

	// reset takes the test directory back to no devices, no calls, and no
	// mount points, keeping the stubs.
	reset := func() {
		for _, p := range []string{callLog, late, late + ".ran", filepath.Join(dir, "disk"), filepath.Join(dir, "root"), filepath.Join(dir, "sys"), filepath.Join(dir, "dev")} {
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

	// standard adds the volume as vda and the guest root as vdb, with their
	// QEMU serials and the sizes bothDisks gives them.
	standard := func() {
		disk("vda", "rvm-vol0", volumeSectors, formatted)
		disk("vdb", "rvm-root", rootSectors, blank)
	}

	// run executes stage 1 from rvm_fail on in shell, with disks as
	// /rvm/disks, the guest paths moved into the test directory, the
	// commands that would change the host stubbed, and reboot replaced by
	// a marker. dd, tr, rm, cat, and mkdir are the real ones. The overlay
	// root has the shell and stage 2 unless env holds NO_SH=1 or
	// NO_STAGE2=1, and the devtmpfs mount succeeds unless env holds
	// NO_DEVTMPFS=1. The device files are regular files, so the check for a
	// block device is for any file.
	run := func(shell guestShell, disks string, env ...string) stage1Run {
		Expect(os.WriteFile(filepath.Join(dir, "disks"), []byte(disks), 0o644)).To(Succeed())
		if !slices.Contains(env, "NO_SH=1") {
			Expect(os.MkdirAll(filepath.Join(dir, "root", "bin"), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "root", "bin", "sh"), nil, 0o755)).To(Succeed())
		}
		if !slices.Contains(env, "NO_STAGE2=1") {
			Expect(os.MkdirAll(filepath.Join(dir, "root", "rvm"), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "root", "rvm", "init"), nil, 0o644)).To(Succeed())
		}
		devtmpfs := "rvm_devtmpfs=1\n"
		if slices.Contains(env, "NO_DEVTMPFS=1") {
			devtmpfs = "rvm_devtmpfs=\n"
		}
		Expect(guestRootInit).To(HavePrefix(stage1Head))
		Expect(guestRootInit).To(ContainSubstring(`[ -b "$rvm_n" ]`))
		script := strings.NewReplacer(
			"/rvm/disks", filepath.Join(dir, "disks"),
			"/rvm/root-", filepath.Join(dir, "root-"),
			"/rvm/disk", filepath.Join(dir, "disk"),
			"/rvm/root", filepath.Join(dir, "root"),
			"/sys/block", filepath.Join(dir, "sys", "block"),
			"/dev/${rvm_b##*/}", filepath.Join(dir, "dev")+"/${rvm_b##*/}",
			`[ -b "$rvm_n" ]`, `[ -e "$rvm_n" ]`,
			"mke2fs -F", filepath.Join(bin, "mke2fs")+" -F",
			"mount -", filepath.Join(bin, "mount")+" -",
			"sleep 1", filepath.Join(bin, "sleep")+" 1",
			"exec chroot", "exec "+filepath.Join(bin, "chroot"),
			"exec /bin/sh", "exec "+filepath.Join(bin, "stage2"),
			"reboot -nf", "echo REBOOT",
		).Replace(strings.TrimPrefix(guestRootInit, stage1Head))
		script = devtmpfs + script
		Expect(strings.ReplaceAll(script, guestStage2, "")).NotTo(ContainSubstring("/rvm/"))
		Expect(script).NotTo(ContainSubstring(" /sys/"))
		Expect(script).NotTo(ContainSubstring("-b \""))

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

	// handoff is the end of stage 2's command line: the volumes' devices, in
	// volume order, as stage 1 passes them.
	handoff := func(volumes []string) string {
		if len(volumes) == 0 {
			return ""
		}
		return " " + strings.Join(volumes, " ")
	}

	// ramRoot is what the stubs record for a guest that keeps the RAM root
	// and passes volumes to stage 2.
	ramRoot := func(volumes ...string) string { return "stage2 " + guestStage2 + handoff(volumes) + "\n" }

	// entered is what the stubs record for a root disk at root that stage
	// 1 formats and enters, passing volumes to stage 2.
	entered := func(root string, volumes ...string) string {
		d := filepath.Join(dir, "disk")
		r := filepath.Join(dir, "root")
		real, err := filepath.EvalSymlinks(dir)
		Expect(err).NotTo(HaveOccurred())
		return "mke2fs -F -b 4096 -m 0 -I 256 -i " + rootRatio + " -L rvm-root " + root + "\n" +
			"mount -t ext4 -o noatime,discard,errors=continue " + root + " " + d + "\n" +
			"mount -t overlay -o lowerdir=/,upperdir=" + d + "/upper,workdir=" + d + "/work overlay " + r + "\n" +
			"mount -o move /proc " + r + "/proc\n" +
			"mount -o move /sys " + r + "/sys\n" +
			"mount -o move /dev " + r + "/dev\n" +
			"mount -o move . /\n" +
			"chroot . /bin/sh " + guestStage2 + handoff(volumes) + "\n" +
			"chroot in " + filepath.Join(real, "root") + "\n"
	}

	// The harness moves /rvm/disks into dir, and the messages name it.
	disksPath := func() string { return filepath.Join(dir, "disks") }

	DescribeTable("finds the drives by identity alone, in any device order and with one size for all, and hands each volume's device to stage 2 in volume order",
		func(shellOf func() guestShell) {
			shell := shellOf()
			// The root and both volumes have one size, so only their
			// identities tell them apart.
			disks := rootEntry("rvm-root", volumeSectors) + "RVM_VOLUMES=2\n" + volEntry(0, "rvm-vol0", volumeSectors) + volEntry(1, "rvm-vol1", volumeSectors)
			for _, order := range [][3]string{{"rvm-root", "rvm-vol0", "rvm-vol1"}, {"rvm-vol1", "rvm-root", "rvm-vol0"}, {"rvm-vol0", "rvm-vol1", "rvm-root"}} {
				reset()
				at := map[string]string{}
				for i, id := range order {
					name := "vd" + string(rune('a'+i))
					at[id] = name
					content := formatted
					if id == "rvm-root" {
						content = blank
					}
					disk(name, id, volumeSectors, content)
				}

				r := run(shell, disks)
				Expect(r.code).To(Equal(0), "%s, order %v: %s", shell.name, order, r.out)
				Expect(r.out).NotTo(ContainSubstring("vm-launch guest setup"))
				Expect(r.calls).To(Equal(entered(dev(at["rvm-root"]), dev(at["rvm-vol0"]), dev(at["rvm-vol1"]))), "%s, order %v", shell.name, order)
				for _, v := range []string{"rvm-vol0", "rvm-vol1"} {
					Expect(os.ReadFile(dev(at[v]))).To(Equal(formatted), "the volume %s is never written", v)
				}
				Expect(filepath.Join(dir, "disk", "upper")).To(BeADirectory())
				Expect(filepath.Join(dir, "disk", "work")).To(BeADirectory())
				Expect(filepath.Join(dir, "root-head")).NotTo(BeAnExistingFile())
				Expect(filepath.Join(dir, "root-used")).NotTo(BeAnExistingFile())
			}
		},
		shellEntries(""),
	)

	DescribeTable("matches the identities Firecracker gives, and an identity read with a newline",
		func(shellOf func() guestShell) {
			shell := shellOf()
			const rootID, volID = "64768123456789012345", "6476802-1"
			disk("vda", volID+"\n", volumeSectors, formatted)
			disk("vdb", rootID, rootSectors, blank)
			r := run(shell, rootEntry(rootID, rootSectors)+"RVM_VOLUMES=1\n"+volEntry(0, volID, volumeSectors))
			Expect(r.code).To(Equal(0), r.out)
			Expect(r.calls).To(Equal(entered(dev("vdb"), dev("vda"))))
		},
		shellEntries(""),
	)

	DescribeTable("keeps the RAM root and formats nothing when /rvm/disks names no root disk",
		func(shellOf func() guestShell) {
			shell := shellOf()
			disk("vda", "rvm-vol1", volumeSectors, formatted)
			disk("vdb", "rvm-vol0", rootSectors, formatted)
			r := run(shell, "RVM_VOLUMES=2\n"+volEntry(0, "rvm-vol0", rootSectors)+volEntry(1, "rvm-vol1", volumeSectors))
			Expect(r.code).To(Equal(0), r.out)
			Expect(r.calls).To(Equal(ramRoot(dev("vdb"), dev("vda"))))
			Expect(filepath.Join(dir, "disk")).NotTo(BeAnExistingFile())
			Expect(os.ReadFile(dev("vda"))).To(Equal(formatted))

			reset()
			r = run(shell, "RVM_VOLUMES=0\n")
			Expect(r.code).To(Equal(0), r.out)
			Expect(r.calls).To(Equal(ramRoot()))
		},
		shellEntries(""),
	)

	DescribeTable("keeps the place of a volume without a drive, passing it an empty argument, and still refuses a device no drive names",
		func(shellOf func() guestShell) {
			shell := shellOf()
			disks := "RVM_VOLUMES=3\n" + volEntry(0, "rvm-vol0", volumeSectors) + "RVM_VOL1_KIND=share\n" + volEntry(2, "rvm-vol2", volumeSectors)
			disk("vda", "rvm-vol2", volumeSectors, formatted)
			disk("vdb", "rvm-vol0", volumeSectors, formatted)
			// A variable the kernel left in init's environment does not
			// stand in for the volume without a drive.
			r := run(shell, disks, "rvm_dev_vol1="+dev("vda"))
			Expect(r.code).To(Equal(0), r.out)
			Expect(r.calls).To(Equal(ramRoot(dev("vdb"), "", dev("vda"))))

			reset()
			disk("vda", "rvm-vol2", volumeSectors, formatted)
			disk("vdb", "rvm-vol0", volumeSectors, formatted)
			disk("vdc", "rvm-vol1", volumeSectors, formatted)
			failed(run(shell, disks), "the block device "+dev("vdc")+" has the identity rvm-vol1, which "+disksPath()+" gives no drive, so the guest will not boot with it", "")
		},
		shellEntries(""),
	)

	DescribeTable("fails at once, touching no device, on a block device that /rvm/disks names no drive by",
		func(shellOf func() guestShell) {
			shell := shellOf()
			standard()
			disk("vdc", "rvm-vol1", volumeSectors, formatted)
			failed(run(shell, bothDisks), "the block device "+dev("vdc")+" has the identity rvm-vol1, which "+disksPath()+" gives no drive, so the guest will not boot with it", "")

			// A device without an identity, as virtio_blk gives one whose
			// hypervisor sets none, is no drive /rvm/disks names either.
			reset()
			standard()
			disk("vdc", "", volumeSectors, formatted)
			failed(run(shell, bothDisks), "the block device "+dev("vdc")+" has no identity, so it is no drive "+disksPath()+" names, and the guest will not boot with it", "")

			// A guest without drives refuses any device.
			reset()
			disk("vda", "rvm-vol0", volumeSectors, formatted)
			failed(run(shell, "RVM_VOLUMES=0\n"), "the block device "+dev("vda")+" has the identity rvm-vol0, which "+disksPath()+" gives no drive, so the guest will not boot with it", "")
			Expect(os.ReadFile(dev("vda"))).To(Equal(formatted))
		},
		shellEntries(""),
	)

	DescribeTable("fails at once, touching no device, when two block devices have one drive's identity",
		func(shellOf func() guestShell) {
			shell := shellOf()
			disk("vda", "rvm-root", rootSectors, formatted)
			disk("vdb", "rvm-root", rootSectors, blank)
			disk("vdc", "rvm-vol0", volumeSectors, formatted)
			failed(run(shell, bothDisks), "two block devices, "+dev("vda")+" and "+dev("vdb")+", have the identity rvm-root of the guest root drive, so the guest cannot tell which one it is", "")
			Expect(os.ReadFile(dev("vda"))).To(Equal(formatted))

			reset()
			disk("vda", "rvm-root", rootSectors, blank)
			disk("vdb", "rvm-vol0", volumeSectors, formatted)
			disk("vdc", "rvm-vol0", volumeSectors, formatted)
			failed(run(shell, bothDisks), "two block devices, "+dev("vdb")+" and "+dev("vdc")+", have the identity rvm-vol0 of the volume drive vol0, so the guest cannot tell which one it is", "")
		},
		shellEntries(""),
	)

	DescribeTable("fails at once, touching no device, when a drive's size is not the one /rvm/disks gives it",
		func(shellOf func() guestShell) {
			shell := shellOf()
			disk("vda", "rvm-vol0", volumeSectors, formatted)
			disk("vdb", "rvm-root", volumeSectors, formatted)
			failed(run(shell, bothDisks), "the guest root drive "+dev("vdb")+" has "+volumeSectors+" sectors, and "+disksPath()+" gives it "+rootSectors+", so the guest will not use it", "")
			Expect(os.ReadFile(dev("vdb"))).To(Equal(formatted))

			reset()
			disk("vda", "rvm-vol0", rootSectors, formatted)
			disk("vdb", "rvm-root", rootSectors, blank)
			failed(run(shell, bothDisks), "the volume drive vol0 "+dev("vda")+" has "+rootSectors+" sectors, and "+disksPath()+" gives it "+volumeSectors+", so the guest will not use it", "")
		},
		shellEntries(""),
	)

	DescribeTable("never formats a drive with data: it fails when the root drive is not blank",
		func(shellOf func() guestShell) {
			shell := shellOf()
			// A volume that stood where the root disk should be, as when a
			// host passed the wrong file under the root's identity.
			disk("vda", "rvm-root", rootSectors, formatted)
			disk("vdb", "rvm-vol0", volumeSectors, blank)
			failed(run(shell, bothDisks), "the guest root disk "+dev("vda")+" is not blank, so vm-launch will not format it", "")
			Expect(os.ReadFile(dev("vda"))).To(Equal(formatted))
			Expect(filepath.Join(dir, "root-head")).NotTo(BeAnExistingFile())
		},
		shellEntries(""),
	)

	DescribeTable("fails rather than guess, before it looks at any device, when /rvm/disks names its drives in a way it cannot use",
		func(shellOf func() guestShell) {
			shell := shellOf()
			standard()
			disks := disksPath()
			rootLine := "the guest root size or inode ratio in " + disks + " is not a positive number"
			rootIDLine := "the guest root drive's identity in " + disks + " is not 1 to " + virtioBlockIDBytesText + " letters, digits, and hyphens"
			countLine := "the volume count in " + disks + " is not a number from 0 to " + maxVolumesText
			vol0 := volEntry(0, "rvm-vol0", volumeSectors)
			root := rootEntry("rvm-root", rootSectors)
			for table, line := range map[string]string{
				"RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=" + rootSectors + "\nRVM_VOLUMES=0\n":                           rootLine,
				"RVM_ROOT_ID=rvm-root\nRVM_VOLUMES=0\n":                                                                 rootLine,
				"RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=" + rootSectors + "\nRVM_ROOT_INODE_RATIO=\nRVM_VOLUMES=0\n":    rootLine,
				rootEntry("rvm-root", "0"+rootSectors) + "RVM_VOLUMES=0\n":                                              rootLine,
				rootEntry("rvm-root", "'"+rootSectors+" '") + "RVM_VOLUMES=0\n":                                         rootLine,
				rootEntry("rvm-root", "-1") + "RVM_VOLUMES=0\n":                                                         rootLine,
				"RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=" + rootSectors + "\nRVM_ROOT_INODE_RATIO=16k\nRVM_VOLUMES=0\n": rootLine,
				"RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=" + rootSectors + "\nRVM_ROOT_INODE_RATIO=0\nRVM_VOLUMES=0\n":   rootLine,
				"RVM_ROOT_SECTORS=" + rootSectors + "\nRVM_ROOT_INODE_RATIO=" + rootRatio + "\nRVM_VOLUMES=0\n":         rootIDLine,
				rootEntry("rvm_root", rootSectors) + "RVM_VOLUMES=0\n":                                                  rootIDLine,
				rootEntry("'rvm root'", rootSectors) + "RVM_VOLUMES=0\n":                                                rootIDLine,
				rootEntry(strings.Repeat("7", virtioBlockIDBytes+1), rootSectors) + "RVM_VOLUMES=0\n":                   rootIDLine,
				"":                        countLine,
				root:                      countLine,
				"RVM_VOLUMES=5\n" + vol0:  countLine,
				"RVM_VOLUMES=01\n" + vol0: countLine,
				"RVM_VOLUMES=-1\n":        countLine,
				"RVM_VOLUMES=x\n":         countLine,
				root + "RVM_VOLUMES=1\n":  "the volume drive vol0 in " + disks + " has no kind",
				root + "RVM_VOLUMES=1\nRVM_VOL0_KIND=plain\nRVM_VOL0_ID=rvm-vol0\nRVM_VOL0_SECTORS=" + volumeSectors + "\n": "the volume drive vol0 in " + disks + " has the kind plain, which the guest does not know",
				root + "RVM_VOLUMES=1\nRVM_VOL0_KIND=Block\nRVM_VOL0_ID=rvm-vol0\nRVM_VOL0_SECTORS=" + volumeSectors + "\n": "the volume drive vol0 in " + disks + " has the kind Block, which the guest does not know",
				root + "RVM_VOLUMES=1\nRVM_VOL0_KIND=share\nRVM_VOL0_ID=rvm-vol0\n":                                         "the volume vol0 in " + disks + " is a share, which has no drive, yet it has a drive identity or size",
				root + "RVM_VOLUMES=1\nRVM_VOL0_KIND=share\nRVM_VOL0_SECTORS=" + volumeSectors + "\n":                       "the volume vol0 in " + disks + " is a share, which has no drive, yet it has a drive identity or size",
				root + "RVM_VOLUMES=1\nRVM_VOL0_KIND=image\nRVM_VOL0_SECTORS=" + volumeSectors + "\n":                       "the volume drive vol0's identity in " + disks + " is not 1 to " + virtioBlockIDBytesText + " letters, digits, and hyphens",
				root + "RVM_VOLUMES=1\n" + volEntry(0, "rvm.vol0", volumeSectors):                                           "the volume drive vol0's identity in " + disks + " is not 1 to " + virtioBlockIDBytesText + " letters, digits, and hyphens",
				root + "RVM_VOLUMES=1\n" + volEntry(0, "rvm-vol0", "1GiB"):                                                  "the volume drive vol0's size in " + disks + " is not a positive number",
				root + "RVM_VOLUMES=1\n" + volEntry(0, "rvm-vol0", "0"):                                                     "the volume drive vol0's size in " + disks + " is not a positive number",
				root + "RVM_VOLUMES=1\n" + volEntry(0, "rvm-vol0", "'*'"):                                                   "the volume drive vol0's size in " + disks + " is not a positive number",
				root + "RVM_VOLUMES=1\n" + volEntry(0, "rvm-root", volumeSectors):                                           "the guest root drive and the volume drive vol0 have the one identity rvm-root in " + disks + ", so the guest cannot tell them apart",
				"RVM_VOLUMES=2\n" + vol0 + volEntry(1, "rvm-vol0", volumeSectors):                                           "the volume drive vol0 and the volume drive vol1 have the one identity rvm-vol0 in " + disks + ", so the guest cannot tell them apart",
			} {
				Expect(os.RemoveAll(callLog)).To(Succeed())
				r := run(shell, table)
				Expect(r.out).To(HaveSuffix("vm-launch guest setup: "+line+"\nREBOOT\n"), "%s: %q", shell.name, table)
				Expect(r.code).To(Equal(1), "%s: %q", shell.name, table)
				Expect(r.calls).To(BeEmpty(), "%s: %q", shell.name, table)
			}
			Expect(os.ReadFile(dev("vda"))).To(Equal(formatted))
		},
		shellEntries(""),
	)

	// blockEntry is what /rvm/disks names the block volume at index i by.
	blockEntry := func(i int, id, sectors string) string {
		return strings.Replace(volEntry(i, id, sectors), "_KIND=image\n", "_KIND=block\n", 1)
	}

	DescribeTable("finds a block volume's drive by identity and size as it finds an image's, and hands its device to stage 2 in its place",
		func(shellOf func() guestShell) {
			shell := shellOf()
			disks := "RVM_VOLUMES=2\n" + volEntry(0, "rvm-vol0", volumeSectors) + blockEntry(1, "rvm-vol1", rootSectors)
			Expect(disks).To(ContainSubstring("RVM_VOL1_KIND=block\n"))
			disk("vda", "rvm-vol1", rootSectors, blank)
			disk("vdb", "rvm-vol0", volumeSectors, formatted)
			r := run(shell, disks)
			Expect(r.code).To(Equal(0), "%s: %s", shell.name, r.out)
			Expect(r.calls).To(Equal(ramRoot(dev("vdb"), dev("vda"))), "%s", shell.name)
			// Stage 1 never formats a volume, so the blank disk stays blank.
			Expect(os.ReadFile(dev("vda"))).To(Equal(blank))

			// A block drive of another size fails as an image's does.
			reset()
			disk("vda", "rvm-vol1", volumeSectors, blank)
			disk("vdb", "rvm-vol0", volumeSectors, formatted)
			failed(run(shell, disks), "the volume drive vol1 "+dev("vda")+" has "+volumeSectors+" sectors, and "+disksPath()+" gives it "+rootSectors+", so the guest will not use it", "")

			// A block drive that never appears is waited for and named.
			reset()
			disk("vdb", "rvm-vol0", volumeSectors, formatted)
			failed(run(shell, disks), "no block device with the identity rvm-vol1 for the volume drive vol1", strings.Repeat("sleep 1\n", 5))
		},
		shellEntries(""),
	)

	DescribeTable("never takes a root drive from init's environment when /rvm/disks names none",
		func(shellOf func() guestShell) {
			shell := shellOf()
			disk("vda", "rvm-vol0", volumeSectors, blank)
			r := run(shell, "RVM_VOLUMES=1\n"+volEntry(0, "rvm-vol0", volumeSectors), "rvm_dev_root="+dev("vda"), "RVM_ROOT_INODE_RATIO="+rootRatio)
			Expect(r.code).To(Equal(0), "%s: %s", shell.name, r.out)
			Expect(r.calls).To(Equal(ramRoot(dev("vda"))), "%s", shell.name)
			Expect(os.ReadFile(dev("vda"))).To(Equal(blank))
		},
		shellEntries(""),
	)

	DescribeTable("fails after six checks, before it formats anything, and names each drive that never appears by its identity",
		func(shellOf func() guestShell) {
			shell := shellOf()
			rootLine := "no block device with the identity rvm-root for the guest root drive"
			volumeLine := "no block device with the identity rvm-vol0 for the volume drive vol0"

			disk("vda", "rvm-vol0", volumeSectors, formatted)
			failed(run(shell, bothDisks), rootLine, strings.Repeat("sleep 1\n", 5))

			reset()
			disk("vda", "rvm-root", rootSectors, blank)
			failed(run(shell, bothDisks), volumeLine, strings.Repeat("sleep 1\n", 5))

			reset()
			failed(run(shell, bothDisks), rootLine+", and "+volumeLine, strings.Repeat("sleep 1\n", 5))
		},
		shellEntries(""),
	)

	DescribeTable("waits for a drive that appears late, and uses it once it does",
		func(shellOf func() guestShell) {
			shell := shellOf()
			// writeLate makes the first sleep run script.
			writeLate := func(script string) { Expect(os.WriteFile(late, []byte(script), 0o644)).To(Succeed()) }

			// A device file that is not there yet.
			disk("vda", "rvm-vol0", volumeSectors, formatted)
			disk("vdb", "rvm-root", rootSectors, nil)
			writeLate("dd if=/dev/zero of=" + shellQuote(dev("vdb")) + " bs=4096 count=16 2>/dev/null\n")
			r := run(shell, bothDisks)
			Expect(r.code).To(Equal(0), "%s: %s", shell.name, r.out)
			Expect(r.calls).To(Equal("sleep 1\n" + entered(dev("vdb"), dev("vda"))))

			reset()
			disk("vda", "rvm-vol0", volumeSectors, formatted)
			disk("vdb", "rvm-root", rootSectors, nil)
			failed(run(shell, bothDisks), "no device node "+dev("vdb")+" yet for the guest root drive", strings.Repeat("sleep 1\n", 5))

			// An identity that cannot be read yet.
			reset()
			disk("vda", "rvm-vol0", volumeSectors, formatted)
			disk("vdb", "rvm-root", rootSectors, blank)
			Expect(os.Remove(filepath.Join(sysBlock("vdb"), "serial"))).To(Succeed())
			writeLate("printf rvm-root > " + shellQuote(filepath.Join(sysBlock("vdb"), "serial")) + "\n")
			r = run(shell, bothDisks)
			Expect(r.code).To(Equal(0), "%s: %s", shell.name, r.out)
			Expect(r.calls).To(Equal("sleep 1\n" + entered(dev("vdb"), dev("vda"))))

			reset()
			disk("vda", "rvm-vol0", volumeSectors, formatted)
			disk("vdb", "rvm-root", rootSectors, blank)
			Expect(os.Remove(filepath.Join(sysBlock("vdb"), "serial"))).To(Succeed())
			failed(run(shell, bothDisks), "no readable identity yet on the block device "+dev("vdb")+", and no block device with the identity rvm-root for the guest root drive", strings.Repeat("sleep 1\n", 5))

			// A size that cannot be read yet: vdb's is a directory, which
			// every user, root included, fails to read.
			reset()
			disk("vda", "rvm-vol0", volumeSectors, formatted)
			disk("vdb", "rvm-root", rootSectors, blank)
			size := filepath.Join(sysBlock("vdb"), "size")
			Expect(os.Remove(size)).To(Succeed())
			Expect(os.Mkdir(size, 0o755)).To(Succeed())
			writeLate("rmdir " + shellQuote(size) + " && echo " + rootSectors + " > " + shellQuote(size) + "\n")
			r = run(shell, bothDisks)
			Expect(r.code).To(Equal(0), "%s: %s", shell.name, r.out)
			Expect(r.calls).To(Equal("sleep 1\n" + entered(dev("vdb"), dev("vda"))))

			reset()
			disk("vda", "rvm-vol0", volumeSectors, formatted)
			disk("vdb", "rvm-root", rootSectors, blank)
			Expect(os.Remove(size)).To(Succeed())
			Expect(os.Mkdir(size, 0o755)).To(Succeed())
			failed(run(shell, bothDisks), "no readable size yet for the guest root drive on "+dev("vdb"), strings.Repeat("sleep 1\n", 5))

			// A whole device that is not there yet.
			reset()
			disk("vda", "rvm-vol0", volumeSectors, formatted)
			b := sysBlock("vdb")
			writeLate("mkdir " + shellQuote(b) + " && printf rvm-root > " + shellQuote(b+"/serial") + " && echo " + rootSectors + " > " + shellQuote(b+"/size") +
				" && dd if=/dev/zero of=" + shellQuote(dev("vdb")) + " bs=4096 count=16 2>/dev/null\n")
			r = run(shell, bothDisks)
			Expect(r.code).To(Equal(0), "%s: %s", shell.name, r.out)
			Expect(r.calls).To(Equal("sleep 1\n" + entered(dev("vdb"), dev("vda"))))
		},
		shellEntries(""),
	)

	It("fails with its own line, before any move, when /dev is not a devtmpfs mount", func() {
		shell := hostShell()
		standard()
		failed(run(shell, bothDisks, "NO_DEVTMPFS=1"), "mounting devtmpfs at /dev failed", "")
	})

	It("fails with its own line, before any move, when the overlay root has no shell or no stage 2", func() {
		shell := hostShell()
		standard()
		root := dev("vdb")
		formatAndMount := "mke2fs -F -b 4096 -m 0 -I 256 -i " + rootRatio + " -L rvm-root " + root + "\n" +
			"mount -t ext4 -o noatime,discard,errors=continue " + root + " " + filepath.Join(dir, "disk") + "\n" +
			"mount -t overlay -o lowerdir=/,upperdir=" + filepath.Join(dir, "disk") + "/upper,workdir=" + filepath.Join(dir, "disk") + "/work overlay " + filepath.Join(dir, "root") + "\n"
		failed(run(shell, bothDisks, "NO_SH=1"), "the overlay root has no /bin/sh to run stage 2", formatAndMount)

		Expect(os.Remove(callLog)).To(Succeed())
		Expect(os.RemoveAll(filepath.Join(dir, "disk"))).To(Succeed())
		Expect(os.RemoveAll(filepath.Join(dir, "root"))).To(Succeed())
		failed(run(shell, bothDisks, "NO_STAGE2=1"), "the overlay root has no "+guestStage2, formatAndMount)
	})

	It("treats a read error, or a root disk it read nothing from, as a failure, never as a blank disk", func() {
		shell := hostShell()
		disk("vda", "rvm-vol0", volumeSectors, formatted)
		// vdb's device file is a directory, which dd cannot read.
		disk("vdb", "rvm-root", rootSectors, nil)
		Expect(os.Mkdir(dev("vdb"), 0o755)).To(Succeed())
		failed(run(shell, bothDisks), "reading the start of the guest root disk "+dev("vdb")+" failed", "")

		Expect(os.Remove(dev("vdb"))).To(Succeed())

		Expect(os.WriteFile(dev("vdb"), nil, 0o600)).To(Succeed())
		failed(run(shell, bothDisks), "the guest root disk "+dev("vdb")+" is not blank, so vm-launch will not format it", "")
	})

	It("names the step that failed, and stops there", func() {
		shell := hostShell()
		standard()
		root := dev("vdb")
		mke2fs := "mke2fs -F -b 4096 -m 0 -I 256 -i " + rootRatio + " -L rvm-root " + root + "\n"
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

// goldenMke2fsConfSHA256 is the sha256 of the pinned mke2fs.conf. Changing
// the file changes the features and the inode layout of every new image, so
// a change has to change this digest on purpose.
const goldenMke2fsConfSHA256 = "14c13f4289408325fed71bb93daecea347debae7fab0fd062288c9bd4867cd7e"

// openFDCount returns the number of descriptors this process holds.
func openFDCount() int {
	entries, err := os.ReadDir("/proc/self/fd")
	Expect(err).NotTo(HaveOccurred())
	return len(entries)
}

var _ = Describe("the guest filesystem tools", func() {
	// toolsDir returns an artifacts directory that holds the four tools,
	// each with bytes of its own, and returns the bytes by name.
	toolsDir := func() (string, map[string]string) {
		dir := GinkgoT().TempDir()
		want := map[string]string{}
		for _, name := range guestToolNames {
			want[name] = "static " + name + strings.Repeat("\x00\xff", 40)
			Expect(os.WriteFile(filepath.Join(dir, name), []byte(want[name]), 0o755)).To(Succeed())
		}
		return dir, want
	}

	volumeGuest := func() guestContents {
		g := taskGuest("true")
		g.vols = []guestVolume{{ContainerDir: "/data", ImageName: "rvm-disk-3.img"}}
		g.drives.volumes = qemuImageDrives(defaultImageSize)
		return g
	}

	archive := func(g guestContents) (names []string, byName map[string]cpioEntry) {
		bb := filepath.Join(GinkgoT().TempDir(), "busybox")
		Expect(os.WriteFile(bb, []byte("busybox"), 0o755)).To(Succeed())
		f, err := newInitramfs(bb, g)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		return archiveEntries(fileBytes(f))
	}

	It("names the tools at fixed guest paths below /rvm/tools, away from the applets that stage 1 installs in /bin", func() {
		Expect([]string{guestMke2fs, guestE2fsck, guestTune2fs, guestExt4grow, guestMke2fsConfig}).To(Equal([]string{
			"/rvm/tools/mke2fs", "/rvm/tools/e2fsck", "/rvm/tools/tune2fs", "/rvm/tools/ext4grow", "/rvm/tools/mke2fs.conf"}))
		Expect(guestToolNames).To(Equal([]string{"mke2fs", "e2fsck", "tune2fs", "ext4grow"}))
		for _, p := range []string{guestMke2fs, guestE2fsck, guestTune2fs, guestExt4grow, guestMke2fsConfig} {
			Expect(p).NotTo(HavePrefix("/bin/"))
		}
	})

	It("pins the mke2fs.conf the guest's mke2fs reads", func() {
		sum := sha256.Sum256([]byte(guestMke2fsConfText))
		Expect(hex.EncodeToString(sum[:])).To(Equal(goldenMke2fsConfSHA256))
		Expect(guestMke2fsConfText).To(HaveSuffix("\n"))
		Expect(guestMke2fsConfText).To(ContainSubstring("base_features = sparse_super,large_file,filetype,resize_inode,dir_index,ext_attr\n"))
		Expect(guestMke2fsConfText).To(MatchRegexp(`ext4 = \{\n\t\tfeatures = has_journal,extent,[a-z_,]*64bit[a-z_,]*\n\t\}`))
	})

	It("puts the four tools and mke2fs.conf in the initramfs of a guest with a volume, with the modes the guest runs them with", func() {
		dir, want := toolsDir()
		tools, err := openGuestTools(dir)
		Expect(err).NotTo(HaveOccurred())
		defer tools.Close()
		g := volumeGuest()
		g.tools = tools

		names, byName := archive(g)
		Expect(byName).To(HaveKey("rvm/tools"))
		Expect(byName["rvm/tools"].mode).To(Equal(uint32(0o040755)))
		for _, name := range guestToolNames {
			e, ok := byName["rvm/tools/"+name]
			Expect(ok).To(BeTrue(), name)
			Expect(e.mode).To(Equal(uint32(0o100755)), name)
			Expect(string(e.data)).To(Equal(want[name]), name)
		}
		conf := byName["rvm/tools/mke2fs.conf"]
		Expect(conf.mode).To(Equal(uint32(0o100644)))
		Expect(string(conf.data)).To(Equal(guestMke2fsConfText))
		Expect(slices.Index(names, "rvm/tools")).To(BeNumerically("<", slices.Index(names, "rvm/tools/mke2fs")), "a directory comes before what it holds")
		Expect(byName).To(HaveKey("rvm/mounts"))
	})

	It("adds nothing to a guest without the tools, so it boots exactly as before", func() {
		dir, _ := toolsDir()
		tools, err := openGuestTools(dir)
		Expect(err).NotTo(HaveOccurred())
		defer tools.Close()

		without := taskGuest("true")
		names, byName := archive(without)
		for _, n := range names {
			Expect(n).NotTo(HavePrefix("rvm/tools"))
		}
		Expect(string(byName["rvm/init"].data)).To(Equal(goldenInitNet))

		with := without
		with.tools = tools
		moreNames, moreByName := archive(with)
		var added []string
		for _, n := range moreNames {
			if !slices.Contains(names, n) {
				added = append(added, n)
				continue
			}
			Expect(moreByName[n]).To(Equal(byName[n]), n)
		}
		Expect(added).To(Equal([]string{"rvm/tools", "rvm/tools/mke2fs", "rvm/tools/e2fsck", "rvm/tools/tune2fs", "rvm/tools/ext4grow", "rvm/tools/mke2fs.conf"}))
		Expect(moreNames).To(HaveLen(len(names) + len(added)))
	})

	It("writes the bytes of the file it checked, not those of a file put in its place afterwards", func() {
		dir, want := toolsDir()
		tools, err := openGuestTools(dir)
		Expect(err).NotTo(HaveOccurred())
		defer tools.Close()
		for _, name := range guestToolNames {
			swap := filepath.Join(dir, name+".new")
			Expect(os.WriteFile(swap, []byte("swapped "+name), 0o755)).To(Succeed())
			Expect(os.Rename(swap, filepath.Join(dir, name))).To(Succeed())
		}
		g := volumeGuest()
		g.tools = tools
		_, byName := archive(g)
		for _, name := range guestToolNames {
			Expect(string(byName["rvm/tools/"+name].data)).To(Equal(want[name]), name)
		}
		// A second archive from the same tools has the same bytes.
		_, again := archive(g)
		Expect(string(again["rvm/tools/ext4grow"].data)).To(Equal(want["ext4grow"]))
	})

	DescribeTable("needs the tools for any volume that is not a share",
		func(volumes, shares int, want bool) { Expect(needsGuestTools(volumes, shares)).To(Equal(want)) },
		Entry("no volume", 0, 0, false),
		Entry("one volume", 1, 0, true),
		Entry("four volumes", 4, 0, true),
		Entry("one share", 1, 1, false),
		Entry("a share and an image", 2, 1, true),
	)

	Describe("openGuestTools", func() {
		hint := "the cell needs the guest e2fsprogs artifact"

		DescribeTable("refuses a tool that is missing, naming it and what the cell needs",
			func(missing string) {
				dir, _ := toolsDir()
				Expect(os.Remove(filepath.Join(dir, missing))).To(Succeed())
				before := openFDCount()
				tools, err := openGuestTools(dir)
				Expect(tools).To(BeNil())
				Expect(err).To(MatchError(ContainSubstring("guest tool " + missing + " is missing")))
				Expect(err).To(MatchError(ContainSubstring(hint)))
				Expect(err).To(MatchError(ContainSubstring(filepath.Join(dir, missing))))
				Expect(openFDCount()).To(Equal(before), "a refusal closes the tools it had opened")
			},
			Entry("mke2fs", "mke2fs"),
			Entry("e2fsck", "e2fsck"),
			Entry("tune2fs", "tune2fs"),
			Entry("ext4grow", "ext4grow"),
		)

		It("refuses a directory with none of them", func() {
			_, err := openGuestTools(GinkgoT().TempDir())
			Expect(err).To(MatchError(ContainSubstring("guest tool mke2fs is missing")))
			Expect(err).To(MatchError(ContainSubstring(hint)))
		})

		It("refuses an artifacts directory that does not exist", func() {
			_, err := openGuestTools(filepath.Join(GinkgoT().TempDir(), "nope"))
			Expect(err).To(MatchError(ContainSubstring("the artifacts directory")))
			Expect(err).To(MatchError(ContainSubstring(hint)))
		})

		DescribeTable("refuses a tool that is not a regular executable file",
			func(name string, prepare func(path string), reason string) {
				dir, _ := toolsDir()
				path := filepath.Join(dir, name)
				Expect(os.Remove(path)).To(Succeed())
				prepare(path)
				before := openFDCount()
				tools, err := openGuestTools(dir)
				Expect(tools).To(BeNil())
				Expect(err).To(MatchError(ContainSubstring("guest tool " + name + " at " + path + " " + reason)))
				Expect(err).To(MatchError(ContainSubstring(hint)))
				Expect(openFDCount()).To(Equal(before))
			},
			Entry("a directory", "e2fsck", func(p string) { Expect(os.Mkdir(p, 0o755)).To(Succeed()) }, "is not a regular file"),
			Entry("a FIFO, which must not hang the launch", "tune2fs", func(p string) { Expect(unix.Mkfifo(p, 0o755)).To(Succeed()) }, "is not a regular file"),
			Entry("a file without an execute bit", "mke2fs", func(p string) { Expect(os.WriteFile(p, []byte("x"), 0o644)).To(Succeed()) }, "is not executable"),
			Entry("a file that only another class may execute", "ext4grow", func(p string) { Expect(os.WriteFile(p, []byte("x"), 0o640)).To(Succeed()) }, "is not executable"),
			Entry("an empty file", "ext4grow", func(p string) { Expect(os.WriteFile(p, nil, 0o755)).To(Succeed()) }, "is empty"),
		)

		It("accepts a tool that is a symbolic link to a file inside the artifacts directory", func() {
			dir, want := toolsDir()
			Expect(os.Mkdir(filepath.Join(dir, "versions"), 0o755)).To(Succeed())
			Expect(os.Rename(filepath.Join(dir, "mke2fs"), filepath.Join(dir, "versions", "mke2fs-1.47.4"))).To(Succeed())
			Expect(os.Symlink("versions/mke2fs-1.47.4", filepath.Join(dir, "mke2fs"))).To(Succeed())
			// An artifacts directory reached through a link is the same directory.
			via := filepath.Join(GinkgoT().TempDir(), "art")
			Expect(os.Symlink(dir, via)).To(Succeed())

			for _, root := range []string{dir, via} {
				tools, err := openGuestTools(root)
				Expect(err).NotTo(HaveOccurred(), root)
				g := volumeGuest()
				g.tools = tools
				_, byName := archive(g)
				tools.Close()
				Expect(string(byName["rvm/tools/mke2fs"].data)).To(Equal(want["mke2fs"]), root)
			}
		})

		DescribeTable("refuses a symbolic link that leaves the artifacts directory",
			func(target func(dir, outside string) string) {
				dir, _ := toolsDir()
				outside := GinkgoT().TempDir()
				Expect(os.WriteFile(filepath.Join(outside, "mke2fs"), []byte("elsewhere"), 0o755)).To(Succeed())
				Expect(os.Remove(filepath.Join(dir, "tune2fs"))).To(Succeed())
				Expect(os.Symlink(target(dir, outside), filepath.Join(dir, "tune2fs"))).To(Succeed())
				before := openFDCount()
				tools, err := openGuestTools(dir)
				Expect(tools).To(BeNil())
				Expect(err).To(MatchError(ContainSubstring("guest tool tune2fs at " + filepath.Join(dir, "tune2fs") + " resolves to ")))
				Expect(err).To(MatchError(ContainSubstring("not a file inside the artifacts directory")))
				Expect(err).To(MatchError(ContainSubstring(hint)))
				Expect(openFDCount()).To(Equal(before))
			},
			Entry("an absolute path", func(_, outside string) string { return filepath.Join(outside, "mke2fs") }),
			Entry("a relative path up out of the directory", func(dir, outside string) string {
				rel, err := filepath.Rel(dir, filepath.Join(outside, "mke2fs"))
				Expect(err).NotTo(HaveOccurred())
				return rel
			}),
		)

		It("refuses a link that leads out through another link, and a link to the artifacts directory itself", func() {
			dir, _ := toolsDir()
			outside := GinkgoT().TempDir()
			Expect(os.WriteFile(filepath.Join(outside, "real"), []byte("elsewhere"), 0o755)).To(Succeed())
			Expect(os.Symlink(filepath.Join(outside, "real"), filepath.Join(dir, "hop"))).To(Succeed())
			Expect(os.Remove(filepath.Join(dir, "e2fsck"))).To(Succeed())
			Expect(os.Symlink("hop", filepath.Join(dir, "e2fsck"))).To(Succeed())
			_, err := openGuestTools(dir)
			Expect(err).To(MatchError(ContainSubstring("guest tool e2fsck")))
			Expect(err).To(MatchError(ContainSubstring("not a file inside the artifacts directory")))

			Expect(os.Remove(filepath.Join(dir, "e2fsck"))).To(Succeed())
			Expect(os.Symlink(".", filepath.Join(dir, "e2fsck"))).To(Succeed())
			_, err = openGuestTools(dir)
			Expect(err).To(MatchError(ContainSubstring("guest tool e2fsck")))
		})

		It("refuses a dangling symbolic link as missing", func() {
			dir, _ := toolsDir()
			Expect(os.Remove(filepath.Join(dir, "ext4grow"))).To(Succeed())
			Expect(os.Symlink("gone", filepath.Join(dir, "ext4grow"))).To(Succeed())
			_, err := openGuestTools(dir)
			Expect(err).To(MatchError(ContainSubstring("guest tool ext4grow is missing")))
			Expect(err).To(MatchError(ContainSubstring(hint)))
		})

		It("closes its tools once, and tolerates nil", func() {
			dir, _ := toolsDir()
			before := openFDCount()
			tools, err := openGuestTools(dir)
			Expect(err).NotTo(HaveOccurred())
			Expect(openFDCount()).To(Equal(before + len(guestToolNames)))
			tools.Close()
			tools.Close()
			Expect(openFDCount()).To(Equal(before))
			var none *guestTools
			none.Close()
		})
	})
})
