//go:build linux

package main

import (
	"fmt"
	"strings"
)

// stackModeAllowsVolumes reports whether an app with the volumes in selected
// may boot the stack guest, and, when it may not, why, as the reason that
// follows "busybox guest: " in the mode line. The stack guest mounts a
// private disk image as the busybox guest does and binds it into the app
// root (see guestStackVolumeBinds). It does not yet serve a share or mount a
// BOSH disk, so an app with either keeps the busybox guest, and the reason
// names the first such volume in volume order. A volume without a provider,
// which findVolumeProviders never returns, keeps the busybox guest too,
// since the stack guest cannot tell what kind of disk it is.
func stackModeAllowsVolumes(selected []selectedVolume) (bool, string) {
	for _, v := range selected {
		path := quoteForLog(v.Volume.ContainerDir)
		switch {
		case v.Volume.Settings.Mode == volumeShare:
			return false, "the volume at " + path + " is a share, which the stack guest does not mount yet"
		case v.Provider == nil:
			return false, "the volume at " + path + " has no provider, so the stack guest cannot tell what kind of disk it is"
		case privateMode(v.Provider.Capabilities(v.Mount)) == attachBlock:
			return false, "the volume at " + path + " is a BOSH disk, which the stack guest does not mount yet"
		}
	}
	return true, ""
}

// checkStackVolumes refuses a stack guest with a volume that is not a
// private disk image, which is a share or a block volume, as volumesOnDrives
// pairs the volumes with their drives. It holds whatever run decided, so the
// initramfs of a stack guest never asks stage 2 to mount a volume that it
// would not bind into the app root. Volumes that volumesOnDrives refuses are
// an error too.
func checkStackVolumes(g guestContents) error {
	if len(g.vols) == 0 {
		return nil
	}
	pairs, err := volumesOnDrives(g)
	if err != nil {
		return err
	}
	for n, p := range pairs {
		switch {
		case p.drive == nil:
			return fmt.Errorf("a guest with a stack mounts only private disk images, and volume %d at %s is a share", n, quoteForLog(p.vol.ContainerDir))
		case p.drive.kind != driveImage:
			return fmt.Errorf("a guest with a stack mounts only private disk images, and volume %d at %s is on a %s drive", n, quoteForLog(p.vol.ContainerDir), p.drive.kind)
		}
	}
	return nil
}

// guestStackVolumeMke2fsArgs are guestVolumeMke2fsArgs for the stack guest,
// whose app runs as uid guestAppUID. root_owner gives the root directory of
// a blank image's new filesystem to that uid and gid, so that the app can
// create files at the top of its volume, as it can at the top of its home.
// mke2fs leaves an image that already holds a filesystem alone, and
// guestStackVolumeBinds gives the root of one that the busybox guest
// formatted, which belongs to root, to the same uid.
const guestStackVolumeMke2fsArgs = guestVolumeMke2fsArgs + ",root_owner=" + guestAppUID + ":" + guestAppUID

// guestStackVolumeSetup is guestVolumeSetup for the stack guest. It is the
// same text with guestStackVolumeMke2fsArgs in place of
// guestVolumeMke2fsArgs, which guestVolumeSetup holds once, as a spec
// checks, so the two guests check, grow, and mount a volume alike and differ
// only in who owns a new filesystem's root.
var guestStackVolumeSetup = strings.Replace(guestVolumeSetup, guestVolumeMke2fsArgs, guestStackVolumeMke2fsArgs, 1)

// guestStackVolumeWalk defines rvm_vwalk, which sets rvm_vat to the path of
// the volume at rvm_vpath in the app root, one part at a time, and returns
// non-zero, with rvm_vat at that part, when a part is a symbolic link.
// stage 2 resolves the path on the initramfs, so a link that the stack or
// the droplet holds on the way, or one that the app made while it ran,
// would take the path out of the app root. With an argument, rvm_vwalk also
// makes each part that does not exist, as a directory that belongs to
// guestAppUID, as the app's own home does, so that the app can use the
// directories that lead to its volume. A part that it cannot make or give to
// guestAppUID fails the boot with a line that names the volume's path.
const guestStackVolumeWalk = `rvm_vwalk() {
	rvm_vat=` + guestAppRoot + `
	rvm_vrest=${rvm_vpath#/}
	while [ -n "$rvm_vrest" ]; do
		rvm_vat=$rvm_vat/${rvm_vrest%%/*}
		case "$rvm_vrest" in
		*/*) rvm_vrest=${rvm_vrest#*/} ;;
		*) rvm_vrest= ;;
		esac
		[ ! -L "$rvm_vat" ] || return 1
		if [ -n "${1:-}" ] && [ ! -e "$rvm_vat" ]; then
			mkdir "$rvm_vat" || rvm_fail "creating the mount point of the volume at $rvm_vpath in the app root failed"
			chown ` + guestAppUID + `:` + guestAppUID + ` "$rvm_vat" || rvm_fail "giving ${rvm_vat#` + guestAppRoot + `}, which the guest made for the volume at $rvm_vpath, to uid ` + guestAppUID + ` failed"
		fi
	done
}
`

// guestStackVolumeBinds follows guestStackVolumeSetup in the stack guest's
// stage 2, once every volume is mounted at its path on the initramfs, where
// only stage 2 sees it. It binds each volume, in volume order, to the same
// path in the app root, where the app sees it, with nosuid and nodev, as
// stage 1 mounts /dev/shm there, so that a file on the volume never gives
// the app root's privileges or a device. vm-launch refuses a volume path
// under another (see checkNotNested), so the binds never depend on their
// order. rvm_vwalk (see guestStackVolumeWalk) makes the mount point, and a
// path that crosses a symbolic link in the app root fails the boot with a
// line that names both. A bind that fails ends the boot with a line that
// names the path too.
//
// Before the bind, a volume whose top directory belongs to root:root, as
// one that the busybox guest formatted does, gets that directory alone given
// to guestAppUID, never what it holds, so that the app can create files at
// the top of its volume as it can on a volume that the stack guest
// formatted. Any other owner stays as it is. The step never fails the boot,
// and a stat or a chown that fails prints a line that names the path and
// leaves the volume as it was, because the app may still use the volume's
// subdirectories, and the status the app exits with is its own.
const guestStackVolumeBinds = guestStackVolumeWalk + `rvm_vi=0
while [ "$rvm_vi" -lt "$RVM_VOLUMES" ]; do
	eval "rvm_vpath=\${RVM_VOL${rvm_vi}_PATH:-}"
	if ! rvm_vown=$(stat -c %u:%g "$rvm_vpath" 2>&1); then
		echo "vm-launch guest setup: reading the owner of the volume at $rvm_vpath failed (${rvm_vown:-it gave no reason}); leaving its owner as it is"
	elif [ "$rvm_vown" = 0:0 ]; then
		rvm_verr=$(chown ` + guestAppUID + `:` + guestAppUID + ` "$rvm_vpath" 2>&1) || echo "vm-launch guest setup: giving the top directory of the volume at $rvm_vpath to uid ` + guestAppUID + ` failed (${rvm_verr:-it gave no reason}); the app may not create files there"
	fi
	rvm_vwalk make || rvm_fail "the volume path $rvm_vpath crosses the symbolic link ${rvm_vat#` + guestAppRoot + `} in the app root, so the guest will not bind the volume there"
	mount -o bind "$rvm_vpath" "$rvm_vat" || rvm_fail "binding the volume at $rvm_vpath into the app root failed"
	mount -o remount,bind,nosuid,nodev,noatime "$rvm_vat" || rvm_fail "making the bind of the volume at $rvm_vpath in the app root nosuid and nodev failed"
	rvm_vi=$((rvm_vi + 1))
done
`

// guestStackVolumeUnbinds unmounts each volume's bind in the app root, last
// first, the reverse of the order guestStackVolumeBinds made them in. The app
// could write to the app root while it ran, so before each unmount it walks
// the path again with rvm_vwalk and checks that the directory there is the
// volume's own top directory, by device and inode, which only the bind can
// show in the app root. A path that now crosses a symbolic link, such as one
// the app made after it moved a directory on the way, and a directory that is
// no longer the volume's are never unmounted, since that would unmount
// whatever else is there, and they count as a bind that does not unmount. A
// bind that stays mounted would keep the volume's filesystem mounted after
// the volume's own unmount, so it is never cleanly unmounted. A bind that
// does not unmount therefore prints a line that names the volume's path,
// with the reason, and counts as a volume that did not unmount, which turns
// a status of 0 into guestFlushFailStatus. It runs once the processes the
// command left are stopped, because a process that still has a file open or
// its working directory on a volume, such as a sidecar or a child of the app,
// keeps the bind busy, and with no process left, nothing can change the app
// root between the check and the unmount.
const guestStackVolumeUnbinds = `rvm_vi=$RVM_VOLUMES
while [ "$rvm_vi" -gt 0 ]; do
	rvm_vi=$((rvm_vi - 1))
	eval "rvm_vpath=\$RVM_VOL${rvm_vi}_PATH"
	if ! rvm_vwalk; then
		echo "vm-launch guest: the path of the volume at $rvm_vpath in the app root now crosses the symbolic link ${rvm_vat#` + guestAppRoot + `}, so the guest cannot unbind the volume or unmount it cleanly"
		rvm_vbad=1
	elif ! rvm_vid=$(stat -c %d:%i "$rvm_vpath" 2>&1); then
		echo "vm-launch guest: reading the top directory of the volume at $rvm_vpath failed (${rvm_vid:-it gave no reason}), so the guest cannot unbind the volume or unmount it cleanly"
		rvm_vbad=1
	elif ! rvm_vatid=$(stat -c %d:%i "$rvm_vat" 2>&1); then
		echo "vm-launch guest: reading what the app root holds at the path of the volume at $rvm_vpath failed (${rvm_vatid:-it gave no reason}), so the guest cannot unbind the volume or unmount it cleanly"
		rvm_vbad=1
	elif [ "$rvm_vid" != "$rvm_vatid" ]; then
		echo "vm-launch guest: the volume at $rvm_vpath is no longer what the app root holds at its path, so the guest cannot unbind the volume or unmount it cleanly"
		rvm_vbad=1
	elif ! rvm_verr=$(umount "$rvm_vat" 2>&1); then
		echo "vm-launch guest: unbinding the volume at $rvm_vpath from the app root failed (${rvm_verr:-it gave no reason}), so the guest cannot unmount the volume cleanly"
		rvm_vbad=1
	fi
done
`

// guestStackVolumeTeardown is guestVolumeTeardown for the stack guest. Once
// the processes the command left are stopped, and before any volume's last
// flush and unmount, it unbinds the volumes (see guestStackVolumeUnbinds).
// The teardown goes on to flush and unmount every volume whether or not
// each unbind succeeded.
const guestStackVolumeTeardown = guestVolumeTeardownStop + guestStackVolumeUnbinds + guestVolumeTeardownUnmount

// guestStackRunVolumeTeardown is guestStackVolumeTeardown after a run section
// (see guestRunSection). It sends SIGKILL to the processes that are left
// without the SIGTERM and its wait of up to guestTeardownTermWait, because
// the section's wind-down has already given the app and its sidecars their
// grace, as a container's processes get theirs before Garden ends the rest.
// Its only wait is guestTeardownKillWait, which the section's
// guestVolumeWindDown leaves room for before the host's stop deadline.
const guestStackRunVolumeTeardown = guestVolumeTeardownFlush + guestVolumeTeardownKill + guestStackVolumeUnbinds + guestVolumeTeardownUnmount
