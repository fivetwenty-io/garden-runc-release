//go:build linux

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// The Docker image guest. Garden packs a Docker app's image into an lz4
// squashfs and binds it, with copies of the image's /etc/passwd and
// /etc/group, into a container whose own root file system is an operator
// stack, so the hypervisor never runs on the image (see the vmimage
// package). The containerizer runs the launcher as vcap on the host side and
// hands vm-launch the user that Diego asked for with --image-user, which is
// what puts vm-launch in image mode. The guest then runs the Docker
// lifecycle's launcher on the image as that user. Image mode has no busybox
// guest to fall back to, because the start command would run on the wrong
// root file system.
const (
	imageUserFlag       = "image-user"
	imageDefaultEnvFlag = "image-default-env"
)

// Where Garden binds the Docker image's files into the container. They are
// variables so that specs can point them elsewhere.
var (
	guestImagePath   = "/opt/garden-vm/image/rootfs.squashfs"
	guestImagePasswd = "/opt/garden-vm/image/passwd"
	guestImageGroup  = "/opt/garden-vm/image/group"
)

// maxImageAccountsBytes caps the passwd and group copies, as Garden caps them
// when it takes them from the image.
const maxImageAccountsBytes = 1 << 20

// maxImageID is the highest uid or gid a user string may name, as Docker
// allows.
const maxImageID = 1<<31 - 1

// The default PATH values that Garden gives a process without one, for root
// and for every other user. A spec keeps them equal to Garden's
// processes.DefaultRootPath and processes.DefaultPath.
const (
	imageRootPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	imageUserPath = "/usr/local/bin:/usr/bin:/bin"
)

// imageDefaultNames are the variables whose Garden defaults
// --image-default-env may hand back to vm-launch, which replaces each with
// the value the image's user gets.
var imageDefaultNames = map[string]bool{"HOME": true, "PATH": true, "USER": true}

// parseImageDefaultEnv reads the comma-separated value of
// --image-default-env. Each name must be one of imageDefaultNames, and an
// empty value names none.
func parseImageDefaultEnv(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	var names []string
	seen := map[string]bool{}
	for _, name := range strings.Split(value, ",") {
		if !imageDefaultNames[name] {
			return nil, fmt.Errorf("--%s names %q, and it takes only HOME, PATH, and USER", imageDefaultEnvFlag, name)
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names, nil
}

// imageUser is the user the Docker image guest runs its processes as: the
// user string Diego asked for, and the uid, gid, and home directory that the
// image gives it.
type imageUser struct {
	name     string
	uid, gid uint32
	home     string
}

// passwdEntry and groupEntry are the fields of the image's account files
// that the resolution reads.
type passwdEntry struct {
	name     string
	uid, gid uint32
	home     string
}

type groupEntry struct {
	name string
	gid  uint32
}

// resolveImageUser resolves the user string spec, which is "user" or
// "user:group" with each part a name or a number, against the image's
// passwd and group files, by Docker's rules. A user part that names an entry
// by name or by uid takes the entry's uid, gid, and home. A number that no
// entry has keeps the number, with gid 0 and home "/". A name that no entry
// has fails, apart from root, which is the user Diego asks for when the app
// names none, and which runs as 0 with gid 0 and home "/" in an image without
// a root entry. An empty user part is uid 0. A group part replaces the gid:
// a name must be in the group file, and a number that no entry has is used
// as it is. A number above maxImageID fails, and so does a user string with
// a newline or a NUL.
func resolveImageUser(spec string, passwd, group []byte) (imageUser, error) {
	userPart, groupPart, hasGroup := strings.Cut(spec, ":")
	if strings.ContainsAny(spec, "\n\x00") {
		return imageUser{}, fmt.Errorf("the image user %q holds a newline or a NUL", spec)
	}
	users, err := parsePasswd(passwd)
	if err != nil {
		return imageUser{}, err
	}
	u := imageUser{name: spec, home: "/"}
	uid, numeric, err := parseImageID(userPart, "user")
	if err != nil {
		return imageUser{}, err
	}
	found := false
	for _, e := range users {
		if (userPart == "" && e.uid == 0) || (userPart != "" && e.name == userPart) || (numeric && e.uid == uid) {
			u.uid, u.gid, u.home, found = e.uid, e.gid, e.home, true
			break
		}
	}
	switch {
	case found:
	case userPart == "" || userPart == "root":
		u.uid, u.gid = 0, 0
	case numeric:
		u.uid, u.gid = uid, 0
	default:
		return imageUser{}, fmt.Errorf("the Docker image has no user %q in its /etc/passwd", userPart)
	}
	if u.home == "" {
		u.home = "/"
	}
	if !hasGroup {
		return u, nil
	}
	if groupPart == "" {
		return imageUser{}, fmt.Errorf("the image user %q names an empty group", spec)
	}
	groups, err := parseGroup(group)
	if err != nil {
		return imageUser{}, err
	}
	gid, numeric, err := parseImageID(groupPart, "group")
	if err != nil {
		return imageUser{}, err
	}
	for _, e := range groups {
		if e.name == groupPart || (numeric && e.gid == gid) {
			u.gid = e.gid
			return u, nil
		}
	}
	if !numeric {
		return imageUser{}, fmt.Errorf("the Docker image has no group %q in its /etc/group", groupPart)
	}
	u.gid = gid
	return u, nil
}

// parseImageID reads a user or group part as a number when it is all
// digits. It reports whether it was one, and a number above maxImageID is an
// error.
func parseImageID(part, what string) (uint32, bool, error) {
	if part == "" || strings.Trim(part, "0123456789") != "" {
		return 0, false, nil
	}
	n, err := strconv.ParseUint(part, 10, 32)
	if err != nil || n > maxImageID {
		return 0, false, fmt.Errorf("the image %s %q is a number above %d", what, part, maxImageID)
	}
	return uint32(n), true, nil
}

// parsePasswd reads the entries of a passwd file that have a name and a
// numeric uid and gid, in file order. Comment lines, short lines, and lines
// whose ids are not numbers are skipped, as the C library skips them.
func parsePasswd(data []byte) ([]passwdEntry, error) {
	var entries []passwdEntry
	err := eachAccountLine(data, "/etc/passwd", func(fields []string) {
		if len(fields) < 7 || fields[0] == "" {
			return
		}
		uid, err1 := strconv.ParseUint(fields[2], 10, 32)
		gid, err2 := strconv.ParseUint(fields[3], 10, 32)
		if err1 != nil || err2 != nil || uid > maxImageID || gid > maxImageID {
			return
		}
		entries = append(entries, passwdEntry{name: fields[0], uid: uint32(uid), gid: uint32(gid), home: fields[5]})
	})
	return entries, err
}

// parseGroup reads the entries of a group file that have a name and a
// numeric gid, in file order, skipping the rest as parsePasswd does.
func parseGroup(data []byte) ([]groupEntry, error) {
	var entries []groupEntry
	err := eachAccountLine(data, "/etc/group", func(fields []string) {
		if len(fields) < 3 || fields[0] == "" {
			return
		}
		gid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil || gid > maxImageID {
			return
		}
		entries = append(entries, groupEntry{name: fields[0], gid: uint32(gid)})
	})
	return entries, err
}

// eachAccountLine calls fn with the colon-separated fields of each line of
// an account file that is not blank and not a comment.
func eachAccountLine(data []byte, name string, fn func(fields []string)) error {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), maxImageAccountsBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fn(strings.Split(line, ":"))
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading the Docker image's %s: %w", name, err)
	}
	return nil
}

// readImageAccounts reads Garden's copy of one of the image's account files,
// which must be a regular file of at most maxImageAccountsBytes.
func readImageAccounts(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("opening the Docker image's account file %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("examining the Docker image's account file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("the Docker image's account file %s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxImageAccountsBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading the Docker image's account file %s: %w", path, err)
	}
	if len(data) > maxImageAccountsBytes {
		return nil, fmt.Errorf("the Docker image's account file %s is over %d bytes", path, maxImageAccountsBytes)
	}
	return data, nil
}

// openGuestImage opens the Docker image that Garden bound into the
// container, checks it as a stack image is checked, and resolves the user
// spec against the image's account files. The caller owns the returned file.
func openGuestImage(spec string) (*os.File, imageUser, error) {
	f, why := openSquashfsImage(guestImagePath, "the Docker image")
	if f == nil {
		return nil, imageUser{}, errors.New(why)
	}
	passwd, err := readImageAccounts(guestImagePasswd)
	if err == nil {
		var group []byte
		if group, err = readImageAccounts(guestImageGroup); err == nil {
			var u imageUser
			if u, err = resolveImageUser(spec, passwd, group); err == nil {
				return f, u, nil
			}
		}
	}
	_ = f.Close()
	return nil, imageUser{}, err
}

// withImageDefaults returns a copy of env in which each of names, the
// variables that the process lacked before Garden gave it defaults, holds
// the value the image's user gets in place of Garden's: Garden's root PATH
// for uid 0 and its other PATH for every other uid, the resolved home
// directory, and the user string Diego asked for.
func withImageDefaults(env map[string]string, names []string, u imageUser) map[string]string {
	out := make(map[string]string, len(env)+len(names))
	for k, v := range env {
		out[k] = v
	}
	for _, name := range names {
		switch name {
		case "PATH":
			out[name] = imageUserPath
			if u.uid == 0 {
				out[name] = imageRootPath
			}
		case "HOME":
			out[name] = u.home
		case "USER":
			out[name] = u.name
		}
	}
	return out
}

// imageGuestDenylist is stackGuestDenylist for the Docker image guest, where
// HOME and TMPDIR describe the image, as PATH and USER do, and so are kept.
func imageGuestDenylist(identity bool) map[string]bool {
	return denylistWithout(denylistWithout(stackGuestDenylist(identity), "HOME"), "TMPDIR")
}

// buildImageGuestEnvWithCerts is buildStackGuestEnvWithCerts for the Docker
// image guest, which keeps the variables imageGuestDenylist keeps.
func buildImageGuestEnvWithCerts(env map[string]string, guestMiB int, identity bool, certDir string, logger *log.Logger) (string, error) {
	deny := imageGuestDenylist(identity)
	if identity {
		env = withEnvValue(withEnvValue(env, instanceCertEnv, guestInstanceCertPath), instanceKeyEnv, guestInstanceKeyPath)
	}
	if certDir != "" {
		env = withEnvValue(env, systemCertPathEnv, certDir)
		deny = denylistWithout(deny, systemCertPathEnv)
	}
	return buildGuestEnvDenying(env, guestMiB, logger, deny)
}

// guestImage is what the Docker image guest's stage 2 needs beyond the stack
// guest's: the uid and gid its processes run as.
type guestImage struct {
	uid, gid uint32
}

// drop is the end of the line that runs a process in the Docker image guest.
// busybox setpriv sets no_new_privs, and busybox nsenter enters the app
// root, clears the supplementary groups, sets the gid and then the uid, and
// execs the process's own argv, which starts with the launcher. Both are the
// initramfs's static busybox, named by path, so nothing from the image runs
// as root and the loader variables of the app's environment load nothing.
// The working directory is the app root itself: busybox nsenter opens the
// directory of -w before it enters the root, and without it the process
// would keep a working directory outside the app root. The launcher then
// enters the image's working directory as the image's user.
func (img *guestImage) drop() string {
	return `/bin/busybox setpriv --nnp /bin/busybox nsenter -r` + guestAppRoot + ` -w` + guestAppRoot +
		` -S ` + strconv.FormatUint(uint64(img.uid), 10) + ` -G ` + strconv.FormatUint(uint64(img.gid), 10) + ` -F -- "$@"`
}

// exec is the Docker image guest's guestExec, with which its run section
// runs the app and each sidecar: it sources the process's environment files,
// sets its arguments from its argv file, and execs the drop. Every step execs
// in place, so the pid that the run section recorded stays the launcher's
// and then the app's.
func (img *guestImage) exec(p guestProcess) string {
	line := ""
	for _, env := range p.envPaths {
		line += ". " + env + " && "
	}
	return line + `eval "set -- $(` + guestRootCat + ` ` + p.argvPath + `)" && exec ` + img.drop()
}

// guestImageAppDirFunc defines rvm_app_dir, which makes the path $1 in the
// app root a real directory with mode $2. A symbolic link there, or anything
// else that is not a directory, is removed from the overlay first, so a
// mount or a write below the path never follows a link that the image's
// author put there.
const guestImageAppDirFunc = `rvm_app_dir() {
	if [ -L "$1" ] || { [ -e "$1" ] && [ ! -d "$1" ]; }; then
		rm -f "$1" || return 1
	fi
	[ -d "$1" ] || mkdir -m "$2" "$1"
}
`

// guestImageSetup is stage 1's branch for the Docker image guest, in place
// of guestStackSetup. The drive search leaves the image's device in
// rvm_stack, because the image takes the stack's drive, and the root disk's
// in rvm_root. The writable layer lives at /rvm/disk, on the root disk or a
// tmpfs, as in the stack guest, and one overlay lays it over the image at
// the app root. There is no droplet and no second overlay.
//
// The image is the app author's, so the branch never follows a link in it.
// Before it mounts anything there, it makes proc, sys, dev, tmp,
// tmp/lifecycle, and etc real directories, parents first (see
// guestImageAppDirFunc). It then mounts proc, sysfs, /dev, /dev/shm, and the
// lifecycle as guestStackSetup does, checks that the launcher is
// executable, and replaces the image's hosts, hostname, and resolv.conf
// files with the guest's. It leaves the image's CA bundle alone, as a runC
// container does. Every failure calls rvm_fail, because the image guest has
// no fallback.
const guestImageSetup = guestImageAppDirFunc + `[ -n "${rvm_stack:-}" ] || rvm_fail "/rvm/disks names no Docker image drive, so the guest has no image to run the app on"
[ -n "$rvm_devtmpfs" ] || rvm_fail "mounting devtmpfs at /dev failed"
mkdir -p /rvm/disk /rvm/stack ` + guestAppRoot + ` || rvm_fail "creating the image guest's mount points failed"
if [ -n "$rvm_root" ]; then
` + guestRootFormat + `	mount -t ext4 -o noatime,discard,errors=continue "$rvm_root" /rvm/disk || rvm_fail "mounting the guest root disk $rvm_root failed"
else
	mount -t tmpfs -o mode=0755 tmpfs /rvm/disk || rvm_fail "mounting a tmpfs at /rvm/disk for the app's writes failed"
fi
mkdir /rvm/disk/upper /rvm/disk/work || rvm_fail "creating the overlay directories failed"
mount -t squashfs -o ro "$rvm_stack" /rvm/stack || rvm_fail "mounting the Docker image $rvm_stack failed; the guest kernel needs squashfs with lz4"
mount -t overlay -o lowerdir=/rvm/stack,upperdir=/rvm/disk/upper,workdir=/rvm/disk/work overlay ` + guestAppRoot + ` || rvm_fail "mounting the app root overlay over the Docker image failed; the guest kernel needs overlayfs"
for rvm_d in proc:0555 sys:0555 dev:0755 tmp:1777 tmp/lifecycle:0755 etc:0755; do
	rvm_app_dir "` + guestAppRoot + `/${rvm_d%:*}" "${rvm_d#*:}" || rvm_fail "making /${rvm_d%:*} a directory in the app root failed"
done
mount -t proc -o nosuid,nodev,noexec proc ` + guestAppRoot + `/proc || rvm_fail "mounting /proc in the app root failed"
mount -t sysfs -o ro,nosuid,nodev,noexec sys ` + guestAppRoot + `/sys || rvm_fail "mounting /sys in the app root failed"
mount -o bind /dev ` + guestAppRoot + `/dev || rvm_fail "binding /dev into the app root failed"
mkdir -p ` + guestAppRoot + `/dev/shm || rvm_fail "creating /dev/shm in the app root failed"
mount -t tmpfs -o noexec,nosuid,nodev,mode=1777,size=50% tmpfs ` + guestAppRoot + `/dev/shm || rvm_fail "mounting /dev/shm in the app root failed"
mount -o bind ` + guestLifecycle + ` ` + guestAppRoot + `/tmp/lifecycle || rvm_fail "binding the lifecycle into the app root failed"
mount -o remount,bind,ro ` + guestAppRoot + `/tmp/lifecycle || rvm_fail "making the lifecycle in the app root read-only failed"
[ -x ` + guestAppRoot + guestStackLauncher + ` ] || rvm_fail "the app root has no executable ` + guestStackLauncher + `"
rm -f ` + guestAppRoot + `/etc/hosts && cat ` + guestHosts + ` >` + guestAppRoot + `/etc/hosts || rvm_fail "writing /etc/hosts in the app root failed"
rm -f ` + guestAppRoot + `/etc/hostname && cat ` + guestHostname + ` >` + guestAppRoot + `/etc/hostname || rvm_fail "writing /etc/hostname in the app root failed"
rm -f ` + guestAppRoot + `/etc/resolv.conf && cat /etc/resolv.conf >` + guestAppRoot + `/etc/resolv.conf || rvm_fail "writing /etc/resolv.conf in the app root failed"
hostname -F ` + guestHostname + ` || rvm_fail "setting the guest's hostname failed"
`

// guestImageDiskRead is guestStackDiskRead for the Docker image guest: it
// adds the image's drive, which carries the stack's identity, RVM_STACK_ID,
// and no droplet drive.
const guestImageDiskRead = `rvm_want_stack=${RVM_STACK_ID:-}
rvm_label_stack="Docker image drive"
rvm_ident "$rvm_want_stack" || rvm_fail "the Docker image drive's identity in /rvm/disks is not 1 to ` + virtioBlockIDBytesText + ` letters, digits, and hyphens"
for rvm_d in $rvm_drives; do
	eval "rvm_o=\$rvm_want_$rvm_d rvm_ol=\$rvm_label_$rvm_d"
	[ "$rvm_o" != "$rvm_want_stack" ] || rvm_fail "the $rvm_ol and the Docker image drive have the one identity $rvm_want_stack in /rvm/disks, so the guest cannot tell them apart"
done
rvm_sectors_stack=
rvm_drives="$rvm_drives stack"
`

// guestImageDiskFind is guestStackDiskFind for the Docker image guest.
const guestImageDiskFind = guestStackDiskFunc + guestDiskRead + guestImageDiskRead + guestDiskWait + `rvm_stack=$rvm_dev_stack
`

// guestImageInit is the guest /init of the Docker image guest. It is
// guestStackInit with the image's drive search and setup.
const guestImageInit = guestInitStart + guestFailFunc + guestImageDiskFind + guestImageSetup + guestStage2Exec
