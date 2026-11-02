//go:build linux

package main

import (
	"strconv"
	"strings"
	"time"
)

// Paths of the stack guest. The app root is where stage 1 assembles the
// stack, the droplet, and their writable layers, and where stage 2 runs the
// app through chroot. The initramfs holds the launcher below guestLifecycle,
// and the container's hosts file and hostname at guestHosts and
// guestHostname.
const (
	guestAppRoot   = "/rvm/app"
	guestLifecycle = "/rvm/lifecycle"
	guestHosts     = "/rvm/hosts"
	guestHostname  = "/rvm/hostname"
)

// The stack's own tools, which stage 2 runs inside the app root to enter the
// app's working directory and drop to the app's user (see stackExec), and
// the launcher's path there, which is where Diego
// puts it in a container. Stage 1 checks that all three are executable before
// it hands over, so a stack without them fails the boot with a named step
// instead of a command that cannot start.
const (
	guestStackEnv      = "/usr/bin/env"
	guestStackSetpriv  = "/usr/bin/setpriv"
	guestStackLauncher = "/tmp/lifecycle/launcher"
)

// The busybox guest that stage 1 falls back to when it cannot mount the stack
// or the droplet image (see guestFallbackFunc). A guest that can fall back
// holds the busybox guest's stage 2, its environment, and the commands that
// install its trusted certificates, below guestFallbackDir. A guest without
// them fails the boot with the mount's own message, as it always has.
const (
	guestFallbackDir  = "/rvm/fallback"
	guestFallbackInit = guestFallbackDir + "/init"
	guestFallbackEnv  = guestFallbackDir + "/env"
	guestFallbackPrep = guestFallbackDir + "/prep"
)

// guestFallbackFunc defines rvm_fallback, which stage 1 calls with the
// reason when the stack or the droplet image cannot be used, and then with
// its own arguments, which are the volumes' devices. Without the fallback
// files it is rvm_fail. With them, it prints the reason as
// "busybox guest: <reason>" on the console, which is the mode line of a
// launch that settled on the busybox guest, unmounts what stage 1 mounted of
// the images, and replaces the guest's stage 2 and environment with the
// busybox guest's, and installs the container's hosts file and hostname as the
// busybox guest's /etc/hosts and /etc/hostname, which its stage 2 sets the
// hostname from. A guest with a root disk then enters the overlay root on
// the formatted disk as guestRootSetup does, and a guest without one runs
// stage 2 on the initramfs. Either way the busybox guest's stage 2 gets the
// volumes' devices, as it does from guestRootInit, and mounts the volumes
// itself. Both end in exec, so the function never returns.
const guestFallbackFunc = `rvm_fallback() {
	rvm_why=$1
	shift
	[ -r ` + guestFallbackInit + ` ] || rvm_fail "$rvm_why"
	echo "busybox guest: $rvm_why" >/dev/console 2>/dev/null || echo "busybox guest: $rvm_why"
	umount /rvm/droplet /rvm/stack 2>/dev/null
	cp ` + guestFallbackInit + ` ` + guestStage2 + ` && cp ` + guestFallbackEnv + ` /rvm/env && . ` + guestFallbackPrep + ` || rvm_fail "installing the busybox guest's files failed"
	cat ` + guestHosts + ` >/etc/hosts && cat ` + guestHostname + ` >/etc/hostname || rvm_fail "installing the container's /etc/hosts and /etc/hostname in the busybox guest failed"
	if [ -n "$rvm_root" ]; then
		mkdir -p /rvm/root && mount -t overlay -o lowerdir=/,upperdir=/rvm/disk/upper,workdir=/rvm/disk/work overlay /rvm/root || rvm_fail "mounting the overlay root of the busybox guest failed"
		[ -x /rvm/root/bin/sh ] && [ -r /rvm/root` + guestStage2 + ` ] || rvm_fail "the overlay root of the busybox guest has no /bin/sh or ` + guestStage2 + `"
		for rvm_m in proc sys dev; do
			mount -o move "/$rvm_m" "/rvm/root/$rvm_m" || rvm_fail "moving /$rvm_m into the overlay root of the busybox guest failed"
		done
		cd /rvm/root && mount -o move . / || rvm_fail "moving the overlay root of the busybox guest onto / failed"
		exec chroot . /bin/sh ` + guestStage2 + ` "$@"
	fi
	exec /bin/sh ` + guestStage2 + ` "$@"
}
`

// guestAppUID is the uid and gid of the vcap user, who owns the droplet in a
// container and runs the app.
const guestAppUID = "2000"

// guestRootFormat checks that the guest root disk rvm_root is blank and
// formats it, as stage 1 does for the rvm.6 guest (see guestRootSetup, which
// holds the same lines, as a spec checks). It is indented for the body of an
// if.
const guestRootFormat = `	dd if="$rvm_root" of=` + guestRootHead + ` bs=4096 count=16 || rvm_fail "reading the start of the guest root disk $rvm_root failed"
	tr -d '\000' <` + guestRootHead + ` >` + guestRootUsed + ` || rvm_fail "checking whether the guest root disk $rvm_root is blank failed"
	rvm_blank=
	[ -s ` + guestRootHead + ` ] && [ ! -s ` + guestRootUsed + ` ] && rvm_blank=1
	rm -f ` + guestRootHead + ` ` + guestRootUsed + `
	[ -n "$rvm_blank" ] || rvm_fail "the guest root disk $rvm_root is not blank, so vm-launch will not format it"
	mke2fs -F -b 4096 -m 0 -I 256 -i "$RVM_ROOT_INODE_RATIO" -L rvm-root "$rvm_root" || rvm_fail "formatting the guest root disk $rvm_root failed"
`

// guestStackSetup is stage 1's branch for a guest that runs the app on its
// own stack. The drive search leaves the stack's device in rvm_stack, the
// droplet's in rvm_droplet, and the root disk's in rvm_root, or nothing in
// rvm_root for a guest without a disk quota. The branch assembles the app
// root at guestAppRoot and then returns, so that stage 1 runs stage 2 on the
// initramfs root, where stage 2 stays PID 1 for the life of the guest.
//
// The writable layers live at /rvm/disk, which is the root disk, formatted
// and mounted as the rvm.6 guest's is, or a tmpfs for a guest without a root
// disk, which keeps the app's writes in RAM as the rvm.6 guest does. The
// stack and the droplet mount read-only as squashfs. Overlay A lays an upper
// layer on /rvm/disk over the stack at the app root, and overlay B lays a
// second over the droplet and the stack's own /home/vcap at the app's home,
// which is what a download into /home/vcap gives a container. The upper
// directory of overlay B belongs to uid 2000, so that the app can create
// files at the top of its home. Both kernels leave overlayfs redirect_dir
// off, so renaming a directory that came from the stack or the droplet fails
// with EXDEV, and tools such as mv fall back to a copy.
//
// The app root then gets a new proc and a read-only sysfs, with the options
// runC gives a container's, the guest's /dev, a /dev/shm of its own with the
// options and size of stage 2's (see guestShmSetup), and the launcher's
// directory from the initramfs, read-only at /tmp/lifecycle. A bind into an
// initramfs mount point is private, so a mount that stage 2 makes at /dev/shm
// later would never reach the app root, which is why the app root mounts its
// own. A read-only bind takes a remount, because the kernel ignores ro on the
// bind itself. Last, stage 1 replaces the stack's hosts, hostname, and
// resolv.conf files, and its CA bundle when the guest has one, with the
// guest's, removing each file first so that a symbolic link in the stack is
// replaced and never written through, and it sets the guest's hostname.
//
// Every step that fails calls rvm_fail with a line that names it, so the
// boot ends before stage 2 and vm-launch shows the console. The three steps
// that find the stack or the droplet unusable call rvm_fallback instead,
// which is rvm_fail in a guest that cannot fall back, and pass it the
// volumes' devices that stage 1 holds as its arguments. The volumes are
// stage 2's to mount in either guest, so the branch never touches them.
const guestStackSetup = guestFallbackFunc + `[ -n "${rvm_stack:-}" ] || rvm_fail "/rvm/disks names no stack drive, so the guest has no stack to run the app on"
[ -n "${rvm_droplet:-}" ] || rvm_fail "/rvm/disks names no droplet drive, so the guest has no droplet to run"
[ -n "$rvm_devtmpfs" ] || rvm_fail "mounting devtmpfs at /dev failed"
mkdir -p /rvm/disk /rvm/stack /rvm/droplet ` + guestAppRoot + ` || rvm_fail "creating the stack guest's mount points failed"
if [ -n "$rvm_root" ]; then
` + guestRootFormat + `	mount -t ext4 -o noatime,discard,errors=continue "$rvm_root" /rvm/disk || rvm_fail "mounting the guest root disk $rvm_root failed"
else
	mount -t tmpfs -o mode=0755 tmpfs /rvm/disk || rvm_fail "mounting a tmpfs at /rvm/disk for the app's writes failed"
fi
mkdir /rvm/disk/upper /rvm/disk/work /rvm/disk/home-upper /rvm/disk/home-work || rvm_fail "creating the overlay directories failed"
chown ` + guestAppUID + `:` + guestAppUID + ` /rvm/disk/home-upper || rvm_fail "giving the upper directory of /home/vcap to uid ` + guestAppUID + ` failed"
mount -t squashfs -o ro "$rvm_stack" /rvm/stack || rvm_fallback "mounting the stack image $rvm_stack failed; the guest kernel needs squashfs with lz4" "$@"
mount -t squashfs -o ro "$rvm_droplet" /rvm/droplet || rvm_fallback "mounting the droplet image $rvm_droplet failed; the guest kernel needs squashfs with lz4" "$@"
[ -d /rvm/stack/home/vcap ] || rvm_fallback "the stack image has no /home/vcap directory to lay the droplet over" "$@"
mount -t overlay -o lowerdir=/rvm/stack,upperdir=/rvm/disk/upper,workdir=/rvm/disk/work overlay ` + guestAppRoot + ` || rvm_fail "mounting the app root overlay over the stack failed; the guest kernel needs overlayfs"
mount -t overlay -o lowerdir=/rvm/droplet:/rvm/stack/home/vcap,upperdir=/rvm/disk/home-upper,workdir=/rvm/disk/home-work overlay ` + guestAppRoot + `/home/vcap || rvm_fail "mounting the droplet overlay at /home/vcap in the app root failed"
mkdir -p ` + guestAppRoot + `/proc ` + guestAppRoot + `/sys ` + guestAppRoot + `/dev ` + guestAppRoot + `/tmp/lifecycle || rvm_fail "creating the mount points in the app root failed"
mount -t proc -o nosuid,nodev,noexec proc ` + guestAppRoot + `/proc || rvm_fail "mounting /proc in the app root failed"
mount -t sysfs -o ro,nosuid,nodev,noexec sys ` + guestAppRoot + `/sys || rvm_fail "mounting /sys in the app root failed"
mount -o bind /dev ` + guestAppRoot + `/dev || rvm_fail "binding /dev into the app root failed"
mkdir -p ` + guestAppRoot + `/dev/shm || rvm_fail "creating /dev/shm in the app root failed"
mount -t tmpfs -o noexec,nosuid,nodev,mode=1777,size=50% tmpfs ` + guestAppRoot + `/dev/shm || rvm_fail "mounting /dev/shm in the app root failed"
mount -o bind ` + guestLifecycle + ` ` + guestAppRoot + `/tmp/lifecycle || rvm_fail "binding the lifecycle into the app root failed"
mount -o remount,bind,ro ` + guestAppRoot + `/tmp/lifecycle || rvm_fail "making the lifecycle in the app root read-only failed"
[ -x ` + guestAppRoot + guestStackLauncher + ` ] || rvm_fail "the app root has no executable ` + guestStackLauncher + `"
[ -x ` + guestAppRoot + guestStackEnv + ` ] || rvm_fail "the stack has no executable ` + guestStackEnv + ` to start the app in its working directory"
[ -x ` + guestAppRoot + guestStackSetpriv + ` ] || rvm_fail "the stack has no executable ` + guestStackSetpriv + ` to run the app as uid ` + guestAppUID + `"
rm -f ` + guestAppRoot + `/etc/hosts && cat ` + guestHosts + ` >` + guestAppRoot + `/etc/hosts || rvm_fail "writing /etc/hosts in the app root failed"
rm -f ` + guestAppRoot + `/etc/hostname && cat ` + guestHostname + ` >` + guestAppRoot + `/etc/hostname || rvm_fail "writing /etc/hostname in the app root failed"
rm -f ` + guestAppRoot + `/etc/resolv.conf && cat /etc/resolv.conf >` + guestAppRoot + `/etc/resolv.conf || rvm_fail "writing /etc/resolv.conf in the app root failed"
if [ -e ` + guestCABundlePath + ` ]; then
	mkdir -p ` + guestAppRoot + `/etc/ssl/certs && rm -f ` + guestAppRoot + guestCABundlePath + ` && cat ` + guestCABundlePath + ` >` + guestAppRoot + guestCABundlePath + ` || rvm_fail "writing the CA bundle ` + guestCABundlePath + ` in the app root failed"
fi
hostname -F ` + guestHostname + ` || rvm_fail "setting the guest's hostname failed"
`

// hasAppRoot reports whether the guest that the launch chose has an app root
// at guestAppRoot, which is where sidecars and the instance identity live. A
// nil stack is the busybox guest, which has none.
func (s *guestStack) hasAppRoot() bool { return s != nil }

// initScript is the stack guest's stage 2. Every stack guest runs the app
// and its sidecars, if it has any, through the run section (see
// guestRunSection), and checks each sidecar's files before the start tag, as
// well as, with an identity, whether the console still echoes. The boot
// pair, the run section's FIFO, and the log FIFOs of every process are set
// up before the start tag too (see guestRunSetup), and so are the trusted
// certificate files, with or without the rest (see guestSystemCertsSetup),
// and the mirrored mounts (see mountMirror.guestSetup). A guest that watches
// mirrored files checks its console's echo as a guest with an identity
// does.
// The guest frames the output of every process (see guestProcessWrapper), so
// no process holds the console, even an app that runs alone: none can read
// the stop request or a pushed pair, and none can write a line that
// vm-launch would take for the guest's own. Only the busybox guest, whose
// command runs as root, shares the console with stage 2.
func (s *guestStack) initScript(nonce string) string {
	return s.initScriptWithVolumes(nonce, false)
}

// initScriptWithVolumes is initScript for a guest that mounts volumes when
// volume is set. Stage 2 then mounts them as the busybox guest's does and
// binds each into the app root, and its teardown unbinds them before it
// unmounts them (see guestStackVolumeBinds and guestStackVolumeTeardown). A
// guest that runs a run section with volumes winds down within
// guestVolumeWindDown, so that the volume teardown after the section fits
// before the host's stop deadline.
// The Docker image guest runs its processes with its own exec (see
// guestImage.exec).
func (s *guestStack) initScriptWithVolumes(nonce string, volume bool) string {
	exec := guestExec(stackExec)
	if s.image != nil {
		exec = s.image.exec
	}
	certs := guestSystemCertsSetup(s.systemCerts)
	procs := s.processes()
	checks := guestSidecarChecks(len(s.sidecars))
	if s.identity != nil || s.mirror.watching() {
		checks += guestIdentityEchoCheck(nonce)
	}
	checks += certs + s.mirror.guestSetup(nonce) + guestRunSetup(s.identity != nil, procs)
	timeout := guestTimeoutSeconds
	if volume {
		timeout = guestVolumeTimeoutSeconds
	}
	if s.windDown > 0 {
		wait := s.windDown
		if volume {
			wait -= guestWindDown - guestVolumeWindDown
		}
		timeout = strconv.Itoa(int(wait / time.Second))
	}
	return stage2Script(nonce, volume, true, checks, guestRunSectionMirroring(nonce, procs, s.identity != nil, s.mirror, exec, timeout))
}

// processes returns the app, from /rvm/argv and the guest environment, and
// then each sidecar, from its own argv and its environment over the guest's.
// Every process starts in the app's working directory. The app records its
// pid in guestAppPid, as the busybox guest's command does.
func (s *guestStack) processes() []guestProcess {
	procs := []guestProcess{{index: 0, argvPath: guestArgv, envPaths: []string{"/rvm/env"}, dir: s.cwd, pidPath: guestAppPid}}
	for i := range s.sidecars {
		n := i + 1
		procs = append(procs, guestProcess{
			index:    n,
			argvPath: guestSidecarFile(n, "argv"),
			envPaths: []string{"/rvm/env", guestSidecarFile(n, "env")},
			dir:      s.cwd,
			pidPath:  guestSidecarFile(n, "pid"),
		})
	}
	return procs
}

// stackExec is the stack guest's guestExec, with which it runs the app and
// each sidecar: it sources the process's environment files, sets its
// arguments from its argv file with eval, which the quoting makes exact for
// any bytes, newlines and quotes included, moves the loader variables into
// the arguments (see guestLoaderHold), and execs busybox chroot into the app
// root. There the stack's setpriv sets the real, effective, and saved uid
// and gid to 2000, takes vcap's supplementary groups from the stack's
// /etc/group, and sets no_new_privs, as Garden does for a container's
// processes, and the stack's env, as uid 2000, enters the working
// directory, puts the loader variables back, and execs the argv (see
// guestStackDrop). The working directory is entered only after the drop, so
// a link in the droplet cannot make root resolve it. Every one of those
// programs execs in place, so the pid that the run section recorded is the
// launcher's, then bash's, and then the start command's own, as it is under
// runC, and the control reader's SIGTERM reaches the process.
//
// The working directory is quoted into the line, and the run section has
// already recorded the pid and set the open-files limit, so nothing after
// the first source reads a shell variable that the environment files can
// set, because they may set any name. A PATH from them does not choose
// chroot or cat, which are named by the busybox binary's path (see
// guestRootCat), and the stack's programs are named by their paths.
func stackExec(p guestProcess) string {
	line := ""
	for _, env := range p.envPaths {
		line += ". " + env + " && "
	}
	return line + `eval "set -- $(` + guestRootCat + ` ` + p.argvPath + `)" && ` + guestLoaderHold + `exec ` + guestRootChroot + ` ` + guestAppRoot + ` ` + guestStackDrop(shellQuote(p.dir))
}

// guestSidecarChecks makes a broken sidecar argv or environment file a
// failed setup step, as guestStackChecks does for /rvm/argv and
// guestEnvChecks for /rvm/env. Both checks run in subshells, so stage 2 never
// takes a sidecar's arguments or environment.
func guestSidecarChecks(sidecars int) string {
	checks := ""
	for n := 1; n <= sidecars; n++ {
		name := guestProcessName(n)
		argv, env := guestSidecarFile(n, "argv"), guestSidecarFile(n, "env")
		checks += `( eval "set -- $(cat ` + argv + `)" && [ "$#" -gt 0 ] ) || rvm_fail "reading the arguments of ` + name + ` from ` + argv + ` failed"
( . ` + env + ` ) || rvm_fail "reading the environment of ` + name + ` from ` + env + ` failed"
`
	}
	return checks
}

// fallbackSteps adds, for a guest that can fall back to the busybox guest,
// the busybox guest's stage 2 for nonce, which mounts the volumes when volume
// is set, with the IPv6 setup when nw has an address, its environment with
// mode 0600, and the commands that remove the mirrored mounts and install its
// trusted certificates, below
// guestFallbackDir.
func (s *guestStack) fallbackSteps(cw *cpioWriter, file func(name string, perm uint32, content string) func() error, nonce string, volume bool, nw *network) []func() error {
	if !s.fallback {
		return nil
	}
	return []func() error{
		func() error { return cw.Dir(strings.TrimPrefix(guestFallbackDir, "/"), 0o755) },
		file(strings.TrimPrefix(guestFallbackInit, "/"), 0o755, withGuestIPv6(initScript(nonce, volume), nw)),
		file(strings.TrimPrefix(guestFallbackEnv, "/"), 0o600, s.fallbackEnv),
		// The mirror's commands come first, because rvm_fallback checks the
		// status of the last of the certificates' commands.
		file(strings.TrimPrefix(guestFallbackPrep, "/"), 0o644, s.mirror.fallbackPrep(nonce)+s.systemCerts.fallbackPrep()),
	}
}
