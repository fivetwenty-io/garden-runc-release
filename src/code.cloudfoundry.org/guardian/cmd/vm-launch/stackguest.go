//go:build linux

package main

// stackModeAllowsVolumes reports whether an app with a volume may boot the
// stack guest. Until stage 2 binds each volume into the app root and unbinds
// it before the volume teardown, a volume app keeps the busybox guest.
const stackModeAllowsVolumes = false

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
// app's working directory and drop to the app's user (see
// guestStackRunCommand), and the launcher's path there, which is where Diego
// puts it in a container. Stage 1 checks that all three are executable before
// it hands over, so a stack without them fails the boot with a named step
// instead of a command that cannot start.
const (
	guestStackEnv      = "/usr/bin/env"
	guestStackSetpriv  = "/usr/bin/setpriv"
	guestStackLauncher = "/tmp/lifecycle/launcher"
)

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
// boot ends before stage 2 and vm-launch shows the console.
const guestStackSetup = `[ -n "${rvm_stack:-}" ] || rvm_fail "/rvm/disks names no stack drive, so the guest has no stack to run the app on"
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
mount -t squashfs -o ro "$rvm_stack" /rvm/stack || rvm_fail "mounting the stack image $rvm_stack failed; the guest kernel needs squashfs with lz4"
mount -t squashfs -o ro "$rvm_droplet" /rvm/droplet || rvm_fail "mounting the droplet image $rvm_droplet failed; the guest kernel needs squashfs with lz4"
[ -d /rvm/stack/home/vcap ] || rvm_fail "the stack image has no /home/vcap directory to lay the droplet over"
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

// initScript is the stack guest's stage 2. A guest with sidecars or an
// instance identity runs the app and its sidecars through the run section
// (see guestRunSection), and checks each sidecar's files before the start
// tag, as well as, with an identity, whether the console still echoes. The
// boot pair and the run section's FIFO are set up before the start tag too
// (see guestRunSetup), and so are the trusted certificate files, with or
// without the rest (see guestSystemCertsSetup). Any other stack guest runs
// stackInitScript.
func (s *guestStack) initScript(nonce string) string {
	certs := guestSystemCertsSetup(s.systemCerts)
	if len(s.sidecars) == 0 && s.identity == nil {
		return stage2Script(nonce, false, true, certs, "")
	}
	procs := s.processes()
	checks := guestSidecarChecks(len(s.sidecars))
	if s.identity != nil {
		checks += guestIdentityEchoCheck(nonce)
	}
	checks += certs + guestRunSetup(s.identity != nil)
	return stage2Script(nonce, false, true, checks, guestRunSection(nonce, procs, s.identity != nil, stackExec))
}

// processes returns the app, from /rvm/argv and the guest environment, and
// then each sidecar, from its own argv and its environment over the guest's.
// Every process starts in the app's working directory. The app records its
// pid in guestAppPid, as it does without sidecars.
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

// stackExec is the stack guest's guestExec. It runs a process as
// guestStackRunCommand runs the app: it sources the process's environment
// files, sets its arguments from its argv file with eval, moves the loader
// variables into the arguments (see guestLoaderHold), and execs busybox
// chroot into the app root, where the stack's setpriv drops to uid 2000
// before the stack's env enters the working directory, puts the loader
// variables back, and execs the argv (see guestStackDrop).
// The working directory is quoted into the line, and the run section has
// already recorded the pid and set the open-files limit, so nothing after
// the first source reads a shell variable that the environment files can
// set.
func stackExec(p guestProcess) string {
	line := ""
	for _, env := range p.envPaths {
		line += ". " + env + " && "
	}
	return line + `eval "set -- $(cat ` + p.argvPath + `)" && ` + guestLoaderHold + `exec chroot ` + guestAppRoot + ` ` + guestStackDrop(shellQuote(p.dir))
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
