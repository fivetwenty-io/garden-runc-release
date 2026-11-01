//go:build linux

// Command vm-launch runs one shell command inside a short-lived QEMU microvm
// or Firecracker guest and makes the command's console output and exit status
// its own. Garden runs it inside the app's container in place of the CF
// launcher, with /dev/kvm and the read-only VM artifacts mounted in.
//
// Usage:
//
//	vm-launch --backend vm-qemu|vm-firecracker [--transparent-proxy] [--allow-volume-shares] [--virtiofsd-path PATH] [--volume-sync-mounts=false] [--artifacts DIR] -- PATH [ARGS...]
//
// When PATH is the CF launcher ("launcher APP-DIR START-COMMAND ..."), the
// guest runs START-COMMAND. Otherwise it runs PATH and ARGS, shell-quoted.
// The guest's busybox sh runs the command with sh -c, as the launcher runs
// it with bash -c, so the command may have at most 131071 bytes.
// The guest has a busybox userland and none of the app's files. Its root
// is the initramfs, which lives in guest RAM, with a disk image laid over it
// when the app has a disk quota (see Guest root disk below), and it gets a
// volume's disk when the app has a volume (see Volumes below).
//
// Every guest gets a NIC, a default route, and DNS, and its traffic leaves
// from the container's network namespace with the container's address, so
// network policies and application security groups apply as they do to the
// container. With PORT, as for an LRP, connections to PORT on the container
// also reach PORT in the guest, and so do connections to each other port in
// CF_INSTANCE_PORTS except 2222, where Diego's SSH daemon listens, up to 16
// ports in all with PORT first; more are left out with a line that says how
// many. QEMU forwards them itself (user-mode networking), with a rule for
// each port that vm-launch adds on QEMU's QMP monitor; for Firecracker,
// vm-launch listens on each port and proxies each connection to the guest
// over Garden's tap device. vm-launch reserves each port when it starts, so
// connections are refused, and it opens a port only while something in the
// guest listens on it at an address other than loopback, which the guest
// reports within a second of a change, even once the app has used up the
// processes the guest can start. Each port opens and closes on its own, so a
// port that the app never listens on stays closed for the whole run. So, as
// for a runc app, a connection to a port, and with it Diego's port health
// check on PORT, succeeds only once the app listens. At the first SIGTERM or
// SIGINT, every port closes for good; open connections close when the guest
// stops. Without PORT, as for a task, nothing outside can connect to the
// guest, as for a runc task.
//
// The Firecracker proxy dials the guest from the container's tap address,
// 169.254.100.1, so the guest sees that address as the peer of every
// connection. With --transparent-proxy, which Garden passes to the vm-launch
// it wraps in a vm-firecracker container when the process has PORT, the proxy
// instead dials from the client's own IPv4 address, so the guest sees the
// peer a runc app would: the gorouter, another app, or the container IP for a
// client inside the container that dials it. A loopback client still shows
// up as 169.254.100.1, because no packet from a loopback address leaves the
// container's loopback device. The transparent dial takes CAP_NET_RAW, which
// Garden grants this vm-launch together with the flag, and Garden routes the
// guest's replies back to the proxy. vm-launch checks that it can make a
// socket transparent before the guest boots and exits 125 when it cannot, and
// a connection whose socket cannot be made transparent is closed rather than
// dialled from the tap address. Firecracker never holds a capability, with or
// without the flag: vm-launch starts it from a thread that has dropped every
// capability from every set it could pass on, and refuses to start a
// Firecracker binary that has file capabilities. A thread with fewer
// capabilities than the rest of vm-launch would let a process of the same
// user write vm-launch's memory, so vm-launch makes itself non-dumpable first
// (see Core dumps).
//
// Stopping: at the first SIGTERM or SIGINT while the guest's command runs,
// vm-launch asks the guest, over its serial console, to stop the command,
// and the guest sends SIGTERM to the command's top process, as runc does to
// a container's first process. For a simple command, that process is the
// app itself. The command may finish its work, and vm-launch then exits with
// the command's status, so an app that drains and exits 0 makes vm-launch
// exit 0. Before the guest has started its command, or once it has reported
// the command's status, vm-launch forwards the signal to the hypervisor
// instead, as it also does when it cannot send the request. Either way,
// vm-launch kills a hypervisor that still runs 8 seconds after the first
// signal, which leaves vm-launch the time to clean up and report before
// Garden's 10 second stop timeout ends it. A later signal never moves that
// deadline, and while the guest stops, vm-launch does nothing else with it.
//
// Volumes: when VCAP_SERVICES names a volume mount, as it does for an app
// bound to a volume service, the guest gets that volume at the same path the
// container sees, backed by a raw image file
// rvm-disk-APPID-PROCESSTYPE-INDEX.img in the root of the volume. An app may
// have up to four read-write volume mounts, each on a path of its own, and
// no volume path may be on or under another. APPID is the
// application_id in VCAP_APPLICATION, which must be a lowercase UUID,
// PROCESSTYPE is its process_type, 1 to 63 lowercase letters, digits,
// underscores, or hyphens, and INDEX is CF_INSTANCE_INDEX. Two apps bound to
// one service instance, and the process types of one app, get separate
// images. A task has neither CF_INSTANCE_INDEX nor process_type, so it has
// no instance image of its own, and a task that has a private volume fails
// to start. A task can have a volume as a share (see Shares below), which
// needs no image. vm-launch creates a missing image under
// a temporary name, as a sparse 64 MiB file with mode 0600, and publishes it
// with renameat2(RENAME_NOREPLACE) once it is sized, so the image name never
// refers to an unsized file. A launch that is killed leaves at worst a
// .rvm-disk-*.tmp file, which nothing reads but which holds up to 64 MiB of
// quota until an operator deletes it, because a quota that counts file
// length, as JuiceFS does, charges a new image its whole size. On an NFS
// volume, whose client refuses renameat2 with a flag, vm-launch allocates
// the image, publishes it with a hard link instead, and removes the temporary
// name, and the next launch removes a temporary name that a killed launch
// left. Once it holds the image's lock, vm-launch grows the image to the size
// VM_VOLUMES asks for, 1 GiB by default, writing only zeros past its end: by
// fallocate on JuiceFS, which only raises the length there, or by truncate
// where the volume has no fallocate, and on NFS by fallocate or, where the
// volume has none, by zero writes that log their progress every 10 seconds
// and that the next start continues when this one is stopped. It never
// shrinks an image, and it keeps a larger one with a line that says so. An
// image below 64 MiB was not made by vm-launch and fails the launch. The
// volume path and the image
// are resolved without following
// symbolic links, the volume path must be a mount point, and the image must
// be a regular file owned by the app's uid, with one link and mode 0600.
// vm-launch never reads the image. It holds an exclusive flock on the image
// for as long as the VM runs, waiting up to 30 seconds in all, over every
// volume, for another instance to release it, checks after the wait that the name still refers to the
// locked file, and passes the image to the hypervisor as file descriptor 3.
// With more than one volume, the volumes are taken in the byte order of
// their paths and numbered from 0 in that order, shares included. Each image
// or disk gets the next file descriptor and the next drive, and its drive
// carries its volume's number, vol0 to vol3, so that the order never depends
// on the order of VCAP_SERVICES. A share takes a number but has no file
// descriptor or drive. vm-launch prepares them in that order and, when one fails,
// releases every one it prepared before it. Two volumes that show one
// directory of one filesystem, so that their images would be one file, fail
// the launch, as does a volume whose image is the file another volume already
// holds, which vm-launch refuses before it waits for the lock. The guest finds
// each image's drive by the identity vm-launch gives the drive and checks its
// size. When the image's first 64 KiB are all zero, the guest formats it as
// a journalled ext4 with the shipped mke2fs, without zeroing its inode
// tables or its journal. Every other image is checked with e2fsck -p before
// it mounts, and an image that e2fsck -p cannot repair fails the boot and is
// never formatted, nor is a non-blank image that does not mount. The guest
// mounts each image at its own path with sync, dirsync, noatime,
// noinit_itable, and errors=remount-ro. With --volume-sync-mounts=false, an
// image whose filesystem has a journal mounts without sync and dirsync,
// while an image without one, such as an ext2 image from an earlier
// release, keeps them.
//
// A BOSH disk volume is a whole block device rather than an image. Its
// volume path is a read-only tmpfs from pdi:bosh-disk that holds a
// descriptor of the disk, and vm-launch opens the device node that the
// descriptor names under /dev/pdi with O_EXCL, which no mount or other
// exclusive open on the cell can share. While the device is busy, as it is
// while the previous instance's VM on the same cell stops, vm-launch tries
// again within the same 30 seconds the image locks share, and then fails
// the launch with exit 125. It checks that the node is the device the
// descriptor names, that the device has the descriptor's size, and that it
// holds an ext4 filesystem with a journal, the descriptor's UUID, and no
// more blocks than the device has, and it passes the device to the
// hypervisor as the volume's drive.
// The volume service attaches a BOSH disk to one VM at a time, so only
// instance 0 of an app can use one, and any other instance fails the launch
// with exit 125. A BOSH disk is as large as its plan, so a size for it in
// VM_VOLUMES fails the launch with exit 125, before any volume is opened.
// The guest finds
// the drive by its identity and size as it finds an image's, and it mounts
// the disk as ext4 with noatime and errors=remount-ro. It never formats a
// block volume: a disk that does not mount fails the boot.
//
// Each volume must be a BOSH disk, JuiceFS, or NFS volume. Cloud Controller
// strips the driver name from volume_mounts, so vm-launch reads the
// filesystem type and source of the mount at each volume path from
// /proc/self/mountinfo and lets the registry of volume providers (see
// pdi.go) pick the provider that owns it. The BOSH disk provider owns a
// read-only tmpfs whose source is pdi:bosh-disk, JuiceFS owns fuse.juicefs,
// and NFS owns nfs4 mounted with local_lock=none. Any other type, an NFSv3
// or mapfs mount, or a path with no mount entry fails the launch with exit
// 125 before anything boots.
//
// Shares: a volume that VM_VOLUMES sets to "mode": "share", on vm-qemu with
// --allow-volume-shares, is granted a share and gets no image. A granted
// share without --virtiofsd-path, or with a path that is not an executable
// file, fails the launch with exit 125. Otherwise vm-launch serves the
// volume's own directory to the guest over virtiofs, with
// one virtiofsd for each share, run from the executable that
// --virtiofsd-path names (on a cell,
// /opt/garden-vm/artifacts/virtiofsd/virtiofsd-wrapper). When that path is
// the wrapper or the virtiofsd of the virtiofsd bundle, vm-launch runs the
// bundle's virtiofsd through the bundle's own loader and libraries, as the
// wrapper does, so it needs no shell from the app's rootfs. Each virtiofsd
// runs as vm-launch's user with no capabilities, no_new_privs, and an empty
// environment, gets a listening Unix socket in the work directory, and must
// report that it is ready within 5 seconds, all of them together and with
// vm-launch's last check of each share's mount, before the guest boots. Its
// log lines go to stderr with the share's path in front. A virtiofsd that
// ends before the guest has reported its status stops the guest, and
// vm-launch exits 125 with a line that names the share, unless the
// hypervisor exited on its own first, which keeps the hypervisor's status. A
// virtiofsd that exits 0 as the hypervisor exits is not a failure, and a
// hypervisor that is still exiting a second later gets one more second, and
// one more for each 4 GiB of guest memory, before vm-launch says so. Once
// the hypervisor has exited, every virtiofsd that still runs gets half a
// second to end and then SIGKILL. QEMU gives the guest one virtiofs device
// for each share, with the tag rvm-vol and the share's volume number, such as
// rvm-vol1, on guest memory that virtiofsd can map. The guest mounts the
// share at the volume's path with mount -t virtiofs, and a share that does
// not mount fails the boot. After the command ends, the guest flushes and
// unmounts the share along with the other volumes before it reports the
// command's status. When the command exited 0 but a flush or unmount failed,
// the guest reports 125 in its place, and vm-launch exits 125. Firecracker
// has no virtiofs device, so a share on vm-firecracker fails the launch with
// exit 125.
//
// Environment: the guest command sees the container's environment after the
// changes the CF launcher would have made to it. vm-launch reads its
// environment once, and when a name appears twice, the last value wins, as
// under runc. VCAP_APPLICATION gets the launcher's host, instance_id, port,
// and instance_index, and its limits.mem becomes the guest size. DATABASE_URL
// is derived from the first MySQL or PostgreSQL uri in VCAP_SERVICES, as the
// launcher derives it. MEMORY_LIMIT, when it is set, becomes the guest size.
// The guest never gets PATH, HOME, TMPDIR, USER, PWD, OLDPWD, DEPS_DIR,
// CF_INSTANCE_CERT, CF_INSTANCE_KEY, CF_SYSTEM_CERT_PATH,
// SERVICE_BINDING_ROOT, VCAP_SERVICES_FILE_PATH, VCAP_PLATFORM_OPTIONS,
// CF_VM_SIDECARS, or a name that starts with __GARDEN_, except that the stack
// guest keeps PATH and USER, and CF_INSTANCE_CERT and CF_INSTANCE_KEY when it
// holds the instance identity pair (see Sidecars and instance identity
// below). It also never gets the variables that its
// busybox sh sets for itself, because the shell would replace a value from
// the container before the command saw it: IFS, OPTIND, PPID, and SHLVL.
// vm-launch names those that are set in one line. The guest's busybox sh
// drops names that are not shell identifiers, such as
// spring.profiles.active, from the environment it starts with, so vm-launch
// leaves them out with one line that names the first 20 and counts any
// others. Every other variable is exported from /rvm/env, which has mode
// 0600 and exists only in the initramfs. One NAME=value entry may have at most
// 131071 bytes, and /rvm/env at most 1 MiB; vm-launch fails rather than
// truncate a value. Unlike the launcher, vm-launch does not run
// buildpack profile.d scripts or .profile, starts the command in /, and runs
// it with busybox sh rather than bash. No line about the guest environment
// holds a value from it. Other lines name values the platform sets, such as
// PORT, MEMORY_LIMIT, the volume path, and the CredHub host.
//
// Trusted certificates: the guest gets one CA bundle at
// /etc/ssl/certs/ca-certificates.crt that holds the certificates of the
// container's own bundle, the first of the usual distribution paths that
// vm-launch can read, and of every file directly under CF_SYSTEM_CERT_PATH,
// each certificate once. Only certificates are copied. Files that cannot be
// read, are not regular files, or hold no PEM certificate are left out,
// with one line that counts them, and a CF_SYSTEM_CERT_PATH that names no
// directory is not an error. The bundle, and every file read for it, may
// have at most 2 MiB. When the bundle holds a certificate and the app has
// not set SSL_CERT_FILE, the guest gets SSL_CERT_FILE naming the bundle, so
// that a TLS library with another default path finds it too.
//
// CredHub: when a binding in VCAP_SERVICES holds a "credhub-ref", vm-launch
// resolves the references before the guest boots, as the launcher does: one
// POST of VCAP_SERVICES to /api/v1/interpolate at the credhub-uri in
// VCAP_PLATFORM_OPTIONS, with the instance identity from CF_INSTANCE_CERT
// and CF_INSTANCE_KEY as the client certificate, trusting only the .crt
// files under CF_SYSTEM_CERT_PATH. The launcher also trusts the system CA
// pool, and vm-launch does not, so a CA from the app's rootfs never vouches
// for CredHub. The response becomes VCAP_SERVICES, and DATABASE_URL comes
// from it. CREDHUB_SKIP_INTERPOLATION skips the step. The launcher's
// -credhubConnectAttempts and -credhubRetryDelay, which default to 3 and 1s,
// set the retries; each attempt may take 45 seconds and goes through
// HTTPS_PROXY when NO_PROXY does not exclude the host. Go's proxy lookup
// reads the process environment itself, so when HTTPS_PROXY or NO_PROXY
// appears twice, the proxy uses the first value, while every other reader
// uses the last. Each failed attempt logs a line with the CredHub host and a
// reason class, never a body or a reference path.
//
// Open files: the guest command gets vm-launch's own RLIMIT_NOFILE, soft
// and hard, which Garden sets to the limit Diego asks for. The guest /init
// raises fs.nr_open to the hard limit when that is higher than the kernel's
// 1048576, and lifts fs.file-max to its highest value, so neither binds
// before the process limit does. A limit above 2147483584, the highest a
// 64-bit kernel allows, is lowered to that with a line that says so. Only
// the command gets the limit; /init's own steps keep the kernel's default.
//
// Shared memory: the guest has a tmpfs at /dev/shm with the options Garden
// gives a container's (noexec, nosuid, nodev, mode 1777), sized at half the
// guest's memory, as the unsized container mount is bounded by the
// container's memory.
//
// Memory: the guest gets MEMORY_LIMIT less 192 MiB, which the container
// keeps for the hypervisor and everything else it runs, with a floor of 128
// MiB and a ceiling of 16 GiB. MEMORY_LIMIT must be whole megabytes, such as
// 512m. When it is missing or malformed, or below the 320m that the floor
// and the reserve need, the guest gets 128 MiB and vm-launch logs a line
// that says so.
//
// Guest root disk: when VCAP_APPLICATION has limits.disk, vm-launch creates
// a sparse image for the guest root in its work directory, with mode 0600,
// and unlinks it at once, so that nothing is left to clean up and the
// container's quota charges the blocks the guest writes until the hypervisor
// and vm-launch have let go of the image. The image is as large as the
// smaller of limits.disk and the space free in the work directory, less 32
// MiB kept for other writers in the container, so that the guest's own
// filesystem fills before the quota does. The hypervisor gets it as the last drive,
// after the volume images' and with discard turned on, so that the blocks the
// guest frees go back to the quota. When less than 16 MiB is left after the
// 32 MiB, or the image cannot be created, vm-launch exits 125 with a line
// that says why. A missing or malformed limits.disk leaves the guest root in
// RAM, with a line that says the disk quota does not apply to it.
//
// The guest's /init finds the image's drive by its identity, checks its size
// in sectors, both of which vm-launch writes in the initramfs, formats it as
// ext2 with online discard, and mounts an overlay with the initramfs as its
// lower layer and the image as its upper. It moves /proc, /sys, and /dev
// into the overlay, moves the overlay onto /, and runs the rest of its setup
// and the command inside it, so everything the guest writes outside /dev and
// the volumes lands on the image and counts against the quota. Every boot
// formats a fresh image, as every start of a runc app gets a fresh
// container. /init formats only the one device with the image's identity,
// and only when it reads as blank, so it never formats a volume; when it
// cannot find, check, format, or mount the image, the guest reboots before
// it starts the command, and vm-launch exits 123 with the console output,
// which ends with the step that failed.
//
// A guest with an image or block volume also gets the guest filesystem tools
// mke2fs, e2fsck, tune2fs, and ext4grow, and a pinned mke2fs.conf, below
// /rvm/tools in its initramfs. vm-launch reads the four tools from the
// artifacts directory beside busybox, and it exits 125 before it prepares
// any volume when one is missing, is not a regular executable file, or is a
// symbolic link that leaves the artifacts directory. A guest without such a
// volume gets none of them.
//
// The initramfs that holds the guest's /init, busybox, command, and
// environment is built in a sealed memfd and never written to disk. The
// hypervisor gets it as the file descriptor after the volume images', 3
// without a volume, 4 with one, and 7 with four, and vm-launch closes its
// own copy once the hypervisor has started. On QEMU, the monitor socket
// comes next, and the guest root image comes last, so the image is file
// descriptor 4 on Firecracker without a volume, 5 on QEMU without a volume,
// and 6 on QEMU with one volume; vm-launch closes its copy of it, too, once
// the hypervisor has started.
//
// Stack guest: when the process is the CF launcher, Garden bound a stack
// image that is a regular file holding an lz4 squashfs, and the app has no
// volume, vm-launch builds a droplet image of /home/vcap in its work
// directory with the mksquashfs in the artifacts directory, opens it
// read-only, and unlinks it. It builds the droplet before it sizes the guest
// root, so the root image gets only the quota the droplet leaves. The guest
// then runs the launcher's whole argv on the stack, as uid 2000, with the
// droplet laid over the stack's /home/vcap, so the start command may be
// empty and the launcher detects it from the droplet. The guest also gets
// the launcher itself, vm-launch's working directory, and the container's
// hostname and /etc/hosts in its initramfs. The hypervisor gets the stack
// and the droplet as two read-only drives after the guest root image, so no
// other drive or file descriptor moves, and vm-launch closes its copies of
// both once the hypervisor has started. When any of those conditions does
// not hold, or the droplet image fails to build, vm-launch boots the busybox
// guest described above, exactly as it would without a stack image. Either
// way, one line just before the hypervisor starts names the guest and why:
// the droplet's size and build time for the stack guest, and the condition
// that failed for the busybox guest. A launcher with an empty start command
// needs the stack guest, so without it vm-launch exits 125 after that line.
//
// Sidecars and instance identity: rep folds an app's sidecars into
// CF_VM_SIDECARS on the launcher's environment, and the stack guest runs each
// one beside the app, as uid 2000 from the same root. vm-launch reads the
// variable before it chooses the guest, and an app with sidecars that would
// get the busybox guest exits 125 with the line "this app has N sidecars,
// which run only in the stack guest;" and the reason for the busybox guest.
// The stack guest also gets the instance identity pair that CF_INSTANCE_CERT
// and CF_INSTANCE_KEY name, when both files exist, checked as a pair and
// each at most 64 KiB, and it installs the pair at
// /etc/cf-instance-credentials in the app's root, where both variables then
// point. A pair that does not match exits 125. The mode line adds the number
// of sidecars and the pair's serial and expiry. Once the guest has started
// its command, vm-launch looks at both files every 5 seconds, and it sends
// each new pair that Diego writes to the guest on its console input, which
// the guest installs and acknowledges. No line holds the pair itself.
//
// Core dumps: vm-launch sets its RLIMIT_CORE to zero, soft and hard, and its
// coredump_filter to zero before it does anything else, and the hypervisor
// inherits both. Then vm-launch makes itself non-dumpable, which also keeps
// a process without CAP_SYS_PTRACE, of any user, from tracing it or opening
// its memory or environment under /proc; the hypervisor's own exec makes it
// dumpable again. A pipe core handler takes a dump despite the limit, but the
// kernel applies the filter to that dump too, so it holds none of the
// process's memory mappings except the vDSO. QEMU also runs with
// dump-guest-core=off, which keeps guest RAM out of a dump of QEMU even if
// something raises the filter again.
//
// The guest's console output, stdout and stderr merged, is written to stdout
// as it arrives. Kernel boot messages and the status marker are dropped.
//
// Exit status:
//
//	0-255  the status the guest reported: the guest command's exit status,
//	       or 125 for a command that exited 0 when the guest then could not
//	       flush or unmount a volume, a share included
//	123    the hypervisor exited cleanly, but the guest never reported a status,
//	       as when the guest cannot find, format, check, or mount a volume image
//	       or the guest root image; a volume the guest could not flush or
//	       unmount after the command is not this, since the guest reports 125
//	124    the hypervisor failed: it exited non-zero before the guest reported a
//	       status, as QEMU does when it cannot open the volume image
//	125    the guest reported it, for a command that exited 0 and a volume,
//	       a share included, that the guest then could not flush or unmount,
//	       or vm-launch could not start the guest: core dumps it could not
//	       disable, a dumpable flag it could not clear, an open files
//	       limit it could not read, bad arguments, a guest command over
//	       131071 bytes, a missing artifact, a guest filesystem tool that
//	       a guest with an image or block volume needs and the cell lacks,
//	       a work file, initramfs, guest root image, or QMP socket it could not
//	       create, a disk quota too small for the guest root image or
//	       that it could not read, a
//	       hypervisor it could not run, PORT already in use in the
//	       container, or a volume it cannot use:
//	       VCAP_SERVICES that is not valid JSON, more than four volume
//	       mounts, two volume mounts on one path, two volumes that share a
//	       directory, a read-only mount, a bad volume path,
//	       CF_INSTANCE_INDEX, application_id, or process_type, a task with
//	       a private volume, an image that fails a check or cannot be created,
//	       a VM_VOLUMES value that is not
//	       a JSON object of volume paths, names a path no volume mounts, or
//	       sets a mode or size it does not allow, or asks for a share that
//	       the backend, the volume, or the operator does not allow, a
//	       granted share without a usable --virtiofsd-path, a share whose
//	       mount changed or could not be checked within 5 seconds, or whose
//	       virtiofsd could not start, ended, or was not ready within 5
//	       seconds, a share whose virtiofsd ended before the guest reported
//	       a status and whose kill ended the hypervisor, or
//	       an image another instance still holds after 30 seconds, a
//	       guest environment that is too large, with one entry over
//	       131071 bytes or more than 1 MiB in all, or a value that holds a
//	       NUL byte, trusted certificates over 2 MiB, VCAP_PLATFORM_OPTIONS
//	       that is not valid JSON, a CF_VM_SIDECARS that does not parse, an
//	       app with sidecars that gets the busybox guest, an instance
//	       identity pair for the stack guest that does not match or has a
//	       file over 64 KiB, a bad launcher CredHub flag, or CredHub
//	       references that cannot be resolved: missing or unreadable
//	       instance identity or CA files, a credhub-uri that is not an
//	       https URL, or every attempt failing
//	128+N  vm-launch received signal N (SIGTERM or SIGINT), or the hypervisor
//	       died from signal N, before the guest reported a status; this
//	       includes a signal while vm-launch waits for the volume image,
//	       resolves CredHub references, or starts virtiofsd, and a guest
//	       command that did not stop within 8 seconds of the signal
//
// A guest command can exit with any of these values itself; whenever vm-launch
// picks the status, it also writes a "vm-launch:" line to stderr.
//
// When the guest kernel killed any process for lack of memory, whatever the
// exit status, vm-launch writes the stderr line "vm-launch: the guest ran out
// of memory: its kernel killed N processes; the guest has M MiB" before it
// exits. Guardian reads that line to report an out-of-memory exit.
//
// Memory metrics: every guest gets a virtio balloon that is never inflated.
// Its guest kernel reports its memory statistics through it every 5 seconds,
// and hands the pages it frees back to the host. vm-launch reads the
// statistics every 10 seconds, over QEMU's QMP monitor, which every QEMU
// guest gets, or over Firecracker's API socket, whose path it removes as soon
// as it has connected, so nothing else in the container can reach the API.
// For each sample that fits the guest's size, it writes one stderr line
// "vm-launch-metrics v1 used=U total=T available=A free=F caches=C" in bytes,
// where used is the total less the memory the guest kernel considers
// available. Guardian removes these lines from the stream and reports used as
// the container's memory. vm-launch logs one line when the statistics stop
// being good and one when they are good again, and it stops reading, with
// one line, once the hypervisor can no longer be read.
//
// A container runs one VM per port: a second vm-launch for the same PORT, such
// as a CF sidecar that gets the app's PORT, cannot reserve it and exits 125,
// as does a vm-launch whose PORT another process already listens on, with a
// line that names the port conflict. A process that starts listening on a
// port after vm-launch reserved it keeps the guest's port closed while it
// listens, with the same line once when the guest listens. vm-launch keeps
// trying to open the port, and opens it once the other process stops
// listening. A conflict on another port of CF_INSTANCE_PORTS at start is
// logged the same way and does not stop the launch, because the port opens
// later when it frees up.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	"golang.org/x/sys/unix"
)

const (
	exitMissingMarker    = 123
	exitHypervisorFailed = 124
	exitLaunchError      = 125
)

// oomLinePrefix is the text, after the logger's "vm-launch: ", that begins
// the line oomMessage writes. Guardian's rundmc package pins the same text
// with the "vm-launch: " in front.
const oomLinePrefix = "the guest ran out of memory"

const defaultArtifactsDir = "/opt/garden-vm/artifacts"

// killGrace is how long the hypervisor may keep running after the guest
// reported its status, when no signal came first.
const killGrace = 5 * time.Second

// transparentProxyFlag names the flag that turns on the transparent port
// proxy. Garden's process builder passes it, as --transparent-proxy, to the
// vm-launch it wraps in a vm-firecracker container when the process has PORT.
const transparentProxyFlag = "transparent-proxy"

// stopDeadline is how long the hypervisor may keep running after the first
// SIGTERM or SIGINT, which is all the time a guest command gets to stop. Diego
// sends SIGKILL 10 seconds after its SIGTERM, and the 2 seconds left cover
// the kernel freeing the guest's memory and vm-launch's own cleanup and exit
// line, for every guest size vm-launch allows. With a share, a virtiofsd that
// outlives a killed QEMU holds the last reference to the guest's memory, and
// the kernel frees it in virtiofsd's exit, which vm-launch does not wait for
// past its kill wait (see virtiofsdKillWait).
const stopDeadline = 8 * time.Second

// volumeSyncMountsFlag names the vm-launch flag with which the operator
// keeps or drops sync and dirsync on the mounts of volume images. It is true
// by default, and with --volume-sync-mounts=false, which Garden renders from
// a job property, an image whose filesystem has a journal mounts without
// them. vm-launch records the setting in /rvm/mounts, and the guest decides
// for each image, because only the guest sees whether its filesystem has a
// journal (see guestVolumeSetup). An image without a journal and a block
// volume are never changed by it.
const volumeSyncMountsFlag = "volume-sync-mounts"

const usage = "usage: vm-launch --backend vm-qemu|vm-firecracker [--transparent-proxy] [--allow-volume-shares] [--virtiofsd-path PATH] [--volume-sync-mounts=false] [--artifacts DIR] -- PATH [ARGS...]\n"

type config struct {
	backend   backend.Kind
	artifacts string
	command   string
	credhub   credhubRetry
	// args is the wrapped process argv after --, which the stack guest's
	// launcher runs whole (see stackCommand).
	args []string
	// commandErr is why the busybox guest cannot run args when only the
	// stack guest can, which is a CF launcher with an empty start command.
	// command is then empty, and run exits with commandErr unless the guest
	// is the stack guest.
	commandErr error
	// transparent makes the Firecracker port proxy dial the guest from its
	// clients' addresses (see transparentSource).
	transparent bool
	// allowVolumeShares is the operator's switch for share mode. Without it
	// an app that asks for a share in VM_VOLUMES is refused (see grantShares).
	allowVolumeShares bool
	// virtiofsd is the path of the executable that runs virtiofsd, which
	// serves a granted share (see virtiofsd.go), or empty.
	virtiofsd string
	// volumeSyncMounts keeps sync and dirsync on every image mount. When it
	// is false, an image with a journal mounts without them (see
	// volumeSyncMountsFlag).
	volumeSyncMounts bool
}

// init holds the main goroutine, and with it run, to the thread-group
// leader for the whole run. The goroutine that starts the hypervisor changes
// its own thread's credentials, so it can then never run on the leader, and
// the leader's /proc status keeps showing vm-launch's own capabilities.
func init() {
	runtime.LockOSThread()
}

func main() {
	logger := log.New(os.Stderr, "vm-launch: ", 0)
	os.Exit(run(os.Args[1:], logger))
}

// coreDumpFilterPath is the file that holds vm-launch's coredump_filter.
// Specs point it elsewhere to make the write fail.
var coreDumpFilterPath = "/proc/self/coredump_filter"

// disableCoreDumps sets vm-launch's RLIMIT_CORE to zero, soft and hard, and
// then its coredump_filter to zero. Specs replace it to make it fail.
var disableCoreDumps = func() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return err
	}
	return writeCoreDumpFilter(coreDumpFilterPath)
}

// writeCoreDumpFilter writes a filter of zero to path. Its error names the
// path and the errno, and nothing else.
func writeCoreDumpFilter(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err == nil {
		_, err = f.WriteString("0")
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}
	if err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// markUndumpable clears vm-launch's dumpable flag and reads it back. A
// process that is not dumpable can be traced, and its memory opened under
// /proc, only by a process with CAP_SYS_PTRACE, which no process in a Garden
// container holds. That matters once the hypervisor's thread has dropped its
// capabilities: the kernel compares the capabilities of a tracer with those
// of the one thread it targets, so that thread would otherwise let a process
// of the same user without capabilities write the memory every thread of
// vm-launch shares, CAP_NET_RAW threads included. The /proc files of a
// process that is not dumpable belong to root, so the coredump_filter write
// must come first. Specs replace markUndumpable for the test process itself,
// which calls run many times and must keep writing its own coredump_filter.
var markUndumpable = func() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return os.NewSyscallError("prctl PR_SET_DUMPABLE", err)
	}
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return os.NewSyscallError("prctl PR_GET_DUMPABLE", err)
	}
	if dumpable != 0 {
		return fmt.Errorf("the dumpable flag is still %d", dumpable)
	}
	return nil
}

func run(argv []string, logger *log.Logger) int {
	// Guest RAM holds what vm-launch puts in the guest, and a core dump of
	// the hypervisor would write that to disk. The hypervisor inherits the
	// limit, and with a hard limit of zero it cannot raise it again. A pipe
	// core handler ignores a limit of zero, so the hypervisor also inherits
	// a coredump_filter of zero, which leaves its memory out of any dump.
	if err := disableCoreDumps(); err != nil {
		logger.Printf("disabling core dumps: %v", err)
		return exitLaunchError
	}
	// This comes before any thread drops a capability. Until the
	// hypervisor's thread does, every thread of a vm-launch that Garden
	// granted CAP_NET_RAW holds it in its permitted set, which keeps a
	// process of the same user without it from tracing any of them.
	if err := markUndumpable(); err != nil {
		logger.Printf("making vm-launch non-dumpable: %v", err)
		return exitLaunchError
	}

	// The guest's output goes to stdout, which a dying reader can break. Go
	// kills a process whose write to fd 1 or 2 hits a broken pipe, unless
	// SIGPIPE is caught or ignored. Catching it turns that into an EPIPE
	// error that the serial filter keeps, so the guest keeps draining and the
	// exit status stays the guest's. vm-launch catches SIGPIPE rather than
	// ignoring it, because an ignored signal stays ignored across exec, and
	// the processes vm-launch starts should get SIGPIPE at its default. QEMU
	// and Firecracker both ignore SIGPIPE themselves.
	pipes := make(chan os.Signal, 1)
	signal.Notify(pipes, syscall.SIGPIPE)
	defer signal.Stop(pipes)

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)

	cfg, err := parseArgs(argv)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(logger.Writer(), usage)
		return 0
	}
	if err != nil {
		logger.Print(err)
		fmt.Fprint(logger.Writer(), usage)
		return exitLaunchError
	}
	// Every reader sees the same environment, so the volume and the guest
	// can never disagree about VCAP_SERVICES. All of this happens before the
	// work directory and the volume lock, so a bad environment exits before
	// any image is opened or created.
	env := lastWinsEnv(os.Environ(), logger)
	lookupEnv := lookupIn(env)
	// The sidecars that rep folded into the launcher's environment run
	// beside the app, from the droplet, so only a guest with an app root can
	// run them. They are read before the guest is chosen, so that every
	// reason for the busybox guest refuses them.
	sidecars, err := parseSidecars(env)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	// The guest runs the app on its stack only when the process is the CF
	// launcher, Garden bound a usable stack image, the app has no volume,
	// and the droplet image builds. Each condition is settled as soon as
	// run can tell, and the first that fails gives the busybox guest, which
	// is then exactly the guest of a launch without a stack image. guestMode
	// is the line that names the guest and why, which run logs once the
	// hypervisor is about to start.
	stackImg, why := stackCandidate(cfg.args)
	defer func() { closeFile(stackImg, "the stack image", logger) }()
	guestMode := ""
	// toBusybox settles on the busybox guest for the reason why. A launcher
	// with an empty start command needs the stack guest, so it then gets the
	// refusal that parseArgs held back, after the line that says why. An app
	// with sidecars needs the stack guest too, so it gets one line that
	// names its sidecars and why.
	toBusybox := func(why string) bool {
		closeFile(stackImg, "the stack image", logger)
		stackImg = nil
		guestMode = "busybox guest: " + why
		if len(sidecars) > 0 {
			logger.Print(sidecarsRefusal(len(sidecars), why))
			return false
		}
		if cfg.commandErr == nil {
			return true
		}
		logger.Print(guestMode)
		logger.Print(cfg.commandErr)
		fmt.Fprint(logger.Writer(), usage)
		return false
	}
	if stackImg == nil && !toBusybox(why) {
		return exitLaunchError
	}
	if err := checkArtifacts(cfg.backend, cfg.artifacts); err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	nw, err := networkFor(cfg.backend, lookupEnv, containerResolvConf, interfaceMTU, logger)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	// The proxy serves ports only, so only then does it need the
	// capability. The hypervisor is confined whatever the flag says (see
	// sup.prepare below).
	if cfg.transparent && len(nw.ports) > 0 {
		if err := checkTransparentDial(); err != nil {
			logger.Print(transparentCheckMessage(err))
			return exitLaunchError
		}
	}
	// The registry refuses a volume no provider owns here, before the work
	// directory exists and before CredHub is asked anything. Every volume
	// is checked before any of them is prepared.
	vols, err := volumesFromEnv(lookupEnv)
	if err == nil {
		err = applyVolumeSettings(lookupEnv, vols)
	}
	var selected []selectedVolume
	if err == nil && len(vols) > 0 {
		selected, err = findVolumeProviders(mountInfoPath, vols)
	}
	// A size on a BOSH disk is refused here, with the providers known and
	// before any volume is opened (see refuseBlockSize).
	if err == nil {
		err = refuseBlockSizes(selected)
	}
	// A share is granted or refused here, with the providers known and
	// still before CredHub, the ports, and the work directory, and so is a
	// grant that this vm-launch has no virtiofsd to serve.
	var shares []shareGrant
	if err == nil {
		if shares, err = grantShares(cfg.backend, cfg.allowVolumeShares, selected); err == nil {
			err = checkVirtiofsd(cfg.virtiofsd, shares)
		}
	}
	// A guest with an image or block volume formats, checks, and grows it
	// with the guest filesystem tools, so a cell without them refuses the
	// launch here, before anything is prepared. The tools stay open until
	// the initramfs is written. A guest without such a volume gets none.
	var tools *guestTools
	if err == nil && needsGuestTools(len(selected), len(shares)) {
		tools, err = openGuestTools(cfg.artifacts)
	}
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	defer tools.Close()
	if stackImg != nil && len(vols) > 0 && !stackModeAllowsVolumes {
		has := "a volume"
		if len(vols) > 1 {
			has = fmt.Sprintf("%d volumes", len(vols))
		}
		if !toBusybox("the app has " + has + ", which the stack guest does not mount yet") {
			return exitLaunchError
		}
	}
	// The stack guest's launcher, argv, working directory, and host files
	// are gathered and checked here, so that a launch the stack guest could
	// not run fails before anything is prepared. The launcher stays open
	// until the initramfs is written.
	var stack *guestStack
	if stackImg != nil {
		if stack, err = newGuestStack(cfg.args); err != nil {
			logger.Print(err)
			return exitLaunchError
		}
	}
	closeLauncher := func() {
		if stack != nil {
			closeFile(stack.launcher.file, "the launcher", logger)
			stack.launcher.file = nil
		}
	}
	defer closeLauncher()
	memMiB := guestMemory(lookupEnv, logger)
	// The launcher derives DATABASE_URL from the resolved VCAP_SERVICES, so
	// the references are resolved before buildGuestEnv.
	services, resolved, err := resolveCredhubRefs(lookupEnv, cfg.credhub, defaultCredhubClient, sigs, logger)
	if err != nil {
		logger.Print(err)
		return stepExitCode(err)
	}
	if resolved {
		env[vcapServicesEnv] = services
	}
	caBundle, err := guestCABundle(rootfsCABundles, lookupEnv, logger)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	sysCerts, err := readSystemCerts(lookupEnv, logger)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	// SSL_CERT_FILE points a TLS library whose own default path is not
	// guestCABundlePath, such as a static OpenSSL build, at the bundle. A
	// value the app set itself stays.
	if _, ok := env[sslCertFileEnv]; !ok && caBundle != nil {
		env[sslCertFileEnv] = guestCABundlePath
	}
	// The two guests keep different variables, so a launch that may still
	// boot the stack guest builds its environment once the droplet image
	// has settled the guest, after the work directory exists.
	var envFile string
	if stack == nil {
		if envFile, err = buildGuestEnvWithCerts(env, memMiB, sysCerts.dirOf(), logger); err != nil {
			logger.Print(err)
			return exitLaunchError
		}
	}
	nofile, err := guestNofile(getNofile, logger)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	for i, port := range nw.ports {
		reservation, err := reservePort(port)
		if err != nil {
			logger.Print(err)
			if errors.Is(err, syscall.EADDRINUSE) {
				logger.Print(portConflictMessage(port))
			}
			// PORT is the one the app and Diego's health check need. Another
			// port that is taken stays closed, and its gate opens it when
			// the other process lets go.
			if i == 0 {
				return exitLaunchError
			}
			continue
		}
		defer func() {
			if err := reservation.Close(); err != nil {
				logger.Printf("releasing port %d: %v", port, err)
			}
		}()
	}

	workDir, err := os.MkdirTemp("", "vm-launch-")
	if err != nil {
		logger.Printf("creating work dir: %v", err)
		return exitLaunchError
	}
	defer func() {
		if err := os.RemoveAll(workDir); err != nil {
			logger.Printf("removing work dir: %v", err)
		}
	}()

	// The droplet image is built before the guest root is sized, so the
	// root image gets only the quota the droplet leaves. An image that does
	// not build gives the busybox guest, whose environment is built then.
	var droplet *os.File
	defer func() { closeFile(droplet, "the droplet image", logger) }()
	if stack != nil {
		img, err := buildDropletImage(cfg.artifacts, dropletHome, workDir)
		if err != nil {
			closeLauncher()
			stack = nil
			if !toBusybox(strings.ReplaceAll(err.Error(), "\n", "; ")) {
				return exitLaunchError
			}
			if envFile, err = buildGuestEnvWithCerts(env, memMiB, sysCerts.dirOf(), logger); err != nil {
				logger.Print(err)
				return exitLaunchError
			}
		} else {
			droplet = img.file
			guestMode = fmt.Sprintf("stack guest: the launcher runs on the stack image, with a droplet image of %s that is %d bytes and took %s to build",
				dropletHome, img.size, img.took.Round(time.Millisecond))
		}
	}
	// The guest is settled here. One with an app root gets the sidecars and
	// the instance identity pair, and its environment keeps CF_INSTANCE_CERT
	// and CF_INSTANCE_KEY only when the pair was read. The busybox guest
	// refused sidecars in toBusybox, and it gets no pair.
	var identity *instanceIdentity
	if stack.hasAppRoot() {
		if identity, err = readInstanceIdentity(env[instanceCertEnv], env[instanceKeyEnv]); err != nil {
			logger.Print(err)
			return exitLaunchError
		}
		files, err := sidecarGuestFilesOf(sidecars, stackGuestDenylist(identity != nil))
		if err != nil {
			logger.Print(err)
			return exitLaunchError
		}
		stack.sidecars, stack.identity, stack.systemCerts = files, identity, sysCerts
		guestMode += guestExtrasLine(sidecars, identity)
	} else if len(sidecars) > 0 {
		logger.Print(sidecarsRefusal(len(sidecars), "the stack guest has no app root"))
		return exitLaunchError
	}
	if stack != nil {
		if envFile, err = buildStackGuestEnvWithCerts(env, memMiB, identity != nil, sysCerts.dirOf(), logger); err != nil {
			logger.Print(err)
			return exitLaunchError
		}
	}

	nonce, err := guestNonce()
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}

	// The providers' attachments stay fenced until the hypervisor is reaped:
	// their Release functions run on the way out of run, after sup.run has
	// waited for the hypervisor, which shares the open files and with them
	// the locks. The volumes are prepared in volume order, so two instances
	// with the same bindings that start at once take their locks in the same
	// order. Instances whose bindings differ may cross, and the lock wait
	// bounds that: it gives up and the deferred release lets go of what the
	// launch holds. The volumes share one lock wait, as long as a single
	// volume's, so that no number of contended volumes waits past Diego's
	// start timeout. When a volume fails, the deferred release lets go of
	// every volume prepared before it, after the failure's own line.
	var prepared preparedVolumes
	defer func() { prepared.release(logger) }()
	lockWaits := newLockBudget(defaultImageOptions.LockWait)
	for _, v := range selected {
		if att, err := prepared.prepare(v, sigs, lockWaits, logger); err != nil {
			logger.Print(err)
			discardAttachment(att, logger)
			return stepExitCode(err)
		}
	}
	// The guest numbers the volumes by volume index, shares included, and
	// /rvm/disks pairs each volume that is not a share with the next drive.
	// The prepared disks must line up with that, or a disk would reach
	// another volume's path.
	if err := checkPreparedOrder(vols, prepared); err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	// The guest root image is sized from the quota the work directory has
	// left. The guest tells its drives apart by identity, so the root may
	// have any volume image's size.
	rootSize, rootInodeRatio, err := rootDiskSize(workDir, lookupEnv, workDirStatfs, logger)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	if rootSize > 0 {
		if err := checkRootImageDir(workDir, unix.Stat); err != nil {
			logger.Print(err)
			return exitLaunchError
		}
	}

	// vm-launch's copies of the files only the hypervisor uses close as soon
	// as the hypervisor has its own, or on the way out when the hypervisor
	// never starts.
	var initrd, qemuMonitor, rootImg *os.File
	closeInherited := func() {
		closeFile(initrd, "the initramfs", logger)
		initrd = nil
		closeFile(qemuMonitor, "QEMU's end of the QMP socket", logger)
		qemuMonitor = nil
		closeFile(rootImg, "the guest root image", logger)
		rootImg = nil
		closeFile(stackImg, "the stack image", logger)
		stackImg = nil
		closeFile(droplet, "the droplet image", logger)
		droplet = nil
	}
	defer closeInherited()
	if rootSize > 0 {
		rootImg, err = createRootImage(workDir, rootSize)
		if err != nil {
			logger.Print(err)
			return exitLaunchError
		}
	}

	// Every drive carries an identity, which /rvm/disks gives the guest. On
	// Firecracker it comes from the open files the hypervisor gets, so it is
	// taken once every one of them exists. Drives that would share an
	// identity are refused before the hypervisor starts.
	var sd *stackDrives
	if stack != nil {
		sd = &stackDrives{stack: stackImg, droplet: droplet}
	}
	drives, err := newGuestDrivesWithStack(cfg.backend, prepared, rootImg, sd)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	initrd, err = buildGuestInitramfs(filepath.Join(cfg.artifacts, artBusybox), guestContents{
		command:        cfg.command,
		nonce:          nonce,
		nw:             nw,
		env:            envFile,
		vols:           vols,
		drives:         drives,
		caBundle:       caBundle,
		systemCerts:    sysCerts,
		nofile:         nofile,
		rootBytes:      rootSize,
		rootInodeRatio: rootInodeRatio,
		tools:          tools,
		noVolumeSync:   !cfg.volumeSyncMounts,
		stack:          stack,
	})
	// The archive holds the tools' and the launcher's bytes now, so the
	// files close here. The deferred calls cover the returns before this
	// point.
	tools.Close()
	closeLauncher()
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	// Every QEMU guest gets the QMP monitor, which the memory poller reads
	// the balloon's statistics on, and on which vm-launch adds and removes
	// the rules that forward the ports.
	var qmp *qmpMonitor
	if cfg.backend == backend.VMQemu {
		var monitor net.Conn
		monitor, qemuMonitor, err = newQMPSocket()
		if err != nil {
			logger.Print(err)
			return exitLaunchError
		}
		defer monitor.Close()
		qmp = newQMPMonitor(monitor)
	}
	// Each share's virtiofsd listens on a socket in the work directory,
	// which QEMU connects to by path. The sockets exist from here on, and
	// the processes start just before QEMU does. The deferred stop covers
	// every way out before the explicit one after sup.run, and kills every
	// virtiofsd that runs.
	shareSrv, err := newShareServers(cfg.virtiofsd, workDir, shares, logger)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	defer shareSrv.stop(0)
	shareSrv.setGuestMemory(memMiB)
	files, drivePaths, initrdPath, monitorFD, rootPath := hypervisorFilesWithStack(prepared.files(), initrd, qemuMonitor, rootImg, sd)
	hvArgv, err := hypervisorArgvWithStack(cfg.backend, cfg.artifacts, workDir, initrdPath, memMiB, nw, drivePaths, rootPath, monitorFD, sd, shareSrv.sockets()...)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}

	select {
	case sig := <-sigs:
		logger.Printf("received %v before the guest started", sig)
		return 128 + signalNumber(sig)
	default:
	}

	// Every virtiofsd is ready before QEMU starts, and one that has ended
	// since keeps QEMU from starting at all.
	if err := shareSrv.start(sigs); err != nil {
		logger.Print(err)
		return stepExitCode(err)
	}
	if reason := shareSrv.failureReason(); reason != "" {
		logger.Printf("%s; exiting %d", reason, exitLaunchError)
		return exitLaunchError
	}

	logger.Print(guestMode)
	cmd := newHypervisorCmd(hvArgv, files)
	sup := supervisor{stdout: os.Stdout, logger: logger, signals: sigs, grace: killGrace, deadline: stopDeadline, started: closeInherited}
	if len(shares) > 0 {
		// A virtiofsd that ends while QEMU runs kills it, which takes QEMU's
		// process, known once it has started. QEMU's reap is reported at
		// once, before the output flush, so a virtiofsd that exits 0 at the
		// disconnect is expected, and the stop of every virtiofsd runs
		// beside the flush.
		sup.started = func() {
			closeInherited()
			shareSrv.guestStarted(cmd.Process)
		}
		sup.reaped = shareSrv.hypervisorReaped
	}
	// Firecracker starts without a capability whether or not vm-launch was
	// given --transparent-proxy, so a grant that reaches vm-launch some other
	// way never reaches the hypervisor.
	if cfg.backend == backend.VMFirecracker {
		sup.prepare = confinedPrepare(cmd)
	}
	// The memory poller starts once the hypervisor has, and stops when the
	// ports close, before the gates send their last commands on the
	// monitor, or once the supervisor returns, before the exit line. A stop
	// ends a read in flight at once, so it never holds up the shutdown.
	poller, closeStats := newGuestMetrics(cfg.backend, qmp, workDir, memMiB, logger)
	stopMetrics := func() {
		poller.stop()
		closeStats()
	}
	defer stopMetrics()
	afterStart := sup.started
	sup.started = func() {
		afterStart()
		poller.start()
	}
	sup.closePorts = stopMetrics
	var gates *portGates
	if len(nw.ports) > 0 {
		// One proxy or one monitor serves every port's opener.
		var open func(port int) portOpener
		if cfg.backend == backend.VMFirecracker {
			var opts []proxyOption
			if cfg.transparent {
				opts = append(opts, withTransparentDial())
			}
			proxy := newProxy(upstreamDialPolicy, logger, opts...)
			defer proxy.Close()
			open = func(port int) portOpener {
				return proxyPort{proxy: proxy, addr: nw.listenAddr(port), upstream: nw.upstream(port)}
			}
		} else {
			open = func(port int) portOpener { return qmpPort{monitor: qmp, port: port} }
		}
		// The explicit gates.end after sup.run is the one that ends the
		// gates, as it must come before the exit line. A panic out of
		// sup.run skips it, and this deferred call covers that one path:
		// deferred calls run last first, so the gates still end before the
		// proxy closes and before the monitor closes. A second end is a
		// no-op.
		gates = startPortGates(nw.ports, open, gateRetry, logger)
		defer gates.end()
		sup.closePorts = func() {
			stopMetrics()
			gates.shutDown()
		}
		sup.listen = gates.set
	}
	// A guest that holds the identity pair gets each of Diego's rewrites of
	// it once the guest has started its command. The watcher stops as soon
	// as the supervisor returns, so its last lines come before the exit
	// line.
	stopWatch := func() {}
	if identity != nil {
		stopWatch = watchIdentity(&sup, nonce, env[instanceCertEnv], env[instanceKeyEnv], identity, logger)
	}
	res, err := sup.run(cmd, nonce)
	stopWatch()
	stopMetrics()
	// QEMU has been reaped, or never started. Every virtiofsd has stopped,
	// or stops now, and its last lines come before the exit line.
	shareSrv.guestEnded()
	if gates != nil {
		// The gates' last lines about the ports come before the exit line.
		gates.end()
	}
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	if res.guestOOMKills > 0 {
		logger.Print(oomMessage(res.guestOOMKills, memMiB))
	}
	code, reason := exitCode(res)
	// A share that stopped being served while the guest still needed it is
	// the cause when vm-launch's kill for it is what ended QEMU. A QEMU that
	// ended on its own keeps its own status. A guest that reported its status
	// keeps that, because it reports it only once it has flushed and
	// unmounted its volumes. For a command that exited 0, the guest reports
	// 125 when it could not flush or unmount a volume, a share included, and
	// vm-launch passes that 125 on (see shareEndedGuest).
	if shareReason := shareSrv.failureReason(); shareReason != "" && shareEndedGuest(res) {
		code, reason = exitLaunchError, shareReason
	}
	if reason != "" {
		logger.Printf("%s; exiting %d", reason, code)
	}
	return code
}

// newGuestMetrics returns the poller of the guest's memory for backend, which
// writes its lines to the logger's writer, vm-launch's stderr, and the
// function that releases its source once the poller has stopped. On QEMU it
// reads the balloon over qmp, and turns its statistics on first. On
// Firecracker it connects to the API socket in workDir first, which removes
// the socket's path.
func newGuestMetrics(kind backend.Kind, qmp *qmpMonitor, workDir string, memMiB int, logger *log.Logger) (*metricsPoller, func()) {
	guestBytes := uint64(memMiB) << 20
	if kind == backend.VMFirecracker {
		source := &firecrackerStatsSource{}
		poller := newMetricsPoller(source, guestBytes, logger.Writer(), logger)
		socket := firecrackerAPISocket(workDir)
		poller.prepare = func(ctx context.Context) error { return source.connect(ctx, socket, fcSocketWait) }
		return poller, func() { _ = source.Close() }
	}
	source := newQEMUGuestStats(qmp)
	poller := newMetricsPoller(source, guestBytes, logger.Writer(), logger)
	poller.prepare = source.Enable
	return poller, func() {}
}

// sidecarsRefusal is the line with which vm-launch refuses an app with n
// sidecars when the guest it gets has no app root, for the reason why.
func sidecarsRefusal(n int, why string) string {
	if n == 1 {
		return "this app has 1 sidecar, which runs only in the stack guest; " + why
	}
	return fmt.Sprintf("this app has %d sidecars, which run only in the stack guest; %s", n, why)
}

// guestExtrasLine is what the stack guest's mode line adds for its sidecars
// and the identity pair id, which may be nil. It names each sidecar's log
// source, quoted, because the sidecar's output carries the app's source, so
// the mode line is where an operator sees which sidecars the guest runs. It
// adds nothing for a guest with neither, so that guest's line stays as it
// was.
func guestExtrasLine(sidecars []vmSidecar, id *instanceIdentity) string {
	var b strings.Builder
	sources := make([]string, len(sidecars))
	for i, sc := range sidecars {
		sources[i] = fmt.Sprintf("%q", sc.LogSource)
	}
	switch n := len(sidecars); {
	case n == 1:
		fmt.Fprintf(&b, "; 1 sidecar runs beside the app, with the log source %s", sources[0])
	case n > 1:
		fmt.Fprintf(&b, "; %d sidecars run beside the app, with the log sources %s", n, joinNames(sources, ""))
	}
	if id != nil {
		fmt.Fprintf(&b, "; the instance identity has serial %s and expires %s", id.serial, id.notAfter.UTC().Format(time.RFC3339))
	}
	return b.String()
}

// sidecarGuestFilesOf returns the guest files of each sidecar, in order,
// with deny as the denylist of their environment files. It returns nil for
// an app without sidecars.
func sidecarGuestFilesOf(sidecars []vmSidecar, deny map[string]bool) ([]guestSidecar, error) {
	if len(sidecars) == 0 {
		return nil, nil
	}
	files := make([]guestSidecar, 0, len(sidecars))
	for i, sc := range sidecars {
		argv, env, err := sidecarGuestFiles(sc, deny)
		if err != nil {
			// The guest numbers the sidecars from 1, because the app is 0.
			return nil, fmt.Errorf("sidecar %d: %w", i+1, err)
		}
		files = append(files, guestSidecar{argv: argv, env: env})
	}
	return files, nil
}

// buildGuestInitramfs is newInitramfs. Specs replace it to see the guest
// that run builds.
var buildGuestInitramfs = newInitramfs

// credWatchInterval is how often the identity watcher looks at the pair.
// Specs shorten it.
var credWatchInterval = 5 * time.Second

// watchIdentity wires a credWatcher for the pair at certPath and keyPath
// into sup. sent is the pair the guest boots with. The watcher starts once
// the supervisor hands over the console writer, which it does after the
// guest has started its command, pushes every new pair as credFrames through
// that writer, and hears the guest's acknowledgements through the serial
// filter. The returned function stops the watcher and waits for it, and it
// must be called once sup.run has returned.
func watchIdentity(sup *supervisor, nonce, certPath, keyPath string, sent *instanceIdentity, logger *log.Logger) (stop func()) {
	var console *consoleWriter
	var w *credWatcher
	// The watcher calls push only from its own goroutine, with its lock
	// held, so push can read the number of the pair it sends from the
	// watcher. A second try keeps the number, which is how the guest's
	// answer finds its push.
	w = newCredWatcher(certPath, keyPath, sent, credWatchInterval, func(id *instanceIdentity) error {
		return console.push(credFrames(nonce, w.seq, id))
	}, logger)
	sup.credAck = w.acked
	quit := make(chan struct{})
	var done chan struct{}
	// The supervisor calls onConsole from its own loop, which must not
	// block, so the watcher runs in a goroutine of its own. console is set
	// before that goroutine starts, so the watcher always sees it.
	sup.onConsole = func(c *consoleWriter) {
		console = c
		done = make(chan struct{})
		go func() {
			defer close(done)
			w.run(quit)
		}()
	}
	return func() {
		close(quit)
		if done != nil {
			<-done
		}
	}
}

// closeFile closes f, when it is set, and logs a failure as closing what.
func closeFile(f *os.File, what string, logger *log.Logger) {
	if f == nil {
		return
	}
	if err := f.Close(); err != nil {
		logger.Printf("closing %s: %v", what, err)
	}
}

// newHypervisorCmd returns the hypervisor command: an empty environment,
// vm-launch's stderr, and SIGKILL when vm-launch dies. files, from
// hypervisorFiles, become the child's file descriptors from firstExtraFD on.
// Each volume image shares vm-launch's open file and with it the flock, so
// the lock lasts while either process lives.
func newHypervisorCmd(argv []string, files []*os.File) *exec.Cmd {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{}
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if len(files) > 0 {
		// ExtraFiles[i] is the child's file descriptor firstExtraFD+i.
		cmd.ExtraFiles = files
	}
	return cmd
}

// portConflictMessage explains a PORT that the guest cannot be given: only one
// VM per container can serve it.
func portConflictMessage(port int) string {
	return fmt.Sprintf("port %d already in use in this container; VM backends run one app process per container", port)
}

func parseArgs(argv []string) (config, error) {
	fs := flag.NewFlagSet("vm-launch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	kind := fs.String("backend", "", "VM backend: vm-qemu or vm-firecracker")
	artifacts := fs.String("artifacts", defaultArtifactsDir, "directory holding the kernel, hypervisor, and busybox")
	transparent := fs.Bool(transparentProxyFlag, false, "dial the Firecracker guest from each client's address, which takes CAP_NET_RAW")
	allowShares := fs.Bool(allowVolumeSharesFlag, false, "allow an app to ask for a volume as a share in VM_VOLUMES, which only QEMU can serve")
	virtiofsd := fs.String(virtiofsdFlag, "", "path of the executable that runs virtiofsd, which serves shares")
	syncMounts := fs.Bool(volumeSyncMountsFlag, true, "mount every volume image with sync and dirsync; with =false, an image whose filesystem has a journal mounts without them")
	if err := fs.Parse(argv); err != nil {
		return config{}, err
	}

	cfg := config{backend: backend.Kind(*kind), transparent: *transparent, allowVolumeShares: *allowShares, volumeSyncMounts: *syncMounts}
	virtiofsdSet := false
	fs.Visit(func(f *flag.Flag) { virtiofsdSet = virtiofsdSet || f.Name == virtiofsdFlag })
	if virtiofsdSet {
		if *virtiofsd == "" {
			return config{}, fmt.Errorf("--%s must not be empty", virtiofsdFlag)
		}
		abs, err := filepath.Abs(*virtiofsd)
		if err != nil {
			return config{}, fmt.Errorf("resolving --%s: %w", virtiofsdFlag, err)
		}
		cfg.virtiofsd = abs
	}
	if _, err := requiredArtifacts(cfg.backend); err != nil {
		return config{}, err
	}
	if cfg.transparent && cfg.backend != backend.VMFirecracker {
		return config{}, fmt.Errorf("--%s is for vm-firecracker only, whose port proxy dials the guest", transparentProxyFlag)
	}
	if *artifacts == "" {
		return config{}, errors.New("--artifacts must not be empty")
	}
	abs, err := filepath.Abs(*artifacts)
	if err != nil {
		return config{}, fmt.Errorf("resolving --artifacts: %w", err)
	}
	cfg.artifacts = abs

	cfg.args = fs.Args()
	cfg.command, cfg.credhub, err = guestCommand(cfg.args)
	if errors.Is(err, errEmptyStartCommand) {
		// The stack guest's launcher takes the start command from the
		// droplet, so the refusal waits until run knows the guest. The
		// launcher's CredHub flags still parse here.
		cfg.commandErr = err
		_, cfg.credhub, err = stackCommand(cfg.args)
	}
	if err != nil {
		return config{}, err
	}
	return cfg, nil
}

// maxGuestCommandBytes caps the guest command. The guest runs it as the
// argument of sh -c (see guestRunCommand), and Linux limits one argument to
// 128 KiB including its NUL.
const maxGuestCommandBytes = 128<<10 - 1

// guestCommand returns the shell command the guest runs for the wrapped
// process argv, and the CredHub retry settings: the launcher's CredHub flags
// for the CF launcher, and the launcher's defaults for any other command. A
// command over maxGuestCommandBytes is an error, because the guest could not
// start it.
func guestCommand(args []string) (string, credhubRetry, error) {
	command, retry, err := wrappedCommand(args)
	if err != nil {
		return "", credhubRetry{}, err
	}
	if len(command) > maxGuestCommandBytes {
		return "", credhubRetry{}, fmt.Errorf("the guest command is %d bytes, over the %d bytes a guest can run as one shell argument", len(command), maxGuestCommandBytes)
	}
	return command, retry, nil
}

// errEmptyStartCommand is wrappedCommand's refusal of a CF launcher argv
// whose start command is empty, which only the stack guest can run.
var errEmptyStartCommand = errors.New("empty start command: VM backends need an explicit command because the droplet's detected start command is not available in the guest")

// wrappedCommand returns the shell command and the CredHub retry settings
// for the wrapped process argv (see guestCommand).
func wrappedCommand(args []string) (string, credhubRetry, error) {
	if len(args) == 0 {
		return "", credhubRetry{}, errors.New("no guest command given after --")
	}
	if !isLauncher(args) {
		return shellJoin(args), defaultCredhubRetry, nil
	}
	// The CF launcher takes APP-DIR START-COMMAND METADATA. An empty start
	// command means "use the droplet's detected one", which lives in the
	// droplet and is not available in the guest.
	if len(args) < 3 {
		return "", credhubRetry{}, fmt.Errorf("launcher argv has %d arguments, want APP-DIR START-COMMAND [METADATA]", len(args)-1)
	}
	if strings.TrimSpace(args[2]) == "" {
		return "", credhubRetry{}, errEmptyStartCommand
	}
	// The launcher parses its CredHub flags from the arguments after
	// START-COMMAND, as vm-launch does here.
	retry, err := credhubRetryFromArgs(args[3:])
	if err != nil {
		return "", credhubRetry{}, err
	}
	return args[2], retry, nil
}

// stackLauncherPath is where the guest has the CF launcher in stack mode.
const stackLauncherPath = "/tmp/lifecycle/launcher"

// stackCommand returns the argv the guest's launcher runs in stack mode,
// quoted for POSIX sh with shellJoin, and the CredHub retry settings from the
// launcher's flags. Unlike wrappedCommand, it hands the launcher the whole
// argv, because the guest has the droplet and so the launcher can detect the
// start command itself. The start command may therefore be empty. The argv
// starts with stackLauncherPath in place of the host's path to the launcher.
func stackCommand(args []string) (argv string, retry credhubRetry, err error) {
	if !isLauncher(args) {
		return "", credhubRetry{}, errors.New("stack mode needs the CF launcher as the wrapped process")
	}
	if len(args) < 3 {
		return "", credhubRetry{}, fmt.Errorf("launcher argv has %d arguments, want APP-DIR START-COMMAND [METADATA]", len(args)-1)
	}
	retry, err = credhubRetryFromArgs(args[3:])
	if err != nil {
		return "", credhubRetry{}, err
	}
	return shellJoin(append([]string{stackLauncherPath}, args[1:]...)), retry, nil
}

// isLauncher reports whether args is the CF launcher's argv.
func isLauncher(args []string) bool {
	return len(args) > 0 && filepath.Base(args[0]) == "launcher"
}

// stackCandidate returns the open stack image when the wrapped process argv
// args is the CF launcher's and Garden bound a usable image (see
// openStackImage), or no file and the reason the guest is the busybox guest.
// The caller owns the returned file.
func stackCandidate(args []string) (*os.File, string) {
	if !isLauncher(args) {
		return nil, "the process is not the CF launcher"
	}
	return openStackImage()
}

// Where vm-launch reads what the stack guest gets from the container. They
// are variables so that specs can point them elsewhere.
var (
	// dropletHome is the app's home directory, which holds the droplet and
	// which the droplet image packs.
	dropletHome = "/home/vcap"
	// containerHostsPath is the container's hosts file, which Garden writes
	// and which the stack guest gets in place of the stack's.
	containerHostsPath = "/etc/hosts"
	// containerHostname returns the container's hostname, which Garden sets
	// to the container's handle and which the stack guest takes as its own.
	containerHostname = os.Hostname
)

// newGuestStack gathers what the stack guest's initramfs holds for the CF
// launcher argv args: the launcher itself, opened and checked as a guest
// tool is, its whole argv from stackCommand, vm-launch's working directory,
// which Garden set to the app's home, and the container's hostname and hosts
// file. It checks the result as newInitramfs will, so that a launcher argv
// over the guest's limit fails before any drive exists. The caller closes the
// launcher.
func newGuestStack(args []string) (*guestStack, error) {
	// The retry settings are the ones parseArgs took from the same flags.
	argv, _, err := stackCommand(args)
	if err != nil {
		return nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("reading the app's working directory for the stack guest: %w", err)
	}
	hostname, err := containerHostname()
	if err != nil {
		return nil, fmt.Errorf("reading the container's hostname for the stack guest: %w", err)
	}
	hosts, err := os.ReadFile(containerHostsPath)
	if err != nil {
		return nil, fmt.Errorf("reading the container's hosts file for the stack guest: %w", err)
	}
	dir, err := filepath.Abs(filepath.Dir(args[0]))
	if err != nil {
		return nil, fmt.Errorf("resolving the launcher's directory: %w", err)
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving the launcher's directory %s: %w", dir, err)
	}
	// The launcher is not one of the guest filesystem tools, so the hint
	// about their artifact does not apply to it.
	launcher, err := openGuestTool(dir, realDir, filepath.Base(args[0]))
	if err != nil {
		return nil, errors.New(strings.TrimSuffix(err.Error(), noGuestToolsHint))
	}
	s := &guestStack{launcher: launcher, argv: argv, cwd: cwd, hostname: hostname, hosts: hosts}
	if err := s.check(0); err != nil {
		launcher.file.Close()
		return nil, err
	}
	return s, nil
}

// workDirStatfs is the statfs that sizes the guest root image from the
// quota left in the work directory. Specs replace it to see what vm-launch
// holds at that moment.
var workDirStatfs = unix.Statfs

// guestNonce returns the nonce of one launch's console markers. Specs
// replace it to compare two launches' initramfs archives byte for byte.
var guestNonce = newNonce

// shellJoin quotes each argument for POSIX sh and joins them with spaces.
func shellJoin(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = shellQuote(a)
	}
	return strings.Join(quoted, " ")
}

func newNonce() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating marker nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func signalNumber(sig os.Signal) int {
	if s, ok := sig.(syscall.Signal); ok {
		return int(s)
	}
	return int(syscall.SIGTERM)
}

// oomMessage is the line vm-launch writes when the guest kernel killed
// processes for lack of memory. Guardian watches the stderr of the vm-launch
// it starts for a line that begins with oomLinePrefix, after the logger's own
// prefix, and records an out-of-memory event for the container, so that Diego
// reports the exit as it does for a container killed by its cgroup. The
// wording after the prefix is for people.
func oomMessage(kills, memMiB int) string {
	noun := "processes"
	if kills == 1 {
		noun = "process"
	}
	return fmt.Sprintf("%s: its kernel killed %d %s; the guest has %d MiB", oomLinePrefix, kills, noun, memMiB)
}

// exitCode maps a guest run to vm-launch's exit status. reason is empty when
// the status is the guest command's own.
func exitCode(r runResult) (code int, reason string) {
	switch {
	case r.markerFound:
		return r.guestStatus, ""
	case r.received != 0:
		return 128 + int(r.received), fmt.Sprintf("stopped by %v before the guest reported a status", r.received)
	case r.state == nil:
		return exitHypervisorFailed, "hypervisor state unknown"
	}
	if ws, ok := r.state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), fmt.Sprintf("hypervisor died from %v before the guest reported a status", ws.Signal())
	}
	if r.state.ExitCode() != 0 {
		return exitHypervisorFailed, fmt.Sprintf("hypervisor failed with exit status %d before the guest reported a status", r.state.ExitCode())
	}
	return exitMissingMarker, "guest ended without reporting a status"
}
