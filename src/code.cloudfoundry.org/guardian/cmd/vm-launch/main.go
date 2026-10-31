//go:build linux

// Command vm-launch runs one shell command inside a short-lived QEMU microvm
// or Firecracker guest and makes the command's console output and exit status
// its own. Garden runs it inside the app's container in place of the CF
// launcher, with /dev/kvm and the read-only VM artifacts mounted in.
//
// Usage:
//
//	vm-launch --backend vm-qemu|vm-firecracker [--transparent-proxy] [--artifacts DIR] -- PATH [ARGS...]
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
// images. A task has neither CF_INSTANCE_INDEX nor process_type, and a task
// that has a volume fails to start. vm-launch creates a missing image under
// a temporary name, as a sparse 1 GiB file with mode 0600, and publishes it
// with renameat2(RENAME_NOREPLACE) once it is sized, so the image name never
// refers to an unsized file. A launch that is killed leaves at worst a
// .rvm-disk-*.tmp file, which nothing reads but which holds up to 1 GiB of
// quota until an operator deletes it, because a quota that counts file
// length, as JuiceFS does, charges a new image its whole size. On an NFS
// volume, whose client refuses renameat2 with a flag, vm-launch allocates
// the image, publishes it with a hard link instead, and removes the temporary
// name, and the next launch removes a temporary name that a killed launch
// left. It sizes only
// an image it creates: an existing image that is not exactly 1 GiB fails the
// launch. The volume path and the image are resolved without following
// symbolic links, the volume path must be a mount point, and the image must
// be a regular file owned by the app's uid, with one link and mode 0600.
// vm-launch never reads the image. It holds an exclusive flock on the image
// for as long as the VM runs, waiting up to 30 seconds in all, over every
// volume, for another instance to release it, checks after the wait that the name still refers to the
// locked file, and passes the image to the hypervisor as file descriptor 3.
// With more than one volume, the volumes are taken in the byte order of
// their paths, and each one's image gets the next file descriptor and the
// next drive, vol0 to vol3, so that the order never depends on the order of
// VCAP_SERVICES. vm-launch prepares them in that order and, when one fails,
// releases every one it prepared before it. Two volumes that show one
// directory of one filesystem, so that their images would be one file, fail
// the launch, as does a volume whose image is the file another volume already
// holds, which vm-launch refuses before it waits for the lock. The guest finds the image by its size, which no guest root
// image shares, formats it as ext2 when its first 64 KiB are all zero, and
// mounts it synchronously; a non-blank image that does not mount is never
// formatted. Every volume image has the same size, so a guest with more than
// one volume finds two drives of that size and fails its boot before it
// formats anything. Each volume must be a JuiceFS or NFS mount. Cloud
// Controller strips the driver name from volume_mounts, so vm-launch reads the
// filesystem type of the mount at each volume path from /proc/self/mountinfo
// and lets the registry of volume providers (see pdi.go) pick the provider
// that owns it. JuiceFS owns fuse.juicefs, and NFS owns nfs4 mounted with
// local_lock=none. Any other type, an NFSv3 or mapfs mount, or a path with no
// mount entry fails the launch with exit 125 before anything boots.
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
// SERVICE_BINDING_ROOT, VCAP_SERVICES_FILE_PATH, VCAP_PLATFORM_OPTIONS, or a
// name that starts with __GARDEN_. It also never gets the variables that its
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
// filesystem fills before the quota does; it is 1 MiB smaller when that would
// equal the volume image's size. The hypervisor gets it as the last drive,
// after the volume images' and with discard turned on, so that the blocks the
// guest frees go back to the quota. When less than 16 MiB is left after the
// 32 MiB, or the image cannot be created, vm-launch exits 125 with a line
// that says why. A missing or malformed limits.disk leaves the guest root in
// RAM, with a line that says the disk quota does not apply to it.
//
// The guest's /init finds the image by its size in sectors, which vm-launch
// writes in the initramfs, formats it as ext2 with online discard, and
// mounts an overlay with the initramfs as its lower layer and the image as
// its upper. It moves /proc, /sys, and /dev into the overlay, moves the
// overlay onto /, and runs the rest of its setup and the command inside it,
// so everything the guest writes outside /dev and the volume lands on
// the image and counts against the quota. Every boot formats a fresh image,
// as every start of a runc app gets a fresh container. /init formats only
// the one device of the image's size, and only when it reads as blank, so
// it never formats the volume; when it cannot find, check, format, or mount
// the image, the guest reboots before it starts the command, and vm-launch
// exits 123 with the console output, which ends with the step that failed.
//
// The initramfs that holds the guest's /init, busybox, command, and
// environment is built in a sealed memfd and never written to disk. The
// hypervisor gets it as the file descriptor after the volume images', 3
// without a volume, 4 with one, and 7 with four, and vm-launch closes its
// own copy once the hypervisor has started. A QEMU monitor socket comes
// next, and the guest root image last, so the image is file descriptor 4
// without a volume or a monitor and 6 with one volume and a monitor;
// vm-launch closes its copy of it, too, once the hypervisor has started.
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
//	0-255  the guest command's exit status
//	123    the hypervisor exited cleanly, but the guest never reported a status,
//	       as when the guest cannot find, format, or mount the volume image
//	       or the guest root image
//	124    the hypervisor failed: it exited non-zero before the guest reported a
//	       status, as QEMU does when it cannot open the volume image
//	125    vm-launch could not start the guest: core dumps it could not
//	       disable, a dumpable flag it could not clear, an open files
//	       limit it could not read, bad arguments, a guest command over
//	       131071 bytes, a missing artifact, a work
//	       file, initramfs, guest root image, or QMP socket it could not
//	       create, a disk quota too small for the guest root image or
//	       that it could not read, a
//	       hypervisor it could not run, PORT already in use in the
//	       container, or a volume it cannot use:
//	       VCAP_SERVICES that is not valid JSON, more than four volume
//	       mounts, two volume mounts on one path, two volumes that share a
//	       directory, a read-only mount, a bad volume path,
//	       CF_INSTANCE_INDEX, application_id, or process_type, a task with
//	       a volume, an image that fails a check or cannot be created,
//	       volume images of different sizes, or
//	       an image another instance still holds after 30 seconds, a
//	       guest environment that is too large, with one entry over
//	       131071 bytes or more than 1 MiB in all, or a value that holds a
//	       NUL byte, trusted certificates over 2 MiB, VCAP_PLATFORM_OPTIONS
//	       that is not valid JSON, a bad launcher CredHub flag, or CredHub
//	       references that cannot be resolved: missing or unreadable
//	       instance identity or CA files, a credhub-uri that is not an
//	       https URL, or every attempt failing
//	128+N  vm-launch received signal N (SIGTERM or SIGINT), or the hypervisor
//	       died from signal N, before the guest reported a status; this
//	       includes a signal while vm-launch waits for the volume image or
//	       resolves CredHub references, and a guest command that did not
//	       stop within 8 seconds of the signal
//
// A guest command can exit with any of these values itself; whenever vm-launch
// picks the status, it also writes a "vm-launch:" line to stderr.
//
// When the guest kernel killed any process for lack of memory, whatever the
// exit status, vm-launch writes the stderr line "vm-launch: the guest ran out
// of memory: its kernel killed N processes; the guest has M MiB" before it
// exits. Guardian reads that line to report an out-of-memory exit.
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
// line, for every guest size vm-launch allows.
const stopDeadline = 8 * time.Second

const usage = "usage: vm-launch --backend vm-qemu|vm-firecracker [--transparent-proxy] [--artifacts DIR] -- PATH [ARGS...]\n"

type config struct {
	backend   backend.Kind
	artifacts string
	command   string
	credhub   credhubRetry
	// transparent makes the Firecracker port proxy dial the guest from its
	// clients' addresses (see transparentSource).
	transparent bool
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
	if err := checkArtifacts(cfg.backend, cfg.artifacts); err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	// Every reader sees the same environment, so the volume and the guest
	// can never disagree about VCAP_SERVICES. All of this happens before the
	// work directory and the volume lock, so a bad environment exits before
	// any image is opened or created.
	env := lastWinsEnv(os.Environ(), logger)
	lookupEnv := lookupIn(env)
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
	var selected []selectedVolume
	if err == nil && len(vols) > 0 {
		selected, err = findVolumeProviders(mountInfoPath, vols)
	}
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
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
	// SSL_CERT_FILE points a TLS library whose own default path is not
	// guestCABundlePath, such as a static OpenSSL build, at the bundle. A
	// value the app set itself stays.
	if _, ok := env[sslCertFileEnv]; !ok && caBundle != nil {
		env[sslCertFileEnv] = guestCABundlePath
	}
	envFile, err := buildGuestEnv(env, memMiB, logger)
	if err != nil {
		logger.Print(err)
		return exitLaunchError
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

	nonce, err := newNonce()
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
	// The guest's /init finds a volume's drive by its size, and /rvm/disks
	// gives one size, the first volume's. With more than one volume of that
	// size, /init sees two drives of the size and fails the boot before it
	// formats anything. A volume of another size would instead be left
	// unmounted while the app wrote to the guest root, so it is refused.
	var vol *guestVolume
	var volumeBytes int64
	if len(prepared) > 0 {
		vol, volumeBytes = &vols[0], prepared[0].Bytes
		for _, v := range prepared[1:] {
			if v.Bytes != volumeBytes {
				logger.Printf("the volume images at %s and %s are %d and %d bytes; the guest finds its volumes by size, so every volume image must have the first one's size",
					quoteForLog(prepared[0].Path), quoteForLog(v.Path), volumeBytes, v.Bytes)
				return exitLaunchError
			}
		}
	}

	// The guest root image is sized from the quota the work directory has
	// left. rootDiskSize keeps its size from equalling the volume image's,
	// which is how the guest tells the two drives apart.
	rootSize, rootInodeRatio, err := rootDiskSize(workDir, lookupEnv, unix.Statfs, volumeBytes, logger)
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
	}
	defer closeInherited()
	if rootSize > 0 {
		rootImg, err = createRootImage(workDir, rootSize)
		if err != nil {
			logger.Print(err)
			return exitLaunchError
		}
	}

	initrd, err = newInitramfs(filepath.Join(cfg.artifacts, artBusybox), guestContents{
		command:        cfg.command,
		nonce:          nonce,
		nw:             nw,
		env:            envFile,
		vol:            vol,
		volumeBytes:    volumeBytes,
		caBundle:       caBundle,
		nofile:         nofile,
		rootBytes:      rootSize,
		rootInodeRatio: rootInodeRatio,
	})
	if err != nil {
		logger.Print(err)
		return exitLaunchError
	}
	// QEMU forwards the ports through rules that vm-launch adds and removes
	// on its QMP monitor.
	var monitor net.Conn
	if len(nw.ports) > 0 && cfg.backend == backend.VMQemu {
		monitor, qemuMonitor, err = newQMPSocket()
		if err != nil {
			logger.Print(err)
			return exitLaunchError
		}
		defer monitor.Close()
	}
	files, drivePaths, initrdPath, monitorFD, rootPath := hypervisorFiles(prepared.files(), initrd, qemuMonitor, rootImg)
	hvArgv, err := hypervisorArgv(cfg.backend, cfg.artifacts, workDir, initrdPath, memMiB, nw, drivePaths, rootPath, monitorFD)
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

	cmd := newHypervisorCmd(hvArgv, files)
	sup := supervisor{stdout: os.Stdout, logger: logger, signals: sigs, grace: killGrace, deadline: stopDeadline, started: closeInherited}
	// Firecracker starts without a capability whether or not vm-launch was
	// given --transparent-proxy, so a grant that reaches vm-launch some other
	// way never reaches the hypervisor.
	if cfg.backend == backend.VMFirecracker {
		sup.prepare = confinedPrepare(cmd)
	}
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
			qmp := newQMPMonitor(monitor)
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
		sup.closePorts = gates.shutDown
		sup.listen = gates.set
	}
	res, err := sup.run(cmd, nonce)
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
	if reason != "" {
		logger.Printf("%s; exiting %d", reason, code)
	}
	return code
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
	if err := fs.Parse(argv); err != nil {
		return config{}, err
	}

	cfg := config{backend: backend.Kind(*kind), transparent: *transparent}
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

	cfg.command, cfg.credhub, err = guestCommand(fs.Args())
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

// wrappedCommand returns the shell command and the CredHub retry settings
// for the wrapped process argv (see guestCommand).
func wrappedCommand(args []string) (string, credhubRetry, error) {
	if len(args) == 0 {
		return "", credhubRetry{}, errors.New("no guest command given after --")
	}
	if filepath.Base(args[0]) != "launcher" {
		return shellJoin(args), defaultCredhubRetry, nil
	}
	// The CF launcher takes APP-DIR START-COMMAND METADATA. An empty start
	// command means "use the droplet's detected one", which lives in the
	// droplet and is not available in the guest.
	if len(args) < 3 {
		return "", credhubRetry{}, fmt.Errorf("launcher argv has %d arguments, want APP-DIR START-COMMAND [METADATA]", len(args)-1)
	}
	if strings.TrimSpace(args[2]) == "" {
		return "", credhubRetry{}, errors.New("empty start command: VM backends need an explicit command because the droplet's detected start command is not available in the guest")
	}
	// The launcher parses its CredHub flags from the arguments after
	// START-COMMAND, as vm-launch does here.
	retry, err := credhubRetryFromArgs(args[3:])
	if err != nil {
		return "", credhubRetry{}, err
	}
	return args[2], retry, nil
}

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
