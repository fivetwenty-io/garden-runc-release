//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// A share (see pdi_share.go) is served by one virtiofsd per shared volume.
// vm-launch starts each virtiofsd as a sibling of QEMU inside the app's
// container, so it runs as the app's user, sees exactly the bind mount the
// app would see, and is charged to the app's cgroup. It starts from an OS
// thread that has set no_new_privs and dropped every capability (see
// confineVirtiofsd and startConfinedAs), so virtiofsd holds no capability,
// and no exec on the way to it can grant one. It runs with --sandbox=none,
// because the namespace sandbox needs a user namespace and the chroot
// sandbox needs root, so the container is the sandbox.
//
// QEMU gets a vhost-user-fs device for each share's socket, and the guest
// mounts each share by its tag (see qemuArgv and guestVolumeSetup).
//
// vm-launch binds a listening Unix socket for each share in its private work
// directory and hands it to virtiofsd as file descriptor 3 with --fd=3, so
// the socket's path and owner are vm-launch's choice and no other process
// can bind it first. QEMU connects to that path. Once virtiofsd has started,
// vm-launch closes its own copy of the socket, so a virtiofsd that has died
// leaves no listener behind and QEMU's connect fails at once rather than
// waiting for a reply that never comes.
//
// virtiofsd has no readiness notice of its own when it gets its socket with
// --fd, so vm-launch reads virtiofsd's log, which goes to its stderr at the
// default info level, and takes the line virtiofsd writes once it is about to
// accept its client (virtiofsdReadyText) as ready. vm-launch boots the guest
// only once every virtiofsd is ready. Every log line is passed on to
// vm-launch's stderr with the share's path in front of it.
//
// Neither QEMU nor any virtiofsd outlives the other:
//
//   - A virtiofsd that ends before QEMU has been reaped stops the guest.
//     virtiofsd exits with status 0 when its client disconnects, which QEMU
//     does as it exits, so an end with status 0 gives QEMU
//     virtiofsdDisconnectGrace to exit on its own before vm-launch kills it.
//     Any other end kills QEMU at once. Unless the guest had already
//     reported its command's status, which comes after the guest has flushed
//     and unmounted its volumes, vm-launch then exits 125 with a line that
//     names the share, so Diego starts the instance again.
//   - The supervisor tells the share servers the moment it reaps QEMU (see
//     hypervisorReaped), before it flushes the guest's last output, so a
//     virtiofsd that exits 0 at the disconnect is never taken for a failure
//     while that flush runs. From then on, each virtiofsd gets
//     virtiofsdStopGrace to see the disconnect and exit, and then SIGKILL.
//     virtiofsd holds no data of its own, because every write the guest made
//     has already reached the host file through a system call, so SIGKILL
//     loses nothing.
//   - A launch that fails before QEMU starts, as when a second virtiofsd
//     cannot start or does not become ready in time, kills every virtiofsd
//     it started, at once.
//   - Each virtiofsd gets SIGKILL as its parent death signal, so one that
//     vm-launch never reaps, because vm-launch itself was killed, dies too.
//
// After the first SIGTERM the guest drains within the 8 second stop
// deadline, during which virtiofsd keeps serving it. Stopping every
// virtiofsd then takes at most virtiofsdStopGrace plus virtiofsdKillWait,
// one second for all of them together, the wait for their last log lines
// included. That stop starts when QEMU is reaped and runs beside the flush
// of the guest's last output, which outputFlushTimeout bounds to the same
// second, so the two together take one of the 2 seconds that stopDeadline
// leaves before Diego's SIGKILL.

// virtiofsdFlag names the vm-launch flag that gives the path of the
// executable that runs virtiofsd. Without it, a granted share fails the
// launch. vm-launch runs inside the app's container, so the path is the one
// the container sees. On a cell it is
// /opt/garden-vm/artifacts/virtiofsd/virtiofsd-wrapper, the wrapper that the
// virtiofsd install puts under the host's artifacts directory,
// /var/vcap/data/vm-runtime/artifacts, which Garden binds read-only at
// /opt/garden-vm/artifacts. The wrapper runs virtiofsd 1.13 through its
// bundled loader, because the app's rootfs may have an older C library.
// vm-launch passes the wrapper virtiofsd's own arguments, and the wrapper
// must pass them, and descriptor 3, on unchanged.
const virtiofsdFlag = "virtiofsd-path"

// virtiofsdListenFD is the file descriptor virtiofsd gets its listening
// socket on: the first descriptor after stdin, stdout, and stderr.
const virtiofsdListenFD = 3

// virtiofsdReadyText is in the line virtiofsd 1.13 writes, at info level,
// when it has opened the shared directory, entered its seccomp filter, and
// is about to accept its client on the socket.
const virtiofsdReadyText = "Waiting for vhost-user socket connection"

// Timing of the virtiofsd lifecycle. Specs shorten them. newShareServers
// takes a copy, which the goroutines of the launch read.
var (
	// virtiofsdReadyTimeout bounds the wait for every virtiofsd of a launch
	// to become ready, all of them together.
	virtiofsdReadyTimeout = 5 * time.Second
	// virtiofsdDisconnectGrace is how long QEMU may keep running after a
	// virtiofsd ended with status 0 before vm-launch kills it.
	virtiofsdDisconnectGrace = time.Second
	// virtiofsdStopGrace is how long a virtiofsd may keep running after QEMU
	// has been reaped before vm-launch sends it SIGKILL.
	virtiofsdStopGrace = 500 * time.Millisecond
	// virtiofsdKillWait is how long vm-launch waits after SIGKILL for every
	// virtiofsd to end and for their last log lines, all of it together. A
	// virtiofsd stuck in I/O on a store that has gone away ends only when
	// the I/O returns, and vm-launch does not wait for that.
	virtiofsdKillWait = 500 * time.Millisecond
)

// Bounds on the virtiofsd log that vm-launch passes on. Past
// maxVirtiofsdLogLines, vm-launch keeps only the latest
// maxVirtiofsdTailLines lines and passes them on when the log ends, because
// the line that says why virtiofsd ended is among its last.
const (
	maxVirtiofsdLineBytes = 4096
	maxVirtiofsdLogLines  = 200
	maxVirtiofsdTailLines = 20
)

// maxSocketPathBytes is the longest path a Unix socket address holds with
// its terminating NUL, which QEMU needs.
const maxSocketPathBytes = len(unix.RawSockaddrUnix{}.Path) - 1

// shareSocket is what QEMU needs to reach the virtiofsd of one share.
type shareSocket struct {
	// Index is the volume index of the share (see shareGrant.Index).
	Index int
	// Tag is the virtiofs tag the guest mounts the share by.
	Tag string
	// Path is the path of the vhost-user socket that virtiofsd serves.
	Path string
}

// checkVirtiofsd makes sure, before anything else of the launch happens, that
// vm-launch can serve the grants it holds: that it was given --virtiofsd-path
// and that the path is an executable regular file. Without a grant, neither
// the flag nor the file is needed.
func checkVirtiofsd(path string, grants []shareGrant) error {
	if len(grants) == 0 {
		return nil
	}
	if path == "" {
		return fmt.Errorf("%s %s is granted a share, but vm-launch was not given --%s, so nothing can serve it; the operator must install virtiofsd and pass its path",
			volumeSettingsEnv, quoteForLog(grants[0].Path), virtiofsdFlag)
	}
	info, err := os.Stat(path)
	switch {
	case err != nil:
		return fmt.Errorf("virtiofsd for shares: %w", err)
	case !info.Mode().IsRegular():
		return fmt.Errorf("virtiofsd for shares: %s is not a regular file", quoteForLog(path))
	case info.Mode().Perm()&0o111 == 0:
		return fmt.Errorf("virtiofsd for shares: %s is not executable", quoteForLog(path))
	}
	return nil
}

// virtiofsdArgv returns the command line of the virtiofsd at path that serves
// sharedDir on virtiofsdListenFD. --cache=auto lets a change that another
// instance makes show up within a second. --inode-file-handles=never keeps
// virtiofsd from file handles, which need CAP_DAC_READ_SEARCH.
// --seccomp=kill stacks virtiofsd's own filter on Garden's. --sandbox=none
// keeps virtiofsd from namespaces, which an unprivileged virtiofsd cannot
// create.
func virtiofsdArgv(path, sharedDir string) []string {
	return []string{
		path,
		fmt.Sprintf("--fd=%d", virtiofsdListenFD),
		"--sandbox=none",
		"--seccomp=kill",
		"--cache=auto",
		"--inode-file-handles=never",
		"--shared-dir=" + sharedDir,
	}
}

// shareSocketName is the name of the socket of the share with tag in the work
// directory.
func shareSocketName(tag string) string { return tag + ".sock" }

// listenShareSocket binds and listens on a Unix socket at path and returns
// it as a file in blocking mode, which virtiofsd needs: it accepts on the
// descriptor without polling it first. The descriptor is close-on-exec, so
// only the process it is handed to explicitly inherits it.
func listenShareSocket(path string) (*os.File, error) {
	if len(path) > maxSocketPathBytes {
		return nil, fmt.Errorf("the share socket path %s is %d bytes, over the %d a Unix socket path may have; TMPDIR is too long", quoteForLog(path), len(path), maxSocketPathBytes)
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("creating the share socket %s: %w", quoteForLog(path), os.NewSyscallError("socket", err))
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("binding the share socket %s: %w", quoteForLog(path), os.NewSyscallError("bind", err))
	}
	// QEMU is the one client.
	if err := unix.Listen(fd, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("listening on the share socket %s: %w", quoteForLog(path), os.NewSyscallError("listen", err))
	}
	return os.NewFile(uintptr(fd), path), nil
}

// checkShareMount opens the directory of g again, without following links,
// and refuses it unless it is still the root of the mount that
// findVolumeProvider inspected: the same mount ID, and in the mount table the
// same device numbers and the same root. virtiofsd opens the directory by
// path, so this is the last look vm-launch has at it before virtiofsd serves
// it, as openVolumeImage's second look is for an image.
func checkShareMount(g shareGrant) error {
	fd, err := openat2Retry(unix.AT_FDCWD, g.Path, &unix.OpenHow{
		// RESOLVE_NO_SYMLINKS refuses a link in any component, the last one
		// included, with ELOOP, as openVolumeImage's second look does.
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return fmt.Errorf("opening the share at %s: %w%s", quoteForLog(g.Path), err, symlinkHint(err))
	}
	defer unix.Close(fd)
	probe, err := dirProbe(fd, g.Path)
	if err != nil {
		return fmt.Errorf("checking the mount of the share at %s: %w", quoteForLog(g.Path), err)
	}
	if probe.MountID != g.Mount.MountID {
		return &volumeError{kind: errMountChanged,
			msg: fmt.Sprintf("the mount of the share at %s changed during start: it was mount ID %d when vm-launch inspected it and is mount ID %d now",
				quoteForLog(g.Path), g.Mount.MountID, probe.MountID)}
	}
	if !probe.MountRoot {
		return notMountRootError(quoteForLog(g.Path), nil)
	}
	now, err := volumeMount(mountInfoPath, g.Path, probe.MountID)
	if err != nil {
		return err
	}
	if now.Major != g.Mount.Major || now.Minor != g.Mount.Minor || now.Root != g.Mount.Root {
		return &volumeError{kind: errMountChanged,
			msg: fmt.Sprintf("the mount of the share at %s changed during start: mount ID %d showed device %d:%d and root %s when vm-launch inspected it and shows device %d:%d and root %s now",
				quoteForLog(g.Path), probe.MountID, g.Mount.Major, g.Mount.Minor, quoteForLog(g.Mount.Root), now.Major, now.Minor, quoteForLog(now.Root))}
	}
	return nil
}

// describeEnd says how a process ended, for a line.
func describeEnd(state *os.ProcessState, waitErr error) string {
	if state == nil {
		return fmt.Sprintf("ended, and waiting for it failed: %v", waitErr)
	}
	if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return fmt.Sprintf("died from %v", ws.Signal())
	}
	return fmt.Sprintf("exited with status %d", state.ExitCode())
}

// shareServer is the virtiofsd of one share.
type shareServer struct {
	grant      shareGrant
	socketPath string
	// listener is vm-launch's copy of the listening socket, until virtiofsd
	// has its own or the launch ends.
	listener *os.File
	// cmd is set once virtiofsd has started.
	cmd *exec.Cmd
	// ready is closed when virtiofsd has logged virtiofsdReadyText.
	ready chan struct{}
	// exited is closed once virtiofsd has been reaped, after state and
	// waitErr are set.
	exited  chan struct{}
	state   *os.ProcessState
	waitErr error
	// endedEarly is set, under shareServers.mu, when virtiofsd ended before
	// start armed the servers, so that arming handles that end.
	endedEarly bool
	// logDone is closed once virtiofsd's log has reached its end and its
	// held-back last lines have been passed on.
	logDone chan struct{}
}

// shareServers are the virtiofsd processes of one launch, one for each share
// in volume order, and the policy that ties their lives to QEMU's.
type shareServers struct {
	// path is the executable that --virtiofsd-path names.
	path    string
	logger  *log.Logger
	servers []*shareServer
	// The lifecycle's timing as the launch began (see virtiofsdReadyTimeout
	// and the rest), which the launch's goroutines read.
	readyTimeout    time.Duration
	disconnectGrace time.Duration
	stopGrace       time.Duration
	killWait        time.Duration

	mu sync.Mutex
	// armed is set once start has every virtiofsd ready. Before that, start
	// itself handles a virtiofsd that ends.
	armed bool
	// guest is QEMU, once it has started.
	guest *os.Process
	// guestReaped is set once QEMU has been reaped, or once run is past the
	// supervisor without a QEMU, and guestDone is closed then.
	guestReaped bool
	guestDone   chan struct{}
	// stopping is set once vm-launch stops the virtiofsd processes itself,
	// after which their ends are expected. stopped is closed then, and
	// stopDone once that stop has finished.
	stopping bool
	stopped  chan struct{}
	stopDone chan struct{}
	// failure is the first share whose virtiofsd ended while the guest
	// needed it, as the reason for the exit line, or empty.
	failure string
}

// newShareServers binds the socket of each grant in workDir. It starts no
// process; start does. On an error every socket it bound is closed, and
// workDir's removal removes their names.
func newShareServers(path, workDir string, grants []shareGrant, logger *log.Logger) (*shareServers, error) {
	s := &shareServers{
		path: path, logger: logger,
		readyTimeout: virtiofsdReadyTimeout, disconnectGrace: virtiofsdDisconnectGrace,
		stopGrace: virtiofsdStopGrace, killWait: virtiofsdKillWait,
		guestDone: make(chan struct{}), stopped: make(chan struct{}), stopDone: make(chan struct{}),
	}
	for _, g := range grants {
		path := filepath.Join(workDir, shareSocketName(g.Tag))
		l, err := listenShareSocket(path)
		if err != nil {
			s.closeListeners()
			return nil, err
		}
		s.servers = append(s.servers, &shareServer{grant: g, socketPath: path, listener: l,
			ready: make(chan struct{}), exited: make(chan struct{}), logDone: make(chan struct{})})
	}
	return s, nil
}

// sockets returns the socket of each share, in volume order, for QEMU's
// vhost-user devices.
func (s *shareServers) sockets() []shareSocket {
	out := make([]shareSocket, len(s.servers))
	for i, srv := range s.servers {
		out[i] = shareSocket{Index: srv.grant.Index, Tag: srv.grant.Tag, Path: srv.socketPath}
	}
	return out
}

// closeListeners closes vm-launch's copy of every socket it still holds.
func (s *shareServers) closeListeners() {
	for _, srv := range s.servers {
		srv.closeListener(s.logger)
	}
}

func (srv *shareServer) closeListener(logger *log.Logger) {
	if srv.listener == nil {
		return
	}
	if err := srv.listener.Close(); err != nil {
		logger.Printf("closing vm-launch's copy of the share socket %s: %v", quoteForLog(srv.socketPath), err)
	}
	srv.listener = nil
}

// start checks each share's mount again, starts its virtiofsd, and waits
// until it is ready, in volume order, all within the ready timeout. A
// SIGTERM or SIGINT on signals ends the wait. On any error, every virtiofsd
// that start started is killed and reaped before start returns, so the
// launch leaves none behind.
func (s *shareServers) start(signals <-chan os.Signal) error {
	if len(s.servers) == 0 {
		return nil
	}
	deadline := time.NewTimer(s.readyTimeout)
	defer deadline.Stop()
	for _, srv := range s.servers {
		if err := s.startOne(srv); err != nil {
			s.stop(0)
			return err
		}
		select {
		case <-srv.ready:
		case <-srv.exited:
			s.stop(0)
			return fmt.Errorf("virtiofsd for the share at %s %s before it was ready to serve the guest",
				quoteForLog(srv.grant.Path), describeEnd(srv.state, srv.waitErr))
		case <-deadline.C:
			s.stop(0)
			return fmt.Errorf("virtiofsd for the share at %s did not report that it was ready within %v",
				quoteForLog(srv.grant.Path), s.readyTimeout)
		case sig := <-signals:
			s.stop(0)
			ss, ok := sig.(syscall.Signal)
			if !ok {
				ss = syscall.SIGTERM
			}
			return &signalledError{Sig: ss, during: "starting virtiofsd for the share at " + quoteForLog(srv.grant.Path)}
		}
	}
	// A virtiofsd that ended after it was ready, while start went on to the
	// next one, is a failure that run sees before it starts QEMU.
	s.mu.Lock()
	s.armed = true
	var early []*shareServer
	for _, srv := range s.servers {
		if srv.endedEarly {
			early = append(early, srv)
		}
	}
	s.mu.Unlock()
	for _, srv := range early {
		s.fail(srv, describeEnd(srv.state, srv.waitErr))
	}
	return nil
}

// startOne checks srv's mount and starts its virtiofsd from a confined
// thread, with an empty environment, its stdout and stderr on a pipe that
// readLog reads, and the socket as its virtiofsdListenFD. vm-launch's copy
// of the socket is closed whether or not the start works.
func (s *shareServers) startOne(srv *shareServer) error {
	defer srv.closeListener(s.logger)
	if err := checkShareMount(srv.grant); err != nil {
		return err
	}
	logR, logW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("creating the log pipe of virtiofsd for the share at %s: %w", quoteForLog(srv.grant.Path), err)
	}
	argv := virtiofsdArgv(s.path, srv.grant.Path)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = logW, logW
	// ExtraFiles[0] is the child's descriptor 3, virtiofsdListenFD.
	cmd.ExtraFiles = []*os.File{srv.listener}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	release, err := startConfinedAs(cmd, func() error { return confineVirtiofsd(hypervisorCaps) }, "virtiofsd")
	if cerr := logW.Close(); cerr != nil {
		s.logger.Printf("closing vm-launch's copy of the log pipe of virtiofsd for the share at %s: %v", quoteForLog(srv.grant.Path), cerr)
	}
	if err != nil {
		logR.Close()
		return fmt.Errorf("starting virtiofsd for the share at %s: %w", quoteForLog(srv.grant.Path), err)
	}
	srv.cmd = cmd
	go srv.readLog(logR, s.logger)
	go s.wait(srv, release)
	return nil
}

// confineVirtiofsd runs on the thread that starts virtiofsd. It sets
// no_new_privs on the thread and then takes every capability from it, as
// confineThread does for the hypervisor. The process the thread starts
// inherits both. With no_new_privs, no exec can raise the permitted set
// above the thread's, which is empty, or honour a set-user-ID bit, so no
// file in the chain that runs virtiofsd gains anything from its file
// capabilities. That chain is the wrapper, the wrapper's interpreter, the
// bundled loader, and virtiofsd itself, plus anything those exec in turn. A
// check of one named file, as the hypervisor gets, would cover less, so
// virtiofsd gets none. The thread ends with virtiofsd (see
// startConfinedAs), so no other part of vm-launch ever runs with the flag.
func confineVirtiofsd(ops capOps) error {
	if err := setNoNewPrivs(); err != nil {
		return err
	}
	return confineThread(ops, "virtiofsd")
}

// setNoNewPrivs sets no_new_privs on the calling thread and reads it back.
// Garden starts vm-launch with it already, which leaves nothing to change.
func setNoNewPrivs() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("setting no_new_privs: %w", os.NewSyscallError("prctl PR_SET_NO_NEW_PRIVS", err))
	}
	set, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("reading no_new_privs back: %w", os.NewSyscallError("prctl PR_GET_NO_NEW_PRIVS", err))
	}
	if set != 1 {
		return fmt.Errorf("no_new_privs reads back as %d after vm-launch set it", set)
	}
	return nil
}

// readLog passes each line of virtiofsd's log to the logger with the share's
// path in front, closes srv.ready at the first line that holds
// virtiofsdReadyText, and closes srv.logDone at the end of the log. It keeps
// reading to the end, so virtiofsd never blocks on its log. It passes on the
// first maxVirtiofsdLogLines lines, each cut at maxVirtiofsdLineBytes and
// with its control bytes escaped, holds back the lines after those but keeps
// the latest maxVirtiofsdTailLines of them, and passes those on at the end.
func (srv *shareServer) readLog(r *os.File, logger *log.Logger) {
	defer close(srv.logDone)
	defer r.Close()
	path := quoteForLog(srv.grant.Path)
	br := bufio.NewReaderSize(r, maxVirtiofsdLineBytes)
	ready, inLongLine := false, false
	lines := 0
	tail := newLineRing(maxVirtiofsdTailLines)
	for {
		chunk, err := br.ReadSlice('\n')
		if len(chunk) > 0 {
			cut := errors.Is(err, bufio.ErrBufferFull)
			if inLongLine {
				// The rest of a line that was already cut and passed on.
				inLongLine = cut
			} else {
				text := strings.TrimRight(string(chunk), "\r\n")
				if !ready && strings.Contains(text, virtiofsdReadyText) {
					ready = true
					close(srv.ready)
				}
				text = escapeControlBytes(text)
				if cut {
					text += " [cut]"
					inLongLine = true
				}
				switch {
				case lines < maxVirtiofsdLogLines:
					logger.Printf("virtiofsd for %s: %s", path, text)
				case lines == maxVirtiofsdLogLines:
					logger.Printf("virtiofsd for %s wrote more than %d lines; vm-launch holds back the rest and passes on the last %d when the log ends", path, maxVirtiofsdLogLines, maxVirtiofsdTailLines)
					tail.add(text)
				default:
					tail.add(text)
				}
				lines++
			}
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			break
		}
	}
	if held := tail.total; held > 0 {
		kept := tail.lines()
		logger.Printf("virtiofsd for %s: %d lines were held back; the last %d follow", path, held, len(kept))
		for _, text := range kept {
			logger.Printf("virtiofsd for %s: %s", path, text)
		}
	}
}

// lineRing keeps the latest lines added to it, up to its size, and counts
// every line added.
type lineRing struct {
	buf   []string
	next  int
	total int
}

func newLineRing(size int) *lineRing { return &lineRing{buf: make([]string, 0, size)} }

func (r *lineRing) add(line string) {
	r.total++
	if len(r.buf) < cap(r.buf) {
		r.buf = append(r.buf, line)
		return
	}
	r.buf[r.next] = line
	r.next = (r.next + 1) % len(r.buf)
}

// lines returns the kept lines, oldest first.
func (r *lineRing) lines() []string {
	out := make([]string, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	return append(out, r.buf[:r.next]...)
}

// escapeControlBytes writes each ASCII control byte of s other than a tab,
// and DEL, as \xNN, so a line that virtiofsd copied from a guest's request
// cannot move a terminal's cursor or hide part of the log.
func escapeControlBytes(s string) string {
	isControl := func(c byte) bool { return (c < 0x20 && c != '\t') || c == 0x7f }
	i := 0
	for i < len(s) && !isControl(s[i]) {
		i++
	}
	if i == len(s) {
		return s
	}
	var b strings.Builder
	b.WriteString(s[:i])
	for ; i < len(s); i++ {
		if c := s[i]; isControl(c) {
			fmt.Fprintf(&b, `\x%02x`, c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// wait reaps srv's virtiofsd, ends the thread that started it, and acts on
// the end (see ended).
func (s *shareServers) wait(srv *shareServer, release func()) {
	err := srv.cmd.Wait()
	srv.state, srv.waitErr = srv.cmd.ProcessState, err
	release()
	close(srv.exited)
	s.ended(srv)
}

// ended acts on the end of srv's virtiofsd. An end after QEMU was reaped, or
// once vm-launch stops virtiofsd itself, is expected. An end before start
// armed the servers is left to start. Any other end fails the share, except
// an end with status 0 after which QEMU is reaped within the disconnect
// grace, since that is virtiofsd seeing QEMU disconnect as QEMU exits.
func (s *shareServers) ended(srv *shareServer) {
	s.mu.Lock()
	expected := s.stopping || s.guestReaped
	if !expected && !s.armed {
		srv.endedEarly = true
		expected = true
	}
	started := s.guest != nil
	s.mu.Unlock()
	if expected {
		return
	}
	how := describeEnd(srv.state, srv.waitErr)
	clean := srv.state != nil && srv.state.Success()
	if !clean || !started {
		s.fail(srv, how)
		return
	}
	grace := time.NewTimer(s.disconnectGrace)
	defer grace.Stop()
	select {
	case <-s.guestDone:
	case <-s.stopped:
	case <-grace.C:
		s.fail(srv, fmt.Sprintf("%s, but the hypervisor still ran %v later", how, s.disconnectGrace))
	}
}

// fail records the first failed share, logs it, and kills QEMU when it runs.
// It does nothing once QEMU has been reaped or vm-launch stops virtiofsd.
func (s *shareServers) fail(srv *shareServer, how string) {
	s.mu.Lock()
	if s.stopping || s.guestReaped {
		s.mu.Unlock()
		return
	}
	first := s.failure == ""
	if first {
		s.failure = fmt.Sprintf("the share at %s stopped being served before the guest reported a status", quoteForLog(srv.grant.Path))
	}
	guest := s.guest
	s.mu.Unlock()
	line := fmt.Sprintf("virtiofsd for the share at %s %s", quoteForLog(srv.grant.Path), how)
	if guest != nil {
		line += "; killing the hypervisor"
	}
	s.logger.Print(line)
	if guest != nil {
		killGuest(guest, s.logger)
	}
}

func killGuest(p *os.Process, logger *log.Logger) {
	if err := p.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		logger.Printf("killing the hypervisor: %v", err)
	}
}

// guestStarted records QEMU once it has started, and kills it at once when a
// share has already failed.
func (s *shareServers) guestStarted(p *os.Process) {
	s.mu.Lock()
	s.guest = p
	failed := s.failure != ""
	s.mu.Unlock()
	if failed {
		killGuest(p, s.logger)
	}
}

// markReaped records that QEMU has been reaped, or that run is past the
// supervisor without one, and closes guestDone. It reports whether this
// call was the one that did. It also reports the grace each virtiofsd gets
// to end on its own, which is the stop grace when QEMU ran, since virtiofsd
// sees it disconnect, and none when QEMU never started, since nothing will
// ever connect. Every call reports that grace, the later ones too, because
// the stop that the first call's caller starts in the background may not
// have begun when run's own stop asks, and then run's stop is the one that
// counts.
func (s *shareServers) markReaped() (grace time.Duration, first bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.guest != nil {
		grace = s.stopGrace
	}
	if s.guestReaped {
		return grace, false
	}
	s.guestReaped = true
	close(s.guestDone)
	return grace, true
}

// hypervisorReaped is the supervisor's reaped hook, which runs as soon as
// QEMU has been reaped and before the supervisor flushes the guest's last
// output. It records the reap, so that a virtiofsd that exits 0 at QEMU's
// disconnect is expected however long the flush takes, and starts stopping
// every virtiofsd in the background, beside the flush. It does not block.
func (s *shareServers) hypervisorReaped() {
	if grace, first := s.markReaped(); first {
		go s.stop(grace)
	}
}

// guestEnded runs once the supervisor has returned. It records the reap if
// the supervisor never reported one, as when QEMU did not start, and stops
// every virtiofsd that still runs, or waits for the stop that
// hypervisorReaped began, so their last lines come before the exit line.
func (s *shareServers) guestEnded() {
	grace, _ := s.markReaped()
	s.stop(grace)
}

// failureReason returns the exit line's reason when a share stopped being
// served before QEMU was reaped, or empty.
func (s *shareServers) failureReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failure
}

// stop ends every virtiofsd. It closes every socket vm-launch still holds,
// gives each virtiofsd grace to end on its own, sends SIGKILL to each that
// still runs, and then waits for them to end and for their last log lines,
// all within the one kill wait. So a stop takes at most grace plus the kill
// wait, however many virtiofsd processes there are. Only the first call
// stops anything. A later call waits until that stop has finished, so run
// can defer stop for every way out and still have the lines where they
// belong.
func (s *shareServers) stop(grace time.Duration) {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		<-s.stopDone
		return
	}
	s.stopping = true
	close(s.stopped)
	s.mu.Unlock()
	defer close(s.stopDone)
	s.closeListeners()

	var running []*shareServer
	for _, srv := range s.servers {
		if srv.cmd != nil {
			running = append(running, srv)
		}
	}
	if len(running) == 0 {
		return
	}
	exited := func(srv *shareServer) <-chan struct{} { return srv.exited }
	if grace > 0 {
		t := time.NewTimer(grace)
		waitEach(t.C, running, exited)
		t.Stop()
	}
	for _, srv := range running {
		if isClosed(srv.exited) {
			continue
		}
		if err := srv.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			s.logger.Printf("killing virtiofsd for the share at %s: %v", quoteForLog(srv.grant.Path), err)
		}
	}
	deadline := time.NewTimer(s.killWait)
	defer deadline.Stop()
	allEnded := waitEach(deadline.C, running, exited)
	for _, srv := range running {
		if !isClosed(srv.exited) {
			s.logger.Printf("virtiofsd for the share at %s did not end within %v of SIGKILL; it ends when its I/O returns", quoteForLog(srv.grant.Path), s.killWait)
		}
	}
	if !allEnded {
		// The kill wait is spent. A virtiofsd that has ended may still have
		// lines on the way, and they come when they come.
		return
	}
	waitEach(deadline.C, running, func(srv *shareServer) <-chan struct{} { return srv.logDone })
}

// waitEach waits until ch(srv) is closed for each of servers in turn, and
// reports whether all of them were before timeout fired.
func waitEach(timeout <-chan time.Time, servers []*shareServer, ch func(*shareServer) <-chan struct{}) bool {
	for _, srv := range servers {
		select {
		case <-ch(srv):
		case <-timeout:
			return false
		}
	}
	return true
}
