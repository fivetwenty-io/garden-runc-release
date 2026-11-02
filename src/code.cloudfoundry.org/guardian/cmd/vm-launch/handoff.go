//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// The volume handoff. When a cell drains, the rep starts a replacement for
// each instance elsewhere and stops the old one only once the replacement
// runs. The replacement of an app with a private image would wait on the old
// instance's lock until it gave up, so the replacement asks the old instance,
// through the volume they share, to let the image go. The operator turns the
// handoff on with --volume-handoff, and a launch without it neither writes a
// request nor reads one (see withoutHandoff).
//
// While its lock wait finds the image locked, a launch writes a request file,
// .rvm-handoff-IMAGENAME, in the root of the volume, and rewrites it every
// handoffRefresh with a higher sequence number. While its guest runs, the
// launch that holds the image reads that file every handoffPoll. It honours a
// request whose process_id is its own, whose token is not its own, and whose
// sequence number rose between two reads, so that a request a departed
// launch left behind never stops anyone. It reads nothing until it has held
// the image for handoffMinHold, so that two instances of one index never pass
// the image back and forth faster than that. The supervisor then stops the
// guest as it does at a first SIGTERM (see supervisor.handoff), and the
// launch's normal way out releases the lock once the hypervisor has exited.
// The waiter takes the lock through its unchanged wait and removes its
// request.
//
// The flock stays the only thing that grants an image. The handoff changes
// when the holder lets go of it and never how anyone gets it, so the request
// file is advice: a request that cannot be written or read only leaves the
// wait as it was. Only a file-image volume whose fence is a distributed flock
// takes part. A block volume waits on its volume service instead, and a share
// has no lock.
const (
	// handoffPrefix begins the request file's name, which is the prefix and
	// the image's name, and the name of the temporary file a request is
	// written to before it is renamed over the request. It is not the image
	// temp prefix, so the sweep of an NFS volume never removes a request.
	handoffPrefix     = ".rvm-handoff-"
	handoffTempSuffix = ".tmp"

	// handoffMagic and handoffVersion begin the request's one line, which is
	// "rvm-handoff 1 PROCESS_ID TOKEN SEQUENCE".
	handoffMagic   = "rvm-handoff"
	handoffVersion = "1"

	// handoffTokenBytes is how many random bytes the token of one vm-launch
	// has. It tells two launches of one process apart.
	handoffTokenBytes = 16

	// handoffRefresh is how often a waiting launch rewrites its request, and
	// handoffPoll is how often the holder reads it. The refresh is the shorter,
	// so two reads one poll apart always see the sequence number rise while
	// the waiter is alive. A holder sees a request within about two polls, and
	// one second more on JuiceFS, whose client caches metadata for a second.
	// With the 8 second stop deadline, a handoff ends well within the 30
	// second lock wait.
	handoffRefresh = time.Second
	handoffPoll    = 2 * time.Second

	// handoffMinHold is how long a launch keeps an image before it honours a
	// request for it. Diego restarts only one instance of an index when it
	// exits, and removes an evacuating, a suspect, or a stray one, so the
	// image changes hands at most twice before Diego converges. The hold
	// bounds the rate whatever Diego does, to one hand-back of an image a
	// minute, and an instance being evacuated has almost always held its
	// image longer than that.
	handoffMinHold = time.Minute

	// maxHandoffRequest is the largest request file the holder reads.
	maxHandoffRequest = 256
)

// handoffTiming is how often the holder reads its requests and how long it
// keeps its image before it honours one. Tests shorten both.
var handoffTiming = struct{ poll, hold time.Duration }{poll: handoffPoll, hold: handoffMinHold}

// handoffTokenPattern is the only token a request carries: the hex of
// handoffTokenBytes bytes.
var handoffTokenPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// handoffIdentity is who a launch is in a request: its process's process_id
// from VCAP_APPLICATION, and the token it drew.
type handoffIdentity struct {
	ProcessID string
	Token     string
}

// valid reports whether id can be written in a request and compared with
// one.
func (id handoffIdentity) valid() bool {
	return applicationIDPattern.MatchString(id.ProcessID) && handoffTokenPattern.MatchString(id.Token)
}

// launchHandoffToken returns the token of this vm-launch, which it draws once
// and uses in every request it writes and every request it reads.
var launchHandoffToken = sync.OnceValues(newHandoffToken)

// newHandoffToken draws a fresh token.
func newHandoffToken() (string, error) {
	var b [handoffTokenBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("drawing the volume handoff token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// handoffRequestName is the name of the request file for the image name.
func handoffRequestName(imageName string) string {
	return handoffPrefix + imageName
}

// handoffRequest is one request as written and read.
type handoffRequest struct {
	ProcessID string
	Token     string
	Seq       uint64
}

// line is the request's text, with its newline.
func (r handoffRequest) line() string {
	return fmt.Sprintf("%s %s %s %s %d\n", handoffMagic, handoffVersion, r.ProcessID, r.Token, r.Seq)
}

// parseHandoffRequest reads a request's text, which must be exactly one line
// that line would write, and reports whether it is one.
func parseHandoffRequest(b []byte) (handoffRequest, bool) {
	text, ok := strings.CutSuffix(string(b), "\n")
	if !ok || strings.ContainsAny(text, "\n\r") {
		return handoffRequest{}, false
	}
	f := strings.Split(text, " ")
	if len(f) != 5 || f[0] != handoffMagic || f[1] != handoffVersion {
		return handoffRequest{}, false
	}
	seq, err := strconv.ParseUint(f[4], 10, 64)
	if err != nil || strconv.FormatUint(seq, 10) != f[4] {
		return handoffRequest{}, false
	}
	r := handoffRequest{ProcessID: f[2], Token: f[3], Seq: seq}
	if !(handoffIdentity{ProcessID: r.ProcessID, Token: r.Token}).valid() {
		return handoffRequest{}, false
	}
	return r, true
}

// writeHandoffRequest writes r as the request file name beneath dirfd: it
// creates a temporary file with a name nothing else uses, writes the line,
// and renames it over name, so a reader sees the old request or the new one
// and never part of one. The temporary file is removed when any step fails.
// A launch killed between the create and the rename leaves a temporary file
// of under 256 bytes, which nothing reads.
func writeHandoffRequest(dirfd int, name string, r handoffRequest) error {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Errorf("drawing a temp file name: %w", err)
	}
	temp := handoffPrefix + hex.EncodeToString(b[:]) + handoffTempSuffix
	fd, err := openat2Retry(dirfd, temp, &unix.OpenHow{
		Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Mode:  imageMode, Resolve: imageOpenResolve,
	})
	if err != nil {
		return fmt.Errorf("creating %s: %w", temp, err)
	}
	f := os.NewFile(uintptr(fd), temp)
	_, werr := io.WriteString(f, r.line())
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = unix.Unlinkat(dirfd, temp, 0)
		return fmt.Errorf("writing %s: %w", temp, err)
	}
	for {
		err = unix.Renameat(dirfd, temp, dirfd, name)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		_ = unix.Unlinkat(dirfd, temp, 0)
		return fmt.Errorf("renaming %s to %s: %w", temp, name, err)
	}
	return nil
}

// readHandoffRequest returns the request file name beneath dirfd and whether
// there is a request there. It asks the filesystem for the directory's
// attributes first, as freshLookup does, so an NFS client looks the name up
// again rather than answer from a stale dentry. A name that is missing, is
// not a regular file owned by vm-launch's effective uid, is larger than
// maxHandoffRequest, or does not hold one request is no request. It follows
// no link and leaves the volume root's mount for nothing.
func readHandoffRequest(dirfd int, name string) (handoffRequest, bool) {
	var stx unix.Statx_t
	_ = unix.Statx(dirfd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_FORCE_SYNC, unix.STATX_TYPE, &stx)
	fd, err := openat2Retry(dirfd, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC,
		Resolve: imageOpenResolve,
	})
	if err != nil {
		return handoffRequest{}, false
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Size > maxHandoffRequest {
		return handoffRequest{}, false
	}
	b, err := io.ReadAll(io.LimitReader(f, maxHandoffRequest+1))
	if err != nil || len(b) > maxHandoffRequest {
		return handoffRequest{}, false
	}
	return parseHandoffRequest(b)
}

// handoffRequester is the waiting side of one image's lock wait. lockImage
// calls refresh each time it finds the image locked, and openVolumeImage
// calls withdraw once the wait has ended, however it ended. A nil requester
// does nothing.
type handoffRequester struct {
	dirfd int
	name  string
	path  string
	id    handoffIdentity
	logf  func(format string, args ...any)

	seq    uint64
	wrote  time.Time
	failed bool
}

// newHandoffRequester returns the requester for the image imageName at path
// in the volume root dirfd, which stays open while the requester is used.
func newHandoffRequester(dirfd int, imageName, path string, id handoffIdentity, logf func(format string, args ...any)) *handoffRequester {
	return &handoffRequester{dirfd: dirfd, name: handoffRequestName(imageName), path: path, id: id, logf: logf}
}

// refresh writes the request with the next sequence number, unless the last
// write, or the last failure, is under handoffRefresh old. The first write
// logs one line, and the first failure logs one line, after which the wait
// goes on and refresh tries again at the next refresh.
func (r *handoffRequester) refresh() {
	if r == nil || (!r.wrote.IsZero() && time.Since(r.wrote) < handoffRefresh) {
		return
	}
	r.wrote = time.Now()
	err := writeHandoffRequest(r.dirfd, r.name, handoffRequest{ProcessID: r.id.ProcessID, Token: r.id.Token, Seq: r.seq + 1})
	switch {
	case err != nil && !r.failed:
		r.failed = true
		r.logf("asking the instance that holds volume image %s to hand it over: %v; this instance waits for the lock without asking", r.path, err)
	case err == nil:
		if r.seq == 0 {
			r.logf("volume image %s is locked; asking the instance that holds it to hand it over, which it does when it is an earlier instance of this process", r.path)
		}
		r.seq++
	}
}

// withdraw removes the request file when it still carries this launch's
// token. Another waiter may rename its own request over the name between the
// read and the removal, and then rewrites it within handoffRefresh.
func (r *handoffRequester) withdraw() {
	if r == nil || r.seq == 0 {
		return
	}
	if req, ok := readHandoffRequest(r.dirfd, r.name); ok && req.Token == r.id.Token {
		_ = unix.Unlinkat(r.dirfd, r.name, 0)
	}
}

// handoffWatch is the holding side of one image: the volume root, opened
// again once the image is held, and the request file's name in it.
type handoffWatch struct {
	dirfd int
	name  string
	path  string
	self  handoffIdentity
}

// openHandoffWatch opens the volume root at dir, without following any link,
// and returns the watch for the image imageName in it, held by self. The
// directory must be on the mount mountID, the one the image was opened on.
func openHandoffWatch(dir string, mountID uint64, imageName string, self handoffIdentity) (*handoffWatch, error) {
	dirfd, err := openat2Retry(unix.AT_FDCWD, dir, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("opening volume %s: %w%s", dir, err, symlinkHint(err))
	}
	probe, err := dirProbe(dirfd, dir)
	switch {
	case err != nil:
		unix.Close(dirfd)
		return nil, fmt.Errorf("checking the mount of volume %s: %w", dir, err)
	case probe.MountID != mountID:
		unix.Close(dirfd)
		return nil, fmt.Errorf("the mount of volume %s changed: the image is on mount ID %d and the directory is on mount ID %d now", dir, mountID, probe.MountID)
	}
	return &handoffWatch{dirfd: dirfd, name: handoffRequestName(imageName), path: filepath.Join(dir, imageName), self: self}, nil
}

// read returns the request in the watch's file that the holder could honour,
// which names its process and not its token, and whether there is one.
func (w *handoffWatch) read() (handoffRequest, bool) {
	r, ok := readHandoffRequest(w.dirfd, w.name)
	if !ok || r.ProcessID != w.self.ProcessID || r.Token == w.self.Token {
		return handoffRequest{}, false
	}
	return r, true
}

// Close closes the watch's directory. A nil watch has nothing to close.
func (w *handoffWatch) Close() error {
	if w == nil {
		return nil
	}
	return unix.Close(w.dirfd)
}

// handoffWatcher reads the requests of every held image while the guest
// runs, and offers the supervisor one line once some image has a live
// request. A nil watcher offers nothing.
type handoffWatcher struct {
	ch       chan string
	done     chan struct{}
	finished chan struct{}
	stopOnce sync.Once
}

// startHandoffWatcher starts reading the requests of watches every poll, from
// hold after it starts, or returns nil when there are none. A request is live
// when two reads one poll apart find the same token with a higher sequence
// number. The watcher then offers its line for one poll, and when the
// supervisor does not take it, because the guest command does not run yet,
// it reads again, so the supervisor never acts on a request older than one
// poll. It stops once the supervisor took a line or stop is called.
func startHandoffWatcher(watches []*handoffWatch, poll, hold time.Duration) *handoffWatcher {
	if len(watches) == 0 {
		return nil
	}
	w := &handoffWatcher{ch: make(chan string), done: make(chan struct{}), finished: make(chan struct{})}
	go func() {
		defer close(w.finished)
		if hold > 0 {
			t := time.NewTimer(hold)
			select {
			case <-t.C:
			case <-w.done:
				t.Stop()
				return
			}
		}
		last := make([]handoffRequest, len(watches))
		seen := make([]bool, len(watches))
		for {
			reason := ""
			for i, watch := range watches {
				r, ok := watch.read()
				if ok && seen[i] && r.Token == last[i].Token && r.Seq > last[i].Seq && reason == "" {
					reason = fmt.Sprintf("another instance of this process is waiting for volume image %s", watch.path)
				}
				last[i], seen[i] = r, ok
			}
			t := time.NewTimer(poll)
			if reason == "" {
				select {
				case <-t.C:
					continue
				case <-w.done:
					t.Stop()
					return
				}
			}
			select {
			case w.ch <- reason:
				t.Stop()
				return
			case <-t.C:
			case <-w.done:
				t.Stop()
				return
			}
		}
	}()
	return w
}

// requests is the channel the supervisor takes a line from, or nil for a nil
// watcher, which the supervisor never takes from.
func (w *handoffWatcher) requests() <-chan string {
	if w == nil {
		return nil
	}
	return w.ch
}

// stop ends the watcher and waits for it. It may be called more than once,
// and on a nil watcher.
func (w *handoffWatcher) stop() {
	if w == nil {
		return
	}
	w.stopOnce.Do(func() { close(w.done) })
	<-w.finished
}

// handoffIdentityFor returns the identity with which the volume v, which its
// provider attaches in mode with capabilities caps, takes part in the
// handoff, or nil when it takes none: a volume that is not a file image
// under a distributed flock, a process without a usable process_id, and a
// launch whose token could not be drawn, which logs one line.
func handoffIdentityFor(v selectedVolume, caps capabilities, mode attachMode, logger *log.Logger) *handoffIdentity {
	if mode != attachFileImage || caps.Fence != fenceDistributedFlock || !applicationIDPattern.MatchString(v.Volume.ProcessID) {
		return nil
	}
	token, err := launchHandoffToken()
	if err != nil {
		logger.Printf("%v; this instance neither asks for nor hands over the volume at %s", err, quoteForLog(v.Volume.ContainerDir))
		return nil
	}
	return &handoffIdentity{ProcessID: v.Volume.ProcessID, Token: token}
}

// withoutHandoff takes vols out of the handoff, for a launch without
// --volume-handoff. A volume takes part only with its process's process_id
// (see handoffIdentityFor), so a volume without one neither asks a holder for
// its image nor watches for requests while the guest runs.
func withoutHandoff(vols []guestVolume) {
	for i := range vols {
		vols[i].ProcessID = ""
	}
}
