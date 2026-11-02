//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Mirrored mounts. Garden and Diego put files into a container by bind-mounting
// them, and a guest with an app root gets those mounts by rule when the
// operator turns on --mirror-mounts (see mirrorMountsFlag), with no code for
// any one of them. vm-launch reads the container's own mount table, leaves out
// the mounts that describe the host or belong to Garden and vm-launch, leaves
// the mounts that have a path of their own on that path, and copies every
// small read-only mount that is left into the initramfs. Stage 2 binds each
// copy read-only into the app root at the mount's own path (see
// mountMirror.guestSetup), and vm-launch pushes later changes to the small
// files over the console (see mirrorWatcher). File-based service bindings
// below /etc/cf-service-bindings are the first mount that takes this path.
const (
	// mirrorFileMaxBytes caps a mirrored file, alone or in a tree.
	mirrorFileMaxBytes = 1 << 20
	// mirrorTreeMaxBytes and mirrorTreeMaxEntries cap a mirrored directory
	// tree.
	mirrorTreeMaxBytes   = 4 << 20
	mirrorTreeMaxEntries = 1024
	// mirrorTotalMaxBytes caps all of a guest's mirrored mounts together.
	// They stay in guest RAM for the life of the guest, in the initramfs.
	mirrorTotalMaxBytes = 8 << 20
	// mirrorWatchMaxBytes caps a file whose changes vm-launch pushes, and
	// mirrorWatchMaxFiles caps how many files it watches. The console
	// carries roughly 1.5 KB of file data a second, so a file at the cap
	// takes about forty seconds to reach the guest.
	mirrorWatchMaxBytes = 64 << 10
	mirrorWatchMaxFiles = 256

	// guestMirrorStage is the initramfs directory that holds the copy of
	// mount n at guestMirrorStage/n, and guestMirrorNext is where the
	// control reader assembles a pushed file. Both are outside the app root.
	guestMirrorStage = "/rvm/mirror"
	guestMirrorNext  = "/rvm/mirror-next"
)

// mirrorDeniedFSTypes are the kernel's pseudo filesystems. A mount of one of
// them describes the host or the container runtime, and the guest has its
// own, so the guest never gets one.
var mirrorDeniedFSTypes = map[string]bool{
	"autofs": true, "binfmt_misc": true, "bpf": true, "cgroup": true, "cgroup2": true,
	"configfs": true, "debugfs": true, "devpts": true, "devtmpfs": true, "fusectl": true,
	"hugetlbfs": true, "mqueue": true, "nsfs": true, "proc": true, "pstore": true,
	"securityfs": true, "sysfs": true, "tracefs": true,
}

// mirrorDeniedDirs are the paths whose mounts the guest never gets, at them,
// below them, or above them. They are the guest's own proc, sysfs, and
// devices, the programs, libraries, and loader that the guest's root runs in
// the app root before it drops to the app's user (see guestStackSetpriv), the
// paths of Garden and vm-launch, and Garden's Envoy configuration, whose
// copy of the instance identity key reaches the guest on a path of its own.
var mirrorDeniedDirs = []string{
	"/proc", "/sys", "/dev",
	"/bin", "/sbin", "/usr", "/lib", "/lib32", "/lib64", "/libx32",
	"/rvm", "/opt/garden-vm", "/etc/cf-assets",
}

// mirrorDeniedPrefixes are the path prefixes whose mounts the guest never
// gets, which are Garden's paths in /tmp and the dynamic loader's
// configuration and cache, and mounts above them are denied too.
var mirrorDeniedPrefixes = []string{"/tmp/garden-", "/etc/ld.so."}

// mirrorNetworkFSTypes are the network filesystems, which a copy at boot
// would let go stale. A filesystem type that starts with "fuse." is one too.
var mirrorNetworkFSTypes = map[string]bool{
	"ceph": true, "cifs": true, "fuse": true, "glusterfs": true, "nfs": true, "nfs4": true, "smb3": true,
}

// mirrorOwnPaths are the container paths that reach the guest on a path of
// their own, whatever the mount table says about them. The launch adds the
// paths it learns from the environment (see mirrorDedicatedPaths).
var mirrorOwnPaths = []string{
	"/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/etc/ssl", "/tmp/lifecycle",
	"/etc/cf-instance-credentials", dropletHome,
}

// errMirrorTooLarge stops the walk of a tree that is over the limits of a
// small mount.
var errMirrorTooLarge = errors.New("over the limits of a mirrored mount")

// mirrorKind is what a mirrored entry is.
type mirrorKind byte

const (
	mirrorDir mirrorKind = iota
	mirrorFile
	mirrorLink
)

// mountMirror is the mounts the guest gets and the files of them that
// vm-launch watches, numbered from 1 in order.
type mountMirror struct {
	mounts  []mirrorMount
	watched []*mirrorWatched
}

// mirrorMount is one mirrored mount. dir says whether it is a directory tree
// or a single file. entries holds the mount's root as its first entry, with
// rel "", and for a tree every entry below it, parents first.
type mirrorMount struct {
	path    string
	dir     bool
	noexec  bool
	bytes   int64
	entries []mirrorEntry
}

// mirrorEntry is one directory, regular file, or symbolic link of a mirrored
// mount, at rel below the mount's root, with its permission bits and owner
// as the container shows them. A file has its bytes in data and a link its
// target in target. state is a file's state as vm-launch read it. place
// marks the empty entry that stands in for another mount point (see
// readMirrorMount). watch is the number of the watched file, or 0.
type mirrorEntry struct {
	rel      string
	kind     mirrorKind
	perm     uint32
	uid, gid uint32
	data     []byte
	target   string
	state    fileState
	place    bool
	watch    int
}

// mirrorWatched is one file whose changes vm-launch pushes: its container
// path, its path in the guest's initramfs, whether the guest rewrites it in
// place, which a file mount needs, and its owner. state, data, and perm are
// what the guest holds.
type mirrorWatched struct {
	number   int
	path     string
	guest    string
	inPlace  bool
	uid, gid uint32
	state    fileState
	data     []byte
	perm     uint32
}

// watching reports whether the mirror has a file to watch. A nil mirror has
// none.
func (m *mountMirror) watching() bool { return m != nil && len(m.watched) > 0 }

// mirrorDedicatedPaths returns the container paths that reach the guest on a
// path of their own: mirrorOwnPaths, the directory CF_SYSTEM_CERT_PATH names,
// the directories of the identity pair's files, and every volume directory.
func mirrorDedicatedPaths(env map[string]string, vols []guestVolume) []string {
	paths := append([]string(nil), mirrorOwnPaths...)
	if v := env[systemCertPathEnv]; path.IsAbs(v) {
		paths = append(paths, path.Clean(v))
	}
	for _, name := range []string{instanceCertEnv, instanceKeyEnv} {
		if v := env[name]; path.IsAbs(v) {
			paths = append(paths, path.Dir(path.Clean(v)))
		}
	}
	for _, v := range vols {
		if path.IsAbs(v.ContainerDir) {
			paths = append(paths, path.Clean(v.ContainerDir))
		}
	}
	return paths
}

// mirrorPathUsable reports whether p is a path the guest can bind a mount
// at: absolute, in its cleaned form, and on one line.
func mirrorPathUsable(p string) bool {
	return path.IsAbs(p) && path.Clean(p) == p && !strings.ContainsAny(p, "\n\x00")
}

// mirrorDenied reports whether the guest never gets a mount of fsType at p.
// A mount above a denied path is denied as well, because its copy would put
// content of the container's at that path too.
func mirrorDenied(p, fsType string) bool {
	if p == "/" || mirrorDeniedFSTypes[fsType] {
		return true
	}
	for _, dir := range mirrorDeniedDirs {
		if underDir(p, dir) || underDir(dir, p) {
			return true
		}
	}
	for _, prefix := range mirrorDeniedPrefixes {
		if strings.HasPrefix(p, prefix) || underDir(path.Dir(prefix), p) {
			return true
		}
	}
	return false
}

// mirrorNetworkFS reports whether fsType is a network filesystem.
func mirrorNetworkFS(fsType string) bool {
	return mirrorNetworkFSTypes[fsType] || strings.HasPrefix(fsType, "fuse.")
}

// hasMountOption reports whether opts holds opt.
func hasMountOption(opts []string, opt string) bool {
	for _, o := range opts {
		if o == opt {
			return true
		}
	}
	return false
}

// readMountMirror reads the mount table at mountinfo and returns the mounts
// the guest gets, or nil when it gets none. dedicated are the paths that
// reach the guest on a path of their own (see mirrorDedicatedPaths). The
// last line for a mount point is the one that counts, because a later mount
// there hides an earlier one.
//
// A mount the guest never gets (see mirrorDenied) and a mount at or below a
// dedicated path are counted in one line. A mount above a dedicated path, on
// a path the guest cannot bind at, on a network filesystem, that is not
// read-only, that is neither a file nor a directory, or that is over the
// limits of a small mount, is held back with a line of its own. A mount
// table that cannot be read or parsed is an error, because the launch could
// not then say which mounts the guest lacks.
func readMountMirror(mountinfo string, dedicated []string, logger *log.Logger) (*mountMirror, error) {
	recs, err := readMountTable(mountinfo)
	if err != nil {
		return nil, err
	}
	points := make(map[string]bool, len(recs))
	for _, rec := range recs {
		points[rec.MountPoint] = true
	}

	m := &mountMirror{}
	var left []string
	var total int64
	for _, rec := range recs {
		p := rec.MountPoint
		if mirrorDenied(p, rec.FSType) {
			left = append(left, p)
			continue
		}
		if firstUnder(p, dedicated) {
			left = append(left, p)
			continue
		}
		if below, ok := dedicatedBelow(p, dedicated); ok {
			logger.Printf("not mirroring the mount at %s into the guest, because %s below it reaches the guest on a path of its own", quoteForLog(p), quoteForLog(below))
			continue
		}
		switch {
		case !mirrorPathUsable(p):
			logger.Printf("not mirroring the mount at %s into the guest, because the guest cannot bind a mount at that path", quoteForLog(p))
			continue
		case mirrorNetworkFS(rec.FSType):
			logger.Printf("not mirroring the %s mount at %s into the guest, because a copy of a network filesystem would go stale; bind it as a volume instead", rec.FSType, quoteForLog(p))
			continue
		case !hasMountOption(rec.MountOptions, "ro"):
			logger.Printf("not mirroring the mount at %s into the guest, because it is writable in the container and the app's writes to the guest's copy would never reach it", quoteForLog(p))
			continue
		}
		mm, special, err := readMirrorMount(p, points)
		switch {
		case errors.Is(err, errMirrorTooLarge):
			logger.Printf("not mirroring the mount at %s into the guest, because it is over the %d bytes of a mirrored file or the %d bytes and %d entries of a mirrored tree; large mounts are not mirrored yet", quoteForLog(p), mirrorFileMaxBytes, mirrorTreeMaxBytes, mirrorTreeMaxEntries)
			continue
		case err != nil:
			logger.Printf("not mirroring the mount at %s into the guest: %v", quoteForLog(p), err)
			continue
		}
		if total+mm.bytes > mirrorTotalMaxBytes {
			logger.Printf("not mirroring the mount at %s into the guest, because the guest's mirrored mounts would be over %d bytes", quoteForLog(p), mirrorTotalMaxBytes)
			continue
		}
		if special > 0 {
			logger.Printf("leaving %d entries out of the mirrored mount at %s, because they are not directories, regular files, or symbolic links, or could not be read", special, quoteForLog(p))
		}
		mm.noexec = hasMountOption(rec.MountOptions, "noexec")
		total += mm.bytes
		m.mounts = append(m.mounts, mm)
	}
	if len(left) > 0 {
		logger.Printf("leaving %d of the container's mounts out of the guest's mirrored mounts, because they belong to the host, Garden, or vm-launch, or reach the guest on a path of their own: %s", len(left), joinLoggedNames(left))
	}
	if len(m.mounts) == 0 {
		logger.Print("mirroring none of the container's mounts into the guest")
		return nil, nil
	}
	m.number()
	logger.Print(m.summary())
	return m, nil
}

// readMountTable returns the records of the mount table at mountinfo, one
// for each mount point, the last line for it winning, in path order, which
// puts every mount before the mounts below it.
func readMountTable(mountinfo string) ([]mountRecord, error) {
	f, err := os.Open(mountinfo)
	if err != nil {
		return nil, fmt.Errorf("reading %s to mirror the container's mounts: %w", mountinfo, err)
	}
	defer f.Close()
	byPoint := map[string]mountRecord{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		rec, err := parseMountInfoRecord(sc.Text())
		if err != nil {
			return nil, fmt.Errorf("line %d of %s: %w", n, mountinfo, err)
		}
		byPoint[rec.MountPoint] = rec
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s to mirror the container's mounts: %w", mountinfo, err)
	}
	recs := make([]mountRecord, 0, len(byPoint))
	for _, rec := range byPoint {
		recs = append(recs, rec)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].MountPoint < recs[j].MountPoint })
	return recs, nil
}

// firstUnder reports whether p is at or below one of dirs.
func firstUnder(p string, dirs []string) bool {
	for _, dir := range dirs {
		if underDir(p, dir) {
			return true
		}
	}
	return false
}

// dedicatedBelow returns a path of dirs that lies below p.
func dedicatedBelow(p string, dirs []string) (string, bool) {
	for _, dir := range dirs {
		if dir != p && underDir(dir, p) {
			return dir, true
		}
	}
	return "", false
}

// readMirrorMount reads the mount at p without following a symbolic link
// anywhere on the way: openat2 refuses one in p itself, and every entry below
// it is opened with O_NOFOLLOW relative to its directory, so a link is copied
// as a link and never read through. Each is opened with O_PATH first, and
// only a directory or a regular file is then opened again for reading, so a
// FIFO or a device in the mount, or one swapped in during the walk, is never
// opened (see reopenMirrorFD). points are every mount point in the
// table. An entry that is another mount point is copied as an empty
// directory or file, so that the guest has a place to bind that mount at,
// and its content is never read by this walk. special counts the entries
// left out.
func readMirrorMount(p string, points map[string]bool) (mm mirrorMount, special int, err error) {
	pfd, err := openat2Retry(unix.AT_FDCWD, p, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return mirrorMount{}, 0, fmt.Errorf("opening it: %w (vm-launch follows no symbolic links on the path of a mirrored mount)", err)
		}
		return mirrorMount{}, 0, fmt.Errorf("opening it: %w", err)
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return mirrorMount{}, 0, fmt.Errorf("reading its attributes: %w", err)
	}
	mm.path = p
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		if st.Size > mirrorFileMaxBytes {
			return mirrorMount{}, 0, errMirrorTooLarge
		}
		f, err := reopenMirrorFD(pfd, unix.O_RDONLY|unix.O_NONBLOCK, p)
		if err != nil {
			return mirrorMount{}, 0, fmt.Errorf("opening it: %w", err)
		}
		data, err := readMirrorData(f, mirrorFileMaxBytes)
		f.Close()
		if err != nil {
			return mirrorMount{}, 0, err
		}
		mm.bytes = int64(len(data))
		mm.entries = []mirrorEntry{{kind: mirrorFile, perm: st.Mode & 0o777, uid: st.Uid, gid: st.Gid, data: data, state: fileStateOf(&st)}}
		return mm, 0, nil
	case unix.S_IFDIR:
		f, err := reopenMirrorFD(pfd, unix.O_RDONLY|unix.O_DIRECTORY, p)
		if err != nil {
			return mirrorMount{}, 0, fmt.Errorf("opening it: %w", err)
		}
		defer f.Close()
		mm.dir = true
		mm.entries = []mirrorEntry{{kind: mirrorDir, perm: st.Mode & 0o777, uid: st.Uid, gid: st.Gid}}
		w := &mirrorWalk{mount: &mm, points: points}
		if err := w.dir(f, ""); err != nil {
			return mirrorMount{}, 0, err
		}
		return mm, w.special, nil
	case unix.S_IFLNK:
		// openat2 hands back the link itself, not ELOOP, for a link at the
		// end of p opened with O_PATH and O_NOFOLLOW.
		return mirrorMount{}, 0, errors.New("it is a symbolic link, and vm-launch follows no symbolic links on the path of a mirrored mount")
	}
	return mirrorMount{}, 0, errors.New("it is neither a regular file nor a directory")
}

// reopenMirrorFD opens the file that the O_PATH descriptor pfd holds again,
// with flags, through /proc/self/fd. That open reaches the inode pfd holds,
// whatever now sits at its path, so a file whose type was checked on pfd
// cannot be swapped for a FIFO or a device before it is read.
func reopenMirrorFD(pfd, flags int, name string) (*os.File, error) {
	for {
		fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(pfd), flags|unix.O_CLOEXEC, 0)
		if err == nil {
			return os.NewFile(uintptr(fd), name), nil
		}
		if !errors.Is(err, unix.EINTR) {
			return nil, err
		}
	}
}

// fileStateOf returns the state that st describes.
func fileStateOf(st *unix.Stat_t) fileState {
	return fileState{dev: uint64(st.Dev), ino: st.Ino, size: st.Size, modTimeNs: st.Mtim.Nano()} //nolint:unconvert // the widths differ by architecture
}

// readMirrorData reads at most max bytes of f, and errMirrorTooLarge for a
// file that holds more.
func readMirrorData(f io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("reading it: %w", err)
	}
	if int64(len(data)) > max {
		return nil, errMirrorTooLarge
	}
	return data, nil
}

// mirrorWalk is the state of the walk of one mirrored tree.
type mirrorWalk struct {
	mount   *mirrorMount
	points  map[string]bool
	special int
}

// add records e, and errMirrorTooLarge when the tree is then over its
// limits.
func (w *mirrorWalk) add(e mirrorEntry) error {
	w.mount.entries = append(w.mount.entries, e)
	w.mount.bytes += int64(len(e.data) + len(e.target))
	if len(w.mount.entries) > mirrorTreeMaxEntries || w.mount.bytes > mirrorTreeMaxBytes {
		return errMirrorTooLarge
	}
	return nil
}

// dir reads the directory open as dir, at rel below the mount's root, in
// name order.
func (w *mirrorWalk) dir(dir *os.File, rel string) error {
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("reading the directory %s in it: %w", quoteForLog(path.Join(".", rel)), err)
	}
	sort.Strings(names)
	dirFD := int(dir.Fd())
	for _, name := range names {
		child := name
		if rel != "" {
			child = rel + "/" + name
		}
		pfd, err := unix.Openat(dirFD, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			w.special++
			continue
		}
		err = w.entry(pfd, name, child)
		unix.Close(pfd)
		if err != nil {
			return err
		}
	}
	return nil
}

// entry reads the entry name, at child below the mount's root, which pfd
// holds open with O_PATH, and opens it again for reading only once its type
// is known to be a directory or a regular file.
func (w *mirrorWalk) entry(pfd int, name, child string) error {
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		w.special++
		return nil
	}
	e := mirrorEntry{rel: child, perm: st.Mode & 0o777, uid: st.Uid, gid: st.Gid}
	if w.points[w.mount.path+"/"+child] {
		// Another mount's place, which that mount fills if the guest gets
		// it.
		e.kind, e.place = mirrorFile, true
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			e.kind = mirrorDir
		}
		return w.add(e)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		sub, err := reopenMirrorFD(pfd, unix.O_RDONLY|unix.O_DIRECTORY, name)
		if err != nil {
			w.special++
			return nil
		}
		defer sub.Close()
		e.kind = mirrorDir
		if err := w.add(e); err != nil {
			return err
		}
		return w.dir(sub, child)
	case unix.S_IFREG:
		if st.Size > mirrorFileMaxBytes {
			return errMirrorTooLarge
		}
		file, err := reopenMirrorFD(pfd, unix.O_RDONLY|unix.O_NONBLOCK, name)
		if err != nil {
			w.special++
			return nil
		}
		data, err := readMirrorData(file, mirrorFileMaxBytes)
		file.Close()
		if errors.Is(err, errMirrorTooLarge) {
			return err
		}
		if err != nil {
			w.special++
			return nil
		}
		e.kind, e.data, e.state = mirrorFile, data, fileStateOf(&st)
		return w.add(e)
	case unix.S_IFLNK:
		// An O_PATH descriptor of a link names the link itself, which
		// readlinkat reads with an empty name.
		target, err := readlinkAt(pfd, "")
		if err != nil {
			w.special++
			return nil
		}
		e.kind, e.target = mirrorLink, target
		return w.add(e)
	}
	w.special++
	return nil
}

// readlinkAt returns the target of the symbolic link name in the directory
// dirFD, or of the link dirFD holds with O_PATH when name is empty.
func readlinkAt(dirFD int, name string) (string, error) {
	for size := 256; size <= 1<<16; size *= 4 {
		buf := make([]byte, size)
		n, err := unix.Readlinkat(dirFD, name, buf)
		if err != nil {
			return "", err
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
	return "", errors.New("the link's target is too long")
}

// number gives each mount its staging directory and each small enough
// regular file a watch number, up to mirrorWatchMaxFiles of them. A file
// mount is rewritten in place in the guest, as a bound file is when the host
// rewrites it, and a file in a tree is replaced by a rename.
func (m *mountMirror) number() {
	for i := range m.mounts {
		mm := &m.mounts[i]
		stage := guestMirrorStage + "/" + fmt.Sprint(i+1)
		for j := range mm.entries {
			e := &mm.entries[j]
			if e.kind != mirrorFile || len(e.data) > mirrorWatchMaxBytes || len(m.watched) == mirrorWatchMaxFiles {
				continue
			}
			if e.place {
				continue
			}
			w := &mirrorWatched{number: len(m.watched) + 1, path: mm.path, guest: stage, inPlace: !mm.dir, uid: e.uid, gid: e.gid, data: e.data, perm: e.perm}
			if mm.dir {
				w.path, w.guest = mm.path+"/"+e.rel, stage+"/"+e.rel
			}
			// The state comes from the open that read data, so a change
			// after that read still differs from it.
			w.state = e.state
			e.watch = w.number
			m.watched = append(m.watched, w)
		}
	}
}

// summary is the launch's line about the mirrored mounts.
func (m *mountMirror) summary() string {
	parts := make([]string, len(m.mounts))
	for i, mm := range m.mounts {
		if mm.dir {
			parts[i] = fmt.Sprintf("%s (a directory of %d entries, %d bytes)", quoteForLog(mm.path), len(mm.entries)-1, mm.bytes)
		} else {
			parts[i] = fmt.Sprintf("%s (a file of %d bytes)", quoteForLog(mm.path), mm.bytes)
		}
	}
	return fmt.Sprintf("mirroring %d of the container's mounts into the guest, read-only: %s; vm-launch pushes changes to %d of their files", len(m.mounts), strings.Join(parts, ", "), len(m.watched))
}

// mirrorEnvNames are the variables that name a path in a mount that the
// guest may get by mirroring. guestEnvDenylist drops them, and the guest
// keeps each one whose path lies in a mirrored mount (see keptEnv).
var mirrorEnvNames = []string{"SERVICE_BINDING_ROOT", "VCAP_SERVICES_FILE_PATH"}

// keptEnv returns the names of mirrorEnvNames whose values in env name a
// path at or below a mirrored mount, which the guest environment keeps. A
// nil mirror keeps none.
func (m *mountMirror) keptEnv(env map[string]string) []string {
	if m == nil {
		return nil
	}
	var keep []string
	for _, name := range mirrorEnvNames {
		v, ok := env[name]
		if !ok || !mirrorPathUsable(v) {
			continue
		}
		for _, mm := range m.mounts {
			if underDir(v, mm.path) {
				keep = append(keep, name)
				break
			}
		}
	}
	return keep
}

// statMirrorFile returns the state of the regular file at p, opened without
// following a symbolic link, and false when it is missing, is not a regular
// file, or cannot be opened.
func statMirrorFile(p string) (fileState, bool) {
	fd, err := openat2Retry(unix.AT_FDCWD, p, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return fileState{}, false
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fileState{}, false
	}
	return fileStateOf(&st), true
}

// readMirrorFile reads the regular file at p, at most max bytes of it,
// without following a symbolic link and without opening anything but a
// regular file for reading (see reopenMirrorFD), and returns its state and
// permission bits as it was read.
func readMirrorFile(p string, max int64) ([]byte, fileState, uint32, error) {
	pfd, err := openat2Retry(unix.AT_FDCWD, p, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fileState{}, 0, err
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return nil, fileState{}, 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fileState{}, 0, errNotRegular
	}
	f, err := reopenMirrorFD(pfd, unix.O_RDONLY|unix.O_NONBLOCK, p)
	if err != nil {
		return nil, fileState{}, 0, err
	}
	defer f.Close()
	data, err := readMirrorData(f, max)
	if err != nil {
		return nil, fileState{}, 0, err
	}
	return data, fileStateOf(&st), st.Mode & 0o777, nil
}
