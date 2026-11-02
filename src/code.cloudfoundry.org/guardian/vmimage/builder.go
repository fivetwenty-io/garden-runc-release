// Package vmimage builds the read-only squashfs image of a Docker image that
// a VM guest boots from. It builds each image once per chain of image layers,
// keeps it in a cache directory on the data disk, and hands Garden a
// directory of hard links to it for each container.
package vmimage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/lager/v3"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	// imageName is the name of the finished image inside its cache entry and
	// inside each container's directory.
	imageName = "rootfs.squashfs"
	// passwdName and groupName name the copies of the image's account files.
	passwdName = "passwd"
	groupName  = "group"

	containersName = "containers"
	tempPrefix     = ".build-"
	lockSuffix     = ".lock"

	buildTimeout = 30 * time.Minute

	// maxFileBytes bounds the dependency record and each account file.
	maxFileBytes  = 1 << 20
	maxToolOutput = 64 * 1024
)

// niceBinary is run by absolute path, because Garden runs as root and its PATH
// must not decide which program a build starts.
const niceBinary = "/usr/bin/nice"

var errLocked = errors.New("another process holds the lock")

// recipeVersion names the way the builder turns a root file system into an
// image. It goes into every cache key beside the mksquashfs options and the
// mksquashfs binary's hash, so a change to the build that those do not show,
// such as a post-processing step, bumps it by hand and retires every older
// image.
const recipeVersion = "1"

// Volumizer is the part of Garden's volumizer that the builder uses.
// gardener.Volumizer satisfies it.
type Volumizer interface {
	Create(log lager.Logger, spec garden.ContainerSpec) (specs.Spec, error)
	Destroy(log lager.Logger, handle string) error
}

type Config struct {
	// Mksquashfs is the absolute path of the static mksquashfs binary.
	Mksquashfs string
	// CacheDir is an absolute path. It holds one directory per cache key, each
	// with the image and the account files inside, one lock file beside each
	// directory, and a containers directory with one directory of hard links
	// per container. The builder creates it with mode 0700 when it is missing.
	CacheDir string
	// CacheBytes is the byte budget of the cache entries, and it must be
	// greater than zero.
	CacheBytes int64
	// MaxUID is the host uid and gid that a namespaced store gives to the
	// image's uid 0 and gid 0.
	MaxUID    uint32
	Volumizer Volumizer
	Logger    lager.Logger
}

// Builder turns Docker images into squashfs images. Its methods are safe to
// call from many goroutines at once, and an exclusive lock on each cache entry
// keeps a second Garden process from building the same image at the same
// time.
type Builder struct {
	mksquashfs string
	cacheDir   string
	cacheBytes int64
	maxUID     uint32
	volumizer  Volumizer
	logger     lager.Logger

	// nice is the program that lowers the priority of a build.
	nice string
	// timeout bounds one run of mksquashfs, so a hung build cannot hold its
	// entry's lock for good.
	timeout time.Duration

	// evictMu lets only one eviction run in this process at a time.
	evictMu sync.Mutex

	mu   sync.Mutex
	tool hashed
	keys map[string]*keyMutex
}

// keyMutex serializes the callers of one cache key within this process. The
// count of holders and waiters lets the last one drop the mutex from the map.
type keyMutex struct {
	mu   sync.Mutex
	refs int
}

// fileID identifies a version of a file well enough to reuse its hash.
type fileID struct {
	dev, ino uint64
	size     int64
	mtime    int64
}

type hashed struct {
	id  fileID
	sum string
}

// New checks the configuration, creates the cache directories, and removes
// the temporary directories that a crashed build left behind.
func New(cfg Config) (*Builder, error) {
	if !filepath.IsAbs(cfg.Mksquashfs) {
		return nil, fmt.Errorf("vm image: the mksquashfs path %q is not absolute", cfg.Mksquashfs)
	}
	if !filepath.IsAbs(cfg.CacheDir) {
		return nil, fmt.Errorf("vm image: the cache directory %q is not absolute", cfg.CacheDir)
	}
	if cfg.CacheBytes <= 0 {
		return nil, fmt.Errorf("vm image: the cache budget of %d bytes is not greater than zero", cfg.CacheBytes)
	}
	if cfg.Volumizer == nil {
		return nil, errors.New("vm image: there is no volumizer")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = lager.NewLogger("vmimage")
	}

	b := &Builder{
		mksquashfs: cfg.Mksquashfs,
		cacheDir:   filepath.Clean(cfg.CacheDir),
		cacheBytes: cfg.CacheBytes,
		maxUID:     cfg.MaxUID,
		volumizer:  cfg.Volumizer,
		logger:     logger,
		nice:       niceBinary,
		timeout:    buildTimeout,
		keys:       map[string]*keyMutex{},
	}

	if err := os.MkdirAll(b.cacheDir, 0700); err != nil {
		return nil, fmt.Errorf("vm image: creating the cache directory: %w", err)
	}
	if err := os.MkdirAll(b.containersDir(), 0755); err != nil {
		return nil, fmt.Errorf("vm image: creating the containers directory: %w", err)
	}
	if err := removeTemps(b.cacheDir); err != nil {
		return nil, fmt.Errorf("vm image: removing leftover build directories: %w", err)
	}
	return b, nil
}

// Image builds or reuses the guest image of a Docker image ref for the
// container handle. It returns the container's link directory, which holds
// rootfs.squashfs, passwd, and group, and the image's environment from the
// build image's runtime spec.
func (b *Builder) Image(log lager.Logger, handle string, image garden.ImageRef) (string, []string, error) {
	if err := checkHandle(handle); err != nil {
		return "", nil, err
	}
	log = log.Session("vm-image", lager.Data{"handle": handle})

	dir, env, err := b.prepare(log, handle, image)
	if err != nil {
		log.Error("failed", err)
		return "", nil, err
	}

	// The build image is gone by now, and the new entry has a link, so the
	// eviction cannot take what this call hands out.
	b.evict(log)
	return dir, env, nil
}

// Release removes the container's link directory. It is idempotent and
// succeeds when nothing exists, which includes a handle that Image refuses,
// because such a handle never has a directory.
func (b *Builder) Release(log lager.Logger, handle string) error {
	if checkHandle(handle) != nil {
		return nil
	}
	log = log.Session("vm-image-release", lager.Data{"handle": handle})

	if err := os.RemoveAll(b.containerDir(handle)); err != nil {
		log.Error("failed", err)
		return fmt.Errorf("vm image: removing the container directory: %w", err)
	}
	log.Info("released")
	return nil
}

// Prune removes the link directory of every handle that keep does not name,
// and then evicts what no container holds any more. Garden calls it at start,
// before it serves, with the handles of the containers that it still has, so
// a directory that a crashed create or a failed destroy left behind stops
// pinning its cache entry.
func (b *Builder) Prune(log lager.Logger, keep []string) error {
	log = log.Session("vm-image-prune")

	kept := make(map[string]bool, len(keep))
	for _, handle := range keep {
		kept[handle] = true
	}

	entries, err := os.ReadDir(b.containersDir())
	if err != nil {
		return fmt.Errorf("vm image: reading the containers directory: %w", err)
	}

	var errs []error
	for _, entry := range entries {
		if kept[entry.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(b.containersDir(), entry.Name())); err != nil {
			errs = append(errs, err)
			continue
		}
		log.Info("pruned", lager.Data{"handle": entry.Name()})
	}

	b.evict(log)
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("vm image: pruning the containers directory: %w", err)
	}
	return nil
}

// prepare creates the build image, finds or builds the cache entry of its
// layers, and links the entry into the container's directory. It destroys the
// build image before it returns, whatever the result.
func (b *Builder) prepare(log lager.Logger, handle string, image garden.ImageRef) (string, []string, error) {
	if image.URI == "" {
		return "", nil, errors.New("vm image: the image reference has no URI")
	}

	buildHandle := handle + backend.VMImageBuildSuffix
	spec, err := b.volumizer.Create(log, garden.ContainerSpec{Handle: buildHandle, Image: image})
	// The build image goes away on every path, including a failed create,
	// because a plugin can fail after it has made part of the image.
	defer b.destroy(log, buildHandle)
	if err != nil {
		return "", nil, fmt.Errorf("vm image: creating the build image: %w", err)
	}

	rootfs, store, err := locateRootfs(spec)
	if err != nil {
		return "", nil, err
	}

	chain, err := readChain(store, buildHandle)
	if err != nil {
		return "", nil, err
	}

	var env []string
	if spec.Process != nil {
		env = append(env, spec.Process.Env...)
	}

	key, err := b.key(chain)
	if err != nil {
		return "", nil, err
	}
	log = log.WithData(lager.Data{"key": key})

	if err := b.publish(log, key, rootfs, handle); err != nil {
		return "", nil, err
	}
	return b.containerDir(handle), env, nil
}

// destroy removes the build image. A failure is logged and goes no further,
// because the image that the caller wants is already built or the caller has
// a better error to report.
func (b *Builder) destroy(log lager.Logger, buildHandle string) {
	if err := b.volumizer.Destroy(log, buildHandle); err != nil {
		log.Error("destroy-build-image-failed", err, lager.Data{"build-handle": buildHandle})
	}
}

// checkHandle refuses a handle that would name something other than one
// directory directly inside the containers directory.
func checkHandle(handle string) error {
	if handle == "" || handle == "." || handle == ".." || strings.Contains(handle, "/") {
		return fmt.Errorf("vm image: the handle %q is not a valid container handle", handle)
	}
	return nil
}

// locateRootfs returns the mounted root file system of the build image and
// the store that holds it. The image plugin lays the root out as
// <store>/images/<id>/rootfs.
func locateRootfs(spec specs.Spec) (rootfs, store string, err error) {
	if len(spec.Mounts) > 0 {
		return "", "", errors.New("vm image: the image plugin did not mount the rootfs")
	}
	if spec.Root == nil {
		return "", "", errors.New("vm image: the build image has no root")
	}

	root := spec.Root.Path
	if !filepath.IsAbs(root) {
		return "", "", fmt.Errorf("vm image: the root path %q is not absolute", root)
	}
	root = filepath.Clean(root)
	if filepath.Base(root) != "rootfs" {
		return "", "", fmt.Errorf("vm image: the root path %q is not named rootfs", root)
	}
	if filepath.Base(filepath.Dir(filepath.Dir(root))) != "images" {
		return "", "", fmt.Errorf("vm image: the root path %q is not under an images directory", root)
	}
	return root, filepath.Dir(filepath.Dir(filepath.Dir(root))), nil
}

// readChain returns the chain IDs of the build image's layers, from the
// dependency record that the image plugin keeps in its store.
func readChain(store, buildHandle string) ([]string, error) {
	name := "image:" + strings.ReplaceAll(buildHandle, "/", "__") + ".json"
	path := filepath.Join(store, "meta", "dependencies", name)

	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("vm image: the dependency record %s is missing: %w", path, err)
	}
	if err != nil {
		return nil, fmt.Errorf("vm image: reading the dependency record: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("vm image: reading the dependency record: %w", err)
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("vm image: reading the dependency record: %s is larger than %d bytes", path, maxFileBytes)
	}

	var chain []string
	if err := json.Unmarshal(data, &chain); err != nil {
		return nil, fmt.Errorf("vm image: reading the dependency record: %w", err)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("vm image: reading the dependency record: %s lists no layers", path)
	}
	for _, id := range chain {
		if id == "" {
			return nil, fmt.Errorf("vm image: reading the dependency record: %s holds an empty layer ID", path)
		}
		if strings.Contains(id, "/") || strings.ContainsFunc(id, unicode.IsSpace) {
			return nil, fmt.Errorf("vm image: reading the dependency record: %s holds the layer ID %q, which has a slash or white space", path, id)
		}
	}
	return chain, nil
}

// squashfsOptions are the mksquashfs options that come after the input and
// output paths. The guest kernels read lz4, and 128 KiB is the squashfs
// default block size. The two actions map the host uid and gid that a
// namespaced store gives to the image's root back to 0 and leave every other
// owner as it is.
func (b *Builder) squashfsOptions() []string {
	return []string{
		"-noappend", "-comp", "lz4", "-b", "128K", "-no-xattrs", "-no-progress", "-quiet",
		"-action", "uid(0)@uid(" + strconv.FormatUint(uint64(b.maxUID), 10) + ")",
		"-action", "gid(0)@gid(" + strconv.FormatUint(uint64(b.maxUID), 10) + ")",
	}
}

// key returns the cache key of a chain of layers. It is the sha256 of a text
// with one line for the recipe version, each mksquashfs option, the
// mksquashfs binary's sha256, the max uid, and each chain ID, so that no two
// items can run together. It reuses the binary's hash while its device,
// inode, size, and modification time stay the same.
func (b *Builder) key(chain []string) (string, error) {
	sum, err := b.toolSum()
	if err != nil {
		return "", err
	}

	digest := sha256.New()
	fmt.Fprintf(digest, "recipe %s\n", recipeVersion)
	for _, option := range b.squashfsOptions() {
		fmt.Fprintf(digest, "option %q\n", option)
	}
	fmt.Fprintf(digest, "mksquashfs %s\n", sum)
	fmt.Fprintf(digest, "max-uid %d\n", b.maxUID)
	for _, id := range chain {
		fmt.Fprintf(digest, "layer %q\n", id)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// toolSum returns the sha256 of the mksquashfs binary.
func (b *Builder) toolSum() (string, error) {
	file, err := os.Open(b.mksquashfs)
	if err != nil {
		return "", fmt.Errorf("vm image: hashing mksquashfs: %w", err)
	}
	defer file.Close()

	id, err := fileIDOf(file)
	if err != nil {
		return "", fmt.Errorf("vm image: hashing mksquashfs: %w", err)
	}

	b.mu.Lock()
	tool := b.tool
	b.mu.Unlock()
	if tool.sum != "" && tool.id == id {
		return tool.sum, nil
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("vm image: hashing mksquashfs: %w", err)
	}
	tool = hashed{id: id, sum: hex.EncodeToString(hash.Sum(nil))}

	b.mu.Lock()
	b.tool = tool
	b.mu.Unlock()
	return tool.sum, nil
}

// publish makes the cache entry of a key ready, building it when it is
// missing, and links it into the container's directory. It holds the entry's
// locks throughout, so that an eviction cannot remove the entry between the
// build and the links.
func (b *Builder) publish(log lager.Logger, key, rootfs, handle string) error {
	unlockKey := b.lockKey(key)
	defer unlockKey()

	lock, err := lockEntry(b.lockPath(key), true)
	if err != nil {
		return fmt.Errorf("vm image: locking the cache entry: %w", err)
	}
	defer lock.Close()

	dir := b.entryDir(key)
	if entryReady(dir) {
		log.Info("cache-hit")
	} else {
		if err := b.build(log, key, rootfs); err != nil {
			return err
		}
	}

	info, err := os.Stat(filepath.Join(dir, imageName))
	if err != nil {
		return fmt.Errorf("vm image: checking the image: %w", err)
	}
	if info.Size() > b.cacheBytes {
		// The entry goes while the lock is held, and the unlink of the lock
		// file follows the pattern that lockEntry's recheck expects.
		err := fmt.Errorf("vm image: the image is %d bytes, which is more than the cache budget of %d bytes", info.Size(), b.cacheBytes)
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			return fmt.Errorf("%w (removing the entry also failed: %v)", err, rmErr)
		}
		if rmErr := os.Remove(b.lockPath(key)); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			return fmt.Errorf("%w (removing the lock file also failed: %v)", err, rmErr)
		}
		return err
	}

	if err := b.link(dir, handle); err != nil {
		return err
	}
	// The eviction orders entries by this time, so a used entry is the last
	// to go.
	now := time.Now()
	if err := os.Chtimes(dir, now, now); err != nil {
		return fmt.Errorf("vm image: marking the entry as used: %w", err)
	}
	return nil
}

// lockKey takes the in-process mutex of a key and returns the function that
// gives it back.
func (b *Builder) lockKey(key string) func() {
	b.mu.Lock()
	km, ok := b.keys[key]
	if !ok {
		km = &keyMutex{}
		b.keys[key] = km
	}
	km.refs++
	b.mu.Unlock()

	km.mu.Lock()
	return func() {
		km.mu.Unlock()

		b.mu.Lock()
		km.refs--
		if km.refs == 0 {
			delete(b.keys, key)
		}
		b.mu.Unlock()
	}
}

// entryReady reports whether a cache entry holds the image and both account
// files.
func entryReady(dir string) bool {
	for _, name := range []string{imageName, passwdName, groupName} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	return true
}

// build makes the cache entry in a temporary directory and renames the
// directory into place once the image and the account files are complete and
// on disk. The caller holds the entry's lock.
func (b *Builder) build(log lager.Logger, key, rootfs string) error {
	tmp, err := os.MkdirTemp(b.cacheDir, tempPrefix+"*")
	if err != nil {
		return fmt.Errorf("vm image: creating a build directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(tmp)
		}
	}()
	if err := os.Chmod(tmp, 0755); err != nil {
		return fmt.Errorf("vm image: creating a build directory: %w", err)
	}

	start := time.Now()
	log.Info("building")
	if err := b.runMksquashfs(rootfs, filepath.Join(tmp, imageName)); err != nil {
		return err
	}
	if err := finishImage(filepath.Join(tmp, imageName)); err != nil {
		return err
	}
	if err := copyAccounts(rootfs, tmp); err != nil {
		return err
	}
	if err := syncDir(tmp); err != nil {
		return fmt.Errorf("vm image: syncing the build directory: %w", err)
	}

	// A directory that an earlier crash or a person left half finished would
	// make the rename fail, and the caller's lock keeps every other process
	// out of the entry.
	dir := b.entryDir(key)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("vm image: removing an incomplete entry: %w", err)
	}
	if err := os.Rename(tmp, dir); err != nil {
		return fmt.Errorf("vm image: moving the entry into the cache: %w", err)
	}
	committed = true
	if err := syncDir(b.cacheDir); err != nil {
		return fmt.Errorf("vm image: syncing the cache directory: %w", err)
	}

	log.Info("built", lager.Data{"build-time": time.Since(start).String()})
	return nil
}

// runMksquashfs builds the image of rootfs at out. It runs at a lower
// priority, because a build reads the whole root file system and compresses
// it while the cell runs apps.
func (b *Builder) runMksquashfs(rootfs, out string) error {
	ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
	defer cancel()

	output := &tailBuffer{max: maxToolOutput}
	cmd := b.mksquashfsCommand(ctx, rootfs, out)
	cmd.Stdout = output
	cmd.Stderr = output
	// A child that mksquashfs leaves behind must not hold the build open
	// through its copy of the output pipe.
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("%w after %s", err, b.timeout)
		}
		return fmt.Errorf("vm image: mksquashfs: %w: %s", err, strings.TrimSpace(output.String()))
	}
	return nil
}

func (b *Builder) mksquashfsCommand(ctx context.Context, rootfs, out string) *exec.Cmd {
	args := append([]string{"-n", "10", b.mksquashfs, rootfs, out}, b.squashfsOptions()...)
	return exec.CommandContext(ctx, b.nice, args...)
}

// finishImage checks that mksquashfs wrote an image, and puts the image in
// its final mode and on disk.
func finishImage(path string) error {
	img, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("vm image: mksquashfs succeeded but wrote no image: %w", err)
	}
	defer img.Close()

	info, err := img.Stat()
	if err != nil {
		return fmt.Errorf("vm image: checking the image: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("vm image: mksquashfs succeeded but wrote a bad image")
	}
	if err := img.Chmod(0644); err != nil {
		return fmt.Errorf("vm image: finishing the image: %w", err)
	}
	if err := img.Sync(); err != nil {
		return fmt.Errorf("vm image: finishing the image: %w", err)
	}
	return img.Close()
}

// copyAccounts copies the image's etc/passwd and etc/group into dir. It reads
// them through a root at rootfs, so that a link inside the image cannot reach
// a file of the host.
func copyAccounts(rootfs, dir string) error {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return fmt.Errorf("vm image: opening the root file system: %w", err)
	}
	defer root.Close()

	for _, name := range []string{passwdName, groupName} {
		if err := copyAccount(root, "etc/"+name, filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// copyAccount writes the file at src in root to dest with mode 0644. A file
// that is missing in the image becomes an empty file, and a file that is not
// regular or is larger than maxFileBytes is an error.
func copyAccount(root *os.Root, src, dest string) error {
	var data []byte

	// The open must not block on a named pipe that the image put in place of
	// the file.
	f, err := root.OpenFile(src, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return fmt.Errorf("vm image: reading /%s from the image: %w", src, err)
	default:
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return fmt.Errorf("vm image: reading /%s from the image: %w", src, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("vm image: /%s in the image is not a regular file", src)
		}
		if info.Size() > maxFileBytes {
			return fmt.Errorf("vm image: /%s in the image is %d bytes, which is more than %d bytes", src, info.Size(), maxFileBytes)
		}
		data, err = io.ReadAll(io.LimitReader(f, maxFileBytes+1))
		if err != nil {
			return fmt.Errorf("vm image: reading /%s from the image: %w", src, err)
		}
		if len(data) > maxFileBytes {
			return fmt.Errorf("vm image: /%s in the image is more than %d bytes", src, maxFileBytes)
		}
	}

	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("vm image: writing %s: %w", filepath.Base(dest), err)
	}
	defer out.Close()
	if _, err := out.Write(data); err != nil {
		return fmt.Errorf("vm image: writing %s: %w", filepath.Base(dest), err)
	}
	// The umask can narrow the mode that the open asked for.
	if err := out.Chmod(0644); err != nil {
		return fmt.Errorf("vm image: writing %s: %w", filepath.Base(dest), err)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("vm image: writing %s: %w", filepath.Base(dest), err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("vm image: writing %s: %w", filepath.Base(dest), err)
	}
	return nil
}

// link replaces the container's directory with a fresh one that holds hard
// links to the entry's three files. It builds the new directory beside the
// cache entries and renames it into place.
func (b *Builder) link(entry, handle string) error {
	if err := os.MkdirAll(b.containersDir(), 0755); err != nil {
		return fmt.Errorf("vm image: creating the containers directory: %w", err)
	}
	tmp, err := os.MkdirTemp(b.cacheDir, tempPrefix+"container-*")
	if err != nil {
		return fmt.Errorf("vm image: creating the container directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(tmp)
		}
	}()
	if err := os.Chmod(tmp, 0755); err != nil {
		return fmt.Errorf("vm image: creating the container directory: %w", err)
	}

	for _, name := range []string{imageName, passwdName, groupName} {
		if err := os.Link(filepath.Join(entry, name), filepath.Join(tmp, name)); err != nil {
			return fmt.Errorf("vm image: linking %s into the container directory: %w", name, err)
		}
	}

	dest := b.containerDir(handle)
	if err := os.RemoveAll(dest); err != nil {
		return fmt.Errorf("vm image: replacing the container directory: %w", err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		return fmt.Errorf("vm image: replacing the container directory: %w", err)
	}
	committed = true
	return nil
}

// cached describes one cache entry for the eviction.
type cached struct {
	key   string
	size  int64
	mtime time.Time
}

// evict removes the oldest entries until the sum of their bytes fits the
// budget. It leaves an entry that a container links and an entry whose lock
// another build holds. A failure is logged and never fails a create.
func (b *Builder) evict(log lager.Logger) {
	b.evictMu.Lock()
	defer b.evictMu.Unlock()

	log = log.Session("evict")

	dirEntries, err := os.ReadDir(b.cacheDir)
	if err != nil {
		log.Error("read-cache-dir", err)
		return
	}

	var entries []cached
	var total int64
	for _, e := range dirEntries {
		if !e.IsDir() || !isKey(e.Name()) {
			continue
		}
		info, err := e.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			log.Error("stat-entry", err, lager.Data{"key": e.Name()})
			continue
		}
		size, err := entrySize(filepath.Join(b.cacheDir, e.Name()))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			log.Error("size-entry", err, lager.Data{"key": e.Name()})
			continue
		}
		entries = append(entries, cached{key: e.Name(), size: size, mtime: info.ModTime()})
		total += size
	}
	if total <= b.cacheBytes {
		return
	}

	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].mtime.Equal(entries[j].mtime) {
			return entries[i].mtime.Before(entries[j].mtime)
		}
		return entries[i].key < entries[j].key
	})

	for _, e := range entries {
		if total <= b.cacheBytes {
			break
		}
		removed, err := b.removeEntry(e.key)
		if err != nil {
			log.Error("remove-failed", err, lager.Data{"key": e.key})
			continue
		}
		if !removed {
			continue
		}
		total -= e.size
		log.Info("removed", lager.Data{"key": e.key, "bytes": e.size})
	}
	if total > b.cacheBytes {
		log.Info("over-budget", lager.Data{"bytes": total, "budget": b.cacheBytes})
	}
}

// removeEntry removes a cache entry unless a container links its image or
// another build holds its lock, and it reports whether it removed the entry.
func (b *Builder) removeEntry(key string) (bool, error) {
	lock, err := lockEntry(b.lockPath(key), false)
	if errors.Is(err, errLocked) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer lock.Close()

	dir := b.entryDir(key)
	links, err := linkCount(filepath.Join(dir, imageName))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if links > 1 {
		return false, nil
	}

	if err := os.RemoveAll(dir); err != nil {
		return false, err
	}
	// A builder that opened the lock file before this unlink checks, once it
	// holds the lock, that the path still names the file it locked.
	if err := os.Remove(b.lockPath(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	return true, nil
}

// entrySize returns the sum of the sizes of the files in a cache entry.
func entrySize(dir string) (int64, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var size int64
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		info, err := f.Info()
		if err != nil {
			return 0, err
		}
		size += info.Size()
	}
	return size, nil
}

func (b *Builder) containersDir() string {
	return filepath.Join(b.cacheDir, containersName)
}

func (b *Builder) containerDir(handle string) string {
	return filepath.Join(b.containersDir(), handle)
}

func (b *Builder) entryDir(key string) string {
	return filepath.Join(b.cacheDir, key)
}

func (b *Builder) lockPath(key string) string {
	return filepath.Join(b.cacheDir, key+lockSuffix)
}

// lockEntry takes an exclusive flock on the lock file at path, creating it
// if needed. With wait false it fails at once when another holder has it.
// The eviction unlinks lock files, so once the lock is held lockEntry checks
// that the path still names the locked file and starts over when it does not.
func lockEntry(path string, wait bool) (*os.File, error) {
	for {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return nil, err
		}
		if err := lockFile(f, wait); err != nil {
			f.Close()
			if errors.Is(err, errLocked) {
				return nil, errLocked
			}
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}

		held, err := fileIDOf(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		named, err := statID(path)
		if err == nil && named.dev == held.dev && named.ino == held.ino {
			return f, nil
		}
		f.Close()
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
}

// removeTemps deletes the temporary directories of builds that a crash or a
// kill left behind.
func removeTemps(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), tempPrefix) {
			if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func statID(path string) (fileID, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileID{}, err
	}
	return idOf(info)
}

func fileIDOf(f *os.File) (fileID, error) {
	info, err := f.Stat()
	if err != nil {
		return fileID{}, err
	}
	return idOf(info)
}

func isKey(name string) bool {
	if len(name) != sha256.Size*2 {
		return false
	}
	for _, c := range name {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// tailBuffer keeps the last max bytes written to it, which is the part of a
// tool's output that names its error.
type tailBuffer struct {
	max int
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	return string(t.buf)
}
