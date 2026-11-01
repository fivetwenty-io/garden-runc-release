// Package vmstack builds the read-only squashfs image of a stack tarball
// that a VM guest mounts as its root file system. It builds each image once
// per tarball content, keeps it in a cache directory on the data disk, and
// hands Garden the directory that holds it.
package vmstack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"code.cloudfoundry.org/lager/v3"
)

const (
	// imageName is the name of the finished image inside its cache entry.
	imageName = "rootfs.squashfs"

	tempPrefix      = "." + imageName + "-"
	lockSuffix      = ".lock"
	failureBackoff  = 60 * time.Second
	maxBackoff      = 15 * time.Minute
	buildTimeout    = 30 * time.Minute
	verifyTimeout   = 5 * time.Minute
	maxHashAttempts = 5
	maxToolOutput   = 64 * 1024
)

// niceBinary is run by absolute path, because Garden runs as root and its PATH
// must not decide which program a build starts.
const niceBinary = "/usr/bin/nice"

var errLocked = errors.New("another build holds the lock")

// sqfstarArgs are the build options that come before the output path. The
// guest kernels read lz4, and 128 KiB is the squashfs default block size.
var sqfstarArgs = []string{"-comp", "lz4", "-b", "128K", "-mem", "256M", "-processors", "1", "-no-progress", "-quiet"}

// recipeVersion names the way the builder turns a tarball into an image. It
// goes into every cache key beside sqfstarArgs and the sqfstar binary's hash,
// so a change to the build that those two do not show, such as a post-processing
// step, bumps it by hand and retires every older image.
const recipeVersion = "1"

type Config struct {
	// Sqfstar is the path of the static sqfstar binary.
	Sqfstar string
	// CacheDir holds one directory per cache key, each with the image inside,
	// and one lock file beside each directory. A key is the sha256 of a
	// tarball's own sha256 and the build recipe, which is the recipe version,
	// the sqfstar options, and the sqfstar binary's sha256.
	CacheDir string
	// Unsquashfs is the path of the static unsquashfs binary. When it is set,
	// the builder checks the whole of each cached image once per process
	// before it hands the image out, and rebuilds an image that fails. When
	// it is empty, the builder trusts an image whose superblock is sound.
	Unsquashfs string
	// Tarballs lists the only tarballs the builder will build.
	Tarballs []string
	// Wait bounds how long Image waits for a build that is running.
	Wait   time.Duration
	Logger lager.Logger
}

// Builder turns listed stack tarballs into squashfs images. Its methods are
// safe to call from many goroutines at once, and an exclusive lock on each
// cache entry keeps a second Garden process from building the same image at
// the same time.
type Builder struct {
	sqfstar    string
	unsquashfs string
	cacheDir   string
	wait       time.Duration
	logger     lager.Logger
	tarballs   []string
	listed     map[string]bool

	// backoff is how long the first failed build keeps the next one from
	// starting. Each further failure of the same key doubles it, up to
	// maxBackoff.
	backoff time.Duration
	// timeout bounds one run of sqfstar, so a hung build cannot hold its
	// entry's lock for good.
	timeout time.Duration
	// verifyTimeout bounds one whole-image check the same way.
	verifyTimeout time.Duration
	// afterHash, when set, runs after each hash of a tarball and before the
	// second stat, so a spec can rewrite the tarball part way.
	afterHash func(path string)

	mu       sync.Mutex
	hashes   map[string]hashed
	tool     hashed
	resolves map[string]*flight
	builds   map[string]*flight
	failures map[string]failure
	// verified holds the keys whose images passed the whole-image check in
	// this process.
	verified map[string]bool
}

// failure records the last failed build of a key and how long it keeps the
// next try away.
type failure struct {
	at    time.Time
	delay time.Duration
}

// fileID identifies a version of a tarball well enough to reuse its hash.
type fileID struct {
	dev, ino uint64
	size     int64
	mtime    int64
}

type hashed struct {
	id  fileID
	sum string
}

// entry is the result of keying a tarball. The sum is the tarball's own
// sha256, and the key names its cache entry.
type entry struct {
	key, sum string
}

// flight is one piece of work that many callers can wait on. Its result
// fields are written before done closes and read only after.
type flight struct {
	done chan struct{}
	dir  string
	err  error
}

func New(config Config) *Builder {
	logger := config.Logger
	if logger == nil {
		logger = lager.NewLogger("vmstack")
	}

	b := &Builder{
		sqfstar:       config.Sqfstar,
		unsquashfs:    config.Unsquashfs,
		cacheDir:      filepath.Clean(config.CacheDir),
		wait:          config.Wait,
		logger:        logger,
		listed:        map[string]bool{},
		backoff:       failureBackoff,
		timeout:       buildTimeout,
		verifyTimeout: verifyTimeout,
		hashes:        map[string]hashed{},
		resolves:      map[string]*flight{},
		builds:        map[string]*flight{},
		failures:      map[string]failure{},
		verified:      map[string]bool{},
	}
	for _, tarball := range config.Tarballs {
		path := filepath.Clean(tarball)
		if b.listed[path] {
			continue
		}
		b.listed[path] = true
		b.tarballs = append(b.tarballs, path)
	}
	return b
}

// Image returns the cache directory that holds the finished image of a
// listed tarball. It starts a build when there is no image, waits at most the
// configured bound for it, and returns false when the bound passes first. The
// build carries on after Image returns, so a later call finds the image.
func (b *Builder) Image(log lager.Logger, tarball string) (string, bool) {
	log = log.Session("vm-stack-image", lager.Data{"tarball": tarball})

	path := filepath.Clean(tarball)
	if !b.listed[path] {
		log.Info("tarball-not-listed")
		return "", false
	}

	if dir, ok := b.ready(path); ok {
		return dir, true
	}

	f := b.resolve(path)
	timer := time.NewTimer(b.wait)
	defer timer.Stop()

	select {
	case <-f.done:
	case <-timer.C:
		select {
		case <-f.done:
		default:
			log.Info("still-building", lager.Data{"wait": b.wait.String()})
			return "", false
		}
	}

	if f.err != nil {
		log.Error("no-image", f.err)
		return "", false
	}
	return f.dir, true
}

// WarmUp builds the image of every listed tarball that exists and returns
// when every build has finished or failed, so callers run it in a goroutine.
// It goes through the same resolutions and entry locks as Image, so a create
// that arrives during the warm-up waits on the build that the warm-up started.
func (b *Builder) WarmUp() {
	log := b.logger.Session("warm-up")
	start := time.Now()
	log.Info("started", lager.Data{"tarballs": b.tarballs})

	type pending struct {
		tarball string
		f       *flight
	}
	var flights []pending
	for _, path := range b.tarballs {
		if _, err := os.Stat(path); err != nil {
			log.Info("tarball-unavailable", lager.Data{"tarball": path, "error": err.Error()})
			continue
		}
		flights = append(flights, pending{tarball: path, f: b.resolve(path)})
	}

	for _, p := range flights {
		<-p.f.done
		if p.f.err != nil {
			log.Error("vm-stack-image-failed", p.f.err, lager.Data{"tarball": p.tarball})
			continue
		}
		log.Info("vm-stack-image-ready", lager.Data{"tarball": p.tarball, "dir": p.f.dir, "elapsed": time.Since(start).String()})
	}
	log.Info("finished", lager.Data{"elapsed": time.Since(start).String()})
}

// Clean removes every cache entry whose key matches no listed tarball's
// current key, which includes entries that an older build recipe made. It keeps the whole cache when it cannot hash a listed
// tarball that exists, and it skips an entry whose lock another build holds.
func (b *Builder) Clean() {
	log := b.logger.Session("clean")

	keep := map[string]bool{}
	for _, path := range b.tarballs {
		e, err := b.key(log, path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			log.Error("keeping-cache", err, lager.Data{"tarball": path})
			return
		}
		keep[e.key] = true
	}

	entries, err := os.ReadDir(b.cacheDir)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		log.Error("read-cache-dir", err)
		return
	}

	stale := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() && isKey(name) {
			stale[name] = !keep[name]
		} else if !entry.IsDir() && strings.HasSuffix(name, lockSuffix) && isKey(strings.TrimSuffix(name, lockSuffix)) {
			key := strings.TrimSuffix(name, lockSuffix)
			stale[key] = !keep[key]
		}
	}

	for key, remove := range stale {
		if !remove {
			continue
		}
		err := b.removeEntry(key)
		if errors.Is(err, errLocked) {
			log.Info("entry-in-use", lager.Data{"key": key})
			continue
		}
		if err != nil {
			log.Error("remove-failed", err, lager.Data{"key": key})
			continue
		}
		log.Info("removed", lager.Data{"key": key})
	}
}

func (b *Builder) removeEntry(key string) error {
	lock, err := lockEntry(b.lockPath(key), false)
	if err != nil {
		return err
	}
	defer lock.Close()

	if err := os.RemoveAll(filepath.Join(b.cacheDir, key)); err != nil {
		return err
	}
	// A builder that opened the lock file before this unlink checks, once it
	// holds the lock, that the path still names the file it locked.
	return os.Remove(b.lockPath(key))
}

// ready returns the image directory without waiting when the tarball's
// hash is already known and its image is in place.
func (b *Builder) ready(path string) (string, bool) {
	id, err := statID(path)
	if err != nil {
		return "", false
	}

	b.mu.Lock()
	h, ok := b.hashes[path]
	b.mu.Unlock()
	if !ok || h.id != id {
		return "", false
	}

	recipe, err := b.recipe()
	if err != nil {
		return "", false
	}

	key := entryKey(h.sum, recipe)
	dir := filepath.Join(b.cacheDir, key)
	if checkImagePath(filepath.Join(dir, imageName)) != nil || !b.isVerified(key) {
		return "", false
	}
	return dir, true
}

// resolve returns the running resolution of a tarball, or starts one. A
// resolution hashes the tarball and then finds or builds its image.
func (b *Builder) resolve(path string) *flight {
	b.mu.Lock()
	defer b.mu.Unlock()

	if f, ok := b.resolves[path]; ok {
		return f
	}

	f := &flight{done: make(chan struct{})}
	b.resolves[path] = f
	go func() {
		log := b.logger.Session("resolve", lager.Data{"tarball": path})
		f.dir, f.err = b.resolveImage(log, path)

		b.mu.Lock()
		delete(b.resolves, path)
		b.mu.Unlock()
		close(f.done)
	}()
	return f
}

func (b *Builder) resolveImage(log lager.Logger, path string) (string, error) {
	e, err := b.key(log, path)
	if err != nil {
		return "", err
	}
	key := e.key

	b.mu.Lock()
	f, ok := b.builds[key]
	if !ok {
		f = &flight{done: make(chan struct{})}
		b.builds[key] = f
	}
	b.mu.Unlock()

	if ok {
		<-f.done
		return f.dir, f.err
	}

	f.dir, f.err = b.build(log.Session("build", lager.Data{"key": key}), e, path)

	b.mu.Lock()
	delete(b.builds, key)
	b.mu.Unlock()
	close(f.done)
	return f.dir, f.err
}

// key returns the cache key of a tarball, together with the tarball's own
// sha256.
func (b *Builder) key(log lager.Logger, path string) (entry, error) {
	sum, err := b.hash(log, path)
	if err != nil {
		return entry{}, err
	}

	recipe, err := b.recipe()
	if err != nil {
		return entry{}, err
	}

	return entry{key: entryKey(sum, recipe), sum: sum}, nil
}

// entryKey is the sha256 of the recipe and the tarball's sha256, in the
// 64 lowercase hex digits that isKey accepts.
func entryKey(sum, recipe string) string {
	key := sha256.Sum256([]byte(recipe + "\n" + sum))
	return hex.EncodeToString(key[:])
}

// recipe returns a digest of everything about the build, other than the
// tarball, that changes the image: the recipe version, the sqfstar options,
// and the sqfstar binary's sha256. It reuses the binary's hash while its
// device, inode, size, and modification time stay the same.
func (b *Builder) recipe() (string, error) {
	file, err := os.Open(b.sqfstar)
	if err != nil {
		return "", fmt.Errorf("hash sqfstar: %w", err)
	}
	defer file.Close()

	id, err := fileIDOf(file)
	if err != nil {
		return "", fmt.Errorf("hash sqfstar: %w", err)
	}

	b.mu.Lock()
	tool := b.tool
	b.mu.Unlock()
	if tool.sum == "" || tool.id != id {
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			return "", fmt.Errorf("hash sqfstar: %w", err)
		}
		tool = hashed{id: id, sum: hex.EncodeToString(hash.Sum(nil))}

		b.mu.Lock()
		b.tool = tool
		b.mu.Unlock()
	}

	digest := sha256.New()
	fmt.Fprintf(digest, "recipe %s\n", recipeVersion)
	for _, arg := range sqfstarArgs {
		fmt.Fprintf(digest, "arg %q\n", arg)
	}
	fmt.Fprintf(digest, "sqfstar %s\n", tool.sum)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// hash returns the sha256 of a tarball. It reuses the last hash while the
// tarball's device, inode, size, and modification time stay the same, and it
// hashes again when they change while it reads.
func (b *Builder) hash(log lager.Logger, path string) (string, error) {
	for attempt := 1; attempt <= maxHashAttempts; attempt++ {
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		before, err := fileIDOf(file)
		if err != nil {
			file.Close()
			return "", err
		}

		b.mu.Lock()
		h, ok := b.hashes[path]
		b.mu.Unlock()
		if ok && h.id == before {
			file.Close()
			return h.sum, nil
		}

		start := time.Now()
		hash := sha256.New()
		_, err = io.Copy(hash, file)
		file.Close()
		if err != nil {
			return "", fmt.Errorf("hash %s: %w", path, err)
		}
		if b.afterHash != nil {
			b.afterHash(path)
		}

		after, err := statID(path)
		if err != nil {
			return "", err
		}
		if after != before {
			log.Info("tarball-changed-while-hashing", lager.Data{"tarball": path, "attempt": attempt})
			continue
		}

		sum := hex.EncodeToString(hash.Sum(nil))
		b.mu.Lock()
		b.hashes[path] = hashed{id: before, sum: sum}
		b.mu.Unlock()
		log.Info("hashed", lager.Data{"tarball": path, "sha256": sum, "elapsed": time.Since(start).String()})
		return sum, nil
	}
	return "", fmt.Errorf("%s changed during each of %d hashes", path, maxHashAttempts)
}

// build returns the directory of the finished image for a key, building it
// under the entry's lock when it is missing or damaged. Every failure after
// the backoff check starts a backoff, so a cell that cannot finish a build
// does not start a new one at every request.
func (b *Builder) build(log lager.Logger, e entry, tarball string) (string, error) {
	key := e.key
	dir := filepath.Join(b.cacheDir, key)
	image := filepath.Join(dir, imageName)
	if checkImagePath(image) == nil && b.isVerified(key) {
		return dir, nil
	}

	b.mu.Lock()
	last, failed := b.failures[key]
	b.mu.Unlock()
	if failed && time.Since(last.at) < last.delay {
		return "", fmt.Errorf("the last build of %s failed %s ago, so the next try waits until %s have passed", tarball, time.Since(last.at).Round(time.Second), last.delay)
	}

	start := time.Now()
	err := b.buildLocked(log, e, tarball)
	if err != nil {
		b.recordFailure(key, last, failed)
		log.Error("build-failed", err, lager.Data{"tarball": tarball, "elapsed": time.Since(start).String()})
		return "", err
	}

	b.mu.Lock()
	delete(b.failures, key)
	b.mu.Unlock()
	return dir, nil
}

// recordFailure starts or lengthens the backoff of a key.
func (b *Builder) recordFailure(key string, last failure, failed bool) {
	delay := b.backoff
	if failed {
		delay = min(max(last.delay*2, b.backoff), max(maxBackoff, b.backoff))
	}

	b.mu.Lock()
	b.failures[key] = failure{at: time.Now(), delay: delay}
	b.mu.Unlock()
}

// buildLocked builds the image under the entry's lock unless another process
// finished it while this one waited.
func (b *Builder) buildLocked(log lager.Logger, e entry, tarball string) error {
	key := e.key
	dir := filepath.Join(b.cacheDir, key)
	image := filepath.Join(dir, imageName)

	if err := os.MkdirAll(b.cacheDir, 0755); err != nil {
		return err
	}
	lock, err := lockEntry(b.lockPath(key), true)
	if err != nil {
		return err
	}
	defer lock.Close()

	// Another Garden process may have finished the image while this one
	// waited for the lock.
	err = checkImagePath(image)
	if err == nil && !b.isVerified(key) {
		err = b.verifyImage(image)
	}
	if err == nil {
		b.markVerified(key)
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		log.Info("removing-bad-image", lager.Data{"image": image, "reason": err.Error()})
		if err := os.Remove(image); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0755); err != nil {
		return err
	}
	if err := removeTemps(dir); err != nil {
		return err
	}

	start := time.Now()
	log.Info("building", lager.Data{"tarball": tarball})
	if err := b.runSqfstar(e.sum, tarball, dir); err != nil {
		return err
	}

	b.markVerified(key)
	log.Info("built", lager.Data{"tarball": tarball, "image": image, "build-time": time.Since(start).String()})
	return nil
}

func (b *Builder) isVerified(key string) bool {
	if b.unsquashfs == "" {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.verified[key]
}

func (b *Builder) markVerified(key string) {
	b.mu.Lock()
	b.verified[key] = true
	b.mu.Unlock()
}

// verifyImage checks the whole of a cached image, which the superblock test
// cannot do. It has unsquashfs read the superblock and then list every
// directory, which walks all of the image's metadata, and it reads the file
// to its end so that a medium error in a data block shows up as well. It does
// nothing when no unsquashfs is configured.
func (b *Builder) verifyImage(image string) error {
	if b.unsquashfs == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.verifyTimeout)
	defer cancel()

	for _, flag := range []string{"-s", "-ll"} {
		output := &tailBuffer{max: maxToolOutput}
		cmd := exec.CommandContext(ctx, niceBinary, "-n", "10", b.unsquashfs, flag, image)
		cmd.Stdout = output
		cmd.Stderr = output
		cmd.WaitDelay = 10 * time.Second
		if err := cmd.Run(); err != nil {
			if ctx.Err() != nil {
				err = fmt.Errorf("%w after %s", err, b.verifyTimeout)
			}
			// The error is formatted without %w so that a missing unsquashfs
			// binary reads as a failed check, not as a missing image.
			return fmt.Errorf("unsquashfs %s %s: %v: %s", flag, image, err, strings.TrimSpace(output.String()))
		}
	}

	f, err := os.Open(image)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(io.Discard, f); err != nil {
		return fmt.Errorf("read %s: %w", image, err)
	}
	return nil
}

// runSqfstar builds the image into a temporary file in dir and renames it
// into place only once it is complete and on disk. The tarball streams
// through a hash on its way to sqfstar, so an image never lands under a key
// whose tarball hash its content does not match.
func (b *Builder) runSqfstar(want, tarball, dir string) error {
	tmp, err := os.CreateTemp(dir, tempPrefix+"*")
	if err != nil {
		return err
	}
	// sqfstar refuses to write over an existing file, so it gets the unique
	// name without the file. The entry's lock keeps every other build out of
	// dir until this one is done.
	tmpPath := tmp.Name()
	tmp.Close()
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			os.Remove(tmpPath)
		}
	}()

	src, err := os.Open(tarball)
	if err != nil {
		return err
	}
	defer src.Close()

	hash := sha256.New()
	output := &tailBuffer{max: maxToolOutput}
	ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
	defer cancel()
	cmd := b.sqfstarCommand(ctx, tmpPath)
	cmd.Stdin = io.TeeReader(src, hash)
	cmd.Stdout = output
	cmd.Stderr = output
	// A child that sqfstar leaves behind must not hold the build open
	// through its copy of the output pipe.
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("%w after %s", err, b.timeout)
		}
		return fmt.Errorf("sqfstar: %w: %s", err, strings.TrimSpace(output.String()))
	}

	// sqfstar can stop reading at the end-of-archive blocks, so the hash
	// takes whatever padding it left.
	if _, err := io.Copy(hash, src); err != nil {
		return fmt.Errorf("hash %s: %w", tarball, err)
	}
	if sum := hex.EncodeToString(hash.Sum(nil)); sum != want {
		return fmt.Errorf("%s changed during the build, from sha256 %s to %s", tarball, want, sum)
	}

	img, err := os.OpenFile(tmpPath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err := finishImage(img); err != nil {
		img.Close()
		return err
	}
	if err := img.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, filepath.Join(dir, imageName)); err != nil {
		return err
	}
	committed = true
	return syncDir(dir)
}

// sqfstarCommand runs sqfstar at a lower priority, because a build reads the
// whole tarball and compresses it while the cell runs apps.
func (b *Builder) sqfstarCommand(ctx context.Context, out string) *exec.Cmd {
	args := append([]string{"-n", "10", b.sqfstar}, sqfstarArgs...)
	return exec.CommandContext(ctx, niceBinary, append(args, out)...)
}

func finishImage(img *os.File) error {
	if err := checkImage(img); err != nil {
		return fmt.Errorf("sqfstar succeeded but wrote a bad image: %w", err)
	}
	if err := img.Chmod(0644); err != nil {
		return err
	}
	return img.Sync()
}

func (b *Builder) lockPath(key string) string {
	return filepath.Join(b.cacheDir, key+lockSuffix)
}

// lockEntry takes an exclusive flock on the lock file at path, creating it
// if needed. With wait false it fails at once when another holder has it.
// Clean unlinks lock files, so once the lock is held lockEntry checks that
// the path still names the locked file and starts over when it does not.
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

// removeTemps deletes the temporary files of builds that a crash or a kill
// left behind. The caller holds the entry's lock, so no build is writing one.
func removeTemps(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), tempPrefix) {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
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
