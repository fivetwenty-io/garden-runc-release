package vmstack

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"code.cloudfoundry.org/lager/v3/lagertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

const realArtifactsEnv = "VM_LAUNCH_ARTIFACTS"

var _ = Describe("Builder", func() {
	var (
		work     string
		cacheDir string
		tarball  string
		runs     string
		stdin    string
		template string
		fake     string
		logger   *lagertest.TestLogger
		config   Config
	)

	// writeFake writes a fake sqfstar that records its arguments and its
	// standard input, sleeps, runs body, and then copies a valid image to its
	// last argument.
	writeFake := func(delay time.Duration, body string) {
		script := fmt.Sprintf(`#!/bin/sh
for out; do :; done
echo "$*" >> %[1]s
cat > %[2]s
sleep %[3]s
%[4]s
cp %[5]s "$out"
`, runs, stdin, fmt.Sprintf("%.3f", delay.Seconds()), body, template)
		Expect(os.WriteFile(fake+".new", []byte(script), 0755)).To(Succeed())
		Expect(os.Rename(fake+".new", fake)).To(Succeed())
	}

	runCount := func() int {
		data, err := os.ReadFile(runs)
		if os.IsNotExist(err) {
			return 0
		}
		Expect(err).NotTo(HaveOccurred())
		return strings.Count(string(data), "\n")
	}

	sum := func(path string) string {
		data, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		h := sha256.Sum256(data)
		return hex.EncodeToString(h[:])
	}

	// keyOf is the cache key of a tarball for the fake sqfstar as it is now.
	keyOf := func(path string) string {
		recipe, err := New(config).recipe()
		Expect(err).NotTo(HaveOccurred())
		return entryKey(sum(path), recipe)
	}

	tempFiles := func(dir string) []string {
		matches, err := filepath.Glob(filepath.Join(dir, tempPrefix+"*"))
		Expect(err).NotTo(HaveOccurred())
		return matches
	}

	BeforeEach(func() {
		work = GinkgoT().TempDir()
		cacheDir = filepath.Join(work, "stacks")
		tarball = filepath.Join(work, "rootfs.tar")
		runs = filepath.Join(work, "runs")
		stdin = filepath.Join(work, "stdin")
		template = filepath.Join(work, "template.squashfs")
		fake = filepath.Join(work, "sqfstar")

		Expect(os.WriteFile(tarball, []byte("the stack tarball\n"), 0644)).To(Succeed())
		Expect(os.WriteFile(template, fakeImage(lz4CompressorID, 4096, 4096), 0644)).To(Succeed())
		writeFake(0, "")

		logger = lagertest.NewTestLogger("vmstack")
		config = Config{
			Sqfstar:  fake,
			CacheDir: cacheDir,
			Tarballs: []string{tarball},
			Wait:     10 * time.Second,
			Logger:   logger,
		}
	})

	It("builds once for ten concurrent calls and returns the same directory to each", func() {
		writeFake(500*time.Millisecond, "")
		b := New(config)

		var wg sync.WaitGroup
		dirs := make([]string, 10)
		oks := make([]bool, 10)
		for i := range dirs {
			wg.Add(1)
			go func(i int) {
				defer GinkgoRecover()
				defer wg.Done()
				dirs[i], oks[i] = b.Image(logger, tarball)
			}(i)
		}
		wg.Wait()

		want := filepath.Join(cacheDir, keyOf(tarball))
		for i := range dirs {
			Expect(oks[i]).To(BeTrue())
			Expect(dirs[i]).To(Equal(want))
		}
		Expect(runCount()).To(Equal(1))
	})

	It("runs sqfstar under nice with the lz4 options, the tarball on standard input, and a temporary output beside the image", func() {
		b := New(config)
		dir, ok := b.Image(logger, tarball)
		Expect(ok).To(BeTrue())

		args, err := os.ReadFile(runs)
		Expect(err).NotTo(HaveOccurred())
		fields := strings.Fields(string(args))
		Expect(fields).To(HaveLen(len(sqfstarArgs) + 1))
		Expect(fields[:len(sqfstarArgs)]).To(Equal(sqfstarArgs))
		out := fields[len(sqfstarArgs)]
		Expect(filepath.Dir(out)).To(Equal(dir))
		Expect(filepath.Base(out)).To(HavePrefix(tempPrefix))

		Expect(os.ReadFile(stdin)).To(Equal([]byte("the stack tarball\n")))
		Expect(sqfstarArgs).To(Equal([]string{"-comp", "lz4", "-b", "128K", "-mem", "256M", "-processors", "1", "-no-progress", "-quiet"}))

		cmd := b.sqfstarCommand(context.Background(), "/out")
		Expect(cmd.Args[:4]).To(Equal([]string{niceBinary, "-n", "10", fake}))

		info, err := os.Stat(filepath.Join(dir, imageName))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0644)))
		info, err = os.Stat(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0755)))
		Expect(tempFiles(dir)).To(BeEmpty())
	})

	It("reuses a finished image after a new Builder starts, without a second build", func() {
		first, ok := New(config).Image(logger, tarball)
		Expect(ok).To(BeTrue())

		second, ok := New(config).Image(logger, tarball)
		Expect(ok).To(BeTrue())
		Expect(second).To(Equal(first))
		Expect(runCount()).To(Equal(1))
	})

	It("reuses the hash of an unchanged tarball", func() {
		b := New(config)
		var hashes atomic.Int32
		b.afterHash = func(string) { hashes.Add(1) }

		for range 3 {
			_, ok := b.Image(logger, tarball)
			Expect(ok).To(BeTrue())
		}
		Expect(hashes.Load()).To(Equal(int32(1)))
	})

	DescribeTable("deletes a damaged image and builds it again",
		func(content []byte) {
			dir := filepath.Join(cacheDir, keyOf(tarball))
			Expect(os.MkdirAll(dir, 0755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, imageName), content, 0644)).To(Succeed())

			got, ok := New(config).Image(logger, tarball)
			Expect(ok).To(BeTrue())
			Expect(got).To(Equal(dir))
			Expect(runCount()).To(Equal(1))
			Expect(checkImagePath(filepath.Join(dir, imageName))).To(Succeed())
			Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("removing-bad-image")))
		},
		Entry("when the image is truncated", fakeImage(lz4CompressorID, 8192, 4096)),
		Entry("when the image has the wrong magic", append([]byte("hsqt"), fakeImage(lz4CompressorID, 4096, 4096)[4:]...)),
		Entry("when the image uses another compressor", fakeImage(6, 4096, 4096)),
		Entry("when the file is shorter than a superblock", []byte("hsqs")),
		Entry("when the file is empty", []byte{}),
	)

	It("returns false within a short wait while a long build carries on, and a later call returns the image", func() {
		writeFake(2*time.Second, "")
		config.Wait = 100 * time.Millisecond
		b := New(config)

		start := time.Now()
		_, ok := b.Image(logger, tarball)
		Expect(ok).To(BeFalse())
		Expect(time.Since(start)).To(BeNumerically("<", time.Second))
		Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("still-building")))

		Eventually(func() bool {
			_, ok := b.Image(logger, tarball)
			return ok
		}, 10*time.Second, 200*time.Millisecond).Should(BeTrue())
		Expect(runCount()).To(Equal(1))
	})

	It("returns false for a tarball that is not listed, without a build", func() {
		other := filepath.Join(work, "other.tar")
		Expect(os.WriteFile(other, []byte("another tarball\n"), 0644)).To(Succeed())

		_, ok := New(config).Image(logger, other)
		Expect(ok).To(BeFalse())
		Expect(runCount()).To(Equal(0))
		Expect(cacheDir).NotTo(BeADirectory())
		Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("tarball-not-listed")))
	})

	It("matches a listed tarball by its cleaned path", func() {
		config.Tarballs = []string{filepath.Join(work, ".", "rootfs.tar")}
		_, ok := New(config).Image(logger, filepath.Join(work, "x", "..", "rootfs.tar"))
		Expect(ok).To(BeTrue())
	})

	It("returns false for a listed tarball that does not exist", func() {
		Expect(os.Remove(tarball)).To(Succeed())
		_, ok := New(config).Image(logger, tarball)
		Expect(ok).To(BeFalse())
		Expect(runCount()).To(Equal(0))
	})

	It("hashes a tarball again when it is rewritten during hashing", func() {
		b := New(config)
		var hashes atomic.Int32
		b.afterHash = func(path string) {
			if hashes.Add(1) == 1 {
				Expect(os.WriteFile(path, []byte("the rewritten stack tarball\n"), 0644)).To(Succeed())
			}
		}

		dir, ok := b.Image(logger, tarball)
		Expect(ok).To(BeTrue())
		Expect(hashes.Load()).To(Equal(int32(2)))
		Expect(dir).To(Equal(filepath.Join(cacheDir, keyOf(tarball))))
		Expect(os.ReadFile(stdin)).To(Equal([]byte("the rewritten stack tarball\n")))
		Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("tarball-changed-while-hashing")))
	})

	It("discards a build when the tarball changes while sqfstar reads it", func() {
		writeFake(0, fmt.Sprintf("echo more >> %s", tarball))
		key := keyOf(tarball)

		_, ok := New(config).Image(logger, tarball)
		Expect(ok).To(BeFalse())
		Expect(filepath.Join(cacheDir, key, imageName)).NotTo(BeAnExistingFile())
		Expect(tempFiles(filepath.Join(cacheDir, key))).To(BeEmpty())
		Expect(string(logger.Buffer().Contents())).To(ContainSubstring("changed during the build"))
	})

	DescribeTable("leaves no image and no temporary file when a build fails, and backs off before the next try",
		func(body, logged string) {
			writeFake(0, body)
			b := New(config)
			dir := filepath.Join(cacheDir, keyOf(tarball))

			_, ok := b.Image(logger, tarball)
			Expect(ok).To(BeFalse())
			Expect(filepath.Join(dir, imageName)).NotTo(BeAnExistingFile())
			Expect(tempFiles(dir)).To(BeEmpty())
			Expect(string(logger.Buffer().Contents())).To(ContainSubstring(logged))

			_, ok = b.Image(logger, tarball)
			Expect(ok).To(BeFalse())
			Expect(runCount()).To(Equal(1))

			writeFake(0, "")
			b.backoff = 0
			got, ok := b.Image(logger, tarball)
			Expect(ok).To(BeTrue())
			// The repaired sqfstar is a new binary, so the image has a new key.
			Expect(got).To(Equal(filepath.Join(cacheDir, keyOf(tarball))))
			Expect(runCount()).To(Equal(2))
		},
		Entry("when sqfstar exits with an error",
			`head -c 100 /dev/zero > "$out"; echo "sqfstar: tar file is corrupt" >&2; exit 1`,
			"tar file is corrupt"),
		Entry("when sqfstar is killed part way",
			`head -c 100 /dev/zero > "$out"; kill -9 $$`,
			"signal: killed"),
		Entry("when sqfstar succeeds but writes a bad image",
			`head -c 100 /dev/zero > "$out"; exit 0`,
			"wrote a bad image"),
	)

	It("kills a build that runs past its time limit and leaves no temporary file", func() {
		writeFake(0, "exec sleep 10")
		b := New(config)
		b.timeout = 300 * time.Millisecond

		start := time.Now()
		_, ok := b.Image(logger, tarball)
		Expect(ok).To(BeFalse())
		Expect(time.Since(start)).To(BeNumerically("<", 5*time.Second))
		dir := filepath.Join(cacheDir, keyOf(tarball))
		Expect(filepath.Join(dir, imageName)).NotTo(BeAnExistingFile())
		Expect(tempFiles(dir)).To(BeEmpty())
		Expect(string(logger.Buffer().Contents())).To(ContainSubstring("after 300ms"))
	})

	It("removes temporary files that an earlier build left behind", func() {
		dir := filepath.Join(cacheDir, keyOf(tarball))
		Expect(os.MkdirAll(dir, 0755)).To(Succeed())
		stale := filepath.Join(dir, tempPrefix+"123456")
		Expect(os.WriteFile(stale, []byte("partial"), 0644)).To(Succeed())

		_, ok := New(config).Image(logger, tarball)
		Expect(ok).To(BeTrue())
		Expect(stale).NotTo(BeAnExistingFile())
		Expect(tempFiles(dir)).To(BeEmpty())
	})

	It("waits for another process's lock and uses the image that process finished", func() {
		key := keyOf(tarball)
		Expect(os.MkdirAll(cacheDir, 0755)).To(Succeed())
		held, err := os.OpenFile(filepath.Join(cacheDir, key+lockSuffix), os.O_RDWR|os.O_CREATE, 0600)
		Expect(err).NotTo(HaveOccurred())
		defer held.Close()
		Expect(unix.Flock(int(held.Fd()), unix.LOCK_EX)).To(Succeed())

		config.Wait = 300 * time.Millisecond
		b := New(config)
		_, ok := b.Image(logger, tarball)
		Expect(ok).To(BeFalse())
		Expect(runCount()).To(Equal(0))

		dir := filepath.Join(cacheDir, key)
		Expect(os.MkdirAll(dir, 0755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, imageName), fakeImage(lz4CompressorID, 4096, 4096), 0644)).To(Succeed())
		Expect(unix.Flock(int(held.Fd()), unix.LOCK_UN)).To(Succeed())

		Eventually(func() bool {
			_, ok := b.Image(logger, tarball)
			return ok
		}, 5*time.Second, 50*time.Millisecond).Should(BeTrue())
		Expect(runCount()).To(Equal(0))
	})

	Describe("the failure backoff", func() {
		It("runs nice by absolute path, whatever PATH holds", func() {
			Expect(niceBinary).To(Equal("/usr/bin/nice"))
			cmd := New(config).sqfstarCommand(context.Background(), "/out")
			Expect(cmd.Path).To(Equal("/usr/bin/nice"))
		})

		It("backs off after a failure that is not an sqfstar failure", func() {
			config.CacheDir = filepath.Join(work, "file")
			Expect(os.WriteFile(config.CacheDir, []byte("not a directory"), 0644)).To(Succeed())
			b := New(config)

			_, ok := b.Image(logger, tarball)
			Expect(ok).To(BeFalse())
			Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("build-failed")))

			Expect(os.Remove(config.CacheDir)).To(Succeed())
			_, ok = b.Image(logger, tarball)
			Expect(ok).To(BeFalse())
			Expect(runCount()).To(Equal(0))
			Expect(string(logger.Buffer().Contents())).To(ContainSubstring("the next try waits until"))
		})

		It("doubles the wait with each failure up to a cap", func() {
			b := New(config)
			var last failure
			failed := false
			var delays []time.Duration
			for range 8 {
				b.recordFailure("key", last, failed)
				last, failed = b.failures["key"], true
				delays = append(delays, last.delay)
			}
			Expect(delays).To(Equal([]time.Duration{
				time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute,
				15 * time.Minute, 15 * time.Minute, 15 * time.Minute, 15 * time.Minute,
			}))
		})

		It("forgets the backoff after a build succeeds", func() {
			config.CacheDir = filepath.Join(work, "file")
			Expect(os.WriteFile(config.CacheDir, []byte("not a directory"), 0644)).To(Succeed())
			b := New(config)
			b.backoff = 100 * time.Millisecond

			_, ok := b.Image(logger, tarball)
			Expect(ok).To(BeFalse())
			Expect(b.failures).To(HaveLen(1))
			Expect(os.Remove(config.CacheDir)).To(Succeed())
			Eventually(func() bool {
				_, ok := b.Image(logger, tarball)
				return ok
			}, 5*time.Second, 50*time.Millisecond).Should(BeTrue())
			Expect(b.failures).To(BeEmpty())
		})
	})

	Describe("the whole-image check", func() {
		var (
			checks  string
			verdict string
		)

		// writeUnsquashfs writes a fake unsquashfs that records its flag and
		// fails when the verdict file holds the word fail.
		writeUnsquashfs := func() string {
			path := filepath.Join(work, "unsquashfs")
			script := fmt.Sprintf(`#!/bin/sh
echo "$1" >> %[1]s
if [ "$(cat %[2]s 2>/dev/null)" = fail ]; then
  echo "SQUASHFS error: unable to read inode table" >&2
  exit 1
fi
`, checks, verdict)
			Expect(os.WriteFile(path, []byte(script), 0755)).To(Succeed())
			return path
		}

		checkCount := func() int {
			data, err := os.ReadFile(checks)
			if os.IsNotExist(err) {
				return 0
			}
			Expect(err).NotTo(HaveOccurred())
			return strings.Count(string(data), "\n")
		}

		BeforeEach(func() {
			checks = filepath.Join(work, "checks")
			verdict = filepath.Join(work, "verdict")
			config.Unsquashfs = writeUnsquashfs()
		})

		It("trusts an image it just built and does not run unsquashfs on it", func() {
			b := New(config)
			_, ok := b.Image(logger, tarball)
			Expect(ok).To(BeTrue())
			_, ok = b.Image(logger, tarball)
			Expect(ok).To(BeTrue())
			Expect(runCount()).To(Equal(1))
			Expect(checkCount()).To(Equal(0))
		})

		It("checks an image from an earlier process once and then trusts it", func() {
			_, ok := New(config).Image(logger, tarball)
			Expect(ok).To(BeTrue())

			b := New(config)
			for range 3 {
				_, ok = b.Image(logger, tarball)
				Expect(ok).To(BeTrue())
			}
			Expect(runCount()).To(Equal(1))
			data, err := os.ReadFile(checks)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.Fields(string(data))).To(Equal([]string{"-s", "-ll"}))
		})

		It("removes an image that passes the superblock test and fails the listing, and builds it again", func() {
			_, ok := New(config).Image(logger, tarball)
			Expect(ok).To(BeTrue())
			image := filepath.Join(cacheDir, keyOf(tarball), imageName)
			Expect(os.WriteFile(verdict, []byte("fail"), 0644)).To(Succeed())
			before := must(statID(image))

			b := New(config)
			dir, ok := b.Image(logger, tarball)
			Expect(ok).To(BeTrue())
			Expect(dir).To(Equal(filepath.Join(cacheDir, keyOf(tarball))))
			Expect(runCount()).To(Equal(2))
			Expect(must(statID(image))).NotTo(Equal(before))
			Expect(string(logger.Buffer().Contents())).To(ContainSubstring("unable to read inode table"))
			Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("removing-bad-image")))
		})

		It("does not take the fast path to an image the process has not checked", func() {
			dir := filepath.Join(cacheDir, keyOf(tarball))
			Expect(os.MkdirAll(dir, 0755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, imageName), fakeImage(lz4CompressorID, 4096, 4096), 0644)).To(Succeed())
			Expect(os.WriteFile(verdict, []byte("fail"), 0644)).To(Succeed())

			// Prime the hash so that the fast path would hand the old image out.
			b := New(config)
			_, err := b.key(logger, tarball)
			Expect(err).NotTo(HaveOccurred())
			_, ready := b.ready(tarball)
			Expect(ready).To(BeFalse())
		})

		It("backs off when the rebuild fails too", func() {
			writeFake(0, "exit 1")
			dir := filepath.Join(cacheDir, keyOf(tarball))
			Expect(os.MkdirAll(dir, 0755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, imageName), fakeImage(lz4CompressorID, 4096, 4096), 0644)).To(Succeed())
			Expect(os.WriteFile(verdict, []byte("fail"), 0644)).To(Succeed())

			b := New(config)
			_, ok := b.Image(logger, tarball)
			Expect(ok).To(BeFalse())
			Expect(b.failures).To(HaveLen(1))
		})
	})

	Describe("WarmUp", func() {
		It("builds every listed tarball that exists and returns once the builds finish", func() {
			config.Tarballs = append(config.Tarballs, filepath.Join(work, "missing.tar"))
			writeFake(300*time.Millisecond, "")
			b := New(config)

			b.WarmUp()
			Expect(filepath.Join(cacheDir, keyOf(tarball), imageName)).To(BeAnExistingFile())
			Expect(runCount()).To(Equal(1))
			Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("vm-stack-image-ready")))
			Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("tarball-unavailable")))

			b.Image(logger, tarball)
			Expect(runCount()).To(Equal(1))
		})

		It("shares a build that an Image call started", func() {
			writeFake(500*time.Millisecond, "")
			config.Wait = 0
			b := New(config)

			_, ok := b.Image(logger, tarball)
			Expect(ok).To(BeFalse())
			b.WarmUp()
			Expect(runCount()).To(Equal(1))

			_, ok = b.Image(logger, tarball)
			Expect(ok).To(BeTrue())
		})
	})

	Describe("the cache key", func() {
		It("is 64 hex digits and differs from the tarball's own hash", func() {
			key := keyOf(tarball)

			Expect(isKey(key)).To(BeTrue())
			Expect(key).NotTo(Equal(sum(tarball)))
		})

		It("changes when the sqfstar options change", func() {
			before := keyOf(tarball)

			saved := sqfstarArgs
			defer func() { sqfstarArgs = saved }()
			sqfstarArgs = append(append([]string{}, saved...), "-root-mode", "755")

			Expect(keyOf(tarball)).NotTo(Equal(before))
		})

		It("changes when the sqfstar binary changes", func() {
			before := keyOf(tarball)

			writeFake(0, "# a newer sqfstar")

			Expect(keyOf(tarball)).NotTo(Equal(before))
		})

		It("changes when the tarball changes and stays put otherwise", func() {
			before := keyOf(tarball)
			Expect(keyOf(tarball)).To(Equal(before))

			Expect(os.WriteFile(tarball, []byte("another stack tarball\n"), 0644)).To(Succeed())

			Expect(keyOf(tarball)).NotTo(Equal(before))
		})

		It("builds a new image and Clean removes the old one after the binary changes", func() {
			b := New(config)
			oldDir, ok := b.Image(logger, tarball)
			Expect(ok).To(BeTrue())
			Expect(runCount()).To(Equal(1))

			writeFake(0, "# a newer sqfstar")

			b = New(config)
			newDir, ok := b.Image(logger, tarball)
			Expect(ok).To(BeTrue())
			Expect(newDir).NotTo(Equal(oldDir))
			Expect(runCount()).To(Equal(2))

			b.Clean()
			Expect(oldDir).NotTo(BeAnExistingFile())
			Expect(filepath.Join(cacheDir, filepath.Base(oldDir)+lockSuffix)).NotTo(BeAnExistingFile())
			Expect(filepath.Join(newDir, imageName)).To(BeAnExistingFile())
		})

		It("builds a new image and Clean removes the old one after the options change", func() {
			saved := sqfstarArgs
			defer func() { sqfstarArgs = saved }()

			oldDir, ok := New(config).Image(logger, tarball)
			Expect(ok).To(BeTrue())

			sqfstarArgs = append(append([]string{}, saved...), "-no-xattrs")

			b := New(config)
			newDir, ok := b.Image(logger, tarball)
			Expect(ok).To(BeTrue())
			Expect(newDir).NotTo(Equal(oldDir))

			b.Clean()
			Expect(oldDir).NotTo(BeAnExistingFile())
			Expect(filepath.Join(newDir, imageName)).To(BeAnExistingFile())
		})

		It("notices a sqfstar binary that is replaced while the builder runs", func() {
			b := New(config)
			oldDir, ok := b.Image(logger, tarball)
			Expect(ok).To(BeTrue())

			writeFake(0, "# a newer sqfstar")

			newDir, ok := b.Image(logger, tarball)
			Expect(ok).To(BeTrue())
			Expect(newDir).NotTo(Equal(oldDir))
		})
	})

	Describe("Clean", func() {
		var oldKey string

		BeforeEach(func() {
			old := sha256.Sum256([]byte("an older stack tarball\n"))
			oldKey = hex.EncodeToString(old[:])
			Expect(os.MkdirAll(filepath.Join(cacheDir, oldKey), 0755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(cacheDir, oldKey, imageName), fakeImage(lz4CompressorID, 4096, 4096), 0644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(cacheDir, oldKey+lockSuffix), nil, 0600)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(cacheDir, "README"), []byte("not ours\n"), 0644)).To(Succeed())
		})

		It("removes an entry for an old hash and keeps the current one", func() {
			b := New(config)
			dir, ok := b.Image(logger, tarball)
			Expect(ok).To(BeTrue())

			b.Clean()
			Expect(filepath.Join(cacheDir, oldKey)).NotTo(BeAnExistingFile())
			Expect(filepath.Join(cacheDir, oldKey+lockSuffix)).NotTo(BeAnExistingFile())
			Expect(filepath.Join(dir, imageName)).To(BeAnExistingFile())
			Expect(filepath.Join(cacheDir, keyOf(tarball)+lockSuffix)).To(BeAnExistingFile())
			Expect(filepath.Join(cacheDir, "README")).To(BeAnExistingFile())
		})

		It("removes the entries of a listed tarball that no longer exists", func() {
			b := New(config)
			dir, ok := b.Image(logger, tarball)
			Expect(ok).To(BeTrue())
			Expect(os.Remove(tarball)).To(Succeed())

			b.Clean()
			Expect(dir).NotTo(BeAnExistingFile())
			Expect(filepath.Join(cacheDir, oldKey)).NotTo(BeAnExistingFile())
		})

		It("keeps an old entry whose lock another build holds", func() {
			held, err := os.OpenFile(filepath.Join(cacheDir, oldKey+lockSuffix), os.O_RDWR, 0)
			Expect(err).NotTo(HaveOccurred())
			defer held.Close()
			Expect(unix.Flock(int(held.Fd()), unix.LOCK_EX)).To(Succeed())

			New(config).Clean()
			Expect(filepath.Join(cacheDir, oldKey, imageName)).To(BeAnExistingFile())
			Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("entry-in-use")))
		})

		It("lets a build that waited on a removed lock file take a fresh one", func() {
			lockPath := filepath.Join(cacheDir, oldKey+lockSuffix)
			held, err := lockEntry(lockPath, true)
			Expect(err).NotTo(HaveOccurred())

			taken := make(chan *os.File)
			go func() {
				defer GinkgoRecover()
				f, err := lockEntry(lockPath, true)
				Expect(err).NotTo(HaveOccurred())
				taken <- f
			}()
			Consistently(taken, 200*time.Millisecond).ShouldNot(Receive())

			Expect(os.Remove(lockPath)).To(Succeed())
			Expect(held.Close()).To(Succeed())

			var waiter *os.File
			Eventually(taken, 5*time.Second).Should(Receive(&waiter))
			defer waiter.Close()
			Expect(fileIDOf(waiter)).To(Equal(must(statID(lockPath))))
		})
	})

	Describe("with the real squashfs tools", func() {
		var art string

		BeforeEach(func() {
			art = os.Getenv(realArtifactsEnv)
			if art == "" {
				Skip(realArtifactsEnv + " is not set; point it at a directory that holds sqfstar and unsquashfs to run the real build")
			}
			for _, tool := range []string{"sqfstar", "unsquashfs"} {
				info, err := os.Stat(filepath.Join(art, tool))
				if err != nil || !info.Mode().IsRegular() {
					Skip(realArtifactsEnv + " holds no regular file " + tool)
				}
			}
			if _, err := exec.LookPath("tar"); err != nil {
				Skip("this system has no tar to list the tarball with")
			}
		})

		It("keeps every owner and mode from a pax tarball", func() {
			Expect(os.WriteFile(tarball, paxStack(), 0644)).To(Succeed())
			config.Sqfstar = filepath.Join(art, "sqfstar")
			dir, ok := New(config).Image(logger, tarball)
			Expect(ok).To(BeTrue(), string(logger.Buffer().Contents()))
			image := filepath.Join(dir, imageName)

			super, err := exec.Command(filepath.Join(art, "unsquashfs"), "-s", image).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), string(super))
			Expect(string(super)).To(ContainSubstring("Compression lz4"))
			Expect(string(super)).To(ContainSubstring("Block size 131072"))

			listed, err := exec.Command(filepath.Join(art, "unsquashfs"), "-lln", image).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), string(listed))
			want, err := exec.Command("tar", "--numeric-owner", "-tvf", tarball).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), string(want))

			got := ownersAndModes(string(listed), "squashfs-root/")
			Expect(got).To(Equal(ownersAndModes(string(want), "")))
			Expect(got).To(HaveKeyWithValue("etc/shadow", "-rw-r----- 0/42"))
			Expect(got).To(HaveKeyWithValue("home/vcap/app.txt", "-rw-r--r-- 2000/2000"))
			Expect(got).To(HaveKeyWithValue("bin/su", "-rwsr-xr-x 0/0"))
			Expect(got).To(HaveKeyWithValue("bin/sh", "lrwxrwxrwx 0/0"))
			Expect(got).To(HaveKeyWithValue("bin/su-link", "-rwsr-xr-x 0/0"))
		})

		It("rebuilds an image whose inode table is damaged and whose superblock is intact", func() {
			Expect(os.WriteFile(tarball, paxStack(), 0644)).To(Succeed())
			config.Sqfstar = filepath.Join(art, "sqfstar")
			config.Unsquashfs = filepath.Join(art, "unsquashfs")
			dir, ok := New(config).Image(logger, tarball)
			Expect(ok).To(BeTrue(), string(logger.Buffer().Contents()))
			image := filepath.Join(dir, imageName)

			// The inode table start is a 64-bit field at offset 64 of the superblock.
			f, err := os.OpenFile(image, os.O_RDWR, 0)
			Expect(err).NotTo(HaveOccurred())
			start := make([]byte, 8)
			_, err = f.ReadAt(start, 64)
			Expect(err).NotTo(HaveOccurred())
			_, err = f.WriteAt(bytes.Repeat([]byte{0xff}, 16), int64(binary.LittleEndian.Uint64(start))+2)
			Expect(err).NotTo(HaveOccurred())
			Expect(f.Close()).To(Succeed())
			Expect(checkImagePath(image)).To(Succeed())
			Expect(exec.Command(config.Unsquashfs, "-ll", image).Run()).NotTo(Succeed())

			logger = lagertest.NewTestLogger("vmstack")
			config.Logger = logger
			dir, ok = New(config).Image(logger, tarball)
			Expect(ok).To(BeTrue(), string(logger.Buffer().Contents()))
			Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("removing-bad-image")))
			Expect(exec.Command(config.Unsquashfs, "-ll", filepath.Join(dir, imageName)).Run()).To(Succeed())
		})
	})
})

// fakeImage returns size bytes that start with a squashfs superblock for the
// given compressor, which claims used bytes.
func fakeImage(compressor uint16, used uint64, size int) []byte {
	img := make([]byte, size)
	binary.LittleEndian.PutUint32(img[magicOffset:], squashfsMagic)
	binary.LittleEndian.PutUint16(img[compressorOffset:], compressor)
	binary.LittleEndian.PutUint64(img[bytesUsedOffset:], used)
	return img
}

// paxStack returns a pax tarball with a root-only file, a file owned by uid
// 2000, a setuid file, a symlink, and a hard link.
func paxStack() []byte {
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	mtime := time.Date(2026, 10, 31, 12, 0, 0, 123456789, time.UTC)
	add := func(h tar.Header, body string) {
		h.Format = tar.FormatPAX
		h.ModTime = mtime
		h.Size = int64(len(body))
		Expect(w.WriteHeader(&h)).To(Succeed())
		_, err := w.Write([]byte(body))
		Expect(err).NotTo(HaveOccurred())
	}

	add(tar.Header{Typeflag: tar.TypeDir, Name: "etc/", Mode: 0755}, "")
	add(tar.Header{Typeflag: tar.TypeReg, Name: "etc/shadow", Mode: 0640, Gid: 42}, "root:*:20000:0:99999:7:::\n")
	add(tar.Header{Typeflag: tar.TypeDir, Name: "home/", Mode: 0755}, "")
	add(tar.Header{Typeflag: tar.TypeDir, Name: "home/vcap/", Mode: 02750, Uid: 2000, Gid: 2000}, "")
	add(tar.Header{Typeflag: tar.TypeReg, Name: "home/vcap/app.txt", Mode: 0644, Uid: 2000, Gid: 2000}, "hello\n")
	add(tar.Header{Typeflag: tar.TypeDir, Name: "bin/", Mode: 0755}, "")
	add(tar.Header{Typeflag: tar.TypeReg, Name: "bin/su", Mode: 04755}, "#!/bin/sh\n")
	add(tar.Header{Typeflag: tar.TypeSymlink, Name: "bin/sh", Linkname: "su", Mode: 0777}, "")
	add(tar.Header{Typeflag: tar.TypeLink, Name: "bin/su-link", Linkname: "bin/su", Mode: 04755}, "")
	Expect(w.Close()).To(Succeed())
	return buf.Bytes()
}

// ownersAndModes maps each path in a long listing from tar -tv or
// unsquashfs -lln to its mode string and numeric owner. It reads a tar hard
// link as the regular file it names, which is how squashfs lists it.
func ownersAndModes(listing, prefix string) map[string]string {
	entries := map[string]string{}
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		mode, owner, path := fields[0], fields[1], fields[5]
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		path = strings.TrimSuffix(strings.TrimPrefix(path, prefix), "/")
		if path == "" {
			continue
		}
		if strings.HasPrefix(mode, "h") {
			mode = "-" + mode[1:]
		}
		entries[path] = mode + " " + owner
	}
	return entries
}

func must[T any](v T, err error) T {
	Expect(err).NotTo(HaveOccurred())
	return v
}
