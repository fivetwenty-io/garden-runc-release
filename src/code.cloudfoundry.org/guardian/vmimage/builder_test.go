package vmimage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/lager/v3/lagertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// fakeVolumizer stands in for Garden's volumizer. It lays out a build image
// as <store>/images/<id>/rootfs, writes the dependency record that the image
// plugin would write, and remembers every create and destroy.
type fakeVolumizer struct {
	mu    sync.Mutex
	store string

	// chain is the layer chain that the dependency record lists.
	chain []string
	// record, when set, replaces the dependency record's content.
	record []byte
	// noRecord leaves the dependency record out.
	noRecord bool
	// populate fills the root file system of each build image.
	populate func(rootfs string)
	// rootFn, when set, decides the spec's root.
	rootFn    func(store, rootfs string) *specs.Root
	mounts    []specs.Mount
	env       []string
	noProcess bool

	createErr  error
	destroyErr error

	created   []garden.ContainerSpec
	destroyed []string
}

func (v *fakeVolumizer) Create(log lager.Logger, spec garden.ContainerSpec) (specs.Spec, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.created = append(v.created, spec)
	if v.createErr != nil {
		return specs.Spec{}, v.createErr
	}

	rootfs := filepath.Join(v.store, "images", "id-"+spec.Handle, "rootfs")
	if err := os.MkdirAll(rootfs, 0755); err != nil {
		return specs.Spec{}, err
	}
	if v.populate != nil {
		v.populate(rootfs)
	}

	if !v.noRecord {
		dir := filepath.Join(v.store, "meta", "dependencies")
		if err := os.MkdirAll(dir, 0755); err != nil {
			return specs.Spec{}, err
		}
		content := v.record
		if content == nil {
			var err error
			if content, err = json.Marshal(v.chain); err != nil {
				return specs.Spec{}, err
			}
		}
		name := "image:" + strings.ReplaceAll(spec.Handle, "/", "__") + ".json"
		if err := os.WriteFile(filepath.Join(dir, name), content, 0644); err != nil {
			return specs.Spec{}, err
		}
	}

	out := specs.Spec{Root: &specs.Root{Path: rootfs}, Mounts: v.mounts}
	if v.rootFn != nil {
		out.Root = v.rootFn(v.store, rootfs)
	}
	if !v.noProcess {
		out.Process = &specs.Process{Env: v.env}
	}
	return out, nil
}

func (v *fakeVolumizer) Destroy(log lager.Logger, handle string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.destroyed = append(v.destroyed, handle)
	os.RemoveAll(filepath.Join(v.store, "images", "id-"+handle))
	name := "image:" + strings.ReplaceAll(handle, "/", "__") + ".json"
	os.Remove(filepath.Join(v.store, "meta", "dependencies", name))
	return v.destroyErr
}

func (v *fakeVolumizer) creates() []garden.ContainerSpec {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]garden.ContainerSpec(nil), v.created...)
}

func (v *fakeVolumizer) destroys() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.destroyed...)
}

var _ = Describe("Builder", func() {
	const maxUID = 4000

	var (
		work     string
		cacheDir string
		runs     string
		niceLog  string
		tool     string
		nice     string
		volume   *fakeVolumizer
		logger   *lagertest.TestLogger
		config   Config
		ref      garden.ImageRef
	)

	// writeTool writes a fake mksquashfs that records its arguments, writes
	// size bytes to its output path, and then runs body.
	writeTool := func(size int, body string) {
		script := fmt.Sprintf(`#!/bin/sh
echo "$*" >> %[1]s
head -c %[2]d /dev/zero > "$2"
%[3]s
`, runs, size, body)
		Expect(os.WriteFile(tool+".new", []byte(script), 0755)).To(Succeed())
		Expect(os.Rename(tool+".new", tool)).To(Succeed())
	}

	newBuilder := func() *Builder {
		b, err := New(config)
		Expect(err).NotTo(HaveOccurred())
		b.nice = nice
		return b
	}

	runLines := func() []string {
		data, err := os.ReadFile(runs)
		if os.IsNotExist(err) {
			return nil
		}
		Expect(err).NotTo(HaveOccurred())
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}

	runCount := func() int {
		return len(runLines())
	}

	entryDirs := func() []string {
		dirs, err := os.ReadDir(cacheDir)
		Expect(err).NotTo(HaveOccurred())
		var keys []string
		for _, d := range dirs {
			if d.IsDir() && isKey(d.Name()) {
				keys = append(keys, d.Name())
			}
		}
		return keys
	}

	tempDirs := func() []string {
		matches, err := filepath.Glob(filepath.Join(cacheDir, tempPrefix+"*"))
		Expect(err).NotTo(HaveOccurred())
		return matches
	}

	containerDir := func(handle string) string {
		return filepath.Join(cacheDir, "containers", handle)
	}

	put := func(rootfs, rel, content string) {
		path := filepath.Join(rootfs, rel)
		Expect(os.MkdirAll(filepath.Dir(path), 0755)).To(Succeed())
		Expect(os.WriteFile(path, []byte(content), 0644)).To(Succeed())
	}

	keyOf := func(chain ...string) string {
		key, err := newBuilder().key(chain)
		Expect(err).NotTo(HaveOccurred())
		return key
	}

	// age sets the modification time of the cache entry of a chain, which is
	// the time that the eviction orders by.
	age := func(chain string, ago time.Duration) {
		when := time.Now().Add(-ago)
		Expect(os.Chtimes(filepath.Join(cacheDir, keyOf(chain)), when, when)).To(Succeed())
	}

	// image builds the image of a one-layer chain for a handle.
	image := func(b *Builder, handle, chain string) (string, []string, error) {
		volume.chain = []string{chain}
		return b.Image(logger, handle, ref)
	}

	BeforeEach(func() {
		work = GinkgoT().TempDir()
		cacheDir = filepath.Join(work, "cache")
		runs = filepath.Join(work, "runs")
		niceLog = filepath.Join(work, "nice")
		tool = filepath.Join(work, "mksquashfs")
		nice = filepath.Join(work, "fake-nice")

		niceScript := fmt.Sprintf("#!/bin/sh\necho \"$*\" >> %s\nshift 2\nexec \"$@\"\n", niceLog)
		Expect(os.WriteFile(nice, []byte(niceScript), 0755)).To(Succeed())
		writeTool(100, "")

		volume = &fakeVolumizer{store: filepath.Join(work, "store"), chain: []string{"layer-a", "layer-b"}}
		logger = lagertest.NewTestLogger("vmimage")
		config = Config{
			Mksquashfs: tool,
			CacheDir:   cacheDir,
			CacheBytes: 1 << 30,
			MaxUID:     maxUID,
			Volumizer:  volume,
			Logger:     logger,
		}
		ref = garden.ImageRef{URI: "docker://registry.example.com/team/app:1", Username: "puller", Password: "s3cret-pull-token"}
	})

	Describe("New", func() {
		It("creates the cache and containers directories with the right modes", func() {
			_, err := New(config)
			Expect(err).NotTo(HaveOccurred())

			info, err := os.Stat(cacheDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0700)))
			Expect(filepath.Join(cacheDir, "containers")).To(BeADirectory())
		})

		It("removes the temporary directories that a crash left behind and keeps the rest", func() {
			stale := filepath.Join(cacheDir, tempPrefix+"123456")
			Expect(os.MkdirAll(stale, 0700)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(stale, imageName), []byte("partial"), 0644)).To(Succeed())
			kept := filepath.Join(cacheDir, strings.Repeat("a", 64))
			Expect(os.MkdirAll(kept, 0755)).To(Succeed())

			_, err := New(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(stale).NotTo(BeADirectory())
			Expect(kept).To(BeADirectory())
		})

		DescribeTable("refuses a bad configuration",
			func(change func(*Config), message string) {
				change(&config)
				_, err := New(config)
				Expect(err).To(MatchError(ContainSubstring(message)))
			},
			Entry("a relative mksquashfs path", func(c *Config) { c.Mksquashfs = "mksquashfs" }, "mksquashfs path"),
			Entry("a relative cache directory", func(c *Config) { c.CacheDir = "cache" }, "cache directory"),
			Entry("a zero budget", func(c *Config) { c.CacheBytes = 0 }, "cache budget"),
			Entry("a negative budget", func(c *Config) { c.CacheBytes = -1 }, "cache budget"),
			Entry("no volumizer", func(c *Config) { c.Volumizer = nil }, "no volumizer"),
		)
	})

	Describe("the cache key", func() {
		It("is 64 hex digits and stable for the same inputs", func() {
			key := keyOf("layer-a", "layer-b")
			Expect(isKey(key)).To(BeTrue())
			Expect(keyOf("layer-a", "layer-b")).To(Equal(key))
		})

		It("changes with the chain IDs, their order, and their number", func() {
			key := keyOf("layer-a", "layer-b")
			Expect(keyOf("layer-a", "layer-c")).NotTo(Equal(key))
			Expect(keyOf("layer-b", "layer-a")).NotTo(Equal(key))
			Expect(keyOf("layer-a")).NotTo(Equal(key))
		})

		It("does not let neighboring IDs run together", func() {
			Expect(keyOf("ab", "c")).NotTo(Equal(keyOf("a", "bc")))
			Expect(keyOf("a\nlayer \"b\"")).NotTo(Equal(keyOf("a", "b")))
		})

		It("changes with the max uid", func() {
			key := keyOf("layer-a")
			config.MaxUID = maxUID + 1
			Expect(keyOf("layer-a")).NotTo(Equal(key))
		})

		It("changes with the contents of the tool", func() {
			key := keyOf("layer-a")
			writeTool(100, "echo changed")
			Expect(keyOf("layer-a")).NotTo(Equal(key))
		})

		It("reuses the tool's hash while the tool stays the same", func() {
			b := newBuilder()
			first, err := b.toolSum()
			Expect(err).NotTo(HaveOccurred())
			Expect(b.tool.sum).To(Equal(first))

			b.tool.sum = "remembered"
			second, err := b.toolSum()
			Expect(err).NotTo(HaveOccurred())
			Expect(second).To(Equal("remembered"))

			writeTool(100, "echo changed")
			third, err := b.toolSum()
			Expect(err).NotTo(HaveOccurred())
			Expect(third).NotTo(Equal("remembered"))
		})

		It("fails when the tool is missing", func() {
			Expect(os.Remove(tool)).To(Succeed())
			_, _, err := newBuilder().Image(logger, "c1", ref)
			Expect(err).To(MatchError(ContainSubstring("vm image: hashing mksquashfs")))
			Expect(volume.destroys()).To(Equal([]string{"c1-vm-image"}))
		})
	})

	Describe("Image", func() {
		It("creates the build image from the reference with no quota and a namespaced store", func() {
			_, _, err := newBuilder().Image(logger, "c1", ref)
			Expect(err).NotTo(HaveOccurred())

			created := volume.creates()
			Expect(created).To(HaveLen(1))
			Expect(created[0].Handle).To(Equal("c1-vm-image"))
			Expect(created[0].Image).To(Equal(ref))
			Expect(created[0].Privileged).To(BeFalse())
			Expect(created[0].Limits).To(Equal(garden.Limits{}))
		})

		It("builds with the exact argv, under nice, into a temporary directory beside the entries", func() {
			b := newBuilder()
			dir, _, err := b.Image(logger, "c1", ref)
			Expect(err).NotTo(HaveOccurred())

			rootfs := filepath.Join(work, "store", "images", "id-c1-vm-image", "rootfs")
			lines := runLines()
			Expect(lines).To(HaveLen(1))
			fields := strings.Fields(lines[0])
			Expect(fields[0]).To(Equal(rootfs))
			Expect(filepath.Base(fields[1])).To(Equal("rootfs.squashfs"))
			Expect(filepath.Dir(filepath.Dir(fields[1]))).To(Equal(cacheDir))
			Expect(filepath.Base(filepath.Dir(fields[1]))).To(HavePrefix(tempPrefix))
			Expect(fields[2:]).To(Equal([]string{
				"-noappend", "-comp", "lz4", "-b", "128K", "-no-xattrs", "-no-progress", "-quiet",
				"-action", "uid(0)@uid(4000)",
				"-action", "gid(0)@gid(4000)",
			}))

			nices, err := os.ReadFile(niceLog)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(nices)).To(HavePrefix("-n 10 " + tool + " " + rootfs + " "))

			Expect(dir).To(Equal(containerDir("c1")))
			Expect(tempDirs()).To(BeEmpty())
		})

		It("runs nice by absolute path, whatever PATH holds", func() {
			b, err := New(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(niceBinary).To(Equal("/usr/bin/nice"))
			cmd := b.mksquashfsCommand(context.Background(), "/rootfs", "/out")
			Expect(cmd.Path).To(Equal("/usr/bin/nice"))
			Expect(cmd.Args[:4]).To(Equal([]string{niceBinary, "-n", "10", tool}))
		})

		It("hands out a container directory of hard links to the entry's three files", func() {
			volume.env = []string{"PATH=/usr/bin", "LANG=C"}
			dir, env, err := newBuilder().Image(logger, "c1", ref)
			Expect(err).NotTo(HaveOccurred())
			Expect(env).To(Equal([]string{"PATH=/usr/bin", "LANG=C"}))

			keys := entryDirs()
			Expect(keys).To(Equal([]string{keyOf("layer-a", "layer-b")}))
			info, err := os.Stat(dir)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0755)))

			for _, name := range []string{imageName, passwdName, groupName} {
				linked, err := os.Stat(filepath.Join(dir, name))
				Expect(err).NotTo(HaveOccurred())
				original, err := os.Stat(filepath.Join(cacheDir, keys[0], name))
				Expect(err).NotTo(HaveOccurred())
				Expect(os.SameFile(linked, original)).To(BeTrue(), name)
				Expect(linked.Mode().Perm()).To(Equal(os.FileMode(0644)), name)
			}
			links, err := linkCount(filepath.Join(cacheDir, keys[0], imageName))
			Expect(err).NotTo(HaveOccurred())
			Expect(links).To(Equal(uint64(2)))

			entry, err := os.Stat(filepath.Join(cacheDir, keys[0]))
			Expect(err).NotTo(HaveOccurred())
			Expect(entry.Mode().Perm()).To(Equal(os.FileMode(0755)))
		})

		It("returns an empty environment when the build spec has no process", func() {
			volume.noProcess = true
			_, env, err := newBuilder().Image(logger, "c1", ref)
			Expect(err).NotTo(HaveOccurred())
			Expect(env).To(BeEmpty())
		})

		It("serves a second image of the same layers from the cache, with its own build image", func() {
			b := newBuilder()
			first, _, err := b.Image(logger, "c1", ref)
			Expect(err).NotTo(HaveOccurred())
			second, _, err := b.Image(logger, "c2", ref)
			Expect(err).NotTo(HaveOccurred())

			Expect(first).NotTo(Equal(second))
			Expect(runCount()).To(Equal(1))
			Expect(entryDirs()).To(HaveLen(1))
			Expect(volume.creates()).To(HaveLen(2))
			Expect(volume.destroys()).To(ConsistOf("c1-vm-image", "c2-vm-image"))
			Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("cache-hit")))

			links, err := linkCount(filepath.Join(cacheDir, entryDirs()[0], imageName))
			Expect(err).NotTo(HaveOccurred())
			Expect(links).To(Equal(uint64(3)))
		})

		It("reuses a finished entry after a new Builder starts", func() {
			_, _, err := newBuilder().Image(logger, "c1", ref)
			Expect(err).NotTo(HaveOccurred())
			_, _, err = newBuilder().Image(logger, "c2", ref)
			Expect(err).NotTo(HaveOccurred())
			Expect(runCount()).To(Equal(1))
		})

		It("builds again when the layers differ", func() {
			b := newBuilder()
			_, _, err := image(b, "c1", "layer-a")
			Expect(err).NotTo(HaveOccurred())
			_, _, err = image(b, "c2", "layer-b")
			Expect(err).NotTo(HaveOccurred())
			Expect(runCount()).To(Equal(2))
			Expect(entryDirs()).To(HaveLen(2))
		})

		It("marks a used entry as new", func() {
			b := newBuilder()
			_, _, err := image(b, "c1", "layer-a")
			Expect(err).NotTo(HaveOccurred())
			age("layer-a", 3*time.Hour)

			_, _, err = image(b, "c2", "layer-a")
			Expect(err).NotTo(HaveOccurred())
			info, err := os.Stat(filepath.Join(cacheDir, keyOf("layer-a")))
			Expect(err).NotTo(HaveOccurred())
			Expect(time.Since(info.ModTime())).To(BeNumerically("<", time.Minute))
		})

		It("replaces the link directory when the same handle asks again", func() {
			b := newBuilder()
			dir, _, err := image(b, "c1", "layer-a")
			Expect(err).NotTo(HaveOccurred())
			Expect(os.WriteFile(filepath.Join(dir, "stray"), []byte("x"), 0644)).To(Succeed())

			dir, _, err = image(b, "c1", "layer-b")
			Expect(err).NotTo(HaveOccurred())
			Expect(filepath.Join(dir, "stray")).NotTo(BeAnExistingFile())
			linked, err := os.Stat(filepath.Join(dir, imageName))
			Expect(err).NotTo(HaveOccurred())
			original, err := os.Stat(filepath.Join(cacheDir, keyOf("layer-b"), imageName))
			Expect(err).NotTo(HaveOccurred())
			Expect(os.SameFile(linked, original)).To(BeTrue())
			Expect(tempDirs()).To(BeEmpty())
		})

		It("builds once for concurrent calls on the same layers", func() {
			writeTool(100, "sleep 0.4")
			b := newBuilder()

			var wg sync.WaitGroup
			errs := make([]error, 8)
			for i := range errs {
				wg.Add(1)
				go func(i int) {
					defer GinkgoRecover()
					defer wg.Done()
					_, _, errs[i] = b.Image(logger, fmt.Sprintf("c%d", i), ref)
				}(i)
			}
			wg.Wait()

			for _, err := range errs {
				Expect(err).NotTo(HaveOccurred())
			}
			Expect(runCount()).To(Equal(1))
			Expect(entryDirs()).To(HaveLen(1))
			Expect(volume.creates()).To(HaveLen(8))
			Expect(volume.destroys()).To(HaveLen(8))
			for i := range errs {
				Expect(filepath.Join(containerDir(fmt.Sprintf("c%d", i)), imageName)).To(BeAnExistingFile())
			}
			Expect(tempDirs()).To(BeEmpty())
			Expect(b.keys).To(BeEmpty())
		})

		It("never logs the reference, the user name, or the password", func() {
			_, _, err := newBuilder().Image(logger, "c1", ref)
			Expect(err).NotTo(HaveOccurred())
			volume.createErr = errors.New("registry refused")
			_, _, err = newBuilder().Image(logger, "c2", ref)
			Expect(err).To(HaveOccurred())

			logs := string(logger.Buffer().Contents())
			Expect(logs).To(ContainSubstring("c1"))
			Expect(logs).NotTo(ContainSubstring(ref.URI))
			Expect(logs).NotTo(ContainSubstring(ref.Username))
			Expect(logs).NotTo(ContainSubstring(ref.Password))
		})

		Describe("the account files", func() {
			read := func(dir, name string) string {
				data, err := os.ReadFile(filepath.Join(dir, name))
				Expect(err).NotTo(HaveOccurred())
				return string(data)
			}

			It("copies etc/passwd and etc/group with mode 0644", func() {
				volume.populate = func(rootfs string) {
					put(rootfs, "etc/passwd", "root:x:0:0:root:/root:/bin/sh\nvcap:x:1000:1000::/home/vcap:/bin/sh\n")
					put(rootfs, "etc/group", "root:x:0:\nvcap:x:1000:\n")
				}
				dir, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).NotTo(HaveOccurred())

				Expect(read(dir, "passwd")).To(Equal("root:x:0:0:root:/root:/bin/sh\nvcap:x:1000:1000::/home/vcap:/bin/sh\n"))
				Expect(read(dir, "group")).To(Equal("root:x:0:\nvcap:x:1000:\n"))
				info, err := os.Stat(filepath.Join(dir, "passwd"))
				Expect(err).NotTo(HaveOccurred())
				Expect(info.Mode().Perm()).To(Equal(os.FileMode(0644)))
			})

			It("turns a missing file into an empty file", func() {
				volume.populate = func(rootfs string) {
					put(rootfs, "etc/passwd", "root:x:0:0::/root:/bin/sh\n")
				}
				dir, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).NotTo(HaveOccurred())
				Expect(read(dir, "passwd")).NotTo(BeEmpty())
				Expect(read(dir, "group")).To(BeEmpty())
			})

			It("turns a missing etc directory into two empty files", func() {
				dir, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).NotTo(HaveOccurred())
				Expect(read(dir, "passwd")).To(BeEmpty())
				Expect(read(dir, "group")).To(BeEmpty())
			})

			It("follows a link that stays inside the image", func() {
				volume.populate = func(rootfs string) {
					put(rootfs, "usr/lib/passwd.real", "inside:x:0:0::/:/bin/sh\n")
					Expect(os.MkdirAll(filepath.Join(rootfs, "etc"), 0755)).To(Succeed())
					Expect(os.Symlink("../usr/lib/passwd.real", filepath.Join(rootfs, "etc", "passwd"))).To(Succeed())
				}
				dir, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).NotTo(HaveOccurred())
				Expect(read(dir, "passwd")).To(Equal("inside:x:0:0::/:/bin/sh\n"))
			})

			It("does not reach a host file through an absolute link", func() {
				secret := filepath.Join(work, "host-secret")
				Expect(os.WriteFile(secret, []byte("HOST SECRET\n"), 0644)).To(Succeed())
				volume.populate = func(rootfs string) {
					Expect(os.MkdirAll(filepath.Join(rootfs, "etc"), 0755)).To(Succeed())
					Expect(os.Symlink(secret, filepath.Join(rootfs, "etc", "passwd"))).To(Succeed())
				}

				dir, _, err := newBuilder().Image(logger, "c1", ref)
				if err == nil {
					Expect(read(dir, "passwd")).NotTo(ContainSubstring("HOST SECRET"))
				}
			})

			It("refuses a relative link that climbs out of the image", func() {
				secret := filepath.Join(work, "host-secret")
				Expect(os.WriteFile(secret, []byte("HOST SECRET\n"), 0644)).To(Succeed())
				volume.populate = func(rootfs string) {
					Expect(os.MkdirAll(filepath.Join(rootfs, "etc"), 0755)).To(Succeed())
					climb := strings.Repeat("../", 40) + strings.TrimPrefix(secret, "/")
					Expect(os.Symlink(climb, filepath.Join(rootfs, "etc", "group"))).To(Succeed())
				}

				_, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).To(MatchError(ContainSubstring("vm image: reading /etc/group from the image")))
				Expect(entryDirs()).To(BeEmpty())
			})

			It("accepts a file of exactly 1 MiB", func() {
				volume.populate = func(rootfs string) {
					put(rootfs, "etc/passwd", strings.Repeat("p", 1<<20))
				}
				dir, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).NotTo(HaveOccurred())
				Expect(read(dir, "passwd")).To(HaveLen(1 << 20))
			})

			It("refuses a file over 1 MiB and leaves nothing behind", func() {
				volume.populate = func(rootfs string) {
					put(rootfs, "etc/group", strings.Repeat("g", 1<<20+1))
				}
				_, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).To(MatchError(ContainSubstring("/etc/group in the image is 1048577 bytes")))
				Expect(entryDirs()).To(BeEmpty())
				Expect(tempDirs()).To(BeEmpty())
				Expect(containerDir("c1")).NotTo(BeADirectory())
				Expect(volume.destroys()).To(Equal([]string{"c1-vm-image"}))
			})

			It("refuses a directory in place of a file", func() {
				volume.populate = func(rootfs string) {
					Expect(os.MkdirAll(filepath.Join(rootfs, "etc", "passwd"), 0755)).To(Succeed())
				}
				_, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).To(MatchError(ContainSubstring("/etc/passwd in the image is not a regular file")))
			})

			It("refuses a named pipe without blocking", func() {
				volume.populate = func(rootfs string) {
					Expect(os.MkdirAll(filepath.Join(rootfs, "etc"), 0755)).To(Succeed())
					Expect(unix.Mkfifo(filepath.Join(rootfs, "etc", "passwd"), 0644)).To(Succeed())
				}
				done := make(chan error, 1)
				go func() {
					_, _, err := newBuilder().Image(logger, "c1", ref)
					done <- err
				}()
				var err error
				Eventually(done, 5*time.Second).Should(Receive(&err))
				Expect(err).To(MatchError(ContainSubstring("not a regular file")))
			})
		})

		Describe("the build image", func() {
			It("is destroyed after a success", func() {
				_, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).NotTo(HaveOccurred())
				Expect(volume.destroys()).To(Equal([]string{"c1-vm-image"}))
				Expect(filepath.Join(work, "store", "images", "id-c1-vm-image")).NotTo(BeADirectory())
			})

			It("is destroyed after a failed build", func() {
				writeTool(100, "exit 1")
				_, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).To(HaveOccurred())
				Expect(volume.destroys()).To(Equal([]string{"c1-vm-image"}))
			})

			It("is destroyed after a failed create, and the create error comes back", func() {
				volume.createErr = errors.New("registry refused")
				_, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).To(MatchError("vm image: creating the build image: registry refused"))
				Expect(volume.destroys()).To(Equal([]string{"c1-vm-image"}))
			})

			It("does not fail a create that worked when the destroy fails", func() {
				volume.destroyErr = errors.New("device busy")
				dir, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).NotTo(HaveOccurred())
				Expect(filepath.Join(dir, imageName)).To(BeAnExistingFile())
				Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("destroy-build-image-failed")))
			})

			It("is not created for an empty image URI", func() {
				_, _, err := newBuilder().Image(logger, "c1", garden.ImageRef{})
				Expect(err).To(MatchError(ContainSubstring("no URI")))
				Expect(volume.creates()).To(BeEmpty())
			})
		})

		DescribeTable("refuses a build image whose spec does not show a mounted rootfs",
			func(mutate func(v *fakeVolumizer), message string) {
				mutate(volume)
				_, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).To(MatchError(ContainSubstring(message)))
				Expect(err.Error()).To(HavePrefix("vm image: "))
				Expect(runCount()).To(Equal(0))
				Expect(entryDirs()).To(BeEmpty())
				Expect(volume.destroys()).To(Equal([]string{"c1-vm-image"}))
			},
			Entry("when the spec has mounts",
				func(v *fakeVolumizer) { v.mounts = []specs.Mount{{Destination: "/", Type: "overlay"}} },
				"vm image: the image plugin did not mount the rootfs"),
			Entry("when the root is nil",
				func(v *fakeVolumizer) { v.rootFn = func(string, string) *specs.Root { return nil } },
				"has no root"),
			Entry("when the root path is relative",
				func(v *fakeVolumizer) {
					v.rootFn = func(string, string) *specs.Root { return &specs.Root{Path: "images/id/rootfs"} }
				},
				"is not absolute"),
			Entry("when the root path is not named rootfs",
				func(v *fakeVolumizer) {
					v.rootFn = func(store string, _ string) *specs.Root {
						return &specs.Root{Path: filepath.Join(store, "images", "id", "root")}
					}
				},
				"is not named rootfs"),
			Entry("when the root path is not under an images directory",
				func(v *fakeVolumizer) {
					v.rootFn = func(store string, _ string) *specs.Root {
						return &specs.Root{Path: filepath.Join(store, "volumes", "id", "rootfs")}
					}
				},
				"is not under an images directory"),
			Entry("when the root path is too shallow for a store",
				func(v *fakeVolumizer) {
					v.rootFn = func(string, string) *specs.Root { return &specs.Root{Path: "/rootfs"} }
				},
				"is not under an images directory"),
		)

		Describe("the dependency record", func() {
			DescribeTable("refuses a record that is not a list of plain layer IDs",
				func(record string, message string) {
					volume.record = []byte(record)
					_, _, err := newBuilder().Image(logger, "c1", ref)
					Expect(err).To(MatchError(ContainSubstring("vm image: reading the dependency record")))
					Expect(err).To(MatchError(ContainSubstring(message)))
					Expect(runCount()).To(Equal(0))
					Expect(entryDirs()).To(BeEmpty())
					Expect(volume.destroys()).To(Equal([]string{"c1-vm-image"}))
				},
				Entry("an empty array", `[]`, "lists no layers"),
				Entry("null", `null`, "lists no layers"),
				Entry("an empty string", `["layer-a",""]`, "empty layer ID"),
				Entry("an ID with a space", `["layer a"]`, "slash or white space"),
				Entry("an ID with a tab", "[\"layer\\ta\"]", "slash or white space"),
				Entry("an ID with a slash", `["../layer-a"]`, "slash or white space"),
				Entry("an object", `{"layers":["layer-a"]}`, "cannot unmarshal"),
				Entry("a list of numbers", `[1,2]`, "cannot unmarshal"),
				Entry("text that is not JSON", `layer-a`, "invalid character"),
				Entry("text after the array", `["layer-a"] x`, "invalid character"),
				Entry("an empty file", ``, "unexpected end of JSON input"),
				Entry("a record over 1 MiB", `["`+strings.Repeat("a", 1<<20)+`"]`, "is larger than 1048576 bytes"),
			)

			It("reports a missing record as its own error", func() {
				volume.noRecord = true
				_, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).To(MatchError(ContainSubstring("vm image: the dependency record")))
				Expect(err).To(MatchError(ContainSubstring("is missing")))
				Expect(errors.Is(err, fs.ErrNotExist)).To(BeTrue())
				Expect(volume.destroys()).To(Equal([]string{"c1-vm-image"}))
			})

			It("reads the record of the build handle with slashes turned into double underscores", func() {
				store := filepath.Join(work, "store")
				dir := filepath.Join(store, "meta", "dependencies")
				Expect(os.MkdirAll(dir, 0755)).To(Succeed())
				Expect(os.WriteFile(filepath.Join(dir, "image:a__b.json"), []byte(`["layer-x"]`), 0644)).To(Succeed())

				chain, err := readChain(store, "a/b")
				Expect(err).NotTo(HaveOccurred())
				Expect(chain).To(Equal([]string{"layer-x"}))
			})
		})

		Describe("when the build fails", func() {
			It("reports the tool's error and the tail of its output, and leaves no entry or temporary directory", func() {
				writeTool(100, `echo "mksquashfs: out of space" >&2; exit 1`)
				_, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).To(MatchError(ContainSubstring("vm image: mksquashfs: exit status 1: mksquashfs: out of space")))
				Expect(entryDirs()).To(BeEmpty())
				Expect(tempDirs()).To(BeEmpty())
				Expect(containerDir("c1")).NotTo(BeADirectory())
				Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("failed")))
			})

			It("builds again on the next call", func() {
				writeTool(100, "exit 1")
				b := newBuilder()
				_, _, err := b.Image(logger, "c1", ref)
				Expect(err).To(HaveOccurred())

				writeTool(100, "")
				_, _, err = b.Image(logger, "c1", ref)
				Expect(err).NotTo(HaveOccurred())
			})

			It("refuses a tool that succeeds without writing an image", func() {
				writeTool(100, `rm -f "$2"`)
				_, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).To(MatchError(ContainSubstring("wrote no image")))
				Expect(entryDirs()).To(BeEmpty())
			})

			It("refuses a tool that writes an empty image", func() {
				writeTool(0, "")
				_, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).To(MatchError(ContainSubstring("wrote a bad image")))
				Expect(entryDirs()).To(BeEmpty())
			})

			It("kills a tool that runs past its time limit", func() {
				writeTool(100, "exec sleep 10")
				b := newBuilder()
				b.timeout = 300 * time.Millisecond

				start := time.Now()
				_, _, err := b.Image(logger, "c1", ref)
				Expect(err).To(MatchError(ContainSubstring("after 300ms")))
				Expect(time.Since(start)).To(BeNumerically("<", 5*time.Second))
				Expect(entryDirs()).To(BeEmpty())
				Expect(tempDirs()).To(BeEmpty())
			})

			It("rebuilds an entry that lacks one of its files", func() {
				b := newBuilder()
				_, _, err := b.Image(logger, "c1", ref)
				Expect(err).NotTo(HaveOccurred())
				key := entryDirs()[0]
				Expect(os.Remove(filepath.Join(cacheDir, key, groupName))).To(Succeed())

				_, _, err = b.Image(logger, "c2", ref)
				Expect(err).NotTo(HaveOccurred())
				Expect(runCount()).To(Equal(2))
				Expect(filepath.Join(cacheDir, key, groupName)).To(BeAnExistingFile())
			})
		})

		Describe("the size limit", func() {
			It("refuses an image bigger than the budget, says both sizes, and removes the entry", func() {
				config.CacheBytes = 100
				writeTool(150, "")
				_, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).To(MatchError("vm image: the image is 150 bytes, which is more than the cache budget of 100 bytes"))
				Expect(entryDirs()).To(BeEmpty())
				Expect(containerDir("c1")).NotTo(BeADirectory())
				Expect(volume.destroys()).To(Equal([]string{"c1-vm-image"}))
			})

			It("accepts an image of exactly the budget", func() {
				config.CacheBytes = 100
				_, _, err := newBuilder().Image(logger, "c1", ref)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Describe("the eviction", func() {
			BeforeEach(func() {
				config.CacheBytes = 250
			})

			It("removes the oldest entry that no container links", func() {
				b := newBuilder()
				_, _, err := image(b, "c1", "layer-a")
				Expect(err).NotTo(HaveOccurred())
				Expect(b.Release(logger, "c1")).To(Succeed())
				age("layer-a", 3*time.Hour)
				_, _, err = image(b, "c2", "layer-b")
				Expect(err).NotTo(HaveOccurred())
				Expect(b.Release(logger, "c2")).To(Succeed())
				age("layer-b", 2*time.Hour)
				Expect(entryDirs()).To(HaveLen(2))

				_, _, err = image(b, "c3", "layer-c")
				Expect(err).NotTo(HaveOccurred())

				Expect(entryDirs()).To(ConsistOf(keyOf("layer-b"), keyOf("layer-c")))
				Expect(filepath.Join(cacheDir, keyOf("layer-a")+lockSuffix)).NotTo(BeAnExistingFile())
				Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("removed")))
			})

			It("keeps an entry that a container links and removes the next oldest", func() {
				b := newBuilder()
				held, _, err := image(b, "c1", "layer-a")
				Expect(err).NotTo(HaveOccurred())
				age("layer-a", 3*time.Hour)
				_, _, err = image(b, "c2", "layer-b")
				Expect(err).NotTo(HaveOccurred())
				Expect(b.Release(logger, "c2")).To(Succeed())
				age("layer-b", 2*time.Hour)

				_, _, err = image(b, "c3", "layer-c")
				Expect(err).NotTo(HaveOccurred())

				Expect(entryDirs()).To(ConsistOf(keyOf("layer-a"), keyOf("layer-c")))
				Expect(filepath.Join(held, imageName)).To(BeAnExistingFile())
			})

			It("keeps an entry whose lock another process holds and removes the next oldest", func() {
				b := newBuilder()
				_, _, err := image(b, "c1", "layer-a")
				Expect(err).NotTo(HaveOccurred())
				Expect(b.Release(logger, "c1")).To(Succeed())
				age("layer-a", 3*time.Hour)
				_, _, err = image(b, "c2", "layer-b")
				Expect(err).NotTo(HaveOccurred())
				Expect(b.Release(logger, "c2")).To(Succeed())
				age("layer-b", 2*time.Hour)

				lock, err := os.OpenFile(filepath.Join(cacheDir, keyOf("layer-a")+lockSuffix), os.O_RDWR|os.O_CREATE, 0600)
				Expect(err).NotTo(HaveOccurred())
				defer lock.Close()
				Expect(unix.Flock(int(lock.Fd()), unix.LOCK_EX)).To(Succeed())

				_, _, err = image(b, "c3", "layer-c")
				Expect(err).NotTo(HaveOccurred())
				Expect(entryDirs()).To(ConsistOf(keyOf("layer-a"), keyOf("layer-c")))
			})

			It("leaves everything alone while the entries fit the budget", func() {
				config.CacheBytes = 300
				b := newBuilder()
				for i, chain := range []string{"layer-a", "layer-b", "layer-c"} {
					_, _, err := image(b, fmt.Sprintf("c%d", i), chain)
					Expect(err).NotTo(HaveOccurred())
					Expect(b.Release(logger, fmt.Sprintf("c%d", i))).To(Succeed())
				}
				Expect(entryDirs()).To(HaveLen(3))
			})

			It("does not remove the entry it just made, even when that leaves the cache over budget", func() {
				config.CacheBytes = 150
				b := newBuilder()
				_, _, err := image(b, "c1", "layer-a")
				Expect(err).NotTo(HaveOccurred())
				_, _, err = image(b, "c2", "layer-b")
				Expect(err).NotTo(HaveOccurred())
				Expect(entryDirs()).To(HaveLen(2))
				Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("over-budget")))
			})

			It("ignores temporary directories, lock files, and the containers directory when it counts", func() {
				Expect(os.MkdirAll(filepath.Join(cacheDir, tempPrefix+"other"), 0755)).To(Succeed())
				Expect(os.WriteFile(filepath.Join(cacheDir, tempPrefix+"other", imageName), make([]byte, 1000), 0644)).To(Succeed())
				_, _, err := image(newBuilder(), "c1", "layer-a")
				Expect(err).NotTo(HaveOccurred())
				Expect(entryDirs()).To(HaveLen(1))
			})
		})
	})

	Describe("Release", func() {
		It("removes the link directory and keeps the entry", func() {
			b := newBuilder()
			dir, _, err := b.Image(logger, "c1", ref)
			Expect(err).NotTo(HaveOccurred())
			_, _, err = b.Image(logger, "c2", ref)
			Expect(err).NotTo(HaveOccurred())

			Expect(b.Release(logger, "c1")).To(Succeed())
			Expect(dir).NotTo(BeADirectory())
			Expect(containerDir("c2")).To(BeADirectory())
			Expect(entryDirs()).To(HaveLen(1))
			links, err := linkCount(filepath.Join(cacheDir, entryDirs()[0], imageName))
			Expect(err).NotTo(HaveOccurred())
			Expect(links).To(Equal(uint64(2)))
		})

		It("is idempotent and succeeds when nothing exists", func() {
			b := newBuilder()
			Expect(b.Release(logger, "never-made")).To(Succeed())

			_, _, err := b.Image(logger, "c1", ref)
			Expect(err).NotTo(HaveOccurred())
			Expect(b.Release(logger, "c1")).To(Succeed())
			Expect(b.Release(logger, "c1")).To(Succeed())
		})
	})

	Describe("Prune", func() {
		It("removes the directories of handles it is not told to keep and evicts what they held", func() {
			config.CacheBytes = 150
			b := newBuilder()
			_, _, err := image(b, "gone", "layer-a")
			Expect(err).NotTo(HaveOccurred())
			age("layer-a", 3*time.Hour)
			kept, _, err := image(b, "kept", "layer-b")
			Expect(err).NotTo(HaveOccurred())
			Expect(entryDirs()).To(HaveLen(2))

			Expect(b.Prune(logger, []string{"kept", "not-on-disk"})).To(Succeed())

			Expect(containerDir("gone")).NotTo(BeADirectory())
			Expect(filepath.Join(kept, imageName)).To(BeAnExistingFile())
			Expect(entryDirs()).To(ConsistOf(keyOf("layer-b")))
			Expect(logger.LogMessages()).To(ContainElement(HaveSuffix("pruned")))
		})

		It("removes every directory when it is told to keep none", func() {
			b := newBuilder()
			_, _, err := image(b, "c1", "layer-a")
			Expect(err).NotTo(HaveOccurred())

			Expect(b.Prune(logger, nil)).To(Succeed())
			entries, err := os.ReadDir(filepath.Join(cacheDir, "containers"))
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty())
		})

		It("fails when it cannot read the containers directory", func() {
			b := newBuilder()
			Expect(os.RemoveAll(filepath.Join(cacheDir, "containers"))).To(Succeed())
			Expect(b.Prune(logger, nil)).To(MatchError(ContainSubstring("vm image: reading the containers directory")))
		})
	})

	DescribeTable("handle validation",
		func(handle string) {
			b := newBuilder()
			_, _, err := b.Image(logger, handle, ref)
			Expect(err).To(MatchError(ContainSubstring("vm image: the handle")))
			Expect(b.Release(logger, handle)).To(Succeed())
			Expect(volume.creates()).To(BeEmpty())
			Expect(runCount()).To(Equal(0))
		},
		Entry("empty", ""),
		Entry("dot", "."),
		Entry("dot dot", ".."),
		Entry("a slash inside", "a/b"),
		Entry("a leading slash", "/a"),
		Entry("a trailing slash", "a/"),
		Entry("a parent path", "../a"),
	)
})
