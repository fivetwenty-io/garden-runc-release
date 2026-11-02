//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// squashTool returns the artifacts directory that realArtifactsEnv names, or
// skips the spec when the variable is unset or the directory holds no
// regular file called name.
func squashTool(name string) string {
	dir := os.Getenv(realArtifactsEnv)
	if dir == "" {
		Skip(realArtifactsEnv + " is not set; point it at a directory that holds " + name)
	}
	p := filepath.Join(dir, name)
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() {
		Skip(realArtifactsEnv + " holds no regular file " + name)
	}
	return dir
}

// writeHomeTree makes a small app home under dir: an executable, a symlink,
// an empty directory, and a nested file.
func writeHomeTree(dir string) {
	Expect(os.MkdirAll(filepath.Join(dir, "app", "lib"), 0o755)).To(Succeed())
	Expect(os.MkdirAll(filepath.Join(dir, "empty"), 0o700)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "app", "run.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "app", "lib", "data.txt"), []byte("data\n"), 0o640)).To(Succeed())
	Expect(os.Symlink("app/run.sh", filepath.Join(dir, "link"))).To(Succeed())
	Expect(os.Chmod(filepath.Join(dir, "empty"), 0o700)).To(Succeed())
}

// listSquashfs returns the unsquashfs -lls listing of the open image, which
// the child reads as its file descriptor 3 because the image has no name.
func listSquashfs(art string, image *os.File) string {
	cmd := exec.Command(filepath.Join(art, "unsquashfs"), "-lls", "/proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{image}
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), string(out))
	return string(out)
}

// The squashfs specs run under the QEMU runner mode, which sets the
// artifacts directory, and they skip without it.
var _ = Describe("the droplet image, built by the real QEMU artifacts mksquashfs", func() {
	var home, work string

	BeforeEach(func() {
		home = GinkgoT().TempDir()
		work = GinkgoT().TempDir()
		writeHomeTree(home)
	})

	It("holds the tree with its modes, owned by 2000:2000", func() {
		art := squashTool("mksquashfs")
		squashTool("unsquashfs")

		img, err := buildDropletImage(context.Background(), art, home, work)
		Expect(err).NotTo(HaveOccurred())
		defer img.file.Close()
		Expect(img.size).To(BeNumerically(">", 0))
		Expect(img.took).To(BeNumerically(">=", 0))

		// The file is unlinked, so list the image through its descriptor.
		listing := listSquashfs(art, img.file)
		for _, want := range []string{
			`-rwxr-xr-x 2000/2000`,
			`/app/run.sh`,
			`-rw-r----- 2000/2000`,
			`/app/lib/data.txt`,
			`drwx------ 2000/2000`,
			`/empty`,
			`lrwxrwxrwx 2000/2000`,
			`/link -> app/run.sh`,
		} {
			Expect(listing).To(ContainSubstring(want))
		}
		owners := regexp.MustCompile(`(?m)^[-dlcbps]\S+ (\d+)/(\d+)`).FindAllStringSubmatch(listing, -1)
		Expect(owners).NotTo(BeEmpty())
		for _, m := range owners {
			Expect(m[1] + "/" + m[2]).To(Equal("2000/2000"))
		}
	})

	It("is an lz4 squashfs", func() {
		art := squashTool("mksquashfs")

		img, err := buildDropletImage(context.Background(), art, home, work)
		Expect(err).NotTo(HaveOccurred())
		defer img.file.Close()

		sb := make([]byte, squashfsSuperblockPrefix)
		_, err = img.file.ReadAt(sb, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(sb[:4]).To(Equal([]byte("hsqs")))
		Expect(int(sb[squashfsCompressorOffset])).To(Equal(squashfsCompressorLZ4))
	})

	It("is open read-only", func() {
		art := squashTool("mksquashfs")

		img, err := buildDropletImage(context.Background(), art, home, work)
		Expect(err).NotTo(HaveOccurred())
		defer img.file.Close()

		_, err = img.file.Write([]byte("x"))
		Expect(err).To(HaveOccurred())
	})

	It("leaves out a work directory inside the home", func() {
		art := squashTool("mksquashfs")
		squashTool("unsquashfs")
		work = filepath.Join(home, ".vm-launch-work")
		Expect(os.Mkdir(work, 0o700)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(work, "scratch"), []byte("scratch"), 0o600)).To(Succeed())

		img, err := buildDropletImage(context.Background(), art, home, work)
		Expect(err).NotTo(HaveOccurred())
		defer img.file.Close()

		listing := listSquashfs(art, img.file)
		Expect(listing).To(ContainSubstring("/app/run.sh"))
		Expect(listing).NotTo(ContainSubstring(".vm-launch-work"))
		Expect(listing).NotTo(ContainSubstring("scratch"))
	})

	It("leaves nothing in the work directory", func() {
		art := squashTool("mksquashfs")

		img, err := buildDropletImage(context.Background(), art, home, work)
		Expect(err).NotTo(HaveOccurred())
		defer img.file.Close()

		entries, err := os.ReadDir(work)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty())
	})

	It("fails with the tool's output when the home is missing", func() {
		art := squashTool("mksquashfs")

		_, err := buildDropletImage(context.Background(), art, filepath.Join(home, "no-such-home"), work)
		Expect(err).To(MatchError(ContainSubstring("mksquashfs")))
		Expect(err.Error()).To(ContainSubstring("no-such-home"))
		entries, _ := os.ReadDir(work)
		Expect(entries).To(BeEmpty())
	})
})

var _ = Describe("the droplet image without the tool", func() {
	It("names a missing binary in the error", func() {
		art := GinkgoT().TempDir()

		_, err := buildDropletImage(context.Background(), art, GinkgoT().TempDir(), GinkgoT().TempDir())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(filepath.Join(art, "mksquashfs")))
	})
})

// mountTmpfs mounts a tmpfs on dir and unmounts it when the spec ends, or
// skips the spec when the process may not mount.
func mountTmpfs(dir string) {
	GinkgoHelper()
	if err := unix.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
		Skip("mounting a tmpfs on " + dir + " needs privileges: " + err.Error())
	}
	DeferCleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })
}

var _ = Describe("relativeToHome", func() {
	It("returns a path inside the home relative to it", func() {
		rel, ok := relativeToHome("/home/vcap", "/home/vcap/persist/deep")
		Expect(ok).To(BeTrue())
		Expect(rel).To(Equal("persist/deep"))
	})

	It("refuses the home itself, its parent, and any path outside it", func() {
		for _, dir := range []string{"/home/vcap", "/home", "/data", "/home/vcapx", "/"} {
			_, ok := relativeToHome("/home/vcap", dir)
			Expect(ok).To(BeFalse(), dir)
		}
	})
})

var _ = Describe("the arguments of the droplet build", func() {
	// argsOf builds with a fake tool that records its arguments and makes an
	// empty image, and returns the arguments.
	argsOf := func(home, work string, exclude ...string) []string {
		GinkgoHelper()
		record := filepath.Join(GinkgoT().TempDir(), "args")
		art := writeFakeSquashTool("printf '%s\\n' \"$@\" >" + record + "\n: >\"$2\"\n")
		img, err := buildDropletImage(context.Background(), art, home, work, exclude...)
		Expect(err).NotTo(HaveOccurred())
		defer img.file.Close()
		raw, err := os.ReadFile(record)
		Expect(err).NotTo(HaveOccurred())
		return strings.Split(strings.TrimSpace(string(raw)), "\n")
	}

	// excludesOf returns the values that follow each -e in args.
	excludesOf := func(args []string) []string {
		var got []string
		for i, a := range args {
			if a == "-e" && i+1 < len(args) {
				got = append(got, args[i+1])
			}
		}
		return got
	}

	It("never leaves the home's filesystem", func() {
		args := argsOf("/home/vcap", GinkgoT().TempDir())
		Expect(args).To(ContainElement("-one-file-system"))
	})

	It("leaves out each volume path under the home, and nothing else", func() {
		args := argsOf("/home/vcap", GinkgoT().TempDir(),
			"/home/vcap/persist", "/home/vcap/deep/er", "/data", "/home/vcap", "/home/vcapx")
		Expect(excludesOf(args)).To(Equal([]string{"persist", "deep/er"}))
	})

	It("leaves out the work directory and the volume paths together", func() {
		home := GinkgoT().TempDir()
		work := filepath.Join(home, ".work")
		Expect(os.Mkdir(work, 0o700)).To(Succeed())
		args := argsOf(home, work, filepath.Join(home, "persist"))
		Expect(excludesOf(args)).To(Equal([]string{".work", "persist"}))
	})

	It("passes the excludes through the signal-watching build too", func() {
		record := filepath.Join(GinkgoT().TempDir(), "args")
		art := writeFakeSquashTool("printf '%s\\n' \"$@\" >" + record + "\n: >\"$2\"\n")
		img, sig, err := buildDropletImageWatching(make(chan os.Signal), time.Hour, art, "/home/vcap", GinkgoT().TempDir(), "/home/vcap/persist")
		Expect(err).NotTo(HaveOccurred())
		Expect(sig).To(BeNil())
		defer img.file.Close()
		raw, err := os.ReadFile(record)
		Expect(err).NotTo(HaveOccurred())
		Expect(excludesOf(strings.Split(strings.TrimSpace(string(raw)), "\n"))).To(Equal([]string{"persist"}))
	})
})

var _ = Describe("the droplet image with a mount under the home, built by the real QEMU artifacts mksquashfs", func() {
	var home, work string

	BeforeEach(func() {
		home = GinkgoT().TempDir()
		work = GinkgoT().TempDir()
		writeHomeTree(home)
		Expect(os.Mkdir(filepath.Join(home, "persist"), 0o755)).To(Succeed())
		mountTmpfs(filepath.Join(home, "persist"))
		Expect(os.WriteFile(filepath.Join(home, "persist", "in-the-mount"), []byte("mount\n"), 0o644)).To(Succeed())
	})

	It("holds an empty directory for the mount and none of what it holds", func() {
		art := squashTool("mksquashfs")
		squashTool("unsquashfs")

		img, err := buildDropletImage(context.Background(), art, home, work)
		Expect(err).NotTo(HaveOccurred())
		defer img.file.Close()

		listing := listSquashfs(art, img.file)
		Expect(listing).To(ContainSubstring("/app/run.sh"))
		Expect(listing).To(MatchRegexp(`(?m)^d\S+ 2000/2000 .* \S*/persist$`))
		Expect(listing).NotTo(ContainSubstring("in-the-mount"))
	})

	It("holds nothing of a volume path that it is told to leave out", func() {
		art := squashTool("mksquashfs")
		squashTool("unsquashfs")

		img, err := buildDropletImage(context.Background(), art, home, work, filepath.Join(home, "persist"))
		Expect(err).NotTo(HaveOccurred())
		defer img.file.Close()

		listing := listSquashfs(art, img.file)
		Expect(listing).To(ContainSubstring("/app/run.sh"))
		Expect(listing).NotTo(ContainSubstring("persist"))
		Expect(listing).NotTo(ContainSubstring("in-the-mount"))
	})
})

var _ = Describe("lastLines", func() {
	It("keeps the last non-empty lines after a newline", func() {
		Expect(lastLines("a\n\nb\nc\nd\n", 2)).To(Equal("\nc\nd"))
	})

	It("is empty for no output", func() {
		Expect(lastLines(" \n\n", 3)).To(Equal(""))
		Expect(strings.TrimSpace(lastLines("x", 3))).To(Equal("x"))
	})
})

// writeFakeSquashTool writes a mksquashfs into a new artifacts directory
// that runs script, and returns the directory.
func writeFakeSquashTool(script string) string {
	art := GinkgoT().TempDir()
	Expect(os.WriteFile(filepath.Join(art, artMksquashfs), []byte("#!/bin/sh\n"+script), 0o755)).To(Succeed())
	return art
}

var _ = Describe("the droplet build under signals and a time limit", func() {
	var home, work string
	var sigs chan os.Signal

	BeforeEach(func() {
		home = GinkgoT().TempDir()
		work = GinkgoT().TempDir()
		sigs = make(chan os.Signal, 4)
	})

	It("kills a build that is still running at the first signal and returns the signal", func() {
		art := writeFakeSquashTool("exec sleep 60\n")
		time.AfterFunc(200*time.Millisecond, func() { sigs <- syscall.SIGTERM })

		start := time.Now()
		img, sig, err := buildDropletImageWatching(sigs, time.Hour, art, home, work)
		Expect(time.Since(start)).To(BeNumerically("<", 10*time.Second))
		Expect(err).NotTo(HaveOccurred())
		Expect(img).To(BeNil())
		Expect(sig).To(Equal(syscall.SIGTERM))
	})

	It("takes only the first of several signals and leaves the rest for the supervisor", func() {
		art := writeFakeSquashTool("exec sleep 60\n")
		time.AfterFunc(200*time.Millisecond, func() {
			sigs <- syscall.SIGINT
			sigs <- syscall.SIGTERM
		})

		_, sig, _ := buildDropletImageWatching(sigs, time.Hour, art, home, work)
		Expect(sig).To(Equal(syscall.SIGINT))
		Expect(sigs).To(Receive(Equal(syscall.SIGTERM)))
	})

	It("loses no signal that arrives after the build finished", func() {
		art := writeFakeSquashTool("printf image > \"$2\"\n")
		img, sig, err := buildDropletImageWatching(sigs, time.Hour, art, home, work)
		Expect(err).NotTo(HaveOccurred())
		Expect(sig).To(BeNil())
		Expect(img).NotTo(BeNil())
		DeferCleanup(img.file.Close)

		sigs <- syscall.SIGTERM
		Expect(sigs).To(Receive(Equal(syscall.SIGTERM)))
	})

	It("leaves a signal that was queued before the watcher ended on the channel when the build ends first", func() {
		art := writeFakeSquashTool("printf image > \"$2\"\n")
		for i := 0; i < 50; i++ {
			img, sig, err := buildDropletImageWatching(sigs, time.Hour, art, home, work)
			Expect(err).NotTo(HaveOccurred())
			if img != nil {
				Expect(sig).To(BeNil())
				Expect(img.file.Close()).To(Succeed())
			}
		}
		sigs <- syscall.SIGTERM
		Expect(sigs).To(Receive(Equal(syscall.SIGTERM)))
	})

	It("fails a build that runs past its limit with the limit in the error, and consumes no signal", func() {
		art := writeFakeSquashTool("exec sleep 60\n")

		start := time.Now()
		img, sig, err := buildDropletImageWatching(sigs, 300*time.Millisecond, art, home, work)
		Expect(time.Since(start)).To(BeNumerically("<", 10*time.Second))
		Expect(img).To(BeNil())
		Expect(sig).To(BeNil())
		Expect(err).To(MatchError(ContainSubstring("the build ran past its limit of 300ms")))
		Expect(errors.Is(err, context.DeadlineExceeded)).To(BeTrue())

		sigs <- syscall.SIGTERM
		Expect(sigs).To(Receive())
	})
})
