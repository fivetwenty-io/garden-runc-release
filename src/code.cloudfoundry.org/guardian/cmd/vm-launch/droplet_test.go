//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

		img, err := buildDropletImage(art, home, work)
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

		img, err := buildDropletImage(art, home, work)
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

		img, err := buildDropletImage(art, home, work)
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

		img, err := buildDropletImage(art, home, work)
		Expect(err).NotTo(HaveOccurred())
		defer img.file.Close()

		listing := listSquashfs(art, img.file)
		Expect(listing).To(ContainSubstring("/app/run.sh"))
		Expect(listing).NotTo(ContainSubstring(".vm-launch-work"))
		Expect(listing).NotTo(ContainSubstring("scratch"))
	})

	It("leaves nothing in the work directory", func() {
		art := squashTool("mksquashfs")

		img, err := buildDropletImage(art, home, work)
		Expect(err).NotTo(HaveOccurred())
		defer img.file.Close()

		entries, err := os.ReadDir(work)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty())
	})

	It("fails with the tool's output when the home is missing", func() {
		art := squashTool("mksquashfs")

		_, err := buildDropletImage(art, filepath.Join(home, "no-such-home"), work)
		Expect(err).To(MatchError(ContainSubstring("mksquashfs")))
		Expect(err.Error()).To(ContainSubstring("no-such-home"))
		entries, _ := os.ReadDir(work)
		Expect(entries).To(BeEmpty())
	})
})

var _ = Describe("the droplet image without the tool", func() {
	It("names a missing binary in the error", func() {
		art := GinkgoT().TempDir()

		_, err := buildDropletImage(art, GinkgoT().TempDir(), GinkgoT().TempDir())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(filepath.Join(art, "mksquashfs")))
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
