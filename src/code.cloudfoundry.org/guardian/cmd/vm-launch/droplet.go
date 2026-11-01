//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// The droplet image. In stack mode the guest runs the app from a squashfs of
// the app's home directory, which vm-launch builds from the container's
// /home/vcap just before it starts the hypervisor.
const (
	// artMksquashfs is the squashfs builder in the artifacts directory.
	artMksquashfs = "mksquashfs"

	// dropletOwner is the uid and gid that own every file in the image, the
	// vcap user the app runs as in the guest.
	dropletOwner = 2000

	// dropletBuildOutputLines is how many of the tool's last output lines go
	// into the error when the build fails.
	dropletBuildOutputLines = 8
)

// dropletImage is the droplet image buildDropletImage made.
type dropletImage struct {
	// file is the open, read-only image. Its directory entry is gone, so the
	// image lives as long as file is open.
	file *os.File
	// size is the image's size in bytes.
	size int64
	// took is how long the build took.
	took time.Duration
}

// buildDropletImage packs the directory home into a squashfs in workDir with
// the mksquashfs in the artifacts directory, as an lz4 image in which every
// file belongs to the droplet owner. It opens the result read-only and
// unlinks it, so nothing is left in workDir. When workDir is inside home, the
// image leaves workDir out. A failure carries the last lines of the tool's
// output.
func buildDropletImage(artifacts, home, workDir string) (*dropletImage, error) {
	tool := filepath.Join(artifacts, artMksquashfs)
	image := filepath.Join(workDir, "droplet.sqfs")
	args := []string{
		home, image,
		"-noappend", "-comp", "lz4", "-b", "128K",
		"-force-uid", fmt.Sprint(dropletOwner), "-force-gid", fmt.Sprint(dropletOwner),
		"-mem", "64M", "-processors", "1", "-no-progress", "-quiet",
	}
	if rel, err := filepath.Rel(home, workDir); err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		args = append(args, "-e", rel)
	}

	start := time.Now()
	var out bytes.Buffer
	cmd := exec.Command(tool, args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		_ = os.Remove(image)
		return nil, fmt.Errorf("building the droplet image with %s: %w%s", tool, err, lastLines(out.String(), dropletBuildOutputLines))
	}
	took := time.Since(start)

	f, err := os.OpenFile(image, os.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		_ = os.Remove(image)
		return nil, fmt.Errorf("opening the droplet image: %w", err)
	}
	if err := os.Remove(image); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("unlinking the droplet image: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("examining the droplet image: %w", err)
	}
	return &dropletImage{file: f, size: info.Size(), took: took}, nil
}

// lastLines returns a newline and the last n non-empty lines of s, or an
// empty string when s has none.
func lastLines(s string, n int) string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return "\n" + strings.Join(lines, "\n")
}
