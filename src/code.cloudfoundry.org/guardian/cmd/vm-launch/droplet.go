//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
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

	// dropletKillWait is how long a cancelled build may take to release its
	// output pipes after mksquashfs is killed.
	dropletKillWait = 5 * time.Second
)

// dropletBuildTimeout is the longest a droplet build may run. Diego gives an
// app minutes to start, so a build that has run for ten minutes has long
// outlived any launch that waits for it. The bound only ends a build that has
// stalled, for example on a huge sparse file, and a healthy cold build of a
// large droplet finishes well inside it. Specs shorten it.
var dropletBuildTimeout = 10 * time.Minute

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
// output. Cancelling ctx kills the tool, and the error then wraps the
// context's error.
func buildDropletImage(ctx context.Context, artifacts, home, workDir string) (*dropletImage, error) {
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
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.WaitDelay = dropletKillWait
	if err := cmd.Run(); err != nil {
		_ = os.Remove(image)
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = fmt.Errorf("%w (%v)", ctxErr, err)
		}
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

// buildDropletImageWatching builds the droplet image as buildDropletImage
// does, within timeout, and stops the build at the first signal on sigs. The
// watcher that reads sigs has ended when this returns, so a signal it did not
// take is still on the channel for the supervisor. A signal it took is
// returned as the second result, and the build is then cancelled, so the
// caller must not start the guest. An error that is not from a signal says
// whether the build ran past timeout.
func buildDropletImageWatching(sigs <-chan os.Signal, timeout time.Duration, artifacts, home, workDir string) (*dropletImage, os.Signal, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	caught := make(chan os.Signal, 1)
	stop := make(chan struct{})
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		select {
		case sig := <-sigs:
			caught <- sig
			cancel()
		case <-stop:
		}
	}()
	img, err := buildDropletImage(ctx, artifacts, home, workDir)
	close(stop)
	<-ended
	select {
	case sig := <-caught:
		if img != nil {
			_ = img.file.Close()
		}
		return nil, sig, nil
	default:
	}
	if errors.Is(err, context.DeadlineExceeded) {
		err = fmt.Errorf("the build ran past its limit of %s: %w", timeout, err)
	}
	return img, nil, err
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
