package rundmc

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/lager/v3"
)

const (
	// The exec streamer runs these binaries from the container's own image,
	// because a sandboxed runtime cannot enter the container's mount namespace
	// with the host's tar the way nstar does.
	containerMkdirPath = "/bin/mkdir"
	containerTarPath   = "/bin/tar"

	// maxStreamStderrBytes bounds how much of the container tar's stderr is kept
	// for error messages, so a failing extraction cannot grow guardian's memory.
	maxStreamStderrBytes = 4096
)

var errEmptyStreamPath = errors.New("path must not be empty")

type tarStreamer interface {
	StreamIn(log lager.Logger, handle string, spec garden.StreamInSpec) error
	StreamOut(log lager.Logger, handle string, spec garden.StreamOutSpec) (io.ReadCloser, error)
}

// NstarStreamer streams tar archives by running the host's tar inside the
// namespaces of the container's init process.
type NstarStreamer struct {
	runtime OCIRuntime
	nstar   NstarRunner
}

func NewNstarStreamer(runtime OCIRuntime, nstar NstarRunner) *NstarStreamer {
	return &NstarStreamer{runtime: runtime, nstar: nstar}
}

func (s *NstarStreamer) StreamIn(log lager.Logger, handle string, spec garden.StreamInSpec) error {
	state, err := s.runtime.State(log, handle)
	if err != nil {
		log.Error("check-pid-failed", err)
		return fmt.Errorf("stream-in: pid not found for container")
	}

	if err := s.nstar.StreamIn(log, state.Pid, spec.Path, spec.User, spec.TarStream); err != nil {
		log.Error("nstar-failed", err)
		return fmt.Errorf("stream-in: nstar: %s", err)
	}

	return nil
}

func (s *NstarStreamer) StreamOut(log lager.Logger, handle string, spec garden.StreamOutSpec) (io.ReadCloser, error) {
	state, err := s.runtime.State(log, handle)
	if err != nil {
		log.Error("check-pid-failed", err)
		return nil, fmt.Errorf("stream-out: pid not found for container")
	}

	stream, err := s.nstar.StreamOut(log, state.Pid, spec.Path, spec.User)
	if err != nil {
		log.Error("nstar-failed", err)
		return nil, fmt.Errorf("stream-out: nstar: %s", err)
	}

	return stream, nil
}

// ExecStreamer streams tar archives by executing the container image's own tar
// as a process inside the container. Sandboxed runtimes such as gVisor use it,
// because their processes do not live in host namespaces nstar could enter.
type ExecStreamer struct {
	runtime OCIRuntime
}

func NewExecStreamer(runtime OCIRuntime) *ExecStreamer {
	return &ExecStreamer{runtime: runtime}
}

func (s *ExecStreamer) StreamIn(log lager.Logger, handle string, spec garden.StreamInSpec) error {
	log = log.Session("exec-stream-in", lager.Data{"path": spec.Path})

	if spec.Path == "" {
		log.Error("invalid-spec", errEmptyStreamPath)
		return fmt.Errorf("stream-in: %w", errEmptyStreamPath)
	}

	user := streamUser(spec.User)

	if err := s.runToCompletion(log, handle, garden.ProcessSpec{
		Path: containerMkdirPath,
		Args: []string{"-p", spec.Path},
		User: user,
	}, nil); err != nil {
		log.Error("mkdir-failed", err)
		return fmt.Errorf("stream-in: mkdir: %w", err)
	}

	// The ownership and permission flags match nstar, so the archive's owners
	// and modes do not carry into the container. nstar's xattr flags are left
	// out on purpose. The image's tar may be busybox, which rejects them, and a
	// rejected flag would fail every stream-in.
	if err := s.runToCompletion(log, handle, garden.ProcessSpec{
		Path: containerTarPath,
		Args: []string{"--no-same-owner", "--no-same-permissions", "-xf", "-", "-C", spec.Path},
		User: user,
	}, spec.TarStream); err != nil {
		log.Error("tar-failed", err)
		return fmt.Errorf("stream-in: tar: %w", err)
	}

	return nil
}

// StreamOut returns the stdout of a tar process running in the container. A
// tar that fails after it has started surfaces as an error from Read on the
// returned stream, so the caller never mistakes a truncated archive for a
// complete one.
func (s *ExecStreamer) StreamOut(log lager.Logger, handle string, spec garden.StreamOutSpec) (io.ReadCloser, error) {
	log = log.Session("exec-stream-out", lager.Data{"path": spec.Path})

	if spec.Path == "" {
		log.Error("invalid-spec", errEmptyStreamPath)
		return nil, fmt.Errorf("stream-out: %w", errEmptyStreamPath)
	}

	sourcePath, compressPath := tarSource(spec.Path)
	reader, writer := io.Pipe()
	stderr := &cappedBuffer{limit: maxStreamStderrBytes}

	process, err := s.runtime.Exec(log, handle, garden.ProcessSpec{
		Path: containerTarPath,
		Args: []string{"-cf", "-", "-C", sourcePath, compressPath},
		User: streamUser(spec.User),
	}, garden.ProcessIO{Stdout: writer, Stderr: stderr})
	if err != nil {
		log.Error("exec-tar-failed", err)
		_ = writer.Close()
		_ = reader.Close()
		return nil, fmt.Errorf("stream-out: exec tar: %w", err)
	}

	go func() {
		if err := waitForSuccess(process, stderr); err != nil {
			log.Error("tar-failed", err)
			_ = writer.CloseWithError(fmt.Errorf("stream-out: tar: %w", err))
			return
		}
		_ = writer.Close()
	}()

	return reader, nil
}

func (s *ExecStreamer) runToCompletion(log lager.Logger, handle string, spec garden.ProcessSpec, stdin io.Reader) error {
	stderr := &cappedBuffer{limit: maxStreamStderrBytes}

	process, err := s.runtime.Exec(log, handle, spec, garden.ProcessIO{
		Stdin:  stdin,
		Stdout: io.Discard,
		Stderr: stderr,
	})
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	return waitForSuccess(process, stderr)
}

func waitForSuccess(process garden.Process, stderr *cappedBuffer) error {
	exitCode, err := process.Wait()
	if err != nil {
		return fmt.Errorf("wait: %w", err)
	}

	if exitCode != 0 {
		return fmt.Errorf("exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
	}

	return nil
}

// tarSource splits a stream-out path into the directory tar changes into and
// the entry it archives. A trailing slash archives the directory's contents
// rather than the directory itself, matching nstar.
func tarSource(path string) (string, string) {
	if strings.HasSuffix(path, "/") {
		return path, "."
	}

	return filepath.Dir(path), filepath.Base(path)
}

func streamUser(user string) string {
	if user == "" {
		return "root"
	}

	return user
}

// cappedBuffer keeps the first limit bytes written to it and discards the rest
// while still reporting a full write, so the process writing into it is never
// blocked or failed by the cap.
type cappedBuffer struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			b.buf.Write(p[:remaining])
		} else {
			b.buf.Write(p)
		}
	}

	return len(p), nil
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}
