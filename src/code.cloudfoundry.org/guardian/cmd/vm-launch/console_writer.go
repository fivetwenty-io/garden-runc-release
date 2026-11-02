//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// consoleChunk is the most console input that a push writes at once, and
// consolePace is the pause between two of its chunks. A push of an identity
// pair is about 5 KB, so it takes about two seconds, and a slow console
// input, such as Firecracker's serial port, never overflows.
const (
	consoleChunk = 256
	consolePace  = 100 * time.Millisecond
)

// errConsoleStopped is what a push returns once a stop request has begun or
// the writer has closed.
var errConsoleStopped = errors.New("the guest console takes no more pushes, because the stop request has begun or vm-launch is done with the console")

// consoleWriter is the one writer of the hypervisor's stdin, which is the
// guest's console input. It carries the stop request (see stopTag) and the
// identity pushes (see credFrames), and it lets a stop go first. A push
// writes whole lines in chunks of at most consoleChunk bytes, takes the lock
// once for each chunk, pauses consolePace between chunks, and gives up the
// rest of its lines when a stop begins, so a stop reaches the pipe after at
// most one more chunk. Chunks hold whole lines, so the stop request always
// starts a line of its own, and the guest discards the frame it cut short.
// Once stop has begun, every push fails at once, unless a tryStop that
// wrote nothing gives the console back.
//
// A write of at most PIPE_BUF bytes to a pipe is atomic, so a chunk is either
// written whole or not at all, and a stop that cuts a blocked chunk short
// leaves nothing of it in the pipe.
type consoleWriter struct {
	f     *os.File
	chunk int
	pace  time.Duration
	// chunkTimeout bounds the write of one chunk, so that a push never
	// waits for good on a guest that reads none of its console.
	chunkTimeout time.Duration

	// stopping is set when stop or close begins, before either takes the
	// lock, so that a push gives way between chunks.
	stopping atomic.Bool
	// wake is closed when stopping is set, which ends a push's pause at
	// once. wakeMu guards wake and woken, because a tryStop that writes
	// nothing puts a fresh channel in its place.
	wakeMu sync.Mutex
	wake   chan struct{}
	woken  bool

	// mu is held for each write. done, which mu guards, is set once stop or
	// close has taken it.
	mu   sync.Mutex
	done bool
}

func newConsoleWriter(f *os.File) *consoleWriter {
	return &consoleWriter{f: f, chunk: consoleChunk, pace: consolePace, chunkTimeout: stopRequestTimeout, wake: make(chan struct{})}
}

// push writes lines, each followed by a newline, in paced chunks. It fails
// before it writes anything when a line holds a newline or is too long for
// a chunk with its newline, and it fails with errConsoleStopped, having
// written only whole chunks, when a stop begins first or while it runs.
func (w *consoleWriter) push(lines []string) error {
	chunks, err := consoleChunks(lines, w.chunk)
	if err != nil {
		return err
	}
	wake := w.wakeChan()
	for i, c := range chunks {
		if i > 0 {
			pause := time.NewTimer(w.pace)
			select {
			case <-wake:
				pause.Stop()
				return errConsoleStopped
			case <-pause.C:
			}
		}
		if err := w.writeChunk(c); err != nil {
			return err
		}
	}
	return nil
}

func (w *consoleWriter) writeChunk(c []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done || w.stopping.Load() {
		return errConsoleStopped
	}
	if err := w.f.SetWriteDeadline(time.Now().Add(w.chunkTimeout)); err != nil && !errors.Is(err, os.ErrNoDeadline) {
		return err
	}
	// A stop that began after the check above moves the deadline into the
	// past, which ends this write at once, unless the deadline above came
	// later still. This check sees that case.
	if w.stopping.Load() {
		return errConsoleStopped
	}
	if _, err := w.f.Write(c); err != nil {
		if w.stopping.Load() {
			return errConsoleStopped
		}
		return err
	}
	return nil
}

// stop writes line and a newline, the stop request, with a deadline of
// stopRequestTimeout, ahead of the rest of any push. It runs once: a second
// stop, or a stop after close, fails without writing. stop, tryStop, and
// close must not run at the same time, because each cuts the other's write
// short.
func (w *consoleWriter) stop(line string) error {
	return w.writeStop(line, false)
}

// tryStop writes the stop request as stop does, but when the write fails
// before any of the line reaches the console, it leaves the writer as it was
// before, so a later stop or push still works. The stop request is far
// shorter than PIPE_BUF, so a write to a pipe puts all of it there or none.
// A write that fails after part of the line went out leaves the writer
// stopped, as stop does, because a later line would run on from that part.
func (w *consoleWriter) tryStop(line string) error {
	return w.writeStop(line, true)
}

func (w *consoleWriter) writeStop(line string, keep bool) error {
	w.halt()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return errConsoleStopped
	}
	w.done = true
	if err := w.f.SetWriteDeadline(time.Now().Add(stopRequestTimeout)); err != nil && !errors.Is(err, os.ErrNoDeadline) {
		if keep {
			w.resume()
		}
		return err
	}
	n, err := w.f.WriteString(line + "\n")
	if err != nil && n == 0 && keep {
		w.resume()
	}
	return err
}

// close ends every push at once and closes the hypervisor's stdin.
func (w *consoleWriter) close() error {
	w.halt()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.done = true
	return w.f.Close()
}

// halt makes every push give way: one that pauses ends at once, and one that
// is blocked in a write on a full pipe ends at once too, because its deadline
// moves into the past.
func (w *consoleWriter) halt() {
	w.stopping.Store(true)
	w.wakeMu.Lock()
	if !w.woken {
		close(w.wake)
		w.woken = true
	}
	w.wakeMu.Unlock()
	// A file without deadlines cannot be cut short, and its write ends on
	// its own.
	_ = w.f.SetWriteDeadline(time.Unix(1, 0))
}

// resume undoes halt and the start of a stop that wrote nothing, so that
// pushes and a stop work again. A push that halt ended stays ended, and its
// caller sends it again. The caller holds mu.
func (w *consoleWriter) resume() {
	w.done = false
	w.wakeMu.Lock()
	w.wake, w.woken = make(chan struct{}), false
	w.wakeMu.Unlock()
	w.stopping.Store(false)
	_ = w.f.SetWriteDeadline(time.Time{})
}

// wakeChan returns the channel that the next halt closes.
func (w *consoleWriter) wakeChan() <-chan struct{} {
	w.wakeMu.Lock()
	defer w.wakeMu.Unlock()
	return w.wake
}

// consoleChunks packs lines, each followed by a newline, into chunks of at
// most size bytes that hold whole lines.
func consoleChunks(lines []string, size int) ([][]byte, error) {
	var chunks [][]byte
	var cur []byte
	for i, l := range lines {
		if strings.ContainsAny(l, "\r\n") {
			return nil, fmt.Errorf("console line %d holds a line break", i)
		}
		if len(l)+1 > size {
			return nil, fmt.Errorf("console line %d is %d bytes, and a chunk holds at most %d with the newline", i, len(l), size)
		}
		if len(cur)+len(l)+1 > size {
			chunks = append(chunks, cur)
			cur = nil
		}
		cur = append(append(cur, l...), '\n')
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	return chunks, nil
}
