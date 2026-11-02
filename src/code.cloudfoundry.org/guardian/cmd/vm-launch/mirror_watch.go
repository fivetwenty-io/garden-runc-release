//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// mirrorFrameData is the most base64 characters one data line of a file push
// carries. With the tag, the nonce, and the newline, a line stays well inside
// one console chunk, and a multiple of four keeps each line whole base64.
const mirrorFrameData = 200

// mirrorFrames returns the console lines that carry data, with mode perm, to
// the guest as push number seq of watched file number, without line endings:
// a begin line, a data line for each piece of the base64 of data, and an end
// line with the sequence, the file's number, the count of data lines, the
// size, the mode in octal, and the hex sha256 of data (see
// mountMirror.guestFileReader).
func mirrorFrames(nonce string, seq, number int, data []byte, perm uint32) []string {
	tag := fileTag(nonce)
	enc := base64.StdEncoding.EncodeToString(data)
	frames := make([]string, 0, len(enc)/mirrorFrameData+3)
	frames = append(frames, fmt.Sprintf("%sbegin %d %d", tag, seq, number))
	lines := 0
	for len(enc) > 0 {
		n := min(len(enc), mirrorFrameData)
		frames = append(frames, tag+"data "+enc[:n])
		enc = enc[n:]
		lines++
	}
	sum := sha256.Sum256(data)
	return append(frames, fmt.Sprintf("%send %d %d %d %d %04o %s", tag, seq, number, lines, len(data), perm&0o777, hex.EncodeToString(sum[:])))
}

// mirrorPush is the push in flight: its sequence number, the file, and the
// content and mode it carries.
type mirrorPush struct {
	seq      int
	file     *mirrorWatched
	data     []byte
	perm     uint32
	sentAt   time.Time
	attempts int
	failed   bool
}

// mirrorWatcher notices changes to the watched files of the mirrored mounts
// and pushes each changed file to the guest, one push at a time. It pushes a
// file again when the guest reports a failure or stays silent, a limited
// number of times, as the identity watcher does (see credWatcher), and a
// newer change to the file in flight replaces the push. A file that goes
// missing, stops being a regular file, or grows over mirrorWatchMaxBytes
// keeps the content the guest has, with one line for each state of it.
type mirrorWatcher struct {
	files      []*mirrorWatched
	interval   time.Duration
	ackTimeout time.Duration
	push       func(seq int, w *mirrorWatched, data []byte, perm uint32) error
	logger     *log.Logger
	now        func() time.Time

	ackMu sync.Mutex
	ack   *credAck

	mu      sync.Mutex
	seq     int
	pending *mirrorPush
	// want holds, for each file whose content differs from what the guest
	// holds, the content and mode to push, by watched number.
	want map[int]mirrorWant
	// refused holds the state of each file that the watcher could not take,
	// so that it says so once for each state, and gone marks each file that
	// is missing or not a regular file, which it says once until the file is
	// back.
	refused map[int]fileState
	gone    map[int]bool
}

// mirrorWant is the content and mode a file should have in the guest.
type mirrorWant struct {
	data []byte
	perm uint32
}

func newMirrorWatcher(files []*mirrorWatched, interval time.Duration, push func(seq int, w *mirrorWatched, data []byte, perm uint32) error, logger *log.Logger) *mirrorWatcher {
	return &mirrorWatcher{
		files: files, interval: interval, ackTimeout: credAckTimeout,
		push: push, logger: logger, now: time.Now,
		want: map[int]mirrorWant{}, refused: map[int]fileState{}, gone: map[int]bool{},
	}
}

// run watches until stop closes.
func (w *mirrorWatcher) run(stop <-chan struct{}) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			w.tick()
		}
	}
}

// acked records the guest's answer to push number seq. It never blocks, so
// the console reader can call it while a push is in progress, and the next
// tick applies the answer.
func (w *mirrorWatcher) acked(seq int, ok bool) {
	w.ackMu.Lock()
	defer w.ackMu.Unlock()
	w.ack = &credAck{seq: seq, ok: ok}
}

// applyAck takes the recorded answer, if any, and applies it. An answer to
// any push but the one in flight does not count. The caller holds the lock.
func (w *mirrorWatcher) applyAck() {
	w.ackMu.Lock()
	ack := w.ack
	w.ack = nil
	w.ackMu.Unlock()
	if ack == nil || w.pending == nil || ack.seq != w.pending.seq {
		return
	}
	p := w.pending
	if !ack.ok {
		p.failed = true
		w.logger.Printf("the guest refused push %d of the mirrored file %s", p.seq, quoteForLog(p.file.path))
		return
	}
	p.file.data, p.file.perm = p.data, p.perm
	if want, ok := w.want[p.file.number]; ok && bytes.Equal(want.data, p.data) && want.perm == p.perm {
		delete(w.want, p.file.number)
	}
	w.pending = nil
	w.logger.Printf("the guest installed push %d of the mirrored file %s, %d bytes", p.seq, quoteForLog(p.file.path), len(p.data))
}

// tick does one pass of the watch.
func (w *mirrorWatcher) tick() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.applyAck()
	for _, f := range w.files {
		w.look(f)
	}
	if p := w.pending; p != nil {
		if want, ok := w.want[p.file.number]; ok && (!bytes.Equal(want.data, p.data) || want.perm != p.perm) {
			// A newer change replaces the push in flight.
			w.pending = nil
		} else if p.failed || w.now().Sub(p.sentAt) >= w.ackTimeout {
			if p.attempts > credMaxResends {
				w.pending = nil
				delete(w.want, p.file.number)
				w.logger.Printf("giving up on push %d of the mirrored file %s after %d tries; waiting for the next change", p.seq, quoteForLog(p.file.path), p.attempts)
				return
			}
			w.send(p)
			return
		} else {
			return
		}
	}
	for _, f := range w.files {
		if want, ok := w.want[f.number]; ok {
			w.seq++
			w.send(&mirrorPush{seq: w.seq, file: f, data: want.data, perm: want.perm})
			return
		}
	}
}

// look stats f and, when it changed, reads it and records whether the guest
// needs it. The caller holds the lock.
func (w *mirrorWatcher) look(f *mirrorWatched) {
	state, ok := statMirrorFile(f.path)
	if !ok {
		if !w.gone[f.number] {
			w.gone[f.number] = true
			w.logger.Printf("the mirrored file %s is gone or is no longer a regular file, so the guest keeps the copy it has", quoteForLog(f.path))
		}
		return
	}
	delete(w.gone, f.number)
	if state == f.state {
		return
	}
	if w.refused[f.number] == state {
		return
	}
	data, read, perm, err := readMirrorFile(f.path, mirrorWatchMaxBytes)
	switch {
	case errors.Is(err, errMirrorTooLarge):
		w.refused[f.number] = state
		w.logger.Printf("the mirrored file %s is now over the %d bytes vm-launch pushes, so the guest keeps the copy it has", quoteForLog(f.path), mirrorWatchMaxBytes)
		return
	case errors.Is(err, os.ErrNotExist):
		return
	case err != nil:
		w.refused[f.number] = state
		w.logger.Printf("reading the mirrored file %s to push it: %v", quoteForLog(f.path), err)
		return
	}
	delete(w.refused, f.number)
	f.state = read
	if bytes.Equal(data, f.data) && perm == f.perm {
		delete(w.want, f.number)
		return
	}
	w.want[f.number] = mirrorWant{data: data, perm: perm}
}

// send pushes p. The time of the push is taken once it is written, because
// a large file takes many seconds to write. The caller holds the lock.
func (w *mirrorWatcher) send(p *mirrorPush) {
	p.attempts++
	p.failed = false
	w.pending = p
	err := w.push(p.seq, p.file, p.data, p.perm)
	p.sentAt = w.now()
	if err != nil {
		p.failed = true
		w.logger.Printf("pushing the mirrored file %s as push %d, try %d: %v", quoteForLog(p.file.path), p.seq, p.attempts, err)
		return
	}
	w.logger.Printf("pushed the mirrored file %s as push %d, %d bytes, try %d", quoteForLog(p.file.path), p.seq, len(p.data), p.attempts)
}

// mirrorWatchInterval is how often vm-launch looks at the watched files of
// the mirrored mounts. Specs shorten it.
var mirrorWatchInterval = 5 * time.Second

// watchMirror wires the watcher of the mirrored files into sup and returns
// the function that stops it, as watchIdentity does. The supervisor hands
// over the console only to a guest that said it takes file pushes (see
// fileOnTag).
func watchMirror(sup *supervisor, nonce string, m *mountMirror, logger *log.Logger) (stop func()) {
	var console *consoleWriter
	w := newMirrorWatcher(m.watched, mirrorWatchInterval, func(seq int, f *mirrorWatched, data []byte, perm uint32) error {
		return console.push(mirrorFrames(nonce, seq, f.number, data, perm))
	}, logger)
	sup.fileAck = w.acked
	quit := make(chan struct{})
	var done chan struct{}
	sup.onFileConsole = func(c *consoleWriter) {
		console = c
		done = make(chan struct{})
		go func() {
			defer close(done)
			w.run(quit)
		}()
	}
	return func() {
		close(quit)
		if done != nil {
			<-done
		}
	}
}
