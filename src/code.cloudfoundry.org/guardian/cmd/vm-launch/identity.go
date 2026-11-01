//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// maxIdentityFileBytes is the most that either file of the instance
	// identity pair may hold. A real pair is a few kilobytes.
	maxIdentityFileBytes = 64 << 10

	// credAckTimeout is how long the watcher waits for the guest to answer
	// a push before it sends the same pair again.
	credAckTimeout = 30 * time.Second

	// credMaxResends is how many times the watcher sends a pair again after
	// the first push, so a pair is pushed at most one more than this.
	credMaxResends = 5
)

// credTag returns the tag that starts every frame line on the console input
// for nonce. A frame line is the tag, then "=", then the frame.
func credTag(nonce string) string { return "RVM_CRED_" + nonce }

// credOKTag returns the tag of the console output line that reports a pair
// the guest installed. The line is the tag, then "=", then the sequence.
func credOKTag(nonce string) string { return "RVM_CREDOK_" + nonce }

// credBadTag returns the tag of the console output line that reports a pair
// the guest refused. The line is the tag, then "=", then the sequence.
func credBadTag(nonce string) string { return "RVM_CREDBAD_" + nonce }

// fileStamp names the state of the two files of the identity pair, so that a
// rewrite by Diego shows as a difference. Each file contributes the device,
// inode, size, and modification time that stat reports, which change when a
// new file is renamed over the old one.
type fileStamp struct {
	cert, key fileState
}

// fileState is what stat reports about one file.
type fileState struct {
	dev, ino  uint64
	size      int64
	modTimeNs int64
}

// instanceIdentity is the instance identity pair that Diego writes for the
// app: a certificate and its key, both in PEM.
type instanceIdentity struct {
	cert, key []byte
	serial    string
	notAfter  time.Time
	stamp     fileStamp
}

// readInstanceIdentity reads the pair at certPath and keyPath. It returns
// nil and no error when either path is empty or names no file, because the
// app then has no identity to carry. It refuses a file over 64 KiB and a key
// that does not belong to the certificate. The returned stamp comes from the
// files as they were opened, so a rewrite after the read shows as a change.
func readInstanceIdentity(certPath, keyPath string) (*instanceIdentity, error) {
	if certPath == "" || keyPath == "" {
		return nil, nil
	}
	cert, certState, err := readIdentityFile(certPath)
	if err != nil {
		return nil, err
	}
	key, keyState, err := readIdentityFile(keyPath)
	if err != nil {
		return nil, err
	}
	if cert == nil || key == nil {
		return nil, nil
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("the instance identity certificate and key do not make a pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("the instance identity certificate does not parse: %w", err)
	}
	return &instanceIdentity{
		cert:     cert,
		key:      key,
		serial:   leaf.SerialNumber.String(),
		notAfter: leaf.NotAfter,
		stamp:    fileStamp{cert: certState, key: keyState},
	}, nil
}

// readIdentityFile reads one file of the pair. It returns nil bytes and no
// error when the file does not exist.
func readIdentityFile(path string) ([]byte, fileState, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fileState{}, nil
	}
	if err != nil {
		return nil, fileState{}, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fileState{}, fmt.Errorf("reading %s: %w", path, err)
	}
	if info.Size() > maxIdentityFileBytes {
		return nil, fileState{}, fmt.Errorf("%s is %d bytes, over the %d bytes an identity file may have", path, info.Size(), maxIdentityFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxIdentityFileBytes+1))
	if err != nil {
		return nil, fileState{}, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(data) > maxIdentityFileBytes {
		return nil, fileState{}, fmt.Errorf("%s is over the %d bytes an identity file may have", path, maxIdentityFileBytes)
	}
	return data, stateOf(info), nil
}

// stateOf converts the stat of a file into a fileState.
func stateOf(info os.FileInfo) fileState {
	state := fileState{size: info.Size(), modTimeNs: info.ModTime().UnixNano()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		state.dev, state.ino = uint64(st.Dev), uint64(st.Ino) //nolint:unconvert // the widths differ by architecture
	}
	return state
}

// statIdentity returns the stamp of the two files as they are now. A file
// that is missing gives a zero state, and ok is false when stat fails for
// another reason.
func statIdentity(certPath, keyPath string) (fileStamp, bool) {
	var stamp fileStamp
	for i, path := range []string{certPath, keyPath} {
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fileStamp{}, false
		}
		if i == 0 {
			stamp.cert = stateOf(info)
		} else {
			stamp.key = stateOf(info)
		}
	}
	return stamp, true
}

// pemLines splits a PEM file into its lines, without line endings. A final
// newline ends the last line and does not start another.
func pemLines(data []byte) []string {
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

// credFrames returns the console lines that carry id to the guest as push
// number seq, without line endings. The lines are a begin line, one crt line
// for each line of the certificate, one key line for each line of the key,
// and an end line with the sequence, the two line counts, and the hex sha256
// of the certificate followed by the key. The guest rebuilds each file by
// joining its lines with a newline and ending the last one with a newline, so
// the digest is of the files in that form, which is the form Diego writes.
func credFrames(nonce string, seq int, id *instanceIdentity) []string {
	tag := credTag(nonce) + "="
	crt, key := pemLines(id.cert), pemLines(id.key)
	sum := sha256.New()
	sum.Write([]byte(strings.Join(crt, "\n") + "\n"))
	sum.Write([]byte(strings.Join(key, "\n") + "\n"))

	frames := make([]string, 0, len(crt)+len(key)+2)
	frames = append(frames, tag+"begin "+strconv.Itoa(seq))
	for _, line := range crt {
		frames = append(frames, tag+"crt "+line)
	}
	for _, line := range key {
		frames = append(frames, tag+"key "+line)
	}
	frames = append(frames, fmt.Sprintf("%send %d %d %d %s", tag, seq, len(crt), len(key), hex.EncodeToString(sum.Sum(nil))))
	return frames
}

// credWatcher notices Diego's rewrite of the identity pair and pushes the new
// pair to the guest. It pushes a pair again when the guest reports a failure
// or stays silent, a limited number of times.
type credWatcher struct {
	certPath, keyPath string
	interval          time.Duration
	push              func(*instanceIdentity) error
	logger            *log.Logger
	now               func() time.Time
	ackTimeout        time.Duration

	mu       sync.Mutex
	seen     fileStamp
	content  *instanceIdentity
	seq      int
	pending  bool
	failed   bool
	sentAt   time.Time
	attempts int
	refused  fileStamp
}

// newCredWatcher returns a watcher for the pair at certPath and keyPath. sent
// is the pair that the guest already holds, or nil. Every interval the
// watcher stats both files, and when they differ from the last pair pushed it
// reads them and calls push with the new pair.
func newCredWatcher(certPath, keyPath string, sent *instanceIdentity, interval time.Duration, push func(*instanceIdentity) error, logger *log.Logger) *credWatcher {
	w := &credWatcher{
		certPath: certPath, keyPath: keyPath,
		interval: interval, push: push, logger: logger,
		now: time.Now, ackTimeout: credAckTimeout,
		content: sent,
	}
	if sent != nil {
		w.seen = sent.stamp
	}
	return w
}

// run watches until stop closes.
func (w *credWatcher) run(stop <-chan struct{}) {
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

// acked records the guest's answer to push number seq. An answer to an older
// push does not count.
func (w *credWatcher) acked(seq int, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.pending || seq != w.seq {
		return
	}
	if ok {
		w.pending = false
		w.logger.Printf("the guest installed instance identity push %d", seq)
		return
	}
	w.failed = true
	w.logger.Printf("the guest refused instance identity push %d", seq)
}

// tick does one pass of the watch.
func (w *credWatcher) tick() {
	w.mu.Lock()
	defer w.mu.Unlock()

	stamp, ok := statIdentity(w.certPath, w.keyPath)
	if !ok {
		return
	}
	if stamp != w.seen {
		if stamp == w.refused {
			return
		}
		id, err := readInstanceIdentity(w.certPath, w.keyPath)
		if err != nil {
			// Diego renames the key and then the certificate, so a pair that
			// does not match yet is expected. We look again on the next tick,
			// and say so once for each state of the files.
			w.refused = stamp
			w.logger.Printf("waiting for a matching instance identity pair: %v", err)
			return
		}
		if id == nil {
			return
		}
		w.refused = fileStamp{}
		w.seen = id.stamp
		if w.content != nil && bytes.Equal(w.content.cert, id.cert) && bytes.Equal(w.content.key, id.key) {
			return
		}
		w.content = id
		w.seq++
		w.attempts = 0
		w.send()
		return
	}
	if w.pending && (w.failed || w.now().Sub(w.sentAt) >= w.ackTimeout) {
		if w.attempts > credMaxResends {
			w.pending = false
			w.logger.Printf("giving up on instance identity push %d after %d tries; waiting for the next change", w.seq, w.attempts)
			return
		}
		w.send()
	}
}

// send pushes the current pair. The caller holds the lock.
func (w *credWatcher) send() {
	w.attempts++
	w.pending = true
	w.failed = false
	w.sentAt = w.now()
	if err := w.push(w.content); err != nil {
		w.failed = true
		w.logger.Printf("pushing instance identity %d (serial %s, try %d): %v", w.seq, w.content.serial, w.attempts, err)
		return
	}
	w.logger.Printf("pushed instance identity %d (serial %s, expires %s, try %d)", w.seq, w.content.serial, w.content.notAfter.UTC().Format(time.RFC3339), w.attempts)
}
