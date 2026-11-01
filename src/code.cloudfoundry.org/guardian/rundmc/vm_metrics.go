package rundmc

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"time"
)

// vmMetricsLinePrefix begins every stderr line vm-launch writes for one
// reading of the guest's balloon statistics. cmd/vm-launch writes the line
// and pins the same text in its own specs. The prefix is not "vm-launch: ", so
// the OOM scanner never takes a metrics line for one of vm-launch's messages.
const vmMetricsLinePrefix = "vm-launch-metrics v1 "

const (
	// vmMetricsMaxLine is the longest metrics line the filter holds back. A
	// longer line that begins with the prefix is ordinary output.
	vmMetricsMaxLine = 256

	// vmMetricsStaleAfter is three and a half poll intervals. A sample older
	// than this no longer describes the guest.
	vmMetricsStaleAfter = 35 * time.Second
)

// vmMemorySample is one parsed metrics line, in bytes.
type vmMemorySample struct {
	Used, Total, Available, Free, Caches uint64
}

// parseVMMetricsLine parses one line, without its newline, in the form
//
//	vm-launch-metrics v1 used=N total=N available=N free=N caches=N
//
// and reports false when the line is not in that form or the numbers cannot
// describe a guest, which is a zero total, a field above the total, or a used
// figure that is not the total less the available memory.
func parseVMMetricsLine(line []byte) (vmMemorySample, bool) {
	var s vmMemorySample

	rest, ok := bytes.CutPrefix(line, []byte(vmMetricsLinePrefix))
	if !ok {
		return s, false
	}

	fields := []struct {
		key string
		dst *uint64
	}{
		{"used", &s.Used},
		{"total", &s.Total},
		{"available", &s.Available},
		{"free", &s.Free},
		{"caches", &s.Caches},
	}

	for i, f := range fields {
		var token []byte
		if i < len(fields)-1 {
			var found bool
			token, rest, found = bytes.Cut(rest, []byte(" "))
			if !found {
				return vmMemorySample{}, false
			}
		} else {
			token, rest = rest, nil
		}

		value, ok := bytes.CutPrefix(token, []byte(f.key+"="))
		if !ok {
			return vmMemorySample{}, false
		}

		n, ok := parseDecimal(value)
		if !ok {
			return vmMemorySample{}, false
		}

		*f.dst = n
	}

	if s.Total == 0 ||
		s.Used > s.Total || s.Available > s.Total || s.Free > s.Total || s.Caches > s.Total ||
		s.Used != s.Total-s.Available {
		return vmMemorySample{}, false
	}

	return s, true
}

// parseDecimal reads an unsigned decimal number of at most 19 digits, which
// cannot overflow, and rejects signs, spaces, and an empty string.
func parseDecimal(b []byte) (uint64, bool) {
	if len(b) == 0 || len(b) > 19 {
		return 0, false
	}

	var n uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}

	return n, true
}

// vmMetricsFilter removes the metrics lines from a stream and passes every
// other byte to next unchanged. At the start of a line it holds bytes back
// while they match the prefix, and releases them as soon as one does not. A
// line that matches the whole prefix is held up to vmMetricsMaxLine bytes,
// parsed at its newline, and dropped. A matched line that grows past the
// limit is released and passes through as ordinary output. The filter holds at
// most vmMetricsMaxLine bytes, however long the lines of the stream are.
type vmMetricsFilter struct {
	next     io.Writer
	onSample func(vmMemorySample)
	onBad    func(dropped int)

	mu      sync.Mutex
	held    []byte
	pass    bool // the rest of this line is ordinary output
	dropped int
}

func newVMMetricsFilter(next io.Writer, onSample func(vmMemorySample), onBad func(dropped int)) *vmMetricsFilter {
	return &vmMetricsFilter{next: next, onSample: onSample, onBad: onBad}
}

func (f *vmMetricsFilter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]byte, 0, len(p)+len(f.held))

	for _, b := range p {
		out = f.step(out, b)
	}

	if len(out) == 0 || f.next == nil {
		return len(p), nil
	}

	if _, err := f.next.Write(out); err != nil {
		return 0, err
	}

	return len(p), nil
}

// step consumes one byte and returns out with whatever it released.
func (f *vmMetricsFilter) step(out []byte, b byte) []byte {
	if f.pass {
		if b == '\n' {
			f.pass = false
		}
		return append(out, b)
	}

	if b == '\n' {
		if len(f.held) == 0 {
			return append(out, b)
		}

		if len(f.held) >= len(vmMetricsLinePrefix) {
			f.complete()
			return out
		}

		// A short line that is only the start of the prefix.
		out = append(out, f.held...)
		f.held = f.held[:0]
		return append(out, b)
	}

	if len(f.held) < len(vmMetricsLinePrefix) && b != vmMetricsLinePrefix[len(f.held)] {
		// Off the prefix, so this line is ordinary output.
		out = append(out, f.held...)
		f.held = f.held[:0]
		f.pass = true
		return append(out, b)
	}

	if len(f.held) >= vmMetricsMaxLine {
		// Too long to be a metrics line.
		out = append(out, f.held...)
		f.held = f.held[:0]
		f.pass = true
		return append(out, b)
	}

	f.held = append(f.held, b)
	return out
}

// complete parses the held line and drops it.
func (f *vmMetricsFilter) complete() {
	sample, ok := parseVMMetricsLine(f.held)
	f.held = f.held[:0]

	if ok {
		if f.onSample != nil {
			f.onSample(sample)
		}
		return
	}

	f.dropped++
	if f.onBad != nil {
		f.onBad(f.dropped)
	}
}

// Flush releases anything the filter still holds, so a line cut off by the end
// of the stream reaches next as it would have without the filter.
func (f *vmMetricsFilter) Flush() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	held := f.held
	f.held = nil
	f.pass = false

	if len(held) == 0 || f.next == nil {
		return nil
	}

	if _, err := f.next.Write(held); err != nil {
		return fmt.Errorf("flush held metrics bytes: %w", err)
	}

	return nil
}

// Dropped reports how many matched lines failed to parse.
func (f *vmMetricsFilter) Dropped() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.dropped
}

// vmGuestSample is a stored sample, with the time Garden received it and the
// process it came from.
type vmGuestSample struct {
	vmMemorySample
	received time.Time
	source   any
}

// vmGuestMemory keeps the newest guest memory sample for each container. Its
// zero value is ready to use and reads the wall clock, and a spec sets now to
// control time.
type vmGuestMemory struct {
	now func() time.Time

	mu      sync.Mutex
	samples map[string]vmGuestSample
}

func (m *vmGuestMemory) clock() time.Time {
	if m.now != nil {
		return m.now()
	}

	return time.Now()
}

// Record stores sample as the newest for handle. The source identifies the
// process that wrote it, so that Forget can tell its own sample from a
// successor's.
func (m *vmGuestMemory) Record(handle string, source any, sample vmMemorySample) {
	received := m.clock()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.samples == nil {
		m.samples = map[string]vmGuestSample{}
	}

	m.samples[handle] = vmGuestSample{vmMemorySample: sample, received: received, source: source}
}

// Fresh returns the container's sample when Garden received it less than
// vmMetricsStaleAfter ago.
func (m *vmGuestMemory) Fresh(handle string) (vmMemorySample, bool) {
	now := m.clock()

	m.mu.Lock()
	defer m.mu.Unlock()

	stored, ok := m.samples[handle]
	if !ok || now.Sub(stored.received) >= vmMetricsStaleAfter {
		return vmMemorySample{}, false
	}

	return stored.vmMemorySample, true
}

// Forget removes the container's sample if it came from source.
func (m *vmGuestMemory) Forget(handle string, source any) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if stored, ok := m.samples[handle]; ok && stored.source == source {
		delete(m.samples, handle)
	}
}

// Remove removes the container's sample whatever its source.
func (m *vmGuestMemory) Remove(handle string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.samples, handle)
}
