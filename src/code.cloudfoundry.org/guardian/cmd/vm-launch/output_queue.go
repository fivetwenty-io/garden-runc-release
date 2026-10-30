//go:build linux

package main

import (
	"io"
	"log"
	"sync"
	"time"
)

// guestOutputLimit bounds the guest command's output that waits for stdout.
// It is far more than a reader that keeps up ever leaves waiting, and small
// next to the memory the container keeps for vm-launch (see
// guestMemoryReserveMiB).
const guestOutputLimit = 1 << 20

// outputFlushTimeout bounds how long vm-launch waits, once the hypervisor has
// exited, for stdout to take the output still waiting for it. It fits in the
// time Diego leaves after the stop deadline (see stopDeadline).
const outputFlushTimeout = time.Second

// outputQueue passes the guest command's output to stdout from a goroutine
// of its own, so a slow reader of stdout never holds up the guest console.
// Firecracker drops a console byte that it cannot write at once, and the
// listen, OOM, and exit lines share the console with the output, so the
// console has to be read as fast as the guest writes it, whatever stdout
// does.
//
// Write never blocks and never fails. Output that would take more than limit
// bytes waiting is dropped, whole writes at a time, and the queue logs one
// line with the count of bytes dropped once stdout has caught up. The limit
// counts what waits, apart from the one write that stdout has in hand. The serial
// filter takes the control lines out before it writes to the queue, so the
// queue only ever drops the command's output. After the first failed write
// to stdout, the queue drops everything without counting it, and err
// returns that failure.
type outputQueue struct {
	w      io.Writer
	limit  int
	logger *log.Logger

	mu sync.Mutex
	// buf is the output waiting for stdout.
	buf []byte
	// dropped counts the bytes dropped since the last line about them.
	dropped int
	closed  bool
	// abandoned is set when close gave up on stdout, after which the queue
	// writes and logs nothing more.
	abandoned bool
	writeErr  error

	// ready holds a token while there is something for the loop to do.
	ready chan struct{}
	done  chan struct{}
}

// newOutputQueue returns a running queue that writes to w and keeps at most
// limit bytes waiting.
func newOutputQueue(w io.Writer, limit int, logger *log.Logger) *outputQueue {
	q := &outputQueue{
		w:      w,
		limit:  limit,
		logger: logger,
		ready:  make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
	go q.loop()
	return q
}

func (q *outputQueue) Write(p []byte) (int, error) {
	q.mu.Lock()
	switch {
	case q.closed || q.writeErr != nil:
	case len(q.buf)+len(p) > q.limit:
		q.dropped += len(p)
	default:
		q.buf = append(q.buf, p...)
	}
	q.mu.Unlock()
	q.wake()
	return len(p), nil
}

// wake hands the loop a token unless it already holds one.
func (q *outputQueue) wake() {
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

func (q *outputQueue) loop() {
	defer close(q.done)
	var spare []byte
	for {
		<-q.ready
		for {
			q.mu.Lock()
			if q.abandoned {
				q.mu.Unlock()
				return
			}
			chunk := q.buf
			q.buf = spare[:0]
			dropped := q.dropped
			q.dropped = 0
			closed, failed := q.closed, q.writeErr != nil
			q.mu.Unlock()
			if len(chunk) > 0 && !failed {
				if _, err := q.w.Write(chunk); err != nil {
					q.mu.Lock()
					q.writeErr = err
					q.mu.Unlock()
				}
			}
			spare = chunk
			if dropped > 0 {
				q.logDropped(dropped)
			}
			if len(chunk) == 0 && dropped == 0 {
				if closed {
					return
				}
				break
			}
		}
	}
}

// logDropped logs the bytes dropped since the last such line, unless close
// has given up on stdout and logged them itself, or stdout has failed, which
// the caller of err reports.
func (q *outputQueue) logDropped(n int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.abandoned && q.writeErr == nil {
		q.logger.Printf("stdout did not keep up with the guest; dropped %d bytes of the guest command's output", n)
	}
}

// close waits up to timeout for stdout to take the output waiting for it,
// and then stops the queue. Output that stdout has not taken by then is
// dropped, and logged as dropped. Writes after close are dropped.
func (q *outputQueue) close(timeout time.Duration) {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.wake()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-q.done:
		return
	case <-timer.C:
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	select {
	case <-q.done:
		return
	default:
	}
	q.abandoned = true
	if n := len(q.buf) + q.dropped; n > 0 && q.writeErr == nil {
		q.logger.Printf("stdout did not take the guest's last output within %v; dropped %d bytes of the guest command's output", timeout, n)
	}
	q.buf, q.dropped = nil, 0
}

// err returns the first failed write to stdout.
func (q *outputQueue) err() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.writeErr
}
