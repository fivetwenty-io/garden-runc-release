//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// dialPolicy says how the proxy reaches the guest. vm-launch listens only
// while the guest app does (see portGate), but the guest's report of that
// lags by up to a second, so a connection that arrives as the guest app
// restarts its listener waits for it instead of failing: the proxy retries
// the upstream dial with exponential backoff until giveUp has passed since
// the client connected.
type dialPolicy struct {
	attemptTimeout time.Duration
	firstBackoff   time.Duration
	maxBackoff     time.Duration
	giveUp         time.Duration
}

// upstreamDialPolicy gives up 2 seconds after the client connected. The
// proxy listens only once the guest app does, so it never sees a guest boot,
// and a dial that the guest refuses means the guest app has closed its
// listener. That is an app that restarts its listener, which 2 seconds
// covers, or an app that stopped listening, whose port the gate closes at the
// guest's next look, within a second. Either way, a client of an app that
// stopped listening learns it within 2 seconds, so the gorouter can try
// another instance. attemptTimeout bounds a dial that gets no answer.
var upstreamDialPolicy = dialPolicy{
	attemptTimeout: time.Second,
	firstBackoff:   25 * time.Millisecond,
	maxBackoff:     500 * time.Millisecond,
	giveUp:         2 * time.Second,
}

// tcpProxy carries TCP connections from a listener in the container to the
// guest, one pair of goroutines per connection. The listener can open and
// close any number of times (see Listen and StopListening); connections
// outlive the listener that accepted them. Each direction is copied
// until EOF and then half-closed, so either side can finish sending while it
// still reads. Copy errors such as a peer reset end that connection only and
// are not logged: they are how TCP connections normally end.
type tcpProxy struct {
	upstream string
	policy   dialPolicy
	logger   *log.Logger
	dialer   net.Dialer

	// ctx is cancelled by Close, which aborts upstream dials and backoff waits.
	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	listener net.Listener
	stopped  bool
	closed   bool
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
}

// errProxyStopped reports a Listen after StopAccepting or Close.
var errProxyStopped = errors.New("the port proxy has stopped accepting connections")

// newProxy returns a proxy for upstream that does not listen yet.
func newProxy(upstream string, policy dialPolicy, logger *log.Logger) *tcpProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &tcpProxy{
		upstream: upstream,
		policy:   policy,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
		conns:    map[net.Conn]struct{}{},
	}
}

// startProxy returns a proxy for upstream that listens on listenAddr.
func startProxy(listenAddr, upstream string, policy dialPolicy, logger *log.Logger) (*tcpProxy, error) {
	p := newProxy(upstream, policy, logger)
	if err := p.Listen(listenAddr); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// Listen listens on listenAddr and accepts connections there until
// StopListening, StopAccepting, or Close. It fails while the proxy already
// listens, and with errProxyStopped after StopAccepting or Close. The
// listener is bound when it returns.
func (p *tcpProxy) Listen(listenAddr string) error {
	p.mu.Lock()
	busy, stopped := p.listener != nil, p.stopped
	p.mu.Unlock()
	switch {
	case stopped:
		return errProxyStopped
	case busy:
		return errors.New("the port proxy is already listening")
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listening for the guest port: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case p.stopped:
		ln.Close()
		return errProxyStopped
	case p.listener != nil:
		ln.Close()
		return errors.New("the port proxy is already listening")
	}
	p.listener = ln
	p.wg.Add(1)
	go p.acceptLoop(ln)
	return nil
}

// Addr is the address of the open listener, or nil when there is none.
func (p *tcpProxy) Addr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return nil
	}
	return p.listener.Addr()
}

// StopListening closes the listener, if there is one, so new connections
// are refused, and leaves established ones running. Listen may open a new
// listener afterwards.
func (p *tcpProxy) StopListening() {
	p.mu.Lock()
	ln := p.listener
	p.listener = nil
	p.mu.Unlock()
	if ln == nil {
		return
	}
	if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		p.logger.Printf("closing the port listener: %v", err)
	}
}

// StopAccepting closes the listener for good: new connections are refused
// from then on, and established ones keep running.
func (p *tcpProxy) StopAccepting() {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
	p.StopListening()
}

// Close stops accepting, closes every connection, and returns once all
// proxy goroutines have ended. It is safe to call more than once.
func (p *tcpProxy) Close() {
	p.StopAccepting()
	p.cancel()
	p.mu.Lock()
	p.closed = true
	for c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
}

// track registers c so that Close can close it, and counts its handler. It
// reports false once Close has begun, and the caller then closes c itself.
func (p *tcpProxy) track(c net.Conn, handler bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.conns[c] = struct{}{}
	if handler {
		p.wg.Add(1)
	}
	return true
}

func (p *tcpProxy) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
	c.Close()
}

func (p *tcpProxy) acceptLoop(ln net.Listener) {
	defer p.wg.Done()
	backoff := time.Duration(0)
	for {
		c, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			// Out of file descriptors or a connection aborted before
			// accept: wait and try again, as net/http does.
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff *= 2; backoff > time.Second {
				backoff = time.Second
			}
			p.logger.Printf("accepting a connection on the guest port: %v; retrying in %v", err, backoff)
			if !p.sleep(backoff) {
				return
			}
			continue
		}
		backoff = 0
		if !p.track(c, true) {
			c.Close()
			return
		}
		go p.handle(c)
	}
}

func (p *tcpProxy) handle(client net.Conn) {
	defer p.wg.Done()
	defer p.untrack(client)

	upstream, err := p.dialUpstream()
	if err != nil {
		if p.ctx.Err() == nil {
			p.logger.Printf("connection from %v: giving up on the guest at %s: %v", client.RemoteAddr(), p.upstream, err)
		}
		return
	}
	if !p.track(upstream, false) {
		upstream.Close()
		return
	}
	defer p.untrack(upstream)

	done := make(chan struct{})
	go func() {
		defer close(done)
		copyHalf(upstream, client)
	}()
	copyHalf(client, upstream)
	<-done
}

// dialUpstream connects to the guest, retrying under the dial policy. It
// fails with the last dial error once the policy gives up, or with the
// context error after Close.
func (p *tcpProxy) dialUpstream() (net.Conn, error) {
	deadline := time.Now().Add(p.policy.giveUp)
	backoff := p.policy.firstBackoff
	for {
		attempt, cancel := context.WithTimeout(p.ctx, p.policy.attemptTimeout)
		c, err := p.dialer.DialContext(attempt, "tcp", p.upstream)
		cancel()
		if err == nil {
			return c, nil
		}
		if p.ctx.Err() != nil {
			return nil, p.ctx.Err()
		}
		if time.Until(deadline) < backoff {
			return nil, err
		}
		if !p.sleep(backoff) {
			return nil, p.ctx.Err()
		}
		if backoff *= 2; backoff > p.policy.maxBackoff {
			backoff = p.policy.maxBackoff
		}
	}
}

// sleep waits for d and reports false if Close came first.
func (p *tcpProxy) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-p.ctx.Done():
		return false
	}
}

type closeWriter interface{ CloseWrite() error }

// copyHalf copies src to dst. At EOF from src it half-closes dst, so dst's
// peer sees EOF and can still send the other way. On an error it closes both
// connections, which also ends the copy in the other direction.
func copyHalf(dst, src net.Conn) {
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		src.Close()
		return
	}
	if cw, ok := dst.(closeWriter); ok {
		if err := cw.CloseWrite(); err == nil {
			return
		}
	}
	dst.Close()
	src.Close()
}
