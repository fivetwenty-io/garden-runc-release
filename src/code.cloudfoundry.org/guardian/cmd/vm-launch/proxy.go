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

// dialPolicy says how the proxy reaches the guest. The listener is up before
// the guest has booted, so a connection that arrives early waits for the
// guest app instead of failing: the proxy retries the upstream dial with
// exponential backoff until giveUp has passed since the client connected.
type dialPolicy struct {
	attemptTimeout time.Duration
	firstBackoff   time.Duration
	maxBackoff     time.Duration
	giveUp         time.Duration
}

// upstreamDialPolicy covers a guest boot of a few seconds with room to spare.
// attemptTimeout cuts short a dial that waits on ARP while eth0 is still down.
var upstreamDialPolicy = dialPolicy{
	attemptTimeout: time.Second,
	firstBackoff:   25 * time.Millisecond,
	maxBackoff:     500 * time.Millisecond,
	giveUp:         30 * time.Second,
}

// tcpProxy carries TCP connections from a listener in the container to the
// guest, one pair of goroutines per connection. Each direction is copied
// until EOF and then half-closed, so either side can finish sending while it
// still reads. Copy errors such as a peer reset end that connection only and
// are not logged: they are how TCP connections normally end.
type tcpProxy struct {
	listener net.Listener
	upstream string
	policy   dialPolicy
	logger   *log.Logger
	dialer   net.Dialer

	// ctx is cancelled by Close, which aborts upstream dials and backoff waits.
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup

	stopOnce sync.Once
}

// startProxy listens on listenAddr and starts accepting connections for
// upstream. The listener is bound when it returns.
func startProxy(listenAddr, upstream string, policy dialPolicy, logger *log.Logger) (*tcpProxy, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listening for the guest port: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &tcpProxy{
		listener: ln,
		upstream: upstream,
		policy:   policy,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
		conns:    map[net.Conn]struct{}{},
	}
	p.wg.Add(1)
	go p.acceptLoop()
	return p, nil
}

// Addr is the bound listener address.
func (p *tcpProxy) Addr() net.Addr { return p.listener.Addr() }

// StopAccepting closes the listener, so new connections are refused, and
// leaves established ones running.
func (p *tcpProxy) StopAccepting() {
	p.stopOnce.Do(func() {
		if err := p.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			p.logger.Printf("closing the port listener: %v", err)
		}
	})
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

func (p *tcpProxy) acceptLoop() {
	defer p.wg.Done()
	backoff := time.Duration(0)
	for {
		c, err := p.listener.Accept()
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
