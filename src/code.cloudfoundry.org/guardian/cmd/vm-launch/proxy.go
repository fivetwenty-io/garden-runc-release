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
	"syscall"
	"time"
)

// dialPolicy says how the proxy reaches the guest. vm-launch listens only
// while the guest app does (see portGate), but the guest's report of that
// lags by up to a second, so a connection that arrives as the guest app
// restarts its listener waits for it instead of failing: the proxy retries
// the upstream dial with exponential backoff until giveUp has passed since
// the client connected, or unansweredGiveUp when the last dial got no answer
// within attemptTimeout.
type dialPolicy struct {
	attemptTimeout   time.Duration
	firstBackoff     time.Duration
	maxBackoff       time.Duration
	giveUp           time.Duration
	unansweredGiveUp time.Duration
}

// upstreamDialPolicy gives up on a guest that refuses the dial 2 seconds
// after the client connected, and on a guest that does not answer it after
// 5 seconds. The proxy listens only once the guest app does, so it never
// sees a guest boot, and a dial that the guest refuses means the guest app
// has closed its listener. That is an app that restarts its listener, which
// 2 seconds covers, or an app that stopped listening, whose port the gate
// closes at the guest's next look, within a second. Either way, a client of
// an app that stopped listening learns it within 2 seconds, so the gorouter
// can try another instance for a request that it retries.
//
// A dial that gets no answer within attemptTimeout means a guest app whose
// accept queue is full, or a guest too busy to answer, and the app may
// still serve. A runc app in that state would hold the gorouter's dial
// through SYN retransmits for the gorouter's endpoint dial timeout, 5
// seconds by default. The proxy has already accepted the gorouter's
// connection, so that timeout no longer applies, and the proxy waits about
// as long in its place.
//
// The wait matches, but what follows it does not. The proxy checks its
// budget after a dial has ended, and counts the wait before the next dial,
// so when every dial goes unanswered it gives up about 5.4 seconds after
// the client connected, and never later than the budget plus attemptTimeout,
// which is 6 seconds. A runc app whose dial timed out would give the
// gorouter a dial error, which the gorouter can retry on another instance
// whatever the request's method. When the proxy gives up, the gorouter has
// already connected and sent its request, so it sees the connection close,
// and it is likely to retry that only for an idempotent request. The same
// holds for the 2 second give-up on a refused dial.
var upstreamDialPolicy = dialPolicy{
	attemptTimeout:   time.Second,
	firstBackoff:     25 * time.Millisecond,
	maxBackoff:       500 * time.Millisecond,
	giveUp:           2 * time.Second,
	unansweredGiveUp: 5 * time.Second,
}

// tcpProxy carries TCP connections from listeners in the container to the
// guest, one pair of goroutines per connection. Each listener has its own
// guest address, and it can open and close any number of times (see Listen
// and StopListening) without touching the others; connections outlive the
// listener that accepted them. Each direction is copied
// until EOF and then half-closed, so either side can finish sending while it
// still reads. Copy errors such as a peer reset end that connection only and
// are not logged: they are how TCP connections normally end.
//
// A transparent proxy (see withTransparentDial) dials the guest from the
// address of each client that transparentSource accepts, so the guest sees
// that address as the connection's peer. Every other client, loopback ones
// among them, is dialled from the container's tap address as before.
type tcpProxy struct {
	policy dialPolicy
	logger *log.Logger
	dialer net.Dialer

	// transparent is set by withTransparentDial, and control is the socket
	// option hook its dials run before they bind.
	transparent bool
	control     func(network, address string, c syscall.RawConn) error

	// ctx is cancelled by Close, which aborts upstream dials and backoff waits.
	ctx    context.Context
	cancel context.CancelFunc

	mu sync.Mutex
	// listeners are the open listeners by the address they listen on.
	listeners map[string]net.Listener
	stopped   bool
	closed    bool
	conns     map[net.Conn]struct{}
	wg        sync.WaitGroup
}

// errProxyStopped reports a Listen after StopAccepting or Close.
var errProxyStopped = errors.New("the port proxy has stopped accepting connections")

// proxyOption changes how a proxy that newProxy returns dials the guest.
type proxyOption func(*tcpProxy)

// withTransparentDial makes the proxy dial the guest from its clients'
// addresses, setting IP_TRANSPARENT on each such socket through
// setTransparent, which takes CAP_NET_RAW. Garden routes the guest's replies
// to these sockets (see the netplugin package's FirecrackerReplyRouting).
func withTransparentDial() proxyOption {
	return func(p *tcpProxy) {
		p.transparent = true
		p.control = setTransparent
	}
}

// newProxy returns a proxy that does not listen yet.
func newProxy(policy dialPolicy, logger *log.Logger, opts ...proxyOption) *tcpProxy {
	ctx, cancel := context.WithCancel(context.Background())
	p := &tcpProxy{
		policy:    policy,
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
		listeners: map[string]net.Listener{},
		conns:     map[net.Conn]struct{}{},
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Listen listens on listenAddr and carries the connections it accepts to
// upstream, until StopListening, StopAccepting, or Close. It fails while the
// proxy already listens on listenAddr, and with errProxyStopped after
// StopAccepting or Close. The listener is bound when it returns.
func (p *tcpProxy) Listen(listenAddr, upstream string) error {
	p.mu.Lock()
	_, busy := p.listeners[listenAddr]
	stopped := p.stopped
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
	if p.stopped {
		ln.Close()
		return errProxyStopped
	}
	if _, busy := p.listeners[listenAddr]; busy {
		ln.Close()
		return errors.New("the port proxy is already listening")
	}
	p.listeners[listenAddr] = ln
	p.wg.Add(1)
	go p.acceptLoop(ln, upstream)
	return nil
}

// StopListening closes the listener on listenAddr, if there is one, so new
// connections to it are refused, and leaves established ones running. Listen
// may open a new listener afterwards.
func (p *tcpProxy) StopListening(listenAddr string) {
	p.mu.Lock()
	ln := p.listeners[listenAddr]
	delete(p.listeners, listenAddr)
	p.mu.Unlock()
	p.closeListener(ln)
}

func (p *tcpProxy) closeListener(ln net.Listener) {
	if ln == nil {
		return
	}
	if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		p.logger.Printf("closing the port listener: %v", err)
	}
}

// StopAccepting closes every listener for good: new connections are refused
// from then on, and established ones keep running.
func (p *tcpProxy) StopAccepting() {
	p.mu.Lock()
	p.stopped = true
	open := p.listeners
	p.listeners = map[string]net.Listener{}
	p.mu.Unlock()
	for _, ln := range open {
		p.closeListener(ln)
	}
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

func (p *tcpProxy) acceptLoop(ln net.Listener, upstream string) {
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
		go p.handle(c, upstream)
	}
}

func (p *tcpProxy) handle(client net.Conn, upstreamAddr string) {
	defer p.wg.Done()
	defer p.untrack(client)

	var source *net.TCPAddr
	if p.transparent {
		source = transparentSource(client.RemoteAddr())
	}
	upstream, err := p.dialUpstream(upstreamAddr, source)
	if err != nil {
		if p.ctx.Err() == nil {
			p.logger.Printf("connection from %v: giving up on the guest at %s: %v", client.RemoteAddr(), upstreamAddr, err)
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

// dialUpstream connects to the guest at addr, retrying under the dial policy. It
// fails with the last dial error once the policy gives up, or with the
// context error after Close. A non-nil source makes each dial a transparent
// one from that address, and a failure to make the socket transparent ends
// the dial at once, because no retry would let it succeed and a plain dial
// would show the guest the wrong peer.
func (p *tcpProxy) dialUpstream(addr string, source *net.TCPAddr) (net.Conn, error) {
	dialer, network := p.dialer, "tcp"
	if source != nil {
		dialer.LocalAddr = source
		dialer.Control = p.control
		network = "tcp4"
	}
	began := time.Now()
	backoff := p.policy.firstBackoff
	for {
		attempt, cancel := context.WithTimeout(p.ctx, p.policy.attemptTimeout)
		c, err := dialer.DialContext(attempt, network, addr)
		cancel()
		if err == nil {
			return c, nil
		}
		if p.ctx.Err() != nil {
			return nil, p.ctx.Err()
		}
		var transparentErr *transparentError
		if errors.As(err, &transparentErr) {
			return nil, err
		}
		budget := p.policy.giveUp
		if isUnanswered(err) {
			budget = p.policy.unansweredGiveUp
		}
		if time.Since(began)+backoff > budget {
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

// isUnanswered reports whether err, from a dial, means that the dial got
// no answer before its timeout.
func isUnanswered(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
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
