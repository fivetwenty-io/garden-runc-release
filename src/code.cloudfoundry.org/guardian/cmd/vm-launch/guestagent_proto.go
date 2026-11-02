//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// The guest agent runs a cf ssh session or a port forward in the guest for
// a client in the container. The client is the shim, which diego-sshd runs
// as the user's shell (see guestagent_shim.go), and it reaches the agent
// through vm-launch's agent relay (see guestagent_host.go), which dials the
// agent over vsock and authenticates the connection. The agent itself is
// vm-launch's own binary, which stage 2 starts as root in the guest (see
// guestagent.go).
const (
	// agentPort is the vsock port the agent listens on in the guest. It is
	// below 1024, so a guest process without CAP_NET_BIND_SERVICE, which
	// the app never has, cannot take it over if the agent stops.
	agentPort = 22

	// agentSocketPath is where vm-launch's agent relay listens in the
	// container, beside the sidecar relay hub's socket.
	agentSocketPath = "/tmp/vm-launch-agent.sock"

	// agentKeyBytes is how many random bytes the boot's agent key has. The
	// key travels as hex, so the hello frame carries twice as many.
	agentKeyBytes = 32

	// agentHelloTimeout bounds how long a connection may take to send its
	// hello and its request, on the agent and on the relay alike, so a
	// client that sends nothing holds no slot for long.
	agentHelloTimeout = 5 * time.Second

	// agentMaxData is the most bytes one data frame carries.
	agentMaxData = 32 << 10

	// agentMaxRequest is the most bytes the request frame carries. The
	// request holds the session's environment, which can be large.
	agentMaxRequest = 1 << 20

	// agentMaxHello is the most bytes a hello frame may claim, which is far
	// more than a key, so that the agent reads no more than this from a
	// connection it has not authenticated.
	agentMaxHello = 128
)

// The frame types. Every type byte is above 0x80, so a text line that
// reaches the agent or a client by mistake is never taken for a frame.
const (
	agentFrameHello     byte = 0x81 // relay to agent: the boot's key
	agentFrameRequest   byte = 0x82 // client to agent: an agentRequest
	agentFrameReady     byte = 0x83 // agent to client: an agentReady
	agentFrameStdin     byte = 0x84 // client to agent: input bytes
	agentFrameStdinEnd  byte = 0x85 // client to agent: the end of the input
	agentFrameSignal    byte = 0x86 // client to agent: one signal number
	agentFrameResize    byte = 0x87 // client to agent: rows and columns, two bytes each
	agentFrameStdout    byte = 0x88 // agent to client: output bytes
	agentFrameStderr    byte = 0x89 // agent to client: error output bytes
	agentFrameExit      byte = 0x8a // agent to client: an agentExit
	agentFrameData      byte = 0x8b // both ways in a forward: bytes
	agentFrameDataEnd   byte = 0x8c // both ways in a forward: the end of the bytes
	agentFrameAccepted  byte = 0x8d // agent to relay: the request is accepted
	agentFrameGo        byte = 0x8e // relay to agent: start what was accepted
	agentFrameHeaderLen      = 5
)

// The kinds of request.
const (
	agentKindSession = "session"
	agentKindForward = "forward"
)

// agentRequest is what a client asks the agent for. A session runs the
// guest's shell with Args, the arguments diego-sshd gave the shim, in Env
// laid under the app's environment, on a terminal of Rows and Cols when TTY
// is set. A forward connects to Host and Port in the guest.
type agentRequest struct {
	Kind string   `json:"kind"`
	Args []string `json:"args,omitempty"`
	Env  []string `json:"env,omitempty"`
	TTY  bool     `json:"tty,omitempty"`
	Rows uint16   `json:"rows,omitempty"`
	Cols uint16   `json:"cols,omitempty"`
	Host string   `json:"host,omitempty"`
	Port int      `json:"port,omitempty"`
}

// agentReady answers a request. Error is empty when the session or forward
// started, and otherwise says why it did not.
type agentReady struct {
	Error string `json:"error,omitempty"`
}

// agentExit is how a session's process ended: with Code, or, when Signal is
// set, killed by that signal.
type agentExit struct {
	Code   int `json:"code"`
	Signal int `json:"signal,omitempty"`
}

// errAgentFrameTooLarge is a frame longer than its type allows.
var errAgentFrameTooLarge = errors.New("the guest agent frame is larger than its type allows")

// agentFrameLimit is the most payload bytes a frame of type typ may carry,
// or -1 for a type that is not a frame.
func agentFrameLimit(typ byte) int {
	switch typ {
	case agentFrameHello:
		return agentMaxHello
	case agentFrameRequest, agentFrameReady, agentFrameExit:
		return agentMaxRequest
	case agentFrameStdin, agentFrameStdout, agentFrameStderr, agentFrameData:
		return agentMaxData
	case agentFrameSignal:
		return 1
	case agentFrameResize:
		return 4
	case agentFrameStdinEnd, agentFrameDataEnd, agentFrameAccepted, agentFrameGo:
		return 0
	default:
		return -1
	}
}

// readAgentFrame reads one frame from r. It refuses an unknown type and a
// length over the type's limit before it reads the payload, so a peer can
// never make it allocate more than agentMaxRequest bytes.
func readAgentFrame(r io.Reader) (byte, []byte, error) {
	var header [agentFrameHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	typ, size := header[0], binary.BigEndian.Uint32(header[1:])
	limit := agentFrameLimit(typ)
	if limit < 0 {
		return 0, nil, fmt.Errorf("the guest agent got a frame of unknown type 0x%02x", typ)
	}
	if size > uint32(limit) {
		return 0, nil, fmt.Errorf("%w: type 0x%02x, %d bytes", errAgentFrameTooLarge, typ, size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
}

// agentFrameWriter writes whole frames to one connection. Several
// goroutines write to it at once, the output pumps and the exit, so each
// frame goes out under the lock in one write.
type agentFrameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (fw *agentFrameWriter) write(typ byte, payload []byte) error {
	if len(payload) > agentFrameLimit(typ) {
		return fmt.Errorf("%w: type 0x%02x, %d bytes", errAgentFrameTooLarge, typ, len(payload))
	}
	buf := make([]byte, agentFrameHeaderLen+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:], uint32(len(payload)))
	copy(buf[agentFrameHeaderLen:], payload)
	fw.mu.Lock()
	defer fw.mu.Unlock()
	_, err := fw.w.Write(buf)
	return err
}

// writeJSON writes v as the payload of one frame.
func (fw *agentFrameWriter) writeJSON(typ byte, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return fw.write(typ, payload)
}

// writeData writes b as frames of type typ, splitting it at agentMaxData.
func (fw *agentFrameWriter) writeData(typ byte, b []byte) error {
	for len(b) > 0 {
		n := min(len(b), agentMaxData)
		if err := fw.write(typ, b[:n]); err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// agentConn is a connection the agent, the relay, or the shim reads frames
// from with a deadline: an accepted vsock socket, a Unix socket, or, in the
// specs, a pipe.
type agentConn interface {
	io.ReadWriteCloser
	SetReadDeadline(t time.Time) error
}

// halfCloser is a connection whose write side can end on its own, so a
// forward can pass on the end of one direction while the other still runs.
type halfCloser interface {
	CloseWrite() error
}
