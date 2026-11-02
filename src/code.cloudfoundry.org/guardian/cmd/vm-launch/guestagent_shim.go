//go:build linux

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The shim is vm-launch as the user's shell in a VM container. Garden binds
// vm-launch over /bin/bash there when the guest agent is on, and diego-sshd
// runs /bin/bash for every cf ssh session and command, so each one reaches
// the shim, which runs it in the guest through the agent relay with the
// same arguments, terminal, signals, and exit status.

// shimFailure is the shim's exit status when the session never ran in the
// guest.
const shimFailure = 1

// shimWait is how long the shim tries to reach the relay, which listens
// once vm-launch has started and well before the guest boots.
const shimWait = 30 * time.Second

// shimSignals are the signals the shim passes to the guest. They are the
// ones diego-sshd can send that a process can catch and that do not report
// a fault in the shim itself.
var shimSignals = []os.Signal{
	syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGABRT,
	syscall.SIGALRM, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2,
}

// isGuestShell reports whether argv0 names the shell that diego-sshd runs,
// which is how vm-launch knows it runs as the shim. A login shell's name
// starts with a hyphen.
func isGuestShell(argv0 string) bool {
	return strings.TrimPrefix(filepath.Base(argv0), "-") == "bash"
}

// agentShim is one run of the shim.
type agentShim struct {
	socket  string
	wait    time.Duration
	stdin   *os.File
	stdout  io.Writer
	stderr  io.Writer
	env     []string
	signals <-chan os.Signal
}

// runGuestShell is vm-launch as the shim, with args, the arguments after
// argv[0]. It exits as the session's process exited, and when a signal
// ended that process, it ends itself with the same signal, so diego-sshd
// reports the signal to the client as it would for a shell in the
// container.
func runGuestShell(args []string) int {
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, append([]os.Signal{syscall.SIGWINCH}, shimSignals...)...)
	s := agentShim{socket: agentSocketPath, wait: shimWait, stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, env: os.Environ(), signals: sigs}
	exit, err := s.run(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vm-launch: %v\n", err)
		return shimFailure
	}
	if exit.Signal != 0 {
		signal.Reset()
		dieOfSignal(syscall.Signal(exit.Signal))
	}
	return exit.Code
}

// dieOfSignal ends the process with sig, whatever the Go runtime would do
// with it, by restoring the signal's default action before it sends the
// signal to itself. A zeroed sigaction is SIG_DFL with no flags and an
// empty mask on every architecture, and 32 bytes covers the kernel's
// structure on each of them. It returns only when the signal's default
// action is to ignore it.
func dieOfSignal(sig syscall.Signal) {
	var action [32]byte
	_, _, _ = unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig), uintptr(unsafe.Pointer(&action)), 0, 8, 0, 0)
	_ = unix.Kill(os.Getpid(), sig)
	time.Sleep(time.Second)
}

// run runs one session and returns how its process ended.
func (s *agentShim) run(args []string) (agentExit, error) {
	conn, err := s.connect()
	if err != nil {
		return agentExit{}, err
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, agentKindSession+"\n"); err != nil {
		return agentExit{}, fmt.Errorf("writing to the guest agent relay: %w", err)
	}
	line, err := readLine(conn, agentMaxLine)
	if err != nil {
		return agentExit{}, fmt.Errorf("reading the guest agent relay's answer: %w", err)
	}
	if line != "ok" {
		return agentExit{}, errors.New(strings.TrimPrefix(line, "error: "))
	}

	req := agentRequest{Kind: agentKindSession, Args: args, Env: s.env}
	tty := isTerminal(s.stdin)
	if tty {
		req.TTY = true
		req.Rows, req.Cols = terminalSize(s.stdin)
		restore, err := makeRaw(s.stdin)
		if err != nil {
			return agentExit{}, err
		}
		defer restore()
	}
	fw := &agentFrameWriter{w: conn}
	if err := fw.writeJSON(agentFrameRequest, req); err != nil {
		return agentExit{}, fmt.Errorf("sending the session to the guest agent: %w", err)
	}
	br := bufio.NewReaderSize(conn, agentMaxData+agentFrameHeaderLen)
	payload, err := readAgentFrameOf(br, agentFrameReady)
	if err != nil {
		return agentExit{}, fmt.Errorf("reading the guest agent's answer: %w", err)
	}
	var ready agentReady
	if err := json.Unmarshal(payload, &ready); err != nil {
		return agentExit{}, fmt.Errorf("decoding the guest agent's answer: %w", err)
	}
	if ready.Error != "" {
		return agentExit{}, errors.New(ready.Error)
	}

	go s.pumpInput(fw)
	go s.passSignals(fw, tty)
	for {
		typ, payload, err := readAgentFrame(br)
		if err != nil {
			return agentExit{}, errors.New("the connection to the guest agent ended before the session's process exited")
		}
		switch typ {
		case agentFrameStdout:
			_, _ = s.stdout.Write(payload)
		case agentFrameStderr:
			_, _ = s.stderr.Write(payload)
		case agentFrameExit:
			var exit agentExit
			if err := json.Unmarshal(payload, &exit); err != nil {
				return agentExit{}, fmt.Errorf("decoding the session's exit: %w", err)
			}
			return exit, nil
		default:
			return agentExit{}, fmt.Errorf("the guest agent sent a frame of type 0x%02x during the session", typ)
		}
	}
}

// connect connects to the relay, trying again until s.wait has passed.
func (s *agentShim) connect() (net.Conn, error) {
	deadline := time.Now().Add(s.wait)
	for {
		conn, err := net.DialTimeout("unix", s.socket, agentDialTimeout)
		if err == nil {
			return conn, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the guest agent relay at %s did not answer within %v: %w", s.socket, s.wait, err)
		}
		time.Sleep(agentDialRetry)
	}
}

// pumpInput sends the shim's input to the session, and its end once it
// ends.
func (s *agentShim) pumpInput(fw *agentFrameWriter) {
	buf := make([]byte, agentMaxData)
	for {
		n, err := s.stdin.Read(buf)
		if n > 0 && fw.write(agentFrameStdin, buf[:n]) != nil {
			return
		}
		if err != nil {
			_ = fw.write(agentFrameStdinEnd, nil)
			return
		}
	}
}

// passSignals sends each signal the shim gets to the session's process,
// and, on a terminal, each new terminal size.
func (s *agentShim) passSignals(fw *agentFrameWriter, tty bool) {
	for sig := range s.signals {
		if sig == syscall.SIGWINCH {
			if tty {
				rows, cols := terminalSize(s.stdin)
				var size [4]byte
				binary.BigEndian.PutUint16(size[0:2], rows)
				binary.BigEndian.PutUint16(size[2:4], cols)
				_ = fw.write(agentFrameResize, size[:])
			}
			continue
		}
		if n, ok := sig.(syscall.Signal); ok {
			_ = fw.write(agentFrameSignal, []byte{byte(n)})
		}
	}
}

// isTerminal reports whether f is a terminal.
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// terminalSize returns the rows and columns of the terminal f, or zeros
// when it has none.
func terminalSize(f *os.File) (rows, cols uint16) {
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0, 0
	}
	return ws.Row, ws.Col
}

// makeRaw puts the terminal f in raw mode, as cfmakeraw does, so that the
// guest's terminal does the line editing and the echo, and returns the
// function that restores the old mode.
func makeRaw(f *os.File) (func(), error) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, fmt.Errorf("reading the terminal's mode: %w", err)
	}
	raw := *old
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return nil, fmt.Errorf("putting the terminal in raw mode: %w", err)
	}
	return func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, old) }, nil
}
