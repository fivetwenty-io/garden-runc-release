//go:build linux

package main

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// realAgentAppPort is the port the agent guest's app listens on, which the
// guest's network does not declare, so only the agent's forward reaches it.
const realAgentAppPort = "9999"

// realAgentApp is the launcher of the agent guest, a static program that
// listens on realAgentAppPort on the guest's loopback. For each connection
// it reads until the client ends its direction and answers with what it
// read. It runs until a stop's SIGTERM.
const realAgentApp = `package main

import (
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	ln, err := net.Listen("tcp", "127.0.0.1:` + realAgentAppPort + `")
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				data, _ := io.ReadAll(c)
				c.Write(append([]byte("the guest app got "), data...))
			}()
		}
	}()
	os.Stdout.WriteString("app-listening\n")
	<-sigs
	os.Stdout.WriteString("app-got-term\n")
}
`

// buildRealAgentBinary builds vm-launch itself for the guest, as the agent
// that goes into the initramfs.
func buildRealAgentBinary() string {
	gocmd, err := exec.LookPath("go")
	if err != nil {
		Skip("no go command on PATH to build vm-launch for the guest")
	}
	bin := filepath.Join(GinkgoT().TempDir(), "vm-launch")
	cmd := exec.Command(gocmd, "build", "-trimpath", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOTOOLCHAIN=local")
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "building vm-launch for the guest: %s", out)
	return bin
}

// realAgentShimRun is one shim session against the agent guest.
type realAgentShimRun struct {
	exit           agentExit
	err            error
	stdout, stderr string
}

// realAgentRun is what the client side saw of one boot of the agent guest.
type realAgentRun struct {
	res        runResult
	out        string
	log        string
	identity   realAgentShimRun
	piped      realAgentShimRun
	terminal   realAgentShimRun
	forward    string
	forwardErr error
	wrongKey   error
}

// runRealAgentShim runs one shim session through the relay at socket with
// args and env, with stdin as its input.
func runRealAgentShim(socket string, stdin *os.File, args, env []string) realAgentShimRun {
	stdout, stderr := &safeBuffer{}, &safeBuffer{}
	s := agentShim{socket: socket, wait: agentRelayWait, stdin: stdin, stdout: stdout, stderr: stderr, env: env, signals: make(chan os.Signal)}
	exit, err := s.run(args)
	return realAgentShimRun{exit: exit, err: err, stdout: stdout.String(), stderr: stderr.String()}
}

// forwardThroughRelay asks the relay at socket for a forward to port in the
// guest, trying again while the app does not listen yet, sends payload,
// ends its direction, and returns what came back.
func forwardThroughRelay(socket, port, payload string) (string, error) {
	deadline := time.Now().Add(agentRelayWait)
	for {
		c, err := net.Dial("unix", socket)
		if err != nil {
			return "", err
		}
		if _, err := io.WriteString(c, "forward 127.0.0.1 "+port+"\n"); err != nil {
			c.Close()
			return "", err
		}
		answer, err := readLine(c, agentMaxLine)
		if err != nil {
			c.Close()
			return "", err
		}
		if answer != "ok" {
			c.Close()
			if time.Now().After(deadline) {
				return "", errors.New(answer)
			}
			time.Sleep(time.Second)
			continue
		}
		defer c.Close()
		if _, err := io.WriteString(c, payload); err != nil {
			return "", err
		}
		if err := c.(*net.UnixConn).CloseWrite(); err != nil {
			return "", err
		}
		if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return "", err
		}
		got, err := io.ReadAll(c)
		return string(got), err
	}
}

// helloWithWrongKey connects to the agent at cid directly, as any process
// on the cell can, and sends a hello with another key and a session
// request. It returns how the agent ended the connection.
func helloWithWrongKey(cid uint32) error {
	c, err := dialVsock(cid, agentPort, agentDialTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	fw := &agentFrameWriter{w: c}
	if err := fw.write(agentFrameHello, []byte(strings.Repeat("0", 2*agentKeyBytes))); err != nil {
		return err
	}
	_ = fw.writeJSON(agentFrameRequest, agentRequest{Kind: agentKindSession, Args: []string{"-c", "id"}})
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	_, _, err = readAgentFrame(c)
	return err
}

// superviseRealAgent boots a stack guest with the guest agent under TCG,
// through the supervisor, with the QEMU vsock device that vm-launch
// reserves. Once QEMU runs, it runs three shim sessions, forwards a port
// the guest does not declare, and tries the agent with a wrong key, and
// then stops the guest with SIGTERM.
func superviseRealAgent() realAgentRun {
	art := realArtifacts()
	qemu := realQEMU()
	requireMicrovm(qemu)
	if _, err := os.Stat(vhostVsockDevice); err != nil {
		Skip("the host has no " + vhostVsockDevice + " for the guest agent's vsock device")
	}
	guestAgentBinary = buildRealAgentBinary()
	DeferCleanup(func() { guestAgentBinary = "/proc/self/exe" })
	sd := &stackDrives{stack: realStackImage(art), droplet: realDropletImage(art)}

	app := buildStaticGuestProgram("agentapp", realAgentApp)
	appInfo, err := os.Stat(app)
	Expect(err).NotTo(HaveOccurred())
	lf, err := os.Open(app)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(lf.Close)

	var r realAgentRun
	bootWithRetry(func() bool {
		workDir := GinkgoT().TempDir()
		socket := filepath.Join(workDir, "agent.sock")
		logBuf := &safeBuffer{}
		agent, err := newHostAgent(backend.VMQemu, workDir, socket, log.New(logBuf, "vm-launch: ", 0))
		Expect(err).NotTo(HaveOccurred())
		defer agent.close()
		if agent.off != "" {
			Skip(agent.off)
		}

		g := taskGuest("")
		g.stack = &guestStack{
			launcher: guestTool{name: "launcher", file: lf, size: appInfo.Size()},
			argv:     shellJoin([]string{stackLauncherPath, "/home/vcap/app", "", `{"start_command":"./app","process_type":"web"}`}),
			cwd:      "/home/vcap",
			hostname: "stack-guest-0",
			hosts:    []byte("127.0.0.1 localhost\n"),
		}
		g.drives, err = newGuestDrivesWithStack(backend.VMQemu, nil, nil, sd)
		Expect(err).NotTo(HaveOccurred())
		g.agent, err = agent.guestFiles(g.stack)
		Expect(err).NotTo(HaveOccurred())
		Expect(g.agent.mode).To(Equal(agentModeStack))
		f := newRealInitramfs(g)

		hvFiles, drives, initrdPath, _, rootPath := hypervisorFilesWithStack(nil, withUserspaceMark(f), nil, nil, sd)
		hvArgv, err := hypervisorArgvWithStack(backend.VMQemu, art, workDir, initrdPath, minGuestMemoryMiB, g.nw, drives, rootPath, 0, sd)
		Expect(err).NotTo(HaveOccurred())
		hvFiles, hvArgv, err = agent.hypervisor(backend.VMQemu, workDir, hvFiles, hvArgv)
		Expect(err).NotTo(HaveOccurred())
		consoleLog := filepath.Join(GinkgoT().TempDir(), "console.log")
		cmd := newHypervisorCmd(consoleLogArgv(markedArgv(tcgArgv(qemu, hvArgv)), consoleLog), hvFiles)
		stderr := &safeBuffer{}
		cmd.Stderr = stderr
		out, errOut := &safeBuffer{}, &safeBuffer{}
		console := newBootWriter(realBootMark)
		stopTail := make(chan struct{})
		tailed := tailFile(consoleLog, console, stopTail)

		signals := make(chan os.Signal, 1)
		var qemuProc *os.Process
		running := make(chan struct{})
		sup := supervisor{
			stdout:   out,
			stderr:   errOut,
			logger:   log.New(logBuf, "", 0),
			signals:  signals,
			grace:    killGrace,
			deadline: stopDeadline,
			started: func() {
				qemuProc = cmd.Process
				agent.closeDevice()
				close(running)
			},
		}
		kill := func() {
			select {
			case <-running:
				_ = qemuProc.Kill()
			default:
			}
		}
		exited := make(chan struct{})
		var res runResult
		var runErr error
		go func() {
			defer close(exited)
			res, runErr = sup.run(cmd, testNonce)
		}()

		// The sessions start at once, and the relay waits for the agent
		// while the guest boots, as it does for a cf ssh that comes early.
		var run realAgentRun
		interacted := make(chan struct{})
		go func() {
			defer close(interacted)
			defer func() { signals <- syscall.SIGTERM }()
			empty, err := os.Open(os.DevNull)
			if err != nil {
				run.identity.err = err
				return
			}
			defer empty.Close()
			run.identity = runRealAgentShim(socket, empty, []string{"-c", `id -u; id -g; cat /home/vcap/app/from-the-droplet; pwd; echo "$FROM_SHIM"`}, []string{"FROM_SHIM=from the shim", "PATH=/usr/bin:/bin"})
			piped, err := os.Open(writeTempFile("piped", "piped in\n"))
			if err != nil {
				run.piped.err = err
				return
			}
			defer piped.Close()
			run.piped = runRealAgentShim(socket, piped, []string{"-c", "cat; exit 5"}, nil)
			master, slave, err := openGuestPTY("/dev/ptmx", "/dev/pts", os.Getuid(), os.Getgid())
			if err != nil {
				run.terminal.err = err
				return
			}
			defer master.Close()
			defer slave.Close()
			run.terminal = runRealAgentShim(socket, slave, []string{"-c", "test -t 0 && test -t 1 && echo on-a-terminal"}, []string{"TERM=xterm"})
			run.forward, run.forwardErr = forwardThroughRelay(socket, realAgentAppPort, "through vsock")
			run.wrongKey = helloWithWrongKey(agent.cid)
		}()

		details := func() string {
			return "stderr: " + stderr.String() + "\nconsole: " + console.String() + "\nlog: " + logBuf.String() + "\nout: " + out.String() + "\nerr: " + errOut.String()
		}
		booted := awaitRealGuest(kill, console, exited, details)
		<-exited
		close(stopTail)
		<-tailed
		select {
		case <-interacted:
		case <-time.After(2 * agentRelayWait):
			Fail("the sessions did not end after the guest stopped\n" + details())
		}
		if !booted {
			return false
		}
		Expect(runErr).NotTo(HaveOccurred())
		Expect(console.String()).To(ContainSubstring(realBootMark), "QEMU exited before the guest started userspace\n%s", details())
		GinkgoWriter.Printf("%s\n", details())
		run.res = res
		run.out = strings.ReplaceAll(out.String(), "\r", "")
		run.log = logBuf.String()
		r = run
		return true
	})
	return r
}

var _ = Describe("the guest agent against a real QEMU", func() {
	It("runs cf ssh sessions through the guest agent in the stack guest as the app's user, forwards a port the guest does not declare, and refuses a wrong key", func() {
		r := superviseRealAgent()
		all := "out: " + r.out + "\nlog: " + r.log

		Expect(r.res.markerFound).To(BeTrue(), all)
		Expect(r.out).To(ContainSubstring("app-listening\n"), all)

		// A command runs in the app root as uid 2000, with the droplet,
		// in /home/vcap, and with the shim's environment.
		Expect(r.identity.err).NotTo(HaveOccurred(), all)
		Expect(r.identity.exit).To(Equal(agentExit{Code: 0}), "%+v\n%s", r.identity, all)
		Expect(r.identity.stdout).To(Equal("2000\n2000\ndroplet-file\n/home/vcap\nfrom the shim\n"), "%+v\n%s", r.identity, all)

		// Input reaches the process and its exit code comes back.
		Expect(r.piped.err).NotTo(HaveOccurred(), all)
		Expect(r.piped.exit).To(Equal(agentExit{Code: 5}), "%+v\n%s", r.piped, all)
		Expect(r.piped.stdout).To(Equal("piped in\n"), "%+v\n%s", r.piped, all)

		// A client on a terminal gets a terminal in the guest.
		Expect(r.terminal.err).NotTo(HaveOccurred(), all)
		Expect(r.terminal.exit).To(Equal(agentExit{Code: 0}), "%+v\n%s", r.terminal, all)
		Expect(r.terminal.stdout).To(ContainSubstring("on-a-terminal\r\n"), "%+v\n%s", r.terminal, all)

		// The app's undeclared port is reached through the agent, with the
		// end of each direction passed on.
		Expect(r.forwardErr).NotTo(HaveOccurred(), all)
		Expect(r.forward).To(Equal("the guest app got through vsock"), all)

		// A process that reaches the agent over vsock without the boot's
		// key gets nothing back.
		Expect(r.wrongKey).To(Or(MatchError(io.EOF), MatchError(syscall.ECONNRESET)), all)

		Expect(r.out).To(ContainSubstring("app-got-term\n"), all)
		Expect(r.res.guestStatus).To(Equal(0), all)
	})
})
