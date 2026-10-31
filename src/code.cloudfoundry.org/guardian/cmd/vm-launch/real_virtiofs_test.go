//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// realShareVirtiofsdRel is where the artifacts directory keeps the wrapper
// that runs the real virtiofsd, as the runtime config installs it.
const realShareVirtiofsdRel = "virtiofsd/virtiofsd-wrapper"

// realShareVirtiofsd returns the path of the real virtiofsd wrapper under the
// artifacts directory that realArtifactsEnv names, or skips the spec when
// that directory holds no executable wrapper, so a host without the real
// virtiofsd runs every other spec.
func realShareVirtiofsd() string {
	art := realArtifacts()
	path := filepath.Join(art, realShareVirtiofsdRel)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		Skip(realArtifactsEnv + " holds no executable " + realShareVirtiofsdRel + ", so there is no real virtiofsd to serve a share")
	}
	return path
}

// realSeccompOnce and realSeccompValue hold the answer of realSeccompMode.
var (
	realSeccompOnce  sync.Once
	realSeccompValue string
)

// realSeccompMode returns the --seccomp mode with which a spec runs the real
// virtiofsd at vfs. It is kill, as vm-launch runs it, wherever virtiofsd can
// load its filter. Where it cannot, as under an x86 emulator on another
// architecture, which has no seccomp for the emulated program, virtiofsd ends
// at once with a panic, and the specs run it with none instead and say so.
// The probe starts virtiofsd with kill and takes an end within the probe time
// for a failure.
func realSeccompMode(vfs string) string {
	realSeccompOnce.Do(func() {
		realSeccompValue = "kill"
		dir, err := os.MkdirTemp("", "rvm-p")
		if err != nil {
			return
		}
		defer os.RemoveAll(dir)
		argv := append(virtiofsdLauncher(vfs), "--socket-path="+filepath.Join(dir, "p.sock"), "--sandbox=none", "--seccomp=kill", "--shared-dir="+dir)
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = []string{}
		if err := cmd.Start(); err != nil {
			return
		}
		ended := make(chan struct{})
		go func() { _ = cmd.Wait(); close(ended) }()
		select {
		case <-ended:
			realSeccompValue = "none"
		case <-time.After(1500 * time.Millisecond):
			_ = cmd.Process.Kill()
			<-ended
		}
	})
	return realSeccompValue
}

// realSeccomp returns realSeccompMode for vfs, and says so in the spec's
// output when the mode is not the one vm-launch runs virtiofsd with.
func realSeccomp(vfs string) string {
	mode := realSeccompMode(vfs)
	if mode != virtiofsdSeccomp {
		GinkgoWriter.Printf("virtiofsd cannot load its seccomp filter on this host, so the spec runs it with --seccomp=%s\n", mode)
	}
	return mode
}

// realVirtiofsdServer serves a directory with the real virtiofsd on a Unix
// socket that it keeps open itself. A real virtiofsd serves one client and
// ends when it leaves, so the server starts a new one on the same listening
// socket whenever one ends before the spec stops it: a boot that the suite
// retries (see bootWithRetry) then finds a virtiofsd waiting, as the first
// one did.
type realVirtiofsdServer struct {
	listener *os.File
	log      safeBuffer

	mu       sync.Mutex
	stopping bool
	current  *os.Process
	done     chan struct{}
}

// serveRealShare starts the real virtiofsd at vfs on a new socket at sock,
// serving dir the way startOne does, with the same arguments and an empty
// environment, and stops it when the spec ends.
func serveRealShare(vfs, sock, dir string) *realVirtiofsdServer {
	GinkgoHelper()
	listener, err := listenShareSocket(sock)
	Expect(err).NotTo(HaveOccurred())
	srv := &realVirtiofsdServer{listener: listener, done: make(chan struct{})}
	DeferCleanup(func() {
		srv.stop(0)
		listener.Close()
	})
	DeferCleanup(func() {
		if CurrentSpecReport().Failed() {
			AddReportEntry("virtiofsd log", srv.log.String())
		}
	})
	argv := virtiofsdArgv(virtiofsdLauncher(vfs), realSeccomp(vfs), dir)
	go func() {
		defer close(srv.done)
		quick := 0
		for {
			srv.mu.Lock()
			if srv.stopping {
				srv.mu.Unlock()
				return
			}
			cmd := exec.Command(argv[0], argv[1:]...)
			cmd.Env = []string{}
			cmd.Dir = "/"
			cmd.Stdout, cmd.Stderr = &srv.log, &srv.log
			cmd.ExtraFiles = []*os.File{listener}
			cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
			if err := cmd.Start(); err != nil {
				srv.log.Write([]byte("starting virtiofsd failed: " + err.Error() + "\n"))
				srv.mu.Unlock()
				return
			}
			srv.current = cmd.Process
			srv.mu.Unlock()
			began := time.Now()
			_ = cmd.Wait()
			// A virtiofsd that ends at once, with no client, is a failure,
			// not a client that left, and starting it again would not help.
			if time.Since(began) < time.Second {
				if quick++; quick == 3 {
					srv.log.Write([]byte("virtiofsd ended three times within a second of its start; not starting it again\n"))
					return
				}
				time.Sleep(200 * time.Millisecond)
			} else {
				quick = 0
			}
		}
	}()
	return srv
}

// stop ends the server. It gives the virtiofsd that serves a client the grace
// to end on its own, which it does once QEMU has gone, and then kills it. It
// returns everything virtiofsd logged.
func (s *realVirtiofsdServer) stop(grace time.Duration) string {
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	select {
	case <-s.done:
	case <-time.After(grace):
		s.mu.Lock()
		if s.current != nil {
			_ = s.current.Kill()
		}
		s.mu.Unlock()
		<-s.done
	}
	return s.log.String()
}

var _ = Describe("a share against a real QEMU and the real virtiofsd", func() {
	const guestDir = "/home/vcap/shared data"

	// bootShare boots a guest with one share of dir, served by the real
	// virtiofsd, that runs command, and returns the console output and
	// the virtiofsd log. The guest has the root image and no other drive.
	bootShare := func(dir, command string) (console, virtiofsdLog string) {
		GinkgoHelper()
		art := realArtifacts()
		vfs := realShareVirtiofsd()
		qemu := realQEMU()
		requireMicrovm(qemu)

		// A Unix socket path is short, so the socket gets a short directory.
		sockDir, err := os.MkdirTemp("", "rvm-s")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { os.RemoveAll(sockDir) })
		tag := shareTag(0)
		sock := filepath.Join(sockDir, shareSocketName(tag))
		srv := serveRealShare(vfs, sock, dir)

		g := taskGuest(command)
		g.vols = []guestVolume{{ContainerDir: guestDir, Settings: volumeSettings{Mode: volumeShare}}}
		withRealRoot(&g)
		Expect(needsGuestTools(len(g.vols), 1)).To(BeFalse(), "a guest with only a share needs no filesystem tools")
		initramfs, err := newInitramfs(guestBusybox(), g)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(initramfs.Close)

		files, drives, initrdPath, _, rootPath := hypervisorFiles(nil, withUserspaceMark(initramfs), nil, realRootImage())
		Expect(drives).To(BeEmpty(), "a share has no drive")
		argv := withRealRootDrive(qemuArgv(art, initrdPath, minGuestMemoryMiB, g.nw, drives, 0, shareSocket{Index: 0, Tag: tag, Path: sock}), rootPath)
		code, stdout, stderr := bootRealQEMU(markedArgv(tcgArgv(qemu, argv)), files)
		Expect(code).To(Equal(0), "QEMU failed: %s\n%s\nvirtiofsd:\n%s", stderr, stdout, srv.log.String())
		return stdout, srv.stop(10 * time.Second)
	}

	It("mounts the share by its tag, shows the guest the host's files, lands the guest's files on the host with the host user as owner, and flushes it at the end", func() {
		dir := GinkgoT().TempDir()
		Expect(os.Chmod(dir, 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "from-host"), []byte("host says hi\n"), 0o644)).To(Succeed())

		out, vfsLog := bootShare(dir, `grep ' virtiofs ' /proc/mounts | cut -d ' ' -f 1,2,3
echo "seen=$(cat '`+guestDir+`/from-host')"
mkdir '`+guestDir+`/made' && echo "from the guest" >'`+guestDir+`/made/note'
echo "wrote=$?"`)
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out+"\nvirtiofsd:\n"+vfsLog)
		Expect(out).To(MatchRegexp(`(?m)^rvm-vol0 /home/vcap/shared\\040data virtiofs\r?$`), out)
		Expect(out).To(MatchRegexp(`(?m)^seen=host says hi\r?$`), out)
		Expect(out).To(MatchRegexp(`(?m)^wrote=0\r?$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		Expect(out).NotTo(ContainSubstring("unmounting"), out)

		// The guest's files are on the host, made by the user that runs
		// virtiofsd, and they were there before the guest ended, since
		// teardown flushes the share and unmounts it before the exit line.
		note := filepath.Join(dir, "made", "note")
		Expect(os.ReadFile(note)).To(Equal([]byte("from the guest\n")))
		info, err := os.Stat(note)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Sys().(*syscall.Stat_t).Uid).To(Equal(uint32(os.Getuid())))
		Expect(vfsLog).To(ContainSubstring("Client disconnected, shutting down"))

		// The share is the host's directory, not a copy: the next guest
		// finds what the first wrote and what the host added since.
		Expect(os.WriteFile(filepath.Join(dir, "later"), []byte("added between boots\n"), 0o644)).To(Succeed())
		out, vfsLog = bootShare(dir, `echo "again=$(cat '`+guestDir+`/made/note')"
echo "later=$(cat '`+guestDir+`/later')"
rm '`+guestDir+`/made/note'`)
		Expect(out).NotTo(ContainSubstring("vm-launch guest setup"), out+"\nvirtiofsd:\n"+vfsLog)
		Expect(out).To(MatchRegexp(`(?m)^again=from the guest\r?$`), out)
		Expect(out).To(MatchRegexp(`(?m)^later=added between boots\r?$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce)+"0"), out)
		Expect(note).NotTo(BeAnExistingFile())
	})

	It("starts the bundled virtiofsd through the bundle's loader, with no shell, and sees it ready and then stops it", func() {
		vfs := realShareVirtiofsd()
		bundle := filepath.Dir(vfs)
		launcher := virtiofsdLauncher(vfs)
		Expect(launcher).To(Equal([]string{
			filepath.Join(bundle, virtiofsdLoaderName), "--library-path", filepath.Join(bundle, virtiofsdLibDirName), filepath.Join(bundle, virtiofsdBinaryName),
		}))
		dir := GinkgoT().TempDir()
		grant := []shareGrant{{Index: 0, Path: dir, Tag: shareTag(0), Mount: shareMountRecord(40, dir)}}
		Expect(checkVirtiofsd(vfs, grant)).To(Succeed())
		DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)
		mountInfoPath = writeTempFile("mountinfo", mountinfoLine(40, dir, "fuse.juicefs"))

		// A Unix socket path is short, so the work directory is too.
		workDir, err := os.MkdirTemp("", "rvm-w")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { os.RemoveAll(workDir) })
		// vm-launch runs as the app's user, and virtiofsd run by a user other
		// than root needs no capabilities. Run by root, as this suite is,
		// virtiofsd drops its supplementary groups and sets its capability
		// set when it starts, and both fail with none. So under root the spec
		// leaves the thread's capabilities alone and keeps the rest of the
		// start: no_new_privs, the loader, the listening socket, and the
		// readiness line. The specs with a fake virtiofsd cover the dropped
		// capabilities.
		if os.Geteuid() == 0 {
			saved := hypervisorCaps
			DeferCleanup(func() { hypervisorCaps = saved })
			hypervisorCaps = &fakeCaps{}
		}
		logBuf := &safeBuffer{}
		s, err := newShareServers(vfs, workDir, grant, log.New(logBuf, "", 0))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { s.stop(0) })
		s.seccomp = realSeccomp(vfs)
		Expect(s.start(nil)).To(Succeed(), logBuf.String())
		Expect(s.servers[0].ready).To(BeClosed())

		// The process is the loader running virtiofsd: no shell came
		// between vm-launch and virtiofsd, and the wrapper never ran. On a
		// host that runs x86-64 programs through a binfmt_misc translator,
		// the process's exe is the translator and its command line keeps the
		// loader's, so the spec reads the loader from the command line and
		// requires only that the exe is no shell.
		pid := s.servers[0].cmd.Process.Pid
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		Expect(err).NotTo(HaveOccurred())
		Expect(filepath.Base(exe)).NotTo(BeElementOf("sh", "dash", "bash", "busybox"))
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		Expect(err).NotTo(HaveOccurred())
		args := strings.Split(strings.TrimSuffix(string(cmdline), "\x00"), "\x00")
		Expect(args).To(ContainElements(launcher[0], filepath.Join(bundle, virtiofsdBinaryName), "--fd=3", "--shared-dir="+dir))
		Expect(args).NotTo(ContainElement(vfs))
		if filepath.Base(exe) == virtiofsdLoaderName {
			Expect(args[0]).To(Equal(launcher[0]))
		}
		Expect(logBuf.String()).To(ContainSubstring(virtiofsdReadyText))

		s.guestEnded()
		Expect(processGone(pid)).To(BeTrue())
		Expect(s.failureReason()).To(BeEmpty())
	})

	It("fails the boot before the start tag, with the share's path, when the guest has no device with the share's tag", func() {
		art := realArtifacts()
		qemu := realQEMU()
		requireMicrovm(qemu)
		g := taskGuest("echo command-ran")
		g.vols = []guestVolume{{ContainerDir: guestDir, Settings: volumeSettings{Mode: volumeShare}}}
		withRealRoot(&g)
		initramfs, err := newInitramfs(guestBusybox(), g)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(initramfs.Close)

		// QEMU gets no vhost-user-fs device, as a launch would give a guest
		// whose share it forgot.
		files, drives, initrdPath, _, rootPath := hypervisorFiles(nil, withUserspaceMark(initramfs), nil, realRootImage())
		argv := withRealRootDrive(qemuArgv(art, initrdPath, minGuestMemoryMiB, g.nw, drives, 0), rootPath)
		code, stdout, stderr := bootRealQEMU(markedArgv(tcgArgv(qemu, argv)), files)
		Expect(code).To(Equal(0), "QEMU failed: %s\n%s", stderr, stdout)
		Expect(stdout).To(MatchRegexp(`(?m)^vm-launch guest setup: mounting the share rvm-vol0 at `+regexp.QuoteMeta(guestDir)+` failed; the hypervisor must give the guest a virtiofs device with that tag\r?$`), stdout)
		Expect(stdout).NotTo(ContainSubstring(startTag(testNonce)), stdout)
		Expect(stdout).NotTo(ContainSubstring("command-ran"), stdout)
	})
})
