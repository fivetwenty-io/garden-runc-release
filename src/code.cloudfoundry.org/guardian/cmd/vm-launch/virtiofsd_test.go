//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// helperShareRun marks a helper process that calls run with its own
// arguments, the mount table at helperShareMountInfo, the kernel's answers
// about volumes taken from that table, for a spec
// that signals or kills vm-launch while it serves a share, or holds its
// stdout. helperShareDisconnectGrace, when set, is the disconnect grace.
const (
	helperShareRun             = "VM_LAUNCH_TEST_SHARE_RUN"
	helperShareMountInfo       = "VM_LAUNCH_TEST_SHARE_MOUNTINFO"
	helperShareDisconnectGrace = "VM_LAUNCH_TEST_SHARE_DISCONNECT_GRACE"
)

// shareRun is the helper process that helperShareRun marks. TestMain runs it.
func shareRun(args []string) int {
	mountInfoPath = os.Getenv(helperShareMountInfo)
	volumeProbe = mountIDByPath(func() string { return mountInfoPath })
	dirProbe = probeByPath
	if v := os.Getenv(helperShareDisconnectGrace); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", helperShareDisconnectGrace, err)
			return 99
		}
		virtiofsdDisconnectGrace = d
	}
	return run(args, log.New(os.Stderr, "vm-launch: ", 0))
}

// quickRaceExit returns the GORACE setting for a helper process whose exit a
// spec times. Under -race, the race detector sleeps for atexit_sleep_ms,
// which is 1000 ms by default, before the process exits, and a spec that
// bounds how long vm-launch takes to stop would otherwise count that second.
// The helper keeps any other GORACE option the suite runs with.
func quickRaceExit() string {
	return "GORACE=" + strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0")
}

// virtiofsdReady is the line a fake virtiofsd writes when it is ready, as
// virtiofsd 1.13.2 writes it.
const virtiofsdReady = `[2026-10-31T00:44:07Z INFO  virtiofsd] Waiting for vhost-user socket connection...`

// Behaviours of a fake virtiofsd. Each runs after the fake has recorded what
// it was started with in $d, the record of the $n-th virtiofsd (from 0).
const (
	// vfsServe becomes ready and serves until $GONE exists, which a fake
	// hypervisor creates as it exits, and then ends as virtiofsd does when
	// its client disconnects.
	vfsServe = `ready; while [ ! -e "$GONE" ]; do sleep 0.01; done; echo '[2026-10-31T00:45:16Z INFO  virtiofsd] Client disconnected, shutting down' >&2; exit 0`
	// vfsHang becomes ready, ignores SIGTERM, and never ends on its own. A
	// spec sends it SIGTERM to show that only SIGKILL ends it.
	vfsHang = `ready; trap '' TERM; while :; do sleep 0.02; done`
	// vfsNeverReady never writes the ready line.
	vfsNeverReady = `echo '[2026-10-31T00:44:07Z WARN  virtiofsd::limits] Failure when trying to set the limit to 1000000' >&2; while :; do sleep 0.02; done`
	// vfsCrash becomes ready and fails 0.3 s later.
	vfsCrash = `ready; sleep 0.3; echo '[2026-10-31T00:44:08Z ERROR virtiofsd] the store went away' >&2; exit 3`
	// vfsQuit becomes ready and exits 0 0.3 s later, as virtiofsd does when
	// its client goes.
	vfsQuit = `ready; sleep 0.3; exit 0`
	// vfsSecondFails serves as vfsHang for the first share and fails at once
	// for the second.
	vfsSecondFails = `if [ "$n" = 1 ]; then echo '[2026-10-31T00:44:07Z ERROR virtiofsd] Error opening shared directory' >&2; exit 1; fi; ` + vfsHang
)

// fakeVirtiofsd writes a script that stands in for the virtiofsd wrapper. It
// records its pid, argv, credentials, environment, and descriptor 3, and
// then runs behaviour. It returns the script's path and the directory that
// holds one record per start, 0 first.
func fakeVirtiofsd(behaviour, gone string) (string, string) {
	dir := GinkgoT().TempDir()
	rec := GinkgoT().TempDir()
	script := `#!/bin/bash
GONE=` + shellQuote(gone) + `
rec=` + shellQuote(rec) + `
n=$(ls -1 "$rec" | wc -l | tr -d ' ')
d="$rec/$n.tmp"
mkdir "$d"
echo $$ >"$d/pid"
printf '%s\n' "$@" >"$d/argv"
grep -E '^(Uid|Gid|Cap[A-Za-z]+|NoNewPrivs):' /proc/$$/status >"$d/status"
tr '\0' '\n' </proc/$$/environ >"$d/env"
readlink /proc/$$/fd/3 >"$d/fd3" 2>&1
grep '^flags' /proc/$$/fdinfo/3 >"$d/fd3flags" 2>&1
cat /proc/net/unix >"$d/unix"
mv "$d" "$rec/$n"
d="$rec/$n"
ready() { echo ` + shellQuote(virtiofsdReady) + ` >&2; }
` + behaviour + "\n"
	path := filepath.Join(dir, "virtiofsd-wrapper")
	Expect(os.WriteFile(path, []byte(script), 0o755)).To(Succeed())
	return path, rec
}

// recordOf returns the file name of the record of the n-th fake virtiofsd,
// once the fake has written it.
func recordOf(rec string, n int, name string) string {
	p := filepath.Join(rec, strconv.Itoa(n), name)
	waitForFile(p)
	return p
}

func readRecord(rec string, n int, name string) string {
	b, err := os.ReadFile(recordOf(rec, n, name))
	Expect(err).NotTo(HaveOccurred())
	return string(b)
}

// recordedPid returns the pid of the n-th fake virtiofsd.
func recordedPid(rec string, n int) int {
	pid, err := strconv.Atoi(strings.TrimSpace(readRecord(rec, n, "pid")))
	Expect(err).NotTo(HaveOccurred())
	return pid
}

// processGone reports whether pid has ended and been reaped, which means the
// kernel has no process with that pid. A zombie is not gone, because a launch that
// leaves one has not reaped what it started.
func processGone(pid int) bool {
	_, err := os.Stat("/proc/" + strconv.Itoa(pid))
	return errors.Is(err, os.ErrNotExist)
}

// processEnded reports whether pid has ended, reaped or not. It is for a
// process whose parent was killed, which whatever adopted it may never reap.
func processEnded(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	// The state follows the command name, which is in parentheses.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	return i < 0 || i+2 >= len(s) || s[i+2] == 'Z' || s[i+2] == 'X'
}

// shortVirtiofsdTimes makes the lifecycle's waits short for the rest of the
// spec.
func shortVirtiofsdTimes() {
	r, d, s, k := virtiofsdReadyTimeout, virtiofsdDisconnectGrace, virtiofsdStopGrace, virtiofsdKillWait
	DeferCleanup(func() {
		virtiofsdReadyTimeout, virtiofsdDisconnectGrace, virtiofsdStopGrace, virtiofsdKillWait = r, d, s, k
	})
	virtiofsdReadyTimeout = 2 * time.Second
	virtiofsdDisconnectGrace = 300 * time.Millisecond
	virtiofsdStopGrace = 200 * time.Millisecond
	virtiofsdKillWait = 500 * time.Millisecond
}

// shareMountRecord is the mount record that mountinfoLine(id, dir, ...)
// describes.
func shareMountRecord(id int, dir string) mountRecord {
	return mountRecord{ContainerDir: dir, MountID: uint64(id), ParentID: 29, Major: 0, Minor: uint32(id), Root: "/", MountPoint: dir}
}

var _ = Describe("the --virtiofsd flag", func() {
	It("is named virtiofsd-path and shown in the usage", func() {
		Expect(virtiofsdFlag).To(Equal("virtiofsd-path"))
		Expect(usage).To(ContainSubstring("[--virtiofsd-path PATH]"))
	})

	It("is empty by default, for either backend", func() {
		for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			cfg, err := parseArgs([]string{"--backend", string(kind), "--", "true"})
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.virtiofsd).To(BeEmpty())
		}
	})

	It("becomes an absolute path", func() {
		// The path a cell passes is the one inside the container, where
		// Garden binds the host's artifacts directory.
		cfg, err := parseArgs([]string{"--backend", "vm-qemu", "--virtiofsd-path", "/opt/garden-vm/artifacts/virtiofsd/virtiofsd-wrapper", "--", "true"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.virtiofsd).To(Equal("/opt/garden-vm/artifacts/virtiofsd/virtiofsd-wrapper"))
		cfg, err = parseArgs([]string{"--backend", "vm-qemu", "--virtiofsd-path=rel/vfs", "--", "true"})
		Expect(err).NotTo(HaveOccurred())
		wd, err := os.Getwd()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.virtiofsd).To(Equal(filepath.Join(wd, "rel/vfs")))
	})

	It("refuses an empty value", func() {
		_, err := parseArgs([]string{"--backend", "vm-qemu", "--virtiofsd-path=", "--", "true"})
		Expect(err).To(MatchError("--virtiofsd-path must not be empty"))
	})
})

var _ = Describe("checkVirtiofsd", func() {
	grant := []shareGrant{{Index: 0, Path: "/shared", Tag: "rvm-vol0"}}

	It("needs nothing without a grant", func() {
		Expect(checkVirtiofsd("", nil)).To(Succeed())
		Expect(checkVirtiofsd("/no/such/dir", nil)).To(Succeed())
	})

	It("refuses a grant without --virtiofsd-path, naming the share", func() {
		Expect(checkVirtiofsd("", grant)).To(MatchError(`VM_VOLUMES "/shared" is granted a share, but vm-launch was not given --virtiofsd-path, so nothing can serve it; the operator must install virtiofsd and pass its path`))
	})

	It("accepts an executable file", func() {
		path, _ := fakeVirtiofsd(vfsHang, "")
		Expect(checkVirtiofsd(path, grant)).To(Succeed())
	})

	It("refuses a path that is missing, not a regular file, or not executable", func() {
		path, _ := fakeVirtiofsd(vfsHang, "")
		missing := filepath.Join(filepath.Dir(path), "missing")
		Expect(checkVirtiofsd(missing, grant)).To(MatchError("virtiofsd for shares: stat " + missing + ": no such file or directory"))

		dir := filepath.Dir(path)
		Expect(checkVirtiofsd(dir, grant)).To(MatchError("virtiofsd for shares: " + quoteForLog(dir) + " is not a regular file"))

		Expect(os.Chmod(path, 0o644)).To(Succeed())
		Expect(checkVirtiofsd(path, grant)).To(MatchError("virtiofsd for shares: " + quoteForLog(path) + " is not executable"))
	})

	It("follows a symbolic link to the executable", func() {
		path, _ := fakeVirtiofsd(vfsHang, "")
		link := filepath.Join(GinkgoT().TempDir(), "virtiofsd")
		Expect(os.Symlink(path, link)).To(Succeed())
		Expect(checkVirtiofsd(link, grant)).To(Succeed())
	})
})

var _ = Describe("virtiofsdArgv", func() {
	It("runs virtiofsd with the flags the lab proved", func() {
		w := "/opt/garden-vm/artifacts/virtiofsd/virtiofsd-wrapper"
		Expect(virtiofsdArgv(w, "/home/vcap/data")).To(Equal([]string{
			w, "--fd=3", "--sandbox=none", "--seccomp=kill", "--cache=auto", "--inode-file-handles=never",
			"--shared-dir=/home/vcap/data",
		}))
	})

	It("keeps a directory with an equals sign or a leading dash in one argument", func() {
		argv := virtiofsdArgv("/v", "/-a=b c")
		Expect(argv[len(argv)-1]).To(Equal("--shared-dir=/-a=b c"))
	})
})

var _ = Describe("listenShareSocket", func() {
	It("listens on a blocking, close-on-exec socket at the path", func() {
		path := filepath.Join(GinkgoT().TempDir(), "rvm-vol0.sock")
		f, err := listenShareSocket(path)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		info, err := os.Lstat(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode() & os.ModeSocket).NotTo(BeZero())

		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(flags & unix.O_NONBLOCK).To(BeZero())
		fdFlags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(fdFlags & unix.FD_CLOEXEC).NotTo(BeZero())
		accept, err := unix.GetsockoptInt(int(f.Fd()), unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
		Expect(err).NotTo(HaveOccurred())
		Expect(accept).To(Equal(1))

		c, err := net.Dial("unix", path)
		Expect(err).NotTo(HaveOccurred())
		c.Close()
	})

	It("refuses a path too long for a socket address, before it creates anything", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, strings.Repeat("a", maxSocketPathBytes)+".sock")
		_, err := listenShareSocket(path)
		Expect(err).To(MatchError(ContainSubstring("over the 107 a Unix socket path may have; TMPDIR is too long")))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("accepts a path of exactly the longest length", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, strings.Repeat("a", maxSocketPathBytes-len(dir)-1))
		Expect(path).To(HaveLen(maxSocketPathBytes))
		f, err := listenShareSocket(path)
		Expect(err).NotTo(HaveOccurred())
		f.Close()
	})

	It("refuses a path that already exists", func() {
		path := filepath.Join(GinkgoT().TempDir(), "taken")
		Expect(os.WriteFile(path, nil, 0o600)).To(Succeed())
		_, err := listenShareSocket(path)
		Expect(err).To(MatchError(ContainSubstring("binding the share socket")))
		Expect(errors.Is(err, unix.EADDRINUSE)).To(BeTrue(), "%v", err)
	})
})

var _ = Describe("checkShareMount", func() {
	var dir string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)
		mountInfoPath = writeTempFile("mountinfo", mountinfoLine(40, dir, "fuse.juicefs"))
	})

	grant := func() shareGrant {
		return shareGrant{Index: 0, Path: dir, Tag: "rvm-vol0", Mount: shareMountRecord(40, dir)}
	}

	It("accepts the mount that was inspected", func() {
		Expect(checkShareMount(grant())).To(Succeed())
	})

	It("asks about the directory it opened", func() {
		var asked []string
		dirProbe = func(fd int, name string) (mountProbe, error) {
			target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
			Expect(err).NotTo(HaveOccurred())
			Expect(target).To(Equal(dir))
			asked = append(asked, name)
			return mountProbe{MountID: 40, MountRoot: true}, nil
		}
		Expect(checkShareMount(grant())).To(Succeed())
		Expect(asked).To(Equal([]string{dir}))
	})

	It("refuses another mount ID", func() {
		dirProbe = func(int, string) (mountProbe, error) { return mountProbe{MountID: 41, MountRoot: true}, nil }
		err := checkShareMount(grant())
		Expect(errors.Is(err, errMountChanged)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError(`the mount of the share at "` + dir + `" changed during start: it was mount ID 40 when vm-launch inspected it and is mount ID 41 now`))
	})

	It("refuses a directory that is no longer a mount point", func() {
		dirProbe = func(int, string) (mountProbe, error) { return mountProbe{MountID: 40}, nil }
		err := checkShareMount(grant())
		Expect(errors.Is(err, errNotMountRoot)).To(BeTrue(), "%v", err)
	})

	It("refuses a mount whose device or root changed", func() {
		g := grant()
		g.Mount.Minor = 99
		err := checkShareMount(g)
		Expect(errors.Is(err, errMountChanged)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError(`the mount of the share at "` + dir + `" changed during start: mount ID 40 showed device 0:99 and root "/" when vm-launch inspected it and shows device 0:40 and root "/" now`))

		g = grant()
		g.Mount.Root = "/apps/one"
		err = checkShareMount(g)
		Expect(errors.Is(err, errMountChanged)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError(ContainSubstring(`root "/apps/one" when vm-launch inspected it and shows device 0:40 and root "/" now`)))
	})

	It("refuses a mount that has left the mount table", func() {
		mountInfoPath = writeTempFile("mountinfo", mountinfoLine(41, "/elsewhere", "fuse.juicefs"))
		dirProbe = func(int, string) (mountProbe, error) { return mountProbe{MountID: 40, MountRoot: true}, nil }
		Expect(checkShareMount(grant())).To(MatchError(ContainSubstring("has no mount entry for its mount ID 40")))
	})

	It("follows no symbolic link, in the last component or a parent", func() {
		link := filepath.Join(GinkgoT().TempDir(), "link")
		Expect(os.Symlink(dir, link)).To(Succeed())
		parent := filepath.Join(GinkgoT().TempDir(), "parent")
		Expect(os.Symlink(filepath.Dir(dir), parent)).To(Succeed())
		for _, p := range []string{link, filepath.Join(parent, filepath.Base(dir))} {
			g := grant()
			g.Path = p
			err := checkShareMount(g)
			Expect(errors.Is(err, unix.ELOOP)).To(BeTrue(), "%v", err)
			Expect(err).To(MatchError(ContainSubstring("vm-launch follows no symbolic links")))
		}
	})

	It("refuses a directory that is gone", func() {
		g := grant()
		g.Path = filepath.Join(dir, "missing")
		Expect(checkShareMount(g)).To(MatchError(ContainSubstring("opening the share at")))
	})
})

var _ = Describe("the volume index", func() {
	It("is each volume's place among all the volumes", func() {
		a, b := GinkgoT().TempDir(), GinkgoT().TempDir()
		info := writeTempFile("mountinfo", mountinfoLine(40, a, "fuse.juicefs")+mountinfoLine(41, b, "fuse.juicefs"))
		saved := volumeProbe
		DeferCleanup(func() { volumeProbe = saved })
		volumeProbe = mountIDByPath(func() string { return info })
		selected, err := findVolumeProviders(info, []guestVolume{{ContainerDir: a}, {ContainerDir: b}})
		Expect(err).NotTo(HaveOccurred())
		Expect(selected[0].Index).To(Equal(0))
		Expect(selected[1].Index).To(Equal(1))
	})

	It("goes with the share's mount record into its grant", func() {
		m := shareMountRecord(40, "/shared")
		m.FSType = juicefsFSType
		v := selectedVolume{Index: 0, Volume: guestVolume{ContainerDir: "/shared", Settings: volumeSettings{Mode: volumeShare}}, Provider: juicefsProvider{}, Mount: m}
		grants, err := grantShares(backend.VMQemu, true, []selectedVolume{v})
		Expect(err).NotTo(HaveOccurred())
		Expect(grants).To(Equal([]shareGrant{{Index: 0, Path: "/shared", Mount: m, Tag: "rvm-vol0", Provider: "JuiceFS"}}))
	})
})

var _ = Describe("preparing the volumes of a launch with a share", func() {
	It("never asks a share's provider for a disk, and keeps the next volume's index", func() {
		shared := fake("Shared")
		shared.caps.Sharing = sharingShared
		shared.prepare = func(prepareRequest) (*attachment, error) {
			Fail("a share reached its provider's Prepare")
			return nil, nil
		}
		dir := GinkgoT().TempDir()
		img, err := os.CreateTemp(dir, "img")
		Expect(err).NotTo(HaveOccurred())
		Expect(img.Truncate(1 << 20)).To(Succeed())
		private := fake("Private")
		private.prepare = func(prepareRequest) (*attachment, error) {
			return &attachment{File: img, Release: func() error { return nil }}, nil
		}
		var pv preparedVolumes
		budget := newLockBudget(time.Second)
		logger := log.New(GinkgoWriter, "", 0)
		att, err := pv.prepare(selectedVolume{Index: 0, Volume: guestVolume{ContainerDir: "/s", Settings: volumeSettings{Mode: volumeShare}}, Provider: shared}, nil, budget, logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(att).To(BeNil())
		Expect(pv).To(BeEmpty())

		att, err = pv.prepare(selectedVolume{Index: 1, Volume: guestVolume{ContainerDir: dir}, Provider: private}, nil, budget, logger)
		Expect(err).NotTo(HaveOccurred(), "%v", err)
		Expect(att).To(BeNil())
		Expect(pv).To(HaveLen(1))
		Expect(pv[0].Index).To(Equal(1))
		Expect(pv[0].Path).To(Equal(dir))
		pv.release(logger)
	})
})

var _ = Describe("virtiofsd's log", func() {
	var (
		logBuf *safeBuffer
		srv    *shareServer
		w      *os.File
	)

	BeforeEach(func() {
		logBuf = &safeBuffer{}
		srv = &shareServer{grant: shareGrant{Path: "/data"}, ready: make(chan struct{}), logDone: make(chan struct{})}
		r, pw, err := os.Pipe()
		Expect(err).NotTo(HaveOccurred())
		w = pw
		go srv.readLog(r, log.New(logBuf, "", 0))
	})

	It("passes each line on with the share's path, and is ready at the ready line", func() {
		fmt.Fprintf(w, "[x WARN  virtiofsd::limits] Failure when trying to set the limit\r\n")
		Consistently(srv.ready, 100*time.Millisecond).ShouldNot(BeClosed())
		fmt.Fprintln(w, virtiofsdReady)
		Eventually(srv.ready).Should(BeClosed())
		fmt.Fprintln(w, virtiofsdReady)
		fmt.Fprint(w, "no newline at the end")
		w.Close()
		Eventually(srv.logDone).Should(BeClosed())
		Expect(logBuf.String()).To(Equal(`virtiofsd for "/data": [x WARN  virtiofsd::limits] Failure when trying to set the limit` + "\n" +
			`virtiofsd for "/data": ` + virtiofsdReady + "\n" +
			`virtiofsd for "/data": ` + virtiofsdReady + "\n" +
			`virtiofsd for "/data": no newline at the end` + "\n"))
	})

	It("cuts a long line once and goes on with the next one", func() {
		fmt.Fprintln(w, strings.Repeat("a", 3*maxVirtiofsdLineBytes))
		fmt.Fprintln(w, "next")
		w.Close()
		Eventually(srv.logDone).Should(BeClosed())
		lines := strings.Split(strings.TrimSuffix(logBuf.String(), "\n"), "\n")
		Expect(lines).To(HaveLen(2))
		Expect(lines[0]).To(Equal(`virtiofsd for "/data": ` + strings.Repeat("a", maxVirtiofsdLineBytes) + " [cut]"))
		Expect(lines[1]).To(Equal(`virtiofsd for "/data": next`))
	})

	It("passes on a bounded number of lines, keeps reading the rest, and passes on the last ones at the end", func() {
		const total = 5000
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 0; i < total-1; i++ {
				fmt.Fprintf(w, "[x WARN  virtiofsd] line %d\n", i)
			}
			// The line that says why virtiofsd ended is its last.
			fmt.Fprintln(w, "[x ERROR virtiofsd] the store went away")
			w.Close()
		}()
		Eventually(done, 10*time.Second).Should(BeClosed())
		Eventually(srv.logDone).Should(BeClosed())
		lines := strings.Split(strings.TrimSuffix(logBuf.String(), "\n"), "\n")
		Expect(lines).To(HaveLen(maxVirtiofsdLogLines + 1 + 1 + maxVirtiofsdTailLines))
		Expect(lines[maxVirtiofsdLogLines-1]).To(Equal(fmt.Sprintf(`virtiofsd for "/data": [x WARN  virtiofsd] line %d`, maxVirtiofsdLogLines-1)))
		Expect(lines[maxVirtiofsdLogLines]).To(Equal(fmt.Sprintf(`virtiofsd for "/data" wrote more than %d lines; vm-launch holds back the rest and passes on the last %d when the log ends`, maxVirtiofsdLogLines, maxVirtiofsdTailLines)))
		Expect(lines[maxVirtiofsdLogLines+1]).To(Equal(fmt.Sprintf(`virtiofsd for "/data": %d lines were held back; the last %d follow`, total-maxVirtiofsdLogLines, maxVirtiofsdTailLines)))
		tail := lines[maxVirtiofsdLogLines+2:]
		for i, line := range tail[:maxVirtiofsdTailLines-1] {
			Expect(line).To(Equal(fmt.Sprintf(`virtiofsd for "/data": [x WARN  virtiofsd] line %d`, total-maxVirtiofsdTailLines+i)))
		}
		Expect(tail[maxVirtiofsdTailLines-1]).To(Equal(`virtiofsd for "/data": [x ERROR virtiofsd] the store went away`))
	})

	It("passes on every held-back line when fewer than the tail were held back", func() {
		for i := 0; i < maxVirtiofsdLogLines+3; i++ {
			fmt.Fprintf(w, "line %d\n", i)
		}
		w.Close()
		Eventually(srv.logDone).Should(BeClosed())
		lines := strings.Split(strings.TrimSuffix(logBuf.String(), "\n"), "\n")
		Expect(lines).To(HaveLen(maxVirtiofsdLogLines + 2 + 3))
		Expect(lines[maxVirtiofsdLogLines+1]).To(Equal(`virtiofsd for "/data": 3 lines were held back; the last 3 follow`))
		Expect(lines[maxVirtiofsdLogLines+2:]).To(Equal([]string{
			fmt.Sprintf(`virtiofsd for "/data": line %d`, maxVirtiofsdLogLines),
			fmt.Sprintf(`virtiofsd for "/data": line %d`, maxVirtiofsdLogLines+1),
			fmt.Sprintf(`virtiofsd for "/data": line %d`, maxVirtiofsdLogLines+2),
		}))
	})

	It("escapes control bytes, so a line cannot drive a terminal, and keeps tabs", func() {
		fmt.Fprint(w, "a\x1b[2Jb\tc\x7fd\re\x00f\n")
		w.Close()
		Eventually(srv.logDone).Should(BeClosed())
		Expect(logBuf.String()).To(Equal(`virtiofsd for "/data": a\x1b[2Jb` + "\t" + `c\x7fd\x0de\x00f` + "\n"))
	})

	It("sees the ready line past the line limit", func() {
		for i := 0; i < maxVirtiofsdLogLines+5; i++ {
			fmt.Fprintf(w, "line %d\n", i)
		}
		fmt.Fprintln(w, virtiofsdReady)
		Eventually(srv.ready).Should(BeClosed())
		w.Close()
		Eventually(srv.logDone).Should(BeClosed())
		Expect(logBuf.String()).To(HaveSuffix(`virtiofsd for "/data": ` + virtiofsdReady + "\n"))
	})
})

var _ = Describe("lineRing", func() {
	It("keeps the latest lines in order and counts every line", func() {
		r := newLineRing(3)
		Expect(r.lines()).To(BeEmpty())
		r.add("a")
		r.add("b")
		Expect(r.lines()).To(Equal([]string{"a", "b"}))
		for _, l := range []string{"c", "d", "e", "f", "g"} {
			r.add(l)
		}
		Expect(r.lines()).To(Equal([]string{"e", "f", "g"}))
		Expect(r.total).To(Equal(7))
	})
})

var _ = Describe("confining virtiofsd", func() {
	// onDiscardedThread runs f on an OS thread that ends with it, so a flag
	// f sets on the thread never reaches another goroutine.
	onDiscardedThread := func(f func()) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer GinkgoRecover()
			runtime.LockOSThread()
			f()
		}()
		<-done
	}

	It("names virtiofsd in its lines", func() {
		f := &fakeCaps{root: true, boundingBits: 0x1, ignoreDrop: true}
		Expect(confineThread(f, "virtiofsd")).To(MatchError("vm-launch runs as root without CAP_SETPCAP, so its bounding set keeps capabilities (0x1), which a root virtiofsd gets"))
		cmd := exec.Command("/bin/true")
		_, err := startConfinedAs(cmd, func() error { return unix.EPERM }, "virtiofsd")
		Expect(err).To(MatchError("confining virtiofsd's capabilities: operation not permitted"))
	})

	It("sets no_new_privs on its thread, and asks about no file's capabilities", func() {
		onDiscardedThread(func() {
			f := &fakeCaps{hasFileCaps: true}
			Expect(confineVirtiofsd(f)).To(Succeed())
			nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(nnp).To(Equal(1))
			Expect(f.calls).NotTo(ContainElement(HavePrefix("fileCaps")))
		})
	})

	It("stops at the first failure to drop a capability", func() {
		onDiscardedThread(func() {
			f := &fakeCaps{errs: map[string]error{"clearAmbient": unix.EPERM}}
			Expect(confineVirtiofsd(f)).To(MatchError("clearing the ambient capabilities: operation not permitted"))
		})
	})
})

var _ = Describe("the virtiofsd of each share", func() {
	var (
		logBuf  *safeBuffer
		logger  *log.Logger
		workDir string
		shares  []string
		gone    string
	)

	BeforeEach(func() {
		shortVirtiofsdTimes()
		logBuf = &safeBuffer{}
		logger = log.New(logBuf, "", 0)
		workDir = GinkgoT().TempDir()
		shares = []string{GinkgoT().TempDir(), GinkgoT().TempDir()}
		gone = filepath.Join(GinkgoT().TempDir(), "gone")
		var table string
		for i, s := range shares {
			table += mountinfoLine(40+i, s, "fuse.juicefs")
		}
		DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)
		mountInfoPath = writeTempFile("mountinfo", table)
	})

	grants := func(n int) []shareGrant {
		var gs []shareGrant
		for i := 0; i < n; i++ {
			gs = append(gs, shareGrant{Index: i, Path: shares[i], Tag: shareTag(i), Mount: shareMountRecord(40+i, shares[i])})
		}
		return gs
	}

	servers := func(behaviour string, n int) (*shareServers, string) {
		vfs, rec := fakeVirtiofsd(behaviour, gone)
		s, err := newShareServers(vfs, workDir, grants(n), logger)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { s.stop(0) })
		return s, rec
	}

	// guest starts a stand-in for QEMU that runs until it is killed, and
	// returns it with a channel that is closed once it has been reaped and
	// a function that returns how it ended then.
	guest := func() (*exec.Cmd, chan struct{}, func() syscall.WaitStatus) {
		cmd := exec.Command("sleep", "30")
		Expect(cmd.Start()).To(Succeed())
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		DeferCleanup(func() { _ = cmd.Process.Kill(); <-done })
		return cmd, done, func() syscall.WaitStatus {
			<-done
			return cmd.ProcessState.Sys().(syscall.WaitStatus)
		}
	}

	It("binds one socket per share in the work directory, named by its tag", func() {
		s, _ := servers(vfsHang, 2)
		Expect(s.sockets()).To(Equal([]shareSocket{
			{Index: 0, Tag: "rvm-vol0", Path: filepath.Join(workDir, "rvm-vol0.sock")},
			{Index: 1, Tag: "rvm-vol1", Path: filepath.Join(workDir, "rvm-vol1.sock")},
		}))
		for _, sock := range s.sockets() {
			info, err := os.Lstat(sock.Path)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode() & os.ModeSocket).NotTo(BeZero())
		}
	})

	It("keeps a share's volume index and tag when a private volume comes first", func() {
		vfs, _ := fakeVirtiofsd(vfsHang, gone)
		s, err := newShareServers(vfs, workDir, []shareGrant{{Index: 1, Path: shares[1], Tag: "rvm-vol1", Mount: shareMountRecord(41, shares[1])}}, logger)
		Expect(err).NotTo(HaveOccurred())
		defer s.stop(0)
		Expect(s.sockets()).To(Equal([]shareSocket{{Index: 1, Tag: "rvm-vol1", Path: filepath.Join(workDir, "rvm-vol1.sock")}}))
	})

	It("closes every socket it bound when a later one fails", func() {
		vfs, _ := fakeVirtiofsd(vfsHang, gone)
		gs := grants(2)
		Expect(os.WriteFile(filepath.Join(workDir, "rvm-vol1.sock"), nil, 0o600)).To(Succeed())
		before := openFDs()
		_, err := newShareServers(vfs, workDir, gs, logger)
		Expect(err).To(MatchError(ContainSubstring("binding the share socket")))
		Expect(openFDs()).To(Equal(before))
	})

	It("starts virtiofsd confined, as vm-launch's user, with an empty environment and the listening socket on descriptor 3", func() {
		s, rec := servers(vfsHang, 1)
		Expect(s.start(nil)).To(Succeed())
		Expect(strings.Split(strings.TrimSpace(readRecord(rec, 0, "argv")), "\n")).To(Equal(virtiofsdArgv(s.path, shares[0])[1:]))
		Expect(readRecord(rec, 0, "env")).To(BeEmpty())

		status := readRecord(rec, 0, "status")
		caps := statusCaps(status)
		for _, set := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb"} {
			Expect(caps[set]).To(BeZero(), set)
		}
		if os.Geteuid() == 0 {
			Expect(caps["CapBnd"]).To(BeZero())
		}
		Expect(status).To(MatchRegexp(`(?m)^Uid:\s+%d\s`, os.Getuid()))
		// vm-launch sets no_new_privs itself, whatever it was started with.
		Expect(status).To(MatchRegexp(`(?m)^NoNewPrivs:\s+1$`))

		// Descriptor 3 is the listening socket at the share's path, in
		// blocking mode.
		fd3 := strings.TrimSpace(readRecord(rec, 0, "fd3"))
		Expect(fd3).To(MatchRegexp(`^socket:\[\d+\]$`))
		inode := strings.TrimSuffix(strings.TrimPrefix(fd3, "socket:["), "]")
		flags := strings.Fields(readRecord(rec, 0, "fd3flags"))
		Expect(flags).To(HaveLen(2))
		f, err := strconv.ParseUint(flags[1], 8, 64)
		Expect(err).NotTo(HaveOccurred())
		Expect(f & unix.O_NONBLOCK).To(BeZero())
		var found bool
		for _, line := range strings.Split(readRecord(rec, 0, "unix"), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 8 && fields[6] == inode {
				found = true
				Expect(fields[3]).To(Equal("00010000"), "listening")
				Expect(fields[7]).To(Equal(filepath.Join(workDir, "rvm-vol0.sock")))
			}
		}
		Expect(found).To(BeTrue(), "descriptor 3 is in /proc/net/unix")

		// vm-launch's own copy is closed, so only virtiofsd listens.
		Expect(s.servers[0].listener).To(BeNil())
		Expect(logBuf.String()).To(Equal(`virtiofsd for "` + shares[0] + `": ` + virtiofsdReady + "\n"))
	})

	It("stops a virtiofsd that outlives QEMU, with SIGKILL after the grace, and leaves no process", func() {
		s, rec := servers(vfsHang, 2)
		Expect(s.start(nil)).To(Succeed())
		pids := []int{recordedPid(rec, 0), recordedPid(rec, 1)}
		g, done, _ := guest()
		s.guestStarted(g.Process)
		Expect(g.Process.Kill()).To(Succeed())
		<-done
		// A SIGTERM changes nothing, because vm-launch stops virtiofsd with SIGKILL.
		for _, pid := range pids {
			Expect(syscall.Kill(pid, syscall.SIGTERM)).To(Succeed())
		}
		Consistently(func() bool { return processEnded(pids[0]) || processEnded(pids[1]) }, 100*time.Millisecond).Should(BeFalse())
		began := time.Now()
		s.guestEnded()
		Expect(time.Since(began)).To(BeNumerically("<", virtiofsdStopGrace+virtiofsdKillWait))
		Expect(time.Since(began)).To(BeNumerically(">=", virtiofsdStopGrace))
		for _, pid := range pids {
			Expect(processGone(pid)).To(BeTrue())
		}
		for _, srv := range s.servers {
			Expect(srv.exited).To(BeClosed())
			ws := srv.state.Sys().(syscall.WaitStatus)
			Expect(ws.Signal()).To(Equal(syscall.SIGKILL))
		}
		Expect(s.failureReason()).To(BeEmpty())
		Expect(logBuf.String()).NotTo(ContainSubstring("did not end"))
	})

	It("stops at once a virtiofsd whose QEMU never started, since nothing will connect to it", func() {
		s, rec := servers(vfsHang, 1)
		Expect(s.start(nil)).To(Succeed())
		pid := recordedPid(rec, 0)
		began := time.Now()
		s.guestEnded()
		Expect(time.Since(began)).To(BeNumerically("<", virtiofsdStopGrace))
		Expect(processGone(pid)).To(BeTrue())
		Expect(s.servers[0].exited).To(BeClosed())
	})

	It("bounds the stop by the grace and the kill wait together, even when a log never ends", func() {
		// Each fake leaves a child behind that holds its log open, so the
		// log reaches its end only when the child does.
		s, rec := servers(`sleep 30 >&2 & echo $! >"$d/child.tmp"; mv "$d/child.tmp" "$d/child"; ready; while :; do sleep 0.02; done`, 2)
		Expect(s.start(nil)).To(Succeed())
		for n := 0; n < 2; n++ {
			child, err := strconv.Atoi(strings.TrimSpace(readRecord(rec, n, "child")))
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = syscall.Kill(child, syscall.SIGKILL) })
		}
		g, done, _ := guest()
		s.guestStarted(g.Process)
		Expect(g.Process.Kill()).To(Succeed())
		<-done
		began := time.Now()
		s.guestEnded()
		took := time.Since(began)
		Expect(took).To(BeNumerically(">=", virtiofsdStopGrace+virtiofsdKillWait))
		Expect(took).To(BeNumerically("<", virtiofsdStopGrace+virtiofsdKillWait+250*time.Millisecond))
		for _, srv := range s.servers {
			Expect(srv.exited).To(BeClosed())
			Expect(srv.logDone).NotTo(BeClosed())
		}
		Expect(logBuf.String()).NotTo(ContainSubstring("did not end"))
	})

	It("spends one kill wait on the exits and the logs together when SIGKILL does not end a virtiofsd", func() {
		// Each server stands for a virtiofsd that SIGKILL cannot end yet,
		// as when it waits in uninterruptible I/O on the share's store, so
		// neither its exit nor its log's end ever comes.
		s, err := newShareServers("/nonexistent/virtiofsd", workDir, grants(2), logger)
		Expect(err).NotTo(HaveOccurred())
		for _, srv := range s.servers {
			cmd := exec.Command("sleep", "30")
			Expect(cmd.Start()).To(Succeed())
			DeferCleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			srv.cmd = cmd
		}
		began := time.Now()
		s.stop(0)
		took := time.Since(began)
		Expect(took).To(BeNumerically(">=", virtiofsdKillWait))
		Expect(took).To(BeNumerically("<", virtiofsdKillWait+250*time.Millisecond))
		Expect(strings.Count(logBuf.String(), "did not end within "+virtiofsdKillWait.String()+" of SIGKILL")).To(Equal(2))
	})

	It("lets a virtiofsd that sees QEMU go end on its own", func() {
		// The fake ends within moments of seeing QEMU go. A grace that a
		// loaded machine cannot spend keeps its clean end from being a kill.
		virtiofsdStopGrace = 5 * time.Second
		s, rec := servers(vfsServe, 1)
		Expect(s.start(nil)).To(Succeed())
		g, done, _ := guest()
		s.guestStarted(g.Process)
		pid := recordedPid(rec, 0)
		Expect(g.Process.Kill()).To(Succeed())
		<-done
		Expect(os.WriteFile(gone, nil, 0o600)).To(Succeed())
		s.guestEnded()
		Expect(processGone(pid)).To(BeTrue())
		Expect(s.servers[0].exited).To(BeClosed())
		Expect(s.servers[0].state.Success()).To(BeTrue())
		Expect(s.failureReason()).To(BeEmpty())
		Expect(logBuf.String()).To(HaveSuffix("Client disconnected, shutting down\n"))
	})

	It("kills QEMU at once when a virtiofsd fails while the guest runs", func() {
		s, _ := servers(vfsCrash, 1)
		Expect(s.start(nil)).To(Succeed())
		g, done, status := guest()
		s.guestStarted(g.Process)
		Eventually(done, 5*time.Second).Should(BeClosed())
		Expect(status().Signal()).To(Equal(syscall.SIGKILL))
		Expect(s.failureReason()).To(Equal(`the share at "` + shares[0] + `" stopped being served before the guest reported a status`))
		Expect(logBuf.String()).To(ContainSubstring(`virtiofsd for "` + shares[0] + `": [2026-10-31T00:44:08Z ERROR virtiofsd] the store went away` + "\n"))
		Expect(logBuf.String()).To(ContainSubstring(`virtiofsd for the share at "` + shares[0] + `" exited with status 3; killing the hypervisor` + "\n"))
		s.guestEnded()
		Expect(s.failureReason()).NotTo(BeEmpty())
	})

	It("gives QEMU the disconnect grace after virtiofsd exits 0, and then kills it", func() {
		s, _ := servers(vfsQuit, 1)
		Expect(s.start(nil)).To(Succeed())
		g, done, status := guest()
		s.guestStarted(g.Process)
		began := time.Now()
		Eventually(done, 5*time.Second).Should(BeClosed())
		Expect(time.Since(began)).To(BeNumerically(">=", virtiofsdDisconnectGrace))
		Expect(status().Signal()).To(Equal(syscall.SIGKILL))
		Expect(logBuf.String()).To(ContainSubstring(fmt.Sprintf(`virtiofsd for the share at "%s" exited with status 0, but the hypervisor still ran %v later; killing the hypervisor`, shares[0], virtiofsdDisconnectGrace)))
		Expect(s.failureReason()).NotTo(BeEmpty())
	})

	It("does not fail a share whose virtiofsd exits 0 as QEMU exits", func() {
		s, _ := servers(vfsQuit, 1)
		// A grace far longer than the spec needs, so QEMU's reap always
		// comes within it.
		s.disconnectGrace = time.Minute
		Expect(s.start(nil)).To(Succeed())
		g, done, _ := guest()
		s.guestStarted(g.Process)
		Eventually(s.servers[0].exited, 5*time.Second).Should(BeClosed())
		Expect(g.Process.Kill()).To(Succeed())
		<-done
		s.hypervisorReaped()
		s.guestEnded()
		Expect(s.failureReason()).To(BeEmpty())
		Expect(logBuf.String()).NotTo(ContainSubstring("killing the hypervisor"))
	})

	It("takes QEMU's reap as the guest's end at once, however long run takes to return after it", func() {
		s, rec := servers(vfsServe, 1)
		Expect(s.start(nil)).To(Succeed())
		g, done, _ := guest()
		s.guestStarted(g.Process)
		pid := recordedPid(rec, 0)
		Expect(g.Process.Kill()).To(Succeed())
		<-done
		s.hypervisorReaped()
		// virtiofsd sees the disconnect and exits 0, and run is still
		// flushing the guest's output for longer than the disconnect grace.
		Expect(os.WriteFile(gone, nil, 0o600)).To(Succeed())
		Eventually(s.servers[0].exited, 5*time.Second).Should(BeClosed())
		Consistently(s.failureReason, 2*s.disconnectGrace).Should(BeEmpty())
		Expect(processGone(pid)).To(BeTrue())
		// The stop began at the reap, so guestEnded only waits for it.
		Expect(s.stopped).To(BeClosed())
		s.guestEnded()
		Expect(s.stopDone).To(BeClosed())
		Expect(logBuf.String()).NotTo(ContainSubstring("killing the hypervisor"))
	})

	It("gives a virtiofsd its stop grace when run stops it before the reap's own stop has begun", func() {
		s, rec := servers(vfsServe, 1)
		s.stopGrace = 5 * time.Second
		Expect(s.start(nil)).To(Succeed())
		g, done, _ := guest()
		s.guestStarted(g.Process)
		pid := recordedPid(rec, 0)
		Expect(g.Process.Kill()).To(Succeed())
		<-done
		// The reap is recorded, as hypervisorReaped does before it hands the
		// stop to a goroutine, and that goroutine has not run yet when run
		// returns from the supervisor and ends the servers itself. The
		// virtiofsd sees the disconnect a moment later, and run's stop must
		// wait for it and for its last line instead of killing it at once.
		_, first := s.markReaped()
		Expect(first).To(BeTrue())
		time.AfterFunc(200*time.Millisecond, func() { _ = os.WriteFile(gone, nil, 0o600) })
		s.guestEnded()
		Expect(processGone(pid)).To(BeTrue())
		Expect(s.servers[0].state.Success()).To(BeTrue())
		Expect(logBuf.String()).To(HaveSuffix("Client disconnected, shutting down\n"))
		Expect(logBuf.String()).NotTo(ContainSubstring("killing"))
	})

	It("kills QEMU as it starts when a virtiofsd has already ended", func() {
		s, _ := servers(vfsCrash, 1)
		Expect(s.start(nil)).To(Succeed())
		Eventually(s.failureReason, 5*time.Second).ShouldNot(BeEmpty())
		Expect(logBuf.String()).To(ContainSubstring(`virtiofsd for the share at "` + shares[0] + `" exited with status 3` + "\n"))
		g, done, status := guest()
		s.guestStarted(g.Process)
		Eventually(done, 5*time.Second).Should(BeClosed())
		Expect(status().Signal()).To(Equal(syscall.SIGKILL))
	})

	It("fails the share when a virtiofsd ends after it was ready, while the next one starts", func() {
		s, rec := servers(`if [ "$n" = 0 ]; then ready; sleep 0.1; exit 4; fi; sleep 0.6; ready; while :; do sleep 0.02; done`, 2)
		Expect(s.start(nil)).To(Succeed())
		Expect(s.failureReason()).To(Equal(`the share at "` + shares[0] + `" stopped being served before the guest reported a status`))
		Expect(strings.Count(logBuf.String(), `virtiofsd for the share at "`+shares[0]+`" exited with status 4`)).To(Equal(1))
		pid := recordedPid(rec, 1)
		s.stop(0)
		Expect(processGone(pid)).To(BeTrue())
	})

	It("kills the first virtiofsd when the second cannot start, and leaves none", func() {
		s, rec := servers(vfsSecondFails, 2)
		err := s.start(nil)
		Expect(err).To(MatchError(`virtiofsd for the share at "` + shares[1] + `" exited with status 1 before it was ready to serve the guest`))
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		Expect(processGone(recordedPid(rec, 0))).To(BeTrue())
		Expect(processGone(recordedPid(rec, 1))).To(BeTrue())
		// The second virtiofsd's own line comes before the error.
		Expect(logBuf.String()).To(HaveSuffix(`virtiofsd for "` + shares[1] + `": [2026-10-31T00:44:07Z ERROR virtiofsd] Error opening shared directory` + "\n"))
		Expect(s.failureReason()).To(BeEmpty())
	})

	It("gives up on a virtiofsd that does not become ready in time, and kills it", func() {
		s, rec := servers(vfsNeverReady, 1)
		began := time.Now()
		err := s.start(nil)
		Expect(err).To(MatchError(fmt.Sprintf(`virtiofsd for the share at "%s" did not report that it was ready within %v`, shares[0], virtiofsdReadyTimeout)))
		Expect(time.Since(began)).To(BeNumerically(">=", virtiofsdReadyTimeout))
		Expect(processGone(recordedPid(rec, 0))).To(BeTrue())
	})

	It("bounds the readiness of every share together", func() {
		s, rec := servers(`sleep 1.2; ready; while :; do sleep 0.02; done`, 2)
		err := s.start(nil)
		Expect(err).To(MatchError(ContainSubstring(`virtiofsd for the share at "` + shares[1] + `" did not report that it was ready`)))
		Expect(processGone(recordedPid(rec, 0))).To(BeTrue())
	})

	It("ends the wait at a signal, kills virtiofsd, and exits 128+N", func() {
		s, rec := servers(vfsNeverReady, 1)
		sigs := make(chan os.Signal, 1)
		go func() {
			defer GinkgoRecover()
			recordOf(rec, 0, "pid")
			sigs <- syscall.SIGTERM
		}()
		err := s.start(sigs)
		Expect(err).To(MatchError(`received terminated while starting virtiofsd for the share at "` + shares[0] + `"`))
		Expect(stepExitCode(err)).To(Equal(143))
		Expect(processGone(recordedPid(rec, 0))).To(BeTrue())
	})

	It("starts no virtiofsd for a share whose mount changed, and kills the ones before it", func() {
		s, rec := servers(vfsHang, 2)
		s.servers[1].grant.Mount.MountID = 99
		err := s.start(nil)
		Expect(errors.Is(err, errMountChanged)).To(BeTrue(), "%v", err)
		Expect(processGone(recordedPid(rec, 0))).To(BeTrue())
		Expect(filepath.Join(rec, "1")).NotTo(BeAnExistingFile())
	})

	It("reports a virtiofsd that cannot be started, and closes its socket", func() {
		s, _ := servers(vfsHang, 1)
		Expect(os.Chmod(s.path, 0o644)).To(Succeed())
		before := openFDs()
		err := s.start(nil)
		Expect(err).To(MatchError(ContainSubstring(`starting virtiofsd for the share at "` + shares[0] + `"`)))
		Expect(errors.Is(err, os.ErrPermission)).To(BeTrue(), "%v", err)
		Expect(s.servers[0].listener).To(BeNil())
		Expect(openFDs()).To(BeNumerically("<", before))
	})

	It("does nothing without a share", func() {
		s, err := newShareServers("", workDir, nil, logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.start(nil)).To(Succeed())
		Expect(s.sockets()).To(BeEmpty())
		s.guestEnded()
		s.stop(0)
		Expect(s.failureReason()).To(BeEmpty())
		Expect(os.ReadDir(workDir)).To(BeEmpty())
		Expect(logBuf.String()).To(BeEmpty())
	})
})

// quietSleep keeps a fake QEMU running without a child that holds its
// output open, as real QEMU has none: vm-launch reads the hypervisor's output
// to its end, which a child left running by SIGKILL would delay.
const quietSleep = "sleep 30 </dev/null >/dev/null 2>&1"

// writeShareHypervisor replaces the executable at path with a fake QEMU that
// records its argv, its pid, and the volume entries of the initramfs's
// /rvm/mounts and /rvm/disks, in that order, runs before, reports guest status 0 under the initramfs's nonce,
// runs after, and creates gone as it exits.
func writeShareHypervisor(path, before, after, gone string) string {
	argvFile := path + ".argv"
	script := `#!/bin/bash
printf '%s\n' "$@" > ` + shellQuote(argvFile) + `
echo $$ > ` + shellQuote(path+".pid") + `
trap 'touch ` + shellQuote(gone) + `' EXIT
for a in "$@"; do
	case "$prev" in -initrd) initrd=$a ;; esac
	prev=$a
done
nonce=$(gzip -dc "$initrd" | grep -a -o 'RVM_START_[0-9a-f]*' | head -n 1 | cut -d_ -f3)
gzip -dc "$initrd" | grep -a -o "RVM_VOL[0-9][0-9]*_[A-Z]*=[^[:space:]]*" > ` + shellQuote(path+".volume") + `
` + before + `
echo "RVM_START_$nonce"
echo "RVM_EXIT_$nonce=0"
` + after + `
`
	Expect(os.Remove(path)).To(Succeed())
	Expect(os.WriteFile(path, []byte(script), 0o755)).To(Succeed())
	return argvFile
}

var _ = Describe("run with a granted share", func() {
	var (
		art      string
		hv       string
		tmp      string
		shareDir string
		infoDir  string
		gone     string
		logBuf   *safeBuffer
	)

	BeforeEach(func() {
		shortVirtiofsdTimes()
		art = makeArtifacts()
		hv = filepath.Join(art, artQEMULoader)
		shareDir = GinkgoT().TempDir()
		infoDir = GinkgoT().TempDir()
		gone = filepath.Join(GinkgoT().TempDir(), "gone")
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		GinkgoT().Setenv("CF_INSTANCE_INDEX", "2")
		GinkgoT().Setenv("VCAP_APPLICATION", vcapApp)
		DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)
		mountInfoPath = filepath.Join(infoDir, "mountinfo")
		Expect(os.WriteFile(mountInfoPath, []byte(mountinfoLine(40, shareDir, "fuse.juicefs")), 0o644)).To(Succeed())
		GinkgoT().Setenv("VCAP_SERVICES", `{"juicefs":[{"name":"b","credentials":{"password":"`+secretSentinel+`"},"volume_mounts":[`+mountJSON(shareDir, "rw")+`]}]}`)
		GinkgoT().Setenv("VM_VOLUMES", `{"`+shareDir+`":{"mode":"share"}}`)
		logBuf = &safeBuffer{}

		saved := defaultImageOptions
		DeferCleanup(func() { defaultImageOptions = saved })
		defaultImageOptions.IsMountRoot = alwaysMountRoot
		defaultImageOptions.LockWait = 300 * time.Millisecond
		defaultImageOptions.LockPoll = 20 * time.Millisecond
	})

	runWith := func(vfs string) int {
		argv := []string{"--backend", "vm-qemu", "--allow-volume-shares", "--artifacts", art}
		if vfs != "" {
			argv = append(argv, "--virtiofsd-path", vfs)
		}
		argv = append(argv, "--", "/tmp/lifecycle/launcher", "app", "true", "")
		return run(argv, log.New(logBuf, "", 0))
	}

	It("refuses a share on Firecracker before anything starts, though a virtiofsd is given", func() {
		vfs, rec := fakeVirtiofsd(vfsServe, gone)
		argvFile := writeShareHypervisor(hv, "", "", gone)
		argv := []string{"--backend", "vm-firecracker", "--allow-volume-shares", "--artifacts", art, "--virtiofsd-path", vfs,
			"--", "/tmp/lifecycle/launcher", "app", "true", ""}
		Expect(run(argv, log.New(logBuf, "", 0))).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal(`VM_VOLUMES ` + quoteForLog(shareDir) + ` mode "share" is not available on vm-firecracker, which has no virtiofs device; shares need the vm-qemu backend` + "\n"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(rec)).To(BeEmpty())
		Expect(workDirsIn(tmp)).To(BeEmpty())
	})

	It("keeps the missing virtiofsd's own line", func() {
		Expect(runWith("")).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal(`VM_VOLUMES "` + shareDir + `" is granted a share, but vm-launch was not given --virtiofsd-path, so nothing can serve it; the operator must install virtiofsd and pass its path` + "\n"))
	})

	It("boots a granted share, serves it with virtiofsd, gives the volume no image, and leaves nothing behind", func() {
		// The fake ends within moments of seeing QEMU go. A grace that a
		// loaded machine cannot spend keeps its clean end from being a kill.
		virtiofsdStopGrace = 5 * time.Second
		vfs, rec := fakeVirtiofsd(vfsServe, gone)
		argvFile := writeShareHypervisor(hv, "", "", gone)
		Expect(runWith(vfs)).To(Equal(0), logBuf.String())
		argv := strings.Split(strings.TrimSpace(readRecord(rec, 0, "argv")), "\n")
		Expect(argv[len(argv)-1]).To(Equal("--shared-dir=" + shareDir))
		Expect(processGone(recordedPid(rec, 0))).To(BeTrue())
		// The socket lived in the work directory, which is gone.
		Expect(readRecord(rec, 0, "unix")).To(MatchRegexp(regexpQuote(tmp) + `/vm-launch-[^/]+/rvm-vol0\.sock`))
		Expect(workDirsIn(tmp)).To(BeEmpty())
		Expect(os.ReadDir(shareDir)).To(BeEmpty())
		// The guest is told of the share at its volume index, with no drive,
		// and QEMU gets no drive for it.
		Expect(os.ReadFile(hv + ".volume")).To(Equal([]byte("RVM_VOL0_KIND=share\nRVM_VOL0_PATH=" + shellQuote(shareDir) + "\n" +
			"RVM_VOL0_KIND=share\n")))
		hvArgv, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(hvArgv)).NotTo(ContainSubstring("virtio-blk-device"))
		Expect(string(hvArgv)).To(ContainSubstring("vhost-user-fs-device,chardev=fs0,tag=rvm-vol0\n"))
		Expect(logBuf.String()).To(ContainSubstring(`virtiofsd for "` + shareDir + `": ` + virtiofsdReady + "\n"))
		Expect(logBuf.String()).To(ContainSubstring("Client disconnected, shutting down\n"))
		Expect(logBuf.String()).NotTo(ContainSubstring("killing"))
		Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel))
	})

	It("stops the guest when virtiofsd dies, and exits 125 with a line that names the share", func() {
		vfs, rec := fakeVirtiofsd(vfsCrash, gone)
		writeShareHypervisor(hv, quietSleep, "", gone)
		began := time.Now()
		Expect(runWith(vfs)).To(Equal(exitLaunchError), logBuf.String())
		Expect(time.Since(began)).To(BeNumerically("<", 10*time.Second))
		pid, err := os.ReadFile(hv + ".pid")
		Expect(err).NotTo(HaveOccurred())
		qemu, err := strconv.Atoi(strings.TrimSpace(string(pid)))
		Expect(err).NotTo(HaveOccurred())
		Expect(processGone(qemu)).To(BeTrue())
		Expect(processGone(recordedPid(rec, 0))).To(BeTrue())
		Expect(logBuf.String()).To(ContainSubstring(`virtiofsd for the share at "` + shareDir + `" exited with status 3; killing the hypervisor` + "\n"))
		Expect(logBuf.String()).To(HaveSuffix(`the share at "` + shareDir + `" stopped being served before the guest reported a status; exiting 125` + "\n"))
		Expect(workDirsIn(tmp)).To(BeEmpty())
	})

	It("keeps the guest's status when virtiofsd fails after the guest reported it", func() {
		vfs, _ := fakeVirtiofsd(`ready; while [ ! -e "$GONE.reported" ]; do sleep 0.01; done; exit 3`, gone)
		writeShareHypervisor(hv, "", "touch "+shellQuote(gone+".reported")+"; "+quietSleep, gone)
		Expect(runWith(vfs)).To(Equal(0), logBuf.String())
		Expect(logBuf.String()).To(ContainSubstring(`exited with status 3; killing the hypervisor`))
		Expect(logBuf.String()).NotTo(ContainSubstring("exiting 125"))
	})

	It("refuses before it boots when the virtiofsd path is missing", func() {
		vfs, rec := fakeVirtiofsd(vfsServe, gone)
		Expect(os.Remove(vfs)).To(Succeed())
		argvFile := writeShareHypervisor(hv, "", "", gone)
		Expect(runWith(vfs)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal("virtiofsd for shares: stat " + vfs + ": no such file or directory\n"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(rec)).To(BeEmpty())
		Expect(workDirsIn(tmp)).To(BeEmpty())
	})

	It("does not boot when virtiofsd cannot start serving", func() {
		vfs, _ := fakeVirtiofsd(vfsNeverReady, gone)
		argvFile := writeShareHypervisor(hv, "", "", gone)
		Expect(runWith(vfs)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(HaveSuffix(fmt.Sprintf(`virtiofsd for the share at "%s" did not report that it was ready within %v`+"\n", shareDir, virtiofsdReadyTimeout)))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(workDirsIn(tmp)).To(BeEmpty())
	})

	It("does not boot when the share's mount changed", func() {
		vfs, rec := fakeVirtiofsd(vfsServe, gone)
		argvFile := writeShareHypervisor(hv, "", "", gone)
		dirProbe = func(int, string) (mountProbe, error) { return mountProbe{MountID: 41, MountRoot: true}, nil }
		Expect(runWith(vfs)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(HaveSuffix(`the mount of the share at "` + shareDir + `" changed during start: it was mount ID 40 when vm-launch inspected it and is mount ID 41 now` + "\n"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(rec)).To(BeEmpty())
	})

	DescribeTable("gives a private volume beside the share its image, and the share none, and numbers both by volume index",
		func(shareFirst bool) {
			// Volumes are numbered in path order, and a path sorts before the
			// same path with more after it.
			privDir := shareDir + "-private"
			made := privDir
			if !shareFirst {
				privDir, shareDir = shareDir, shareDir+"-share"
				made = shareDir
				GinkgoT().Setenv("VM_VOLUMES", `{"`+shareDir+`":{"mode":"share"}}`)
			}
			Expect(os.Mkdir(made, 0o755)).To(Succeed())
			DeferCleanup(os.RemoveAll, made)
			shareIndex, privIndex := 0, 1
			if !shareFirst {
				shareIndex, privIndex = 1, 0
			}
			Expect(os.WriteFile(mountInfoPath, []byte(mountinfoLine(40, shareDir, "fuse.juicefs")+mountinfoLine(41, privDir, "fuse.juicefs")), 0o644)).To(Succeed())
			GinkgoT().Setenv("VCAP_SERVICES", `{"juicefs":[{"name":"b","credentials":{"password":"`+secretSentinel+`"},"volume_mounts":[`+mountJSON(shareDir, "rw")+`,`+mountJSON(privDir, "rw")+`]}]}`)
			vfs, rec := fakeVirtiofsd(vfsServe, gone)
			argvFile := writeShareHypervisor(hv, "", "", gone)
			Expect(runWith(vfs)).To(Equal(0), logBuf.String())

			Expect(os.ReadDir(shareDir)).To(BeEmpty())
			image := filepath.Join(privDir, "rvm-disk-"+testAppID+"-web-2.img")
			Expect(image).To(BeAnExistingFile())
			Expect(readRecord(rec, 0, "argv")).To(ContainSubstring("--shared-dir=" + shareDir + "\n"))
			Expect(readRecord(rec, 0, "unix")).To(ContainSubstring("/" + shareTag(shareIndex) + ".sock"))
			Expect(filepath.Join(rec, "1")).NotTo(BeAnExistingFile())

			// The share keeps its volume index and has no drive. The private
			// volume keeps its own, on the one drive, whose serial carries
			// the same number, so no drive takes the share's number.
			entries := func(n int, share, private string) string {
				if n == shareIndex {
					return share
				}
				return private
			}
			shareMount := fmt.Sprintf("RVM_VOL%d_KIND=share\nRVM_VOL%d_PATH=%s\n", shareIndex, shareIndex, shellQuote(shareDir))
			privMount := fmt.Sprintf("RVM_VOL%d_KIND=image\nRVM_VOL%d_PATH=%s\nRVM_VOL%d_IMAGE=%s\n", privIndex, privIndex, shellQuote(privDir), privIndex, shellQuote(filepath.Base(image)))
			shareDisk := fmt.Sprintf("RVM_VOL%d_KIND=share\n", shareIndex)
			privDisk := fmt.Sprintf("RVM_VOL%d_KIND=image\nRVM_VOL%d_ID=rvm-vol%d\nRVM_VOL%d_SECTORS=%d\n", privIndex, privIndex, privIndex, privIndex, defaultImageSize/sectorBytes)
			Expect(os.ReadFile(hv + ".volume")).To(Equal([]byte(
				entries(0, shareMount, privMount) + entries(1, shareMount, privMount) +
					entries(0, shareDisk, privDisk) + entries(1, shareDisk, privDisk))))
			argv, err := os.ReadFile(argvFile)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.Count(string(argv), "virtio-blk-device")).To(Equal(1))
			Expect(string(argv)).To(ContainSubstring(fmt.Sprintf(",serial=rvm-vol%d\n", privIndex)))
			Expect(string(argv)).NotTo(ContainSubstring(fmt.Sprintf("serial=rvm-vol%d", shareIndex)))
		},
		Entry("with the share first in path order", true),
		Entry("with the share second in path order", false),
	)
})

// workDirsIn returns the vm-launch work directories left in dir.
func workDirsIn(dir string) []string {
	matches, err := filepath.Glob(filepath.Join(dir, "vm-launch-*"))
	Expect(err).NotTo(HaveOccurred())
	return matches
}

// regexpQuote quotes s for a regular expression.
func regexpQuote(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

var _ = Describe("a vm-launch process serving a share", func() {
	var (
		art      string
		hv       string
		shareDir string
		info     string
		gone     string
		started  string
	)

	BeforeEach(func() {
		art = makeArtifacts()
		hv = filepath.Join(art, artQEMULoader)
		shareDir = GinkgoT().TempDir()
		gone = filepath.Join(GinkgoT().TempDir(), "gone")
		started = filepath.Join(GinkgoT().TempDir(), "started")
		info = writeTempFile("mountinfo", mountinfoLine(40, shareDir, "fuse.juicefs"))
	})

	// launch starts this test binary as a vm-launch that serves the share
	// with the vfs, with its stderr in the returned buffer.
	launch := func(vfs string) (*exec.Cmd, *safeBuffer) {
		self, err := os.Executable()
		Expect(err).NotTo(HaveOccurred())
		cmd := exec.Command(self, "--backend", "vm-qemu", "--allow-volume-shares", "--virtiofsd-path", vfs, "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", "")
		stderr := &safeBuffer{}
		cmd.Stderr = stderr
		cmd.Env = []string{
			helperShareRun + "=1", helperShareMountInfo + "=" + info,
			"TMPDIR=" + GinkgoT().TempDir(), "PATH=" + os.Getenv("PATH"), quickRaceExit(),
			"CF_INSTANCE_INDEX=2", "VCAP_APPLICATION=" + vcapApp, "MEMORY_LIMIT=512m",
			`VCAP_SERVICES={"juicefs":[{"name":"b","volume_mounts":[` + mountJSON(shareDir, "rw") + `]}]}`,
			`VM_VOLUMES={"` + shareDir + `":{"mode":"share"}}`,
		}
		Expect(cmd.Start()).To(Succeed())
		DeferCleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd, stderr
	}

	qemuPid := func() int {
		waitForFile(hv + ".pid")
		b, err := os.ReadFile(hv + ".pid")
		Expect(err).NotTo(HaveOccurred())
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		Expect(err).NotTo(HaveOccurred())
		return pid
	}

	// drainingGuest is a fake QEMU whose guest command runs until the stop
	// request comes, drains for 0.3 s, and reports status 0.
	drainingGuest := func() {
		Expect(os.Remove(hv)).To(Succeed())
		script := `#!/bin/bash
echo $$ > ` + shellQuote(hv+".pid") + `
trap 'touch ` + shellQuote(gone) + `' EXIT
for a in "$@"; do
	case "$prev" in -initrd) initrd=$a ;; esac
	prev=$a
done
nonce=$(gzip -dc "$initrd" | grep -a -o 'RVM_START_[0-9a-f]*' | head -n 1 | cut -d_ -f3)
echo "RVM_START_$nonce"
touch ` + shellQuote(started) + `
IFS= read -r line
sleep 0.3
echo "RVM_EXIT_$nonce=0"
`
		Expect(os.WriteFile(hv, []byte(script), 0o755)).To(Succeed())
	}

	// sinceGone returns how long ago the fake QEMU exited, from the time it
	// touched gone.
	sinceGone := func() time.Duration {
		info, err := os.Stat(gone)
		Expect(err).NotTo(HaveOccurred())
		return time.Since(info.ModTime())
	}

	It("drains at SIGTERM with virtiofsd serving, and then stops it, within the stop budget", func(ctx SpecContext) {
		vfs, rec := fakeVirtiofsd(vfsServe, gone)
		drainingGuest()
		cmd, stderr := launch(vfs)
		waitForFile(started)
		vpid := recordedPid(rec, 0)
		began := time.Now()
		Expect(cmd.Process.Signal(syscall.SIGTERM)).To(Succeed())
		err := cmd.Wait()
		Expect(err).NotTo(HaveOccurred(), stderr.String())
		// The guest drains in 0.3 s, and from QEMU's exit on, vm-launch
		// takes no more than the stop grace and the kill wait.
		Expect(sinceGone()).To(BeNumerically("<", virtiofsdStopGrace+virtiofsdKillWait))
		Expect(time.Since(began)).To(BeNumerically("<", 300*time.Millisecond+virtiofsdStopGrace+virtiofsdKillWait+time.Second))
		Expect(processGone(vpid)).To(BeTrue())
		Expect(processGone(qemuPid())).To(BeTrue())
		Expect(stderr.String()).To(ContainSubstring("asking the guest command to stop"))
		Expect(stderr.String()).To(ContainSubstring("Client disconnected, shutting down"))
	}, SpecTimeout(time.Minute))

	It("kills at the end of a drain a virtiofsd that ignores SIGTERM and never ends", func(ctx SpecContext) {
		vfs, rec := fakeVirtiofsd(vfsHang, gone)
		drainingGuest()
		cmd, stderr := launch(vfs)
		waitForFile(started)
		vpid := recordedPid(rec, 0)
		// A stop that signals every process of the container reaches
		// virtiofsd too, which ignores it and keeps serving the drain.
		Expect(syscall.Kill(vpid, syscall.SIGTERM)).To(Succeed())
		Expect(cmd.Process.Signal(syscall.SIGTERM)).To(Succeed())
		Consistently(func() bool { return processEnded(vpid) }, 200*time.Millisecond).Should(BeFalse())
		Expect(cmd.Wait()).To(Succeed(), stderr.String())
		// From QEMU's exit on, vm-launch waits the stop grace, sends
		// SIGKILL, and is done within the kill wait.
		Expect(sinceGone()).To(BeNumerically(">=", virtiofsdStopGrace))
		Expect(sinceGone()).To(BeNumerically("<", virtiofsdStopGrace+virtiofsdKillWait))
		Expect(processGone(vpid)).To(BeTrue())
		Expect(stderr.String()).NotTo(ContainSubstring("did not end"))
		Expect(stderr.String()).NotTo(ContainSubstring("killing the hypervisor"))
	}, SpecTimeout(time.Minute))

	It("does not take a virtiofsd that exits 0 as QEMU exits for a failure while stdout holds the guest's last output", func(ctx SpecContext) {
		// The guest writes more than a pipe holds and then reports status
		// 0. Nothing reads vm-launch's stdout, so the flush of that output
		// takes the whole flush timeout, longer than the disconnect grace.
		Expect(os.Remove(hv)).To(Succeed())
		script := `#!/bin/bash
echo $$ > ` + shellQuote(hv+".pid") + `
trap 'touch ` + shellQuote(gone) + `' EXIT
for a in "$@"; do
	case "$prev" in -initrd) initrd=$a ;; esac
	prev=$a
done
nonce=$(gzip -dc "$initrd" | grep -a -o 'RVM_START_[0-9a-f]*' | head -n 1 | cut -d_ -f3)
echo "RVM_START_$nonce"
head -c 300000 /dev/zero | tr '\0' x
echo
echo "RVM_EXIT_$nonce=0"
`
		Expect(os.WriteFile(hv, []byte(script), 0o755)).To(Succeed())
		vfs, _ := fakeVirtiofsd(vfsServe, gone)
		stdoutR, stdoutW, err := os.Pipe()
		Expect(err).NotTo(HaveOccurred())
		defer stdoutR.Close()
		self, err := os.Executable()
		Expect(err).NotTo(HaveOccurred())
		cmd := exec.Command(self, "--backend", "vm-qemu", "--allow-volume-shares", "--virtiofsd-path", vfs, "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", "")
		stderr := &safeBuffer{}
		cmd.Stdout, cmd.Stderr = stdoutW, stderr
		cmd.Env = []string{
			helperShareRun + "=1", helperShareMountInfo + "=" + info, helperShareDisconnectGrace + "=100ms",
			"TMPDIR=" + GinkgoT().TempDir(), "PATH=" + os.Getenv("PATH"), quickRaceExit(),
			"CF_INSTANCE_INDEX=2", "VCAP_APPLICATION=" + vcapApp, "MEMORY_LIMIT=512m",
			`VCAP_SERVICES={"juicefs":[{"name":"b","volume_mounts":[` + mountJSON(shareDir, "rw") + `]}]}`,
			`VM_VOLUMES={"` + shareDir + `":{"mode":"share"}}`,
		}
		Expect(cmd.Start()).To(Succeed())
		Expect(stdoutW.Close()).To(Succeed())
		DeferCleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		Expect(cmd.Wait()).To(Succeed(), stderr.String())
		Expect(stderr.String()).To(ContainSubstring("stdout did not take the guest's last output within " + outputFlushTimeout.String()))
		Expect(stderr.String()).To(ContainSubstring("Client disconnected, shutting down"))
		Expect(stderr.String()).NotTo(ContainSubstring("still ran"))
		Expect(stderr.String()).NotTo(ContainSubstring("killing the hypervisor"))
		Expect(stderr.String()).NotTo(ContainSubstring("stopped being served"))
	}, SpecTimeout(time.Minute))

	It("takes QEMU and virtiofsd with it when vm-launch is killed", func(ctx SpecContext) {
		vfs, rec := fakeVirtiofsd(vfsHang, gone)
		writeShareHypervisor(hv, "touch "+shellQuote(started)+"; "+quietSleep, "", gone)
		cmd, _ := launch(vfs)
		waitForFile(started)
		vpid, qemu := recordedPid(rec, 0), qemuPid()
		Expect(cmd.Process.Kill()).To(Succeed())
		_ = cmd.Wait()
		// Whatever adopts them once vm-launch is gone may never reap them,
		// so an ended process counts here, a zombie included.
		Eventually(func() bool { return processEnded(vpid) && processEnded(qemu) }, 5*time.Second, 20*time.Millisecond).Should(BeTrue())
	}, SpecTimeout(time.Minute))
})
