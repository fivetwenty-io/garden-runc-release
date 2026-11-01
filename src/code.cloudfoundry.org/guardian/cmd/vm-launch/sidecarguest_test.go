//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// probeToolsBin is guestToolsBin with probe, the host's cat under a name
// that no busybox applet has. The guest's busybox runs its own cat as an
// applet inside the shell's process, so only a program that the kernel
// execs shows, in its /proc/self/status, the signal dispositions that the
// shell gave it.
func probeToolsBin(shell guestShell) string {
	bin := guestToolsBin(shell)
	cat, err := exec.LookPath("cat")
	Expect(err).NotTo(HaveOccurred())
	Expect(os.Symlink(cat, filepath.Join(bin, "probe"))).To(Succeed())
	return bin
}

// quoteArgs quotes each argument for the shell, as an argv file holds them.
func quoteArgs(args ...string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}

// stubGuestExec stands in for the stack's guestExec: it sources each of the
// process's env files, enters its working directory, and execs its argv.
func stubGuestExec(p guestProcess) string {
	line := ""
	for _, env := range p.envPaths {
		line += ". " + env + " && "
	}
	return line + "cd " + p.dir + ` && eval "set -- $(cat ` + p.argvPath + `)" && exec "$@"`
}

// sectionProcs writes, for each script, an argv file that runs it with
// sh -c, and returns the processes, the app first. Every process sources
// appEnv, and each sidecar then sources its entry of sidecarEnvs, when it
// has one. Each process has a scratch directory of its own as its working
// directory, named p<index> in dir, where its script keeps its files.
func sectionProcs(dir string, scripts []string, appEnv string, sidecarEnvs ...string) []guestProcess {
	appEnvPath := filepath.Join(dir, "app.env")
	Expect(os.WriteFile(appEnvPath, []byte(appEnv), 0o600)).To(Succeed())
	procs := make([]guestProcess, len(scripts))
	for i, script := range scripts {
		own := filepath.Join(dir, "p"+strconv.Itoa(i))
		Expect(os.Mkdir(own, 0o755)).To(Succeed())
		p := guestProcess{
			index:    i,
			argvPath: filepath.Join(own, "argv"),
			envPaths: []string{appEnvPath},
			dir:      own,
			pidPath:  filepath.Join(own, "pid"),
		}
		Expect(os.WriteFile(p.argvPath, []byte(quoteArgs("sh", "-c", script, "proc"+strconv.Itoa(i))+"\n"), 0o600)).To(Succeed())
		if i > 0 && i <= len(sidecarEnvs) {
			envPath := filepath.Join(own, "env")
			Expect(os.WriteFile(envPath, []byte(sidecarEnvs[i-1]), 0o600)).To(Succeed())
			p.envPaths = append(p.envPaths, envPath)
		}
		procs[i] = p
	}
	return procs
}

// sectionRun is the run section running in a real shell, with a FIFO as
// the console that the spec writes console input to, and every guest path
// it uses in a scratch directory.
type sectionRun struct {
	cmd      *exec.Cmd
	out      string
	acks     string
	root     string
	mountLog string
	console  *os.File
	done     chan error
}

// startSection runs guestRunSection for procs in shell with stubGuestExec,
// and then prints the status it left. With identity set, the boot pair is
// pair, and mount logs its arguments in place of mounting. prepare, when it
// is set, runs just before the shell starts.
func startSection(shell guestShell, procs []guestProcess, identity bool, pair testIdentityPair, prepare func(r *sectionRun)) *sectionRun {
	dir := GinkgoT().TempDir()
	r := &sectionRun{
		out:      filepath.Join(dir, "out"),
		acks:     filepath.Join(dir, "acks"),
		root:     filepath.Join(dir, "root"),
		mountLog: filepath.Join(dir, "mount.log"),
		done:     make(chan error, 1),
	}
	Expect(os.Mkdir(r.root, 0o755)).To(Succeed())
	crtPath, keyPath := filepath.Join(dir, "instance.crt"), filepath.Join(dir, "instance.key")
	if identity {
		Expect(os.WriteFile(crtPath, pair.crt, 0o600)).To(Succeed())
		Expect(os.WriteFile(keyPath, pair.key, 0o600)).To(Succeed())
	}
	fifo := filepath.Join(dir, "console")
	Expect(syscall.Mkfifo(fifo, 0o600)).To(Succeed())
	console, err := os.OpenFile(fifo, os.O_RDWR, 0)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { _ = console.Close() })
	r.console = console

	section := guestRunSection(testNonce, procs, identity, stubGuestExec)
	script := strings.NewReplacer(
		guestEvents, filepath.Join(dir, "events"),
		"</dev/console", "<"+fifo,
		">/dev/console", ">>"+r.acks,
		"/proc/self/oom_score_adj", filepath.Join(dir, "oom_score_adj"),
		guestIdentityCert, crtPath,
		guestIdentityKey, keyPath,
		guestIdentityNext, filepath.Join(dir, "next"),
		guestAppRootEtc, filepath.Join(r.root, "etc"),
		"reboot -nf", "echo REBOOT",
	).Replace("RVM_NOFILE_SOFT=$(ulimit -S -n)\nRVM_NOFILE_HARD=$(ulimit -H -n)\n" + guestFailFunc +
		`mount() { echo "mount $*" >>` + r.mountLog + `; }
` + section + "echo \"status=$rvm_status\"\n")

	out, err := os.Create(r.out)
	Expect(err).NotTo(HaveOccurred())
	defer out.Close()
	r.cmd = exec.Command(shell.argv[0], append(shell.argv[1:], "-c", script)...)
	r.cmd.Env = []string{"PATH=" + probeToolsBin(shell)}
	r.cmd.Stdout = out
	r.cmd.Stderr = out
	r.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if prepare != nil {
		prepare(r)
	}
	Expect(r.cmd.Start()).To(Succeed())
	pgid := r.cmd.Process.Pid
	go func() { r.done <- r.cmd.Wait() }()
	DeferCleanup(func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) })
	return r
}

// credDir is where the run's app root holds the instance identity.
func (r *sectionRun) credDir() string {
	return filepath.Join(r.root, "etc", "cf-instance-credentials")
}

// output returns what the run has printed so far.
func (r *sectionRun) output() string {
	out, err := os.ReadFile(r.out)
	Expect(err).NotTo(HaveOccurred())
	return string(out)
}

// finish waits up to limit for the shell to exit and returns its output.
// Nothing of the run may outlive the shell.
func (r *sectionRun) finish(limit time.Duration) string {
	select {
	case err := <-r.done:
		Expect(err).NotTo(HaveOccurred(), r.output())
	case <-time.After(limit):
		Fail(fmt.Sprintf("the run did not end within %v:\n%s", limit, r.output()))
	}
	out := r.output()
	pgid := r.cmd.Process.Pid
	Eventually(func() string { return groupProcesses(pgid) }, 2*time.Second, 10*time.Millisecond).
		Should(BeEmpty(), "processes of the run outlived it, after it printed:\n"+out)
	return out
}

// groupProcesses lists the processes in process group pgid that have not
// exited, one line each with its pid and its command line. It leaves out
// zombies: a process that a signal ended can leave a child that outlives it
// by a moment, and the init of the spec's container never reaps that child
// once it exits, as stage 2 does in the guest, where it is init.
func groupProcesses(pgid int) string {
	stats, _ := filepath.Glob("/proc/[0-9]*/stat")
	list := ""
	for _, stat := range stats {
		raw, err := os.ReadFile(stat)
		if err != nil {
			continue
		}
		// The fields after the command's closing parenthesis start with the
		// state, the parent's pid, and the process group.
		fields := strings.Fields(string(raw[strings.LastIndexByte(string(raw), ')')+1:]))
		if len(fields) < 3 || fields[0] == "Z" || fields[2] != strconv.Itoa(pgid) {
			continue
		}
		cmdline, _ := os.ReadFile(filepath.Join(filepath.Dir(stat), "cmdline"))
		list += filepath.Base(filepath.Dir(stat)) + " " + strings.ReplaceAll(strings.TrimRight(string(cmdline), "\x00"), "\x00", " ") + "\n"
	}
	return list
}

// processFile waits until process index of procs has written the file name
// in its directory, ending in a newline, and returns it.
func processFile(procs []guestProcess, index int, name string) string {
	path := filepath.Join(procs[index].dir, name)
	var text string
	Eventually(func() string {
		raw, _ := os.ReadFile(path)
		text = string(raw)
		return text
	}, 10*time.Second, 10*time.Millisecond).Should(HaveSuffix("\n"), path)
	return text
}

// The scripts of the processes. startScript first has probe write its
// /proc/self/status (see probeToolsBin), so that sigs holds the signal dispositions that a
// program the process starts gets, and then writes the process's pid, its
// working directory, and A and B from its environment to start. termScript then waits for SIGTERM and exits with the
// given status on it, and deafScript ignores SIGTERM.
const startScript = `probe /proc/self/status >sigs; echo "pid=$$ dir=$(pwd) A=${A-unset} B=${B-unset}" >start; `

// ignoredSignals returns the SigIgn line of a /proc/<pid>/status.
func ignoredSignals(status string) string {
	for _, line := range strings.Split(status, "\n") {
		if mask, ok := strings.CutPrefix(line, "SigIgn:"); ok {
			return strings.TrimSpace(mask)
		}
	}
	Fail("no SigIgn line in:\n" + status)
	return ""
}

func termScript(status int) string {
	return startScript + `trap 'echo term >term; exit ` + strconv.Itoa(status) + `' TERM; while :; do sleep 0.05; done`
}

const deafScript = startScript + `trap '' TERM; while :; do sleep 0.05; done`

// exitAfterScript waits until each of the processes in others has written
// its start file and then exits with status.
func exitAfterScript(status int, others ...int) string {
	waits := ""
	for _, other := range others {
		waits += "until [ -s ../p" + strconv.Itoa(other) + "/start ]; do sleep 0.05; done; "
	}
	return startScript + waits + "exit " + strconv.Itoa(status)
}

var _ = Describe("the run section", func() {
	appEnv := "export A=app\nexport B=base\n"

	// foregroundIgnored is the SigIgn mask of a program that shell runs in
	// the foreground, in a subshell that execs it, as stage 2 runs the single
	// command.
	foregroundIgnored := func(shell guestShell) string {
		cmd := exec.Command(shell.argv[0], append(shell.argv[1:], "-c", `( exec probe /proc/self/status )`)...)
		cmd.Env = []string{"PATH=" + probeToolsBin(shell)}
		out, err := cmd.Output()
		Expect(err).NotTo(HaveOccurred())
		ignored := ignoredSignals(string(out))
		mask, err := strconv.ParseUint(ignored, 16, 64)
		Expect(err).NotTo(HaveOccurred())
		Expect(mask&(1<<(syscall.SIGINT-1)|1<<(syscall.SIGQUIT-1))).To(BeZero(), "a foreground command ignores SIGINT or SIGQUIT")
		return ignored
	}

	DescribeTable("starts the app and its sidecars with their own argv and environment, and a sidecar's exit gives its status and stops the others with SIGTERM",
		func(shellOf func() guestShell) {
			shell := shellOf()
			ignored := foregroundIgnored(shell)
			procs := sectionProcs(GinkgoT().TempDir(), []string{termScript(143), termScript(143), exitAfterScript(3, 0, 1)},
				appEnv, "export B='one two'\nunset A\n", "export B=two\n")
			r := startSection(shell, procs, false, testIdentityPair{}, nil)
			Expect(r.finish(10*time.Second)).To(Equal("vm-launch guest: sidecar 2 exited with status 3; stopping the app and the other sidecar\nstatus=3\n"), shell.name)

			for i, want := range []string{"A=app B=base", "A=unset B=one two", "A=app B=two"} {
				pid := strings.TrimSpace(processFile(procs, i, "pid"))
				Expect(processFile(procs, i, "start")).To(Equal("pid="+pid+" dir="+procs[i].dir+" "+want+"\n"), "process %d", i)
				sigs, err := os.ReadFile(filepath.Join(procs[i].dir, "sigs"))
				Expect(err).NotTo(HaveOccurred())
				Expect(ignoredSignals(string(sigs))).To(Equal(ignored), "process %d", i)
			}
			for _, i := range []int{0, 1} {
				Expect(processFile(procs, i, "term")).To(Equal("term\n"), "process %d", i)
			}
			Expect(filepath.Join(procs[2].dir, "term")).NotTo(BeAnExistingFile())
		},
		shellEntries(""),
	)

	DescribeTable("names the app and stops the sidecar when the app exits first",
		func(shellOf func() guestShell) {
			shell := shellOf()
			procs := sectionProcs(GinkgoT().TempDir(), []string{exitAfterScript(0, 1), termScript(143)}, appEnv)
			r := startSection(shell, procs, false, testIdentityPair{}, nil)
			Expect(r.finish(10*time.Second)).To(Equal("vm-launch guest: the app exited with status 0; stopping the sidecar\nstatus=0\n"), shell.name)
			Expect(processFile(procs, 1, "term")).To(Equal("term\n"))
		},
		shellEntries(""),
	)

	DescribeTable("gives the app's status when vm-launch asks for a stop, and signals every process",
		func(shellOf func() guestShell) {
			shell := shellOf()
			procs := sectionProcs(GinkgoT().TempDir(), []string{termScript(7), termScript(9), termScript(11)}, appEnv)
			r := startSection(shell, procs, false, testIdentityPair{}, nil)
			for i := range procs {
				processFile(procs, i, "start")
			}
			_, err := r.console.WriteString(stopTag(testNonce) + "\n")
			Expect(err).NotTo(HaveOccurred())
			Expect(r.finish(10*time.Second)).To(Equal("status=7\n"), shell.name)
			for i := range procs {
				Expect(processFile(procs, i, "term")).To(Equal("term\n"), "process %d", i)
			}
		},
		shellEntries(""),
	)

	DescribeTable("ends the wait 6 seconds after the first exit or the stop when a process ignores SIGTERM",
		func(shellOf func() guestShell, scripts []string, stop bool, want string) {
			shell := shellOf()
			procs := sectionProcs(GinkgoT().TempDir(), scripts, appEnv)
			r := startSection(shell, procs, false, testIdentityPair{}, nil)
			for i := range procs {
				processFile(procs, i, "start")
			}
			if stop {
				_, err := r.console.WriteString(stopTag(testNonce) + "\n")
				Expect(err).NotTo(HaveOccurred())
			}
			began := time.Now()
			Expect(r.finish(20*time.Second)).To(Equal(want), shell.name)
			Expect(time.Since(began)).To(BeNumerically(">=", guestWindDown-500*time.Millisecond))
			Expect(time.Since(began)).To(BeNumerically("<", guestWindDown+3*time.Second))
		},
		append(
			shellEntries("after a sidecar's exit, with the first status", []string{termScript(143), deafScript, exitAfterScript(3, 0, 1)}, false,
				"vm-launch guest: sidecar 2 exited with status 3; stopping the app and the other sidecar\n"+
					"vm-launch guest: the app and its sidecars did not all exit within 6 seconds; ending the rest\nstatus=3\n"),
			shellEntries("after a stop, with 137 for the app that SIGKILL ended", []string{deafScript, termScript(9)}, true,
				"vm-launch guest: the app and its sidecars did not all exit within 6 seconds; ending the rest\nstatus=137\n")...,
		),
	)

	It("ends its wind-down 2 seconds before the host's stop deadline, with a text that matches its duration", func() {
		Expect(guestWindDown + 2*time.Second).To(BeNumerically("<=", stopDeadline))
		Expect(guestTimeoutSeconds).To(Equal(strconv.Itoa(int(guestWindDown / time.Second))))
		Expect(guestWindDown % time.Second).To(BeZero())
		Expect(guestEventLoop(sectionProcs(GinkgoT().TempDir(), []string{"exit 0", "exit 0"}, appEnv))).To(ContainSubstring("sleep " + guestTimeoutSeconds + " &\n"))
	})

	DescribeTable("runs the app alone and gives its status",
		func(shellOf func() guestShell) {
			shell := shellOf()
			procs := sectionProcs(GinkgoT().TempDir(), []string{startScript + "exit 5"}, appEnv)
			r := startSection(shell, procs, false, testIdentityPair{}, nil)
			Expect(r.finish(5*time.Second)).To(Equal("status=5\n"), shell.name)
			pid := strings.TrimSpace(processFile(procs, 0, "pid"))
			Expect(processFile(procs, 0, "start")).To(HavePrefix("pid=" + pid + " "))
		},
		shellEntries(""),
	)

	DescribeTable("installs the boot pair before the app starts, and a pushed pair while it runs",
		func(shellOf func() guestShell) {
			shell := shellOf()
			boot, pushed := newTestIdentityPair(1, "rsa"), newTestIdentityPair(2, "pkcs8")
			// The app reads its pair through a link to the run's app root,
			// which the spec makes before the run starts.
			script := `cat cred/instance.crt >seen; ` + startScript + `until [ -e go ]; do sleep 0.05; done; exit 0`
			procs := sectionProcs(GinkgoT().TempDir(), []string{script}, appEnv)
			r := startSection(shell, procs, true, boot, func(r *sectionRun) {
				Expect(os.Symlink(r.credDir(), filepath.Join(procs[0].dir, "cred"))).To(Succeed())
			})
			processFile(procs, 0, "start")
			seen, err := os.ReadFile(filepath.Join(procs[0].dir, "seen"))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(seen)).To(Equal(string(boot.crt)))
			mounts, err := os.ReadFile(r.mountLog)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(mounts)).To(Equal("mount -t tmpfs -o mode=0755,size=1m,nosuid,nodev,noexec tmpfs " + r.credDir() + "\n"))

			_, err = r.console.WriteString(consoleInput(testPushFrames(1, pushed.crt, pushed.key)))
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() string {
				raw, _ := os.ReadFile(r.acks)
				return string(raw)
			}, 10*time.Second, 10*time.Millisecond).Should(Equal(credOKTag(testNonce) + "1\n"))
			for name, want := range map[string][]byte{"instance.crt": pushed.crt, "instance.key": pushed.key} {
				got, err := os.ReadFile(filepath.Join(r.credDir(), name))
				Expect(err).NotTo(HaveOccurred())
				Expect(string(got)).To(Equal(string(want)), name)
			}

			Expect(os.WriteFile(filepath.Join(procs[0].dir, "go"), nil, 0o600)).To(Succeed())
			Expect(r.finish(10*time.Second)).To(Equal("status=0\n"), shell.name)
		},
		shellEntries(""),
	)

	DescribeTable("leaves every frame line alone and keeps the boot pair when the console still echoes its input",
		func(shellOf func() guestShell) {
			shell := shellOf()
			boot, pushed := newTestIdentityPair(1, "rsa"), newTestIdentityPair(2, "pkcs8")
			procs := sectionProcs(GinkgoT().TempDir(), []string{termScript(7)}, appEnv)
			r := startSection(shell, procs, true, boot, func(r *sectionRun) {
				r.cmd.Env = append(r.cmd.Env, "rvm_echo=1")
			})
			processFile(procs, 0, "start")
			// The reader reads the push before the stop request, which ends
			// it, so the push has had its chance by the time the run ends.
			_, err := r.console.WriteString(consoleInput(testPushFrames(1, pushed.crt, pushed.key)) + stopTag(testNonce) + "\n")
			Expect(err).NotTo(HaveOccurred())
			Expect(r.finish(10*time.Second)).To(Equal("status=7\n"), shell.name)
			acks, _ := os.ReadFile(r.acks)
			Expect(string(acks)).NotTo(ContainSubstring("RVM_CRED"))
			for name, want := range map[string][]byte{"instance.crt": boot.crt, "instance.key": boot.key} {
				got, err := os.ReadFile(filepath.Join(r.credDir(), name))
				Expect(err).NotTo(HaveOccurred())
				Expect(string(got)).To(Equal(string(want)), name)
			}
		},
		shellEntries(""),
	)

	It("says that it takes no pushes, from its echo check, only when the console refuses to turn off echo", func() {
		bin := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(bin, "stty"), []byte("#!/bin/sh\necho \"stty $*\" >&2\nexit \"$STTY_RC\"\n"), 0o755)).To(Succeed())
		check := strings.ReplaceAll(guestIdentityEchoCheck(testNonce), "</dev/console", "</dev/null")
		for rc, want := range map[string]string{"0": "rvm_echo=[]\n", "1": credOffTag(testNonce) + "\nrvm_echo=[1]\n"} {
			cmd := exec.Command("/bin/sh", "-c", "rvm_echo=stale\n"+check+`echo "rvm_echo=[$rvm_echo]"`)
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "STTY_RC=" + rc}
			out, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(out)).To(Equal(want), "stty exits %s", rc)
		}
	})

	It("installs the identity first only when it has one, and starts the reader with every pid file and each process through exec", func() {
		procs := []guestProcess{
			{index: 0, argvPath: "/a/argv", envPaths: []string{"/a/env"}, dir: "/a", pidPath: guestAppPid},
			{index: 1, argvPath: guestSidecarFile(1, "argv"), envPaths: []string{"/a/env", guestSidecarFile(1, "env")}, dir: "/a", pidPath: guestSidecarFile(1, "pid")},
		}
		run := func(p guestProcess) string { return "run-process " + strconv.Itoa(p.index) }
		without := guestRunSection(testNonce, procs, false, run)
		with := guestRunSection(testNonce, procs, true, run)
		Expect(without).NotTo(ContainSubstring(guestIdentitySetup))
		Expect(with).To(HavePrefix(guestIdentitySetup))
		Expect(with).To(ContainSubstring(guestControlReader(testNonce, []string{guestAppPid, "/rvm/sidecar/1/pid"}, true)))
		Expect(without).To(ContainSubstring(guestControlReader(testNonce, []string{guestAppPid, "/rvm/sidecar/1/pid"}, false)))
		for _, text := range []string{with, without} {
			Expect(strings.Count(text, "\t\trun-process 0\n")).To(Equal(1))
			Expect(strings.Count(text, "\t\trun-process 1\n")).To(Equal(1))
			Expect(text).To(HaveSuffix("rvm_status=$?\ncommand exec 4>&- 5>&-\n" + guestStopReaderStop))
		}
	})
})
