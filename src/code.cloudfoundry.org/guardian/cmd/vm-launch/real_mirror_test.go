//go:build linux

package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// The paths at which the spec bind-mounts a directory and a file into its own
// mount namespace, as Diego binds file-based service bindings and as an
// operator might bind any other file.
const (
	realMirrorBindings = "/etc/cf-service-bindings"
	realMirrorFile     = "/srv/vm-launch-mirror/extra.txt"
)

// realMirrorLauncher is the mirror guest's launcher. It reports what the app
// sees at the two variables and the two mirrored mounts, that it cannot
// write to either, and how the guest mounted the bindings, and then reports
// each file once its content has changed to the second version. A stop's
// SIGTERM makes it exit 7.
const realMirrorLauncher = `#!/bin/sh
trap 'echo app-got-term; exit 7' TERM
echo "app-root=$SERVICE_BINDING_ROOT"
echo "app-vcap-path=$VCAP_SERVICES_FILE_PATH"
echo "app-uri=$(cat $SERVICE_BINDING_ROOT/svc/uri)"
echo "app-link=$(cat $SERVICE_BINDING_ROOT/svc/link)"
echo "app-vcap=$(cat $VCAP_SERVICES_FILE_PATH)"
echo "app-extra=$(cat ` + realMirrorFile + `)"
echo "app-uri-stat=$(stat -c '%a %u %g' $SERVICE_BINDING_ROOT/svc/uri)"
if (echo x >$SERVICE_BINDING_ROOT/new) 2>/dev/null; then echo app-bindings-writable; else echo app-bindings-read-only; fi
if (echo x >>` + realMirrorFile + `) 2>/dev/null; then echo app-extra-writable; else echo app-extra-read-only; fi
echo "app-mount=$(grep 'cf-service-bindings ' /proc/mounts)"
echo app-ready
while :; do
	if [ -z "$uri" ] && [ "$(cat $SERVICE_BINDING_ROOT/svc/uri)" = "postgres://second" ]; then
		uri=1
		echo "app-uri-changed=$(cat $SERVICE_BINDING_ROOT/svc/uri) $(stat -c '%a %u %g' $SERVICE_BINDING_ROOT/svc/uri)"
	fi
	if [ -z "$extra" ] && [ "$(cat ` + realMirrorFile + `)" = "extra, second and longer" ]; then
		extra=1
		echo "app-extra-changed=$(cat ` + realMirrorFile + `)"
	fi
	/bin/busybox sleep 1
done
`

// realMirrorWriter passes guest output to w. It calls ready once the app has
// reported what it sees, and done once the app has seen both changes, each
// once, from the console goroutine.
type realMirrorWriter struct {
	w           *safeBuffer
	ready, done func()
	readyOnce   sync.Once
	doneOnce    sync.Once
}

func (r *realMirrorWriter) Write(p []byte) (int, error) {
	n, err := r.w.Write(p)
	out := r.w.String()
	if strings.Contains(out, "app-ready\n") {
		r.readyOnce.Do(r.ready)
	}
	if strings.Contains(out, "app-uri-changed=") && strings.Contains(out, "app-extra-changed=") {
		r.doneOnce.Do(r.done)
	}
	return n, err
}

// bindReadOnly bind-mounts src at dst, creating dst as a directory or an
// empty file to match src, remounts the bind read-only with extra flags, and
// undoes all of it when the spec ends.
func bindReadOnly(src, dst string, extra uintptr) {
	st, err := os.Stat(src)
	Expect(err).NotTo(HaveOccurred())
	Expect(os.MkdirAll(filepath.Dir(dst), 0o755)).To(Succeed())
	if st.IsDir() {
		Expect(os.Mkdir(dst, 0o755)).To(Succeed())
	} else {
		Expect(os.WriteFile(dst, nil, 0o644)).To(Succeed())
	}
	DeferCleanup(os.Remove, dst)
	Expect(unix.Mount(src, dst, "", unix.MS_BIND, "")).To(Succeed())
	DeferCleanup(unix.Unmount, dst, unix.MNT_DETACH)
	Expect(unix.Mount("", dst, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|extra, "")).To(Succeed())
}

var _ = Describe("a stack guest with mirrored mounts against a real QEMU", func() {
	It("mirrors a bound directory of service bindings and a bound file to the same paths, read-only, gives the app both binding variables, and pushes changes to both files to the running guest", func() {
		art := realArtifacts()
		qemu := realQEMU()
		requireMicrovm(qemu)
		if os.Getuid() != 0 {
			Skip("binding mounts into the spec's mount namespace needs root")
		}

		interval := mirrorWatchInterval
		mirrorWatchInterval = time.Second
		DeferCleanup(func() { mirrorWatchInterval = interval })

		src := GinkgoT().TempDir()
		bindings := filepath.Join(src, "bindings")
		Expect(os.MkdirAll(filepath.Join(bindings, "svc"), 0o755)).To(Succeed())
		uri := filepath.Join(bindings, "svc", "uri")
		Expect(os.WriteFile(uri, []byte("postgres://first"), 0o640)).To(Succeed())
		Expect(os.Chown(uri, 2000, 2000)).To(Succeed())
		Expect(os.Symlink("uri", filepath.Join(bindings, "svc", "link"))).To(Succeed())
		Expect(os.WriteFile(filepath.Join(bindings, "vcap_services"), []byte(`{"p-mysql":[]}`), 0o644)).To(Succeed())
		extra := filepath.Join(src, "extra.txt")
		Expect(os.WriteFile(extra, []byte("extra, first"), 0o644)).To(Succeed())
		// Cleanups run last first, so the directory bindReadOnly creates for
		// the file goes once the bind and the file are gone.
		DeferCleanup(os.Remove, filepath.Dir(realMirrorFile))
		bindReadOnly(bindings, realMirrorBindings, unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC)
		bindReadOnly(extra, realMirrorFile, 0)

		env := map[string]string{
			"SERVICE_BINDING_ROOT":    realMirrorBindings,
			"VCAP_SERVICES_FILE_PATH": realMirrorBindings + "/vcap_services",
		}
		mirrorLog := &safeBuffer{}
		m, err := readMountMirror(mountInfoPath, mirrorDedicatedPaths(env, nil), log.New(mirrorLog, "", 0))
		Expect(err).NotTo(HaveOccurred(), mirrorLog.String())
		Expect(m).NotTo(BeNil(), mirrorLog.String())
		var paths []string
		for _, mm := range m.mounts {
			paths = append(paths, mm.path)
		}
		Expect(paths).To(Equal([]string{realMirrorBindings, realMirrorFile}), mirrorLog.String())
		Expect(m.keptEnv(env)).To(ConsistOf("SERVICE_BINDING_ROOT", "VCAP_SERVICES_FILE_PATH"))
		first := make([]mirrorWatched, len(m.watched))
		for i, w := range m.watched {
			first[i] = *w
		}

		sd := &stackDrives{stack: realStackImage(art), droplet: realDropletImage(art)}
		launcher := writeTempFile("launcher", realMirrorLauncher)
		lf, err := os.Open(launcher)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(lf.Close)
		g := taskGuest("")
		g.env, err = buildStackGuestEnvKeeping(env, minGuestMemoryMiB, false, "", m.keptEnv(env), log.New(GinkgoWriter, "", 0))
		Expect(err).NotTo(HaveOccurred())
		g.stack = &guestStack{
			launcher: guestTool{name: "launcher", file: lf, size: int64(len(realMirrorLauncher))},
			argv:     shellJoin([]string{stackLauncherPath, "/home/vcap/app", "", `{"start_command":"./app","process_type":"web"}`}),
			cwd:      "/home/vcap",
			hostname: "stack-guest-0",
			hosts:    []byte("127.0.0.1 localhost\n"),
			mirror:   m,
		}
		g.drives, err = newGuestDrivesWithStack(backend.VMQemu, nil, nil, sd)
		Expect(err).NotTo(HaveOccurred())
		f := newRealInitramfs(g)

		// change rewrites the bound file in place, as a bind of a file pins
		// its inode, and replaces the binding's file by a rename, as Diego
		// and Kubernetes-style binding writers do.
		var changeErr error
		change := func() {
			if changeErr = os.WriteFile(extra, []byte("extra, second and longer"), 0o644); changeErr != nil {
				return
			}
			next := uri + ".next"
			if changeErr = os.WriteFile(next, []byte("postgres://second"), 0o600); changeErr != nil {
				return
			}
			if changeErr = os.Chmod(next, 0o600); changeErr != nil {
				return
			}
			if changeErr = os.Chown(next, 2000, 2000); changeErr != nil {
				return
			}
			changeErr = os.Rename(next, uri)
		}

		var r realStop
		bootWithRetry(func() bool {
			// A retried boot starts from the first content again, which is
			// what its initramfs holds.
			Expect(os.WriteFile(extra, []byte("extra, first"), 0o644)).To(Succeed())
			Expect(os.WriteFile(uri, []byte("postgres://first"), 0o640)).To(Succeed())
			Expect(os.Chmod(uri, 0o640)).To(Succeed())
			for i, w := range m.watched {
				*w = first[i]
				state, ok := statMirrorFile(w.path)
				Expect(ok).To(BeTrue())
				w.state = state
			}

			files, drives, initrdPath, _, rootPath := hypervisorFilesWithStack(nil, withUserspaceMark(f), nil, nil, sd)
			hvArgv, err := hypervisorArgvWithStack(backend.VMQemu, art, GinkgoT().TempDir(), initrdPath, minGuestMemoryMiB, g.nw, drives, rootPath, 0, sd)
			Expect(err).NotTo(HaveOccurred())
			consoleLog := filepath.Join(GinkgoT().TempDir(), "console.log")
			cmd := newHypervisorCmd(consoleLogArgv(markedArgv(tcgArgv(qemu, hvArgv)), consoleLog), files)
			stderr := &safeBuffer{}
			cmd.Stderr = stderr
			out, logBuf := &safeBuffer{}, &safeBuffer{}
			console := newBootWriter(realBootMark)
			stopTail := make(chan struct{})
			tailed := tailFile(consoleLog, console, stopTail)

			signals := make(chan os.Signal, 1)
			var signalled time.Time
			var qemuProc *os.Process
			running := make(chan struct{})
			sup := supervisor{
				stdout: &realMirrorWriter{w: out, ready: change, done: func() {
					signalled = time.Now()
					signals <- syscall.SIGTERM
				}},
				logger:   log.New(logBuf, "", 0),
				signals:  signals,
				grace:    killGrace,
				deadline: stopDeadline,
				started: func() {
					qemuProc = cmd.Process
					close(running)
				},
			}
			stopWatch := watchMirror(&sup, testNonce, m, sup.logger)
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
			details := func() string {
				return "stderr: " + stderr.String() + "\nconsole: " + console.String() + "\nlog: " + logBuf.String()
			}
			booted := awaitRealGuest(kill, console, exited, details)
			<-exited
			stopWatch()
			ended := time.Now()
			close(stopTail)
			<-tailed
			if !booted {
				return false
			}
			Expect(runErr).NotTo(HaveOccurred())
			Expect(console.String()).To(ContainSubstring(realBootMark), "QEMU exited before the guest started userspace\n%s", details())
			GinkgoWriter.Printf("%s\n", details())
			r = realStop{res: res, out: strings.ReplaceAll(out.String(), "\r", ""), log: logBuf.String(), signalled: signalled, ended: ended}
			return true
		})
		out := r.out
		Expect(changeErr).NotTo(HaveOccurred())

		Expect(out).To(MatchRegexp(`(?m)^app-root=`+realMirrorBindings+`$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-vcap-path=`+realMirrorBindings+`/vcap_services$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-uri=postgres://first$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-link=postgres://first$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-vcap=\{"p-mysql":\[\]\}$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-extra=extra, first$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-uri-stat=640 2000 2000$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-bindings-read-only$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-extra-read-only$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-mount=\S+ \S*cf-service-bindings \S+ ro,nosuid,nodev,noexec`), out)

		Expect(out).To(MatchRegexp(`(?m)^app-extra-changed=extra, second and longer$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-uri-changed=postgres://second 600 2000 2000$`), out)
		Expect(r.log).To(ContainSubstring("the guest installed push 1 of the mirrored file "), r.log)
		Expect(r.log).To(ContainSubstring("the guest installed push 2 of the mirrored file "), r.log)
		Expect(r.log).NotTo(ContainSubstring("refused push"), r.log)
		Expect(r.log).NotTo(ContainSubstring("did not say that it takes pushes"), r.log)
		Expect(out).NotTo(ContainSubstring(fileTag(testNonce)), "no pushed line reaches the app's output")

		Expect(r.res.markerFound).To(BeTrue(), r.log)
		Expect(codeOf(r.res)).To(Equal(7), out)
		Expect(out).To(MatchRegexp(`(?m)^app-got-term$`), out)
	})
})
