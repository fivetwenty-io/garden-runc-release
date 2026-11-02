//go:build linux

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// mountInfoLine is one line of a fake mount table for a mount of fsType at
// point with the mount options opts.
func mountInfoLine(id int, point, opts, fsType string) string {
	return fmt.Sprintf("%d 1 0:%d / %s %s - %s src rw", id, id, strings.ReplaceAll(point, " ", `\040`), opts, fsType)
}

// writeMountTable writes lines as a mount table in dir and returns its path.
func writeMountTable(dir string, lines ...string) string {
	p := filepath.Join(dir, "mountinfo")
	Expect(os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644)).To(Succeed())
	return p
}

// mirrorRels returns the rel of every entry of mm, in order.
func mirrorRels(mm mirrorMount) []string {
	rels := make([]string, len(mm.entries))
	for i, e := range mm.entries {
		rels[i] = e.rel
	}
	return rels
}

var _ = Describe("mirrored mounts", func() {
	var (
		dir    string
		logBuf *bytes.Buffer
		logger *log.Logger
	)

	BeforeEach(func() {
		var err error
		dir, err = os.MkdirTemp("", "mirror")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(os.RemoveAll, dir)
		logBuf = &bytes.Buffer{}
		logger = log.New(logBuf, "", 0)
	})

	write := func(rel, content string, perm os.FileMode) {
		p := filepath.Join(dir, rel)
		Expect(os.MkdirAll(filepath.Dir(p), 0o755)).To(Succeed())
		Expect(os.WriteFile(p, []byte(content), perm)).To(Succeed())
		Expect(os.Chmod(p, perm)).To(Succeed())
	}

	Describe("readMountMirror", func() {
		It("mirrors the read-only directories and files, copies links as links, and leaves out what the rules leave out", func() {
			write("bind/a", "alpha", 0o644)
			write("bind/sub/b", "beta", 0o600)
			write("bind/inner/c", "gamma", 0o644)
			Expect(os.Symlink("/etc/passwd", filepath.Join(dir, "bind/l"))).To(Succeed())
			Expect(unix.Mkfifo(filepath.Join(dir, "bind/fifo"), 0o600)).To(Succeed())
			write("file.txt", "hello", 0o640)
			write("rw/x", "x", 0o644)
			write("nfs/x", "x", 0o644)
			write("vol/x", "x", 0o644)
			write("above/vol/x", "x", 0o644)
			table := writeMountTable(dir,
				mountInfoLine(1, "/", "rw", "overlay"),
				mountInfoLine(2, "/proc", "rw,nosuid", "proc"),
				mountInfoLine(3, "/etc/hosts", "ro", "ext4"),
				mountInfoLine(4, "/tmp/garden-init", "ro", "ext4"),
				mountInfoLine(5, dir+"/bind", "ro,nosuid,nodev,noexec", "ext4"),
				mountInfoLine(6, dir+"/bind/inner", "ro", "ext4"),
				mountInfoLine(7, dir+"/file.txt", "ro", "ext4"),
				mountInfoLine(8, dir+"/rw", "rw", "ext4"),
				mountInfoLine(9, dir+"/nfs", "ro", "nfs4"),
				mountInfoLine(10, dir+"/vol", "ro", "ext4"),
				mountInfoLine(11, dir+"/above", "ro", "ext4"),
				mountInfoLine(12, "/sys/fs/cgroup", "ro", "cgroup2"),
			)

			m, err := readMountMirror(table, []string{"/etc/hosts", dir + "/vol", dir + "/above/vol"}, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(m).NotTo(BeNil())
			Expect(m.mounts).To(HaveLen(3))

			bind, inner, file := m.mounts[0], m.mounts[1], m.mounts[2]
			Expect(bind.path).To(Equal(dir + "/bind"))
			Expect(bind.dir).To(BeTrue())
			Expect(bind.noexec).To(BeTrue())
			Expect(mirrorRels(bind)).To(Equal([]string{"", "a", "inner", "l", "sub", "sub/b"}))
			Expect(bind.entries[2].place).To(BeTrue(), "the nested mount point is a place, and its content is not read")
			Expect(bind.entries[2].kind).To(Equal(mirrorDir))
			Expect(bind.entries[3].kind).To(Equal(mirrorLink))
			Expect(bind.entries[3].target).To(Equal("/etc/passwd"))
			Expect(bind.entries[5].data).To(Equal([]byte("beta")))
			Expect(bind.entries[5].perm).To(Equal(uint32(0o600)))
			Expect(bind.entries[5].uid).To(Equal(uint32(os.Getuid())))

			Expect(inner.path).To(Equal(dir + "/bind/inner"))
			Expect(inner.noexec).To(BeFalse())
			Expect(mirrorRels(inner)).To(Equal([]string{"", "c"}))

			Expect(file.path).To(Equal(dir + "/file.txt"))
			Expect(file.dir).To(BeFalse())
			Expect(file.entries).To(HaveLen(1))
			Expect(file.entries[0].data).To(Equal([]byte("hello")))
			Expect(file.entries[0].perm).To(Equal(uint32(0o640)))

			Expect(m.watched).To(HaveLen(4))
			paths := []string{}
			for _, w := range m.watched {
				paths = append(paths, w.path)
			}
			Expect(paths).To(Equal([]string{dir + "/bind/a", dir + "/bind/sub/b", dir + "/bind/inner/c", dir + "/file.txt"}))
			Expect(m.watched[0].guest).To(Equal("/rvm/mirror/1/a"))
			Expect(m.watched[2].guest).To(Equal("/rvm/mirror/2/c"))
			Expect(m.watched[3].guest).To(Equal("/rvm/mirror/3"))
			Expect(m.watched[3].inPlace).To(BeTrue())
			Expect(m.watched[0].inPlace).To(BeFalse())
			Expect(m.watched[3].state.size).To(Equal(int64(5)))

			out := logBuf.String()
			Expect(out).To(ContainSubstring("leaving 1 entries out of the mirrored mount at " + quoteForLog(dir+"/bind")))
			Expect(out).To(ContainSubstring("not mirroring the mount at " + quoteForLog(dir+"/rw") + " into the guest, because it is writable"))
			Expect(out).To(ContainSubstring("not mirroring the nfs4 mount at " + quoteForLog(dir+"/nfs") + " into the guest"))
			Expect(out).To(ContainSubstring("not mirroring the mount at " + quoteForLog(dir+"/above") + " into the guest, because " + quoteForLog(dir+"/above/vol") + " below it reaches the guest on a path of its own"))
			Expect(out).To(ContainSubstring("leaving 6 of the container's mounts out of the guest's mirrored mounts"))
			Expect(out).To(ContainSubstring("mirroring 3 of the container's mounts into the guest, read-only"))
			Expect(out).To(ContainSubstring("vm-launch pushes changes to 4 of their files"))
		})

		It("holds back a mount over the limits of a small mount", func() {
			write("big/huge", strings.Repeat("x", mirrorFileMaxBytes+1), 0o644)
			table := writeMountTable(dir, mountInfoLine(5, dir+"/big", "ro", "ext4"))
			m, err := readMountMirror(table, nil, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(m).To(BeNil())
			Expect(logBuf.String()).To(ContainSubstring("not mirroring the mount at " + quoteForLog(dir+"/big") + " into the guest, because it is over"))
			Expect(logBuf.String()).To(ContainSubstring("large mounts are not mirrored yet"))
			Expect(logBuf.String()).To(ContainSubstring("mirroring none of the container's mounts into the guest"))
		})

		It("refuses a mount point that is reached through a symbolic link", func() {
			write("real/a", "a", 0o644)
			Expect(os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link"))).To(Succeed())
			table := writeMountTable(dir, mountInfoLine(5, dir+"/link", "ro", "ext4"))
			m, err := readMountMirror(table, nil, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(m).To(BeNil())
			Expect(logBuf.String()).To(ContainSubstring("not mirroring the mount at " + quoteForLog(dir+"/link") + " into the guest: it is a symbolic link, and vm-launch follows no symbolic links on the path of a mirrored mount"))
		})

		It("holds back a mount whose root is a FIFO at once, without opening it for reading", func() {
			Expect(unix.Mkfifo(filepath.Join(dir, "pipe"), 0o600)).To(Succeed())
			table := writeMountTable(dir, mountInfoLine(5, dir+"/pipe", "ro", "ext4"))
			done := make(chan struct{})
			var m *mountMirror
			var err error
			go func() {
				defer GinkgoRecover()
				defer close(done)
				m, err = readMountMirror(table, nil, logger)
			}()
			// An open for reading of a FIFO with no writer would block
			// until one came.
			Eventually(done, 5*time.Second).Should(BeClosed())
			Expect(err).NotTo(HaveOccurred())
			Expect(m).To(BeNil())
			Expect(logBuf.String()).To(ContainSubstring("not mirroring the mount at " + quoteForLog(dir+"/pipe") + " into the guest: it is neither a regular file nor a directory"))
		})

		It("watches each file from the state it had when vm-launch read it", func() {
			write("watched.txt", "as read", 0o644)
			table := writeMountTable(dir, mountInfoLine(5, dir+"/watched.txt", "ro", "ext4"))
			m, err := readMountMirror(table, nil, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(m.watched).To(HaveLen(1))
			Expect(m.watched[0].state).To(Equal(m.mounts[0].entries[0].state))
			Expect(m.watched[0].state.size).To(Equal(int64(len("as read"))))

			read := fileState{dev: 1, ino: 2, size: 3, modTimeNs: 4}
			later := &mountMirror{mounts: []mirrorMount{{path: "/etc/x", entries: []mirrorEntry{{kind: mirrorFile, perm: 0o644, data: []byte("abc"), state: read}}}}}
			later.number()
			Expect(later.watched[0].state).To(Equal(read), "number takes the state of the read, and does not stat the file again")
		})

		It("fails on a mount table it cannot parse", func() {
			table := writeMountTable(dir, "not a mount line")
			_, err := readMountMirror(table, nil, logger)
			Expect(err).To(MatchError(ContainSubstring("line 1 of " + table)))
		})

		It("keeps the binding variables only when they name a path in a mirrored mount", func() {
			write("bindings/svc/uri", "postgres://", 0o644)
			table := writeMountTable(dir, mountInfoLine(5, dir+"/bindings", "ro", "ext4"))
			m, err := readMountMirror(table, nil, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(m.keptEnv(map[string]string{
				"SERVICE_BINDING_ROOT":    dir + "/bindings",
				"VCAP_SERVICES_FILE_PATH": "/elsewhere/vcap_services",
			})).To(Equal([]string{"SERVICE_BINDING_ROOT"}))
			Expect(m.keptEnv(map[string]string{"VCAP_SERVICES_FILE_PATH": dir + "/bindings/vcap_services"})).To(Equal([]string{"VCAP_SERVICES_FILE_PATH"}))
			var none *mountMirror
			Expect(none.keptEnv(map[string]string{"SERVICE_BINDING_ROOT": dir + "/bindings"})).To(BeEmpty())
		})
	})

	It("names the paths that reach the guest on their own, from the environment and the volumes", func() {
		paths := mirrorDedicatedPaths(map[string]string{
			systemCertPathEnv: "/etc/cf-system-certificates",
			instanceCertEnv:   "/etc/cf-instance-credentials/instance.crt",
		}, []guestVolume{{ContainerDir: "/data"}})
		Expect(paths).To(ContainElements("/etc/hosts", "/home/vcap", "/tmp/lifecycle", "/etc/cf-system-certificates", "/etc/cf-instance-credentials", "/data"))
	})

	It("denies the pseudo filesystems and the paths of Garden and vm-launch", func() {
		Expect(mirrorDenied("/", "ext4")).To(BeTrue())
		Expect(mirrorDenied("/data", "proc")).To(BeTrue())
		Expect(mirrorDenied("/dev/shm", "tmpfs")).To(BeTrue())
		Expect(mirrorDenied("/opt/garden-vm/stack", "ext4")).To(BeTrue())
		Expect(mirrorDenied("/tmp/garden-init", "ext4")).To(BeTrue())
		Expect(mirrorDenied("/etc/cf-service-bindings", "ext4")).To(BeFalse())
		Expect(mirrorDenied("/developer", "ext4")).To(BeFalse())
	})

	DescribeTable("denies the programs, libraries, and loader that the guest's root runs in the app root, and Diego's own assets",
		func(p string) {
			Expect(mirrorDenied(p, "ext4")).To(BeTrue())
		},
		Entry("setpriv", "/usr/bin/setpriv"),
		Entry("all of /usr", "/usr"),
		Entry("a program in /bin", "/bin/sh"),
		Entry("a program in /sbin", "/sbin/x"),
		Entry("the C library", "/lib/x86_64-linux-gnu/libc.so.6"),
		Entry("the 64-bit loader", "/lib64/ld-linux-x86-64.so.2"),
		Entry("/lib32", "/lib32/x"),
		Entry("/libx32", "/libx32/x"),
		Entry("the loader's preload list", "/etc/ld.so.preload"),
		Entry("the loader's cache", "/etc/ld.so.cache"),
		Entry("a file the loader's configuration includes", "/etc/ld.so.conf.d/x.conf"),
		Entry("Diego's assets", "/etc/cf-assets/envoy_config/envoy.yaml"),
		Entry("/etc, which holds the loader's files", "/etc"),
		Entry("/tmp, which holds Garden's files", "/tmp"),
		Entry("/opt, which holds vm-launch's files", "/opt"),
	)

	DescribeTable("mirrors the paths beside the denied ones",
		func(p string) {
			Expect(mirrorDenied(p, "ext4")).To(BeFalse())
		},
		Entry("the service bindings", "/etc/cf-service-bindings"),
		Entry("a file that only starts like the loader's", "/etc/ldap.conf"),
		Entry("a directory that only starts like /lib", "/library"),
		Entry("a directory in /tmp that is not Garden's", "/tmp/app-data"),
		Entry("a directory in /opt that is not vm-launch's", "/opt/app"),
	)

	Describe("the guest's side", func() {
		mirror := func() *mountMirror {
			m := &mountMirror{mounts: []mirrorMount{
				{path: "/etc/cf-service-bindings", dir: true, noexec: true, entries: []mirrorEntry{
					{kind: mirrorDir, perm: 0o755},
					{rel: "svc", kind: mirrorDir, perm: 0o755},
					{rel: "svc/uri", kind: mirrorFile, perm: 0o644, uid: 2000, gid: 2000, data: []byte("postgres://")},
					{rel: "svc/link", kind: mirrorLink, target: "uri"},
				}},
				{path: "/etc/it's here", entries: []mirrorEntry{{kind: mirrorFile, perm: 0o600, data: []byte("file")}}},
			}}
			m.number()
			return m
		}

		It("stages each mount in the initramfs with its owners and modes", func() {
			var buf bytes.Buffer
			cw := newCPIOWriter(&buf)
			for _, step := range mirror().stackSteps(cw) {
				Expect(step()).To(Succeed())
			}
			Expect(cw.Close()).To(Succeed())
			byName := map[string]cpioEntry{}
			var names []string
			for _, e := range readNewc(buf.Bytes()) {
				names = append(names, e.name)
				byName[e.name] = e
			}
			Expect(names).To(Equal([]string{"rvm/mirror", "rvm/mirror-next", "rvm/mirror/1", "rvm/mirror/1/svc", "rvm/mirror/1/svc/uri", "rvm/mirror/1/svc/link", "rvm/mirror/2", cpioTrailer}))
			Expect(byName["rvm/mirror-next"].mode).To(Equal(uint32(cpioTypeDir | 0o700)))
			Expect(byName["rvm/mirror/1/svc/uri"].mode).To(Equal(uint32(cpioTypeRegular | 0o644)))
			Expect(string(byName["rvm/mirror/1/svc/uri"].data)).To(Equal("postgres://"))
			Expect(byName["rvm/mirror/1/svc/link"].mode).To(Equal(uint32(cpioTypeSymlink | 0o777)))
			Expect(string(byName["rvm/mirror/1/svc/link"].data)).To(Equal("uri"))
			Expect(byName["rvm/mirror/2"].mode).To(Equal(uint32(cpioTypeRegular | 0o600)))

			raw := buf.Bytes()
			i := bytes.Index(raw, []byte("rvm/mirror/1/svc/uri\x00"))
			Expect(i).To(BeNumerically(">", cpioHeaderSize))
			hdr := string(raw[i-cpioHeaderSize : i])
			Expect(hdr[22:30]).To(Equal("000007d0"), "the uid field")
			Expect(hdr[30:38]).To(Equal("000007d0"), "the gid field")
		})

		It("binds each staged copy read-only into the app root, refusing symbolic links on the way", func() {
			setup := mirror().guestSetup(testNonce)
			Expect(setup).To(ContainSubstring(`[ ! -L '/rvm/app/etc' ] && [ ! -L '/rvm/app/etc/cf-service-bindings' ] || rvm_fail`))
			Expect(setup).To(ContainSubstring("mkdir -p '/rvm/app/etc/cf-service-bindings' || rvm_fail"))
			Expect(setup).To(ContainSubstring("mount -o bind /rvm/mirror/1 '/rvm/app/etc/cf-service-bindings' || rvm_fail"))
			Expect(setup).To(ContainSubstring("mount -o remount,bind,ro,nosuid,nodev,noexec '/rvm/app/etc/cf-service-bindings' || rvm_fail"))
			Expect(setup).To(ContainSubstring(`mkdir -p '/rvm/app/etc' && { [ -e '/rvm/app/etc/it'\''s here' ] || printf '' >'/rvm/app/etc/it'\''s here'; } || rvm_fail`))
			Expect(setup).To(ContainSubstring("mount -o remount,bind,ro,nosuid,nodev '/rvm/app/etc/it'\\''s here' || rvm_fail"))
			Expect(setup).To(HaveSuffix(`[ -n "$rvm_echo" ] || echo ` + fileOnTag(testNonce) + "\n"))
			var none *mountMirror
			Expect(none.guestSetup(testNonce)).To(BeEmpty())
		})

		It("checks the console's echo and installs pushes only in a stack guest that watches files", func() {
			s := &guestStack{argv: "'/tmp/lifecycle/launcher' 'app' 'run' ''", cwd: "/home/vcap/app", hostname: "h", mirror: mirror()}
			script := s.initScript(testNonce)
			Expect(script).To(ContainSubstring(guestIdentityEchoCheck(testNonce)))
			Expect(script).To(ContainSubstring("mount -o bind /rvm/mirror/1 '/rvm/app/etc/cf-service-bindings'"))
			Expect(script).To(ContainSubstring(`"` + fileTag(testNonce) + `"*) [ -n "$rvm_echo" ] || rvm_file "${rvm_line#"` + fileTag(testNonce) + `"}" ;;`))
			Expect(strings.Index(script, fileOnTag(testNonce))).To(BeNumerically("<", strings.Index(script, startTag(testNonce))))

			s.mirror = nil
			plain := s.initScript(testNonce)
			Expect(plain).NotTo(ContainSubstring("rvm_file"))
			Expect(plain).NotTo(ContainSubstring(guestIdentityEchoCheck(testNonce)))
		})

		It("removes the staged copies for the busybox guest and says so, and has nothing to remove without a mirror", func() {
			var none *mountMirror
			Expect(none.fallbackPrep(testNonce)).To(BeEmpty())

			stage := filepath.Join(dir, "mirror")
			next := filepath.Join(dir, "mirror-next")
			console := filepath.Join(dir, "console")
			Expect(os.MkdirAll(filepath.Join(stage, "1", "svc"), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(stage, "1", "svc", "uri"), []byte("postgres://"), 0o644)).To(Succeed())
			Expect(os.Mkdir(next, 0o700)).To(Succeed())
			prep := mirror().fallbackPrep(testNonce)
			Expect(prep).To(HavePrefix("rm -rf " + guestMirrorStage + " " + guestMirrorNext + " || rvm_fail "))
			// The longer path goes first, because the stage's path is a
			// prefix of it.
			script := strings.NewReplacer(guestMirrorNext, next, guestMirrorStage, stage, "/dev/console", console).Replace(prep)
			out, err := exec.Command(guestBusybox(), "sh", "-c", `rvm_fail() { echo "failed: $1"; exit 1; }`+"\n"+script).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), string(out))
			Expect(string(out)).To(BeEmpty())
			Expect(stage).NotTo(BeAnExistingFile())
			Expect(next).NotTo(BeAnExistingFile())
			Expect(os.ReadFile(console)).To(Equal([]byte(mirrorOffTag(testNonce) + "\n")))
		})
	})

	Describe("the initramfs of a stack guest that can fall back to the busybox guest", func() {
		stackGuest := func(m *mountMirror) guestContents {
			f, err := os.Open(writeTempFile("launcher", "#!/bin/sh\n"))
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(f.Close)
			g := taskGuest("")
			g.drives.stackID, g.drives.dropletID = qemuStackSerial, qemuDropletSerial
			g.stack = &guestStack{
				launcher: guestTool{name: "launcher", file: f, size: int64(len("#!/bin/sh\n"))},
				argv:     shellJoin([]string{stackLauncherPath, "/home/vcap/app", "", ""}),
				cwd:      "/home/vcap/app",
				hostname: "stack-guest-0",
				hosts:    []byte("127.0.0.1 localhost\n"),
				fallback: true,
				mirror:   m,
			}
			return g
		}
		archive := func(g guestContents) ([]string, map[string]cpioEntry) {
			var archive bytes.Buffer
			Expect(writeInitramfsArchive(&archive, strings.NewReader("busybox"), int64(len("busybox")), g)).To(Succeed())
			return archiveEntries(archive.Bytes())
		}
		prepName := strings.TrimPrefix(guestFallbackPrep, "/")

		It("holds nothing of the mirror without one", func() {
			names, byName := archive(stackGuest(nil))
			for _, n := range names {
				Expect(n).NotTo(HavePrefix("rvm/mirror"))
			}
			script := string(byName["rvm/init"].data)
			for _, s := range []string{fileTag(testNonce), fileOnTag(testNonce), mirrorOffTag(testNonce), "rvm_file", guestIdentityEchoCheck(testNonce)} {
				Expect(script).NotTo(ContainSubstring(s))
			}
			Expect(string(byName[prepName].data)).To(Equal((*systemCerts)(nil).fallbackPrep()), "the busybox guest's preparation is the certificates' alone")
		})

		It("removes the mirrored mounts before the busybox guest's other preparation", func() {
			m := &mountMirror{mounts: []mirrorMount{{path: "/etc/cf-service-bindings", dir: true, entries: []mirrorEntry{
				{kind: mirrorDir, perm: 0o755},
				{rel: "uri", kind: mirrorFile, perm: 0o644, data: []byte("postgres://")},
			}}}}
			m.number()
			names, byName := archive(stackGuest(m))
			Expect(names).To(ContainElements("rvm/mirror", "rvm/mirror/1", "rvm/mirror/1/uri"))
			Expect(string(byName[prepName].data)).To(Equal(m.fallbackPrep(testNonce) + (*systemCerts)(nil).fallbackPrep()))
		})
	})

	Describe("mirrorFrames", func() {
		It("carries the bytes in lines that each fit a console chunk, with an end line the guest checks", func() {
			data := bytes.Repeat([]byte{0, 1, 2, 0xff, '\n'}, 400)
			frames := mirrorFrames(testNonce, 3, 7, data, 0o640)
			tag := fileTag(testNonce)
			Expect(frames[0]).To(Equal(tag + "begin 3 7"))
			var enc strings.Builder
			for _, f := range frames[1 : len(frames)-1] {
				Expect(f).To(HavePrefix(tag + "data "))
				enc.WriteString(strings.TrimPrefix(f, tag+"data "))
			}
			decoded, err := base64.StdEncoding.DecodeString(enc.String())
			Expect(err).NotTo(HaveOccurred())
			Expect(decoded).To(Equal(data))
			Expect(frames[len(frames)-1]).To(MatchRegexp(`^`+tag+`end 3 7 %d 2000 0640 [0-9a-f]{64}$`, len(frames)-2))
			_, err = consoleChunks(frames, consoleChunk)
			Expect(err).NotTo(HaveOccurred())
		})

		It("carries an empty file as a begin line and an end line", func() {
			frames := mirrorFrames(testNonce, 1, 1, nil, 0o644)
			Expect(frames).To(HaveLen(2))
			Expect(frames[1]).To(HavePrefix(fileTag(testNonce) + "end 1 1 0 0 0644 e3b0c442"))
		})
	})

	Describe("the guest's file reader, in the guest's busybox", func() {
		var stage, next string

		BeforeEach(func() {
			stage = filepath.Join(dir, "stage")
			next = filepath.Join(dir, "next")
			Expect(os.MkdirAll(filepath.Join(stage, "tree"), 0o755)).To(Succeed())
			Expect(os.Mkdir(next, 0o700)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(stage, "file"), []byte("old file"), 0o644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(stage, "tree", "two"), []byte("old two"), 0o644)).To(Succeed())
		})

		// feed runs the reader in the guest's busybox, with its scratch
		// directory and its console in the spec's, and calls rvm_file with
		// each line after the tag.
		feed := func(lines ...string) string {
			uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
			m := &mountMirror{watched: []*mirrorWatched{
				{number: 1, guest: filepath.Join(stage, "file"), inPlace: true, uid: uid, gid: gid},
				{number: 2, guest: filepath.Join(stage, "tree", "two"), uid: uid, gid: gid},
			}}
			reader := strings.NewReplacer(guestMirrorNext, next, " >/dev/console", "").Replace(m.guestFileReader(testNonce))
			script := "rvm_echo=\n" + reader
			tag := fileTag(testNonce)
			for _, l := range lines {
				script += "rvm_file " + shellQuote(strings.TrimPrefix(l, tag)) + "\n"
			}
			out, err := exec.Command(guestBusybox(), "sh", "-c", script).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), string(out))
			return string(out)
		}

		It("rewrites a file mount in place and renames a file in a tree into place", func() {
			before, err := os.Stat(filepath.Join(stage, "file"))
			Expect(err).NotTo(HaveOccurred())
			frames := append(mirrorFrames(testNonce, 1, 1, []byte("new file\n"), 0o640), mirrorFrames(testNonce, 2, 2, bytes.Repeat([]byte("x"), 1000), 0o600)...)
			out := feed(frames...)
			Expect(out).To(Equal(fileOKTag(testNonce) + "1\n" + fileOKTag(testNonce) + "2\n"))

			after, err := os.Stat(filepath.Join(stage, "file"))
			Expect(err).NotTo(HaveOccurred())
			Expect(os.SameFile(before, after)).To(BeTrue(), "a file mount keeps its inode")
			Expect(after.Mode().Perm()).To(Equal(os.FileMode(0o640)))
			Expect(os.ReadFile(filepath.Join(stage, "file"))).To(Equal([]byte("new file\n")))

			two, err := os.Stat(filepath.Join(stage, "tree", "two"))
			Expect(err).NotTo(HaveOccurred())
			Expect(two.Mode().Perm()).To(Equal(os.FileMode(0o600)))
			Expect(os.ReadFile(filepath.Join(stage, "tree", "two"))).To(Equal(bytes.Repeat([]byte("x"), 1000)))
			entries, err := os.ReadDir(next)
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty())
		})

		It("refuses a push whose digest, count, or file number is wrong, and keeps the old file", func() {
			good := mirrorFrames(testNonce, 4, 2, []byte("new two"), 0o644)
			badSum := append([]string(nil), good...)
			badSum[len(badSum)-1] = badSum[len(badSum)-1][:len(badSum[len(badSum)-1])-1] + "0"
			short := append(append([]string(nil), good[0]), good[len(good)-1])
			unknown := mirrorFrames(testNonce, 6, 9, []byte("nowhere"), 0o644)
			mixed := mirrorFrames(testNonce, 7, 1, []byte("x"), 0o644)
			mixed[len(mixed)-1] = strings.Replace(mixed[len(mixed)-1], "end 7 1 ", "end 7 2 ", 1)
			out := feed(append(append(append(badSum, short...), unknown...), mixed...)...)
			bad := fileBadTag(testNonce)
			Expect(out).To(Equal(bad + "4\n" + bad + "4\n" + bad + "6\n" + bad + "7\n"))
			Expect(os.ReadFile(filepath.Join(stage, "tree", "two"))).To(Equal([]byte("old two")))
			Expect(os.ReadFile(filepath.Join(stage, "file"))).To(Equal([]byte("old file")))
		})

		It("discards a frame that a new begin line interrupts", func() {
			first := mirrorFrames(testNonce, 1, 2, []byte("first"), 0o644)
			second := mirrorFrames(testNonce, 2, 2, []byte("second"), 0o644)
			out := feed(append(first[:len(first)-1], second...)...)
			Expect(out).To(Equal(fileOKTag(testNonce) + "2\n"))
			Expect(os.ReadFile(filepath.Join(stage, "tree", "two"))).To(Equal([]byte("second")))
		})
	})

	Describe("the watcher", func() {
		type pushed struct {
			seq    int
			number int
			data   string
			perm   uint32
		}
		var (
			files  []*mirrorWatched
			pushes []pushed
			now    time.Time
			w      *mirrorWatcher
		)

		BeforeEach(func() {
			write("one", "one", 0o644)
			write("two", "two", 0o644)
			files = nil
			for i, name := range []string{"one", "two"} {
				p := filepath.Join(dir, name)
				state, ok := statMirrorFile(p)
				Expect(ok).To(BeTrue())
				files = append(files, &mirrorWatched{number: i + 1, path: p, state: state, data: []byte(name), perm: 0o644})
			}
			pushes = nil
			now = time.Unix(1000, 0)
			w = newMirrorWatcher(files, time.Hour, func(seq int, f *mirrorWatched, data []byte, perm uint32) error {
				pushes = append(pushes, pushed{seq, f.number, string(data), perm})
				return nil
			}, logger)
			w.now = func() time.Time { return now }
		})

		// rewrite gives the file a new inode and modification time, as a
		// rewrite on the host does.
		rewrite := func(name, content string, perm os.FileMode) {
			p := filepath.Join(dir, name)
			Expect(os.WriteFile(p+".new", []byte(content), perm)).To(Succeed())
			Expect(os.Chmod(p+".new", perm)).To(Succeed())
			Expect(os.Rename(p+".new", p)).To(Succeed())
		}

		It("pushes nothing while nothing changes, and pushes a change once the guest acknowledges it", func() {
			w.tick()
			Expect(pushes).To(BeEmpty())

			rewrite("two", "TWO", 0o640)
			w.tick()
			Expect(pushes).To(Equal([]pushed{{1, 2, "TWO", 0o640}}))
			w.tick()
			Expect(pushes).To(HaveLen(1), "one push is in flight until the guest answers or the wait runs out")

			w.acked(1, true)
			w.tick()
			Expect(pushes).To(HaveLen(1))
			Expect(files[1].data).To(Equal([]byte("TWO")))
			Expect(logBuf.String()).To(ContainSubstring("the guest installed push 1 of the mirrored file " + quoteForLog(files[1].path)))
		})

		It("pushes again after a refusal or a silence, and gives up after the resends", func() {
			rewrite("one", "ONE", 0o644)
			w.tick()
			w.acked(1, false)
			w.tick()
			Expect(pushes).To(Equal([]pushed{{1, 1, "ONE", 0o644}, {1, 1, "ONE", 0o644}}))

			now = now.Add(credAckTimeout)
			w.tick()
			Expect(pushes).To(HaveLen(3))
			for range credMaxResends {
				now = now.Add(credAckTimeout)
				w.tick()
			}
			Expect(logBuf.String()).To(ContainSubstring("giving up on push 1 of the mirrored file"))
			n := len(pushes)
			now = now.Add(credAckTimeout)
			w.tick()
			Expect(pushes).To(HaveLen(n))
		})

		It("replaces the push in flight with a newer change, and takes the changed files in turn", func() {
			rewrite("one", "ONE", 0o644)
			rewrite("two", "TWO", 0o644)
			w.tick()
			rewrite("one", "ONE again", 0o644)
			w.tick()
			Expect(pushes).To(Equal([]pushed{{1, 1, "ONE", 0o644}, {2, 2, "TWO", 0o644}}))
			w.acked(1, true)
			w.tick()
			Expect(pushes).To(HaveLen(2), "an answer to a replaced push does not count")
			w.acked(2, true)
			w.tick()
			Expect(pushes).To(Equal([]pushed{{1, 1, "ONE", 0o644}, {2, 2, "TWO", 0o644}, {3, 1, "ONE again", 0o644}}))
		})

		It("pushes a file back when it changes back before the guest answers the push of the change", func() {
			rewrite("one", "ONE", 0o644)
			w.tick()
			rewrite("one", "one", 0o644)
			w.tick()
			Expect(pushes).To(Equal([]pushed{{1, 1, "ONE", 0o644}, {2, 1, "one", 0o644}}))
			w.acked(1, true)
			w.tick()
			Expect(pushes).To(HaveLen(2), "an answer to the replaced push does not count")
			w.acked(2, true)
			w.tick()
			Expect(pushes).To(HaveLen(2))
			Expect(files[0].data).To(Equal([]byte("one")))
		})

		It("pushes the next change after it gave up, even one back to the content it pushed before", func() {
			rewrite("one", "ONE", 0o644)
			w.tick()
			for range credMaxResends + 1 {
				now = now.Add(credAckTimeout)
				w.tick()
			}
			Expect(logBuf.String()).To(ContainSubstring("giving up on push 1 of the mirrored file"))
			n := len(pushes)
			// The guest may hold ONE or one, so vm-launch no longer knows
			// which, and pushes the next change whatever it is.
			rewrite("one", "one", 0o644)
			w.tick()
			Expect(pushes).To(HaveLen(n + 1))
			Expect(pushes[n]).To(Equal(pushed{2, 1, "one", 0o644}))
		})

		It("gives every changed file a turn while another changes after each push", func() {
			rewrite("one", "ONE 1", 0o644)
			rewrite("two", "TWO", 0o644)
			w.tick()
			w.acked(1, true)
			rewrite("one", "ONE 2", 0o644)
			w.tick()
			w.acked(2, true)
			rewrite("one", "ONE 3", 0o644)
			w.tick()
			Expect(pushes).To(Equal([]pushed{{1, 1, "ONE 1", 0o644}, {2, 2, "TWO", 0o644}, {3, 1, "ONE 3", 0o644}}))
		})

		It("keeps the guest's copy of a file that grows too large or goes away, with one line each", func() {
			rewrite("one", strings.Repeat("x", mirrorWatchMaxBytes+1), 0o644)
			Expect(os.Remove(files[1].path)).To(Succeed())
			w.tick()
			w.tick()
			Expect(pushes).To(BeEmpty())
			Expect(strings.Count(logBuf.String(), "is now over the")).To(Equal(1))
			Expect(strings.Count(logBuf.String(), "is gone or is no longer a regular file")).To(Equal(1))

			rewrite("two", "back", 0o644)
			w.tick()
			Expect(pushes).To(Equal([]pushed{{1, 2, "back", 0o644}}))
		})
	})

	Describe("the serial filter", func() {
		start := "RVM_START_" + testNonce + "\r\n"
		marker := "RVM_EXIT_" + testNonce + "=0\r\n"

		It("swallows the guest's word that it takes file pushes and its answers to them", func() {
			var out bytes.Buffer
			var acks []ackReport
			f := newSerialFilter(&out, testNonce)
			f.onFileAck(testNonce, func(seq int, ok bool) { acks = append(acks, ackReport{seq, ok}) })
			_, _ = io.WriteString(f, "boot\r\n"+fileOnTag(testNonce)+"\r\n")
			Expect(f.fileOn).To(BeTrue())
			Expect(string(f.bootLog)).To(Equal("boot\r\n"))
			_, _ = io.WriteString(f, start+"a\r\n"+fileOKTag(testNonce)+"3\r\nb"+fileBadTag(testNonce)+"4\r\n"+credOKTag(testNonce)+"5\r\n"+marker)
			f.finish()
			Expect(acks).To(Equal([]ackReport{{3, true}, {4, false}}))
			Expect(out.String()).To(Equal("a\nb" + credOKTag(testNonce) + "5\n"))
		})

		It("swallows the word of a guest that fell back to the busybox guest that it removed its mirrored mounts, only for a guest with them", func() {
			var out bytes.Buffer
			f := newSerialFilter(&out, testNonce)
			f.onFileAck(testNonce, func(int, bool) {})
			f.onMirror(testNonce)
			_, _ = io.WriteString(f, "boot\r\nbusybox guest: no stack\r\n"+mirrorOffTag(testNonce)+"\r\n")
			Expect(f.mirrorDropped).To(BeTrue())
			Expect(string(f.bootLog)).To(Equal("boot\r\nbusybox guest: no stack\r\n"))
			_, _ = io.WriteString(f, start+"a\r\n"+marker)
			f.finish()
			Expect(f.fileOn).To(BeFalse())
			Expect(out.String()).To(Equal("a\n"))

			out.Reset()
			plain := newSerialFilter(&out, testNonce)
			_, _ = io.WriteString(plain, "boot\r\n"+mirrorOffTag(testNonce)+"\r\n")
			Expect(plain.mirrorDropped).To(BeFalse())
			Expect(string(plain.bootLog)).To(Equal("boot\r\n" + mirrorOffTag(testNonce) + "\r\n"))
			_, _ = io.WriteString(plain, start+marker)
			plain.finish()
		})

		It("leaves fileOn unset for a guest that never says so", func() {
			var out bytes.Buffer
			f := newSerialFilter(&out, testNonce)
			f.onFileAck(testNonce, func(int, bool) {})
			_, _ = io.WriteString(f, "boot\r\n"+start+fileOnTag(testNonce)+"\r\n"+marker)
			f.finish()
			Expect(f.fileOn).To(BeFalse())
			Expect(out.String()).To(Equal(fileOnTag(testNonce) + "\n"))
		})
	})

	It("keeps a binding variable in the stack and image guests' environments only when asked to", func() {
		env := map[string]string{"SERVICE_BINDING_ROOT": "/etc/cf-service-bindings", "VCAP_SERVICES_FILE_PATH": "/etc/cf-service-bindings/vcap_services"}
		kept, err := buildStackGuestEnvKeeping(env, 256, false, "", []string{"SERVICE_BINDING_ROOT"}, logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(kept).To(ContainSubstring("SERVICE_BINDING_ROOT="))
		Expect(kept).NotTo(ContainSubstring("VCAP_SERVICES_FILE_PATH="))
		plain, err := buildStackGuestEnvWithCerts(env, 256, false, "", logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(plain).NotTo(ContainSubstring("SERVICE_BINDING_ROOT="))
		image, err := buildImageGuestEnvKeeping(env, 256, false, "", []string{"VCAP_SERVICES_FILE_PATH"}, logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(image).To(ContainSubstring("VCAP_SERVICES_FILE_PATH="))
		Expect(image).NotTo(ContainSubstring("SERVICE_BINDING_ROOT="))
		Expect(stackGuestDenylist(false)["SERVICE_BINDING_ROOT"]).To(BeTrue(), "the shared deny list is never changed")
	})

	It("keeps a binding variable in each sidecar's environment from the sidecar's own value", func() {
		m := &mountMirror{mounts: []mirrorMount{{path: "/etc/cf-service-bindings", dir: true}}}
		appEnv := map[string]string{"SERVICE_BINDING_ROOT": "/etc/cf-service-bindings"}
		deny := stackGuestDenylist(false)
		sidecars := []vmSidecar{
			{Args: []string{"inherits"}},
			{Args: []string{"outside"}, Env: []string{"SERVICE_BINDING_ROOT=/elsewhere"}},
			{Args: []string{"inside"}, Env: []string{"SERVICE_BINDING_ROOT=/etc/cf-service-bindings/other", "VCAP_SERVICES_FILE_PATH=/etc/cf-service-bindings/vcap_services"}},
			{Args: []string{"unsets"}, Unset: []string{"SERVICE_BINDING_ROOT"}},
		}
		files, err := sidecarGuestFilesMirroring(sidecars, deny, appEnv, m)
		Expect(err).NotTo(HaveOccurred())
		Expect(files).To(HaveLen(4))
		Expect(files[0].env).To(BeEmpty(), "a sidecar without its own value inherits the app's")
		Expect(files[1].env).To(Equal("unset SERVICE_BINDING_ROOT\n"), "a sidecar's value outside the mirrored mounts never reaches the guest, and the app's does not take its place")
		Expect(files[2].env).To(Equal("export SERVICE_BINDING_ROOT=" + sidecarQuote("/etc/cf-service-bindings/other") + "\n" +
			"export VCAP_SERVICES_FILE_PATH=" + sidecarQuote("/etc/cf-service-bindings/vcap_services") + "\n"))
		Expect(files[3].env).To(Equal("unset SERVICE_BINDING_ROOT\n"))

		plain, err := sidecarGuestFilesOf(sidecars, deny)
		Expect(err).NotTo(HaveOccurred())
		withoutMirror, err := sidecarGuestFilesMirroring(sidecars, deny, appEnv, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(withoutMirror).To(Equal(plain))
		for _, f := range plain {
			Expect(f.env).NotTo(ContainSubstring("export SERVICE_BINDING_ROOT"))
			Expect(f.env).NotTo(ContainSubstring("VCAP_SERVICES_FILE_PATH"))
		}
	})

	It("takes --mirror-mounts, off by default", func() {
		cfg, err := parseArgs([]string{"--backend", "vm-qemu", "--", "/bin/true"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.mirrorMounts).To(BeFalse())
		cfg, err = parseArgs([]string{"--backend", "vm-qemu", "--mirror-mounts", "--", "/bin/true"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.mirrorMounts).To(BeTrue())
	})
})
