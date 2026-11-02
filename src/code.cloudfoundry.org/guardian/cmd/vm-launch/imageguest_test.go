//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/rundmc/processes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The account files of the specs' Docker image: root, a named user with a
// home directory, a user without one, and a group that lists the named user
// as a member, which the guest must not give it.
const (
	testImagePasswd = "# the image's users\nroot:x:0:0:root:/root:/bin/false\napp:x:1234:1235:app:/home/app:/nonexistent\nnohome:x:1300:1300:::/nonexistent\nbroken:x:abc:1:::\n"
	testImageGroup  = "root:x:0:\napp:x:1235:\nextra:x:77:app\n"
)

var _ = Describe("the Docker image guest's flags", func() {
	It("puts vm-launch in image mode with the user and the names of Garden's defaults", func() {
		cfg, err := parseArgs([]string{"--backend", "vm-qemu", "--image-user", "app:extra", "--image-default-env", "HOME,PATH,HOME", "--", "/tmp/lifecycle/launcher", "app", "", "{}"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.image).To(Equal(&imageConfig{user: "app:extra", defaultEnv: []string{"HOME", "PATH"}}))
	})

	It("takes an empty list of defaults", func() {
		cfg, err := parseArgs([]string{"--backend", "vm-qemu", "--image-user", "0", "--image-default-env", "", "--", "/tmp/lifecycle/launcher", "app", "", "{}"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.image).To(Equal(&imageConfig{user: "0"}))
	})

	It("leaves image mode off without --image-user", func() {
		cfg, err := parseArgs([]string{"--backend", "vm-qemu", "--", "/tmp/lifecycle/launcher", "app", "true", "{}"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.image).To(BeNil())
	})

	DescribeTable("refuses",
		func(args []string, want string) {
			_, err := parseArgs(append(append([]string{"--backend", "vm-qemu"}, args...), "--", "/tmp/lifecycle/launcher", "app", "", "{}"))
			Expect(err).To(MatchError(want))
		},
		Entry("an empty user", []string{"--image-user", ""}, "--image-user must not be empty"),
		Entry("defaults without a user", []string{"--image-default-env", "HOME"}, "--image-default-env needs --image-user"),
		Entry("a default that Garden never gives", []string{"--image-user", "app", "--image-default-env", "HOME,LANG"}, `--image-default-env names "LANG", and it takes only HOME, PATH, and USER`),
		Entry("an empty name in the list", []string{"--image-user", "app", "--image-default-env", "HOME,"}, `--image-default-env names "", and it takes only HOME, PATH, and USER`),
	)
})

var _ = Describe("resolveImageUser", func() {
	DescribeTable("resolves a user string by Docker's rules",
		func(spec string, want imageUser) {
			want.name = spec
			Expect(resolveImageUser(spec, []byte(testImagePasswd), []byte(testImageGroup))).To(Equal(want))
		},
		Entry("a name in passwd", "app", imageUser{uid: 1234, gid: 1235, home: "/home/app"}),
		Entry("a uid in passwd", "1234", imageUser{uid: 1234, gid: 1235, home: "/home/app"}),
		Entry("root", "root", imageUser{uid: 0, gid: 0, home: "/root"}),
		Entry("an empty user part, which is uid 0", ":77", imageUser{uid: 0, gid: 77, home: "/root"}),
		Entry("a user in passwd without a home", "nohome", imageUser{uid: 1300, gid: 1300, home: "/"}),
		Entry("a uid that passwd does not list", "4321", imageUser{uid: 4321, gid: 0, home: "/"}),
		Entry("a name and a group name", "app:extra", imageUser{uid: 1234, gid: 77, home: "/home/app"}),
		Entry("a name and a gid in group", "app:0", imageUser{uid: 1234, gid: 0, home: "/home/app"}),
		Entry("a uid and a gid that neither file lists", "4321:55", imageUser{uid: 4321, gid: 55, home: "/"}),
		Entry("the highest id", "2147483647:2147483647", imageUser{uid: 2147483647, gid: 2147483647, home: "/"}),
	)

	It("runs root as 0:0 with home / in an image without a root entry", func() {
		Expect(resolveImageUser("root", []byte("app:x:1234:1235::/home/app:\n"), nil)).To(Equal(imageUser{name: "root", home: "/"}))
		Expect(resolveImageUser("root", nil, nil)).To(Equal(imageUser{name: "root", home: "/"}))
	})

	DescribeTable("refuses",
		func(spec, want string) {
			_, err := resolveImageUser(spec, []byte(testImagePasswd), []byte(testImageGroup))
			Expect(err).To(MatchError(want))
		},
		Entry("a name that passwd does not list", "nobody", `the Docker image has no user "nobody" in its /etc/passwd`),
		Entry("a group name that group does not list", "app:wheel", `the Docker image has no group "wheel" in its /etc/group`),
		Entry("an empty group", "app:", `the image user "app:" names an empty group`),
		Entry("a uid above the highest", "2147483648", `the image user "2147483648" is a number above 2147483647`),
		Entry("a gid above the highest", "app:99999999999", `the image group "99999999999" is a number above 2147483647`),
		Entry("a newline", "app\nroot", `the image user "app\nroot" holds a newline or a NUL`),
		Entry("a NUL", "app\x00", `the image user "app\x00" holds a newline or a NUL`),
	)

	It("refuses a passwd file with a line over the cap", func() {
		_, err := resolveImageUser("app", []byte(strings.Repeat("x", maxImageAccountsBytes+1)), nil)
		Expect(err).To(MatchError(ContainSubstring("reading the Docker image's /etc/passwd")))
	})
})

var _ = Describe("the Docker image guest's environment", func() {
	It("keeps Garden's default PATH values", func() {
		Expect("PATH=" + imageRootPath).To(Equal(processes.DefaultRootPath))
		Expect("PATH=" + imageUserPath).To(Equal(processes.DefaultPath))
	})

	It("replaces only the named defaults with the image user's values", func() {
		env := map[string]string{"HOME": "/home/vcap", "PATH": processes.DefaultPath[len("PATH="):], "USER": "app", "LANG": "C"}
		u := imageUser{name: "app", uid: 1234, gid: 1235, home: "/home/app"}

		got := withImageDefaults(env, []string{"HOME"}, u)
		Expect(got).To(Equal(map[string]string{"HOME": "/home/app", "PATH": imageUserPath, "USER": "app", "LANG": "C"}))
		Expect(env["HOME"]).To(Equal("/home/vcap"))

		Expect(withImageDefaults(env, nil, u)).To(Equal(env))
	})

	It("gives root Garden's root PATH and every other user the other", func() {
		env := map[string]string{"PATH": "/from/garden", "USER": "root"}
		Expect(withImageDefaults(env, []string{"PATH", "USER"}, imageUser{name: "root", home: "/"})).To(Equal(map[string]string{"PATH": imageRootPath, "USER": "root"}))
		Expect(withImageDefaults(env, []string{"PATH", "USER"}, imageUser{name: "4321", uid: 4321, home: "/"})).To(Equal(map[string]string{"PATH": imageUserPath, "USER": "4321"}))
	})

	It("keeps HOME and TMPDIR, which describe the image, and denies what the stack guest denies otherwise", func() {
		for _, identity := range []bool{false, true} {
			stack, image := stackGuestDenylist(identity), imageGuestDenylist(identity)
			Expect(stack).To(HaveKey("HOME"))
			Expect(stack).To(HaveKey("TMPDIR"))
			Expect(image).NotTo(HaveKey("HOME"))
			Expect(image).NotTo(HaveKey("TMPDIR"))
			for name := range stack {
				if name != "HOME" && name != "TMPDIR" {
					Expect(image).To(HaveKey(name))
				}
			}
			Expect(image).To(HaveLen(len(stack) - 2))
		}
	})

	It("writes the image's HOME, TMPDIR, PATH, and USER into the guest environment, with no CA bundle path", func() {
		env := map[string]string{"HOME": "/home/app", "TMPDIR": "/scratch", "PATH": imageUserPath, "USER": "app", "PWD": "/somewhere"}
		out, err := buildImageGuestEnvWithCerts(env, minGuestMemoryMiB, false, "", log.New(io.Discard, "", 0))
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("export HOME='/home/app'\n"))
		Expect(out).To(ContainSubstring("export TMPDIR='/scratch'\n"))
		Expect(out).To(ContainSubstring("export PATH='" + imageUserPath + "'\n"))
		Expect(out).To(ContainSubstring("export USER='app'\n"))
		Expect(out).NotTo(ContainSubstring("PWD="))
		Expect(out).NotTo(ContainSubstring(sslCertFileEnv))
	})
})

var _ = Describe("openGuestImage", func() {
	var dir, savedImage, savedPasswd, savedGroup string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		savedImage, savedPasswd, savedGroup = guestImagePath, guestImagePasswd, guestImageGroup
		DeferCleanup(func() { guestImagePath, guestImagePasswd, guestImageGroup = savedImage, savedPasswd, savedGroup })
		guestImagePath = filepath.Join(dir, "rootfs.squashfs")
		guestImagePasswd = filepath.Join(dir, "passwd")
		guestImageGroup = filepath.Join(dir, "group")
		writeSuperblock(guestImagePath, squashfsMagic, squashfsCompressorLZ4)
		Expect(os.WriteFile(guestImagePasswd, []byte(testImagePasswd), 0o644)).To(Succeed())
		Expect(os.WriteFile(guestImageGroup, []byte(testImageGroup), 0o644)).To(Succeed())
	})

	It("names the paths Garden binds by default", func() {
		Expect([]string{savedImage, savedPasswd, savedGroup}).To(Equal([]string{"/opt/garden-vm/image/rootfs.squashfs", "/opt/garden-vm/image/passwd", "/opt/garden-vm/image/group"}))
	})

	It("opens the image read-only and resolves the user against the account files", func() {
		f, u, err := openGuestImage("app")
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(u).To(Equal(imageUser{name: "app", uid: 1234, gid: 1235, home: "/home/app"}))
		_, err = f.Write([]byte("x"))
		Expect(err).To(HaveOccurred())
	})

	It("refuses an image that is not an lz4 squashfs, naming the Docker image", func() {
		Expect(os.Remove(guestImagePath)).To(Succeed())
		writeSuperblock(guestImagePath, squashfsMagic, 1)
		_, _, err := openGuestImage("app")
		Expect(err).To(MatchError("the Docker image " + guestImagePath + " uses squashfs compressor 1, and the guest reads only lz4"))
	})

	It("refuses an account file that is a symbolic link", func() {
		Expect(os.Remove(guestImagePasswd)).To(Succeed())
		Expect(os.Symlink(guestImageGroup, guestImagePasswd)).To(Succeed())
		f, _, err := openGuestImage("app")
		Expect(f).To(BeNil())
		Expect(err).To(MatchError(ContainSubstring("opening the Docker image's account file " + guestImagePasswd)))
	})

	It("refuses an account file that is not a regular file", func() {
		Expect(os.Remove(guestImageGroup)).To(Succeed())
		Expect(os.Mkdir(guestImageGroup, 0o755)).To(Succeed())
		_, _, err := openGuestImage("app:extra")
		Expect(err).To(MatchError("the Docker image's account file " + guestImageGroup + " is not a regular file"))
	})

	It("refuses an account file over the cap", func() {
		Expect(os.WriteFile(guestImagePasswd, bytes.Repeat([]byte("#\n"), maxImageAccountsBytes/2+1), 0o444)).To(Succeed())
		_, _, err := openGuestImage("app")
		Expect(err).To(MatchError("the Docker image's account file " + guestImagePasswd + " is over 1048576 bytes"))
	})

	It("refuses a user the image does not have", func() {
		_, _, err := openGuestImage("nobody")
		Expect(err).To(MatchError(`the Docker image has no user "nobody" in its /etc/passwd`))
	})
})

var _ = Describe("the Docker image guest's command", func() {
	var dir, stub string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		// The stub stands in for busybox setpriv and nsenter, which need
		// root. It prints its name, its pid, and each argument in brackets,
		// and then runs what follows -- from the test's app root.
		stub = filepath.Join(dir, "bin", "drop")
		Expect(os.MkdirAll(filepath.Dir(stub), 0o755)).To(Succeed())
		Expect(os.WriteFile(stub, []byte(`#!/bin/sh
echo "drop $$"
for a; do printf '[%s]\n' "$a"; done
while [ "$1" != -- ]; do shift; done
shift
prog=$1
shift
exec `+shellQuote(dir+"/rvm/app")+`"$prog" "$@"
`), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(dir, "rvm", "app", "tmp", "lifecycle"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "rvm", "app", "tmp", "lifecycle", "launcher"), []byte(`#!/bin/sh
echo "launcher $$"
for a; do printf '[%s]\n' "$a"; done
echo "FROM_ENV=$FROM_ENV"
exit "${LAUNCHER_RC:-0}"
`), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "rvm", "env"), []byte("export FROM_ENV='from /rvm/env'\nexport PATH='/nowhere'\n"), 0o600)).To(Succeed())
	})

	// run runs text and the status line in the guest's busybox sh, with the
	// drop's two busybox programs replaced by the stub, the guest paths
	// moved into the test directory, and cat called through the test's
	// busybox. It returns the standard output and the pid the subshell
	// recorded.
	run := func(text string, env ...string) (string, string) {
		GinkgoHelper()
		text = strings.NewReplacer(
			"/bin/busybox setpriv --nnp /bin/busybox nsenter", stub,
			guestRootCat, guestBusybox()+" cat",
			"/rvm/", dir+"/rvm/",
		).Replace("RVM_NOFILE_HARD=$(ulimit -H -n) RVM_NOFILE_SOFT=256\n"+text+guestRunStatus) + "echo \"status=$rvm_status\"\n"
		Expect(text).To(ContainSubstring(stub + " -r"))
		cmd := exec.Command(guestBusybox(), "sh", "-c", text)
		cmd.Env = append([]string{"PATH=/usr/bin:/bin"}, env...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		Expect(err).NotTo(HaveOccurred(), stderr.String())
		pid, err := os.ReadFile(filepath.Join(dir, "rvm", "app-pid"))
		Expect(err).NotTo(HaveOccurred(), stderr.String())
		return string(out), strings.TrimSuffix(string(pid), "\n")
	}

	// appRun is the app's line from img's run section, in a subshell that
	// records its pid as the run section's does.
	appRun := func(img *guestImage) string {
		app := (&guestStack{cwd: "/"}).processes()[0]
		return "command exec 3>&2\n( read -r rvm_self rvm_rest </proc/self/stat && echo \"$rvm_self\" >" + guestAppPid + " && " + img.exec(app) + " ) </dev/null\n"
	}

	bracketed := func(args ...string) string {
		var b strings.Builder
		for _, a := range args {
			b.WriteString("[" + a + "]\n")
		}
		return b.String()
	}

	It("drops to the image's uid and gid in the app root with no_new_privs, by the busybox binary's path, and enters the app root as its working directory", func() {
		Expect((&guestImage{uid: 1234, gid: 1235}).drop()).To(Equal(`/bin/busybox setpriv --nnp /bin/busybox nsenter -r/rvm/app -w/rvm/app -S 1234 -G 1235 -F -- "$@"`))
		Expect((&guestImage{}).drop()).To(Equal(`/bin/busybox setpriv --nnp /bin/busybox nsenter -r/rvm/app -w/rvm/app -S 0 -G 0 -F -- "$@"`))
	})

	It("runs the launcher's argv through the drop, unchanged, with the recorded pid that of every program it execs", func() {
		argv := []string{"/tmp/lifecycle/launcher", "app", "echo \"it's $HOME\" `id -u`\nsecond line", "", `{"cmd":["/server"]}`}
		Expect(os.WriteFile(filepath.Join(dir, "rvm", "argv"), []byte(shellJoin(argv)), 0o644)).To(Succeed())
		out, pid := run(appRun(&guestImage{uid: 1234, gid: 1235}))
		Expect(pid).To(MatchRegexp(`^[1-9][0-9]*$`))
		Expect(out).To(Equal("drop " + pid + "\n" +
			bracketed(append([]string{"-r" + dir + "/rvm/app", "-w" + dir + "/rvm/app", "-S", "1234", "-G", "1235", "-F", "--"}, argv...)...) +
			"launcher " + pid + "\n" + bracketed(argv[1:]...) +
			"FROM_ENV=from /rvm/env\nstatus=0\n"))
	})

	It("keeps the launcher's exit status", func() {
		Expect(os.WriteFile(filepath.Join(dir, "rvm", "argv"), []byte(shellJoin([]string{"/tmp/lifecycle/launcher", "app", "", ""})), 0o644)).To(Succeed())
		out, _ := run(appRun(&guestImage{}), "LAUNCHER_RC=7")
		Expect(out).To(HaveSuffix("status=7\n"))
	})

	It("runs a sidecar's argv through the same drop after its environment files", func() {
		line := (&guestImage{uid: 9, gid: 8}).exec(guestProcess{index: 1, argvPath: "/rvm/sidecars/1/argv", envPaths: []string{"/rvm/env", "/rvm/sidecars/1/env"}, dir: "/"})
		Expect(line).To(Equal(`. /rvm/env && . /rvm/sidecars/1/env && eval "set -- $(` + guestRootCat + ` /rvm/sidecars/1/argv)" && exec /bin/busybox setpriv --nnp /bin/busybox nsenter -r/rvm/app -w/rvm/app -S 9 -G 8 -F -- "$@"`))
	})
})

var _ = Describe("stage 1 of the Docker image guest", func() {
	var dir, bin, callLog, root, app string
	var paths *strings.Replacer

	type imageStep struct{ call, line string }

	// imageSteps are the stubbed commands of a boot with a root disk of an
	// image without proc, sys, dev, or tmp, in order.
	imageSteps := func() []imageStep {
		d := dir + "/rvm"
		return []imageStep{
			{"mkdir -p " + d + "/disk " + d + "/stack " + d + "/app", "creating the image guest's mount points failed"},
			{"mke2fs -F -b 4096 -m 0 -I 256 -i 16384 -L rvm-root " + root, "formatting the guest root disk " + root + " failed"},
			{"mount -t ext4 -o noatime,discard,errors=continue " + root + " " + d + "/disk", "mounting the guest root disk " + root + " failed"},
			{"mkdir " + d + "/disk/upper " + d + "/disk/work", "creating the overlay directories failed"},
			{"mount -t squashfs -o ro /dev/vdb " + d + "/stack", "mounting the Docker image /dev/vdb failed; the guest kernel needs squashfs with lz4"},
			{"mount -t overlay -o lowerdir=" + d + "/stack,upperdir=" + d + "/disk/upper,workdir=" + d + "/disk/work overlay " + d + "/app", "mounting the app root overlay over the Docker image failed; the guest kernel needs overlayfs"},
			{"mkdir -m 0555 " + d + "/app/proc", "making /proc a directory in the app root failed"},
			{"mkdir -m 0555 " + d + "/app/sys", "making /sys a directory in the app root failed"},
			{"mkdir -m 0755 " + d + "/app/dev", "making /dev a directory in the app root failed"},
			{"mkdir -m 1777 " + d + "/app/tmp", "making /tmp a directory in the app root failed"},
			{"mkdir -m 0755 " + d + "/app/tmp/lifecycle", "making /tmp/lifecycle a directory in the app root failed"},
			{"mount -t proc -o nosuid,nodev,noexec proc " + d + "/app/proc", "mounting /proc in the app root failed"},
			{"mount -t sysfs -o ro,nosuid,nodev,noexec sys " + d + "/app/sys", "mounting /sys in the app root failed"},
			{"mount -o bind /dev " + d + "/app/dev", "binding /dev into the app root failed"},
			{"mkdir -p " + d + "/app/dev/shm", "creating /dev/shm in the app root failed"},
			{"mount -t tmpfs -o noexec,nosuid,nodev,mode=1777,size=50% tmpfs " + d + "/app/dev/shm", "mounting /dev/shm in the app root failed"},
			{"mount -o bind " + d + "/lifecycle " + d + "/app/tmp/lifecycle", "binding the lifecycle into the app root failed"},
			{"mount -o remount,bind,ro " + d + "/app/tmp/lifecycle", "making the lifecycle in the app root read-only failed"},
			{"hostname -F " + d + "/hostname", "setting the guest's hostname failed"},
		}
	}

	callsOf := func(steps []imageStep) string {
		var calls strings.Builder
		for _, s := range steps {
			calls.WriteString(s.call + "\n")
		}
		return calls.String()
	}

	failLine := func(msg string) string {
		return "vm-launch guest setup: " + paths.Replace(msg) + "\nREBOOT\n"
	}

	writeFile := func(name, content string, perm os.FileMode) {
		GinkgoHelper()
		p := filepath.Join(dir, name)
		Expect(os.MkdirAll(filepath.Dir(p), 0o755)).To(Succeed())
		Expect(os.WriteFile(p, []byte(content), perm)).To(Succeed())
	}

	readFile := func(name string) string {
		GinkgoHelper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		Expect(err).NotTo(HaveOccurred())
		return string(b)
	}

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		paths = strings.NewReplacer("/rvm/", dir+"/rvm/")
		bin = filepath.Join(dir, "bin")
		Expect(os.Mkdir(bin, 0o755)).To(Succeed())
		callLog = filepath.Join(dir, "calls")
		app = filepath.Join(dir, "rvm", "app")

		// Each stub records its argv and fails when RVM_TEST_FAIL is the
		// line it recorded. mkdir then makes the directories, and the bind
		// of the lifecycle copies it, so that the launcher check sees the
		// launcher; the other mounts change nothing.
		stub := func(name, body string) {
			script := "#!/bin/sh\nline=\"" + name + " $*\"\necho \"$line\" >> " + shellQuote(callLog) + "\n" +
				"[ \"$line\" != \"${RVM_TEST_FAIL:-}\" ] || exit 1\n" + body + "\n"
			Expect(os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755)).To(Succeed())
		}
		stub("mkdir", `exec /bin/mkdir "$@"`)
		stub("mount", `if [ "$1 $2 $3" = "-o bind `+dir+`/rvm/lifecycle" ]; then exec /bin/cp -R "$3/." "$4/"; fi`)
		for _, name := range []string{"hostname", "mke2fs"} {
			stub(name, "exit 0")
		}

		root = filepath.Join(dir, "vda")
		Expect(os.WriteFile(root, nil, 0o600)).To(Succeed())
		Expect(os.Truncate(root, 1<<20)).To(Succeed())

		// The app root holds what the overlay of a Docker image would show:
		// no proc, sys, or dev, a tmp that is a link to etc, an etc/hosts
		// that is a link to passwd, and a resolv.conf that is a link out of
		// etc.
		writeFile("rvm/app/etc/passwd", testImagePasswd, 0o644)
		writeFile("rvm/app/etc/hostname", "image\n", 0o644)
		writeFile("rvm/app/etc/ssl/certs/ca-certificates.crt", "the image's bundle\n", 0o644)
		writeFile("rvm/app/outside/resolv.conf", "nameserver 127.0.0.53\n", 0o644)
		Expect(os.Symlink("passwd", filepath.Join(app, "etc", "hosts"))).To(Succeed())
		Expect(os.Symlink("../outside/resolv.conf", filepath.Join(app, "etc", "resolv.conf"))).To(Succeed())
		Expect(os.Symlink("etc", filepath.Join(app, "tmp"))).To(Succeed())
		writeFile("rvm/lifecycle/launcher", "", 0o755)
		writeFile("rvm/hosts", "127.0.0.1 localhost\n10.255.0.2 instance-guid\n", 0o644)
		writeFile("rvm/hostname", "instance-guid\n", 0o644)
		writeFile("etc/resolv.conf", "nameserver 169.254.0.2\n", 0o644)
	})

	// run runs rvm_fail and the image branch in the guest's busybox sh, as
	// the stack guest's stage 1 spec does, and returns the standard output
	// and the calls the stubs recorded.
	run := func(vars string, env ...string) (string, string) {
		GinkgoHelper()
		script := strings.NewReplacer(
			"reboot -nf", "echo REBOOT",
			"mount -", filepath.Join(bin, "mount")+" -",
			"/dev/console", "/dev/stdout",
			"mkdir ", filepath.Join(bin, "mkdir")+" ",
			"hostname -F", filepath.Join(bin, "hostname")+" -F",
			"mke2fs -F", filepath.Join(bin, "mke2fs")+" -F",
			"/rvm/", dir+"/rvm/",
			"cat /etc/", "cat "+dir+"/etc/",
		).Replace(guestFailFunc+vars+guestImageSetup) + "echo STAGE1_DONE\n"
		Expect(strings.Count(script, filepath.Join(bin, "mount")+" -")).To(Equal(strings.Count(guestImageSetup, "mount -")))
		Expect(strings.Count(script, filepath.Join(bin, "mkdir")+" ")).To(Equal(strings.Count(guestImageSetup, "mkdir ")))
		Expect(script).NotTo(ContainSubstring("cat /etc/"))

		cmd := exec.Command(guestBusybox(), "sh", "-c", script)
		cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin"}, env...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			_, ok := err.(*exec.ExitError)
			Expect(ok).To(BeTrue(), "%v: %s", err, stderr.String())
		}
		calls, err := os.ReadFile(callLog)
		if os.IsNotExist(err) {
			err = nil
		}
		Expect(err).NotTo(HaveOccurred())
		return string(out), string(calls)
	}

	withRoot := func() string {
		return "rvm_devtmpfs=1 rvm_root=" + shellQuote(root) + " rvm_stack=/dev/vdb RVM_ROOT_INODE_RATIO=16384\n"
	}
	const withoutRoot = "rvm_devtmpfs=1 rvm_root= rvm_stack=/dev/vdb\n"

	It("lays one overlay over the image, makes every mount point a real directory without following the image's links, and writes the guest's files", func() {
		out, calls := run(withRoot())
		Expect(out).To(Equal("STAGE1_DONE\n"))
		Expect(calls).To(Equal(callsOf(imageSteps())))

		// The image's tmp was a link to etc. It is a directory now, and
		// etc holds no lifecycle.
		info, err := os.Lstat(filepath.Join(app, "tmp"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.IsDir()).To(BeTrue(), info.Mode().String())
		Expect(info.Mode() & (os.ModePerm | os.ModeSticky)).To(Equal(os.ModePerm | os.ModeSticky))
		Expect(filepath.Join(app, "etc", "lifecycle")).NotTo(BeAnExistingFile())
		Expect(filepath.Join(app, "tmp", "lifecycle", "launcher")).To(BeAnExistingFile())

		// hosts and resolv.conf were links, which stage 1 replaced with the
		// guest's files instead of writing through them.
		for _, name := range []string{"hosts", "resolv.conf"} {
			info, err := os.Lstat(filepath.Join(app, "etc", name))
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().IsRegular()).To(BeTrue(), name+" "+info.Mode().String())
		}
		Expect(readFile("rvm/app/etc/hosts")).To(Equal("127.0.0.1 localhost\n10.255.0.2 instance-guid\n"))
		Expect(readFile("rvm/app/etc/passwd")).To(Equal(testImagePasswd))
		Expect(readFile("rvm/app/etc/resolv.conf")).To(Equal("nameserver 169.254.0.2\n"))
		Expect(readFile("rvm/app/outside/resolv.conf")).To(Equal("nameserver 127.0.0.53\n"))
		Expect(readFile("rvm/app/etc/hostname")).To(Equal("instance-guid\n"))
		// The image keeps its own CA bundle, as a runC container of it does.
		Expect(readFile("rvm/app/etc/ssl/certs/ca-certificates.crt")).To(Equal("the image's bundle\n"))
		Expect(filepath.Join(dir, "rvm", "disk", "upper")).To(BeADirectory())
		Expect(filepath.Join(dir, "rvm", "disk", "home-upper")).NotTo(BeAnExistingFile())
	})

	It("mounts a tmpfs for the app's writes in a guest without a root disk, and never formats anything", func() {
		out, calls := run(withoutRoot)
		Expect(out).To(Equal("STAGE1_DONE\n"))
		steps := imageSteps()
		Expect(calls).To(Equal(callsOf(steps[:1]) + "mount -t tmpfs -o mode=0755 tmpfs " + dir + "/rvm/disk\n" + callsOf(steps[3:])))
	})

	It("replaces a mount point that is a file or a link to a directory, and keeps one that is a directory", func() {
		writeFile("rvm/app/proc", "not a directory\n", 0o644)
		Expect(os.MkdirAll(filepath.Join(app, "outside", "sys"), 0o755)).To(Succeed())
		Expect(os.Symlink("outside/sys", filepath.Join(app, "sys"))).To(Succeed())
		Expect(os.Mkdir(filepath.Join(app, "dev"), 0o700)).To(Succeed())
		out, calls := run(withRoot())
		Expect(out).To(Equal("STAGE1_DONE\n"))
		Expect(calls).To(ContainSubstring("mkdir -m 0555 " + app + "/proc\n"))
		Expect(calls).To(ContainSubstring("mkdir -m 0555 " + app + "/sys\n"))
		Expect(calls).NotTo(ContainSubstring("mkdir -m 0755 " + app + "/dev\n"))
		Expect(filepath.Join(app, "proc")).To(BeADirectory())
		info, err := os.Lstat(filepath.Join(app, "sys"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.IsDir()).To(BeTrue(), info.Mode().String())
		Expect(filepath.Join(app, "outside", "sys")).To(BeADirectory())
	})

	It("replaces an etc that is a link before it writes anything there", func() {
		Expect(os.RemoveAll(filepath.Join(app, "etc"))).To(Succeed())
		Expect(os.Remove(filepath.Join(app, "tmp"))).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(app, "outside", "etc"), 0o755)).To(Succeed())
		Expect(os.Symlink("outside/etc", filepath.Join(app, "etc"))).To(Succeed())
		out, calls := run(withRoot())
		Expect(out).To(Equal("STAGE1_DONE\n"))
		Expect(calls).To(ContainSubstring("mkdir -m 0755 " + app + "/etc\n"))
		Expect(readFile("rvm/app/etc/hosts")).To(Equal("127.0.0.1 localhost\n10.255.0.2 instance-guid\n"))
		entries, err := os.ReadDir(filepath.Join(app, "outside", "etc"))
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty())
	})

	DescribeTable("fails the boot, with no fallback, when a step fails",
		func(step int) {
			s := imageSteps()[step]
			out, calls := run(withRoot(), "RVM_TEST_FAIL="+s.call)
			Expect(out).To(Equal(failLine(s.line)))
			Expect(calls).To(HaveSuffix(s.call + "\n"))
		},
		Entry("the image's mount", 4),
		Entry("the overlay", 5),
		Entry("the mount point for /tmp", 9),
		Entry("the lifecycle's bind", 16),
	)

	It("fails the boot without a Docker image drive", func() {
		out, calls := run("rvm_devtmpfs=1 rvm_root= rvm_stack=\n")
		Expect(out).To(Equal(failLine("/rvm/disks names no Docker image drive, so the guest has no image to run the app on")))
		Expect(calls).To(BeEmpty())
	})

	It("fails the boot when the lifecycle holds no executable launcher", func() {
		Expect(os.Chmod(filepath.Join(dir, "rvm", "lifecycle", "launcher"), 0o644)).To(Succeed())
		out, _ := run(withRoot())
		Expect(out).To(Equal(failLine("the app root has no executable /tmp/lifecycle/launcher")))
	})
})

var _ = Describe("the Docker image guest's drives and archive", func() {
	image := func() *guestStack {
		return &guestStack{argv: "'/tmp/lifecycle/launcher'", cwd: "/", hostname: "h", image: &guestImage{uid: 1, gid: 1}}
	}

	It("names only the image, in the stack's place, in /rvm/disks", func() {
		g := taskGuest("")
		g.stack = image()
		g.drives = guestDrives{stackID: qemuStackSerial}
		disks, err := disksFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(disks).To(Equal("RVM_VOLUMES=0\nRVM_STACK_ID=rvm-stack\n"))

		g.drives.dropletID = qemuDropletSerial
		_, err = disksFile(g)
		Expect(err).To(HaveOccurred())
		g.drives = guestDrives{}
		_, err = disksFile(g)
		Expect(err).To(HaveOccurred())
	})

	It("gives the image the stack's identity and refuses a droplet", func() {
		img := openSizedFile(4096)
		drives, err := newGuestDrivesWithStack(backend.VMQemu, nil, nil, &stackDrives{stack: img, image: true})
		Expect(err).NotTo(HaveOccurred())
		Expect(drives.stackID).To(Equal(qemuStackSerial))
		Expect(drives.dropletID).To(BeEmpty())

		_, err = newGuestDrivesWithStack(backend.VMQemu, nil, nil, &stackDrives{stack: img, droplet: openSizedFile(4096), image: true})
		Expect(err).To(MatchError(ContainSubstring("the Docker image guest has no droplet image, yet it was given one")))
	})

	It("gives QEMU and Firecracker the image as the one read-only drive after the root", func() {
		img := openSizedFile(4096)
		sd := &stackDrives{stack: img, image: true}
		files, _, _, _, _ := hypervisorFilesWithStack(nil, img, nil, nil, sd)
		Expect(files).To(HaveLen(2))

		argv, err := hypervisorArgvWithStack(backend.VMQemu, "/art", GinkgoT().TempDir(), "/initrd", minGuestMemoryMiB, taskNetwork(), nil, "", 0, sd)
		Expect(err).NotTo(HaveOccurred())
		joined := strings.Join(argv, "\n")
		Expect(joined).To(ContainSubstring(strings.Join(qemuReadOnlyDrive(stackDriveID, qemuStackSerial, 4), "\n")))
		Expect(joined).NotTo(ContainSubstring(qemuDropletSerial))
	})

	It("refuses a fallback", func() {
		s := image()
		s.launcher = guestTool{name: "launcher", file: openSizedFile(1), size: 1}
		s.fallback = true
		Expect(s.check()).To(MatchError("the Docker image guest has no busybox guest to fall back to, yet it was given one"))
	})
})

var _ = Describe("run with a Docker image", func() {
	const (
		hostname = "c0ffee00-1111-4222-8333-444455556666"
		hosts    = "127.0.0.1 localhost\n10.255.7.9 " + hostname + "\n"
	)

	var (
		art, tmp, dir, imagePath, launcher, qemu string
		logBuf                                   *bytes.Buffer
	)

	BeforeEach(func() {
		art = makeArtifacts()
		qemu = filepath.Join(art, "qemu/ld-linux-x86-64.so.2")
		// A droplet build would fail the launch, so a spec that passes
		// shows that the image guest builds none.
		Expect(os.WriteFile(filepath.Join(art, artMksquashfs), []byte("#!/bin/sh\necho 'the image guest built a droplet' >&2\nexit 1\n"), 0o755)).To(Succeed())
		dir = GinkgoT().TempDir()
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		GinkgoT().Setenv("VCAP_APPLICATION", `{"limits":{"mem":512}}`)
		GinkgoT().Setenv("HOME", "/home/vcap")
		GinkgoT().Setenv("PATH", os.Getenv("PATH"))
		GinkgoT().Setenv("USER", "root")
		GinkgoT().Setenv("FROM_GARDEN", "kept")
		logBuf = &bytes.Buffer{}

		imagePath = filepath.Join(dir, "image", "rootfs.squashfs")
		Expect(os.MkdirAll(filepath.Dir(imagePath), 0o755)).To(Succeed())
		writeSuperblock(imagePath, squashfsMagic, squashfsCompressorLZ4)
		Expect(os.WriteFile(filepath.Join(dir, "image", "passwd"), []byte(testImagePasswd), 0o444)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "image", "group"), []byte(testImageGroup), 0o444)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "hosts"), []byte(hosts), 0o644)).To(Succeed())
		launcher = filepath.Join(dir, "lifecycle", "launcher")
		Expect(os.MkdirAll(filepath.Dir(launcher), 0o755)).To(Succeed())
		Expect(os.WriteFile(launcher, []byte("the Docker lifecycle's launcher\n"), 0o755)).To(Succeed())

		savedStack, savedImage, savedPasswd, savedGroup := stackImagePath, guestImagePath, guestImagePasswd, guestImageGroup
		savedHosts, savedHostname, savedNonce := containerHostsPath, containerHostname, guestNonce
		DeferCleanup(func() {
			stackImagePath, guestImagePath, guestImagePasswd, guestImageGroup = savedStack, savedImage, savedPasswd, savedGroup
			containerHostsPath, containerHostname, guestNonce = savedHosts, savedHostname, savedNonce
		})
		// The container has no stack image, so a launch that took the stack
		// path would show it.
		stackImagePath = filepath.Join(dir, "none", "rootfs.squashfs")
		guestImagePath = imagePath
		guestImagePasswd = filepath.Join(dir, "image", "passwd")
		guestImageGroup = filepath.Join(dir, "image", "group")
		containerHostsPath = filepath.Join(dir, "hosts")
		containerHostname = func() (string, error) { return hostname, nil }
		guestNonce = func() (string, error) { return testNonce, nil }
	})

	runWith := func(kind backend.Kind, user string, args ...string) int {
		return run(append([]string{"--backend", string(kind), "--artifacts", art, "--image-user", user, "--image-default-env", "HOME,PATH,USER", "--"}, args...), log.New(logBuf, "", 0))
	}

	It("gives QEMU the image as the one read-only drive in the stack's place, and a guest that runs the launcher on it as the image's user", func() {
		initrdCopy := filepath.Join(art, "initrd-copy")
		argvFile := writeFakeHypervisor(qemu, `cp "$initrd" `+shellQuote(initrdCopy)+` || exit 1
`+initramfsAt("3")+readOnlyImageAt("5", "*/rootfs.squashfs", imagePath)+noFilesUnder(tmp)+initramfsReleased+stackImagesReleased)
		Expect(runWith(backend.VMQemu, "app", launcher, "app", "", `{"cmd":["/server"]}`)).To(Equal(0), logBuf.String())

		argv, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(argv)).To(ContainSubstring(strings.Join(qemuReadOnlyDrive(stackDriveID, qemuStackSerial, 5), "\n") + "\n"))
		Expect(string(argv)).NotTo(ContainSubstring(qemuDropletSerial))

		raw, err := os.ReadFile(initrdCopy)
		Expect(err).NotTo(HaveOccurred())
		_, byName := archiveEntries(raw)
		Expect(string(byName["init"].data)).To(Equal(guestImageInit))
		procs := (&guestStack{cwd: "/"}).processes()
		Expect(string(byName["rvm/init"].data)).To(Equal(stage2Script(testNonce, false, true, guestRunSetup(false, procs), guestRunSection(testNonce, procs, false, (&guestImage{uid: 1234, gid: 1235}).exec))))
		Expect(string(byName["rvm/lifecycle/launcher"].data)).To(Equal("the Docker lifecycle's launcher\n"))
		Expect(string(byName["rvm/argv"].data)).To(Equal(`'/tmp/lifecycle/launcher' 'app' '' '{"cmd":["/server"]}'`))
		Expect(string(byName["rvm/cwd"].data)).To(Equal("/"))
		Expect(string(byName["rvm/disks"].data)).To(Equal("RVM_VOLUMES=0\nRVM_STACK_ID=rvm-stack\n"))
		Expect(byName).NotTo(HaveKey("rvm/fallback/init"))
		env := string(byName["rvm/env"].data)
		Expect(env).To(ContainSubstring("export HOME='/home/app'\n"))
		Expect(env).To(ContainSubstring("export PATH='" + imageUserPath + "'\n"))
		Expect(env).To(ContainSubstring("export USER='app'\n"))
		Expect(env).To(ContainSubstring("export FROM_GARDEN='kept'\n"))
		Expect(env).NotTo(ContainSubstring(sslCertFileEnv))

		Expect(logBuf.String()).To(ContainSubstring("image guest: the launcher runs on the Docker image as uid 1234 and gid 1235, with an image of 96 bytes\n"))
		Expect(strings.Count(logBuf.String(), "guest: ")).To(Equal(1), logBuf.String())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(heldFilesEndingIn("rootfs.squashfs")).To(BeZero())
	})

	It("gives Firecracker the image as its one read-only drive", func() {
		letFirecrackerSeeVMLaunch()
		fcCopy := filepath.Join(art, "fc-copy.json")
		writeFakeHypervisor(filepath.Join(art, "firecracker/firecracker"),
			`p=; for a in "$@"; do [ "$p" = --config-file ] && cp "$a" `+shellQuote(fcCopy)+`; p=$a; done
`+initramfsAt("3")+readOnlyImageAt("4", "*/rootfs.squashfs", imagePath)+stackImagesReleased)
		Expect(runWith(backend.VMFirecracker, "4321:55", launcher, "app", "", "{}")).To(Equal(0), logBuf.String())

		raw, err := os.ReadFile(fcCopy)
		Expect(err).NotTo(HaveOccurred())
		var cfg struct {
			Drives []firecrackerDrive `json:"drives"`
		}
		Expect(json.Unmarshal(raw, &cfg)).To(Succeed())
		Expect(cfg.Drives).To(HaveLen(1))
		Expect(cfg.Drives[0].PathOnHost).To(Equal("/proc/self/fd/4"))
		Expect(cfg.Drives[0].IsReadOnly).To(BeTrue())
		Expect(logBuf.String()).To(ContainSubstring("image guest: the launcher runs on the Docker image as uid 4321 and gid 55"))
	})

	// expectRefused checks that a launch with args is refused with the
	// image guest's line for why, before any hypervisor starts.
	expectRefused := func(user string, args []string, why string) {
		GinkgoHelper()
		argvFile := writeFakeHypervisor(qemu, "")
		Expect(runWith(backend.VMQemu, user, args...)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("image guest: " + why + "\n"))
		Expect(logBuf.String()).NotTo(ContainSubstring("busybox guest"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(heldFilesEndingIn("rootfs.squashfs")).To(BeZero())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	}

	It("refuses a process that is not the CF launcher", func() {
		expectRefused("app", []string{"/bin/sh", "-c", "echo hi"}, "the process is not the CF launcher")
	})

	It("refuses a container without the image", func() {
		Expect(os.Remove(imagePath)).To(Succeed())
		expectRefused("app", []string{launcher, "app", "", "{}"}, "the Docker image cannot be opened: open "+imagePath+": no such file or directory")
	})

	It("refuses a user the image does not have", func() {
		expectRefused("nobody", []string{launcher, "app", "", "{}"}, `the Docker image has no user "nobody" in its /etc/passwd`)
	})

	It("refuses an app with a volume", func() {
		GinkgoT().Setenv("CF_INSTANCE_INDEX", "2")
		GinkgoT().Setenv("VCAP_APPLICATION", vcapApp)
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"juicefs": {mountJSON(filepath.Join(dir, "volume"), "rw")}}))
		expectRefused("app", []string{launcher, "app", "", "{}"}, "the Docker image guest mounts no volumes, and the app has 1")
	})
})
