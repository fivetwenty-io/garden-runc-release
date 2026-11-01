//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// realStackToolsSource is the program that stands in for the stack's GNU
// env and util-linux setpriv in the test stack, built static for the guest.
// Run as env, it takes only -C DIR PROG ARGS, as root, and NAME=value...
// PROG ARGS, as uid 2000, and run as setpriv, only the exact options stage 2
// passes (see guestStackRunCommand), so a change to that command line fails
// the boot instead of passing unnoticed. Either one refuses to run as root
// with a loader variable in its environment, because the stack's own,
// dynamically linked, would load what the variable names (see
// guestLoaderNames), so a guest that let one through fails the boot. Its setpriv
// does what util-linux's does with those options: it sets the supplementary
// groups to the gid and to every group in /etc/group that lists the user
// /etc/passwd gives the uid, sets the real, effective, and saved gid and uid,
// and sets no_new_privs on every thread before it execs PROG.
const realStackToolsSource = `package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// prSetNoNewPrivs is PR_SET_NO_NEW_PRIVS from linux/prctl.h.
const prSetNoNewPrivs = 38

// vcap is the uid and gid the app runs as.
const vcap = 2000

// loaderNames are variables that glibc's loader would act on in a
// dynamically linked env or setpriv.
var loaderNames = []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "GCONV_PATH"}

func main() {
	var err error
	for _, name := range loaderNames {
		if _, set := os.LookupEnv(name); set && os.Getuid() == 0 {
			fmt.Fprintf(os.Stderr, "%s: %s reached it while it runs as root\n", filepath.Base(os.Args[0]), name)
			os.Exit(125)
		}
	}
	switch name := filepath.Base(os.Args[0]); name {
	case "env":
		err = env(os.Args[1:])
	case "setpriv":
		err = setpriv(os.Args[1:])
	default:
		err = fmt.Errorf("run as %s, which is neither env nor setpriv", name)
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", filepath.Base(os.Args[0]), err)
	os.Exit(125)
}

func env(args []string) error {
	if os.Getuid() != 0 {
		for len(args) > 0 && strings.Contains(args[0], "=") {
			name, value, _ := strings.Cut(args[0], "=")
			if err := os.Setenv(name, value); err != nil {
				return err
			}
			args = args[1:]
		}
		if len(args) == 0 {
			return fmt.Errorf("want NAME=value... PROG [ARG...] as uid %d, got no PROG", os.Getuid())
		}
		return run(args)
	}
	if len(args) < 3 || args[0] != "-C" {
		return fmt.Errorf("want -C DIR PROG [ARG...] as root, got %q", args)
	}
	if err := os.Chdir(args[1]); err != nil {
		return err
	}
	return run(args[2:])
}

func setpriv(args []string) error {
	want := []string{"--reuid=2000", "--regid=2000", "--init-groups", "--no-new-privs", "--"}
	if len(args) <= len(want) || strings.Join(args[:len(want)], "\x00") != strings.Join(want, "\x00") {
		return fmt.Errorf("want %q PROG [ARG...], got %q", want, args)
	}
	groups, err := initGroups()
	if err != nil {
		return err
	}
	if err := syscall.Setgroups(groups); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setresgid(vcap, vcap, vcap); err != nil {
		return fmt.Errorf("setresgid: %w", err)
	}
	if err := syscall.Setresuid(vcap, vcap, vcap); err != nil {
		return fmt.Errorf("setresuid: %w", err)
	}
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); errno != 0 {
		return fmt.Errorf("prctl PR_SET_NO_NEW_PRIVS: %w", errno)
	}
	return run(args[len(want):])
}

// initGroups returns the gid and the gids of the groups in /etc/group that
// list the user whom /etc/passwd gives the uid.
func initGroups() ([]int, error) {
	user, err := field("/etc/passwd", 2, "2000", 0)
	if err != nil {
		return nil, err
	}
	groups := []int{vcap}
	f, err := os.Open("/etc/group")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		parts := strings.Split(s.Text(), ":")
		if len(parts) != 4 {
			continue
		}
		for _, member := range strings.Split(parts[3], ",") {
			if member == user {
				var gid int
				if _, err := fmt.Sscanf(parts[2], "%d", &gid); err == nil && gid != vcap {
					groups = append(groups, gid)
				}
			}
		}
	}
	return groups, s.Err()
}

// field returns field out of the first line of the colon-separated file
// whose field key is value.
func field(file string, key int, value string, out int) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		parts := strings.Split(s.Text(), ":")
		if len(parts) > key && len(parts) > out && parts[key] == value {
			return parts[out], nil
		}
	}
	if err := s.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("%s has no entry with %s in field %d", file, value, key)
}

func run(argv []string) error {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, argv, os.Environ())
}
`

// realStackLauncher is the test launcher, which stage 1 binds into the app
// root at /tmp/lifecycle/launcher. It prints who it runs as, whether
// no_new_privs is set, its working directory, and each of its arguments, and
// writes a file under /home/vcap/tmp and reads it back. It also reads a file
// from the droplet and one from the stack, and prints the guest's hostname,
// the owner of the directory it made, and three of the loader variables.
const realStackLauncher = `#!/bin/sh
echo "app-id=$(id)"
echo "app-$(grep NoNewPrivs /proc/self/status | tr -d '[:space:]')"
echo "app-cwd=$(pwd)"
for a in "$0" "$@"; do
	echo "app-arg=[$a]"
done
mkdir -p /home/vcap/tmp && echo written-by-the-app >/home/vcap/tmp/proof && echo "app-readback=$(cat /home/vcap/tmp/proof)"
echo "app-owner=$(stat -c %u:%g /home/vcap/tmp /home/vcap/tmp/proof | tr '\n' ' ')"
echo "app-droplet=$(cat /home/vcap/app/from-the-droplet)"
echo "app-stack=$(cat /etc/stack-name)"
echo "app-hostname=$(hostname)"
echo "app-loader=[${LD_PRELOAD-unset}] [${LD_LIBRARY_PATH-unset}] [${LD_AUDIT-unset}]"
`

// realStackApplets are the busybox applets the test stack has in /bin, the
// ones realStackLauncher runs.
var realStackApplets = []string{"sh", "id", "grep", "tr", "pwd", "echo", "mkdir", "cat", "stat", "hostname"}

// buildRealStackTools builds realStackToolsSource as a static x86-64
// binary in a temporary directory with the go command on PATH, and skips
// the spec where there is none. It returns the binary's path.
func buildRealStackTools() string {
	gocmd, err := exec.LookPath("go")
	if err != nil {
		Skip("no go command on PATH to build the test stack's env and setpriv")
	}
	dir := GinkgoT().TempDir()
	Expect(os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module stacktools\n\ngo 1.21\n"), 0o644)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "main.go"), []byte(realStackToolsSource), 0o644)).To(Succeed())
	bin := filepath.Join(dir, "stacktools")
	cmd := exec.Command(gocmd, "build", "-trimpath", "-o", bin, ".")
	cmd.Dir = dir
	// The suite's vendor mode and workspace do not apply to this module,
	// which needs nothing beyond the standard library.
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local")
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "building the test stack's tools: %s", out)
	return bin
}

// realStackImage builds a small stack as an lz4 squashfs with the
// mksquashfs in the artifacts directory, as a stack image is built, and
// returns it open read-only, as vm-launch opens the stack image, closed when
// the spec ends. The stack holds the guest's busybox with the applets the
// launcher runs, the tools from buildRealStackTools at /usr/bin/env and
// /usr/bin/setpriv, a vcap user and group of 2000, an empty /home/vcap, and
// the directories stage 1 mounts on, and every file in it belongs to root.
func realStackImage(art string) *os.File {
	tools := buildRealStackTools()
	busybox, err := os.ReadFile(guestBusybox())
	Expect(err).NotTo(HaveOccurred())
	toolBytes, err := os.ReadFile(tools)
	Expect(err).NotTo(HaveOccurred())

	root := filepath.Join(GinkgoT().TempDir(), "stack")
	for _, d := range []string{"bin", "usr/bin", "etc", "home/vcap", "proc", "sys", "dev"} {
		Expect(os.MkdirAll(filepath.Join(root, d), 0o755)).To(Succeed())
	}
	Expect(os.Mkdir(filepath.Join(root, "tmp"), 0o755)).To(Succeed())
	Expect(os.Chmod(filepath.Join(root, "tmp"), 0o1777)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(root, "bin/busybox"), busybox, 0o755)).To(Succeed())
	for _, applet := range realStackApplets {
		Expect(os.Symlink("busybox", filepath.Join(root, "bin", applet))).To(Succeed())
	}
	for _, tool := range []string{"env", "setpriv"} {
		Expect(os.WriteFile(filepath.Join(root, "usr/bin", tool), toolBytes, 0o755)).To(Succeed())
	}
	for name, content := range map[string]string{
		"etc/passwd":     "root:x:0:0:root:/root:/bin/sh\nvcap:x:2000:2000::/home/vcap:/bin/sh\n",
		"etc/group":      "root:x:0:\nvcap:x:2000:\n",
		"etc/hosts":      "the stack's own hosts file\n",
		"etc/hostname":   "the-stacks-own-hostname\n",
		"etc/stack-name": "test-stack\n",
	} {
		Expect(os.WriteFile(filepath.Join(root, name), []byte(content), 0o644)).To(Succeed())
	}

	image := filepath.Join(GinkgoT().TempDir(), "rootfs.squashfs")
	out, err := exec.Command(filepath.Join(art, artMksquashfs), root, image,
		"-noappend", "-comp", "lz4", "-b", "128K", "-all-root", "-no-progress", "-quiet").CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "building the test stack: %s", out)
	f, err := os.Open(image)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(f.Close)
	return f
}

// realDropletImage builds the droplet image of a home directory that holds
// /home/vcap/app/from-the-droplet with buildDropletImage, as run does, and
// returns it, closed when the spec ends.
func realDropletImage(art string) *os.File {
	home := filepath.Join(GinkgoT().TempDir(), "home")
	Expect(os.MkdirAll(filepath.Join(home, "app"), 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(home, "app/from-the-droplet"), []byte("droplet-file\n"), 0o644)).To(Succeed())
	droplet, err := buildDropletImage(art, home, GinkgoT().TempDir())
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(droplet.file.Close)
	return droplet.file
}

// bootRealStackGuest boots a real guest under TCG with a stack, as vm-launch
// boots one with QEMU: the test stack, a droplet, and the test launcher,
// with the launcher argv argv, env as the guest environment, and a guest
// root image when withRoot is set. It returns the console output, with carriage returns removed, and fails
// the spec unless QEMU exits 0 and the guest started the launcher.
func bootRealStackGuest(argv []string, withRoot bool, env string) string {
	art := realArtifacts()
	qemu := realQEMU()
	requireMicrovm(qemu)
	sd := &stackDrives{stack: realStackImage(art), droplet: realDropletImage(art)}

	launcher := writeTempFile("launcher", realStackLauncher)
	lf, err := os.Open(launcher)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(lf.Close)
	g := taskGuest("")
	g.env = env
	g.stack = &guestStack{
		launcher: guestTool{name: "launcher", file: lf, size: int64(len(realStackLauncher))},
		argv:     shellJoin(argv),
		cwd:      "/home/vcap",
		hostname: "stack-guest-0",
		hosts:    []byte("127.0.0.1 localhost\n"),
	}
	var root *os.File
	if withRoot {
		withRealRoot(&g)
		root = realRootImage()
	}
	g.drives, err = newGuestDrivesWithStack(backend.VMQemu, nil, root, sd)
	Expect(err).NotTo(HaveOccurred())

	f := newRealInitramfs(g)
	files, drives, initrdPath, _, rootPath := hypervisorFilesWithStack(nil, withUserspaceMark(f), nil, root, sd)
	hvArgv, err := hypervisorArgvWithStack(backend.VMQemu, art, GinkgoT().TempDir(), initrdPath, minGuestMemoryMiB, g.nw, drives, rootPath, 0, sd)
	Expect(err).NotTo(HaveOccurred())
	code, stdout, stderr := bootRealQEMU(markedArgv(tcgArgv(qemu, hvArgv)), files)
	Expect(code).To(Equal(0), "QEMU failed: %s\n%s", stderr, stdout)
	Expect(stdout).To(ContainSubstring(startTag(testNonce)), stdout)
	return strings.ReplaceAll(stdout, "\r", "")
}

var _ = Describe("the stack guest against a real QEMU", func() {
	DescribeTable("runs the launcher from the stack and the droplet as vcap with no_new_privs, in its working directory, with its argv in order, and lets it write under /home/vcap",
		func(withRoot bool) {
			argv := []string{stackLauncherPath, "/home/vcap/app", "", `{"start_command":"echo it's \"started\"","process_type":"web"}`}
			out := bootRealStackGuest(argv, withRoot, noGuestEnv)

			Expect(out).To(MatchRegexp(`(?m)^app-id=uid=2000\(vcap\) gid=2000\(vcap\) groups=2000\(vcap\)$`), out)
			Expect(out).To(MatchRegexp(`(?m)^app-NoNewPrivs:1$`), out)
			Expect(out).To(MatchRegexp(`(?m)^app-cwd=/home/vcap$`), out)
			var got []string
			for _, m := range regexp.MustCompile(`(?m)^app-arg=\[(.*)\]$`).FindAllStringSubmatch(out, -1) {
				got = append(got, m[1])
			}
			Expect(got).To(Equal(argv), out)
			Expect(out).To(MatchRegexp(`(?m)^app-readback=written-by-the-app$`), out)
			Expect(out).To(MatchRegexp(`(?m)^app-owner=2000:2000 2000:2000 $`), out)
			Expect(out).To(MatchRegexp(`(?m)^app-droplet=droplet-file$`), out)
			Expect(out).To(MatchRegexp(`(?m)^app-stack=test-stack$`), out)
			Expect(out).To(MatchRegexp(`(?m)^app-hostname=stack-guest-0$`), out)
			Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
		},
		Entry("on a guest root disk", true),
		Entry("with the app root's upper layer in RAM", false),
	)

	It("gives the launcher the app's loader variables only after setpriv has dropped to vcap, so a library that does not exist never reaches a program that runs as root", func() {
		argv := []string{stackLauncherPath, "/home/vcap/app", "", `{"start_command":"./app","process_type":"web"}`}
		out := bootRealStackGuest(argv, false, "export LD_PRELOAD='/home/vcap/app/no-such-preload.so'\nexport LD_LIBRARY_PATH=''\n")

		Expect(out).NotTo(ContainSubstring("while it runs as root"), out)
		Expect(out).To(MatchRegexp(`(?m)^app-id=uid=2000\(vcap\) gid=2000\(vcap\) groups=2000\(vcap\)$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-NoNewPrivs:1$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-cwd=/home/vcap$`), out)
		Expect(out).To(MatchRegexp(`(?m)^app-loader=\[/home/vcap/app/no-such-preload.so\] \[\] \[unset\]$`), out)
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})
})
