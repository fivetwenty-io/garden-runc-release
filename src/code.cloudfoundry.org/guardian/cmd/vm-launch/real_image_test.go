//go:build linux

package main

import (
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// realImageLauncherSource is the test launcher of the Docker image guest,
// built static, because the test image has no shell and no C library, as a
// distroless image has none. It prints who it runs as, its supplementary
// groups, whether no_new_privs is set, its effective capabilities, its
// working directory, each of its arguments, and four variables. It then
// reports whether the image has a /bin/sh, the mode of /tmp, the first line
// of /etc/hosts, whether /etc/passwd is still the image's, the image's name,
// and the hostname, writes a file under /tmp and reads it back, and tries to
// write into the read-only lifecycle.
const realImageLauncherSource = `package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	groups, _ := os.Getgroups()
	fmt.Printf("img-id=uid=%d gid=%d euid=%d egid=%d groups=%v\n", os.Getuid(), os.Getgid(), os.Geteuid(), os.Getegid(), groups)
	status, _ := os.ReadFile("/proc/self/status")
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "NoNewPrivs:") || strings.HasPrefix(line, "CapEff:") {
			fmt.Printf("img-%s\n", strings.Join(strings.Fields(line), ""))
		}
	}
	cwd, err := os.Getwd()
	fmt.Printf("img-cwd=%s %v\n", cwd, err)
	for _, a := range os.Args {
		fmt.Printf("img-arg=[%s]\n", a)
	}
	for _, name := range []string{"HOME", "PATH", "USER", "FROM_GARDEN"} {
		fmt.Printf("img-env=%s=[%s]\n", name, os.Getenv(name))
	}
	if _, err := os.Lstat("/bin/sh"); os.IsNotExist(err) {
		fmt.Println("img-sh=absent")
	} else {
		fmt.Println("img-sh=present")
	}
	if info, err := os.Lstat("/tmp"); err == nil {
		fmt.Printf("img-tmp=%s\n", info.Mode())
	}
	hosts, _ := os.ReadFile("/etc/hosts")
	fmt.Printf("img-hosts=%s\n", strings.SplitN(string(hosts), "\n", 2)[0])
	passwd, _ := os.ReadFile("/etc/passwd")
	fmt.Printf("img-passwd-app=%v\n", strings.Contains(string(passwd), "\napp:x:1234:1235:"))
	name, _ := os.ReadFile("/etc/image-name")
	fmt.Printf("img-name=%s\n", strings.TrimSpace(string(name)))
	host, _ := os.Hostname()
	fmt.Printf("img-hostname=%s\n", host)
	if err := os.WriteFile("/tmp/proof", []byte("written-by-the-app"), 0o600); err != nil {
		fmt.Printf("img-write=%v\n", err)
	} else {
		back, _ := os.ReadFile("/tmp/proof")
		fmt.Printf("img-write=%s\n", back)
	}
	if err := os.WriteFile("/tmp/lifecycle/planted", []byte("x"), 0o755); err != nil {
		fmt.Println("img-lifecycle=denied")
	} else {
		fmt.Println("img-lifecycle=written")
	}
}
`

// buildStaticGuestProgram builds source as a static x86-64 binary in a
// temporary directory with the go command on PATH, and skips the spec where
// there is none. It returns the binary's path.
func buildStaticGuestProgram(module, source string) string {
	gocmd, err := exec.LookPath("go")
	if err != nil {
		Skip("no go command on PATH to build " + module)
	}
	dir := GinkgoT().TempDir()
	Expect(os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module "+module+"\n\ngo 1.21\n"), 0o644)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0o644)).To(Succeed())
	bin := filepath.Join(dir, module)
	cmd := exec.Command(gocmd, "build", "-trimpath", "-o", bin, ".")
	cmd.Dir = dir
	// The suite's vendor mode and workspace do not apply to this module,
	// which needs nothing beyond the standard library.
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local")
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "building %s: %s", module, out)
	return bin
}

// realDockerImage builds a small Docker-style image as an lz4 squashfs with
// the mksquashfs in the artifacts directory, as Garden builds one, and
// returns it open read-only, closed when the spec ends. The image has no
// shell, no proc, sys, or dev, a /tmp that is a link to etc, and an
// /etc/hosts that is a link to passwd, so the guest must make real
// directories and files of them without following the links.
func realDockerImage(art string) *os.File {
	root := filepath.Join(GinkgoT().TempDir(), "image")
	Expect(os.MkdirAll(filepath.Join(root, "etc"), 0o755)).To(Succeed())
	for name, content := range map[string]string{
		"etc/passwd":     testImagePasswd,
		"etc/group":      testImageGroup,
		"etc/image-name": "docker-style-image\n",
	} {
		Expect(os.WriteFile(filepath.Join(root, name), []byte(content), 0o644)).To(Succeed())
	}
	Expect(os.Symlink("passwd", filepath.Join(root, "etc", "hosts"))).To(Succeed())
	Expect(os.Symlink("etc", filepath.Join(root, "tmp"))).To(Succeed())

	image := filepath.Join(GinkgoT().TempDir(), "rootfs.squashfs")
	out, err := exec.Command(filepath.Join(art, artMksquashfs), root, image,
		"-noappend", "-comp", "lz4", "-b", "128K", "-no-xattrs", "-all-root", "-no-progress", "-quiet").CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "building the test image: %s", out)
	f, err := os.Open(image)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(f.Close)
	return f
}

// bootRealImageGuest boots a real Docker image guest under TCG, as vm-launch
// boots one with QEMU, for the user string spec resolved against the test
// image's account files, with the launcher argv argv and the environment
// that vm-launch gives a process whose HOME, PATH, and USER are Garden's
// defaults. It returns the console output, with carriage returns removed,
// and fails the spec unless QEMU exits 0 and the guest started the launcher.
func bootRealImageGuest(spec string, argv []string) string {
	art := realArtifacts()
	qemu := realQEMU()
	requireMicrovm(qemu)
	u, err := resolveImageUser(spec, []byte(testImagePasswd), []byte(testImageGroup))
	Expect(err).NotTo(HaveOccurred())
	sd := &stackDrives{stack: realDockerImage(art), image: true}

	bin := buildStaticGuestProgram("imagelauncher", realImageLauncherSource)
	lf, err := os.Open(bin)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(lf.Close)
	info, err := lf.Stat()
	Expect(err).NotTo(HaveOccurred())

	env, err := buildImageGuestEnvWithCerts(withImageDefaults(map[string]string{
		"HOME": "/home/vcap", "PATH": imageRootPath, "USER": "root", "FROM_GARDEN": "kept",
	}, []string{"HOME", "PATH", "USER"}, u), minGuestMemoryMiB, false, "", log.New(io.Discard, "", 0))
	Expect(err).NotTo(HaveOccurred())

	g := taskGuest("")
	g.env = env
	g.stack = &guestStack{
		launcher: guestTool{name: "launcher", file: lf, size: info.Size()},
		argv:     shellJoin(argv),
		cwd:      "/",
		hostname: "image-guest-0",
		hosts:    []byte("127.0.0.1 localhost\n"),
		image:    &guestImage{uid: u.uid, gid: u.gid},
	}
	g.drives, err = newGuestDrivesWithStack(backend.VMQemu, nil, nil, sd)
	Expect(err).NotTo(HaveOccurred())

	f := newRealInitramfs(g)
	files, drives, initrdPath, _, rootPath := hypervisorFilesWithStack(nil, withUserspaceMark(f), nil, nil, sd)
	hvArgv, err := hypervisorArgvWithStack(backend.VMQemu, art, GinkgoT().TempDir(), initrdPath, minGuestMemoryMiB, g.nw, drives, rootPath, 0, sd)
	Expect(err).NotTo(HaveOccurred())
	code, stdout, stderr := bootRealQEMU(markedArgv(tcgArgv(qemu, hvArgv)), files)
	Expect(code).To(Equal(0), "QEMU failed: %s\n%s", stderr, stdout)
	Expect(stdout).To(ContainSubstring(startTag(testNonce)), stdout)
	return strings.ReplaceAll(stdout, "\r", "")
}

var _ = Describe("the Docker image guest against a real QEMU", func() {
	DescribeTable("runs the launcher on an image without a shell as the image's user, with no_new_privs and no other groups, at the top of the app root, with its argv in order and the image user's environment",
		func(spec, id, capEff, home, path, user string) {
			argv := []string{stackLauncherPath, "app", "", `{"cmd":["/server","it's \"started\""],"workdir":"/srv"}`}
			out := bootRealImageGuest(spec, argv)

			Expect(out).To(MatchRegexp(`(?m)^img-id=`+regexp.QuoteMeta(id)+`$`), out)
			Expect(out).To(MatchRegexp(`(?m)^img-NoNewPrivs:1$`), out)
			Expect(out).To(MatchRegexp(`(?m)^img-CapEff:`+capEff+`$`), out)
			Expect(out).To(MatchRegexp(`(?m)^img-cwd=/ <nil>$`), out)
			var got []string
			for _, m := range regexp.MustCompile(`(?m)^img-arg=\[(.*)\]$`).FindAllStringSubmatch(out, -1) {
				got = append(got, m[1])
			}
			Expect(got).To(Equal(argv), out)
			Expect(out).To(ContainSubstring("img-env=HOME=[" + home + "]\n"))
			Expect(out).To(ContainSubstring("img-env=PATH=[" + path + "]\n"))
			Expect(out).To(ContainSubstring("img-env=USER=[" + user + "]\n"))
			Expect(out).To(ContainSubstring("img-env=FROM_GARDEN=[kept]\n"))
			Expect(out).To(ContainSubstring("img-sh=absent\n"))
			Expect(out).To(ContainSubstring("img-tmp=dtrwxrwxrwx\n"))
			Expect(out).To(ContainSubstring("img-hosts=127.0.0.1 localhost\n"))
			Expect(out).To(ContainSubstring("img-passwd-app=true\n"))
			Expect(out).To(ContainSubstring("img-name=docker-style-image\n"))
			Expect(out).To(ContainSubstring("img-hostname=image-guest-0\n"))
			Expect(out).To(ContainSubstring("img-write=written-by-the-app\n"))
			Expect(out).To(ContainSubstring("img-lifecycle=denied\n"))
			Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
		},
		Entry("a named user from the image's passwd", "app", "uid=1234 gid=1235 euid=1234 egid=1235 groups=[]", "0000000000000000", "/home/app", imageUserPath, "app"),
		Entry("a numeric user and group that the image does not list", "4321:55", "uid=4321 gid=55 euid=4321 egid=55 groups=[]", "0000000000000000", "/", imageUserPath, "4321:55"),
		Entry("root, which keeps its capabilities in the guest", "root", "uid=0 gid=0 euid=0 egid=0 groups=[]", "[0-9a-f]*[1-9a-f][0-9a-f]*", "/root", imageRootPath, "root"),
	)
})
