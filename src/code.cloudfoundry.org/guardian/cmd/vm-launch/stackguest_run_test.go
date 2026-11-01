//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("the stack guest's command", func() {
	var dir, bin string

	writeFile := func(name, content string, perm os.FileMode) {
		GinkgoHelper()
		p := filepath.Join(dir, name)
		Expect(os.MkdirAll(filepath.Dir(p), 0o755)).To(Succeed())
		Expect(os.WriteFile(p, []byte(content), perm)).To(Succeed())
	}

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		bin = filepath.Join(dir, "bin")
		Expect(os.Mkdir(bin, 0o755)).To(Succeed())

		// Each stub prints its name, its pid, and each argument in
		// brackets, so that an argument with a newline shows as one. chroot
		// runs the program it is given from the test's app root, env enters
		// the directory -C names there, and setpriv runs what follows --.
		// The launcher prints its working directory, its open-files limit,
		// a variable from /rvm/env, and then exits with LAUNCHER_RC.
		show := `echo "$(basename "$0") $$"
for a; do printf '[%s]\n' "$a"; done
`
		writeFile("bin/chroot", "#!/bin/sh\n"+show+`root=$1
shift
prog=$1
shift
export STUB_ROOT="$root"
exec "$root$prog" "$@"
`, 0o755)
		writeFile("rvm/app/usr/bin/env", "#!/bin/sh\n"+show+`[ "$1" = -C ] || exit 125
cd "$STUB_ROOT$2" || exit 125
shift 2
prog=$1
shift
exec "$STUB_ROOT$prog" "$@"
`, 0o755)
		writeFile("rvm/app/usr/bin/setpriv", "#!/bin/sh\n"+show+`while [ "$1" != -- ]; do shift; done
shift
prog=$1
shift
exec "$STUB_ROOT$prog" "$@"
`, 0o755)
		writeFile("rvm/app/tmp/lifecycle/launcher", "#!/bin/sh\n"+show+`echo "pwd=$(pwd) nofile=$(ulimit -n) FROM_ENV=$FROM_ENV"
exit "${LAUNCHER_RC:-0}"
`, 0o755)
		Expect(os.MkdirAll(filepath.Join(dir, "rvm", "app", "home", "vcap"), 0o755)).To(Succeed())
		writeFile("rvm/env", "export FROM_ENV='from /rvm/env'\n", 0o600)
		writeFile("rvm/cwd", "/home/vcap\n", 0o644)
	})

	// script returns text in the guest's shell, with the guest paths moved
	// into the test directory, chroot called as the stub by path, because
	// the guest's busybox runs its own applets before anything on PATH, and
	// reboot replaced by a marker.
	script := func(text string) string {
		return strings.NewReplacer(
			"reboot -nf", "echo REBOOT",
			"exec chroot ", "exec "+filepath.Join(bin, "chroot")+" ",
			"/rvm/", dir+"/rvm/",
		).Replace(text)
	}

	// run runs the command and the status line in the guest's busybox sh,
	// with the open-files limit at 256 soft and the current hard limit, and
	// returns its standard output and the pid the subshell recorded.
	run := func(env ...string) (string, string) {
		GinkgoHelper()
		text := script("RVM_NOFILE_HARD=$(ulimit -H -n) RVM_NOFILE_SOFT=256\n"+guestStackRunCommand+guestRunStatus) + "echo \"status=$rvm_status\"\n"
		Expect(text).To(ContainSubstring("exec " + filepath.Join(bin, "chroot") + " " + dir + "/rvm/app "))
		cmd := exec.Command(guestBusybox(), "sh", "-c", text)
		cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin"}, env...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		Expect(err).NotTo(HaveOccurred(), stderr.String())
		pid, err := os.ReadFile(filepath.Join(dir, "rvm", "app-pid"))
		Expect(err).NotTo(HaveOccurred(), stderr.String())
		return string(out), strings.TrimSuffix(string(pid), "\n")
	}

	// bracketed is each of args in the stubs' brackets, one per line.
	bracketed := func(args ...string) string {
		var b strings.Builder
		for _, a := range args {
			b.WriteString("[" + a + "]\n")
		}
		return b.String()
	}

	// want is the output of a run of the launcher argv, whose pid is pid.
	want := func(pid string, argv []string, status string) string {
		launch := append([]string{"/usr/bin/setpriv", "--reuid=2000", "--regid=2000", "--init-groups", "--no-new-privs", "--"}, argv...)
		return "chroot " + pid + "\n" + bracketed(append([]string{dir + "/rvm/app", "/usr/bin/env", "-C", "/home/vcap"}, launch...)...) +
			"env " + pid + "\n" + bracketed(append([]string{"-C", "/home/vcap"}, launch...)...) +
			"setpriv " + pid + "\n" + bracketed(launch[1:]...) +
			"launcher " + pid + "\n" + bracketed(argv[1:]...) +
			"pwd=" + dir + "/rvm/app/home/vcap nofile=256 FROM_ENV=from /rvm/env\n" +
			"status=" + status + "\n"
	}

	It("runs the launcher's argv in the app root, through env and setpriv, as uid 2000, with the recorded pid that of every program it execs", func() {
		argv := []string{"/tmp/lifecycle/launcher", "app", "bundle exec rackup -p $PORT", `{"start_command":"x"}`}
		writeFile("rvm/argv", shellJoin(argv), 0o644)
		out, pid := run()
		Expect(pid).To(MatchRegexp(`^[1-9][0-9]*$`))
		Expect(out).To(Equal(want(pid, argv, "0")))
	})

	It("passes an argument with quotes, $, backslashes, and newlines, and empty arguments, through unchanged", func() {
		argv := []string{"/tmp/lifecycle/launcher", "app", "echo \"it's $HOME\" `id -u` \\n\nsecond line\n", "", "--credhub-retry=3"}
		writeFile("rvm/argv", shellJoin(argv), 0o644)
		out, pid := run()
		Expect(out).To(Equal(want(pid, argv, "0")))

		argv = []string{"/tmp/lifecycle/launcher", "app", "", ""}
		writeFile("rvm/argv", shellJoin(argv)+"\n", 0o644)
		out, pid = run()
		Expect(out).To(Equal(want(pid, argv, "0")))
	})

	It("keeps the launcher's exit status", func() {
		argv := []string{"/tmp/lifecycle/launcher", "app", "exit 3", ""}
		writeFile("rvm/argv", shellJoin(argv), 0o644)
		out, pid := run("LAUNCHER_RC=3")
		Expect(out).To(Equal(want(pid, argv, "3")))
	})

	It("starts as the rvm.6 guest's command does", func() {
		Expect(guestRunCommand).To(HavePrefix(guestRunPrefix))
		Expect(guestStackRunCommand).To(HavePrefix(guestRunPrefix))
	})

	// check runs rvm_fail and the checks in the guest's busybox sh with
	// stage 2's arguments, and returns their standard output, which ends
	// with the arguments the checks left.
	check := func() string {
		GinkgoHelper()
		text := script(strings.Replace(guestFailFunc, "reboot -nf", "echo REBOOT", 1)+guestStackChecks) + "echo \"OK $*\"\n"
		out, err := exec.Command(guestBusybox(), "sh", "-c", text, "sh", "/dev/vdd", "/dev/vde").Output()
		if err != nil {
			_, ok := err.(*exec.ExitError)
			Expect(ok).To(BeTrue(), "%v", err)
		}
		return string(out)
	}

	It("passes an argv that parses to at least one argument and an absolute working directory, and keeps stage 2's arguments", func() {
		writeFile("rvm/argv", shellJoin([]string{"/tmp/lifecycle/launcher", "app", "a\nb", ""}), 0o644)
		Expect(check()).To(Equal("OK /dev/vdd /dev/vde\n"))
	})

	DescribeTable("fails the boot with a named step on an argv or a working directory the command cannot use",
		func(argv, cwd *string, line string) {
			if argv != nil {
				writeFile("rvm/argv", *argv, 0o644)
			}
			if cwd == nil {
				Expect(os.Remove(filepath.Join(dir, "rvm", "cwd"))).To(Succeed())
			} else {
				writeFile("rvm/cwd", *cwd, 0o644)
			}
			Expect(check()).To(Equal("vm-launch guest setup: " + strings.ReplaceAll(line, "/rvm/", dir+"/rvm/") + "\nREBOOT\n"))
		},
		Entry("no argv", nil, ptr("/home/vcap\n"), "reading the app's arguments from /rvm/argv failed"),
		Entry("an empty argv", ptr("\n"), ptr("/home/vcap\n"), "reading the app's arguments from /rvm/argv failed"),
		Entry("an argv that does not parse", ptr("'/tmp/lifecycle/launcher' 'app"), ptr("/home/vcap\n"), "reading the app's arguments from /rvm/argv failed"),
		Entry("no working directory", ptr("'/tmp/lifecycle/launcher'"), nil, "/rvm/cwd holds no absolute working directory for the app"),
		Entry("an empty working directory", ptr("'/tmp/lifecycle/launcher'"), ptr(""), "/rvm/cwd holds no absolute working directory for the app"),
		Entry("a relative working directory", ptr("'/tmp/lifecycle/launcher'"), ptr("home/vcap\n"), "/rvm/cwd holds no absolute working directory for the app"),
	)
})
