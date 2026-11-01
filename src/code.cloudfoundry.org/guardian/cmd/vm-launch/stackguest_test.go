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

var _ = Describe("stage 1 of the stack guest", func() {
	var (
		dir, bin, callLog, root string
		// paths moves the guest's /rvm into the test directory, as run
		// does with the script, so that a spec can name a guest path in an
		// expected line.
		paths *strings.Replacer
	)

	// stackStep is one command stage 1 runs through a stub, as the stub
	// records its argv, and the line stage 1 fails the boot with when that
	// command fails.
	type stackStep struct{ call, line string }

	// stackSteps are the stubbed commands of a boot with a root disk and a
	// CA bundle, in order. A boot without a root disk has the tmpfs mount
	// in place of the format and the ext4 mount, and one without a CA
	// bundle has no mkdir of /etc/ssl/certs.
	stackSteps := func() []stackStep {
		d := dir + "/rvm"
		return []stackStep{
			{"mkdir -p " + d + "/disk " + d + "/stack " + d + "/droplet " + d + "/app", "creating the stack guest's mount points failed"},
			{"mke2fs -F -b 4096 -m 0 -I 256 -i 16384 -L rvm-root " + root, "formatting the guest root disk " + root + " failed"},
			{"mount -t ext4 -o noatime,discard,errors=continue " + root + " " + d + "/disk", "mounting the guest root disk " + root + " failed"},
			{"mkdir " + d + "/disk/upper " + d + "/disk/work " + d + "/disk/home-upper " + d + "/disk/home-work", "creating the overlay directories failed"},
			{"chown 2000:2000 " + d + "/disk/home-upper", "giving the upper directory of /home/vcap to uid 2000 failed"},
			{"mount -t squashfs -o ro /dev/vdb " + d + "/stack", "mounting the stack image /dev/vdb failed; the guest kernel needs squashfs with lz4"},
			{"mount -t squashfs -o ro /dev/vdc " + d + "/droplet", "mounting the droplet image /dev/vdc failed; the guest kernel needs squashfs with lz4"},
			{"mount -t overlay -o lowerdir=" + d + "/stack,upperdir=" + d + "/disk/upper,workdir=" + d + "/disk/work overlay " + d + "/app", "mounting the app root overlay over the stack failed; the guest kernel needs overlayfs"},
			{"mount -t overlay -o lowerdir=" + d + "/droplet:" + d + "/stack/home/vcap,upperdir=" + d + "/disk/home-upper,workdir=" + d + "/disk/home-work overlay " + d + "/app/home/vcap", "mounting the droplet overlay at /home/vcap in the app root failed"},
			{"mkdir -p " + d + "/app/proc " + d + "/app/sys " + d + "/app/dev " + d + "/app/tmp/lifecycle", "creating the mount points in the app root failed"},
			{"mount -t proc -o nosuid,nodev,noexec proc " + d + "/app/proc", "mounting /proc in the app root failed"},
			{"mount -t sysfs -o ro,nosuid,nodev,noexec sys " + d + "/app/sys", "mounting /sys in the app root failed"},
			{"mount -o bind /dev " + d + "/app/dev", "binding /dev into the app root failed"},
			{"mkdir -p " + d + "/app/dev/shm", "creating /dev/shm in the app root failed"},
			{"mount -t tmpfs -o noexec,nosuid,nodev,mode=1777,size=50% tmpfs " + d + "/app/dev/shm", "mounting /dev/shm in the app root failed"},
			{"mount -o bind " + d + "/lifecycle " + d + "/app/tmp/lifecycle", "binding the lifecycle into the app root failed"},
			{"mount -o remount,bind,ro " + d + "/app/tmp/lifecycle", "making the lifecycle in the app root read-only failed"},
			{"mkdir -p " + d + "/app/etc/ssl/certs", "writing the CA bundle /etc/ssl/certs/ca-certificates.crt in the app root failed"},
			{"hostname -F " + d + "/hostname", "setting the guest's hostname failed"},
		}
	}

	callsOf := func(steps []stackStep) string {
		var calls strings.Builder
		for _, s := range steps {
			calls.WriteString(s.call + "\n")
		}
		return calls.String()
	}

	// failLine is what rvm_fail prints for msg, with the guest paths in the
	// test directory, followed by the stand-in for its reboot.
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

		// Each stub records its argv and fails when RVM_TEST_FAIL is the
		// line it recorded. mkdir then makes the directories, which are in
		// the test directory; the others change nothing.
		stub := func(name, body string) {
			script := "#!/bin/sh\nline=\"" + name + " $*\"\necho \"$line\" >> " + shellQuote(callLog) + "\n" +
				"[ \"$line\" != \"${RVM_TEST_FAIL:-}\" ] || exit 1\n" + body + "\n"
			Expect(os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755)).To(Succeed())
		}
		stub("mkdir", `exec /bin/mkdir "$@"`)
		for _, name := range []string{"mount", "chown", "hostname", "mke2fs"} {
			stub(name, "exit 0")
		}

		// The root disk is a blank image, which the real dd reads.
		root = filepath.Join(dir, "vda")
		Expect(os.WriteFile(root, nil, 0o600)).To(Succeed())
		Expect(os.Truncate(root, 1<<20)).To(Succeed())

		// The mounts are stubs, so the test directory holds what the
		// stack and the initramfs would show at each guest path.
		Expect(os.MkdirAll(filepath.Join(dir, "rvm", "stack", "home", "vcap"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(dir, "rvm", "app", "home", "vcap"), 0o755)).To(Succeed())
		writeFile("rvm/app/usr/bin/env", "", 0o755)
		writeFile("rvm/app/usr/bin/setpriv", "", 0o755)
		writeFile("rvm/app/tmp/lifecycle/launcher", "", 0o755)
		writeFile("rvm/app/etc/hosts", "127.0.0.1 localhost\n", 0o644)
		writeFile("rvm/app/etc/hostname", "stack\n", 0o644)
		writeFile("rvm/app/etc/ssl/certs/ca-certificates.crt", "the stack's bundle\n", 0o644)
		writeFile("rvm/app/run/systemd/resolve/stub-resolv.conf", "nameserver 127.0.0.53\n", 0o644)
		Expect(os.Symlink("../run/systemd/resolve/stub-resolv.conf", filepath.Join(dir, "rvm", "app", "etc", "resolv.conf"))).To(Succeed())
		writeFile("rvm/hosts", "127.0.0.1 localhost\n10.255.0.2 instance-guid\n", 0o644)
		writeFile("rvm/hostname", "instance-guid\n", 0o644)
		writeFile("etc/resolv.conf", "nameserver 169.254.0.2\n", 0o644)
		writeFile("etc/ssl/certs/ca-certificates.crt", "the guest's bundle\n", 0o644)
	})

	// run runs rvm_fail and the stack branch in the guest's busybox sh, with
	// the drive search's results set as vars give them, the guest paths moved
	// into the test directory, the commands that would change the host
	// called as the stubs by path, because the guest's busybox runs its own
	// applets before anything on PATH, and reboot replaced by a marker. It
	// returns the standard output, which holds rvm_fail's line, and the
	// calls the stubs recorded.
	run := func(vars string, env ...string) (string, string) {
		GinkgoHelper()
		script := strings.NewReplacer(
			"reboot -nf", "echo REBOOT",
			"mount -", filepath.Join(bin, "mount")+" -",
			"mkdir ", filepath.Join(bin, "mkdir")+" ",
			"chown ", filepath.Join(bin, "chown")+" ",
			"hostname -F", filepath.Join(bin, "hostname")+" -F",
			"mke2fs -F", filepath.Join(bin, "mke2fs")+" -F",
			"/rvm/", dir+"/rvm/",
			"cat /etc/", "cat "+dir+"/etc/",
			"[ -e /etc/", "[ -e "+dir+"/etc/",
		).Replace(guestFailFunc+vars+guestStackSetup) + "echo STAGE1_DONE\n"
		Expect(strings.Count(script, filepath.Join(bin, "mount")+" -")).To(Equal(strings.Count(guestStackSetup, "mount -")))
		Expect(strings.Count(script, filepath.Join(bin, "mkdir")+" ")).To(Equal(strings.Count(guestStackSetup, "mkdir ")))
		Expect(script).NotTo(ContainSubstring("cat /etc/"))
		Expect(script).NotTo(ContainSubstring("[ -e /etc/"))

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

	// withRoot and withoutRoot are what the drive search leaves for a guest
	// with a root disk and for one without.
	withRoot := func() string {
		return "rvm_devtmpfs=1 rvm_root=" + shellQuote(root) + " rvm_stack=/dev/vdb rvm_droplet=/dev/vdc RVM_ROOT_INODE_RATIO=16384\n"
	}
	const withoutRoot = "rvm_devtmpfs=1 rvm_root= rvm_stack=/dev/vdb rvm_droplet=/dev/vdc\n"

	It("formats the root disk, mounts the stack and the droplet read-only under two overlays, fills the app root, and writes the guest's files over the stack's", func() {
		out, calls := run(withRoot())
		Expect(out).To(Equal("STAGE1_DONE\n"))
		Expect(calls).To(Equal(callsOf(stackSteps())))

		Expect(readFile("rvm/app/etc/hosts")).To(Equal("127.0.0.1 localhost\n10.255.0.2 instance-guid\n"))
		Expect(readFile("rvm/app/etc/hostname")).To(Equal("instance-guid\n"))
		Expect(readFile("rvm/app/etc/ssl/certs/ca-certificates.crt")).To(Equal("the guest's bundle\n"))
		// The stack's resolv.conf was a link, which stage 1 replaced with
		// the guest's file instead of writing through it.
		info, err := os.Lstat(filepath.Join(dir, "rvm", "app", "etc", "resolv.conf"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().IsRegular()).To(BeTrue(), info.Mode().String())
		Expect(readFile("rvm/app/etc/resolv.conf")).To(Equal("nameserver 169.254.0.2\n"))
		Expect(readFile("rvm/app/run/systemd/resolve/stub-resolv.conf")).To(Equal("nameserver 127.0.0.53\n"))

		// The blank check's scratch files are gone.
		Expect(filepath.Join(dir, "rvm", "root-head")).NotTo(BeAnExistingFile())
		Expect(filepath.Join(dir, "rvm", "root-used")).NotTo(BeAnExistingFile())
		for _, d := range []string{"upper", "work", "home-upper", "home-work"} {
			Expect(filepath.Join(dir, "rvm", "disk", d)).To(BeADirectory())
		}
	})

	It("mounts a tmpfs for the app's writes in a guest without a root disk, and never formats anything", func() {
		out, calls := run(withoutRoot)
		Expect(out).To(Equal("STAGE1_DONE\n"))
		steps := stackSteps()
		want := callsOf(steps[:1]) + "mount -t tmpfs -o mode=0755 tmpfs " + dir + "/rvm/disk\n" + callsOf(steps[3:])
		Expect(calls).To(Equal(want))
		Expect(calls).NotTo(ContainSubstring("mke2fs"))
		Expect(calls).NotTo(ContainSubstring("ext4"))
	})

	It("keeps the stack's CA bundle in a guest without one", func() {
		Expect(os.Remove(filepath.Join(dir, "etc", "ssl", "certs", "ca-certificates.crt"))).To(Succeed())
		out, calls := run(withRoot())
		Expect(out).To(Equal("STAGE1_DONE\n"))
		steps := stackSteps()
		Expect(calls).To(Equal(callsOf(steps[:len(steps)-2]) + callsOf(steps[len(steps)-1:])))
		Expect(readFile("rvm/app/etc/ssl/certs/ca-certificates.crt")).To(Equal("the stack's bundle\n"))
	})

	It("fails the boot with a line that names the step when any stubbed command fails, and runs nothing after it", func() {
		// Each run starts from the state BeforeEach made: no calls, and no
		// directories on the root disk.
		reset := func() {
			Expect(os.RemoveAll(callLog)).To(Succeed())
			Expect(os.RemoveAll(filepath.Join(dir, "rvm", "disk"))).To(Succeed())
		}
		steps := stackSteps()
		for i, step := range steps {
			reset()
			out, calls := run(withRoot(), "RVM_TEST_FAIL="+step.call)
			Expect(out).To(Equal(failLine(step.line)), step.call)
			Expect(calls).To(Equal(callsOf(steps[:i+1])), step.call)
		}

		reset()
		tmpfs := "mount -t tmpfs -o mode=0755 tmpfs " + dir + "/rvm/disk"
		out, calls := run(withoutRoot, "RVM_TEST_FAIL="+tmpfs)
		Expect(out).To(Equal(failLine("mounting a tmpfs at /rvm/disk for the app's writes failed")))
		Expect(calls).To(Equal(callsOf(steps[:1]) + tmpfs + "\n"))
	})

	DescribeTable("fails the boot with a line that names the step when a check or a write fails",
		func(change func() string, msg string, stubbed int) {
			vars := change()
			out, calls := run(vars)
			// ROOT in msg stands for the root disk, whose path the
			// entries cannot know.
			Expect(out).To(Equal(failLine(strings.ReplaceAll(msg, "ROOT", root))))
			Expect(calls).To(Equal(callsOf(stackSteps()[:stubbed])))
		},
		Entry("no stack drive", func() string { return strings.Replace(withRoot(), "rvm_stack=/dev/vdb", "rvm_stack=", 1) },
			"/rvm/disks names no stack drive, so the guest has no stack to run the app on", 0),
		Entry("no droplet drive", func() string { return strings.Replace(withRoot(), "rvm_droplet=/dev/vdc", "rvm_droplet=", 1) },
			"/rvm/disks names no droplet drive, so the guest has no droplet to run", 0),
		Entry("no devtmpfs at /dev", func() string { return strings.Replace(withRoot(), "rvm_devtmpfs=1", "rvm_devtmpfs=", 1) },
			"mounting devtmpfs at /dev failed", 0),
		Entry("a root disk that cannot be read", func() string {
			return strings.Replace(withRoot(), shellQuote(root), shellQuote(root+"-missing"), 1)
		}, "reading the start of the guest root disk ROOT-missing failed", 1),
		Entry("a root disk that is not blank", func() string {
			f, err := os.OpenFile(root, os.O_WRONLY, 0)
			Expect(err).NotTo(HaveOccurred())
			_, err = f.WriteAt([]byte{1}, 4096)
			Expect(err).NotTo(HaveOccurred())
			Expect(f.Close()).To(Succeed())
			return withRoot()
		}, "the guest root disk ROOT is not blank, so vm-launch will not format it", 1),
		Entry("a stack without /home/vcap", func() string {
			Expect(os.RemoveAll(filepath.Join(dir, "rvm", "stack", "home"))).To(Succeed())
			return withRoot()
		}, "the stack image has no /home/vcap directory to lay the droplet over", 7),
		Entry("an app root without the launcher", func() string {
			Expect(os.Chmod(filepath.Join(dir, "rvm", "app", "tmp", "lifecycle", "launcher"), 0o644)).To(Succeed())
			return withRoot()
		}, "the app root has no executable /tmp/lifecycle/launcher", 17),
		Entry("a stack without env", func() string {
			Expect(os.Remove(filepath.Join(dir, "rvm", "app", "usr", "bin", "env"))).To(Succeed())
			return withRoot()
		}, "the stack has no executable /usr/bin/env to start the app in its working directory", 17),
		Entry("a stack without setpriv", func() string {
			Expect(os.Chmod(filepath.Join(dir, "rvm", "app", "usr", "bin", "setpriv"), 0o644)).To(Succeed())
			return withRoot()
		}, "the stack has no executable /usr/bin/setpriv to run the app as uid 2000", 17),
		Entry("an initramfs without the hosts file", func() string {
			Expect(os.Remove(filepath.Join(dir, "rvm", "hosts"))).To(Succeed())
			return withRoot()
		}, "writing /etc/hosts in the app root failed", 17),
		Entry("an initramfs without the hostname file", func() string {
			Expect(os.Remove(filepath.Join(dir, "rvm", "hostname"))).To(Succeed())
			return withRoot()
		}, "writing /etc/hostname in the app root failed", 17),
		Entry("an initramfs without resolv.conf", func() string {
			Expect(os.Remove(filepath.Join(dir, "etc", "resolv.conf"))).To(Succeed())
			return withRoot()
		}, "writing /etc/resolv.conf in the app root failed", 17),
		Entry("an app root whose /etc cannot take the CA bundle", func() string {
			Expect(os.RemoveAll(filepath.Join(dir, "rvm", "app", "etc", "ssl"))).To(Succeed())
			writeFile("rvm/app/etc/ssl", "not a directory\n", 0o644)
			return withRoot()
		}, "writing the CA bundle /etc/ssl/certs/ca-certificates.crt in the app root failed", 18),
	)

	It("formats the root disk with the very lines the rvm.6 guest uses", func() {
		Expect(guestRootSetup).To(ContainSubstring(guestRootFormat))
	})

	It("keeps volume apps on the busybox guest", func() {
		Expect(stackModeAllowsVolumes).To(BeFalse())
	})
})
