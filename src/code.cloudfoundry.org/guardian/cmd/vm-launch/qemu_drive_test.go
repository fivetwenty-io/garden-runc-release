//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// realQEMU returns a QEMU system binary on PATH, or skips the spec. The
// binary only parses the drive options here, with no guest, so any
// architecture will do for the specs that use no machine. The specs that
// need the microvm machine skip unless it is qemu-system-x86_64 or
// qemu-system-i386 (requireMicrovm).
func realQEMU() string {
	for _, name := range []string{"qemu-system-x86_64", "qemu-system-aarch64", "qemu-system-i386"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	Skip("no qemu-system binary on PATH; run these specs where QEMU is installed")
	return ""
}

// requireMicrovm skips a spec unless qemu is an x86 system emulator, which
// is the only kind with the microvm machine type. The pair check and its
// control use it together, so the control always runs where the check does.
func requireMicrovm(qemu string) {
	base := filepath.Base(qemu)
	if !strings.Contains(base, "x86_64") && !strings.Contains(base, "i386") {
		Skip("the microvm machine type needs qemu-system-x86_64 or qemu-system-i386")
	}
}

// optionAfter returns the argument that follows flag in the generated QEMU
// command line. flag may appear more than once; the one whose argument
// contains marker is returned.
func optionAfter(argv []string, flag, marker string) string {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) && strings.Contains(argv[i+1], marker) {
			return argv[i+1]
		}
	}
	Fail("no " + flag + " " + marker + " in the QEMU command line")
	return ""
}

// driveOption returns the -drive argument of the generated QEMU command line.
func driveOption(argv []string) string { return optionAfter(argv, "-drive", "") }

// rootDriveOption and rootDeviceOption return the guest root image's -drive
// and -device arguments of the generated QEMU command line.
func rootDriveOption(argv []string) string { return optionAfter(argv, "-drive", "id=root0") }

func rootDeviceOption(argv []string) string { return optionAfter(argv, "-device", "drive=root0") }

// deviceOption returns the volume's -device argument of the generated QEMU
// command line.
func deviceOption(argv []string) string { return optionAfter(argv, "-device", "virtio-blk") }

// runRealQEMU runs QEMU with argv, files as its extra files from
// firstExtraFD on, as vm-launch passes them, and stdin as its input. It
// returns QEMU's exit status, stdout, and stderr, and fails the spec when
// QEMU is still running after timeout.
func runRealQEMU(argv []string, files []*os.File, stdin string, timeout time.Duration) (int, string, string) {
	cmd := newHypervisorCmd(argv, files)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = strings.NewReader(stdin)
	Expect(cmd.Start()).To(Succeed())

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			return 0, stdout.String(), stderr.String()
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), stdout.String(), stderr.String()
		}
		Expect(err).NotTo(HaveOccurred())
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		Fail(fmt.Sprintf("QEMU was still running after %v: %s", timeout, stderr.String()))
	}
	return -1, "", ""
}

var _ = Describe("the QEMU volume drive against a real QEMU", func() {
	// parseDrive starts QEMU stopped, with no display, and the drive's file as
	// file descriptor 3 exactly as vm-launch passes the image. QEMU parses and
	// opens the drive during start up; the monitor's quit then ends a QEMU
	// that accepted it. machine and extra are the machine type and any
	// further arguments, such as the -device that uses the drive.
	parseDrive := func(qemu string, machine []string, args ...string) (int, string) {
		img, err := os.CreateTemp(GinkgoT().TempDir(), "image")
		Expect(err).NotTo(HaveOccurred())
		defer img.Close()
		Expect(img.Truncate(1 << 20)).To(Succeed())

		argv := append([]string{qemu, "-S", "-display", "none"}, machine...)
		argv = append(argv, "-nodefaults", "-no-user-config", "-monitor", "stdio")
		code, _, stderr := runRealQEMU(append(argv, args...), []*os.File{img}, "quit\n", 30*time.Second)
		return code, stderr
	}

	noMachine := []string{"-machine", "none"}
	microvm := []string{"-M", "microvm,accel=tcg"}

	It("accepts the machine option vm-launch generates, with TCG in place of KVM", func() {
		qemu := realQEMU()
		requireMicrovm(qemu)
		machine := optionAfter(qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, taskNetwork(), nil, 0), "-M", "microvm")
		Expect(strings.Split(machine, ",")).To(ContainElement("dump-guest-core=off"))
		code, stderr := parseDrive(qemu, []string{"-M", strings.Replace(machine, "accel=kvm", "accel=tcg", 1)})
		Expect(code).To(Equal(0), "QEMU rejected -M %s: %s", machine, stderr)
	})

	It("rejects a dump-guest-core value it does not know, so the machine check above can fail", func() {
		qemu := realQEMU()
		requireMicrovm(qemu)
		machine := optionAfter(qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, taskNetwork(), nil, 0), "-M", "microvm")
		machine = strings.Replace(strings.Replace(machine, "accel=kvm", "accel=tcg", 1), "dump-guest-core=off", "dump-guest-core=maybe", 1)
		code, stderr := parseDrive(qemu, []string{"-M", machine})
		Expect(code).NotTo(Equal(0))
		Expect(stderr).To(ContainSubstring("dump-guest-core"))
	})

	It("accepts the -netdev and -device pair vm-launch generates for a task on a microvm machine", func() {
		qemu := realQEMU()
		requireMicrovm(qemu)
		argv := qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, taskNetwork(), nil, 0)
		netdev, device := optionAfter(argv, "-netdev", "user"), optionAfter(argv, "-device", "virtio-net")
		Expect(netdev).NotTo(ContainSubstring("hostfwd"))
		code, stderr := parseDrive(qemu, microvm, "-netdev", netdev, "-device", device)
		Expect(code).To(Equal(0), "QEMU rejected -netdev %s -device %s: %s", netdev, device, stderr)
	})

	It("rejects a NIC that names a netdev that does not exist, so the NIC check above can fail", func() {
		qemu := realQEMU()
		requireMicrovm(qemu)
		argv := qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, taskNetwork(), nil, 0)
		device := strings.Replace(optionAfter(argv, "-device", "virtio-net"), "netdev=n0", "netdev=n9", 1)
		code, stderr := parseDrive(qemu, microvm, "-netdev", optionAfter(argv, "-netdev", "user"), "-device", device)
		Expect(code).NotTo(Equal(0))
		Expect(stderr).To(ContainSubstring("n9"))
	})

	It("accepts the drive option string vm-launch generates", func() {
		qemu := realQEMU()
		drive := driveOption(qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, taskNetwork(), []string{volumeDrivePath(0)}, 0))
		code, stderr := parseDrive(qemu, noMachine, "-drive", drive)
		Expect(code).To(Equal(0), "QEMU rejected -drive %s: %s", drive, stderr)
	})

	It("accepts the -drive and -device pair vm-launch generates on a microvm machine", func() {
		qemu := realQEMU()
		requireMicrovm(qemu)
		argv := qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, taskNetwork(), []string{volumeDrivePath(0)}, 0)
		drive, device := driveOption(argv), deviceOption(argv)
		Expect(device).To(ContainSubstring("drive=vol0"))
		code, stderr := parseDrive(qemu, microvm, "-drive", drive, "-device", device)
		Expect(code).To(Equal(0), "QEMU rejected -drive %s -device %s: %s", drive, device, stderr)
	})

	It("rejects a -device that names a drive that does not exist, so the pair check above can fail", func() {
		qemu := realQEMU()
		requireMicrovm(qemu)
		argv := qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, taskNetwork(), []string{volumeDrivePath(0)}, 0)
		device := strings.Replace(deviceOption(argv), "drive=vol0", "drive=vol9", 1)
		code, stderr := parseDrive(qemu, microvm, "-drive", driveOption(argv), "-device", device)
		Expect(code).NotTo(Equal(0))
		Expect(stderr).To(ContainSubstring("vol9"))
	})

	// rootArgv is the command line with a guest root image on file descriptor
	// 4. parseDrive passes its one file as file descriptor 3, so the specs
	// below point the drive at that.
	rootArgv := func() []string {
		argv, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", goldenInitrd, goldenMemMiB, taskNetwork(), nil, procSelfFD(4), 0)
		Expect(err).NotTo(HaveOccurred())
		return argv
	}
	onFDThree := func(option string) string { return strings.Replace(option, procSelfFD(4), procSelfFD(3), 1) }

	It("accepts the root image's drive option string, with discard=unmap and detect-zeroes=unmap", func() {
		qemu := realQEMU()
		drive := onFDThree(rootDriveOption(rootArgv()))
		Expect(strings.Split(drive, ",")).To(ContainElements("discard=unmap", "detect-zeroes=unmap"))
		code, stderr := parseDrive(qemu, noMachine, "-drive", drive)
		Expect(code).To(Equal(0), "QEMU rejected -drive %s: %s", drive, stderr)
	})

	It("accepts the root image's -drive and -device pair on a microvm machine", func() {
		qemu := realQEMU()
		requireMicrovm(qemu)
		argv := rootArgv()
		drive, device := onFDThree(rootDriveOption(argv)), rootDeviceOption(argv)
		code, stderr := parseDrive(qemu, microvm, "-drive", drive, "-device", device)
		Expect(code).To(Equal(0), "QEMU rejected -drive %s -device %s: %s", drive, device, stderr)
	})

	It("rejects a discard value it does not know, so the root drive check above can fail", func() {
		qemu := realQEMU()
		drive := strings.Replace(onFDThree(rootDriveOption(rootArgv())), "discard=unmap", "discard=maybe", 1)
		code, stderr := parseDrive(qemu, noMachine, "-drive", drive)
		Expect(code).NotTo(Equal(0))
		Expect(stderr).To(ContainSubstring("discard"))
	})

	It("rejects a detect-zeroes value it does not know, so the root drive check above can fail", func() {
		qemu := realQEMU()
		drive := strings.Replace(onFDThree(rootDriveOption(rootArgv())), "detect-zeroes=unmap", "detect-zeroes=maybe", 1)
		code, stderr := parseDrive(qemu, noMachine, "-drive", drive)
		Expect(code).NotTo(Equal(0))
		Expect(stderr).To(ContainSubstring("detect-zeroes"))
	})

	It("accepts the serial on every volume device and on the root device of a microvm machine", func() {
		qemu := realQEMU()
		requireMicrovm(qemu)
		argv, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", procSelfFD(3+maxVolumes), goldenMemMiB, taskNetwork(), drivePathsFor(maxVolumes), procSelfFD(4+maxVolumes), 0)
		Expect(err).NotTo(HaveOccurred())
		var files []*os.File
		var args []string
		for i := range maxVolumes {
			files = append(files, openSizedFile(1<<20))
			id := volumeDriveID(i)
			args = append(args, "-drive", optionAfter(argv, "-drive", "id="+id+","), "-device", optionAfter(argv, "-device", "drive="+id+","))
		}
		// The initramfs's descriptor comes before the root image's, as in
		// vm-launch, and nothing here reads it.
		files = append(files, openSizedFile(1<<20), openSizedFile(1<<20))
		args = append(args, "-drive", rootDriveOption(argv), "-device", rootDeviceOption(argv))
		Expect(strings.Count(strings.Join(args, " "), ",serial=")).To(Equal(maxVolumes + 1))
		code, _, stderr := runRealQEMU(append([]string{qemu, "-S", "-display", "none", "-M", "microvm,accel=tcg", "-nodefaults", "-no-user-config", "-monitor", "stdio"}, args...),
			files, "quit\n", 30*time.Second)
		Expect(code).To(Equal(0), "QEMU rejected %q: %s", args, stderr)
	})

	It("rejects a serial property that the device does not have, so the serial check above can fail", func() {
		qemu := realQEMU()
		requireMicrovm(qemu)
		argv := qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, taskNetwork(), []string{volumeDrivePath(0)}, 0)
		device := strings.Replace(deviceOption(argv), ",serial=", ",serial-number=", 1)
		code, stderr := parseDrive(qemu, microvm, "-drive", driveOption(argv), "-device", device)
		Expect(code).NotTo(Equal(0))
		Expect(stderr).To(ContainSubstring("serial-number"))
	})

	It("rejects the unprefixed locking option, so the check above can fail", func() {
		qemu := realQEMU()
		drive := strings.Replace(driveOption(qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, taskNetwork(), []string{volumeDrivePath(0)}, 0)), "file.locking=off", "locking=off", 1)
		Expect(drive).To(ContainSubstring(",locking=off,"))
		code, stderr := parseDrive(qemu, noMachine, "-drive", drive)
		Expect(code).NotTo(Equal(0))
		Expect(stderr).To(ContainSubstring("locking"))
	})
})

// realArtifactsEnv names a directory that holds the real guest kernel as
// kernel/bzImage, for the specs that start a real guest.
const realArtifactsEnv = "VM_LAUNCH_ARTIFACTS"

// realArtifacts returns the directory realArtifactsEnv names, or skips the
// spec when it is unset or holds no kernel/bzImage.
func realArtifacts() string {
	dir := os.Getenv(realArtifactsEnv)
	if dir == "" {
		Skip(realArtifactsEnv + " is not set; point it at a directory that holds the guest kernel as " + artBzImage)
	}
	info, err := os.Stat(filepath.Join(dir, artBzImage))
	if err != nil || !info.Mode().IsRegular() {
		Skip(realArtifactsEnv + " holds no regular file " + artBzImage)
	}
	return dir
}

// tcgArgv turns vm-launch's QEMU command line into one for qemu, a system
// QEMU on PATH: it drops the bundled loader and its share directory, and
// runs the guest under TCG with QEMU's max CPU model in place of KVM and the
// host CPU.
func tcgArgv(qemu string, argv []string) []string {
	start := -1
	for i, a := range argv {
		if strings.HasSuffix(a, artQEMUBinary) {
			start = i + 1
		}
	}
	Expect(start).To(BeNumerically(">", 0), "no QEMU binary in %q", argv)
	out := []string{qemu}
	for i := start; i < len(argv); i++ {
		switch {
		case argv[i] == "-L" && i+1 < len(argv):
			i++
		case argv[i] == "-M" && i+1 < len(argv):
			out = append(out, "-M", strings.Replace(argv[i+1], "accel=kvm", "accel=tcg", 1))
			i++
		case argv[i] == "-cpu" && i+1 < len(argv):
			out = append(out, "-cpu", "max")
			i++
		default:
			out = append(out, argv[i])
		}
	}
	return out
}

var _ = Describe("the initramfs memfd against a real QEMU", func() {
	// stoppedQEMU starts QEMU stopped with the real kernel and initrdPath as
	// its initrd, and with files as its extra files. QEMU loads the kernel
	// and the initrd while it sets up the machine, before the -S pause, so
	// the monitor's quit ends a QEMU that could read both.
	stoppedQEMU := func(qemu, kernel, initrdPath string, files []*os.File) (int, string) {
		argv := []string{qemu, "-S", "-display", "none", "-M", "microvm,accel=tcg", "-nodefaults", "-no-user-config",
			"-m", "128", "-kernel", kernel, "-initrd", initrdPath, "-monitor", "stdio"}
		code, _, stderr := runRealQEMU(argv, files, "quit\n", 60*time.Second)
		return code, stderr
	}

	// memfdInitramfs builds an initramfs for command and the guest
	// environment guestEnv, with the busybox at busyboxPath, in the sealed
	// memfd vm-launch passes to the hypervisor.
	memfdInitramfs := func(busyboxPath, command, guestEnv string) *os.File {
		f, err := newInitramfs(busyboxPath, guestContents{command: command, nonce: testNonce, nw: taskNetwork(), env: guestEnv, nofile: testNofile})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		return f
	}

	fakeBusybox := func() string {
		bb := filepath.Join(GinkgoT().TempDir(), "busybox")
		Expect(os.WriteFile(bb, []byte("not run"), 0o755)).To(Succeed())
		return bb
	}

	It("loads the kernel and the sealed initramfs through /proc/self/fd", func() {
		art := realArtifacts()
		qemu := realQEMU()
		requireMicrovm(qemu)
		files, _, initrdPath, _, _ := hypervisorFiles(nil, memfdInitramfs(fakeBusybox(), "true", noGuestEnv), nil, nil)
		Expect(initrdPath).To(Equal(goldenInitrd))
		code, stderr := stoppedQEMU(qemu, filepath.Join(art, artBzImage), initrdPath, files)
		Expect(code).To(Equal(0), "QEMU could not load the memfd initramfs: %s", stderr)
	})

	It("fails for an initrd path that names no open file, so the load check above can fail", func() {
		art := realArtifacts()
		qemu := realQEMU()
		requireMicrovm(qemu)
		files, _, _, _, _ := hypervisorFiles(nil, memfdInitramfs(fakeBusybox(), "true", noGuestEnv), nil, nil)
		code, stderr := stoppedQEMU(qemu, filepath.Join(art, artBzImage), procSelfFD(9), files)
		Expect(code).NotTo(Equal(0))
		Expect(stderr).To(ContainSubstring(procSelfFD(9)))
	})

	It("boots a guest that reads from each drive the identity vm-launch gives it, and the drive's own size", func() {
		art := realArtifacts()
		qemu := realQEMU()
		requireMicrovm(qemu)
		// Every drive has a size of its own, so a serial on the wrong drive
		// shows. The guest's /rvm/disks names none of them, so /init leaves
		// them alone and the command reads them raw.
		sizes := []int64{1 << 20, 2 << 20, 3 << 20, 4 << 20}
		vols := make([]*os.File, len(sizes))
		for i, size := range sizes {
			vols[i] = openSizedFile(size)
		}
		root := openSizedFile(8 << 20)
		drives, err := newGuestDrives(backend.VMQemu, preparedFiles(vols...), root)
		Expect(err).NotTo(HaveOccurred())
		want := map[string]string{drives.rootID: strconv.Itoa(8 << 20 / sectorBytes)}
		for i, d := range drives.volumes {
			want[d.id] = strconv.FormatInt(sizes[i]/sectorBytes, 10)
		}
		Expect(want).To(HaveLen(len(sizes) + 1))

		f := memfdInitramfs(guestBusybox(), `for d in /sys/block/vd*; do echo "drive=$(cat "$d/serial"):$(cat "$d/size")"; done`, noGuestEnv)
		files, drivePaths, initrdPath, _, rootPath := hypervisorFiles(vols, withUserspaceMark(f), nil, root)
		argv := markedArgv(tcgArgv(qemu, withRealRootDrive(qemuArgv(art, initrdPath, minGuestMemoryMiB, taskNetwork(), drivePaths, 0), rootPath)))
		code, stdout, stderr := bootRealQEMU(argv, files)
		Expect(code).To(Equal(0), "QEMU failed: %s\n%s", stderr, stdout)
		Expect(stdout).To(ContainSubstring(exitTag(testNonce)+"0"), stdout)

		got := map[string]string{}
		for _, m := range regexp.MustCompile(`(?m)^drive=([^:\r\n]*):([0-9]+)\r?$`).FindAllStringSubmatch(stdout, -1) {
			Expect(got).NotTo(HaveKey(m[1]), "two drives with the serial %q:\n%s", m[1], stdout)
			got[m[1]] = m[2]
		}
		Expect(got).To(Equal(want), stdout)
	})

	It("boots a guest from the memfd initramfs under TCG and runs the command with the guest environment", func() {
		art := realArtifacts()
		qemu := realQEMU()
		requireMicrovm(qemu)
		bb := guestBusybox()
		files, _, initrdPath, _, _ := hypervisorFiles(nil, withUserspaceMark(memfdInitramfs(bb, `echo "hello from the $RVM_SOURCE"; exit 7`, "export RVM_SOURCE='memfd initramfs'\n")), nil, nil)
		argv := markedArgv(tcgArgv(qemu, qemuArgv(art, initrdPath, 128, taskNetwork(), nil, 0)))
		code, stdout, stderr := bootRealQEMU(argv, files)
		Expect(code).To(Equal(0), "QEMU failed: %s\n%s", stderr, stdout)
		Expect(stdout).To(ContainSubstring(startTag(testNonce)))
		Expect(stdout).To(ContainSubstring("hello from the memfd initramfs"))
		Expect(stdout).To(ContainSubstring(exitTag(testNonce) + "7"))
	})
})
