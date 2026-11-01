//go:build linux

package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
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

// addFDOption returns the -add-fd argument of the generated QEMU command line,
// which puts the volume's descriptor in the set its drive opens.
func addFDOption(argv []string) string { return optionAfter(argv, "-add-fd", "") }

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
	// file descriptor 3 exactly as vm-launch passes the image, open read-write
	// as vm-launch opens it, because QEMU takes a read-write drive only from a
	// read-write descriptor. QEMU parses and
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
		argv := qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, taskNetwork(), drivePathsFor(1), 0)
		drive := driveOption(argv)
		code, stderr := parseDrive(qemu, noMachine, "-add-fd", addFDOption(argv), "-drive", drive)
		Expect(code).To(Equal(0), "QEMU rejected -drive %s: %s", drive, stderr)
	})

	It("rejects the drive without its file descriptor set, so the check above can fail", func() {
		qemu := realQEMU()
		drive := driveOption(qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, taskNetwork(), drivePathsFor(1), 0))
		code, stderr := parseDrive(qemu, noMachine, "-drive", drive)
		Expect(code).NotTo(Equal(0))
		Expect(stderr).To(ContainSubstring("/dev/fdset/3"))
	})

	It("accepts the -drive and -device pair vm-launch generates on a microvm machine", func() {
		qemu := realQEMU()
		requireMicrovm(qemu)
		argv := qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, taskNetwork(), drivePathsFor(1), 0)
		drive, device := driveOption(argv), deviceOption(argv)
		Expect(device).To(ContainSubstring("drive=vol0"))
		code, stderr := parseDrive(qemu, microvm, "-add-fd", addFDOption(argv), "-drive", drive, "-device", device)
		Expect(code).To(Equal(0), "QEMU rejected -drive %s -device %s: %s", drive, device, stderr)
	})

	It("rejects a -device that names a drive that does not exist, so the pair check above can fail", func() {
		qemu := realQEMU()
		requireMicrovm(qemu)
		argv := qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, taskNetwork(), drivePathsFor(1), 0)
		device := strings.Replace(deviceOption(argv), "drive=vol0", "drive=vol9", 1)
		code, stderr := parseDrive(qemu, microvm, "-add-fd", addFDOption(argv), "-drive", driveOption(argv), "-device", device)
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
			args = append(args, "-add-fd", optionAfter(argv, "-add-fd", "fd="+strconv.Itoa(firstVolumeFD+i)+","),
				"-drive", optionAfter(argv, "-drive", "id="+id+","), "-device", optionAfter(argv, "-device", "drive="+id+","))
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
		argv := qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, taskNetwork(), drivePathsFor(1), 0)
		device := strings.Replace(deviceOption(argv), ",serial=", ",serial-number=", 1)
		code, stderr := parseDrive(qemu, microvm, "-add-fd", addFDOption(argv), "-drive", driveOption(argv), "-device", device)
		Expect(code).NotTo(Equal(0))
		Expect(stderr).To(ContainSubstring("serial-number"))
	})

	It("rejects the unprefixed locking option, so the check above can fail", func() {
		qemu := realQEMU()
		argv := qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, taskNetwork(), drivePathsFor(1), 0)
		drive := strings.Replace(driveOption(argv), "file.locking=off", "locking=off", 1)
		Expect(drive).To(ContainSubstring(",locking=off,"))
		code, stderr := parseDrive(qemu, noMachine, "-add-fd", addFDOption(argv), "-drive", drive)
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
		// shows. The guest's /rvm/disks names every drive, as stage 1 needs
		// it to, and the command reads the serials and sizes raw.
		sizes := []int64{1 << 20, 2 << 20, 3 << 20, 4 << 20}
		vols := make([]*os.File, len(sizes))
		for i, size := range sizes {
			vols[i] = openSizedFile(size)
		}
		root := openSizedFile(8 << 20)
		prepared := preparedFiles(vols...)
		drives, err := newGuestDrives(backend.VMQemu, prepared, root)
		Expect(err).NotTo(HaveOccurred())
		want := map[string]string{drives.rootID: strconv.Itoa(8 << 20 / sectorBytes)}
		for i, d := range drives.volumes {
			want[d.id] = strconv.FormatInt(sizes[i]/sectorBytes, 10)
		}
		Expect(want).To(HaveLen(len(sizes) + 1))

		g := taskGuest(`for d in /sys/block/vd*; do echo "drive=$(cat "$d/serial"):$(cat "$d/size")"; done`)
		g.drives = drives
		for i := range vols {
			g.vols = append(g.vols, guestVolume{ContainerDir: "/vol" + strconv.Itoa(i), ImageName: "volume.img"})
		}
		g.rootBytes, g.rootInodeRatio = 8<<20, inodeRatioFor(8<<20)
		f := newRealInitramfs(g)
		files, drivePaths, initrdPath, _, rootPath := hypervisorFiles(prepared.files(), withUserspaceMark(f), nil, root)
		argv := markedArgv(tcgArgv(qemu, withRealRootDrive(qemuArgv(art, initrdPath, minGuestMemoryMiB, taskNetwork(), drivePaths, 0), rootPath)))
		code, stdout, stderr := bootRealQEMU(argv, files)
		Expect(code).To(Equal(0), "QEMU failed: %s\n%s", stderr, stdout)
		Expect(stdout).NotTo(ContainSubstring("vm-launch guest setup"), stdout)
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

var _ = Describe("QEMU arguments for a guest with shares", func() {
	task := taskNetwork()

	// shareAt is the socket of the share at volume index i, as shareServers
	// reports it for a work directory of /work.
	shareAt := func(i int) shareSocket {
		return shareSocket{Index: i, Tag: shareTag(i), Path: fmt.Sprintf("/work/rvm-vol%d.sock", i)}
	}
	// sharedBase is goldenQEMUBase with the machine naming the memfd.
	sharedBase := func(initrd string) []string {
		base := withInitrd(goldenQEMUBase, initrd)
		out := append([]string(nil), base...)
		for i, a := range out {
			if a == "-M" {
				out[i+1] += ",memory-backend=mem0"
			}
		}
		return out
	}
	memfd := func(mib int) []string {
		return []string{"-object", fmt.Sprintf("memory-backend-memfd,id=mem0,size=%dM,share=on", mib)}
	}
	fsDevice := func(i int) []string {
		return []string{
			"-chardev", fmt.Sprintf("socket,id=fs%d,path=/work/rvm-vol%d.sock", i, i),
			"-device", fmt.Sprintf("vhost-user-fs-device,chardev=fs%d,tag=rvm-vol%d", i, i),
		}
	}
	// driveAt is the QEMU drive and device of the volume at volume index i
	// whose image is on file descriptor fd.
	driveAt := func(i, fd int) []string {
		return []string{
			"-add-fd", fmt.Sprintf("fd=%d,set=%d", fd, fd),
			"-drive", fmt.Sprintf("if=none,id=vol%d,format=raw,file.driver=file,file.filename=/dev/fdset/%d,cache=writeback,aio=threads,file.locking=off,file.auto-read-only=off,werror=report,rerror=report,discard=ignore", i, fd),
			"-device", fmt.Sprintf("virtio-blk-device,drive=vol%d,serial=rvm-vol%d", i, i),
		}
	}

	It("keeps every argument of a guest with no share, with and without a drive and a monitor", func() {
		Expect(qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, task, nil, 0)).To(Equal(concat(goldenQEMUBase, goldenQEMUTaskNetdev)))
		Expect(qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, task, nil, 0, []shareSocket{}...)).To(Equal(concat(goldenQEMUBase, goldenQEMUTaskNetdev)))
		Expect(qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, task, drivePathsFor(1), 5)).To(Equal(
			concat(withInitrd(goldenQEMUBase, goldenVolumeInitrd), goldenQEMUTaskNetdev, goldenQEMUDrive, goldenQEMUMonitor("5"))))
		argv, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", goldenVolumeInitrd, goldenMemMiB, task, drivePathsFor(1), "", 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal(concat(withInitrd(goldenQEMUBase, goldenVolumeInitrd), goldenQEMUTaskNetdev, goldenQEMUDrive)))
	})

	It("gives one share shared memory the size of the guest's, a socket, and a vhost-user-fs device", func() {
		Expect(qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, task, nil, 0, shareAt(0))).To(Equal(
			concat(sharedBase(goldenInitrd), goldenQEMUTaskNetdev, memfd(goldenMemMiB), fsDevice(0))))
	})

	It("sizes the shared memory by the guest's memory, which stays the -m value", func() {
		argv := qemuArgv(goldenArt, goldenInitrd, 2048, task, nil, 0, shareAt(0))
		Expect(optionAfter(argv, "-m", "")).To(Equal("2048"))
		Expect(optionAfter(argv, "-object", "memory-backend-memfd")).To(Equal("memory-backend-memfd,id=mem0,size=2048M,share=on"))
		plain := qemuArgv(goldenArt, goldenInitrd, 2048, task, nil, 0)
		Expect(optionAfter(plain, "-m", "")).To(Equal("2048"))
	})

	It("gives two shares one memfd and a chardev and device each, numbered by volume index", func() {
		Expect(qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, task, nil, 0, shareAt(1), shareAt(3))).To(Equal(
			concat(sharedBase(goldenInitrd), goldenQEMUTaskNetdev, memfd(goldenMemMiB), fsDevice(1), fsDevice(3))))
	})

	It("keeps a private volume's drive, serial, and name at its volume index when a share comes first", func() {
		drives := []volumeDrive{{fd: firstVolumeFD, id: qemuVolumeSerial(1), mode: attachFileImage, index: 1}}
		argv, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", goldenVolumeInitrd, goldenMemMiB, task, drives, "", 0, shareAt(0))
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal(concat(sharedBase(goldenVolumeInitrd), goldenQEMUTaskNetdev, driveAt(1, 3), memfd(goldenMemMiB), fsDevice(0))))
		Expect(argv).NotTo(ContainElement(ContainSubstring("id=vol0,")))
		Expect(argv).NotTo(ContainElement(ContainSubstring("drive=vol0,")))
		Expect(argv).NotTo(ContainElement(ContainSubstring("serial=rvm-vol0")))
	})

	It("lets a share sit between two private volumes and names each drive by its volume index", func() {
		drives := []volumeDrive{
			{fd: firstVolumeFD, id: qemuVolumeSerial(0), mode: attachFileImage, index: 0},
			{fd: firstVolumeFD + 1, id: qemuVolumeSerial(2), mode: attachFileImage, index: 2},
		}
		argv, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", procSelfFD(5), goldenMemMiB, task, drives, "", 6, shareAt(1))
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal(concat(sharedBase(procSelfFD(5)), goldenQEMUTaskNetdev, driveAt(0, 3), driveAt(2, 4), memfd(goldenMemMiB), fsDevice(1), goldenQEMUMonitor("6"))))
	})

	It("takes the drive's volume index from the attachment, so hypervisorFiles names a drive after a share by its volume index", func() {
		img := openSizedFile(1 << 20)
		att := imageAttachments(img)[0]
		att.Index = 2
		_, drives, _, _, _ := hypervisorFiles([]*attachment{att}, openSizedFile(1<<20), nil, nil)
		Expect(drives).To(HaveLen(1))
		Expect(drives[0].index).To(Equal(2))
		argv, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", procSelfFD(4), goldenMemMiB, task, drives, "", 0, shareAt(0), shareAt(1))
		Expect(err).NotTo(HaveOccurred())
		Expect(optionAfter(argv, "-drive", "")).To(ContainSubstring("id=vol2,"))
	})

	It("records the volume index on the attachment when it identifies the drives", func() {
		first, second := openSizedFile(1<<20), openSizedFile(1<<20)
		vols := preparedVolumes{
			{Index: 1, Path: "/a", Attachment: &attachment{File: first, Mode: attachFileImage}},
			{Index: 3, Path: "/b", Attachment: &attachment{File: second, Mode: attachFileImage}},
		}
		_, err := newGuestDrives(backend.VMQemu, vols, nil)
		Expect(err).NotTo(HaveOccurred())
		_, drives, _, _, _ := hypervisorFiles(vols.files(), openSizedFile(1<<20), nil, nil)
		Expect([]int{drives[0].index, drives[1].index}).To(Equal([]int{1, 3}))
		Expect([]string{drives[0].id, drives[1].id}).To(Equal([]string{"rvm-vol1", "rvm-vol3"}))
	})

	It("names a Firecracker drive by its volume index", func() {
		drives := []volumeDrive{{fd: firstVolumeFD, id: "12345", mode: attachFileImage, index: 2}}
		raw := fcConfigJSON(goldenVolumeInitrd, goldenMemMiB, task, drives, "")
		Expect(raw).To(ContainSubstring(`"drive_id":"vol2"`))
		Expect(raw).NotTo(ContainSubstring(`"drive_id":"vol0"`))
	})

	It("refuses shares on Firecracker, which has no vhost-user-fs device", func() {
		work := GinkgoT().TempDir()
		_, err := hypervisorArgv(backend.VMFirecracker, goldenArt, work, goldenInitrd, goldenMemMiB, task, nil, "", 0, shareAt(0))
		Expect(err).To(MatchError(ContainSubstring("cannot serve shares")))
		Expect(filepath.Join(work, "fc.json")).NotTo(BeAnExistingFile())
	})

	DescribeTable("refuses a share list it cannot turn into devices",
		func(shares []shareSocket, message string) {
			_, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", goldenInitrd, goldenMemMiB, task, nil, "", 0, shares...)
			Expect(err).To(MatchError(ContainSubstring(message)))
		},
		Entry("two shares at one index", []shareSocket{shareAt(1), shareAt(1)}, "two shares have the volume index 1"),
		Entry("a negative index", []shareSocket{{Index: -1, Tag: "rvm-vol-1", Path: "/work/s.sock"}}, "below 0"),
		Entry("no socket path", []shareSocket{{Index: 0, Tag: "rvm-vol0"}}, "no socket path"),
		Entry("no tag", []shareSocket{{Index: 0, Path: "/work/s.sock"}}, "empty or has a comma"),
		Entry("a tag with a comma", []shareSocket{{Index: 0, Tag: "a,b", Path: "/work/s.sock"}}, "empty or has a comma"),
	)

	It("doubles a comma in the socket path, which QEMU reads as the next key", func() {
		argv := qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, task, nil, 0, shareSocket{Index: 0, Tag: "rvm-vol0", Path: "/work,x/s.sock"})
		Expect(optionAfter(argv, "-chardev", "id=fs0")).To(Equal("socket,id=fs0,path=/work,,x/s.sock"))
	})

	It("takes the sockets of a shareServers for the arguments, so the chardev path is the socket the share is served on", func() {
		work := GinkgoT().TempDir()
		srv, err := newShareServers("/unused", work, []shareGrant{{Index: 2, Path: "/p", Tag: shareTag(2)}}, log.New(io.Discard, "", 0))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { srv.stop(0) })
		argv, err := hypervisorArgv(backend.VMQemu, goldenArt, work, goldenInitrd, goldenMemMiB, task, nil, "", 0, srv.sockets()...)
		Expect(err).NotTo(HaveOccurred())
		Expect(optionAfter(argv, "-chardev", "id=fs2")).To(Equal("socket,id=fs2,path=" + filepath.Join(work, "rvm-vol2.sock")))
		Expect(optionAfter(argv, "-device", "vhost-user-fs-device")).To(Equal("vhost-user-fs-device,chardev=fs2,tag=rvm-vol2"))
	})

	Describe("against a real QEMU", func() {
		// The machine with its memory named, and the memfd, as QEMU parses
		// them; the guest never starts.
		sharedMachine := func(qemu string) (string, []string) {
			requireMicrovm(qemu)
			argv := qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, task, nil, 0, shareAt(0))
			machine := strings.Replace(optionAfter(argv, "-M", "microvm"), "accel=kvm", "accel=tcg", 1)
			return machine, []string{"-object", optionAfter(argv, "-object", "memory-backend-memfd"), "-m", strconv.Itoa(goldenMemMiB)}
		}
		run := func(qemu, machine string, args ...string) (int, string) {
			argv := append([]string{qemu, "-S", "-display", "none", "-M", machine, "-nodefaults", "-no-user-config", "-monitor", "stdio"}, args...)
			code, _, stderr := runRealQEMU(argv, nil, "quit\n", 30*time.Second)
			return code, stderr
		}

		It("accepts the machine and the memfd that vm-launch generates for a share", func() {
			qemu := realQEMU()
			machine, args := sharedMachine(qemu)
			Expect(machine).To(ContainSubstring(",memory-backend=mem0"))
			code, stderr := run(qemu, machine, args...)
			Expect(code).To(Equal(0), "QEMU rejected -M %s %q: %s", machine, args, stderr)
		})

		It("rejects a machine that names a memory backend that does not exist, so the check above can fail", func() {
			qemu := realQEMU()
			machine, args := sharedMachine(qemu)
			code, stderr := run(qemu, strings.Replace(machine, "memory-backend=mem0", "memory-backend=nope", 1), args...)
			Expect(code).NotTo(Equal(0))
			Expect(stderr).To(ContainSubstring("nope"))
		})
	})
})
