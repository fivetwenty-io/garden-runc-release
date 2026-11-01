//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// kcmpFile is KCMP_FILE, the kcmp type that asks whether two processes'
// file descriptors are the same open file.
const kcmpFile = 0

// sameOpenFile reports whether file descriptor fd of this process and file
// descriptor qfd of process pid are the same open file. It skips the spec
// where kcmp is not allowed, as under the default container seccomp profile.
func sameOpenFile(fd uintptr, pid, qfd int) bool {
	r, _, errno := unix.Syscall6(unix.SYS_KCMP, uintptr(os.Getpid()), uintptr(pid), kcmpFile, fd, uintptr(qfd), 0)
	switch errno {
	case 0:
		return r == 0
	case unix.EPERM, unix.EACCES, unix.ENOSYS:
		Skip("kcmp is not allowed here; run the spec as root in a privileged container: " + errno.Error())
	}
	Fail(fmt.Sprintf("kcmp of file descriptor %d against %d of process %d: %v", fd, qfd, pid, errno))
	return false
}

// openFilesOf returns the file descriptors of process pid that open the
// file f opens, found by device and inode, in no particular order.
func openFilesOf(pid int, f *os.File) []int {
	var want unix.Stat_t
	Expect(unix.Fstat(int(f.Fd()), &want)).To(Succeed())
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(dir)
	Expect(err).NotTo(HaveOccurred())
	var fds []int
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		Expect(err).NotTo(HaveOccurred())
		var st unix.Stat_t
		if err := unix.Stat(filepath.Join(dir, e.Name()), &st); err != nil {
			// QEMU may close a descriptor between the listing and the stat.
			continue
		}
		if st.Dev == want.Dev && st.Ino == want.Ino {
			fds = append(fds, fd)
		}
	}
	return fds
}

// stoppedQEMU starts QEMU stopped, with no machine and the monitor on stdio,
// files as its extra files from firstExtraFD on, as vm-launch passes them,
// and args, and waits for the monitor's answer to info block. It returns
// QEMU's process ID and that answer. The spec's cleanup quits QEMU, and kills
// it when the monitor does not end it.
func stoppedQEMU(qemu string, files []*os.File, args ...string) (int, string) {
	argv := append([]string{qemu, "-S", "-display", "none", "-machine", "none", "-nodefaults", "-no-user-config", "-monitor", "stdio"}, args...)
	cmd := newHypervisorCmd(argv, files)
	var stdout, stderr safeBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	Expect(err).NotTo(HaveOccurred())
	Expect(cmd.Start()).To(Succeed())
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	DeferCleanup(func() {
		_, _ = io.WriteString(stdin, "quit\n")
		_ = stdin.Close()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})

	_, err = io.WriteString(stdin, "info block\n")
	Expect(err).NotTo(HaveOccurred())
	// The monitor prints its prompt once at start and again after it answers.
	deadline := time.After(30 * time.Second)
	for strings.Count(stdout.String(), "(qemu)") < 2 {
		select {
		case <-done:
			Fail(fmt.Sprintf("QEMU exited before it answered info block: %s", stderr.String()))
		case <-deadline:
			Fail(fmt.Sprintf("QEMU did not answer info block in 30s: %s%s", stdout.String(), stderr.String()))
		case <-time.After(50 * time.Millisecond):
		}
	}
	return cmd.Process.Pid, stdout.String()
}

var _ = Describe("the volume drive's open file against a real QEMU", func() {
	// imageDrive returns the files vm-launch passes for one volume image and
	// the -add-fd and -drive options it gives QEMU for it.
	imageDrive := func(img *os.File) ([]*os.File, string, string) {
		files, drives, initrd, _, _ := hypervisorFiles(imageAttachments(img), openSizedFile(1<<20), nil, nil)
		argv := qemuArgv(goldenArt, initrd, goldenMemMiB, taskNetwork(), drives, 0)
		return files, addFDOption(argv), driveOption(argv)
	}

	It("opens an image drive from its file descriptor set, so QEMU holds only vm-launch's open file of the image", func() {
		qemu := realQEMU()
		img := openSizedFile(1 << 20)
		files, addFD, drive := imageDrive(img)
		pid, info := stoppedQEMU(qemu, files, "-add-fd", addFD, "-drive", drive)
		Expect(info).To(MatchRegexp(`vol0[^:\n]*: /dev/fdset/3 \(raw\)`))
		qfds := openFilesOf(pid, img)
		Expect(qfds).NotTo(BeEmpty(), "QEMU holds no descriptor of the image")
		for _, q := range qfds {
			Expect(sameOpenFile(img.Fd(), pid, q)).To(BeTrue(), "QEMU's file descriptor %d is an open file of its own, which the image's flock does not cover", q)
		}
	})

	It("sees an open file of QEMU's own when the drive names the image by its /proc/self/fd path, so the check above can fail", func() {
		qemu := realQEMU()
		img := openSizedFile(1 << 20)
		files, _, drive := imageDrive(img)
		reopen := strings.Replace(drive, "file.filename="+qemuFDSetPath(firstVolumeFD), "file.filename="+procSelfFD(firstVolumeFD), 1)
		Expect(reopen).NotTo(Equal(drive))
		pid, _ := stoppedQEMU(qemu, files, "-drive", reopen)
		var own []int
		for _, q := range openFilesOf(pid, img) {
			if !sameOpenFile(img.Fd(), pid, q) {
				own = append(own, q)
			}
		}
		Expect(own).NotTo(BeEmpty(), "QEMU reopened the image by path and still shares vm-launch's open file")
	})

	Describe("on a loop device", func() {
		var att *attachment

		BeforeEach(func() {
			requireLoopDevices()
			volumeProbe, dirProbe = probeVolume, probeMountFD
			disk := newLoopDisk(64 << 20)
			record := GinkgoT().TempDir()
			runTool("mount", "-t", "tmpfs", "-o", "ro,size=4k,nodev,nosuid,noexec", fmt.Sprintf("%s%d:%d=%d", gardenDiskseqSource, disk.major, disk.minor, sysfsDiskseq(disk)), record)
			DeferCleanup(func() { runTool("umount", record) })
			dir := descriptorMount(blockDescriptorText(disk.major, disk.minor, disk.size, disk.uuid, testBlockDisk))
			_, m, err := findVolumeProvider("/proc/self/mountinfo", dir)
			Expect(err).NotTo(HaveOccurred())
			p := &blockProvider{name: "BOSH disk", source: boshDiskDescriptorSource, nodeDir: disk.nodeDir, host: linuxBlockHost{}}
			att, err = p.Prepare(prepareRequest{Mount: m, Mode: attachBlock, LockBudget: newLockBudget(300 * time.Millisecond)})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { Expect(att.Release()).To(Succeed()) })
			att.ID = qemuVolumeSerial(0)
		})

		// blockDrive returns the files vm-launch passes for the device and the
		// QEMU command line it builds for them.
		blockDrive := func() ([]*os.File, []string) {
			files, drives, initrd, _, _ := hypervisorFiles([]*attachment{att}, openSizedFile(1<<20), nil, nil)
			return files, qemuArgv(goldenArt, initrd, goldenMemMiB, taskNetwork(), drives, 0)
		}

		It("opens the device from its file descriptor set with direct I/O, so QEMU holds only the exclusive open file vm-launch checked", func() {
			qemu := realQEMU()
			files, argv := blockDrive()
			pid, info := stoppedQEMU(qemu, files, "-add-fd", addFDOption(argv), "-drive", driveOption(argv))
			Expect(info).To(MatchRegexp(`vol0[^:\n]*: /dev/fdset/3 \(raw\)`))
			Expect(info).To(MatchRegexp(`Cache mode:\s+writeback, direct`))
			qfds := openFilesOf(pid, att.File)
			Expect(qfds).NotTo(BeEmpty(), "QEMU holds no descriptor of the device")
			for _, q := range qfds {
				Expect(sameOpenFile(att.File.Fd(), pid, q)).To(BeTrue(), "QEMU's file descriptor %d is an open file of its own, outside vm-launch's exclusive claim", q)
			}
		})

		It("is refused by QEMU when the device's open file lacks O_DIRECT, so the direct I/O step is what lets the drive open", func() {
			qemu := realQEMU()
			flags, err := unix.FcntlInt(att.File.Fd(), unix.F_GETFL, 0)
			Expect(err).NotTo(HaveOccurred())
			_, err = unix.FcntlInt(att.File.Fd(), unix.F_SETFL, flags&^unix.O_DIRECT)
			Expect(err).NotTo(HaveOccurred())
			files, argv := blockDrive()
			code, _, stderr := runRealQEMU([]string{qemu, "-S", "-display", "none", "-machine", "none", "-nodefaults", "-no-user-config", "-monitor", "stdio",
				"-add-fd", addFDOption(argv), "-drive", driveOption(argv)}, files, "quit\n", 30*time.Second)
			Expect(code).NotTo(Equal(0))
			Expect(stderr).To(ContainSubstring("Failed to find file descriptor with matching flags"))
		})
	})
})
