//go:build linux

package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// realQEMU returns a QEMU system binary on PATH, or skips the spec. The
// binary only parses the drive options here, with no guest, so any
// architecture will do for the specs that use no machine. The specs that
// need the microvm machine skip unless it is qemu-system-x86_64.
func realQEMU() string {
	for _, name := range []string{"qemu-system-x86_64", "qemu-system-aarch64", "qemu-system-i386"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	Skip("no qemu-system binary on PATH; run these specs where QEMU is installed")
	return ""
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

// deviceOption returns the volume's -device argument of the generated QEMU
// command line.
func deviceOption(argv []string) string { return optionAfter(argv, "-device", "virtio-blk") }

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
		cmd := newHypervisorCmd(append(argv, args...), img)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		cmd.Stdin = strings.NewReader("quit\n")
		cmd.Stdout = io.Discard
		Expect(cmd.Start()).To(Succeed())

		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err == nil {
				return 0, stderr.String()
			}
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode(), stderr.String()
			}
			Expect(err).NotTo(HaveOccurred())
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			Fail("QEMU neither accepted nor rejected the drive within 30 seconds: " + stderr.String())
		}
		return -1, ""
	}

	noMachine := []string{"-machine", "none"}
	microvm := []string{"-M", "microvm,accel=tcg"}

	It("accepts the drive option string vm-launch generates", func() {
		qemu := realQEMU()
		drive := driveOption(qemuArgv(goldenArt, goldenInitrd, nil, volumeDrivePath()))
		code, stderr := parseDrive(qemu, noMachine, "-drive", drive)
		Expect(code).To(Equal(0), "QEMU rejected -drive %s: %s", drive, stderr)
	})

	It("accepts the -drive and -device pair vm-launch generates on a microvm machine", func() {
		qemu := realQEMU()
		if !strings.Contains(filepath.Base(qemu), "x86_64") && !strings.Contains(filepath.Base(qemu), "i386") {
			Skip("the microvm machine type needs qemu-system-x86_64")
		}
		argv := qemuArgv(goldenArt, goldenInitrd, nil, volumeDrivePath())
		drive, device := driveOption(argv), deviceOption(argv)
		Expect(device).To(ContainSubstring("drive=vol0"))
		code, stderr := parseDrive(qemu, microvm, "-drive", drive, "-device", device)
		Expect(code).To(Equal(0), "QEMU rejected -drive %s -device %s: %s", drive, device, stderr)
	})

	It("rejects a -device that names a drive that does not exist, so the pair check above can fail", func() {
		qemu := realQEMU()
		if !strings.Contains(filepath.Base(qemu), "x86_64") {
			Skip("the microvm machine type needs qemu-system-x86_64")
		}
		argv := qemuArgv(goldenArt, goldenInitrd, nil, volumeDrivePath())
		device := strings.Replace(deviceOption(argv), "drive=vol0", "drive=vol9", 1)
		code, stderr := parseDrive(qemu, microvm, "-drive", driveOption(argv), "-device", device)
		Expect(code).NotTo(Equal(0))
		Expect(stderr).To(ContainSubstring("vol9"))
	})

	It("rejects the unprefixed locking option, so the check above can fail", func() {
		qemu := realQEMU()
		drive := strings.Replace(driveOption(qemuArgv(goldenArt, goldenInitrd, nil, volumeDrivePath())), "file.locking=off", "locking=off", 1)
		Expect(drive).To(ContainSubstring(",locking=off,"))
		code, stderr := parseDrive(qemu, noMachine, "-drive", drive)
		Expect(code).NotTo(Equal(0))
		Expect(stderr).To(ContainSubstring("locking"))
	})
})
