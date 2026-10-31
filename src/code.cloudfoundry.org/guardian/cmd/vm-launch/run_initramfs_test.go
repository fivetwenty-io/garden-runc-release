//go:build linux

package main

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// initramfsAt is fake hypervisor shell that fails unless its file descriptor
// fd is the initramfs memfd.
func initramfsAt(fd string) string {
	return `case "$(readlink /proc/self/fd/` + fd + `)" in "/memfd:vm-launch-initramfs (deleted)") ;; *) echo "fd ` + fd + ` is not the initramfs memfd" >&2; exit 1 ;; esac
`
}

// initramfsReleased is fake hypervisor shell that waits up to five seconds
// for its parent, vm-launch, to close its copy of the initramfs memfd, and
// fails when it never does. The hypervisor's own copy stays open.
const initramfsReleased = `n=0
ls /proc/$PPID/fd >/dev/null 2>&1 || { echo "cannot read the descriptors of vm-launch" >&2; exit 1; }
while for l in /proc/$PPID/fd/*; do readlink "$l"; done 2>/dev/null | grep -q -F memfd:vm-launch-initramfs; do
	n=$((n + 1))
	[ "$n" -gt 100 ] && { echo "vm-launch still holds the initramfs" >&2; exit 1; }
	sleep 0.05
done
`

// noFilesUnder is fake hypervisor shell that fails when dir holds a regular
// file other than Firecracker's configuration.
func noFilesUnder(dir string) string {
	return `files=$(find ` + shellQuote(dir) + ` -type f ! -name fc.json)
[ -z "$files" ] || { echo "files under TMPDIR: $files" >&2; exit 1; }
`
}

var _ = Describe("run with the initramfs in a memfd", func() {
	var (
		art    string
		tmp    string
		logBuf *bytes.Buffer
	)

	BeforeEach(func() {
		art = makeArtifacts()
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		logBuf = &bytes.Buffer{}
	})

	runVM := func(kind backend.Kind) int {
		return run([]string{"--backend", string(kind), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}, log.New(logBuf, "", 0))
	}

	It("gives QEMU the initramfs as fd 3, writes it nowhere, and closes its own copy once QEMU runs", func() {
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"),
			`[ "$initrd" = /proc/self/fd/3 ] || { echo "-initrd is $initrd" >&2; exit 1; }
`+initramfsAt("3")+noFilesUnder(tmp)+initramfsReleased)
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		Expect(os.ReadFile(argvFile)).To(ContainSubstring("\n-initrd\n/proc/self/fd/3\n"))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("gives Firecracker the initramfs as fd 3 and keeps only its configuration on disk", func() {
		letFirecrackerSeeVMLaunch()
		// The copy goes outside TMPDIR, which must stay empty.
		fcCopy := filepath.Join(art, "fc-copy.json")
		writeFakeHypervisor(filepath.Join(art, "firecracker/firecracker"),
			`p=; for a in "$@"; do [ "$p" = --config-file ] && cp "$a" `+shellQuote(fcCopy)+`; p=$a; done
[ "$initrd" = /proc/self/fd/3 ] || { echo "initrd_path is $initrd" >&2; exit 1; }
`+initramfsAt("3")+noFilesUnder(tmp)+initramfsReleased)
		Expect(runVM(backend.VMFirecracker)).To(Equal(0), logBuf.String())
		Expect(os.ReadFile(fcCopy)).To(ContainSubstring(`"initrd_path":"/proc/self/fd/3"`))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	// initrdOf runs a QEMU guest whose fake hypervisor copies the initramfs
	// it gets, and returns the archive's entries by name.
	initrdOf := func() map[string]cpioEntry {
		initrdCopy := filepath.Join(art, "initrd-copy")
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), `cp "$initrd" `+shellQuote(initrdCopy)+` || exit 1
`)
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		raw, err := os.ReadFile(initrdCopy)
		Expect(err).NotTo(HaveOccurred())
		_, byName := archiveEntries(raw)
		return byName
	}

	It("gives the guest the root image's size in sectors and its inode ratio in /rvm/disks, with both boot stages", func() {
		// A 64 MiB quota leaves 32 MiB after the headroom.
		GinkgoT().Setenv("VCAP_APPLICATION", `{"limits":{"disk":64}}`)
		byName := initrdOf()
		Expect(string(byName["rvm/disks"].data)).To(Equal("RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=65536\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUMES=0\n"))
		Expect(string(byName["init"].data)).To(Equal(guestRootInit))
		Expect(byName).To(HaveKey("rvm/init"))
	})

	It("names no root disk in /rvm/disks without a disk quota, so the guest root stays in RAM", func() {
		GinkgoT().Setenv("VCAP_APPLICATION", `{"limits":{"mem":512}}`)
		byName := initrdOf()
		Expect(byName).To(HaveKey("rvm/disks"))
		Expect(string(byName["rvm/disks"].data)).To(Equal("RVM_VOLUMES=0\n"))
		Expect(string(byName["init"].data)).To(Equal(guestRootInit))
	})

	It("closes its copy of the initramfs when the hypervisor cannot be started", func() {
		Expect(os.Remove(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"))).To(Succeed())
		Expect(os.WriteFile(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), []byte("not runnable"), 0o644)).To(Succeed())
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("starting hypervisor"))
		Expect(heldInitramfs()).To(BeZero())
	})
})

// heldInitramfs counts this process's descriptors for an initramfs memfd.
func heldInitramfs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	Expect(err).NotTo(HaveOccurred())
	n := 0
	for _, e := range entries {
		if link, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && strings.HasPrefix(link, "/memfd:"+initramfsName) {
			n++
		}
	}
	return n
}

var _ = Describe("the initramfs release check", func() {
	It("fails while the parent still holds the initramfs, so the run specs above can fail", func() {
		bb := filepath.Join(GinkgoT().TempDir(), "busybox")
		Expect(os.WriteFile(bb, []byte("busybox"), 0o755)).To(Succeed())
		f, err := newInitramfs(bb, taskGuest("true"))
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()

		cmd := exec.Command("/bin/bash", "-c", strings.Replace(initramfsReleased, "-gt 100", "-gt 4", 1))
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		began := time.Now()
		Expect(cmd.Run()).To(HaveOccurred())
		Expect(stderr.String()).To(ContainSubstring("vm-launch still holds the initramfs"))
		Expect(time.Since(began)).To(BeNumerically("<", 5*time.Second))
	})
})

var _ = Describe("the guest command's length", func() {
	It("takes a command of 131071 bytes and rejects one of 131072, in either form, naming the size only", func() {
		for _, wrap := range []func(string) []string{
			func(c string) []string { return []string{"/tmp/lifecycle/launcher", "app", c, ""} },
			// shellJoin quotes the one argument, which adds two bytes.
			func(c string) []string { return []string{c[2:]} },
		} {
			fits := strings.Repeat("x", maxGuestCommandBytes)
			command, _, err := guestCommand(wrap(fits))
			Expect(err).NotTo(HaveOccurred())
			Expect(command).To(HaveLen(maxGuestCommandBytes))

			_, _, err = guestCommand(wrap(secretSentinel + fits[len(secretSentinel)-1:]))
			Expect(err).To(MatchError("the guest command is 131072 bytes, over the 131071 bytes a guest can run as one shell argument"))
		}
	})

	It("exits 125 before the hypervisor starts", func() {
		art := makeArtifacts()
		GinkgoT().Setenv("TMPDIR", GinkgoT().TempDir())
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		var logBuf bytes.Buffer
		code := run([]string{"--backend", "vm-qemu", "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", strings.Repeat("y", maxGuestCommandBytes+1), ""}, log.New(&logBuf, "", 0))
		Expect(code).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(HavePrefix("the guest command is 131072 bytes, over the 131071 bytes a guest can run as one shell argument\n"))
		Expect(logBuf.String()).NotTo(ContainSubstring("yyyy"))
		Expect(argvFile).NotTo(BeAnExistingFile())
	})
})
