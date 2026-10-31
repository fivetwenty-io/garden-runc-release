//go:build linux

package main

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

var _ = Describe("run with the guest filesystem tools", func() {
	var (
		art    string
		tmp    string
		volDir string
		out    string
		logBuf *bytes.Buffer
	)

	BeforeEach(func() {
		requireOpenat2()
		art = makeArtifacts()
		volDir = GinkgoT().TempDir()
		out = GinkgoT().TempDir()
		infoDir := GinkgoT().TempDir()
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		GinkgoT().Setenv("CF_INSTANCE_INDEX", "2")
		GinkgoT().Setenv("VCAP_APPLICATION", vcapApp)
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"juicefs": {mountJSON(volDir, "rw")}}))
		logBuf = &bytes.Buffer{}

		// The mount table lives outside the TMPDIR the specs check for
		// leftovers.
		DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)
		mountInfoPath = filepath.Join(infoDir, "mountinfo")
		Expect(os.WriteFile(mountInfoPath, []byte(mountinfoLine(40, volDir, "fuse.juicefs")), 0o644)).To(Succeed())

		saved := defaultImageOptions
		DeferCleanup(func() { defaultImageOptions = saved })
		defaultImageOptions.IsMountRoot = alwaysMountRoot
	})

	runVM := func(kind backend.Kind) int {
		return run([]string{"--backend", string(kind), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}, log.New(logBuf, "", 0))
	}

	// initrdOf runs a QEMU guest whose fake hypervisor copies its initramfs
	// and returns the archive's entries by name.
	initrdOf := func() map[string]cpioEntry {
		initrdCopy := filepath.Join(out, "initrd")
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), `cp "$initrd" `+shellQuote(initrdCopy)+` || exit 1
`)
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		raw, err := os.ReadFile(initrdCopy)
		Expect(err).NotTo(HaveOccurred())
		_, byName := archiveEntries(raw)
		return byName
	}

	// toolEntries lists the names of the archive entries below /rvm/tools.
	toolEntries := func(byName map[string]cpioEntry) []string {
		var names []string
		for n := range byName {
			if strings.HasPrefix(n, "rvm/tools") {
				names = append(names, n)
			}
		}
		return names
	}

	It("gives a guest with an image volume the four tools from the artifacts directory and the pinned mke2fs.conf", func() {
		byName := initrdOf()
		Expect(toolEntries(byName)).To(ConsistOf("rvm/tools", "rvm/tools/mke2fs", "rvm/tools/e2fsck", "rvm/tools/tune2fs", "rvm/tools/ext4grow", "rvm/tools/mke2fs.conf"))
		Expect(byName["rvm/tools"].mode).To(Equal(uint32(0o040755)))
		for _, name := range guestToolNames {
			want, err := os.ReadFile(filepath.Join(art, name))
			Expect(err).NotTo(HaveOccurred())
			Expect(byName["rvm/tools/"+name].data).To(Equal(want), name)
			Expect(byName["rvm/tools/"+name].mode).To(Equal(uint32(0o100755)), name)
		}
		Expect(string(byName["rvm/tools/mke2fs.conf"].data)).To(Equal(guestMke2fsConfText))
		Expect(byName["rvm/tools/mke2fs.conf"].mode).To(Equal(uint32(0o100644)))
		Expect(byName).To(HaveKey("rvm/mounts"))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("gives a guest with no volume no tool and no mke2fs.conf, and starts it on a cell that has none", func() {
		GinkgoT().Setenv("VCAP_SERVICES", `{}`)
		for _, name := range guestToolNames {
			Expect(os.Remove(filepath.Join(art, name))).To(Succeed())
		}
		byName := initrdOf()
		Expect(toolEntries(byName)).To(BeEmpty())
		Expect(byName).NotTo(HaveKey("rvm/mounts"))
		nonce := regexp.MustCompile(`RVM_START_([0-9a-f]+)`).FindSubmatch(byName["rvm/init"].data)
		Expect(nonce).To(HaveLen(2))
		Expect(string(byName["rvm/init"].data)).To(Equal(initScript(string(nonce[1]), false)))
	})

	It("gives a guest with no volume none of the tools even when the cell has them", func() {
		GinkgoT().Setenv("VCAP_SERVICES", `{}`)
		Expect(toolEntries(initrdOf())).To(BeEmpty())
	})

	DescribeTable("exits 125 for a guest with a volume on a cell that lacks a tool, before it prepares the volume or starts anything",
		func(kind backend.Kind, hypervisor, missing string) {
			Expect(os.Remove(filepath.Join(art, missing))).To(Succeed())
			if kind == backend.VMFirecracker {
				letFirecrackerSeeVMLaunch()
			}
			argvFile := writeFakeHypervisor(filepath.Join(art, hypervisor), "")
			Expect(runVM(kind)).To(Equal(exitLaunchError))
			Expect(logBuf.String()).To(Equal("guest tool " + missing + " is missing: " + filepath.Join(art, missing) + " does not exist" + noGuestToolsHint + "\n"))
			Expect(logBuf.String()).To(ContainSubstring("the cell needs the guest e2fsprogs artifact"))
			Expect(argvFile).NotTo(BeAnExistingFile())
			Expect(os.ReadDir(volDir)).To(BeEmpty(), "no image was created")
			Expect(os.ReadDir(tmp)).To(BeEmpty(), "no work directory was made")
			Expect(heldInitramfs()).To(BeZero())
		},
		Entry("QEMU without mke2fs", backend.VMQemu, "qemu/ld-linux-x86-64.so.2", "mke2fs"),
		Entry("QEMU without e2fsck", backend.VMQemu, "qemu/ld-linux-x86-64.so.2", "e2fsck"),
		Entry("QEMU without tune2fs", backend.VMQemu, "qemu/ld-linux-x86-64.so.2", "tune2fs"),
		Entry("QEMU without ext4grow", backend.VMQemu, "qemu/ld-linux-x86-64.so.2", "ext4grow"),
		Entry("Firecracker without mke2fs", backend.VMFirecracker, "firecracker/firecracker", "mke2fs"),
		Entry("Firecracker without ext4grow", backend.VMFirecracker, "firecracker/firecracker", "ext4grow"),
	)

	It("exits 125 for a tool that is a symbolic link out of the artifacts directory", func() {
		elsewhere := filepath.Join(GinkgoT().TempDir(), "mke2fs")
		Expect(os.WriteFile(elsewhere, []byte("elsewhere"), 0o755)).To(Succeed())
		Expect(os.Remove(filepath.Join(art, "mke2fs"))).To(Succeed())
		Expect(os.Symlink(elsewhere, filepath.Join(art, "mke2fs"))).To(Succeed())
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("guest tool mke2fs"))
		Expect(logBuf.String()).To(ContainSubstring(elsewhere))
		Expect(logBuf.String()).To(ContainSubstring("the cell needs the guest e2fsprogs artifact"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(volDir)).To(BeEmpty())
	})

	It("exits 125 for a tool that cannot be executed or holds nothing", func() {
		for name, prepare := range map[string]func(string){
			"e2fsck":  func(p string) { Expect(os.Chmod(p, 0o644)).To(Succeed()) },
			"tune2fs": func(p string) { Expect(os.WriteFile(p, nil, 0o755)).To(Succeed()) },
		} {
			logBuf.Reset()
			prepare(filepath.Join(art, name))
			argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
			Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError), name)
			Expect(logBuf.String()).To(ContainSubstring("guest tool "+name+" at "+filepath.Join(art, name)), name)
			Expect(argvFile).NotTo(BeAnExistingFile(), name)
			Expect(os.WriteFile(filepath.Join(art, name), []byte("tool "+name), 0o755)).To(Succeed())
			Expect(os.Chmod(filepath.Join(art, name), 0o755)).To(Succeed())
		}
	})

	It("closes the tools it opened once the hypervisor has started", func() {
		before := openFDCount()
		initrdOf()
		Expect(openFDCount()).To(Equal(before))
	})
})
