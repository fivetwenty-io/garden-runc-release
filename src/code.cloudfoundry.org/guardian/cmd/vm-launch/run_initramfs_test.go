//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

var _ = Describe("the initramfs of a guest without a stack", func() {
	// archiveSum is the sha256 of the uncompressed archive that
	// writeInitramfsArchive builds for g, so that the check does not depend
	// on the compressor's output.
	archiveSum := func(g guestContents) string {
		var archive bytes.Buffer
		Expect(writeInitramfsArchive(&archive, strings.NewReader("busybox"), int64(len("busybox")), g)).To(Succeed())
		sum := sha256.Sum256(gunzip(archive.Bytes()))
		return hex.EncodeToString(sum[:])
	}

	// The sums are those of the archives from before the stack guest, so
	// that a guest without a stack boots the very initramfs it always did.
	It("is byte for byte the archive it was before the stack guest, for a task, an LRP with a root disk and a CA bundle, and a guest with a volume", func() {
		task := taskGuest("true")
		Expect(archiveSum(task)).To(Equal("56a82e4104526177e88073e7e336bb9b7587555ccf5ccac5942991a35f39d3ea"))

		lrp := taskGuest("exec ./server")
		lrp.nw = &network{ports: []int{8080}, address: qemuGuestCIDR, gateway: qemuGateway, resolvConf: "nameserver 10.0.2.3\n"}
		lrp.rootBytes, lrp.rootInodeRatio, lrp.drives.rootID = 64<<20, inodeRatioFor(64<<20), qemuRootSerial
		lrp.caBundle = []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")
		Expect(archiveSum(lrp)).To(Equal("112057c868b6523968d6afd3ecb590b1355796692189cab097defa817ebc9603"))

		vol := taskGuest("true")
		vol.vols = []guestVolume{{ContainerDir: "/home/vcap/data", ImageName: "rvm-disk-0.img"}}
		vol.drives.volumes = qemuImageDrives(defaultImageSize)
		Expect(archiveSum(vol)).To(Equal("93cbe815c6c3235c643ba59e761f5b2365bc6f8b40acb9ad3e3c031b7dce200f"))
	})
})

var _ = Describe("the initramfs of a guest with a stack", func() {
	const launcherBytes = "#!/bin/sh\nexec the-launcher \"$@\"\n"

	// stackGuest returns a task guest with a stack, its launcher in a
	// temporary file, and the stack and droplet drives' QEMU serials.
	stackGuest := func() guestContents {
		f, err := os.Open(writeTempFile("launcher", launcherBytes))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		g := taskGuest("")
		g.drives.stackID, g.drives.dropletID = qemuStackSerial, qemuDropletSerial
		g.stack = &guestStack{
			launcher: guestTool{name: "launcher", file: f, size: int64(len(launcherBytes))},
			argv:     shellJoin([]string{stackLauncherPath, "/home/vcap/app", "", `{"start_command":"it's \"here\""}`}),
			cwd:      "/home/vcap/app",
			hostname: "4f1b6c5e-3a2d-4c7b-9e0f-1a2b3c4d5e6f",
			hosts:    []byte("127.0.0.1 localhost\n10.255.0.2 4f1b6c5e-3a2d-4c7b-9e0f-1a2b3c4d5e6f\n"),
		}
		return g
	}

	write := func(g guestContents) error {
		var archive bytes.Buffer
		return writeInitramfsArchive(&archive, strings.NewReader("busybox"), int64(len("busybox")), g)
	}

	archive := func(g guestContents) ([]string, map[string]cpioEntry) {
		var archive bytes.Buffer
		Expect(writeInitramfsArchive(&archive, strings.NewReader("busybox"), int64(len("busybox")), g)).To(Succeed())
		return archiveEntries(archive.Bytes())
	}

	It("holds the launcher, the argv, the working directory, the hosts file, and the hostname, with their modes, and runs the stack guest's two stages", func() {
		g := stackGuest()
		names, byName := archive(g)
		Expect(names).To(Equal([]string{"bin", "dev", "dev/console", "dev/null", "etc", "proc", "sys", "tmp", "rvm",
			"bin/busybox", "rvm/cmd", "rvm/net", "rvm/env", "rvm/limits", "etc/resolv.conf",
			"rvm/lifecycle", "rvm/lifecycle/launcher", "rvm/argv", "rvm/cwd", "rvm/hosts", "rvm/hostname",
			"rvm/disks", "rvm/init", "init", cpioTrailer}))
		Expect(byName["rvm/lifecycle"].mode).To(Equal(uint32(0o040755)))
		Expect(string(byName["rvm/lifecycle/launcher"].data)).To(Equal(launcherBytes))
		Expect(byName["rvm/lifecycle/launcher"].mode).To(Equal(uint32(0o100755)))
		want := map[string]string{
			"rvm/argv":     g.stack.argv,
			"rvm/cwd":      "/home/vcap/app",
			"rvm/hosts":    string(g.stack.hosts),
			"rvm/hostname": g.stack.hostname + "\n",
		}
		for name, content := range want {
			Expect(string(byName[name].data)).To(Equal(content), name)
			Expect(byName[name].mode).To(Equal(uint32(0o100644)), name)
		}
		Expect(string(byName["rvm/disks"].data)).To(Equal("RVM_VOLUMES=0\nRVM_STACK_ID=rvm-stack\nRVM_DROPLET_ID=rvm-droplet\n"))
		Expect(string(byName["init"].data)).To(Equal(guestStackInit))
		Expect(byName["init"].mode).To(Equal(uint32(0o100755)))
		Expect(string(byName["rvm/init"].data)).To(Equal(stackInitScript(testNonce)))
		Expect(byName["rvm/init"].mode).To(Equal(uint32(0o100755)))
	})

	It("reads /rvm/argv back in the guest's shell as the argv it was given", func() {
		g := stackGuest()
		_, byName := archive(g)
		out, err := exec.Command("/bin/sh", "-c", `eval "set -- $(cat "$1")" && printf '[%s]' "$@"`, "sh", writeTempFile("argv", string(byName["rvm/argv"].data))).Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(out)).To(Equal(`[/tmp/lifecycle/launcher][/home/vcap/app][][{"start_command":"it's \"here\""}]`))
	})

	It("names the stack and droplet drives after the root and the volumes in /rvm/disks", func() {
		g := stackGuest()
		g.rootBytes, g.rootInodeRatio, g.drives.rootID = 64<<20, inodeRatioFor(64<<20), qemuRootSerial
		disks, err := disksFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(disks).To(Equal("RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=131072\nRVM_ROOT_INODE_RATIO=" + strconv.FormatInt(inodeRatioFor(64<<20), 10) + "\n" +
			"RVM_VOLUMES=0\nRVM_STACK_ID=rvm-stack\nRVM_DROPLET_ID=rvm-droplet\n"))
		g.stack = nil
		g.drives.stackID, g.drives.dropletID = "", ""
		disks, err = disksFile(g)
		Expect(err).NotTo(HaveOccurred())
		Expect(disks).NotTo(ContainSubstring("STACK"))
		Expect(disks).NotTo(ContainSubstring("DROPLET"))
	})

	DescribeTable("refuses stack and droplet identities that stage 1 could not match to its drives, so no initramfs is built",
		func(change func(*guestContents), want string) {
			g := stackGuest()
			change(&g)
			_, err := disksFile(g)
			Expect(err).To(MatchError(want))
			Expect(write(g)).To(MatchError(want))
		},
		Entry("a stack without the stack image's identity", func(g *guestContents) { g.drives.stackID = "" },
			`a guest with a stack needs the identities of both the stack image and the droplet image, and has "" and "rvm-droplet"`),
		Entry("a stack without the droplet image's identity", func(g *guestContents) { g.drives.dropletID = "" },
			`a guest with a stack needs the identities of both the stack image and the droplet image, and has "rvm-stack" and ""`),
		Entry("the identities without a stack", func(g *guestContents) { g.stack = nil },
			`drive identities "rvm-stack" and "rvm-droplet" for no stack and droplet images`),
		Entry("the stack image with the root's identity", func(g *guestContents) {
			g.rootBytes, g.rootInodeRatio, g.drives.rootID = 64<<20, inodeRatioFor(64<<20), qemuRootSerial
			g.drives.stackID = qemuRootSerial
		}, `the guest root image and the stack image would both have the drive identity "rvm-root", so the guest could not tell them apart`),
		Entry("the droplet image with the stack's identity", func(g *guestContents) { g.drives.dropletID = qemuStackSerial },
			`the stack image and the droplet image would both have the drive identity "rvm-stack", so the guest could not tell them apart`),
		Entry("an identity the guest cannot match", func(g *guestContents) { g.drives.dropletID = "rvm droplet" },
			`the drive identity "rvm droplet" of the droplet image is not 1 to 20 letters, digits, and hyphens, so the guest could not match it`),
	)

	It("takes a launcher argv of 131071 bytes quoted and refuses one of 131072, which the guest could not hand the launcher", func() {
		g := stackGuest()
		g.stack.argv = shellJoin([]string{stackLauncherPath, "/home/vcap/app", ""}) + " "
		g.stack.argv += shellQuote(strings.Repeat("x", maxGuestCommandBytes-len(g.stack.argv)-2))
		Expect(g.stack.argv).To(HaveLen(maxGuestCommandBytes))
		Expect(write(g)).To(Succeed())
		g.stack.argv = strings.Replace(g.stack.argv, "'x", "'xx", 1)
		Expect(write(g)).To(MatchError("the launcher's argv is 131072 bytes quoted, over the 131071 bytes a guest takes"))
	})

	DescribeTable("refuses a stack the guest could not run, so no initramfs is built",
		func(change func(*guestContents), want string) {
			g := stackGuest()
			change(&g)
			Expect(write(g)).To(MatchError(want))
		},
		Entry("a volume", func(g *guestContents) {
			g.vols = []guestVolume{{ContainerDir: "/home/vcap/data", ImageName: "rvm-disk-0.img"}}
			g.drives.volumes = qemuImageDrives(defaultImageSize)
		}, "a guest with a stack mounts no volumes, and this one has 1"),
		Entry("no launcher", func(g *guestContents) { g.stack.launcher = guestTool{} },
			"a guest with a stack needs the launcher, and it has none"),
		Entry("an empty launcher", func(g *guestContents) { g.stack.launcher.size = 0 },
			"a guest with a stack needs the launcher, and it has none"),
		Entry("no argv", func(g *guestContents) { g.stack.argv = "" },
			"a guest with a stack needs the launcher's argv, and it has none"),
		Entry("a relative working directory", func(g *guestContents) { g.stack.cwd = "home/vcap/app" },
			`the app's working directory "home/vcap/app" is not an absolute path on one line`),
		Entry("no working directory", func(g *guestContents) { g.stack.cwd = "" },
			`the app's working directory "" is not an absolute path on one line`),
		Entry("a working directory that ends in a newline, which $(cat) drops", func(g *guestContents) { g.stack.cwd = "/home/vcap/app\n" },
			`the app's working directory "/home/vcap/app\n" is not an absolute path on one line`),
		Entry("no hostname", func(g *guestContents) { g.stack.hostname = "" },
			`the guest hostname "" is not 1 to 64 letters, digits, dots, and hyphens`),
		Entry("a hostname of two lines", func(g *guestContents) { g.stack.hostname = "a\nb" },
			`the guest hostname "a\nb" is not 1 to 64 letters, digits, dots, and hyphens`),
		Entry("a hostname over 64 bytes", func(g *guestContents) { g.stack.hostname = strings.Repeat("h", 65) },
			`the guest hostname "`+strings.Repeat("h", 65)+`" is not 1 to 64 letters, digits, dots, and hyphens`),
	)

	It("runs the stack guest's stage 1 in place of the overlay root, after the drive search that knows the stack and droplet drives", func() {
		Expect(guestStackInit).To(HavePrefix(guestInitStart + guestFailFunc + guestStackDiskFind))
		Expect(guestStackInit).To(HaveSuffix(guestStackSetup + guestStage2Exec))
		Expect(guestStackInit).NotTo(ContainSubstring(guestRootSetup))
		Expect(guestRootInit).To(Equal(guestInitStart + guestFailFunc + guestDiskFind + guestRootSetup + guestStage2Exec))
		Expect(guestStackDiskFind).To(Equal(guestStackDiskFunc + guestDiskRead + guestStackDiskRead + guestDiskWait + "rvm_stack=$rvm_dev_stack\nrvm_droplet=$rvm_dev_droplet\n"))
		for name, script := range map[string]string{"stage 1": guestStackInit, "stage 2": stackInitScript(testNonce)} {
			out, err := exec.Command("/bin/sh", "-n", "-c", script).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), "%s: %s", name, out)
		}
	})

	It("differs from the rvm.6 drive search only in the size check, which it skips for a drive without a size", func() {
		Expect(guestDiskFunc).To(Equal(guestDiskFuncStart + guestDiskSizeCheck + guestDiskFuncEnd))
		Expect(strings.Count(guestDiskFunc, guestDiskSizeCheck)).To(Equal(1))
		Expect(guestStackDiskFunc).To(Equal(strings.Replace(guestDiskFunc, guestDiskSizeCheck, guestStackDiskSizeCheck, 1)))
		Expect(guestStackDiskSizeCheck).To(Equal(strings.Replace(guestDiskSizeCheck, `[ "$rvm_s" = "$rvm_w" ]`, `[ -z "$rvm_w" ] || [ "$rvm_s" = "$rvm_w" ]`, 1)))
	})

	It("runs the launcher in stage 2 after the argv and working directory checks, and mounts no /dev/shm of its own", func() {
		script := stackInitScript(testNonce)
		Expect(script).To(Equal(strings.NewReplacer(guestShmSetup, "", guestEnvChecks, guestEnvChecks+guestStackChecks, guestRunCommand, guestStackRunCommand).Replace(initScript(testNonce, false))))
		Expect(script).NotTo(ContainSubstring(guestShmSetup))
		Expect(script).NotTo(ContainSubstring(guestRunCommand))
		Expect(script).NotTo(ContainSubstring("/rvm/cmd"))
		start := strings.Index(script, "\necho "+startTag(testNonce)+"\n")
		Expect(strings.Index(script, guestEnvChecks+guestStackChecks)).To(BeNumerically(">", 0))
		Expect(strings.Index(script, guestStackChecks)).To(BeNumerically("<", start))
		Expect(strings.Index(script, guestStackRunCommand)).To(BeNumerically(">", start))
	})
})
