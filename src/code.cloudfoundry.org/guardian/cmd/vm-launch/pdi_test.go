//go:build linux

package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// findVolumeProviderErr is the error findVolumeProvider returns for the mount
// at dir in the table at mountinfo, which is all the specs of the registry's
// refusals look at.
func findVolumeProviderErr(mountinfo, dir string) error {
	_, _, err := findIn(mountinfo, dir)
	return err
}

// fakeDiskProvider is a provider whose answers a spec sets.
type fakeDiskProvider struct {
	name    string
	matches map[string]matchStrength
	caps    capabilities
	prepare func(prepareRequest) (*attachment, error)
}

func (f *fakeDiskProvider) Name() string                                  { return f.name }
func (f *fakeDiskProvider) Match(m mountRecord) matchStrength             { return f.matches[m.FSType] }
func (f *fakeDiskProvider) Capabilities(mountRecord) capabilities         { return f.caps }
func (f *fakeDiskProvider) Prepare(r prepareRequest) (*attachment, error) { return f.prepare(r) }

// fileImageCaps are the capabilities every provider vm-launch accepts has.
var fileImageCaps = capabilities{Modes: []attachMode{attachFileImage}, Fence: fenceDistributedFlock}

// fake returns a provider that matches each fstype with the strength after it.
func fake(name string, matches ...any) *fakeDiskProvider {
	f := &fakeDiskProvider{name: name, matches: map[string]matchStrength{}, caps: fileImageCaps,
		prepare: func(prepareRequest) (*attachment, error) {
			return nil, errors.New("fake provider " + name + " prepares nothing")
		}}
	for i := 0; i+1 < len(matches); i += 2 {
		f.matches[matches[i].(string)] = matches[i+1].(matchStrength)
	}
	return f
}

// withProviders replaces diskProviders with a registry of ps, registered in
// the order given, for the rest of the spec.
func withProviders(ps ...diskProvider) {
	saved := diskProviders
	DeferCleanup(func() { diskProviders = saved })
	diskProviders = &providerRegistry{}
	for _, p := range ps {
		Expect(diskProviders.register(p)).To(Succeed())
	}
}

func providerNamesOf(r *providerRegistry) []string {
	var names []string
	for _, p := range r.providers {
		names = append(names, p.Name())
	}
	return names
}

var _ = Describe("the volume provider registry", func() {
	record := func(fstype string) mountRecord { return mountRecord{ContainerDir: "/data", FSType: fstype} }

	It("holds BOSH disk, JuiceFS, and NFS", func() {
		Expect(providerNamesOf(diskProviders)).To(Equal([]string{"BOSH disk", "JuiceFS", "NFS"}))
		p, err := diskProviders.selectProvider(record("fuse.juicefs"))
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Name()).To(Equal("JuiceFS"))
		for _, other := range []string{"", "cifs", "ext4", "fuse", "juicefs", "fuse.juicefs2", "FUSE.JUICEFS"} {
			_, err := diskProviders.selectProvider(record(other))
			Expect(err).To(MatchError(`volume path "/data" is a `+strconv.Quote(other)+` mount; VM backends support only BOSH disk, JuiceFS, and NFS volumes today`), other)
		}
	})

	It("declares JuiceFS a file-image provider with a lock that holds across cells", func() {
		c := juicefsProvider{}.Capabilities(record("fuse.juicefs"))
		Expect(c.Modes).To(Equal([]attachMode{attachFileImage}))
		Expect(c.Fence).To(Equal(fenceDistributedFlock))
		Expect(juicefsProvider{}.Match(record("fuse.juicefs"))).To(Equal(strongMatch))
		Expect(juicefsProvider{}.Match(record("fuse.mapfs"))).To(Equal(noMatch))
	})

	It("names every registered provider when it refuses a volume", func() {
		for _, c := range []struct {
			providers []diskProvider
			names     string
		}{
			{nil, "no"},
			{[]diskProvider{fake("A", "fuse.a", strongMatch)}, "A"},
			{[]diskProvider{fake("A", "fuse.a", strongMatch), fake("B", "fuse.b", strongMatch)}, "A and B"},
			{[]diskProvider{fake("A", "fuse.a", strongMatch), fake("B", "fuse.b", strongMatch), fake("C", "fuse.c", strongMatch)}, "A, B, and C"},
		} {
			withProviders(c.providers...)
			err := findVolumeProviderErr(writeTempFile("mountinfo", mountinfoLine(40, "/data", "cifs")), "/data")
			Expect(err).To(MatchError(HaveSuffix("; VM backends support only "+c.names+" volumes today")), c.names)
			empty := writeTempFile("mountinfo", "")
			err = findVolumeProviderErr(empty, "/data")
			Expect(err).To(MatchError(`volume path "/data" has no mount entry for its mount ID `+strconv.FormatUint(noSuchMountID, 10)+` in `+empty+"; VM backends support only "+c.names+" volumes today"), c.names)
		}
		withProviders(fake("A", "fuse.a", strongMatch), fake("B", "fuse.b", strongMatch))
		Expect(findVolumeProviderErr(writeTempFile("mountinfo", mountinfoLine(40, "/data", "fuse.b")), "/data")).To(Succeed())
	})

	It("keeps the providers in name order, whatever order they register in", func() {
		withProviders(fake("C"), fake("A"), fake("B"))
		Expect(providerNamesOf(diskProviders)).To(Equal([]string{"A", "B", "C"}))
		Expect(diskProviders.supportedLine()).To(Equal("VM backends support only A, B, and C volumes today"))
	})

	It("refuses a nil provider, a provider with no name, and a name registered twice", func() {
		r := &providerRegistry{}
		Expect(r.register(nil)).To(MatchError("registering a nil volume provider"))
		Expect(r.register(fake(""))).To(MatchError("registering a volume provider with no name"))
		Expect(r.register(fake("A"))).To(Succeed())
		Expect(r.register(fake("A"))).To(MatchError("registering volume provider A twice"))
		Expect(providerNamesOf(r)).To(Equal([]string{"A"}))
	})

	It("panics when a provider's init registers a name twice", func() {
		withProviders(fake("A"))
		Expect(func() { registerDiskProvider(fake("A")) }).To(PanicWith(MatchError("registering volume provider A twice")))
		Expect(func() { registerDiskProvider(fake("B")) }).NotTo(Panic())
		Expect(providerNamesOf(diskProviders)).To(Equal([]string{"A", "B"}))
	})

	It("selects the one strong match over any weak ones", func() {
		withProviders(fake("A", "fs", weakMatch), fake("B", "fs", strongMatch), fake("C", "fs", weakMatch))
		p, err := diskProviders.selectProvider(record("fs"))
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Name()).To(Equal("B"))
	})

	It("selects a single weak match when nothing matches strongly", func() {
		withProviders(fake("A", "fs", weakMatch), fake("B", "other", strongMatch))
		p, err := diskProviders.selectProvider(record("fs"))
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Name()).To(Equal("A"))
	})

	It("refuses a volume that two providers claim equally, and names them", func() {
		withProviders(fake("B", "fs", strongMatch), fake("A", "fs", strongMatch), fake("C", "fs", weakMatch))
		_, err := diskProviders.selectProvider(record("fs"))
		Expect(err).To(MatchError(`volume path "/data" is a "fs" mount, which the A and B volume providers all claim; vm-launch refuses a volume whose provider it cannot tell`))

		withProviders(fake("A", "fs", weakMatch), fake("B", "fs", weakMatch), fake("C", "fs", weakMatch))
		_, err = diskProviders.selectProvider(record("fs"))
		Expect(err).To(MatchError(ContainSubstring("which the A, B, and C volume providers all claim")))
	})

	It("refuses a provider that offers neither attach mode, or no lock that holds across cells", func() {
		noMode := fake("A", "fs", strongMatch)
		noMode.caps = capabilities{Fence: fenceDistributedFlock}
		withProviders(noMode)
		_, err := diskProviders.selectProvider(record("fs"))
		Expect(err).To(MatchError(`volume path "/data": the A volume provider offers neither file-image mode nor block mode, the modes VM backends attach`))

		noFence := fake("A", "fs", strongMatch)
		noFence.caps = capabilities{Modes: []attachMode{attachFileImage}}
		withProviders(noFence)
		_, err = diskProviders.selectProvider(record("fs"))
		Expect(err).To(MatchError(`volume path "/data": the A volume provider declares no lock that holds across cells; VM backends allow one writer per disk`))
	})

	It("hands the provider the mount it found", func() {
		info := writeTempFile("mountinfo", mountinfoLine(40, "/data", "nfs4")+mountinfoLine(41, "/data", "fuse.juicefs"))
		p, m, err := findIn(info, "/data")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Name()).To(Equal("JuiceFS"))
		Expect(m).To(Equal(mountRecord{ContainerDir: "/data", MountID: 41, ParentID: 29, Minor: 41, Root: "/", MountPoint: "/data",
			MountOptions: []string{"rw", "relatime"}, OptionalFields: []string{"shared:41"}, FSType: "fuse.juicefs",
			Source: "src", SuperOptions: []string{"rw"}}))
	})

	It("keeps the cause of a mount table that cannot be read", func() {
		_, _, err := findIn(filepath.Join(GinkgoT().TempDir(), "absent"), "/data")
		Expect(errors.Is(err, syscall.ENOENT)).To(BeTrue())
		Expect(err).To(MatchError(HaveSuffix(`to find the filesystem of volume path "/data": no such file or directory; VM backends support only BOSH disk, JuiceFS, and NFS volumes today`)))
	})
})

var _ = Describe("the JuiceFS provider's Prepare", func() {
	var (
		dir  string
		name string
		img  string
	)

	BeforeEach(func() {
		requireOpenat2()
		dir = GinkgoT().TempDir()
		name = "rvm-disk-0.img"
		img = filepath.Join(dir, name)
		saved := defaultImageOptions
		DeferCleanup(func() { defaultImageOptions = saved })
		defaultImageOptions.IsMountRoot = alwaysMountRoot
		defaultImageOptions.LockWait = 100 * time.Millisecond
		defaultImageOptions.LockPoll = 10 * time.Millisecond
		// The directory is on mount 40, as the request says.
		dirProbe = func(int, string) (mountProbe, error) { return mountProbe{MountID: 40, MountRoot: true}, nil }
	})

	request := func() prepareRequest {
		return prepareRequest{Mount: mountRecord{ContainerDir: dir, MountID: 40, FSType: juicefsFSType}, ImageName: name, Mode: attachFileImage}
	}

	It("returns the image locked, and Release unlocks it", func() {
		att, err := juicefsProvider{}.Prepare(request())
		Expect(err).NotTo(HaveOccurred())
		Expect(att.File.Name()).To(Equal(img))
		Expect(statOf(img).Size).To(Equal(int64(defaultImageSize)))
		Expect(lockedElsewhere(img)).To(BeTrue())
		Expect(att.Release()).To(Succeed())
		Expect(lockedElsewhere(img)).To(BeFalse())
		Expect(img).To(BeARegularFile(), "Release never deletes the image")
	})

	It("uses the image options in force when it runs", func() {
		defaultImageOptions.Size = 1 << 20
		att, err := juicefsProvider{}.Prepare(request())
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(att.Release)
		Expect(statOf(img).Size).To(Equal(int64(1 << 20)))
	})

	It("returns the image code's errors as they are", func() {
		writeImage(img, defaultImageSize, nil)
		holder, err := os.OpenFile(img, os.O_RDWR, 0)
		Expect(err).NotTo(HaveOccurred())
		defer holder.Close()
		Expect(syscall.Flock(int(holder.Fd()), syscall.LOCK_EX)).To(Succeed())

		_, err = juicefsProvider{}.Prepare(request())
		Expect(errors.Is(err, errVolumeInUse)).To(BeTrue())
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))

		sigs := make(chan os.Signal, 1)
		sigs <- syscall.SIGTERM
		req := request()
		req.Signals = sigs
		_, err = juicefsProvider{}.Prepare(req)
		Expect(stepExitCode(err)).To(Equal(128 + int(syscall.SIGTERM)))
	})

	It("calls BeforeLock before it takes the fence, and gives the refusal back with the image closed", func() {
		writeImage(img, defaultImageSize, nil)
		holder, err := os.OpenFile(img, os.O_RDWR, 0)
		Expect(err).NotTo(HaveOccurred())
		defer holder.Close()
		Expect(syscall.Flock(int(holder.Fd()), syscall.LOCK_EX)).To(Succeed())
		defaultImageOptions.LockWait = 10 * time.Second

		req := request()
		var seen *os.File
		req.BeforeLock = func(f *os.File) error { seen = f; return errors.New("spoken for") }
		began := time.Now()
		att, err := juicefsProvider{}.Prepare(req)
		Expect(err).To(MatchError("spoken for"))
		Expect(att).To(BeNil())
		Expect(time.Since(began)).To(BeNumerically("<", time.Second), "it did not wait for the lock")
		Expect(seen.Name()).To(Equal(img))
	})

	It("takes the time it waits for the fence from the budget in the request", func() {
		writeImage(img, defaultImageSize, nil)
		holder, err := os.OpenFile(img, os.O_RDWR, 0)
		Expect(err).NotTo(HaveOccurred())
		defer holder.Close()
		Expect(syscall.Flock(int(holder.Fd()), syscall.LOCK_EX)).To(Succeed())
		defaultImageOptions.LockWait = 10 * time.Second

		req := request()
		req.LockBudget = newLockBudget(150 * time.Millisecond)
		began := time.Now()
		_, err = juicefsProvider{}.Prepare(req)
		Expect(errors.Is(err, errVolumeInUse)).To(BeTrue(), "%v", err)
		Expect(time.Since(began)).To(BeNumerically("<", 3*time.Second))
		Expect(req.LockBudget.remaining).To(BeZero())
	})

	It("opens the directory only on the mount it was given, and creates nothing on another", func() {
		dirProbe = func(int, string) (mountProbe, error) { return mountProbe{MountID: 41, MountRoot: true}, nil }
		_, err := juicefsProvider{}.Prepare(request())
		Expect(errors.Is(err, errMountChanged)).To(BeTrue(), "%v", err)
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("refuses an attach mode other than file image and creates nothing", func() {
		req := request()
		req.Mode = 0
		_, err := juicefsProvider{}.Prepare(req)
		Expect(err).To(MatchError("the JuiceFS volume provider attaches only in file-image mode, not in attach mode 0"))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})
})

var _ = Describe("the JuiceFS volume path", func() {
	var (
		art    string
		tmp    string
		volDir string
		img    string
		logBuf *bytes.Buffer
		out    string
	)

	BeforeEach(func() {
		requireOpenat2()
		art = makeArtifacts()
		volDir = GinkgoT().TempDir()
		img = filepath.Join(volDir, "rvm-disk-"+testAppID+"-web-2.img")
		tmp = GinkgoT().TempDir()
		out = GinkgoT().TempDir()
		// The mount table lives outside the TMPDIR the specs check for
		// leftovers.
		DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)
		mountInfoPath = writeTempFile("mountinfo", mountinfoLine(40, volDir, "fuse.juicefs"))
		GinkgoT().Setenv("TMPDIR", tmp)
		GinkgoT().Setenv("CF_INSTANCE_INDEX", "2")
		GinkgoT().Setenv("MEMORY_LIMIT", "256m")
		GinkgoT().Setenv("VCAP_APPLICATION", `{"application_id":"`+testAppID+`","process_type":"web","name":"app","limits":{"disk":64}}`)
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"juicefs": {mountJSON(volDir, "rw")}}))
		logBuf = &bytes.Buffer{}

		saved := defaultImageOptions
		DeferCleanup(func() { defaultImageOptions = saved })
		defaultImageOptions.IsMountRoot = alwaysMountRoot
		defaultImageOptions.LockWait = 300 * time.Millisecond
		defaultImageOptions.LockPoll = 20 * time.Millisecond
	})

	runVM := func(kind backend.Kind) int {
		return run([]string{"--backend", string(kind), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""},
			log.New(logBuf, "", 0))
	}

	// capture runs vm-launch with a fake hypervisor that keeps a copy of its
	// argv, of the Firecracker configuration when there is one, and of the
	// initramfs, and returns them with the temporary paths replaced by
	// placeholders. The fake hypervisor also keeps the device, device type,
	// and inode numbers of the volume and the root image as it sees them
	// through /proc/self/fd, run together as Firecracker runs them, one line
	// for each.
	capture := func(kind backend.Kind, hypervisor string) (argv, config, mounts, disks string) {
		writeFakeHypervisor(filepath.Join(art, hypervisor), fdThreeChecks(img)+initramfsAt("4")+
			`cp "$initrd" `+shellQuote(filepath.Join(out, "initrd"))+` || exit 1
p=; for a in "$@"; do [ "$p" = --config-file ] && { cp "$a" `+shellQuote(filepath.Join(out, "fc.json"))+` || exit 1; }; p=$a; done
stat -L -c %d%r%i /proc/self/fd/3 /proc/self/fd/5 >`+shellQuote(filepath.Join(out, "ids"))+` || exit 1
`)
		Expect(runVM(kind)).To(Equal(0), logBuf.String())
		Expect(logBuf.String()).NotTo(ContainSubstring("releasing"))
		Expect(lockedElsewhere(img)).To(BeFalse(), "the lock ends with the run")

		work := regexp.MustCompile(regexp.QuoteMeta(tmp) + `/vm-launch-[0-9]+`)
		normal := func(s string) string {
			s = work.ReplaceAllString(s, "@WORK")
			s = strings.ReplaceAll(s, art, "@ART")
			return strings.ReplaceAll(s, volDir, "@VOL")
		}
		raw, err := os.ReadFile(filepath.Join(art, hypervisor) + ".argv")
		Expect(err).NotTo(HaveOccurred())
		argv = normal(string(raw))
		if kind == backend.VMFirecracker {
			raw, err = os.ReadFile(filepath.Join(out, "fc.json"))
			Expect(err).NotTo(HaveOccurred())
			config = normal(string(raw))
		}
		raw, err = os.ReadFile(filepath.Join(out, "initrd"))
		Expect(err).NotTo(HaveOccurred())
		_, byName := archiveEntries(raw)
		return argv, config, normal(string(byName["rvm/mounts"].data)), string(byName["rvm/disks"].data)
	}

	// The golden values below were recorded from vm-launch before the volume
	// path ran through the provider registry, with the same environment. The
	// drive identities came later: the serials on QEMU's two devices, and the
	// RVM_ROOT_ID, RVM_VOLUMES, and RVM_VOL0 lines in /rvm/disks, whose
	// identities stand in as @ROOTID and @VOLID. With the lookup by identity,
	// /rvm/disks lost RVM_VOLUME_SECTORS, and /rvm/mounts names each volume
	// by its index.
	const (
		goldenPDIMounts = "RVM_VOLUMES=1\nRVM_VOL0_PATH='@VOL'\nRVM_VOL0_IMAGE='rvm-disk-" + testAppID + "-web-2.img'\n"
		goldenPDIDisks  = "RVM_ROOT_ID=@ROOTID\nRVM_ROOT_SECTORS=65536\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUMES=1\n" +
			"RVM_VOL0_KIND=image\nRVM_VOL0_ID=@VOLID\nRVM_VOL0_SECTORS=2097152\n"
		goldenPDIFC = `{"boot-source":{"kernel_image_path":"@ART/kernel/vmlinux","initrd_path":"/proc/self/fd/4","boot_args":"console=ttyS0 reboot=k panic=1 rdinit=/init quiet"},` +
			`"drives":[{"drive_id":"vol0","path_on_host":"/proc/self/fd/3","is_root_device":false,"is_read_only":false,"cache_type":"Writeback","io_engine":"Sync"},` +
			`{"drive_id":"root0","path_on_host":"/proc/self/fd/5","is_root_device":false,"is_read_only":false,"cache_type":"Unsafe","io_engine":"Sync","discard":true}],` +
			`"machine-config":{"vcpu_count":1,"mem_size_mib":128},` +
			`"network-interfaces":[{"iface_id":"eth0","guest_mac":"06:00:a9:fe:64:02","host_dev_name":"tap0"}]}`
	)
	goldenPDIQEMU := []string{
		"--library-path", "@ART/qemu/lib", "@ART/qemu/qemu-system-x86_64-microvm",
		"-L", "@ART/qemu/share",
		"-M", "microvm,accel=kvm,dump-guest-core=off",
		"-cpu", "host",
		"-smp", "1",
		"-m", "128",
		"-nodefaults", "-no-user-config", "-nographic",
		"-serial", "stdio",
		"-no-reboot",
		"-kernel", "@ART/kernel/bzImage",
		"-initrd", "/proc/self/fd/4",
		"-append", "console=ttyS0 reboot=t panic=-1 rdinit=/init pci=off quiet",
		"-netdev", "user,id=n0,net=10.0.2.0/24",
		"-device", "virtio-net-device,netdev=n0",
		"-drive", "if=none,id=vol0,file=/proc/self/fd/3,format=raw,cache=writeback,aio=threads,file.locking=off,werror=report,rerror=report,discard=ignore",
		"-device", "virtio-blk-device,drive=vol0,serial=rvm-vol0",
		"-drive", "if=none,id=root0,file=/proc/self/fd/5,format=raw,cache=unsafe,aio=threads,file.locking=off,werror=report,rerror=report,discard=unmap,detect-zeroes=unmap",
		"-device", "virtio-blk-device,drive=root0,serial=rvm-root",
	}

	It("gives QEMU the command line, /rvm/mounts, and /rvm/disks of before the registry, with the serials as the identities", func() {
		argv, _, mounts, disks := capture(backend.VMQemu, "qemu/ld-linux-x86-64.so.2")
		Expect(argv).To(Equal(strings.Join(goldenPDIQEMU, "\n") + "\n"))
		Expect(mounts).To(Equal(goldenPDIMounts))
		Expect(disks).To(Equal(strings.NewReplacer("@ROOTID", "rvm-root", "@VOLID", "rvm-vol0").Replace(goldenPDIDisks)))
	})

	It("gives Firecracker the configuration, /rvm/mounts, and /rvm/disks of before the registry, with the identities Firecracker derives from the files it opens", func() {
		argv, config, mounts, disks := capture(backend.VMFirecracker, "firecracker/firecracker")
		Expect(argv).To(Equal("--no-api\n--config-file\n@WORK/fc.json\n"))
		Expect(config).To(Equal(goldenPDIFC))
		Expect(mounts).To(Equal(goldenPDIMounts))
		raw, err := os.ReadFile(filepath.Join(out, "ids"))
		Expect(err).NotTo(HaveOccurred())
		seen := strings.Fields(string(raw))
		Expect(seen).To(HaveLen(2))
		for i, id := range seen {
			seen[i] = id[:min(len(id), virtioBlockIDBytes)]
		}
		Expect(seen[0]).NotTo(Equal(seen[1]))
		Expect(disks).To(Equal(strings.NewReplacer("@ROOTID", seen[1], "@VOLID", seen[0]).Replace(goldenPDIDisks)))
	})

	It("exits 125 before it creates anything when the selected provider cannot be attached", func() {
		bad := fake("Bad", "fuse.juicefs", strongMatch)
		bad.caps = capabilities{Modes: []attachMode{attachFileImage}}
		withProviders(bad)
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal(`volume path ` + strconv.Quote(volDir) + `: the Bad volume provider declares no lock that holds across cells; VM backends allow one writer per disk` + "\n"))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(os.ReadDir(volDir)).To(BeEmpty())
		Expect(argvFile).NotTo(BeAnExistingFile())
	})

	It("exits 125 before it creates anything when the kernel does not report the mount ID", func() {
		volumeProbe = probeVolume
		statxCall = func(_ int, _ string, _ int, _ int, st *unix.Statx_t) error {
			st.Mask = unix.STATX_TYPE
			return nil
		}
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal("the kernel did not report a mount ID through statx for volume " + strconv.Quote(volDir) +
			" (STATX_MNT_ID needs Linux 5.8 or later), so vm-launch cannot tell which mount holds it\n"))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(os.ReadDir(volDir)).To(BeEmpty())
		Expect(argvFile).NotTo(BeAnExistingFile())
	})

	It("exits 125 before it creates anything when the volume is a subdirectory of a JuiceFS mount", func() {
		// The real probe reads the attributes from statx, which answers that
		// the directory is on mount 40, a JuiceFS line of the mount table,
		// and is not that mount's root. alwaysMountRoot is in force, so only
		// the check before Prepare can refuse it.
		volumeProbe = probeVolume
		statxCall = func(_ int, _ string, _ int, _ int, st *unix.Statx_t) error {
			st.Mask, st.Mnt_id = unix.STATX_MNT_ID, 40
			st.Attributes_mask = unix.STATX_ATTR_MOUNT_ROOT
			return nil
		}
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal("volume " + volDir + " is not a mount point\n"))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(os.ReadDir(volDir)).To(BeEmpty())
		Expect(argvFile).NotTo(BeAnExistingFile())

		// With the attribute set, the same volume starts.
		statxCall = func(_ int, _ string, _ int, _ int, st *unix.Statx_t) error {
			st.Mask, st.Mnt_id = unix.STATX_MNT_ID, 40
			st.Attributes_mask, st.Attributes = unix.STATX_ATTR_MOUNT_ROOT, unix.STATX_ATTR_MOUNT_ROOT
			return nil
		}
		dirProbe = probeByPath
		logBuf.Reset()
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
	})

	It("exits 125 with one line and creates nothing when the volume's mount changes between the inspection and Prepare", func() {
		dirProbe = func(int, string) (mountProbe, error) { return mountProbe{MountID: 99, MountRoot: true}, nil }
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(HaveSuffix("the mount of volume " + volDir + " changed during start: it was mount ID 40 when vm-launch inspected it and is mount ID 99 now\n"))
		Expect(strings.Count(logBuf.String(), "changed during start")).To(Equal(1))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(os.ReadDir(volDir)).To(BeEmpty())
		Expect(argvFile).NotTo(BeAnExistingFile())
	})

	It("releases an attachment that Prepare returns along with an error, and exits as the error says", func() {
		for name, c := range map[string]struct {
			err  error
			code int
		}{
			"an ordinary error": {errors.New("the fake disk failed after its fence"), exitLaunchError},
			"a signal":          {&signalledError{Sig: syscall.SIGTERM, during: "waiting for the fake disk"}, 128 + int(syscall.SIGTERM)},
		} {
			released := 0
			p := fake("Fake", "fuse.juicefs", strongMatch)
			p.prepare = func(prepareRequest) (*attachment, error) {
				return &attachment{Release: func() error { released++; return errors.New("the fake fence would not let go") }}, c.err
			}
			withProviders(p)
			logBuf.Reset()
			argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
			Expect(runVM(backend.VMQemu)).To(Equal(c.code), name)
			Expect(released).To(Equal(1), name)
			Expect(logBuf.String()).To(HaveSuffix(c.err.Error()+"\nreleasing the volume image: the fake fence would not let go\n"), name)
			Expect(argvFile).NotTo(BeAnExistingFile(), name)
			Expect(os.ReadDir(tmp)).To(BeEmpty(), name)
		}
	})

	It("closes the file of an attachment that Prepare returns along with an error and no Release", func() {
		f, err := os.CreateTemp(out, "disk")
		Expect(err).NotTo(HaveOccurred())
		p := fake("Fake", "fuse.juicefs", strongMatch)
		p.prepare = func(prepareRequest) (*attachment, error) {
			return &attachment{File: f}, errors.New("the fake disk failed")
		}
		withProviders(p)
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(HaveSuffix("the fake disk failed\n"))
		Expect(f.Close()).NotTo(Succeed(), "the file was closed")
	})

	It("logs a cleanup that fails when it refuses an unusable attachment", func() {
		f, err := os.CreateTemp(out, "disk")
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Close()).To(Succeed())
		for name, c := range map[string]struct {
			att  *attachment
			want string
		}{
			"no file, Release fails": {&attachment{Release: func() error { return errors.New("the fake fence would not let go") }},
				"releasing the volume image: the fake fence would not let go\nthe Fake volume provider prepared the disk without an error but returned no disk file\n"},
			"no Release, close fails": {&attachment{File: f}, "closing the volume image: close " + f.Name() + ": file already closed\nthe Fake volume provider prepared the disk without an error but returned no Release function\n"},
		} {
			p := fake("Fake", "fuse.juicefs", strongMatch)
			att := c.att
			p.prepare = func(prepareRequest) (*attachment, error) { return att, nil }
			withProviders(p)
			logBuf.Reset()
			writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
			Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError), name)
			Expect(logBuf.String()).To(HaveSuffix(c.want), name)
		}
	})

	It("selects the volume's mount by the kernel's mount ID when a later mount shares its mount point", func() {
		volumeProbe = func(string) (mountProbe, error) { return mountProbe{MountID: 40, MountRoot: true}, nil }
		mountInfoPath = writeTempFile("mountinfo", mountinfoLine(40, volDir, "fuse.juicefs")+mountinfoLine(41, volDir, "ext4"))
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())

		volumeProbe = func(string) (mountProbe, error) { return mountProbe{MountID: 41, MountRoot: true}, nil }
		logBuf.Reset()
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring(`is a "ext4" mount`))
	})

	It("passes the provider the mount, the image name, file-image mode, and the signals, and exits as its error says", func() {
		var got prepareRequest
		p := fake("Fake", "fuse.juicefs", strongMatch)
		p.prepare = func(r prepareRequest) (*attachment, error) {
			got = r
			return nil, &signalledError{Sig: syscall.SIGTERM, during: "waiting for the fake disk"}
		}
		withProviders(p)
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(128 + int(syscall.SIGTERM)))
		Expect(logBuf.String()).To(HaveSuffix("received terminated while waiting for the fake disk\n"))
		Expect(got.Mount).To(Equal(mountRecord{ContainerDir: volDir, MountID: 40, ParentID: 29, Minor: 40, Root: "/", MountPoint: volDir,
			MountOptions: []string{"rw", "relatime"}, OptionalFields: []string{"shared:40"}, FSType: "fuse.juicefs",
			Source: "src", SuperOptions: []string{"rw"}}))
		Expect(got.ImageName).To(Equal("rvm-disk-" + testAppID + "-web-2.img"))
		Expect(got.Mode).To(Equal(attachFileImage))
		Expect(got.Signals).NotTo(BeNil())
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("exits 125 and names the provider when Prepare returns an unusable attachment without an error", func() {
		for name, c := range map[string]struct {
			make func(f *os.File, released *bool) *attachment
			want string
		}{
			"no attachment": {func(*os.File, *bool) *attachment { return nil }, "returned no attachment"},
			"no file": {func(_ *os.File, released *bool) *attachment {
				return &attachment{Release: func() error { *released = true; return nil }}
			}, "returned no disk file"},
			"no Release": {func(f *os.File, _ *bool) *attachment { return &attachment{File: f} }, "returned no Release function"},
		} {
			f, err := os.CreateTemp(out, "disk")
			Expect(err).NotTo(HaveOccurred())
			released := false
			att := c.make(f, &released)
			if att != nil && att.File != nil {
				defer f.Close()
			}
			p := fake("Fake", "fuse.juicefs", strongMatch)
			p.prepare = func(prepareRequest) (*attachment, error) { return att, nil }
			withProviders(p)
			logBuf.Reset()
			argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
			Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError), name)
			Expect(logBuf.String()).To(HaveSuffix("the Fake volume provider prepared the disk without an error but "+c.want+"\n"), name)
			Expect(argvFile).NotTo(BeAnExistingFile(), name)
			Expect(os.ReadDir(tmp)).To(BeEmpty(), name)
			if name == "no file" {
				Expect(released).To(BeTrue(), "the half-built attachment is released")
			}
			if name == "no Release" {
				Expect(f.Close()).NotTo(Succeed(), "the file was closed")
			}
		}
	})

	It("releases the attachment after the hypervisor exits, and logs a release that fails", func() {
		f, err := os.CreateTemp(GinkgoT().TempDir(), "disk")
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Truncate(defaultImageSize)).To(Succeed())
		hypervisorDone := filepath.Join(out, "hypervisor-done")
		released := false
		p := fake("Fake", "fuse.juicefs", strongMatch)
		p.prepare = func(prepareRequest) (*attachment, error) {
			return &attachment{File: f, Release: func() error {
				Expect(hypervisorDone).To(BeAnExistingFile(), "Release runs after the hypervisor")
				released = true
				Expect(f.Close()).To(Succeed())
				return errors.New("the fake fence would not let go")
			}}, nil
		}
		withProviders(p)
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), `: >`+shellQuote(hypervisorDone)+"\n")
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		Expect(released).To(BeTrue())
		Expect(logBuf.String()).To(HaveSuffix("releasing the volume image: the fake fence would not let go\n"))
	})
})
