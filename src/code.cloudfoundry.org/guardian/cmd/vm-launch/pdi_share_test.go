//go:build linux

package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// shareVol is a selected volume at path with the provider and settings given.
func shareVol(path string, p diskProvider, mode volumeMode) selectedVolume {
	return selectedVolume{
		Volume:   guestVolume{ContainerDir: path, ImageName: "i", Settings: volumeSettings{Mode: mode}},
		Provider: p,
		Mount:    mountRecord{ContainerDir: path},
	}
}

// indexed gives each of vs its place in the list as its volume index, as
// findVolumeProviders does when it selects every volume of a launch.
func indexed(vs ...selectedVolume) []selectedVolume {
	for i := range vs {
		vs[i].Index = i
	}
	return vs
}

// privateProvider is a provider that declares private volumes only, as a
// block provider would.
func privateProvider(name string) *fakeDiskProvider {
	f := fake(name)
	f.caps.Sharing = sharingPrivate
	return f
}

var _ = Describe("which providers can be shared", func() {
	It("lets JuiceFS and NFS declare their volumes shareable", func() {
		Expect(juicefsProvider{}.Capabilities(mountRecord{FSType: juicefsFSType}).Sharing).To(Equal(sharingShared))
		Expect(nfsProvider{}.Capabilities(mountRecord{FSType: nfs4FSType}).Sharing).To(Equal(sharingShared))
	})

	It("leaves a provider that declares nothing private", func() {
		Expect(capabilities{}.Sharing).NotTo(Equal(sharingShared))
		Expect(fileImageCaps.Sharing).NotTo(Equal(sharingShared))
	})

	It("names file-image mode in a line", func() {
		Expect(attachFileImage.String()).To(Equal("file-image mode"))
	})
})

var _ = Describe("grantShares", func() {
	juice := func(path string, mode volumeMode) selectedVolume { return shareVol(path, juicefsProvider{}, mode) }
	nfs := func(path string, mode volumeMode) selectedVolume { return shareVol(path, nfsProvider{}, mode) }

	Describe("when no volume asks for a share", func() {
		It("grants nothing and refuses nothing, whatever the backend, provider, and switch", func() {
			for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
				for _, allow := range []bool{true, false} {
					for _, p := range []diskProvider{juicefsProvider{}, nfsProvider{}, privateProvider("Block"), nil} {
						grants, err := grantShares(kind, allow, []selectedVolume{shareVol("/data", p, volumePrivate), shareVol("/other", p, volumePrivate)})
						Expect(err).NotTo(HaveOccurred())
						Expect(grants).To(BeEmpty())
					}
				}
			}
		})

		It("grants nothing for no volumes", func() {
			grants, err := grantShares(backend.VMQemu, true, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(grants).To(BeEmpty())
		})
	})

	Describe("a granted share", func() {
		It("is a JuiceFS volume on QEMU with the operator's switch on", func() {
			grants, err := grantShares(backend.VMQemu, true, []selectedVolume{juice("/shared", volumeShare)})
			Expect(err).NotTo(HaveOccurred())
			Expect(grants).To(Equal([]shareGrant{{Index: 0, Path: "/shared", Mount: mountRecord{ContainerDir: "/shared"}, Tag: "rvm-vol0", Provider: "JuiceFS"}}))
		})

		It("is a kernel NFSv4 volume on QEMU with the operator's switch on", func() {
			grants, err := grantShares(backend.VMQemu, true, []selectedVolume{nfs("/shared", volumeShare)})
			Expect(err).NotTo(HaveOccurred())
			Expect(grants).To(Equal([]shareGrant{{Index: 0, Path: "/shared", Mount: mountRecord{ContainerDir: "/shared"}, Tag: "rvm-vol0", Provider: "NFS"}}))
		})

		It("takes its index and tag from its place among all the volumes, and skips the private ones", func() {
			grants, err := grantShares(backend.VMQemu, true, indexed(
				juice("/a", volumePrivate), nfs("/b", volumeShare), juice("/c", volumePrivate), juice("/d", volumeShare),
			))
			Expect(err).NotTo(HaveOccurred())
			Expect(grants).To(Equal([]shareGrant{
				{Index: 1, Path: "/b", Mount: mountRecord{ContainerDir: "/b"}, Tag: "rvm-vol1", Provider: "NFS"},
				{Index: 3, Path: "/d", Mount: mountRecord{ContainerDir: "/d"}, Tag: "rvm-vol3", Provider: "JuiceFS"},
			}))
		})

		It("takes the volume index it was selected with, not its place in the list it is given", func() {
			v := juice("/c", volumeShare)
			v.Index = 2
			grants, err := grantShares(backend.VMQemu, true, []selectedVolume{v})
			Expect(err).NotTo(HaveOccurred())
			Expect(grants).To(Equal([]shareGrant{{Index: 2, Path: "/c", Mount: mountRecord{ContainerDir: "/c"}, Tag: "rvm-vol2", Provider: "JuiceFS"}}))
		})

		It("is any provider that declares its volumes shareable", func() {
			p := fake("Other")
			p.caps.Sharing = sharingShared
			grants, err := grantShares(backend.VMQemu, true, []selectedVolume{shareVol("/x", p, volumeShare)})
			Expect(err).NotTo(HaveOccurred())
			Expect(grants).To(HaveLen(1))
			Expect(grants[0].Provider).To(Equal("Other"))
		})

		It("asks the provider about the volume's own mount", func() {
			var asked []string
			p := &askingProvider{fakeDiskProvider: *privateProvider("Ask"), asked: &asked}
			_, err := grantShares(backend.VMQemu, true, []selectedVolume{shareVol("/x", p, volumeShare)})
			Expect(err).To(HaveOccurred())
			Expect(asked).To(Equal([]string{"/x"}))
		})

		It("numbers the tags rvm-vol0 to rvm-vol3", func() {
			Expect([]string{shareTag(0), shareTag(1), shareTag(2), shareTag(3)}).To(Equal([]string{"rvm-vol0", "rvm-vol1", "rvm-vol2", "rvm-vol3"}))
		})
	})

	DescribeTable("a refused share",
		func(kind backend.Kind, allow bool, vol selectedVolume, want string) {
			grants, err := grantShares(kind, allow, []selectedVolume{vol})
			Expect(err).To(MatchError(want))
			Expect(grants).To(BeNil())
		},
		Entry("on Firecracker, with the switch on",
			backend.VMFirecracker, true, juice("/shared", volumeShare),
			`VM_VOLUMES "/shared" mode "share" is not available on vm-firecracker, which has no virtiofs device; shares need the vm-qemu backend`),
		Entry("on Firecracker, with the switch off",
			backend.VMFirecracker, false, juice("/shared", volumeShare),
			`VM_VOLUMES "/shared" mode "share" is not available on vm-firecracker, which has no virtiofs device; shares need the vm-qemu backend`),
		Entry("on Firecracker, for NFS",
			backend.VMFirecracker, true, nfs("/shared", volumeShare),
			`VM_VOLUMES "/shared" mode "share" is not available on vm-firecracker, which has no virtiofs device; shares need the vm-qemu backend`),
		Entry("on Firecracker, for a provider that cannot share, which gets the backend's line first",
			backend.VMFirecracker, false, shareVol("/disk", privateProvider("Block"), volumeShare),
			`VM_VOLUMES "/disk" mode "share" is not available on vm-firecracker, which has no virtiofs device; shares need the vm-qemu backend`),
		Entry("on a backend that is neither",
			backend.Kind("vm-other"), true, juice("/shared", volumeShare),
			`VM_VOLUMES "/shared" mode "share" is not available on vm-other, which cannot serve a share; shares need the vm-qemu backend`),
		Entry("for a block provider that declares its volumes private",
			backend.VMQemu, true, shareVol("/disk", privateProvider("BOSH disk"), volumeShare),
			`VM_VOLUMES "/disk" mode "share" is not available for a BOSH disk volume; only JuiceFS and NFSv4 volumes can be shared`),
		Entry("for a provider that declares nothing",
			backend.VMQemu, true, shareVol("/disk", fake("Plain"), volumeShare),
			`VM_VOLUMES "/disk" mode "share" is not available for a Plain volume; only JuiceFS and NFSv4 volumes can be shared`),
		Entry("for a provider that cannot share, with the switch off, which gets the provider's line first",
			backend.VMQemu, false, shareVol("/disk", privateProvider("Block"), volumeShare),
			`VM_VOLUMES "/disk" mode "share" is not available for a Block volume; only JuiceFS and NFSv4 volumes can be shared`),
		Entry("for a volume with no provider",
			backend.VMQemu, true, shareVol("/disk", nil, volumeShare),
			`VM_VOLUMES "/disk" mode "share" is not available for a volume that no provider owns; only JuiceFS and NFSv4 volumes can be shared`),
		Entry("for JuiceFS without the operator's switch",
			backend.VMQemu, false, juice("/shared", volumeShare),
			`VM_VOLUMES "/shared" mode "share" is not allowed on this cell; the operator has not turned on volume shares`),
		Entry("for NFS without the operator's switch",
			backend.VMQemu, false, nfs("/shared", volumeShare),
			`VM_VOLUMES "/shared" mode "share" is not allowed on this cell; the operator has not turned on volume shares`),
	)

	It("quotes and cuts a long or odd volume path in its line", func() {
		long := "/" + strings.Repeat("d", 300)
		_, err := grantShares(backend.VMQemu, false, []selectedVolume{juice(long, volumeShare)})
		Expect(err).To(MatchError(`VM_VOLUMES "/` + strings.Repeat("d", 63) + `"... mode "share" is not allowed on this cell; the operator has not turned on volume shares`))
		_, err = grantShares(backend.VMQemu, false, []selectedVolume{juice("/a\"b\nc", volumeShare)})
		Expect(err).To(MatchError(HavePrefix(`VM_VOLUMES "/a\"b\nc" mode`)))
		Expect(err.Error()).NotTo(ContainSubstring("\n"))
	})

	It("refuses the whole launch when one of several shares is refused, and returns no grants", func() {
		grants, err := grantShares(backend.VMQemu, true, []selectedVolume{
			juice("/ok", volumeShare), shareVol("/disk", privateProvider("Block"), volumeShare), nfs("/ok2", volumeShare),
		})
		Expect(err).To(MatchError(`VM_VOLUMES "/disk" mode "share" is not available for a Block volume; only JuiceFS and NFSv4 volumes can be shared`))
		Expect(grants).To(BeNil())
	})

	It("reports the first refused volume in volume order", func() {
		_, err := grantShares(backend.VMQemu, false, []selectedVolume{
			juice("/a", volumePrivate), shareVol("/b", privateProvider("Block"), volumeShare), juice("/c", volumeShare),
		})
		Expect(err).To(MatchError(ContainSubstring(`"/b"`)))
	})

	It("does not refuse a private volume of a provider that cannot share, beside a share", func() {
		grants, err := grantShares(backend.VMQemu, true, indexed(shareVol("/disk", privateProvider("Block"), volumePrivate), juice("/shared", volumeShare)))
		Expect(err).NotTo(HaveOccurred())
		Expect(grants).To(HaveLen(1))
		Expect(grants[0].Index).To(Equal(1))
		Expect(grants[0].Tag).To(Equal("rvm-vol1"))
	})
})

// askingProvider records the path of each mount Capabilities is asked about.
type askingProvider struct {
	fakeDiskProvider
	asked *[]string
}

func (a *askingProvider) Capabilities(m mountRecord) capabilities {
	*a.asked = append(*a.asked, m.ContainerDir)
	return a.fakeDiskProvider.Capabilities(m)
}

var _ = Describe("the --allow-volume-shares flag", func() {
	It("is named allow-volume-shares", func() {
		Expect(allowVolumeSharesFlag).To(Equal("allow-volume-shares"))
		Expect(usage).To(ContainSubstring("[--" + allowVolumeSharesFlag + "]"))
	})

	It("is off by default and on when given, for either backend", func() {
		for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			cfg, err := parseArgs([]string{"--backend", string(kind), "--", "true"})
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.allowVolumeShares).To(BeFalse())

			cfg, err = parseArgs([]string{"--backend", string(kind), "--allow-volume-shares", "--", "true"})
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.allowVolumeShares).To(BeTrue())
		}
	})

	It("takes an explicit value, and refuses one that is not a boolean", func() {
		cfg, err := parseArgs([]string{"--backend", "vm-qemu", "--allow-volume-shares=false", "--", "true"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.allowVolumeShares).To(BeFalse())
		_, err = parseArgs([]string{"--backend", "vm-qemu", "--allow-volume-shares=maybe", "--", "true"})
		Expect(err).To(HaveOccurred())
	})

	It("does not change the other settings", func() {
		cfg, err := parseArgs([]string{"--backend", "vm-firecracker", "--transparent-proxy", "--allow-volume-shares", "--", "true"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.transparent).To(BeTrue())
		Expect(cfg.allowVolumeShares).To(BeTrue())
		Expect(cfg.backend).To(Equal(backend.VMFirecracker))
	})
})

var _ = Describe("run with a share request", func() {
	var (
		art     string
		tmp     string
		volDir  string
		infoDir string
		logBuf  *bytes.Buffer
	)

	// setMountInfo makes line the mount table. infoDir is made before TMPDIR
	// is set, so that it is not inside the directory that must stay empty.
	setMountInfo := func(line string) {
		mountInfoPath = filepath.Join(infoDir, "mountinfo")
		Expect(os.WriteFile(mountInfoPath, []byte(line), 0o644)).To(Succeed())
	}

	BeforeEach(func() {
		art = makeArtifacts()
		volDir = GinkgoT().TempDir()
		infoDir = GinkgoT().TempDir()
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		GinkgoT().Setenv("CF_INSTANCE_INDEX", "2")
		GinkgoT().Setenv("VCAP_APPLICATION", vcapApp)
		DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)
		// The credentials hold a sentinel that no refusal line may repeat.
		GinkgoT().Setenv("VCAP_SERVICES", `{"juicefs":[{"name":"b","credentials":{"password":"`+secretSentinel+`"},"volume_mounts":[`+mountJSON(volDir, "rw")+`]}]}`)
		setMountInfo(mountinfoLine(40, volDir, "fuse.juicefs"))
		logBuf = &bytes.Buffer{}

		saved := defaultImageOptions
		DeferCleanup(func() { defaultImageOptions = saved })
		defaultImageOptions.IsMountRoot = alwaysMountRoot
		defaultImageOptions.LockWait = 300 * time.Millisecond
		defaultImageOptions.LockPoll = 20 * time.Millisecond
		GinkgoT().Setenv("VM_VOLUMES", `{"`+volDir+`":{"mode":"share"}}`)
	})

	runWith := func(args ...string) int {
		argv := append(append([]string{}, args...), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", "")
		return run(argv, log.New(logBuf, "", 0))
	}

	// refused checks that run exits 125 with exactly the line, before it
	// starts a hypervisor, creates a work directory, or touches the volume.
	refused := func(want string, args ...string) {
		GinkgoHelper()
		logBuf.Reset()
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runWith(args...)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal(want + "\n"))
		Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(os.ReadDir(volDir)).To(BeEmpty())
	}

	shareLine := func(tail string) string { return `VM_VOLUMES ` + quoteForLog(volDir) + ` mode "share" ` + tail }

	It("refuses a share on Firecracker whether or not the operator allows shares", func() {
		line := shareLine(`is not available on vm-firecracker, which has no virtiofs device; shares need the vm-qemu backend`)
		refused(line, "--backend", "vm-firecracker")
		refused(line, "--backend", "vm-firecracker", "--allow-volume-shares")
	})

	It("refuses a share on QEMU when the operator has not allowed shares", func() {
		refused(shareLine(`is not allowed on this cell; the operator has not turned on volume shares`), "--backend", "vm-qemu")
	})

	It("refuses a share of a volume whose provider cannot share, with the switch on", func() {
		withProviders(privateProvider("Block"))
		diskProviders.providers[0].(*fakeDiskProvider).matches["fuse.juicefs"] = strongMatch
		refused(shareLine(`is not available for a Block volume; only JuiceFS and NFSv4 volumes can be shared`), "--backend", "vm-qemu", "--allow-volume-shares")
	})

	noVirtiofsd := func() string {
		return `VM_VOLUMES ` + quoteForLog(volDir) + ` is granted a share, but vm-launch was not given --virtiofsd-path, so nothing can serve it; the operator must install virtiofsd and pass its path`
	}

	It("grants a JuiceFS share on QEMU with the switch on, and stops before it boots when there is no virtiofsd", func() {
		refused(noVirtiofsd(), "--backend", "vm-qemu", "--allow-volume-shares")
	})

	It("grants a kernel NFSv4 share on QEMU with the switch on, and stops before it boots when there is no virtiofsd", func() {
		setMountInfo(nfsMountinfoLine(40, volDir, "nfs4", "10.0.0.5:/export", labNFSOptions))
		GinkgoT().Setenv("VCAP_SERVICES", `{"nfs":[{"name":"b","credentials":{"password":"`+secretSentinel+`"},"volume_mounts":[`+mountJSON(volDir, "rw")+`]}]}`)
		refused(noVirtiofsd(), "--backend", "vm-qemu", "--allow-volume-shares")
		refused(shareLine(`is not allowed on this cell; the operator has not turned on volume shares`), "--backend", "vm-qemu")
	})

	It("lets a volume that no provider owns keep the registry's refusal", func() {
		setMountInfo(mountinfoLine(40, volDir, "cifs"))
		refused(`volume path `+quoteForLog(volDir)+` is a "cifs" mount; VM backends support only JuiceFS and NFS volumes today`,
			"--backend", "vm-qemu", "--allow-volume-shares")
	})

	It("lets a bad VM_VOLUMES value keep its own refusal", func() {
		GinkgoT().Setenv("VM_VOLUMES", `{"`+volDir+`":{"mode":"share","size":"1G"}}`)
		refused(`VM_VOLUMES `+quoteForLog(volDir)+` sets a size, but a share has no image; its space is the volume's own quota`,
			"--backend", "vm-qemu", "--allow-volume-shares")
	})

	It("does not look at the switch for a volume that stays private", func() {
		for _, value := range []string{`{"` + volDir + `":{"mode":"private"}}`, `{"` + volDir + `":{}}`, ``} {
			GinkgoT().Setenv("VM_VOLUMES", value)
			for _, args := range [][]string{{"--backend", "vm-qemu"}, {"--backend", "vm-qemu", "--allow-volume-shares"}} {
				logBuf.Reset()
				writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
				Expect(runWith(args...)).To(Equal(0), logBuf.String())
				Expect(logBuf.String()).NotTo(ContainSubstring("share"))
			}
		}
	})
})
