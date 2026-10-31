//go:build linux

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// blockPlanLine is the refusal of a BOSH disk in mount mode for the volume at
// dir, which is on fstype and source, written out in full.
func blockPlanLine(dir, fstype, source string) string {
	return fmt.Sprintf("volume path %q is a BOSH disk bound in the driver's mount mode (%s on the whole disk %q); "+
		"VM backends attach a BOSH disk only in block mode, so bind a service instance of the bosh-disk block plan", dir, fstype, source)
}

// diskLine is a mountinfo line for the root of a filesystem mounted at /data.
func diskLine(fstype, source, root string) string {
	return fmt.Sprintf("41 30 8:16 %s /data rw,nodev,relatime shared:5 - %s %s rw\n", root, fstype, source)
}

var _ = Describe("the mount refusals", func() {
	It("registers the BOSH disk refusal and leaves the supported providers alone", func() {
		Expect(mountRefusals).To(HaveLen(3), "the BOSH disk refusal, the NFS refusal, and the block-mode descriptor refusal")
		Expect(providerNamesOf(diskProviders)).To(Equal([]string{"BOSH disk", "JuiceFS", "NFS"}))
		Expect(diskProviders.supportedLine()).To(Equal("VM backends support only BOSH disk, JuiceFS, and NFS volumes today"))
	})

	It("panics on a nil refusal and keeps registration order", func() {
		saved := mountRefusals
		DeferCleanup(func() { mountRefusals = saved })
		Expect(func() { registerMountRefusal(nil) }).To(PanicWith("registering a nil mount refusal"))
		Expect(mountRefusals).To(HaveLen(len(saved)))

		var order []string
		registerMountRefusal(func(mountRecord) error { order = append(order, "first"); return nil })
		registerMountRefusal(func(mountRecord) error { order = append(order, "second"); return nil })
		_, err := diskProviders.selectProvider(mountRecord{ContainerDir: "/data", FSType: "fuse.juicefs"})
		Expect(err).NotTo(HaveOccurred())
		Expect(order).To(Equal([]string{"first", "second"}))
	})

	It("stops at the first refusal that answers, before any provider is asked", func() {
		saved := mountRefusals
		DeferCleanup(func() { mountRefusals = saved })
		mountRefusals = nil
		asked := 0
		registerMountRefusal(func(mountRecord) error { return fmt.Errorf("first refusal") })
		registerMountRefusal(func(mountRecord) error { asked++; return fmt.Errorf("second refusal") })
		p := fake("Strong", "fuse.juicefs", strongMatch)
		withProviders(p)
		_, err := diskProviders.selectProvider(mountRecord{ContainerDir: "/data", FSType: "fuse.juicefs"})
		Expect(err).To(MatchError("first refusal"))
		Expect(asked).To(BeZero())
	})

	It("refuses a mount-mode BOSH disk even when a provider matches ext4 strongly", func() {
		withProviders(fake("Greedy", "ext4", strongMatch, "xfs", strongMatch))
		_, err := diskProviders.selectProvider(mountRecord{ContainerDir: "/data", Root: "/", FSType: "ext4", Source: "/dev/sdb"})
		Expect(err).To(MatchError(blockPlanLine("/data", "ext4", "/dev/sdb")))
	})

	DescribeTable("refuses a BOSH disk in mount mode",
		func(fstype, source string) {
			_, m, err := findIn(writeTempFile("mountinfo", diskLine(fstype, source, "/")), "/data")
			Expect(m).To(Equal(mountRecord{}))
			Expect(err).To(MatchError(blockPlanLine("/data", fstype, source)))
			Expect(err.Error()).NotTo(ContainSubstring("VM backends support only"))
		},
		Entry("ext4 on a SCSI disk", "ext4", "/dev/sda"),
		Entry("ext4 on the second SCSI disk", "ext4", "/dev/sdb"),
		Entry("ext4 on a disk named with two letters", "ext4", "/dev/sdaa"),
		Entry("ext4 on a virtio disk", "ext4", "/dev/vdb"),
		Entry("ext4 on a Xen disk", "ext4", "/dev/xvdf"),
		Entry("ext4 on an IDE disk", "ext4", "/dev/hdb"),
		Entry("ext4 on an NVMe namespace", "ext4", "/dev/nvme1n1"),
		Entry("xfs on a SCSI disk", "xfs", "/dev/sdb"),
		Entry("xfs on an NVMe namespace", "xfs", "/dev/nvme12n3"),
	)

	DescribeTable("leaves the mounts that are not a BOSH disk in mount mode to the providers",
		func(line string, fstype string) {
			_, m, err := findIn(writeTempFile("mountinfo", line), "/data")
			Expect(m).To(Equal(mountRecord{}))
			Expect(err).To(MatchError(`volume path "/data" is a ` + `"` + fstype + `"` + ` mount; VM backends support only BOSH disk, JuiceFS, and NFS volumes today`))
		},
		Entry("a partition", diskLine("ext4", "/dev/sdb1", "/"), "ext4"),
		Entry("a partition of a virtio disk", diskLine("ext4", "/dev/vdb2", "/"), "ext4"),
		Entry("a partition of an NVMe namespace", diskLine("ext4", "/dev/nvme1n1p1", "/"), "ext4"),
		Entry("a device-mapper volume", diskLine("ext4", "/dev/mapper/vg-data", "/"), "ext4"),
		Entry("a loop device", diskLine("ext4", "/dev/loop3", "/"), "ext4"),
		Entry("a path under /dev", diskLine("ext4", "/dev/disk/by-id/sdb", "/"), "ext4"),
		Entry("a path that only ends like a disk", diskLine("ext4", "/mnt/dev/sdb", "/"), "ext4"),
		Entry("a name that only starts like a disk", diskLine("ext4", "/dev/sdb-old", "/"), "ext4"),
		Entry("a source that is not a device", diskLine("ext4", "src", "/"), "ext4"),
		Entry("a source with no name", diskLine("ext4", "none", "/"), "ext4"),
		Entry("a subdirectory of a disk", diskLine("ext4", "/dev/sdb", "/data"), "ext4"),
		Entry("an XFS partition", diskLine("xfs", "/dev/sdb1", "/"), "xfs"),
		Entry("ext3 on a disk", diskLine("ext3", "/dev/sdb", "/"), "ext3"),
		Entry("btrfs on a disk", diskLine("btrfs", "/dev/sdb", "/"), "btrfs"),
		Entry("a tmpfs named for another device", diskLine("tmpfs", "/dev/sdb", "/"), "tmpfs"),
	)

	It("does not refuse a JuiceFS mount, whatever its source says", func() {
		for _, source := range []string{"JuiceFS:vol", "/dev/sdb", "/dev/nvme1n1", "pdi:bosh-disk"} {
			p, m, err := findIn(writeTempFile("mountinfo", diskLine("fuse.juicefs", source, "/")), "/data")
			Expect(err).NotTo(HaveOccurred(), source)
			Expect(p.Name()).To(Equal("JuiceFS"))
			Expect(m.Source).To(Equal(source))
		}
	})

	It("never answers an NFS mount with the BOSH disk line, even when its source looks like a whole disk", func() {
		// The NFS provider owns nfs4 with local_lock=none, and its refusal
		// answers nfs, fuse.mapfs, and nfs4 without that option in its own
		// words. None of them is a BOSH disk in mount mode, so the BOSH disk
		// refusal stays silent for all of them.
		for _, c := range []struct {
			name, fstype, source, superOptions string
			owned                              bool
		}{
			{"a kernel NFSv4 mount the provider owns", "nfs4", "10.0.0.5:/export", labNFSOptions, true},
			{"the same mount with a disk-like source", "nfs4", "/dev/sdb", labNFSOptions, true},
			{"an NFSv4 mount without the lock option", "nfs4", "10.0.0.5:/export", "rw,vers=4.1", false},
			{"an NFSv4 mount without the lock option, disk-like source", "nfs4", "/dev/sdb", "rw,vers=4.1", false},
			{"a kernel NFSv3 mount", "nfs", "10.0.0.5:/export", "rw,vers=3", false},
			{"a kernel NFSv3 mount with a disk-like source", "nfs", "/dev/sdb", "rw,vers=3", false},
			{"a mapfs mount", "fuse.mapfs", "/var/vcap/data/nfs", "rw", false},
			{"a mapfs mount with a disk-like source", "fuse.mapfs", "/dev/sdb", "rw", false},
		} {
			m := mountRecord{ContainerDir: "/data", Root: "/", FSType: c.fstype, Source: c.source, SuperOptions: strings.Split(c.superOptions, ",")}
			Expect(refuseBoshDiskMountMode(m)).To(Succeed(), c.name)

			p, got, err := findIn(writeTempFile("mountinfo", nfsMountinfoLine(40, "/data", c.fstype, c.source, c.superOptions)), "/data")
			if c.owned {
				Expect(err).NotTo(HaveOccurred(), c.name)
				Expect(p.Name()).To(Equal("NFS"), c.name)
				Expect(got.FSType).To(Equal(c.fstype), c.name)
				continue
			}
			// A mount the NFS provider refuses says so in NFS's own words.
			Expect(err).To(MatchError(refuseNFSMount(m)), c.name)
			Expect(err.Error()).NotTo(ContainSubstring("mount mode"), c.name)
			Expect(err.Error()).NotTo(ContainSubstring("block plan"), c.name)
		}
	})

	It("keeps the BOSH disk refusal ahead of the NFS provider for an ext4 or xfs whole disk", func() {
		for _, fstype := range []string{"ext4", "xfs"} {
			_, _, err := findIn(writeTempFile("mountinfo", diskLine(fstype, "/dev/sdb", "/")), "/data")
			Expect(err).To(MatchError(blockPlanLine("/data", fstype, "/dev/sdb")))
		}
	})

	It("does not refuse NFS or the block-mode descriptor when providers claim them", func() {
		withProviders(fake("NFS", "nfs4", strongMatch), fake("Block", "tmpfs", strongMatch))
		for _, line := range []string{
			nfsMountinfoLine(41, "/data", "nfs4", "10.0.0.5:/export", labNFSOptions),
			strings.Replace(diskLine("tmpfs", "pdi:bosh-disk", "/"), " rw\n", " ro\n", 1),
		} {
			p, _, err := findIn(writeTempFile("mountinfo", line), "/data")
			Expect(err).NotTo(HaveOccurred(), line)
			Expect(p).NotTo(BeNil())
		}
	})

	It("quotes and bounds a source it names", func() {
		m := mountRecord{ContainerDir: "/data", Root: "/", FSType: "ext4", Source: "/dev/sdb"}
		Expect(refuseBoshDiskMountMode(m)).To(MatchError(ContainSubstring(`"/dev/sdb"`)))
		m.ContainerDir = "/da\nta/" + strings.Repeat("x", 4*maxLoggedValueLen)
		err := refuseBoshDiskMountMode(m)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).NotTo(ContainSubstring("\n"))
		Expect(len(err.Error())).To(BeNumerically("<", 2*maxLoggedValueLen+400))
	})

	It("answers nil for the empty record", func() {
		Expect(refuseBoshDiskMountMode(mountRecord{})).To(Succeed())
	})
})

var _ = Describe("run with a BOSH disk bound in mount mode", func() {
	var (
		art    string
		tmp    string
		volDir string
		logBuf *bytes.Buffer
	)

	BeforeEach(func() {
		requireOpenat2()
		art = makeArtifacts()
		volDir = GinkgoT().TempDir()
		tmp = GinkgoT().TempDir()
		DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)
		mountInfoPath = writeTempFile("mountinfo", fmt.Sprintf("40 29 8:16 / %s rw,nodev - ext4 /dev/sdb rw\n", volDir))
		GinkgoT().Setenv("TMPDIR", tmp)
		GinkgoT().Setenv("CF_INSTANCE_INDEX", "0")
		GinkgoT().Setenv("VCAP_APPLICATION", vcapApp)
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"bosh-disk": {mountJSON(volDir, "rw")}}))
		logBuf = &bytes.Buffer{}
	})

	It("exits 125 with the block plan line before it creates anything", func() {
		argvFile := writeFakeHypervisor(art+"/qemu/ld-linux-x86-64.so.2", "")
		code := run([]string{"--backend", string(backend.VMQemu), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""},
			log.New(logBuf, "", 0))
		Expect(code).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring(blockPlanLine(volDir, "ext4", "/dev/sdb")))
		Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(os.ReadDir(volDir)).To(BeEmpty())
		Expect(argvFile).NotTo(BeAnExistingFile())
	})
})
