//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// labNFSOptions are the superblock options of the lab's kernel NFSv4 mount,
// as nfsv3driver mounts a binding that gives no uid.
const labNFSOptions = "rw,vers=4.1,hard,proto=tcp,timeo=600,retrans=2,sec=sys,local_lock=none"

// nfsMountinfoLine is a mountinfo line for a volume at point with the given
// filesystem type, source, and superblock options.
func nfsMountinfoLine(id int, point, fstype, source, superOptions string) string {
	return fmt.Sprintf("%d 29 0:%d / %s rw,relatime shared:%d - %s %s %s\n", id, id, point, id, fstype, source, superOptions)
}

var _ = Describe("the NFS provider", func() {
	record := func(fstype string, superOptions ...string) mountRecord {
		return mountRecord{ContainerDir: "/data", FSType: fstype, SuperOptions: superOptions}
	}

	It("matches a kernel NFSv4 mount with local_lock=none strongly, whatever else its options say", func() {
		for name, m := range map[string]mountRecord{
			"only the lock option": record("nfs4", "local_lock=none"),
			"the lab's options":    record("nfs4", strings.Split(labNFSOptions, ",")...),
			"NFS 4.2":              record("nfs4", "rw", "vers=4.2", "local_lock=none"),
			"NFS 4.0":              record("nfs4", "rw", "vers=4.0", "local_lock=none"),
		} {
			Expect(nfsProvider{}.Match(m)).To(Equal(strongMatch), name)
		}
	})

	It("claims the mounts it refuses weakly, so that its own words explain the refusal", func() {
		for name, m := range map[string]mountRecord{
			"an NFSv4 mount with no lock option":        record("nfs4", "rw", "vers=4.1"),
			"an NFSv4 mount with no options":            record("nfs4"),
			"an NFSv4 mount with local_lock=all":        record("nfs4", "rw", "local_lock=all"),
			"an NFSv4 mount with local_lock=flock":      record("nfs4", "rw", "local_lock=flock"),
			"an NFSv4 mount with local_lock=posix":      record("nfs4", "rw", "local_lock=posix"),
			"a lock option that only starts like it":    record("nfs4", "local_lock=none2"),
			"the option in the wrong case":              record("nfs4", "LOCAL_LOCK=NONE"),
			"the option name without its value":         record("nfs4", "local_lock"),
			"an NFSv3 mount":                            record("nfs", "rw", "vers=3", "local_lock=none"),
			"a mapfs mount":                             record("fuse.mapfs", "rw"),
			"a mapfs mount that carries the lock label": record("fuse.mapfs", "local_lock=none"),
		} {
			Expect(nfsProvider{}.Match(m)).To(Equal(weakMatch), name)
		}
	})

	It("matches no other filesystem type", func() {
		for _, fstype := range []string{"", "NFS4", "nfs42", "nfs4 ", "NFS", "fuse.juicefs", "fuse", "mapfs", "FUSE.MAPFS", "fuse.mapfs2", "ext4", "cifs", "tmpfs"} {
			Expect(nfsProvider{}.Match(record(fstype, "local_lock=none"))).To(Equal(noMatch), fstype)
		}
	})

	It("is a file-image provider with a lock that holds across cells, and is named NFS", func() {
		Expect(nfsProvider{}.Name()).To(Equal("NFS"))
		c := nfsProvider{}.Capabilities(record("nfs4", "local_lock=none"))
		Expect(c.Modes).To(Equal([]attachMode{attachFileImage}))
		Expect(c.Fence).To(Equal(fenceDistributedFlock))
		Expect(checkCapabilities(nfsProvider{}, c)).To(Succeed())
	})

	It("is in the registry beside JuiceFS, and the registry picks it for a kernel NFSv4 mount", func() {
		Expect(providerNamesOf(diskProviders)).To(ContainElement("NFS"))
		p, err := diskProviders.selectProvider(record("nfs4", strings.Split(labNFSOptions, ",")...))
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Name()).To(Equal("NFS"))
		p, err = diskProviders.selectProvider(record("fuse.juicefs"))
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Name()).To(Equal("JuiceFS"))
	})

	It("is the provider findVolumeProvider returns for the lab's NFSv4 mount, with the whole record", func() {
		info := writeTempFile("mountinfo", nfsMountinfoLine(40, "/data", "nfs4", "10.108.0.1:/tank/nfs/labs/wayneeseguin/agents", labNFSOptions))
		p, m, err := findIn(info, "/data")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Name()).To(Equal("NFS"))
		Expect(m.MountID).To(Equal(uint64(40)))
		Expect(m.FSType).To(Equal("nfs4"))
		Expect(m.Source).To(Equal("10.108.0.1:/tank/nfs/labs/wayneeseguin/agents"))
		Expect(m.SuperOptions).To(ContainElements("vers=4.1", "local_lock=none"))
	})

	It("is the provider findVolumeProvider returns for the mounts it refuses, so that Prepare can explain", func() {
		for _, c := range []struct{ fstype, options string }{
			{"nfs", "rw,vers=3,hard,proto=tcp"},
			{"nfs4", "rw,vers=4.1,hard"},
			{"fuse.mapfs", "rw"},
		} {
			info := writeTempFile("mountinfo", nfsMountinfoLine(40, "/data", c.fstype, "src", c.options))
			p, _, err := findIn(info, "/data")
			Expect(err).NotTo(HaveOccurred(), c.fstype)
			Expect(p.Name()).To(Equal("NFS"), c.fstype)
		}
	})
})

var _ = Describe("the NFS provider's Prepare", func() {
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
		saved, savedProbe := defaultImageOptions, dirProbe
		DeferCleanup(func() { defaultImageOptions, dirProbe = saved, savedProbe })
		defaultImageOptions.IsMountRoot = alwaysMountRoot
		defaultImageOptions.LockWait = 100 * time.Millisecond
		defaultImageOptions.LockPoll = 10 * time.Millisecond
		defaultImageOptions.Size = 4 << 20
		// The directory is on mount 40, as the request says.
		dirProbe = func(int, string) (mountProbe, error) { return mountProbe{MountID: 40, MountRoot: true}, nil }
	})

	request := func(fstype string, superOptions ...string) prepareRequest {
		return prepareRequest{
			Mount:     mountRecord{ContainerDir: dir, MountID: 40, FSType: fstype, SuperOptions: superOptions},
			ImageName: name, Mode: attachFileImage,
		}
	}
	kernelNFS4 := func() prepareRequest { return request("nfs4", strings.Split(labNFSOptions, ",")...) }

	It("creates the image allocated, with fallocate KEEP_SIZE on the whole range, and returns it locked", func() {
		var calls []fallocateCall
		defaultImageOptions.fallocate = func(fd int, mode uint32, off, length int64) error {
			calls = append(calls, fallocateCall{mode, off, length})
			return unix.Fallocate(fd, mode, off, length)
		}
		att, err := nfsProvider{}.Prepare(kernelNFS4())
		if err != nil && errors.Is(err, unix.EOPNOTSUPP) {
			Skip("this filesystem has no fallocate")
		}
		Expect(err).NotTo(HaveOccurred())
		Expect(calls).To(Equal([]fallocateCall{{unix.FALLOC_FL_KEEP_SIZE, 0, 4 << 20}}))
		Expect(att.File.Name()).To(Equal(img))
		st := statOf(img)
		Expect(st.Size).To(Equal(int64(4 << 20)))
		Expect(st.Blocks * 512).To(BeNumerically(">=", 4<<20))
		Expect(lockedElsewhere(img)).To(BeTrue())
		Expect(att.Release()).To(Succeed())
		Expect(lockedElsewhere(img)).To(BeFalse())
		Expect(img).To(BeARegularFile(), "Release never deletes the image")
		Expect(defaultImageOptions.Preallocate).To(BeFalse(), "the shared defaults stay as JuiceFS needs them")
	})

	It("falls back to sequential 1 MiB zero writes when the server has no ALLOCATE", func() {
		var chunks []int64
		defaultImageOptions.fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
		defaultImageOptions.afterZeroChunk = func(end int64) { chunks = append(chunks, end) }
		att, err := nfsProvider{}.Prepare(kernelNFS4())
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(att.Release)
		Expect(chunks).To(Equal([]int64{1 << 20, 2 << 20, 3 << 20, 4 << 20}))
		st := statOf(img)
		Expect(st.Size).To(Equal(int64(4 << 20)))
		Expect(st.Blocks * 512).To(BeNumerically(">=", 4<<20))
	})

	It("uses the image options in force when it runs", func() {
		defaultImageOptions.Size = 1 << 20
		att, err := nfsProvider{}.Prepare(kernelNFS4())
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(att.Release)
		Expect(statOf(img).Size).To(Equal(int64(1 << 20)))
	})

	It("opens an image that exists without allocating or changing it", func() {
		writeImage(img, 4<<20, []byte("keep"))
		defaultImageOptions.fallocate = func(int, uint32, int64, int64) error { Fail("fallocate was called"); return nil }
		att, err := nfsProvider{}.Prepare(kernelNFS4())
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(att.Release)
		Expect(os.ReadFile(img)).To(HavePrefix("keep"))
	})

	It("returns the image code's errors as they are", func() {
		writeImage(img, 4<<20, nil)
		holder, err := os.OpenFile(img, os.O_RDWR, 0)
		Expect(err).NotTo(HaveOccurred())
		defer holder.Close()
		Expect(syscall.Flock(int(holder.Fd()), syscall.LOCK_EX)).To(Succeed())

		_, err = nfsProvider{}.Prepare(kernelNFS4())
		Expect(errors.Is(err, errVolumeInUse)).To(BeTrue())
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))
	})

	It("exits 128 plus the signal when one arrives while it writes the zeros, and leaves nothing on the volume", func() {
		sigs := make(chan os.Signal, 1)
		defaultImageOptions.fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
		defaultImageOptions.afterZeroChunk = func(end int64) {
			if end == 2<<20 {
				sigs <- syscall.SIGTERM
			}
		}
		req := kernelNFS4()
		req.Signals = sigs
		_, err := nfsProvider{}.Prepare(req)
		Expect(stepExitCode(err)).To(Equal(128 + int(syscall.SIGTERM)))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("exits 125 with the quota's words and leaves nothing on the volume when the server refuses the allocation", func() {
		defaultImageOptions.fallocate = func(int, uint32, int64, int64) error { return unix.ENOSPC }
		_, err := nfsProvider{}.Prepare(kernelNFS4())
		Expect(errors.Is(err, unix.ENOSPC)).To(BeTrue(), "%v", err)
		Expect(err.Error()).To(HaveSuffix("(the volume's quota refused it)"))
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("opens the directory only on the mount it was given, and creates nothing on another", func() {
		dirProbe = func(int, string) (mountProbe, error) { return mountProbe{MountID: 41, MountRoot: true}, nil }
		defaultImageOptions.fallocate = func(int, uint32, int64, int64) error { Fail("fallocate was called"); return nil }
		_, err := nfsProvider{}.Prepare(kernelNFS4())
		Expect(errors.Is(err, errMountChanged)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError(ContainSubstring("it was mount ID 40 when vm-launch inspected it and is mount ID 41 now")))
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("refuses a directory whose mount ID cannot be read and creates nothing", func() {
		dirProbe = func(int, string) (mountProbe, error) { return mountProbe{}, unix.ENOSYS }
		_, err := nfsProvider{}.Prepare(kernelNFS4())
		Expect(err).To(MatchError(ContainSubstring("checking the mount of volume " + dir)))
		Expect(stepExitCode(err)).To(Equal(exitLaunchError))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	It("refuses an attach mode other than file image and creates nothing", func() {
		req := kernelNFS4()
		req.Mode = 0
		_, err := nfsProvider{}.Prepare(req)
		Expect(err).To(MatchError("the NFS volume provider attaches only in file-image mode, not in attach mode 0"))
		Expect(os.ReadDir(dir)).To(BeEmpty())
	})

	Describe("the mounts it refuses", func() {
		refuses := func(req prepareRequest, want string) {
			defaultImageOptions.fallocate = func(int, uint32, int64, int64) error { Fail("fallocate was called"); return nil }
			att, err := nfsProvider{}.Prepare(req)
			Expect(att).To(BeNil())
			Expect(err).To(MatchError(want))
			Expect(stepExitCode(err)).To(Equal(exitLaunchError))
			Expect(os.ReadDir(dir)).To(BeEmpty(), "a refused mount gets no image and no temp file")
		}
		quoted := func() string { return fmt.Sprintf("%q", dir) }

		It("refuses a kernel NFSv3 mount and asks for version 4.1 or 4.2", func() {
			refuses(request("nfs", "rw", "vers=3", "local_lock=none"),
				"volume path "+quoted()+` is a kernel NFSv3 mount ("nfs"); VM backends support only NFSv4, because NFSv3 locks depend on lockd and on options that a binding can turn off; bind the service with version 4.1 or 4.2`)
		})

		It("refuses a mapfs mount and says the binding needs no uid and gid for a VM app", func() {
			refuses(request("fuse.mapfs", "rw"),
				"volume path "+quoted()+` is a "fuse.mapfs" mount, which the NFS service makes when the binding sets uid and gid; mapfs keeps flock local to each cell, so two instances on two cells could write one image at once; bind the service without uid and gid for a VM app`)
		})

		DescribeTable("refuses a kernel NFSv4 mount whose locks stay on one cell",
			func(superOptions ...string) {
				refuses(request("nfs4", superOptions...),
					"volume path "+quoted()+` is an NFSv4 mount without local_lock=none, so its flock stays local to each cell and two instances on two cells could write one image at once; VM backends need an NFSv4 mount with local_lock=none`)
			},
			Entry("no lock option", "rw", "vers=4.2", "hard"),
			Entry("no options at all"),
			Entry("local_lock=all", "rw", "local_lock=all"),
			Entry("local_lock=flock", "rw", "local_lock=flock"),
			Entry("local_lock=posix", "rw", "local_lock=posix"),
		)

		It("refuses the mount even when the image already exists, and leaves it alone", func() {
			writeImage(img, 4<<20, []byte("keep"))
			_, err := nfsProvider{}.Prepare(request("fuse.mapfs", "rw"))
			Expect(err).To(HaveOccurred())
			Expect(os.ReadFile(img)).To(HavePrefix("keep"))
			Expect(lockedElsewhere(img)).To(BeFalse(), "a refused mount never takes the lock")
		})

		It("quotes a volume path that is long or holds odd bytes", func() {
			req := request("nfs", "rw")
			req.Mount.ContainerDir = "/da\nta" + strings.Repeat("x", 600)
			_, err := nfsProvider{}.Prepare(req)
			Expect(err).To(MatchError(ContainSubstring(`volume path "/da\nta`)))
			Expect(err.Error()).NotTo(ContainSubstring("\n"))
			Expect(len(err.Error())).To(BeNumerically("<", 900))
		})
	})
})
