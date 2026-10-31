package bundlerules_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/lager/v3/lagertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/opencontainers/runtime-spec/specs-go"

	"code.cloudfoundry.org/guardian/backend"
	spec "code.cloudfoundry.org/guardian/gardener/container-spec"
	"code.cloudfoundry.org/guardian/rundmc/bundlerules"
	"code.cloudfoundry.org/guardian/rundmc/goci"
)

type fakePDISource struct {
	mountID  uint64
	mountErr error
	file     bundlerules.PDIDescriptorFile
	readErr  error

	mu     sync.Mutex
	reads  int
	closed bool
}

func (s *fakePDISource) MountID() (uint64, error) { return s.mountID, s.mountErr }
func (s *fakePDISource) ReadDescriptor() (bundlerules.PDIDescriptorFile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	return s.file, s.readErr
}
func (s *fakePDISource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// fakePDIHost stands in for mknod, the probe open, and node removal. Its
// nodes are regular files that record the device and group they stand for.
type fakePDIHost struct {
	sources   map[string]*fakePDISource
	mknodErr  error
	probeErr  error
	removeErr error

	mu         sync.Mutex
	opened     []string
	mknods     []string
	probes     []string
	probeSizes []int64
	removes    []string
}

func (h *fakePDIHost) OpenSource(path string) (bundlerules.PDISource, error) {
	h.mu.Lock()
	h.opened = append(h.opened, path)
	h.mu.Unlock()
	src, ok := h.sources[path]
	if !ok {
		return nil, syscall.ENOENT
	}
	return src, nil
}

func (h *fakePDIHost) Mknod(path string, major, minor, gid uint32) error {
	h.mu.Lock()
	h.mknods = append(h.mknods, path)
	h.mu.Unlock()
	if h.mknodErr != nil {
		return h.mknodErr
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o660)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("mknod: %w", os.ErrExist)
		}
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "b %d:%d gid=%d", major, minor, gid)
	return err
}

func (h *fakePDIHost) Probe(path string, major, minor uint32, size int64) error {
	h.mu.Lock()
	h.probes = append(h.probes, path)
	h.probeSizes = append(h.probeSizes, size)
	h.mu.Unlock()
	return h.probeErr
}

func (h *fakePDIHost) RemoveNode(path string, major, minor uint32) error {
	h.mu.Lock()
	h.removes = append(h.removes, path)
	h.mu.Unlock()
	if h.removeErr != nil {
		return h.removeErr
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

const (
	pdiKVMGid    = 991
	pdiVolume    = "/var/vcap/data/volumes/bosh-disk/vol-1"
	pdiVolume2   = "/var/vcap/data/volumes/bosh-disk/vol-2"
	pdiHostsFile = "/var/vcap/data/garden/depot/handle-1/hosts"
	pdiUUID      = "bc20d783-6145-4623-86bb-35110042b24b"
	pdiDiskSize  = 2147483648
)

func pdiDescriptorData(major, minor int, size int64) []byte {
	return []byte(fmt.Sprintf("version=1\nmajor=%d\nminor=%d\nsize=%d\nuuid=%s\ndisk_name=bosh-disk-01\n", major, minor, size, pdiUUID))
}

func pdiRegularFile(data []byte) bundlerules.PDIDescriptorFile {
	return bundlerules.PDIDescriptorFile{Regular: true, UID: 0, Size: int64(len(data)), Data: data}
}

var _ = Describe("PDIDevices", func() {
	var (
		root         string
		sysfs        string
		mountInfo    []string
		host         *fakePDIHost
		volumes      *bundlerules.PDIDevices
		rule         bundlerules.ExecutionBackend
		artifactsDir string
		inputBndl    goci.Bndl
		desiredSpec  spec.DesiredContainerSpec
		newBndl      goci.Bndl
		applyErr     error
		logger       *lagertest.TestLogger
	)

	writeFile := func(path, content string) {
		Expect(os.MkdirAll(filepath.Dir(path), 0o755)).To(Succeed())
		Expect(os.WriteFile(path, []byte(content), 0o644)).To(Succeed())
	}

	// blockDevice adds a whole disk to the fake sysfs the way the kernel lays
	// it out: /sys/dev/block/MAJ:MIN links to the device's directory.
	blockDevice := func(name string, major, minor int, sectors uint64) string {
		dir := filepath.Join(sysfs, "devices", "virtual", "block", name)
		writeFile(filepath.Join(dir, "size"), fmt.Sprintf("%d\n", sectors))
		writeFile(filepath.Join(dir, "dev"), fmt.Sprintf("%d:%d\n", major, minor))
		Expect(os.MkdirAll(filepath.Join(dir, "queue"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(sysfs, "dev", "block"), 0o755)).To(Succeed())
		Expect(os.Symlink(dir, filepath.Join(sysfs, "dev", "block", fmt.Sprintf("%d:%d", major, minor)))).To(Succeed())
		return dir
	}

	partition := func(diskDir, name string, major, minor int) string {
		dir := filepath.Join(diskDir, name)
		writeFile(filepath.Join(dir, "partition"), "1\n")
		writeFile(filepath.Join(dir, "size"), "2048\n")
		writeFile(filepath.Join(dir, "dev"), fmt.Sprintf("%d:%d\n", major, minor))
		Expect(os.Symlink(dir, filepath.Join(sysfs, "dev", "block", fmt.Sprintf("%d:%d", major, minor)))).To(Succeed())
		return dir
	}

	nodePath := func(name string) string { return filepath.Join(volumes.NodeDir, name) }
	claimPath := func(name string) string { return filepath.Join(volumes.ClaimDir, name) }

	// readClaimFile returns a claim file as written: the tag, a newline, and
	// the handle.
	readClaimFile := func(name string) string {
		data, err := os.ReadFile(claimPath(name))
		Expect(err).NotTo(HaveOccurred())
		return string(data)
	}

	readClaim := func(name string) string {
		_, handle, _ := strings.Cut(readClaimFile(name), "\n")
		return handle
	}

	noNodesOrClaims := func() {
		nodes, _ := os.ReadDir(volumes.NodeDir)
		Expect(nodes).To(BeEmpty())
		claims, _ := os.ReadDir(volumes.ClaimDir)
		Expect(claims).To(BeEmpty())
	}

	BeforeEach(func() {
		root = GinkgoT().TempDir()
		sysfs = filepath.Join(root, "sys")
		logger = lagertest.NewTestLogger("pdi")

		mountInfo = []string{
			`22 1 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw`,
			`100 1 252:1 / /var/vcap/data rw,relatime shared:1 - ext4 /dev/sda3 rw`,
			`200 100 0:55 / /var/vcap/data/volumes/bosh-disk/vol-1 ro,nosuid,nodev,noexec,relatime shared:90 - tmpfs pdi:bosh-disk ro,size=16k,mode=755`,
		}

		diskDir := blockDevice("sdb", 8, 16, pdiDiskSize/512)
		partition(diskDir, "sdb1", 8, 17)
		blockDevice("sdc", 8, 32, pdiDiskSize/512)

		host = &fakePDIHost{sources: map[string]*fakePDISource{
			pdiVolume:    {mountID: 200, file: pdiRegularFile(pdiDescriptorData(8, 16, pdiDiskSize))},
			pdiHostsFile: {mountID: 100},
		}}

		volumes = &bundlerules.PDIDevices{
			KVMGid:        pdiKVMGid,
			NodeDir:       filepath.Join(root, "dev", "pdi"),
			ClaimDir:      filepath.Join(root, "run", "garden-pdi-claims"),
			SysfsDir:      sysfs,
			MountInfoPath: filepath.Join(root, "mountinfo"),
			Host:          host,
			Logger:        logger,
		}
		Expect(os.MkdirAll(filepath.Join(root, "dev"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(root, "run"), 0o755)).To(Succeed())

		artifactsDir = GinkgoT().TempDir()
		for _, rel := range bundlerules.DefaultVMArtifacts[backend.VMQemu] {
			writeFile(filepath.Join(artifactsDir, rel), "x")
		}
		rule = bundlerules.NewExecutionBackend(artifactsDir, "/var/vcap/packages/guardian/bin/vm-launch", pdiKVMGid)
		rule.BlockVolumes = volumes

		inputBndl = goci.Bundle().
			WithDeviceRestrictions([]specs.LinuxDeviceCgroup{{Allow: false, Access: "rwm"}}).
			WithCapabilities("CAP_CHOWN")

		desiredSpec = spec.DesiredContainerSpec{
			Handle:           "handle-1",
			ExecutionBackend: string(backend.VMQemu),
			BindMounts: []garden.BindMount{
				{SrcPath: pdiVolume, DstPath: "/var/vcap/data/disk", Mode: garden.BindMountModeRW, Origin: garden.BindMountOriginHost},
				{SrcPath: pdiHostsFile, DstPath: "/etc/hosts", Mode: garden.BindMountModeRW, Origin: garden.BindMountOriginHost},
			},
		}
	})

	JustBeforeEach(func() {
		writeFile(volumes.MountInfoPath, strings.Join(mountInfo, "\n")+"\n")
		newBndl, applyErr = rule.Apply(inputBndl, desiredSpec)
	})

	expectRefused := func(substring string) {
		GinkgoHelper()
		Expect(applyErr).To(MatchError(bundlerules.ErrBlockVolumeRefused))
		Expect(applyErr).To(MatchError(ContainSubstring(substring)))
		noNodesOrClaims()
	}

	Context("with a valid descriptor for an unused device", func() {
		It("adds exactly one block node after /dev/kvm", func() {
			Expect(applyErr).NotTo(HaveOccurred())
			devices := newBndl.Devices()
			Expect(devices).To(HaveLen(2))
			Expect(devices[0].Path).To(Equal("/dev/kvm"))

			mode := os.FileMode(0o660)
			uid, gid := uint32(0), uint32(pdiKVMGid)
			Expect(devices[1]).To(Equal(specs.LinuxDevice{
				Path:     nodePath("8-16"),
				Type:     "b",
				Major:    8,
				Minor:    16,
				FileMode: &mode,
				UID:      &uid,
				GID:      &gid,
			}))
		})

		It("adds exactly one read-write cgroup rule for b 8:16 after the kvm rule", func() {
			rules := newBndl.Resources().Devices
			Expect(rules).To(HaveLen(3))
			Expect(rules[1].Type).To(Equal("c"))

			major, minor := int64(8), int64(16)
			Expect(rules[2]).To(Equal(specs.LinuxDeviceCgroup{Allow: true, Type: "b", Major: &major, Minor: &minor, Access: "rw"}))
		})

		It("creates the host node for the kvm group, then probes it against the descriptor's size", func() {
			Expect(host.mknods).To(Equal([]string{nodePath("8-16")}))
			Expect(host.probes).To(Equal([]string{nodePath("8-16")}))
			Expect(host.probeSizes).To(Equal([]int64{pdiDiskSize}))
			data, err := os.ReadFile(nodePath("8-16"))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).To(Equal("b 8:16 gid=991"))
		})

		It("records the container as the device's owner under the Garden's empty tag", func() {
			Expect(readClaimFile("8-16")).To(Equal("\nhandle-1"))
		})

		It("reads the descriptor only for the descriptor bind mount, and closes every source", func() {
			Expect(host.opened).To(ConsistOf(pdiVolume, pdiHostsFile))
			Expect(host.sources[pdiVolume].reads).To(Equal(1))
			Expect(host.sources[pdiHostsFile].reads).To(BeZero())
			Expect(host.sources[pdiVolume].closed).To(BeTrue())
			Expect(host.sources[pdiHostsFile].closed).To(BeTrue())
		})

		It("adds no mount, because the descriptor's bind mount is the Mounts rule's", func() {
			Expect(newBndl.Mounts()).To(HaveLen(2))
		})

		It("logs the claim", func() {
			Expect(logger).To(gbytes.Say("pdi-device-claimed"))
		})

		When("the container is destroyed", func() {
			It("removes the node and the claim, and a second release is harmless", func() {
				Expect(volumes.Release(logger, "handle-1")).To(Succeed())
				Expect(host.removes).To(Equal([]string{nodePath("8-16")}))
				noNodesOrClaims()

				Expect(volumes.Release(logger, "handle-1")).To(Succeed())
			})

			It("leaves another container's device alone", func() {
				Expect(volumes.Release(logger, "handle-2")).To(Succeed())
				Expect(host.removes).To(BeEmpty())
				Expect(readClaim("8-16")).To(Equal("handle-1"))
				Expect(nodePath("8-16")).To(BeARegularFile())
			})

			When("the node cannot be removed", func() {
				It("keeps the claim, so the device stays refused and the destroy can be retried", func() {
					host.removeErr = errors.New("unlink failed")
					Expect(volumes.Release(logger, "handle-1")).To(MatchError(ContainSubstring("unlink failed")))
					Expect(readClaim("8-16")).To(Equal("handle-1"))
				})
			})

			When("a crash left the claim without its node", func() {
				It("removes the claim", func() {
					Expect(os.Remove(nodePath("8-16"))).To(Succeed())
					Expect(volumes.Release(logger, "handle-1")).To(Succeed())
					noNodesOrClaims()
				})
			})
		})

		When("Garden starts", func() {
			It("keeps the device of a container it still knows", func() {
				Expect(volumes.ReleaseUnknown(logger, []string{"handle-1", "other"})).To(Succeed())
				Expect(readClaim("8-16")).To(Equal("handle-1"))
			})

			It("releases the device of a container it does not know", func() {
				Expect(volumes.ReleaseUnknown(logger, []string{"other"})).To(Succeed())
				noNodesOrClaims()
			})

			It("skips files in the claim directory that are not claims", func() {
				writeFile(claimPath("README"), "handle-9")
				Expect(volumes.ReleaseUnknown(logger, nil)).To(Succeed())
				Expect(claimPath("README")).To(BeARegularFile())
				Expect(claimPath("8-16")).NotTo(BeAnExistingFile())
			})
		})

		When("a Garden with another tag shares the node and claim directories", func() {
			var other *bundlerules.PDIDevices
			var otherDesired spec.DesiredContainerSpec

			BeforeEach(func() {
				mountInfo = append(mountInfo, `201 100 0:56 / /var/vcap/data/volumes/bosh-disk/vol-2 ro,nosuid,nodev,noexec - tmpfs pdi:bosh-disk ro`)
				host.sources[pdiVolume2] = &fakePDISource{mountID: 201, file: pdiRegularFile(pdiDescriptorData(8, 32, pdiDiskSize))}
			})

			JustBeforeEach(func() {
				other = &bundlerules.PDIDevices{
					KVMGid:        pdiKVMGid,
					Tag:           "b2",
					NodeDir:       volumes.NodeDir,
					ClaimDir:      volumes.ClaimDir,
					SysfsDir:      sysfs,
					MountInfoPath: volumes.MountInfoPath,
					Host:          host,
					Logger:        logger,
				}
				otherDesired = spec.DesiredContainerSpec{
					Handle:           "handle-b",
					ExecutionBackend: string(backend.VMQemu),
					BindMounts:       []garden.BindMount{{SrcPath: pdiVolume2, DstPath: "/var/vcap/data/disk", Mode: garden.BindMountModeRW}},
				}
			})

			It("writes each Garden's tag into its claims", func() {
				_, err := other.Claim(otherDesired)
				Expect(err).NotTo(HaveOccurred())
				Expect(readClaimFile("8-16")).To(Equal("\nhandle-1"))
				Expect(readClaimFile("8-32")).To(Equal("b2\nhandle-b"))
			})

			It("leaves the other Garden's claims and nodes alone when it sweeps at start-up", func() {
				_, err := other.Claim(otherDesired)
				Expect(err).NotTo(HaveOccurred())

				Expect(other.ReleaseUnknown(logger, nil)).To(Succeed())
				Expect(readClaim("8-16")).To(Equal("handle-1"))
				Expect(nodePath("8-16")).To(BeARegularFile())
				Expect(claimPath("8-32")).NotTo(BeAnExistingFile())
				Expect(nodePath("8-32")).NotTo(BeAnExistingFile())

				_, err = other.Claim(otherDesired)
				Expect(err).NotTo(HaveOccurred())
				Expect(volumes.ReleaseUnknown(logger, nil)).To(Succeed())
				Expect(claimPath("8-16")).NotTo(BeAnExistingFile())
				Expect(readClaimFile("8-32")).To(Equal("b2\nhandle-b"))
				Expect(nodePath("8-32")).To(BeARegularFile())
			})

			It("does not release another Garden's container that has the same handle", func() {
				Expect(other.Release(logger, "handle-1")).To(Succeed())
				Expect(readClaim("8-16")).To(Equal("handle-1"))
				Expect(nodePath("8-16")).To(BeARegularFile())
			})

			It("refuses a device that the other Garden has claimed, and never removes that claim", func() {
				_, err := other.Claim(spec.DesiredContainerSpec{
					Handle:           "handle-b",
					ExecutionBackend: string(backend.VMQemu),
					BindMounts:       []garden.BindMount{{SrcPath: pdiVolume, DstPath: "/var/vcap/data/disk", Mode: garden.BindMountModeRW}},
				})
				Expect(err).To(MatchError(bundlerules.ErrBlockVolumeRefused))
				Expect(err).To(MatchError(ContainSubstring(`already given to container "handle-1" of the Garden tagged ""`)))

				Expect(other.Release(logger, "handle-b")).To(Succeed())
				Expect(readClaimFile("8-16")).To(Equal("\nhandle-1"))
				Expect(nodePath("8-16")).To(BeARegularFile())
			})
		})

		When("the claim directory holds entries that are not this container's", func() {
			It("logs a malformed claim and leaves it alone, and the destroy still succeeds", func() {
				writeFile(claimPath("8-99"), "no-newline-so-no-tag")
				writeFile(claimPath("8-98"), "\n")
				Expect(volumes.Release(logger, "handle-1")).To(Succeed())

				Expect(logger).To(gbytes.Say("pdi-claim-malformed"))
				Expect(claimPath("8-99")).To(BeARegularFile())
				Expect(claimPath("8-98")).To(BeARegularFile())
				Expect(claimPath("8-16")).NotTo(BeAnExistingFile())
			})

			It("leaves a claim with another tag alone", func() {
				writeFile(claimPath("8-99"), "zz\nhandle-1")
				Expect(volumes.Release(logger, "handle-1")).To(Succeed())
				Expect(claimPath("8-99")).To(BeARegularFile())
				Expect(claimPath("8-16")).NotTo(BeAnExistingFile())
			})

			It("does not fail when the claim directory cannot be listed", func() {
				Expect(os.RemoveAll(volumes.ClaimDir)).To(Succeed())
				writeFile(volumes.ClaimDir, "not a directory")
				Expect(volumes.Release(logger, "handle-2")).To(Succeed())
				Expect(logger).To(gbytes.Say("pdi-claim-dir-unreadable"))
			})

			It("still reports a failure to remove a node it owns", func() {
				writeFile(claimPath("8-99"), "garbage")
				host.removeErr = errors.New("unlink failed")
				Expect(volumes.Release(logger, "handle-1")).To(MatchError(ContainSubstring("unlink failed")))
			})
		})

		When("the node at the path is not the one Garden made", func() {
			It("logs it, leaves it in place, releases the claim, and lets the destroy succeed", func() {
				host.removeErr = fmt.Errorf("%w: it is not block device 8:16", bundlerules.ErrPDIForeignNode)
				Expect(volumes.Release(logger, "handle-1")).To(Succeed())
				Expect(logger).To(gbytes.Say("pdi-node-left-in-place"))
				Expect(claimPath("8-16")).NotTo(BeAnExistingFile())
			})
		})

		When("a release and a create overlap", func() {
			It("holds the new create back until the release has finished the node and the claim", func() {
				blocker := &blockingRemove{fakePDIHost: host, entered: make(chan struct{}), proceed: make(chan struct{})}
				volumes.Host = blocker

				released := make(chan error, 1)
				go func() { released <- volumes.Release(logger, "handle-1") }()
				Eventually(blocker.entered).Should(BeClosed())

				second := desiredSpec
				second.Handle = "handle-2"
				created := make(chan error, 1)
				go func() {
					_, err := volumes.Claim(second)
					created <- err
				}()
				Consistently(created, 100*time.Millisecond).ShouldNot(Receive())

				close(blocker.proceed)
				Eventually(released).Should(Receive(BeNil()))
				Eventually(created).Should(Receive(BeNil()))
				Expect(readClaim("8-16")).To(Equal("handle-2"))
				Expect(nodePath("8-16")).To(BeARegularFile())
			})

			It("never lets a stale release remove the device of a new owner", func() {
				var wg sync.WaitGroup
				var mu sync.Mutex
				var problems []string
				note := func(format string, args ...interface{}) {
					mu.Lock()
					defer mu.Unlock()
					problems = append(problems, fmt.Sprintf(format, args...))
				}

				for i := 0; i < 4; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for n := 0; n < 25; n++ {
							if err := volumes.Release(logger, "handle-1"); err != nil {
								note("release of handle-1: %s", err)
							}
							if err := volumes.ReleaseUnknown(logger, []string{"handle-1", "racer-0", "racer-1", "racer-2", "racer-3"}); err != nil {
								note("sweep: %s", err)
							}
						}
					}()
				}
				for i := 0; i < 4; i++ {
					handle := fmt.Sprintf("racer-%d", i)
					wg.Add(1)
					go func() {
						defer wg.Done()
						racer := desiredSpec
						racer.Handle = handle
						for n := 0; n < 25; n++ {
							if _, err := volumes.Claim(racer); err != nil {
								continue
							}
							if data, err := os.ReadFile(claimPath("8-16")); err != nil || string(data) != "\n"+handle {
								note("%s lost its claim: %q, %v", handle, data, err)
							}
							if _, err := os.Stat(nodePath("8-16")); err != nil {
								note("%s lost its node: %s", handle, err)
							}
							if err := volumes.Release(logger, handle); err != nil {
								note("release of %s: %s", handle, err)
							}
						}
					}()
				}
				wg.Wait()

				Expect(problems).To(BeEmpty())
			})
		})

		When("a second container names the same device", func() {
			It("refuses it and leaves the first container's node and claim in place", func() {
				Expect(applyErr).NotTo(HaveOccurred())
				second := desiredSpec
				second.Handle = "handle-2"
				_, err := rule.Apply(inputBndl, second)
				Expect(err).To(MatchError(bundlerules.ErrBlockVolumeRefused))
				Expect(err).To(MatchError(ContainSubstring(`already given to container "handle-1"`)))

				Expect(readClaim("8-16")).To(Equal("handle-1"))
				Expect(nodePath("8-16")).To(BeARegularFile())

				// The failed create's destroy must not take the first container's device.
				Expect(volumes.Release(logger, "handle-2")).To(Succeed())
				Expect(readClaim("8-16")).To(Equal("handle-1"))
			})
		})

		When("the device is a partition", func() {
			BeforeEach(func() {
				host.sources[pdiVolume].file = pdiRegularFile(pdiDescriptorData(8, 17, 2048*512))
			})

			It("gives it", func() {
				Expect(applyErr).NotTo(HaveOccurred())
				Expect(newBndl.Devices()[1].Path).To(Equal(nodePath("8-17")))
			})

			When("its whole disk is mounted", func() {
				BeforeEach(func() {
					mountInfo = append(mountInfo, `300 100 8:16 / /mnt rw - ext4 /dev/sdb rw`)
				})

				It("refuses the container", func() {
					expectRefused("device 8:16 (from " + pdiVolume + ") is mounted on the host at /mnt")
				})
			})
		})

		When("the bundle has no cgroup resources yet", func() {
			BeforeEach(func() {
				inputBndl.Spec.Linux.Resources = nil
			})

			It("creates the kvm and block rules", func() {
				Expect(newBndl.Resources().Devices).To(HaveLen(2))
			})
		})
	})

	Context("with two descriptors", func() {
		BeforeEach(func() {
			mountInfo = append(mountInfo, `201 100 0:56 / /var/vcap/data/volumes/bosh-disk/vol-2 ro,nosuid,nodev,noexec - tmpfs pdi:bosh-disk ro`)
			host.sources[pdiVolume2] = &fakePDISource{mountID: 201, file: pdiRegularFile(pdiDescriptorData(8, 32, pdiDiskSize))}
			desiredSpec.BindMounts = append(desiredSpec.BindMounts, garden.BindMount{SrcPath: pdiVolume2, DstPath: "/var/vcap/data/disk2", Mode: garden.BindMountModeRW})
		})

		It("gives both devices", func() {
			Expect(applyErr).NotTo(HaveOccurred())
			Expect(newBndl.Devices()).To(HaveLen(3))
			Expect(readClaim("8-16")).To(Equal("handle-1"))
			Expect(readClaim("8-32")).To(Equal("handle-1"))
		})

		When("the second device fails the exclusive open", func() {
			BeforeEach(func() {
				probes := 0
				rule.BlockVolumes.Host = &probeOnce{fakePDIHost: host, fail: func() bool { probes++; return probes == 2 }}
			})

			It("releases the first device it had already claimed", func() {
				expectRefused("device 8:32")
				Expect(host.removes).To(ContainElements(nodePath("8-16"), nodePath("8-32")))
			})
		})

		When("both name the same device", func() {
			BeforeEach(func() {
				host.sources[pdiVolume2].file = pdiRegularFile(pdiDescriptorData(8, 16, pdiDiskSize))
			})

			It("refuses the container before creating anything", func() {
				expectRefused("both name device 8:16")
				Expect(host.mknods).To(BeEmpty())
			})
		})
	})

	Context("when the device fails a host check", func() {
		When("the size in sysfs differs from the descriptor", func() {
			BeforeEach(func() {
				host.sources[pdiVolume].file = pdiRegularFile(pdiDescriptorData(8, 16, pdiDiskSize-512))
			})

			It("refuses the container", func() {
				expectRefused("device 8:16 is 2147483648 bytes, and the descriptor in " + pdiVolume + " says 2147483136")
				Expect(host.mknods).To(BeEmpty())
			})
		})

		When("the device is not on this host", func() {
			BeforeEach(func() {
				host.sources[pdiVolume].file = pdiRegularFile(pdiDescriptorData(8, 48, pdiDiskSize))
			})

			It("refuses the container", func() {
				expectRefused("device 8:48 named by " + pdiVolume + " is not a block device on this host")
			})
		})

		When("the device is mounted on the host", func() {
			BeforeEach(func() {
				mountInfo = append(mountInfo, `300 100 8:16 / /var/vcap/store rw,relatime - ext4 /dev/sdb rw`)
			})

			It("refuses the container", func() {
				expectRefused("device 8:16 (from " + pdiVolume + ") is mounted on the host at /var/vcap/store")
				Expect(host.mknods).To(BeEmpty())
			})
		})

		When("a partition of the device is mounted on the host", func() {
			BeforeEach(func() {
				mountInfo = append(mountInfo, `300 100 8:17 / /mnt\040disk rw,relatime - ext4 /dev/sdb1 rw`)
			})

			It("refuses the container", func() {
				expectRefused("device 8:17 (from " + pdiVolume + ") is mounted on the host at /mnt disk")
			})
		})

		When("the exclusive open fails, as it does while an app holds the device", func() {
			BeforeEach(func() {
				host.probeErr = fmt.Errorf("exclusive open: %w", syscall.EBUSY)
			})

			It("refuses the container and removes the node and claim it made", func() {
				expectRefused("device 8:16 named by " + pdiVolume + " failed the exclusive probe")
				Expect(applyErr).To(MatchError(ContainSubstring("device or resource busy")))
				Expect(host.removes).To(Equal([]string{nodePath("8-16")}))
			})
		})

		When("a node Garden did not create is already at the path", func() {
			BeforeEach(func() {
				writeFile(filepath.Join(root, "dev", "pdi", "8-16"), "operator node")
			})

			It("refuses the container and leaves that node alone", func() {
				Expect(applyErr).To(MatchError(bundlerules.ErrBlockVolumeRefused))
				Expect(applyErr).To(MatchError(ContainSubstring("already exists on the host, and Garden did not create it")))
				data, err := os.ReadFile(nodePath("8-16"))
				Expect(err).NotTo(HaveOccurred())
				Expect(string(data)).To(Equal("operator node"))
				claims, _ := os.ReadDir(volumes.ClaimDir)
				Expect(claims).To(BeEmpty())
				Expect(host.removes).To(BeEmpty())
			})
		})

		When("mknod fails", func() {
			BeforeEach(func() {
				host.mknodErr = errors.New("mknod: operation not permitted")
			})

			It("refuses the container and removes its claim", func() {
				expectRefused("operation not permitted")
			})
		})
	})

	Context("when the descriptor is not acceptable", func() {
		setFile := func(file bundlerules.PDIDescriptorFile) {
			host.sources[pdiVolume].file = file
		}

		When("it is a symbolic link", func() {
			BeforeEach(func() {
				host.sources[pdiVolume].readErr = errors.New("device is a symbolic link")
			})

			It("refuses the container", func() {
				expectRefused("reading the descriptor in " + pdiVolume + ": device is a symbolic link")
			})
		})

		When("it is not a regular file", func() {
			BeforeEach(func() {
				setFile(bundlerules.PDIDescriptorFile{Regular: false})
			})

			It("refuses the container", func() {
				expectRefused("is not a regular file")
			})
		})

		When("it is not owned by root", func() {
			BeforeEach(func() {
				file := pdiRegularFile(pdiDescriptorData(8, 16, pdiDiskSize))
				file.UID = 2000
				setFile(file)
			})

			It("refuses the container", func() {
				expectRefused("is owned by uid 2000, not 0")
			})
		})

		When("it is 4 KiB or more", func() {
			BeforeEach(func() {
				data := append(pdiDescriptorData(8, 16, pdiDiskSize), []byte(strings.Repeat("x", 4096))...)
				setFile(pdiRegularFile(data[:4097]))
			})

			It("refuses the container", func() {
				expectRefused("must be shorter than 4096")
			})
		})

		When("fstat reports a size other than what was read", func() {
			BeforeEach(func() {
				file := pdiRegularFile(pdiDescriptorData(8, 16, pdiDiskSize))
				file.Size++
				setFile(file)
			})

			It("refuses the container", func() {
				expectRefused("changed while it was read")
			})
		})

		for _, tc := range []struct{ name, content string }{
			{"is empty", ""},
			{"lacks a key", "version=1\nmajor=8\nminor=16\nsize=2147483648\nuuid=" + pdiUUID + "\n"},
			{"repeats a key", string(pdiDescriptorData(8, 16, pdiDiskSize)) + "major=8\n"},
			{"has an unknown key", string(pdiDescriptorData(8, 16, pdiDiskSize)) + "extra=1\n"},
			{"has a blank line", string(pdiDescriptorData(8, 16, pdiDiskSize)) + "\n"},
			{"has a carriage return", strings.Replace(string(pdiDescriptorData(8, 16, pdiDiskSize)), "major=8\n", "major=8\r\n", 1)},
			{"has a leading zero", strings.Replace(string(pdiDescriptorData(8, 16, pdiDiskSize)), "minor=16", "minor=016", 1)},
			{"has a signed number", strings.Replace(string(pdiDescriptorData(8, 16, pdiDiskSize)), "major=8", "major=+8", 1)},
			{"has a padded number", strings.Replace(string(pdiDescriptorData(8, 16, pdiDiskSize)), "major=8", "major= 8", 1)},
			{"has a major over 32 bits", strings.Replace(string(pdiDescriptorData(8, 16, pdiDiskSize)), "major=8", "major=4294967296", 1)},
			{"has a zero size", strings.Replace(string(pdiDescriptorData(8, 16, pdiDiskSize)), "size=2147483648", "size=0", 1)},
			{"has an upper-case uuid", strings.Replace(string(pdiDescriptorData(8, 16, pdiDiskSize)), pdiUUID, strings.ToUpper(pdiUUID), 1)},
			{"has an empty disk name", strings.Replace(string(pdiDescriptorData(8, 16, pdiDiskSize)), "disk_name=bosh-disk-01", "disk_name=", 1)},
			{"has another version", strings.Replace(string(pdiDescriptorData(8, 16, pdiDiskSize)), "version=1", "version=2", 1)},
			{"lacks the final newline", strings.TrimSuffix(string(pdiDescriptorData(8, 16, pdiDiskSize)), "\n")},
			{"is not UTF-8", string(pdiDescriptorData(8, 16, pdiDiskSize)[:10]) + "\xff\n"},
		} {
			tc := tc
			When("it "+tc.name, func() {
				BeforeEach(func() {
					setFile(pdiRegularFile([]byte(tc.content)))
				})

				It("refuses the container", func() {
					expectRefused("the descriptor in " + pdiVolume + ": descriptor")
					Expect(host.mknods).To(BeEmpty())
				})
			})
		}

		It("accepts the keys in any order", func() {
			Expect(applyErr).NotTo(HaveOccurred())
			Expect(volumes.Release(logger, "handle-1")).To(Succeed())

			setFile(pdiRegularFile([]byte("disk_name=d=1\nuuid=" + pdiUUID + "\nsize=2147483648\nminor=16\nmajor=8\nversion=1\n")))
			_, err := rule.Apply(inputBndl, desiredSpec)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("when the source mount is not a well-formed descriptor tmpfs", func() {
		When("the tmpfs is writable", func() {
			BeforeEach(func() {
				mountInfo[2] = `200 100 0:55 / /var/vcap/data/volumes/bosh-disk/vol-1 rw,nosuid,nodev,noexec - tmpfs pdi:bosh-disk rw`
			})

			It("refuses the container", func() {
				expectRefused("is a descriptor tmpfs from pdi:bosh-disk that is not read-only")
			})
		})

		When("the tmpfs is read-only for this mount but read-write in its super options", func() {
			BeforeEach(func() {
				mountInfo[2] = `200 100 0:55 / /var/vcap/data/volumes/bosh-disk/vol-1 ro,nosuid,nodev,noexec - tmpfs pdi:bosh-disk rw,size=16k`
			})

			It("refuses the container, because another mount of the tmpfs can write", func() {
				expectRefused("is a descriptor tmpfs from pdi:bosh-disk that is not read-only")
			})
		})

		When("the tmpfs is read-only in its super options but its mount here is read-write, as a copy that propagated before the remount is", func() {
			BeforeEach(func() {
				mountInfo[2] = `200 100 0:55 / /var/vcap/data/volumes/bosh-disk/vol-1 rw,nosuid,nodev,noexec - tmpfs pdi:bosh-disk ro,size=16k`
			})

			It("gives the device", func() {
				Expect(applyErr).NotTo(HaveOccurred())
				Expect(newBndl.Devices()).To(HaveLen(2))
			})
		})

		When("a filesystem other than tmpfs has a pdi: source, as a user's FUSE mount can", func() {
			BeforeEach(func() {
				mountInfo[2] = `200 100 0:55 / /var/vcap/data/volumes/bosh-disk/vol-1 ro,nosuid,nodev - fuse.sshfs pdi:bosh-disk ro`
			})

			It("refuses the container without reading the descriptor", func() {
				expectRefused("is a fuse.sshfs mount from pdi:bosh-disk, and a descriptor must be on tmpfs")
				Expect(host.sources[pdiVolume].reads).To(BeZero())
			})
		})

		When("the tmpfs source does not start with pdi:", func() {
			BeforeEach(func() {
				mountInfo[2] = `200 100 0:55 / /var/vcap/data/volumes/bosh-disk/vol-1 ro - tmpfs tmpfs ro`
			})

			It("treats the bind mount as an ordinary one", func() {
				Expect(applyErr).NotTo(HaveOccurred())
				Expect(newBndl.Devices()).To(HaveLen(1))
				Expect(host.sources[pdiVolume].reads).To(BeZero())
				noNodesOrClaims()
			})
		})

		When("the source's mount is not in the mount table", func() {
			BeforeEach(func() {
				host.sources[pdiVolume].mountID = 999
			})

			It("refuses the container", func() {
				expectRefused("mount 999 of " + pdiVolume + " is not in")
			})
		})

		When("the source cannot be opened", func() {
			BeforeEach(func() {
				delete(host.sources, pdiVolume)
			})

			It("refuses the container", func() {
				expectRefused("opening bind mount source " + pdiVolume)
			})
		})

		When("the mount ID cannot be read", func() {
			BeforeEach(func() {
				host.sources[pdiVolume].mountErr = errors.New("statx: function not implemented")
			})

			It("refuses the container", func() {
				expectRefused("statx: function not implemented")
			})
		})

		When("the mount table has a line it cannot read", func() {
			BeforeEach(func() {
				mountInfo = append(mountInfo, "garbage")
			})

			It("refuses the container", func() {
				expectRefused("is not a mountinfo line")
			})
		})
	})

	When("the descriptor's bind mount is read-only", func() {
		BeforeEach(func() {
			desiredSpec.BindMounts[0].Mode = garden.BindMountModeRO
		})

		It("refuses the container, because block mode needs the device read-write", func() {
			expectRefused("bind mount " + pdiVolume + " is a device descriptor and is read-only, and block mode needs it read-write")
			Expect(host.mknods).To(BeEmpty())
		})
	})

	When("a bind mount that is not a descriptor is read-only", func() {
		BeforeEach(func() {
			desiredSpec.BindMounts[1].Mode = garden.BindMountModeRO
		})

		It("gives the device", func() {
			Expect(applyErr).NotTo(HaveOccurred())
		})
	})

	When("the container has no bind mounts", func() {
		BeforeEach(func() {
			desiredSpec.BindMounts = nil
		})

		It("does not read the mount table or touch the host", func() {
			Expect(applyErr).NotTo(HaveOccurred())
			Expect(host.opened).To(BeEmpty())
			Expect(newBndl.Devices()).To(HaveLen(1))
		})
	})

	When("no bind mount is a descriptor", func() {
		BeforeEach(func() {
			desiredSpec.BindMounts = desiredSpec.BindMounts[1:]
		})

		It("creates nothing", func() {
			Expect(applyErr).NotTo(HaveOccurred())
			Expect(newBndl.Devices()).To(HaveLen(1))
			Expect(host.mknods).To(BeEmpty())
			_, err := os.Stat(volumes.NodeDir)
			Expect(err).To(MatchError(os.ErrNotExist))
		})
	})

	When("the node directory is a link", func() {
		BeforeEach(func() {
			Expect(os.Symlink(root, filepath.Join(root, "dev", "pdi"))).To(Succeed())
		})

		It("refuses the container", func() {
			Expect(applyErr).To(MatchError(bundlerules.ErrBlockVolumeRefused))
			Expect(applyErr).To(MatchError(ContainSubstring("not a directory")))
			Expect(host.mknods).To(BeEmpty())
		})
	})

	for _, kind := range []string{"", string(backend.OCIRunc), string(backend.OCIGvisor)} {
		kind := kind
		When(`the backend is "`+kind+`"`, func() {
			BeforeEach(func() {
				desiredSpec.ExecutionBackend = kind
			})

			It("leaves the descriptor bind mount as a plain directory and never looks at it", func() {
				Expect(applyErr).NotTo(HaveOccurred())
				Expect(newBndl.Devices()).To(BeEmpty())
				Expect(newBndl.Resources().Devices).To(Equal([]specs.LinuxDeviceCgroup{{Allow: false, Access: "rwm"}}))
				Expect(host.opened).To(BeEmpty())
				noNodesOrClaims()
			})
		})
	}

	When("the backend is vm-firecracker", func() {
		BeforeEach(func() {
			desiredSpec.ExecutionBackend = string(backend.VMFirecracker)
			for _, rel := range bundlerules.DefaultVMArtifacts[backend.VMFirecracker] {
				writeFile(filepath.Join(artifactsDir, rel), "x")
			}
		})

		It("adds the block node after /dev/kvm and /dev/net/tun", func() {
			Expect(applyErr).NotTo(HaveOccurred())
			devices := newBndl.Devices()
			Expect(devices).To(HaveLen(3))
			Expect(devices[2].Path).To(Equal(nodePath("8-16")))
			Expect(devices[2].Type).To(Equal("b"))
			Expect(newBndl.Resources().Devices[3].Access).To(Equal("rw"))
		})
	})

	When("an earlier VM check fails", func() {
		BeforeEach(func() {
			Expect(os.Remove(filepath.Join(artifactsDir, "busybox"))).To(Succeed())
		})

		It("claims nothing", func() {
			Expect(applyErr).To(MatchError(backend.ErrBackendUnavailable))
			Expect(host.opened).To(BeEmpty())
			noNodesOrClaims()
		})
	})
})

// blockingRemove wraps the fake host so that RemoveNode announces itself and
// then waits, which holds a release half done.
type blockingRemove struct {
	*fakePDIHost
	entered chan struct{}
	proceed chan struct{}
	once    sync.Once
}

func (b *blockingRemove) RemoveNode(path string, major, minor uint32) error {
	b.once.Do(func() { close(b.entered) })
	<-b.proceed
	return b.fakePDIHost.RemoveNode(path, major, minor)
}

// probeOnce wraps the fake host so that only the calls fail() picks fail the
// probe.
type probeOnce struct {
	*fakePDIHost
	fail func() bool
}

func (p *probeOnce) Probe(path string, major, minor uint32, size int64) error {
	p.mu.Lock()
	p.probes = append(p.probes, path)
	p.mu.Unlock()
	if p.fail() {
		return fmt.Errorf("exclusive open: %w", syscall.EBUSY)
	}
	return nil
}
