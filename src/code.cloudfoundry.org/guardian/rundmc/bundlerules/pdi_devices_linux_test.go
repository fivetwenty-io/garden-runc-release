package bundlerules_test

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"

	"code.cloudfoundry.org/guardian/rundmc/bundlerules"
)

var _ = Describe("LinuxPDIHost", func() {
	var (
		host bundlerules.LinuxPDIHost
		dir  string
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
	})

	readDescriptor := func(path string) (bundlerules.PDIDescriptorFile, error) {
		src, err := host.OpenSource(path)
		Expect(err).NotTo(HaveOccurred())
		defer src.Close()
		return src.ReadDescriptor()
	}

	Describe("OpenSource", func() {
		It("reports the mount ID that mountinfo lists for the source", func() {
			src, err := host.OpenSource(dir)
			Expect(err).NotTo(HaveOccurred())
			defer src.Close()

			id, err := src.MountID()
			Expect(err).NotTo(HaveOccurred())

			f, err := os.Open("/proc/self/mountinfo")
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			var ids []uint64
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				v, err := strconv.ParseUint(strings.Fields(scanner.Text())[0], 10, 64)
				Expect(err).NotTo(HaveOccurred())
				ids = append(ids, v)
			}
			Expect(ids).To(ContainElement(id))
		})

		It("fails for a missing source", func() {
			_, err := host.OpenSource(filepath.Join(dir, "missing"))
			Expect(errors.Is(err, syscall.ENOENT)).To(BeTrue())
		})
	})

	Describe("ReadDescriptor", func() {
		It("reads a regular file with its owner and size", func() {
			Expect(os.WriteFile(filepath.Join(dir, "device"), []byte("version=1\n"), 0o444)).To(Succeed())

			file, err := readDescriptor(dir)
			Expect(err).NotTo(HaveOccurred())
			Expect(file.Regular).To(BeTrue())
			Expect(file.UID).To(BeEquivalentTo(os.Getuid()))
			Expect(file.Size).To(BeEquivalentTo(10))
			Expect(file.Data).To(Equal([]byte("version=1\n")))
		})

		It("reads at most one byte past the size limit", func() {
			Expect(os.WriteFile(filepath.Join(dir, "device"), make([]byte, 10000), 0o444)).To(Succeed())

			file, err := readDescriptor(dir)
			Expect(err).NotTo(HaveOccurred())
			Expect(file.Size).To(BeEquivalentTo(10000))
			Expect(file.Data).To(HaveLen(bundlerules.PDIDescriptorSizeLimit + 1))
		})

		It("refuses a symbolic link, even to a regular file", func() {
			Expect(os.WriteFile(filepath.Join(dir, "target"), []byte("version=1\n"), 0o444)).To(Succeed())
			Expect(os.Symlink("target", filepath.Join(dir, "device"))).To(Succeed())

			_, err := readDescriptor(dir)
			Expect(err).To(MatchError(ContainSubstring("device is a symbolic link")))
		})

		It("returns a FIFO's type without reading or blocking on it", func() {
			Expect(unix.Mkfifo(filepath.Join(dir, "device"), 0o444)).To(Succeed())

			file, err := readDescriptor(dir)
			Expect(err).NotTo(HaveOccurred())
			Expect(file.Regular).To(BeFalse())
			Expect(file.Data).To(BeEmpty())
		})

		It("fails when there is no descriptor", func() {
			_, err := readDescriptor(dir)
			Expect(err).To(MatchError(ContainSubstring("opening device")))
		})

		It("fails when the source is a file rather than a directory", func() {
			path := filepath.Join(dir, "hosts")
			Expect(os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o644)).To(Succeed())

			_, err := readDescriptor(path)
			Expect(errors.Is(err, syscall.ENOTDIR)).To(BeTrue())
		})
	})

	Describe("block nodes", func() {
		var node string

		BeforeEach(func() {
			node = filepath.Join(dir, "7-250")
		})

		It("probes and refuses a node that is not a block device", func() {
			Expect(os.WriteFile(node, nil, 0o600)).To(Succeed())
			Expect(host.Probe(node, 7, 250, 4096)).To(MatchError(ContainSubstring("not block device 7:250")))
		})

		It("fails the probe for a missing node", func() {
			Expect(host.Probe(node, 7, 250, 4096)).To(MatchError(ContainSubstring("exclusive open")))
		})

		It("does not remove something that is not the named block device", func() {
			Expect(os.WriteFile(node, nil, 0o600)).To(Succeed())
			err := host.RemoveNode(node, 7, 250)
			Expect(err).To(MatchError(ContainSubstring("not block device 7:250")))
			Expect(errors.Is(err, bundlerules.ErrPDIForeignNode)).To(BeTrue())
			Expect(node).To(BeARegularFile())
		})

		It("treats a missing node as removed", func() {
			Expect(host.RemoveNode(node, 7, 250)).To(Succeed())
		})

		When("running as root, which mknod needs", func() {
			BeforeEach(func() {
				if os.Getuid() != 0 {
					Skip("mknod of a block device needs root")
				}
			})

			It("creates a root:gid 0660 node whatever the umask, refuses to replace it, and removes only the named device", func() {
				old := unix.Umask(0o077)
				defer unix.Umask(old)

				Expect(host.Mknod(node, 7, 250, 991)).To(Succeed())

				var st unix.Stat_t
				Expect(unix.Lstat(node, &st)).To(Succeed())
				Expect(st.Mode & unix.S_IFMT).To(BeEquivalentTo(unix.S_IFBLK))
				Expect(st.Mode & 0o7777).To(BeEquivalentTo(0o660))
				Expect(st.Rdev).To(Equal(unix.Mkdev(7, 250)))
				Expect(st.Uid).To(BeZero())
				Expect(st.Gid).To(BeEquivalentTo(991))

				Expect(errors.Is(host.Mknod(node, 7, 250, 991), os.ErrExist)).To(BeTrue())

				Expect(errors.Is(host.RemoveNode(node, 7, 251), bundlerules.ErrPDIForeignNode)).To(BeTrue())
				Expect(unix.Lstat(node, &st)).To(Succeed())

				Expect(host.RemoveNode(node, 7, 250)).To(Succeed())
				Expect(unix.Lstat(node, &st)).To(MatchError(unix.ENOENT))
				Expect(host.RemoveNode(node, 7, 250)).To(Succeed())
			})

			It("creates no node in a directory that is missing", func() {
				Expect(host.Mknod(filepath.Join(dir, "missing", "7-250"), 7, 250, 991)).To(MatchError(ContainSubstring("mknod")))
			})

			It("removes the node it made when it cannot finish it", func() {
				// A gid of all ones tells chown to change nothing, so the node keeps its
				// own group, the final check fails, and mknod has already made the node.
				err := host.Mknod(node, 7, 250, 0xFFFFFFFF)
				Expect(err).To(MatchError(ContainSubstring("the node is mode")))

				var st unix.Stat_t
				Expect(unix.Lstat(node, &st)).To(MatchError(unix.ENOENT))
			})
		})
	})

	Describe("publishing a claim", func() {
		It("creates the claim with its content and mode 0600, and never replaces one", func() {
			old := unix.Umask(0o077)
			defer unix.Umask(old)

			Expect(bundlerules.PublishPDIClaim(dir, "8-16", []byte("g\nh\n7\n"))).To(Succeed())
			data, err := os.ReadFile(filepath.Join(dir, "8-16"))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).To(Equal("g\nh\n7\n"))
			info, err := os.Stat(filepath.Join(dir, "8-16"))
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))

			err = bundlerules.PublishPDIClaim(dir, "8-16", []byte("other\n"))
			Expect(errors.Is(err, os.ErrExist)).To(BeTrue(), "%v", err)
			data, err = os.ReadFile(filepath.Join(dir, "8-16"))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).To(Equal("g\nh\n7\n"))
		})

		It("leaves no other file in the directory", func() {
			Expect(bundlerules.PublishPDIClaim(dir, "8-16", []byte("x\n"))).To(Succeed())
			Expect(bundlerules.PublishPDIClaim(dir, "8-16", []byte("y\n"))).NotTo(Succeed())
			entries, err := os.ReadDir(dir)
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(1))
		})

		It("lets a reader see either no claim or the whole claim, never part of it", func() {
			content := []byte(strings.Repeat("h", 60000) + "\n")
			claim := filepath.Join(dir, "8-16")
			done := make(chan struct{})
			exited := make(chan struct{})
			problems := make(chan string, 1)
			go func() {
				defer GinkgoRecover()
				defer close(exited)
				for {
					select {
					case <-done:
						return
					default:
					}
					data, err := os.ReadFile(claim)
					if err == nil && len(data) != len(content) {
						select {
						case problems <- "read " + strconv.Itoa(len(data)) + " bytes":
						default:
						}
					}
				}
			}()
			for i := 0; i < 200; i++ {
				Expect(bundlerules.PublishPDIClaim(dir, "8-16", content)).To(Succeed())
				Expect(os.Remove(claim)).To(Succeed())
			}
			close(done)
			Eventually(exited).Should(BeClosed())
			Expect(problems).NotTo(Receive())
		})

		It("fails for a directory that is missing", func() {
			Expect(bundlerules.PublishPDIClaim(filepath.Join(dir, "missing"), "8-16", []byte("x\n"))).To(MatchError(ContainSubstring("creating a claim in")))
		})
	})

	Describe("NewPDILeftoverReleaser", func() {
		It("returns nothing to release when no claim directory exists", func() {
			if _, err := os.Lstat(bundlerules.DefaultPDIClaimDir); err == nil {
				Skip(bundlerules.DefaultPDIClaimDir + " exists on this host")
			}
			releaser, err := bundlerules.NewPDILeftoverReleaser(nil, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(releaser).To(BeNil())
		})

		It("refuses a tag that holds a newline", func() {
			_, err := bundlerules.NewPDILeftoverReleaser(nil, "a\nb")
			Expect(err).To(MatchError(ContainSubstring("newline")))
		})
	})

	It("NewPDIDevices waits for a held device as long as vm-launch waits for a busy one", func() {
		volumes, err := bundlerules.NewPDIDevices(nil, 991, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(volumes.ClaimWait).To(Equal(30 * time.Second))
	})

	Describe("Probe against a loop device", func() {
		const size = 8 << 20

		var node string

		BeforeEach(func() {
			if os.Getuid() != 0 {
				Skip("a loop device needs root")
			}
			ctl, err := unix.Open("/dev/loop-control", unix.O_RDWR|unix.O_CLOEXEC, 0)
			if err != nil {
				Skip("no /dev/loop-control: " + err.Error())
			}
			defer unix.Close(ctl)
			n, err := unix.IoctlRetInt(ctl, unix.LOOP_CTL_GET_FREE)
			Expect(err).NotTo(HaveOccurred())

			backing := filepath.Join(dir, "disk.img")
			Expect(os.WriteFile(backing, nil, 0o600)).To(Succeed())
			Expect(os.Truncate(backing, size)).To(Succeed())
			backingFd, err := unix.Open(backing, unix.O_RDWR|unix.O_CLOEXEC, 0)
			Expect(err).NotTo(HaveOccurred())
			defer unix.Close(backingFd)

			node = filepath.Join(dir, "loop-node")
			Expect(host.Mknod(node, 7, uint32(n), 0)).To(Succeed())
			loopFd, err := unix.Open(node, unix.O_RDWR|unix.O_CLOEXEC, 0)
			Expect(err).NotTo(HaveOccurred())
			if err := unix.IoctlSetInt(loopFd, unix.LOOP_SET_FD, backingFd); err != nil {
				unix.Close(loopFd)
				Skip("cannot attach a loop device: " + err.Error())
			}
			DeferCleanup(func() {
				Expect(unix.IoctlSetInt(loopFd, unix.LOOP_CLR_FD, 0)).To(Succeed())
				Expect(unix.Close(loopFd)).To(Succeed())
			})
		})

		It("accepts the device at the descriptor's size", func() {
			Expect(host.Probe(node, 7, uint32(loopMinor(node)), size)).To(Succeed())
		})

		It("refuses a device whose size differs from the descriptor's", func() {
			err := host.Probe(node, 7, uint32(loopMinor(node)), size-512)
			Expect(err).To(MatchError(ContainSubstring("the device is 8388608 bytes, and the descriptor says 8388096")))
		})

		It("refuses the device while another exclusive opener holds it, and accepts it again afterwards", func() {
			held, err := unix.Open(node, unix.O_RDWR|unix.O_EXCL|unix.O_CLOEXEC, 0)
			Expect(err).NotTo(HaveOccurred())

			err = host.Probe(node, 7, uint32(loopMinor(node)), size)
			Expect(errors.Is(err, unix.EBUSY)).To(BeTrue(), "got %v", err)

			Expect(unix.Close(held)).To(Succeed())
			Expect(host.Probe(node, 7, uint32(loopMinor(node)), size)).To(Succeed())
		})

		It("refuses the node when it is a different device number", func() {
			Expect(host.Probe(node, 7, uint32(loopMinor(node))+1, size)).To(MatchError(ContainSubstring("is not block device")))
		})
	})
})

// loopMinor returns the minor number of the block node at path.
func loopMinor(path string) uint32 {
	var st unix.Stat_t
	Expect(unix.Lstat(path, &st)).To(Succeed())
	return unix.Minor(st.Rdev)
}
