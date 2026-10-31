//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The hypervisor command lines and Firecracker configuration without a
// volume, for the artifacts below, with the initramfs passed as file
// descriptor 3, as it is without a volume. Apart from the initramfs path,
// QEMU's dump-guest-core=off, and a task's NIC, they are those of cf68f18,
// from before volume support. Every guest has a NIC, so goldenQEMUBase is a
// full command line only with a netdev after it, and goldenFCNet is the
// configuration of a task and of an LRP alike.
const (
	goldenArt    = "/opt/garden-vm/artifacts"
	goldenInitrd = "/proc/self/fd/3"
	// goldenVolumeInitrd is the initramfs path with a volume, whose image
	// keeps file descriptor 3.
	goldenVolumeInitrd = "/proc/self/fd/4"
	// goldenMemMiB is the guest size the golden strings embed, the floor
	// every guest had before its size came from MEMORY_LIMIT.
	goldenMemMiB = 128

	goldenFCNet = `{"boot-source":{"kernel_image_path":"/opt/garden-vm/artifacts/kernel/vmlinux","initrd_path":"/proc/self/fd/3","boot_args":"console=ttyS0 reboot=k panic=1 rdinit=/init quiet"},"drives":[],"machine-config":{"vcpu_count":1,"mem_size_mib":128},"network-interfaces":[{"iface_id":"eth0","guest_mac":"06:00:a9:fe:64:02","host_dev_name":"tap0"}]}`

	// goldenFCDrive is the drives entry a volume adds.
	goldenFCDrive = `"drives":[{"drive_id":"vol0","path_on_host":"/proc/self/fd/3","is_root_device":false,"is_read_only":false,"cache_type":"Writeback","io_engine":"Sync"}]`

	// goldenFCRootDrive is the drive entry of the guest root image, on file
	// descriptor 4 without a volume. It is the only entry with discard, and
	// discard takes the Sync engine.
	goldenFCRootDrive = `{"drive_id":"root0","path_on_host":"/proc/self/fd/4","is_root_device":false,"is_read_only":false,"cache_type":"Unsafe","io_engine":"Sync","discard":true}`
)

var (
	goldenQEMUBase = []string{
		"/opt/garden-vm/artifacts/qemu/ld-linux-x86-64.so.2", "--library-path", "/opt/garden-vm/artifacts/qemu/lib",
		"/opt/garden-vm/artifacts/qemu/qemu-system-x86_64-microvm", "-L", "/opt/garden-vm/artifacts/qemu/share",
		"-M", "microvm,accel=kvm,dump-guest-core=off", "-cpu", "host", "-smp", "1", "-m", "128",
		"-nodefaults", "-no-user-config", "-nographic", "-serial", "stdio", "-no-reboot",
		"-kernel", "/opt/garden-vm/artifacts/kernel/bzImage", "-initrd", "/proc/self/fd/3",
		"-append", "console=ttyS0 reboot=t panic=-1 rdinit=/init pci=off quiet",
	}
	// goldenQEMUNetdev is the NIC of an LRP on PORT 8080. QEMU forwards
	// nothing when it starts; vm-launch adds the forwarding rule over the QMP
	// monitor (goldenQEMUMonitor) once the guest listens.
	goldenQEMUNetdev = []string{
		"-netdev", "user,id=n0,net=10.0.2.0/24",
		"-device", "virtio-net-device,netdev=n0",
	}
	// goldenQEMUMonitor is the QMP monitor of an LRP, on fd 4 without a
	// volume and fd 5 with one, after every other option.
	goldenQEMUMonitor = func(fd string) []string {
		return []string{"-chardev", "socket,id=qmp0,fd=" + fd + ",server=off", "-mon", "chardev=qmp0,mode=control"}
	}
	// goldenQEMUTaskNetdev is the NIC of a task, which has no port to forward.
	goldenQEMUTaskNetdev = []string{
		"-netdev", "user,id=n0,net=10.0.2.0/24",
		"-device", "virtio-net-device,netdev=n0",
	}
	// goldenQEMUDrive is what a volume adds to the QEMU command line. The
	// serial is the drive's identity.
	goldenQEMUDrive = []string{
		"-drive", "if=none,id=vol0,file=/proc/self/fd/3,format=raw,cache=writeback,aio=threads,file.locking=off,werror=report,rerror=report,discard=ignore",
		"-device", "virtio-blk-device,drive=vol0,serial=rvm-vol0",
	}
	// goldenQEMURootDrive is what a guest root image adds to the QEMU command
	// line, for the image on file descriptor fd.
	goldenQEMURootDrive = func(fd string) []string {
		return []string{
			"-drive", "if=none,id=root0,file=/proc/self/fd/" + fd + ",format=raw,cache=unsafe,aio=threads,file.locking=off,werror=report,rerror=report,discard=unmap,detect-zeroes=unmap",
			"-device", "virtio-blk-device,drive=root0,serial=rvm-root",
		}
	}
)

// withInitrd returns a golden QEMU command line with its -initrd argument
// replaced.
func withInitrd(argv []string, initrd string) []string {
	out := append([]string(nil), argv...)
	for i := range out[:len(out)-1] {
		if out[i] == "-initrd" {
			out[i+1] = initrd
			return out
		}
	}
	Fail("no -initrd in the golden QEMU command line")
	return nil
}

// fcWithInitrd returns a golden Firecracker configuration with its
// initrd_path replaced.
func fcWithInitrd(cfg, initrd string) string {
	Expect(cfg).To(ContainSubstring(`"initrd_path":"` + goldenInitrd + `"`))
	return strings.Replace(cfg, `"initrd_path":"`+goldenInitrd+`"`, `"initrd_path":"`+initrd+`"`, 1)
}

func concat(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// fcConfigJSON returns the Firecracker configuration file that hypervisorArgv
// writes for a guest of memMiB MiB, the one Firecracker is started with.
func fcConfigJSON(initrd string, memMiB int, nw *network, drivePaths []volumeDrive, rootPath string) string {
	work := GinkgoT().TempDir()
	_, err := hypervisorArgv(backend.VMFirecracker, goldenArt, work, initrd, memMiB, nw, drivePaths, rootPath, 0)
	Expect(err).NotTo(HaveOccurred())
	raw, err := os.ReadFile(filepath.Join(work, "fc.json"))
	Expect(err).NotTo(HaveOccurred())
	return string(raw)
}

var _ = Describe("hypervisor volume drive", func() {
	nw := &network{ports: []int{8080}}
	task := &network{}

	It("passes the image as file descriptor 3 by its /proc/self/fd path", func() {
		Expect(firstVolumeFD).To(Equal(3))
		Expect(volumeDrivePath(0)).To(Equal("/proc/self/fd/3"))
		Expect(volumeDriveID(0)).To(Equal("vol0"))
	})

	Describe("hypervisorFiles", func() {
		var img, initrd, monitor, root *os.File

		BeforeEach(func() {
			open := func() *os.File {
				f, err := os.Open(os.DevNull)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(f.Close)
				return f
			}
			img, initrd, monitor, root = open(), open(), open(), open()
		})

		It("passes the initramfs as file descriptor 3 without a volume", func() {
			files, drive, initrdPath, _, _ := hypervisorFiles(nil, initrd, nil, nil)
			Expect(files).To(HaveLen(1))
			Expect(files[0]).To(BeIdenticalTo(initrd))
			Expect(drive).To(BeEmpty())
			Expect(initrdPath).To(Equal(goldenInitrd))
		})

		It("keeps the volume image on file descriptor 3 and moves the initramfs to 4", func() {
			files, drive, initrdPath, _, _ := hypervisorFiles(imageAttachments(img), initrd, nil, nil)
			Expect(files).To(HaveLen(2))
			Expect(files[0]).To(BeIdenticalTo(img))
			Expect(files[1]).To(BeIdenticalTo(initrd))
			Expect(drive).To(Equal(drivePathsFor(1)))
			Expect(initrdPath).To(Equal(goldenVolumeInitrd))
		})

		It("gives no root path without a root image", func() {
			_, _, _, _, rootPath := hypervisorFiles(imageAttachments(img), initrd, monitor, nil)
			Expect(rootPath).To(BeEmpty())
		})

		It("puts the root image after every other file, so that none of them moves", func() {
			for _, c := range []struct {
				name          string
				img, monitor  bool
				drive         []volumeDrive
				initrd        string
				monitorFD, fd int
			}{
				{name: "alone", initrd: "/proc/self/fd/3", fd: 4},
				{name: "with a volume", img: true, drive: imageDrives("/proc/self/fd/3"), initrd: "/proc/self/fd/4", fd: 5},
				{name: "with a monitor", monitor: true, initrd: "/proc/self/fd/3", monitorFD: 4, fd: 5},
				{name: "with a volume and a monitor", img: true, monitor: true, drive: imageDrives("/proc/self/fd/3"), initrd: "/proc/self/fd/4", monitorFD: 5, fd: 6},
			} {
				var i []*attachment
				var m *os.File
				if c.img {
					i = imageAttachments(img)
				}
				if c.monitor {
					m = monitor
				}
				files, drive, initrdPath, monitorFD, rootPath := hypervisorFiles(i, initrd, m, root)
				Expect(files[len(files)-1]).To(BeIdenticalTo(root), c.name)
				Expect(rootPath).To(Equal(procSelfFD(c.fd)), c.name)
				Expect(drive).To(Equal(c.drive), c.name)
				Expect(initrdPath).To(Equal(c.initrd), c.name)
				Expect(monitorFD).To(Equal(c.monitorFD), c.name)
			}
		})
	})

	It("keeps the QEMU command line without a volume byte for byte", func() {
		Expect(qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, task, nil, 0)).To(Equal(concat(goldenQEMUBase, goldenQEMUTaskNetdev)))
		Expect(qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, nw, nil, 4)).To(Equal(concat(goldenQEMUBase, goldenQEMUNetdev, goldenQEMUMonitor("4"))))
	})

	It("keeps the Firecracker configuration without a volume byte for byte, for a task and an LRP alike", func() {
		for _, n := range []*network{task, nw} {
			Expect(fcConfigJSON(goldenInitrd, goldenMemMiB, n, nil, "")).To(Equal(goldenFCNet), "ports %v", n.ports)
		}
	})

	It("attaches the image to QEMU as one raw virtio-blk drive, after the NIC", func() {
		Expect(qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, task, drivePathsFor(1), 0)).To(Equal(concat(withInitrd(goldenQEMUBase, goldenVolumeInitrd), goldenQEMUTaskNetdev, goldenQEMUDrive)))
		Expect(qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, nw, drivePathsFor(1), 5)).To(Equal(concat(withInitrd(goldenQEMUBase, goldenVolumeInitrd), goldenQEMUNetdev, goldenQEMUDrive, goldenQEMUMonitor("5"))))
	})

	It("pins the QEMU drive to raw, reported errors, and no QEMU locking", func() {
		opts := qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, task, drivePathsFor(1), 0)
		drive := opts[len(opts)-3]
		for _, o := range []string{"format=raw", "werror=report", "rerror=report", "file.locking=off", "cache=writeback"} {
			Expect(strings.Split(drive, ",")).To(ContainElement(o))
		}
		// With format=raw, QEMU routes an unprefixed locking option to the raw
		// driver, which rejects it; it must be addressed to the file driver.
		Expect(strings.Split(drive, ",")).NotTo(ContainElement("locking=off"))
	})

	It("gives Firecracker the image as its only drive", func() {
		for _, n := range []*network{task, nw} {
			raw := fcConfigJSON(goldenVolumeInitrd, goldenMemMiB, n, drivePathsFor(1), "")
			Expect(raw).To(Equal(strings.Replace(fcWithInitrd(goldenFCNet, goldenVolumeInitrd), `"drives":[]`, goldenFCDrive, 1)))

			var cfg map[string]any
			Expect(json.Unmarshal([]byte(raw), &cfg)).To(Succeed())
			Expect(cfg["drives"]).To(Equal([]any{map[string]any{
				"drive_id":       "vol0",
				"path_on_host":   "/proc/self/fd/3",
				"is_root_device": false,
				"is_read_only":   false,
				"cache_type":     "Writeback",
				"io_engine":      "Sync",
			}}))
		}
	})

	It("writes the Firecracker drive into the config file hypervisorArgv makes", func() {
		work := GinkgoT().TempDir()
		argv, err := hypervisorArgv(backend.VMFirecracker, goldenArt, work, goldenVolumeInitrd, goldenMemMiB, task, drivePathsFor(1), "", 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal([]string{goldenArt + "/firecracker/firecracker", "--no-api", "--config-file", work + "/fc.json"}))
		raw, err := os.ReadFile(filepath.Join(work, "fc.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring(goldenFCDrive))
		Expect(string(raw)).To(ContainSubstring(`"initrd_path":"` + goldenVolumeInitrd + `"`))

		qemu, err := hypervisorArgv(backend.VMQemu, goldenArt, work, goldenVolumeInitrd, goldenMemMiB, task, drivePathsFor(1), "", 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(qemu).To(Equal(concat(withInitrd(goldenQEMUBase, goldenVolumeInitrd), goldenQEMUTaskNetdev, goldenQEMUDrive)))
	})
})

var _ = Describe("hypervisor guest root drive", func() {
	nw := &network{ports: []int{8080}}
	task := &network{}

	It("attaches the root image to QEMU as a raw virtio-blk drive with discard, after everything else", func() {
		argv, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", goldenInitrd, goldenMemMiB, task, nil, procSelfFD(4), 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal(concat(goldenQEMUBase, goldenQEMUTaskNetdev, goldenQEMURootDrive("4"))))

		argv, err = hypervisorArgv(backend.VMQemu, goldenArt, "/unused", goldenVolumeInitrd, goldenMemMiB, nw, drivePathsFor(1), procSelfFD(6), 5)
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal(concat(withInitrd(goldenQEMUBase, goldenVolumeInitrd), goldenQEMUNetdev, goldenQEMUDrive, goldenQEMUMonitor("5"), goldenQEMURootDrive("6"))))
	})

	It("pins the QEMU root drive to raw, unmap and zero detection, unsafe caching, reported errors, and no QEMU locking", func() {
		drive := goldenQEMURootDrive("4")[1]
		Expect(qemuRootDrive("/proc/self/fd/4")[1]).To(Equal(drive))
		for _, o := range []string{"format=raw", "discard=unmap", "detect-zeroes=unmap", "cache=unsafe", "werror=report", "rerror=report", "file.locking=off", "id=root0"} {
			Expect(strings.Split(drive, ",")).To(ContainElement(o))
		}
	})

	It("leaves the volume drive on QEMU unchanged when a root image comes with it", func() {
		argv, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", goldenVolumeInitrd, goldenMemMiB, task, drivePathsFor(1), procSelfFD(5), 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal(concat(withInitrd(goldenQEMUBase, goldenVolumeInitrd), goldenQEMUTaskNetdev, goldenQEMUDrive, goldenQEMURootDrive("5"))))
		Expect(strings.Join(goldenQEMUDrive, " ")).To(ContainSubstring("discard=ignore"))
	})

	Describe("Firecracker", func() {
		firecrackerConfig := func(initrd string, drivePaths []volumeDrive, rootPath string, n *network) (string, map[string]any) {
			raw := fcConfigJSON(initrd, goldenMemMiB, n, drivePaths, rootPath)
			var cfg map[string]any
			Expect(json.Unmarshal([]byte(raw), &cfg)).To(Succeed())
			return raw, cfg
		}

		It("gives the root image as the only drive, with discard on the Sync engine", func() {
			for _, n := range []*network{task, nw} {
				raw, cfg := firecrackerConfig(goldenInitrd, nil, procSelfFD(4), n)
				Expect(raw).To(Equal(strings.Replace(goldenFCNet, `"drives":[]`, `"drives":[`+goldenFCRootDrive+`]`, 1)), "ports %v", n.ports)
				Expect(cfg["drives"]).To(Equal([]any{map[string]any{
					"drive_id":       "root0",
					"path_on_host":   "/proc/self/fd/4",
					"is_root_device": false,
					"is_read_only":   false,
					"cache_type":     "Unsafe",
					"io_engine":      "Sync",
					"discard":        true,
				}}))
			}
		})

		It("puts the root drive after the volume drive and leaves the volume's JSON as it is", func() {
			raw, _ := firecrackerConfig(goldenVolumeInitrd, drivePathsFor(1), procSelfFD(5), task)
			rootDrive := strings.Replace(goldenFCRootDrive, "/proc/self/fd/4", "/proc/self/fd/5", 1)
			volumeDrive := strings.TrimSuffix(strings.TrimPrefix(goldenFCDrive, `"drives":[`), `]`)
			Expect(raw).To(ContainSubstring(`"drives":[` + volumeDrive + `,` + rootDrive + `]`))
			Expect(strings.Count(raw, `"discard"`)).To(Equal(1))
		})

		It("never makes the root image the root device, so the kernel command line has no root=", func() {
			raw, cfg := firecrackerConfig(goldenInitrd, nil, procSelfFD(4), task)
			Expect(raw).NotTo(ContainSubstring(`"is_root_device":true`))
			Expect(cfg["boot-source"].(map[string]any)["boot_args"]).To(Equal(firecrackerKernelArgs))
			Expect(firecrackerKernelArgs).NotTo(ContainSubstring("root="))
		})

		It("omits discard from a drive that does not set it", func() {
			raw, err := json.Marshal(firecrackerDrive{DriveID: "x"})
			Expect(err).NotTo(HaveOccurred())
			Expect(string(raw)).NotTo(ContainSubstring("discard"))
		})

		It("keeps the configuration without a root image byte for byte", func() {
			raw, _ := firecrackerConfig(goldenInitrd, nil, "", task)
			Expect(raw).To(Equal(goldenFCNet))
		})
	})
})

// goldenQEMUVolumeDrive is what the volume at index i of volume order adds
// to the QEMU command line, with its image on file descriptor fd: the drive
// of goldenQEMUDrive under the volume's own name and serial.
func goldenQEMUVolumeDrive(i int, fd string) []string {
	id := "vol" + strconv.Itoa(i)
	return []string{
		"-drive", "if=none,id=" + id + ",file=/proc/self/fd/" + fd + ",format=raw,cache=writeback,aio=threads,file.locking=off,werror=report,rerror=report,discard=ignore",
		"-device", "virtio-blk-device,drive=" + id + ",serial=rvm-vol" + strconv.Itoa(i),
	}
}

// goldenFCVolumeDrive is the drives entry of the volume at index i of volume
// order, with its image on file descriptor fd.
func goldenFCVolumeDrive(i int, fd string) string {
	return `{"drive_id":"vol` + strconv.Itoa(i) + `","path_on_host":"/proc/self/fd/` + fd + `","is_root_device":false,"is_read_only":false,"cache_type":"Writeback","io_engine":"Sync"}`
}

// drivePathsFor returns the drives of n volume images as hypervisorFiles
// gives them after newGuestDrives has named them for QEMU.
func drivePathsFor(n int) []volumeDrive {
	paths := make([]string, n)
	for i := range paths {
		paths[i] = volumeDrivePath(i)
	}
	return imageDrives(paths...)
}

// imageDrives returns image drives at paths, in volume order, with the QEMU
// serials newGuestDrives gives them.
func imageDrives(paths ...string) []volumeDrive {
	drives := make([]volumeDrive, len(paths))
	for i, p := range paths {
		drives[i] = volumeDrive{path: p, id: qemuVolumeSerial(i), mode: attachFileImage, index: i}
	}
	return drives
}

// imageAttachments returns files as volume images in file-image mode, in
// volume order, with the QEMU serials newGuestDrives gives them.
func imageAttachments(files ...*os.File) []*attachment {
	atts := make([]*attachment, len(files))
	for i, f := range files {
		atts[i] = &attachment{File: f, Mode: attachFileImage, ID: qemuVolumeSerial(i), Index: i, Release: func() error { return nil }}
	}
	return atts
}

var _ = Describe("hypervisor drives for several volumes", func() {
	nw := &network{ports: []int{8080}}
	task := &network{}

	It("builds the one-volume drive from the per-volume golden, so the specs below extend the golden above", func() {
		Expect(goldenQEMUVolumeDrive(0, "3")).To(Equal(goldenQEMUDrive))
		Expect(`"drives":[` + goldenFCVolumeDrive(0, "3") + `]`).To(Equal(goldenFCDrive))
	})

	It("names each volume's drive after its index and opens it from its own file descriptor", func() {
		for i := range maxVolumes {
			Expect(volumeDriveID(i)).To(Equal("vol" + strconv.Itoa(i)))
			Expect(volumeDrivePath(i)).To(Equal(procSelfFD(3 + i)))
		}
		Expect(maxVolumes).To(Equal(4))
	})

	Describe("hypervisorFiles", func() {
		open := func() *os.File {
			f, err := os.Open(os.DevNull)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(f.Close)
			return f
		}

		It("puts the volume images first, in the order given, then the initramfs, the monitor, and the root image", func() {
			for n := 1; n <= maxVolumes; n++ {
				imgs := make([]*os.File, n)
				for i := range imgs {
					imgs[i] = open()
				}
				initrd, monitor, root := open(), open(), open()
				files, drives, initrdPath, monitorFD, rootPath := hypervisorFiles(imageAttachments(imgs...), initrd, monitor, root)
				Expect(files).To(HaveLen(n+3), "%d volumes", n)
				for i, img := range imgs {
					Expect(files[i]).To(BeIdenticalTo(img), "%d volumes, volume %d", n, i)
				}
				Expect(files[n]).To(BeIdenticalTo(initrd))
				Expect(files[n+1]).To(BeIdenticalTo(monitor))
				Expect(files[n+2]).To(BeIdenticalTo(root))
				Expect(drives).To(Equal(drivePathsFor(n)), "%d volumes", n)
				Expect(initrdPath).To(Equal(procSelfFD(3 + n)))
				Expect(monitorFD).To(Equal(4 + n))
				Expect(rootPath).To(Equal(procSelfFD(5 + n)))
			}
		})

		It("gives no drive paths for an empty list of images", func() {
			files, drives, initrdPath, _, _ := hypervisorFiles([]*attachment{}, open(), nil, nil)
			Expect(files).To(HaveLen(1))
			Expect(drives).To(BeEmpty())
			Expect(initrdPath).To(Equal(goldenInitrd))
		})
	})

	It("gives QEMU one drive for each volume, in volume order, after the NIC and before the monitor and the root drive", func() {
		argv, err := hypervisorArgv(backend.VMQemu, goldenArt, "/unused", procSelfFD(7), goldenMemMiB, nw, drivePathsFor(4), procSelfFD(9), 8)
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal(concat(withInitrd(goldenQEMUBase, procSelfFD(7)), goldenQEMUNetdev,
			goldenQEMUVolumeDrive(0, "3"), goldenQEMUVolumeDrive(1, "4"), goldenQEMUVolumeDrive(2, "5"), goldenQEMUVolumeDrive(3, "6"),
			goldenQEMUMonitor("8"), goldenQEMURootDrive("9"))))

		argv, err = hypervisorArgv(backend.VMQemu, goldenArt, "/unused", procSelfFD(5), goldenMemMiB, task, drivePathsFor(2), "", 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal(concat(withInitrd(goldenQEMUBase, procSelfFD(5)), goldenQEMUTaskNetdev,
			goldenQEMUVolumeDrive(0, "3"), goldenQEMUVolumeDrive(1, "4"))))
	})

	It("gives Firecracker one drive for each volume, in volume order, before the root drive", func() {
		for _, n := range []*network{task, nw} {
			raw := fcConfigJSON(procSelfFD(7), goldenMemMiB, n, drivePathsFor(4), procSelfFD(8))
			rootDrive := strings.Replace(goldenFCRootDrive, "/proc/self/fd/4", "/proc/self/fd/8", 1)
			Expect(raw).To(Equal(strings.Replace(fcWithInitrd(goldenFCNet, procSelfFD(7)), `"drives":[]`,
				`"drives":[`+goldenFCVolumeDrive(0, "3")+`,`+goldenFCVolumeDrive(1, "4")+`,`+goldenFCVolumeDrive(2, "5")+`,`+goldenFCVolumeDrive(3, "6")+`,`+rootDrive+`]`, 1)), "ports %v", n.ports)
		}
		raw := fcConfigJSON(procSelfFD(5), goldenMemMiB, task, drivePathsFor(2), "")
		Expect(raw).To(Equal(strings.Replace(fcWithInitrd(goldenFCNet, procSelfFD(5)), `"drives":[]`,
			`"drives":[`+goldenFCVolumeDrive(0, "3")+`,`+goldenFCVolumeDrive(1, "4")+`]`, 1)))
	})

	It("keeps the drive order of the paths it is given, so the order comes from the caller alone", func() {
		paths := imageDrives(procSelfFD(6), procSelfFD(3))
		argv := qemuArgv(goldenArt, procSelfFD(7), goldenMemMiB, task, paths, 0)
		Expect(optionAfter(argv, "-drive", "id=vol0")).To(ContainSubstring("file=/proc/self/fd/6,"))
		Expect(optionAfter(argv, "-drive", "id=vol1")).To(ContainSubstring("file=/proc/self/fd/3,"))
		cfg := newFirecrackerConfig(goldenArt, procSelfFD(7), goldenMemMiB, task, paths, "")
		Expect(cfg.Drives).To(HaveLen(2))
		Expect(cfg.Drives[0].DriveID).To(Equal("vol0"))
		Expect(cfg.Drives[0].PathOnHost).To(Equal(procSelfFD(6)))
		Expect(cfg.Drives[1].DriveID).To(Equal("vol1"))
		Expect(cfg.Drives[1].PathOnHost).To(Equal(procSelfFD(3)))
	})

	It("refuses more drives than a guest can have, or a drive with no path, on either backend, and writes no configuration", func() {
		for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			work := GinkgoT().TempDir()
			_, err := hypervisorArgv(kind, goldenArt, work, procSelfFD(8), goldenMemMiB, task, drivePathsFor(5), "", 0)
			Expect(err).To(MatchError("5 volume drives, over the 4 a guest can have"), string(kind))
			_, err = hypervisorArgv(kind, goldenArt, work, procSelfFD(5), goldenMemMiB, task, []volumeDrive{drivePathsFor(1)[0], {}}, "", 0)
			Expect(err).To(MatchError("volume drive vol1 has no path"), string(kind))
			Expect(os.ReadDir(work)).To(BeEmpty(), string(kind))
		}
	})

	It("keeps every drive ID unique, on QEMU and on Firecracker, with four volumes and a root image", func() {
		argv := withRealRootDrive(qemuArgv(goldenArt, procSelfFD(7), goldenMemMiB, task, drivePathsFor(4), 0), procSelfFD(8))
		ids := map[string]int{}
		for i, a := range argv {
			if a == "-drive" {
				for _, o := range strings.Split(argv[i+1], ",") {
					if id, ok := strings.CutPrefix(o, "id="); ok {
						ids[id]++
					}
				}
			}
		}
		Expect(ids).To(Equal(map[string]int{"vol0": 1, "vol1": 1, "vol2": 1, "vol3": 1, "root0": 1}))

		cfg := newFirecrackerConfig(goldenArt, procSelfFD(7), goldenMemMiB, task, drivePathsFor(4), procSelfFD(8))
		var fcIDs []string
		for _, d := range cfg.Drives {
			fcIDs = append(fcIDs, d.DriveID)
		}
		Expect(fcIDs).To(Equal([]string{"vol0", "vol1", "vol2", "vol3", "root0"}))
	})
})

// blockDrive is what the QEMU monitor's "info block -v" reports for one
// drive: the path it opened and its virtual size in bytes.
type blockDrive struct {
	path string
	size int64
}

var (
	blockDriveLine = regexp.MustCompile(`^(\S+) \(#block\d+\): (\S+) \(\w+\)$`)
	blockSizeLine  = regexp.MustCompile(`^virtual size: .*\((\d+) bytes\)$`)
)

// parseBlockInfo reads the output of "info block -v" into the drives it
// lists, by drive ID. A drive line looks like "vol0 (#block154):
// /proc/self/fd/3 (raw)", and its size follows on a "virtual size" line.
func parseBlockInfo(out string) map[string]blockDrive {
	drives := map[string]blockDrive{}
	var id string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if m := blockDriveLine.FindStringSubmatch(line); m != nil {
			id = m[1]
			drives[id] = blockDrive{path: m[2]}
			continue
		}
		if m := blockSizeLine.FindStringSubmatch(line); m != nil && id != "" {
			size, err := strconv.ParseInt(m[1], 10, 64)
			Expect(err).NotTo(HaveOccurred())
			d := drives[id]
			d.size = size
			drives[id] = d
		}
	}
	return drives
}

var _ = Describe("parseBlockInfo", func() {
	It("reads each drive's path and virtual size from the monitor's output", func() {
		out := "QEMU 10.0.13 monitor - type 'help' for more information\r\n(qemu) info block -v\r\n" +
			"vol0 (#block154): /proc/self/fd/3 (raw)\r\n    Attached to:      /machine/peripheral-anon/device[0]\r\n    Cache mode:       writeback\r\n\r\n" +
			"Images:\r\nimage: /proc/self/fd/3\r\nfile format: raw\r\nvirtual size: 1 MiB (1048576 bytes)\r\ndisk size: 0 B\r\n\r\n" +
			"root0 (#block303): /proc/self/fd/8 (raw)\r\nImages:\r\nimage: /proc/self/fd/8\r\nvirtual size: 8 MiB (8388608 bytes)\r\n(qemu) quit\r\n"
		Expect(parseBlockInfo(out)).To(Equal(map[string]blockDrive{
			"vol0":  {path: "/proc/self/fd/3", size: 1 << 20},
			"root0": {path: "/proc/self/fd/8", size: 8 << 20},
		}))
		Expect(parseBlockInfo("")).To(BeEmpty())
	})
})

var _ = Describe("hypervisor drives for several volumes against a real QEMU", func() {
	// sparseImage returns an open sparse file of size bytes, closed when the
	// spec ends.
	sparseImage := func(size int64) *os.File {
		f, err := os.CreateTemp(GinkgoT().TempDir(), "image")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		Expect(f.Truncate(size)).To(Succeed())
		return f
	}

	It("accepts four volume drives and the root drive on a microvm machine, each opened from its own file descriptor and showing its own image", func() {
		qemu := realQEMU()
		requireMicrovm(qemu)
		// Every image has a size of its own, so that a drive that opened the
		// wrong descriptor, or the same one as another drive, shows the wrong
		// size.
		imgs := []*os.File{sparseImage(1 << 20), sparseImage(2 << 20), sparseImage(3 << 20), sparseImage(4 << 20)}
		root := sparseImage(8 << 20)
		// The stand-in initramfs only holds its file descriptor's place:
		// QEMU, started stopped, never loads a kernel.
		initrd := sparseImage(0)
		files, drivePaths, _, _, rootPath := hypervisorFiles(imageAttachments(imgs...), initrd, nil, root)
		argv := withRealRootDrive(qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, taskNetwork(), drivePaths, 0), rootPath)
		var drives []string
		for i := 0; i+1 < len(argv); i++ {
			if argv[i] == "-drive" || (argv[i] == "-device" && strings.HasPrefix(argv[i+1], "virtio-blk")) {
				drives = append(drives, argv[i], argv[i+1])
			}
		}
		Expect(drives).To(HaveLen(20))
		code, stdout, stderr := runRealQEMU(append([]string{qemu, "-S", "-display", "none", "-M", "microvm,accel=tcg",
			"-nodefaults", "-no-user-config", "-monitor", "stdio"}, drives...), files, "info block -v\nquit\n", 30*time.Second)
		Expect(code).To(Equal(0), "QEMU rejected %q: %s", drives, stderr)

		// The volumes are on file descriptors 3 to 6, and the root, after the
		// initramfs on 7, is on 8.
		want := map[string]blockDrive{"root0": {path: rootPath, size: 8 << 20}}
		for i := range imgs {
			want["vol"+strconv.Itoa(i)] = blockDrive{path: "/proc/self/fd/" + strconv.Itoa(3+i), size: int64(i+1) << 20}
		}
		Expect(parseBlockInfo(stdout)).To(Equal(want), "QEMU reported these drives:\n%s", stdout)
	})

	It("rejects a second drive that reuses the first one's name, so the check above can fail", func() {
		qemu := realQEMU()
		requireMicrovm(qemu)
		imgs := []*os.File{sparseImage(1 << 20), sparseImage(1 << 20)}
		files, drivePaths, _, _, _ := hypervisorFiles(imageAttachments(imgs...), sparseImage(0), nil, nil)
		argv := qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, taskNetwork(), drivePaths, 0)
		second := strings.Replace(optionAfter(argv, "-drive", "id=vol1"), "id=vol1", "id=vol0", 1)
		code, _, stderr := runRealQEMU([]string{qemu, "-S", "-display", "none", "-M", "microvm,accel=tcg", "-nodefaults", "-no-user-config", "-monitor", "stdio",
			"-drive", optionAfter(argv, "-drive", "id=vol0"), "-drive", second}, files, "quit\n", 30*time.Second)
		Expect(code).NotTo(Equal(0))
		Expect(stderr).To(ContainSubstring("vol0"))
	})

	// bootKinds boots a real guest that runs cmd with img as its one volume at
	// /home/vcap/data, which /rvm/disks and /rvm/mounts give the kind kind,
	// and returns the console output once QEMU has exited 0, which it does
	// after a failed setup too, because the guest reboots. QEMU gets img as a
	// file image whatever the kind, because the guest learns the kind from
	// the initramfs alone, so a regular file can stand in for a block
	// volume's disk.
	bootKinds := func(img *os.File, kind driveKind, cmd string) string {
		info, err := img.Stat()
		Expect(err).NotTo(HaveOccurred())
		g := taskGuest(cmd)
		g.vols = []guestVolume{{ContainerDir: "/home/vcap/data", ImageName: "volume.img"}}
		g.drives.volumes = qemuImageDrives(info.Size())
		g.drives.volumes[0].kind = kind
		withRealRoot(&g)

		art := realArtifacts()
		qemu := realQEMU()
		requireMicrovm(qemu)
		f, err := newInitramfs(guestBusybox(), g)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		files, drivePaths, initrdPath, _, rootPath := hypervisorFiles(imageAttachments(img), withUserspaceMark(f), nil, realRootImage())
		argv := markedArgv(tcgArgv(qemu, withRealRootDrive(qemuArgv(art, initrdPath, minGuestMemoryMiB, g.nw, drivePaths, 0), rootPath)))
		code, stdout, stderr := bootRealQEMU(argv, files)
		Expect(code).To(Equal(0), "QEMU failed: %s\n%s", stderr, stdout)
		return stdout
	}

	It("never formats a blank block volume, fails the boot instead, and mounts a block volume with data as ext4 with noatime and without sync", func() {
		const size = 32 << 20
		img := sparseImage(size)

		// A blank disk of the block kind fails the boot before the command,
		// with the line that names the volume's disk, and stays blank.
		stdout := bootKinds(img, driveBlock, "echo never-ran")
		Expect(stdout).To(MatchRegexp(`vm-launch guest setup: mounting volume 0's disk /dev/vd[a-z]+ at /home/vcap/data failed; vm-launch never formats a block volume, so the guest will not boot with it`))
		Expect(stdout).NotTo(ContainSubstring(startTag(testNonce)), stdout)
		Expect(stdout).NotTo(ContainSubstring("never-ran"), stdout)
		head := make([]byte, 1<<20)
		_, err := img.ReadAt(head, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(bytes.Count(head, []byte{0})).To(Equal(len(head)), "the guest wrote to the blank block volume")

		// The same disk as an image is formatted, and the command leaves a
		// file on it.
		stdout = bootKinds(img, driveImage, "echo kept >/home/vcap/data/mark && sync -f /home/vcap/data")
		Expect(stdout).To(ContainSubstring(exitTag(testNonce)+"0"), stdout)
		Expect(extLabel(img)).To(Equal("rvm-volume"))

		// As a block volume the disk now mounts as it is, with noatime and
		// without sync or dirsync, and keeps the file.
		stdout = bootKinds(img, driveBlock, `grep " /home/vcap/data ext4 " /proc/mounts | sed 's/^/mount=/'; echo "mark=$(cat /home/vcap/data/mark)"`)
		Expect(stdout).NotTo(ContainSubstring("vm-launch guest setup"), stdout)
		Expect(stdout).To(ContainSubstring(exitTag(testNonce)+"0"), stdout)
		Expect(stdout).To(MatchRegexp(`(?m)^mark=kept\r?$`))
		m := regexp.MustCompile(`(?m)^mount=/dev/vd[a-z]+ /home/vcap/data ext4 (\S+) `).FindStringSubmatch(stdout)
		Expect(m).NotTo(BeNil(), stdout)
		options := strings.Split(m[1], ",")
		Expect(options).To(ContainElement("noatime"), m[1])
		Expect(options).NotTo(ContainElement("sync"), m[1])
		Expect(options).NotTo(ContainElement("dirsync"), m[1])
		Expect(extLabel(img)).To(Equal("rvm-volume"))
	})

	It("boots a guest with two volume images of one size and mounts each at its own path from the drive with its identity", func() {
		vols := []*os.File{sparseImage(defaultImageSize), sparseImage(defaultImageSize)}
		root := realRootImage()
		g := taskGuest(`for p in /home/vcap/data /home/vcap/logs; do
	d=$(grep " $p ext4 " /proc/mounts | cut -d ' ' -f 1)
	d=${d#/dev/}
	echo "mount=$p:$d:$(cat /sys/block/$d/serial)"
done
`)
		g.vols = []guestVolume{{ContainerDir: "/home/vcap/data", ImageName: "volume.img"}, {ContainerDir: "/home/vcap/logs", ImageName: "volume.img"}}
		g.drives.volumes = qemuImageDrives(defaultImageSize, defaultImageSize)
		withRealRoot(&g)

		art := realArtifacts()
		qemu := realQEMU()
		requireMicrovm(qemu)
		f, err := newInitramfs(guestBusybox(), g)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		files, drivePaths, initrdPath, _, rootPath := hypervisorFiles(imageAttachments(vols...), withUserspaceMark(f), nil, root)
		Expect(drivePaths).To(Equal(drivePathsFor(2)))
		argv := markedArgv(tcgArgv(qemu, withRealRootDrive(qemuArgv(art, initrdPath, minGuestMemoryMiB, g.nw, drivePaths, 0), rootPath)))
		code, stdout, stderr := bootRealQEMU(argv, files)
		Expect(code).To(Equal(0), "QEMU failed: %s\n%s", stderr, stdout)
		Expect(stdout).NotTo(ContainSubstring("vm-launch guest setup"), stdout)
		Expect(stdout).To(ContainSubstring(exitTag(testNonce)+"0"), stdout)

		devices := map[string]string{}
		for _, m := range regexp.MustCompile(`(?m)^mount=([^:\r\n]+):(vd[a-z]+):([^\r\n]*)\r?$`).FindAllStringSubmatch(stdout, -1) {
			Expect(devices).NotTo(HaveKey(m[1]), stdout)
			devices[m[1]] = m[3]
			Expect(m[2]).NotTo(BeEmpty())
		}
		Expect(devices).To(Equal(map[string]string{"/home/vcap/data": "rvm-vol0", "/home/vcap/logs": "rvm-vol1"}), stdout)
		for i, img := range vols {
			Expect(extLabel(img)).To(Equal("rvm-volume"), "volume image %d", i)
		}
		Expect(extLabel(root)).To(Equal("rvm-root"))
	})
})
