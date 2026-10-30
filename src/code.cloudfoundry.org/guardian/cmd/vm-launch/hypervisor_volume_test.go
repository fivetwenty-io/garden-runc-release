//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

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
	// goldenQEMUDrive is what a volume adds to the QEMU command line.
	goldenQEMUDrive = []string{
		"-drive", "if=none,id=vol0,file=/proc/self/fd/3,format=raw,cache=writeback,aio=threads,file.locking=off,werror=report,rerror=report,discard=ignore",
		"-device", "virtio-blk-device,drive=vol0",
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

var _ = Describe("hypervisor volume drive", func() {
	nw := &network{ports: []int{8080}}
	task := &network{}

	It("passes the image as file descriptor 3 by its /proc/self/fd path", func() {
		Expect(volumeDriveFD).To(Equal(3))
		Expect(volumeDrivePath()).To(Equal("/proc/self/fd/3"))
	})

	Describe("hypervisorFiles", func() {
		var img, initrd *os.File

		BeforeEach(func() {
			var err error
			img, err = os.Open(os.DevNull)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(img.Close)
			initrd, err = os.Open(os.DevNull)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(initrd.Close)
		})

		It("passes the initramfs as file descriptor 3 without a volume", func() {
			files, drive, initrdPath, _ := hypervisorFiles(nil, initrd, nil)
			Expect(files).To(HaveLen(1))
			Expect(files[0]).To(BeIdenticalTo(initrd))
			Expect(drive).To(BeEmpty())
			Expect(initrdPath).To(Equal(goldenInitrd))
		})

		It("keeps the volume image on file descriptor 3 and moves the initramfs to 4", func() {
			files, drive, initrdPath, _ := hypervisorFiles(img, initrd, nil)
			Expect(files).To(HaveLen(2))
			Expect(files[0]).To(BeIdenticalTo(img))
			Expect(files[1]).To(BeIdenticalTo(initrd))
			Expect(drive).To(Equal(volumeDrivePath()))
			Expect(initrdPath).To(Equal(goldenVolumeInitrd))
		})
	})

	It("keeps the QEMU command line without a volume byte for byte", func() {
		Expect(qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, task, "", 0)).To(Equal(concat(goldenQEMUBase, goldenQEMUTaskNetdev)))
		Expect(qemuArgv(goldenArt, goldenInitrd, goldenMemMiB, nw, "", 4)).To(Equal(concat(goldenQEMUBase, goldenQEMUNetdev, goldenQEMUMonitor("4"))))
	})

	It("keeps the Firecracker configuration without a volume byte for byte, for a task and an LRP alike", func() {
		for _, n := range []*network{task, nw} {
			raw, err := firecrackerConfigJSON(goldenArt, goldenInitrd, goldenMemMiB, n, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(raw)).To(Equal(goldenFCNet), "ports %v", n.ports)
		}
	})

	It("attaches the image to QEMU as one raw virtio-blk drive, after the NIC", func() {
		Expect(qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, task, volumeDrivePath(), 0)).To(Equal(concat(withInitrd(goldenQEMUBase, goldenVolumeInitrd), goldenQEMUTaskNetdev, goldenQEMUDrive)))
		Expect(qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, nw, volumeDrivePath(), 5)).To(Equal(concat(withInitrd(goldenQEMUBase, goldenVolumeInitrd), goldenQEMUNetdev, goldenQEMUDrive, goldenQEMUMonitor("5"))))
	})

	It("pins the QEMU drive to raw, reported errors, and no QEMU locking", func() {
		opts := qemuArgv(goldenArt, goldenVolumeInitrd, goldenMemMiB, task, volumeDrivePath(), 0)
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
			raw, err := firecrackerConfigJSON(goldenArt, goldenVolumeInitrd, goldenMemMiB, n, volumeDrivePath())
			Expect(err).NotTo(HaveOccurred())
			Expect(string(raw)).To(Equal(strings.Replace(fcWithInitrd(goldenFCNet, goldenVolumeInitrd), `"drives":[]`, goldenFCDrive, 1)))

			var cfg map[string]any
			Expect(json.Unmarshal(raw, &cfg)).To(Succeed())
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
		argv, err := hypervisorArgv(backend.VMFirecracker, goldenArt, work, goldenVolumeInitrd, goldenMemMiB, task, volumeDrivePath(), 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal([]string{goldenArt + "/firecracker/firecracker", "--no-api", "--config-file", work + "/fc.json"}))
		raw, err := os.ReadFile(filepath.Join(work, "fc.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring(goldenFCDrive))
		Expect(string(raw)).To(ContainSubstring(`"initrd_path":"` + goldenVolumeInitrd + `"`))

		qemu, err := hypervisorArgv(backend.VMQemu, goldenArt, work, goldenVolumeInitrd, goldenMemMiB, task, volumeDrivePath(), 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(qemu).To(Equal(concat(withInitrd(goldenQEMUBase, goldenVolumeInitrd), goldenQEMUTaskNetdev, goldenQEMUDrive)))
	})
})
