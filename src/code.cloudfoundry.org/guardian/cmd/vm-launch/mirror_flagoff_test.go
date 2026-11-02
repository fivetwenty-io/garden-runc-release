//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// flagOffGolden holds the digest and size of each initramfs archive below,
// as the launch built them before mirrored mounts existed. The spec that
// reads it writes it afresh when VM_LAUNCH_UPDATE_FLAG_OFF_GOLDEN is set.
const flagOffGolden = "testdata/flag-off-initramfs.sha256"

var _ = Describe("the initramfs without mirrored mounts", func() {
	It("is byte for byte the archive of the launch before mirrored mounts, for each kind of guest", func() {
		f, err := os.Open(writeTempFile("launcher", "#!/bin/sh\n"))
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		stack := func() guestContents {
			g := taskGuest("")
			g.drives.stackID, g.drives.dropletID = qemuStackSerial, qemuDropletSerial
			g.stack = &guestStack{
				launcher: guestTool{name: "launcher", file: f, size: int64(len("#!/bin/sh\n"))},
				argv:     shellJoin([]string{stackLauncherPath, "/home/vcap/app", "", ""}),
				cwd:      "/home/vcap/app",
				hostname: "stack-guest-0",
				hosts:    []byte("127.0.0.1 localhost\n"),
			}
			return g
		}
		fallback := stack()
		fallback.stack.fallback, fallback.stack.fallbackEnv = true, "export FOR_BUSYBOX=1\n"
		volumes := stack()
		volumes.stack.fallback = true
		volumes.vols = []guestVolume{{ContainerDir: "/home/vcap/data", ImageName: "rvm-disk-0.img"}}
		volumes.drives.volumes = qemuImageDrives(defaultImageSize)
		sidecar := stack()
		sidecar.stack.sidecars = []guestSidecar{{argv: "'/tmp/lifecycle/launcher' 'x'", env: "export A='b'\n"}}
		guests := []struct {
			name  string
			guest guestContents
		}{
			{"task", taskGuest("echo hi")},
			{"stack", stack()},
			{"stack-fallback", fallback},
			{"stack-volumes", volumes},
			{"stack-sidecar", sidecar},
		}

		var got strings.Builder
		for _, g := range guests {
			var buf bytes.Buffer
			Expect(writeInitramfsArchive(&buf, strings.NewReader("busybox"), int64(len("busybox")), g.guest)).To(Succeed())
			fmt.Fprintf(&got, "%s %x %d\n", g.name, sha256.Sum256(buf.Bytes()), buf.Len())
		}
		if os.Getenv("VM_LAUNCH_UPDATE_FLAG_OFF_GOLDEN") != "" {
			Expect(os.WriteFile(flagOffGolden, []byte(got.String()), 0o644)).To(Succeed())
		}
		want, err := os.ReadFile(flagOffGolden)
		Expect(err).NotTo(HaveOccurred())
		Expect(got.String()).To(Equal(string(want)), "an initramfs without mirrored mounts changed. If the change to the guest is on purpose and leaves mirrored mounts out of it, run this spec again with VM_LAUNCH_UPDATE_FLAG_OFF_GOLDEN=1 to write "+flagOffGolden+" afresh, and commit it with the change")
	})
})
