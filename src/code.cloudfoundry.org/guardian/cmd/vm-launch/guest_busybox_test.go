//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// guestBusyboxEnv names the busybox binary that the VM guests run, for the
// specs that need the guest's own shell. That binary comes from Ubuntu's
// busybox-static 1:1.37.0-7ubuntu1 amd64 package, and guestBusyboxSHA256 is
// its sha256.
const (
	guestBusyboxEnv    = "VM_LAUNCH_GUEST_BUSYBOX"
	guestBusyboxSHA256 = "df12634c17fcdca839ae5dc47d7627b7558511f7645de7c99ccf097a0f28ed5b"
)

// guestBusybox returns the path guestBusyboxEnv names, or skips the spec
// when it is unset. The skip names the variable, and Ginkgo lists it in a
// verbose run, but it does not fail the run, so a release check must set the
// variable and confirm that these specs ran. No other shell can stand in,
// because the host's /bin/sh may be dash, which lacks the `read -t` and
// `read -u` that the watcher's pause uses. Without the variable, the golden
// /init text spec alone guards the pause, and the spec that times two pauses
// does not run. A file that is not the guest's busybox fails the spec,
// because another build behaves differently: Debian's and busybox.net's
// builds import environment names that the guest's build drops.
func guestBusybox() string {
	path := os.Getenv(guestBusyboxEnv)
	if path == "" {
		Skip(guestBusyboxEnv + " is not set; point it at the guest's busybox, from Ubuntu's busybox-static 1:1.37.0-7ubuntu1 amd64 package (sha256 " + guestBusyboxSHA256 + "), to run this check against the guest's shell")
	}
	raw, err := os.ReadFile(path)
	Expect(err).NotTo(HaveOccurred(), "reading %s %s", guestBusyboxEnv, path)
	sum := sha256.Sum256(raw)
	Expect(hex.EncodeToString(sum[:])).To(Equal(guestBusyboxSHA256), "%s names %s, which is not the guest's busybox", guestBusyboxEnv, path)
	return path
}
