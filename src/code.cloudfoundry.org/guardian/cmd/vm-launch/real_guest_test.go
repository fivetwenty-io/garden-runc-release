//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// bootRealGuest boots a guest with contents g, the guest's busybox, and the
// real kernel under TCG, as vm-launch would with QEMU, and returns the
// console output. It fails the spec unless QEMU exits 0, and skips it
// where the real kernel, the guest's busybox, or an x86 QEMU is missing.
func bootRealGuest(g guestContents) string {
	art := realArtifacts()
	qemu := realQEMU()
	requireMicrovm(qemu)
	f, err := newInitramfs(guestBusybox(), g)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(f.Close)
	files, _, initrdPath := hypervisorFiles(nil, f)
	argv := tcgArgv(qemu, qemuArgv(art, initrdPath, minGuestMemoryMiB, g.nw, ""))
	code, stdout, stderr := runRealQEMU(argv, files, "", 5*time.Minute)
	Expect(code).To(Equal(0), "QEMU failed: %s\n%s", stderr, stdout)
	Expect(stdout).To(ContainSubstring(startTag(testNonce)), stdout)
	return stdout
}

var _ = Describe("the guest userland against a real QEMU", func() {
	It("gives the command the CA bundle at the standard path, with SSL_CERT_FILE naming it", func() {
		dir := GinkgoT().TempDir()
		rootfs := filepath.Join(dir, "ca-certificates.crt")
		Expect(os.WriteFile(rootfs, []byte(newFixtureCert("rootfs").pem), 0o644)).To(Succeed())
		certDir := filepath.Join(dir, "system")
		Expect(os.Mkdir(certDir, 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(certDir, "trusted-ca-1.crt"), []byte(newFixtureCert("system").pem), 0o644)).To(Succeed())
		logger := log.New(GinkgoWriter, "", 0)
		bundle, err := guestCABundle([]string{rootfs}, lookupIn(map[string]string{systemCertPathEnv: certDir}), logger)
		Expect(err).NotTo(HaveOccurred())
		envFile, err := buildGuestEnv(map[string]string{sslCertFileEnv: guestCABundlePath}, minGuestMemoryMiB, logger)
		Expect(err).NotTo(HaveOccurred())
		sum := sha256.Sum256(bundle)

		g := taskGuest(`echo "certs=$(grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt) file=$SSL_CERT_FILE"
sha256sum /etc/ssl/certs/ca-certificates.crt
ls -ld /etc/ssl/certs/ca-certificates.crt`)
		g.env = envFile
		g.caBundle = bundle
		out := bootRealGuest(g)
		Expect(out).To(ContainSubstring("certs=2 file=" + guestCABundlePath))
		Expect(out).To(ContainSubstring(hex.EncodeToString(sum[:]) + "  " + guestCABundlePath))
		Expect(out).To(MatchRegexp(`-rw-r--r-- +1 0 +0 .*` + guestCABundlePath))
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})
})
