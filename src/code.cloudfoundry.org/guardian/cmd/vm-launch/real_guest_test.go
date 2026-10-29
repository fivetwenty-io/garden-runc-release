//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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

	It("gives the command the container's open files limit above the kernel's default fs.nr_open", func() {
		g := taskGuest(`echo "soft=$(ulimit -S -n) hard=$(ulimit -H -n) nr_open=$(cat /proc/sys/fs/nr_open) file_max=$(cat /proc/sys/fs/file-max)"
echo "init=$(sed -n 's/^Max open files *\([0-9]*\) *\([0-9]*\).*/\1 \2/p' /proc/1/limits)"`)
		g.nofile = nofileLimit{soft: 1500000, hard: 2000000}
		out := bootRealGuest(g)
		Expect(out).To(ContainSubstring("soft=1500000 hard=2000000 nr_open=2000000 file_max=9223372036854775807"))
		// /init keeps the kernel's own limit; only the command gets the
		// container's.
		Expect(out).To(MatchRegexp(`init=\d+ \d+`))
		Expect(out).NotTo(ContainSubstring("init=1500000 2000000"))
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})

	It("gives the command a /dev/shm tmpfs of half the guest's memory, mounted as Garden mounts it", func() {
		out := bootRealGuest(taskGuest(`grep ' /dev/shm ' /proc/mounts
ls -ld /dev/shm
echo "memtotal=$(sed -n 's/^MemTotal: *\([0-9]*\) kB$/\1/p' /proc/meminfo)"
echo "shm_kib=$(df -k /dev/shm | sed -n '2s/^[^ ]*  *\([0-9]*\) .*/\1/p')"
echo shared >/dev/shm/probe && echo "wrote=$(cat /dev/shm/probe)"
cp /bin/busybox /dev/shm/bb && chmod 755 /dev/shm/bb
/dev/shm/bb true && echo exec=allowed || echo exec=denied`))
		m := regexp.MustCompile(`(?m)^tmpfs /dev/shm tmpfs (\S+) 0 0\r?$`).FindStringSubmatch(out)
		Expect(m).NotTo(BeNil(), out)
		opts := strings.Split(m[1], ",")
		Expect(opts).To(ContainElements("rw", "nosuid", "nodev", "noexec"), out)
		// The kernel leaves mode=1777 out of the options, because it is the
		// tmpfs default, so the mode is checked on the directory.
		Expect(out).To(MatchRegexp(`(?m)^drwxrwxrwt +\d+ 0 +0 .* /dev/shm\r?$`))
		// The kernel also leaves the size out when it equals the tmpfs
		// default of half the memory at the time it shows the options, which
		// moves as the kernel frees boot memory, so the size comes from df.
		kib := func(name string) uint64 {
			m := regexp.MustCompile(name + `=(\d+)`).FindStringSubmatch(out)
			Expect(m).NotTo(BeNil(), out)
			n, err := strconv.ParseUint(m[1], 10, 64)
			Expect(err).NotTo(HaveOccurred())
			return n
		}
		sizeKiB, memKiB := kib("shm_kib"), kib("memtotal")
		// tmpfs takes half of the guest's pages, so the size is within a
		// page of half of MemTotal.
		Expect(sizeKiB).To(BeNumerically("~", memKiB/2, 4), out)
		Expect(sizeKiB).To(BeNumerically("<=", minGuestMemoryMiB*1024/2), out)
		Expect(out).To(ContainSubstring("wrote=shared"))
		Expect(out).To(ContainSubstring("exec=denied"))
		Expect(out).To(ContainSubstring(exitTag(testNonce) + "0"))
	})
})
