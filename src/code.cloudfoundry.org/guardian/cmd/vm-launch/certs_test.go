//go:build linux

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// fixtureCert is a self-signed CA certificate, as DER and as PEM.
type fixtureCert struct {
	der []byte
	pem string
}

// newFixtureCert makes a self-signed CA certificate named cn.
func newFixtureCert(cn string) fixtureCert {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	return signFixtureCert(key, cn)
}

// signFixtureCert makes a CA certificate named cn for key, signed by key.
// Each call gives a new serial number, and so a distinct certificate.
func signFixtureCert(key *ecdsa.PrivateKey, cn string) fixtureCert {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	return fixtureCert{der: der, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// fixtureKeyPEM is a PEM private key that must never reach the guest.
func fixtureKeyPEM() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	der, err := x509.MarshalECPrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// bundleCerts returns the DER of every block in bundle, failing the spec for
// anything that is not a parseable CERTIFICATE block or for leftover bytes.
func bundleCerts(bundle []byte) [][]byte {
	var ders [][]byte
	rest := bundle
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		Expect(block).NotTo(BeNil(), "bytes left that are not PEM: %q", rest)
		Expect(block.Type).To(Equal("CERTIFICATE"))
		Expect(block.Headers).To(BeEmpty())
		_, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		ders = append(ders, block.Bytes)
	}
	return ders
}

// envLookup returns a lookup over vars, in the form of os.LookupEnv.
func envLookup(vars map[string]string) func(string) (string, bool) {
	return lookupIn(vars)
}

var _ = Describe("the guest CA bundle", func() {
	var (
		dir     string
		certDir string
		logBuf  *bytes.Buffer
		logger  *log.Logger
		a, b, c fixtureCert
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		certDir = filepath.Join(dir, "cf-system-certificates")
		Expect(os.Mkdir(certDir, 0o755)).To(Succeed())
		logBuf = &bytes.Buffer{}
		logger = log.New(logBuf, "", 0)
		a, b, c = newFixtureCert("rootfs-a"), newFixtureCert("system-b"), newFixtureCert("system-c")
	})

	write := func(path, content string) string {
		Expect(os.WriteFile(path, []byte(content), 0o644)).To(Succeed())
		return path
	}
	withCertPath := envLookup(map[string]string{systemCertPathEnv: ""})

	It("holds the container's bundle and then each system certificate, once each, in name order", func() {
		rootfs := write(filepath.Join(dir, "ca-certificates.crt"), "# a comment the guest never sees\n"+a.pem+b.pem)
		write(filepath.Join(certDir, "z.crt"), b.pem)
		write(filepath.Join(certDir, "m.pem"), c.pem+a.pem)
		bundle, err := guestCABundle([]string{rootfs}, envLookup(map[string]string{systemCertPathEnv: certDir}), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(bundleCerts(bundle)).To(Equal([][]byte{a.der, b.der, c.der}))
		Expect(string(bundle)).NotTo(ContainSubstring("comment"))
		Expect(logBuf.String()).To(BeEmpty())
	})

	It("uses the first container bundle that it can read, as Go does", func() {
		first := filepath.Join(dir, "missing.crt")
		dangling := filepath.Join(dir, "dangling.crt")
		Expect(os.Symlink(filepath.Join(dir, "nowhere"), dangling)).To(Succeed())
		second := write(filepath.Join(dir, "second.crt"), a.pem)
		third := write(filepath.Join(dir, "third.crt"), b.pem)
		bundle, err := guestCABundle([]string{first, dangling, second, third}, withCertPath, logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(bundleCerts(bundle)).To(Equal([][]byte{a.der}))
		Expect(logBuf.String()).To(BeEmpty())
	})

	It("follows symbolic links to certificate files", func() {
		target := write(filepath.Join(dir, "target.crt"), b.pem)
		Expect(os.Symlink(target, filepath.Join(certDir, "link.crt"))).To(Succeed())
		bundle, err := guestCABundle(nil, envLookup(map[string]string{systemCertPathEnv: certDir}), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(bundleCerts(bundle)).To(Equal([][]byte{b.der}))
	})

	It("copies only certificates, never a key or another block", func() {
		key := fixtureKeyPEM()
		write(filepath.Join(certDir, "mixed.pem"), key+b.pem+"-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n")
		write(filepath.Join(certDir, "key.pem"), key)
		bundle, err := guestCABundle(nil, envLookup(map[string]string{systemCertPathEnv: certDir}), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(bundleCerts(bundle)).To(Equal([][]byte{b.der}))
		Expect(string(bundle)).NotTo(ContainSubstring("PRIVATE KEY"))
		Expect(logBuf.String()).To(Equal("leaving 1 files out of the guest's trusted certificates: 0 unreadable, 0 not regular files, 1 with no PEM certificate\n"))
	})

	It("leaves out a certificate block with PEM headers, as Go does", func() {
		withHeaders := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: c.der}))
		write(filepath.Join(certDir, "headers.pem"), withHeaders+b.pem)
		bundle, err := guestCABundle(nil, envLookup(map[string]string{systemCertPathEnv: certDir}), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(bundleCerts(bundle)).To(Equal([][]byte{b.der}))
		Expect(logBuf.String()).To(BeEmpty())
	})

	It("never opens a FIFO under the directory", func() {
		fifo := filepath.Join(certDir, "fifo.crt")
		Expect(syscall.Mkfifo(fifo, 0o644)).To(Succeed())
		write(filepath.Join(certDir, "good.crt"), b.pem)
		watch, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
		Expect(err).NotTo(HaveOccurred())
		defer unix.Close(watch)
		_, err = unix.InotifyAddWatch(watch, fifo, unix.IN_OPEN)
		Expect(err).NotTo(HaveOccurred())
		events := make([]byte, 4096)

		bundle, err := guestCABundle(nil, envLookup(map[string]string{systemCertPathEnv: certDir}), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(bundleCerts(bundle)).To(Equal([][]byte{b.der}))
		_, err = unix.Read(watch, events)
		Expect(err).To(MatchError(unix.EAGAIN), "the FIFO was opened")

		// An open of the FIFO shows up on the watch.
		f, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Close()).To(Succeed())
		n, err := unix.Read(watch, events)
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(BeNumerically(">=", unix.SizeofInotifyEvent))
	})

	It("leaves out unreadable, irregular, and non-PEM files with one line that only counts them", func() {
		write(filepath.Join(certDir, "good.crt"), b.pem)
		write(filepath.Join(certDir, "der.crt"), string(c.der))
		write(filepath.Join(certDir, "empty.crt"), "")
		Expect(os.Symlink("loop.crt", filepath.Join(certDir, "loop.crt"))).To(Succeed())
		Expect(os.Mkdir(filepath.Join(certDir, "subdir"), 0o755)).To(Succeed())
		Expect(syscall.Mkfifo(filepath.Join(certDir, "fifo"), 0o644)).To(Succeed())
		unreadable := 1
		if os.Geteuid() != 0 {
			// root reads a file of mode 0000 anyway.
			write(filepath.Join(certDir, "secret.crt"), c.pem)
			Expect(os.Chmod(filepath.Join(certDir, "secret.crt"), 0)).To(Succeed())
			unreadable = 2
		}
		bundle, err := guestCABundle(nil, envLookup(map[string]string{systemCertPathEnv: certDir}), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(bundleCerts(bundle)).To(Equal([][]byte{b.der}))
		Expect(logBuf.String()).To(Equal(
			"leaving " + strconv.Itoa(unreadable+4) + " files out of the guest's trusted certificates: " + strconv.Itoa(unreadable) + " unreadable, 2 not regular files, 2 with no PEM certificate\n"))
		Expect(logBuf.String()).NotTo(ContainSubstring("good.crt"))
	})

	It("is not an error when CF_SYSTEM_CERT_PATH is unset, empty, missing, or not a directory", func() {
		rootfs := write(filepath.Join(dir, "ca-certificates.crt"), a.pem)
		notDir := write(filepath.Join(dir, "plain"), b.pem)
		for _, vars := range []map[string]string{
			{},
			{systemCertPathEnv: ""},
			{systemCertPathEnv: filepath.Join(dir, "nope")},
			{systemCertPathEnv: notDir},
		} {
			logBuf.Reset()
			bundle, err := guestCABundle([]string{rootfs}, envLookup(vars), logger)
			Expect(err).NotTo(HaveOccurred(), "%v", vars)
			Expect(bundleCerts(bundle)).To(Equal([][]byte{a.der}), "%v", vars)
		}
		logBuf.Reset()
		_, err := guestCABundle([]string{rootfs}, envLookup(map[string]string{systemCertPathEnv: filepath.Join(dir, "nope")}), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(logBuf.String()).To(Equal(systemCertPathEnv + " " + filepath.Join(dir, "nope") + " does not exist; the guest gets no certificates from it\n"))
	})

	It("returns no bundle, with one line, when there is no certificate", func() {
		bundle, err := guestCABundle([]string{filepath.Join(dir, "nope")}, envLookup(map[string]string{systemCertPathEnv: certDir}), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(bundle).To(BeNil())
		Expect(logBuf.String()).To(Equal("found no trusted certificates for the guest; it gets no CA bundle\n"))
	})

	It("fails, naming the cap, when the certificates are over 2 MiB", func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		var many strings.Builder
		for many.Len() <= maxCABundleBytes {
			many.WriteString(signFixtureCert(key, "many").pem)
		}
		// Split over two files that are each under the cap.
		half := strings.Index(many.String()[many.Len()/2:], "-----BEGIN") + many.Len()/2
		write(filepath.Join(certDir, "a.crt"), many.String()[:half])
		write(filepath.Join(certDir, "b.crt"), many.String()[half:])
		_, err = guestCABundle(nil, envLookup(map[string]string{systemCertPathEnv: certDir}), logger)
		Expect(err).To(MatchError(errCABundleTooLarge))
		Expect(err.Error()).To(Equal("the trusted certificates for the guest are over the 2097152 bytes a guest may have"))
	})

	It("fails for one file over 2 MiB without reading it all, naming the file", func() {
		big := filepath.Join(certDir, "big.crt")
		write(big, a.pem)
		Expect(os.Truncate(big, maxCABundleBytes+1)).To(Succeed())
		_, err := guestCABundle(nil, envLookup(map[string]string{systemCertPathEnv: certDir}), logger)
		Expect(err).To(MatchError(errCABundleTooLarge))
		Expect(err.Error()).To(HavePrefix(big + ": "))

		rootfs := filepath.Join(dir, "rootfs.crt")
		write(rootfs, a.pem)
		Expect(os.Truncate(rootfs, maxCABundleBytes+1)).To(Succeed())
		_, err = guestCABundle([]string{rootfs}, withCertPath, logger)
		Expect(err).To(MatchError(errCABundleTooLarge))
	})

	It("accepts a bundle of exactly 2 MiB", func() {
		cert := newFixtureCert("exact")
		builder := &caBundleBuilder{seen: map[[sha256.Size]byte]bool{}}
		builder.pem = make([]byte, maxCABundleBytes-len(cert.pem))
		Expect(builder.add([]byte(cert.pem))).To(Succeed())
		Expect(builder.pem).To(HaveLen(maxCABundleBytes))
		Expect(builder.add([]byte(newFixtureCert("one more").pem))).To(MatchError(errCABundleTooLarge))
	})

	It("never logs a certificate", func() {
		write(filepath.Join(certDir, "der.crt"), string(a.der))
		write(filepath.Join(certDir, "good.crt"), b.pem)
		_, err := guestCABundle(nil, envLookup(map[string]string{systemCertPathEnv: certDir}), logger)
		Expect(err).NotTo(HaveOccurred())
		for _, p := range []string{a.pem, b.pem} {
			body := strings.Split(p, "\n")[1]
			Expect(logBuf.String()).NotTo(ContainSubstring(body))
		}
	})
})

var _ = Describe("the CA bundle in the initramfs", func() {
	It("holds the bundle at /etc/ssl/certs/ca-certificates.crt after the parent directories", func() {
		cert := newFixtureCert("in the archive")
		bb := filepath.Join(GinkgoT().TempDir(), "busybox")
		Expect(os.WriteFile(bb, []byte("busybox"), 0o755)).To(Succeed())
		g := taskGuest("true")
		g.caBundle = []byte(cert.pem)
		f, err := newInitramfs(bb, g)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		names, byName := archiveEntries(fileBytes(f))
		Expect(names).To(Equal([]string{"bin", "dev", "dev/console", "dev/null", "etc", "proc", "sys", "tmp", "rvm",
			"bin/busybox", "rvm/cmd", "rvm/net", "rvm/env", "rvm/limits", "etc/resolv.conf",
			"etc/ssl", "etc/ssl/certs", "etc/ssl/certs/ca-certificates.crt", "init", cpioTrailer}))
		Expect(byName["etc/ssl"].mode).To(Equal(uint32(0o040755)))
		Expect(byName["etc/ssl/certs"].mode).To(Equal(uint32(0o040755)))
		Expect(byName["etc/ssl/certs/ca-certificates.crt"].mode).To(Equal(uint32(0o100644)))
		Expect(string(byName["etc/ssl/certs/ca-certificates.crt"].data)).To(Equal(cert.pem))
	})

	It("leaves /etc/ssl out without a bundle", func() {
		bb := filepath.Join(GinkgoT().TempDir(), "busybox")
		Expect(os.WriteFile(bb, []byte("busybox"), 0o755)).To(Succeed())
		f, err := newInitramfs(bb, taskGuest("true"))
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		names, _ := archiveEntries(fileBytes(f))
		for _, n := range names {
			Expect(n).NotTo(HavePrefix("etc/ssl"))
		}
	})

	It("rejects contents without a network", func() {
		bb := filepath.Join(GinkgoT().TempDir(), "busybox")
		Expect(os.WriteFile(bb, []byte("busybox"), 0o755)).To(Succeed())
		held := heldInitramfs()
		_, err := newInitramfs(bb, guestContents{command: "true", nonce: testNonce})
		Expect(err).To(MatchError("writing the initramfs: no guest network"))
		Expect(heldInitramfs()).To(Equal(held))
	})
})

var _ = Describe("run with trusted certificates", func() {
	var (
		art     string
		scratch string
		certDir string
		logBuf  *bytes.Buffer
		rootfs  fixtureCert
		system  fixtureCert
	)

	BeforeEach(func() {
		art = makeArtifacts()
		scratch = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", GinkgoT().TempDir())
		logBuf = &bytes.Buffer{}
		rootfs, system = newFixtureCert("rootfs"), newFixtureCert("system")
		bundlePath := filepath.Join(scratch, "ca-certificates.crt")
		Expect(os.WriteFile(bundlePath, []byte(rootfs.pem), 0o644)).To(Succeed())
		orig := rootfsCABundles
		rootfsCABundles = []string{bundlePath}
		DeferCleanup(func() { rootfsCABundles = orig })
		certDir = filepath.Join(scratch, "system")
		Expect(os.Mkdir(certDir, 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(certDir, "trusted-ca-1.crt"), []byte(system.pem), 0o644)).To(Succeed())
		GinkgoT().Setenv(systemCertPathEnv, certDir)
	})

	runVM := func(kind backend.Kind) int {
		return run([]string{"--backend", string(kind), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}, log.New(logBuf, "", 0))
	}

	// guestArchive runs a VM of kind whose fake hypervisor copies the
	// initramfs, and returns its entries by name.
	guestArchive := func(kind backend.Kind) map[string]cpioEntry {
		hv := "qemu/ld-linux-x86-64.so.2"
		if kind == backend.VMFirecracker {
			hv = "firecracker/firecracker"
		}
		initrdCopy := filepath.Join(scratch, string(kind)+".initrd")
		writeFakeHypervisor(filepath.Join(art, hv), `cat "$initrd" > `+shellQuote(initrdCopy)+"\n")
		Expect(runVM(kind)).To(Equal(0), logBuf.String())
		raw, err := os.ReadFile(initrdCopy)
		Expect(err).NotTo(HaveOccurred())
		_, byName := archiveEntries(raw)
		return byName
	}

	It("gives the guest the container's bundle and the system certificates, and points SSL_CERT_FILE at them", func() {
		for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			byName := guestArchive(kind)
			Expect(bundleCerts(byName["etc/ssl/certs/ca-certificates.crt"].data)).To(Equal([][]byte{rootfs.der, system.der}), string(kind))
			Expect(string(byName["rvm/env"].data)).To(ContainSubstring("export SSL_CERT_FILE='/etc/ssl/certs/ca-certificates.crt'\n"))
			Expect(string(byName["rvm/env"].data)).NotTo(ContainSubstring(systemCertPathEnv))
		}
	})

	It("keeps the app's own SSL_CERT_FILE", func() {
		GinkgoT().Setenv(sslCertFileEnv, "/home/vcap/app/certs.pem")
		byName := guestArchive(backend.VMQemu)
		Expect(byName).To(HaveKey("etc/ssl/certs/ca-certificates.crt"))
		Expect(string(byName["rvm/env"].data)).To(ContainSubstring("export SSL_CERT_FILE='/home/vcap/app/certs.pem'\n"))
	})

	It("sets no SSL_CERT_FILE when there is no certificate", func() {
		rootfsCABundles = []string{filepath.Join(scratch, "nope")}
		Expect(os.Remove(filepath.Join(certDir, "trusted-ca-1.crt"))).To(Succeed())
		byName := guestArchive(backend.VMQemu)
		Expect(byName).NotTo(HaveKey("etc/ssl/certs/ca-certificates.crt"))
		Expect(string(byName["rvm/env"].data)).NotTo(ContainSubstring(sslCertFileEnv))
		Expect(logBuf.String()).To(ContainSubstring("found no trusted certificates for the guest"))
	})

	It("exits 125 before the hypervisor starts when the certificates are over the cap", func() {
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		big := filepath.Join(certDir, "big.crt")
		Expect(os.WriteFile(big, []byte(system.pem), 0o644)).To(Succeed())
		Expect(os.Truncate(big, maxCABundleBytes+1)).To(Succeed())
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("the trusted certificates for the guest are over the 2097152 bytes a guest may have"))
		Expect(argvFile).NotTo(BeAnExistingFile())
	})
})
