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
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// identityCA signs the leaf certificates that the identity specs write.
type identityCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newIdentityCA() *identityCA {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "instance identity test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return &identityCA{key: key, cert: cert}
}

// issue returns a certificate with the given serial and expiry, signed by the
// CA, and its key, both as PEM.
func (ca *identityCA) issue(serial int64, notAfter time.Time) (certPEM, keyPEM []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "instance"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	Expect(err).NotTo(HaveOccurred())
	keyDER, err := x509.MarshalECPrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// renameInto writes data beside path and renames it over path, as Diego does.
func renameInto(path string, data []byte) {
	tmp := path + ".tmp"
	Expect(os.WriteFile(tmp, data, 0o644)).To(Succeed())
	Expect(os.Rename(tmp, path)).To(Succeed())
}

var _ = Describe("the instance identity pair", func() {
	var (
		ca       *identityCA
		certPath string
		keyPath  string
	)

	BeforeEach(func() {
		ca = newIdentityCA()
		dir := GinkgoT().TempDir()
		certPath = filepath.Join(dir, "instance.crt")
		keyPath = filepath.Join(dir, "instance.key")
	})

	Describe("readInstanceIdentity", func() {
		It("reads a matching pair with its serial and expiry", func() {
			notAfter := time.Now().Add(3 * time.Hour).Truncate(time.Second)
			crt, key := ca.issue(4242, notAfter)
			renameInto(certPath, crt)
			renameInto(keyPath, key)

			id, err := readInstanceIdentity(certPath, keyPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(id).NotTo(BeNil())
			Expect(id.cert).To(Equal(crt))
			Expect(id.key).To(Equal(key))
			Expect(id.serial).To(Equal("4242"))
			Expect(id.notAfter.Equal(notAfter)).To(BeTrue())
			Expect(id.stamp.cert.size).To(Equal(int64(len(crt))))
			Expect(id.stamp.key.size).To(Equal(int64(len(key))))
			Expect(id.stamp.cert.ino).NotTo(BeZero())
		})

		It("returns nil and no error when a path is empty or missing", func() {
			crt, key := ca.issue(1, time.Now().Add(time.Hour))
			renameInto(certPath, crt)
			renameInto(keyPath, key)

			for _, paths := range [][2]string{
				{"", keyPath}, {certPath, ""}, {"", ""},
				{certPath, keyPath + ".gone"}, {certPath + ".gone", keyPath},
			} {
				id, err := readInstanceIdentity(paths[0], paths[1])
				Expect(err).NotTo(HaveOccurred(), "%q", paths)
				Expect(id).To(BeNil(), "%q", paths)
			}
		})

		It("refuses a key that does not belong to the certificate", func() {
			crt, _ := ca.issue(1, time.Now().Add(time.Hour))
			_, otherKey := ca.issue(2, time.Now().Add(time.Hour))
			renameInto(certPath, crt)
			renameInto(keyPath, otherKey)

			id, err := readInstanceIdentity(certPath, keyPath)
			Expect(err).To(HaveOccurred())
			Expect(id).To(BeNil())
		})

		It("refuses a file over 64 KiB", func() {
			crt, key := ca.issue(1, time.Now().Add(time.Hour))
			renameInto(certPath, append(crt, bytes.Repeat([]byte("#"), maxIdentityFileBytes)...))
			renameInto(keyPath, key)

			id, err := readInstanceIdentity(certPath, keyPath)
			Expect(err).To(MatchError(ContainSubstring("over the 65536 bytes")))
			Expect(id).To(BeNil())

			renameInto(certPath, crt)
			renameInto(keyPath, append(key, bytes.Repeat([]byte("#"), maxIdentityFileBytes)...))
			id, err = readInstanceIdentity(certPath, keyPath)
			Expect(err).To(HaveOccurred())
			Expect(id).To(BeNil())
		})

		It("gives a different stamp after the files are replaced", func() {
			crt, key := ca.issue(1, time.Now().Add(time.Hour))
			renameInto(certPath, crt)
			renameInto(keyPath, key)
			first, err := readInstanceIdentity(certPath, keyPath)
			Expect(err).NotTo(HaveOccurred())

			crt, key = ca.issue(2, time.Now().Add(time.Hour))
			renameInto(keyPath, key)
			renameInto(certPath, crt)
			second, err := readInstanceIdentity(certPath, keyPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(second.stamp).NotTo(Equal(first.stamp))
		})
	})

	Describe("credFrames", func() {
		var id *instanceIdentity

		BeforeEach(func() {
			crt, key := ca.issue(7, time.Now().Add(time.Hour))
			renameInto(certPath, crt)
			renameInto(keyPath, key)
			var err error
			id, err = readInstanceIdentity(certPath, keyPath)
			Expect(err).NotTo(HaveOccurred())
		})

		It("names its tags from the nonce", func() {
			Expect(credTag("abc")).To(Equal("RVM_CRED_abc="))
			Expect(credOKTag("abc")).To(Equal("RVM_CREDOK_abc="))
			Expect(credBadTag("abc")).To(Equal("RVM_CREDBAD_abc="))
		})

		It("reassembles into the exact bytes, with the right counts and digest", func() {
			frames := credFrames("n0nce", 3, id)
			tag := "RVM_CRED_n0nce="

			Expect(frames[0]).To(Equal(tag + "begin 3"))
			var crt, key []string
			for _, line := range frames[1 : len(frames)-1] {
				Expect(line).To(HavePrefix(tag))
				kind, text, _ := strings.Cut(strings.TrimPrefix(line, tag), " ")
				switch kind {
				case "crt":
					crt = append(crt, text)
				case "key":
					key = append(key, text)
				default:
					Fail("unexpected frame " + line)
				}
			}
			gotCrt := strings.Join(crt, "\n") + "\n"
			gotKey := strings.Join(key, "\n") + "\n"
			Expect(gotCrt).To(Equal(string(id.cert)))
			Expect(gotKey).To(Equal(string(id.key)))

			sum := sha256.Sum256([]byte(gotCrt + gotKey))
			Expect(frames[len(frames)-1]).To(Equal(fmt.Sprintf("%send 3 %d %d %s", tag, len(crt), len(key), hex.EncodeToString(sum[:]))))
		})

		It("keeps every line short and free of line endings", func() {
			// The end line holds a 64 character digest after a tag that
			// carries a 16 character nonce, so it runs a little past 100
			// bytes. Every other line is a tag and one PEM line.
			frames := credFrames("0123456789abcdef", 12, id)
			for _, line := range frames[:len(frames)-1] {
				Expect(len(line)).To(BeNumerically("<", 100), line)
			}
			Expect(len(frames[len(frames)-1])).To(BeNumerically("<", 120))
			for _, line := range frames {
				Expect(line).NotTo(ContainSubstring("\n"))
				Expect(line).NotTo(ContainSubstring("\r"))
			}
		})
	})

	Describe("the watcher", func() {
		var (
			mu     sync.Mutex
			pushed []*instanceIdentity
			failed error
			stop   chan struct{}
			done   chan struct{}
			logs   *lockedBuffer
			w      *credWatcher
		)

		pushes := func() int {
			mu.Lock()
			defer mu.Unlock()
			return len(pushed)
		}

		write := func(serial int64) (crt, key []byte) {
			crt, key = ca.issue(serial, time.Now().Add(time.Hour))
			renameInto(keyPath, key)
			renameInto(certPath, crt)
			return crt, key
		}

		start := func(sent *instanceIdentity) {
			logs = &lockedBuffer{}
			w = newCredWatcher(certPath, keyPath, sent, 10*time.Millisecond, func(id *instanceIdentity) error {
				mu.Lock()
				defer mu.Unlock()
				pushed = append(pushed, id)
				return failed
			}, log.New(logs, "", 0))
			stop = make(chan struct{})
			done = make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				w.run(stop)
			}()
		}

		BeforeEach(func() {
			pushed, failed = nil, nil
			write(100)
		})

		AfterEach(func() {
			close(stop)
			Eventually(done).Should(BeClosed())
		})

		sent := func() *instanceIdentity {
			id, err := readInstanceIdentity(certPath, keyPath)
			Expect(err).NotTo(HaveOccurred())
			return id
		}

		It("pushes nothing while the pair is as it was sent", func() {
			start(sent())
			Consistently(pushes, 200*time.Millisecond, 20*time.Millisecond).Should(BeZero())
		})

		It("pushes exactly once for a new key followed by a new certificate", func() {
			start(sent())
			crt, key := write(101)

			Eventually(pushes).Should(Equal(1))
			Consistently(pushes, 300*time.Millisecond, 20*time.Millisecond).Should(Equal(1))
			mu.Lock()
			defer mu.Unlock()
			Expect(pushed[0].cert).To(Equal(crt))
			Expect(pushed[0].key).To(Equal(key))
			Expect(pushed[0].serial).To(Equal("101"))
		})

		It("pushes nothing while only the new key is in place", func() {
			start(sent())
			_, key := ca.issue(102, time.Now().Add(time.Hour))
			renameInto(keyPath, key)

			Consistently(pushes, 300*time.Millisecond, 20*time.Millisecond).Should(BeZero())
			Expect(logs.String()).NotTo(ContainSubstring("PRIVATE KEY"))
		})

		It("pushes the pair again when the guest reports a failure", func() {
			start(sent())
			write(103)
			Eventually(pushes).Should(Equal(1))

			w.acked(1, false)
			Eventually(pushes).Should(Equal(2))
			mu.Lock()
			Expect(pushed[1]).To(BeIdenticalTo(pushed[0]))
			mu.Unlock()
		})

		It("pushes the pair again when no answer comes in time", func() {
			start(sent())
			w.mu.Lock()
			w.ackTimeout = 50 * time.Millisecond
			w.mu.Unlock()
			write(104)
			Eventually(pushes).Should(BeNumerically(">=", 2))
		})

		It("stops pushing a pair once the guest installs it", func() {
			start(sent())
			w.mu.Lock()
			w.ackTimeout = 50 * time.Millisecond
			w.mu.Unlock()
			write(105)
			Eventually(pushes).Should(Equal(1))
			w.acked(1, true)
			Consistently(pushes, 300*time.Millisecond, 20*time.Millisecond).Should(Equal(1))
		})

		It("gives up after the sixth failure and logs one line", func() {
			start(sent())
			write(106)
			for n := 1; n <= 6; n++ {
				Eventually(pushes).Should(Equal(n))
				w.acked(1, false)
			}
			Consistently(pushes, 400*time.Millisecond, 20*time.Millisecond).Should(Equal(6))
			Expect(strings.Count(logs.String(), "giving up")).To(Equal(1))
		})

		It("pushes the next change after giving up", func() {
			start(sent())
			write(107)
			for n := 1; n <= 6; n++ {
				Eventually(pushes).Should(Equal(n))
				w.acked(1, false)
			}
			Consistently(pushes, 200*time.Millisecond, 20*time.Millisecond).Should(Equal(6))
			write(108)
			Eventually(pushes).Should(Equal(7))
		})

		It("counts a push that errors as a failure and logs no file contents", func() {
			mu.Lock()
			failed = io.ErrClosedPipe
			mu.Unlock()
			start(sent())
			crt, key := write(109)
			Eventually(pushes).Should(Equal(6))
			Consistently(pushes, 300*time.Millisecond, 20*time.Millisecond).Should(Equal(6))
			Expect(logs.String()).NotTo(ContainSubstring(string(bytes.Split(crt, []byte("\n"))[1])))
			Expect(logs.String()).NotTo(ContainSubstring(string(bytes.Split(key, []byte("\n"))[1])))
		})
	})
})

// lockedBuffer is a log destination that specs also read.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
