//go:build linux

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"syscall"
)

// The guest trust store. A runc app trusts the certificates of its root
// filesystem's CA bundle, which the cell's rootfs setup extends with the
// operator's trusted certificates, and it can read the files under
// CF_SYSTEM_CERT_PATH. The guest has neither, so vm-launch copies both into
// one bundle in the initramfs at the path that Go, OpenSSL on Debian and
// Ubuntu, GnuTLS, and rustls look at first.
const (
	guestCABundlePath = "/etc/ssl/certs/ca-certificates.crt"
	sslCertFileEnv    = "SSL_CERT_FILE"

	// maxCABundleBytes caps the guest bundle and every file read for it. A
	// stock Mozilla bundle is about 220 KiB, so the cap leaves room for
	// roughly ten times that. The bundle stays in guest RAM for the life of
	// the guest, and 2 MiB is under 2% of the smallest guest.
	maxCABundleBytes = 2 << 20
)

// rootfsCABundles are the CA bundle paths of the common Linux distributions,
// in the order Go's crypto/x509 tries them. The container's bundle is the
// first of them that vm-launch can read, as it is for Go.
var rootfsCABundles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

// errCABundleTooLarge reports trusted certificates over maxCABundleBytes.
var errCABundleTooLarge = fmt.Errorf("the trusted certificates for the guest are over the %d bytes a guest may have", maxCABundleBytes)

// caBundleBuilder collects distinct certificates as PEM, in the order they
// are added, and counts the files it leaves out.
type caBundleBuilder struct {
	pem        []byte
	certs      int
	seen       map[[sha256.Size]byte]bool
	unreadable int
	notPEM     int
	notRegular int
}

// guestCABundle returns the guest's CA bundle: the certificates of the
// container's own bundle (the first readable file of bundles) followed by
// those of every file directly under the directory CF_SYSTEM_CERT_PATH
// names, in name order, each certificate once. Only CERTIFICATE blocks that
// parse as X.509 certificates are copied, re-encoded as PEM, so nothing else
// a file holds, such as a key or a comment, reaches the guest.
//
// A file that cannot be opened or read, one that is not a regular file once
// symbolic links are followed, and one with no certificate are left out and
// counted in one line. A CF_SYSTEM_CERT_PATH that is unset, empty, or names
// no directory is not an error. A bundle or a file over maxCABundleBytes is
// an error, because a guest that silently lacks a trusted certificate fails
// in ways that are hard to trace. The result is nil when there is no
// certificate at all. No line or error holds a certificate.
func guestCABundle(bundles []string, lookupEnv func(string) (string, bool), logger *log.Logger) ([]byte, error) {
	b := &caBundleBuilder{seen: map[[sha256.Size]byte]bool{}}
	for _, path := range bundles {
		data, err := readCertFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if errors.Is(err, errCABundleTooLarge) {
			return nil, err
		}
		if err != nil {
			b.leaveOut(err)
			continue
		}
		if err := b.add(data); err != nil {
			return nil, err
		}
		break
	}

	if dir, ok := lookupEnv(systemCertPathEnv); ok && dir != "" {
		if err := b.addDir(dir, logger); err != nil {
			return nil, err
		}
	}

	if left := b.unreadable + b.notPEM + b.notRegular; left > 0 {
		logger.Printf("leaving %d files out of the guest's trusted certificates: %d unreadable, %d not regular files, %d with no PEM certificate", left, b.unreadable, b.notRegular, b.notPEM)
	}
	if b.certs == 0 {
		logger.Print("found no trusted certificates for the guest; it gets no CA bundle")
		return nil, nil
	}
	return b.pem, nil
}

// addDir adds the certificates of every entry directly under dir.
func (b *caBundleBuilder) addDir(dir string, logger *log.Logger) error {
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		logger.Printf("%s %s does not exist; the guest gets no certificates from it", systemCertPathEnv, dir)
		return nil
	case err != nil:
		logger.Printf("reading %s %s: %v; the guest gets no certificates from it", systemCertPathEnv, dir, errnoOf(err))
		return nil
	}
	for _, e := range entries {
		data, err := readCertFile(filepath.Join(dir, e.Name()))
		if errors.Is(err, errCABundleTooLarge) {
			return err
		}
		if err != nil {
			b.leaveOut(err)
			continue
		}
		if err := b.add(data); err != nil {
			return err
		}
	}
	return nil
}

// errNotRegular reports a certificate path that is not a regular file.
var errNotRegular = errors.New("not a regular file")

// leaveOut counts a file that is left out for err.
func (b *caBundleBuilder) leaveOut(err error) {
	if errors.Is(err, errNotRegular) {
		b.notRegular++
		return
	}
	b.unreadable++
}

// add appends the certificates in data that it does not hold yet, and counts
// data as a file with no PEM certificate when it holds none at all.
func (b *caBundleBuilder) add(data []byte) error {
	found := false
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			continue
		}
		found = true
		sum := sha256.Sum256(block.Bytes)
		if b.seen[sum] {
			continue
		}
		encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
		if len(b.pem)+len(encoded) > maxCABundleBytes {
			return errCABundleTooLarge
		}
		b.seen[sum] = true
		b.pem = append(b.pem, encoded...)
		b.certs++
	}
	if !found {
		b.notPEM++
	}
	return nil
}

// readCertFile reads path, following symbolic links, when it is a regular
// file of at most maxCABundleBytes. A missing file gives an error that
// matches fs.ErrNotExist. It never opens anything but a regular file, so a
// device node or a FIFO under the directory can neither block it nor see an
// open, and it opens without blocking in case the file was replaced.
func readCertFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotRegular
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info, err = f.Stat(); err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotRegular
	}
	if info.Size() > maxCABundleBytes {
		return nil, fmt.Errorf("%s: %w", path, errCABundleTooLarge)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCABundleBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCABundleBytes {
		return nil, fmt.Errorf("%s: %w", path, errCABundleTooLarge)
	}
	return data, nil
}

// errnoOf returns the errno inside err, when there is one, so that a log
// line names the failure without repeating a path.
func errnoOf(err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	return err
}
