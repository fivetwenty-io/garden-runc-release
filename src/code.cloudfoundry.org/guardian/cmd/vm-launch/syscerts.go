//go:build linux

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// The operator's trusted certificates, as files. Under runC, Diego's executor
// bind-mounts a directory of them read-only into the container, usually at
// /etc/cf-system-certificates, and sets CF_SYSTEM_CERT_PATH to its path. The
// guest has no such mount, so vm-launch reads the files from the path the
// variable names, and the guest installs them at the same path with the same
// names and bytes. A guest with a stack puts them on a tmpfs in the app root
// (see guestSystemCertsSetup), as the instance identity pair is. The rvm.6
// guest, which runs the command as root on the initramfs, gets them at the
// path in the initramfs itself.
const (
	// maxSystemCertFiles caps how many files the guest gets from the
	// directory, and maxSystemCertBytes caps the size of all of them
	// together and of each. The files stay in guest RAM for the life of the
	// guest, once in the initramfs and once on the tmpfs, and the cap is the
	// one that the guest's CA bundle has.
	maxSystemCertFiles = 256
	maxSystemCertBytes = maxCABundleBytes

	// guestSystemCertsStage is the initramfs directory that holds the files
	// of a guest with a stack until stage 2 copies them into the app root.
	guestSystemCertsStage = "/rvm/syscerts"

	// systemCertsTmpfsBytes is the size of the tmpfs that holds the files in
	// the app root. It leaves a page for each file beyond its bytes, because
	// a tmpfs counts whole pages.
	systemCertsTmpfsBytes = maxSystemCertBytes + maxSystemCertFiles*4096
)

// systemCertNamePattern is the file names that the guest copies. Such a name
// needs no quoting in a shell word or a cpio header, and it cannot be "." or
// "..", or start with a dot.
var systemCertNamePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

// systemCertReserved are the first path components that the guest uses for
// itself, so that a directory below one of them is never installed.
var systemCertReserved = map[string]bool{"bin": true, "dev": true, "proc": true, "rvm": true, "sys": true}

// errSystemCertsTooLarge reports trusted certificate files over the limits.
var errSystemCertsTooLarge = fmt.Errorf("the trusted certificate files for the guest are over the %d files or %d bytes a guest may have", maxSystemCertFiles, maxSystemCertBytes)

// systemCerts is the directory CF_SYSTEM_CERT_PATH names and the files vm-launch
// read from it, in name order.
type systemCerts struct {
	dir   string
	files []systemCertFile
}

// systemCertFile is one file of the directory.
type systemCertFile struct {
	name string
	data []byte
}

// usableSystemCertDir reports whether dir is a path the guest installs the
// trusted certificates at: an absolute path in its cleaned form, on one line,
// that is not the root, not below a directory the guest uses for itself, and
// not in the CA store at /etc/ssl or the launcher's /tmp/lifecycle.
func usableSystemCertDir(dir string) bool {
	if !path.IsAbs(dir) || path.Clean(dir) != dir || dir == "/" || strings.ContainsAny(dir, "\n\x00") {
		return false
	}
	first := strings.SplitN(strings.TrimPrefix(dir, "/"), "/", 2)[0]
	return !systemCertReserved[first] && !underDir(dir, "/etc/ssl") && !underDir(dir, "/tmp/lifecycle")
}

// underDir reports whether p is dir or a path below it.
func underDir(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// readSystemCerts reads the regular files directly under the directory that
// CF_SYSTEM_CERT_PATH names, following symbolic links, in name order. It
// returns nil when the variable is unset or empty, when the path is not one
// the guest installs at, when the directory does not exist or cannot be read,
// and when it holds no usable file, with one line that says why. Files whose
// names the guest cannot copy, that cannot be read, or that are not regular
// files are left out and counted in one line. More than maxSystemCertFiles
// files, or more than maxSystemCertBytes bytes in all, is an error, because a
// guest that silently lacks a trusted certificate fails in ways that are hard
// to trace. No line holds a file's bytes.
func readSystemCerts(lookupEnv func(string) (string, bool), logger *log.Logger) (*systemCerts, error) {
	dir, ok := lookupEnv(systemCertPathEnv)
	if !ok || dir == "" {
		return nil, nil
	}
	if !usableSystemCertDir(dir) {
		logger.Printf("%s %q is not a path the guest installs the trusted certificates at; the guest gets no %s", systemCertPathEnv, dir, systemCertPathEnv)
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		logger.Printf("%s %s does not exist; the guest gets no %s", systemCertPathEnv, dir, systemCertPathEnv)
		return nil, nil
	case err != nil:
		logger.Printf("reading %s %s: %v; the guest gets no %s", systemCertPathEnv, dir, errnoOf(err), systemCertPathEnv)
		return nil, nil
	}

	certs := &systemCerts{dir: dir}
	total, badName, unreadable, notRegular := 0, 0, 0, 0
	for _, e := range entries {
		if !systemCertNamePattern.MatchString(e.Name()) {
			badName++
			continue
		}
		data, err := readCertFile(filepath.Join(dir, e.Name()))
		switch {
		case errors.Is(err, errCABundleTooLarge):
			return nil, errSystemCertsTooLarge
		case errors.Is(err, errNotRegular):
			notRegular++
			continue
		case err != nil:
			unreadable++
			continue
		}
		total += len(data)
		if len(certs.files) == maxSystemCertFiles || total > maxSystemCertBytes {
			return nil, errSystemCertsTooLarge
		}
		certs.files = append(certs.files, systemCertFile{name: e.Name(), data: data})
	}
	if left := badName + unreadable + notRegular; left > 0 {
		logger.Printf("leaving %d files out of the guest's %s: %d with a name the guest does not copy, %d unreadable, %d not regular files", left, systemCertPathEnv, badName, unreadable, notRegular)
	}
	if len(certs.files) == 0 {
		logger.Printf("%s %s holds no file to copy; the guest gets no %s", systemCertPathEnv, dir, systemCertPathEnv)
		return nil, nil
	}
	return certs, nil
}

// dirOf returns the directory the guest installs the files at, or "" for no
// certificates.
func (c *systemCerts) dirOf() string {
	if c == nil {
		return ""
	}
	return c.dir
}

// guestSystemCertsSetup is the setup step of a guest with a stack and
// trusted certificates, before the start tag. It installs the files that the
// initramfs holds at guestSystemCertsStage in the app root at certs.dir, on a
// tmpfs with the options that keep them out of reach of devices and
// programs, with mode 0644, owned by root, and read-only once copied, as a
// container sees the directory. It refuses a symbolic link at any component
// of the path in the app root, because stage 2 runs outside the app root and
// would follow the link to a path of the guest's own. Any failure is a named
// setup step, because an app that expects its trusted certificates should
// not start without them.
func guestSystemCertsSetup(certs *systemCerts) string {
	if certs == nil {
		return ""
	}
	dest := guestAppRoot + certs.dir
	var links []string
	for p := dest; len(p) > len(guestAppRoot); p = path.Dir(p) {
		links = append([]string{"[ ! -L " + shellQuote(p) + " ]"}, links...)
	}
	q := shellQuote(dest)
	return strings.Join(links, " && ") + ` || rvm_fail "a component of ` + certs.dir + ` in the app root is a symbolic link, so the trusted certificates cannot be installed there"
mkdir -p ` + q + ` || rvm_fail "creating ` + certs.dir + ` in the app root failed"
mount -t tmpfs -o mode=0755,size=` + fmt.Sprint(systemCertsTmpfsBytes) + `,nosuid,nodev,noexec tmpfs ` + q + ` || rvm_fail "mounting a tmpfs at ` + certs.dir + ` in the app root failed"
cp ` + guestSystemCertsStage + `/* ` + q + `/ && chmod 0644 ` + q + `/* || rvm_fail "copying the trusted certificates into ` + certs.dir + ` in the app root failed"
mount -o remount,ro ` + q + ` || rvm_fail "making ` + certs.dir + ` in the app root read-only failed"
`
}

// stackSteps are the initramfs entries of a guest with a stack: the files in
// guestSystemCertsStage, which stage 2 copies into the app root.
func (c *systemCerts) stackSteps(cw *cpioWriter) []func() error {
	if c == nil {
		return nil
	}
	stage := strings.TrimPrefix(guestSystemCertsStage, "/")
	steps := []func() error{func() error { return cw.Dir(stage, 0o755) }}
	for _, f := range c.files {
		steps = append(steps, c.fileStep(cw, stage+"/"+f.name, f))
	}
	return steps
}

// busyboxSteps are the initramfs entries of the rvm.6 guest: the directory
// and its files, at their own path.
func (c *systemCerts) busyboxSteps(cw *cpioWriter) []func() error {
	if c == nil {
		return nil
	}
	var steps []func() error
	dir := ""
	for _, part := range strings.Split(strings.TrimPrefix(c.dir, "/"), "/") {
		dir = path.Join(dir, part)
		if dir == "etc" || dir == "tmp" {
			continue
		}
		steps = append(steps, func(dir string) func() error {
			return func() error { return cw.Dir(dir, 0o755) }
		}(dir))
	}
	for _, f := range c.files {
		steps = append(steps, c.fileStep(cw, strings.TrimPrefix(c.dir, "/")+"/"+f.name, f))
	}
	return steps
}

func (c *systemCerts) fileStep(cw *cpioWriter, name string, f systemCertFile) func() error {
	return func() error { return cw.File(name, 0o644, int64(len(f.data)), strings.NewReader(string(f.data))) }
}

// fallbackPrep is the commands that give the busybox guest the trusted
// certificate files from guestSystemCertsStage at their own path, which the
// guest that falls back runs as root on the initramfs. Without certificates
// it is a no-op.
func (c *systemCerts) fallbackPrep() string {
	if c == nil {
		return ":\n"
	}
	q := shellQuote(c.dir)
	return "mkdir -p " + q + " && cp " + guestSystemCertsStage + "/* " + q + "/ && chmod 0644 " + q + "/*\n"
}
