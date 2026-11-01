//go:build linux

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("the trusted certificate files", func() {
	var (
		dir     string
		logBuf  *bytes.Buffer
		logger  *log.Logger
		lookup  func(string) (string, bool)
		writeIn func(name, content string)
	)

	BeforeEach(func() {
		dir = filepath.Join(GinkgoT().TempDir(), "etc", "cf-system-certificates")
		Expect(os.MkdirAll(dir, 0o755)).To(Succeed())
		logBuf = &bytes.Buffer{}
		logger = log.New(logBuf, "", 0)
		lookup = func(name string) (string, bool) {
			if name == systemCertPathEnv {
				return dir, true
			}
			return "", false
		}
		writeIn = func(name, content string) {
			GinkgoHelper()
			Expect(os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)).To(Succeed())
		}
	})

	Describe("readSystemCerts", func() {
		It("reads each regular file under the directory, in name order, with its bytes unchanged", func() {
			writeIn("b.crt", "second\n")
			writeIn("a.crt", "first\n")
			Expect(os.Symlink(filepath.Join(dir, "a.crt"), filepath.Join(dir, "link.crt"))).To(Succeed())

			certs, err := readSystemCerts(lookup, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(certs.dir).To(Equal(dir))
			Expect(certs.files).To(Equal([]systemCertFile{
				{name: "a.crt", data: []byte("first\n")},
				{name: "b.crt", data: []byte("second\n")},
				{name: "link.crt", data: []byte("first\n")},
			}))
			Expect(logBuf.String()).To(BeEmpty())
		})

		It("gives nothing, without a line, when the variable is unset or empty", func() {
			for _, lookup := range []func(string) (string, bool){
				func(string) (string, bool) { return "", false },
				func(string) (string, bool) { return "", true },
			} {
				certs, err := readSystemCerts(lookup, logger)
				Expect(err).NotTo(HaveOccurred())
				Expect(certs).To(BeNil())
			}
			Expect(logBuf.String()).To(BeEmpty())
		})

		DescribeTable("gives nothing, with one line, for a path the guest does not install at",
			func(path string) {
				certs, err := readSystemCerts(func(string) (string, bool) { return path, true }, logger)
				Expect(err).NotTo(HaveOccurred())
				Expect(certs).To(BeNil())
				Expect(strings.Count(logBuf.String(), "\n")).To(Equal(1), logBuf.String())
			},
			Entry("relative", "etc/certs"),
			Entry("not cleaned", "/etc/certs/../certs"),
			Entry("the root", "/"),
			Entry("with a trailing slash", "/etc/certs/"),
			Entry("below the guest's own /rvm", "/rvm/app"),
			Entry("below /proc", "/proc/certs"),
			Entry("below the launcher's directory", "/tmp/lifecycle/certs"),
			Entry("in the CA store", "/etc/ssl/certs"),
			Entry("on two lines", "/etc/a\n/b"),
		)

		It("gives nothing, with one line, when the directory does not exist", func() {
			Expect(os.RemoveAll(dir)).To(Succeed())
			certs, err := readSystemCerts(lookup, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(certs).To(BeNil())
			Expect(logBuf.String()).To(ContainSubstring("does not exist"))
		})

		It("leaves out names the guest does not copy, directories, and broken links, and counts them in one line", func() {
			writeIn("good.crt", "good\n")
			writeIn(".hidden", "hidden\n")
			writeIn("has space.crt", "space\n")
			Expect(os.Mkdir(filepath.Join(dir, "sub"), 0o755)).To(Succeed())
			Expect(os.Symlink("/no/such/file", filepath.Join(dir, "broken"))).To(Succeed())

			certs, err := readSystemCerts(lookup, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(certs.files).To(Equal([]systemCertFile{{name: "good.crt", data: []byte("good\n")}}))
			Expect(logBuf.String()).To(Equal(fmt.Sprintf(
				"leaving 4 files out of the guest's %s: 2 with a name the guest does not copy, 1 unreadable, 1 not regular files\n", systemCertPathEnv)))
		})

		It("gives nothing, with one line, when no file is usable", func() {
			writeIn(".hidden", "hidden\n")
			certs, err := readSystemCerts(lookup, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(certs).To(BeNil())
			Expect(logBuf.String()).To(ContainSubstring("holds no file to copy"))
		})

		It("accepts exactly maxSystemCertFiles files and refuses one more", func() {
			for i := 0; i < maxSystemCertFiles; i++ {
				writeIn(fmt.Sprintf("c%03d.crt", i), "x")
			}
			certs, err := readSystemCerts(lookup, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(certs.files).To(HaveLen(maxSystemCertFiles))

			writeIn("c999.crt", "x")
			_, err = readSystemCerts(lookup, logger)
			Expect(err).To(MatchError(errSystemCertsTooLarge))
		})

		It("accepts files that add up to maxSystemCertBytes and refuses one byte more, and refuses a file over the cap", func() {
			writeIn("a.crt", strings.Repeat("a", maxSystemCertBytes/2))
			writeIn("b.crt", strings.Repeat("b", maxSystemCertBytes/2))
			certs, err := readSystemCerts(lookup, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(certs.files).To(HaveLen(2))

			writeIn("c.crt", "c")
			_, err = readSystemCerts(lookup, logger)
			Expect(err).To(MatchError(errSystemCertsTooLarge))

			Expect(os.Remove(filepath.Join(dir, "c.crt"))).To(Succeed())
			writeIn("a.crt", strings.Repeat("a", maxSystemCertBytes+1))
			_, err = readSystemCerts(lookup, logger)
			Expect(err).To(MatchError(errSystemCertsTooLarge))
		})

		It("never writes a file's bytes to the log", func() {
			writeIn("good.crt", "secret-bytes\n")
			writeIn(".hidden", "secret-bytes\n")
			_, err := readSystemCerts(lookup, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(logBuf.String()).NotTo(ContainSubstring("secret-bytes"))
		})
	})

	Describe("the guest environment", func() {
		env := map[string]string{"A": "1", systemCertPathEnv: "/the/container/path"}

		It("exports CF_SYSTEM_CERT_PATH with the guest's directory in both guests, and drops it without one", func() {
			logger := log.New(&bytes.Buffer{}, "", 0)
			for name, build := range map[string]func(string) (string, error){
				"busybox": func(certDir string) (string, error) { return buildGuestEnvWithCerts(env, 320, certDir, logger) },
				"stack": func(certDir string) (string, error) {
					return buildStackGuestEnvWithCerts(env, 320, false, certDir, logger)
				},
				"stack with identity": func(certDir string) (string, error) {
					return buildStackGuestEnvWithCerts(env, 320, true, certDir, logger)
				},
			} {
				with, err := build("/etc/cf-system-certificates")
				Expect(err).NotTo(HaveOccurred(), name)
				Expect(with).To(ContainSubstring("export CF_SYSTEM_CERT_PATH='/etc/cf-system-certificates'\n"), name)
				Expect(with).NotTo(ContainSubstring("/the/container/path"), name)

				without, err := build("")
				Expect(err).NotTo(HaveOccurred(), name)
				Expect(without).NotTo(ContainSubstring("CF_SYSTEM_CERT_PATH"), name)
			}
		})

		It("is what buildGuestEnv and buildStackGuestEnv give without a directory", func() {
			logger := log.New(&bytes.Buffer{}, "", 0)
			plain, err := buildGuestEnv(env, 320, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(buildGuestEnvWithCerts(env, 320, "", logger)).To(Equal(plain))
			stack, err := buildStackGuestEnv(env, 320, true, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(buildStackGuestEnvWithCerts(env, 320, true, "", logger)).To(Equal(stack))
		})
	})

	Describe("guestSystemCertsSetup", func() {
		certs := &systemCerts{dir: "/etc/cf-system-certificates", files: []systemCertFile{{name: "a.crt", data: []byte("a")}}}

		It("is empty without certificates", func() {
			Expect(guestSystemCertsSetup(nil)).To(BeEmpty())
		})

		It("refuses a link at every component, mounts a read-only tmpfs, and copies the staged files with mode 0644", func() {
			setup := guestSystemCertsSetup(certs)
			Expect(setup).To(HavePrefix("[ ! -L '/rvm/app/etc' ] && [ ! -L '/rvm/app/etc/cf-system-certificates' ] || rvm_fail "))
			Expect(setup).To(ContainSubstring("mkdir -p '/rvm/app/etc/cf-system-certificates' ||"))
			Expect(setup).To(ContainSubstring(fmt.Sprintf("mount -t tmpfs -o mode=0755,size=%d,nosuid,nodev,noexec tmpfs '/rvm/app/etc/cf-system-certificates' ||", systemCertsTmpfsBytes)))
			Expect(setup).To(ContainSubstring("cp /rvm/syscerts/* '/rvm/app/etc/cf-system-certificates'/ && chmod 0644 '/rvm/app/etc/cf-system-certificates'/* ||"))
			Expect(setup).To(ContainSubstring("mount -o remount,ro '/rvm/app/etc/cf-system-certificates' ||"))
			Expect(strings.Count(setup, "\n")).To(Equal(5))
		})

		It("runs before the start tag in the stack guest's stage 2, with and without the run section", func() {
			setup := guestSystemCertsSetup(certs)
			plain := (&guestStack{systemCerts: certs}).initScript(testNonce)
			Expect(plain).To(ContainSubstring(setup))
			Expect(strings.Index(plain, setup)).To(BeNumerically("<", strings.Index(plain, "echo "+startTag(testNonce))))

			withIdentity := (&guestStack{systemCerts: certs, identity: &instanceIdentity{cert: []byte("c"), key: []byte("k")}}).initScript(testNonce)
			Expect(withIdentity).To(ContainSubstring(setup))
			Expect(strings.Index(withIdentity, setup)).To(BeNumerically("<", strings.Index(withIdentity, "echo "+startTag(testNonce))))

			Expect((&guestStack{}).initScript(testNonce)).NotTo(ContainSubstring("/rvm/syscerts"))
		})
	})

	Describe("the initramfs", func() {
		certs := &systemCerts{dir: "/etc/cf-system-certificates", files: []systemCertFile{
			{name: "a.crt", data: []byte("first\n")},
			{name: "b.crt", data: []byte("second\n")},
		}}

		build := func(g guestContents) map[string]cpioEntry {
			GinkgoHelper()
			bb := filepath.Join(GinkgoT().TempDir(), "busybox")
			Expect(os.WriteFile(bb, []byte("busybox"), 0o755)).To(Succeed())
			f, err := newInitramfs(bb, g)
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			_, byName := archiveEntries(fileBytes(f))
			return byName
		}

		It("holds the rvm.6 guest's files at their own path, readable by everyone", func() {
			g := taskGuest("true")
			g.systemCerts = certs
			entries := build(g)
			Expect(entries["etc/cf-system-certificates"].mode).To(Equal(uint32(0o040755)))
			Expect(entries["etc/cf-system-certificates/a.crt"].mode).To(Equal(uint32(0o100644)))
			Expect(string(entries["etc/cf-system-certificates/a.crt"].data)).To(Equal("first\n"))
			Expect(string(entries["etc/cf-system-certificates/b.crt"].data)).To(Equal("second\n"))
			Expect(entries).NotTo(HaveKey("rvm/syscerts"))
		})

		It("holds a deeper path's directories once each", func() {
			g := taskGuest("true")
			g.systemCerts = &systemCerts{dir: "/opt/trust/certs", files: certs.files}
			names := []string{}
			bb := filepath.Join(GinkgoT().TempDir(), "busybox")
			Expect(os.WriteFile(bb, []byte("busybox"), 0o755)).To(Succeed())
			f, err := newInitramfs(bb, g)
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			names, _ = archiveEntries(fileBytes(f))
			for _, want := range []string{"opt", "opt/trust", "opt/trust/certs", "opt/trust/certs/a.crt"} {
				Expect(names).To(ContainElement(want))
			}
			seen := map[string]bool{}
			for _, n := range names {
				Expect(seen[n]).To(BeFalse(), n)
				seen[n] = true
			}
		})

		It("holds the stack guest's files in /rvm/syscerts for stage 2, and none at the path itself", func() {
			f, err := os.Open(writeTempFile("launcher", "#!/bin/sh\n"))
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(f.Close)
			g := taskGuest("")
			g.drives.stackID, g.drives.dropletID = qemuStackSerial, qemuDropletSerial
			g.systemCerts = certs
			g.stack = &guestStack{
				launcher:    guestTool{name: "launcher", file: f, size: int64(len("#!/bin/sh\n"))},
				argv:        shellJoin([]string{stackLauncherPath}),
				cwd:         "/home/vcap/app",
				hostname:    "stack-guest-0",
				hosts:       []byte("127.0.0.1 localhost\n"),
				systemCerts: certs,
			}
			entries := build(g)
			Expect(entries["rvm/syscerts"].mode).To(Equal(uint32(0o040755)))
			Expect(string(entries["rvm/syscerts/a.crt"].data)).To(Equal("first\n"))
			Expect(entries["rvm/syscerts/b.crt"].mode).To(Equal(uint32(0o100644)))
			Expect(entries).NotTo(HaveKey("etc/cf-system-certificates"))
		})
	})
})
