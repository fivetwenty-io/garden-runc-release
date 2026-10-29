package users_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"code.cloudfoundry.org/guardian/rundmc/users"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("LookupImageUser", func() {
	const (
		imagePasswd = `root:x:0:0:root:/root:/bin/sh
vcap:x:1000:1000:VCAP:/home/vcap:/bin/sh
childuser:x:1234:4321:child:/child-home:/bin/sh
`
		imageGroup = `root:x:0:
vcap:x:1000:
childgroup:x:4321:
extra:x:5678:childuser,vcap
`
		// These files sit outside the image root. Their root entry has a home
		// directory that the defaults never produce.
		hostPasswd = `root:x:0:0:root:/host-secret-home:/bin/sh
hostonly:x:4242:4343:host:/host-only:/bin/sh
`
		hostGroup = `hostgroup:x:9999:root,hostonly
`
	)

	var (
		rootfs         string
		hostDir        string
		hostPasswdPath string
		hostGroupPath  string
	)

	writeImageFile := func(path, contents string) {
		full := filepath.Join(rootfs, path)
		Expect(os.MkdirAll(filepath.Dir(full), 0755)).To(Succeed())
		Expect(os.WriteFile(full, []byte(contents), 0644)).To(Succeed())
	}

	symlinkInImage := func(target, path string) {
		full := filepath.Join(rootfs, path)
		Expect(os.MkdirAll(filepath.Dir(full), 0755)).To(Succeed())
		Expect(os.Symlink(target, full)).To(Succeed())
	}

	// lookupWithin fails the spec when the lookup does not return within the
	// timeout, so a lookup that blocks on a FIFO fails instead of hanging.
	lookupWithin := func(name string) (*users.ExecUser, error) {
		type result struct {
			user *users.ExecUser
			err  error
		}
		done := make(chan result, 1)
		go func() {
			defer GinkgoRecover()
			u, err := users.LookupImageUser(rootfs, name)
			done <- result{u, err}
		}()

		var r result
		Eventually(done, "5s").Should(Receive(&r), "LookupImageUser did not return")
		return r.user, r.err
	}

	BeforeEach(func() {
		rootfs = GinkgoT().TempDir()
		hostDir = GinkgoT().TempDir()

		hostPasswdPath = filepath.Join(hostDir, "passwd")
		hostGroupPath = filepath.Join(hostDir, "group")
		Expect(os.WriteFile(hostPasswdPath, []byte(hostPasswd), 0600)).To(Succeed())
		Expect(os.WriteFile(hostGroupPath, []byte(hostGroup), 0600)).To(Succeed())
	})

	Context("when the image has regular passwd and group files", func() {
		BeforeEach(func() {
			writeImageFile("etc/passwd", imagePasswd)
			writeImageFile("etc/group", imageGroup)
		})

		It("resolves a named user's uid, gid, home, and supplementary gids", func() {
			u, err := lookupWithin("childuser")
			Expect(err).NotTo(HaveOccurred())
			Expect(u).To(Equal(&users.ExecUser{Uid: 1234, Gid: 4321, Home: "/child-home", Sgids: []int{5678}}))
		})

		It("resolves root from the image", func() {
			u, err := lookupWithin("root")
			Expect(err).NotTo(HaveOccurred())
			Expect(u.Uid).To(Equal(0))
			Expect(u.Gid).To(Equal(0))
			Expect(u.Home).To(Equal("/root"))
		})

		It("resolves a user:group spec", func() {
			u, err := lookupWithin("vcap:extra")
			Expect(err).NotTo(HaveOccurred())
			Expect(u.Uid).To(Equal(1000))
			Expect(u.Gid).To(Equal(5678))
			Expect(u.Home).To(Equal("/home/vcap"))
		})

		It("resolves a numeric uid:gid that the image does not name", func() {
			u, err := lookupWithin("5000:6000")
			Expect(err).NotTo(HaveOccurred())
			Expect(u.Uid).To(Equal(5000))
			Expect(u.Gid).To(Equal(6000))
		})

		It("fails for a user the image does not have", func() {
			_, err := lookupWithin("nobody-here")
			Expect(err).To(MatchError(ContainSubstring("no matching entries in passwd file")))
		})
	})

	Context("when /etc/passwd is an absolute symlink inside the image", func() {
		BeforeEach(func() {
			writeImageFile("image-passwd", imagePasswd)
			symlinkInImage("/image-passwd", "etc/passwd")
			writeImageFile("etc/group", imageGroup)
		})

		It("resolves the symlink against the image root", func() {
			u, err := lookupWithin("childuser")
			Expect(err).NotTo(HaveOccurred())
			Expect(u).To(Equal(&users.ExecUser{Uid: 1234, Gid: 4321, Home: "/child-home", Sgids: []int{5678}}))
		})
	})

	Context("when /etc/passwd and /etc/group are absolute symlinks to files outside the image", func() {
		BeforeEach(func() {
			symlinkInImage(hostPasswdPath, "etc/passwd")
			symlinkInImage(hostGroupPath, "etc/group")
		})

		It("does not resolve a named user from outside the image", func() {
			_, err := lookupWithin("hostonly")
			Expect(err).To(MatchError(ContainSubstring("no matching entries in passwd file")))
		})

		It("treats passwd as missing, so root gets the defaults", func() {
			u, err := lookupWithin("root")
			Expect(err).NotTo(HaveOccurred())
			Expect(u).To(Equal(&users.ExecUser{Uid: 0, Gid: 0, Home: "/", Sgids: []int{}}))
		})
	})

	Context("when /etc/passwd is a relative symlink that climbs out of the image", func() {
		BeforeEach(func() {
			climb := strings.Repeat("../", 32)
			symlinkInImage(climb+strings.TrimPrefix(hostPasswdPath, "/"), "etc/passwd")
			symlinkInImage(climb+strings.TrimPrefix(hostGroupPath, "/"), "etc/group")
		})

		It("does not resolve a named user from outside the image", func() {
			_, err := lookupWithin("hostonly")
			Expect(err).To(MatchError(ContainSubstring("no matching entries in passwd file")))
		})

		It("treats passwd as missing, so root gets the defaults", func() {
			u, err := lookupWithin("root")
			Expect(err).NotTo(HaveOccurred())
			Expect(u).To(Equal(&users.ExecUser{Uid: 0, Gid: 0, Home: "/", Sgids: []int{}}))
		})
	})

	Context("when /etc is an absolute symlink to a directory outside the image", func() {
		BeforeEach(func() {
			symlinkInImage(hostDir, "etc")
		})

		It("does not resolve a named user from outside the image", func() {
			_, err := lookupWithin("hostonly")
			Expect(err).To(MatchError(ContainSubstring("no matching entries in passwd file")))

			u, err := lookupWithin("root")
			Expect(err).NotTo(HaveOccurred())
			Expect(u.Home).To(Equal("/"))
		})
	})

	Context("when /etc/passwd is a FIFO", func() {
		BeforeEach(func() {
			Expect(os.MkdirAll(filepath.Join(rootfs, "etc"), 0755)).To(Succeed())
			Expect(syscall.Mkfifo(filepath.Join(rootfs, "etc", "passwd"), 0644)).To(Succeed())
			writeImageFile("etc/group", imageGroup)
		})

		It("returns an error promptly instead of blocking", func() {
			_, err := lookupWithin("root")
			Expect(err).To(MatchError(ContainSubstring("/etc/passwd in the container image is not a regular file")))
		})
	})

	Context("when /etc/group is a FIFO", func() {
		BeforeEach(func() {
			writeImageFile("etc/passwd", imagePasswd)
			Expect(syscall.Mkfifo(filepath.Join(rootfs, "etc", "group"), 0644)).To(Succeed())
		})

		It("returns an error promptly instead of blocking", func() {
			_, err := lookupWithin("vcap")
			Expect(err).To(MatchError(ContainSubstring("/etc/group in the container image is not a regular file")))
		})
	})

	Context("when /etc/passwd is a symlink to a FIFO", func() {
		BeforeEach(func() {
			Expect(os.MkdirAll(filepath.Join(rootfs, "etc"), 0755)).To(Succeed())
			Expect(syscall.Mkfifo(filepath.Join(rootfs, "pipe"), 0644)).To(Succeed())
			symlinkInImage("/pipe", "etc/passwd")
		})

		It("returns an error promptly instead of blocking", func() {
			_, err := lookupWithin("root")
			Expect(err).To(MatchError(ContainSubstring("/etc/passwd in the container image is not a regular file")))
		})
	})

	Context("when /etc/passwd is a directory", func() {
		BeforeEach(func() {
			Expect(os.MkdirAll(filepath.Join(rootfs, "etc", "passwd"), 0755)).To(Succeed())
		})

		It("returns an error", func() {
			_, err := lookupWithin("root")
			Expect(err).To(MatchError(ContainSubstring("/etc/passwd in the container image is not a regular file")))
		})
	})

	Context("when /etc/passwd is a symlink loop", func() {
		BeforeEach(func() {
			symlinkInImage("/etc/passwd", "etc/passwd")
		})

		It("returns an error rather than treating passwd as missing", func() {
			_, err := lookupWithin("root")
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when /etc/passwd is larger than the limit", func() {
		BeforeEach(func() {
			writeImageFile("etc/passwd", imagePasswd)
			Expect(os.Truncate(filepath.Join(rootfs, "etc", "passwd"), users.MaxImageIdentityFileSize+1)).To(Succeed())
		})

		It("returns an error without reading it, and without the root path", func() {
			_, err := lookupWithin("root")
			Expect(err).To(MatchError(users.ErrImageIdentityFileTooLarge))
			Expect(err.Error()).NotTo(ContainSubstring(rootfs))
		})
	})

	Context("when the image has no passwd or group file", func() {
		It("resolves root to the defaults", func() {
			u, err := lookupWithin("root")
			Expect(err).NotTo(HaveOccurred())
			Expect(u).To(Equal(&users.ExecUser{Uid: 0, Gid: 0, Home: "/", Sgids: []int{}}))
		})

		It("resolves a numeric uid:gid", func() {
			u, err := lookupWithin("1234:4321")
			Expect(err).NotTo(HaveOccurred())
			Expect(u.Uid).To(Equal(1234))
			Expect(u.Gid).To(Equal(4321))
		})

		It("fails for a named user", func() {
			_, err := lookupWithin("childuser")
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when the image has no passwd file and a bad group file", func() {
		BeforeEach(func() {
			Expect(os.MkdirAll(filepath.Join(rootfs, "etc"), 0755)).To(Succeed())
			Expect(syscall.Mkfifo(filepath.Join(rootfs, "etc", "group"), 0644)).To(Succeed())
		})

		// LookupUser is not called here: it opens the group file for a
		// numeric user, and that blocks on a FIFO.
		It("resolves root to the defaults, as LookupUser does", func() {
			u, err := lookupWithin("root")
			Expect(err).NotTo(HaveOccurred())
			Expect(u).To(Equal(&users.ExecUser{Uid: 0, Gid: 0, Home: "/", Sgids: []int{}}))
		})

		It("fails closed for a user that needs the group file", func() {
			_, err := lookupWithin("1234:4321")
			Expect(err).To(MatchError(ContainSubstring("/etc/group in the container image is not a regular file")))
		})
	})

	Context("when the image has no passwd file and a directory as the group file", func() {
		BeforeEach(func() {
			Expect(os.MkdirAll(filepath.Join(rootfs, "etc", "group"), 0755)).To(Succeed())
		})

		It("resolves root to the defaults, as LookupUser does", func() {
			expected, stockErr := users.LookupUser(rootfs, "root")
			Expect(stockErr).NotTo(HaveOccurred())

			u, err := lookupWithin("root")
			Expect(err).NotTo(HaveOccurred())
			Expect(u).To(Equal(expected))
		})
	})

	Context("when /etc is a regular file", func() {
		BeforeEach(func() {
			writeImageFile("etc", "not a directory\n")
		})

		It("treats passwd and group as missing, so a numeric uid:gid resolves as LookupUser resolves it", func() {
			expected, stockErr := users.LookupUser(rootfs, "1000:1001")
			Expect(stockErr).NotTo(HaveOccurred())

			u, err := lookupWithin("1000:1001")
			Expect(err).NotTo(HaveOccurred())
			Expect(u).To(Equal(expected))
			Expect(u.Uid).To(Equal(1000))
			Expect(u.Gid).To(Equal(1001))
		})

		It("gives the same answer for a named user and for root as LookupUser", func() {
			for _, name := range []string{"root", "childuser"} {
				expected, stockErr := users.LookupUser(rootfs, name)
				u, err := lookupWithin(name)
				if stockErr != nil {
					Expect(err).To(HaveOccurred(), name)
					continue
				}
				Expect(err).NotTo(HaveOccurred(), name)
				Expect(u).To(Equal(expected), name)
			}
		})
	})

	Context("when the image has passwd but no group file", func() {
		BeforeEach(func() {
			writeImageFile("etc/passwd", imagePasswd)
		})

		It("resolves the user with no supplementary gids", func() {
			u, err := lookupWithin("childuser")
			Expect(err).NotTo(HaveOccurred())
			Expect(u).To(Equal(&users.ExecUser{Uid: 1234, Gid: 4321, Home: "/child-home", Sgids: []int{}}))
		})
	})

	Context("when the image root does not exist", func() {
		It("returns an error instead of resolving root to the defaults", func() {
			_, err := users.LookupImageUser(filepath.Join(rootfs, "missing"), "root")
			Expect(err).To(MatchError(ContainSubstring("open image root")))
		})

		It("does not put the root path in the error", func() {
			_, err := users.LookupImageUser(filepath.Join(rootfs, "missing"), "root")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).NotTo(ContainSubstring(rootfs))
		})
	})

	Context("when the image root is not a directory", func() {
		It("returns an error", func() {
			_, err := users.LookupImageUser(hostPasswdPath, "root")
			Expect(err).To(MatchError(ContainSubstring("open image root")))
		})
	})

	Context("when the image root path is empty", func() {
		It("returns an error", func() {
			_, err := users.LookupImageUser("", "root")
			Expect(err).To(MatchError(ContainSubstring("image root path is empty")))
		})
	})
})

var _ = Describe("the image identity file reader", func() {
	It("reads a file no larger than the limit", func() {
		data, err := io.ReadAll(users.NewCappedReader(strings.NewReader("12345"), 5, "/etc/passwd"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(data)).To(Equal("12345"))
	})

	It("fails once a file grows past the limit", func() {
		_, err := io.ReadAll(users.NewCappedReader(strings.NewReader("123456"), 5, "/etc/passwd"))
		Expect(err).To(MatchError(users.ErrImageIdentityFileTooLarge))
		Expect(err).To(MatchError(ContainSubstring("/etc/passwd in the container image grew past 5 bytes")))
	})
})
