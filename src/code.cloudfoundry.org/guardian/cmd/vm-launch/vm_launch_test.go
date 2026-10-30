//go:build linux

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

func TestVMLaunch(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "VM Launch Suite")
}

const testNonce = "0123456789abcdef"

// helperArtifacts names the artifacts directory of a helper process that a
// spec starts: this test binary running vm-launch, in a process of its own,
// for a spec that needs vm-launch's own stdout or signals.
const helperArtifacts = "VM_LAUNCH_TEST_ARTIFACTS"

// helperStopCheck marks a helper process that calls run, which fails at
// once on its arguments, with a logger whose first write also goes to the
// broken stdout. run only logs once it has registered SIGPIPE, so that write
// must come back as an error, and the helper reports it on stderr. Then
// the helper writes to its stdout again, after run has returned. The runtime
// kills a process whose write to a broken stdout returns while nothing
// catches SIGPIPE, so a helper that dies by SIGPIPE shows that run stopped
// catching it, and the stderr line shows that run was catching it while it ran.
const helperStopCheck = "VM_LAUNCH_TEST_SIGPIPE_AFTER_RUN"

// stdoutProbe is a log writer that, on its first write, also writes to the
// process's stdout and keeps the error.
type stdoutProbe struct {
	once sync.Once
	err  error
}

func (p *stdoutProbe) Write(b []byte) (int, error) {
	p.once.Do(func() {
		_, p.err = os.Stdout.WriteString("written during run\n")
	})
	return len(b), nil
}

func init() {
	if os.Getenv(helperStopCheck) != "" {
		probe := &stdoutProbe{}
		code := run([]string{"--backend", "nope", "--", "true"}, log.New(probe, "", 0))
		fmt.Fprintf(os.Stderr, "run returned %d, and a write to a broken stdout during it returned: %v\n", code, probe.err)
		_, err := os.Stdout.WriteString("written after run\n")
		fmt.Fprintf(os.Stderr, "a write to a broken stdout after run returned: %v\n", err)
		os.Exit(0)
	}
	if art := os.Getenv(helperArtifacts); art != "" {
		os.Exit(run([]string{"--backend", "vm-qemu", "--artifacts", art, "--", "true"}, log.New(os.Stderr, "vm-launch: ", 0)))
	}
}

type cpioEntry struct {
	name           string
	mode, nlink    uint32
	rmajor, rminor uint32
	data           []byte
}

func align4(n int) int { return (n + 3) &^ 3 }

// readNewc parses a newc archive strictly: magic, 4-byte alignment, NUL
// terminated names, and a trailer that ends the archive.
func readNewc(b []byte) []cpioEntry {
	var entries []cpioEntry
	off := 0
	for {
		Expect(off % 4).To(BeZero())
		Expect(len(b)).To(BeNumerically(">=", off+cpioHeaderSize))
		Expect(string(b[off : off+6])).To(Equal("070701"))
		field := func(i int) uint32 {
			v, err := strconv.ParseUint(string(b[off+6+8*i:off+14+8*i]), 16, 32)
			Expect(err).NotTo(HaveOccurred())
			return uint32(v)
		}
		namesize := int(field(11))
		size := int(field(6))
		nameEnd := off + cpioHeaderSize + namesize
		Expect(b[nameEnd-1]).To(BeZero())
		dataOff := align4(nameEnd)
		e := cpioEntry{
			name:   string(b[off+cpioHeaderSize : nameEnd-1]),
			mode:   field(1),
			nlink:  field(4),
			rmajor: field(9),
			rminor: field(10),
			data:   b[dataOff : dataOff+size],
		}
		entries = append(entries, e)
		off = align4(dataOff + size)
		if e.name == cpioTrailer {
			Expect(off).To(Equal(len(b)))
			return entries
		}
	}
}

func gunzip(b []byte) []byte {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	Expect(err).NotTo(HaveOccurred())
	out, err := io.ReadAll(zr)
	Expect(err).NotTo(HaveOccurred())
	return out
}

// taskNetwork returns the QEMU guest network of a process without PORT, such
// as a task.
func taskNetwork() *network {
	return &network{address: qemuGuestCIDR, gateway: qemuGateway, resolvConf: "nameserver 10.0.2.3\n"}
}

// noGuestEnv is the /rvm/env of a container environment that holds nothing
// the guest gets.
const noGuestEnv = ""

// taskGuest returns the initramfs contents of a task that runs command, with
// no guest environment, no volume, and no CA bundle.
func taskGuest(command string) guestContents {
	return guestContents{command: command, nonce: testNonce, nw: taskNetwork(), env: noGuestEnv, nofile: testNofile}
}

// testNofile is the open-files limit of the guests specs build, soft and
// hard alike, as Garden sets them.
var testNofile = nofileLimit{soft: 1024, hard: 1024}

// buildInitramfs builds an initramfs through newInitramfs, with busybox as
// the busybox binary and an empty guest environment, and returns the
// archive.
func buildInitramfs(busybox []byte, command string, nw *network, vol *guestVolume) []byte {
	return buildInitramfsWithEnv(busybox, command, nw, noGuestEnv, vol)
}

// buildInitramfsWithEnv is buildInitramfs with the guest environment
// guestEnv.
func buildInitramfsWithEnv(busybox []byte, command string, nw *network, guestEnv string, vol *guestVolume) []byte {
	bb := filepath.Join(GinkgoT().TempDir(), "busybox")
	Expect(os.WriteFile(bb, busybox, 0o755)).To(Succeed())
	f, err := newInitramfs(bb, guestContents{command: command, nonce: testNonce, nw: nw, env: guestEnv, vol: vol, nofile: testNofile})
	Expect(err).NotTo(HaveOccurred())
	defer f.Close()
	return fileBytes(f)
}

// fileBytes reads all of f without moving its offset.
func fileBytes(f *os.File) []byte {
	info, err := f.Stat()
	Expect(err).NotTo(HaveOccurred())
	b := make([]byte, info.Size())
	_, err = f.ReadAt(b, 0)
	Expect(err).NotTo(HaveOccurred())
	return b
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

// feed pushes chunks through a serial filter and finishes it.
func feed(chunks ...string) (*serialFilter, string) {
	var out bytes.Buffer
	f := newSerialFilter(&out, testNonce)
	for _, c := range chunks {
		n, err := f.Write([]byte(c))
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(len(c)))
	}
	f.finish()
	return f, out.String()
}

// signalOnWrite queues sig on signals at the first write.
type signalOnWrite struct {
	w       io.Writer
	signals chan os.Signal
	sig     os.Signal
	sent    bool
}

func (s *signalOnWrite) Write(p []byte) (int, error) {
	if !s.sent {
		s.sent = true
		s.signals <- s.sig
	}
	return s.w.Write(p)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func codeOf(r runResult) int {
	code, _ := exitCode(r)
	return code
}

func processState(script string) *os.ProcessState {
	cmd := exec.Command("/bin/sh", "-c", script)
	_ = cmd.Run()
	Expect(cmd.ProcessState).NotTo(BeNil())
	return cmd.ProcessState
}

var _ = Describe("initramfs", func() {
	var busybox []byte

	BeforeEach(func() {
		busybox = make([]byte, 1001)
		for i := range busybox {
			busybox[i] = byte(i * 7)
		}
	})

	writeArchive := func() []byte {
		return buildInitramfs(busybox, "echo 'hi there'; exit 3\n", taskNetwork(), nil)
	}

	It("writes a gzip newc archive with the guest layout", func() {
		entries := readNewc(gunzip(writeArchive()))

		var names []string
		byName := map[string]cpioEntry{}
		for _, e := range entries {
			names = append(names, e.name)
			byName[e.name] = e
		}
		Expect(names).To(Equal([]string{"bin", "dev", "dev/console", "dev/null", "etc", "proc", "sys", "tmp", "rvm",
			"bin/busybox", "rvm/cmd", "rvm/net", "rvm/env", "rvm/limits", "etc/resolv.conf", "init", cpioTrailer}))

		Expect(byName["bin"].mode).To(Equal(uint32(0o040755)))
		Expect(byName["tmp"].mode).To(Equal(uint32(0o041777)))
		Expect(byName["dev/console"].mode).To(Equal(uint32(0o020600)))
		Expect([]uint32{byName["dev/console"].rmajor, byName["dev/console"].rminor}).To(Equal([]uint32{5, 1}))
		Expect([]uint32{byName["dev/null"].rmajor, byName["dev/null"].rminor}).To(Equal([]uint32{1, 3}))
		Expect(byName["bin/busybox"].mode).To(Equal(uint32(0o100755)))
		Expect(byName["bin/busybox"].data).To(Equal(busybox))
		Expect(string(byName["rvm/cmd"].data)).To(Equal("echo 'hi there'; exit 3\n"))
		Expect(byName["init"].mode).To(Equal(uint32(0o100755)))
		Expect(string(byName["init"].data)).To(Equal(initScript(testNonce, false)))
	})

	It("writes an /init that brackets the command with nonce markers and reboots", func() {
		script := initScript(testNonce, false)
		Expect(script).To(HavePrefix("#!/bin/busybox sh\n"))
		Expect(script).To(ContainSubstring("\necho RVM_START_" + testNonce + "\n"))
		Expect(script).To(ContainSubstring("\n( { read -r rvm_self rvm_rest </proc/self/stat && echo \"$rvm_self\" >/rvm/app-pid; } || echo \"vm-launch guest: recording the command's pid in /rvm/app-pid failed; a stop request cannot reach the command\"; ulimit -n \"$RVM_NOFILE_HARD\" && ulimit -S -n \"$RVM_NOFILE_SOFT\" && . /rvm/env && exec sh -c \"$(cat /rvm/cmd)\" ) </dev/null\nrvm_status=$?\n" + guestListenStop + "echo RVM_EXIT_" + testNonce + "=$rvm_status >/dev/console || echo RVM_EXIT_" + testNonce + "=$rvm_status\nreboot -f\n"))
		Expect(script).NotTo(ContainSubstring("poweroff"))
	})

	It("round-trips through GNU cpio", func() {
		cpioBin, err := exec.LookPath("cpio")
		if err != nil {
			Skip("cpio not installed")
		}
		plain := filepath.Join(GinkgoT().TempDir(), "initrd.cpio")
		Expect(os.WriteFile(plain, gunzip(writeArchive()), 0o600)).To(Succeed())

		list, err := exec.Command("sh", "-c", `"$0" -t --quiet < "$1"`, cpioBin, plain).CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(list))
		Expect(strings.Fields(string(list))).To(Equal([]string{"bin", "dev", "dev/console", "dev/null", "etc", "proc", "sys", "tmp", "rvm",
			"bin/busybox", "rvm/cmd", "rvm/net", "rvm/env", "rvm/limits", "etc/resolv.conf", "init"}))

		if os.Geteuid() != 0 {
			Skip("extracting device nodes needs root")
		}
		dest := GinkgoT().TempDir()
		extract := exec.Command("sh", "-c", `"$0" -i -d --quiet < "$1"`, cpioBin, plain)
		extract.Dir = dest
		out, err := extract.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(out))

		Expect(os.ReadFile(filepath.Join(dest, "bin/busybox"))).To(Equal(busybox))
		Expect(os.ReadFile(filepath.Join(dest, "init"))).To(Equal([]byte(initScript(testNonce, false))))
		Expect(os.ReadFile(filepath.Join(dest, "rvm/cmd"))).To(Equal([]byte("echo 'hi there'; exit 3\n")))
		info, err := os.Stat(filepath.Join(dest, "init"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o755)))

		var st syscall.Stat_t
		Expect(syscall.Stat(filepath.Join(dest, "dev/console"), &st)).To(Succeed())
		Expect(st.Mode & syscall.S_IFMT).To(Equal(uint32(syscall.S_IFCHR)))
		Expect(st.Rdev).To(Equal(uint64(5<<8 | 1)))
	})

	Describe("the memfd", func() {
		var f *os.File

		BeforeEach(func() {
			bb := filepath.Join(GinkgoT().TempDir(), "busybox")
			Expect(os.WriteFile(bb, busybox, 0o755)).To(Succeed())
			var err error
			f, err = newInitramfs(bb, taskGuest("true"))
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = f.Close() })
		})

		It("is a close-on-exec memfd, not a file on disk", func() {
			link, err := os.Readlink(procSelfFD(int(f.Fd())))
			Expect(err).NotTo(HaveOccurred())
			Expect(link).To(Equal("/memfd:vm-launch-initramfs (deleted)"))
			flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(flags & unix.FD_CLOEXEC).To(Equal(unix.FD_CLOEXEC))
		})

		It("carries every seal, so nothing can change it", func() {
			seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
			Expect(err).NotTo(HaveOccurred())
			// F_SEAL_EXEC comes with MFD_NOEXEC_SEAL, which kernels before
			// 6.3 do not have.
			Expect(seals &^ unix.F_SEAL_EXEC).To(Equal(unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE | unix.F_SEAL_SEAL))

			before := fileBytes(f)
			_, err = f.WriteAt([]byte("x"), 0)
			Expect(err).To(MatchError(syscall.EPERM))
			Expect(f.Truncate(1)).To(MatchError(syscall.EPERM))
			Expect(f.Truncate(int64(len(before)) + 1)).To(MatchError(syscall.EPERM))
			_, err = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE)
			Expect(err).To(MatchError(syscall.EPERM))

			// A new open through /proc/self/fd, as the hypervisor makes, reads
			// the archive and cannot write it either.
			rw, err := os.OpenFile(procSelfFD(int(f.Fd())), os.O_RDWR, 0)
			Expect(err).NotTo(HaveOccurred())
			defer rw.Close()
			_, err = rw.Write([]byte("x"))
			Expect(err).To(MatchError(syscall.EPERM))
			Expect(io.ReadAll(rw)).To(Equal(before))
			readNewc(gunzip(before))
		})

		It("is not executable, and cannot be made executable, on a kernel with MFD_NOEXEC_SEAL", func() {
			// The kernel's support decides the skip, so that a vm-launch
			// that stops asking for the flag fails here on a kernel that
			// has it.
			probe, err := unix.MemfdCreate("vm-launch-noexec-probe", unix.MFD_NOEXEC_SEAL)
			if errors.Is(err, unix.EINVAL) {
				Skip("this kernel has no MFD_NOEXEC_SEAL, which Linux 6.3 added")
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(unix.Close(probe)).To(Succeed())

			seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(seals & unix.F_SEAL_EXEC).To(Equal(unix.F_SEAL_EXEC))
			info, err := f.Stat()
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm() & 0o111).To(BeZero())
			Expect(unix.Fchmod(int(f.Fd()), 0o755)).To(MatchError(syscall.EPERM))
		})
	})

	Describe("the memfd_create flags", func() {
		var (
			bb    string
			calls []int
			orig  func(string, int) (int, error)
		)

		BeforeEach(func() {
			bb = filepath.Join(GinkgoT().TempDir(), "busybox")
			Expect(os.WriteFile(bb, busybox, 0o755)).To(Succeed())
			calls = nil
			orig = memfdCreate
			DeferCleanup(func() { memfdCreate = orig })
		})

		// kernel makes memfdCreate record its flags and fail with err when
		// they hold MFD_NOEXEC_SEAL, as a kernel without it does with EINVAL.
		kernel := func(err error) {
			memfdCreate = func(name string, flags int) (int, error) {
				calls = append(calls, flags)
				if err != nil && flags&unix.MFD_NOEXEC_SEAL != 0 {
					return -1, err
				}
				return orig(name, flags)
			}
		}

		It("asks for MFD_NOEXEC_SEAL first", func() {
			kernel(nil)
			f, err := newInitramfs(bb, taskGuest("true"))
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			Expect(calls).To(Equal([]int{unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING | unix.MFD_NOEXEC_SEAL}))
		})

		It("falls back to the plain flags on a kernel that rejects MFD_NOEXEC_SEAL", func() {
			kernel(unix.EINVAL)
			f, err := newInitramfs(bb, taskGuest("true"))
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			Expect(calls).To(Equal([]int{
				unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING | unix.MFD_NOEXEC_SEAL,
				unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING,
			}))
			seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(seals &^ unix.F_SEAL_EXEC).To(Equal(unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE | unix.F_SEAL_SEAL))
			readNewc(gunzip(fileBytes(f)))
		})

		It("returns any other error without trying again, and holds no memfd", func() {
			kernel(unix.EACCES)
			held := heldInitramfs()
			_, err := newInitramfs(bb, taskGuest("true"))
			Expect(err).To(MatchError("creating the initramfs memfd: permission denied"))
			Expect(errors.Is(err, unix.EACCES)).To(BeTrue())
			Expect(calls).To(HaveLen(1))
			Expect(heldInitramfs()).To(Equal(held))
		})
	})

	It("fails when busybox is missing or not a regular file, and leaves no memfd behind", func() {
		dir := GinkgoT().TempDir()
		held := heldInitramfs()
		_, err := newInitramfs(filepath.Join(dir, "nope"), taskGuest("true"))
		Expect(err).To(MatchError(ContainSubstring("opening busybox")))
		_, err = newInitramfs(dir, taskGuest("true"))
		Expect(err).To(MatchError(ContainSubstring("not a regular file")))
		Expect(heldInitramfs()).To(Equal(held))
	})

	It("reports a destination it cannot write", func() {
		bb := filepath.Join(GinkgoT().TempDir(), "busybox")
		Expect(os.WriteFile(bb, busybox, 0o755)).To(Succeed())
		ro, err := os.Open(bb)
		Expect(err).NotTo(HaveOccurred())
		defer ro.Close()
		Expect(writeInitramfs(ro, bb, taskGuest("true"))).To(MatchError(ContainSubstring("writing the initramfs")))
	})

	Describe("cpioWriter", func() {
		It("rejects unclean, absolute, and reserved names", func() {
			cw := newCPIOWriter(io.Discard)
			for _, name := range []string{"", "/init", "a/../b", "a/", cpioTrailer, "a\x00b"} {
				Expect(cw.Dir(name, 0o755)).To(MatchError(ContainSubstring("clean relative path")), name)
			}
		})

		It("rejects mode bits outside the permission mask", func() {
			Expect(newCPIOWriter(io.Discard).Dir("d", 0o40755)).To(MatchError(ContainSubstring("permission bits")))
		})

		It("rejects sizes the header cannot hold", func() {
			cw := newCPIOWriter(io.Discard)
			Expect(cw.File("f", 0o644, 1<<32, strings.NewReader(""))).To(MatchError(ContainSubstring("outside newc range")))
			Expect(cw.File("f", 0o644, -1, strings.NewReader(""))).To(MatchError(ContainSubstring("outside newc range")))
		})

		It("fails when the source is shorter than the declared size", func() {
			err := newCPIOWriter(io.Discard).File("f", 0o644, 10, strings.NewReader("short"))
			Expect(err).To(MatchError(ContainSubstring("source ended after 5 of 10 bytes")))
		})

		It("reports write failures", func() {
			err := newCPIOWriter(failingWriter{errors.New("disk full")}).Dir("d", 0o755)
			Expect(err).To(MatchError(ContainSubstring("disk full")))
		})
	})
})

var _ = Describe("serialFilter", func() {
	start := "RVM_START_" + testNonce + "\r\n"
	marker := func(rc string) string { return "RVM_EXIT_" + testNonce + "=" + rc }

	stream := "[    0.123] kernel noise\r\n" + start +
		"hello\r\n" +
		"RVM_EXIT_ffffffffffffffff=9\r\n" +
		"wor\rld\r\n" +
		"partial" + marker("42") + "\r\n" +
		"reboot: Restarting system\r\n"
	want := "hello\nRVM_EXIT_ffffffffffffffff=9\nwor\rld\npartial"

	It("streams guest output and reads the status", func() {
		f, out := feed(stream)
		Expect(out).To(Equal(want))
		Expect(f.markerFound()).To(BeTrue())
		Expect(f.status).To(Equal(42))
	})

	It("gives the same result for every two-way split of the stream", func() {
		for i := 0; i <= len(stream); i++ {
			f, out := feed(stream[:i], stream[i:])
			Expect(out).To(Equal(want), "split at %d", i)
			Expect(f.status).To(Equal(42), "split at %d", i)
		}
	})

	It("gives the same result when fed one byte at a time", func() {
		chunks := make([]string, len(stream))
		for i := range stream {
			chunks[i] = stream[i : i+1]
		}
		f, out := feed(chunks...)
		Expect(out).To(Equal(want))
		Expect(f.markerFound()).To(BeTrue())
	})

	It("emits output before the marker arrives", func() {
		var out bytes.Buffer
		f := newSerialFilter(&out, testNonce)
		_, _ = f.Write([]byte(start + "line one\r\nRVM_EX"))
		Expect(out.String()).To(Equal("line one\n"))
		_, _ = f.Write([]byte("IT_" + testNonce + "=0\n"))
		Eventually(f.exited).Should(BeClosed())
	})

	It("passes through everything when the marker is absent", func() {
		f, out := feed(start, "a\r\nb")
		Expect(out).To(Equal("a\nb"))
		Expect(f.markerFound()).To(BeFalse())
	})

	It("ignores markers with another nonce", func() {
		f, out := feed(start, "RVM_EXIT_aaaaaaaaaaaaaaaa=3\r\n")
		Expect(out).To(Equal("RVM_EXIT_aaaaaaaaaaaaaaaa=3\n"))
		Expect(f.markerFound()).To(BeFalse())
	})

	DescribeTable("treats malformed markers as output",
		func(rest string) {
			f, out := feed(start, marker(rest))
			Expect(out).To(Equal(marker(rest)))
			Expect(f.markerFound()).To(BeFalse())
		},
		Entry("status above 255", "256\n"),
		Entry("four digits", "1000\n"),
		Entry("no digits", "\n"),
		Entry("letters", "1a\n"),
		Entry("CR without LF", "1\rx"),
		Entry("no terminator at end of stream", "12"),
	)

	It("finds a real marker after a malformed one", func() {
		f, out := feed(start, marker("x")+marker("7")+"\n")
		Expect(out).To(Equal(marker("x")))
		Expect(f.status).To(Equal(7))
	})

	It("drops everything when the guest never starts and keeps it for diagnostics", func() {
		f, out := feed("Kernel panic - not syncing\r\n", "no newline")
		Expect(out).To(BeEmpty())
		Expect(f.started()).To(BeFalse())
		Expect(string(f.bootLog)).To(Equal("Kernel panic - not syncing\r\nno newline"))
	})

	It("bounds the kept boot output", func() {
		f, _ := feed(strings.Repeat("x", 3*maxBootLog), "\n", strings.Repeat("y\n", maxBootLog))
		Expect(len(f.bootLog)).To(Equal(maxBootLog))
		Expect(string(f.bootLog)).To(HaveSuffix("y\ny\n"))
	})

	It("finds the start tag at the end of an overlong line", func() {
		noise := strings.Repeat("x", 2*maxBootLog)
		f, out := feed(noise, "RVM_START_"+testNonce[:5], testNonce[5:], "\nok\n")
		Expect(f.started()).To(BeTrue())
		Expect(out).To(Equal("ok\n"))
	})

	It("keeps a lone CR at end of stream", func() {
		_, out := feed(start, "spin\r")
		Expect(out).To(Equal("spin\r"))
	})

	It("keeps draining when the destination fails", func() {
		f := newSerialFilter(failingWriter{errors.New("broken pipe")}, testNonce)
		n, err := f.Write([]byte(start + "out\n" + marker("5") + "\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(BeNumerically(">", 0))
		Expect(f.writeErr).To(MatchError("broken pipe"))
		Expect(f.status).To(Equal(5))
	})
})

var _ = Describe("exitCode", func() {
	It("returns the guest status when the marker was seen, whatever the hypervisor did", func() {
		code, reason := exitCode(runResult{markerFound: true, guestStatus: 3, received: syscall.SIGTERM, state: processState("kill -KILL $$")})
		Expect(code).To(Equal(3))
		Expect(reason).To(BeEmpty())
	})

	DescribeTable("maps runs without a marker",
		func(res func() runResult, want int) {
			code, reason := exitCode(res())
			Expect(code).To(Equal(want))
			Expect(reason).NotTo(BeEmpty())
		},
		Entry("forwarded signal", func() runResult {
			return runResult{received: syscall.SIGTERM, state: processState("exit 0")}
		}, 143),
		Entry("hypervisor killed by a signal", func() runResult { return runResult{state: processState("kill -KILL $$")} }, 137),
		Entry("hypervisor failure", func() runResult { return runResult{state: processState("exit 1")} }, exitHypervisorFailed),
		Entry("clean exit, no marker", func() runResult { return runResult{state: processState("exit 0")} }, exitMissingMarker),
		Entry("no process state", func() runResult { return runResult{} }, exitHypervisorFailed),
	)
})

var _ = Describe("parseArgs", func() {
	It("accepts the form garden wraps the CF launcher in", func() {
		cfg, err := parseArgs([]string{"--backend", "vm-qemu", "--", "/tmp/lifecycle/launcher", "app", "echo hi && exit 3", ""})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).To(Equal(config{backend: backend.VMQemu, artifacts: defaultArtifactsDir, command: "echo hi && exit 3", credhub: credhubRetry{attempts: 3, delay: time.Second}}))
	})

	It("takes --artifacts and makes it absolute", func() {
		cfg, err := parseArgs([]string{"--backend", "vm-firecracker", "--artifacts", "rel/art", "--", "/tmp/lifecycle/launcher", "app", "true", "{}"})
		Expect(err).NotTo(HaveOccurred())
		Expect(filepath.IsAbs(cfg.artifacts)).To(BeTrue())
		Expect(cfg.artifacts).To(HaveSuffix("/rel/art"))
		Expect(cfg.backend).To(Equal(backend.VMFirecracker))
	})

	It("shell-quotes argv that is not the CF launcher", func() {
		args := []string{"printf", "%s|", "it's", "a b", "$HOME"}
		cfg, err := parseArgs(append([]string{"--backend", "vm-qemu", "--"}, args...))
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.command).To(Equal(`'printf' '%s|' 'it'\''s' 'a b' '$HOME'`))
		out, err := exec.Command("/bin/sh", "-c", cfg.command).Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(out)).To(Equal("it's|a b|$HOME|"))
	})

	DescribeTable("rejects bad invocations",
		func(argv []string, msg string) {
			_, err := parseArgs(argv)
			Expect(err).To(MatchError(ContainSubstring(msg)))
		},
		Entry("missing backend", []string{"--", "true"}, "unsupported backend"),
		Entry("non-VM backend", []string{"--backend", "oci-gvisor", "--", "true"}, "unsupported backend"),
		Entry("unknown flag", []string{"--backend", "vm-qemu", "--memory", "1", "--", "true"}, "flag provided but not defined"),
		Entry("empty artifacts", []string{"--backend", "vm-qemu", "--artifacts", "", "--", "true"}, "--artifacts must not be empty"),
		Entry("no command", []string{"--backend", "vm-qemu", "--"}, "no guest command"),
		Entry("short launcher argv", []string{"--backend", "vm-qemu", "--", "/tmp/lifecycle/launcher", "app"}, "launcher argv has 1 arguments"),
		Entry("empty start command", []string{"--backend", "vm-qemu", "--", "/tmp/lifecycle/launcher", "app", " ", ""}, "empty start command"),
	)

	It("reports help as flag.ErrHelp", func() {
		_, err := parseArgs([]string{"-h"})
		Expect(err).To(MatchError(ContainSubstring("help requested")))
	})
})

var _ = Describe("hypervisor command lines", func() {
	const art = "/opt/garden-vm/artifacts"

	It("builds the QEMU microvm command line through the bundled loader", func() {
		argv, err := hypervisorArgv(backend.VMQemu, art, "/unused", "/proc/self/fd/3", 128, taskNetwork(), "", 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal([]string{
			art + "/qemu/ld-linux-x86-64.so.2", "--library-path", art + "/qemu/lib",
			art + "/qemu/qemu-system-x86_64-microvm", "-L", art + "/qemu/share",
			"-M", "microvm,accel=kvm,dump-guest-core=off", "-cpu", "host", "-smp", "1", "-m", "128",
			"-nodefaults", "-no-user-config", "-nographic", "-serial", "stdio", "-no-reboot",
			"-kernel", art + "/kernel/bzImage", "-initrd", "/proc/self/fd/3",
			"-append", "console=ttyS0 reboot=t panic=-1 rdinit=/init pci=off quiet",
			"-netdev", "user,id=n0,net=10.0.2.0/24", "-device", "virtio-net-device,netdev=n0",
		}))
	})

	It("writes the Firecracker config and builds its command line", func() {
		work := GinkgoT().TempDir()
		argv, err := hypervisorArgv(backend.VMFirecracker, art, work, "/proc/self/fd/3", 128, taskNetwork(), "", 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal([]string{art + "/firecracker/firecracker", "--no-api", "--config-file", work + "/fc.json"}))

		raw, err := os.ReadFile(filepath.Join(work, "fc.json"))
		Expect(err).NotTo(HaveOccurred())
		var cfg map[string]any
		Expect(json.Unmarshal(raw, &cfg)).To(Succeed())
		Expect(cfg).To(Equal(map[string]any{
			"boot-source": map[string]any{
				"kernel_image_path": art + "/kernel/vmlinux",
				"initrd_path":       "/proc/self/fd/3",
				"boot_args":         "console=ttyS0 reboot=k panic=1 rdinit=/init quiet",
			},
			"drives":         []any{},
			"machine-config": map[string]any{"vcpu_count": float64(1), "mem_size_mib": float64(128)},
			"network-interfaces": []any{map[string]any{
				"iface_id":      "eth0",
				"guest_mac":     "06:00:a9:fe:64:02",
				"host_dev_name": "tap0",
			}},
		}))
	})

	It("rejects other backends", func() {
		_, err := hypervisorArgv(backend.OCIRunc, art, "/w", "/w/i", 128, taskNetwork(), "", 0)
		Expect(err).To(MatchError(ContainSubstring("unsupported backend")))
	})

	Describe("checkArtifacts", func() {
		var root string

		BeforeEach(func() {
			root = GinkgoT().TempDir()
			for _, d := range []string{"kernel", "qemu/lib", "qemu/share", "firecracker"} {
				Expect(os.MkdirAll(filepath.Join(root, d), 0o755)).To(Succeed())
			}
			for _, f := range []string{"kernel/bzImage", "kernel/vmlinux", "qemu/ld-linux-x86-64.so.2",
				"qemu/qemu-system-x86_64-microvm", "firecracker/firecracker", "busybox"} {
				Expect(os.WriteFile(filepath.Join(root, f), []byte("x"), 0o755)).To(Succeed())
			}
		})

		It("accepts a complete layout for both backends", func() {
			Expect(checkArtifacts(backend.VMQemu, root)).To(Succeed())
			Expect(checkArtifacts(backend.VMFirecracker, root)).To(Succeed())
		})

		It("names the missing artifact", func() {
			Expect(os.Remove(filepath.Join(root, "kernel/vmlinux"))).To(Succeed())
			Expect(checkArtifacts(backend.VMQemu, root)).To(Succeed())
			Expect(checkArtifacts(backend.VMFirecracker, root)).To(MatchError(ContainSubstring(root + "/kernel/vmlinux")))
		})

		It("checks artifact types", func() {
			Expect(os.RemoveAll(filepath.Join(root, "qemu/lib"))).To(Succeed())
			Expect(os.WriteFile(filepath.Join(root, "qemu/lib"), nil, 0o644)).To(Succeed())
			Expect(checkArtifacts(backend.VMQemu, root)).To(MatchError(ContainSubstring("is not a directory")))

			Expect(os.Remove(filepath.Join(root, "busybox"))).To(Succeed())
			Expect(os.Mkdir(filepath.Join(root, "busybox"), 0o755)).To(Succeed())
			Expect(checkArtifacts(backend.VMFirecracker, root)).To(MatchError(ContainSubstring("is not a regular file")))
		})
	})
})

var _ = Describe("supervisor", func() {
	var (
		out     *bytes.Buffer
		logBuf  *bytes.Buffer
		signals chan os.Signal
		sup     supervisor
	)

	BeforeEach(func() {
		out = &bytes.Buffer{}
		logBuf = &bytes.Buffer{}
		signals = make(chan os.Signal, 1)
		sup = supervisor{stdout: out, logger: log.New(logBuf, "", 0), signals: signals, grace: 200 * time.Millisecond}
	})

	// fakeHypervisor stands in for QEMU or Firecracker: a shell that writes
	// console bytes to stdout.
	fakeHypervisor := func(script string) *exec.Cmd {
		return exec.Command("/bin/sh", "-c", script)
	}
	startLine := `printf 'boot noise\r\nRVM_START_` + testNonce + `\r\n'; `

	It("streams output and reports the guest status", func() {
		res, err := sup.run(fakeHypervisor(startLine+`printf 'out\r\nRVM_EXIT_`+testNonce+`=42\r\n'`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("out\n"))
		Expect(codeOf(res)).To(Equal(42))
	})

	It("kills a hypervisor that hangs after the guest reported", func() {
		began := time.Now()
		res, err := sup.run(fakeHypervisor(startLine+`printf 'RVM_EXIT_`+testNonce+`=7\n'; exec sleep 60`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(time.Since(began)).To(BeNumerically("<", 10*time.Second))
		Expect(codeOf(res)).To(Equal(7))
		Expect(logBuf.String()).To(ContainSubstring("killing it"))
	})

	It("forwards SIGTERM and exits 128+15", func() {
		signals <- syscall.SIGTERM
		res, err := sup.run(fakeHypervisor(startLine+`exec sleep 60`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.received).To(Equal(syscall.SIGTERM))
		Expect(codeOf(res)).To(Equal(143))
		Expect(logBuf.String()).To(ContainSubstring("forwarding it to the hypervisor"))
	})

	It("runs the stopping hook once, at the first signal, after the signal's line", func() {
		calls := 0
		sup.stopping = func() {
			calls++
			sup.logger.Print("stopping")
		}
		sent := false
		// Two signals once the traps are installed, which the first guest
		// output proves.
		sup.stdout = writerFunc(func(p []byte) (int, error) {
			if !sent {
				sent = true
				signals <- syscall.SIGINT
				signals <- syscall.SIGTERM
			}
			return out.Write(p)
		})
		res, err := sup.run(fakeHypervisor(`trap '' INT TERM; `+startLine+`echo ready; exec sleep 60`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(calls).To(Equal(1))
		Expect(res.received).To(Equal(syscall.SIGINT))
		Expect(codeOf(res)).To(Equal(130))
		Expect(logBuf.String()).To(HavePrefix("received interrupt, forwarding it to the hypervisor\nstopping\nreceived terminated, forwarding it to the hypervisor\n"))
	})

	It("kills a hypervisor that ignores the forwarded signal", func() {
		// Signal only once the trap is installed, which the first guest
		// output proves.
		sup.stdout = &signalOnWrite{w: out, signals: signals, sig: syscall.SIGINT}
		res, err := sup.run(fakeHypervisor(`trap '' INT; `+startLine+`echo ready; exec sleep 60`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(130))
		Expect(logBuf.String()).To(ContainSubstring("killing it"))
	})

	It("reports a failing hypervisor with its console output", func() {
		res, err := sup.run(fakeHypervisor(`printf 'Could not access KVM kernel module\n'; exit 1`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(exitHypervisorFailed))
		Expect(out.String()).To(BeEmpty())
		Expect(logBuf.String()).To(ContainSubstring("guest never started its command"))
		Expect(logBuf.String()).To(ContainSubstring("Could not access KVM kernel module"))
	})

	It("reports a guest that ends without a status", func() {
		res, err := sup.run(fakeHypervisor(startLine+`printf 'partial'`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("partial"))
		Expect(codeOf(res)).To(Equal(exitMissingMarker))
	})

	It("fails when the hypervisor cannot be started", func() {
		_, err := sup.run(exec.Command("/nonexistent/qemu"), testNonce)
		Expect(err).To(MatchError(ContainSubstring("starting hypervisor /nonexistent/qemu")))
	})
})

var _ = Describe("run", func() {
	It("exits 125 with usage on bad arguments", func() {
		var logBuf bytes.Buffer
		Expect(run([]string{"--backend", "nope", "--", "true"}, log.New(&logBuf, "vm-launch: ", 0))).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("unsupported backend"))
		Expect(logBuf.String()).To(ContainSubstring("usage: vm-launch"))
	})

	It("exits 125 naming a missing artifact", func() {
		var logBuf bytes.Buffer
		art := GinkgoT().TempDir()
		code := run([]string{"--backend", "vm-firecracker", "--artifacts", art, "--", "true"}, log.New(&logBuf, "", 0))
		Expect(code).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring(art + "/kernel/vmlinux"))
	})

	It("leaves SIGPIPE at its default for the processes started after it", func() {
		Expect(run([]string{"--backend", "nope", "--", "true"}, log.New(io.Discard, "", 0))).To(Equal(exitLaunchError))
		out, err := exec.Command("/bin/sh", "-c", "grep '^SigIgn:' /proc/self/status").Output()
		Expect(err).NotTo(HaveOccurred())
		mask, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(string(out), "SigIgn:")), 16, 64)
		Expect(err).NotTo(HaveOccurred(), string(out))
		Expect(mask&(1<<(syscall.SIGPIPE-1))).To(BeZero(), "a child of vm-launch's process ignores SIGPIPE: %s", out)
	})
})

var _ = Describe("run with a stdout that nobody reads", func() {
	It("catches SIGPIPE while it runs and stops catching it once it has returned, so the runtime's default applies again", func() {
		r, w, err := os.Pipe()
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Close()).To(Succeed())
		defer w.Close()

		var stderr bytes.Buffer
		cmd := exec.Command(os.Args[0])
		cmd.Env = []string{helperStopCheck + "=1", "PATH=" + os.Getenv("PATH")}
		cmd.Stdout = w
		cmd.Stderr = &stderr
		_ = cmd.Run()

		state := cmd.ProcessState
		Expect(state).NotTo(BeNil())
		status := state.Sys().(syscall.WaitStatus)
		Expect(status.Signaled()).To(BeTrue(), "the helper was not killed by SIGPIPE; stderr: %s", stderr.String())
		Expect(status.Signal()).To(Equal(syscall.SIGPIPE), stderr.String())
		// A helper that run did not protect dies inside run, before it says this.
		Expect(stderr.String()).To(ContainSubstring("during it returned: write /dev/stdout: broken pipe"))
		Expect(stderr.String()).NotTo(ContainSubstring("after run returned"))
	})

	It("reports the write error and still exits with the guest's status instead of dying from SIGPIPE", func() {
		art := makeArtifacts()
		script := `#!/bin/bash
for a in "$@"; do
	case "$prev" in -initrd) initrd=$a ;; esac
	prev=$a
done
nonce=$(gzip -dc "$initrd" | grep -a -o 'RVM_START_[0-9a-f]*' | head -n 1 | cut -d_ -f3)
echo "RVM_START_$nonce"
echo "guest output nobody reads"
echo "RVM_EXIT_$nonce=7"
`
		loader := filepath.Join(art, "qemu/ld-linux-x86-64.so.2")
		Expect(os.Remove(loader)).To(Succeed())
		Expect(os.WriteFile(loader, []byte(script), 0o755)).To(Succeed())

		r, w, err := os.Pipe()
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Close()).To(Succeed())
		defer w.Close()

		var stderr bytes.Buffer
		cmd := exec.Command(os.Args[0])
		cmd.Env = []string{helperArtifacts + "=" + art, "TMPDIR=" + GinkgoT().TempDir(), "PATH=" + os.Getenv("PATH")}
		cmd.Stdout = w
		cmd.Stderr = &stderr
		err = cmd.Run()

		state := cmd.ProcessState
		Expect(state).NotTo(BeNil())
		Expect(state.Sys().(syscall.WaitStatus).Signaled()).To(BeFalse(), stderr.String())
		Expect(state.ExitCode()).To(Equal(7), stderr.String())
		Expect(err).To(HaveOccurred()) // a non-zero exit status
		Expect(stderr.String()).To(ContainSubstring("writing guest output"))
		Expect(stderr.String()).To(ContainSubstring("broken pipe"))
	})
})
