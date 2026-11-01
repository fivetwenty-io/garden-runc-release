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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	"code.cloudfoundry.org/guardian/rundmc/processes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// TestMain runs the helper processes that must call run as main does: from
// main's goroutine once every init function has run, which is not how the
// Go runtime schedules a call from init, and with the real markUndumpable.
// The specs themselves run with a markUndumpable that does nothing, because
// they call run in this process many times, and a process that is not
// dumpable can no longer write its own coredump_filter as a non-root user.
func TestMain(m *testing.M) {
	if art := os.Getenv(helperTransparentRun); art != "" {
		os.Exit(transparentRun(art))
	}
	if pids := os.Getenv(helperOpenMem); pids != "" {
		os.Exit(openMem(pids))
	}
	if port := os.Getenv(helperTalkPort); port != "" {
		os.Exit(talk(port))
	}
	if addr := os.Getenv(helperResetClient); addr != "" {
		os.Exit(resetClient(addr))
	}
	if os.Getenv(helperUndumpable) != "" {
		os.Exit(undumpable())
	}
	if os.Getenv(helperShareRun) != "" {
		os.Exit(shareRun(os.Args[1:]))
	}
	markUndumpable = func() error { return nil }
	os.Exit(m.Run())
}

func TestVMLaunch(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "VM Launch Suite")
}

const testNonce = "0123456789abcdef"

// helperArtifacts names the artifacts directory of a helper process that a
// spec starts: this test binary running vm-launch, in a process of its own,
// for a spec that needs vm-launch's own stdout or signals.
const helperArtifacts = "VM_LAUNCH_TEST_ARTIFACTS"

// helperBackend names the backend of a helper process that helperArtifacts
// starts. It is vm-qemu when unset.
const helperBackend = "VM_LAUNCH_TEST_BACKEND"

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
	if ports := os.Getenv(helperEchoPorts); ports != "" {
		os.Exit(echoPeers(ports))
	}
	if art := os.Getenv(helperArtifacts); art != "" {
		kind := string(backend.VMQemu)
		if k := os.Getenv(helperBackend); k != "" {
			kind = k
		}
		os.Exit(run([]string{"--backend", kind, "--artifacts", art, "--", "true"}, log.New(os.Stderr, "vm-launch: ", 0)))
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
	g := guestContents{command: command, nonce: testNonce, nw: nw, env: guestEnv, nofile: testNofile}
	if vol != nil {
		g.vols, g.drives.volumes = []guestVolume{*vol}, qemuImageDrives(defaultImageSize)
	}
	f, err := newInitramfs(bb, g)
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
			"bin/busybox", "rvm/cmd", "rvm/net", "rvm/env", "rvm/limits", "etc/resolv.conf", "rvm/disks", "rvm/init", "init", cpioTrailer}))

		Expect(byName["bin"].mode).To(Equal(uint32(0o040755)))
		Expect(byName["tmp"].mode).To(Equal(uint32(0o041777)))
		Expect(byName["dev/console"].mode).To(Equal(uint32(0o020600)))
		Expect([]uint32{byName["dev/console"].rmajor, byName["dev/console"].rminor}).To(Equal([]uint32{5, 1}))
		Expect([]uint32{byName["dev/null"].rmajor, byName["dev/null"].rminor}).To(Equal([]uint32{1, 3}))
		Expect(byName["bin/busybox"].mode).To(Equal(uint32(0o100755)))
		Expect(byName["bin/busybox"].data).To(Equal(busybox))
		Expect(string(byName["rvm/cmd"].data)).To(Equal("echo 'hi there'; exit 3\n"))
		Expect(byName["init"].mode).To(Equal(uint32(0o100755)))
		Expect(string(byName["init"].data)).To(Equal(guestRootInit))
		Expect(byName["rvm/init"].mode).To(Equal(uint32(0o100755)))
		Expect(string(byName["rvm/init"].data)).To(Equal(initScript(testNonce, false)))
		Expect(byName["rvm/disks"].mode).To(Equal(uint32(0o100644)))
		Expect(string(byName["rvm/disks"].data)).To(Equal("RVM_VOLUMES=0\n"))
	})

	It("writes an /init that brackets the command with nonce markers and reboots", func() {
		script := initScript(testNonce, false)
		Expect(script).To(HavePrefix("#!/bin/busybox sh\n"))
		Expect(script).To(ContainSubstring("\necho RVM_START_" + testNonce + "\n"))
		Expect(script).To(ContainSubstring("\ncommand exec 3>&2 2>/dev/null\n( command exec 2>&3 3>&-; { read -r rvm_self rvm_rest </proc/self/stat && echo \"$rvm_self\" >/rvm/app-pid; } || echo \"vm-launch guest: recording the command's pid in /rvm/app-pid failed; a stop request cannot reach the command\"; ulimit -n \"$RVM_NOFILE_HARD\" && ulimit -S -n \"$RVM_NOFILE_SOFT\" && . /rvm/env && exec sh -c \"$(cat /rvm/cmd)\" ) </dev/null\nrvm_status=$?\ncommand exec 2>&3 3>&-\n" + guestStopReaderStop + guestListenStop + guestOOMReport(testNonce) + "echo RVM_EXIT_" + testNonce + "=$rvm_status >/dev/console || echo RVM_EXIT_" + testNonce + "=$rvm_status\nreboot -nf\n"))
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
			"bin/busybox", "rvm/cmd", "rvm/net", "rvm/env", "rvm/limits", "etc/resolv.conf", "rvm/disks", "rvm/init", "init"}))

		if os.Geteuid() != 0 {
			Skip("extracting device nodes needs root")
		}
		dest := GinkgoT().TempDir()
		extract := exec.Command("sh", "-c", `"$0" -i -d --quiet < "$1"`, cpioBin, plain)
		extract.Dir = dest
		out, err := extract.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(out))

		Expect(os.ReadFile(filepath.Join(dest, "bin/busybox"))).To(Equal(busybox))
		Expect(os.ReadFile(filepath.Join(dest, "init"))).To(Equal([]byte(guestRootInit)))
		Expect(os.ReadFile(filepath.Join(dest, "rvm/init"))).To(Equal([]byte(initScript(testNonce, false))))
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
		Expect(cfg).To(Equal(config{backend: backend.VMQemu, artifacts: defaultArtifactsDir, command: "echo hi && exit 3", credhub: credhubRetry{attempts: 3, delay: time.Second},
			args: []string{"/tmp/lifecycle/launcher", "app", "echo hi && exit 3", ""}, volumeSyncMounts: true}))
	})

	It("holds back the refusal of an empty start command, which only the stack guest can run, and still parses the CredHub flags", func() {
		cfg, err := parseArgs([]string{"--backend", "vm-qemu", "--", "/tmp/lifecycle/launcher", "app", " ", "-credhubConnectAttempts=7", ""})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.commandErr).To(MatchError(errEmptyStartCommand))
		Expect(cfg.commandErr).To(MatchError(ContainSubstring("empty start command")))
		Expect(cfg.command).To(BeEmpty())
		Expect(cfg.credhub).To(Equal(credhubRetry{attempts: 7, delay: time.Second}))
		Expect(cfg.args).To(Equal([]string{"/tmp/lifecycle/launcher", "app", " ", "-credhubConnectAttempts=7", ""}))

		_, err = parseArgs([]string{"--backend", "vm-qemu", "--", "/tmp/lifecycle/launcher", "app", "", "-credhubRetryDelay=soon", ""})
		Expect(err).To(MatchError(ContainSubstring("-credhubRetryDelay")))
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
		Entry("transparent proxy for QEMU", []string{"--backend", "vm-qemu", "--transparent-proxy", "--", "true"}, "--transparent-proxy is for vm-firecracker only"),
	)

	It("takes --transparent-proxy for vm-firecracker, and leaves it off by default", func() {
		cfg, err := parseArgs([]string{"--backend", "vm-firecracker", "--transparent-proxy", "--", "true"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.transparent).To(BeTrue())

		cfg, err = parseArgs([]string{"--backend", "vm-firecracker", "--", "true"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.transparent).To(BeFalse())
	})

	It("keeps volume image mounts synchronous by default and takes --volume-sync-mounts=false on either backend", func() {
		Expect(volumeSyncMountsFlag).To(Equal("volume-sync-mounts"))
		Expect(usage).To(ContainSubstring("[--volume-sync-mounts=false]"))
		for _, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			for flags, want := range map[string]bool{"": true, "--volume-sync-mounts": true, "--volume-sync-mounts=true": true, "--volume-sync-mounts=false": false, "--volume-sync-mounts=0": false} {
				argv := []string{"--backend", string(kind)}
				if flags != "" {
					argv = append(argv, flags)
				}
				cfg, err := parseArgs(append(argv, "--", "true"))
				Expect(err).NotTo(HaveOccurred(), "%s %q", kind, flags)
				Expect(cfg.volumeSyncMounts).To(Equal(want), "%s %q", kind, flags)
			}
		}
		_, err := parseArgs([]string{"--backend", "vm-qemu", "--volume-sync-mounts=maybe", "--", "true"})
		Expect(err).To(MatchError(ContainSubstring("invalid boolean value")))
	})

	It("names the flag Garden's process builder passes", func() {
		Expect("--" + transparentProxyFlag).To(Equal(processes.VMLaunchTransparentProxyFlag))
		Expect(usage).To(ContainSubstring("[" + processes.VMLaunchTransparentProxyFlag + "]"))
	})

	It("reports help as flag.ErrHelp", func() {
		_, err := parseArgs([]string{"-h"})
		Expect(err).To(MatchError(ContainSubstring("help requested")))
	})
})

var _ = Describe("hypervisor command lines", func() {
	const art = "/opt/garden-vm/artifacts"

	It("builds the QEMU microvm command line through the bundled loader", func() {
		argv, err := hypervisorArgv(backend.VMQemu, art, "/unused", "/proc/self/fd/3", 128, taskNetwork(), nil, "", 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal([]string{
			art + "/qemu/ld-linux-x86-64.so.2", "--library-path", art + "/qemu/lib",
			art + "/qemu/qemu-system-x86_64-microvm", "-L", art + "/qemu/share",
			"-M", "microvm,accel=kvm,dump-guest-core=off", "-cpu", "host", "-smp", "1", "-m", "128",
			"-nodefaults", "-no-user-config", "-nographic", "-serial", "stdio", "-no-reboot",
			"-kernel", art + "/kernel/bzImage", "-initrd", "/proc/self/fd/3",
			"-append", "console=ttyS0 reboot=t panic=-1 rdinit=/init pci=off quiet",
			"-netdev", "user,id=n0,net=10.0.2.0/24", "-device", "virtio-net-device,netdev=n0",
			"-device", "virtio-balloon-device,id=balloon0,deflate-on-oom=on,free-page-reporting=on",
		}))
	})

	It("writes the Firecracker config and builds its command line", func() {
		work := GinkgoT().TempDir()
		argv, err := hypervisorArgv(backend.VMFirecracker, art, work, "/proc/self/fd/3", 128, taskNetwork(), nil, "", 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal([]string{art + "/firecracker/firecracker", "--api-sock", work + "/fc.sock", "--config-file", work + "/fc.json"}))

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
			"balloon": map[string]any{
				"amount_mib":               float64(0),
				"deflate_on_oom":           true,
				"stats_polling_interval_s": float64(5),
				"free_page_reporting":      true,
			},
		}))
	})

	It("rejects other backends", func() {
		_, err := hypervisorArgv(backend.OCIRunc, art, "/w", "/w/i", 128, taskNetwork(), nil, "", 0)
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
		sup = supervisor{stdout: out, logger: log.New(logBuf, "", 0), signals: signals, grace: 200 * time.Millisecond, deadline: 200 * time.Millisecond}
	})

	// fakeHypervisor stands in for QEMU or Firecracker: a shell that writes
	// console bytes to stdout.
	fakeHypervisor := func(script string) *exec.Cmd {
		return exec.Command("/bin/sh", "-c", script)
	}
	startLine := `printf 'boot noise\r\nRVM_START_` + testNonce + `\r\n'; `

	It("streams output and reports the guest status", func(ctx SpecContext) {
		res, err := sup.run(fakeHypervisor(startLine+`printf 'out\r\nRVM_EXIT_`+testNonce+`=42\r\n'`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("out\n"))
		Expect(codeOf(res)).To(Equal(42))
	}, SpecTimeout(time.Minute))

	It("kills a hypervisor that hangs after the guest reported", func(ctx SpecContext) {
		began := time.Now()
		res, err := sup.run(fakeHypervisor(startLine+`printf 'RVM_EXIT_`+testNonce+`=7\n'; exec sleep 60`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(time.Since(began)).To(BeNumerically("<", 10*time.Second))
		Expect(codeOf(res)).To(Equal(7))
		Expect(logBuf.String()).To(ContainSubstring("killing it"))
	}, SpecTimeout(time.Minute))

	It("forwards SIGTERM that comes before the guest started its command and exits 128+15", func(ctx SpecContext) {
		signals <- syscall.SIGTERM
		res, err := sup.run(fakeHypervisor(`exec sleep 60`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.received).To(Equal(syscall.SIGTERM))
		Expect(codeOf(res)).To(Equal(143))
		Expect(logBuf.String()).To(HavePrefix("received terminated before the guest started its command, forwarding it to the hypervisor\n"))
	}, SpecTimeout(time.Minute))

	It("runs the port-closing hook once, when the deadline kills a guest it asked to stop, after the kill's line", func(ctx SpecContext) {
		calls := 0
		sup.closePorts = func() {
			calls++
			sup.logger.Print("closing the ports")
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
		Expect(logBuf.String()).To(Equal("received interrupt, asking the guest command to stop\n" +
			"received terminated again; the guest is already stopping\n" +
			"the guest did not stop within 200ms of the signal; killing the hypervisor\n" +
			"closing the ports\n"))
	}, SpecTimeout(time.Minute))

	It("kills a hypervisor that ignores the forwarded signal", func(ctx SpecContext) {
		trapped := filepath.Join(GinkgoT().TempDir(), "trapped")
		// Signal only once the trap is installed, which the file proves.
		sup.started = func() {
			defer GinkgoRecover()
			Eventually(trapped, 10*time.Second, 5*time.Millisecond).Should(BeAnExistingFile())
			signals <- syscall.SIGINT
		}
		res, err := sup.run(fakeHypervisor(`trap '' INT; : >'`+trapped+`'; exec sleep 60`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(130))
		Expect(logBuf.String()).To(Equal("received interrupt before the guest started its command, forwarding it to the hypervisor\n" +
			"the guest did not stop within 200ms of the signal; killing the hypervisor\n" +
			"guest never started its command and wrote no console output\n"))
	}, SpecTimeout(time.Minute))

	It("reports a failing hypervisor with its console output", func(ctx SpecContext) {
		res, err := sup.run(fakeHypervisor(`printf 'Could not access KVM kernel module\n'; exit 1`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(codeOf(res)).To(Equal(exitHypervisorFailed))
		Expect(out.String()).To(BeEmpty())
		Expect(logBuf.String()).To(ContainSubstring("guest never started its command"))
		Expect(logBuf.String()).To(ContainSubstring("Could not access KVM kernel module"))
	}, SpecTimeout(time.Minute))

	It("reports a guest that ends without a status", func(ctx SpecContext) {
		res, err := sup.run(fakeHypervisor(startLine+`printf 'partial'`), testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("partial"))
		Expect(codeOf(res)).To(Equal(exitMissingMarker))
	}, SpecTimeout(time.Minute))

	It("fails when the hypervisor cannot be started", func(ctx SpecContext) {
		_, err := sup.run(exec.Command("/nonexistent/qemu"), testNonce)
		Expect(err).To(MatchError(ContainSubstring("starting hypervisor /nonexistent/qemu")))
	}, SpecTimeout(time.Minute))
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

// rootImageAt is fake hypervisor shell that fails unless its file descriptor
// fd is the guest root image: a regular file of size bytes with mode 0600,
// open for writing, whose name is gone. The write goes through a new open
// without O_TRUNC, which the image allows because the hypervisor reopens it
// by /proc/self/fd/N.
func rootImageAt(fd string, size int64) string {
	return `case "$(readlink /proc/self/fd/` + fd + `)" in */root.img\ \(deleted\)) ;; *) echo "fd ` + fd + ` is not the unlinked root image" >&2; exit 1 ;; esac
[ "$(stat -L -c '%F %s %a' /proc/self/fd/` + fd + `)" = "regular file ` + strconv.FormatInt(size, 10) + ` 600" ] || { echo "fd ` + fd + ` is not a 0600 regular file of ` + strconv.FormatInt(size, 10) + ` bytes" >&2; exit 1; }
exec 8<>/proc/self/fd/` + fd + ` && printf x >&8 || { echo "cannot write to the root image" >&2; exit 1; }
exec 8>&-
`
}

// rootImageReleased is fake hypervisor shell that waits up to five seconds
// for its parent, vm-launch, to close its copy of the guest root image, and
// fails when it never does. The hypervisor's own copy stays open.
const rootImageReleased = `n=0
ls /proc/$PPID/fd >/dev/null 2>&1 || { echo "cannot read the descriptors of vm-launch" >&2; exit 1; }
while for l in /proc/$PPID/fd/*; do readlink "$l"; done 2>/dev/null | grep -q -F 'root.img (deleted)'; do
	n=$((n + 1))
	[ "$n" -gt 100 ] && { echo "vm-launch still holds the root image" >&2; exit 1; }
	sleep 0.05
done
`

// noRootImage is fake hypervisor shell that fails when it has a file
// descriptor for a guest root image.
const noRootImage = `for l in /proc/self/fd/*; do
	case "$(readlink "$l" 2>/dev/null)" in *root.img*) echo "the hypervisor has a root image without a disk quota" >&2; exit 1 ;; esac
done
`

var _ = Describe("run with a guest root image", func() {
	const (
		diskMiB = 64
		// rootSize is what the image has for a disk quota of diskMiB when the
		// work directory has room: the quota less the headroom.
		rootSize = (diskMiB - rootDiskHeadroomMiB) * bytesPerMiB
	)

	var (
		art    string
		tmp    string
		logBuf *bytes.Buffer
	)

	BeforeEach(func() {
		art = makeArtifacts()
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		GinkgoT().Setenv("VCAP_APPLICATION", fmt.Sprintf(`{"limits":{"disk":%d}}`, diskMiB))
		logBuf = &bytes.Buffer{}
	})

	runVM := func(kind backend.Kind) int {
		return run([]string{"--backend", string(kind), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}, log.New(logBuf, "", 0))
	}

	It("gives QEMU the root image as the file descriptor after the initramfs, with discard, and keeps nothing on disk", func() {
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"),
			initramfsAt("3")+rootImageAt("5", rootSize)+noFilesUnder(tmp)+initramfsReleased+rootImageReleased)
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())

		argv, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(argv)).To(HaveSuffix("\n" + strings.Join(concat(goldenQEMUMonitor("4"), goldenQEMURootDrive("5"), goldenQEMUBalloon), "\n") + "\n"))
		Expect(string(argv)).To(ContainSubstring("\n-initrd\n/proc/self/fd/3\n"))
		Expect(logBuf.String()).NotTo(ContainSubstring("does not apply"))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("gives Firecracker the root image as a drive with discard on the Sync engine", func() {
		letFirecrackerSeeVMLaunch()
		// The copy goes outside TMPDIR, which must stay empty.
		fcCopy := filepath.Join(art, "fc-copy.json")
		writeFakeHypervisor(filepath.Join(art, "firecracker/firecracker"),
			`p=; for a in "$@"; do [ "$p" = --config-file ] && cp "$a" `+shellQuote(fcCopy)+`; p=$a; done
`+initramfsAt("3")+rootImageAt("4", rootSize)+noFilesUnder(tmp)+initramfsReleased+rootImageReleased)
		Expect(runVM(backend.VMFirecracker)).To(Equal(0), logBuf.String())

		cfg, err := os.ReadFile(fcCopy)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(cfg)).To(ContainSubstring(`"drives":[` + goldenFCRootDrive + `]`))
		Expect(string(cfg)).To(ContainSubstring(`"initrd_path":"/proc/self/fd/3"`))
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("closes its copy of the root image when the hypervisor cannot be started", func() {
		Expect(os.Remove(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"))).To(Succeed())
		Expect(os.WriteFile(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), []byte("not runnable"), 0o644)).To(Succeed())
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("starting hypervisor"))
		Expect(heldRootImages()).To(BeZero())
	})

	It("exits 125 with the quota line before the hypervisor starts when too little quota is left", func() {
		GinkgoT().Setenv("VCAP_APPLICATION", `{"limits":{"disk":40}}`)
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("the app's disk limit is 40 MiB, and the guest root needs at least 48 MiB of it, which is 16 MiB plus 32 MiB kept for other writers; raise the app's disk quota"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(heldRootImages()).To(BeZero())
	})

	It("exits 125 with a clear line, and no image, when the work directory is on another filesystem than the root", func() {
		var root, shm unix.Stat_t
		Expect(unix.Stat("/", &root)).To(Succeed())
		if err := unix.Stat("/dev/shm", &shm); err != nil || shm.Dev == root.Dev {
			Skip("/dev/shm is not on another filesystem than /")
		}
		other, err := os.MkdirTemp("/dev/shm", "vm-launch-spec-")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(other)).To(Succeed()) })
		GinkgoT().Setenv("TMPDIR", other)
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")

		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring(other + "/vm-launch-"))
		Expect(logBuf.String()).To(ContainSubstring("is not on the container's root filesystem, whose disk quota the guest root is sized from; unset TMPDIR or point it at a directory on the root filesystem"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(other)).To(BeEmpty())
		Expect(heldRootImages()).To(BeZero())
	})

	It("exits 125 with the image error before the hypervisor starts when the image cannot be sized", func() {
		saved := truncateRootImage
		DeferCleanup(func() { truncateRootImage = saved })
		truncateRootImage = func(*os.File, int64) error { return syscall.EDQUOT }
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM(backend.VMQemu)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("creating the guest root image in "))
		Expect(logBuf.String()).To(ContainSubstring("sizing it to"))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(heldRootImages()).To(BeZero())
	})

	It("keeps the RAM root, with no drive and one line, for a missing or malformed disk limit", func() {
		for name, app := range map[string]string{
			"no limits":          `{"name":"app"}`,
			"no limits.disk":     `{"limits":{"mem":512}}`,
			"a disk of zero":     `{"limits":{"disk":0}}`,
			"a negative disk":    `{"limits":{"disk":-1}}`,
			"a disk that's text": `{"limits":{"disk":"lots"}}`,
			"not JSON":           `nope`,
		} {
			logBuf.Reset()
			GinkgoT().Setenv("VCAP_APPLICATION", app)
			argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), initramfsAt("3")+noRootImage+noFilesUnder(tmp))
			Expect(runVM(backend.VMQemu)).To(Equal(0), name+": "+logBuf.String())

			argv, err := os.ReadFile(argvFile)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(argv)).NotTo(ContainSubstring("-drive"), name)
			Expect(strings.Count(logBuf.String(), "the disk quota does not apply to the guest root")).To(Equal(1), name+": "+logBuf.String())
		}
	})

	It("keeps the RAM root when VCAP_APPLICATION is unset", func() {
		Expect(os.Unsetenv("VCAP_APPLICATION")).To(Succeed())
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), initramfsAt("3")+noRootImage)
		Expect(runVM(backend.VMQemu)).To(Equal(0), logBuf.String())
		argv, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(argv)).NotTo(ContainSubstring("-drive"))
	})
})

// heldRootImages counts this process's descriptors for an unlinked guest
// root image.
func heldRootImages() int {
	entries, err := os.ReadDir("/proc/self/fd")
	Expect(err).NotTo(HaveOccurred())
	n := 0
	for _, e := range entries {
		if link, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && strings.HasSuffix(link, "/"+rootImageName+" (deleted)") {
			n++
		}
	}
	return n
}

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

var _ = Describe("stackCommand", func() {
	It("passes the launcher's whole argv, quoted, after the guest's launcher path", func() {
		argv, retry, err := stackCommand([]string{"/tmp/lifecycle/launcher", "app", "", ""})
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(Equal(`'/tmp/lifecycle/launcher' 'app' '' ''`))
		Expect(retry).To(Equal(defaultCredhubRetry))
	})

	It("replaces the host's path to the launcher", func() {
		argv, _, err := stackCommand([]string{"/some/where/launcher", "app", "start", "{}"})
		Expect(err).NotTo(HaveOccurred())
		Expect(argv).To(HavePrefix(`'/tmp/lifecycle/launcher' `))
	})

	It("keeps a start command with quotes, dollar signs, and newlines whole", func() {
		start := "echo 'it'\"s\" $HOME `id`\nexit \\1"
		argv, _, err := stackCommand([]string{"/tmp/lifecycle/launcher", "app", start, `{"a":"b"}`})
		Expect(err).NotTo(HaveOccurred())

		out, err := exec.Command("sh", "-c", `set -- `+argv+`; printf '%s\0' "$@"`).Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")).To(Equal(
			[]string{"/tmp/lifecycle/launcher", "app", start, `{"a":"b"}`}))
	})

	It("gives the CredHub retry settings that wrappedCommand gives", func() {
		args := []string{"/tmp/lifecycle/launcher", "app", "true", "-credhubConnectAttempts=7", "-credhubRetryDelay=2s", "{}"}
		_, want, err := wrappedCommand(args)
		Expect(err).NotTo(HaveOccurred())

		argv, got, err := stackCommand(args)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(want))
		Expect(got).To(Equal(credhubRetry{attempts: 7, delay: 2 * time.Second}))
		Expect(argv).To(HaveSuffix(`'-credhubConnectAttempts=7' '-credhubRetryDelay=2s' '{}'`))
	})

	It("refuses a launcher without a start command argument", func() {
		_, _, err := stackCommand([]string{"/tmp/lifecycle/launcher", "app"})
		Expect(err).To(MatchError(ContainSubstring("want APP-DIR START-COMMAND")))
	})

	It("refuses a process that is not the launcher, and an empty argv", func() {
		_, _, err := stackCommand([]string{"/bin/true"})
		Expect(err).To(MatchError(ContainSubstring("CF launcher")))
		_, _, err = stackCommand(nil)
		Expect(err).To(HaveOccurred())
	})

	It("refuses CredHub flags that do not parse", func() {
		_, _, err := stackCommand([]string{"/tmp/lifecycle/launcher", "app", "", "-credhubRetryDelay=soon", "{}"})
		Expect(err).To(MatchError(ContainSubstring("-credhubRetryDelay")))
	})

	It("leaves wrappedCommand's behavior alone", func() {
		cmd, _, err := wrappedCommand([]string{"/tmp/lifecycle/launcher", "app", "run it", "{}"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cmd).To(Equal("run it"))
		_, _, err = wrappedCommand([]string{"/tmp/lifecycle/launcher", "app", " ", "{}"})
		Expect(err).To(MatchError(ContainSubstring("empty start command")))
		cmd, _, err = wrappedCommand([]string{"/bin/echo", "a b"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cmd).To(Equal(`'/bin/echo' 'a b'`))
	})
})

// heldFilesEndingIn counts this process's descriptors whose target ends
// with suffix.
func heldFilesEndingIn(suffix string) int {
	entries, err := os.ReadDir("/proc/self/fd")
	Expect(err).NotTo(HaveOccurred())
	n := 0
	for _, e := range entries {
		if link, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && strings.HasSuffix(link, suffix) {
			n++
		}
	}
	return n
}

// readOnlyImageAt is fake hypervisor shell that fails unless its file
// descriptor fd is open for reading only, its target matches the shell
// pattern target, and its content is the file at want.
func readOnlyImageAt(fd, target, want string) string {
	return `case "$(readlink /proc/self/fd/` + fd + `)" in ` + target + `) ;; *) echo "fd ` + fd + ` is $(readlink /proc/self/fd/` + fd + `)" >&2; exit 1 ;; esac
flags=$(awk '/^flags:/ { print $2 }' /proc/self/fdinfo/` + fd + `)
[ $((flags & 3)) -eq 0 ] || { echo "fd ` + fd + ` is open with flags $flags, not for reading only" >&2; exit 1; }
[ "$(sha256sum </proc/self/fd/` + fd + `)" = "$(sha256sum <` + shellQuote(want) + `)" ] || { echo "fd ` + fd + ` does not hold ` + want + `" >&2; exit 1; }
`
}

// stackImagesReleased is fake hypervisor shell that waits up to five seconds
// for its parent, vm-launch, to close its copies of the stack and droplet
// images, and fails when it never does. The hypervisor's own copies stay
// open.
const stackImagesReleased = `n=0
ls /proc/$PPID/fd >/dev/null 2>&1 || { echo "cannot read the descriptors of vm-launch" >&2; exit 1; }
while for l in /proc/$PPID/fd/*; do readlink "$l"; done 2>/dev/null | grep -q -e 'rootfs.squashfs$' -e 'droplet.sqfs (deleted)$' -e '/launcher$'; do
	n=$((n + 1))
	[ "$n" -gt 100 ] && { echo "vm-launch still holds the stack image, the droplet image, or the launcher" >&2; exit 1; }
	sleep 0.05
done
`

var _ = Describe("run with a stack image", func() {
	const (
		hostname = "c0ffee00-1111-4222-8333-444455556666"
		hosts    = "127.0.0.1 localhost\n10.255.7.9 " + hostname + "\n"
		// dropletBuilder is a fake mksquashfs that writes a short file in
		// place of the image, which names the directory it packs.
		dropletBuilder = "#!/bin/sh\nprintf 'droplet of %s' \"$1\" >\"$2\"\n"
	)

	var (
		art       string
		tmp       string
		dir       string
		stackImg  string
		home      string
		launcher  string
		logBuf    *bytes.Buffer
		qemu      string
		launchArg []string
	)

	BeforeEach(func() {
		art = makeArtifacts()
		qemu = filepath.Join(art, "qemu/ld-linux-x86-64.so.2")
		Expect(os.WriteFile(filepath.Join(art, artMksquashfs), []byte(dropletBuilder), 0o755)).To(Succeed())
		// Every other file of a spec lives in dir, outside the TMPDIR that
		// the specs check for leftovers.
		dir = GinkgoT().TempDir()
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		GinkgoT().Setenv("VCAP_APPLICATION", `{"limits":{"mem":512}}`)
		logBuf = &bytes.Buffer{}

		stackImg = filepath.Join(dir, "rootfs.squashfs")
		writeSuperblock(stackImg, squashfsMagic, squashfsCompressorLZ4)
		home = filepath.Join(dir, "home")
		Expect(os.MkdirAll(filepath.Join(home, "app"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "hosts"), []byte(hosts), 0o644)).To(Succeed())
		launcher = filepath.Join(dir, "lifecycle", "launcher")
		Expect(os.MkdirAll(filepath.Dir(launcher), 0o755)).To(Succeed())
		Expect(os.WriteFile(launcher, []byte("#!/bin/sh\necho the launcher\n"), 0o755)).To(Succeed())
		launchArg = []string{launcher, "app", "", ""}

		savedImage, savedHome, savedHosts, savedHostname, savedNonce, savedStatfs := stackImagePath, dropletHome, containerHostsPath, containerHostname, guestNonce, workDirStatfs
		DeferCleanup(func() {
			stackImagePath, dropletHome, containerHostsPath, containerHostname, guestNonce, workDirStatfs = savedImage, savedHome, savedHosts, savedHostname, savedNonce, savedStatfs
		})
		stackImagePath = stackImg
		dropletHome = home
		containerHostsPath = filepath.Join(dir, "hosts")
		containerHostname = func() (string, error) { return hostname, nil }
		guestNonce = func() (string, error) { return testNonce, nil }
	})

	runWith := func(kind backend.Kind, args []string) int {
		return run(append([]string{"--backend", string(kind), "--artifacts", art, "--"}, args...), log.New(logBuf, "", 0))
	}

	// guestOf runs a QEMU guest for args and returns the initramfs and the
	// command line its fake hypervisor got.
	guestOf := func(args []string) (initrd, argv []byte) {
		GinkgoHelper()
		initrdCopy := filepath.Join(art, "initrd-copy")
		argvFile := writeFakeHypervisor(qemu, `cp "$initrd" `+shellQuote(initrdCopy)+" || exit 1\n")
		Expect(runWith(backend.VMQemu, args)).To(Equal(0), logBuf.String())
		initrd, err := os.ReadFile(initrdCopy)
		Expect(err).NotTo(HaveOccurred())
		argv, err = os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		return initrd, argv
	}

	// todaysGuestOf is guestOf for a container without a stack image, whose
	// guest is the busybox guest of every launch before the stack guest.
	todaysGuestOf := func(args []string) (initrd, argv []byte) {
		GinkgoHelper()
		stackImagePath = filepath.Join(dir, "none", "rootfs.squashfs")
		defer func() { stackImagePath = stackImg }()
		return guestOf(args)
	}

	// expectTodaysGuest checks that args give the busybox guest byte for
	// byte, with the mode line that says why.
	expectTodaysGuest := func(args []string, why string) {
		GinkgoHelper()
		initrd, argv := guestOf(args)
		Expect(logBuf.String()).To(ContainSubstring("busybox guest: " + why + "\n"))
		Expect(logBuf.String()).NotTo(ContainSubstring("stack guest:"))
		Expect(strings.Count(logBuf.String(), "guest: ")).To(Equal(1), logBuf.String())
		Expect(argv).NotTo(ContainSubstring("rvm-stack"))
		_, byName := archiveEntries(initrd)
		Expect(string(byName["init"].data)).To(Equal(guestRootInit))
		Expect(byName).NotTo(HaveKey("rvm/lifecycle/launcher"))
		Expect(byName).NotTo(HaveKey("rvm/argv"))

		wantInitrd, wantArgv := todaysGuestOf(args)
		Expect(initrd).To(Equal(wantInitrd))
		Expect(argv).To(Equal(wantArgv))
		Expect(heldFilesEndingIn("rootfs.squashfs")).To(BeZero())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	}

	It("gives QEMU the stack and the droplet as read-only drives after the root image, and a guest that runs the launcher's whole argv", func() {
		GinkgoT().Setenv("VCAP_APPLICATION", `{"limits":{"disk":64}}`)
		want := filepath.Join(dir, "droplet")
		Expect(os.WriteFile(want, []byte("droplet of "+home), 0o644)).To(Succeed())
		initrdCopy := filepath.Join(art, "initrd-copy")
		argvFile := writeFakeHypervisor(qemu, `cp "$initrd" `+shellQuote(initrdCopy)+` || exit 1
`+initramfsAt("3")+rootImageAt("5", (64-rootDiskHeadroomMiB)*bytesPerMiB)+
			readOnlyImageAt("6", "*/rootfs.squashfs", stackImg)+
			readOnlyImageAt("7", `*/droplet.sqfs\ \(deleted\)`, want)+
			noFilesUnder(tmp)+initramfsReleased+rootImageReleased+stackImagesReleased)
		Expect(runWith(backend.VMQemu, launchArg)).To(Equal(0), logBuf.String())

		argv, err := os.ReadFile(argvFile)
		Expect(err).NotTo(HaveOccurred())
		drives := concat(goldenQEMUMonitor("4"), goldenQEMURootDrive("5"), qemuReadOnlyDrive(stackDriveID, qemuStackSerial, 6), qemuReadOnlyDrive(dropletDriveID, qemuDropletSerial, 7), goldenQEMUBalloon)
		Expect(string(argv)).To(HaveSuffix("\n" + strings.Join(drives, "\n") + "\n"))

		raw, err := os.ReadFile(initrdCopy)
		Expect(err).NotTo(HaveOccurred())
		_, byName := archiveEntries(raw)
		Expect(string(byName["init"].data)).To(Equal(guestStackInit))
		Expect(string(byName["rvm/init"].data)).To(Equal(stackInitScript(testNonce)))
		Expect(string(byName["rvm/lifecycle/launcher"].data)).To(Equal("#!/bin/sh\necho the launcher\n"))
		Expect(string(byName["rvm/argv"].data)).To(Equal(`'/tmp/lifecycle/launcher' 'app' '' ''`))
		cwd, err := os.Getwd()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(byName["rvm/cwd"].data)).To(Equal(cwd))
		Expect(string(byName["rvm/hosts"].data)).To(Equal(hosts))
		Expect(string(byName["rvm/hostname"].data)).To(Equal(hostname + "\n"))
		Expect(string(byName["rvm/disks"].data)).To(Equal("RVM_ROOT_ID=rvm-root\nRVM_ROOT_SECTORS=65536\nRVM_ROOT_INODE_RATIO=16384\nRVM_VOLUMES=0\nRVM_STACK_ID=rvm-stack\nRVM_DROPLET_ID=rvm-droplet\n"))

		Expect(logBuf.String()).To(MatchRegexp(`(?m)^stack guest: the launcher runs on the stack image, with a droplet image of ` + regexp.QuoteMeta(home) + ` that is ` + strconv.Itoa(len("droplet of "+home)) + ` bytes and took \S+ to build$`))
		Expect(strings.Count(logBuf.String(), "guest: ")).To(Equal(1), logBuf.String())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(heldFilesEndingIn("rootfs.squashfs")).To(BeZero())
		Expect(heldFilesEndingIn("droplet.sqfs (deleted)")).To(BeZero())
	})

	It("gives Firecracker the stack and the droplet as read-only drives after the volumes and the root", func() {
		letFirecrackerSeeVMLaunch()
		fcCopy := filepath.Join(art, "fc-copy.json")
		writeFakeHypervisor(filepath.Join(art, "firecracker/firecracker"),
			`p=; for a in "$@"; do [ "$p" = --config-file ] && cp "$a" `+shellQuote(fcCopy)+`; p=$a; done
`+initramfsAt("3")+readOnlyImageAt("4", "*/rootfs.squashfs", stackImg)+stackImagesReleased)
		Expect(runWith(backend.VMFirecracker, []string{launcher, "app", "./server", "{}"})).To(Equal(0), logBuf.String())

		raw, err := os.ReadFile(fcCopy)
		Expect(err).NotTo(HaveOccurred())
		var cfg struct {
			Drives []firecrackerDrive `json:"drives"`
		}
		Expect(json.Unmarshal(raw, &cfg)).To(Succeed())
		Expect(cfg.Drives).To(HaveLen(2))
		Expect(cfg.Drives[0].PathOnHost).To(Equal("/proc/self/fd/4"))
		Expect(cfg.Drives[1].PathOnHost).To(Equal("/proc/self/fd/5"))
		for _, d := range cfg.Drives {
			Expect(d.IsReadOnly).To(BeTrue(), d.DriveID)
			Expect(d.IsRootDevice).To(BeFalse(), d.DriveID)
		}
		Expect(logBuf.String()).To(ContainSubstring("stack guest: "))
	})

	It("builds the droplet image before it sizes the guest root, so the root gets only the quota the droplet leaves", func() {
		GinkgoT().Setenv("VCAP_APPLICATION", `{"limits":{"disk":64}}`)
		held := -1
		workDirStatfs = func(path string, st *unix.Statfs_t) error {
			held = heldFilesEndingIn("droplet.sqfs (deleted)")
			return unix.Statfs(path, st)
		}
		writeFakeHypervisor(qemu, "")
		Expect(runWith(backend.VMQemu, launchArg)).To(Equal(0), logBuf.String())
		Expect(held).To(Equal(1))
	})

	It("keeps today's guest for a process that is not the CF launcher", func() {
		expectTodaysGuest([]string{"/bin/sh", "-c", "echo hi"}, "the process is not the CF launcher")
	})

	It("keeps today's guest when the container has no stack image", func() {
		stackImagePath = filepath.Join(dir, "none", "rootfs.squashfs")
		_, argv := guestOf([]string{launcher, "app", "true", ""})
		Expect(argv).NotTo(ContainSubstring("rvm-stack"))
		Expect(logBuf.String()).To(ContainSubstring("busybox guest: the stack image cannot be opened: open " + stackImagePath + ": no such file or directory\n"))
	})

	It("keeps today's guest when the stack image is not an lz4 squashfs", func() {
		Expect(os.Remove(stackImg)).To(Succeed())
		writeSuperblock(stackImg, squashfsMagic, 1)
		expectTodaysGuest([]string{launcher, "app", "true", ""}, "the stack image "+stackImg+" uses squashfs compressor 1, and the guest reads only lz4")
	})

	It("keeps today's guest when the droplet image does not build, with the tool's output on the line", func() {
		Expect(os.WriteFile(filepath.Join(art, artMksquashfs), []byte("#!/bin/sh\necho 'cannot read the droplet' >&2\nexit 1\n"), 0o755)).To(Succeed())
		expectTodaysGuest([]string{launcher, "app", "true", ""}, "building the droplet image with "+filepath.Join(art, artMksquashfs)+": exit status 1; cannot read the droplet")
	})

	It("keeps today's guest when the container's hostname is not one the stack guest accepts", func() {
		containerHostname = func() (string, error) { return "web_1", nil }
		_, argv := guestOf([]string{launcher, "app", "true", ""})
		Expect(argv).NotTo(ContainSubstring("rvm-stack"))
		Expect(logBuf.String()).To(ContainSubstring("busybox guest: "))
		Expect(logBuf.String()).NotTo(ContainSubstring("stack guest:"))
		Expect(strings.Count(logBuf.String(), "guest: ")).To(Equal(1), logBuf.String())
		Expect(heldFilesEndingIn("rootfs.squashfs")).To(BeZero())
		Expect(heldFilesEndingIn("/launcher")).To(BeZero())
	})

	It("keeps today's guest for an app with a volume", func() {
		volDir := filepath.Join(dir, "volume")
		infoDir := filepath.Join(dir, "info")
		Expect(os.Mkdir(volDir, 0o755)).To(Succeed())
		Expect(os.Mkdir(infoDir, 0o755)).To(Succeed())
		savedInfo, savedOpts := mountInfoPath, defaultImageOptions
		DeferCleanup(func() { mountInfoPath, defaultImageOptions = savedInfo, savedOpts })
		mountInfoPath = filepath.Join(infoDir, "mountinfo")
		Expect(os.WriteFile(mountInfoPath, []byte(mountinfoLine(40, volDir, "fuse.juicefs")), 0o644)).To(Succeed())
		defaultImageOptions.IsMountRoot = alwaysMountRoot
		GinkgoT().Setenv("CF_INSTANCE_INDEX", "2")
		GinkgoT().Setenv("VCAP_APPLICATION", vcapApp)
		GinkgoT().Setenv("VCAP_SERVICES", vcapWith(map[string][]string{"juicefs": {mountJSON(volDir, "rw")}}))
		img := filepath.Join(volDir, "rvm-disk-"+testAppID+"-web-2.img")

		initrd, argv := guestOf([]string{launcher, "app", "true", ""})
		Expect(logBuf.String()).To(ContainSubstring("busybox guest: the app has a volume, which the stack guest does not mount yet\n"))
		Expect(argv).NotTo(ContainSubstring("rvm-stack"))
		Expect(heldFilesEndingIn("rootfs.squashfs")).To(BeZero())
		// Each launch starts from no image, so both create it alike.
		Expect(os.Remove(img)).To(Succeed())
		wantInitrd, wantArgv := todaysGuestOf([]string{launcher, "app", "true", ""})
		Expect(initrd).To(Equal(wantInitrd))
		Expect(argv).To(Equal(wantArgv))
	})

	It("refuses an empty start command after the line that says why when the guest is the busybox guest", func() {
		stackImagePath = filepath.Join(dir, "none", "rootfs.squashfs")
		argvFile := writeFakeHypervisor(qemu, "")
		Expect(runWith(backend.VMQemu, launchArg)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(HavePrefix("busybox guest: the stack image cannot be opened: "))
		Expect(logBuf.String()).To(HaveSuffix("\n" + errEmptyStartCommand.Error() + "\n" + usage))
		Expect(argvFile).NotTo(BeAnExistingFile())

		logBuf.Reset()
		stackImagePath = stackImg
		Expect(os.WriteFile(filepath.Join(art, artMksquashfs), []byte("#!/bin/sh\nexit 1\n"), 0o755)).To(Succeed())
		Expect(runWith(backend.VMQemu, launchArg)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("busybox guest: building the droplet image with "))
		Expect(logBuf.String()).To(ContainSubstring(errEmptyStartCommand.Error()))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
		Expect(heldFilesEndingIn("rootfs.squashfs")).To(BeZero())
		Expect(heldFilesEndingIn("/launcher")).To(BeZero())
	})

	It("keeps today's guest for a launcher argv over the stack guest's limit, with the reason on the line", func() {
		_, argv := guestOf([]string{launcher, "app", "true", strings.Repeat("m", maxGuestCommandBytes)})
		Expect(argv).NotTo(ContainSubstring("rvm-stack"))
		Expect(logBuf.String()).To(ContainSubstring("busybox guest: the launcher's argv is "))
		Expect(logBuf.String()).NotTo(ContainSubstring("stack guest:"))
		Expect(heldFilesEndingIn("rootfs.squashfs")).To(BeZero())
		Expect(heldFilesEndingIn("/launcher")).To(BeZero())
	})

	It("closes the stack image, the droplet image, and the launcher when the hypervisor cannot be started", func() {
		Expect(os.Remove(qemu)).To(Succeed())
		Expect(os.WriteFile(qemu, []byte("not runnable"), 0o644)).To(Succeed())
		Expect(runWith(backend.VMQemu, launchArg)).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring("starting hypervisor"))
		Expect(logBuf.String()).To(ContainSubstring("stack guest: "))
		Expect(heldFilesEndingIn("rootfs.squashfs")).To(BeZero())
		Expect(heldFilesEndingIn("droplet.sqfs (deleted)")).To(BeZero())
		Expect(heldFilesEndingIn("/launcher")).To(BeZero())
		Expect(heldInitramfs()).To(BeZero())
	})

	Describe("with sidecars and the instance identity pair", func() {
		const (
			twoSidecars = `{"version":1,"sidecars":[` +
				`{"args":["app","./side --port 8081",""],"log_source":"APP/PROC/WEB/SIDECAR/ONE"},` +
				`{"args":["app","./other 'quoted' $HOME",""],"env":["SIDE=1","HOME=/elsewhere"],"unset":["LANG"],"log_source":"APP/PROC/WEB/SIDECAR/TWO"}]}`
			oneSidecar = `{"version":1,"sidecars":[{"args":["app","./side",""]}]}`
		)

		var (
			ca                *identityCA
			certPath, keyPath string
			certPEM, keyPEM   []byte
			notAfter          time.Time
			built             guestContents
		)

		BeforeEach(func() {
			ca = newIdentityCA()
			creds := filepath.Join(dir, "creds")
			Expect(os.Mkdir(creds, 0o755)).To(Succeed())
			certPath, keyPath = filepath.Join(creds, "instance.crt"), filepath.Join(creds, "instance.key")
			notAfter = time.Now().Add(time.Hour).Truncate(time.Second)
			certPEM, keyPEM = ca.issue(4242, notAfter)
			Expect(os.WriteFile(certPath, certPEM, 0o644)).To(Succeed())
			Expect(os.WriteFile(keyPath, keyPEM, 0o644)).To(Succeed())

			saved := buildGuestInitramfs
			DeferCleanup(func() { buildGuestInitramfs = saved })
			built = guestContents{}
			buildGuestInitramfs = func(busybox string, g guestContents) (*os.File, error) {
				built = g
				return saved(busybox, g)
			}
		})

		withPair := func() {
			GinkgoT().Setenv("CF_INSTANCE_CERT", certPath)
			GinkgoT().Setenv("CF_INSTANCE_KEY", keyPath)
		}

		It("gives a launcher with two sidecars and a pair a guest that holds both, and keeps the two names", func() {
			withPair()
			GinkgoT().Setenv("LANG", "en_US.UTF-8")
			GinkgoT().Setenv(sidecarsEnvVar, twoSidecars)
			writeFakeHypervisor(qemu, "")
			Expect(runWith(backend.VMQemu, launchArg)).To(Equal(0), logBuf.String())

			Expect(built.stack).NotTo(BeNil())
			sidecars, id := built.stack.sidecars, built.stack.identity
			Expect(sidecars).To(Equal([]guestSidecar{
				{argv: `'/tmp/lifecycle/launcher' 'app' './side --port 8081' ''`},
				{argv: `'/tmp/lifecycle/launcher' 'app' './other '\''quoted'\'' $HOME' ''`, env: "export SIDE='1'\nunset LANG\n"},
			}))
			Expect(id).NotTo(BeNil())
			Expect(id.cert).To(Equal(certPEM))
			Expect(id.key).To(Equal(keyPEM))
			Expect(id.serial).To(Equal("4242"))

			Expect(built.env).To(ContainSubstring("export CF_INSTANCE_CERT='/etc/cf-instance-credentials/instance.crt'\n"))
			Expect(built.env).To(ContainSubstring("export CF_INSTANCE_KEY='/etc/cf-instance-credentials/instance.key'\n"))
			Expect(built.env).NotTo(ContainSubstring(sidecarsEnvVar))
			Expect(logBuf.String()).To(MatchRegexp(`(?m)^stack guest: the launcher runs on the stack image, with a droplet image of .* to build; ` +
				`2 sidecars run beside the app, with the log sources "APP/PROC/WEB/SIDECAR/ONE" and "APP/PROC/WEB/SIDECAR/TWO"; the instance identity has serial 4242 and expires ` + regexp.QuoteMeta(notAfter.UTC().Format(time.RFC3339)) + `$`))
			Expect(strings.Count(logBuf.String(), "guest: ")).To(Equal(1), logBuf.String())
			Expect(logBuf.String()).NotTo(ContainSubstring("BEGIN"))
		})

		It("leaves out the pair and its names when the files are missing, and still carries the sidecars", func() {
			GinkgoT().Setenv("CF_INSTANCE_CERT", filepath.Join(dir, "none", "instance.crt"))
			GinkgoT().Setenv("CF_INSTANCE_KEY", filepath.Join(dir, "none", "instance.key"))
			GinkgoT().Setenv(sidecarsEnvVar, oneSidecar)
			writeFakeHypervisor(qemu, "")
			Expect(runWith(backend.VMQemu, launchArg)).To(Equal(0), logBuf.String())

			sidecars, id := built.stack.sidecars, built.stack.identity
			Expect(sidecars).To(Equal([]guestSidecar{{argv: `'/tmp/lifecycle/launcher' 'app' './side' ''`}}))
			Expect(id).To(BeNil())
			Expect(built.env).NotTo(ContainSubstring("CF_INSTANCE_CERT"))
			Expect(built.env).NotTo(ContainSubstring("CF_INSTANCE_KEY"))
			Expect(logBuf.String()).To(MatchRegexp(`(?m)^stack guest: .* to build; 1 sidecar runs beside the app, with the log source ""$`))
		})

		It("exits 125 when the pair does not match, before the hypervisor starts", func() {
			_, otherKey := ca.issue(7, notAfter)
			Expect(os.WriteFile(keyPath, otherKey, 0o644)).To(Succeed())
			withPair()
			argvFile := writeFakeHypervisor(qemu, "")
			Expect(runWith(backend.VMQemu, launchArg)).To(Equal(exitLaunchError))
			Expect(logBuf.String()).To(ContainSubstring("the instance identity certificate and key do not make a pair"))
			Expect(logBuf.String()).NotTo(ContainSubstring("BEGIN"))
			Expect(argvFile).NotTo(BeAnExistingFile())
			Expect(os.ReadDir(tmp)).To(BeEmpty())
			Expect(heldFilesEndingIn("rootfs.squashfs")).To(BeZero())
			Expect(heldFilesEndingIn("droplet.sqfs (deleted)")).To(BeZero())
			Expect(heldFilesEndingIn("/launcher")).To(BeZero())
		})

		It("exits 125 with one line that names the sidecars and the reason when the guest would be the busybox guest", func() {
			withPair()
			GinkgoT().Setenv(sidecarsEnvVar, twoSidecars)
			argvFile := writeFakeHypervisor(qemu, "")

			stackImagePath = filepath.Join(dir, "none", "rootfs.squashfs")
			Expect(runWith(backend.VMQemu, launchArg)).To(Equal(exitLaunchError))
			Expect(logBuf.String()).To(Equal("this app has 2 sidecars, which run only in the stack guest; the stack image cannot be opened: open " + stackImagePath + ": no such file or directory\n"))
			Expect(argvFile).NotTo(BeAnExistingFile())

			logBuf.Reset()
			stackImagePath = stackImg
			Expect(os.WriteFile(filepath.Join(art, artMksquashfs), []byte("#!/bin/sh\necho 'cannot read the droplet' >&2\nexit 1\n"), 0o755)).To(Succeed())
			Expect(runWith(backend.VMQemu, []string{launcher, "app", "true", ""})).To(Equal(exitLaunchError))
			// The guest's memory is settled before the droplet image, so its
			// line comes first.
			Expect(logBuf.String()).To(HaveSuffix("\nthis app has 2 sidecars, which run only in the stack guest; building the droplet image with " + filepath.Join(art, artMksquashfs) + ": exit status 1; cannot read the droplet\n"))
			Expect(logBuf.String()).NotTo(ContainSubstring("guest: "))
			Expect(argvFile).NotTo(BeAnExistingFile())

			logBuf.Reset()
			GinkgoT().Setenv(sidecarsEnvVar, oneSidecar)
			Expect(runWith(backend.VMQemu, []string{"/bin/sh", "-c", "echo hi"})).To(Equal(exitLaunchError))
			Expect(logBuf.String()).To(Equal("this app has 1 sidecar, which runs only in the stack guest; the process is not the CF launcher\n"))
			Expect(argvFile).NotTo(BeAnExistingFile())
			Expect(os.ReadDir(tmp)).To(BeEmpty())
			Expect(heldFilesEndingIn("rootfs.squashfs")).To(BeZero())
			Expect(heldFilesEndingIn("/launcher")).To(BeZero())
		})

		It("exits 125 with the reason when the stack guest's gathering fails for an app with sidecars", func() {
			withPair()
			GinkgoT().Setenv(sidecarsEnvVar, oneSidecar)
			containerHostname = func() (string, error) { return "web_1", nil }
			argvFile := writeFakeHypervisor(qemu, "")

			Expect(runWith(backend.VMQemu, launchArg)).To(Equal(exitLaunchError))
			Expect(logBuf.String()).To(HavePrefix("this app has 1 sidecar, which runs only in the stack guest; "))
			Expect(logBuf.String()).To(ContainSubstring("hostname"))
			Expect(logBuf.String()).NotTo(ContainSubstring("guest: "))
			Expect(argvFile).NotTo(BeAnExistingFile())
			Expect(os.ReadDir(tmp)).To(BeEmpty())
			Expect(heldFilesEndingIn("rootfs.squashfs")).To(BeZero())
			Expect(heldFilesEndingIn("/launcher")).To(BeZero())
		})

		It("exits 125 for a sidecar description it cannot read, before it chooses the guest", func() {
			GinkgoT().Setenv(sidecarsEnvVar, `{"version":2,"sidecars":[]}`)
			argvFile := writeFakeHypervisor(qemu, "")
			Expect(runWith(backend.VMQemu, launchArg)).To(Equal(exitLaunchError))
			Expect(logBuf.String()).To(Equal("CF_VM_SIDECARS has version 2, and this vm-launch reads only version 1\n"))
			Expect(argvFile).NotTo(BeAnExistingFile())
			Expect(heldFilesEndingIn("rootfs.squashfs")).To(BeZero())
		})

		It("gives the stack slice's guest byte for byte to a launch without the variable and without the files", func() {
			initrd, argv := guestOf(launchArg)
			Expect(built.stack).NotTo(BeNil())
			sidecars, id := built.stack.sidecars, built.stack.identity
			Expect(sidecars).To(BeNil())
			Expect(id).To(BeNil())
			Expect(built.env).NotTo(ContainSubstring("CF_INSTANCE_CERT"))
			Expect(logBuf.String()).To(MatchRegexp(`(?m)^stack guest: the launcher runs on the stack image, with a droplet image of .* bytes and took \S+ to build$`))

			logBuf.Reset()
			GinkgoT().Setenv("CF_INSTANCE_CERT", filepath.Join(dir, "none", "instance.crt"))
			GinkgoT().Setenv("CF_INSTANCE_KEY", filepath.Join(dir, "none", "instance.key"))
			GinkgoT().Setenv(sidecarsEnvVar, "")
			again, againArgv := guestOf(launchArg)
			Expect(again).To(Equal(initrd))
			Expect(againArgv).To(Equal(argv))
		})

		It("pushes a rename of the pair after the start tag once, as frames on the guest's console input, and hears the guest's answer", func() {
			savedInterval := credWatchInterval
			DeferCleanup(func() { credWatchInterval = savedInterval })
			credWatchInterval = 10 * time.Millisecond
			withPair()
			newCert, newKey := ca.issue(4343, notAfter.Add(time.Hour))
			Expect(os.WriteFile(certPath+".tmp", newCert, 0o644)).To(Succeed())
			Expect(os.WriteFile(keyPath+".tmp", newKey, 0o644)).To(Succeed())
			console := filepath.Join(dir, "console-in")
			// The fake guest renames the new pair into place after its start
			// tag, key first as Diego does, and records its console input up
			// to the end of the first push, which it then acknowledges.
			script := `#!/bin/bash
echo "RVM_START_` + testNonce + `"
mv ` + shellQuote(keyPath+".tmp") + " " + shellQuote(keyPath) + `
mv ` + shellQuote(certPath+".tmp") + " " + shellQuote(certPath) + `
while IFS= read -r -t 20 line; do
	printf '%s\n' "$line" >>` + shellQuote(console) + `
	case "$line" in "` + credTag(testNonce) + `end "*) break ;; esac
done
echo "` + credOKTag(testNonce) + `1"
sleep 0.5
echo "RVM_EXIT_` + testNonce + `=0"
`
			Expect(os.Remove(qemu)).To(Succeed())
			Expect(os.WriteFile(qemu, []byte(script), 0o755)).To(Succeed())
			Expect(runWith(backend.VMQemu, launchArg)).To(Equal(0), logBuf.String())

			pushed, err := readInstanceIdentity(certPath, keyPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(pushed.serial).To(Equal("4343"))
			got, err := os.ReadFile(console)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(got)).To(Equal(strings.Join(credFrames(testNonce, 1, pushed), "\n") + "\n"))
			Expect(strings.Count(string(got), credTag(testNonce)+"begin ")).To(Equal(1))

			out := logBuf.String()
			Expect(out).To(ContainSubstring("pushed instance identity 1 (serial 4343, expires " + notAfter.Add(time.Hour).UTC().Format(time.RFC3339) + ", try 1)\n"))
			Expect(strings.Count(out, "pushed instance identity")).To(Equal(1), out)
			Expect(out).To(ContainSubstring("the guest installed instance identity push 1\n"))
			Expect(out).NotTo(ContainSubstring("BEGIN"))
		})
	})
})
