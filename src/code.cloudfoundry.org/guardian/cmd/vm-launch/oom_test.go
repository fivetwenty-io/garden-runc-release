//go:build linux

package main

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// oomTagLine is the console line the guest writes for count kills.
func oomTagLine(count string) string { return "RVM_OOM_" + testNonce + "=" + count }

var _ = Describe("the guest OOM report", func() {
	It("pins the tag and the prefix of the stderr line that guardian reads", func() {
		Expect(oomTag(testNonce)).To(Equal("RVM_OOM_0123456789abcdef="))
		Expect("vm-launch: " + oomLinePrefix).To(Equal("vm-launch: the guest ran out of memory"))
		Expect(oomMessage(3, 128)).To(Equal("the guest ran out of memory: its kernel killed 3 processes; the guest has 128 MiB"))
		Expect(oomMessage(1, 320)).To(Equal("the guest ran out of memory: its kernel killed 1 process; the guest has 320 MiB"))
	})

	It("runs after the command and its helpers end, and before the exit line", func() {
		script := initScript(testNonce, false)
		report := guestOOMReport(testNonce)
		Expect(strings.Count(script, report)).To(Equal(1))
		Expect(strings.Index(script, report)).To(BeNumerically(">", strings.Index(script, guestRunStatus)))
		Expect(strings.Index(script, report)).To(BeNumerically(">", strings.Index(script, guestListenStop)))
		Expect(strings.Index(script, report)).To(BeNumerically("<", strings.Index(script, "echo RVM_EXIT_")))
	})

	It("runs before the volume teardown", func() {
		script := initScript(testNonce, true)
		Expect(strings.Index(script, guestOOMReport(testNonce))).To(BeNumerically("<", strings.Index(script, guestVolumeTeardown)))
	})

	It("is written after the start tag, never during setup", func() {
		script := initScript(testNonce, false)
		Expect(strings.Index(script, oomTag(testNonce))).To(BeNumerically(">", strings.Index(script, "echo RVM_START_")))
	})

	// reportWith runs the report in shell against a /proc/vmstat that holds
	// vmstat, or none when vmstat is nil, and returns what it wrote on the
	// console and on stderr.
	reportWith := func(shell guestShell, vmstat *string) (console, stderr string) {
		dir := GinkgoT().TempDir()
		vm := filepath.Join(dir, "vmstat")
		if vmstat != nil {
			Expect(os.WriteFile(vm, []byte(*vmstat), 0o644)).To(Succeed())
		}
		con := filepath.Join(dir, "console")
		report := guestOOMReport(testNonce)
		Expect(strings.Count(report, "/proc/vmstat")).To(Equal(1))
		Expect(strings.Count(report, ">/dev/console")).To(Equal(1))
		report = strings.Replace(report, "/proc/vmstat", vm, 1)
		report = strings.Replace(report, ">/dev/console", ">"+con, 1)
		cmd := exec.Command(shell.argv[0], append(shell.argv[1:], "-c", report)...)
		var errOut bytes.Buffer
		cmd.Stderr = &errOut
		Expect(cmd.Run()).To(Succeed(), errOut.String())
		raw, err := os.ReadFile(con)
		if os.IsNotExist(err) {
			return "", errOut.String()
		}
		Expect(err).NotTo(HaveOccurred())
		return string(raw), errOut.String()
	}
	vmstat := func(s string) *string { return &s }

	DescribeTable("writes the count when /proc/vmstat holds one above zero",
		func(shellOf func() guestShell, stat, want string) {
			console, stderr := reportWith(shellOf(), vmstat(stat))
			Expect(console).To(Equal(want))
			Expect(stderr).To(BeEmpty())
		},
		append(shellEntries("a count of 3", "nr_free_pages 1\noom_kill 3\npgfault 9\n", oomTagLine("3")+"\n"),
			shellEntries("a count of 1", "oom_kill 1\n", oomTagLine("1")+"\n")...),
	)
	DescribeTable("writes nothing when the count is zero, absent, or not a plain number",
		func(shellOf func() guestShell, stat string) {
			console, stderr := reportWith(shellOf(), vmstat(stat))
			Expect(console).To(BeEmpty())
			Expect(stderr).To(BeEmpty())
		},
		shellEntries("a count of zero", "oom_kill 0\n"),
		shellEntries("a key that only starts with oom_kill", "oom_kill_x 5\nnr_oom_kill 5\n"),
		shellEntries("no oom_kill line", "nr_free_pages 1\npgfault 9\n"),
		shellEntries("a count that is not a number", "oom_kill abc\n"),
		shellEntries("a count with a sign", "oom_kill -3\n"),
		shellEntries("a count with a leading zero", "oom_kill 007\n"),
		shellEntries("an empty count", "oom_kill\n"),
		shellEntries("an empty file", ""),
	)
	DescribeTable("writes nothing and stays quiet when /proc/vmstat cannot be read",
		func(shellOf func() guestShell) {
			console, stderr := reportWith(shellOf(), nil)
			Expect(console).To(BeEmpty())
			Expect(stderr).To(BeEmpty())
		},
		shellEntries(""),
	)
	DescribeTable("uses the first oom_kill line",
		func(shellOf func() guestShell) {
			console, _ := reportWith(shellOf(), vmstat("oom_kill 2\noom_kill 9\n"))
			Expect(console).To(Equal(oomTagLine("2") + "\n"))
		},
		shellEntries(""),
	)
	DescribeTable("falls back to the shared console when /dev/console cannot be opened",
		func(shellOf func() guestShell) {
			dir := GinkgoT().TempDir()
			vm := filepath.Join(dir, "vmstat")
			Expect(os.WriteFile(vm, []byte("oom_kill 4\n"), 0o644)).To(Succeed())
			shell := shellOf()
			report := strings.Replace(guestOOMReport(testNonce), "/proc/vmstat", vm, 1)
			report = strings.Replace(report, ">/dev/console", ">"+filepath.Join(dir, "missing", "console"), 1)
			out, err := exec.Command(shell.argv[0], append(shell.argv[1:], "-c", report)...).Output()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(out)).To(Equal(oomTagLine("4") + "\n"))
		},
		shellEntries(""),
	)
})

var _ = Describe("serialFilter with an OOM line", func() {
	start := "RVM_START_" + testNonce + "\r\n"
	marker := "RVM_EXIT_" + testNonce + "=137\r\n"

	It("swallows the line, keeps the count, and keeps the output around it", func() {
		f, out := feed(start, "one\r\n", oomTagLine("3")+"\r\n", "two\r\n", marker)
		Expect(out).To(Equal("one\ntwo\n"))
		Expect(f.oomKills).To(Equal(3))
		Expect(f.markerFound()).To(BeTrue())
		Expect(f.status).To(Equal(137))
	})

	It("finds the tag in the middle of a line and keeps the text before it", func() {
		f, out := feed(start, "partial"+oomTagLine("12")+"\r\n", marker)
		Expect(out).To(Equal("partial"))
		Expect(f.oomKills).To(Equal(12))
	})

	It("accepts LF line endings", func() {
		f, out := feed(start, "a\n"+oomTagLine("2")+"\n"+"b\n"+"RVM_EXIT_"+testNonce+"=0\n")
		Expect(out).To(Equal("a\nb\n"))
		Expect(f.oomKills).To(Equal(2))
	})

	It("gives the same result for every two-way split of the stream", func() {
		stream := start + "x\r\nab" + oomTagLine("7") + "\r\ny\r\n" + marker
		for i := 0; i <= len(stream); i++ {
			f, out := feed(stream[:i], stream[i:])
			Expect(out).To(Equal("x\nab"+"y\n"), "split at %d", i)
			Expect(f.oomKills).To(Equal(7), "split at %d", i)
			Expect(f.status).To(Equal(137), "split at %d", i)
		}
	})

	It("gives the same result when fed one byte at a time", func() {
		stream := start + "x\r\n" + oomTagLine("15") + "\r\ny\r\n" + marker
		chunks := make([]string, len(stream))
		for i := range stream {
			chunks[i] = stream[i : i+1]
		}
		f, out := feed(chunks...)
		Expect(out).To(Equal("x\ny\n"))
		Expect(f.oomKills).To(Equal(15))
		Expect(f.markerFound()).To(BeTrue())
	})

	It("handles an OOM line and a listen line in either order", func() {
		for _, lines := range [][]string{
			{oomTagLine("2") + "\r\n", listenTag(testNonce) + "8080:1\r\n"},
			{listenTag(testNonce) + "8080:1\r\n", oomTagLine("2") + "\r\n"},
		} {
			var out bytes.Buffer
			var ups []bool
			f := newSerialFilter(&out, testNonce)
			f.onListen(testNonce, func(port int, up bool) { ups = append(ups, up) })
			for _, c := range append(append([]string{start, "a\r\n"}, lines...), "b\r\n", marker) {
				_, _ = f.Write([]byte(c))
			}
			f.finish()
			Expect(out.String()).To(Equal("a\nb\n"))
			Expect(f.oomKills).To(Equal(2))
			Expect(ups).To(Equal([]bool{true}))
		}
	})

	It("handles an OOM line and a listen line that arrive in one write, in either order", func() {
		for _, lines := range []string{
			oomTagLine("2") + "\r\n" + listenTag(testNonce) + "8080:1\r\n",
			listenTag(testNonce) + "8080:1\r\n" + oomTagLine("2") + "\r\n",
		} {
			var out bytes.Buffer
			var ups []bool
			f := newSerialFilter(&out, testNonce)
			f.onListen(testNonce, func(port int, up bool) { ups = append(ups, up) })
			_, _ = f.Write([]byte(start + "a\r\n" + lines + "b\r\n" + marker))
			f.finish()
			Expect(out.String()).To(Equal("a\nb\n"))
			Expect(f.oomKills).To(Equal(2))
			Expect(ups).To(Equal([]bool{true}))
		}
	})

	It("does not take an OOM line that follows the exit marker in the same write", func() {
		f, out := feed(start + "a\r\n" + marker + oomTagLine("4") + "\r\n")
		Expect(out).To(Equal("a\n"))
		Expect(f.oomKills).To(BeZero())
		Expect(f.status).To(Equal(137))
	})

	It("handles an OOM line right before the exit marker, in one write", func() {
		f, out := feed(start + "a\r\n" + oomTagLine("5") + "\r\n" + marker)
		Expect(out).To(Equal("a\n"))
		Expect(f.oomKills).To(Equal(5))
		Expect(f.status).To(Equal(137))
	})

	It("keeps the last count when the guest reports twice", func() {
		f, _ := feed(start, oomTagLine("2")+"\r\n", oomTagLine("6")+"\r\n", marker)
		Expect(f.oomKills).To(Equal(6))
	})

	DescribeTable("leaves a malformed tag in the output",
		func(tail string) {
			f, out := feed(start, "a"+oomTagLine("")+tail, marker)
			Expect(out).To(Equal("a" + oomTagLine("") + strings.ReplaceAll(tail, "\r\n", "\n")))
			Expect(f.oomKills).To(BeZero())
			Expect(f.markerFound()).To(BeTrue())
		},
		Entry("no digits", "\r\n"),
		Entry("letters", "x\r\n"),
		Entry("digits then letters", "3x\r\n"),
		Entry("a sign", "-3\r\n"),
		Entry("more digits than a count may have", "1234567890\r\n"),
		Entry("a bare CR", "3\rx\r\n"),
	)

	It("keeps a tag that never gets its line ending", func() {
		f, out := feed(start, "a"+oomTagLine("4"))
		Expect(out).To(Equal("a" + oomTagLine("4")))
		Expect(f.oomKills).To(BeZero())
	})

	It("ignores a tag with another nonce", func() {
		f, out := feed(start, "RVM_OOM_ffffffffffffffff=3\r\n", marker)
		Expect(out).To(Equal("RVM_OOM_ffffffffffffffff=3\n"))
		Expect(f.oomKills).To(BeZero())
	})

	It("ignores the tag before the start tag and after the exit marker", func() {
		f, out := feed(oomTagLine("3")+"\r\n", start, "a\r\n", marker, oomTagLine("4")+"\r\n")
		Expect(out).To(Equal("a\n"))
		Expect(f.oomKills).To(BeZero())
	})

	It("reports no kills when the guest wrote no line", func() {
		f, _ := feed(start, "a\r\n", marker)
		Expect(f.oomKills).To(BeZero())
	})
})

var _ = Describe("run with a guest OOM", func() {
	var (
		art    string
		logBuf *bytes.Buffer
	)

	BeforeEach(func() {
		art = makeArtifacts()
		GinkgoT().Setenv("TMPDIR", GinkgoT().TempDir())
		GinkgoT().Setenv("MEMORY_LIMIT", "512m")
		// A disk quota keeps the log to the lines these specs are about.
		GinkgoT().Setenv("VCAP_APPLICATION", `{"limits":{"disk":64}}`)
		logBuf = &bytes.Buffer{}
	})

	// runGuest runs vm-launch against a fake QEMU that prints the start tag,
	// then body, and then exits.
	runGuest := func(body string) int {
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"),
			`echo "RVM_START_$nonce"
`+body+`
exit 0
`)
		return run([]string{"--backend", string(backend.VMQemu), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true", ""}, log.New(logBuf, "vm-launch: ", 0))
	}

	It("writes the line, with the count and the guest size, before the exit status when the guest ran out of memory", func() {
		code := runGuest(`echo "hello"
echo "RVM_OOM_$nonce=2"
echo "RVM_EXIT_$nonce=137"`)
		Expect(code).To(Equal(137))
		Expect(logBuf.String()).To(Equal("vm-launch: the guest ran out of memory: its kernel killed 2 processes; the guest has 320 MiB\n"))
	})

	It("writes the line whatever the status, such as 0", func() {
		code := runGuest(`echo "RVM_OOM_$nonce=1"
echo "RVM_EXIT_$nonce=0"`)
		Expect(code).To(Equal(0))
		Expect(logBuf.String()).To(Equal("vm-launch: the guest ran out of memory: its kernel killed 1 process; the guest has 320 MiB\n"))
	})

	It("writes the line before a line that explains vm-launch's own exit status", func() {
		code := runGuest(`echo "RVM_OOM_$nonce=2"`)
		Expect(code).To(Equal(exitMissingMarker))
		lines := strings.Split(strings.TrimSuffix(logBuf.String(), "\n"), "\n")
		Expect(lines).To(HaveLen(2), logBuf.String())
		Expect(lines[0]).To(HavePrefix("vm-launch: the guest ran out of memory"))
		Expect(lines[1]).To(ContainSubstring("exiting " + strconv.Itoa(exitMissingMarker)))
	})

	It("writes no line when the guest reports no kills", func() {
		code := runGuest(`echo "RVM_EXIT_$nonce=137"`)
		Expect(code).To(Equal(137))
		Expect(logBuf.String()).NotTo(ContainSubstring("ran out of memory"))
	})

	It("writes no line when the guest reports a count of zero", func() {
		code := runGuest(`echo "RVM_OOM_$nonce=0"
echo "RVM_EXIT_$nonce=1"`)
		Expect(code).To(Equal(1))
		Expect(logBuf.String()).NotTo(ContainSubstring("ran out of memory"))
	})

	It("starts the line the way guardian expects, behind the logger's prefix", func() {
		runGuest(`echo "RVM_OOM_$nonce=2"
echo "RVM_EXIT_$nonce=137"`)
		Expect(regexp.MustCompile(`(?m)^vm-launch: the guest ran out of memory`).MatchString(logBuf.String())).To(BeTrue(), logBuf.String())
	})
})
