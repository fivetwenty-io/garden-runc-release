//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// helperFakeFirecracker marks a helper process that stands in for
// Firecracker's serial console: it writes a guest run of the given number of
// output bytes to a stdout that it makes non-blocking, and loses whatever
// stdout does not take at once, as Firecracker does (its serial device logs
// "Failed the write to serial" and drops the byte). It reports on stderr how
// many console bytes it lost, and then creates the file that
// helperFakeFirecrackerWritten names.
const (
	helperFakeFirecracker        = "VM_LAUNCH_TEST_FAKE_FIRECRACKER"
	helperFakeFirecrackerNonce   = "VM_LAUNCH_TEST_FAKE_FIRECRACKER_NONCE"
	helperFakeFirecrackerWritten = "VM_LAUNCH_TEST_FAKE_FIRECRACKER_WRITTEN"
)

// fakeFirecrackerChunk is one write of the guest command's output: a line of
// 4 KiB.
var fakeFirecrackerChunk = append(bytes.Repeat([]byte("x"), 4095), '\n')

func init() {
	if burst := os.Getenv(helperFakeFirecracker); burst != "" {
		os.Exit(fakeFirecracker(burst))
	}
}

func fakeFirecracker(burstArg string) int {
	burst, err := strconv.Atoi(burstArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "the fake Firecracker's burst %q: %v\n", burstArg, err)
		return 2
	}
	nonce := os.Getenv(helperFakeFirecrackerNonce)
	if err := unix.SetNonblock(1, true); err != nil {
		fmt.Fprintf(os.Stderr, "making stdout non-blocking: %v\n", err)
		return 2
	}
	lost := 0
	serial := func(b []byte) {
		for len(b) > 0 {
			n, err := unix.Write(1, b)
			if n > 0 {
				b = b[n:]
			}
			if err != nil {
				if !errors.Is(err, unix.EAGAIN) {
					fmt.Fprintf(os.Stderr, "writing to serial: %v\n", err)
				}
				lost += len(b)
				return
			}
		}
	}
	serial([]byte("boot noise\r\n" + startTag(nonce) + "\r\n"))
	for written := 0; written < burst; written += len(fakeFirecrackerChunk) {
		if written == burst/2/len(fakeFirecrackerChunk)*len(fakeFirecrackerChunk) {
			serial([]byte(listenTag(nonce) + "8080:1\r\n"))
		}
		serial(fakeFirecrackerChunk)
		// About 40 MB/s at most, far more than a guest console carries.
		time.Sleep(100 * time.Microsecond)
	}
	serial([]byte(oomTag(nonce) + "2\r\n"))
	serial([]byte(exitTag(nonce) + "0\r\n"))
	fmt.Fprintf(os.Stderr, "the fake Firecracker lost %d console bytes\n", lost)
	if err := os.WriteFile(os.Getenv(helperFakeFirecrackerWritten), nil, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	return 0
}

var _ = Describe("the supervisor with a Firecracker that loses what stdout does not take at once", func() {
	const burst = 4 << 20

	var (
		written string
		logBuf  *safeBuffer
		mu      sync.Mutex
		listens []string
		sup     supervisor
	)

	BeforeEach(func() {
		written = filepath.Join(GinkgoT().TempDir(), "written")
		logBuf = &safeBuffer{}
		listens = nil
		sup = supervisor{
			logger:  log.New(logBuf, "", 0),
			signals: make(chan os.Signal, 1),
			grace:   5 * time.Second, deadline: 5 * time.Second,
			listen: func(port int, up bool) {
				mu.Lock()
				defer mu.Unlock()
				listens = append(listens, fmt.Sprintf("%d:%v", port, up))
			},
		}
	})

	fakeFirecrackerCmd := func() (*exec.Cmd, *bytes.Buffer) {
		cmd := exec.Command(os.Args[0])
		cmd.Env = []string{
			helperFakeFirecracker + "=" + strconv.Itoa(burst),
			helperFakeFirecrackerNonce + "=" + testNonce,
			helperFakeFirecrackerWritten + "=" + written,
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		return cmd, &stderr
	}
	// awaitWritten waits, without Gomega, as it runs off the spec's
	// goroutine, until the fake has written all it writes.
	awaitWritten := func() {
		for i := 0; i < 2000; i++ {
			if _, err := os.Stat(written); err == nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	It("reads the console while stdout is held up, so the guest loses no console byte, and drops output past its limit with one line about it", func(ctx SpecContext) {
		delivered := 0
		var deliveredMu sync.Mutex
		// stdout takes nothing until the guest has written everything,
		// like a log pipe that stalls for the length of the burst.
		sup.stdout = writerFunc(func(p []byte) (int, error) {
			awaitWritten()
			deliveredMu.Lock()
			defer deliveredMu.Unlock()
			delivered += len(p)
			return len(p), nil
		})
		cmd, stderr := fakeFirecrackerCmd()
		res, err := sup.run(cmd, testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(stderr.String()).To(Equal("the fake Firecracker lost 0 console bytes\n"))
		Expect(res.markerFound).To(BeTrue(), logBuf.String())
		Expect(res.guestOOMKills).To(Equal(2))
		Expect(codeOf(res)).To(Equal(0))
		mu.Lock()
		Expect(listens).To(Equal([]string{"8080:true"}))
		mu.Unlock()

		m := regexp.MustCompile(`^stdout did not keep up with the guest; dropped (\d+) bytes of the guest command's output\n$`).FindStringSubmatch(logBuf.String())
		Expect(m).NotTo(BeNil(), logBuf.String())
		dropped, err := strconv.Atoi(m[1])
		Expect(err).NotTo(HaveOccurred())
		deliveredMu.Lock()
		defer deliveredMu.Unlock()
		// What waits stays within the limit; the write that stdout held up
		// came on top of it.
		Expect(delivered).To(BeNumerically(">", guestOutputLimit/2))
		Expect(delivered).To(BeNumerically("<=", 2*guestOutputLimit))
		Expect(delivered + dropped).To(Equal(burst))
	}, SpecTimeout(time.Minute))

	It("passes all the output on, and logs nothing, when stdout keeps up", func(ctx SpecContext) {
		var out bytes.Buffer
		sup.stdout = &out
		cmd, stderr := fakeFirecrackerCmd()
		res, err := sup.run(cmd, testNonce)
		Expect(err).NotTo(HaveOccurred())
		Expect(stderr.String()).To(Equal("the fake Firecracker lost 0 console bytes\n"))
		Expect(res.markerFound).To(BeTrue())
		Expect(out.Len()).To(Equal(burst))
		Expect(logBuf.String()).To(BeEmpty())
	}, SpecTimeout(time.Minute))
})
