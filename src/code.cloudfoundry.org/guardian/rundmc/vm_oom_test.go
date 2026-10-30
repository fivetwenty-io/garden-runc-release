package rundmc_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"code.cloudfoundry.org/guardian/rundmc"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testingAllocs(f func()) float64 { return testing.AllocsPerRun(5, f) }

type shortWriter struct{ limit int }

func (w shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		return w.limit, errors.New("boom")
	}
	return len(p), nil
}

var _ = Describe("the OOM line scanner", func() {
	const line = "vm-launch: the guest ran out of memory: its kernel killed 2 processes; the guest has 128 MiB\n"

	var (
		out     *bytes.Buffer
		scanner rundmc.OOMLineScanner
	)

	BeforeEach(func() {
		out = new(bytes.Buffer)
		scanner = rundmc.NewOOMLineScanner(out)
	})

	write := func(chunks ...string) {
		for _, chunk := range chunks {
			n, err := scanner.Write([]byte(chunk))
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(len(chunk)))
		}
	}

	It("pins the prefix that vm-launch writes", func() {
		Expect(rundmc.OOMLinePrefix).To(Equal("vm-launch: the guest ran out of memory"))
	})

	It("passes every byte through unchanged", func() {
		write("first\n", line, "last")
		Expect(out.String()).To(Equal("first\n" + line + "last"))
	})

	It("sees a line that begins with the prefix", func() {
		write(line)
		Expect(scanner.Seen()).To(BeTrue())
	})

	It("sees the line after earlier lines in the same write", func() {
		write("one\ntwo\n" + line)
		Expect(scanner.Seen()).To(BeTrue())
	})

	It("sees the line when the prefix has no newline after it", func() {
		write(rundmc.OOMLinePrefix)
		Expect(scanner.Seen()).To(BeTrue())
	})

	It("sees the line when the prefix is split across two writes", func() {
		write("vm-launch: the guest ran ", "out of memory: its kernel killed 1 process\n")
		Expect(scanner.Seen()).To(BeTrue())
	})

	It("sees the line when every byte arrives in its own write", func() {
		for _, b := range []byte(line) {
			write(string(b))
		}
		Expect(scanner.Seen()).To(BeTrue())
	})

	It("sees the line when a write ends exactly at a newline before it", func() {
		write("one\n", line)
		Expect(scanner.Seen()).To(BeTrue())
	})

	It("does not see the prefix in the middle of a line", func() {
		write("app said " + line)
		Expect(scanner.Seen()).To(BeFalse())
	})

	It("does not see the prefix after a partial line split across writes", func() {
		write("app said ", line)
		Expect(scanner.Seen()).To(BeFalse())
	})

	It("does not see a line that stops short of the prefix", func() {
		write("vm-launch: the guest ran out of memor\n")
		Expect(scanner.Seen()).To(BeFalse())
	})

	It("does not see a partial prefix that is cut off by a newline and then completed", func() {
		write("vm-launch: the guest ran out", "\nof memory\n")
		Expect(scanner.Seen()).To(BeFalse())
	})

	It("does not see a different vm-launch line", func() {
		write("vm-launch: received terminated, asking the guest command to stop\n")
		Expect(scanner.Seen()).To(BeFalse())
	})

	It("sees nothing when nothing was written", func() {
		Expect(scanner.Seen()).To(BeFalse())
	})

	It("keeps what it saw after later output", func() {
		write(line, "more\n", "and more")
		Expect(scanner.Seen()).To(BeTrue())
	})

	It("keeps no memory for a long line without a newline", func() {
		big := []byte(strings.Repeat("x", 4<<20))
		scanner = rundmc.NewOOMLineScanner(io.Discard)

		allocs := testingAllocs(func() { _, _ = scanner.Write(big) })

		Expect(allocs).To(BeZero())
		Expect(scanner.Seen()).To(BeFalse())
	})

	It("returns the count and error of the writer it wraps", func() {
		scanner = rundmc.NewOOMLineScanner(shortWriter{limit: 3})

		n, err := scanner.Write([]byte("abcdef"))

		Expect(n).To(Equal(3))
		Expect(err).To(MatchError("boom"))
	})

	It("still sees the line when the writer it wraps fails", func() {
		scanner = rundmc.NewOOMLineScanner(shortWriter{limit: 0})

		_, _ = scanner.Write([]byte(line))

		Expect(scanner.Seen()).To(BeTrue())
	})

	It("accepts writes with no writer behind it", func() {
		scanner = rundmc.NewOOMLineScanner(nil)

		write(line)

		Expect(scanner.Seen()).To(BeTrue())
	})

	It("is safe to read while another goroutine writes", func() {
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 0; i < 1000; i++ {
				_, _ = scanner.Write([]byte("x\n"))
			}
			_, _ = scanner.Write([]byte(line))
		}()
		for i := 0; i < 1000; i++ {
			_ = scanner.Seen()
		}
		<-done
		Expect(scanner.Seen()).To(BeTrue())
	})
})
