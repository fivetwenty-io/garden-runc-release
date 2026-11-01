package rundmc

import (
	"bytes"
	"errors"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const sampleLine = "vm-launch-metrics v1 used=72351744 total=322961408 available=250609664 free=250134528 caches=30212096"

var _ = Describe("parsing a VM metrics line", func() {
	It("reads the pinned line", func() {
		sample, ok := parseVMMetricsLine([]byte(sampleLine))

		Expect(ok).To(BeTrue())
		Expect(sample).To(Equal(vmMemorySample{
			Used: 72351744, Total: 322961408, Available: 250609664, Free: 250134528, Caches: 30212096,
		}))
	})

	DescribeTable("rejects a line that is not in the form",
		func(line string) {
			_, ok := parseVMMetricsLine([]byte(line))
			Expect(ok).To(BeFalse())
		},
		Entry("another prefix", "vm-launch-metrics v2 used=1 total=2 available=1 free=1 caches=1"),
		Entry("no fields", "vm-launch-metrics v1 "),
		Entry("a missing field", "vm-launch-metrics v1 used=1 total=2 available=1 free=1"),
		Entry("an extra field", sampleLine+" extra=1"),
		Entry("a trailing space", sampleLine+" "),
		Entry("fields out of order", "vm-launch-metrics v1 total=2 used=1 available=1 free=1 caches=1"),
		Entry("a double space", "vm-launch-metrics v1 used=1  total=2 available=1 free=1 caches=1"),
		Entry("a negative number", "vm-launch-metrics v1 used=-1 total=2 available=1 free=1 caches=1"),
		Entry("a signed number", "vm-launch-metrics v1 used=+1 total=2 available=1 free=1 caches=1"),
		Entry("a hexadecimal number", "vm-launch-metrics v1 used=0x1 total=2 available=1 free=1 caches=1"),
		Entry("an empty number", "vm-launch-metrics v1 used= total=2 available=1 free=1 caches=1"),
		Entry("a number past 19 digits", "vm-launch-metrics v1 used=1 total=99999999999999999999 available=1 free=1 caches=1"),
		Entry("a zero total", "vm-launch-metrics v1 used=0 total=0 available=0 free=0 caches=0"),
		Entry("available above total", "vm-launch-metrics v1 used=0 total=2 available=3 free=1 caches=1"),
		Entry("free above total", "vm-launch-metrics v1 used=1 total=2 available=1 free=3 caches=1"),
		Entry("caches above total", "vm-launch-metrics v1 used=1 total=2 available=1 free=1 caches=3"),
		Entry("used above total", "vm-launch-metrics v1 used=3 total=2 available=1 free=1 caches=1"),
		Entry("used that is not total less available", "vm-launch-metrics v1 used=2 total=4 available=1 free=1 caches=1"),
	)
})

var _ = Describe("the VM metrics filter", func() {
	var (
		out     *bytes.Buffer
		samples []vmMemorySample
		bad     []int
		filter  *vmMetricsFilter
	)

	BeforeEach(func() {
		out = new(bytes.Buffer)
		samples = nil
		bad = nil
		filter = newVMMetricsFilter(out,
			func(s vmMemorySample) { samples = append(samples, s) },
			func(n int) { bad = append(bad, n) },
		)
	})

	// feedAt writes input in two chunks cut at every offset and checks the
	// result each time, with a fresh filter.
	feedAt := func(input, want string, wantSamples int) {
		for cut := 0; cut <= len(input); cut++ {
			out.Reset()
			samples = nil
			bad = nil
			filter = newVMMetricsFilter(out,
				func(s vmMemorySample) { samples = append(samples, s) },
				func(n int) { bad = append(bad, n) },
			)

			n, err := filter.Write([]byte(input[:cut]))
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(cut))
			n, err = filter.Write([]byte(input[cut:]))
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(len(input) - cut))
			Expect(filter.Flush()).To(Succeed())

			Expect(out.String()).To(Equal(want), "cut at %d", cut)
			Expect(samples).To(HaveLen(wantSamples), "cut at %d", cut)
		}
	}

	It("removes a metrics line and stores its sample, split at every offset", func() {
		feedAt(sampleLine+"\n", "", 1)
		Expect(samples[0].Used).To(Equal(uint64(72351744)))
	})

	It("passes ordinary lines around a metrics line unchanged", func() {
		feedAt("before\n"+sampleLine+"\nafter\n", "before\nafter\n", 1)
	})

	It("passes a line that only nearly matches the prefix", func() {
		feedAt("vm-launch-metrics v2 used=1\nvm-launch: other\nvm-launch-metrics\n", "vm-launch-metrics v2 used=1\nvm-launch: other\nvm-launch-metrics\n", 0)
	})

	It("passes a line that is only the start of the prefix", func() {
		feedAt("vm-launch-m\nnext\n", "vm-launch-m\nnext\n", 0)
	})

	It("matches the prefix only at the start of a line", func() {
		feedAt("x "+sampleLine+"\n", "x "+sampleLine+"\n", 0)
	})

	It("drops two metrics lines in a row and keeps the newest in order", func() {
		second := strings.Replace(sampleLine, "used=72351744", "used=72351745", 1)
		second = strings.Replace(second, "available=250609664", "available=250609663", 1)
		feedAt(sampleLine+"\n"+second+"\n", "", 2)
		Expect(samples[1].Used).To(Equal(uint64(72351745)))
	})

	It("releases a matched line that runs past the limit as ordinary output", func() {
		long := vmMetricsLinePrefix + strings.Repeat("x", vmMetricsMaxLine) + "\nnext\n"
		feedAt(long, long, 0)
	})

	It("holds a line of exactly the limit and parses it", func() {
		line := vmMetricsLinePrefix + strings.Repeat("x", vmMetricsMaxLine-len(vmMetricsLinePrefix))
		Expect(line).To(HaveLen(vmMetricsMaxLine))

		_, err := filter.Write([]byte(line + "\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(out.Len()).To(BeZero())
		Expect(bad).To(Equal([]int{1}))
	})

	It("drops and counts a matched line that fails to parse", func() {
		_, err := filter.Write([]byte(vmMetricsLinePrefix + "used=1\nok\n" + vmMetricsLinePrefix + "bad\n"))
		Expect(err).NotTo(HaveOccurred())

		Expect(out.String()).To(Equal("ok\n"))
		Expect(samples).To(BeEmpty())
		Expect(bad).To(Equal([]int{1, 2}))
		Expect(filter.Dropped()).To(Equal(2))
	})

	It("flushes a cut-off line so it reaches the logs as it would have", func() {
		_, err := filter.Write([]byte("kept\n" + sampleLine))
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal("kept\n"))

		Expect(filter.Flush()).To(Succeed())
		Expect(out.String()).To(Equal("kept\n" + sampleLine))
		Expect(samples).To(BeEmpty())
	})

	It("never holds more than the limit however long a line is", func() {
		_, err := filter.Write([]byte(vmMetricsLinePrefix + strings.Repeat("y", 100000)))
		Expect(err).NotTo(HaveOccurred())
		Expect(cap(filter.held)).To(BeNumerically("<=", 2*vmMetricsMaxLine))
		Expect(filter.held).To(BeEmpty())
	})

	It("passes every byte through a nil next without failing", func() {
		nilFilter := newVMMetricsFilter(nil, nil, nil)
		n, err := nilFilter.Write([]byte("hello\n" + sampleLine + "\nbad " + vmMetricsLinePrefix + "\n" + vmMetricsLinePrefix + "z\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(BeNumerically(">", 0))
		Expect(nilFilter.Flush()).To(Succeed())
	})

	It("reports the error of the next writer", func() {
		failing := newVMMetricsFilter(failWriter{}, nil, nil)

		_, err := failing.Write([]byte("hello\n"))
		Expect(err).To(MatchError("boom"))
	})

	It("reports the error of the next writer on flush", func() {
		failing := newVMMetricsFilter(failWriter{}, nil, nil)
		_, err := failing.Write([]byte(vmMetricsLinePrefix + "partial"))
		Expect(err).NotTo(HaveOccurred())

		Expect(failing.Flush()).To(MatchError(ContainSubstring("boom")))
	})
})

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

var _ = Describe("the guest memory store", func() {
	var (
		clock time.Time
		store *vmGuestMemory
	)

	sample := func(used uint64) vmMemorySample {
		return vmMemorySample{Used: used, Total: used + 10, Available: 10}
	}

	BeforeEach(func() {
		clock = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
		store = &vmGuestMemory{now: func() time.Time { return clock }}
	})

	It("has a zero value that works on the wall clock", func() {
		var zero vmGuestMemory

		_, ok := zero.Fresh("a")
		Expect(ok).To(BeFalse())

		zero.Record("a", nil, sample(5))
		got, ok := zero.Fresh("a")
		Expect(ok).To(BeTrue())
		Expect(got.Used).To(Equal(uint64(5)))
	})

	It("returns nothing for a container with no sample", func() {
		_, ok := store.Fresh("a")
		Expect(ok).To(BeFalse())
	})

	It("keeps the newest sample for each container", func() {
		store.Record("a", 1, sample(1))
		store.Record("b", 1, sample(2))
		store.Record("a", 1, sample(3))

		a, _ := store.Fresh("a")
		b, _ := store.Fresh("b")
		Expect(a.Used).To(Equal(uint64(3)))
		Expect(b.Used).To(Equal(uint64(2)))
	})

	It("serves a sample until it is 35 seconds old and not after", func() {
		store.Record("a", 1, sample(1))

		clock = clock.Add(vmMetricsStaleAfter - time.Nanosecond)
		_, ok := store.Fresh("a")
		Expect(ok).To(BeTrue())

		clock = clock.Add(time.Nanosecond)
		_, ok = store.Fresh("a")
		Expect(ok).To(BeFalse())
	})

	It("measures age from the newest record", func() {
		store.Record("a", 1, sample(1))
		clock = clock.Add(30 * time.Second)
		store.Record("a", 1, sample(2))
		clock = clock.Add(30 * time.Second)

		got, ok := store.Fresh("a")
		Expect(ok).To(BeTrue())
		Expect(got.Used).To(Equal(uint64(2)))
	})

	It("forgets a sample only for the process that wrote it", func() {
		first, second := new(int), new(int)
		store.Record("a", first, sample(1))
		store.Record("a", second, sample(2))

		store.Forget("a", first)
		_, ok := store.Fresh("a")
		Expect(ok).To(BeTrue())

		store.Forget("a", second)
		_, ok = store.Fresh("a")
		Expect(ok).To(BeFalse())
	})

	It("removes a container's sample whatever its source", func() {
		store.Record("a", new(int), sample(1))
		store.Record("b", new(int), sample(1))

		store.Remove("a")

		_, ok := store.Fresh("a")
		Expect(ok).To(BeFalse())
		_, ok = store.Fresh("b")
		Expect(ok).To(BeTrue())
	})

	It("ignores forgetting and removing what it does not hold", func() {
		store.Forget("a", 1)
		store.Remove("a")
	})
})
