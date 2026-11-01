//go:build linux

package main

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("the guest memory sample", func() {
	const guestBytes = 322961408

	good := guestMemorySample{Total: 322961408, Available: 250609664, Free: 250134528, Caches: 30212096}

	It("pins the line byte for byte", func() {
		Expect(good.line()).To(Equal("vm-launch-metrics v1 used=72351744 total=322961408 available=250609664 free=250134528 caches=30212096\n"))
		Expect(metricsLinePrefix).To(Equal("vm-launch-metrics v1 "))
	})

	It("keeps the longest line under 160 bytes", func() {
		const most = ^uint64(0)
		line := guestMemorySample{Total: most, Available: 0, Free: most, Caches: most}.line()
		Expect(len(line)).To(BeNumerically("<", 160))
	})

	It("computes used as the total less the available memory", func() {
		Expect(good.used()).To(Equal(uint64(72351744)))
		Expect(guestMemorySample{Total: 100, Available: 100}.used()).To(Equal(uint64(0)))
		Expect(guestMemorySample{Total: 100, Available: 0}.used()).To(Equal(uint64(100)))
	})

	It("accepts a sample that fits the guest", func() {
		Expect(good.check(guestBytes)).To(Succeed())
		Expect(guestMemorySample{Total: guestBytes, Available: guestBytes, Free: guestBytes, Caches: guestBytes}.check(guestBytes)).To(Succeed())
		Expect(guestMemorySample{Total: 1}.check(guestBytes)).To(Succeed())
	})

	DescribeTable("rejects a sample that cannot be right",
		func(s guestMemorySample, message string) {
			Expect(s.check(guestBytes)).To(MatchError(ContainSubstring(message)))
		},
		Entry("a zero total", guestMemorySample{Available: 0, Free: 0, Caches: 0}, "total of zero"),
		Entry("a total above the guest's size", guestMemorySample{Total: guestBytes + 1, Available: 1}, "above its size"),
		Entry("available above the total", guestMemorySample{Total: 1000, Available: 1001}, "available, above its total"),
		Entry("free above the total", guestMemorySample{Total: 1000, Free: 1001}, "free, above its total"),
		Entry("caches above the total", guestMemorySample{Total: 1000, Caches: 1001}, "of caches, above its total"),
	)
})
