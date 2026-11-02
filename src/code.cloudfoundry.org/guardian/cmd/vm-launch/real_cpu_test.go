//go:build linux

package main

import (
	"fmt"
	"regexp"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	// realCPUBusySeconds is how long the guest's command keeps a vCPU busy,
	// and realCPUIdleSeconds how long it then sleeps. The watcher writes a
	// line every guestCPUInterval seconds, so the run holds lines from the
	// busy stretch and from the idle one.
	realCPUBusySeconds = 8
	realCPUIdleSeconds = 14

	// realCPUBusyTicks is the least that the guest may report for the first
	// five busy seconds, which is 60% of a vCPU at 100 ticks a second.
	realCPUBusyTicks = 300

	// realCPUIdleTicks is the most that the guest may report for the
	// guestCPUInterval seconds of the sleep. An idle guest shows a few ticks
	// of timer interrupts, and this is a fifth of what a busy one shows.
	realCPUIdleTicks = 100
)

// realCPUScript busies the guest's vCPU for realCPUBusySeconds of guest
// uptime without starting a process, and then sleeps.
var realCPUScript = fmt.Sprintf(`read up rest </proc/uptime
end=$((${up%%.*} + %d))
while :; do
	read up rest </proc/uptime
	[ "${up%%.*}" -ge "$end" ] && break
done
sleep %d`, realCPUBusySeconds, realCPUIdleSeconds)

var _ = Describe("a real QEMU guest's CPU watcher", func() {
	It("reports the ticks of a busy guest and almost none for an idle one", func() {
		out := bootRealGuest(taskGuest(realCPUScript))

		lines := regexp.MustCompile(regexp.QuoteMeta(cpuTag(testNonce)) + `([0-9]+):([0-9]+)\r?\n`).FindAllStringSubmatch(out, -1)
		Expect(len(lines)).To(BeNumerically(">=", 3), "the guest wrote %d CPU lines in a run of %d seconds\n%s", len(lines), realCPUBusySeconds+realCPUIdleSeconds, out)

		busy := make([]uint64, len(lines))
		for i, m := range lines {
			user, err := strconv.ParseUint(m[1], 10, 64)
			Expect(err).NotTo(HaveOccurred())
			system, err := strconv.ParseUint(m[2], 10, 64)
			Expect(err).NotTo(HaveOccurred())
			busy[i] = user + system
			if i > 0 {
				Expect(busy[i]).To(BeNumerically(">=", busy[i-1]), "the busy ticks fell between lines %d and %d", i-1, i)
			}
		}
		AddReportEntry("guest busy ticks", fmt.Sprint(busy))

		Expect(busy[1]-busy[0]).To(BeNumerically(">=", realCPUBusyTicks), "the busy guest reported %d ticks in its first %d seconds", busy[1]-busy[0], guestCPUInterval)
		last := len(busy) - 1
		Expect(busy[last]-busy[last-1]).To(BeNumerically("<=", realCPUIdleTicks), "the idle guest reported %d ticks in %d seconds", busy[last]-busy[last-1], guestCPUInterval)
	})
})
