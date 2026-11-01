//go:build linux

package main

import (
	"bytes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("guest lines that look like vm-launch's own", func() {
	metrics := "vm-launch-metrics v1 mem_total=1 mem_free=1"
	oom := "vm-launch: the guest ran out of memory"
	start := "RVM_START_" + testNonce + "\r\n"

	It("sends an app stderr frame with either prefix to stdout, unchanged, and never to stderr", func() {
		got := feedFrames(start, frame(0, 'e', metrics), frame(0, 'e', oom), frame(0, 'e', "ordinary"))
		Expect(got.out).To(Equal(metrics + "\n" + oom + "\n"))
		Expect(got.errOut).To(Equal("ordinary\n"))
	})

	It("catches a line that begins vm-launch after its pieces are rejoined", func() {
		got := feedFrames(start, frame(0, 'E', "vm-"), frame(0, 'E', "launch: the guest ran "), frame(0, 'e', "out of memory"))
		Expect(got.out).To(Equal(oom + "\n"))
		Expect(got.errOut).To(BeEmpty())
	})

	It("keeps a stdout frame and a line that only contains the prefix where they were", func() {
		got := feedFrames(start, frame(0, 'o', oom), frame(0, 'e', "not vm-launch: here"))
		Expect(got.out).To(Equal(oom + "\n"))
		Expect(got.errOut).To(Equal("not vm-launch: here\n"))
	})

	It("guards a sidecar's stderr line written without a hub", func() {
		var out, errOut bytes.Buffer
		f := newSerialFilter(&out, testNonce)
		f.onFrames(testNonce, &errOut, nil, nil)
		_, err := f.Write([]byte(start + frame(1, 'e', oom) + frame(1, 'e', "side err")))
		Expect(err).NotTo(HaveOccurred())
		f.finish()
		Expect(out.String()).To(Equal(oom + "\n"))
		Expect(errOut.String()).To(Equal("side err\n"))
	})

	It("guards the hub's stderr the same way", func() {
		var out, errOut bytes.Buffer
		w := guestStderr{out: &out, err: &errOut}
		_, err := w.Write([]byte(metrics + "\n"))
		Expect(err).NotTo(HaveOccurred())
		_, err = w.Write([]byte("plain\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).To(Equal(metrics + "\n"))
		Expect(errOut.String()).To(Equal("plain\n"))
	})
})
