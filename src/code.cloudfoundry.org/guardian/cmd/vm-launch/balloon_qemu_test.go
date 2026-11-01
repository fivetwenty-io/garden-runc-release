//go:build linux

package main

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const statsReply = `{"return": {"stats": {"stat-free-memory": 250134528, "stat-total-memory": 322961408, "stat-available-memory": 281227264, "stat-disk-caches": 30212096, "stat-swap-in": 0, "stat-swap-out": 0, "stat-major-faults": 112, "stat-minor-faults": 48211, "stat-htlb-pgalloc": 0, "stat-htlb-pgfail": 0}, "last-update": 1793557300}}`

// qomRequest is the QMP command with id and the balloon's path and property,
// and a value when value is not empty.
func qomRequest(id int, command, property, value string) string {
	args := map[string]any{"path": "/machine/peripheral/balloon0", "property": property}
	if value != "" {
		args["value"] = json.RawMessage(value)
	}
	b, err := json.Marshal(map[string]any{"execute": command, "arguments": args, "id": id})
	Expect(err).NotTo(HaveOccurred())
	return string(b)
}

var _ = Describe("the QEMU balloon", func() {
	It("adds one device that is never inflated and reports free pages", func() {
		Expect(qemuBalloonArgs()).To(Equal([]string{
			"-device", "virtio-balloon-device,id=balloon0,deflate-on-oom=on,free-page-reporting=on",
		}))
	})

	Describe("the statistics source", func() {
		var (
			source *qemuGuestStats
			qemu   *fakeQMP
			clock  time.Time
		)

		BeforeEach(func() {
			var m *qmpMonitor
			m, qemu = newFakeQMP()
			source = newQEMUGuestStats(m)
			clock = time.Unix(1793557300, 0)
			source.now = func() time.Time { return clock }
		})

		// handshake plays QEMU's greeting and its answer to the capabilities
		// request, which come before the first command.
		handshake := func() {
			qemu.send(fakeGreeting)
			Expect(qemu.recv()).To(Equal(capsRequest(1)))
			qemu.reply(`{"return": {}}`)
		}

		It("turns on polling every five seconds", func() {
			done := qemu.serve(func() {
				handshake()
				Expect(qemu.recv()).To(Equal(qomRequest(2, "qom-set", "guest-stats-polling-interval", "5")))
				qemu.reply(`{"return": {}}`)
			})
			Expect(source.Enable(context.Background())).To(Succeed())
			Eventually(done).Should(BeClosed())
		})

		It("reports the failure to turn on polling", func() {
			done := qemu.serve(func() {
				handshake()
				qemu.recv()
				qemu.reply(`{"error": {"class": "DeviceNotFound", "desc": "no such device"}}`)
			})
			err := source.Enable(context.Background())
			Expect(err).To(MatchError(ContainSubstring("turning on the balloon statistics")))
			Expect(err).To(MatchError(ContainSubstring("no such device")))
			Eventually(done).Should(BeClosed())
		})

		It("reads the four memory statistics", func() {
			done := qemu.serve(func() {
				handshake()
				Expect(qemu.recv()).To(Equal(qomRequest(2, "qom-get", "guest-stats", "")))
				qemu.reply(statsReply)
			})
			Expect(source.Read(context.Background())).To(Equal(guestMemorySample{
				Total: 322961408, Available: 281227264, Free: 250134528, Caches: 30212096,
			}))
			Eventually(done).Should(BeClosed())
		})

		It("fails when the guest has not sent a statistic", func() {
			for _, missing := range []string{"stat-free-memory", "stat-total-memory", "stat-available-memory", "stat-disk-caches"} {
				m, q := newFakeQMP()
				s := newQEMUGuestStats(m)
				done := q.serve(func() {
					q.send(fakeGreeting)
					q.recv()
					q.reply(`{"return": {}}`)
					q.recv()
					q.reply(strings.Replace(statsReply, `"`+missing+`": `, `"`+missing+`": -1, "x": `, 1))
				})
				_, err := s.Read(context.Background())
				Expect(err).To(MatchError(ContainSubstring("the guest has not sent " + missing)))
				Eventually(done).Should(BeClosed())
			}
		})

		It("fails when the guest has sent nothing yet", func() {
			done := qemu.serve(func() {
				handshake()
				qemu.recv()
				qemu.reply(`{"return": {"stats": {"stat-free-memory": -1, "stat-total-memory": -1, "stat-available-memory": -1, "stat-disk-caches": -1}, "last-update": 0}}`)
			})
			_, err := source.Read(context.Background())
			Expect(err).To(MatchError(ContainSubstring("the guest has not sent")))
			Eventually(done).Should(BeClosed())
		})

		It("fails on a reply that is not statistics", func() {
			done := qemu.serve(func() {
				handshake()
				qemu.recv()
				qemu.reply(`{"return": "nope"}`)
			})
			_, err := source.Read(context.Background())
			Expect(err).To(MatchError(ContainSubstring("the reply is malformed")))
			Eventually(done).Should(BeClosed())
		})

		It("reads an unchanged answer until it has stood for 30 seconds, then rejects it", func() {
			done := qemu.serve(func() {
				handshake()
				for id := 2; id <= 5; id++ {
					Expect(qemu.recv()).To(Equal(qomRequest(id, "qom-get", "guest-stats", "")))
					qemu.reply(statsReply)
				}
			})
			ctx := context.Background()
			_, err := source.Read(ctx)
			Expect(err).NotTo(HaveOccurred())
			clock = clock.Add(10 * time.Second)
			_, err = source.Read(ctx)
			Expect(err).NotTo(HaveOccurred())
			clock = clock.Add(20 * time.Second)
			_, err = source.Read(ctx)
			Expect(err).NotTo(HaveOccurred())
			clock = clock.Add(time.Second)
			_, err = source.Read(ctx)
			Expect(err).To(MatchError(ContainSubstring("has not answered the balloon for 31s")))
			Eventually(done).Should(BeClosed())
		})

		It("accepts a stale answer again once the guest answers", func() {
			done := qemu.serve(func() {
				handshake()
				qemu.recv()
				qemu.reply(statsReply)
				qemu.recv()
				qemu.reply(statsReply)
				qemu.recv()
				qemu.reply(strings.Replace(statsReply, "1793557300", "1793557345", 1))
			})
			ctx := context.Background()
			_, err := source.Read(ctx)
			Expect(err).NotTo(HaveOccurred())
			clock = clock.Add(45 * time.Second)
			_, err = source.Read(ctx)
			Expect(err).To(HaveOccurred())
			clock = clock.Add(10 * time.Second)
			_, err = source.Read(ctx)
			Expect(err).NotTo(HaveOccurred())
			Eventually(done).Should(BeClosed())
		})

		It("does not touch the monitor once its context is done", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := source.Read(ctx)
			Expect(err).To(MatchError(context.Canceled))
			Expect(source.Enable(ctx)).To(MatchError(context.Canceled))
		})

		It("leaves the monitor usable after a command times out", func() {
			m, q := newFakeQMP()
			m.timeout = 100 * time.Millisecond
			s := newQEMUGuestStats(m)
			late := make(chan struct{})
			done := q.serve(func() {
				q.send(fakeGreeting)
				q.recv()
				q.reply(`{"return": {}}`)
				q.recv()
				<-late
				q.reply(statsReply)
				q.recv()
				q.reply(statsReply)
			})
			_, err := s.Read(context.Background())
			Expect(err).To(HaveOccurred())
			close(late)
			Expect(s.Read(context.Background())).To(Equal(guestMemorySample{
				Total: 322961408, Available: 281227264, Free: 250134528, Caches: 30212096,
			}))
			Eventually(done).Should(BeClosed())
		})

		It("fails every read once the monitor breaks", func() {
			qemu.send("this is not a QMP greeting")
			_, err := source.Read(context.Background())
			Expect(err).To(MatchError(ContainSubstring("a line that is not a QMP message")))
			_, err = source.Read(context.Background())
			Expect(err).To(MatchError(ContainSubstring("a line that is not a QMP message")))
		})
	})
})
