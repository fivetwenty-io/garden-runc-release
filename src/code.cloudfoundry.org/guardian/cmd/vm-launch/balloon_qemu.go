//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	// qemuBalloonID names the guest's balloon device, which the statistics
	// commands address by its QOM path.
	qemuBalloonID = "balloon0"

	// qemuBalloonPath is the QOM path of the balloon device.
	qemuBalloonPath = "/machine/peripheral/" + qemuBalloonID

	// qemuStatsIntervalSeconds is how often QEMU asks the guest for
	// statistics once polling is on.
	qemuStatsIntervalSeconds = 5

	// qemuStatsStaleAfter is how long the guest's last answer may stay the
	// same before the statistics stop counting. It is six polling intervals.
	qemuStatsStaleAfter = 30 * time.Second
)

// qemuBalloonArgs returns the arguments of the guest's balloon device. The
// balloon is never inflated, because the guest keeps all of its memory. The
// device reports the guest kernel's statistics and, with free page
// reporting, returns the pages the guest frees to the host. It comes after
// every other device, so no other device's virtio-mmio transport moves.
func qemuBalloonArgs() []string {
	return []string{"-device", "virtio-balloon-device,id=" + qemuBalloonID + ",deflate-on-oom=on,free-page-reporting=on"}
}

// qemuGuestStats reads the guest's memory statistics from QEMU's balloon
// device over the QMP monitor.
type qemuGuestStats struct {
	monitor *qmpMonitor
	now     func() time.Time

	// lastUpdate is the guest's last answer, in seconds, as of the previous
	// read, and movedAt is when a read first saw that value.
	lastUpdate int64
	movedAt    time.Time
	seen       bool
}

var _ guestStatsSource = (*qemuGuestStats)(nil)

func newQEMUGuestStats(monitor *qmpMonitor) *qemuGuestStats {
	return &qemuGuestStats{monitor: monitor, now: time.Now}
}

// Enable turns on QEMU's polling of the guest. The device reports nothing
// until it is on. It gives up when ctx ends, and the monitor stays usable.
func (s *qemuGuestStats) Enable(ctx context.Context) error {
	_, err := s.monitor.commandContext(ctx, "qom-set", map[string]any{
		"path":     qemuBalloonPath,
		"property": "guest-stats-polling-interval",
		"value":    qemuStatsIntervalSeconds,
	})
	if err != nil {
		return fmt.Errorf("turning on the balloon statistics: %w", err)
	}
	return nil
}

// qemuGuestStatsReply is the value of the balloon's guest-stats property.
// QEMU reports -1 for a statistic that the guest has not sent.
type qemuGuestStatsReply struct {
	Stats struct {
		Free      *int64 `json:"stat-free-memory"`
		Total     *int64 `json:"stat-total-memory"`
		Available *int64 `json:"stat-available-memory"`
		Caches    *int64 `json:"stat-disk-caches"`
	} `json:"stats"`
	LastUpdate int64 `json:"last-update"`
}

// Read returns the newest sample. It fails when the guest has not sent all
// four memory statistics, and when the guest's last answer has not changed
// for 30 seconds, because a guest that stops answering leaves its old
// numbers in place. It gives up when ctx ends, even while it waits for the
// monitor or for QEMU's reply, so a stop never waits behind it, and the
// monitor stays usable for the port gates. A monitor that is broken for good
// gives an error that says it is fatal (see qmpBrokenError).
func (s *qemuGuestStats) Read(ctx context.Context) (guestMemorySample, error) {
	ret, err := s.monitor.commandContext(ctx, "qom-get", map[string]any{
		"path":     qemuBalloonPath,
		"property": "guest-stats",
	})
	if err != nil {
		return guestMemorySample{}, fmt.Errorf("reading the balloon statistics: %w", err)
	}
	var reply qemuGuestStatsReply
	if err := json.Unmarshal(ret, &reply); err != nil {
		return guestMemorySample{}, fmt.Errorf("reading the balloon statistics: the reply is malformed: %w", err)
	}
	if err := s.checkFresh(reply.LastUpdate); err != nil {
		return guestMemorySample{}, err
	}
	var sample guestMemorySample
	for _, f := range []struct {
		name string
		in   *int64
		out  *uint64
	}{
		{"stat-total-memory", reply.Stats.Total, &sample.Total},
		{"stat-available-memory", reply.Stats.Available, &sample.Available},
		{"stat-free-memory", reply.Stats.Free, &sample.Free},
		{"stat-disk-caches", reply.Stats.Caches, &sample.Caches},
	} {
		if f.in == nil || *f.in < 0 {
			return guestMemorySample{}, fmt.Errorf("the guest has not sent %s", f.name)
		}
		*f.out = uint64(*f.in)
	}
	return sample, nil
}

// checkFresh records the guest's last answer and fails when it has stayed
// the same for longer than qemuStatsStaleAfter.
func (s *qemuGuestStats) checkFresh(lastUpdate int64) error {
	now := s.now()
	if !s.seen || lastUpdate != s.lastUpdate {
		s.seen, s.lastUpdate, s.movedAt = true, lastUpdate, now
		return nil
	}
	if age := now.Sub(s.movedAt); age > qemuStatsStaleAfter {
		return errors.New("the guest has not answered the balloon for " + age.Round(time.Second).String())
	}
	return nil
}
