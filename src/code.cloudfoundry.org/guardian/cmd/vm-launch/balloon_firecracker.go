//go:build linux

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Firecracker's balloon is never inflated. The device exists for the
// statistics the guest kernel reports through it, and for free page
// reporting, which hands the pages the guest has freed back to the host.
// Firecracker turns statistics on only when the polling interval is above
// zero before boot, so the interval belongs in the config file.
const (
	fcBalloonStatsIntervalSeconds = 5
	fcAPISocketName               = "fc.sock"
	fcStatsPath                   = "/balloon/statistics"

	// fcLogLevel is the lowest level Firecracker logs at (see
	// firecrackerAPIArgv).
	fcLogLevel = "Warn"

	// fcSocketWait is how long the source waits for Firecracker to create
	// its API socket after the process starts.
	fcSocketWait = 5 * time.Second

	// fcSocketPoll is how often the source looks for the socket while it
	// waits.
	fcSocketPoll = 50 * time.Millisecond

	// fcReadTimeout bounds one request and its reply.
	fcReadTimeout = 2 * time.Second
)

// errFirecrackerStatsPending is what Read returns when Firecracker answered
// but the guest has not reported yet, so the reply has no total or available
// memory. The caller skips that reading and asks again at its next interval.
var errFirecrackerStatsPending = errors.New("the guest has not reported balloon statistics yet")

// firecrackerBalloon is the config file's balloon entry.
type firecrackerBalloon struct {
	AmountMiB             int  `json:"amount_mib"`
	DeflateOnOOM          bool `json:"deflate_on_oom"`
	StatsPollingIntervalS int  `json:"stats_polling_interval_s"`
	FreePageReporting     bool `json:"free_page_reporting"`
}

// newFirecrackerBalloon returns the balloon entry for every guest. The
// balloon stays at zero MiB, so the guest keeps all of its memory.
func newFirecrackerBalloon() *firecrackerBalloon {
	return &firecrackerBalloon{
		AmountMiB:             0,
		DeflateOnOOM:          true,
		StatsPollingIntervalS: fcBalloonStatsIntervalSeconds,
		FreePageReporting:     true,
	}
}

// firecrackerAPISocket returns the path of Firecracker's API socket in
// workDir.
func firecrackerAPISocket(workDir string) string {
	return filepath.Join(workDir, fcAPISocketName)
}

// firecrackerAPIArgv returns the command line that boots Firecracker from
// its config file and also serves its API on socketPath, which the statistics
// source reads. Firecracker writes its log to stdout, the guest console's
// stream, and at its default level it logs two lines for every API request,
// which the serial filter would pass on as the app's output once the guest
// has started its command. Its log stays at fcLogLevel, so only its warnings
// and errors reach the console.
func firecrackerAPIArgv(root, configPath, socketPath string) []string {
	return []string{filepath.Join(root, artFirecracker), "--level", fcLogLevel, "--api-sock", socketPath, "--config-file", configPath}
}

// firecrackerStatsSource reads the balloon statistics over one kept
// connection to Firecracker's API socket. It removes the socket's path once
// it is connected, so no other process in the container can open a new
// connection to the API. A connection that breaks ends the source for good,
// because nothing can reach the socket again. Its zero value connects with
// connect.
type firecrackerStatsSource struct {
	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Reader
}

var _ guestStatsSource = (*firecrackerStatsSource)(nil)

// firecrackerAPIGone is the error of a source whose connection to the API
// is closed, or could not be made. The source removes the socket's path once
// it connects, so nothing can connect again, and the error says it is fatal.
type firecrackerAPIGone struct{ err error }

func (e firecrackerAPIGone) Error() string { return e.err.Error() }
func (e firecrackerAPIGone) Unwrap() error { return e.err }
func (e firecrackerAPIGone) Fatal() bool   { return true }

// newFirecrackerStatsSource waits up to wait for the socket at socketPath,
// connects to it, and removes the path. It gives up early when ctx ends.
func newFirecrackerStatsSource(ctx context.Context, socketPath string, wait time.Duration) (*firecrackerStatsSource, error) {
	s := &firecrackerStatsSource{}
	if err := s.connect(ctx, socketPath, wait); err != nil {
		return nil, err
	}
	return s, nil
}

// connect waits up to wait for the socket at socketPath, connects to it,
// and removes the path. It gives up early when ctx ends, with ctx's error,
// and the source may connect again later. Any other failure is fatal,
// because a socket that never appeared, or a path that could not be removed,
// will not come right.
func (s *firecrackerStatsSource) connect(ctx context.Context, socketPath string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		conn, err := net.DialTimeout("unix", socketPath, fcReadTimeout)
		if err == nil {
			if rmErr := os.Remove(socketPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				_ = conn.Close()
				return firecrackerAPIGone{fmt.Errorf("remove the firecracker API socket path: %w", rmErr)}
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.conn != nil {
				_ = conn.Close()
				return errors.New("the firecracker API is already connected")
			}
			s.conn, s.reader = conn, bufio.NewReader(conn)
			return nil
		}
		if time.Now().After(deadline) {
			return firecrackerAPIGone{fmt.Errorf("connect to the firecracker API socket: %w", err)}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(fcSocketPoll):
		}
	}
}

// firecrackerBalloonStats is the reply of GET /balloon/statistics, limited to
// the fields the sample uses. A pointer tells a missing field from a zero.
type firecrackerBalloonStats struct {
	FreeMemory      *uint64 `json:"free_memory"`
	TotalMemory     *uint64 `json:"total_memory"`
	AvailableMemory *uint64 `json:"available_memory"`
	DiskCaches      *uint64 `json:"disk_caches"`
}

// Read asks Firecracker for the newest statistics on the kept connection,
// with a deadline of two seconds or the earlier deadline of ctx. Any error
// other than errFirecrackerStatsPending closes the connection, because a
// reply that arrives late would answer the wrong request, and is fatal,
// because the connection cannot be made again. A source that is closed, or
// never connected, fails every read with an error that is fatal too.
func (s *firecrackerStatsSource) Read(ctx context.Context) (guestMemorySample, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn == nil {
		return guestMemorySample{}, firecrackerAPIGone{errors.New("the firecracker API connection is closed")}
	}

	sample, err := s.roundTrip(ctx)
	if err != nil && !errors.Is(err, errFirecrackerStatsPending) {
		_ = s.closeLocked()
		return sample, firecrackerAPIGone{fmt.Errorf("%w; the firecracker API connection is closed", err)}
	}
	return sample, err
}

func (s *firecrackerStatsSource) roundTrip(ctx context.Context) (guestMemorySample, error) {
	if err := ctx.Err(); err != nil {
		return guestMemorySample{}, err
	}

	deadline := time.Now().Add(fcReadTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := s.conn.SetDeadline(deadline); err != nil {
		return guestMemorySample{}, fmt.Errorf("set the firecracker API deadline: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = s.conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if _, err := io.WriteString(s.conn, "GET "+fcStatsPath+" HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n"); err != nil {
		return guestMemorySample{}, fmt.Errorf("request the balloon statistics: %w", err)
	}
	resp, err := http.ReadResponse(s.reader, nil)
	if err != nil {
		return guestMemorySample{}, fmt.Errorf("read the balloon statistics reply: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return guestMemorySample{}, fmt.Errorf("read the balloon statistics body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return guestMemorySample{}, fmt.Errorf("balloon statistics returned status %d: %s", resp.StatusCode, body)
	}
	if resp.Close {
		return guestMemorySample{}, errors.New("firecracker closed the API connection")
	}

	var stats firecrackerBalloonStats
	if err := json.Unmarshal(body, &stats); err != nil {
		return guestMemorySample{}, fmt.Errorf("parse the balloon statistics: %w", err)
	}
	if stats.TotalMemory == nil || stats.AvailableMemory == nil {
		return guestMemorySample{}, errFirecrackerStatsPending
	}

	sample := guestMemorySample{Total: *stats.TotalMemory, Available: *stats.AvailableMemory}
	if stats.FreeMemory != nil {
		sample.Free = *stats.FreeMemory
	}
	if stats.DiskCaches != nil {
		sample.Caches = *stats.DiskCaches
	}
	return sample, nil
}

// Close ends the connection. It is safe to call more than once.
func (s *firecrackerStatsSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeLocked()
}

func (s *firecrackerStatsSource) closeLocked() error {
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	s.reader = nil
	return err
}
