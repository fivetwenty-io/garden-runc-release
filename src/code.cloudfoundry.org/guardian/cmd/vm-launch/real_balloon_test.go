//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	// realBalloonGuestMiB is the memory of the guests below. The fill takes
	// realBalloonFillMiB of it, which /dev/shm, half of the guest's memory,
	// holds with room to spare.
	realBalloonGuestMiB = 256
	realBalloonFillMiB  = 64

	// realBalloonRiseMiB is how much the guest's figure has to rise when the
	// fill lands, and how far it has to fall back after the removal. The
	// guest's own use moves a little beside the fill, so the bound is 8 MiB
	// under the fill.
	realBalloonRiseMiB = 56

	// realBalloonReturnMiB is how much of the fill free page reporting has to
	// give back to the host, as the drop in the hypervisor's resident memory.
	// It is half of the fill, because the guest reports only the free blocks
	// it can find whole.
	realBalloonReturnMiB = 32

	// realBalloonSettle is how long after the removal the specs look for the
	// fall of the figure and of the resident memory.
	realBalloonSettle = 15 * time.Second

	// realBalloonRunTime bounds a whole fill run, from the guest's boot.
	realBalloonRunTime = 5 * time.Minute

	// realBalloonPollInterval is the interval of the poller in the specs. It
	// is shorter than vm-launch's, so a run holds several lines.
	realBalloonPollInterval = 3 * time.Second
)

// realBalloonFillScript is the guest's command in the fill runs. It marks
// each phase on the console, so that the host knows when to look: an idle
// guest, the writing of a file into /dev/shm, which the guest holds in
// memory it cannot reclaim, the end of that write, and the removal of the
// file. The data is not zeros, so the host cannot take a page of it for a
// page it never touched.
const realBalloonFillScript = `echo balloon-idle
sleep 20
echo balloon-filling
tr '\000' x </dev/zero | dd of=/dev/shm/fill bs=1M count=64 iflag=fullblock 2>/dev/null
echo balloon-filled
sleep 15
rm /dev/shm/fill
echo balloon-freed
sleep 90
`

// realBalloonMarkers are the console lines of realBalloonFillScript, in the
// order the guest prints them.
var realBalloonMarkers = []string{"balloon-idle", "balloon-filling", "balloon-filled", "balloon-freed"}

// realBalloon is one real QEMU guest that a spec drives, with the QMP monitor
// that vm-launch would hold.
type realBalloon struct {
	cmd     *exec.Cmd
	console *bootWriter
	stderr  *safeBuffer
	monitor *qmpMonitor
}

// details describes the run for a failure.
func (h *realBalloon) details() string {
	return "stderr: " + h.stderr.String() + "\nconsole:\n" + h.console.String()
}

// waitFor fails the spec unless the guest's console holds text within the
// time given.
func (h *realBalloon) waitFor(text string, within time.Duration) {
	GinkgoHelper()
	deadline := time.Now().Add(within)
	for !strings.Contains(h.console.String(), text) {
		if time.Now().After(deadline) {
			Fail(fmt.Sprintf("the guest never printed %q within %v\n%s", text, within, h.details()))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// hostRSS returns the bytes of the hypervisor's own memory that are resident,
// anonymous and shared alike. Guest RAM is anonymous memory, and a guest with
// a share has it in a memfd, which the kernel counts as shared memory.
func (h *realBalloon) hostRSS() uint64 {
	GinkgoHelper()
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", h.cmd.Process.Pid))
	Expect(err).NotTo(HaveOccurred())
	var total uint64
	for _, key := range []string{"RssAnon", "RssShmem"} {
		m := regexp.MustCompile(`(?m)^` + key + `:\s+([0-9]+) kB$`).FindSubmatch(status)
		Expect(m).NotTo(BeNil(), "no %s in\n%s", key, status)
		kib, err := strconv.ParseUint(string(m[1]), 10, 64)
		Expect(err).NotTo(HaveOccurred())
		total += kib << 10
	}
	return total
}

// runRealBalloonGuest boots the guest that build describes under TCG, with a
// QMP monitor on the file that build is given, as vm-launch runs QEMU for a
// guest with a monitor. Once the guest has started userspace, it calls drive,
// and it ends QEMU when drive returns. It fails the spec unless the argv holds
// the balloon device, which vm-launch gives every QEMU guest.
func runRealBalloonGuest(build func(qmp *os.File) ([]string, []*os.File), drive func(h *realBalloon)) {
	bootWithRetry(func() bool {
		conn, qmp, err := newQMPSocket()
		Expect(err).NotTo(HaveOccurred())
		defer conn.Close()
		defer qmp.Close()
		argv, files := build(qmp)
		Expect(argv).To(ContainElement(qemuBalloonArgs()[1]), "the guest has no balloon device, so there are no statistics to read")
		Expect(argv).To(ContainElement(ContainSubstring("rdinit=/"+realTestInit)), "the guest would never print %s", realBootMark)

		cmd := newHypervisorCmd(argv, files)
		h := &realBalloon{cmd: cmd, console: newBootWriter(realBootMark), stderr: &safeBuffer{}, monitor: newQMPMonitor(conn)}
		cmd.Stdout, cmd.Stderr = h.console, h.stderr
		Expect(cmd.Start()).To(Succeed())
		exited := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(exited)
		}()
		kill := func() {
			_ = cmd.Process.Kill()
			<-exited
		}
		defer kill()

		select {
		case <-h.console.booted:
		case <-exited:
			Fail("QEMU exited before the guest started userspace\n" + h.details())
		case <-time.After(realBootTimeout):
			kill()
			AddReportEntry("real QEMU boot retry", fmt.Sprintf("the guest did not print %s in %v, so QEMU was killed\n%s", realBootMark, realBootTimeout, h.details()))
			return false
		}
		drive(h)
		select {
		case <-exited:
			Fail("QEMU exited while the spec still drove the guest\n" + h.details())
		default:
		}
		return true
	})
}

// balloonSample is one look at a fill run, once a second: the hypervisor's
// resident memory and, when the guest had answered, its statistics.
type balloonSample struct {
	at  time.Time
	rss uint64
	mem *guestMemorySample
}

// realFillRun is what a fill run saw.
type realFillRun struct {
	// series holds a sample each second, from the guest's first phase until
	// 20 seconds after the removal.
	series []balloonSample

	// at holds when the loop first saw each of realBalloonMarkers.
	at map[string]time.Time

	// stderr is what the real poller wrote as vm-launch's stderr, and
	// pollerLog is what it logged.
	stderr, pollerLog string
}

// driveBalloonFill drives a guest that runs realBalloonFillScript. It turns
// the statistics on, starts the real poller on a three second interval with
// the buffer that stands for vm-launch's stderr, and then looks once a second
// at the hypervisor's memory and at the guest's statistics until the guest's
// file has been gone for 20 seconds.
func driveBalloonFill(h *realBalloon) realFillRun {
	GinkgoHelper()
	stats := newQEMUGuestStats(h.monitor)
	enable, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	Expect(stats.Enable(enable)).To(Succeed(), h.details())

	guestBytes := uint64(realBalloonGuestMiB) << 20
	out, pollerLog := &safeBuffer{}, &safeBuffer{}
	poller := newMetricsPoller(newQEMUGuestStats(h.monitor), guestBytes, out, log.New(pollerLog, "", 0))
	poller.interval = realBalloonPollInterval
	poller.start()
	defer poller.stop()

	run := realFillRun{at: map[string]time.Time{}}
	deadline := time.Now().Add(realBalloonRunTime)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		now := time.Now()
		console := h.console.String()
		for _, m := range realBalloonMarkers {
			if _, seen := run.at[m]; !seen && strings.Contains(console, m) {
				run.at[m] = now
			}
		}
		s := balloonSample{at: now, rss: h.hostRSS()}
		read, cancelRead := context.WithTimeout(context.Background(), metricsReadTimeout)
		if mem, err := stats.Read(read); err == nil {
			s.mem = &mem
		}
		cancelRead()
		run.series = append(run.series, s)
		if freed, ok := run.at["balloon-freed"]; ok && now.Sub(freed) > realBalloonSettle+5*time.Second {
			break
		}
	}
	for _, m := range realBalloonMarkers {
		Expect(run.at).To(HaveKey(m), "the guest never printed %s\n%s", m, h.details())
	}
	poller.stop()
	run.stderr, run.pollerLog = out.String(), pollerLog.String()
	return run
}

// between returns the samples taken from the time from to the time to.
func (r realFillRun) between(from, to time.Time) []balloonSample {
	var out []balloonSample
	for _, s := range r.series {
		if !s.at.Before(from) && !s.at.After(to) {
			out = append(out, s)
		}
	}
	return out
}

// idle returns the guest's figure just before the fill began, which is the
// last sample from the idle phase that carries statistics.
func (r realFillRun) idle() uint64 {
	GinkgoHelper()
	var used uint64
	found := false
	for _, s := range r.between(r.at["balloon-idle"], r.at["balloon-filling"]) {
		if s.mem != nil {
			used, found = s.mem.used(), true
		}
	}
	Expect(found).To(BeTrue(), "the guest sent no statistics while it was idle, which lasted %v", r.at["balloon-filling"].Sub(r.at["balloon-idle"]))
	return used
}

// peak returns the highest figure of the guest from the start of the fill to
// the removal.
func (r realFillRun) peak() uint64 {
	var peak uint64
	for _, s := range r.between(r.at["balloon-filling"], r.at["balloon-freed"]) {
		if s.mem != nil {
			peak = max(peak, s.mem.used())
		}
	}
	return peak
}

// settled returns the lowest figure of the guest within realBalloonSettle of
// the removal, and whether the guest sent any statistics in that time.
func (r realFillRun) settled() (uint64, bool) {
	freed := r.at["balloon-freed"]
	low, found := uint64(0), false
	for _, s := range r.between(freed, freed.Add(realBalloonSettle)) {
		if s.mem != nil && (!found || s.mem.used() < low) {
			low, found = s.mem.used(), true
		}
	}
	return low, found
}

// rssPeak returns the most resident memory of the hypervisor from the end of
// the fill to the removal, and rssLow the least within realBalloonSettle of
// the removal.
func (r realFillRun) rssPeak() uint64 {
	var peak uint64
	for _, s := range r.between(r.at["balloon-filled"], r.at["balloon-freed"]) {
		peak = max(peak, s.rss)
	}
	return peak
}

func (r realFillRun) rssLow() uint64 {
	freed := r.at["balloon-freed"]
	low := ^uint64(0)
	for _, s := range r.between(freed, freed.Add(realBalloonSettle)) {
		low = min(low, s.rss)
	}
	return low
}

// expectFigureFollows requires the guest's figure to rise with the fill and
// to fall back after the removal, and records the idle figure.
func expectFigureFollows(r realFillRun) {
	GinkgoHelper()
	idle, peak := r.idle(), r.peak()
	low, ok := r.settled()
	AddReportEntry("idle guest figure", fmt.Sprintf("used=%d MiB, peak=%d MiB, after the removal=%d MiB, of %d MiB", idle>>20, peak>>20, low>>20, realBalloonGuestMiB))
	Expect(peak).To(BeNumerically(">=", idle+realBalloonRiseMiB<<20), "the figure did not rise by %d MiB with the %d MiB fill: idle %d bytes, peak %d bytes", realBalloonRiseMiB, realBalloonFillMiB, idle, peak)
	Expect(ok).To(BeTrue(), "the guest sent no statistics within %v of the removal", realBalloonSettle)
	Expect(low).To(BeNumerically("<=", peak-realBalloonRiseMiB<<20), "the figure did not fall by %d MiB within %v of the removal: peak %d bytes, then %d bytes", realBalloonRiseMiB, realBalloonSettle, peak, low)
}

// expectMemoryReturned requires the hypervisor's resident memory to fall by
// realBalloonReturnMiB within realBalloonSettle of the removal, which only
// free page reporting does, as the guest's balloon never inflates.
func expectMemoryReturned(r realFillRun) {
	GinkgoHelper()
	peak, low := r.rssPeak(), r.rssLow()
	AddReportEntry("hypervisor resident memory", fmt.Sprintf("peak=%d MiB, within %v of the removal=%d MiB", peak>>20, realBalloonSettle, low>>20))
	Expect(peak).To(BeNumerically(">=", low+realBalloonReturnMiB<<20), "free page reporting did not return %d MiB to the host within %v of the removal: resident %d bytes at the peak, %d bytes after", realBalloonReturnMiB, realBalloonSettle, peak, low)
}

// bootBalloonFill boots a guest that runs realBalloonFillScript, with a share
// of an empty host directory when withShare is set, and returns what the run
// saw. The share is served by the real virtiofsd, and it puts the guest's RAM
// in a memfd.
func bootBalloonFill(withShare bool) realFillRun {
	GinkgoHelper()
	art := realArtifacts()
	qemu := realQEMU()
	requireMicrovm(qemu)

	g := taskGuest(realBalloonFillScript)
	var shares []shareSocket
	if withShare {
		vfs := realShareVirtiofsd()
		// A Unix socket path is short, so the socket gets a short directory.
		sockDir, err := os.MkdirTemp("", "rvm-s")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { os.RemoveAll(sockDir) })
		dir := GinkgoT().TempDir()
		Expect(os.Chmod(dir, 0o755)).To(Succeed())
		tag := shareTag(0)
		sock := filepath.Join(sockDir, shareSocketName(tag))
		serveRealShare(vfs, sock, dir)
		g.vols = []guestVolume{{ContainerDir: "/home/vcap/shared", Settings: volumeSettings{Mode: volumeShare}}}
		shares = []shareSocket{{Index: 0, Tag: tag, Path: sock}}
	}
	withRealRoot(&g)
	marked := withUserspaceMark(newRealInitramfs(g))
	root := realRootImage()

	var run realFillRun
	runRealBalloonGuest(func(qmp *os.File) ([]string, []*os.File) {
		files, drives, initrdPath, monitorFD, rootPath := hypervisorFiles(nil, marked, qmp, root)
		argv, err := hypervisorArgvWithStack(backend.VMQemu, art, GinkgoT().TempDir(), initrdPath, realBalloonGuestMiB, g.nw, drives, rootPath, monitorFD, nil, shares...)
		Expect(err).NotTo(HaveOccurred())
		return markedArgv(tcgArgv(qemu, argv)), files
	}, func(h *realBalloon) {
		run = driveBalloonFill(h)
	})
	return run
}

// realMetricsLine matches the line that vm-launch writes to its stderr.
var realMetricsLine = regexp.MustCompile(`^` + regexp.QuoteMeta(metricsLinePrefix) + `used=([0-9]+) total=([0-9]+) available=([0-9]+) free=([0-9]+) caches=([0-9]+)$`)

var _ = Describe("a real QEMU guest with the virtio balloon", func() {
	Describe("a guest that fills and empties /dev/shm", Ordered, func() {
		var run realFillRun

		BeforeAll(func() {
			run = bootBalloonFill(false)
		})

		It("reports a figure that rises by what the guest holds in memory and falls back when the guest lets it go", func() {
			expectFigureFollows(run)
		})

		It("returns the memory the guest frees to the host through free page reporting", func() {
			expectMemoryReturned(run)
		})

		It("writes well-formed metrics lines to stderr while the guest runs, each from a sample that fits the guest", func() {
			var lines []string
			for _, line := range strings.Split(strings.TrimSuffix(run.stderr, "\n"), "\n") {
				if line != "" {
					lines = append(lines, line)
				}
			}
			Expect(len(lines)).To(BeNumerically(">=", 2), "stderr:\n%s\npoller log:\n%s", run.stderr, run.pollerLog)
			for _, line := range lines {
				m := realMetricsLine.FindStringSubmatch(line)
				Expect(m).NotTo(BeNil(), "not a metrics line: %q", line)
				var n [5]uint64
				for i := range n {
					v, err := strconv.ParseUint(m[i+1], 10, 64)
					Expect(err).NotTo(HaveOccurred())
					n[i] = v
				}
				used, total, available := n[0], n[1], n[2]
				Expect(total).To(BeNumerically(">", 0), line)
				Expect(total).To(BeNumerically("<=", uint64(realBalloonGuestMiB)<<20), line)
				Expect(used).To(Equal(total-available), line)
			}
			Expect(run.pollerLog).NotTo(ContainSubstring("can no longer be read"), run.pollerLog)
		})
	})

	It("reports the same figure, and returns the same memory, for a guest with a share, whose RAM is a memfd", func() {
		run := bootBalloonFill(true)
		expectFigureFollows(run)
		expectMemoryReturned(run)
	})

	It("fits the balloon on the guest with the most drives, a stack guest with four volumes, a root, the stack, and the droplet beside the NIC, and every drive still answers with its own serial", func() {
		art := realArtifacts()
		qemu := realQEMU()
		requireMicrovm(qemu)

		// A stack guest mounts private disk images, so the guest with the
		// most devices is a stack guest with the root, all four volumes,
		// the stack, and the droplet. Its launcher only says that it ran and
		// then waits, with the stack's own busybox, so that the host can
		// look at the guest's devices while the guest runs.
		sd := &stackDrives{stack: realStackImage(art), droplet: realDropletImage(art)}
		launcher := "#!/bin/sh\necho balloon-command-ran\nexec /bin/busybox sleep 120\n"
		lf, err := os.Open(writeTempFile("launcher", launcher))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(lf.Close)
		g := taskGuest("")
		g.stack = &guestStack{
			launcher: guestTool{name: "launcher", file: lf, size: int64(len(launcher))},
			argv:     shellJoin([]string{stackLauncherPath, "/home/vcap/app", "", "{}"}),
			cwd:      "/home/vcap",
			hostname: "stack-guest-0",
			hosts:    []byte("127.0.0.1 localhost\n"),
		}
		var vols []*os.File
		var sizes []int64
		for i := range maxVolumes {
			vols = append(vols, openSizedFile(defaultImageSize))
			sizes = append(sizes, defaultImageSize)
			g.vols = append(g.vols, guestVolume{ContainerDir: "/home/vcap/data" + strconv.Itoa(i), ImageName: "volume.img"})
		}
		Expect(vols).To(HaveLen(4), "this spec is for the guest with the most volume drives")
		withRealRoot(&g)
		root := realRootImage()
		g.drives, err = newGuestDrivesWithStack(backend.VMQemu, nil, root, sd)
		Expect(err).NotTo(HaveOccurred())
		g.drives.volumes = qemuImageDrives(sizes...)
		marked := withUserspaceMark(newRealInitramfs(g))

		runRealBalloonGuest(func(qmp *os.File) ([]string, []*os.File) {
			files, drives, initrdPath, monitorFD, rootPath := hypervisorFilesWithStack(imageAttachments(vols...), marked, qmp, root, sd)
			argv, err := hypervisorArgvWithStack(backend.VMQemu, art, GinkgoT().TempDir(), initrdPath, realBalloonGuestMiB, g.nw, drives, rootPath, monitorFD, sd)
			Expect(err).NotTo(HaveOccurred())
			return markedArgv(tcgArgv(qemu, argv)), files
		}, func(h *realBalloon) {
			// Stage 1 compares every drive's serial and size with /rvm/disks
			// and fails the boot before the command on a mismatch, so the
			// command's line shows that each drive the guest has is the one
			// it was told about.
			h.waitFor("balloon-command-ran", realBootTimeout)
			Expect(h.console.String()).NotTo(ContainSubstring("vm-launch guest setup"), h.details())

			tree, err := h.monitor.humanCommand("info qtree")
			Expect(err).NotTo(HaveOccurred())
			var devices, serials []string
			for _, m := range regexp.MustCompile(`(?m)^\s+dev: (virtio-[a-z]+-device),`).FindAllStringSubmatch(tree, -1) {
				devices = append(devices, m[1])
			}
			for _, m := range regexp.MustCompile(`(?m)^\s+serial = "([^"]*)"\r?$`).FindAllStringSubmatch(tree, -1) {
				serials = append(serials, m[1])
			}
			// Nine devices, each on a virtio-mmio transport of its own, out
			// of the 24 the microvm machine has: the NIC, the four volumes,
			// the root, the stack, the droplet, and the balloon.
			Expect(devices).To(ConsistOf(slices.Concat(
				[]string{"virtio-net-device", "virtio-balloon-device"},
				slices.Repeat([]string{"virtio-blk-device"}, maxVolumes+3),
			)), tree)
			Expect(serials).To(ConsistOf(qemuVolumeSerial(0), qemuVolumeSerial(1), qemuVolumeSerial(2), qemuVolumeSerial(3), qemuRootSerial, qemuStackSerial, qemuDropletSerial), tree)

			// The balloon works beside all of them: the guest answers a read
			// with statistics that fit its size.
			stats := newQEMUGuestStats(h.monitor)
			enable, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			Expect(stats.Enable(enable)).To(Succeed(), h.details())
			var sample guestMemorySample
			Eventually(func() error {
				read, cancelRead := context.WithTimeout(context.Background(), metricsReadTimeout)
				defer cancelRead()
				var err error
				sample, err = stats.Read(read)
				return err
			}, realBootTimeout, 2*time.Second).Should(Succeed(), h.details())
			Expect(sample.check(uint64(realBalloonGuestMiB) << 20)).To(Succeed())
		})
	})
})
