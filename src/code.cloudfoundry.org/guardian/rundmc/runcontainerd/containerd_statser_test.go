package runcontainerd_test

import (
	"errors"
	"time"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/guardian/rundmc/runcontainerd"
	"code.cloudfoundry.org/guardian/rundmc/runcontainerd/runcontainerdfakes"
	"code.cloudfoundry.org/lager/v3/lagertest"
	cgroup1stats "github.com/containerd/cgroups/v3/cgroup1/stats"
	cgroup2stats "github.com/containerd/cgroups/v3/cgroup2/stats"
	apievents "github.com/containerd/containerd/api/events"
	"github.com/containerd/typeurl/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type rawAny struct {
	typeURL string
	value   []byte
}

func (a rawAny) GetTypeUrl() string { return a.typeURL }
func (a rawAny) GetValue() []byte   { return a.value }

var _ = Describe("ContainerdStatser", func() {
	var (
		logger           *lagertest.TestLogger
		containerManager *runcontainerdfakes.FakeContainerManager
		statser          *runcontainerd.ContainerdStatser
		createdAt        time.Time

		stats    gardener.StatsContainerMetrics
		statsErr error
	)

	marshal := func(metrics any) typeurl.Any {
		data, err := typeurl.MarshalAny(metrics)
		Expect(err).NotTo(HaveOccurred())
		return data
	}

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("containerd-statser")
		containerManager = new(runcontainerdfakes.FakeContainerManager)
		statser = runcontainerd.NewContainerdStatser(containerManager)
		createdAt = time.Now().Add(-time.Hour)
	})

	JustBeforeEach(func() {
		stats, statsErr = statser.Stats(logger, "some-id")
	})

	It("asks containerd for the metrics of the container's task", func() {
		Expect(containerManager.TaskMetricsCallCount()).To(Equal(1))
		_, actualID := containerManager.TaskMetricsArgsForCall(0)
		Expect(actualID).To(Equal("some-id"))
	})

	Context("when the shim reports cgroup v2 metrics with a memory.stat breakdown", func() {
		BeforeEach(func() {
			containerManager.TaskMetricsReturns(marshal(&cgroup2stats.Metrics{
				Memory: &cgroup2stats.MemoryStat{
					Anon:         100,
					File:         50,
					InactiveFile: 30,
					ActiveFile:   20,
					InactiveAnon: 10,
					ActiveAnon:   90,
					Unevictable:  5,
					Pgfault:      3,
					Pgmajfault:   1,
					Usage:        999,
				},
				CPU:  &cgroup2stats.CPUStat{UsageUsec: 3, UserUsec: 2, SystemUsec: 1},
				Pids: &cgroup2stats.PidsStat{Current: 4, Limit: 1024},
			}), createdAt, nil)
		})

		It("maps the memory.stat fields that the runc statser fills on cgroup v2", func() {
			Expect(statsErr).NotTo(HaveOccurred())
			Expect(stats.Memory).To(Equal(garden.ContainerMemoryStat{
				Anon:                  100,
				File:                  50,
				InactiveFile:          30,
				ActiveFile:            20,
				InactiveAnon:          10,
				ActiveAnon:            90,
				Unevictable:           5,
				Pgfault:               3,
				Pgmajfault:            1,
				TotalUsageTowardLimit: 120,
			}))
		})

		It("converts CPU time from microseconds to nanoseconds", func() {
			Expect(stats.CPU).To(Equal(garden.ContainerCPUStat{Usage: 3000, User: 2000, System: 1000}))
		})

		It("reports the pids", func() {
			Expect(stats.Pid).To(Equal(garden.ContainerPidStat{Current: 4, Max: 1024}))
		})

		It("reports the container age from its creation time", func() {
			Expect(stats.Age).To(BeNumerically(">=", time.Hour))
			Expect(stats.Age).To(BeNumerically("<", time.Hour+time.Minute))
		})
	})

	Context("when the shim reports only a total cgroup v2 memory usage, as runsc does", func() {
		BeforeEach(func() {
			containerManager.TaskMetricsReturns(marshal(&cgroup2stats.Metrics{
				Memory: &cgroup2stats.MemoryStat{Usage: 4096, UsageLimit: 8192},
			}), createdAt, nil)
		})

		It("uses the total as the usage toward the limit", func() {
			Expect(statsErr).NotTo(HaveOccurred())
			Expect(stats.Memory.TotalUsageTowardLimit).To(Equal(uint64(4096)))
		})
	})

	Context("when the cgroup v2 inactive file pages exceed anon and file", func() {
		BeforeEach(func() {
			containerManager.TaskMetricsReturns(marshal(&cgroup2stats.Metrics{
				Memory: &cgroup2stats.MemoryStat{Anon: 1, File: 1, InactiveFile: 5},
			}), createdAt, nil)
		})

		It("reports zero usage toward the limit", func() {
			Expect(stats.Memory.TotalUsageTowardLimit).To(BeZero())
		})
	})

	Context("when the shim reports cgroup v1 metrics with a memory.stat breakdown", func() {
		BeforeEach(func() {
			containerManager.TaskMetricsReturns(marshal(&cgroup1stats.Metrics{
				Memory: &cgroup1stats.MemoryStat{
					Cache:                   11,
					RSS:                     12,
					MappedFile:              13,
					PgPgIn:                  14,
					PgPgOut:                 15,
					PgFault:                 16,
					PgMajFault:              17,
					InactiveAnon:            18,
					ActiveAnon:              19,
					InactiveFile:            20,
					ActiveFile:              21,
					Unevictable:             22,
					HierarchicalMemoryLimit: 23,
					HierarchicalSwapLimit:   24,
					TotalCache:              100,
					TotalRSS:                200,
					TotalMappedFile:         25,
					TotalPgPgIn:             26,
					TotalPgPgOut:            27,
					TotalPgFault:            28,
					TotalPgMajFault:         29,
					TotalInactiveAnon:       30,
					TotalActiveAnon:         31,
					TotalInactiveFile:       50,
					TotalActiveFile:         32,
					TotalUnevictable:        33,
					Usage:                   &cgroup1stats.MemoryEntry{Usage: 999},
				},
				CPU: &cgroup1stats.CPUStat{
					Usage: &cgroup1stats.CPUUsage{Total: 300, Kernel: 100, User: 200},
				},
				Pids: &cgroup1stats.PidsStat{Current: 2, Limit: 512},
			}), createdAt, nil)
		})

		It("maps the memory.stat fields that the runc statser fills on cgroup v1", func() {
			Expect(statsErr).NotTo(HaveOccurred())
			Expect(stats.Memory).To(Equal(garden.ContainerMemoryStat{
				Cache:                   11,
				Rss:                     12,
				MappedFile:              13,
				Pgpgin:                  14,
				Pgpgout:                 15,
				Pgfault:                 16,
				Pgmajfault:              17,
				InactiveAnon:            18,
				ActiveAnon:              19,
				InactiveFile:            20,
				ActiveFile:              21,
				Unevictable:             22,
				HierarchicalMemoryLimit: 23,
				HierarchicalMemswLimit:  24,
				TotalCache:              100,
				TotalRss:                200,
				TotalMappedFile:         25,
				TotalPgpgin:             26,
				TotalPgpgout:            27,
				TotalPgfault:            28,
				TotalPgmajfault:         29,
				TotalInactiveAnon:       30,
				TotalActiveAnon:         31,
				TotalInactiveFile:       50,
				TotalActiveFile:         32,
				TotalUnevictable:        33,
				TotalUsageTowardLimit:   250,
			}))
		})

		It("reports CPU time in nanoseconds unchanged", func() {
			Expect(stats.CPU).To(Equal(garden.ContainerCPUStat{Usage: 300, User: 200, System: 100}))
		})

		It("reports the pids", func() {
			Expect(stats.Pid).To(Equal(garden.ContainerPidStat{Current: 2, Max: 512}))
		})
	})

	Context("when the shim reports only a total cgroup v1 memory usage, as runsc does", func() {
		BeforeEach(func() {
			containerManager.TaskMetricsReturns(marshal(&cgroup1stats.Metrics{
				Memory: &cgroup1stats.MemoryStat{Usage: &cgroup1stats.MemoryEntry{Usage: 8192}},
			}), createdAt, nil)
		})

		It("uses the total as the usage toward the limit", func() {
			Expect(statsErr).NotTo(HaveOccurred())
			Expect(stats.Memory.TotalUsageTowardLimit).To(Equal(uint64(8192)))
		})
	})

	Context("when the metrics carry no memory, CPU, or pids sections", func() {
		BeforeEach(func() {
			containerManager.TaskMetricsReturns(marshal(&cgroup1stats.Metrics{}), createdAt, nil)
		})

		It("reports zero values for them", func() {
			Expect(statsErr).NotTo(HaveOccurred())
			Expect(stats.Memory).To(Equal(garden.ContainerMemoryStat{}))
			Expect(stats.CPU).To(Equal(garden.ContainerCPUStat{}))
			Expect(stats.Pid).To(Equal(garden.ContainerPidStat{}))
		})
	})

	Context("when getting the task metrics fails", func() {
		BeforeEach(func() {
			containerManager.TaskMetricsReturns(nil, time.Time{}, errors.New("metrics-failed"))
		})

		It("returns the error", func() {
			Expect(statsErr).To(MatchError("metrics-failed"))
		})
	})

	Context("when the task metrics carry no data", func() {
		BeforeEach(func() {
			containerManager.TaskMetricsReturns(nil, createdAt, nil)
		})

		It("returns an error", func() {
			Expect(statsErr).To(MatchError("task metrics carry no data"))
		})
	})

	Context("when the task metrics cannot be decoded", func() {
		BeforeEach(func() {
			containerManager.TaskMetricsReturns(rawAny{typeURL: "example.com/not.a.Type", value: []byte("x")}, createdAt, nil)
		})

		It("returns an error naming the type", func() {
			Expect(statsErr).To(MatchError(ContainSubstring("decoding task metrics of type example.com/not.a.Type")))
		})
	})

	Context("when the task metrics are of an unsupported type", func() {
		BeforeEach(func() {
			containerManager.TaskMetricsReturns(marshal(&apievents.TaskOOM{ContainerID: "some-id"}), createdAt, nil)
		})

		It("returns an error naming the type", func() {
			Expect(statsErr).To(MatchError(ContainSubstring("unsupported task metrics type")))
		})
	})
})
