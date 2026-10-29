package runcontainerd

import (
	"errors"
	"fmt"
	"time"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/lager/v3"
	cgroup1stats "github.com/containerd/cgroups/v3/cgroup1/stats"
	cgroup2stats "github.com/containerd/cgroups/v3/cgroup2/stats"
	"github.com/containerd/typeurl/v2"
)

// ContainerdStatser reads container metrics from the containerd task metrics
// API. The runc statser shells out to `runc events --stats`, which knows
// nothing of containers that another runtime such as runsc runs.
//
// A shim reports cgroup v1 or cgroup v2 metrics depending on its own
// configuration, not on the host, so both encodings are accepted. They are
// mapped onto the fields that the runc statser fills from the matching
// memory.stat file. The usage toward the memory limit uses the runc statser's
// formula without its swap term, because containerd's metrics do not carry the
// memory.stat swap counters. runsc reports only a total memory usage and no
// memory.stat breakdown, and in that case the total is the usage toward the
// limit.
type ContainerdStatser struct {
	containerManager ContainerManager
}

func NewContainerdStatser(containerManager ContainerManager) *ContainerdStatser {
	return &ContainerdStatser{containerManager: containerManager}
}

func (s *ContainerdStatser) Stats(log lager.Logger, id string) (gardener.StatsContainerMetrics, error) {
	log = log.Session("containerd-stats", lager.Data{"id": id})

	data, createdAt, err := s.containerManager.TaskMetrics(log, id)
	if err != nil {
		log.Error("getting-task-metrics-failed", err)
		return gardener.StatsContainerMetrics{}, err
	}
	if data == nil {
		err := errors.New("task metrics carry no data")
		log.Error("task-metrics-empty", err)
		return gardener.StatsContainerMetrics{}, err
	}

	decoded, err := typeurl.UnmarshalAny(data)
	if err != nil {
		log.Error("decoding-task-metrics-failed", err, lager.Data{"type": data.GetTypeUrl()})
		return gardener.StatsContainerMetrics{}, fmt.Errorf("decoding task metrics of type %s: %w", data.GetTypeUrl(), err)
	}

	var stats gardener.StatsContainerMetrics
	switch metrics := decoded.(type) {
	case *cgroup1stats.Metrics:
		stats = statsFromCgroup1(metrics)
	case *cgroup2stats.Metrics:
		stats = statsFromCgroup2(metrics)
	default:
		err := fmt.Errorf("unsupported task metrics type %s", data.GetTypeUrl())
		log.Error("unsupported-task-metrics", err)
		return gardener.StatsContainerMetrics{}, err
	}

	stats.Age = time.Since(createdAt)
	return stats, nil
}

func statsFromCgroup1(metrics *cgroup1stats.Metrics) gardener.StatsContainerMetrics {
	memory := metrics.GetMemory()
	memoryStat := garden.ContainerMemoryStat{
		Cache:                   memory.GetCache(),
		Rss:                     memory.GetRSS(),
		MappedFile:              memory.GetMappedFile(),
		Pgpgin:                  memory.GetPgPgIn(),
		Pgpgout:                 memory.GetPgPgOut(),
		Pgfault:                 memory.GetPgFault(),
		Pgmajfault:              memory.GetPgMajFault(),
		InactiveAnon:            memory.GetInactiveAnon(),
		ActiveAnon:              memory.GetActiveAnon(),
		InactiveFile:            memory.GetInactiveFile(),
		ActiveFile:              memory.GetActiveFile(),
		Unevictable:             memory.GetUnevictable(),
		HierarchicalMemoryLimit: memory.GetHierarchicalMemoryLimit(),
		HierarchicalMemswLimit:  memory.GetHierarchicalSwapLimit(),
		TotalCache:              memory.GetTotalCache(),
		TotalRss:                memory.GetTotalRSS(),
		TotalMappedFile:         memory.GetTotalMappedFile(),
		TotalPgpgin:             memory.GetTotalPgPgIn(),
		TotalPgpgout:            memory.GetTotalPgPgOut(),
		TotalPgfault:            memory.GetTotalPgFault(),
		TotalPgmajfault:         memory.GetTotalPgMajFault(),
		TotalInactiveAnon:       memory.GetTotalInactiveAnon(),
		TotalActiveAnon:         memory.GetTotalActiveAnon(),
		TotalInactiveFile:       memory.GetTotalInactiveFile(),
		TotalActiveFile:         memory.GetTotalActiveFile(),
		TotalUnevictable:        memory.GetTotalUnevictable(),
	}

	if memoryStat.TotalRss == 0 && memoryStat.TotalCache == 0 {
		memoryStat.TotalUsageTowardLimit = memory.GetUsage().GetUsage()
	} else {
		memoryStat.TotalUsageTowardLimit = saturatingSub(memoryStat.TotalRss+memoryStat.TotalCache, memoryStat.TotalInactiveFile)
	}

	cpuUsage := metrics.GetCPU().GetUsage()
	return gardener.StatsContainerMetrics{
		Memory: memoryStat,
		CPU: garden.ContainerCPUStat{
			Usage:  cpuUsage.GetTotal(),
			System: cpuUsage.GetKernel(),
			User:   cpuUsage.GetUser(),
		},
		Pid: garden.ContainerPidStat{
			Current: metrics.GetPids().GetCurrent(),
			Max:     metrics.GetPids().GetLimit(),
		},
	}
}

func statsFromCgroup2(metrics *cgroup2stats.Metrics) gardener.StatsContainerMetrics {
	memory := metrics.GetMemory()
	memoryStat := garden.ContainerMemoryStat{
		Anon:         memory.GetAnon(),
		File:         memory.GetFile(),
		InactiveAnon: memory.GetInactiveAnon(),
		ActiveAnon:   memory.GetActiveAnon(),
		InactiveFile: memory.GetInactiveFile(),
		ActiveFile:   memory.GetActiveFile(),
		Unevictable:  memory.GetUnevictable(),
		Pgfault:      memory.GetPgfault(),
		Pgmajfault:   memory.GetPgmajfault(),
	}

	if memoryStat.Anon == 0 && memoryStat.File == 0 {
		memoryStat.TotalUsageTowardLimit = memory.GetUsage()
	} else {
		memoryStat.TotalUsageTowardLimit = saturatingSub(memoryStat.File+memoryStat.Anon, memoryStat.InactiveFile)
	}

	// cgroup v2 reports CPU time in microseconds; garden reports nanoseconds.
	cpu := metrics.GetCPU()
	return gardener.StatsContainerMetrics{
		Memory: memoryStat,
		CPU: garden.ContainerCPUStat{
			Usage:  cpu.GetUsageUsec() * 1000,
			System: cpu.GetSystemUsec() * 1000,
			User:   cpu.GetUserUsec() * 1000,
		},
		Pid: garden.ContainerPidStat{
			Current: metrics.GetPids().GetCurrent(),
			Max:     metrics.GetPids().GetLimit(),
		},
	}
}

func saturatingSub(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}
