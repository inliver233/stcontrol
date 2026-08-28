package agent

import (
	"fmt"
	"math"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
)

type CapacityMetrics struct {
	CPUPct             float64
	MemPct             float64
	DiskPct            float64
	DiskTotalBytes     int64
	DiskAvailableBytes int64
}

func CollectCapacityMetrics(dataDir string) (CapacityMetrics, error) {
	return collectCapacityMetricsImpl(dataDir)
}

// collectMetricsImpl 用 gopsutil 采集系统负载。
func collectMetricsImpl(dataDir string) (cpuPct, memPct, diskPct float64, err error) {
	metrics, err := collectCapacityMetricsImpl(dataDir)
	return metrics.CPUPct, metrics.MemPct, metrics.DiskPct, err
}

// normalizedLoadPercent turns the one-minute runnable-load average into a
// machine-wide pressure percentage.  The old implementation used a single
// 500ms cpu.Percent sample.  That value is an instantaneous scheduler sample
// and is especially misleading in a container or while a short-lived backup
// compressor is running; the Controller then treated it as a sustained
// capacity average.  uptime(1) uses the same load-average source, so this
// keeps the Agent and the operator's host-level view on one stable scale.
func normalizedLoadPercent(load1 float64, logicalCPUCount int) float64 {
	if math.IsNaN(load1) || math.IsInf(load1, 0) || load1 < 0 || logicalCPUCount <= 0 {
		return 0
	}
	value := load1 / float64(logicalCPUCount) * 100
	if value > 100 {
		return 100
	}
	return value
}

func collectCPUPct() (float64, error) {
	// Prefer the same one-minute load average exposed by uptime.  It is already
	// smoothed by the kernel and avoids classifying a 500ms spike as sustained
	// node pressure.  A platform without load-average support falls back to a
	// longer cpu.Percent sample so the metric remains useful outside Linux.
	if average, err := load.Avg(); err == nil && average != nil {
		logicalCPUCount, countErr := cpu.Counts(true)
		if countErr == nil && logicalCPUCount > 0 &&
			!math.IsNaN(average.Load1) && !math.IsInf(average.Load1, 0) && average.Load1 >= 0 {
			return normalizedLoadPercent(average.Load1, logicalCPUCount), nil
		}
	}
	cpuVals, err := cpu.Percent(2*time.Second, false)
	if err != nil {
		return 0, fmt.Errorf("collect CPU metrics: %w", err)
	}
	if len(cpuVals) == 0 || math.IsNaN(cpuVals[0]) || math.IsInf(cpuVals[0], 0) {
		return 0, fmt.Errorf("collect CPU metrics: no valid samples")
	}
	return math.Max(0, math.Min(100, cpuVals[0])), nil
}

func collectCapacityMetricsImpl(dataDir string) (CapacityMetrics, error) {
	var metrics CapacityMetrics
	// CPU: prefer the kernel's one-minute load average normalized by logical
	// CPU count; see collectCPUPct for why this is more stable than a 500ms
	// instantaneous percentage.
	var err error
	metrics.CPUPct, err = collectCPUPct()
	if err != nil {
		return metrics, err
	}

	// 内存
	vm, err := mem.VirtualMemory()
	if err != nil {
		return metrics, fmt.Errorf("collect memory metrics: %w", err)
	}
	metrics.MemPct = vm.UsedPercent

	// 磁盘: 取数据目录所在分区
	path := dataDir
	if path == "" {
		path = "/"
	}
	du, err := disk.Usage(path)
	if err != nil {
		return metrics, fmt.Errorf("collect disk metrics: %w", err)
	}
	if du.Total > math.MaxInt64 || du.Free > math.MaxInt64 {
		return metrics, fmt.Errorf("disk metrics exceed supported range")
	}
	metrics.DiskPct = du.UsedPercent
	metrics.DiskTotalBytes = int64(du.Total)
	metrics.DiskAvailableBytes = int64(du.Free)
	return metrics, nil
}
