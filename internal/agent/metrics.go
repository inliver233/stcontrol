package agent

import (
	"fmt"
	"math"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
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

func collectCapacityMetricsImpl(dataDir string) (CapacityMetrics, error) {
	var metrics CapacityMetrics
	// CPU: 采样 500ms
	cpuVals, err := cpu.Percent(500*time.Millisecond, false)
	if err != nil {
		return metrics, fmt.Errorf("collect CPU metrics: %w", err)
	}
	if len(cpuVals) == 0 {
		return metrics, fmt.Errorf("collect CPU metrics: no samples")
	}
	metrics.CPUPct = cpuVals[0]

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
