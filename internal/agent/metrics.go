package agent

import (
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

// collectMetricsImpl 用 gopsutil 采集系统负载。
func collectMetricsImpl(dataDir string) (cpuPct, memPct, diskPct float64, err error) {
	// CPU: 采样 500ms
	cpuVals, err := cpu.Percent(500*time.Millisecond, false)
	if err == nil && len(cpuVals) > 0 {
		cpuPct = cpuVals[0]
	}

	// 内存
	vm, err := mem.VirtualMemory()
	if err == nil {
		memPct = vm.UsedPercent
	}

	// 磁盘: 取数据目录所在分区
	path := dataDir
	if path == "" {
		path = "/"
	}
	du, err := disk.Usage(path)
	if err == nil {
		diskPct = du.UsedPercent
	}

	return cpuPct, memPct, diskPct, nil
}
