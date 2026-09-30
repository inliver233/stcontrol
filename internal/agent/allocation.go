package agent

import (
	"log"
	"time"
)

// defaultAllocationRefreshInterval bounds how stale the reported allocation may
// become. Allocation feeds quota watermarks, which move far slower than the
// heartbeat interval, while a full walk of a large tavern (millions of files)
// can take longer than one heartbeat.
const defaultAllocationRefreshInterval = 5 * time.Minute

type allocationSnapshot struct {
	valid      bool
	bytes      int64
	computedAt time.Time
	refreshing bool
}

// cachedAllocatedBytes returns the managed data size without walking the data
// tree on every heartbeat. The first call computes synchronously so the first
// heartbeat still reports a real value; later calls return the cached value
// and refresh it in the background once it is older than the refresh interval.
// A failed background refresh keeps the previous value and retries after the
// next interval.
func (a *Agent) cachedAllocatedBytes(compute func() (int64, error)) (int64, error) {
	interval := a.allocationRefreshInterval
	if interval <= 0 {
		return compute()
	}

	a.allocationMu.Lock()
	snapshot := a.allocation
	if !snapshot.valid {
		a.allocationMu.Unlock()
		size, err := compute()
		if err == nil {
			a.storeAllocation(size, time.Now())
		}
		return size, err
	}
	if time.Since(snapshot.computedAt) >= interval && !snapshot.refreshing {
		a.allocation.refreshing = true
		go a.refreshAllocation(compute)
	}
	a.allocationMu.Unlock()
	return snapshot.bytes, nil
}

func (a *Agent) refreshAllocation(compute func() (int64, error)) {
	size, err := compute()
	a.allocationMu.Lock()
	defer a.allocationMu.Unlock()
	a.allocation.refreshing = false
	if err != nil {
		// Keep the last good value; retry once another interval has passed.
		a.allocation.computedAt = time.Now()
		log.Printf("刷新节点数据占用失败，继续使用上次结果: %v", err)
		return
	}
	a.allocation.valid = true
	a.allocation.bytes = size
	a.allocation.computedAt = time.Now()
}

// storeAllocation records a size measured elsewhere (for example by the full
// activity scan used when the adapter is unavailable).
func (a *Agent) storeAllocation(size int64, at time.Time) {
	a.allocationMu.Lock()
	defer a.allocationMu.Unlock()
	a.allocation.valid = true
	a.allocation.bytes = size
	a.allocation.computedAt = at
}
