package agent

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestCachedAllocatedBytesAvoidsWalkingOnEveryHeartbeat(t *testing.T) {
	a := &Agent{allocationRefreshInterval: time.Hour}
	var calls atomic.Int32
	compute := func() (int64, error) {
		calls.Add(1)
		return 100 * int64(calls.Load()), nil
	}

	if size, err := a.cachedAllocatedBytes(compute); err != nil || size != 100 {
		t.Fatalf("first call must compute synchronously: size=%d err=%v", size, err)
	}
	for range 5 {
		if size, err := a.cachedAllocatedBytes(compute); err != nil || size != 100 {
			t.Fatalf("fresh cache must be reused: size=%d err=%v", size, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("fresh cache walked the data tree %d times", calls.Load())
	}
}

func TestCachedAllocatedBytesRefreshesStaleValueInBackgroundOnce(t *testing.T) {
	a := &Agent{allocationRefreshInterval: time.Minute}
	a.storeAllocation(100, time.Now().Add(-2*time.Minute))
	release := make(chan struct{})
	var calls atomic.Int32
	compute := func() (int64, error) {
		calls.Add(1)
		<-release
		return 200, nil
	}

	for range 3 {
		if size, err := a.cachedAllocatedBytes(compute); err != nil || size != 100 {
			t.Fatalf("stale value must be served while refreshing: size=%d err=%v", size, err)
		}
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.allocationMu.Lock()
		done := !a.allocation.refreshing && a.allocation.bytes == 200
		a.allocationMu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background refresh did not complete")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent heartbeats started %d refreshes", calls.Load())
	}
	if size, _ := a.cachedAllocatedBytes(compute); size != 200 {
		t.Fatalf("refreshed value not used: %d", size)
	}
}

func TestCachedAllocatedBytesKeepsLastValueWhenRefreshFails(t *testing.T) {
	a := &Agent{allocationRefreshInterval: time.Minute}
	a.storeAllocation(100, time.Now().Add(-2*time.Minute))
	done := make(chan struct{})
	a.cachedAllocatedBytes(func() (int64, error) {
		defer close(done)
		return 0, errors.New("walk failed")
	})
	<-done
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.allocationMu.Lock()
		refreshing := a.allocation.refreshing
		a.allocationMu.Unlock()
		if !refreshing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed refresh never finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
	size, err := a.cachedAllocatedBytes(func() (int64, error) {
		t.Fatal("a failed refresh must wait for the next interval before retrying")
		return 0, nil
	})
	if err != nil || size != 100 {
		t.Fatalf("last good value must be kept: size=%d err=%v", size, err)
	}
}

func TestCachedAllocatedBytesFirstFailureIsReported(t *testing.T) {
	a := &Agent{allocationRefreshInterval: time.Minute}
	if _, err := a.cachedAllocatedBytes(func() (int64, error) { return 0, errors.New("boom") }); err == nil {
		t.Fatal("the first synchronous failure must be reported")
	}
	if size, err := a.cachedAllocatedBytes(func() (int64, error) { return 7, nil }); err != nil || size != 7 {
		t.Fatalf("a failed first measurement must not be cached: size=%d err=%v", size, err)
	}
}

func TestCachedAllocatedBytesWithoutIntervalAlwaysComputes(t *testing.T) {
	a := &Agent{}
	var calls atomic.Int32
	for range 3 {
		a.cachedAllocatedBytes(func() (int64, error) { calls.Add(1); return 1, nil })
	}
	if calls.Load() != 3 {
		t.Fatalf("zero interval must keep the original per-heartbeat behavior, got %d walks", calls.Load())
	}
}
