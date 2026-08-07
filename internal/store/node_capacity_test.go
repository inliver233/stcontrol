package store

import (
	"database/sql"
	"math"
	"testing"
	"time"
)

func healthyCapacityFacts(now time.Time) NodeHeartbeatFacts {
	return NodeHeartbeatFacts{
		CPUPct: 20, MemPct: 30, DiskPct: 25, MetricsValid: true,
		DiskTotalBytes: 200 << 30, DiskAvailableBytes: 100 << 30,
		DiskQuotaBytes: 180 << 30, AllocatedDiskBytes: 20 << 30,
		ObservedAt: now,
	}
}

func TestEvaluateNodeCapacityUsesBusyAndSustainedHardThresholds(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 1, 0, 0, 0, time.UTC)
	policy := testNodeCapacityPolicy()
	facts := healthyCapacityFacts(now)
	current := nodeCapacityCursor{State: "open", ChangedAt: now.Add(-time.Hour)}

	decision := evaluateNodeCapacity(now, current, facts, nodeMetricWindow{CPUAvg: 55}, policy)
	if decision.State != "busy" || decision.Reason != "cpu_busy" {
		t.Fatalf("busy decision=%+v", decision)
	}
	decision = evaluateNodeCapacity(now, current, facts, nodeMetricWindow{CPUAvg: 65}, policy)
	if decision.State != "busy" || decision.Reason != "cpu_sustained" || !decision.PressureSince.Valid {
		t.Fatalf("initial pressure decision=%+v", decision)
	}
	current.PressureSince = sql.NullTime{Time: now.Add(-policy.Sustain), Valid: true}
	decision = evaluateNodeCapacity(now, current, facts, nodeMetricWindow{CPUAvg: 65}, policy)
	if decision.State != "full" || decision.Reason != "cpu_sustained" || !decision.CooldownUntil.Valid {
		t.Fatalf("sustained pressure decision=%+v", decision)
	}
}

func TestEvaluateNodeCapacityDiskAndQuotaWatermarksCloseImmediately(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 1, 5, 0, 0, time.UTC)
	policy := testNodeCapacityPolicy()
	current := nodeCapacityCursor{State: "open", ChangedAt: now.Add(-time.Hour)}
	facts := healthyCapacityFacts(now)
	facts.DiskAvailableBytes = policy.MinDiskFreeBytes - 1
	decision := evaluateNodeCapacity(now, current, facts, nodeMetricWindow{}, policy)
	if decision.State != "full" || decision.Reason != "disk_low_watermark" {
		t.Fatalf("disk decision=%+v", decision)
	}
	facts = healthyCapacityFacts(now)
	facts.AllocatedDiskBytes = facts.DiskQuotaBytes - policy.MinDiskFreeBytes + 1
	decision = evaluateNodeCapacity(now, current, facts, nodeMetricWindow{}, policy)
	if decision.State != "full" || decision.Reason != "quota_low_watermark" {
		t.Fatalf("quota decision=%+v", decision)
	}
}

func TestEvaluateNodeCapacityUserAndQueueLimitsCloseImmediately(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 1, 7, 0, 0, time.UTC)
	policy := testNodeCapacityPolicy()
	current := nodeCapacityCursor{State: "open", ChangedAt: now.Add(-time.Hour)}
	facts := healthyCapacityFacts(now)
	facts.OnlineUsers = policy.MaxOnlineUsers
	decision := evaluateNodeCapacity(now, current, facts, nodeMetricWindow{}, policy)
	if decision.State != "full" || decision.Reason != "online_user_limit" {
		t.Fatalf("user decision=%+v", decision)
	}
	facts = healthyCapacityFacts(now)
	facts.TaskQueueDepth = policy.MaxTaskQueueDepth
	decision = evaluateNodeCapacity(now, current, facts, nodeMetricWindow{}, policy)
	if decision.State != "full" || decision.Reason != "task_queue_limit" {
		t.Fatalf("queue decision=%+v", decision)
	}
}

func TestBusyThresholdChecksDoNotOverflowLargePolicies(t *testing.T) {
	t.Parallel()
	policy := testNodeCapacityPolicy()
	policy.MinDiskFreeBytes = math.MaxInt64/2 + 1
	policy.MaxOnlineUsers = math.MaxInt
	policy.MaxTaskQueueDepth = math.MaxInt
	facts := healthyCapacityFacts(time.Now().UTC())
	facts.DiskTotalBytes = math.MaxInt64
	facts.DiskAvailableBytes = math.MaxInt64
	facts.DiskQuotaBytes = math.MaxInt64
	facts.AllocatedDiskBytes = 0
	if reason := nodeBusyCapacityReason(facts, nodeMetricWindow{}, policy); reason != "disk_low" {
		t.Fatalf("reason=%q", reason)
	}
	if !atLeastFourFifths(math.MaxInt, math.MaxInt) {
		t.Fatal("large integer busy threshold overflowed")
	}
}

func TestEvaluateNodeCapacityRecoveryRequiresLowWatermarkAndCooldown(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 1, 10, 0, 0, time.UTC)
	policy := testNodeCapacityPolicy()
	facts := healthyCapacityFacts(now)
	current := nodeCapacityCursor{
		State: "full", Reason: "cpu_sustained", ChangedAt: now.Add(-time.Hour),
		RecoverySince: sql.NullTime{Time: now.Add(-policy.Recovery), Valid: true},
		CooldownUntil: sql.NullTime{Time: now.Add(time.Minute), Valid: true},
	}
	decision := evaluateNodeCapacity(now, current, facts, nodeMetricWindow{CPUAvg: 20}, policy)
	if decision.State != "full" {
		t.Fatalf("cooldown was bypassed: %+v", decision)
	}
	current.CooldownUntil = sql.NullTime{Time: now.Add(-time.Second), Valid: true}
	decision = evaluateNodeCapacity(now, current, facts, nodeMetricWindow{CPUAvg: 20}, policy)
	if decision.State != "open" || decision.Reason != "" || decision.CooldownUntil.Valid {
		t.Fatalf("recovered decision=%+v", decision)
	}
}

func TestEvaluateNodeCapacityFailsClosedWithoutMetrics(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	facts := healthyCapacityFacts(now)
	facts.MetricsValid = false
	decision := evaluateNodeCapacity(now, nodeCapacityCursor{State: "open"}, facts, nodeMetricWindow{}, testNodeCapacityPolicy())
	if decision.State != "unknown" || decision.Reason != "metrics_unavailable" {
		t.Fatalf("decision=%+v", decision)
	}
}
