package store

import (
	"database/sql"
	"encoding/hex"
	"math"
	"time"
)

type NodeHeartbeatFacts struct {
	CPUPct                   float64
	MemPct                   float64
	DiskPct                  float64
	MetricsValid             bool
	DiskTotalBytes           int64
	DiskAvailableBytes       int64
	DiskQuotaBytes           int64
	AllocatedDiskBytes       int64
	OnlineUsers              int
	TaskQueueDepth           int
	TelemetrySource          string
	TavernVersion            string
	AgentVersion             string
	TransferURL              string
	CompatibilityState       string
	CompatibilityReasonCode  string
	CompatibilityFingerprint string
	RegistrationPolicy       NodeRegistrationPolicy
	ObservedAt               time.Time
}

type NodeCapacityPolicy struct {
	CPUBusyPct        float64
	MemBusyPct        float64
	DiskBusyPct       float64
	HardPct           float64
	Window            time.Duration
	Sustain           time.Duration
	Recovery          time.Duration
	Cooldown          time.Duration
	MinDiskFreeBytes  int64
	MaxOnlineUsers    int
	MaxTaskQueueDepth int
}

type nodeMetricWindow struct {
	CPUAvg, CPUPeak   float64
	MemAvg, MemPeak   float64
	DiskAvg, DiskPeak float64
}

type nodeCapacityCursor struct {
	State         string
	Reason        string
	PressureSince sql.NullTime
	RecoverySince sql.NullTime
	ChangedAt     time.Time
	CooldownUntil sql.NullTime
}

type nodeCapacityDecision struct {
	State         string
	Reason        string
	PressureSince sql.NullTime
	RecoverySince sql.NullTime
	ChangedAt     time.Time
	CooldownUntil sql.NullTime
}

func validNodeHeartbeatFacts(f NodeHeartbeatFacts) bool {
	if f.ObservedAt.IsZero() || f.OnlineUsers < 0 || f.TaskQueueDepth < 0 ||
		f.OnlineUsers > 1_000_000 || f.TaskQueueDepth > 1_000_000 ||
		len(f.AgentVersion) > 128 || len(f.TavernVersion) > 128 || len(f.TransferURL) > 2048 {
		return false
	}
	if f.MetricsValid && (!validPercent(f.CPUPct) || !validPercent(f.MemPct) || !validPercent(f.DiskPct) ||
		f.DiskTotalBytes <= 0 || f.DiskAvailableBytes < 0 || f.DiskAvailableBytes > f.DiskTotalBytes ||
		f.DiskQuotaBytes <= 0 || f.DiskQuotaBytes > f.DiskTotalBytes || f.AllocatedDiskBytes < 0) {
		return false
	}
	if f.TelemetrySource != "adapter" && f.TelemetrySource != "directory_fallback" &&
		f.TelemetrySource != "agent" && f.TelemetrySource != "unavailable" {
		return false
	}
	if f.CompatibilityState != "unknown" && f.CompatibilityState != "compatible" &&
		f.CompatibilityState != "incompatible" {
		return false
	}
	switch f.CompatibilityReasonCode {
	case "", "adapter_unavailable", "version_unsupported", "missing_capability", "invalid_health", "invalid_report":
	default:
		return false
	}
	if (f.CompatibilityState == "compatible" && f.CompatibilityReasonCode != "") ||
		(f.CompatibilityState != "compatible" && f.CompatibilityReasonCode == "") {
		return false
	}
	fingerprint, err := hex.DecodeString(f.CompatibilityFingerprint)
	return err == nil && len(fingerprint) == 32
}

func validNodeCapacityPolicy(p NodeCapacityPolicy) bool {
	return validPercent(p.CPUBusyPct) && validPercent(p.MemBusyPct) && validPercent(p.DiskBusyPct) &&
		validPercent(p.HardPct) && p.HardPct > p.CPUBusyPct && p.HardPct > p.MemBusyPct &&
		p.HardPct > p.DiskBusyPct && p.Window > 0 && p.Sustain > 0 && p.Recovery > 0 &&
		p.Cooldown > 0 && p.MinDiskFreeBytes > 0 && p.MaxOnlineUsers > 0 && p.MaxTaskQueueDepth > 0
}

func validPercent(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 100
}

func evaluateNodeCapacity(
	now time.Time,
	current nodeCapacityCursor,
	metrics NodeHeartbeatFacts,
	window nodeMetricWindow,
	policy NodeCapacityPolicy,
) nodeCapacityDecision {
	if !metrics.MetricsValid {
		return capacityDecision(current, "unknown", "metrics_unavailable", now,
			sql.NullTime{}, sql.NullTime{}, sql.NullTime{})
	}
	hardReason, immediate := nodeHardCapacityReason(metrics, window, policy)
	busyReason := nodeBusyCapacityReason(metrics, window, policy)
	pressureSince := current.PressureSince
	if hardReason == "" || immediate {
		pressureSince = sql.NullTime{}
	} else if !pressureSince.Valid {
		pressureSince = sql.NullTime{Time: now, Valid: true}
	}
	hardSustained := hardReason != "" && (immediate ||
		(pressureSince.Valid && !now.Before(pressureSince.Time.Add(policy.Sustain))))

	if current.State == "full" {
		if hardReason != "" || busyReason != "" {
			reason := current.Reason
			if hardSustained || immediate {
				reason = hardReason
			}
			if reason == "" {
				reason = busyReason
			}
			return capacityDecision(current, "full", reason, now, pressureSince,
				sql.NullTime{}, current.CooldownUntil)
		}
		recoverySince := current.RecoverySince
		if !recoverySince.Valid {
			recoverySince = sql.NullTime{Time: now, Valid: true}
		}
		cooledDown := !current.CooldownUntil.Valid || !now.Before(current.CooldownUntil.Time)
		if cooledDown && !now.Before(recoverySince.Time.Add(policy.Recovery)) {
			return capacityDecision(current, "open", "", now, sql.NullTime{}, sql.NullTime{}, sql.NullTime{})
		}
		return capacityDecision(current, "full", current.Reason, now, sql.NullTime{},
			recoverySince, current.CooldownUntil)
	}
	if hardSustained {
		return capacityDecision(current, "full", hardReason, now, pressureSince, sql.NullTime{},
			sql.NullTime{Time: now.Add(policy.Cooldown), Valid: true})
	}
	if hardReason != "" {
		return capacityDecision(current, "busy", hardReason, now, pressureSince, sql.NullTime{}, sql.NullTime{})
	}
	if busyReason != "" {
		return capacityDecision(current, "busy", busyReason, now, sql.NullTime{}, sql.NullTime{}, sql.NullTime{})
	}
	return capacityDecision(current, "open", "", now, sql.NullTime{}, sql.NullTime{}, sql.NullTime{})
}

func capacityDecision(
	current nodeCapacityCursor,
	state, reason string,
	now time.Time,
	pressureSince, recoverySince, cooldownUntil sql.NullTime,
) nodeCapacityDecision {
	changedAt := current.ChangedAt
	if changedAt.IsZero() || current.State != state {
		changedAt = now
	}
	return nodeCapacityDecision{
		State: state, Reason: reason, PressureSince: pressureSince,
		RecoverySince: recoverySince, ChangedAt: changedAt, CooldownUntil: cooldownUntil,
	}
}

func nodeHardCapacityReason(metrics NodeHeartbeatFacts, window nodeMetricWindow, policy NodeCapacityPolicy) (string, bool) {
	if metrics.DiskAvailableBytes < policy.MinDiskFreeBytes {
		return "disk_low_watermark", true
	}
	if metrics.DiskQuotaBytes-metrics.AllocatedDiskBytes < policy.MinDiskFreeBytes {
		return "quota_low_watermark", true
	}
	if metrics.OnlineUsers >= policy.MaxOnlineUsers {
		return "online_user_limit", true
	}
	if metrics.TaskQueueDepth >= policy.MaxTaskQueueDepth {
		return "task_queue_limit", true
	}
	if window.CPUAvg >= policy.HardPct {
		return "cpu_sustained", false
	}
	if window.MemAvg >= policy.HardPct {
		return "memory_sustained", false
	}
	if window.DiskAvg >= policy.HardPct {
		return "disk_sustained", false
	}
	return "", false
}

func nodeBusyCapacityReason(metrics NodeHeartbeatFacts, window nodeMetricWindow, policy NodeCapacityPolicy) string {
	if belowTwiceReserve(metrics.DiskAvailableBytes, policy.MinDiskFreeBytes) {
		return "disk_low"
	}
	if belowTwiceReserve(metrics.DiskQuotaBytes-metrics.AllocatedDiskBytes, policy.MinDiskFreeBytes) {
		return "quota_low"
	}
	if atLeastFourFifths(metrics.OnlineUsers, policy.MaxOnlineUsers) {
		return "online_users_busy"
	}
	if atLeastFourFifths(metrics.TaskQueueDepth, policy.MaxTaskQueueDepth) {
		return "task_queue_busy"
	}
	if window.CPUAvg >= policy.CPUBusyPct {
		return "cpu_busy"
	}
	if window.MemAvg >= policy.MemBusyPct {
		return "memory_busy"
	}
	if window.DiskAvg >= policy.DiskBusyPct {
		return "disk_busy"
	}
	return ""
}

func belowTwiceReserve(available, reserve int64) bool {
	return available < reserve || available-reserve < reserve
}

func atLeastFourFifths(value, limit int) bool {
	return value >= limit-limit/5
}
