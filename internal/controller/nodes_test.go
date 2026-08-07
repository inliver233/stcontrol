package controller

import (
	"database/sql"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func TestNodeRegistrableRequiresFreshNodeOwnedPolicy(t *testing.T) {
	t.Parallel()
	server := &Server{Cfg: &config.ControllerConfig{Node: config.NodePolicy{
		RegisterCPU: 50, RegisterMem: 50, RegisterDisk: 50,
	}}}
	node := &store.Node{
		Role: "compute", ConnectivityState: "online", OperationalState: "active",
		CapacityState: "open", CompatibilityState: "compatible", AllowRegister: true,
		RegistrationPolicyState: "open", RegistrationPolicyVersion: 4,
		RegistrationPolicyExpiresAt: sql.NullTime{Time: time.Now().UTC().Add(time.Minute), Valid: true},
	}
	if !server.nodeRegistrable(node) {
		t.Fatal("fresh open policy was rejected")
	}
	node.CapacityState = "busy"
	if !server.nodeRegistrable(node) {
		t.Fatal("busy node was not retained as a lower-ranked allocation option")
	}
	node.CapacityState = "full"
	if server.nodeRegistrable(node) {
		t.Fatal("durably full node was accepted")
	}
	node.CapacityState = "open"
	node.RegistrationPolicyState = "error"
	if server.nodeRegistrable(node) {
		t.Fatal("policy read error was accepted")
	}
	node.RegistrationPolicyState = "invitation_required"
	node.RegistrationPolicyExpiresAt.Time = time.Now().UTC().Add(-time.Second)
	if server.nodeRegistrable(node) {
		t.Fatal("expired invitation policy was accepted")
	}
}

func TestAvailableNodeRankPrefersOpenOverBusy(t *testing.T) {
	t.Parallel()
	open := availableNode{Registrable: true, capacityState: "open"}
	busy := availableNode{Registrable: true, capacityState: "busy"}
	closed := availableNode{}
	if availableNodeRank(open) >= availableNodeRank(busy) || availableNodeRank(busy) >= availableNodeRank(closed) {
		t.Fatalf("ranks open=%d busy=%d closed=%d", availableNodeRank(open), availableNodeRank(busy), availableNodeRank(closed))
	}
}

func TestNormalizeRegistrationPolicyRejectsInvalidFreshnessAndDiagnostics(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	fact := normalizeRegistrationPolicy(protocol.RegistrationPolicyReport{
		State: "open", Version: 3, ExpiresAt: now.Add(time.Minute),
	}, now)
	if fact.State != "open" || fact.Version != 3 || fact.ErrorCode != "" {
		t.Fatalf("valid fact=%+v", fact)
	}
	fact = normalizeRegistrationPolicy(protocol.RegistrationPolicyReport{
		State: "open", Version: 3, ExpiresAt: now.Add(11 * time.Minute), ErrorCode: "sensitive detail",
	}, now)
	if fact.State != "error" || fact.ErrorCode != "invalid_policy_report" || !fact.ExpiresAt.Equal(now) {
		t.Fatalf("invalid fact=%+v", fact)
	}
}

func TestNodeStatusLabelsUseOnlyProductHealthStates(t *testing.T) {
	t.Parallel()
	server := &Server{}
	node := &store.Node{
		Role: "compute", ConnectivityState: "online", OperationalState: "active",
		CapacityState: "open", CompatibilityState: "compatible", AllowRegister: true,
		RegistrationPolicyState:     "open",
		RegistrationPolicyExpiresAt: sql.NullTime{Time: time.Now().UTC().Add(time.Minute), Valid: true},
	}
	if label := server.nodeStatusLabel(node); label != "开放" {
		t.Fatalf("label=%q", label)
	}
	node.CapacityState = "busy"
	if label := server.nodeStatusLabel(node); label != "繁忙" {
		t.Fatalf("label=%q", label)
	}
	node.CapacityState = "full"
	if label := server.nodeStatusLabel(node); label != "满载" {
		t.Fatalf("label=%q", label)
	}
	node.ConnectivityState = "offline"
	if label := server.nodeStatusLabel(node); label != "故障" {
		t.Fatalf("label=%q", label)
	}
}

func TestAvailableNodeModelDoesNotExposeInternalLoadOrReasonCodes(t *testing.T) {
	t.Parallel()
	encoded, err := json.Marshal(availableNode{
		ID: 12, Name: "node", StatusLabel: "繁忙", Registrable: true,
		Recommended: true, capacityState: "busy",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"cpu", "mem", "disk", "reason", "capacityState"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("public node leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestNormalizeHeartbeatFactsFailsClosedOnInvalidMetricsAndCompatibility(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 1, 30, 0, 0, time.UTC)
	facts := normalizeHeartbeatFacts(protocol.HeartbeatRequest{
		CPUPct: math.NaN(), MemPct: 20, DiskPct: 30, MetricsValid: true,
		DiskTotalBytes: 100, DiskAvailableBytes: 50, DiskQuotaBytes: 100,
		TelemetrySource: "invented", Compatibility: protocol.NodeCompatibilityReport{
			State: "compatible", Fingerprint: "not-a-digest", ErrorCode: "private diagnostic",
		},
	}, "", store.NodeRegistrationPolicy{State: "error", ObservedAt: now}, now)
	if facts.MetricsValid || facts.TelemetrySource != "unavailable" ||
		facts.CompatibilityState != "unknown" || facts.CompatibilityReasonCode != "invalid_report" ||
		len(facts.CompatibilityFingerprint) != 64 {
		t.Fatalf("facts=%+v", facts)
	}
}

func TestNormalizeHeartbeatFactsRejectsQuotaAboveFilesystem(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	facts := normalizeHeartbeatFacts(protocol.HeartbeatRequest{
		CPUPct: 10, MemPct: 20, DiskPct: 30, MetricsValid: true,
		DiskTotalBytes: 100, DiskAvailableBytes: 50, DiskQuotaBytes: 101,
		TelemetrySource: "agent", Compatibility: protocol.NodeCompatibilityReport{
			State: "compatible", Fingerprint: strings.Repeat("a", 64),
		},
	}, "", store.NodeRegistrationPolicy{State: "error", ObservedAt: now}, now)
	if facts.MetricsValid {
		t.Fatal("quota above real filesystem total was accepted")
	}
}

func TestNormalizeHeartbeatFactsRejectsInconsistentCompatibility(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	facts := normalizeHeartbeatFacts(protocol.HeartbeatRequest{
		Compatibility: protocol.NodeCompatibilityReport{
			State: "compatible", Fingerprint: strings.Repeat("a", 64), ErrorCode: "missing_capability",
		},
	}, "", store.NodeRegistrationPolicy{State: "error", ObservedAt: now}, now)
	if facts.CompatibilityState != "unknown" || facts.CompatibilityReasonCode != "invalid_report" {
		t.Fatalf("facts=%+v", facts)
	}
}

func TestNodeCapacityPolicyFallsBackFromUnsafeThresholds(t *testing.T) {
	t.Parallel()
	server := &Server{Cfg: &config.ControllerConfig{Node: config.NodePolicy{
		RegisterCPU: 80, RegisterMem: 80, RegisterDisk: 80, AllocationHardPct: 60,
	}}}
	policy := server.nodeCapacityPolicy()
	if policy.CPUBusyPct != 50 || policy.HardPct != 60 || policy.MinDiskFreeBytes <= 0 ||
		policy.Window <= 0 || policy.MaxOnlineUsers <= 0 {
		t.Fatalf("policy=%+v", policy)
	}
}
