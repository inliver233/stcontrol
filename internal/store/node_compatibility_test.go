package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func compatibilityFacts(now time.Time, state, reason, fingerprint string) NodeHeartbeatFacts {
	return NodeHeartbeatFacts{
		ObservedAt: now, CompatibilityState: state, CompatibilityReasonCode: reason,
		CompatibilityFingerprint: fingerprint, AgentVersion: "agent-v2", TavernVersion: "tavern-v2",
	}
}

func TestDecideNodeCompatibilityIncidentInitialAndUpgradeIsolation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 1, 0, 0, 0, time.UTC)
	fingerprintA := strings.Repeat("a", 64)
	fingerprintB := strings.Repeat("b", 64)

	initial := decideNodeCompatibilityIncident(nodeCompatibilityCursor{},
		compatibilityFacts(now, "compatible", "", fingerprintA))
	if initial.Action != "" || initial.EffectiveState != "compatible" {
		t.Fatalf("initial compatible report was isolated: %+v", initial)
	}

	changed := decideNodeCompatibilityIncident(nodeCompatibilityCursor{
		HasHistory: true, ConnectivityState: "online", Fingerprint: fingerprintA,
	}, compatibilityFacts(now, "compatible", "", fingerprintB))
	if changed.Action != "open" || changed.IncidentState != "verifying" ||
		changed.IncidentReason != "fingerprint_changed" || changed.CompatibleObservations != 1 ||
		changed.EffectiveState != "unknown" || changed.EffectiveReasonCode != "upgrade_verifying" {
		t.Fatalf("fingerprint change decision=%+v", changed)
	}

	reconnected := decideNodeCompatibilityIncident(nodeCompatibilityCursor{
		HasHistory: true, ConnectivityState: "offline", Fingerprint: fingerprintA,
	}, compatibilityFacts(now, "compatible", "", fingerprintA))
	if reconnected.Action != "open" || reconnected.IncidentReason != "node_reconnected" ||
		reconnected.EffectiveState != "unknown" {
		t.Fatalf("reconnect decision=%+v", reconnected)
	}

	incompatible := decideNodeCompatibilityIncident(nodeCompatibilityCursor{},
		compatibilityFacts(now, "incompatible", "missing_capability", fingerprintA))
	if incompatible.Action != "open" || incompatible.IncidentState != "isolated" ||
		incompatible.EffectiveState != "incompatible" || !incompatible.Notify {
		t.Fatalf("incompatible decision=%+v", incompatible)
	}
}

func TestDecideNodeCompatibilityIncidentRequiresDistinctStableObservations(t *testing.T) {
	t.Parallel()
	started := time.Date(2026, 8, 9, 2, 0, 0, 0, time.UTC)
	fingerprintA := strings.Repeat("a", 64)
	fingerprintB := strings.Repeat("b", 64)

	begin := decideNodeCompatibilityIncident(nodeCompatibilityCursor{
		IncidentID: "incident", IncidentState: "isolated", IncidentReason: "missing_capability",
		IncidentFingerprint: fingerprintA, IncidentLastSeenAt: started.Add(-time.Second),
	}, compatibilityFacts(started, "compatible", "", fingerprintA))
	if begin.Action != "update" || begin.IncidentState != "verifying" ||
		begin.CompatibleObservations != 1 || !begin.VerificationStartedAt.Valid {
		t.Fatalf("verification start=%+v", begin)
	}

	cursor := nodeCompatibilityCursor{
		IncidentID: "incident", IncidentState: "verifying", IncidentReason: "missing_capability",
		IncidentFingerprint: fingerprintA, CompatibleObservations: 1,
		VerificationStartedAt: sql.NullTime{Time: started, Valid: true}, IncidentLastSeenAt: started,
	}
	duplicate := decideNodeCompatibilityIncident(cursor,
		compatibilityFacts(started, "compatible", "", fingerprintA))
	if duplicate.Action != "" || duplicate.CompatibleObservations != 0 || duplicate.EffectiveState != "unknown" {
		t.Fatalf("duplicate observation advanced verification: %+v", duplicate)
	}

	secondAt := started.Add(15 * time.Second)
	second := decideNodeCompatibilityIncident(cursor,
		compatibilityFacts(secondAt, "compatible", "", fingerprintA))
	if second.Action != "update" || second.CompatibleObservations != 2 || second.EffectiveState != "unknown" {
		t.Fatalf("second observation=%+v", second)
	}
	cursor.CompatibleObservations = second.CompatibleObservations
	cursor.IncidentLastSeenAt = secondAt
	resolved := decideNodeCompatibilityIncident(cursor,
		compatibilityFacts(started.Add(30*time.Second), "compatible", "", fingerprintA))
	if resolved.Action != "resolve" || resolved.CompatibleObservations != 3 ||
		resolved.EffectiveState != "compatible" || resolved.EffectiveReasonCode != "" {
		t.Fatalf("stable verification did not resolve: %+v", resolved)
	}

	reset := decideNodeCompatibilityIncident(cursor,
		compatibilityFacts(started.Add(31*time.Second), "compatible", "", fingerprintB))
	if reset.Action != "update" || reset.CompatibleObservations != 1 ||
		reset.IncidentFingerprint != fingerprintB || reset.EffectiveState != "unknown" {
		t.Fatalf("changed verification fingerprint did not reset: %+v", reset)
	}

	isolated := decideNodeCompatibilityIncident(cursor,
		compatibilityFacts(started.Add(31*time.Second), "incompatible", "version_unsupported", fingerprintA))
	if isolated.Action != "update" || isolated.IncidentState != "isolated" ||
		isolated.CompatibleObservations != 0 || isolated.EffectiveState != "incompatible" {
		t.Fatalf("incompatible verification report did not isolate: %+v", isolated)
	}
}

func TestGetNodeCompatibilityIncidentStatus(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 3, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT state,reason_code,compatible_observations`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{
			"state", "reason_code", "compatible_observations", "observed_agent_version",
			"observed_tavern_version", "first_seen_at", "last_seen_at", "resolved_at",
		}).AddRow("verifying", "node_reconnected", 2, "agent-v2", "tavern-v2", now, now.Add(time.Second), nil))
	status, err := st.GetNodeCompatibilityIncidentStatus(context.Background(), 12)
	if err != nil || status == nil || status.State != "verifying" ||
		status.CompatibleObservations != 2 || status.RequiredObservations != 3 || status.ResolvedAt != nil {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if _, err := st.GetNodeCompatibilityIncidentStatus(context.Background(), 0); !errors.Is(err, ErrNodeCompatibilityState) {
		t.Fatalf("invalid node id error=%v", err)
	}
	assertMockExpectations(t, mock)
}
