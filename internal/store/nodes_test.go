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

func testNodeCapacityPolicy() NodeCapacityPolicy {
	return NodeCapacityPolicy{
		CPUBusyPct: 50, MemBusyPct: 50, DiskBusyPct: 50, HardPct: 60,
		Window: 2 * time.Minute, Sustain: 2 * time.Minute,
		Recovery: 3 * time.Minute, Cooldown: 5 * time.Minute,
		MinDiskFreeBytes: 5 << 30, MaxOnlineUsers: 500, MaxTaskQueueDepth: 50,
	}
}

func testNodeHeartbeat(now time.Time) NodeHeartbeatFacts {
	return NodeHeartbeatFacts{
		CPUPct: 10, MemPct: 20, DiskPct: 30, MetricsValid: true,
		DiskTotalBytes: 200 << 30, DiskAvailableBytes: 100 << 30,
		DiskQuotaBytes: 180 << 30, AllocatedDiskBytes: 20 << 30,
		OnlineUsers: 3, TaskQueueDepth: 2, TelemetrySource: "directory_fallback",
		TavernVersion: "tavern", AgentVersion: "agent", TransferURL: "https://transfer.example",
		CompatibilityState: "compatible", CompatibilityFingerprint: strings.Repeat("a", 64),
		RegistrationPolicy: NodeRegistrationPolicy{
			State: "invitation_required", Version: 9, ExpiresAt: now.Add(time.Minute),
			ObservedAt: now,
		},
		ObservedAt: now,
	}
}

func TestCreateNodeGeneratesRequiredDurableUUID(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Now().UTC()
	node := &Node{Name: "node", Role: "compute", Status: "pending", AllowRegister: true}
	mock.ExpectQuery(`INSERT INTO nodes \(uuid,name`).WithArgs(
		"node", "compute", "", "", node.Region, "pending", true, false,
	).WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(int64(12), now))
	if err := st.CreateNode(context.Background(), node); err != nil || node.ID != 12 {
		t.Fatalf("node=%+v err=%v", node, err)
	}
	assertMockExpectations(t, mock)
}

func TestUpdateNodeHeartbeatStoresWindowedHealthAndVersionedPolicy(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 0, 5, 0, 0, time.UTC)
	facts := testNodeHeartbeat(now)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT capacity_state,capacity_reason_code`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{
			"capacity_state", "capacity_reason_code", "pressure_since", "recovery_since", "changed_at", "cooldown_until",
		}).AddRow("unknown", nil, nil, nil, now.Add(-time.Hour), nil))
	mock.ExpectExec(`INSERT INTO node_metric_samples`).WithArgs(
		int64(12), now, 10.0, 20.0, 30.0, int64(100<<30), 3, 2,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT COALESCE\(AVG\(cpu_avg_pct\),0\)`).WithArgs(int64(12), now.Add(-2*time.Minute)).
		WillReturnRows(sqlmock.NewRows([]string{
			"cpu_avg", "cpu_peak", "mem_avg", "mem_peak", "disk_avg", "disk_peak",
		}).AddRow(10.0, 10.0, 20.0, 20.0, 30.0, 30.0))
	mock.ExpectExec(`(?s)UPDATE nodes SET cpu_pct=.*connectivity_state='online'.*capacity_state=\$21.*compatibility_state=\$27.*telemetry_source=\$34.*\$31>registration_policy_version.*version_reuse`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.UpdateNodeHeartbeat(context.Background(), 12, facts, testNodeCapacityPolicy()); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestUpdateNodeHeartbeatRejectsInvalidFactsBeforeTransaction(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	facts := testNodeHeartbeat(time.Now().UTC())
	facts.DiskAvailableBytes = facts.DiskTotalBytes + 1
	if err := st.UpdateNodeHeartbeat(context.Background(), 12, facts, testNodeCapacityPolicy()); err == nil {
		t.Fatal("invalid disk facts were accepted")
	}
	facts = testNodeHeartbeat(time.Now().UTC())
	facts.DiskQuotaBytes = facts.DiskTotalBytes + 1
	if err := st.UpdateNodeHeartbeat(context.Background(), 12, facts, testNodeCapacityPolicy()); err == nil {
		t.Fatal("quota above the real filesystem total was accepted")
	}
	facts = testNodeHeartbeat(time.Now().UTC())
	facts.CompatibilityReasonCode = "missing_capability"
	if err := st.UpdateNodeHeartbeat(context.Background(), 12, facts, testNodeCapacityPolicy()); err == nil {
		t.Fatal("compatible state with an error reason was accepted")
	}
	assertMockExpectations(t, mock)
}

func TestGetNodeByIDReadsIndependentHealthDimensions(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 0, 10, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT .*connectivity_state.*capacity_state.*telemetry_source.* FROM nodes`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "role", "base_url", "transfer_url", "region",
			"cpu_pct", "mem_pct", "disk_pct", "agent_version", "tavern_version", "last_seen_at", "status",
			"connectivity_state", "operational_state", "capacity_state", "capacity_reason_code",
			"capacity_changed_at", "capacity_cooldown_until", "compatibility_state", "compatibility_reason_code",
			"compatibility_fingerprint", "compatibility_reported_at", "metrics_observed_at",
			"cpu_window_avg", "cpu_window_peak", "mem_window_avg", "mem_window_peak",
			"disk_window_avg", "disk_window_peak", "disk_total_bytes", "disk_available_bytes",
			"disk_quota_bytes", "allocated_disk_bytes", "online_users", "task_queue_depth", "telemetry_source",
			"allow_register", "is_backup_target", "registration_policy_state", "registration_policy_version",
			"registration_policy_expires_at", "registration_policy_observed_at", "registration_policy_error_code", "created_at",
		}).AddRow(
			int64(12), "node", "compute", "https://node.example", "", "hk",
			10.0, 20.0, 30.0, "agent", "tavern", now, "online",
			"online", "active", "busy", "cpu_busy", now, nil, "compatible", nil,
			strings.Repeat("a", 64), now, now, 51.0, 62.0, 20.0, 25.0, 30.0, 35.0,
			int64(200<<30), int64(100<<30), int64(180<<30), int64(20<<30), 3, 2, "directory_fallback",
			true, false, "open", int64(4), now.Add(time.Minute), now, nil, now,
		))
	node, err := st.GetNodeByID(context.Background(), 12)
	if err != nil || node == nil || node.ConnectivityState != "online" ||
		node.OperationalState != "active" || node.CapacityState != "busy" ||
		node.CompatibilityState != "compatible" || node.CPUWindowAvg.Float64 != 51 {
		t.Fatalf("node=%+v err=%v", node, err)
	}
	assertMockExpectations(t, mock)
}

func TestUpdateNodeSettingsPreservesAgentOwnedTransferURL(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	node := &Node{
		ID: 12, Name: "node", BaseURL: "https://node.example", Role: "compute",
		OperationalState: "maintenance", AllowRegister: false, IsBackupTarget: true,
	}
	mock.ExpectExec(`UPDATE nodes SET name=.*is_backup_target=\$6 WHERE`).WithArgs(
		int64(12), "node", "https://node.example", node.Region, false, true,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.UpdateNodeSettings(context.Background(), node); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestStaleNodeAndMetricRetentionUpdateDurableHealth(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectExec(`UPDATE nodes SET status='offline',connectivity_state='offline',capacity_state='unknown'`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 2))
	if err := st.MarkStaleNodesOffline(context.Background(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkStaleNodesOffline(context.Background(), 0); err == nil {
		t.Fatal("zero heartbeat timeout was accepted")
	}
	before := time.Now().UTC().Add(-24 * time.Hour)
	mock.ExpectExec(`DELETE FROM node_metric_samples`).WithArgs(before).
		WillReturnResult(sqlmock.NewResult(0, 8))
	removed, err := st.CleanupNodeMetricSamples(context.Background(), before)
	if err != nil || removed != 8 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	if _, err := st.CleanupNodeMetricSamples(context.Background(), time.Time{}); err == nil {
		t.Fatal("zero retention boundary was accepted")
	}
	assertMockExpectations(t, mock)
}

func TestUpdateNodeStatusKeepsConnectivityDimensionConsistent(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectExec(`UPDATE nodes SET status=\$2,connectivity_state=\$3`).WithArgs(
		int64(12), "offline", "offline",
	).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.UpdateNodeStatus(context.Background(), 12, "offline"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateNodeStatus(context.Background(), 0, "invented"); err == nil {
		t.Fatal("invalid node status was accepted")
	}
	assertMockExpectations(t, mock)
}

func TestTransitionNodeLifecycleRetiresOnlyUnreferencedNode(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 5, 0, 0, 0, time.UTC)
	p := TransitionNodeLifecycleParams{
		OperationID: "11111111-1111-4111-8111-111111111111",
		NodeID:      12, ToState: "retired", ReasonCode: "operator_retired",
		AdminID: 5, Now: now,
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT to_state FROM node_lifecycle_events`).WithArgs(p.OperationID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT operational_state FROM nodes`).WithArgs(p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"operational_state"}).AddRow("maintenance"))
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec(`UPDATE nodes SET operational_state`).WithArgs(p.NodeID, p.ToState).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE agent_credentials.*DELETE FROM enrollment_tokens.*UPDATE agent_commands`).
		WithArgs(p.NodeID, now).WillReturnResult(sqlmock.NewResult(0, 4))
	mock.ExpectExec(`INSERT INTO node_lifecycle_events`).WithArgs(
		p.OperationID, p.NodeID, "maintenance", p.ToState, p.ReasonCode, p.AdminID, now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	state, err := st.TransitionNodeLifecycle(context.Background(), p)
	if err != nil || state != "retired" {
		t.Fatalf("state=%q err=%v", state, err)
	}
	assertMockExpectations(t, mock)
}

func TestTransitionNodeLifecycleBlocksRetirementWithDependencies(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := TransitionNodeLifecycleParams{
		OperationID: "22222222-2222-4222-8222-222222222222",
		NodeID:      12, ToState: "retired", ReasonCode: "operator_retired", AdminID: 5,
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT to_state FROM node_lifecycle_events`).WithArgs(p.OperationID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT operational_state FROM nodes`).WithArgs(p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"operational_state"}).AddRow("draining"))
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectRollback()
	state, err := st.TransitionNodeLifecycle(context.Background(), p)
	if state != "" || !errors.Is(err, ErrNodeLifecycleBlocked) {
		t.Fatalf("state=%q err=%v", state, err)
	}
	assertMockExpectations(t, mock)
}

func TestTransitionNodeLifecycleReplaysOnlyMatchingOperation(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := TransitionNodeLifecycleParams{
		OperationID: "33333333-3333-4333-8333-333333333333",
		NodeID:      12, ToState: "draining", ReasonCode: "operator_draining", AdminID: 5,
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT to_state FROM node_lifecycle_events`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"to_state"}).AddRow("draining"))
	mock.ExpectCommit()
	state, err := st.TransitionNodeLifecycle(context.Background(), p)
	if err != nil || state != "draining" {
		t.Fatalf("state=%q err=%v", state, err)
	}

	p.OperationID = "44444444-4444-4444-8444-444444444444"
	p.ToState = "retired"
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT to_state FROM node_lifecycle_events`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"to_state"}).AddRow("draining"))
	mock.ExpectRollback()
	state, err = st.TransitionNodeLifecycle(context.Background(), p)
	if state != "" || !errors.Is(err, ErrNodeLifecycleBlocked) {
		t.Fatalf("state=%q err=%v", state, err)
	}
	assertMockExpectations(t, mock)
}

func TestTransitionNodeLifecycleRejectsInvalidTransitionBeforeMutation(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := TransitionNodeLifecycleParams{
		OperationID: "55555555-5555-4555-8555-555555555555",
		NodeID:      12, ToState: "retired", ReasonCode: "skip_drain", AdminID: 5,
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT to_state FROM node_lifecycle_events`).WithArgs(p.OperationID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT operational_state FROM nodes`).WithArgs(p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"operational_state"}).AddRow("active"))
	mock.ExpectRollback()
	_, err := st.TransitionNodeLifecycle(context.Background(), p)
	if !errors.Is(err, ErrNodeLifecycleBlocked) {
		t.Fatalf("error=%v", err)
	}
	assertMockExpectations(t, mock)
}
