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
			"connectivity_state", "compatibility_fingerprint", "compatibility_reported_at",
			"node_controller_generation", "active_controller_generation",
		}).AddRow("unknown", nil, nil, nil, now.Add(-time.Hour), nil, "unknown", nil, nil, int64(5), int64(5)))
	mock.ExpectExec(`INSERT INTO node_metric_samples`).WithArgs(
		int64(12), now, 10.0, 20.0, 30.0, int64(100<<30), 3, 2,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT COALESCE\(AVG\(cpu_avg_pct\),0\)`).WithArgs(int64(12), now.Add(-2*time.Minute)).
		WillReturnRows(sqlmock.NewRows([]string{
			"cpu_avg", "cpu_peak", "mem_avg", "mem_peak", "disk_avg", "disk_peak",
		}).AddRow(10.0, 10.0, 20.0, 20.0, 30.0, 30.0))
	mock.ExpectQuery(`SELECT id::text,state,reason_code,observed_fingerprint`).WithArgs(int64(12)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`(?s)UPDATE nodes SET cpu_pct=.*connectivity_state=CASE.*THEN 'online'.*capacity_state=\$21.*compatibility_state=\$27.*telemetry_source=\$34.*\$31>registration_policy_version.*version_reuse`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.UpdateNodeHeartbeat(context.Background(), 12, 5, facts, testNodeCapacityPolicy()); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestUpdateNodeHeartbeatIsIdempotentAndRejectsOlderReport(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 0, 5, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		observedAt time.Time
		wantErr    error
	}{
		{name: "duplicate", observedAt: now},
		{name: "older", observedAt: now.Add(-time.Second), wantErr: ErrStaleNodeHeartbeat},
	} {
		t.Run(test.name, func(t *testing.T) {
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			facts := testNodeHeartbeat(test.observedAt)
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT capacity_state,capacity_reason_code`).WithArgs(int64(12)).
				WillReturnRows(sqlmock.NewRows([]string{
					"capacity_state", "capacity_reason_code", "pressure_since", "recovery_since", "changed_at", "cooldown_until",
					"connectivity_state", "compatibility_fingerprint", "compatibility_reported_at",
					"node_controller_generation", "active_controller_generation",
				}).AddRow("open", nil, nil, nil, now.Add(-time.Hour), nil, "online", strings.Repeat("a", 64), now, int64(5), int64(5)))
			if test.wantErr == nil {
				mock.ExpectCommit()
			} else {
				mock.ExpectRollback()
			}
			err := st.UpdateNodeHeartbeat(context.Background(), 12, 5, facts, testNodeCapacityPolicy())
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("err=%v want=%v", err, test.wantErr)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestUpdateNodeHeartbeatRejectsNodeOutsideActiveGeneration(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 0, 6, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT capacity_state,capacity_reason_code`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{
			"capacity_state", "capacity_reason_code", "pressure_since", "recovery_since", "changed_at", "cooldown_until",
			"connectivity_state", "compatibility_fingerprint", "compatibility_reported_at",
			"node_controller_generation", "active_controller_generation",
		}).AddRow("unknown", nil, nil, nil, now.Add(-time.Hour), nil, "offline", nil, nil, int64(0), int64(6)))
	mock.ExpectRollback()
	err := st.UpdateNodeHeartbeat(context.Background(), 12, 5, testNodeHeartbeat(now), testNodeCapacityPolicy())
	if !errors.Is(err, ErrStaleControllerMode) {
		t.Fatalf("err=%v, want generation fence", err)
	}
	assertMockExpectations(t, mock)
}

func TestUpdateNodeRecoveryHeartbeatKeepsNodeOffline(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 0, 7, 0, 0, time.UTC)
	facts := testNodeHeartbeat(now)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT capacity_state,capacity_reason_code`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{
			"capacity_state", "capacity_reason_code", "pressure_since", "recovery_since", "changed_at", "cooldown_until",
			"connectivity_state", "compatibility_fingerprint", "compatibility_reported_at",
			"node_controller_generation", "active_controller_generation",
		}).AddRow("unknown", nil, nil, nil, now.Add(-time.Hour), nil, "offline", nil, nil, int64(0), int64(6)))
	mock.ExpectQuery(`(?s)SELECT EXISTS .*controller_rebuild_operations`).WithArgs(
		int64(6), int64(12), int64(5),
	).WillReturnRows(sqlmock.NewRows([]string{"allowed"}).AddRow(true))
	mock.ExpectExec(`INSERT INTO node_metric_samples`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT COALESCE\(AVG\(cpu_avg_pct\),0\)`).
		WillReturnRows(sqlmock.NewRows([]string{
			"cpu_avg", "cpu_peak", "mem_avg", "mem_peak", "disk_avg", "disk_peak",
		}).AddRow(10.0, 10.0, 20.0, 20.0, 30.0, 30.0))
	mock.ExpectQuery(`SELECT id::text,state,reason_code,observed_fingerprint`).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`(?s)UPDATE nodes SET.*status=CASE WHEN \$35::boolean THEN 'online' ELSE 'offline' END.*connectivity_state=CASE WHEN \$35::boolean THEN 'online' ELSE 'offline' END`).
		WithArgs(
			int64(12), 10.0, 20.0, 30.0, "tavern", "agent", "https://transfer.example", now,
			int64(20<<30), int64(100<<30), int64(200<<30), int64(180<<30), 3, 2,
			10.0, 10.0, 20.0, 20.0, 30.0, 30.0, "open", "", nil, nil, now, nil,
			"compatible", strings.Repeat("a", 64), "", "invitation_required", int64(9),
			now.Add(time.Minute), "", "directory_fallback", false,
		).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.UpdateNodeRecoveryHeartbeat(
		context.Background(), 12, 5, facts, testNodeCapacityPolicy(),
	); err != nil {
		t.Fatalf("UpdateNodeRecoveryHeartbeat: %v", err)
	}
	assertMockExpectations(t, mock)
}

func TestUpdateNodeHeartbeatRejectsInvalidFactsBeforeTransaction(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	facts := testNodeHeartbeat(time.Now().UTC())
	facts.DiskAvailableBytes = facts.DiskTotalBytes + 1
	if err := st.UpdateNodeHeartbeat(context.Background(), 12, 5, facts, testNodeCapacityPolicy()); err == nil {
		t.Fatal("invalid disk facts were accepted")
	}
	facts = testNodeHeartbeat(time.Now().UTC())
	facts.DiskQuotaBytes = facts.DiskTotalBytes + 1
	if err := st.UpdateNodeHeartbeat(context.Background(), 12, 5, facts, testNodeCapacityPolicy()); err == nil {
		t.Fatal("quota above the real filesystem total was accepted")
	}
	facts = testNodeHeartbeat(time.Now().UTC())
	facts.CompatibilityReasonCode = "missing_capability"
	if err := st.UpdateNodeHeartbeat(context.Background(), 12, 5, facts, testNodeCapacityPolicy()); err == nil {
		t.Fatal("compatible state with an error reason was accepted")
	}
	facts = testNodeHeartbeat(time.Now().UTC())
	facts.AgentVersion = strings.Repeat("x", 129)
	if err := st.UpdateNodeHeartbeat(context.Background(), 12, 5, facts, testNodeCapacityPolicy()); err == nil {
		t.Fatal("oversized version fact was accepted")
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
			"connectivity_state", "operational_state", "control_mode", "control_mode_generation",
			"desired_control_mode", "desired_mode_generation", "capacity_state", "capacity_reason_code",
			"capacity_changed_at", "capacity_cooldown_until", "compatibility_state", "compatibility_reason_code",
			"compatibility_fingerprint", "compatibility_reported_at", "metrics_observed_at",
			"cpu_window_avg", "cpu_window_peak", "mem_window_avg", "mem_window_peak",
			"disk_window_avg", "disk_window_peak", "disk_total_bytes", "disk_available_bytes",
			"disk_quota_bytes", "expected_disk_quota_bytes", "quota_policy_version", "quota_sync_state",
			"quota_sync_at", "quota_sync_error_code", "allocated_disk_bytes", "online_users", "task_queue_depth", "telemetry_source",
			"client_latency_ms", "client_latency_observed_at",
			"allow_register", "recommendation_weight", "is_backup_target", "registration_policy_state", "registration_policy_version",
			"registration_policy_expires_at", "registration_policy_observed_at", "registration_policy_error_code", "created_at",
		}).AddRow(
			int64(12), "node", "compute", "https://node.example", "", "hk",
			10.0, 20.0, 30.0, "agent", "tavern", now, "online",
			"online", "active", "managed", int64(4), "managed", int64(4),
			"busy", "cpu_busy", now, nil, "compatible", nil,
			strings.Repeat("a", 64), now, now, 51.0, 62.0, 20.0, 25.0, 30.0, 35.0,
			int64(200<<30), int64(100<<30), int64(180<<30), int64(0), int64(0), "synced", nil, nil,
			int64(20<<30), 3, 2, "directory_fallback", nil, nil,
			true, 0, false, "open", int64(4), now.Add(time.Minute), now, nil, now,
		))
	node, err := st.GetNodeByID(context.Background(), 12)
	if err != nil || node == nil || node.ConnectivityState != "online" ||
		node.OperationalState != "active" || node.CapacityState != "busy" ||
		node.CompatibilityState != "compatible" || node.ControlMode != "managed" ||
		node.DesiredModeGeneration != 4 || node.CPUWindowAvg.Float64 != 51 {
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
	mock.ExpectExec(`UPDATE nodes SET name=.*recommendation_weight=\$7 WHERE`).WithArgs(
		int64(12), "node", "https://node.example", node.Region, false, true, 0,
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
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE nodes SET status='offline',connectivity_state='offline',capacity_state='unknown'`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectQuery(`UPDATE controller_rebuild_nodes item`).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"rebuild_id"}))
	mock.ExpectCommit()
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

func TestStaleNodeDefersRebuildAndRecomputesReadinessAtomically(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	rebuildID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE nodes SET status='offline',connectivity_state='offline',capacity_state='unknown'`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)UPDATE controller_rebuild_nodes item.*COALESCE\(node.last_seen_at,rebuild.started_at\)<\$1.*RETURNING rebuild.id::text`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"rebuild_id"}).AddRow(rebuildID))
	mock.ExpectExec(`UPDATE controller_rebuild_nodes item`).WithArgs(rebuildID, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`(?s)count\(\*\).*FILTER`).WithArgs(rebuildID).
		WillReturnRows(sqlmock.NewRows([]string{"total", "reconciled", "ready"}).AddRow(2, 1, 2))
	mock.ExpectExec(`UPDATE controller_rebuild_operations SET total_nodes`).WithArgs(
		rebuildID, 2, 1, sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE controller_rebuild_operations\s+SET state=\$2`).WithArgs(
		rebuildID, "ready_with_deferred", sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.MarkStaleNodesOffline(context.Background(), time.Minute); err != nil {
		t.Fatalf("MarkStaleNodesOffline: %v", err)
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

func TestUpdateNodeStatusRejectsStaleGenerationOnlinePublication(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectExec(`(?s)UPDATE nodes SET status=\$2,connectivity_state=\$3.*\$2<>'online' OR controller_generation=\(.*controller_epochs.*state='active'`).
		WithArgs(int64(12), "online", "online").
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := st.UpdateNodeStatus(context.Background(), 12, "online"); !errors.Is(err, ErrStaleControllerMode) {
		t.Fatalf("UpdateNodeStatus error=%v, want ErrStaleControllerMode", err)
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
	mock.ExpectQuery(`SELECT node_id,to_state,reason_code`).WithArgs(p.OperationID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectQuery(`SELECT operational_state,control_mode,desired_control_mode`).WithArgs(p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"operational_state", "control_mode", "desired_control_mode"}).
			AddRow("maintenance", "managed", "managed"))
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec(`UPDATE nodes SET operational_state`).WithArgs(p.NodeID, p.ToState).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE agent_credentials`).WithArgs(p.NodeID, now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE agent_credential_rotations`).WithArgs(p.NodeID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM enrollment_tokens`).WithArgs(p.NodeID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE agent_commands`).WithArgs(p.NodeID, now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE admin_node_links`).WithArgs(p.NodeID, now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE control_tickets`).WithArgs(p.NodeID, now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE tickets`).WithArgs(p.NodeID, now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE snapshot_transfer_capabilities`).WithArgs(p.NodeID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO node_lifecycle_events`).WithArgs(
		p.OperationID, p.NodeID, "maintenance", p.ToState, p.ReasonCode, p.AdminID, int64(7), now,
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
	mock.ExpectQuery(`SELECT node_id,to_state,reason_code`).WithArgs(p.OperationID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectQuery(`SELECT operational_state,control_mode,desired_control_mode`).WithArgs(p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"operational_state", "control_mode", "desired_control_mode"}).
			AddRow("maintenance", "managed", "managed"))
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
	mock.ExpectQuery(`SELECT node_id,to_state,reason_code`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"node_id", "to_state", "reason_code", "actor_admin_id"}).
			AddRow(p.NodeID, "draining", p.ReasonCode, p.AdminID))
	mock.ExpectCommit()
	state, err := st.TransitionNodeLifecycle(context.Background(), p)
	if err != nil || state != "draining" {
		t.Fatalf("state=%q err=%v", state, err)
	}

	p.OperationID = "44444444-4444-4444-8444-444444444444"
	p.ToState = "retired"
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT node_id,to_state,reason_code`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"node_id", "to_state", "reason_code", "actor_admin_id"}).
			AddRow(p.NodeID, "draining", "different_reason", p.AdminID))
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
	mock.ExpectQuery(`SELECT node_id,to_state,reason_code`).WithArgs(p.OperationID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectQuery(`SELECT operational_state,control_mode,desired_control_mode`).WithArgs(p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"operational_state", "control_mode", "desired_control_mode"}).
			AddRow("active", "managed", "managed"))
	mock.ExpectRollback()
	_, err := st.TransitionNodeLifecycle(context.Background(), p)
	if !errors.Is(err, ErrNodeLifecycleBlocked) {
		t.Fatalf("error=%v", err)
	}
	assertMockExpectations(t, mock)
}

func TestTransitionNodeLifecycleRejectsFreeTextReasonAndIndependentRetirement(t *testing.T) {
	t.Parallel()
	if ValidMachineReasonCode("operator retired") || ValidMachineReasonCode("UPPER_CASE") ||
		ValidMachineReasonCode(strings.Repeat("a", 65)) || !ValidMachineReasonCode("operator_retired_2") {
		t.Fatal("machine reason code validation mismatch")
	}
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	if _, err := st.TransitionNodeLifecycle(context.Background(), TransitionNodeLifecycleParams{
		OperationID: "66666666-6666-4666-8666-666666666666", NodeID: 12,
		ToState: "draining", ReasonCode: "human readable", AdminID: 5,
	}); !errors.Is(err, ErrNodeLifecycleBlocked) {
		t.Fatalf("free-text reason error=%v", err)
	}
	p := TransitionNodeLifecycleParams{
		OperationID: "77777777-7777-4777-8777-777777777777", NodeID: 12,
		ToState: "retired", ReasonCode: "operator_retired", AdminID: 5,
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT node_id,to_state,reason_code`).WithArgs(p.OperationID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectQuery(`SELECT operational_state,control_mode,desired_control_mode`).WithArgs(p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"operational_state", "control_mode", "desired_control_mode"}).
			AddRow("maintenance", "independent-draining", "managed"))
	mock.ExpectRollback()
	if _, err := st.TransitionNodeLifecycle(context.Background(), p); !errors.Is(err, ErrNodeLifecycleBlocked) {
		t.Fatalf("independent retirement error=%v", err)
	}
	assertMockExpectations(t, mock)
}

func TestTransitionNodeLifecycleCreatesDurableDrainOperationAndItems(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 5, 30, 0, 0, time.UTC)
	p := TransitionNodeLifecycleParams{
		OperationID: "88888888-8888-4888-8888-888888888888",
		NodeID:      12, ToState: "draining", ReasonCode: "operator_draining", AdminID: 5, Now: now,
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT node_id,to_state,reason_code`).WithArgs(p.OperationID).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectQuery(`SELECT operational_state,control_mode,desired_control_mode`).WithArgs(p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"operational_state", "control_mode", "desired_control_mode"}).
			AddRow("active", "managed", "managed"))
	mock.ExpectExec(`UPDATE nodes SET operational_state`).WithArgs(p.NodeID, p.ToState).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`INSERT INTO node_retirement_operations`).WithArgs(
		p.OperationID, p.NodeID, p.AdminID, p.ReasonCode, int64(7), now,
	).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("99999999-9999-4999-8999-999999999999"))
	mock.ExpectExec(`WITH node_role AS`).WithArgs(
		"99999999-9999-4999-8999-999999999999", p.NodeID, now,
	).WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(`UPDATE node_retirement_operations operation SET state`).WithArgs(
		"99999999-9999-4999-8999-999999999999", now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO node_lifecycle_events`).WithArgs(
		p.OperationID, p.NodeID, "active", p.ToState, p.ReasonCode, p.AdminID, int64(7), now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	state, err := st.TransitionNodeLifecycle(context.Background(), p)
	if err != nil || state != "draining" {
		t.Fatalf("state=%q err=%v", state, err)
	}
	assertMockExpectations(t, mock)
}
func TestUpdateNodeExpectedQuotaBumpsVersionOnceAndIsIdempotent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)

	// 1) change from 0 to 200GB bumps version to 1 and marks pending
	st, mock, closeDB := newMockStore(t)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT expected_disk_quota_bytes FROM nodes WHERE id=\$1 FOR UPDATE`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{"expected_disk_quota_bytes"}).AddRow(int64(0)))
	mock.ExpectExec(`UPDATE nodes SET expected_disk_quota_bytes=\$2,.*quota_policy_version=quota_policy_version\+1,.*quota_sync_state=CASE WHEN \$2=0 THEN 'synced' ELSE 'pending' END,.*quota_sync_at=\$3, quota_sync_error_code=NULL`).
		WithArgs(int64(12), int64(200<<30), now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.UpdateNodeExpectedQuota(context.Background(), 12, 200<<30, now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
	closeDB()

	// 2) same value again is a no-op (no version bump)
	st, mock, closeDB = newMockStore(t)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT expected_disk_quota_bytes FROM nodes WHERE id=\$1 FOR UPDATE`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{"expected_disk_quota_bytes"}).AddRow(int64(200 << 30)))
	mock.ExpectCommit()
	if err := st.UpdateNodeExpectedQuota(context.Background(), 12, 200<<30, now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
	closeDB()

	// 3) back to 0 (inherit agent.yaml) marks synced
	st, mock, closeDB = newMockStore(t)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT expected_disk_quota_bytes FROM nodes WHERE id=\$1 FOR UPDATE`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{"expected_disk_quota_bytes"}).AddRow(int64(200 << 30)))
	mock.ExpectExec(`UPDATE nodes SET expected_disk_quota_bytes=\$2,.*quota_sync_state=CASE WHEN \$2=0 THEN 'synced' ELSE 'pending' END,.*quota_sync_at=\$3, quota_sync_error_code=NULL`).
		WithArgs(int64(12), int64(0), now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.UpdateNodeExpectedQuota(context.Background(), 12, 0, now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
	closeDB()

	// 4) invalid inputs rejected
	st, mock, closeDB = newMockStore(t)
	if err := st.UpdateNodeExpectedQuota(context.Background(), 0, 1<<30, now); err == nil {
		t.Fatal("zero node id was accepted")
	}
	if err := st.UpdateNodeExpectedQuota(context.Background(), 12, -1, now); err == nil {
		t.Fatal("negative quota was accepted")
	}
	closeDB()
}
func TestRecordNodeClientLatencySmoothsAndValidates(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 14, 1, 0, 0, 0, time.UTC)
	mock.ExpectExec(`(?s)UPDATE nodes SET.*client_latency_ms=CASE.*client_latency_observed_at=\$3.*WHERE id=\$1`).
		WithArgs(int64(12), int64(150), now).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.RecordNodeClientLatency(context.Background(), 12, 150, now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
	closeDB()

	// Invalid samples are rejected before touching the database.
	st2, _, closeDB2 := newMockStore(t)
	defer closeDB2()
	if err := st2.RecordNodeClientLatency(context.Background(), 0, 150, now); err == nil {
		t.Fatal("zero node id accepted")
	}
	if err := st2.RecordNodeClientLatency(context.Background(), 12, -1, now); err == nil {
		t.Fatal("negative latency accepted")
	}
	if err := st2.RecordNodeClientLatency(context.Background(), 12, 4_000_000, now); err == nil {
		t.Fatal("oversized latency accepted")
	}
}
