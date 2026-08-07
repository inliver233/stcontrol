package store

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func restoreWorkflowParams(now time.Time) CreateRestoreWorkflowParams {
	return CreateRestoreWorkflowParams{
		OperationID:        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		RequestDigest:      bytes.Repeat([]byte{1}, 32),
		WorkflowID:         "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		RestoreSnapshotID:  "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		CapabilityID:       "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		CapabilityHash:     bytes.Repeat([]byte{2}, 32),
		GlobalUserID:       70,
		TargetNodeID:       9,
		ExpectedRecoveryAt: now.Add(-2 * time.Hour),
		CapabilityExpires:  now.Add(15 * time.Minute),
		Now:                now,
	}
}

func TestListRestoreTargetsOnlyReturnsEligibleComputeNodes(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`(?s)FROM user_protection_states protection.*node.capacity_state IN \('open','busy'\).*protection.state='restore_required'.*copy.state='conflict'`).
		WithArgs(int64(70), 50).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "region"}).
			AddRow(int64(9), "compute-b", "hk"))
	targets, err := st.ListRestoreTargets(context.Background(), 70, 0)
	if err != nil || len(targets) != 1 || targets[0].NodeID != 9 {
		t.Fatalf("targets=%+v err=%v", targets, err)
	}
	assertMockExpectations(t, mock)
}

func TestCreateRestoreWorkflowPersistsAcknowledgedFactsBeforeTransfer(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 14, 0, 0, 0, time.UTC)
	p := restoreWorkflowParams(now)
	sourceManifest := bytes.Repeat([]byte{3}, 32)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.GlobalUserID))
	mock.ExpectQuery(`FROM restore_operations operation`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"request_digest"}))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
	mock.ExpectQuery(`SELECT user_id, writer_node_id`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery(`(?s)FROM global_users global_user.*protection.state='restore_required'.*protection.latest_recovery_at=\$2`).
		WithArgs(p.GlobalUserID, p.ExpectedRecoveryAt).
		WillReturnRows(sqlmock.NewRows([]string{
			"legacy_user_id", "username", "display_name", "home_node_id", "source_node_id", "source_snapshot_id",
			"published_at", "manifest_sha256", "activity_epoch",
		}).AddRow(int64(7), "alice", "Alice", int64(8), int64(10),
			"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", p.ExpectedRecoveryAt, sourceManifest, int64(5)))
	mock.ExpectQuery(`(?s)SELECT node.id FROM nodes node.*node.capacity_state IN \('open','busy'\).*node_accounts account`).
		WithArgs(p.GlobalUserID, p.TargetNodeID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.TargetNodeID))
	mock.ExpectExec(`INSERT INTO workflows`).WithArgs(
		p.WorkflowID, p.OperationID, p.GlobalUserID, int64(10), p.TargetNodeID, int64(5), int64(4), now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT status FROM node_accounts`).WithArgs(p.GlobalUserID, p.TargetNodeID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}))
	mock.ExpectQuery(`(?s)SELECT password_hash,password_salt,password_material_version.*FROM node_accounts`).
		WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"password_hash", "password_salt", "version"}).
			AddRow("node-hash", "node-salt", int64(3)))
	mock.ExpectExec(`INSERT INTO node_accounts`).WithArgs(
		p.GlobalUserID, p.TargetNodeID, "alice", int64(3), "node-hash", "node-salt", `{}`, p.WorkflowID, now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO snapshot_manifests`).WithArgs(
		p.RestoreSnapshotID, p.WorkflowID, p.GlobalUserID, int64(10), int64(5), make([]byte, 32), now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO snapshot_transfer_capabilities`).WithArgs(
		p.CapabilityID, p.WorkflowID, p.RestoreSnapshotID, int64(10), p.TargetNodeID,
		p.CapabilityHash, int64(4), p.CapabilityExpires, now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	for _, step := range []string{"provision_account", "prepare_target", "transfer", "verify", "publish"} {
		mock.ExpectExec(`INSERT INTO workflow_steps`).WithArgs(p.WorkflowID, step, "pending", now).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectQuery(`INSERT INTO restore_operations`).WithArgs(
		p.OperationID, p.RequestDigest, p.WorkflowID, p.GlobalUserID, int64(10), p.TargetNodeID,
		"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", p.RestoreSnapshotID, p.ExpectedRecoveryAt, now,
	).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(12)))
	mock.ExpectExec(`INSERT INTO user_replicas`).WithArgs(int64(7), p.TargetNodeID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		p.GlobalUserID, p.OperationID, int64(4), p.RequestDigest, int64(10), p.TargetNodeID,
		"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", p.ExpectedRecoveryAt,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	execution, err := st.CreateRestoreWorkflow(context.Background(), p)
	if err != nil || execution.JobID != 12 || execution.SourceNodeID != 10 ||
		execution.TargetNodeID != 9 || !bytes.Equal(execution.SourceManifestSHA256, sourceManifest) {
		t.Fatalf("execution=%+v err=%v", execution, err)
	}
	assertMockExpectations(t, mock)
}

func TestCreateRestoreWorkflowReplaysOnlyExactRequest(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 14, 30, 0, 0, time.UTC)
	p := restoreWorkflowParams(now)
	sourceManifest := bytes.Repeat([]byte{3}, 32)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.GlobalUserID))
	mock.ExpectQuery(`(?s)FROM restore_operations operation.*JOIN LATERAL`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{
			"request_digest", "user_id", "target_node_id", "id", "workflow_id", "state", "attempt",
			"legacy_user_id", "username", "display_name", "source_node_id", "source_snapshot_id", "restore_snapshot_id",
			"manifest_sha256", "source_published_at", "activity_epoch", "controller_generation",
			"capability_id", "token_hash", "expires_at", "capability_state",
			"account_status", "local_user_id", "account_version", "password_hash", "password_salt",
			"oauth_provider", "oauth_subject",
		}).AddRow(p.RequestDigest, p.GlobalUserID, p.TargetNodeID, int64(12), p.WorkflowID, "transferring", 1,
			int64(7), "alice", "Alice", int64(10), "source-snapshot", p.RestoreSnapshotID,
			sourceManifest, p.ExpectedRecoveryAt, int64(5), int64(4), p.CapabilityID,
			p.CapabilityHash, p.CapabilityExpires, "prepared", "pending", "", int64(2),
			"node-hash", "node-salt", "", ""))
	mock.ExpectCommit()

	execution, err := st.CreateRestoreWorkflow(context.Background(), p)
	if err != nil || execution.Handle != "alice" || execution.CapabilityID != p.CapabilityID ||
		!bytes.Equal(execution.SourceManifestSHA256, sourceManifest) {
		t.Fatalf("execution=%+v err=%v", execution, err)
	}
	assertMockExpectations(t, mock)
}

func TestCreateRestoreWorkflowRejectsConcurrentSnapshotMutation(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := restoreWorkflowParams(time.Now().UTC())
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.GlobalUserID))
	mock.ExpectQuery(`FROM restore_operations operation`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"request_digest"}))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
	mock.ExpectQuery(`SELECT user_id, writer_node_id`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectRollback()
	_, err := st.CreateRestoreWorkflow(context.Background(), p)
	if err != ErrRestoreConflict {
		t.Fatalf("error=%v", err)
	}
	assertMockExpectations(t, mock)
}

func TestGetRestoreWorkflowExecutionReturnsAccountAndSnapshotFacts(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 14, 40, 0, 0, time.UTC)
	digest := bytes.Repeat([]byte{3}, 32)
	mock.ExpectQuery(`(?s)FROM restore_operations operation.*JOIN node_accounts target_account`).
		WithArgs("workflow").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "operation_id", "workflow_id", "state", "attempt", "user_id", "legacy_user_id",
			"username", "display_name", "source_node_id", "target_node_id", "source_snapshot_id",
			"restore_snapshot_id", "manifest_sha256", "source_published_at", "activity_epoch",
			"generation", "capability_id", "token_hash", "expires_at", "capability_state",
			"account_status", "local_user_id", "account_version", "password_hash", "password_salt",
			"oauth_provider", "oauth_subject",
		}).AddRow(int64(12), "operation", "workflow", "scheduled", 0, int64(70), int64(7),
			"alice", "Alice", int64(10), int64(9), "source", "restore", digest, now.Add(-time.Hour),
			int64(5), int64(4), "capability", bytes.Repeat([]byte{2}, 32), now.Add(time.Minute),
			"prepared", "pending", "", int64(3), "node-hash", "node-salt", "", ""))
	execution, err := st.GetRestoreWorkflowExecution(context.Background(), "workflow")
	if err != nil || execution == nil || execution.AccountVersion != 3 ||
		execution.PasswordHash != "node-hash" || !bytes.Equal(execution.SourceManifestSHA256, digest) {
		t.Fatalf("execution=%+v err=%v", execution, err)
	}
	assertMockExpectations(t, mock)
}

func TestCompleteRestoreWorkflowAtomicallyPromotesVerifiedTarget(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 15, 0, 0, 0, time.UTC)
	p := CompleteRestoreWorkflowParams{
		WorkflowID: "workflow", RestoreSnapshotID: "restore-snapshot",
		CapabilityHash: bytes.Repeat([]byte{2}, 32), ManifestSHA256: bytes.Repeat([]byte{4}, 32),
		ArchiveSHA256: bytes.Repeat([]byte{5}, 32), FileCount: 3, TotalBytes: 120, Now: now,
	}
	sourcePublished := now.Add(-2 * time.Hour)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT workflow.state,global_user.status,legacy.status.*FROM workflows workflow`).
		WithArgs(p.WorkflowID, p.RestoreSnapshotID).
		WillReturnRows(sqlmock.NewRows([]string{
			"state", "global_status", "legacy_status", "operation_id", "user_id", "legacy_user_id",
			"source_node_id", "target_node_id", "home_node_id", "generation", "source_snapshot_id", "published_at",
		}).AddRow("publishing", "active", "active", "operation", int64(70), int64(7), int64(10), int64(9),
			int64(8), int64(4), "source-snapshot", sourcePublished))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
	mock.ExpectQuery(`(?s)SELECT copy.snapshot_id::text FROM replica_copies copy.*copy.published_at=\$4`).
		WithArgs(int64(70), int64(10), "source-snapshot", sourcePublished).
		WillReturnRows(sqlmock.NewRows([]string{"snapshot_id"}).AddRow("source-snapshot"))
	mock.ExpectQuery(`(?s)SELECT account.id FROM node_accounts account.*account.status='active'`).
		WithArgs(int64(70), int64(9)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(22)))
	mock.ExpectExec(`UPDATE snapshot_manifests`).WithArgs(
		p.RestoreSnapshotID, p.WorkflowID, p.ManifestSHA256, p.ArchiveSHA256, p.FileCount, p.TotalBytes,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT COALESCE\(MAX\(data_version\),0\)\+1`).WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"data_version"}).AddRow(int64(6)))
	mock.ExpectExec(`UPDATE user_replicas SET kind='hot_standby'`).WithArgs(int64(7), int64(8)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE user_replicas SET kind='home'`).WithArgs(
		int64(7), int64(9), int64(6), fmt.Sprintf("%x", p.ManifestSHA256), p.TotalBytes, now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE users SET home_node_id`).WithArgs(int64(7), int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE replica_copies SET is_authoritative=false`).WithArgs(int64(70), int64(8), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO replica_copies`).WithArgs(int64(70), int64(9), p.RestoreSnapshotID, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE node_accounts`).WithArgs(int64(70), int64(9), now, int64(8)).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`UPDATE user_activity_leases`).WithArgs(int64(70), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE control_tickets`).WithArgs(int64(70), now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`UPDATE snapshot_transfer_capabilities`).WithArgs(p.WorkflowID, now, p.CapabilityHash).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflows SET state='succeeded'`).WithArgs(p.WorkflowID, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='succeeded'`).WithArgs(p.WorkflowID, now).
		WillReturnResult(sqlmock.NewResult(0, 5))
	mock.ExpectExec(`UPDATE restore_operations SET completed_at`).WithArgs(p.WorkflowID, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO user_protection_states`).WithArgs(int64(70), int64(9), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		int64(70), "operation", int64(4), int64(10), int64(9), "source-snapshot",
		sourcePublished, p.RestoreSnapshotID, p.WorkflowID,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := st.CompleteRestoreWorkflow(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestCompleteRestoreAccountProvisionActivatesExactVersion(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 14, 45, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT workflow.user_id,workflow.target_node_id,workflow.state.*FROM workflows workflow`).
		WithArgs("workflow").
		WillReturnRows(sqlmock.NewRows([]string{
			"user_id", "target_node_id", "workflow_state", "account_status", "account_version", "local_user_id",
		}).AddRow(int64(70), int64(9), "scheduled", "pending", int64(3), nil))
	mock.ExpectExec(`UPDATE node_accounts SET status='active'`).WithArgs(
		int64(70), int64(9), int64(3), "local-alice", now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='succeeded'`).WithArgs("workflow", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.CompleteRestoreAccountProvision(
		context.Background(), "workflow", 3, "local-alice", now,
	); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestFailRestoreWorkflowLeavesNoLoginEligiblePartialReplica(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 15, 30, 0, 0, time.UTC)
	digest := bytes.Repeat([]byte{1}, 32)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT workflow.state,operation.operation_id::text.*FROM workflows workflow`).
		WithArgs("workflow").
		WillReturnRows(sqlmock.NewRows([]string{
			"state", "operation_id", "user_id", "legacy_user_id", "target_node_id", "generation", "digest",
		}).AddRow("transferring", "operation", int64(70), int64(7), int64(9), int64(4), digest))
	mock.ExpectExec(`UPDATE workflows SET state='failed'`).WithArgs(
		"workflow", "restore_failed", "恢复未完成", now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='failed'`).WithArgs("workflow", "restore_failed", now).
		WillReturnResult(sqlmock.NewResult(0, 4))
	mock.ExpectExec(`UPDATE snapshot_transfer_capabilities SET state='revoked'`).WithArgs("workflow").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE snapshot_manifests SET state='invalid'`).WithArgs("workflow").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE user_replicas SET state='error'`).WithArgs(int64(7), int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE node_accounts SET status='error'`).WithArgs(int64(70), int64(9), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE restore_operations SET completed_at`).WithArgs("workflow", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		int64(70), "operation", int64(4), digest, int64(9), "restore_failed",
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.FailRestoreWorkflow(
		context.Background(), "workflow", "restore_failed", "恢复未完成", now,
	); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestRestoreWorkflowSchedulingAndStatusUsePublicOperationIdentity(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 16, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT id::text FROM workflows WHERE workflow_type='restore'`).WithArgs(100).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("workflow"))
	ids, err := st.ListResumableRestoreWorkflowIDs(context.Background(), 0)
	if err != nil || len(ids) != 1 || ids[0] != "workflow" {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
	mock.ExpectExec(`UPDATE workflows workflow SET lease_owner`).WithArgs("workflow", "worker", now, now.Add(time.Minute)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	claimed, err := st.ClaimRestoreWorkflow(context.Background(), "workflow", "worker", now, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("claimed=%v err=%v", claimed, err)
	}
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE workflows workflow SET state='transferring'`).WithArgs("workflow", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='pending'`).WithArgs("workflow", now).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectCommit()
	if err := st.ResetRestoreTransferForRetry(context.Background(), "workflow", now); err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`(?s)FROM restore_operations operation.*WHERE operation.user_id=\$1`).
		WithArgs(int64(70), "operation").
		WillReturnRows(sqlmock.NewRows([]string{
			"operation_id", "state", "target_node_id", "target_name", "source_published_at", "error_summary",
		}).AddRow("operation", "transferring", int64(9), "compute-b", now.Add(-time.Hour), nil))
	status, err := st.GetRestoreOperationStatus(context.Background(), 70, "operation")
	if err != nil || status == nil || status.State != "transferring" || status.TargetNodeName != "compute-b" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	assertMockExpectations(t, mock)
}
