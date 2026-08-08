package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func snapshotWorkflowParams(now time.Time) CreateSnapshotWorkflowParams {
	return CreateSnapshotWorkflowParams{
		WorkflowID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		SnapshotID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", CapabilityID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		CapabilityHash: make([]byte, 32), LegacyBackupJobID: 6, LegacyUserID: 7, GlobalUserID: 70,
		SourceNodeID: 8, TargetNodeID: 9, DestinationKind: "archive",
		CapabilityExpires: now.Add(15 * time.Minute), Now: now,
	}
}

func TestCreateSnapshotWorkflowPersistsFactsBeforeMutation(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 21, 0, 0, 0, time.UTC)
	p := snapshotWorkflowParams(now)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(3)))
	mock.ExpectQuery(`SELECT activity_epoch, writer_node_id, lease_expires_at`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"activity_epoch", "writer_node_id", "lease_expires_at", "in_flight_reads", "in_flight_writes", "state"}))
	mock.ExpectExec(`INSERT INTO workflows`).
		WithArgs(p.WorkflowID, p.OperationID, int64(70), int64(8), int64(9), int64(1), int64(3), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	for _, step := range []string{"quiesce", "snapshot", "prepare_target", "transfer", "verify", "publish", "cleanup"} {
		mock.ExpectExec(`INSERT INTO workflow_steps`).WithArgs(p.WorkflowID, step, "pending", now).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectExec(`INSERT INTO snapshot_manifests`).
		WithArgs(p.SnapshotID, p.WorkflowID, int64(70), int64(8), int64(1), make([]byte, 32), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO snapshot_transfer_capabilities`).
		WithArgs(p.CapabilityID, p.WorkflowID, p.SnapshotID, int64(8), int64(9), p.CapabilityHash, int64(3), p.CapabilityExpires, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE backup_jobs SET workflow_id`).
		WithArgs(int64(6), p.WorkflowID, p.SnapshotID, int64(1), int64(7), int64(8), int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO user_replicas`).
		WithArgs(int64(7), int64(9), "archive").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	workflow, err := st.CreateSnapshotWorkflow(context.Background(), p)
	if err != nil || workflow.ActivityEpoch != 1 || workflow.ControllerGeneration != 3 {
		t.Fatalf("workflow=%+v err=%v", workflow, err)
	}
	assertMockExpectations(t, mock)
}

func TestCreateSnapshotWorkflowRejectsLiveWriter(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 21, 0, 0, 0, time.UTC)
	p := snapshotWorkflowParams(now)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(3)))
	mock.ExpectQuery(`SELECT activity_epoch, writer_node_id, lease_expires_at`).
		WillReturnRows(sqlmock.NewRows([]string{"activity_epoch", "writer_node_id", "lease_expires_at", "in_flight_reads", "in_flight_writes", "state"}).
			AddRow(int64(4), int64(8), now.Add(time.Minute), int64(0), int64(0), "active"))
	mock.ExpectRollback()
	_, err := st.CreateSnapshotWorkflow(context.Background(), p)
	if !errors.Is(err, ErrSnapshotUserActive) {
		t.Fatalf("error=%v, want ErrSnapshotUserActive", err)
	}
	assertMockExpectations(t, mock)
}

func TestSnapshotProgressRequiresExactActorAndTransition(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 21, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT workflow.state`).WithArgs("workflow", "snapshot").
		WillReturnRows(sqlmock.NewRows([]string{"state", "source_node_id", "target_node_id", "controller_generation"}).
			AddRow("quiescing", int64(8), int64(9), int64(3)))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(3)))
	mock.ExpectExec(`UPDATE workflows SET state`).WithArgs("workflow", "drained", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflow_steps`).WithArgs("workflow", "quiesce", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.SetSnapshotWorkflowProgress(context.Background(), "workflow", "snapshot", 8, "drained", now); err != nil {
		t.Fatal(err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT workflow.state`).WithArgs("workflow", "snapshot").
		WillReturnRows(sqlmock.NewRows([]string{"state", "source_node_id", "target_node_id", "controller_generation"}).
			AddRow("transferring", int64(8), int64(9), int64(3)))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(3)))
	mock.ExpectRollback()
	err := st.SetSnapshotWorkflowProgress(context.Background(), "workflow", "snapshot", 8, "verifying", now)
	if !errors.Is(err, ErrSnapshotStateConflict) {
		t.Fatalf("error=%v, want transition conflict", err)
	}
	assertMockExpectations(t, mock)
}

func TestCompleteSnapshotWorkflowPublishesFactsAfterVerification(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 21, 0, 0, 0, time.UTC)
	p := CompleteSnapshotWorkflowParams{
		WorkflowID: "workflow", SnapshotID: "snapshot", CapabilityHash: make([]byte, 32),
		TargetNodeID: 9, ReplicaKind: "archive", ReplicaOrigin: "configured", ManifestSHA256: make([]byte, 32),
		ArchiveSHA256: make([]byte, 32), FileCount: 2, TotalBytes: 30, Now: now,
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT workflow.user_id, global_user.legacy_user_id`).WithArgs("workflow").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "legacy_user_id", "controller_generation", "state"}).
			AddRow(int64(70), int64(7), int64(3), "publishing"))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(3)))
	mock.ExpectExec(`UPDATE snapshot_manifests`).
		WithArgs("snapshot", "workflow", p.ManifestSHA256, p.ArchiveSHA256, int64(2), int64(30)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT snapshot_id FROM replica_copies`).WithArgs(int64(70), int64(9)).
		WillReturnRows(sqlmock.NewRows([]string{"snapshot_id"}))
	mock.ExpectQuery(`SELECT COALESCE\(MAX\(data_version\),0\)\+1`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"data_version"}).AddRow(int64(5)))
	mock.ExpectExec(`INSERT INTO replica_copies`).
		WithArgs(int64(70), int64(9), "snapshot", "archive", "configured", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE alerts SET state='resolved'`).
		WithArgs(int64(70), int64(9), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE replica_copies SET state='stale'`).
		WithArgs(int64(70), int64(9), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE user_replicas SET state='stale'`).
		WithArgs(int64(7), int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE snapshot_transfer_capabilities`).
		WithArgs("workflow", now, p.CapabilityHash).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE backup_jobs SET status='done'`).
		WithArgs("workflow", int64(5), int64(30), int64(2), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE user_replicas SET state='ready'`).
		WithArgs(int64(7), int64(9), int64(5), strings.Repeat("0", 64), int64(30), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflows SET state='succeeded'`).WithArgs("workflow", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='succeeded'`).WithArgs("workflow", now).
		WillReturnResult(sqlmock.NewResult(0, 7))
	mock.ExpectCommit()
	version, err := st.CompleteSnapshotWorkflow(context.Background(), p)
	if err != nil || version != 5 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	assertMockExpectations(t, mock)
}

func TestCompleteSnapshotWorkflowReplaysCommittedResult(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := CompleteSnapshotWorkflowParams{
		WorkflowID: "workflow", SnapshotID: "snapshot", CapabilityHash: make([]byte, 32),
		TargetNodeID: 9, ReplicaKind: "archive", ReplicaOrigin: "configured", ManifestSHA256: make([]byte, 32),
		ArchiveSHA256: make([]byte, 32),
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT workflow.user_id, global_user.legacy_user_id`).WithArgs("workflow").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "legacy_user_id", "controller_generation", "state"}).
			AddRow(int64(70), int64(7), int64(3), "succeeded"))
	mock.ExpectQuery(`SELECT data_version FROM backup_jobs`).WithArgs("workflow").
		WillReturnRows(sqlmock.NewRows([]string{"data_version"}).AddRow(int64(5)))
	mock.ExpectCommit()
	version, err := st.CompleteSnapshotWorkflow(context.Background(), p)
	if err != nil || version != 5 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	assertMockExpectations(t, mock)
}

func TestGetSnapshotWorkflowExecutionReadsDurableTransferMode(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	expires := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT workflow.id, workflow.state, workflow.attempt`).WithArgs("workflow").
		WillReturnRows(sqlmock.NewRows([]string{
			"workflow_id", "state", "attempt", "snapshot_id", "activity_epoch",
			"controller_generation", "global_user_id", "legacy_user_id", "username",
			"source_node_id", "target_node_id", "capability_id", "token_hash",
			"expires_at", "capability_state", "job_id", "trigger", "transfer_mode", "kind",
		}).AddRow(
			"workflow", "quiescing", 1, "snapshot", int64(4), int64(3), int64(70), int64(7), "alice",
			int64(8), int64(9), "capability", make([]byte, 32), expires, "prepared", int64(11),
			"offline", "relay", "archive",
		))
	execution, err := st.GetSnapshotWorkflowExecution(context.Background(), "workflow")
	if err != nil || execution == nil || execution.TransferMode != "relay" || execution.DestinationKind != "archive" {
		t.Fatalf("execution=%+v err=%v", execution, err)
	}
	assertMockExpectations(t, mock)
}

func TestSnapshotWorkflowClaimRetryAndResume(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 22, 0, 0, 0, time.UTC)
	mock.ExpectExec(`UPDATE workflows workflow SET lease_owner`).
		WithArgs("workflow", "controller-worker", now, now.Add(time.Hour)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	claimed, err := st.ClaimSnapshotWorkflow(context.Background(), "workflow", "controller-worker", now, time.Hour)
	if err != nil || !claimed {
		t.Fatalf("claimed=%v err=%v", claimed, err)
	}
	mock.ExpectQuery(`UPDATE workflows SET resume_state='quiescing'`).
		WithArgs("workflow", "network_error", "retry safely", now.Add(10*time.Second), now).
		WillReturnRows(sqlmock.NewRows([]string{"attempt"}).AddRow(2))
	attempt, err := st.ScheduleSnapshotRetry(context.Background(), "workflow", "network_error", "retry safely", now, 10*time.Second)
	if err != nil || attempt != 2 {
		t.Fatalf("attempt=%d err=%v", attempt, err)
	}
	mock.ExpectExec(`UPDATE workflows workflow SET transfer_mode='relay'`).WithArgs("workflow", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.SwitchSnapshotWorkflowToRelay(context.Background(), "workflow", now); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(`UPDATE workflows SET state=resume_state`).WithArgs("workflow", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.ResumeSnapshotRetry(context.Background(), "workflow", now); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(`UPDATE workflows SET lease_owner=NULL`).WithArgs("workflow", "controller-worker").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.ReleaseSnapshotWorkflow(context.Background(), "workflow", "controller-worker"); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}
