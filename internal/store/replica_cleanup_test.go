package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestScheduleReplicaCleanupTasksPersistsArchiveAndStableHotCandidates(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE replica_cleanup_tasks task SET state='cancelled'`).WithArgs(now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO replica_cleanup_tasks .*'superseded_archive'.*current.integrity_state='verified'.*workflow.state NOT IN`).
		WithArgs(now).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`(?s)INSERT INTO replica_cleanup_tasks .*'stable_archive_available'.*protection.changed_at<=\$2.*archive.integrity_state='verified'`).
		WithArgs(now, now.Add(-ReplicaCleanupStabilityWindow), now.Add(-ReplicaCleanupProjectionMaxAge)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	count, err := st.ScheduleReplicaCleanupTasks(context.Background(), now)
	if err != nil || count != 3 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimReplicaCleanupTaskFencesGenerationAndMarksExactCopyDeleting(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 1, 10, 0, 0, time.UTC)
	operationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	owner := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE replica_cleanup_tasks SET state='retry_wait'`).WithArgs(now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectQuery(`(?s)FROM replica_cleanup_tasks task.*FOR UPDATE OF task SKIP LOCKED`).
		WithArgs(now, now.Add(-ReplicaCleanupStabilityWindow), now.Add(-ReplicaCleanupProjectionMaxAge)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "replica_id", "user_id", "legacy_user_id", "node_id", "snapshot_id",
			"handle", "replica_kind", "reason_code", "attempt",
		}).AddRow(testCleanupID, testReplicaID, int64(70), int64(7), int64(9), testCleanupSnapshotID,
			"alice", "archive", "superseded_archive", 1))
	mock.ExpectQuery(`SELECT id FROM global_users WHERE id=\$1 FOR UPDATE`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
	mock.ExpectExec(`UPDATE replica_cleanup_tasks SET state='running'`).
		WithArgs(now, operationID, int64(7), owner, now.Add(time.Minute), testCleanupID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE replica_copies SET state='deleting'`).
		WithArgs(testReplicaID, now, testCleanupSnapshotID, "archive").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE user_replicas SET state='deleting'`).
		WithArgs(int64(7), int64(9), "archive").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	task, err := st.ClaimReplicaCleanupTask(context.Background(), operationID, owner, now, time.Minute)
	if err != nil || task == nil || task.Attempt != 2 || task.ControllerGeneration != 7 || task.LeaseOwner != owner {
		t.Fatalf("task=%+v err=%v", task, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimReplicaCleanupTaskLeavesUnsafeCandidatesQueued(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 1, 12, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE replica_cleanup_tasks SET state='retry_wait'`).WithArgs(now).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectQuery(`(?s)FROM replica_cleanup_tasks task.*archive.integrity_state='verified'.*FOR UPDATE OF task SKIP LOCKED`).
		WithArgs(now, now.Add(-ReplicaCleanupStabilityWindow), now.Add(-ReplicaCleanupProjectionMaxAge)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "replica_id", "user_id", "legacy_user_id", "node_id", "snapshot_id",
			"handle", "replica_kind", "reason_code", "attempt",
		}))
	mock.ExpectCommit()
	task, err := st.ClaimReplicaCleanupTask(
		context.Background(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", now, time.Minute,
	)
	if err != nil || task != nil {
		t.Fatalf("task=%+v err=%v", task, err)
	}
	assertMockExpectations(t, mock)
}

func TestCompleteReplicaCleanupDeletesOnlyExactFencedFacts(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 1, 20, 0, 0, time.UTC)
	task := cleanupStoreTestTask()
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(task.ControllerGeneration))
	mock.ExpectQuery(`(?s)SELECT state,operation_id::text,controller_generation,lease_owner.*FROM replica_cleanup_tasks WHERE id=\$1 FOR UPDATE`).
		WithArgs(task.ID).
		WillReturnRows(sqlmock.NewRows([]string{"state", "operation_id", "controller_generation", "lease_owner"}).
			AddRow("running", task.OperationID, task.ControllerGeneration, task.LeaseOwner))
	mock.ExpectExec(`DELETE FROM replica_copies`).WithArgs(
		task.ReplicaID, task.GlobalUserID, task.NodeID, task.SnapshotID, task.ReplicaKind,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM user_replicas`).WithArgs(task.LegacyUserID, task.NodeID, task.ReplicaKind).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE snapshot_manifests manifest SET state='deleted'`).WithArgs(task.SnapshotID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE replica_cleanup_tasks SET state=\$5`).WithArgs(
		task.ID, task.OperationID, task.ControllerGeneration, task.LeaseOwner,
		"succeeded", nil, "deleted", now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		now, task.GlobalUserID, task.OperationID, task.ControllerGeneration, "succeeded",
		task.ID, task.NodeID, task.SnapshotID, task.ReplicaKind, task.ReasonCode, "deleted",
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.CompleteReplicaCleanupTask(context.Background(), task, "deleted", now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestCompleteReplicaCleanupExactReplayIsIdempotent(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 1, 25, 0, 0, time.UTC)
	task := cleanupStoreTestTask()
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(task.ControllerGeneration))
	mock.ExpectQuery(`(?s)SELECT state,operation_id::text,controller_generation,lease_owner.*FROM replica_cleanup_tasks WHERE id=\$1 FOR UPDATE`).
		WithArgs(task.ID).
		WillReturnRows(sqlmock.NewRows([]string{"state", "operation_id", "controller_generation", "lease_owner"}).
			AddRow("succeeded", task.OperationID, task.ControllerGeneration, nil))
	mock.ExpectCommit()
	if err := st.CompleteReplicaCleanupTask(context.Background(), task, "already_absent", now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestRetryReplicaCleanupKeepsDeletingFenceUntilExactReplay(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 1, 30, 0, 0, time.UTC)
	task := cleanupStoreTestTask()
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE replica_cleanup_tasks SET state='retry_wait'`).WithArgs(
		task.ID, task.OperationID, task.ControllerGeneration, now, now.Add(time.Minute),
		"node_unavailable", task.LeaseOwner,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.RetryReplicaCleanupTask(context.Background(), task, "node_unavailable", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

const (
	testCleanupID         = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	testReplicaID         = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	testCleanupSnapshotID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
)

func cleanupStoreTestTask() ReplicaCleanupTask {
	return ReplicaCleanupTask{
		ID: testCleanupID, ReplicaID: testReplicaID, GlobalUserID: 70, LegacyUserID: 7,
		NodeID: 9, SnapshotID: testCleanupSnapshotID, Handle: "alice",
		ReplicaKind: "archive", ReasonCode: "superseded_archive", Attempt: 2,
		OperationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ControllerGeneration: 7,
		LeaseOwner: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	}
}
