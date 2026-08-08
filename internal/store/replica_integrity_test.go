package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

const (
	integrityReplicaID   = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	integrityOperationID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	integritySnapshotID  = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
)

func TestClaimReplicaIntegrityTaskUsesDurableLeaseAndGeneration(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 14, 0, 0, 0, time.UTC)
	manifest, archive := make([]byte, 32), make([]byte, 32)
	mock.ExpectQuery(`(?s)WITH candidate AS .*FOR UPDATE OF copy SKIP LOCKED.*UPDATE replica_copies`).
		WithArgs(integrityOperationID, now, now.Add(9*time.Hour)).
		WillReturnRows(sqlmock.NewRows([]string{
			"replica_id", "operation_id", "global_user_id", "legacy_user_id", "node_id",
			"snapshot_id", "handle", "manifest_sha256", "archive_sha256", "file_count",
			"total_bytes", "attempt", "controller_generation",
		}).AddRow(
			integrityReplicaID, integrityOperationID, int64(70), int64(7), int64(9),
			integritySnapshotID, "alice", manifest, archive, int64(2), int64(30), 1, int64(4),
		))
	task, err := st.ClaimReplicaIntegrityTask(context.Background(), integrityOperationID, now, 9*time.Hour)
	if err != nil || task == nil || task.ControllerGeneration != 4 || task.Attempt != 1 {
		t.Fatalf("task=%+v err=%v", task, err)
	}
	assertMockExpectations(t, mock)
}

func TestCompleteReplicaIntegrityTaskRequiresMatchingImmutableFacts(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 14, 0, 0, 0, time.UTC)
	p := CompleteReplicaIntegrityParams{
		ReplicaID: integrityReplicaID, OperationID: integrityOperationID, SnapshotID: integritySnapshotID,
		ManifestSHA256: make([]byte, 32), ArchiveSHA256: make([]byte, 32), FileCount: 2,
		TotalBytes: 30, Now: now, NextCheckAfter: 24 * time.Hour,
	}
	mock.ExpectExec(`UPDATE replica_copies copy SET integrity_state='verified'`).
		WithArgs(p.ReplicaID, p.OperationID, p.SnapshotID, p.ManifestSHA256, p.ArchiveSHA256,
			p.FileCount, now, now.Add(24*time.Hour), p.TotalBytes).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.CompleteReplicaIntegrityTask(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestFailReplicaIntegrityTaskRetriesTransientFailure(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 14, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`UPDATE replica_copies copy SET integrity_state=\$3`).
		WithArgs(integrityReplicaID, integrityOperationID, "retry_wait", "ready", now,
			now.Add(10*time.Minute), "node_unavailable").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "legacy_user_id", "node_id"}).
			AddRow(int64(70), int64(7), int64(9)))
	mock.ExpectCommit()
	if err := st.FailReplicaIntegrityTask(
		context.Background(), integrityReplicaID, integrityOperationID, "node_unavailable", false,
		now, 10*time.Minute,
	); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestFailReplicaIntegrityTaskQuarantinesCorruptCopyAndAlerts(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 14, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`UPDATE replica_copies copy SET integrity_state=\$3`).
		WithArgs(integrityReplicaID, integrityOperationID, "corrupt", "corrupt", now,
			now.Add(10*time.Minute), "receipt_mismatch").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "legacy_user_id", "node_id"}).
			AddRow(int64(70), int64(7), int64(9)))
	mock.ExpectExec(`UPDATE user_replicas SET state='corrupt'`).WithArgs(int64(7), int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO alerts`).WithArgs(integrityReplicaID, int64(70), int64(9), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.FailReplicaIntegrityTask(
		context.Background(), integrityReplicaID, integrityOperationID, "receipt_mismatch", true,
		now, 10*time.Minute,
	); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestReplicaIntegrityStoreRejectsInvalidStateInput(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	if _, err := st.ClaimReplicaIntegrityTask(context.Background(), "bad", time.Time{}, time.Hour); !errors.Is(err, ErrInvalidReplicaIntegrity) {
		t.Fatalf("claim error=%v", err)
	}
	if err := st.CompleteReplicaIntegrityTask(context.Background(), CompleteReplicaIntegrityParams{}); !errors.Is(err, ErrInvalidReplicaIntegrity) {
		t.Fatalf("complete error=%v", err)
	}
	assertMockExpectations(t, mock)
}
