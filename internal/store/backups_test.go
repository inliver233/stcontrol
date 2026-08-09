package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestAbortBackupJobAndSnapshotWorkflowCommitsBothFacts(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 13, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT status,workflow_id::text FROM backup_jobs`).WithArgs(int64(77)).
		WillReturnRows(sqlmock.NewRows([]string{"status", "workflow_id"}).AddRow("running", "workflow-77"))
	mock.ExpectExec(`UPDATE backup_jobs SET status='aborted'`).
		WithArgs(int64(77), "user returned", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflows SET state='cancelled'`).
		WithArgs("workflow-77", "user returned", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='cancelled'`).
		WithArgs("workflow-77", now).
		WillReturnResult(sqlmock.NewResult(0, 4))
	mock.ExpectExec(`UPDATE snapshot_transfer_capabilities SET state='revoked'`).
		WithArgs("workflow-77").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := st.AbortBackupJobAndSnapshotWorkflow(context.Background(), 77, "user returned", now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestAbortBackupJobAndSnapshotWorkflowRejectsCompletedJob(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT status,workflow_id::text FROM backup_jobs`).WithArgs(int64(77)).
		WillReturnRows(sqlmock.NewRows([]string{"status", "workflow_id"}).AddRow("done", "workflow-77"))
	mock.ExpectRollback()

	err := st.AbortBackupJobAndSnapshotWorkflow(context.Background(), 77, "too late", time.Now().UTC())
	if !errors.Is(err, ErrBackupJobTerminal) {
		t.Fatalf("error=%v, want ErrBackupJobTerminal", err)
	}
	assertMockExpectations(t, mock)
}

func TestAbortBackupJobAndSnapshotWorkflowWithoutWorkflowIsStillDurable(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 13, 5, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT status,workflow_id::text FROM backup_jobs`).WithArgs(int64(78)).
		WillReturnRows(sqlmock.NewRows([]string{"status", "workflow_id"}).AddRow("pending", nil))
	mock.ExpectExec(`UPDATE backup_jobs SET status='aborted'`).
		WithArgs(int64(78), "administrator cancelled", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := st.AbortBackupJobAndSnapshotWorkflow(context.Background(), 78, "administrator cancelled", now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}
