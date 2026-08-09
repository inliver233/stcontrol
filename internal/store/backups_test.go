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
	mock.ExpectQuery(`SELECT job.status,job.workflow_id::text`).WithArgs(int64(77)).
		WillReturnRows(sqlmock.NewRows([]string{"status", "workflow_id", "workflow_state"}).AddRow("running", "workflow-77", "snapshotting"))
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
	mock.ExpectQuery(`SELECT job.status,job.workflow_id::text`).WithArgs(int64(77)).
		WillReturnRows(sqlmock.NewRows([]string{"status", "workflow_id", "workflow_state"}).AddRow("done", "workflow-77", "succeeded"))
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
	mock.ExpectQuery(`SELECT job.status,job.workflow_id::text`).WithArgs(int64(78)).
		WillReturnRows(sqlmock.NewRows([]string{"status", "workflow_id", "workflow_state"}).AddRow("pending", nil, ""))
	mock.ExpectExec(`UPDATE backup_jobs SET status='aborted'`).
		WithArgs(int64(78), "administrator cancelled", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := st.AbortBackupJobAndSnapshotWorkflow(context.Background(), 78, "administrator cancelled", now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestAbortBackupJobAndSnapshotWorkflowRejectsRepeatedOrLinkedTerminalJob(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name          string
		jobStatus     string
		workflowState string
	}{
		{name: "already aborted", jobStatus: "aborted", workflowState: "cancelled"},
		{name: "workflow already published", jobStatus: "running", workflowState: "succeeded"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT job.status,job.workflow_id::text`).WithArgs(int64(79)).
				WillReturnRows(sqlmock.NewRows([]string{"status", "workflow_id", "workflow_state"}).
					AddRow(test.jobStatus, "workflow-79", test.workflowState))
			mock.ExpectRollback()
			err := st.AbortBackupJobAndSnapshotWorkflow(
				context.Background(), 79, "too late", time.Now().UTC(),
			)
			if !errors.Is(err, ErrBackupJobTerminal) {
				t.Fatalf("error=%v, want ErrBackupJobTerminal", err)
			}
			assertMockExpectations(t, mock)
		})
	}
}
