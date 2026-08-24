package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func newControllerRetryTestServer(t *testing.T) (*Server, sqlmock.Sqlmock, func()) {
	t.Helper()
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultController()
	return &Server{Store: &store.Store{DB: database}, Cfg: cfg}, mock, func() { _ = database.Close() }
}

func expectControllerWorkflowRetry(
	mock sqlmock.Sqlmock,
	workflowType, workflowID, resumeState, code, summary string,
	attempt int,
) {
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT workflow_type FROM workflows`).WithArgs(workflowID).
		WillReturnRows(sqlmock.NewRows([]string{"workflow_type"}).AddRow(workflowType))
	mock.ExpectQuery(`UPDATE workflows SET resume_state=\$2`).WithArgs(
		workflowID, resumeState, code, summary, sqlmock.AnyArg(), sqlmock.AnyArg(), workflowType,
	).WillReturnRows(sqlmock.NewRows([]string{"attempt"}).AddRow(attempt))
	expectedSteps := int64(5)
	if workflowType == "restore" {
		mock.ExpectExec(`UPDATE snapshot_transfer_capabilities SET state='revoked'`).WithArgs(workflowID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectedSteps = 4
	}
	mock.ExpectExec(`UPDATE workflow_steps SET state='retry_wait'`).WithArgs(workflowID, code, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, expectedSteps))
	mock.ExpectCommit()
}

func TestRetryRestoreWorkflowPreservesCauseAndFailsAtAttemptLimit(t *testing.T) {
	server, mock, closeDatabase := newControllerRetryTestServer(t)
	defer closeDatabase()
	server.Cfg.Backup.RetryMax = 3
	execution := &store.RestoreWorkflowExecution{WorkflowID: "restore-workflow", Attempt: 10}
	cause := errors.New("bounded restore transport failure")
	expectControllerWorkflowRetry(
		mock, "restore", execution.WorkflowID, "scheduled", "restore_transport", "retry restore", 3,
	)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT workflow.state,operation.operation_id::text`).WithArgs(execution.WorkflowID).
		WillReturnError(errors.New("failure persistence unavailable"))
	mock.ExpectRollback()

	err := server.retryRestoreWorkflow(context.Background(), execution, "restore_transport", "retry restore", cause)
	if !errors.Is(err, cause) {
		t.Fatalf("retry error=%v, want original cause", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRetryRestoreWorkflowReturnsStableCodeAndHonorsCancellation(t *testing.T) {
	server, mock, closeDatabase := newControllerRetryTestServer(t)
	defer closeDatabase()
	execution := &store.RestoreWorkflowExecution{WorkflowID: "restore-workflow", Attempt: 1}
	expectControllerWorkflowRetry(
		mock, "restore", execution.WorkflowID, "scheduled", "source_unavailable", "retry source", 1,
	)
	if err := server.retryRestoreWorkflow(
		context.Background(), execution, "source_unavailable", "retry source", nil,
	); err == nil || err.Error() != "source_unavailable" {
		t.Fatalf("stable retry error=%v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := server.retryRestoreWorkflow(
		cancelled, execution, "source_unavailable", "retry source", nil,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled retry error=%v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRetryConflictResolutionFailsAtBoundedAttemptAndHonorsCancellation(t *testing.T) {
	server, mock, closeDatabase := newControllerRetryTestServer(t)
	defer closeDatabase()
	execution := &store.ConflictResolutionExecution{WorkflowID: "conflict-workflow", Attempt: 10}
	expectControllerWorkflowRetry(
		mock, "conflict_resolution", execution.WorkflowID, "scheduled", "source_unavailable", "retry conflict", 5,
	)
	mock.ExpectBegin()
	mock.ExpectQuery(`UPDATE workflows workflow SET state='failed'`).WithArgs(
		execution.WorkflowID, "source_unavailable", "retry conflict", sqlmock.AnyArg(),
	).
		WillReturnError(errors.New("failure persistence unavailable"))
	mock.ExpectRollback()
	if err := server.retryConflictResolution(
		context.Background(), execution, "source_unavailable", "retry conflict", nil,
	); err == nil || err.Error() != "source_unavailable" {
		t.Fatalf("stable conflict retry error=%v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := server.retryConflictResolution(
		cancelled, execution, "source_unavailable", "retry conflict", nil,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled conflict retry error=%v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreCommandDefinitiveFailureStateMatrix(t *testing.T) {
	for _, testCase := range []struct {
		state string
		want  bool
	}{
		{state: "failed", want: true},
		{state: "cancelled", want: true},
		{state: "expired", want: true},
		{state: "succeeded", want: false},
		{state: "running", want: false},
	} {
		t.Run(testCase.state, func(t *testing.T) {
			server, mock, closeDatabase := newControllerRetryTestServer(t)
			defer closeDatabase()
			mock.ExpectQuery(`WITH expired AS`).WithArgs("operation-id").
				WillReturnRows(sqlmock.NewRows([]string{"state", "result_summary", "updated_at"}).
					AddRow(testCase.state, []byte(`{}`), time.Now().UTC()))
			if got := server.restoreCommandDefinitivelyFailed(context.Background(), "operation-id"); got != testCase.want {
				t.Fatalf("state=%s definitive=%v want=%v", testCase.state, got, testCase.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("store error", func(t *testing.T) {
		server, mock, closeDatabase := newControllerRetryTestServer(t)
		defer closeDatabase()
		mock.ExpectQuery(`WITH expired AS`).WithArgs("operation-id").WillReturnError(errors.New("database unavailable"))
		if server.restoreCommandDefinitivelyFailed(context.Background(), "operation-id") {
			t.Fatal("database error classified as definitive command failure")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}
