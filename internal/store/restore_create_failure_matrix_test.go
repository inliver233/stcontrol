package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestCreateRestoreWorkflowRejectsInvalidAndExpiredRequests(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 8, 30, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		mutate func(*CreateRestoreWorkflowParams)
	}{
		{name: "missing target", mutate: func(p *CreateRestoreWorkflowParams) { p.TargetNodeID = 0 }},
		{name: "zero time and expiration", mutate: func(p *CreateRestoreWorkflowParams) {
			p.Now = time.Time{}
			p.CapabilityExpires = time.Time{}
		}},
		{name: "expired capability", mutate: func(p *CreateRestoreWorkflowParams) { p.CapabilityExpires = now }},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := restoreWorkflowParams(now)
			tc.mutate(&p)
			if _, err := st.CreateRestoreWorkflow(context.Background(), p); !errors.Is(err, ErrInvalidRestoreWorkflow) {
				t.Fatalf("error=%v, want ErrInvalidRestoreWorkflow", err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func expectRestoreCreateFailureAt(
	mock sqlmock.Sqlmock,
	p CreateRestoreWorkflowParams,
	stage string,
	injected error,
) error {
	mock.ExpectBegin()
	lock := mock.ExpectQuery(`SELECT id FROM global_users WHERE id=\$1 FOR UPDATE`).WithArgs(p.GlobalUserID)
	if stage == "global user lock" {
		lock.WillReturnError(injected)
		return injected
	}
	lock.WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.GlobalUserID))

	replay := mock.ExpectQuery(`(?s)FROM restore_operations operation.*JOIN LATERAL`).WithArgs(p.OperationID)
	if stage == "replay query" {
		replay.WillReturnError(injected)
		return injected
	}
	replay.WillReturnRows(sqlmock.NewRows([]string{"request_digest"}))

	fault := mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(p.GlobalUserID)
	if stage == "fault query" {
		fault.WillReturnError(injected)
		return injected
	}
	if stage == "fault not recoverable" {
		fault.WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("freezing"))
		return ErrUserDataFaultState
	}
	fault.WillReturnRows(sqlmock.NewRows([]string{"state"}))

	generation := mock.ExpectQuery(`SELECT generation FROM controller_epochs`)
	if stage == "no active generation" {
		generation.WillReturnError(sql.ErrNoRows)
		return ErrNoActiveController
	}
	if stage == "generation query" {
		generation.WillReturnError(injected)
		return injected
	}
	generation.WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))

	lease := mock.ExpectQuery(`SELECT user_id, writer_node_id`).WithArgs(p.GlobalUserID)
	if stage == "lease query" {
		lease.WillReturnError(injected)
		return injected
	}
	if stage == "active lease" {
		lease.WillReturnRows(sqlmock.NewRows([]string{
			"user_id", "writer_node_id", "session_id", "activity_epoch", "state", "lease_expires_at",
			"last_page", "last_request", "reads", "writes", "generation", "updated_at",
		}).AddRow(p.GlobalUserID, int64(8), "session", int64(3), "active", p.Now.Add(time.Minute),
			p.Now, p.Now, 0, 0, int64(4), p.Now))
		return ErrReplicaTakeoverLeaseActive
	}
	lease.WillReturnRows(sqlmock.NewRows([]string{"user_id"}))

	active := mock.ExpectQuery(`(?s)SELECT EXISTS \(.*FROM workflows WHERE user_id`).WithArgs(p.GlobalUserID)
	if stage == "workflow activity query" {
		active.WillReturnError(injected)
		return injected
	}
	if stage == "workflow active" {
		active.WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
		return ErrRestoreConflict
	}
	active.WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	source := mock.ExpectQuery(`(?s)FROM global_users global_user.*protection.state='restore_required'`).
		WithArgs(p.GlobalUserID, p.ExpectedRecoveryAt)
	if stage == "source unavailable" {
		source.WillReturnError(sql.ErrNoRows)
		return ErrRestoreUnavailable
	}
	if stage == "source query" {
		source.WillReturnError(injected)
		return injected
	}
	sourceNodeID := int64(10)
	oldHomeNodeID := int64(8)
	if stage == "source target collision" {
		sourceNodeID = p.TargetNodeID
	}
	source.WillReturnRows(sqlmock.NewRows([]string{
		"legacy_user_id", "username", "display_name", "home_node_id", "source_node_id", "source_snapshot_id",
		"published_at", "manifest_sha256", "activity_epoch",
	}).AddRow(int64(7), "alice", "Alice", oldHomeNodeID, sourceNodeID,
		"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", p.ExpectedRecoveryAt, bytes.Repeat([]byte{3}, 32), int64(5)))
	if stage == "source target collision" {
		return ErrRestoreUnavailable
	}

	target := mock.ExpectQuery(`(?s)SELECT node.id FROM nodes node.*node.capacity_state IN \('open','busy'\)`).
		WithArgs(p.GlobalUserID, p.TargetNodeID)
	if stage == "target unavailable" {
		target.WillReturnError(sql.ErrNoRows)
		return ErrRestoreUnavailable
	}
	if stage == "target query" {
		target.WillReturnError(injected)
		return injected
	}
	target.WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.TargetNodeID))

	workflow := mock.ExpectExec(`INSERT INTO workflows`)
	if stage == "workflow insert" {
		workflow.WillReturnError(injected)
		return injected
	}
	workflow.WillReturnResult(sqlmock.NewResult(0, 1))

	account := mock.ExpectQuery(`SELECT status FROM node_accounts`).WithArgs(p.GlobalUserID, p.TargetNodeID)
	if stage == "target account query" {
		account.WillReturnError(injected)
		return injected
	}
	if stage == "target account blocked" {
		account.WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("conflict"))
		return ErrRestoreUnavailable
	}
	account.WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("active"))

	manifest := mock.ExpectExec(`INSERT INTO snapshot_manifests`)
	if stage == "manifest insert" {
		manifest.WillReturnError(injected)
		return injected
	}
	manifest.WillReturnResult(sqlmock.NewResult(0, 1))

	capability := mock.ExpectExec(`INSERT INTO snapshot_transfer_capabilities`)
	if stage == "capability insert" {
		capability.WillReturnError(injected)
		return injected
	}
	capability.WillReturnResult(sqlmock.NewResult(0, 1))

	for index, step := range []string{"provision_account", "prepare_target", "transfer", "verify", "publish"} {
		stepState := "pending"
		if index == 0 {
			stepState = "succeeded"
		}
		stepInsert := mock.ExpectExec(`INSERT INTO workflow_steps`).WithArgs(p.WorkflowID, step, stepState, p.Now)
		if stage == "workflow step insert" && index == 0 {
			stepInsert.WillReturnError(injected)
			return injected
		}
		stepInsert.WillReturnResult(sqlmock.NewResult(0, 1))
	}

	operation := mock.ExpectQuery(`INSERT INTO restore_operations`)
	if stage == "restore operation insert" {
		operation.WillReturnError(injected)
		return injected
	}
	operation.WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(12)))

	replica := mock.ExpectExec(`INSERT INTO user_replicas`)
	if stage == "replica projection" {
		replica.WillReturnError(injected)
		return injected
	}
	replica.WillReturnResult(sqlmock.NewResult(0, 1))

	audit := mock.ExpectExec(`INSERT INTO audit_events`)
	if stage == "audit insert" {
		audit.WillReturnError(injected)
		return injected
	}
	audit.WillReturnResult(sqlmock.NewResult(0, 1))

	if stage != "commit" {
		panic("unhandled restore create failure stage: " + stage)
	}
	mock.ExpectCommit().WillReturnError(injected)
	return injected
}

func TestCreateRestoreWorkflowRollsBackAtEveryDurableBoundary(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 8, 35, 0, 0, time.UTC)
	injected := errors.New("injected restore create failure")
	stages := []string{
		"global user lock", "replay query", "fault query", "fault not recoverable",
		"no active generation", "generation query", "lease query", "active lease",
		"workflow activity query", "workflow active", "source unavailable", "source query",
		"source target collision", "target unavailable", "target query", "workflow insert",
		"target account query", "target account blocked", "manifest insert", "capability insert",
		"workflow step insert", "restore operation insert", "replica projection", "audit insert", "commit",
	}
	for _, stage := range stages {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := restoreWorkflowParams(now)
			wantErr := expectRestoreCreateFailureAt(mock, p, stage, injected)
			if stage != "commit" {
				mock.ExpectRollback()
			}
			execution, err := st.CreateRestoreWorkflow(context.Background(), p)
			if execution != nil || !errors.Is(err, wantErr) {
				t.Fatalf("execution=%+v error=%v, want %v", execution, err, wantErr)
			}
			assertMockExpectations(t, mock)
		})
	}
}
