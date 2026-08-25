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

func completeConflictResolutionCreateParams(now time.Time) CreateConflictResolutionParams {
	p := conflictResolutionCreateParams(now)
	p.Decisions = []ConflictResolutionDecision{{
		Path: "chats/session.jsonl", SourceNodeID: 10, Action: "use_source",
	}}
	p.Transfers = []ConflictResolutionTransferInput{{
		EvidenceID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", SourceNodeID: 10,
		CapabilityID:   "ffffffff-ffff-4fff-8fff-ffffffffffff",
		CapabilityHash: bytes.Repeat([]byte{2}, 32), ExpiresAt: now.Add(15 * time.Minute),
	}}
	return p
}

func TestCreateConflictResolutionRejectsInvalidDecisionAndTransferScopes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 8, 20, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*CreateConflictResolutionParams)
	}{
		{name: "zero time still validates duplicate decision", mutate: func(p *CreateConflictResolutionParams) {
			p.Now = time.Time{}
			p.Decisions = append(p.Decisions, p.Decisions[0])
		}},
		{name: "invalid decision action", mutate: func(p *CreateConflictResolutionParams) {
			p.Decisions[0].Action = "overwrite_everything"
		}},
		{name: "expired transfer", mutate: func(p *CreateConflictResolutionParams) {
			p.Transfers[0].ExpiresAt = now
		}},
		{name: "duplicate evidence", mutate: func(p *CreateConflictResolutionParams) {
			p.Transfers = append(p.Transfers, p.Transfers[0])
		}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := completeConflictResolutionCreateParams(now)
			tc.mutate(&p)
			if _, err := st.CreateConflictResolution(context.Background(), p); !errors.Is(err, ErrInvalidConflictResolution) {
				t.Fatalf("error=%v, want ErrInvalidConflictResolution", err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func expectConflictResolutionCreateFailureAt(
	mock sqlmock.Sqlmock,
	p CreateConflictResolutionParams,
	stage string,
	injected error,
) error {
	mock.ExpectBegin()
	replay := mock.ExpectQuery(`(?s)SELECT operation.request_digest,operation.user_id,operation.base_node_id.*FROM conflict_resolution_operations operation`).
		WithArgs(p.OperationID)
	if stage == "replay query" {
		replay.WillReturnError(injected)
		return injected
	}
	replay.WillReturnRows(sqlmock.NewRows([]string{
		"request_digest", "user_id", "base_node_id", "workflow_id", "state", "attempt",
		"conflict_id", "conflict_version", "legacy_user_id", "handle", "result_snapshot_id",
		"activity_epoch", "controller_generation", "default_action",
	}))

	lock := mock.ExpectQuery(`SELECT id FROM global_users WHERE id=\$1 FOR UPDATE`).WithArgs(p.GlobalUserID)
	if stage == "global user lock" {
		lock.WillReturnError(injected)
		return injected
	}
	lock.WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.GlobalUserID))

	generation := mock.ExpectQuery(`SELECT generation FROM controller_epochs`)
	if stage == "no active generation" {
		generation.WillReturnError(sql.ErrNoRows)
		return ErrNoActiveController
	}
	if stage == "generation query" {
		generation.WillReturnError(injected)
		return injected
	}
	generation.WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(3)))

	conflict := mock.ExpectQuery(`(?s)SELECT global_user.legacy_user_id,COALESCE\(base_account.local_handle,legacy.username\),conflict.version.*FROM replica_conflicts conflict`).
		WithArgs(p.ConflictID, p.GlobalUserID, p.ExpectedConflictVersion, p.BaseNodeID)
	if stage == "conflict state" {
		conflict.WillReturnError(sql.ErrNoRows)
		return ErrConflictResolutionState
	}
	if stage == "conflict query" {
		conflict.WillReturnError(injected)
		return injected
	}
	conflict.WillReturnRows(sqlmock.NewRows([]string{
		"legacy_user_id", "handle", "version", "activity_epoch",
	}).AddRow(int64(7), "alice", int64(4), int64(2)))

	existing := mock.ExpectQuery(`SELECT EXISTS \(SELECT 1 FROM conflict_resolution_operations`).WithArgs(p.ConflictID)
	if stage == "existing query" {
		existing.WillReturnError(injected)
		return injected
	}
	if stage == "existing resolution" {
		existing.WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
		return ErrConflictResolutionState
	}
	existing.WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	base := mock.ExpectQuery(`SELECT source.evidence_id::text FROM replica_conflict_sources source`).
		WithArgs(p.ConflictID, p.BaseNodeID)
	if stage == "base evidence missing" {
		base.WillReturnError(sql.ErrNoRows)
		return ErrConflictResolutionState
	}
	if stage == "base evidence query" {
		base.WillReturnError(injected)
		return injected
	}
	base.WillReturnRows(sqlmock.NewRows([]string{"evidence_id"}).AddRow("base-evidence"))

	sourceCount := mock.ExpectQuery(`SELECT count\(\*\) FROM replica_conflict_sources`).WithArgs(p.ConflictID)
	if stage == "source count query" {
		sourceCount.WillReturnError(injected)
		return injected
	}
	if stage == "source count mismatch" {
		sourceCount.WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
		return ErrConflictResolutionState
	}
	sourceCount.WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	transferValid := mock.ExpectQuery(`SELECT EXISTS \(SELECT 1 FROM replica_conflict_sources`).
		WithArgs(p.ConflictID, p.Transfers[0].EvidenceID, p.Transfers[0].SourceNodeID, p.BaseNodeID)
	if stage == "transfer query" {
		transferValid.WillReturnError(injected)
		return injected
	}
	if stage == "transfer not ready" {
		transferValid.WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
		return ErrConflictResolutionState
	}
	transferValid.WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	decisionValid := mock.ExpectQuery(`SELECT EXISTS \(SELECT 1 FROM replica_conflict_sources`).
		WithArgs(p.ConflictID, p.Decisions[0].SourceNodeID)
	if stage == "decision query" {
		decisionValid.WillReturnError(injected)
		return injected
	}
	if stage == "decision source missing" {
		decisionValid.WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
		return ErrConflictResolutionState
	}
	decisionValid.WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	active := mock.ExpectQuery(`SELECT EXISTS \(SELECT 1 FROM workflows WHERE user_id`).WithArgs(p.GlobalUserID)
	if stage == "active workflow query" {
		active.WillReturnError(injected)
		return injected
	}
	if stage == "active workflow" {
		active.WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
		return ErrConflictResolutionState
	}
	active.WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	workflow := mock.ExpectExec(`INSERT INTO workflows`)
	if stage == "workflow insert" {
		workflow.WillReturnError(injected)
		return injected
	}
	workflow.WillReturnResult(sqlmock.NewResult(0, 1))

	manifest := mock.ExpectExec(`INSERT INTO snapshot_manifests`)
	if stage == "manifest insert" {
		manifest.WillReturnError(injected)
		return injected
	}
	manifest.WillReturnResult(sqlmock.NewResult(0, 1))

	operation := mock.ExpectExec(`INSERT INTO conflict_resolution_operations`)
	if stage == "operation insert" {
		operation.WillReturnError(injected)
		return injected
	}
	operation.WillReturnResult(sqlmock.NewResult(0, 1))

	decision := mock.ExpectExec(`INSERT INTO conflict_resolution_decisions`)
	if stage == "decision insert" {
		decision.WillReturnError(injected)
		return injected
	}
	decision.WillReturnResult(sqlmock.NewResult(0, 1))

	transfer := mock.ExpectExec(`INSERT INTO conflict_resolution_transfers`)
	if stage == "transfer insert" {
		transfer.WillReturnError(injected)
		return injected
	}
	transfer.WillReturnResult(sqlmock.NewResult(0, 1))

	for index, step := range []string{"transfer_evidence", "prepare", "apply_decisions", "publish", "finalize"} {
		stepInsert := mock.ExpectExec(`INSERT INTO workflow_steps`).WithArgs(p.WorkflowID, step, p.Now)
		if stage == "workflow step insert" && index == 0 {
			stepInsert.WillReturnError(injected)
			return injected
		}
		stepInsert.WillReturnResult(sqlmock.NewResult(0, 1))
	}

	conflictUpdate := mock.ExpectExec(`UPDATE replica_conflicts`).WithArgs(p.ConflictID, p.Now)
	if stage == "conflict update" {
		conflictUpdate.WillReturnError(injected)
		return injected
	}
	conflictUpdate.WillReturnResult(sqlmock.NewResult(0, 1))

	audit := mock.ExpectExec(`INSERT INTO audit_events`)
	if stage == "audit insert" {
		audit.WillReturnError(injected)
		return injected
	}
	audit.WillReturnResult(sqlmock.NewResult(0, 1))

	if stage != "commit" {
		panic("unhandled conflict resolution failure stage: " + stage)
	}
	mock.ExpectCommit().WillReturnError(injected)
	return injected
}

func TestCreateConflictResolutionRollsBackAtEveryDurableBoundary(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 8, 25, 0, 0, time.UTC)
	injected := errors.New("injected conflict resolution create failure")
	stages := []string{
		"replay query", "global user lock", "no active generation", "generation query",
		"conflict state", "conflict query", "existing query", "existing resolution",
		"base evidence missing", "base evidence query", "source count query", "source count mismatch",
		"transfer query", "transfer not ready", "decision query", "decision source missing",
		"active workflow query", "active workflow", "workflow insert", "manifest insert",
		"operation insert", "decision insert", "transfer insert", "workflow step insert",
		"conflict update", "audit insert", "commit",
	}
	for _, stage := range stages {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := completeConflictResolutionCreateParams(now)
			wantErr := expectConflictResolutionCreateFailureAt(mock, p, stage, injected)
			if stage != "commit" {
				mock.ExpectRollback()
			}
			execution, err := st.CreateConflictResolution(context.Background(), p)
			if execution != nil || !errors.Is(err, wantErr) {
				t.Fatalf("execution=%+v error=%v, want %v", execution, err, wantErr)
			}
			assertMockExpectations(t, mock)
		})
	}
}
