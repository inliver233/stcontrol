package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func expectTakeoverStart(mock sqlmock.Sqlmock, p ConfirmReplicaTakeoverParams) {
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.GlobalUserID))
	mock.ExpectQuery(`FROM replica_takeover_operations`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"request_digest"}))
}

func expectTakeoverReadyReplica(mock sqlmock.Sqlmock, p ConfirmReplicaTakeoverParams) {
	expectTakeoverStart(mock, p)
	mock.ExpectQuery(`SELECT global_user.legacy_user_id`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"legacy_user_id", "home_node_id"}).AddRow(int64(7), int64(8)))
	mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("recovery_available"))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
	mock.ExpectQuery(`SELECT user_id, writer_node_id`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
	mock.ExpectQuery(`(?s)SELECT copy.snapshot_id::text.*snapshot.user_id=\$2.*copy.published_at=\$4`).
		WithArgs(int64(7), p.GlobalUserID, p.TargetNodeID, p.ExpectedRecoveryAt).
		WillReturnRows(sqlmock.NewRows([]string{"snapshot_id", "published_at"}).
			AddRow("snapshot", p.ExpectedRecoveryAt))
}

func TestConfirmReplicaTakeoverRejectsConflictingIdempotencyKey(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := takeoverParams(time.Date(2026, 8, 24, 3, 0, 0, 0, time.UTC))
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.GlobalUserID))
	mock.ExpectQuery(`FROM replica_takeover_operations`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{
			"request_digest", "user_id", "source", "target", "snapshot", "published", "generation",
		}).AddRow(p.RequestDigest, p.GlobalUserID, int64(8), int64(10), "snapshot", p.ExpectedRecoveryAt, int64(4)))
	mock.ExpectRollback()
	if _, err := st.ConfirmReplicaTakeover(context.Background(), p); !errors.Is(err, ErrReplicaTakeoverConflict) {
		t.Fatalf("err=%v, want ErrReplicaTakeoverConflict", err)
	}
	assertMockExpectations(t, mock)
}

func TestConfirmReplicaTakeoverFencesUnavailableIdentityAndRecoveryState(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 3, 5, 0, 0, time.UTC)
	tests := []struct {
		name  string
		setup func(sqlmock.Sqlmock, ConfirmReplicaTakeoverParams)
		want  error
	}{
		{
			name: "global identity missing",
			setup: func(mock sqlmock.Sqlmock, p ConfirmReplicaTakeoverParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.GlobalUserID).
					WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			},
			want: ErrGlobalUserNotFound,
		},
		{
			name: "active identity missing",
			setup: func(mock sqlmock.Sqlmock, p ConfirmReplicaTakeoverParams) {
				expectTakeoverStart(mock, p)
				mock.ExpectQuery(`SELECT global_user.legacy_user_id`).WithArgs(p.GlobalUserID).
					WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			},
			want: ErrReplicaTakeoverUnavailable,
		},
		{
			name: "target already home",
			setup: func(mock sqlmock.Sqlmock, p ConfirmReplicaTakeoverParams) {
				expectTakeoverStart(mock, p)
				mock.ExpectQuery(`SELECT global_user.legacy_user_id`).WithArgs(p.GlobalUserID).
					WillReturnRows(sqlmock.NewRows([]string{"legacy_user_id", "home_node_id"}).
						AddRow(int64(7), p.TargetNodeID))
				mock.ExpectRollback()
			},
			want: ErrReplicaTakeoverUnavailable,
		},
		{
			name: "data fault not recoverable",
			setup: func(mock sqlmock.Sqlmock, p ConfirmReplicaTakeoverParams) {
				expectTakeoverStart(mock, p)
				mock.ExpectQuery(`SELECT global_user.legacy_user_id`).WithArgs(p.GlobalUserID).
					WillReturnRows(sqlmock.NewRows([]string{"legacy_user_id", "home_node_id"}).AddRow(int64(7), int64(8)))
				mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(p.GlobalUserID).
					WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("detected"))
				mock.ExpectRollback()
			},
			want: ErrUserDataFaultState,
		},
		{
			name: "no active controller",
			setup: func(mock sqlmock.Sqlmock, p ConfirmReplicaTakeoverParams) {
				expectTakeoverStart(mock, p)
				mock.ExpectQuery(`SELECT global_user.legacy_user_id`).WithArgs(p.GlobalUserID).
					WillReturnRows(sqlmock.NewRows([]string{"legacy_user_id", "home_node_id"}).AddRow(int64(7), int64(8)))
				mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(p.GlobalUserID).
					WillReturnRows(sqlmock.NewRows([]string{"state"}))
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			},
			want: ErrNoActiveController,
		},
		{
			name: "verified replica missing",
			setup: func(mock sqlmock.Sqlmock, p ConfirmReplicaTakeoverParams) {
				expectTakeoverStart(mock, p)
				mock.ExpectQuery(`SELECT global_user.legacy_user_id`).WithArgs(p.GlobalUserID).
					WillReturnRows(sqlmock.NewRows([]string{"legacy_user_id", "home_node_id"}).AddRow(int64(7), int64(8)))
				mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(p.GlobalUserID).
					WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("recovery_available"))
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
					WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
				mock.ExpectQuery(`SELECT user_id, writer_node_id`).WithArgs(p.GlobalUserID).
					WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
				mock.ExpectQuery(`(?s)SELECT copy.snapshot_id::text.*copy.published_at=\$4`).
					WithArgs(int64(7), p.GlobalUserID, p.TargetNodeID, p.ExpectedRecoveryAt).
					WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			},
			want: ErrReplicaTakeoverUnavailable,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := takeoverParams(now)
			tc.setup(mock, p)
			_, err := st.ConfirmReplicaTakeover(context.Background(), p)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v, want %v", err, tc.want)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestConfirmReplicaTakeoverRollsBackFencedReplicaMutations(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 3, 10, 0, 0, time.UTC)
	for _, stage := range []string{"old home", "target home", "authoritative copy"} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := takeoverParams(now)
			expectTakeoverReadyReplica(mock, p)
			oldHomeRows := int64(1)
			if stage == "old home" {
				oldHomeRows = 0
			}
			mock.ExpectExec(`UPDATE user_replicas SET kind='hot_standby'`).WithArgs(int64(7), int64(8)).
				WillReturnResult(sqlmock.NewResult(0, oldHomeRows))
			if stage != "old home" {
				targetRows := int64(1)
				if stage == "target home" {
					targetRows = 0
				}
				mock.ExpectExec(`UPDATE user_replicas SET kind='home'`).WithArgs(int64(7), p.TargetNodeID).
					WillReturnResult(sqlmock.NewResult(0, targetRows))
				if stage == "authoritative copy" {
					mock.ExpectExec(`UPDATE users SET home_node_id`).WithArgs(int64(7), p.TargetNodeID).
						WillReturnResult(sqlmock.NewResult(0, 1))
					mock.ExpectExec(`UPDATE control_tickets`).WithArgs(p.GlobalUserID, now).
						WillReturnResult(sqlmock.NewResult(0, 1))
					mock.ExpectExec(`UPDATE replica_copies SET is_authoritative=false`).WithArgs(p.GlobalUserID, now).
						WillReturnResult(sqlmock.NewResult(0, 1))
					mock.ExpectExec(`INSERT INTO replica_copies`).WithArgs(p.GlobalUserID, int64(8), now).
						WillReturnResult(sqlmock.NewResult(0, 1))
					mock.ExpectExec(`UPDATE replica_copies SET replica_kind='active'`).WithArgs(
						p.GlobalUserID, p.TargetNodeID, "snapshot", now,
					).WillReturnResult(sqlmock.NewResult(0, 0))
				}
			}
			mock.ExpectRollback()
			if _, err := st.ConfirmReplicaTakeover(context.Background(), p); !errors.Is(err, ErrReplicaTakeoverUnavailable) {
				t.Fatalf("stage=%q err=%v, want ErrReplicaTakeoverUnavailable", stage, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func expectTakeoverMutationFailureAt(
	mock sqlmock.Sqlmock,
	p ConfirmReplicaTakeoverParams,
	stage string,
	injected error,
) {
	expectTakeoverReadyReplica(mock, p)
	oldHome := mock.ExpectExec(`UPDATE user_replicas SET kind='hot_standby'`).WithArgs(int64(7), int64(8))
	if stage == "old home" {
		oldHome.WillReturnError(injected)
		return
	}
	if stage == "old home rows" {
		oldHome.WillReturnResult(sqlmock.NewErrorResult(injected))
		return
	}
	oldHome.WillReturnResult(sqlmock.NewResult(0, 1))
	targetHome := mock.ExpectExec(`UPDATE user_replicas SET kind='home'`).WithArgs(int64(7), p.TargetNodeID)
	if stage == "target home" {
		targetHome.WillReturnError(injected)
		return
	}
	if stage == "target home rows" {
		targetHome.WillReturnResult(sqlmock.NewErrorResult(injected))
		return
	}
	targetHome.WillReturnResult(sqlmock.NewResult(0, 1))
	user := mock.ExpectExec(`UPDATE users SET home_node_id`).WithArgs(int64(7), p.TargetNodeID)
	if stage == "user" {
		user.WillReturnError(injected)
		return
	}
	user.WillReturnResult(sqlmock.NewResult(0, 1))
	control := mock.ExpectExec(`UPDATE control_tickets`).WithArgs(p.GlobalUserID, p.Now)
	if stage == "control tickets" {
		control.WillReturnError(injected)
		return
	}
	control.WillReturnResult(sqlmock.NewResult(0, 1))
	deauthorize := mock.ExpectExec(`UPDATE replica_copies SET is_authoritative=false`).WithArgs(p.GlobalUserID, p.Now)
	if stage == "deauthorize" {
		deauthorize.WillReturnError(injected)
		return
	}
	deauthorize.WillReturnResult(sqlmock.NewResult(0, 1))
	oldCopy := mock.ExpectExec(`INSERT INTO replica_copies`).WithArgs(p.GlobalUserID, int64(8), p.Now)
	if stage == "old copy" {
		oldCopy.WillReturnError(injected)
		return
	}
	oldCopy.WillReturnResult(sqlmock.NewResult(0, 1))
	authoritative := mock.ExpectExec(`UPDATE replica_copies SET replica_kind='active'`).WithArgs(
		p.GlobalUserID, p.TargetNodeID, "snapshot", p.Now,
	)
	if stage == "authoritative" {
		authoritative.WillReturnError(injected)
		return
	}
	if stage == "authoritative rows" {
		authoritative.WillReturnResult(sqlmock.NewErrorResult(injected))
		return
	}
	authoritative.WillReturnResult(sqlmock.NewResult(0, 1))
	account := mock.ExpectExec(`UPDATE node_accounts SET status`).WithArgs(
		p.GlobalUserID, p.TargetNodeID, p.Now, int64(8),
	)
	if stage == "node accounts" {
		account.WillReturnError(injected)
		return
	}
	account.WillReturnResult(sqlmock.NewResult(0, 2))
	operation := mock.ExpectExec(`INSERT INTO replica_takeover_operations`).WithArgs(
		p.OperationID, p.RequestDigest, p.GlobalUserID, int64(8), p.TargetNodeID,
		"snapshot", p.ExpectedRecoveryAt, nil, int64(4), p.Now,
	)
	if stage == "operation" {
		operation.WillReturnError(injected)
		return
	}
	operation.WillReturnResult(sqlmock.NewResult(0, 1))
	protection := mock.ExpectExec(`INSERT INTO user_protection_states`).WithArgs(p.GlobalUserID, p.TargetNodeID, p.Now)
	if stage == "protection" {
		protection.WillReturnError(injected)
		return
	}
	protection.WillReturnResult(sqlmock.NewResult(0, 1))
	resolve := mock.ExpectExec(`UPDATE user_data_faults SET state='resolved'`).WithArgs(
		p.GlobalUserID, "takeover", p.OperationID, p.Now,
	)
	if stage == "resolve fault" {
		resolve.WillReturnError(injected)
		return
	}
	if stage == "resolve rows" {
		resolve.WillReturnResult(sqlmock.NewErrorResult(injected))
		return
	}
	resolve.WillReturnResult(sqlmock.NewResult(0, 1))
	resolveAlert := mock.ExpectExec(`UPDATE alerts SET state='resolved'`).WithArgs(p.GlobalUserID, p.Now)
	if stage == "resolve alert" {
		resolveAlert.WillReturnError(injected)
		return
	}
	resolveAlert.WillReturnResult(sqlmock.NewResult(0, 1))
	audit := mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		p.GlobalUserID, p.OperationID, int64(4), p.RequestDigest, int64(8), p.TargetNodeID, p.ExpectedRecoveryAt,
	)
	if stage == "audit" {
		audit.WillReturnError(injected)
		return
	}
	audit.WillReturnResult(sqlmock.NewResult(0, 1))
	if stage != "commit" {
		panic("unhandled replica takeover failure stage: " + stage)
	}
	mock.ExpectCommit().WillReturnError(injected)
}

func TestConfirmReplicaTakeoverRollsBackEveryPublicationFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 9, 35, 0, 0, time.UTC)
	injected := errors.New("injected takeover publication failure")
	for _, stage := range []string{
		"old home", "old home rows", "target home", "target home rows", "user",
		"control tickets", "deauthorize", "old copy", "authoritative", "authoritative rows",
		"node accounts", "operation", "protection", "resolve fault", "resolve rows",
		"resolve alert", "audit", "commit",
	} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := takeoverParams(now)
			expectTakeoverMutationFailureAt(mock, p, stage, injected)
			if stage != "commit" {
				mock.ExpectRollback()
			}
			_, err := st.ConfirmReplicaTakeover(context.Background(), p)
			if !errors.Is(err, injected) {
				t.Fatalf("stage=%q error=%v", stage, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}
