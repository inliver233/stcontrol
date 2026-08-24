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
