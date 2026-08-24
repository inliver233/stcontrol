package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

const (
	testHomeRetirementItemID     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testHomeRetirementWorkflowID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	testHomeRetirementID         = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	testHomeRetirementOperation  = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	testHomeRetirementSnapshot   = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
)

func expectHomeRetirementHeader(mock sqlmock.Sqlmock, itemState string) {
	mock.ExpectQuery(`SELECT operation.id::text,operation.operation_id::text,item.item_kind,item.state`).WithArgs(
		testHomeRetirementItemID, testHomeRetirementWorkflowID,
	).WillReturnRows(sqlmock.NewRows([]string{
		"retirement_id", "operation_id", "item_kind", "item_state", "workflow_state",
		"global_status", "legacy_status", "user_id", "legacy_user_id", "source_node_id",
		"target_node_id", "generation",
	}).AddRow(testHomeRetirementID, testHomeRetirementOperation, "authoritative_home", itemState,
		"succeeded", "active", "active", int64(70), int64(7), int64(8), int64(9), int64(4)))
}

func expectHomeRetirementPromotionPrefix(mock sqlmock.Sqlmock, now time.Time) {
	mock.ExpectBegin()
	expectHomeRetirementHeader(mock, "promoting")
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
	mock.ExpectQuery(`SELECT home_node_id FROM users`).WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"home_node_id"}).AddRow(int64(8)))
	mock.ExpectQuery(`SELECT EXISTS \(SELECT 1 FROM user_activity_leases`).WithArgs(int64(70), now).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery(`SELECT copy.snapshot_id::text`).WithArgs(int64(70), int64(9), testHomeRetirementWorkflowID).
		WillReturnRows(sqlmock.NewRows([]string{"snapshot_id"}).AddRow(testHomeRetirementSnapshot))
}

func expectHomeRetirementPromotionFailureAt(
	mock sqlmock.Sqlmock,
	now time.Time,
	stage string,
	injected error,
) {
	expectHomeRetirementPromotionPrefix(mock, now)
	deauthorize := mock.ExpectExec(`UPDATE replica_copies SET is_authoritative=false`).WithArgs(int64(70), int64(8), now)
	if stage == "deauthorize" {
		deauthorize.WillReturnError(injected)
		return
	}
	deauthorize.WillReturnResult(sqlmock.NewResult(0, 1))
	promote := mock.ExpectExec(`UPDATE replica_copies SET replica_kind='active'`).WithArgs(
		int64(70), int64(9), now, testHomeRetirementSnapshot,
	)
	if stage == "promote copy" {
		promote.WillReturnError(injected)
		return
	}
	if stage == "promote copy rows" {
		promote.WillReturnResult(sqlmock.NewErrorResult(injected))
		return
	}
	promote.WillReturnResult(sqlmock.NewResult(0, 1))
	oldLegacy := mock.ExpectExec(`UPDATE user_replicas SET kind='hot_standby'`).WithArgs(int64(7), int64(8))
	if stage == "old legacy" {
		oldLegacy.WillReturnError(injected)
		return
	}
	if stage == "old legacy rows" {
		oldLegacy.WillReturnResult(sqlmock.NewErrorResult(injected))
		return
	}
	oldLegacy.WillReturnResult(sqlmock.NewResult(0, 1))
	newLegacy := mock.ExpectExec(`UPDATE user_replicas SET kind='home'`).WithArgs(int64(7), int64(9))
	if stage == "new legacy" {
		newLegacy.WillReturnError(injected)
		return
	}
	if stage == "new legacy rows" {
		newLegacy.WillReturnResult(sqlmock.NewErrorResult(injected))
		return
	}
	newLegacy.WillReturnResult(sqlmock.NewResult(0, 1))
	home := mock.ExpectExec(`UPDATE users SET home_node_id`).WithArgs(int64(7), int64(9))
	if stage == "home user" {
		home.WillReturnError(injected)
		return
	}
	home.WillReturnResult(sqlmock.NewResult(0, 1))
	accounts := mock.ExpectExec(`UPDATE node_accounts SET status`).WithArgs(int64(70), int64(9), now, int64(8))
	if stage == "accounts" {
		accounts.WillReturnError(injected)
		return
	}
	accounts.WillReturnResult(sqlmock.NewResult(0, 2))
	leases := mock.ExpectExec(`UPDATE user_activity_leases`).WithArgs(int64(70), now)
	if stage == "leases" {
		leases.WillReturnError(injected)
		return
	}
	leases.WillReturnResult(sqlmock.NewResult(0, 1))
	tickets := mock.ExpectExec(`UPDATE control_tickets`).WithArgs(int64(70), now)
	if stage == "tickets" {
		tickets.WillReturnError(injected)
		return
	}
	tickets.WillReturnResult(sqlmock.NewResult(0, 1))
	item := mock.ExpectExec(`UPDATE node_retirement_items SET state='succeeded'`).WithArgs(testHomeRetirementItemID, now)
	if stage == "item" {
		item.WillReturnError(injected)
		return
	}
	if stage == "item rows" {
		item.WillReturnResult(sqlmock.NewErrorResult(injected))
		return
	}
	item.WillReturnResult(sqlmock.NewResult(0, 1))
	audit := mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		int64(70), testHomeRetirementOperation, int64(4), testHomeRetirementID,
		int64(8), int64(9), testHomeRetirementSnapshot,
	)
	if stage == "audit" {
		audit.WillReturnError(injected)
		return
	}
	audit.WillReturnResult(sqlmock.NewResult(0, 1))
	if stage != "commit" {
		panic("unhandled home retirement completion failure stage: " + stage)
	}
	mock.ExpectCommit().WillReturnError(injected)
}

func TestCompleteNodeRetirementHomeMigrationFencesPreconditionsAndReplay(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 9, 40, 0, 0, time.UTC)
	injected := errors.New("injected retirement completion failure")
	for _, tc := range []struct {
		name  string
		setup func(sqlmock.Sqlmock)
		want  error
	}{
		{
			name: "begin",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin().WillReturnError(injected)
			},
			want: injected,
		},
		{
			name: "header",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT operation.id::text`).WillReturnError(injected)
				mock.ExpectRollback()
			},
			want: injected,
		},
		{
			name: "invalid header state",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectHomeRetirementHeader(mock, "pending")
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
					WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
				mock.ExpectRollback()
			},
			want: ErrNodeRetirementState,
		},
		{
			name: "generation query",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectHomeRetirementHeader(mock, "promoting")
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).WillReturnError(injected)
				mock.ExpectRollback()
			},
			want: injected,
		},
		{
			name: "stale generation",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectHomeRetirementHeader(mock, "promoting")
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
					WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(5)))
				mock.ExpectRollback()
			},
			want: ErrNodeRetirementState,
		},
		{
			name: "replay fact lookup",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectHomeRetirementHeader(mock, "succeeded")
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
					WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
				mock.ExpectQuery(`SELECT EXISTS`).WillReturnError(injected)
				mock.ExpectRollback()
			},
			want: injected,
		},
		{
			name: "incomplete replay",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectHomeRetirementHeader(mock, "succeeded")
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
					WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
				mock.ExpectQuery(`SELECT EXISTS`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
				mock.ExpectRollback()
			},
			want: ErrNodeRetirementState,
		},
		{
			name: "replay commit",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectHomeRetirementHeader(mock, "succeeded")
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
					WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
				mock.ExpectQuery(`SELECT EXISTS`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
				mock.ExpectCommit().WillReturnError(injected)
			},
			want: injected,
		},
		{
			name: "home changed",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectHomeRetirementHeader(mock, "promoting")
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
					WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
				mock.ExpectQuery(`SELECT home_node_id FROM users`).WillReturnRows(
					sqlmock.NewRows([]string{"home_node_id"}).AddRow(int64(10)))
				mock.ExpectRollback()
			},
			want: ErrNodeRetirementState,
		},
		{
			name: "busy lookup",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectHomeRetirementHeader(mock, "promoting")
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
				mock.ExpectQuery(`SELECT home_node_id FROM users`).WillReturnRows(sqlmock.NewRows([]string{"home_node_id"}).AddRow(int64(8)))
				mock.ExpectQuery(`SELECT EXISTS \(SELECT 1 FROM user_activity_leases`).WillReturnError(injected)
				mock.ExpectRollback()
			},
			want: injected,
		},
		{
			name: "busy user",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectHomeRetirementHeader(mock, "promoting")
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
				mock.ExpectQuery(`SELECT home_node_id FROM users`).WillReturnRows(sqlmock.NewRows([]string{"home_node_id"}).AddRow(int64(8)))
				mock.ExpectQuery(`SELECT EXISTS \(SELECT 1 FROM user_activity_leases`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
				mock.ExpectRollback()
			},
			want: ErrSnapshotUserActive,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			tc.setup(mock)
			err := st.CompleteNodeRetirementHomeMigration(
				context.Background(), testHomeRetirementItemID, testHomeRetirementWorkflowID, now,
			)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
			assertMockExpectations(t, mock)
		})
	}

	t.Run("snapshot unavailable", func(t *testing.T) {
		st, mock, closeDB := newMockStore(t)
		defer closeDB()
		mock.ExpectBegin()
		expectHomeRetirementHeader(mock, "promoting")
		mock.ExpectQuery(`SELECT generation FROM controller_epochs`).WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
		mock.ExpectQuery(`SELECT home_node_id FROM users`).WillReturnRows(sqlmock.NewRows([]string{"home_node_id"}).AddRow(int64(8)))
		mock.ExpectQuery(`SELECT EXISTS \(SELECT 1 FROM user_activity_leases`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
		mock.ExpectQuery(`SELECT copy.snapshot_id::text`).WillReturnError(injected)
		mock.ExpectRollback()
		err := st.CompleteNodeRetirementHomeMigration(
			context.Background(), testHomeRetirementItemID, testHomeRetirementWorkflowID, now,
		)
		if !errors.Is(err, ErrNodeRetirementState) {
			t.Fatalf("error=%v", err)
		}
		assertMockExpectations(t, mock)
	})
}

func TestCompleteNodeRetirementHomeMigrationRollsBackEveryPromotionFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 9, 45, 0, 0, time.UTC)
	injected := errors.New("injected home retirement promotion failure")
	for _, stage := range []string{
		"deauthorize", "promote copy", "promote copy rows", "old legacy", "old legacy rows",
		"new legacy", "new legacy rows", "home user", "accounts", "leases", "tickets",
		"item", "item rows", "audit", "commit",
	} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			expectHomeRetirementPromotionFailureAt(mock, now, stage, injected)
			if stage != "commit" {
				mock.ExpectRollback()
			}
			err := st.CompleteNodeRetirementHomeMigration(
				context.Background(), testHomeRetirementItemID, testHomeRetirementWorkflowID, now,
			)
			if !errors.Is(err, injected) {
				t.Fatalf("stage=%q error=%v", stage, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}
