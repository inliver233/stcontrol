package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

const (
	retirementReplicaItemID      = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	retirementReplicaOperationID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	retirementReplicaID          = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
)

func expectRetirementReplicaCompletionPrefix(
	mock sqlmock.Sqlmock,
	kind, state string,
	workflowID, workflowState any,
) {
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT operation.id::text,operation.operation_id::text,item.item_kind,item.state.*FROM node_retirement_items item`).
		WithArgs(retirementReplicaItemID).
		WillReturnRows(sqlmock.NewRows([]string{
			"retirement_id", "operation_id", "item_kind", "state", "user_id", "legacy_user_id",
			"source_node_id", "target_node_id", "controller_generation", "workflow_id", "workflow_state",
		}).AddRow(
			retirementReplicaID, retirementReplicaOperationID, kind, state, int64(70), int64(7),
			int64(8), int64(9), int64(3), workflowID, workflowState,
		))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(3)))
}

func expectRetirementReplicaCompletionCommit(mock sqlmock.Sqlmock, kind string, now time.Time, workflowID any) {
	mock.ExpectExec(`UPDATE node_accounts SET status='stale'`).
		WithArgs(int64(70), int64(8), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE node_retirement_items SET state='succeeded'`).
		WithArgs(retirementReplicaItemID, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).
		WithArgs(
			int64(70), retirementReplicaOperationID, int64(3), retirementReplicaID,
			kind, int64(8), int64(9), workflowID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

func TestCompleteNodeRetirementReplicaItemCommitsOnlyProtectedRedundantReplica(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 7, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		protected bool
		wantErr   error
	}{
		{name: "protection missing rolls back", protected: false, wantErr: ErrNodeRetirementState},
		{name: "healthy home and archive permit removal", protected: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			expectRetirementReplicaCompletionPrefix(mock, "redundant_replica", "pending", nil, nil)
			mock.ExpectQuery(`(?s)SELECT EXISTS \(.*FROM users legacy JOIN nodes home.*AND EXISTS \(.*FROM replica_copies`).
				WithArgs(int64(70), int64(7), int64(8)).
				WillReturnRows(sqlmock.NewRows([]string{"protected"}).AddRow(tc.protected))
			if tc.protected {
				mock.ExpectExec(`UPDATE replica_copies SET state='stale'`).
					WithArgs(int64(70), int64(8), now).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`UPDATE user_replicas SET state='stale'`).
					WithArgs(int64(7), int64(8)).
					WillReturnResult(sqlmock.NewResult(0, 1))
				expectRetirementReplicaCompletionCommit(mock, "redundant_replica", now, nil)
			} else {
				mock.ExpectRollback()
			}
			err := st.CompleteNodeRetirementReplicaItem(context.Background(), retirementReplicaItemID, now)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error=%v, want %v", err, tc.wantErr)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestCompleteNodeRetirementReplicaItemRequiresSourceMetadataToBeUnreferenced(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 7, 5, 0, 0, time.UTC)
	tests := []struct {
		name    string
		safe    bool
		wantErr error
	}{
		{name: "active source reference rolls back", safe: false, wantErr: ErrNodeRetirementState},
		{name: "unreferenced metadata can become stale", safe: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			expectRetirementReplicaCompletionPrefix(mock, "account_metadata", "retry_wait", nil, nil)
			mock.ExpectQuery(`(?s)SELECT NOT EXISTS \(.*FROM users.*AND NOT EXISTS \(.*FROM replica_copies.*AND NOT EXISTS \(.*FROM user_replicas`).
				WithArgs(int64(70), int64(7), int64(8)).
				WillReturnRows(sqlmock.NewRows([]string{"safe"}).AddRow(tc.safe))
			if tc.safe {
				expectRetirementReplicaCompletionCommit(mock, "account_metadata", now, nil)
			} else {
				mock.ExpectRollback()
			}
			err := st.CompleteNodeRetirementReplicaItem(context.Background(), retirementReplicaItemID, now)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error=%v, want %v", err, tc.wantErr)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestCompleteNodeRetirementReplicaItemReplayRevalidatesDurableResult(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 7, 10, 0, 0, time.UTC)
	workflowID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	tests := []struct {
		name      string
		committed bool
		wantErr   error
	}{
		{name: "missing durable result rejects replay", committed: false, wantErr: ErrNodeRetirementState},
		{name: "durable result accepts exact replay", committed: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			expectRetirementReplicaCompletionPrefix(mock, "archive_replica", "succeeded", workflowID, "succeeded")
			mock.ExpectQuery(`(?s)SELECT NOT EXISTS \(.*AND \(.*archive_replica`).
				WithArgs(int64(70), int64(7), int64(8), "archive_replica", int64(9), workflowID).
				WillReturnRows(sqlmock.NewRows([]string{"committed"}).AddRow(tc.committed))
			if tc.committed {
				mock.ExpectCommit()
			} else {
				mock.ExpectRollback()
			}
			err := st.CompleteNodeRetirementReplicaItem(context.Background(), retirementReplicaItemID, now)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error=%v, want %v", err, tc.wantErr)
			}
			assertMockExpectations(t, mock)
		})
	}
}
