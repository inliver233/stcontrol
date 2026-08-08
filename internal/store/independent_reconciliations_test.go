package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestListIndependentReconciliationWorkClassifiesDurableStates(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 20, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT reconciliation.id::text,reconciliation.state`).
		WithArgs(25, now).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "state", "attempt", "node_id", "user_id", "legacy_user_id",
			"local_handle", "marker", "workflow_id", "workflow_state", "action",
		}).AddRow(
			"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "snapshotting", 1, int64(7), int64(70), int64(17),
			"alice", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			sql.NullString{String: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Valid: true},
			sql.NullString{String: "succeeded", Valid: true}, "complete",
		))
	items, err := st.ListIndependentReconciliationWork(context.Background(), 25, now)
	if err != nil || len(items) != 1 || items[0].Action != "complete" ||
		items[0].Handle != "alice" || !items[0].WorkflowID.Valid {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	assertMockExpectations(t, mock)
}

func TestIndependentReconciliationCompletionUsesExactMarkerAndRetries(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	ctx := context.Background()
	now := time.Date(2026, 8, 8, 20, 0, 0, 0, time.UTC)
	id := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	marker := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	mock.ExpectExec(`SET state='completing'`).WithArgs(id, marker, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.BeginIndependentReconciliationCompletion(ctx, id, marker, now); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(`SET state='succeeded'`).WithArgs(id, marker, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.CompleteIndependentReconciliation(ctx, id, marker, now); err != nil {
		t.Fatal(err)
	}

	delay := 30 * time.Second
	mock.ExpectExec(`SET state=CASE WHEN attempt>=9`).
		WithArgs(id, marker, "adapter_completion_failed", now.Add(delay), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.RetryIndependentReconciliationCompletion(
		ctx, id, marker, "adapter_completion_failed", now, delay,
	); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(`SET state=CASE WHEN reconciliation.attempt>=4`).
		WithArgs(id, marker, "snapshot_failed", now.Add(delay), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.RestartIndependentReconciliationSnapshot(
		ctx, id, marker, "snapshot_failed", now, delay,
	); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}
