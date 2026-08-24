package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestCompleteNodeRetirementHomeMigrationResumesAfterTransientRetry(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 24, 6, 0, 0, 0, time.UTC)
	itemID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	workflowID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	retirementID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	operationID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	snapshotID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT operation.id::text,operation.operation_id::text,item.item_kind,item.state.*FROM node_retirement_items item`).
		WithArgs(itemID, workflowID).
		WillReturnRows(sqlmock.NewRows([]string{
			"retirement_id", "operation_id", "item_kind", "item_state", "workflow_state",
			"global_status", "legacy_status", "user_id", "legacy_user_id", "source_node_id",
			"target_node_id", "generation",
		}).AddRow(retirementID, operationID, "authoritative_home", "retry_wait", "succeeded",
			"active", "active", int64(70), int64(7), int64(8), int64(9), int64(4)))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
	mock.ExpectQuery(`SELECT home_node_id FROM users`).WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"home_node_id"}).AddRow(int64(8)))
	mock.ExpectQuery(`(?s)SELECT EXISTS \(SELECT 1 FROM user_activity_leases`).WithArgs(int64(70), now).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery(`(?s)SELECT copy.snapshot_id::text.*snapshot.workflow_id=\$3`).
		WithArgs(int64(70), int64(9), workflowID).
		WillReturnRows(sqlmock.NewRows([]string{"snapshot_id"}).AddRow(snapshotID))
	mock.ExpectExec(`UPDATE replica_copies SET is_authoritative=false`).WithArgs(int64(70), int64(8), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE replica_copies SET replica_kind='active'`).
		WithArgs(int64(70), int64(9), now, snapshotID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE user_replicas SET kind='hot_standby'`).WithArgs(int64(7), int64(8)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE user_replicas SET kind='home'`).WithArgs(int64(7), int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE users SET home_node_id`).WithArgs(int64(7), int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE node_accounts`).WithArgs(int64(70), int64(9), now, int64(8)).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`UPDATE user_activity_leases`).WithArgs(int64(70), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE control_tickets`).WithArgs(int64(70), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE node_retirement_items SET state='succeeded'.*state IN \('snapshotting','promoting','retry_wait','blocked'\)`).
		WithArgs(itemID, now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).
		WithArgs(int64(70), operationID, int64(4), retirementID, int64(8), int64(9), snapshotID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := st.CompleteNodeRetirementHomeMigration(context.Background(), itemID, workflowID, now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}
