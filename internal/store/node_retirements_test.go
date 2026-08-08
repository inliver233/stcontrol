package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

const (
	testRetirementID = "11111111-1111-4111-8111-111111111111"
	testWorkerID     = "22222222-2222-4222-8222-222222222222"
	testLifecycleID  = "33333333-3333-4333-8333-333333333333"
	testItemID       = "44444444-4444-4444-8444-444444444444"
)

func TestGetNodeRetirementStatusReturnsBoundedProgressFacts(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 5, 35, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT operation.id::text`).WithArgs(int64(12)).WillReturnRows(sqlmock.NewRows([]string{
		"id", "operation_id", "node_id", "state", "reason_code", "total", "pending", "waiting",
		"running", "blocked", "failed", "completed", "error_code", "generation", "created_at", "updated_at", "completed_at",
	}).AddRow(
		"99999999-9999-4999-8999-999999999999", "88888888-8888-4888-8888-888888888888",
		int64(12), "migrating", "operator_draining", 8, 2, 1, 2, 1, 0, 2, "target_unavailable",
		int64(7), now.Add(-time.Minute), now, nil,
	))
	status, err := st.GetNodeRetirementStatus(context.Background(), 12)
	if err != nil || status == nil || status.TotalItems != 8 || status.CompletedItems != 2 ||
		status.BlockedItems != 1 || status.ErrorCode != "target_unavailable" || status.ControllerGeneration != 7 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	assertMockExpectations(t, mock)
}

func TestListSchedulableNodeRetirementIDsBoundsLimit(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`SELECT id::text FROM node_retirement_operations`).WithArgs(100).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).
			AddRow("11111111-1111-4111-8111-111111111111").
			AddRow("22222222-2222-4222-8222-222222222222"))
	ids, err := st.ListSchedulableNodeRetirementIDs(context.Background(), 1001)
	if err != nil || len(ids) != 2 {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimNodeRetirementFencesGenerationAndStartsRetiringState(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 0, 30, 0, 0, time.UTC)
	ttl := 2 * time.Minute
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT operation.node_id,operation.state`).
		WithArgs(testRetirementID, now).
		WillReturnRows(sqlmock.NewRows([]string{
			"node_id", "operation_state", "generation", "admin_id", "node_state",
		}).AddRow(int64(12), "scheduled", int64(7), int64(3), "draining"))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectExec(`UPDATE nodes SET operational_state='retiring'`).
		WithArgs(int64(12)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO node_lifecycle_events`).
		WithArgs(testLifecycleID, int64(12), int64(3), int64(7), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE node_retirement_operations SET state=CASE`).
		WithArgs(testRetirementID, testWorkerID, now, now.Add(ttl)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	claimed, err := st.ClaimNodeRetirement(
		context.Background(), testRetirementID, testWorkerID, testLifecycleID, now, ttl,
	)
	if err != nil || !claimed {
		t.Fatalf("claimed=%v err=%v", claimed, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimNodeRetirementReturnsUnclaimedWhenLeaseIsUnavailable(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 0, 31, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT operation.node_id,operation.state`).
		WithArgs(testRetirementID, now).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	claimed, err := st.ClaimNodeRetirement(
		context.Background(), testRetirementID, testWorkerID, testLifecycleID, now, time.Minute,
	)
	if err != nil || claimed {
		t.Fatalf("claimed=%v err=%v", claimed, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimNodeRetirementRejectsStaleControllerGeneration(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 0, 31, 30, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT operation.node_id,operation.state`).
		WithArgs(testRetirementID, now).
		WillReturnRows(sqlmock.NewRows([]string{
			"node_id", "operation_state", "generation", "admin_id", "node_state",
		}).AddRow(int64(12), "scheduled", int64(6), int64(3), "draining"))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectRollback()
	claimed, err := st.ClaimNodeRetirement(
		context.Background(), testRetirementID, testWorkerID, testLifecycleID, now, time.Minute,
	)
	if claimed || err != ErrNodeRetirementState {
		t.Fatalf("claimed=%v err=%v", claimed, err)
	}
	assertMockExpectations(t, mock)
}

func TestGetNextNodeRetirementItemReturnsWorkflowAndActivityFacts(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 0, 32, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT item.id::text,operation.id::text`).
		WithArgs(testRetirementID, now).
		WillReturnRows(sqlmock.NewRows([]string{
			"item_id", "retirement_id", "operation_id", "node_id", "node_role", "operation_state",
			"generation", "kind", "state", "attempt", "user_id", "legacy_user_id", "handle",
			"home_node_id", "target_node_id", "workflow_id", "workflow_state", "busy",
		}).AddRow(
			testItemID, testRetirementID, testLifecycleID, int64(12), "compute", "migrating",
			int64(7), "authoritative_home", "snapshotting", 2, int64(70), int64(7), "alice",
			int64(12), int64(13), "55555555-5555-4555-8555-555555555555", "succeeded", false,
		))
	item, err := st.GetNextNodeRetirementItem(context.Background(), testRetirementID, now)
	if err != nil || item == nil || item.ItemKind != "authoritative_home" || item.UserID != 70 ||
		item.HomeNodeID != 12 || item.TargetNodeID != 13 || item.WorkflowState != "succeeded" || item.UserBusy {
		t.Fatalf("item=%+v err=%v", item, err)
	}
	assertMockExpectations(t, mock)
}

func TestRetryNodeRetirementItemFencesGenerationAndDelaysOperation(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 0, 33, 0, 0, time.UTC)
	delay := 45 * time.Second
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE node_retirement_items item SET state=\$2`).
		WithArgs(testItemID, "retry_wait", "snapshot_workflow_terminal", now.Add(delay), true, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE node_retirement_operations operation SET state=\$2`).
		WithArgs(testItemID, "retry_wait", "snapshot_workflow_terminal", now.Add(delay), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.RetryNodeRetirementItem(
		context.Background(), testItemID, "retry_wait", "snapshot_workflow_terminal",
		true, now, delay,
	); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestDeferNodeRetirementReleasesShortLease(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 0, 34, 0, 0, time.UTC)
	delay := 20 * time.Second
	mock.ExpectExec(`UPDATE node_retirement_operations SET state='retry_wait'`).
		WithArgs(testRetirementID, testWorkerID, "snapshot_workflow_running", now.Add(delay), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.DeferNodeRetirement(
		context.Background(), testRetirementID, testWorkerID, "snapshot_workflow_running", now, delay,
	); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestRetirementTargetAvailableRejectsHandleCollision(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`SELECT NOT EXISTS`).WithArgs(int64(70), int64(12), "alice").
		WillReturnRows(sqlmock.NewRows([]string{"available"}).AddRow(false))
	available, err := st.RetirementTargetAvailable(context.Background(), 70, 12, "alice")
	if err != nil || available {
		t.Fatalf("available=%v err=%v", available, err)
	}
	assertMockExpectations(t, mock)
}
