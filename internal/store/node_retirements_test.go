package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
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
