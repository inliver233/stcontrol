package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestGetLatestControllerRebuildReturnsBoundedNodeProgress(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 5, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`FROM controller_rebuild_operations`).WillReturnRows(
		sqlmock.NewRows([]string{
			"id", "operation_id", "generation", "previous_generation", "source",
			"state", "total_nodes", "reconciled_nodes", "error_code",
			"started_at", "updated_at", "completed_at",
		}).AddRow(
			"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			5, 4, "passive-controller", "reconciling", 2, 1, nil,
			now.Add(-time.Minute), now, nil,
		),
	)
	mock.ExpectQuery(`FROM controller_rebuild_nodes item`).WithArgs(
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
	).WillReturnRows(sqlmock.NewRows([]string{
		"node_id", "node_name", "role", "state", "authenticated_generation",
		"credential_version", "last_heartbeat_at", "credential_activated_at", "reconciled_at",
	}).AddRow(12, "compute-a", "compute", "rotation_pending", 4, 2, now, nil, nil).
		AddRow(13, "storage-a", "storage", "reconciled", 5, 3, now, now, now))
	status, err := st.GetLatestControllerRebuild(context.Background())
	if err != nil || status == nil || status.Generation != 5 || status.TotalNodes != 2 ||
		len(status.Nodes) != 2 || status.Nodes[0].State != "rotation_pending" ||
		status.Nodes[1].ReconciledAt == nil {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	assertMockExpectations(t, mock)
}

func TestGetLatestControllerRebuildReturnsNilBeforeFirstPromotion(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`FROM controller_rebuild_operations`).WillReturnRows(
		sqlmock.NewRows([]string{
			"id", "operation_id", "generation", "previous_generation", "source",
			"state", "total_nodes", "reconciled_nodes", "error_code",
			"started_at", "updated_at", "completed_at",
		}),
	)
	status, err := st.GetLatestControllerRebuild(context.Background())
	if err != nil || status != nil {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	assertMockExpectations(t, mock)
}
