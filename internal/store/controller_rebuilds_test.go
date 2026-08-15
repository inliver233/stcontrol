package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestControllerRebuildDeferredMigrationKeepsReadyStateNonTerminal(t *testing.T) {
	t.Parallel()
	sqlText, err := os.ReadFile(filepath.Join("migrations", "0050_controller_rebuild_deferred.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"'draining','deferred','reconciled'",
		"'reconciling','ready_with_deferred','succeeded','failed'",
		"WHERE state IN ('reconciling','ready_with_deferred')",
		"UPDATE nodes node",
		"node.controller_generation<>epoch.generation",
		"capacity_reason_code='controller_generation_stale'",
		"UPDATE controller_rebuild_nodes item",
		"node.connectivity_state<>'online'",
		"WITH progress AS (",
		"WHEN progress.total_nodes=progress.reconciled_nodes THEN 'succeeded'",
		"WHEN progress.total_nodes=progress.ready_nodes THEN 'ready_with_deferred'",
		"THEN COALESCE(rebuild.completed_at,now())",
	} {
		if !strings.Contains(string(sqlText), required) {
			t.Fatalf("controller-rebuild migration missing %q", required)
		}
	}
}

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

func TestCredentialActivationRemainsDeferredUntilSuccessorHeartbeat(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 5, 10, 0, 0, time.UTC)
	rebuildID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)UPDATE controller_rebuild_nodes item SET.*node.connectivity_state='online'.*THEN 'credential_activated' ELSE 'deferred' END`).
		WithArgs(int64(12), int64(6), int64(2), now).
		WillReturnRows(sqlmock.NewRows([]string{"rebuild_id"}).AddRow(rebuildID))
	mock.ExpectExec(`UPDATE controller_rebuild_nodes item`).WithArgs(rebuildID, now).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`(?s)count\(\*\).*FILTER`).WithArgs(rebuildID).
		WillReturnRows(sqlmock.NewRows([]string{"total", "reconciled", "ready"}).AddRow(1, 0, 1))
	mock.ExpectExec(`UPDATE controller_rebuild_operations SET total_nodes`).WithArgs(
		rebuildID, 1, 0, now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE controller_rebuild_operations\s+SET state=\$2`).WithArgs(
		rebuildID, "ready_with_deferred", now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := st.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := markControllerRebuildCredentialActivatedLocked(
		context.Background(), tx, 12, 6, 2, now,
	); err != nil {
		t.Fatalf("markControllerRebuildCredentialActivatedLocked: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}
