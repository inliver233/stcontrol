package store

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestGetOpenReplicaConflictReturnsFrozenSources(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	detected := time.Date(2026, 8, 8, 13, 30, 0, 0, time.UTC)
	published := detected.Add(-time.Hour)
	manifest := bytes.Repeat([]byte{3}, 32)
	mock.ExpectQuery(`FROM replica_conflicts`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "state", "protection_version", "generation", "version", "detected", "updated",
		}).AddRow("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "detected", int64(3), int64(4), int64(1), detected, detected))
	mock.ExpectQuery(`FROM replica_conflict_sources`).WithArgs("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").
		WillReturnRows(sqlmock.NewRows([]string{
			"node_id", "node_name", "node_role", "snapshot_id", "source_kind", "replica_state",
			"authoritative", "manifest", "files", "bytes", "published", "data_version", "checksum", "captured",
		}).AddRow(int64(8), "compute-a", "compute", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			"active", "conflict", true, manifest, int64(12), int64(4096), published, int64(7), "legacy", detected).
			AddRow(int64(9), "compute-b", "compute", nil, "hot_standby", "conflict", false,
				nil, nil, nil, nil, int64(8), "other", detected))
	conflict, err := store.GetOpenReplicaConflict(context.Background(), 70)
	if err != nil || conflict == nil || len(conflict.Sources) != 2 {
		t.Fatalf("conflict=%+v err=%v", conflict, err)
	}
	first := conflict.Sources[0].Public()
	second := conflict.Sources[1].Public()
	if first.EvidenceState != "immutable" || first.FileCount == nil || *first.FileCount != 12 {
		t.Fatalf("first source=%+v", first)
	}
	if second.EvidenceState != "live_capture_required" || second.FileCount != nil {
		t.Fatalf("second source=%+v", second)
	}
	assertMockExpectations(t, mock)
}

func TestGetOpenReplicaConflictValidatesUser(t *testing.T) {
	t.Parallel()
	store := &Store{}
	if conflict, err := store.GetOpenReplicaConflict(context.Background(), 0); err == nil || conflict != nil {
		t.Fatalf("conflict=%+v err=%v", conflict, err)
	}
}
