package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestTryAcquireControllerLeadershipIsFailClosed(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`SELECT pg_try_advisory_lock`).WithArgs(controllerAdvisoryLockID).
		WillReturnRows(sqlmock.NewRows([]string{"acquired"}).AddRow(false))
	leadership, acquired, err := store.TryAcquireControllerLeadership(context.Background())
	if err != nil || acquired || leadership != nil {
		t.Fatalf("leadership=%+v acquired=%v err=%v", leadership, acquired, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPromoteControllerEpochFencesBrowserCredentials(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT generation,signing_key_version FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation", "signing_key_version"}).AddRow(int64(4), int64(2)))
	mock.ExpectQuery(`SELECT gen_random_uuid`).WillReturnRows(
		sqlmock.NewRows([]string{"operation_id", "rebuild_id"}).
			AddRow("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"),
	)
	operationID := "11111111-1111-4111-8111-111111111111"
	rebuildID := "22222222-2222-4222-8222-222222222222"
	mock.ExpectExec(`UPDATE controller_epochs SET state='revoked'`).WithArgs(int64(4), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO controller_epochs`).WithArgs(int64(5), operationID, "manual-promotion", int64(3), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE controller_sessions`).WithArgs(now).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`UPDATE control_tickets`).WithArgs(now).WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(`UPDATE agent_credential_rotations`).WithArgs(int64(4)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE controller_rebuild_operations SET state='failed'`).WithArgs(now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO controller_rebuild_operations`).WithArgs(
		rebuildID, operationID, int64(5), int64(4), "manual-promotion", now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO controller_rebuild_nodes`).WithArgs(rebuildID, now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`(?s)UPDATE nodes SET controller_generation=0,status='offline',connectivity_state='offline'.*capacity_reason_code='controller_generation_promoted'.*connectivity_state='online' AND controller_generation<>\$3`).
		WithArgs(rebuildID, now, int64(5)).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`UPDATE controller_rebuild_operations rebuild SET`).WithArgs(rebuildID, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		int64(5), operationID, int64(4), "manual-promotion", rebuildID,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	generation, err := store.PromoteControllerEpoch(context.Background(), "manual-promotion", now)
	if err != nil || generation != 5 {
		t.Fatalf("generation=%d err=%v", generation, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
