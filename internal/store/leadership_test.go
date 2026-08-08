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
	mock.ExpectExec(`(?s)UPDATE controller_epochs SET state='revoked'.*UPDATE controller_sessions.*UPDATE control_tickets.*UPDATE nodes`).
		WithArgs(int64(4), now, int64(5), "manual-promotion", int64(3)).
		WillReturnResult(sqlmock.NewResult(0, 4))
	mock.ExpectCommit()
	generation, err := store.PromoteControllerEpoch(context.Background(), "manual-promotion", now)
	if err != nil || generation != 5 {
		t.Fatalf("generation=%d err=%v", generation, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
