package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPasswordFallbackHashAcceptsPreviousWhileSyncIncomplete(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT identity.previous_password_hash`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"previous_password_hash", "password_changed_at", "incomplete"}).
			AddRow("previous-bcrypt", now.Add(-time.Hour), true))
	hash, err := st.PasswordFallbackHash(context.Background(), 70, now)
	if err != nil || hash != "previous-bcrypt" {
		t.Fatalf("hash=%q err=%v", hash, err)
	}
	assertMockExpectations(t, mock)
}

func TestPasswordFallbackHashDropsAfterNodeConvergence(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT identity.previous_password_hash`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"previous_password_hash", "password_changed_at", "incomplete"}).
			AddRow("previous-bcrypt", now.Add(-time.Hour), false))
	hash, err := st.PasswordFallbackHash(context.Background(), 70, now)
	if err != nil || hash != "" {
		t.Fatalf("hash=%q err=%v, want empty after convergence", hash, err)
	}
	assertMockExpectations(t, mock)
}

func TestPasswordFallbackHashDropsAfterWindowElapsed(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	// Change happened more than passwordFallbackWindow ago, still incomplete.
	mock.ExpectQuery(`SELECT identity.previous_password_hash`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"previous_password_hash", "password_changed_at", "incomplete"}).
			AddRow("previous-bcrypt", now.Add(-passwordFallbackWindow-time.Hour), true))
	hash, err := st.PasswordFallbackHash(context.Background(), 70, now)
	if err != nil || hash != "" {
		t.Fatalf("hash=%q err=%v, want empty after window", hash, err)
	}
	assertMockExpectations(t, mock)
}

func TestPasswordFallbackHashReturnsEmptyWithoutPrevious(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT identity.previous_password_hash`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"previous_password_hash", "password_changed_at", "incomplete"}).
			AddRow(nil, nil, true))
	hash, err := st.PasswordFallbackHash(context.Background(), 70, now)
	if err != nil || hash != "" {
		t.Fatalf("hash=%q err=%v, want empty without previous", hash, err)
	}
	assertMockExpectations(t, mock)
}

func TestClearPasswordFallbackIfConverged(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	mock.ExpectExec(`UPDATE auth_identities identity`).WithArgs(int64(70), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.ClearPasswordFallbackIfConverged(context.Background(), 70, now); err != nil {
		t.Fatalf("ClearPasswordFallbackIfConverged: %v", err)
	}
	assertMockExpectations(t, mock)
}

func TestListPendingPasswordRemovals(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT global_user.legacy_user_id`).WithArgs(20, now.Add(-2*time.Minute)).
		WillReturnRows(sqlmock.NewRows([]string{"legacy_user_id", "global_user_id", "node_id", "local_handle"}).
			AddRow(int64(7), int64(70), int64(12), "alice"))
	removals, err := st.ListPendingPasswordRemovals(context.Background(), 20, now)
	if err != nil || len(removals) != 1 || removals[0].LocalHandle != "alice" ||
		removals[0].GlobalUserID != 70 || removals[0].LegacyUserID != 7 {
		t.Fatalf("removals=%+v err=%v", removals, err)
	}
	assertMockExpectations(t, mock)
}

func TestActivatePasswordRemovalAndMarkError(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	mock.ExpectExec(`UPDATE node_account_password_removals`).
		WithArgs(int64(70), int64(12), now).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.ActivatePasswordRemoval(context.Background(), 70, 12, now); err != nil {
		t.Fatalf("ActivatePasswordRemoval: %v", err)
	}
	mock.ExpectExec(`UPDATE node_account_password_removals`).
		WithArgs(int64(70), int64(12), now).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.MarkPasswordRemovalError(context.Background(), 70, 12, now); err != nil {
		t.Fatalf("MarkPasswordRemovalError: %v", err)
	}
	assertMockExpectations(t, mock)
}
