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

func TestPasswordRemovalVersionMigrationCancelsUnsafeLegacyIntent(t *testing.T) {
	t.Parallel()
	sqlText, err := os.ReadFile(filepath.Join("migrations", "0049_password_removal_version.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"account.password_hash IS NULL",
		"account.password_salt IS NULL",
		"account.password_material_version>0",
		"SET state='completed',updated_at=now()",
		"AND NOT EXISTS (",
	} {
		if !strings.Contains(string(sqlText), required) {
			t.Fatalf("password-removal migration missing %q", required)
		}
	}
}

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
	mock.ExpectQuery(`(?s)SELECT global_user.legacy_user_id.*JOIN node_accounts account.*account.password_material_version=removal.password_material_version.*account.password_hash IS NULL AND account.password_salt IS NULL.*node.connectivity_state='online'.*node.controller_generation=\(SELECT generation FROM controller_epochs`).
		WithArgs(20, now.Add(-2*time.Minute)).
		WillReturnRows(sqlmock.NewRows([]string{
			"legacy_user_id", "global_user_id", "node_id", "local_handle", "password_material_version",
		}).AddRow(int64(7), int64(70), int64(12), "alice", int64(3)))
	removals, err := st.ListPendingPasswordRemovals(context.Background(), 20, now)
	if err != nil || len(removals) != 1 || removals[0].LocalHandle != "alice" ||
		removals[0].GlobalUserID != 70 || removals[0].LegacyUserID != 7 || removals[0].Version != 3 {
		t.Fatalf("removals=%+v err=%v", removals, err)
	}
	assertMockExpectations(t, mock)
}

func TestListPendingPasswordRemovalsReturnsNoRowsForReboundMaterial(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 12, 5, 0, 0, time.UTC)
	mock.ExpectQuery(`(?s)JOIN node_accounts account.*account.password_material_version=removal.password_material_version.*account.password_hash IS NULL`).
		WithArgs(20, now.Add(-passwordRemovalBackoff)).
		WillReturnRows(sqlmock.NewRows([]string{
			"legacy_user_id", "global_user_id", "node_id", "local_handle", "password_material_version",
		}))
	removals, err := st.ListPendingPasswordRemovals(context.Background(), 20, now)
	if err != nil || len(removals) != 0 {
		t.Fatalf("removals=%+v err=%v, want stale intent filtered", removals, err)
	}
	assertMockExpectations(t, mock)
}

func TestActivatePasswordRemovalAndMarkError(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	mock.ExpectExec(`UPDATE node_account_password_removals`).
		WithArgs(int64(70), int64(12), int64(3), now).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.ActivatePasswordRemoval(context.Background(), 70, 12, 3, now); err != nil {
		t.Fatalf("ActivatePasswordRemoval: %v", err)
	}
	mock.ExpectExec(`UPDATE node_account_password_removals`).
		WithArgs(int64(70), int64(12), int64(3), now).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.MarkPasswordRemovalError(context.Background(), 70, 12, 3, now); err != nil {
		t.Fatalf("MarkPasswordRemovalError: %v", err)
	}
	assertMockExpectations(t, mock)
}
