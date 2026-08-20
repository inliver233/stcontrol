package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestListUserIdentitiesReturnsNoProviderSubjects(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 23, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT provider,password_version,status,created_at`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"provider", "password_version", "status", "created_at"}).
			AddRow("password", int64(2), "active", now).AddRow("discord", int64(0), "active", now))
	identities, err := st.ListUserIdentities(context.Background(), 70)
	if err != nil || len(identities) != 2 || identities[1].Provider != "discord" {
		t.Fatalf("identities=%+v err=%v", identities, err)
	}
	assertMockExpectations(t, mock)
}

func TestBindOAuthIdentitySerializesPerUserAndRejectsDuplicates(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 23, 5, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(`SELECT user_id FROM auth_identities`).WithArgs(int64(70), "discord", "subject-1").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
	mock.ExpectExec(`INSERT INTO auth_identities`).WithArgs(int64(70), "discord", "subject-1", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE node_accounts SET oauth_subjects`).WithArgs(int64(70), "discord", "subject-1", now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`INSERT INTO node_account_oauth_syncs`).
		WithArgs(int64(70), "discord", "subject-1", true, now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()
	if err := st.BindOAuthIdentity(context.Background(), 70, "discord", "subject-1", now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestUnbindOAuthIdentityStagesExactSubjectRemoval(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 23, 16, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
	mock.ExpectQuery(`SELECT provider_subject FROM auth_identities`).WithArgs(int64(70), "discord").
		WillReturnRows(sqlmock.NewRows([]string{"provider_subject"}).AddRow("discord-subject"))
	mock.ExpectExec(`UPDATE auth_identities SET status='revoked'`).
		WithArgs(int64(70), "discord", now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE node_accounts SET oauth_subjects`).
		WithArgs(int64(70), "discord", now).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`INSERT INTO node_account_oauth_syncs`).
		WithArgs(int64(70), "discord", "discord-subject", false, now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectQuery(`SELECT provider,provider_subject,password_hash`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"provider", "provider_subject", "password_hash"}).
			AddRow("password", "alice", "bcrypt-hash"))
	mock.ExpectExec(`UPDATE users SET auth_provider`).
		WithArgs(int64(7), "password", nil, sql.NullString{String: "bcrypt-hash", Valid: true}, int64(70)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.UnbindUserIdentity(context.Background(), 7, 70, "discord", now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestBindPasswordIdentityUpdatesNormalizedAndLegacyVerifier(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 23, 10, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT legacy.username`).WithArgs(int64(70), int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"username"}).AddRow("alice"))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(`SELECT user_id FROM auth_identities`).WithArgs(int64(70), "password", "alice").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
	mock.ExpectExec(`INSERT INTO auth_identities`).WithArgs(int64(70), "alice", "bcrypt-hash", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE users SET password_enc=NULL`).WithArgs(int64(7), "bcrypt-hash").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE node_accounts`).WithArgs(int64(70), "node-hash", "node-salt", now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`UPDATE node_account_password_removals`).WithArgs(int64(70), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.BindPasswordIdentity(
		context.Background(), 7, 70, "bcrypt-hash", "node-hash", "node-salt", now,
	); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestUnbindIdentityProtectsLastLoginMethod(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectRollback()
	err := st.UnbindUserIdentity(context.Background(), 7, 70, "password", time.Now())
	if !errors.Is(err, ErrLastIdentity) {
		t.Fatalf("error=%v, want ErrLastIdentity", err)
	}
	assertMockExpectations(t, mock)
}

func TestUnbindIdentityUpdatesLegacyProjectionAtomically(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 23, 15, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	mock.ExpectExec(`UPDATE auth_identities SET status='revoked'`).WithArgs(int64(70), "password", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE node_accounts SET password_hash=NULL`).WithArgs(int64(70), now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`INSERT INTO node_account_password_removals`).
		WithArgs(int64(70), now).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectQuery(`SELECT provider,provider_subject,password_hash`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"provider", "provider_subject", "password_hash"}).
			AddRow("discord", "stable-subject", nil))
	mock.ExpectExec(`UPDATE users SET auth_provider`).
		WithArgs(int64(7), "discord", "stable-subject", sql.NullString{}, int64(70)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.UnbindUserIdentity(context.Background(), 7, 70, "password", now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}
