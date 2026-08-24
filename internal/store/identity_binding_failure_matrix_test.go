package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func expectOAuthIdentitySlot(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(`SELECT user_id FROM auth_identities`).WithArgs(int64(70), "discord", "subject-1").
		WillReturnError(sql.ErrNoRows)
}

func TestBindOAuthIdentityFencesSlotAndPublicationFailures(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	injected := errors.New("injected OAuth identity binding failure")
	for _, tc := range []struct {
		name  string
		setup func(sqlmock.Sqlmock)
		want  error
	}{
		{
			name: "begin", setup: func(mock sqlmock.Sqlmock) { mock.ExpectBegin().WillReturnError(injected) }, want: injected,
		},
		{
			name: "user missing", setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			}, want: ErrInvalidIdentity,
		},
		{
			name: "user lookup", setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WillReturnError(injected)
				mock.ExpectRollback()
			}, want: injected,
		},
		{
			name: "identity count", setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(70))
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WillReturnError(injected)
				mock.ExpectRollback()
			}, want: injected,
		},
		{
			name: "identity limit", setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(70))
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
				mock.ExpectRollback()
			}, want: ErrIdentityConflict,
		},
		{
			name: "slot occupied", setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(70))
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
				mock.ExpectQuery(`SELECT user_id FROM auth_identities`).WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow(80))
				mock.ExpectRollback()
			}, want: ErrIdentityConflict,
		},
		{
			name: "slot lookup", setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(70))
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
				mock.ExpectQuery(`SELECT user_id FROM auth_identities`).WillReturnError(injected)
				mock.ExpectRollback()
			}, want: injected,
		},
		{
			name: "identity insert", setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectOAuthIdentitySlot(mock)
				mock.ExpectExec(`INSERT INTO auth_identities`).WillReturnError(injected)
				mock.ExpectRollback()
			}, want: injected,
		},
		{
			name: "node projection", setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectOAuthIdentitySlot(mock)
				mock.ExpectExec(`INSERT INTO auth_identities`).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`UPDATE node_accounts SET`).WillReturnError(injected)
				mock.ExpectRollback()
			}, want: injected,
		},
		{
			name: "node sync", setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectOAuthIdentitySlot(mock)
				mock.ExpectExec(`INSERT INTO auth_identities`).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`UPDATE node_accounts SET`).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`INSERT INTO node_account_oauth_syncs`).WillReturnError(injected)
				mock.ExpectRollback()
			}, want: injected,
		},
		{
			name: "commit", setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectOAuthIdentitySlot(mock)
				mock.ExpectExec(`INSERT INTO auth_identities`).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`UPDATE node_accounts SET`).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`INSERT INTO node_account_oauth_syncs`).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit().WillReturnError(injected)
			}, want: injected,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			tc.setup(mock)
			err := st.BindOAuthIdentity(context.Background(), 70, "discord", "subject-1", now)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func expectPasswordIdentityPrefix(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT legacy.username`).WithArgs(int64(70), int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"username"}).AddRow("alice"))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(`SELECT user_id FROM auth_identities`).WillReturnError(sql.ErrNoRows)
}

func TestBindPasswordIdentityRollsBackEveryPublicationFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 10, 5, 0, 0, time.UTC)
	injected := errors.New("injected password identity binding failure")
	for _, stage := range []string{"identity", "legacy user", "node material", "clear removal", "commit"} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			expectPasswordIdentityPrefix(mock)
			identity := mock.ExpectExec(`INSERT INTO auth_identities`)
			if stage == "identity" {
				identity.WillReturnError(injected)
			} else {
				identity.WillReturnResult(sqlmock.NewResult(0, 1))
				legacy := mock.ExpectExec(`UPDATE users SET password_enc=NULL`)
				if stage == "legacy user" {
					legacy.WillReturnError(injected)
				} else {
					legacy.WillReturnResult(sqlmock.NewResult(0, 1))
					material := mock.ExpectExec(`UPDATE node_accounts`)
					if stage == "node material" {
						material.WillReturnError(injected)
					} else {
						material.WillReturnResult(sqlmock.NewResult(0, 1))
						clear := mock.ExpectExec(`UPDATE node_account_password_removals`)
						if stage == "clear removal" {
							clear.WillReturnError(injected)
						} else {
							clear.WillReturnResult(sqlmock.NewResult(0, 1))
							mock.ExpectCommit().WillReturnError(injected)
						}
					}
				}
			}
			if stage != "commit" {
				mock.ExpectRollback()
			}
			err := st.BindPasswordIdentity(
				context.Background(), 7, 70, "bcrypt-hash", "node-hash", "node-salt", now,
			)
			if !errors.Is(err, injected) {
				t.Fatalf("stage=%q error=%v", stage, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestBindPasswordIdentityFencesMissingLegacyProjection(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{name: "missing", err: sql.ErrNoRows, want: ErrInvalidIdentity},
		{name: "lookup", err: errors.New("lookup failed"), want: errors.New("lookup failed")},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT legacy.username`).WillReturnError(tc.err)
			mock.ExpectRollback()
			err := st.BindPasswordIdentity(context.Background(), 7, 70, "bcrypt", "node", "salt", time.Now())
			if tc.name == "missing" {
				if !errors.Is(err, tc.want) {
					t.Fatalf("error=%v", err)
				}
			} else if err == nil || err.Error() != tc.err.Error() {
				t.Fatalf("error=%v", err)
			}
			assertMockExpectations(t, mock)
		})
	}
}
