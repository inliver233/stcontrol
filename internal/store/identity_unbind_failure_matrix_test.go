package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func expectUnbindPasswordFailureAt(mock sqlmock.Sqlmock, now time.Time, stage string, injected error) {
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(70))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	revoke := mock.ExpectExec(`UPDATE auth_identities SET status='revoked'`)
	if stage == "revoke" {
		revoke.WillReturnError(injected)
		return
	}
	if stage == "revoke rows" {
		revoke.WillReturnResult(sqlmock.NewErrorResult(injected))
		return
	}
	revoke.WillReturnResult(sqlmock.NewResult(0, 1))
	accounts := mock.ExpectExec(`UPDATE node_accounts SET password_hash=NULL`)
	if stage == "accounts" {
		accounts.WillReturnError(injected)
		return
	}
	accounts.WillReturnResult(sqlmock.NewResult(0, 1))
	removals := mock.ExpectExec(`INSERT INTO node_account_password_removals`)
	if stage == "removals" {
		removals.WillReturnError(injected)
		return
	}
	removals.WillReturnResult(sqlmock.NewResult(0, 1))
	next := mock.ExpectQuery(`SELECT provider,provider_subject,password_hash`)
	if stage == "next identity" {
		next.WillReturnError(injected)
		return
	}
	next.WillReturnRows(sqlmock.NewRows([]string{"provider", "provider_subject", "password_hash"}).
		AddRow("discord", "subject", nil))
	legacy := mock.ExpectExec(`UPDATE users SET auth_provider`)
	if stage == "legacy user" {
		legacy.WillReturnError(injected)
		return
	}
	if stage == "legacy rows" {
		legacy.WillReturnResult(sqlmock.NewErrorResult(injected))
		return
	}
	legacy.WillReturnResult(sqlmock.NewResult(0, 1))
	if stage != "commit" {
		panic("unhandled password identity unbind stage: " + stage)
	}
	mock.ExpectCommit().WillReturnError(injected)
}

func TestUnbindPasswordIdentityRollsBackEveryProjectionFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 10, 10, 0, 0, time.UTC)
	injected := errors.New("injected identity unbind failure")
	for _, stage := range []string{
		"revoke", "revoke rows", "accounts", "removals", "next identity", "legacy user", "legacy rows", "commit",
	} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			expectUnbindPasswordFailureAt(mock, now, stage, injected)
			if stage != "commit" {
				mock.ExpectRollback()
			}
			err := st.UnbindUserIdentity(context.Background(), 7, 70, "password", now)
			if !errors.Is(err, injected) {
				t.Fatalf("stage=%q error=%v", stage, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestUnbindIdentityFencesCountSubjectAndAffectedRowFailures(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 10, 15, 0, 0, time.UTC)
	injected := errors.New("injected identity unbind precondition failure")
	for _, tc := range []struct {
		name  string
		setup func(sqlmock.Sqlmock)
		want  error
	}{
		{
			name: "begin", setup: func(mock sqlmock.Sqlmock) { mock.ExpectBegin().WillReturnError(injected) }, want: injected,
		},
		{
			name: "count", setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(70))
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WillReturnError(injected)
				mock.ExpectRollback()
			}, want: injected,
		},
		{
			name: "OAuth identity missing", setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(70))
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
				mock.ExpectQuery(`SELECT provider_subject FROM auth_identities`).WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			}, want: ErrInvalidIdentity,
		},
		{
			name: "OAuth identity lookup", setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(70))
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
				mock.ExpectQuery(`SELECT provider_subject FROM auth_identities`).WillReturnError(injected)
				mock.ExpectRollback()
			}, want: injected,
		},
		{
			name: "zero revoke", setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(70))
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
				mock.ExpectQuery(`SELECT provider_subject FROM auth_identities`).WillReturnRows(sqlmock.NewRows([]string{"subject"}).AddRow("subject"))
				mock.ExpectExec(`UPDATE auth_identities SET status='revoked'`).WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectRollback()
			}, want: ErrInvalidIdentity,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			tc.setup(mock)
			err := st.UnbindUserIdentity(context.Background(), 7, 70, "discord", now)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestUnbindOAuthIdentityRollsBackNodeConvergenceFailures(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 10, 20, 0, 0, time.UTC)
	injected := errors.New("injected OAuth unbind convergence failure")
	for _, stage := range []string{"accounts", "sync"} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT id FROM global_users`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(70))
			mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
			mock.ExpectQuery(`SELECT provider_subject FROM auth_identities`).WillReturnRows(sqlmock.NewRows([]string{"subject"}).AddRow("subject"))
			mock.ExpectExec(`UPDATE auth_identities SET status='revoked'`).WillReturnResult(sqlmock.NewResult(0, 1))
			accounts := mock.ExpectExec(`UPDATE node_accounts SET oauth_subjects`)
			if stage == "accounts" {
				accounts.WillReturnError(injected)
			} else {
				accounts.WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`INSERT INTO node_account_oauth_syncs`).WillReturnError(injected)
			}
			mock.ExpectRollback()
			err := st.UnbindUserIdentity(context.Background(), 7, 70, "discord", now)
			if !errors.Is(err, injected) {
				t.Fatalf("stage=%q error=%v", stage, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}
