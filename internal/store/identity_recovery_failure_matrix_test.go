package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func expectExistingIdentityRecoveryFailureAt(
	mock sqlmock.Sqlmock,
	p RecoverUserPasswordIdentityParams,
	stage string,
	injected error,
) {
	expectNewRecoveryPrefix(mock, p, "active", "active")
	identity := mock.ExpectQuery(`SELECT id,password_version FROM auth_identities`).WithArgs(int64(70))
	if stage == "identity lookup" {
		identity.WillReturnError(injected)
		return
	}
	identity.WillReturnRows(sqlmock.NewRows([]string{"id", "password_version"}).AddRow(int64(91), int64(3)))
	updateIdentity := mock.ExpectQuery(`UPDATE auth_identities`).WithArgs(int64(91), p.PasswordHash, p.Now)
	if stage == "identity update" {
		updateIdentity.WillReturnError(injected)
		return
	}
	updateIdentity.WillReturnRows(sqlmock.NewRows([]string{"password_version"}).AddRow(int64(4)))
	legacy := mock.ExpectExec(`UPDATE users SET password_enc=NULL`).WithArgs(int64(7), p.PasswordHash, "active")
	if stage == "legacy user" {
		legacy.WillReturnError(injected)
		return
	}
	legacy.WillReturnResult(sqlmock.NewResult(0, 1))
	global := mock.ExpectExec(`UPDATE global_users SET status`).WithArgs(int64(70), "active", p.Now)
	if stage == "global user" {
		global.WillReturnError(injected)
		return
	}
	global.WillReturnResult(sqlmock.NewResult(0, 1))
	material := mock.ExpectExec(`UPDATE node_accounts`).WithArgs(
		int64(70), p.NodePasswordHash, p.NodePasswordSalt, p.Now,
	)
	if stage == "node material" {
		material.WillReturnError(injected)
		return
	}
	if stage == "node count" {
		material.WillReturnResult(sqlmock.NewErrorResult(injected))
	} else {
		material.WillReturnResult(sqlmock.NewResult(0, 2))
	}
	clearRemoval := mock.ExpectExec(`UPDATE node_account_password_removals`).WithArgs(int64(70), p.Now)
	if stage == "clear removal" {
		clearRemoval.WillReturnError(injected)
		return
	}
	clearRemoval.WillReturnResult(sqlmock.NewResult(0, 1))
	if stage == "node count" {
		return
	}
	sessions := mock.ExpectExec(`UPDATE controller_sessions`).WithArgs(int64(70), p.Now)
	if stage == "sessions" {
		sessions.WillReturnError(injected)
		return
	}
	sessions.WillReturnResult(sqlmock.NewResult(0, 2))
	operation := mock.ExpectQuery(`INSERT INTO identity_recovery_operations`).WithArgs(
		p.OperationID, int64(70), p.AdminID, p.RequestDigest, int64(4), 2, p.Now,
	)
	if stage == "operation" {
		operation.WillReturnError(injected)
		return
	}
	operation.WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(4)))
	audit := mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		p.AdminID, p.UserUUID, p.OperationID, int64(4), p.RequestDigest, int64(4), 2,
	)
	if stage == "audit" {
		audit.WillReturnError(injected)
		return
	}
	audit.WillReturnResult(sqlmock.NewResult(0, 1))
	if stage != "commit" {
		panic("unhandled identity recovery failure stage: " + stage)
	}
	mock.ExpectCommit().WillReturnError(injected)
}

func TestRecoverUserPasswordIdentityFencesLookupAndReplayFailures(t *testing.T) {
	t.Parallel()
	injected := errors.New("injected identity recovery failure")
	now := time.Date(2026, 8, 24, 9, 10, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		setup func(sqlmock.Sqlmock, RecoverUserPasswordIdentityParams)
		want  error
	}{
		{
			name: "begin",
			setup: func(mock sqlmock.Sqlmock, _ RecoverUserPasswordIdentityParams) {
				mock.ExpectBegin().WillReturnError(injected)
			},
			want: injected,
		},
		{
			name: "operation lookup",
			setup: func(mock sqlmock.Sqlmock, p RecoverUserPasswordIdentityParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`FROM identity_recovery_operations recovery`).WithArgs(p.OperationID).
					WillReturnError(injected)
				mock.ExpectRollback()
			},
			want: injected,
		},
		{
			name: "inactive admin",
			setup: func(mock sqlmock.Sqlmock, p RecoverUserPasswordIdentityParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`FROM identity_recovery_operations recovery`).WillReturnError(sql.ErrNoRows)
				mock.ExpectQuery(`SELECT id FROM admins`).WithArgs(p.AdminID).WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			},
			want: ErrInvalidIdentityRecovery,
		},
		{
			name: "admin lookup",
			setup: func(mock sqlmock.Sqlmock, p RecoverUserPasswordIdentityParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`FROM identity_recovery_operations recovery`).WillReturnError(sql.ErrNoRows)
				mock.ExpectQuery(`SELECT id FROM admins`).WithArgs(p.AdminID).WillReturnError(injected)
				mock.ExpectRollback()
			},
			want: injected,
		},
		{
			name: "user missing",
			setup: func(mock sqlmock.Sqlmock, p RecoverUserPasswordIdentityParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`FROM identity_recovery_operations recovery`).WillReturnError(sql.ErrNoRows)
				mock.ExpectQuery(`SELECT id FROM admins`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.AdminID))
				mock.ExpectQuery(`SELECT global_user.id,global_user.legacy_user_id`).WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			},
			want: ErrInvalidIdentityRecovery,
		},
		{
			name: "user lookup",
			setup: func(mock sqlmock.Sqlmock, p RecoverUserPasswordIdentityParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`FROM identity_recovery_operations recovery`).WillReturnError(sql.ErrNoRows)
				mock.ExpectQuery(`SELECT id FROM admins`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.AdminID))
				mock.ExpectQuery(`SELECT global_user.id,global_user.legacy_user_id`).WillReturnError(injected)
				mock.ExpectRollback()
			},
			want: injected,
		},
		{
			name: "replay commit",
			setup: func(mock sqlmock.Sqlmock, p RecoverUserPasswordIdentityParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`FROM identity_recovery_operations recovery`).WithArgs(p.OperationID).
					WillReturnRows(sqlmock.NewRows([]string{
						"admin_id", "request_digest", "password_version", "staged_node_count", "global_user_id",
						"legacy_user_id", "uuid", "username", "status",
					}).AddRow(p.AdminID, p.RequestDigest, int64(2), 3, int64(70), int64(7), p.UserUUID, "alice", "active"))
				mock.ExpectCommit().WillReturnError(injected)
			},
			want: injected,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := recoveryParams(now)
			tc.setup(mock, p)
			_, err := st.RecoverUserPasswordIdentity(context.Background(), p)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestRecoverUserPasswordIdentityRollsBackEveryCredentialPublicationFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 9, 15, 0, 0, time.UTC)
	injected := errors.New("injected identity recovery failure")
	for _, stage := range []string{
		"identity lookup", "identity update", "legacy user", "global user", "node material",
		"clear removal", "node count", "sessions", "operation", "audit", "commit",
	} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := recoveryParams(now)
			expectExistingIdentityRecoveryFailureAt(mock, p, stage, injected)
			if stage != "commit" {
				mock.ExpectRollback()
			}
			_, err := st.RecoverUserPasswordIdentity(context.Background(), p)
			if !errors.Is(err, injected) {
				t.Fatalf("stage=%q error=%v", stage, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestRecoverUserPasswordIdentityFencesMissingIdentitySlotFailures(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 9, 20, 0, 0, time.UTC)
	injected := errors.New("injected identity slot failure")
	for _, tc := range []struct {
		name  string
		setup func(sqlmock.Sqlmock)
		want  error
	}{
		{
			name: "count lookup",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WillReturnError(injected)
			},
			want: injected,
		},
		{
			name: "identity limit",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
			},
			want: ErrIdentityRecoveryConflict,
		},
		{
			name: "slot lookup",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
				mock.ExpectQuery(`SELECT user_id FROM auth_identities`).WillReturnError(injected)
			},
			want: injected,
		},
		{
			name: "identity insert",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
				mock.ExpectQuery(`SELECT user_id FROM auth_identities`).WillReturnError(sql.ErrNoRows)
				mock.ExpectExec(`INSERT INTO auth_identities`).WillReturnError(injected)
			},
			want: injected,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := recoveryParams(now)
			expectNewRecoveryPrefix(mock, p, "active", "active")
			mock.ExpectQuery(`SELECT id,password_version FROM auth_identities`).WillReturnError(sql.ErrNoRows)
			tc.setup(mock)
			mock.ExpectRollback()
			_, err := st.RecoverUserPasswordIdentity(context.Background(), p)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
			assertMockExpectations(t, mock)
		})
	}
}
