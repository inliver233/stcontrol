package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func recoveryParams(now time.Time) RecoverUserPasswordIdentityParams {
	return RecoverUserPasswordIdentityParams{
		OperationID:      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		UserUUID:         "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		AdminID:          5,
		RequestDigest:    bytes.Repeat([]byte{1}, 32),
		PasswordHash:     "bcrypt-hash",
		NodePasswordHash: "durable-node-hash",
		NodePasswordSalt: "durable-node-salt",
		Now:              now,
	}
}

func expectNewRecoveryPrefix(
	mock sqlmock.Sqlmock,
	p RecoverUserPasswordIdentityParams,
	globalStatus, legacyStatus string,
) {
	mock.ExpectBegin()
	mock.ExpectQuery(`FROM identity_recovery_operations recovery`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{
			"admin_id", "request_digest", "password_version", "staged_node_count", "global_user_id",
			"legacy_user_id", "uuid", "username", "status",
		}))
	mock.ExpectQuery(`SELECT id FROM admins`).WithArgs(p.AdminID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.AdminID))
	mock.ExpectQuery(`SELECT global_user.id,global_user.legacy_user_id`).WithArgs(p.UserUUID).
		WillReturnRows(sqlmock.NewRows([]string{
			"global_user_id", "legacy_user_id", "uuid", "username", "global_status", "legacy_status",
		}).AddRow(int64(70), int64(7), p.UserUUID, "alice", globalStatus, legacyStatus))
}

func expectRecoverySuffix(
	mock sqlmock.Sqlmock,
	p RecoverUserPasswordIdentityParams,
	passwordVersion int64,
	stagedNodes int64,
	resultStatus string,
) {
	mock.ExpectExec(`UPDATE users SET password_enc=NULL`).WithArgs(int64(7), p.PasswordHash, resultStatus).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE global_users SET status`).WithArgs(int64(70), resultStatus, p.Now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE node_accounts`).WithArgs(
		int64(70), p.NodePasswordHash, p.NodePasswordSalt, p.Now,
	).WillReturnResult(sqlmock.NewResult(0, stagedNodes))
	mock.ExpectExec(`UPDATE controller_sessions`).WithArgs(int64(70), p.Now).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectQuery(`INSERT INTO identity_recovery_operations`).WithArgs(
		p.OperationID, int64(70), p.AdminID, p.RequestDigest, passwordVersion, int(stagedNodes), p.Now,
	).WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(4)))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		p.AdminID, p.UserUUID, p.OperationID, int64(4), p.RequestDigest, passwordVersion, int(stagedNodes),
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

func TestRecoverUserPasswordIdentityCreatesMissingIdentityAndStagesAllNodes(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 5, 0, 0, 0, time.UTC)
	p := recoveryParams(now)
	expectNewRecoveryPrefix(mock, p, "recovering", "recovering")
	mock.ExpectQuery(`SELECT id,password_version FROM auth_identities`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "password_version"}))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM auth_identities`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	mock.ExpectQuery(`SELECT user_id FROM auth_identities`).WithArgs(int64(70), "password", "alice").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
	mock.ExpectExec(`INSERT INTO auth_identities`).WithArgs(
		int64(70), "alice", p.PasswordHash, int64(1), now,
	).WillReturnResult(sqlmock.NewResult(91, 1))
	expectRecoverySuffix(mock, p, 1, 2, "active")

	result, err := st.RecoverUserPasswordIdentity(context.Background(), p)
	if err != nil || result.GlobalUserID != 70 || result.LegacyUserID != 7 ||
		result.PasswordVersion != 1 || result.StagedNodeCount != 2 || result.Replayed ||
		result.UserStatus != "active" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	assertMockExpectations(t, mock)
}

func TestRecoverUserPasswordIdentityResetsExistingPasswordAndPreservesDisabled(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 5, 5, 0, 0, time.UTC)
	p := recoveryParams(now)
	expectNewRecoveryPrefix(mock, p, "disabled", "active")
	mock.ExpectQuery(`SELECT id,password_version FROM auth_identities`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "password_version"}).AddRow(int64(91), int64(3)))
	mock.ExpectQuery(`UPDATE auth_identities`).WithArgs(int64(91), p.PasswordHash, now).
		WillReturnRows(sqlmock.NewRows([]string{"password_version"}).AddRow(int64(4)))
	expectRecoverySuffix(mock, p, 4, 1, "disabled")

	result, err := st.RecoverUserPasswordIdentity(context.Background(), p)
	if err != nil || result.PasswordVersion != 4 || result.UserStatus != "disabled" ||
		result.StagedNodeCount != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	assertMockExpectations(t, mock)
}

func TestRecoverUserPasswordIdentityReplaysOnlyMatchingDigestAndPrincipal(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := recoveryParams(time.Date(2026, 8, 8, 5, 10, 0, 0, time.UTC))

	mock.ExpectBegin()
	mock.ExpectQuery(`FROM identity_recovery_operations recovery`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{
			"admin_id", "request_digest", "password_version", "staged_node_count", "global_user_id",
			"legacy_user_id", "uuid", "username", "status",
		}).AddRow(p.AdminID, p.RequestDigest, int64(2), 3, int64(70), int64(7), p.UserUUID, "alice", "active"))
	mock.ExpectCommit()
	result, err := st.RecoverUserPasswordIdentity(context.Background(), p)
	if err != nil || !result.Replayed || result.PasswordVersion != 2 || result.StagedNodeCount != 3 {
		t.Fatalf("result=%+v err=%v", result, err)
	}

	p.RequestDigest = bytes.Repeat([]byte{9}, 32)
	mock.ExpectBegin()
	mock.ExpectQuery(`FROM identity_recovery_operations recovery`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{
			"admin_id", "request_digest", "password_version", "staged_node_count", "global_user_id",
			"legacy_user_id", "uuid", "username", "status",
		}).AddRow(p.AdminID, bytes.Repeat([]byte{1}, 32), int64(2), 3, int64(70), int64(7), p.UserUUID, "alice", "active"))
	mock.ExpectRollback()
	_, err = st.RecoverUserPasswordIdentity(context.Background(), p)
	if !errors.Is(err, ErrIdentityRecoveryConflict) {
		t.Fatalf("error=%v, want conflict", err)
	}
	assertMockExpectations(t, mock)
}

func TestRecoverUserPasswordIdentityRejectsInvalidInputWithoutDatabaseAccess(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := recoveryParams(time.Now().UTC())
	p.UserUUID = "alice"
	_, err := st.RecoverUserPasswordIdentity(context.Background(), p)
	if !errors.Is(err, ErrInvalidIdentityRecovery) {
		t.Fatalf("error=%v, want invalid input", err)
	}
	assertMockExpectations(t, mock)
}

func TestRecoverUserPasswordIdentityRollsBackWithoutActiveController(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 5, 15, 0, 0, time.UTC)
	p := recoveryParams(now)
	expectNewRecoveryPrefix(mock, p, "active", "active")
	mock.ExpectQuery(`SELECT id,password_version FROM auth_identities`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "password_version"}).AddRow(int64(91), int64(1)))
	mock.ExpectQuery(`UPDATE auth_identities`).WithArgs(int64(91), p.PasswordHash, now).
		WillReturnRows(sqlmock.NewRows([]string{"password_version"}).AddRow(int64(2)))
	mock.ExpectExec(`UPDATE users SET password_enc=NULL`).WithArgs(int64(7), p.PasswordHash, "active").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE global_users SET status`).WithArgs(int64(70), "active", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE node_accounts`).WithArgs(
		int64(70), p.NodePasswordHash, p.NodePasswordSalt, now,
	).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`UPDATE controller_sessions`).WithArgs(int64(70), now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectQuery(`INSERT INTO identity_recovery_operations`).WithArgs(
		p.OperationID, int64(70), p.AdminID, p.RequestDigest, int64(2), 2, now,
	).WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}))
	mock.ExpectRollback()

	_, err := st.RecoverUserPasswordIdentity(context.Background(), p)
	if !errors.Is(err, ErrNoActiveController) {
		t.Fatalf("error=%v, want no active controller", err)
	}
	assertMockExpectations(t, mock)
}

func TestIdentityRecoveryModelsNeverSerializeCredentialMaterial(t *testing.T) {
	t.Parallel()
	encoded, err := json.Marshal(recoveryParams(time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"bcrypt-hash", "durable-node-hash", "durable-node-salt"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("serialized recovery params leaked %q: %s", secret, encoded)
		}
	}
}
