package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestCreateUserWritesNormalizedFactsWithoutReversiblePassword(t *testing.T) {
	t.Parallel()

	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	createdAt := time.Date(2026, 8, 7, 13, 0, 0, 0, time.UTC)
	user := &User{
		Username:     "alice",
		DisplayName:  "Alice",
		PasswordEnc:  sql.NullString{String: "must-not-be-written", Valid: true},
		PasswordHash: sql.NullString{String: "bcrypt-hash", Valid: true},
		AuthProvider: "password",
		HomeNodeID:   sql.NullInt64{Int64: 12, Valid: true},
		Status:       "active",
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO users .*VALUES \(\$1,\$2,NULL,\$3`).
		WithArgs("alice", "Alice", "bcrypt-hash", "password", nil, nil, nil, int64(12), "active").
		WillReturnRows(sqlmock.NewRows([]string{"id", "uuid", "created_at"}).
			AddRow(int64(7), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", createdAt))
	mock.ExpectQuery(`INSERT INTO global_users`).
		WithArgs("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", int64(7), "Alice", "active", createdAt).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
	mock.ExpectExec(`INSERT INTO auth_identities`).
		WithArgs(int64(70), "password", "alice", "bcrypt-hash").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`INSERT INTO node_accounts`).
		WithArgs(int64(70), int64(12), "alice", "active").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.ID != 7 || user.GlobalID != 70 || user.UUID == "" {
		t.Fatalf("unexpected created user: %+v", user)
	}
	assertMockExpectations(t, mock)
}

func TestCreateUserRejectsPasswordIdentityWithoutHash(t *testing.T) {
	t.Parallel()

	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	createdAt := time.Date(2026, 8, 7, 13, 0, 0, 0, time.UTC)
	user := &User{Username: "alice", DisplayName: "Alice", AuthProvider: "password", Status: "active"}

	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO users`).
		WithArgs("alice", "Alice", nil, "password", nil, nil, nil, nil, "active").
		WillReturnRows(sqlmock.NewRows([]string{"id", "uuid", "created_at"}).
			AddRow(int64(7), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", createdAt))
	mock.ExpectQuery(`INSERT INTO global_users`).
		WithArgs("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", int64(7), "Alice", "active", createdAt).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
	mock.ExpectRollback()

	if err := store.CreateUser(context.Background(), user); err == nil || !strings.Contains(err.Error(), "password hash") {
		t.Fatalf("CreateUser error=%v, want missing password hash", err)
	}
	assertMockExpectations(t, mock)
}

func TestUpdateUserPasswordClearsLegacyCiphertextAndVersionsIdentity(t *testing.T) {
	t.Parallel()

	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 23, 45, 0, 0, time.UTC)

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE users SET password_enc=NULL, password_hash=\$2`).
		WithArgs(int64(7), "new-hash").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`UPDATE auth_identities`).
		WithArgs(int64(7), "new-hash", now).
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow(int64(70)))
	mock.ExpectExec(`UPDATE node_accounts`).
		WithArgs(int64(70), "node-hash", "node-salt", now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`UPDATE node_account_password_removals`).
		WithArgs(int64(70), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := store.UpdateUserPassword(
		context.Background(), 7, "new-hash", "node-hash", "node-salt", now,
	); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}
	assertMockExpectations(t, mock)
}

func TestListUserNodeAccountsIncludesStagedPasswordVersion(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`SELECT account.node_id,account.local_handle,node.status,account.password_material_version`).
		WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{
			"node_id", "local_handle", "node_status", "password_material_version",
		}).AddRow(int64(12), "alice", "online", int64(4)))
	accounts, err := st.ListUserNodeAccounts(context.Background(), 70)
	if err != nil || len(accounts) != 1 || accounts[0].PasswordMaterialVersion != 4 {
		t.Fatalf("accounts=%+v err=%v", accounts, err)
	}
	assertMockExpectations(t, mock)
}

func TestNodeAccountProvisioningVersionsMaterialAndActivatesAtomically(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 19, 30, 0, 0, time.UTC)
	mock.ExpectQuery(`UPDATE node_accounts`).
		WithArgs(int64(70), int64(12), "node-hash", "node-salt", nil, now).
		WillReturnRows(sqlmock.NewRows([]string{"password_material_version"}).AddRow(int64(4)))
	version, err := st.SetNodeAccountProvisioning(
		context.Background(), 70, 12, "node-hash", "node-salt", "", "", now,
	)
	if err != nil || version != 4 {
		t.Fatalf("version=%d err=%v", version, err)
	}

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE node_accounts SET status='active'`).
		WithArgs(int64(70), int64(12), "local-user-id", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE users SET status='active'`).WithArgs(int64(7)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE global_users SET status='active'`).WithArgs(int64(70), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.ActivateNodeAccount(context.Background(), 7, 70, 12, "local-user-id", now); err != nil {
		t.Fatalf("ActivateNodeAccount: %v", err)
	}
	assertMockExpectations(t, mock)
}

func TestOAuthNodeAccountProvisioningHasNoPasswordMaterial(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 19, 30, 0, 0, time.UTC)
	mock.ExpectQuery(`UPDATE node_accounts`).
		WithArgs(int64(70), int64(12), nil, nil, `{"discord":"stable-subject"}`, now).
		WillReturnRows(sqlmock.NewRows([]string{"password_material_version"}).AddRow(int64(0)))
	version, err := st.SetNodeAccountProvisioning(
		context.Background(), 70, 12, "", "", "discord", "stable-subject", now,
	)
	if err != nil || version != 0 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	assertMockExpectations(t, mock)
}

func TestListPendingPasswordSyncsOnlyReturnsDurableRetryMaterial(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 23, 30, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT global_user.legacy_user_id`).WithArgs(20, now.Add(-2*time.Minute)).
		WillReturnRows(sqlmock.NewRows([]string{
			"legacy_user_id", "global_user_id", "node_id", "local_handle",
			"password_hash", "password_salt", "password_material_version",
		}).AddRow(int64(7), int64(70), int64(12), "alice", "node-hash", "node-salt", int64(4)))
	syncs, err := st.ListPendingPasswordSyncs(context.Background(), 20, now)
	if err != nil || len(syncs) != 1 || syncs[0].Version != 4 || syncs[0].PasswordHash != "node-hash" {
		t.Fatalf("syncs=%+v err=%v", syncs, err)
	}
	assertMockExpectations(t, mock)
}

func TestListPendingPasswordSyncsForUserReturnsOnlyDurableStagedMaterial(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`FROM node_accounts account`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{
			"legacy_user_id", "global_user_id", "node_id", "local_handle",
			"password_hash", "password_salt", "password_material_version",
		}).AddRow(int64(7), int64(70), int64(12), "alice", "stored-hash", "stored-salt", int64(5)))
	syncs, err := st.ListPendingPasswordSyncsForUser(context.Background(), 70)
	if err != nil || len(syncs) != 1 || syncs[0].PasswordHash != "stored-hash" ||
		syncs[0].PasswordSalt != "stored-salt" || syncs[0].Version != 5 {
		t.Fatalf("syncs=%+v err=%v", syncs, err)
	}
	assertMockExpectations(t, mock)
}

func TestListPendingPasswordSyncsForUserRejectsInvalidUser(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	if _, err := st.ListPendingPasswordSyncsForUser(context.Background(), 0); err == nil {
		t.Fatal("invalid global user was accepted")
	}
	assertMockExpectations(t, mock)
}

func TestSensitiveModelFieldsAreNeverSerialized(t *testing.T) {
	t.Parallel()

	userJSON, err := json.Marshal(User{
		Username:     "alice",
		PasswordEnc:  sql.NullString{String: "ciphertext", Valid: true},
		PasswordHash: sql.NullString{String: "hash", Valid: true},
		OAuthID:      sql.NullString{String: "oauth-subject", Valid: true},
	})
	if err != nil {
		t.Fatalf("marshal User: %v", err)
	}
	nodeJSON, err := json.Marshal(Node{TransferURL: "https://private-transfer.example"})
	if err != nil {
		t.Fatalf("marshal Node: %v", err)
	}
	serialized := string(userJSON) + string(nodeJSON)
	for _, secret := range []string{"ciphertext", "hash", "oauth-subject", "private-transfer"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("serialized models leaked %q: %s", secret, serialized)
		}
	}
}
