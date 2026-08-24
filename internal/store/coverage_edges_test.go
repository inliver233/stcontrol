package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
)

func TestUserLookupDeletionAndHomeNodeMutations(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	ctx := context.Background()
	createdAt := time.Date(2026, 8, 24, 3, 0, 0, 0, time.UTC)
	uuid := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if user, err := st.GetUserByUUID(ctx, ""); err != nil || user != nil {
		t.Fatalf("empty UUID user=%+v err=%v", user, err)
	}
	mock.ExpectQuery(`WHERE gu.uuid=\$1`).WithArgs(uuid).WillReturnRows(sqlmock.NewRows([]string{
		"id", "global_id", "uuid", "username", "display_name", "password_enc", "password_hash",
		"auth_provider", "oauth_id", "avatar_url", "email", "home_node_id", "status", "created_at",
	}).AddRow(int64(7), int64(70), uuid, "alice", "Alice", nil, "hash", "password", nil, nil, nil, int64(9), "active", createdAt))
	user, err := st.GetUserByUUID(ctx, uuid)
	if err != nil || user == nil || user.GlobalID != 70 || user.Username != "alice" {
		t.Fatalf("user=%+v err=%v", user, err)
	}
	mock.ExpectQuery(`WHERE gu.uuid=\$1`).WithArgs("missing").WillReturnRows(sqlmock.NewRows([]string{
		"id", "global_id", "uuid", "username", "display_name", "password_enc", "password_hash",
		"auth_provider", "oauth_id", "avatar_url", "email", "home_node_id", "status", "created_at",
	}))
	if user, err := st.GetUserByUUID(ctx, "missing"); err != nil || user != nil {
		t.Fatalf("missing UUID user=%+v err=%v", user, err)
	}

	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM global_users`).WithArgs(int64(7)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM users`).WithArgs(int64(7)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.DeleteUser(ctx, 7); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	mock.ExpectExec(`UPDATE users SET home_node_id`).WithArgs(int64(7), int64(9)).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.SetUserHomeNode(ctx, 7, 9); err != nil {
		t.Fatalf("SetUserHomeNode: %v", err)
	}
	mock.ExpectExec(`UPDATE user_replicas SET state`).WithArgs(int64(70), int64(9), "ready", int64(4), "digest", int64(128), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.UpdateReplicaState(ctx, 70, 9, "ready", 4, "digest", 128); err != nil {
		t.Fatalf("UpdateReplicaState: %v", err)
	}
	assertMockExpectations(t, mock)
}

func TestFindRunningBackupReturnsRecordMissingAndFailure(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	ctx := context.Background()
	now := time.Now().UTC()
	columns := []string{"id", "user_id", "src_node_id", "dst_node_id", "trigger", "status", "data_version", "bytes", "file_count", "error", "started_at", "finished_at", "created_at"}
	mock.ExpectQuery(`FROM backup_jobs`).WithArgs(int64(7), int64(8)).
		WillReturnRows(sqlmock.NewRows(columns).AddRow(int64(3), int64(7), int64(8), int64(9), "offline", "running", int64(4), int64(128), int64(2), nil, now, nil, now))
	job, err := st.FindRunningBackupForUserOnNode(ctx, 7, 8)
	if err != nil || job == nil || job.ID != 3 || job.Status != "running" {
		t.Fatalf("job=%+v err=%v", job, err)
	}
	mock.ExpectQuery(`FROM backup_jobs`).WithArgs(int64(7), int64(10)).WillReturnRows(sqlmock.NewRows(columns))
	if job, err := st.FindRunningBackupForUserOnNode(ctx, 7, 10); err != nil || job != nil {
		t.Fatalf("missing job=%+v err=%v", job, err)
	}
	dbErr := errors.New("database unavailable")
	mock.ExpectQuery(`FROM backup_jobs`).WithArgs(int64(7), int64(11)).WillReturnError(dbErr)
	if _, err := st.FindRunningBackupForUserOnNode(ctx, 7, 11); !errors.Is(err, dbErr) {
		t.Fatalf("database error=%v", err)
	}
	assertMockExpectations(t, mock)
}

func TestConstraintErrorsMapToStableDomainErrors(t *testing.T) {
	t.Parallel()
	unique := &pq.Error{Code: "23505"}
	foreign := &pq.Error{Code: "23503"}
	if !errors.Is(identityInsertError("insert identity", unique), ErrIdentityConflict) {
		t.Fatal("identity uniqueness did not map to conflict")
	}
	if err := identityInsertError("insert identity", foreign); errors.Is(err, ErrIdentityConflict) || err == nil {
		t.Fatalf("foreign identity error=%v", err)
	}
	if !errors.Is(registrationInsertError(unique), ErrRegistrationConflict) {
		t.Fatal("registration uniqueness did not map to conflict")
	}
	if got := registrationInsertError(sql.ErrNoRows); !errors.Is(got, sql.ErrNoRows) {
		t.Fatalf("registration error=%v", got)
	}
}
