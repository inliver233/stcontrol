package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestAdminBootstrapIsSingleAndTransactional(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 22, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(`LOCK TABLE admins`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM admins`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectExec(`INSERT INTO admins`).WithArgs("admin-one", "bcrypt-hash", now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	created, err := st.BootstrapAdmin(context.Background(), "admin-one", "bcrypt-hash", now)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	assertMockExpectations(t, mock)
}

func TestHasActiveAdmin(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`SELECT EXISTS`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	exists, err := st.HasActiveAdmin(context.Background())
	if err != nil || !exists {
		t.Fatalf("exists=%v err=%v", exists, err)
	}
	assertMockExpectations(t, mock)
}

func TestAdminBootstrapDoesNotReplaceExistingAdministrator(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectBegin()
	mock.ExpectExec(`LOCK TABLE admins`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM admins`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectCommit()
	created, err := st.BootstrapAdmin(context.Background(), "admin-two", "new-hash", time.Now())
	if err != nil || created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	assertMockExpectations(t, mock)
}

func TestAdminLookupAndListNeverExposeHashInJSONModel(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 22, 5, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT id,uuid::text,username,password_hash`).WithArgs("admin-one").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "uuid", "username", "password_hash", "password_version", "status", "created_by",
			"created_at", "updated_at", "last_login_at", "disabled_at",
		}).AddRow(int64(1), "uuid-1", "admin-one", "secret-hash", int64(2), "active", nil, now, now, now, nil))
	admin, err := st.GetAdminByUsername(context.Background(), "admin-one")
	if err != nil || admin == nil || admin.PasswordHash != "secret-hash" || admin.LastLoginAt == nil {
		t.Fatalf("admin=%+v err=%v", admin, err)
	}
	mock.ExpectQuery(`SELECT id,uuid::text,username,password_version`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "uuid", "username", "password_version", "status", "created_by",
			"created_at", "updated_at", "last_login_at", "disabled_at",
		}).AddRow(int64(1), "uuid-1", "admin-one", int64(2), "active", nil, now, now, now, nil))
	admins, err := st.ListAdmins(context.Background())
	if err != nil || len(admins) != 1 || admins[0].PasswordHash != "" {
		t.Fatalf("admins=%+v err=%v", admins, err)
	}
	encoded, err := json.Marshal(admin)
	if err != nil || bytes.Contains(encoded, []byte("secret-hash")) || bytes.Contains(encoded, []byte("password_hash")) {
		t.Fatalf("admin JSON exposed password material: %s err=%v", encoded, err)
	}
	assertMockExpectations(t, mock)
}

func TestAdminCreationAndLoginUpdateRequireActiveIdentity(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 22, 10, 0, 0, time.UTC)
	mock.ExpectQuery(`INSERT INTO admins`).WithArgs("admin-two", "hash-two", int64(1), now).
		WillReturnRows(sqlmock.NewRows([]string{"id", "uuid", "created_at", "updated_at"}).AddRow(int64(2), "uuid-2", now, now))
	admin, err := st.CreateAdmin(context.Background(), "admin-two", "hash-two", 1, now)
	if err != nil || admin == nil || admin.ID != 2 || admin.CreatedBy == nil || *admin.CreatedBy != 1 {
		t.Fatalf("admin=%+v err=%v", admin, err)
	}
	mock.ExpectExec(`UPDATE admins SET last_login_at`).WithArgs(int64(2), now).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.RecordAdminLogin(context.Background(), 2, now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestLastActiveAdminCannotBeDisabled(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT status FROM admins`).WithArgs(int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("active"))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM admins WHERE status='active'`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectRollback()
	err := st.SetAdminStatus(context.Background(), 1, "disabled", time.Now())
	if !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("error=%v, want ErrLastAdmin", err)
	}
	assertMockExpectations(t, mock)
}

func TestAdminDisableAndPasswordResetRevokeSessions(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 22, 15, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT status FROM admins`).WithArgs(int64(2)).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("active"))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM admins WHERE status='active'`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	mock.ExpectExec(`UPDATE admins SET status`).WithArgs(int64(2), "disabled", now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE controller_sessions`).WithArgs(int64(2), now).WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(`UPDATE admin_node_links`).WithArgs(int64(2), now).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`UPDATE control_tickets`).WithArgs(int64(2), now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := st.SetAdminStatus(context.Background(), 2, "disabled", now); err != nil {
		t.Fatal(err)
	}

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE admins SET password_hash`).WithArgs(int64(2), "new-hash", now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE controller_sessions`).WithArgs(int64(2), now).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	if err := st.ResetAdminPassword(context.Background(), 2, "new-hash", now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}
