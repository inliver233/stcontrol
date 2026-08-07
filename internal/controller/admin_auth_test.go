package controller

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	"stcontrol/internal/crypto"
	"stcontrol/internal/store"
)

func TestAdminLoginCreatesPersistedAdminSession(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	passwordHash, err := crypto.HashPassword("strong-admin-password")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	mock.ExpectQuery(`SELECT id,uuid::text,username,password_hash`).WithArgs("admin-one").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "uuid", "username", "password_hash", "password_version", "status", "created_by",
			"created_at", "updated_at", "last_login_at", "disabled_at",
		}).AddRow(int64(9), "uuid-9", "admin-one", passwordHash, int64(1), "active", nil, now, now, nil, nil))
	mock.ExpectExec(`UPDATE admins SET last_login_at`).WithArgs(int64(9), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`INSERT INTO controller_sessions`).
		WithArgs(sqlmock.AnyArg(), nil, int64(9), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(4)))
	mock.ExpectExec(`INSERT INTO audit_logs`).WithArgs("admin-one", "admin-login", "controller", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	server := &Server{
		Cfg: &config.ControllerConfig{PublicURL: "https://control.example"}, Store: &store.Store{DB: db},
		secretKey: []byte("01234567890123456789012345678901"),
	}
	req := httptest.NewRequest(http.MethodPost, "https://control.example/api/auth/admin/login",
		bytes.NewBufferString(`{"username":"ADMIN-ONE","password":"strong-admin-password"}`))
	recorder := httptest.NewRecorder()
	server.handleAdminLogin(recorder, req)
	if recorder.Code != http.StatusOK || len(recorder.Result().Cookies()) != 2 {
		t.Fatalf("status=%d body=%s cookies=%+v", recorder.Code, recorder.Body.String(), recorder.Result().Cookies())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMeReturnsAdminPrincipalWithoutUserLookup(t *testing.T) {
	t.Parallel()
	server := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/users/me", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxKey("stcontrol-session"), &session{
		AdminID: 9, Username: "admin-one", IsAdmin: true,
	}))
	recorder := httptest.NewRecorder()
	server.handleMe(recorder, req)
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(`"is_admin":true`)) ||
		!bytes.Contains(recorder.Body.Bytes(), []byte(`"auth_provider":"admin"`)) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
