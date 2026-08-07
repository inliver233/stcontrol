package controller

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/store"
)

func TestPasswordLoginCreatesRecoveryOnlySessionForConflictUser(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	passwordHash, err := controlcrypto.HashPassword("correct-password")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 14, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`(?s)FROM users u.*WHERE username=\$1`).WithArgs("alice").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "global_id", "uuid", "username", "display_name", "password_enc", "password_hash",
			"auth_provider", "oauth_id", "avatar_url", "email", "home_node_id", "status", "created_at",
		}).AddRow(int64(7), int64(70), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "alice", "Alice",
			nil, passwordHash, "password", nil, nil, nil, int64(8), "conflict", now))
	mock.ExpectQuery(`INSERT INTO controller_sessions`).
		WithArgs(sqlmock.AnyArg(), int64(70), nil, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(4)))
	server := &Server{
		Cfg:   &config.ControllerConfig{PublicURL: "https://control.example"},
		Store: &store.Store{DB: db}, secretKey: []byte("01234567890123456789012345678901"),
	}
	req := httptest.NewRequest(http.MethodPost, "https://control.example/api/auth/login",
		strings.NewReader(`{"username":"Alice","password":"correct-password"}`))
	recorder := httptest.NewRecorder()
	server.handleLogin(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response["recovery_required"] != true {
		t.Fatalf("response=%v err=%v", response, err)
	}
	if len(recorder.Result().Cookies()) != 2 {
		t.Fatalf("cookies=%+v", recorder.Result().Cookies())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestConflictSessionCanOnlyReachConflictRoute(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	token := "conflict-session-token"
	tokenHash := sha256.Sum256([]byte(token))
	csrfHash := make([]byte, sha256.Size)
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	mock.ExpectQuery(`(?s)FROM controller_sessions s.*gu.status='conflict'.*JOIN replica_conflicts conflict`).
		WithArgs(tokenHash[:], sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "legacy_user_id", "user_id", "admin_id", "username", "is_admin",
			"csrf_hash", "expires_at", "last_seen_at", "controller_generation",
		}).AddRow("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", int64(7), int64(70), int64(0),
			"alice", false, csrfHash, expires, now, int64(4)))
	mock.ExpectQuery(`FROM replica_conflicts`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "state", "protection_version", "generation", "version", "detected", "updated",
		}).AddRow("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "detected", int64(2), int64(4), int64(1), now, now))
	mock.ExpectQuery(`FROM replica_conflict_sources`).WithArgs("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").
		WillReturnRows(sqlmock.NewRows([]string{
			"node_id", "node_name", "node_role", "snapshot_id", "source_kind", "replica_state",
			"authoritative", "manifest", "files", "bytes", "published", "data_version", "checksum", "captured",
		}).AddRow(int64(8), "compute-a", "compute", nil, "active", "conflict", true,
			nil, nil, nil, nil, int64(8), "legacy", now))
	server := &Server{
		Cfg:   &config.ControllerConfig{PublicURL: "https://control.example"},
		Store: &store.Store{DB: db}, secretKey: []byte("01234567890123456789012345678901"),
	}
	req := httptest.NewRequest(http.MethodGet, "https://control.example/api/conflicts/me", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"capture_required"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	mock.ExpectQuery(`SELECT s.id, gu.legacy_user_id`).WithArgs(tokenHash[:], sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "legacy_user_id", "user_id", "admin_id", "username", "is_admin",
			"csrf_hash", "expires_at", "last_seen_at", "controller_generation",
		}))
	normalReq := httptest.NewRequest(http.MethodGet, "https://control.example/api/users/me", nil)
	normalReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	normalRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(normalRecorder, normalReq)
	if normalRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("normal route status=%d body=%s", normalRecorder.Code, normalRecorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
