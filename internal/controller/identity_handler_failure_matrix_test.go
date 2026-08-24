package controller

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func identityHandlerRequest(method, target, body, provider string, authenticated bool) *http.Request {
	req := adminRouteRequest(method, target, body, "provider", provider)
	if authenticated {
		req = req.WithContext(context.WithValue(req.Context(), ctxKey("stcontrol-session"), &session{
			ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", UserID: 7, GlobalUserID: 70, Username: "alice",
		}))
	}
	return req
}

func identityHandlerServer(db *sql.DB) *Server {
	cfg := config.DefaultController()
	cfg.OAuth.LinuxDo = config.OAuthProvider{
		Enabled: true, ClientID: "client", ClientSecret: "secret",
		CallbackURL: "https://control.example/api/auth/oauth/linuxdo/callback",
	}
	return &Server{Cfg: cfg, Store: &store.Store{DB: db}, secretKey: []byte(strings.Repeat("k", 32))}
}

func TestIdentityHandlersFenceSessionsExistingMethodsAndStoreFailures(t *testing.T) {
	t.Parallel()
	injected := errors.New("injected identity handler failure")
	now := time.Now().UTC()
	for _, tc := range []struct {
		name   string
		kind   string
		auth   bool
		body   string
		setup  func(sqlmock.Sqlmock)
		status int
	}{
		{name: "list unauthenticated", kind: "list", status: http.StatusForbidden},
		{
			name: "list unavailable", kind: "list", auth: true,
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT provider,password_version`).WillReturnError(injected)
			},
			status: http.StatusInternalServerError,
		},
		{name: "begin unauthenticated", kind: "begin", status: http.StatusBadRequest},
		{
			name: "begin list unavailable", kind: "begin", auth: true,
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT provider,password_version`).WillReturnError(injected)
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "begin duplicate", kind: "begin", auth: true,
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT provider,password_version`).WillReturnRows(
					sqlmock.NewRows([]string{"provider", "password_version", "status", "created_at"}).AddRow("linuxdo", 0, "active", now))
			}, status: http.StatusConflict,
		},
		{
			name: "begin identity limit", kind: "begin", auth: true,
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT provider,password_version`).WillReturnRows(
					sqlmock.NewRows([]string{"provider", "password_version", "status", "created_at"}).
						AddRow("password", 1, "active", now).AddRow("discord", 0, "active", now).AddRow("other", 0, "active", now))
			}, status: http.StatusConflict,
		},
		{
			name: "begin state persistence", kind: "begin", auth: true,
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT provider,password_version`).WillReturnRows(
					sqlmock.NewRows([]string{"provider", "password_version", "status", "created_at"}).AddRow("password", 1, "active", now))
				mock.ExpectExec(`INSERT INTO oauth_authorization_states`).WillReturnError(injected)
			}, status: http.StatusServiceUnavailable,
		},
		{name: "bind unauthenticated", kind: "bind", body: `{"password":"password-1"}`, status: http.StatusForbidden},
		{name: "bind invalid password", kind: "bind", auth: true, body: `{}`, status: http.StatusBadRequest},
		{
			name: "bind store failure", kind: "bind", auth: true, body: `{"password":"password-1"}`,
			setup:  func(mock sqlmock.Sqlmock) { mock.ExpectBegin().WillReturnError(injected) },
			status: http.StatusInternalServerError,
		},
		{name: "unbind unauthenticated", kind: "unbind", status: http.StatusForbidden},
		{name: "unbind invalid provider", kind: "unbind", auth: true, status: http.StatusBadRequest},
		{
			name: "unbind store failure", kind: "unbind-discord", auth: true,
			setup:  func(mock sqlmock.Sqlmock) { mock.ExpectBegin().WillReturnError(injected) },
			status: http.StatusInternalServerError,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			server := identityHandlerServer(db)
			if tc.setup != nil {
				tc.setup(mock)
			}
			provider := "linuxdo"
			if tc.kind == "unbind" {
				provider = "unknown"
			} else if tc.kind == "unbind-discord" {
				provider = "discord"
			}
			req := identityHandlerRequest(http.MethodPost, "/api/account/identities/"+provider, tc.body, provider, tc.auth)
			recorder := httptest.NewRecorder()
			switch tc.kind {
			case "list":
				server.handleListIdentities(recorder, req)
			case "begin":
				server.handleBeginOAuthIdentityBinding(recorder, req)
			case "bind":
				server.handleBindPasswordIdentity(recorder, req)
			default:
				server.handleUnbindIdentity(recorder, req)
			}
			if recorder.Code != tc.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
