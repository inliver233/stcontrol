package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-chi/chi/v5"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

const oauthCallbackState = "callback-state-value"

func oauthCallbackRequest(t *testing.T, withSession bool) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"https://control.example/api/auth/oauth/linuxdo/callback?code=provider-code&state="+oauthCallbackState, nil)
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("provider", "linuxdo")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
	req.AddCookie(&http.Cookie{Name: oauthStateCookieName("linuxdo"), Value: oauthCallbackState})
	if withSession {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "controller-session-token"})
	}
	return req
}

func oauthCallbackServer(db *sql.DB) *Server {
	cfg := config.DefaultController()
	cfg.PublicURL = "https://control.example"
	cfg.OAuth.LinuxDo = config.OAuthProvider{
		Enabled: true, ClientID: "client", ClientSecret: "secret",
		CallbackURL: "https://control.example/api/auth/oauth/linuxdo/callback",
		TokenURL:    "https://provider.example/token", UserInfoURL: "https://provider.example/user",
	}
	server := New(cfg, &store.Store{DB: db}, []byte("0123456789abcdef0123456789abcdef"))
	server.oauthHTTP = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body string
		switch request.URL.Path {
		case "/token":
			body = `{"access_token":"provider-token"}`
		case "/user":
			body = `{"id":4242,"username":"alice","name":"Alice"}`
		default:
			return nil, errors.New("unexpected provider endpoint")
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(body)), Request: request,
		}, nil
	})}
	return server
}

func expectOAuthLoginState(mock sqlmock.Sqlmock, nodeID any) {
	stateHash := sha256.Sum256([]byte(oauthCallbackState))
	mock.ExpectQuery(`UPDATE oauth_authorization_states AS state`).WithArgs(stateHash[:], "linuxdo", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"node_id"}).AddRow(nodeID))
}

func oauthUserRows(status string) *sqlmock.Rows {
	now := time.Date(2026, 8, 24, 9, 50, 0, 0, time.UTC)
	return sqlmock.NewRows([]string{
		"id", "global_id", "uuid", "username", "display_name", "password_enc", "password_hash",
		"auth_provider", "oauth_id", "avatar_url", "email", "home_node_id", "status", "created_at",
	}).AddRow(int64(7), int64(70), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "alice", "Alice",
		nil, nil, "linuxdo", "4242", nil, nil, int64(8), status, now)
}

func TestOAuthCallbackHandlesStateAndStoreFailuresWithoutProviderLeakage(t *testing.T) {
	t.Parallel()
	injected := errors.New("injected OAuth callback failure")
	for _, tc := range []struct {
		name   string
		setup  func(sqlmock.Sqlmock)
		status int
	}{
		{
			name: "session service",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`FROM controller_sessions s`).WillReturnError(injected)
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "state store",
			setup: func(mock sqlmock.Sqlmock) {
				stateHash := sha256.Sum256([]byte(oauthCallbackState))
				mock.ExpectQuery(`UPDATE oauth_authorization_states AS state`).WithArgs(stateHash[:], "linuxdo", sqlmock.AnyArg()).
					WillReturnError(injected)
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "state replay",
			setup: func(mock sqlmock.Sqlmock) {
				stateHash := sha256.Sum256([]byte(oauthCallbackState))
				mock.ExpectQuery(`UPDATE oauth_authorization_states AS state`).WithArgs(stateHash[:], "linuxdo", sqlmock.AnyArg()).
					WillReturnError(sql.ErrNoRows)
			},
			status: http.StatusBadRequest,
		},
		{
			name: "identity lookup",
			setup: func(mock sqlmock.Sqlmock) {
				expectOAuthLoginState(mock, nil)
				mock.ExpectQuery(`FROM auth_identities identity`).WithArgs("linuxdo", "4242").WillReturnError(injected)
			},
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
			server := oauthCallbackServer(db)
			tc.setup(mock)
			req := oauthCallbackRequest(t, tc.name == "session service")
			recorder := httptest.NewRecorder()
			server.handleOAuthCallback(recorder, req)
			if recorder.Code != tc.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOAuthCallbackCreatesPendingEnrollmentWithoutSelectedNode(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := oauthCallbackServer(db)
	expectOAuthLoginState(mock, nil)
	mock.ExpectQuery(`FROM auth_identities identity`).WithArgs("linuxdo", "4242").WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`INSERT INTO oauth_pending_enrollments`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "linuxdo", "4242", "Alice", nil,
			int64(0), int64(0), nil, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	req := oauthCallbackRequest(t, false)
	recorder := httptest.NewRecorder()
	server.handleOAuthCallback(recorder, req)
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "/select-node?provider=linuxdo" {
		t.Fatalf("status=%d location=%q body=%s", recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
	}
	if len(recorder.Result().Cookies()) < 2 {
		t.Fatalf("expected cleared state and pending cookies: %+v", recorder.Result().Cookies())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestOAuthCallbackFencesPendingCreationAndDisabledIdentity(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		setup  func(sqlmock.Sqlmock)
		status int
	}{
		{
			name: "pending persistence",
			setup: func(mock sqlmock.Sqlmock) {
				expectOAuthLoginState(mock, nil)
				mock.ExpectQuery(`FROM auth_identities identity`).WillReturnError(sql.ErrNoRows)
				mock.ExpectExec(`INSERT INTO oauth_pending_enrollments`).WillReturnError(errors.New("write failed"))
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "disabled identity",
			setup: func(mock sqlmock.Sqlmock) {
				expectOAuthLoginState(mock, nil)
				mock.ExpectQuery(`FROM auth_identities identity`).WillReturnRows(oauthUserRows("disabled"))
			},
			status: http.StatusForbidden,
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
			server := oauthCallbackServer(db)
			tc.setup(mock)
			recorder := httptest.NewRecorder()
			server.handleOAuthCallback(recorder, oauthCallbackRequest(t, false))
			if recorder.Code != tc.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
