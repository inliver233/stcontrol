package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-chi/chi/v5"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func TestListIdentitiesUsesAuthenticatedGlobalUser(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery(`SELECT provider,password_version,status,created_at`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"provider", "password_version", "status", "created_at"}).
			AddRow("password", int64(1), "active", now).AddRow("discord", int64(0), "active", now))
	server := &Server{Store: &store.Store{DB: db}}
	req := httptest.NewRequest(http.MethodGet, "/api/users/me/identities", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxKey("stcontrol-session"), &session{
		UserID: 7, GlobalUserID: 70, Username: "alice",
	}))
	recorder := httptest.NewRecorder()
	server.handleListIdentities(recorder, req)
	var response struct {
		Identities []store.AuthIdentity `json:"identities"`
		CanUnbind  bool                 `json:"can_unbind"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || recorder.Code != http.StatusOK ||
		len(response.Identities) != 2 || !response.CanUnbind {
		t.Fatalf("status=%d response=%+v err=%v", recorder.Code, response, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBeginOAuthBindingPersistsSessionScopedState(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`SELECT provider,password_version,status,created_at`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"provider", "password_version", "status", "created_at"}).
			AddRow("password", int64(1), "active", time.Now()))
	mock.ExpectExec(`INSERT INTO oauth_authorization_states`).
		WithArgs(sqlmock.AnyArg(), "discord", int64(70), "session-id", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	server := &Server{
		Cfg: &config.ControllerConfig{OAuth: config.OAuthConfig{Discord: config.OAuthProvider{
			Enabled: true, ClientID: "client", CallbackURL: "https://control.example/api/auth/oauth/discord/callback",
		}}}, Store: &store.Store{DB: db},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/users/me/identities/discord/bind", nil)
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("provider", "discord")
	rctx := context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx)
	req = req.WithContext(context.WithValue(rctx, ctxKey("stcontrol-session"), &session{
		ID: "session-id", UserID: 7, GlobalUserID: 70, Username: "alice",
	}))
	recorder := httptest.NewRecorder()
	server.handleBeginOAuthIdentityBinding(recorder, req)
	var response struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s err=%v", recorder.Code, recorder.Body.String(), err)
	}
	parsed, err := url.Parse(response.AuthorizationURL)
	if err != nil || parsed.Scheme != "https" || parsed.Query().Get("state") == "" || parsed.Query().Get("client_id") != "client" {
		t.Fatalf("authorization URL=%q err=%v", response.AuthorizationURL, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestOAuthAuthorizationURLRejectsPlaintextProviderEndpoint(t *testing.T) {
	t.Parallel()
	_, err := oauthAuthorizationURL("linuxdo", oauthCfg{
		ClientID: "client", CallbackURL: "https://control.example/callback", AuthURL: "http://provider.example/authorize",
	}, "state")
	if err == nil {
		t.Fatal("plaintext OAuth authorization endpoint accepted")
	}
}
