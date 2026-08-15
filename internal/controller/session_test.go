package controller

import (
	"crypto/sha256"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func TestCSRFTokenIsSessionBoundAndValidated(t *testing.T) {
	t.Parallel()
	server := &Server{secretKey: []byte("01234567890123456789012345678901")}
	first := server.deriveCSRFToken("session-one")
	second := server.deriveCSRFToken("session-two")
	if first == "" || first == second {
		t.Fatalf("CSRF tokens not session-bound: %q %q", first, second)
	}
	digest := sha256.Sum256([]byte(first))
	sess := &session{CSRFHash: digest[:]}
	req := httptest.NewRequest(http.MethodPost, "/api/users/me/password", nil)
	req.Header.Set("X-CSRF-Token", first)
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: first})
	if !server.validateCSRF(req, sess) {
		t.Fatal("valid double-submit CSRF token rejected")
	}
	req.Header.Set("X-CSRF-Token", second)
	if server.validateCSRF(req, sess) {
		t.Fatal("mismatched CSRF token accepted")
	}
}

func TestLogoutRouteLivesInsideAuthSubtreeAndRevokesSession(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	cfg := config.DefaultController()
	cfg.StaticDir = t.TempDir()
	server := New(cfg, &store.Store{DB: db}, []byte("01234567890123456789012345678901"))
	handler := server.Handler()

	unauthenticated := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated logout status=%d body=%s", unauthenticated.Code, unauthenticated.Body.String())
	}

	const rawSession = "opaque-session-token"
	sessionDigest := sha256.Sum256([]byte(rawSession))
	csrfToken := server.deriveCSRFToken("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	csrfDigest := sha256.Sum256([]byte(csrfToken))
	now := time.Now().UTC()
	mock.ExpectQuery(`SELECT s.id, gu.legacy_user_id`).
		WithArgs(sessionDigest[:], sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "legacy_user_id", "user_id", "admin_id", "username", "is_admin",
			"csrf_hash", "expires_at", "last_seen_at", "controller_generation",
		}).AddRow(
			"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", int64(7), int64(70), nil, "alice", false,
			csrfDigest[:], now.Add(time.Hour), now, int64(1),
		))
	mock.ExpectExec(`UPDATE controller_sessions SET revoked_at`).
		WithArgs(sessionDigest[:], sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	authenticated := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	authenticated.AddCookie(&http.Cookie{Name: sessionCookie, Value: rawSession})
	authenticated.AddCookie(&http.Cookie{Name: csrfCookie, Value: csrfToken})
	authenticated.Header.Set("X-CSRF-Token", csrfToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, authenticated)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authenticated logout status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestCreateUserSessionPersistsOnlyDigestsAndSetsSecureCookies(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	server := &Server{
		Cfg:       &config.ControllerConfig{PublicURL: "https://control.example"},
		Store:     &store.Store{DB: db},
		secretKey: []byte("01234567890123456789012345678901"),
	}
	user := &store.User{ID: 7, GlobalID: 70, Username: "alice", PasswordHash: sql.NullString{String: "hash", Valid: true}}
	mock.ExpectQuery(`INSERT INTO controller_sessions`).
		WithArgs(sqlmock.AnyArg(), int64(70), nil, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(3)))

	req := httptest.NewRequest(http.MethodPost, "https://control.example/api/auth/login", nil)
	recorder := httptest.NewRecorder()
	if err := server.createUserSession(recorder, req, user); err != nil {
		t.Fatalf("createUserSession: %v", err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("got %d cookies, want 2", len(cookies))
	}
	byName := map[string]*http.Cookie{}
	for _, cookie := range cookies {
		byName[cookie.Name] = cookie
	}
	if byName[sessionCookie] == nil || !byName[sessionCookie].HttpOnly || !byName[sessionCookie].Secure {
		t.Fatalf("session cookie flags are unsafe: %+v", byName[sessionCookie])
	}
	if byName[csrfCookie] == nil || byName[csrfCookie].HttpOnly || !byName[csrfCookie].Secure {
		t.Fatalf("CSRF cookie flags are wrong: %+v", byName[csrfCookie])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestCreateAdminSessionUsesAdminPrincipalAndShortTTL(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{
		Cfg: &config.ControllerConfig{PublicURL: "https://control.example"}, Store: &store.Store{DB: db},
		secretKey: []byte("01234567890123456789012345678901"),
	}
	mock.ExpectQuery(`INSERT INTO controller_sessions`).
		WithArgs(sqlmock.AnyArg(), nil, int64(9), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(3)))
	req := httptest.NewRequest(http.MethodPost, "https://control.example/api/auth/admin/login", nil)
	recorder := httptest.NewRecorder()
	if err := server.createAdminSession(recorder, req, &store.Admin{ID: 9, Username: "admin-one", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 || cookies[0].MaxAge > int(adminSessionTTL.Seconds()) {
		t.Fatalf("cookies=%+v", cookies)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureCSRFCookieRestoresMissingCookie(t *testing.T) {
	t.Parallel()
	server := &Server{
		Cfg:       &config.ControllerConfig{PublicURL: "http://localhost:8080"},
		secretKey: []byte("01234567890123456789012345678901"),
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/users/me", nil)
	recorder := httptest.NewRecorder()
	server.ensureCSRFCookie(recorder, req, &session{
		ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ExpiresAt: time.Now().Add(time.Hour),
	})
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != csrfCookie || cookies[0].Value == "" || cookies[0].Secure {
		t.Fatalf("unexpected restored cookie: %+v", cookies)
	}
}

func TestValidMutationOrigin(t *testing.T) {
	t.Parallel()
	server := &Server{Cfg: &config.ControllerConfig{PublicURL: "https://control.example"}}
	tests := []struct {
		name      string
		origin    string
		fetchSite string
		want      bool
	}{
		{name: "same origin", origin: "https://control.example", fetchSite: "same-origin", want: true},
		{name: "wrong host", origin: "https://evil.example", fetchSite: "cross-site", want: false},
		{name: "wrong scheme", origin: "http://control.example", fetchSite: "same-site", want: false},
		{name: "non browser", want: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://control.example/api/auth/login", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tt.fetchSite)
			}
			if got := server.validMutationOrigin(req); got != tt.want {
				t.Fatalf("validMutationOrigin=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestOAuthPendingCookieIsHttpOnlyAndPathScoped(t *testing.T) {
	t.Parallel()
	server := &Server{Cfg: &config.ControllerConfig{PublicURL: "https://control.example"}}
	req := httptest.NewRequest(http.MethodGet, "https://control.example/api/auth/oauth/discord/callback", nil)
	recorder := httptest.NewRecorder()
	server.setOAuthPendingCookie(recorder, req, "opaque-token", 600)
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != oauthPendingCookie || !cookies[0].HttpOnly ||
		!cookies[0].Secure || cookies[0].Path != "/api/auth/oauth/complete" {
		t.Fatalf("unsafe OAuth pending cookie: %+v", cookies)
	}
}

func TestOAuthStateCookieIsProviderScopedAndHostOnly(t *testing.T) {
	t.Parallel()
	server := &Server{Cfg: &config.ControllerConfig{PublicURL: "https://control.example"}}
	req := httptest.NewRequest(http.MethodGet, "https://control.example/api/auth/oauth/discord/callback", nil)
	recorder := httptest.NewRecorder()
	server.setOAuthStateCookie(recorder, req, "discord", "opaque-state", 600)
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 ||
		cookies[0].Name != oauthStateCookieName("discord") ||
		!cookies[0].HttpOnly ||
		!cookies[0].Secure ||
		cookies[0].SameSite != http.SameSiteLaxMode ||
		cookies[0].MaxAge != 600 ||
		cookies[0].Path != oauthCallbackPath("discord") ||
		cookies[0].Domain != "" {
		t.Fatalf("unsafe OAuth state cookie: %+v", cookies)
	}
}

func TestConsumeOAuthStateCookieClearsMismatchedCookie(t *testing.T) {
	t.Parallel()
	server := &Server{Cfg: &config.ControllerConfig{PublicURL: "https://control.example"}}
	req := httptest.NewRequest(http.MethodGet, "https://control.example/api/auth/oauth/discord/callback", nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookieName("discord"), Value: "stored-state"})
	recorder := httptest.NewRecorder()
	if server.consumeOAuthStateCookie(recorder, req, "discord", "other-state") {
		t.Fatal("mismatched OAuth state cookie was accepted")
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 ||
		cookies[0].Name != oauthStateCookieName("discord") ||
		!cookies[0].HttpOnly ||
		!cookies[0].Secure ||
		cookies[0].SameSite != http.SameSiteLaxMode ||
		cookies[0].Path != oauthCallbackPath("discord") ||
		cookies[0].MaxAge != -1 {
		t.Fatalf("unexpected OAuth state cleanup cookie: %+v", cookies)
	}
}
