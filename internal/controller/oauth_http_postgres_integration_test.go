package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

type oauthRoundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip oauthRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

// TestControllerOAuthHTTPStatePendingLoginAndIdentityBinding proves the OAuth
// browser surface with the real router and PostgreSQL while replacing only the
// external provider transport. It covers single-use hashed state, bounded
// provider errors, pending-enrollment claim/replay, existing-user login,
// session-bound identity binding, password fallback and last-identity safety.
func TestControllerOAuthHTTPStatePendingLoginAndIdentityBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller OAuth PostgreSQL HTTP integration is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated Controller OAuth store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	node := createControllerBackupNode(t, ctx, st, "oauth-http-compute", "compute", false, 1)
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET allow_register=true,
		  registration_policy_state='open',registration_policy_version=1,
		  registration_policy_expires_at=now()+interval '1 hour',
		  registration_policy_observed_at=now()
		WHERE id=$1`, node.ID); err != nil {
		t.Fatalf("open node-owned OAuth registration policy: %v", err)
	}

	cfg := config.DefaultController()
	cfg.StaticDir = t.TempDir()
	cfg.Relay.Listen = ""
	cfg.OAuth.LinuxDo = config.OAuthProvider{
		Enabled: true, ClientID: "linux-client", ClientSecret: "linux-secret",
		AuthURL:     "https://provider.example/linux/authorize",
		TokenURL:    "https://provider.example/linux/token",
		UserInfoURL: "https://provider.example/linux/user",
	}
	cfg.OAuth.Discord = config.OAuthProvider{
		Enabled: true, ClientID: "discord-client", ClientSecret: "discord-secret",
		GuildID: "guild-42",
	}
	server := New(cfg, st, []byte("0123456789abcdef0123456789abcdef"))
	// This scenario deliberately exercises many invalid and replayed OAuth
	// states from one httptest client. Keep its authentication budget above the
	// scenario size; rate-limit behavior is covered independently.
	server.loginLimiter = newRateLimiter(1_000, time.Minute, 1_000)

	providerCalls := make(map[string]int)
	server.oauthHTTP = &http.Client{
		Timeout: 2 * time.Second,
		Transport: oauthRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			providerCalls[request.Method+" "+request.URL.Host+request.URL.Path]++
			if request.URL.Query().Get("client_secret") != "" || request.URL.Query().Get("access_token") != "" {
				t.Errorf("OAuth secret entered provider URL: %s", request.URL.Redacted())
			}
			switch {
			case request.Method == http.MethodPost && request.URL.Host == "provider.example" && request.URL.Path == "/linux/token":
				if err := request.ParseForm(); err != nil {
					t.Errorf("parse LinuxDo token form: %v", err)
				}
				if request.Form.Get("client_secret") != "linux-secret" || request.Form.Get("grant_type") != "authorization_code" {
					t.Errorf("unexpected LinuxDo token form: %v", request.Form)
				}
				if request.Form.Get("code") == "provider-fail" {
					return oauthProviderResponse(request, http.StatusBadGateway, `{"error":"provider unavailable"}`), nil
				}
				return oauthProviderResponse(request, http.StatusOK, `{"access_token":"linux-access"}`), nil
			case request.Method == http.MethodGet && request.URL.Host == "provider.example" && request.URL.Path == "/linux/user":
				if request.Header.Get("Authorization") != "Bearer linux-access" {
					t.Errorf("LinuxDo bearer missing from header")
				}
				return oauthProviderResponse(request, http.StatusOK,
					`{"id":4242,"username":"oauth-user","name":"OAuth User","avatar_template":"/avatar/{size}.png"}`), nil
			case request.Method == http.MethodPost && request.URL.Host == "discord.com" && request.URL.Path == "/api/oauth2/token":
				if err := request.ParseForm(); err != nil {
					t.Errorf("parse Discord token form: %v", err)
				}
				if request.Form.Get("client_secret") != "discord-secret" {
					t.Errorf("Discord client secret missing from form")
				}
				return oauthProviderResponse(request, http.StatusOK, `{"access_token":"discord-access"}`), nil
			case request.Method == http.MethodGet && request.URL.Host == "discord.com" && request.URL.Path == "/api/users/@me":
				return oauthProviderResponse(request, http.StatusOK,
					`{"id":"discord-99","username":"discord-user","global_name":"Discord User","avatar":"avatar-hash"}`), nil
			case request.Method == http.MethodGet && request.URL.Host == "discord.com" &&
				request.URL.Path == "/api/users/@me/guilds/guild-42/member":
				return oauthProviderResponse(request, http.StatusOK, `{}`), nil
			default:
				t.Errorf("unexpected OAuth provider request: %s %s", request.Method, request.URL.Redacted())
				return oauthProviderResponse(request, http.StatusNotFound, `{}`), nil
			}
		}),
	}
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	cfg.PublicURL = httpServer.URL
	cfg.OAuth.LinuxDo.CallbackURL = httpServer.URL + "/api/auth/oauth/linuxdo/callback"
	cfg.OAuth.Discord.CallbackURL = httpServer.URL + "/api/auth/oauth/discord/callback"

	newOAuthClient := func() *http.Client {
		t.Helper()
		client := newControllerHTTPClient(t)
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
		return client
	}

	client := newOAuthClient()
	assertControllerHTTPStatus(t, client, http.MethodGet, httpServer.URL+"/api/auth/oauth/unknown", nil, false, http.StatusBadRequest)
	assertControllerHTTPStatus(t, client, http.MethodGet, httpServer.URL+"/api/auth/oauth/linuxdo?node_id=invalid", nil, false, http.StatusBadRequest)
	assertControllerHTTPStatus(t, client, http.MethodGet, httpServer.URL+"/api/auth/oauth/linuxdo/callback", nil, false, http.StatusBadRequest)

	// Provider failure consumes the one-time state before any remote call, so
	// a callback replay cannot turn a transient provider response into a state
	// oracle or make another token exchange.
	failureState := beginOAuthState(t, client, httpServer.URL+"/api/auth/oauth/linuxdo")
	missingCookieClient := newOAuthClient()
	failureCalls := providerCalls["POST provider.example/linux/token"]
	assertControllerHTTPStatus(t, missingCookieClient, http.MethodGet,
		httpServer.URL+"/api/auth/oauth/linuxdo/callback?code=provider-fail&state="+url.QueryEscape(failureState), nil, false, http.StatusBadRequest)
	if providerCalls["POST provider.example/linux/token"] != failureCalls {
		t.Fatal("callback without login-bound OAuth cookie reached provider token exchange")
	}
	providerMismatchCalls := providerCalls["POST discord.com/api/oauth2/token"]
	assertControllerHTTPStatus(t, client, http.MethodGet,
		httpServer.URL+"/api/auth/oauth/discord/callback?code=provider-fail&state="+url.QueryEscape(failureState), nil, false, http.StatusBadRequest)
	if providerCalls["POST discord.com/api/oauth2/token"] != providerMismatchCalls {
		t.Fatal("provider-mismatched OAuth cookie reached provider token exchange")
	}
	overrideOAuthStateCookie(t, client, httpServer.URL+"/api/auth/oauth/linuxdo/callback", "linuxdo", "mismatched-state")
	assertControllerHTTPStatus(t, client, http.MethodGet,
		httpServer.URL+"/api/auth/oauth/linuxdo/callback?code=provider-fail&state="+url.QueryEscape(failureState), nil, false, http.StatusBadRequest)
	if providerCalls["POST provider.example/linux/token"] != failureCalls {
		t.Fatal("callback with mismatched login-bound OAuth cookie reached provider token exchange")
	}
	failureState = beginOAuthState(t, client, httpServer.URL+"/api/auth/oauth/linuxdo")
	status, _, body := controllerHTTPRequest(t, client, http.MethodGet,
		httpServer.URL+"/api/auth/oauth/linuxdo/callback?code=provider-fail&state="+url.QueryEscape(failureState), nil, false)
	if status != http.StatusBadGateway {
		t.Fatalf("provider failure callback: status=%d body=%s", status, body)
	}
	failureCalls = providerCalls["POST provider.example/linux/token"]
	assertControllerHTTPStatus(t, client, http.MethodGet,
		httpServer.URL+"/api/auth/oauth/linuxdo/callback?code=provider-fail&state="+url.QueryEscape(failureState), nil, false, http.StatusBadRequest)
	if providerCalls["POST provider.example/linux/token"] != failureCalls {
		t.Fatal("replayed OAuth state reached provider token exchange")
	}

	state := beginOAuthState(t, client,
		httpServer.URL+"/api/auth/oauth/linuxdo?node_id="+strconv.FormatInt(node.ID, 10))
	stateDigest := sha256.Sum256([]byte(state))
	var persistedState []byte
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state_hash FROM oauth_authorization_states
		WHERE provider='linuxdo' AND state_hash=$1`, stateDigest[:]).Scan(&persistedState); err != nil ||
		!bytes.Equal(persistedState, stateDigest[:]) || bytes.Contains(persistedState, []byte(state)) {
		t.Fatalf("OAuth state persistence: digest=%x err=%v", persistedState, err)
	}
	status, headers, body := controllerHTTPRequest(t, client, http.MethodGet,
		httpServer.URL+"/api/auth/oauth/linuxdo/callback?code=new-code&state="+url.QueryEscape(state), nil, false)
	if status != http.StatusFound || headers.Get("Location") != "/select-node?node_id="+strconv.FormatInt(node.ID, 10) {
		t.Fatalf("new OAuth callback: status=%d location=%q body=%s", status, headers.Get("Location"), body)
	}
	pendingToken := controllerCookieValue(t, client, httpServer.URL+"/api/auth/oauth/complete", oauthPendingCookie)
	if pendingToken == "" {
		t.Fatal("new OAuth callback did not issue path-scoped pending cookie")
	}
	pendingDigest := sha256.Sum256([]byte(pendingToken))
	var storedPendingDigest []byte
	var pendingSubject, pendingState string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT token_hash,provider_subject,state FROM oauth_pending_enrollments
		WHERE token_hash=$1`, pendingDigest[:]).Scan(&storedPendingDigest, &pendingSubject, &pendingState); err != nil ||
		!bytes.Equal(storedPendingDigest, pendingDigest[:]) || pendingSubject != "4242" || pendingState != "pending" ||
		bytes.Contains(storedPendingDigest, []byte(pendingToken)) {
		t.Fatalf("OAuth pending persistence: subject=%q state=%q digest=%x err=%v", pendingSubject, pendingState, storedPendingDigest, err)
	}
	assertControllerHTTPStatus(t, client, http.MethodGet,
		httpServer.URL+"/api/auth/oauth/linuxdo/callback?code=new-code&state="+url.QueryEscape(state), nil, false, http.StatusBadRequest)

	completeURL := httpServer.URL + "/api/auth/oauth/complete"
	assertControllerHTTPStatus(t, newOAuthClient(), http.MethodPost, completeURL,
		map[string]any{"operation_id": "75000000-0000-4000-8000-000000000001", "node_id": node.ID}, false, http.StatusUnauthorized)
	assertControllerHTTPStatus(t, client, http.MethodPost, completeURL, map[string]string{}, false, http.StatusBadRequest)

	user := &store.User{
		Username: "oauth-user", DisplayName: "OAuth User", AuthProvider: "linuxdo",
		OAuthID:    sql.NullString{String: "4242", Valid: true},
		HomeNodeID: sql.NullInt64{Int64: node.ID, Valid: true}, Status: "active",
	}
	if err := st.CreateUser(ctx, user); err != nil {
		t.Fatalf("create already-provisioned OAuth identity: %v", err)
	}

	// Preserve the raw pending cookie in another browser to model a lost
	// response. The second exact completion must recover the consumed user
	// result rather than create a duplicate identity.
	replayClient := newOAuthClient()
	completeParsed, _ := url.Parse(completeURL)
	replayClient.Jar.SetCookies(completeParsed, []*http.Cookie{{
		Name: oauthPendingCookie, Value: pendingToken, Path: "/api/auth/oauth/complete",
	}})
	completeRequest := map[string]any{
		"operation_id": "75000000-0000-4000-8000-000000000001", "node_id": node.ID,
	}
	assertControllerHTTPStatus(t, client, http.MethodPost, completeURL, completeRequest, false, http.StatusOK)
	assertControllerSessionCookies(t, client, httpServer.URL)
	assertControllerHTTPStatus(t, replayClient, http.MethodPost, completeURL, completeRequest, false, http.StatusOK)
	assertControllerSessionCookies(t, replayClient, httpServer.URL)
	var oauthUsers, consumedPendings int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM auth_identities WHERE provider='linuxdo' AND provider_subject='4242'`).Scan(&oauthUsers); err != nil {
		t.Fatalf("count OAuth identities: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM oauth_pending_enrollments
		WHERE token_hash=$1 AND state='consumed' AND result_user_id=$2`, pendingDigest[:], user.ID).Scan(&consumedPendings); err != nil ||
		oauthUsers != 1 || consumedPendings != 1 {
		t.Fatalf("OAuth completion facts: identities=%d pending=%d err=%v", oauthUsers, consumedPendings, err)
	}

	// A later login for the same provider subject creates only a normal user
	// session and never re-enters pending enrollment.
	loginClient := newOAuthClient()
	loginState := beginOAuthState(t, loginClient, httpServer.URL+"/api/auth/oauth/linuxdo")
	status, headers, body = controllerHTTPRequest(t, loginClient, http.MethodGet,
		httpServer.URL+"/api/auth/oauth/linuxdo/callback?code=existing-code&state="+url.QueryEscape(loginState), nil, false)
	if status != http.StatusFound || headers.Get("Location") != "/" {
		t.Fatalf("existing OAuth login: status=%d location=%q body=%s", status, headers.Get("Location"), body)
	}
	assertControllerSessionCookies(t, loginClient, httpServer.URL)

	// Bind Discord to the current session. The binding state is tied to both
	// the global user and durable session ID and cannot be replayed as login
	// state after it is consumed.
	status, _, body = controllerHTTPRequest(t, client, http.MethodPost,
		httpServer.URL+"/api/users/me/identities/discord/bind", nil, true)
	if status != http.StatusOK {
		t.Fatalf("begin Discord identity binding: status=%d body=%s", status, body)
	}
	var bindingResponse struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	if err := json.Unmarshal(body, &bindingResponse); err != nil || bindingResponse.AuthorizationURL == "" {
		t.Fatalf("decode Discord binding response: response=%+v err=%v", bindingResponse, err)
	}
	bindingURL, err := url.Parse(bindingResponse.AuthorizationURL)
	if err != nil || bindingURL.Query().Get("state") == "" {
		t.Fatalf("parse Discord binding URL %q: %v", bindingResponse.AuthorizationURL, err)
	}
	bindingState := bindingURL.Query().Get("state")
	bindingCallback := httpServer.URL + "/api/auth/oauth/discord/callback?code=discord-bind&state=" + url.QueryEscape(bindingState)
	status, headers, body = controllerHTTPRequest(t, client, http.MethodGet, bindingCallback, nil, false)
	if status != http.StatusFound || headers.Get("Location") != "/account?identity_bound=discord" {
		t.Fatalf("Discord binding callback: status=%d location=%q body=%s", status, headers.Get("Location"), body)
	}
	assertControllerHTTPStatus(t, client, http.MethodGet, bindingCallback, nil, false, http.StatusBadRequest)
	status, _, body = controllerHTTPRequest(t, client, http.MethodGet, httpServer.URL+"/api/users/me/identities", nil, false)
	if status != http.StatusOK || !strings.Contains(string(body), `"provider":"discord"`) ||
		!strings.Contains(string(body), `"provider":"linuxdo"`) {
		t.Fatalf("bound identity list: status=%d body=%s", status, body)
	}
	assertControllerHTTPStatus(t, client, http.MethodDelete,
		httpServer.URL+"/api/users/me/identities/discord", nil, true, http.StatusOK)

	// Keep the node unavailable while adding password fallback so the
	// deterministic controller records pending synchronization instead of
	// waiting on a synthetic Agent. Identity creation still succeeds safely.
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET status='offline',connectivity_state='offline' WHERE id=$1`, node.ID); err != nil {
		t.Fatalf("make OAuth user's node unavailable: %v", err)
	}
	const fallbackPassword = "oauth-password-fallback-2026"
	assertControllerHTTPStatus(t, client, http.MethodPost,
		httpServer.URL+"/api/users/me/identities/password",
		map[string]string{"password": fallbackPassword}, true, http.StatusAccepted)
	assertControllerHTTPStatus(t, client, http.MethodDelete,
		httpServer.URL+"/api/users/me/identities/linuxdo", nil, true, http.StatusOK)
	assertControllerHTTPStatus(t, client, http.MethodDelete,
		httpServer.URL+"/api/users/me/identities/password", nil, true, http.StatusConflict)

	passwordClient := newOAuthClient()
	assertControllerHTTPStatus(t, passwordClient, http.MethodPost, httpServer.URL+"/api/auth/login",
		map[string]string{"username": user.Username, "password": fallbackPassword}, false, http.StatusOK)
	assertControllerSessionCookies(t, passwordClient, httpServer.URL)

	var auditCount int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM audit_logs
		WHERE actor=$1 AND action IN ('identity-bind','identity-unbind')`, user.Username).Scan(&auditCount); err != nil || auditCount != 4 {
		t.Fatalf("identity audit count=%d err=%v, want 4", auditCount, err)
	}
	if providerCalls["GET discord.com/api/users/@me/guilds/guild-42/member"] != 1 {
		t.Fatalf("Discord guild membership checks=%d, want 1", providerCalls["GET discord.com/api/users/@me/guilds/guild-42/member"])
	}
}

func oauthProviderResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)), Request: request,
	}
}

func beginOAuthState(t *testing.T, client *http.Client, target string) string {
	t.Helper()
	status, headers, body := controllerHTTPRequest(t, client, http.MethodGet, target, nil, false)
	if status != http.StatusFound {
		t.Fatalf("begin OAuth: status=%d body=%s", status, body)
	}
	authorizationURL, err := url.Parse(headers.Get("Location"))
	if err != nil || authorizationURL.Query().Get("state") == "" {
		t.Fatalf("parse OAuth authorization redirect %q: %v", headers.Get("Location"), err)
	}
	return authorizationURL.Query().Get("state")
}

func overrideOAuthStateCookie(t *testing.T, client *http.Client, target, provider, state string) {
	t.Helper()
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse OAuth state override target %q: %v", target, err)
	}
	client.Jar.SetCookies(parsed, []*http.Cookie{{
		Name: oauthStateCookieName(provider), Value: state, Path: oauthCallbackPath(provider),
	}})
}
