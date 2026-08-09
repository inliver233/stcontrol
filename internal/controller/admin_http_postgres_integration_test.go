package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/store"
)

// TestControllerAdminAndUserHTTPRoutesUseDurableFacts proves that the actual
// router, session/CSRF middleware and PostgreSQL-backed admin/user handlers are
// wired together. It deliberately includes unauthenticated, wrong-role,
// malformed, replay-safe and post-revocation requests rather than treating a
// successful dashboard render as sufficient acceptance evidence.
func TestControllerAdminAndUserHTTPRoutesUseDurableFacts(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller admin PostgreSQL HTTP integration is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated Controller admin store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	const (
		rootUsername = "root-admin"
		rootPassword = "root-admin-password-2026"
		userPassword = "user-password-2026"
	)
	rootHash, err := controlcrypto.HashPassword(rootPassword)
	if err != nil {
		t.Fatalf("hash root administrator password: %v", err)
	}
	created, err := st.BootstrapAdmin(ctx, rootUsername, rootHash, time.Now().UTC())
	if err != nil || !created {
		t.Fatalf("bootstrap root administrator: created=%v err=%v", created, err)
	}
	rootAdmin, err := st.GetAdminByUsername(ctx, rootUsername)
	if err != nil || rootAdmin == nil {
		t.Fatalf("read root administrator: admin=%+v err=%v", rootAdmin, err)
	}

	compute := createControllerBackupNode(t, ctx, st, "admin-http-compute", "compute", false, 1)
	user := createControllerBackupUser(t, ctx, st, compute.ID, "admin-http-user")
	userHash, err := controlcrypto.HashPassword(userPassword)
	if err != nil {
		t.Fatalf("hash HTTP user password: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE users SET password_hash=$2 WHERE id=$1`, user.ID, userHash); err != nil {
		t.Fatalf("install real legacy user password hash: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE auth_identities SET password_hash=$2
		WHERE user_id=$1 AND provider='password'`, user.GlobalID, userHash); err != nil {
		t.Fatalf("install real global user password hash: %v", err)
	}

	cfg := config.DefaultController()
	cfg.StaticDir = t.TempDir()
	cfg.Relay.Listen = ""
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	server := New(cfg, st, secretKey)
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	cfg.PublicURL = httpServer.URL

	unauthenticated := newControllerHTTPClient(t)
	adminClient := newControllerHTTPClient(t)
	userClient := newControllerHTTPClient(t)

	t.Run("public endpoints and authorization boundaries", func(t *testing.T) {
		assertControllerHTTPStatus(t, unauthenticated, http.MethodGet, httpServer.URL+"/api/health", nil, false, http.StatusNoContent)
		status, _, installBody := controllerHTTPRequest(t, unauthenticated, http.MethodGet, httpServer.URL+"/install.sh", nil, false)
		if status != http.StatusOK || !bytes.Contains(installBody, []byte("stcontrol")) {
			t.Fatalf("install script: status=%d body=%q", status, installBody)
		}
		// The endpoint is public, but an empty browser has no pending
		// registration cookie and therefore receives the bounded no-work result.
		assertControllerHTTPStatus(t, unauthenticated, http.MethodGet, httpServer.URL+"/api/auth/registration/status", nil, false, http.StatusUnauthorized)
		assertControllerHTTPStatus(t, unauthenticated, http.MethodGet, httpServer.URL+"/api/nodes/available", nil, false, http.StatusOK)
		assertControllerHTTPStatus(t, unauthenticated, http.MethodGet, httpServer.URL+"/api/admin/overview", nil, false, http.StatusUnauthorized)

		assertControllerHTTPStatus(t, adminClient, http.MethodPost, httpServer.URL+"/api/auth/admin/login",
			map[string]string{"username": rootUsername, "password": "wrong-password"}, false, http.StatusForbidden)
		if got := controllerCookieValue(t, adminClient, httpServer.URL, sessionCookie); got != "" {
			t.Fatalf("wrong-password login issued a session cookie: %q", got)
		}
		assertControllerHTTPStatus(t, adminClient, http.MethodPost, httpServer.URL+"/api/auth/admin/login",
			map[string]string{"username": rootUsername, "password": rootPassword}, false, http.StatusOK)
		assertControllerSessionCookies(t, adminClient, httpServer.URL)

		assertControllerHTTPStatus(t, userClient, http.MethodPost, httpServer.URL+"/api/auth/login",
			map[string]string{"username": user.Username, "password": "wrong-password"}, false, http.StatusForbidden)
		assertControllerHTTPStatus(t, userClient, http.MethodPost, httpServer.URL+"/api/auth/login",
			map[string]string{"username": user.Username, "password": userPassword}, false, http.StatusOK)
		assertControllerSessionCookies(t, userClient, httpServer.URL)
		assertControllerHTTPStatus(t, userClient, http.MethodGet, httpServer.URL+"/api/admin/overview", nil, false, http.StatusForbidden)

		status, headers, body := controllerHTTPRequest(t, adminClient, http.MethodGet, httpServer.URL+"/api/admin/overview", nil, false)
		if status != http.StatusOK || !strings.Contains(headers.Get("Cache-Control"), "no-store") ||
			bytes.Contains(body, []byte(rootPassword)) || bytes.Contains(body, []byte(rootHash)) {
			t.Fatalf("authenticated overview: status=%d cache=%q body=%s", status, headers.Get("Cache-Control"), body)
		}
		// A valid session is not enough for a mutation: the durable session's
		// CSRF digest must match both the cookie and request header.
		assertControllerHTTPStatus(t, adminClient, http.MethodPost, httpServer.URL+"/api/admin/nodes", map[string]string{"name": "csrf-bypass"}, false, http.StatusForbidden)
	})

	t.Run("user pages are durable and logout revokes the opaque session", func(t *testing.T) {
		for _, path := range []string{
			"/api/users/me",
			"/api/users/me/nodes",
			"/api/users/me/protection",
			"/api/users/me/restore-targets",
			"/api/users/me/identities",
			"/api/users/me/import-claims",
		} {
			assertControllerHTTPStatus(t, userClient, http.MethodGet, httpServer.URL+path, nil, false, http.StatusOK)
		}
		assertControllerHTTPStatus(t, userClient, http.MethodPost, httpServer.URL+"/api/auth/logout", nil, true, http.StatusOK)
		assertControllerHTTPStatus(t, userClient, http.MethodGet, httpServer.URL+"/api/users/me", nil, false, http.StatusUnauthorized)
		assertControllerHTTPStatus(t, userClient, http.MethodGet, httpServer.URL+"/api/admin/overview", nil, false, http.StatusUnauthorized)
	})

	var lifecycleNodeID int64
	t.Run("admin read models validate empty, filtered and bounded pages", func(t *testing.T) {
		for _, path := range []string{
			"/api/admin/overview",
			"/api/admin/controller/rebuild",
			"/api/admin/nodes",
			"/api/admin/node-links",
			"/api/admin/users?limit=1&q=admin-http-user&status=active",
			"/api/admin/backups?limit=1",
			"/api/admin/alerts/protection?limit=10",
			"/api/admin/admins",
		} {
			assertControllerHTTPStatus(t, adminClient, http.MethodGet, httpServer.URL+path, nil, false, http.StatusOK)
		}
		assertControllerHTTPStatus(t, adminClient, http.MethodGet, httpServer.URL+"/api/admin/users?limit=101", nil, false, http.StatusBadRequest)
		assertControllerHTTPStatus(t, adminClient, http.MethodGet, httpServer.URL+"/api/admin/backups?before=-1", nil, false, http.StatusBadRequest)

		status, _, body := controllerHTTPRequest(t, adminClient, http.MethodGet, httpServer.URL+"/api/admin/admins", nil, false)
		if status != http.StatusOK || bytes.Contains(body, []byte(rootHash)) || bytes.Contains(body, []byte(rootPassword)) || bytes.Contains(body, []byte("password_hash")) {
			t.Fatalf("administrator list exposed credential material: status=%d body=%s", status, body)
		}
	})

	t.Run("node actions persist lifecycle, retirement and enrollment facts", func(t *testing.T) {
		assertControllerHTTPStatus(t, adminClient, http.MethodPost, httpServer.URL+"/api/admin/nodes", map[string]string{}, true, http.StatusBadRequest)
		status, _, body := controllerHTTPRequest(t, adminClient, http.MethodPost, httpServer.URL+"/api/admin/nodes", map[string]any{
			"name": "admin-http-lifecycle", "role": "compute", "base_url": "https://lifecycle.example/control",
		}, true)
		if status != http.StatusOK {
			t.Fatalf("create lifecycle node: status=%d body=%s", status, body)
		}
		lifecycleNodeID = controllerJSONInt64(t, body, "id")
		nodePath := httpServer.URL + "/api/admin/nodes/" + strconv.FormatInt(lifecycleNodeID, 10)

		assertControllerHTTPStatus(t, adminClient, http.MethodPut, httpServer.URL+"/api/admin/nodes/not-an-id", map[string]string{"name": "invalid"}, true, http.StatusBadRequest)
		assertControllerHTTPStatus(t, adminClient, http.MethodPut, nodePath, map[string]string{}, true, http.StatusBadRequest)
		assertControllerHTTPStatus(t, adminClient, http.MethodPut, nodePath, map[string]any{
			"name": "admin-http-lifecycle-updated", "base_url": "https://lifecycle.example/control",
			"allow_register": true, "is_backup_target": false,
		}, true, http.StatusOK)

		assertControllerHTTPStatus(t, adminClient, http.MethodGet, nodePath+"/retirement", nil, false, http.StatusNotFound)
		assertControllerHTTPStatus(t, adminClient, http.MethodGet, nodePath+"/compatibility-incident", nil, false, http.StatusNotFound)
		assertControllerHTTPStatus(t, adminClient, http.MethodGet, nodePath+"/imports/latest?limit=1&offset=0", nil, false, http.StatusOK)
		assertControllerHTTPStatus(t, adminClient, http.MethodGet, nodePath+"/imports/latest?limit=101", nil, false, http.StatusBadRequest)

		assertControllerHTTPStatus(t, adminClient, http.MethodPost, nodePath+"/admin-link", map[string]string{}, true, http.StatusBadRequest)
		assertControllerHTTPStatus(t, adminClient, http.MethodDelete, nodePath+"/admin-link", nil, true, http.StatusConflict)
		assertControllerHTTPStatus(t, adminClient, http.MethodPost, nodePath+"/admin-handoff",
			map[string]string{"operation_id": "73000000-0000-4000-8000-000000000001"}, true, http.StatusForbidden)

		status, _, enrollmentBody := controllerHTTPRequest(t, adminClient, http.MethodPost, nodePath+"/register-token", nil, true)
		if status != http.StatusOK {
			t.Fatalf("create node enrollment token: status=%d body=%s", status, enrollmentBody)
		}
		var enrollment struct {
			Token      string `json:"token"`
			InstallCmd string `json:"install_cmd"`
		}
		if err := json.Unmarshal(enrollmentBody, &enrollment); err != nil || enrollment.Token == "" ||
			!strings.Contains(enrollment.InstallCmd, enrollment.Token) {
			t.Fatalf("decode enrollment response: response=%+v err=%v body=%s", enrollment, err, enrollmentBody)
		}
		var storedTokenHash []byte
		if err := st.DB.QueryRowContext(ctx, `
			SELECT token_hash FROM enrollment_tokens
			WHERE expected_node_id=$1 ORDER BY created_at DESC LIMIT 1`, lifecycleNodeID).Scan(&storedTokenHash); err != nil {
			t.Fatalf("read enrollment token digest: %v", err)
		}
		wantTokenHash := sha256.Sum256([]byte(enrollment.Token))
		if !bytes.Equal(storedTokenHash, wantTokenHash[:]) || bytes.Contains(storedTokenHash, []byte(enrollment.Token)) {
			t.Fatalf("enrollment token was not stored as its SHA-256 digest")
		}

		assertControllerHTTPStatus(t, adminClient, http.MethodPost, nodePath+"/lifecycle",
			map[string]string{"operation_id": "invalid", "state": "active", "reason_code": "operator_activation"}, true, http.StatusBadRequest)
		lifecycle := func(operationID, state string) {
			t.Helper()
			assertControllerHTTPStatus(t, adminClient, http.MethodPost, nodePath+"/lifecycle", map[string]any{
				"operation_id": operationID, "state": state, "reason_code": "operator_" + state,
			}, true, http.StatusOK)
		}
		lifecycle("73000000-0000-4000-8000-000000000002", "active")
		// Exact replays are idempotent and do not create a second lifecycle event.
		lifecycle("73000000-0000-4000-8000-000000000002", "active")
		lifecycle("73000000-0000-4000-8000-000000000003", "maintenance")
		lifecycle("73000000-0000-4000-8000-000000000004", "draining")
		assertControllerHTTPStatus(t, adminClient, http.MethodGet, nodePath+"/retirement", nil, false, http.StatusOK)
		var lifecycleEvents int
		if err := st.DB.QueryRowContext(ctx, `SELECT count(*) FROM node_lifecycle_events WHERE node_id=$1`, lifecycleNodeID).Scan(&lifecycleEvents); err != nil || lifecycleEvents != 3 {
			t.Fatalf("durable lifecycle events=%d err=%v, want 3", lifecycleEvents, err)
		}
	})

	var secondAdminID int64
	const secondAdminPassword = "auditor-password-2026"
	const resetAdminPassword = "auditor-password-reset-2026"
	secondAdminClient := newControllerHTTPClient(t)
	t.Run("administrator mutations revoke sessions and protect the final admin", func(t *testing.T) {
		assertControllerHTTPStatus(t, adminClient, http.MethodPost, httpServer.URL+"/api/admin/admins",
			map[string]string{"username": "auditor", "password": "too-short"}, true, http.StatusBadRequest)
		status, _, body := controllerHTTPRequest(t, adminClient, http.MethodPost, httpServer.URL+"/api/admin/admins",
			map[string]string{"username": "auditor", "password": secondAdminPassword}, true)
		if status != http.StatusCreated {
			t.Fatalf("create second administrator: status=%d body=%s", status, body)
		}
		secondAdminID = controllerJSONInt64(t, body, "id")
		assertControllerHTTPStatus(t, adminClient, http.MethodPost, httpServer.URL+"/api/admin/admins",
			map[string]string{"username": "auditor", "password": secondAdminPassword}, true, http.StatusConflict)

		assertControllerHTTPStatus(t, secondAdminClient, http.MethodPost, httpServer.URL+"/api/auth/admin/login",
			map[string]string{"username": "auditor", "password": secondAdminPassword}, false, http.StatusOK)
		secondPath := httpServer.URL + "/api/admin/admins/" + strconv.FormatInt(secondAdminID, 10)
		assertControllerHTTPStatus(t, adminClient, http.MethodPut, secondPath+"/password",
			map[string]string{"password": "short"}, true, http.StatusBadRequest)
		assertControllerHTTPStatus(t, adminClient, http.MethodPut, secondPath+"/password",
			map[string]string{"password": resetAdminPassword}, true, http.StatusOK)
		assertControllerHTTPStatus(t, secondAdminClient, http.MethodGet, httpServer.URL+"/api/admin/overview", nil, false, http.StatusUnauthorized)
		assertControllerHTTPStatus(t, secondAdminClient, http.MethodPost, httpServer.URL+"/api/auth/admin/login",
			map[string]string{"username": "auditor", "password": secondAdminPassword}, false, http.StatusForbidden)
		assertControllerHTTPStatus(t, secondAdminClient, http.MethodPost, httpServer.URL+"/api/auth/admin/login",
			map[string]string{"username": "auditor", "password": resetAdminPassword}, false, http.StatusOK)

		assertControllerHTTPStatus(t, adminClient, http.MethodPut, secondPath+"/status",
			map[string]string{"status": "disabled"}, true, http.StatusOK)
		assertControllerHTTPStatus(t, secondAdminClient, http.MethodGet, httpServer.URL+"/api/admin/overview", nil, false, http.StatusUnauthorized)
		rootPath := httpServer.URL + "/api/admin/admins/" + strconv.FormatInt(rootAdmin.ID, 10)
		assertControllerHTTPStatus(t, adminClient, http.MethodPut, rootPath+"/status",
			map[string]string{"status": "disabled"}, true, http.StatusConflict)
	})

	t.Run("error actions stay bounded and disabling a user closes authorization", func(t *testing.T) {
		assertControllerHTTPStatus(t, adminClient, http.MethodPost, httpServer.URL+"/api/admin/users/not-an-id/backup", nil, true, http.StatusBadRequest)
		assertControllerHTTPStatus(t, adminClient, http.MethodPost, httpServer.URL+"/api/admin/users/999999/backup", nil, true, http.StatusNotFound)
		assertControllerHTTPStatus(t, adminClient, http.MethodPost, httpServer.URL+"/api/admin/backups/not-an-id/abort", nil, true, http.StatusBadRequest)
		assertControllerHTTPStatus(t, adminClient, http.MethodPost, httpServer.URL+"/api/admin/backups/999999/abort", nil, true, http.StatusNotFound)
		assertControllerHTTPStatus(t, adminClient, http.MethodGet, httpServer.URL+"/api/admin/users/"+url.PathEscape(user.UUID)+"/data-fault", nil, false, http.StatusNotFound)
		assertControllerHTTPStatus(t, adminClient, http.MethodPost, httpServer.URL+"/api/admin/users/"+url.PathEscape(user.UUID)+"/data-faults",
			map[string]string{"operation_id": "invalid"}, true, http.StatusBadRequest)

		// Re-login the user, then prove the admin status mutation makes the
		// previously valid durable session unusable on its next request.
		assertControllerHTTPStatus(t, userClient, http.MethodPost, httpServer.URL+"/api/auth/login",
			map[string]string{"username": user.Username, "password": userPassword}, false, http.StatusOK)
		assertControllerHTTPStatus(t, adminClient, http.MethodPost,
			httpServer.URL+"/api/admin/users/"+strconv.FormatInt(user.ID, 10)+"/disable", nil, true, http.StatusOK)
		assertControllerHTTPStatus(t, userClient, http.MethodGet, httpServer.URL+"/api/users/me", nil, false, http.StatusUnauthorized)
		assertControllerHTTPStatus(t, userClient, http.MethodPost, httpServer.URL+"/api/auth/login",
			map[string]string{"username": user.Username, "password": userPassword}, false, http.StatusForbidden)

		var userStatus string
		if err := st.DB.QueryRowContext(ctx, `SELECT status FROM users WHERE id=$1`, user.ID).Scan(&userStatus); err != nil || userStatus != "disabled" {
			t.Fatalf("disabled user status=%q err=%v", userStatus, err)
		}
	})
}

func newControllerHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create HTTP cookie jar: %v", err)
	}
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func controllerHTTPRequest(
	t *testing.T,
	client *http.Client,
	method, target string,
	body any,
	withCSRF bool,
) (int, http.Header, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode %s %s body: %v", method, target, err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatalf("create %s %s request: %v", method, target, err)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse request target %q: %v", target, err)
	}
	req.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withCSRF {
		token := controllerCookieValue(t, client, target, csrfCookie)
		if token == "" {
			t.Fatalf("%s %s requested CSRF protection without a CSRF cookie", method, target)
		}
		req.Header.Set("X-CSRF-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("execute %s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s response: %v", method, target, err)
	}
	return resp.StatusCode, resp.Header.Clone(), responseBody
}

func assertControllerHTTPStatus(
	t *testing.T,
	client *http.Client,
	method, target string,
	body any,
	withCSRF bool,
	want int,
) {
	t.Helper()
	got, _, responseBody := controllerHTTPRequest(t, client, method, target, body, withCSRF)
	if got != want {
		t.Fatalf("%s %s: status=%d, want %d, body=%s", method, target, got, want, responseBody)
	}
}

func controllerCookieValue(t *testing.T, client *http.Client, target, name string) string {
	t.Helper()
	if client == nil || client.Jar == nil {
		return ""
	}
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse cookie target %q: %v", target, err)
	}
	for _, cookie := range client.Jar.Cookies(parsed) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

func assertControllerSessionCookies(t *testing.T, client *http.Client, target string) {
	t.Helper()
	if controllerCookieValue(t, client, target, sessionCookie) == "" ||
		controllerCookieValue(t, client, target, csrfCookie) == "" {
		t.Fatalf("authenticated client is missing its session or CSRF cookie")
	}
}

func controllerJSONInt64(t *testing.T, body []byte, field string) int64 {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(body, &object); err != nil {
		t.Fatalf("decode JSON object: %v body=%s", err, body)
	}
	value, ok := object[field].(float64)
	if !ok || value <= 0 || value != float64(int64(value)) {
		t.Fatalf("JSON field %q is not a positive integer: %v (body=%s)", field, object[field], body)
	}
	return int64(value)
}
