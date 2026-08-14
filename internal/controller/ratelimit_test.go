package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
)

func TestRateLimiterAllowsUpToLimitThenRejects(t *testing.T) {
	t.Parallel()
	limiter := newRateLimiter(3, time.Minute, 100)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !limiter.allow("key-a", now) {
			t.Fatalf("request %d within limit was rejected", i+1)
		}
	}
	if limiter.allow("key-a", now) {
		t.Fatal("request beyond limit was allowed")
	}
	// A different key is unaffected.
	if !limiter.allow("key-b", now) {
		t.Fatal("unrelated key was rejected")
	}
	// Window expiry resets the counter.
	if !limiter.allow("key-a", now.Add(2*time.Minute)) {
		t.Fatal("request after window expiry was rejected")
	}
}

func TestRateLimiterRespectsMaxKeys(t *testing.T) {
	t.Parallel()
	limiter := newRateLimiter(10, time.Minute, 2)
	now := time.Now()
	limiter.allow("a", now)
	limiter.allow("b", now)
	if limiter.allow("c", now) {
		t.Fatal("key beyond maxKeys was allowed")
	}
}

func TestRateLimitMiddlewareRejectsBurst(t *testing.T) {
	t.Parallel()
	server := &Server{rateLimiter: newRateLimiter(2, time.Minute, 100)}
	handler := server.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 2; i++ {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("request %d status=%d", i+1, recorder.Code)
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("burst status=%d want 429", recorder.Code)
	}
	if recorder.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
}

func TestLoginLockoutLocksAfterFailuresAndRecovers(t *testing.T) {
	t.Parallel()
	now := time.Now()
	lockout := newLoginLockout(3, time.Minute, 10*time.Minute)
	lockout.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		lockout.recordFailure("alice")
	}
	if locked, wait := lockout.locked("alice"); !locked || wait <= 0 {
		t.Fatalf("expected lockout after 3 failures, locked=%v wait=%v", locked, wait)
	}
	// Backoff grows for continued failures.
	lockout.recordFailure("alice")
	lockout.recordFailure("alice")
	if _, wait := lockout.locked("alice"); wait < time.Minute {
		t.Fatalf("expected growing backoff, got %v", wait)
	}
	// Success clears the counter.
	lockout.recordSuccess("alice")
	if locked, _ := lockout.locked("alice"); locked {
		t.Fatal("lockout not cleared after success")
	}
	// Lock expiry allows retry.
	lockout.recordFailure("bob")
	lockout.recordFailure("bob")
	lockout.recordFailure("bob")
	if locked, _ := lockout.locked("bob"); !locked {
		t.Fatal("bob should be locked")
	}
	now = now.Add(30 * time.Minute)
	if locked, _ := lockout.locked("bob"); locked {
		t.Fatal("bob should be unlocked after expiry")
	}
}

func TestLoginLockoutMiddlewareRejectsLockedUsername(t *testing.T) {
	t.Parallel()
	lockout := newLoginLockout(2, time.Minute, 10*time.Minute)
	lockout.recordFailure("alice")
	lockout.recordFailure("alice")
	server := &Server{loginLockout: lockout}
	handler := server.loginLockoutMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	body := `{"username":"alice","password":"x"}`
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body)))
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want 429", recorder.Code)
	}
	if recorder.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
	// Unlocked username passes through with body intact.
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"bob","password":"x"}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("unlocked status=%d", recorder.Code)
	}
}


func TestClientIPIgnoresSpoofedForwardedHeadersFromPublicPeer(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodGet, "/api/users/me", nil)
	request.RemoteAddr = "203.0.113.9:4711"
	request.Header.Set("X-Real-IP", "10.0.0.7")
	request.Header.Set("True-Client-IP", "10.0.0.8")
	request.Header.Set("X-Forwarded-For", "198.51.100.23, 10.0.0.9")
	if got := clientIP(request); got != "203.0.113.9" {
		t.Fatalf("public peer clientIP=%q, want the true peer 203.0.113.9", got)
	}
	// A loopback peer (deployment behind a local proxy) still trusts XFF.
	request.RemoteAddr = "127.0.0.1:4711"
	if got := clientIP(request); got != "198.51.100.23" {
		t.Fatalf("loopback peer clientIP=%q, want first XFF segment", got)
	}
}

// TestRouterDoesNotRewriteRemoteAddrWithSpoofableHeaders guards the removal of
// the global middleware.RealIP (D1): chi must not rewrite RemoteAddr before
// the rate limiting stack sees it, otherwise a public attacker could rotate
// per-IP limit keys with forged X-Real-IP/XFF headers.
func TestRouterDoesNotRewriteRemoteAddrWithSpoofableHeaders(t *testing.T) {
	t.Parallel()
	var seenRemoteAddr string
	router := newRouter()
	router.Get("/probe", func(w http.ResponseWriter, r *http.Request) {
		seenRemoteAddr = r.RemoteAddr
		w.WriteHeader(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodGet, "/probe", nil)
	request.RemoteAddr = "203.0.113.9:4711"
	request.Header.Set("X-Real-IP", "10.0.0.7")
	request.Header.Set("X-Forwarded-For", "198.51.100.23, 10.0.0.9")
	router.ServeHTTP(httptest.NewRecorder(), request)
	if seenRemoteAddr != "203.0.113.9:4711" {
		t.Fatalf("RemoteAddr rewritten to %q; router must not trust spoofable headers", seenRemoteAddr)
	}
}

// TestGlobalRateLimitMountedOnUserAndAdminRoutes guards the R21 global
// 120/min per-IP limiter actually being mounted (D2): the user and admin
// route groups must return 429 once the budget is exhausted.
func TestGlobalRateLimitMountedOnUserAndAdminRoutes(t *testing.T) {
	t.Parallel()
	server := &Server{Cfg: &config.ControllerConfig{}, rateLimiter: newRateLimiter(2, time.Minute, 100)}
	router := server.Handler()
	hit := func(path string) int {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.RemoteAddr = "203.0.113.9:4711"
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		return recorder.Code
	}
	// Two requests exhaust the budget; the third must be shed before auth.
	for i := 0; i < 2; i++ {
		if code := hit("/api/users/me"); code == http.StatusTooManyRequests {
			t.Fatalf("request %d shed too early with status 429", i+1)
		}
	}
	if code := hit("/api/users/me"); code != http.StatusTooManyRequests {
		t.Fatalf("user route status=%d want 429 after budget exhaustion", code)
	}
	// Budget is shared per IP across the admin group as well.
	if code := hit("/api/admin/overview"); code != http.StatusTooManyRequests {
		t.Fatalf("admin route status=%d want 429 under the same exhausted IP budget", code)
	}
	// Health check and agent HMAC channel stay outside the global limiter.
	healthy := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	healthy.RemoteAddr = "203.0.113.9:4711"
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, healthy)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("health route status=%d want 204 (must not be rate limited)", recorder.Code)
	}
}
