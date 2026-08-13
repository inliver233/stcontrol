package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

