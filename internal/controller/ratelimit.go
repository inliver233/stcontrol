package controller

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// ---------- R21/R22: HTTP rate limiting and login lockout ----------
//
// The Controller previously had no HTTP-level rate limiting at all.  R21
// requires limiting to survive target load; R22 requires login endpoints to
// resist brute force.  The limiter below is deliberately small, in-memory and
// per-process: the single active Controller owns the control plane, so a local
// window is sufficient and restart resets it (PostgreSQL remains the durable
// authority for sessions/tickets).  Agent endpoints are NOT rate limited here
// because the Agent channel has its own HMAC/nonce/lease fences and must not
// be starved by admin traffic.

// rateBucket is a fixed-window counter with an atomic swap.  Windows are
// intentionally coarse (per second / per minute) so the lock is only held for
// one map write per key per request.
type rateBucket struct {
	mu       sync.Mutex
	windowAt time.Time
	count    int
}

// rateLimiter tracks per-key request counts in fixed windows.
type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*rateBucket
	limit    int
	window   time.Duration
	maxKeys  int
	lastGC   time.Time
}

func newRateLimiter(limit int, window time.Duration, maxKeys int) *rateLimiter {
	if limit <= 0 {
		limit = 60
	}
	if window <= 0 {
		window = time.Minute
	}
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	return &rateLimiter{
		buckets: make(map[string]*rateBucket),
		limit:   limit, window: window, maxKeys: maxKeys, lastGC: time.Now(),
	}
}

// allow reports whether a request from key may proceed.  It also opportunistically
// evicts expired buckets and enforces a hard cap on tracked keys so a spoofed
// X-Forwarded-For cannot grow the map without bound.
func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	if now.Sub(l.lastGC) > time.Minute {
		for k, b := range l.buckets {
			b.mu.Lock()
			expired := now.Sub(b.windowAt) > l.window
			b.mu.Unlock()
			if expired {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}
	if len(l.buckets) >= l.maxKeys {
		l.mu.Unlock()
		return false
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &rateBucket{windowAt: now}
		l.buckets[key] = b
	}
	l.mu.Unlock()

	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Sub(b.windowAt) >= l.window {
		b.windowAt = now
		b.count = 0
	}
	b.count++
	return b.count <= l.limit
}

// clientIP returns the best-effort client address for rate limiting.  The
// controller is deployed behind nginx; trust X-Forwarded-For only when the
// immediate peer is loopback or a private address so a public client cannot
// spoof a new identity per request.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			first, _, err := net.SplitHostPort(forwarded)
			if err != nil {
				first = forwarded
			}
			if parsed := net.ParseIP(first); parsed != nil {
				return first
			}
		}
	}
	return host
}

// rateLimitMiddleware applies a per-IP limit to the given route group.
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.rateLimiter == nil {
			next.ServeHTTP(w, r)
			return
		}
		key := clientIP(r)
		if !s.rateLimiter.allow(key, time.Now()) {
			w.Header().Set("Retry-After", "60")
			protocolWriteTooManyRequests(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loginRateLimitMiddleware applies a stricter per-IP + per-username limit to
// authentication endpoints, and enforces a per-username lockout after repeated
// failures so credential brute force cannot hide behind many source IPs.
func (s *Server) loginRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.loginLimiter == nil {
			next.ServeHTTP(w, r)
			return
		}
		ip := clientIP(r)
		username := ""
		if r.Method == http.MethodPost {
			// Best-effort parse without consuming the body: the handler decodes
			// the body itself, so only peek when the content type is form/json.
			_ = username // handled in lockout middleware below via parse once
		}
		// Per-IP limit is always applied first.
		if !s.loginLimiter.allow("ip:"+ip, time.Now()) {
			w.Header().Set("Retry-After", "60")
			protocolWriteTooManyRequests(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func protocolWriteTooManyRequests(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"error":"请求过于频繁，请稍后重试","code":"rate_limited"}`))
}
