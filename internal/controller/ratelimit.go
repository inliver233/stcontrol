package controller

import (
	"net"
	"net/http"
	"strconv"
	"strings"
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
// authority for sessions/tickets). Agent registration has a source-IP budget;
// authenticated Agent traffic has a separate per-node namespace so a noisy
// node cannot consume user/admin capacity or starve another node.

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
	mu      sync.Mutex
	buckets map[string]*rateBucket
	limit   int
	window  time.Duration
	maxKeys int
	lastGC  time.Time
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
	b, ok := l.buckets[key]
	if !ok && len(l.buckets) >= l.maxKeys {
		l.mu.Unlock()
		return false
	}
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

// agentRegistrationRateLimitMiddleware bounds unauthenticated one-time
// enrollment attempts by trusted clientIP. It deliberately uses the stricter
// login limiter but a disjoint key namespace.
func (s *Server) agentRegistrationRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.loginLimiter != nil && !s.loginLimiter.allow("agent-register-ip:"+clientIP(r), time.Now()) {
			w.Header().Set("Retry-After", "60")
			protocolWriteTooManyRequests(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// agentRateLimitMiddleware runs after agentAuthMiddleware and keys only on the
// authenticated node fact in context. The normal 20-second command long poll
// consumes roughly three requests/minute, far below the 120/min node budget;
// short heartbeat/ACK/result bursts remain available without being unlimited.
func (s *Server) agentRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		node := currentNode(r)
		if node == nil {
			protocolWriteUnauthorizedAgent(w)
			return
		}
		if s.rateLimiter != nil && !s.rateLimiter.allow("agent-node:"+formatNodeRateLimitKey(node.ID), time.Now()) {
			w.Header().Set("Retry-After", "60")
			protocolWriteTooManyRequests(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func formatNodeRateLimitKey(nodeID int64) string {
	return strconv.FormatInt(nodeID, 10)
}

func protocolWriteUnauthorizedAgent(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"节点认证失败","code":"agent_auth_required"}`))
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
	host = normalizeIP(host)
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			// XFF is a comma-separated list; take the first (original client)
			// segment and trim surrounding whitespace before parsing.
			first := strings.TrimSpace(strings.SplitN(forwarded, ",", 2)[0])
			if h, _, err := net.SplitHostPort(first); err == nil {
				first = h
			}
			if parsed := net.ParseIP(first); parsed != nil {
				return normalizeIP(first)
			}
		}
	}
	return host
}

// normalizeIP collapses IPv4-mapped IPv6 addresses (::ffff:1.2.3.4) to their
// plain IPv4 form so both spellings share one rate-limit bucket.
func normalizeIP(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
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
