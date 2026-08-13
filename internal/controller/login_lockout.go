package controller

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"stcontrol/internal/protocol"
)

// ---------- R22: login lockout ----------
//
// Beyond per-IP rate limiting, authentication endpoints also enforce a
// per-username lockout: after a small number of consecutive failures the
// username is temporarily locked with a growing backoff so credential brute
// force cannot hide behind many source IPs.  Success clears the failure
// counter.  The state is in-memory (the single active Controller owns the
// control plane); a restart resets counters but never weakens the durable
// session/ticket authority.

type loginFailureState struct {
	failures    int
	lockedUntil time.Time
}

// loginLockout tracks per-username consecutive failures.
type loginLockout struct {
	mu          sync.Mutex
	failures    map[string]loginFailureState
	maxFailures int
	baseDelay   time.Duration
	maxDelay    time.Duration
	now         func() time.Time
}

func newLoginLockout(maxFailures int, baseDelay, maxDelay time.Duration) *loginLockout {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if baseDelay <= 0 {
		baseDelay = 30 * time.Second
	}
	if maxDelay <= 0 {
		maxDelay = 15 * time.Minute
	}
	return &loginLockout{
		failures:    make(map[string]loginFailureState),
		maxFailures: maxFailures,
		baseDelay:   baseDelay,
		maxDelay:    maxDelay,
		now:         time.Now,
	}
}

// locked reports whether the username is currently locked out and, if so,
// how long until it unlocks.  Callers must report failures via recordFailure
// and clear via recordSuccess.
func (l *loginLockout) locked(username string) (bool, time.Duration) {
	if username == "" {
		return false, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	state, ok := l.failures[username]
	if !ok {
		return false, 0
	}
	now := l.now()
	if state.lockedUntil.After(now) {
		return true, state.lockedUntil.Sub(now)
	}
	return false, 0
}

// recordFailure increments the failure counter and applies exponential
// backoff once the threshold is reached.
func (l *loginLockout) recordFailure(username string) {
	if username == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.failures[username]
	state.failures++
	if state.failures >= l.maxFailures {
		delay := l.baseDelay
		for i := l.maxFailures; i < state.failures && delay < l.maxDelay; i++ {
			delay *= 2
			if delay > l.maxDelay {
				delay = l.maxDelay
			}
		}
		state.lockedUntil = l.now().Add(delay)
	}
	l.failures[username] = state
}

// recordSuccess clears the failure counter for a username.
func (l *loginLockout) recordSuccess(username string) {
	if username == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, username)
}

// peekLoginUsername decodes the JSON body once and returns both the username
// and the reconstructed body so a subsequent handler can decode it again
// without reading a consumed stream.
func peekLoginUsername(r *http.Request) (string, []byte) {
	if r.Body == nil {
		return "", nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return "", nil
	}
	var body struct {
		Username string `json:"username"`
	}
	_ = json.Unmarshal(raw, &body)
	return body.Username, raw
}

// loginLockoutMiddleware rejects locked-out usernames before the handler runs.
// The JSON body is buffered once and restored so the handler sees the exact
// original request.
func (s *Server) loginLockoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.loginLockout == nil {
			next.ServeHTTP(w, r)
			return
		}
		username, raw := peekLoginUsername(r)
		if raw != nil {
			r.Body = io.NopCloser(bytes.NewReader(raw))
		}
		if locked, wait := s.loginLockout.locked(username); locked {
			w.Header().Set("Retry-After", formatRetryAfter(wait))
			protocol.WriteError(w, http.StatusTooManyRequests, "登录尝试过于频繁，请稍后再试")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func formatRetryAfter(wait time.Duration) string {
	seconds := int(wait.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return itoa(seconds)
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	if negative {
		index--
		digits[index] = '-'
	}
	return string(digits[index:])
}
