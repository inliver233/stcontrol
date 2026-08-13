package ai

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// redaction.go implements field-level redaction and secret scanning for the
// AI 监管层 (ai接入优化方案详细.md §4.4). Observation builders must never pass
// raw identifiers, paths, keys or content through; every value that reaches
// the provider goes through Redactor or is constructed from allowlisted enum
// buckets by the builder itself.

// Redactor derives short-lived, per-task pseudonymous refs with HMAC so the
// same fact cannot be correlated across tasks. It also scans text for secret
// patterns before anything may leave the server.
type Redactor struct {
	key []byte
}

// NewRedactor builds a Redactor from a server-side secret (e.g. the control
// plane master key). A new observation salt is mixed in per observation so
// refs are not stable across tasks.
func NewRedactor(masterKey []byte) *Redactor {
	if len(masterKey) == 0 {
		// Tests and misconfiguration: derive a random per-process key so the
		// refs are still non-reversible and non-correlatable across restarts.
		masterKey = make([]byte, 32)
		_, _ = rand.Read(masterKey)
	}
	return &Redactor{key: append([]byte(nil), masterKey...)}
}

// Ref derives a short pseudonymous ref for a stable internal identifier.
// The salt (observation salt) must differ per observation.
func (r *Redactor) Ref(prefix, salt, id string) string {
	mac := hmac.New(sha256.New, r.key)
	_, _ = mac.Write([]byte(salt))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(id))
	sum := mac.Sum(nil)
	return fmt.Sprintf("%s_%s", prefix, base64.RawURLEncoding.EncodeToString(sum[:12]))
}

// Bucket rounds a percentage into the documented 5% buckets.
func Bucket(pct float64) int64 {
	if pct < 0 {
		return 0
	}
	if pct > 100 {
		return 100
	}
	return int64(pct/5) * 5
}

// secretPatterns match the credential shapes that must never leave the server
// (keys, tokens, JWTs, bearer, cookies, nonces, hashes, paths, URLs).
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:sk|pk|rk|ak|api[_-]?key|secret|token|bearer|password|passwd|pwd|nonce|jti|salt)\b[=:\s]+\s*[^\s,;]{8,}`),
	regexp.MustCompile(`(?i)authorization\s*[:=]\s*\S+`),
	regexp.MustCompile(`(?i)set-cookie\s*[:=]`),
	regexp.MustCompile(`(?i)x-csrf-token\s*[:=]\s*\S+`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), // JWT
	regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`),                                         // long base64 blob
	regexp.MustCompile(`[a-f0-9]{64}`),                                                     // sha256 hex
	regexp.MustCompile(`[A-Za-z]:\\[^\s"]+`),                                               // windows path
	regexp.MustCompile(`/(?:home|Users|data|var|tmp|srv|opt)/[^\s"]+`),                     // unix path
	regexp.MustCompile(`https?://[^\s"]+`),                                                 // URL
}

// ContainsSecret reports whether text matches any secret pattern. Returns the
// first matched pattern kind for diagnostics.
func ContainsSecret(text string) (bool, string) {
	if len(text) > 1<<20 {
		return true, "oversized"
	}
	for _, re := range secretPatterns {
		if loc := re.FindStringIndex(text); loc != nil {
			start := loc[0]
			if start > 24 {
				start -= 24
			}
			snippet := text[start:loc[1]]
			if len(snippet) > 64 {
				snippet = snippet[:64]
			}
			return true, hex.EncodeToString([]byte(snippet))
		}
	}
	return false, ""
}

// SanitizeText strips secret-bearing spans from free text (used for alert
// summaries before they may be embedded in an observation).
func SanitizeText(text string) string {
	if text == "" {
		return ""
	}
	out := text
	for _, re := range secretPatterns {
		out = re.ReplaceAllString(out, "[redacted]")
	}
	// Collapse repeated redaction markers.
	for strings.Contains(out, "[redacted] [redacted]") {
		out = strings.ReplaceAll(out, "[redacted] [redacted]", "[redacted]")
	}
	if len(out) > 512 {
		out = out[:512] + "…"
	}
	return out
}

// ObservationID builds a fresh observation identifier.
func ObservationID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "obs_" + base64.RawURLEncoding.EncodeToString(b[:])
}

// refPattern matches refs the model may emit (ev_/ref_ + 8-80 URL-safe chars).
var refPattern = regexp.MustCompile(`^(?:ev|ref)_[A-Za-z0-9_-]{8,80}$`)

// ValidRef reports whether a candidate/evidence ref has the allowed shape.
func ValidRef(ref string) bool { return refPattern.MatchString(ref) }
