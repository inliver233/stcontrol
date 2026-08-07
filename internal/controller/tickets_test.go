package controller

import (
	"crypto/hmac"
	"encoding/base64"
	"strings"
	"testing"
)

func TestLoginHandoffCodeRoundTrip(t *testing.T) {
	t.Parallel()
	key := []byte("01234567890123456789012345678901")
	jti := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	secret := deriveLoginHandoffSecret(key, jti)
	code := jti + "." + base64.RawURLEncoding.EncodeToString(secret)

	gotJTI, gotSecret, ok := parseLoginHandoffCode(code)
	if !ok || gotJTI != jti || !hmac.Equal(gotSecret, secret) {
		t.Fatalf("parseLoginHandoffCode failed: jti=%q ok=%v", gotJTI, ok)
	}
}

func TestLoginHandoffCodeRejectsMalformedValues(t *testing.T) {
	t.Parallel()
	for _, code := range []string{
		"", "not-a-uuid.secret", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.not-base64!",
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa." + base64.RawURLEncoding.EncodeToString([]byte("short")),
	} {
		if _, _, ok := parseLoginHandoffCode(code); ok {
			t.Fatalf("parseLoginHandoffCode(%q) succeeded", code)
		}
	}
}

func TestNewUUIDProducesCanonicalDistinctValues(t *testing.T) {
	t.Parallel()
	a, err := newUUID()
	if err != nil {
		t.Fatalf("newUUID: %v", err)
	}
	b, err := newUUID()
	if err != nil {
		t.Fatalf("newUUID: %v", err)
	}
	if !isUUID(a) || !isUUID(b) || a == b || strings.ToLower(a) != a {
		t.Fatalf("unexpected UUIDs: %q %q", a, b)
	}
}
