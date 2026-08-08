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

func TestAdministratorHandoffUsesPurposeSeparatedSecret(t *testing.T) {
	t.Parallel()
	key := []byte("01234567890123456789012345678901")
	jti := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	adminSecret := deriveAdminHandoffSecret(key, jti)
	loginSecret := deriveLoginHandoffSecret(key, jti)
	if hmac.Equal(adminSecret, loginSecret) {
		t.Fatal("administrator and user handoffs derived the same secret")
	}
	if !hmac.Equal(adminSecret, deriveAdminHandoffSecret(key, jti)) {
		t.Fatal("administrator handoff derivation is not deterministic")
	}
}

func TestAdministratorVerificationDigestBindsPrincipalNodeAndPassword(t *testing.T) {
	t.Parallel()
	server := &Server{secretKey: []byte("01234567890123456789012345678901")}
	base, err := server.adminNodeVerificationDigest(1, 2, "node-admin", "password-one")
	if err != nil || len(base) != 32 {
		t.Fatalf("digest length=%d err=%v", len(base), err)
	}
	variants := []struct {
		adminID  int64
		nodeID   int64
		handle   string
		password string
	}{
		{2, 2, "node-admin", "password-one"},
		{1, 3, "node-admin", "password-one"},
		{1, 2, "other-admin", "password-one"},
		{1, 2, "node-admin", "password-two"},
	}
	for _, variant := range variants {
		digest, err := server.adminNodeVerificationDigest(
			variant.adminID, variant.nodeID, variant.handle, variant.password,
		)
		if err != nil {
			t.Fatal(err)
		}
		if hmac.Equal(base, digest) {
			t.Fatalf("digest did not bind variant=%+v", variant)
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
