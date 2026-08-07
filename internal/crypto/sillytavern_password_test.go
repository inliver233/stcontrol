package crypto

import (
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

func TestSillyTavernPasswordMaterialMatchesNodeScryptParameters(t *testing.T) {
	t.Parallel()
	password := "pa\u0308ssword"
	hash, salt, err := SillyTavernPasswordMaterial(password)
	if err != nil {
		t.Fatal(err)
	}
	decodedSalt, err := base64.StdEncoding.DecodeString(salt)
	if err != nil || len(decodedSalt) != 16 {
		t.Fatalf("salt=%q decoded=%d err=%v", salt, len(decodedSalt), err)
	}
	want, err := scrypt.Key([]byte(norm.NFC.String(password)), []byte(salt), 1<<14, 8, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	if hash != base64.StdEncoding.EncodeToString(want) {
		t.Fatalf("hash mismatch: %q", hash)
	}
}

func TestSillyTavernPasswordMaterialUsesFreshSalt(t *testing.T) {
	t.Parallel()
	hashA, saltA, err := SillyTavernPasswordMaterial("same-password")
	if err != nil {
		t.Fatal(err)
	}
	hashB, saltB, err := SillyTavernPasswordMaterial("same-password")
	if err != nil {
		t.Fatal(err)
	}
	if saltA == saltB || hashA == hashB {
		t.Fatal("password material was reused")
	}
}
