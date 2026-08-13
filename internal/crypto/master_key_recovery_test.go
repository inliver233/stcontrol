package crypto

import (
	"bytes"
	"testing"
)

func TestMasterKeyRecoverySealAndOpenRoundTrip(t *testing.T) {
	t.Parallel()
	masterKey := bytes.Repeat([]byte{0x42}, 32)
	passphrase := "recovery-passphrase-123"

	envelope, err := SealMasterKeyRecovery(passphrase, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.FormatVersion != 1 || envelope.SaltB64 == "" || envelope.CiphertextB64 == "" {
		t.Fatalf("incomplete envelope: %+v", envelope)
	}
	if HashMasterKeyRecovery(envelope) == "" {
		t.Fatal("empty digest")
	}

	// JSON round trip.
	data, err := EncodeMasterKeyRecoveryJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMasterKeyRecoveryJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.CiphertextB64 != envelope.CiphertextB64 {
		t.Fatal("JSON round trip changed envelope")
	}

	// Correct passphrase unwraps the exact key.
	got, err := OpenMasterKeyRecovery(passphrase, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, masterKey) {
		t.Fatal("unwrapped key mismatch")
	}
}

func TestMasterKeyRecoveryRejectsWrongPassphraseAndTampering(t *testing.T) {
	t.Parallel()
	masterKey := bytes.Repeat([]byte{0x24}, 32)
	envelope, err := SealMasterKeyRecovery("correct-horse-battery", masterKey)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong passphrase fails (GCM auth tag).
	if _, err := OpenMasterKeyRecovery("wrong-passphrase", envelope); err == nil {
		t.Fatal("wrong passphrase was accepted")
	}

	// Tampered ciphertext fails.
	tampered := *envelope
	tampered.CiphertextB64 = "AAAA" + envelope.CiphertextB64
	if _, err := OpenMasterKeyRecovery("correct-horse-battery", &tampered); err == nil {
		t.Fatal("tampered envelope was accepted")
	}

	// Reject weak passphrase and bad KDF params.
	if _, err := SealMasterKeyRecovery("short", masterKey); err == nil {
		t.Fatal("short passphrase was accepted")
	}
	bad := *envelope
	bad.ScryptN = -1
	if _, err := OpenMasterKeyRecovery("correct-horse-battery", &bad); err == nil {
		t.Fatal("invalid KDF params were accepted")
	}
}