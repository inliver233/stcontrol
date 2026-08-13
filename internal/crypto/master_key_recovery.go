package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// ---------- Round 61: master-key recovery material ----------
//
// A lost control-plane master key (CONTROLLER_SECRET_KEY) permanently breaks
// every encrypted Agent credential, so the controller disaster backup includes
// an optional recovery envelope: the master key, encrypted under a key derived
// from a recovery passphrase the operator keeps out-of-band (printed or in a
// password manager).  Only a holder of that passphrase can unwrap the envelope;
// the backup archive itself never contains the key in plaintext.

// MasterKeyRecoveryEnvelope is the on-disk format stored in the backup archive.
type MasterKeyRecoveryEnvelope struct {
	FormatVersion int    `json:"format_version"` // 1
	ScryptN       int    `json:"scrypt_n"`
	ScryptR       int    `json:"scrypt_r"`
	ScryptP       int    `json:"scrypt_p"`
	SaltB64       string `json:"salt_b64"`
	CiphertextB64 string `json:"ciphertext_b64"`
}

// SealMasterKeyRecovery derives an AES-256 key from the recovery passphrase
// (scrypt with a fresh random salt) and encrypts the master key.  The returned
// envelope is JSON-serializable and safe to store in the disaster backup.
func SealMasterKeyRecovery(passphrase string, masterKey []byte) (*MasterKeyRecoveryEnvelope, error) {
	if len(passphrase) < 8 {
		return nil, errors.New("recovery passphrase must be at least 8 characters")
	}
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	const (
		n = 1 << 15
		r = 8
		p = 1
	)
	derived, err := scrypt.Key([]byte(passphrase), salt, n, r, p, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, masterKey, nil)
	return &MasterKeyRecoveryEnvelope{
		FormatVersion: 1,
		ScryptN:       n, ScryptR: r, ScryptP: p,
		SaltB64:       base64.StdEncoding.EncodeToString(salt),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// OpenMasterKeyRecovery unwraps an envelope produced by SealMasterKeyRecovery.
func OpenMasterKeyRecovery(passphrase string, envelope *MasterKeyRecoveryEnvelope) ([]byte, error) {
	if envelope == nil || envelope.FormatVersion != 1 {
		return nil, errors.New("unsupported master key recovery envelope")
	}
	if len(passphrase) < 8 {
		return nil, errors.New("recovery passphrase must be at least 8 characters")
	}
	if envelope.ScryptN <= 0 || envelope.ScryptR <= 0 || envelope.ScryptP <= 0 ||
		envelope.ScryptN > 1<<20 || envelope.ScryptR > 64 || envelope.ScryptP > 4 {
		return nil, errors.New("invalid recovery KDF parameters")
	}
	salt, err := base64.StdEncoding.DecodeString(envelope.SaltB64)
	if err != nil || len(salt) < 8 {
		return nil, errors.New("invalid recovery salt")
	}
	derived, err := scrypt.Key([]byte(passphrase), salt, envelope.ScryptN, envelope.ScryptR, envelope.ScryptP, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(envelope.CiphertextB64)
	if err != nil || len(raw) < gcm.NonceSize() {
		return nil, errors.New("invalid recovery ciphertext")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("recovery passphrase incorrect or envelope corrupted")
	}
	if len(plaintext) != 32 {
		return nil, errors.New("unwrapped master key has invalid length")
	}
	return plaintext, nil
}

// EncodeMasterKeyRecoveryJSON / DecodeMasterKeyRecoveryJSON are thin helpers so
// callers embed the envelope as a JSON object in the backup manifest.
func EncodeMasterKeyRecoveryJSON(envelope *MasterKeyRecoveryEnvelope) ([]byte, error) {
	if envelope == nil {
		return nil, errors.New("nil recovery envelope")
	}
	return json.Marshal(envelope)
}

func DecodeMasterKeyRecoveryJSON(data []byte) (*MasterKeyRecoveryEnvelope, error) {
	var envelope MasterKeyRecoveryEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	return &envelope, nil
}

// HashMasterKeyRecovery derives a stable public digest of an envelope so the
// manifest can prove a recovery envelope is present without exposing it.
func HashMasterKeyRecovery(envelope *MasterKeyRecoveryEnvelope) string {
	if envelope == nil {
		return ""
	}
	data, _ := json.Marshal(envelope)
	sum := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(sum[:])
}
