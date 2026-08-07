package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

const (
	sillyTavernScryptN      = 1 << 14
	sillyTavernScryptR      = 8
	sillyTavernScryptP      = 1
	sillyTavernScryptKeyLen = 64
)

// SillyTavernPasswordMaterial derives the same base64 scrypt material as
// crypto.scryptSync(password.normalize(), salt, 64) in SillyTavern.
func SillyTavernPasswordMaterial(password string) (hash string, salt string, err error) {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", "", fmt.Errorf("generate password salt: %w", err)
	}
	salt = base64.StdEncoding.EncodeToString(saltBytes)
	hashBytes, err := scrypt.Key(
		[]byte(norm.NFC.String(password)), []byte(salt),
		sillyTavernScryptN, sillyTavernScryptR, sillyTavernScryptP, sillyTavernScryptKeyLen,
	)
	if err != nil {
		return "", "", fmt.Errorf("derive SillyTavern password hash: %w", err)
	}
	return base64.StdEncoding.EncodeToString(hashBytes), salt, nil
}
