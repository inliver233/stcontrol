// Package crypto 提供控制面凭据加密、密码验证材料和用途隔离的密钥派生。
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// ---------- 密钥 ----------

// LoadKey 从 base64 字符串解码 32 字节 AES 密钥。
func LoadKey(b64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode secret key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("secret key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}

// GenerateKey 生成 32 字节随机密钥（base64 输出）。
func GenerateKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ---------- AES-256-GCM 凭据加密 ----------

// Encrypt 用 AES-GCM 加密明文，输出 base64(nonce|ciphertext)。
func Encrypt(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt 解密 base64(nonce|ciphertext)。
func Decrypt(key []byte, encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// ---------- bcrypt ----------

// HashPassword 生成 bcrypt 哈希。
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

// CheckPassword 校验密码。
func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// ---------- 随机密码 ----------

// RandomPassword 生成指定长度的随机密码（base64url, 截断）。
func RandomPassword(n int) (string, error) {
	if n <= 0 {
		n = 24
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := base64.RawURLEncoding.EncodeToString(b)
	if len(s) > n {
		s = s[:n]
	}
	return s, nil
}

// DeriveAgentCommandKey derives an AES-256 key used only for queued command
// payloads. It prevents credentials/password material from appearing in the
// command table as plaintext.
func DeriveAgentCommandKey(psk string) []byte {
	return sha256Of([]byte("stcontrol-agent-command:v1:" + psk))
}

// DeriveAgentCommandAuthKey is domain-separated from the AES-GCM key and
// authenticates the plaintext digest used for idempotent command comparison.
func DeriveAgentCommandAuthKey(psk string) []byte {
	return sha256Of([]byte("stcontrol-agent-command-auth:v1:" + psk))
}
