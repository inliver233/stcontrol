// Package crypto 提供凭据加密(AES-GCM)、密码哈希(bcrypt)、JWT 票据签发/校验。
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

// ---------- JWT 一次性票据 ----------

// TicketClaims 票据载荷。
type TicketClaims struct {
	Handle string `json:"sub"`   // 节点上的 handle
	Node   string `json:"aud"`   // 目标节点 base_url
	Nonce  string `json:"nonce"`
	jwt.RegisteredClaims
}

// IssueTicket 签发一次性登录票据(HS256)。
// secret 为该节点的 agent_psk 派生密钥; ttl 一般 60s; jti 唯一编号防重放。
func IssueTicket(secret []byte, handle, nodeBaseURL, jti string, ttl time.Duration) (string, error) {
	now := time.Now()
	nonce, err := RandomPassword(16)
	if err != nil {
		return "", err
	}
	claims := TicketClaims{
		Handle: handle,
		Node:   nodeBaseURL,
		Nonce:  nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// VerifyTicket 校验票据签名与有效期，返回载荷。不校验 aud(由调用方比对本节点)。
func VerifyTicket(secret []byte, tokenStr string) (*TicketClaims, error) {
	claims := &TicketClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// DeriveTicketSecret 从节点 PSK 派生票据密钥（HMAC-SHA256 语义, 这里直接 SHA256）。
func DeriveTicketSecret(psk string) []byte {
	h := sha256Of([]byte("stcontrol-ticket:" + psk))
	return h
}
