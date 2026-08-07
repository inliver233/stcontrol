package internal_test

import (
	"bytes"
	"net/http"
	"testing"

	"stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

// TestHMACRoundTrip 验证总控签名 → 子控验签 的往返一致性。
func TestHMACRoundTrip(t *testing.T) {
	psk := "test-psk-1234567890"
	body := []byte(`{"hello":"world"}`)

	req, _ := http.NewRequest(http.MethodPost, "https://controller.example/api/agent/commands/lease", bytes.NewReader(body))
	protocol.SignRequest(req, 7, psk, body)

	if err := protocol.VerifyRequest(req, psk, body); err != nil {
		t.Fatalf("验签失败: %v", err)
	}

	// 篡改 body 应失败
	if err := protocol.VerifyRequest(req, psk, []byte(`{"hello":"evil"}`)); err == nil {
		t.Fatal("篡改 body 后验签竟然通过")
	}
	// 错误 PSK 应失败
	if err := protocol.VerifyRequest(req, "wrong-psk", body); err == nil {
		t.Fatal("错误 PSK 验签竟然通过")
	}
}

func TestHMACRejectsMalformedNonce(t *testing.T) {
	t.Parallel()
	body := []byte(`{"hello":"world"}`)
	req, _ := http.NewRequest(http.MethodPost, "http://agent/agent/heartbeat", bytes.NewReader(body))
	protocol.SignRequest(req, 7, "test-psk", body)
	req.Header.Set(protocol.HeaderNonce, "not-hex")
	req.Header.Set(protocol.HeaderSignature, protocol.Sign(
		"test-psk", req.Method, req.URL.Path,
		req.Header.Get(protocol.HeaderTimestamp), "not-hex", body,
	))
	if err := protocol.VerifyRequest(req, "test-psk", body); err == nil {
		t.Fatal("malformed nonce unexpectedly verified")
	}
}

// TestGetHMACEmptyBody 验证 GET 请求(nil body) 的签名验签。
func TestGetHMACEmptyBody(t *testing.T) {
	psk := "psk-for-get"
	req, _ := http.NewRequest(http.MethodGet, "http://agent/agent/health", nil)
	protocol.SignRequest(req, 3, psk, nil)
	if err := protocol.VerifyRequest(req, psk, nil); err != nil {
		t.Fatalf("GET 验签失败: %v", err)
	}
}

// TestCredentialEncrypt 验证凭据加密/解密往返。
func TestCredentialEncrypt(t *testing.T) {
	keyB64, _ := crypto.GenerateKey()
	key, _ := crypto.LoadKey(keyB64)
	plain := []byte("user-password-123")
	enc, err := crypto.Encrypt(key, plain)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	dec, err := crypto.Decrypt(key, enc)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatal("解密结果与原文不一致")
	}
	// 错误密钥解密应失败
	key2B64, _ := crypto.GenerateKey()
	key2, _ := crypto.LoadKey(key2B64)
	if _, err := crypto.Decrypt(key2, enc); err == nil {
		t.Fatal("错误密钥竟然解密成功")
	}
}

// TestBcrypt 验证密码哈希与校验。
func TestBcrypt(t *testing.T) {
	hash, err := crypto.HashPassword("mypassword")
	if err != nil {
		t.Fatalf("哈希失败: %v", err)
	}
	if !crypto.CheckPassword(hash, "mypassword") {
		t.Fatal("正确密码校验失败")
	}
	if crypto.CheckPassword(hash, "wrong") {
		t.Fatal("错误密码竟然校验通过")
	}
}
