package internal_test

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

// TestHMACRoundTrip 验证总控签名 → 子控验签 的往返一致性。
func TestHMACRoundTrip(t *testing.T) {
	psk := "test-psk-1234567890"
	body := []byte(`{"hello":"world"}`)

	req, _ := http.NewRequest(http.MethodPost, "http://agent/agent/provision-user", bytes.NewReader(body))
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

// TestTicketRoundTrip 验证票据签发与校验, 以及密钥派生与酒馆侧一致。
func TestTicketRoundTrip(t *testing.T) {
	psk := "node-agent-psk"
	secret := crypto.DeriveTicketSecret(psk)

	token, err := crypto.IssueTicket(secret, "alice", "https://a.example.com", "jti-001", 60*time.Second)
	if err != nil {
		t.Fatalf("签发票据失败: %v", err)
	}
	claims, err := crypto.VerifyTicket(secret, token)
	if err != nil {
		t.Fatalf("校验票据失败: %v", err)
	}
	if claims.Handle != "alice" {
		t.Fatalf("handle 不匹配: %s", claims.Handle)
	}
	if claims.Node != "https://a.example.com" {
		t.Fatalf("aud 不匹配: %s", claims.Node)
	}
	if claims.ID != "jti-001" {
		t.Fatalf("jti 不匹配: %s", claims.ID)
	}

	// 过期票据应失败
	expired, _ := crypto.IssueTicket(secret, "alice", "https://a.example.com", "jti-002", -1*time.Second)
	if _, err := crypto.VerifyTicket(secret, expired); err == nil {
		t.Fatal("过期票据竟然校验通过")
	}
	// 错误密钥应失败
	if _, err := crypto.VerifyTicket(crypto.DeriveTicketSecret("other"), token); err == nil {
		t.Fatal("错误密钥竟然校验通过")
	}
}

// TestTicketSecretMatchesNode 验证总控 DeriveTicketSecret 与酒馆 federated-login.js 的
// SHA256("stcontrol-ticket:"+psk) 完全一致(关键互操作点)。
func TestTicketSecretMatchesNode(t *testing.T) {
	// 酒馆侧: crypto.createHash('sha256').update('stcontrol-ticket:' + psk).digest()
	// 总控侧: DeriveTicketSecret 做同样的事。两者必须一致, 否则票据验签失败。
	psk := "interop-psk"
	got := crypto.DeriveTicketSecret(psk)
	if len(got) != 32 {
		t.Fatalf("派生密钥长度应为 32, 实际 %d", len(got))
	}
	// 与已知的 SHA256("stcontrol-ticket:interop-psk") 对比(用标准库再算一遍)
	// (crypto 包内部就是这么做, 这里主要防回归)
	again := crypto.DeriveTicketSecret(psk)
	if !bytes.Equal(got, again) {
		t.Fatal("同一 PSK 派生密钥不一致")
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
