package internal_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/crypto"
)

// TestTicketJSONFormat 验证 Go 签发的 JWT payload 中, handle 在 "sub"、node 在 "aud"、
// 与酒馆 Node 侧 verifyTicketJWT 期望的字段完全一致。
func TestTicketJSONFormat(t *testing.T) {
	secret := crypto.DeriveTicketSecret("fmt-psk")
	token, err := crypto.IssueTicket(secret, "bob", "https://b.example.com", "jti-9", 60*time.Second)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT 段数错误: %d", len(parts))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload 解码失败: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("payload 解析失败: %v", err)
	}
	// Node 侧读 payload.sub / payload.aud / payload.jti / payload.exp
	if payload["sub"] != "bob" {
		t.Errorf("sub 字段错误: %v", payload["sub"])
	}
	// aud 可能是 string 或 []string, 两种都接受(Node JSON.parse 后都能取到)
	aud := payload["aud"]
	switch v := aud.(type) {
	case string:
		if v != "https://b.example.com" {
			t.Errorf("aud 字符串错误: %v", v)
		}
	case []any:
		if len(v) == 0 || v[0] != "https://b.example.com" {
			t.Errorf("aud 数组错误: %v", v)
		}
	default:
		t.Errorf("aud 类型未知: %T", aud)
	}
	if payload["jti"] != "jti-9" {
		t.Errorf("jti 字段错误: %v", payload["jti"])
	}
	if _, ok := payload["exp"]; !ok {
		t.Error("缺少 exp 字段")
	}
}
