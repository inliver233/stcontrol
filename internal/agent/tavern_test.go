package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func TestTavernAdapterUsesLoopbackAndSignedHashOnlyPayload(t *testing.T) {
	t.Parallel()
	const psk = "node-local-agent-secret"
	var captured []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		captured, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		if err := protocol.VerifyRequest(r, psk, captured); err != nil {
			t.Errorf("signature: %v", err)
		}
		_ = json.NewEncoder(w).Encode(protocol.ProvisionUserResponse{OK: true, Handle: "alice", LocalUserID: "alice"})
	}))
	defer server.Close()
	a, err := New(&config.AgentConfig{
		TavernURL: server.URL, AgentPSK: psk, NodeID: 12, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.provisionUser(context.Background(), &protocol.ProvisionUserRequest{
		Handle: "alice", Name: "Alice", PasswordHash: "scrypt-hash", PasswordSalt: "salt",
	})
	if err != nil || result.LocalUserID != "alice" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(captured, &payload); err != nil {
		t.Fatal(err)
	}
	if _, exists := payload["password"]; exists || payload["password_hash"] != "scrypt-hash" {
		t.Fatalf("payload=%s", captured)
	}
}

func TestTavernAdapterRejectsNonLoopbackTarget(t *testing.T) {
	t.Parallel()
	a := &Agent{Cfg: &config.AgentConfig{TavernURL: "https://node.example", AgentPSK: "secret", NodeID: 12}}
	err := a.callTavernAdapter(context.Background(), "/api/stcontrol/internal/users/provision", struct{}{}, nil)
	if err == nil {
		t.Fatal("non-loopback adapter target was accepted")
	}
}
