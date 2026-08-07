package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
		RegistrationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", PolicyVersion: 3,
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
	if payload["registration_id"] != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" || payload["policy_version"] != float64(3) {
		t.Fatalf("registration fencing missing: %s", captured)
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

func TestRegistrationPolicyRequiresFreshVersionedAdapterFact(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/stcontrol/internal/registration-policy" {
			t.Errorf("path=%q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(adapterRegistrationPolicy{
			OK: true, Mode: "invitation_required", Version: 8,
		})
	}))
	defer server.Close()
	a, err := New(&config.AgentConfig{
		TavernURL: server.URL, AgentPSK: "secret", NodeID: 12,
		DataDir: t.TempDir(), HeartbeatSec: 15,
	})
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC()
	report := a.registrationPolicy(context.Background())
	if report.State != "invitation_required" || report.Version != 8 ||
		!report.ExpiresAt.After(before.Add(59*time.Second)) {
		t.Fatalf("report=%+v", report)
	}
}

func TestRegistrationPolicyFailsClosedWhenAdapterCannotBeRead(t *testing.T) {
	t.Parallel()
	a := &Agent{Cfg: &config.AgentConfig{
		TavernURL: "https://not-loopback.example", AgentPSK: "secret", NodeID: 12,
	}}
	report := a.registrationPolicy(context.Background())
	if report.State != "error" || report.Version != 0 || report.ErrorCode != "adapter_unavailable" {
		t.Fatalf("report=%+v", report)
	}
}
