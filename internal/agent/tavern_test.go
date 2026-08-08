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

func TestTavernAdapterVerifiesAndRechecksNodeAdministrator(t *testing.T) {
	t.Parallel()
	const psk = "node-local-agent-secret"
	var verifyRequest protocol.VerifyNodeAdminRequest
	var checkRequest protocol.CheckNodeAdminRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		if err := protocol.VerifyRequest(r, psk, body); err != nil {
			t.Errorf("signature: %v", err)
		}
		switch r.URL.Path {
		case "/api/stcontrol/internal/admin/verify":
			if err := json.Unmarshal(body, &verifyRequest); err != nil {
				t.Errorf("decode verify request: %v", err)
			}
		case "/api/stcontrol/internal/admin/check":
			if err := json.Unmarshal(body, &checkRequest); err != nil {
				t.Errorf("decode check request: %v", err)
			}
		default:
			t.Errorf("path=%q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(protocol.NodeAdminVerification{
			Handle: "node-admin", LocalUserID: "local-user-7", IsAdmin: true, PermissionVersion: 9,
		})
	}))
	defer server.Close()
	a, err := New(&config.AgentConfig{
		TavernURL: server.URL, AgentPSK: psk, NodeID: 12, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	verification, err := a.verifyNodeAdmin(context.Background(), protocol.VerifyNodeAdminRequest{
		OperationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Handle: "node-admin", Password: "not-persisted",
	})
	if err != nil || !verification.IsAdmin || verification.PermissionVersion != 9 {
		t.Fatalf("verification=%+v err=%v", verification, err)
	}
	if verifyRequest.Password != "not-persisted" || verifyRequest.Handle != "node-admin" {
		t.Fatalf("verify request=%+v", verifyRequest)
	}
	verification, err = a.checkNodeAdmin(context.Background(), protocol.CheckNodeAdminRequest{Handle: "node-admin"})
	if err != nil || !verification.IsAdmin || checkRequest.Handle != "node-admin" {
		t.Fatalf("verification=%+v request=%+v err=%v", verification, checkRequest, err)
	}
}

func TestTavernAdapterRejectsIncompleteAdministratorFact(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(protocol.NodeAdminVerification{Handle: "node-admin", IsAdmin: true})
	}))
	defer server.Close()
	a, err := New(&config.AgentConfig{
		TavernURL: server.URL, AgentPSK: "secret", NodeID: 12, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.checkNodeAdmin(context.Background(), protocol.CheckNodeAdminRequest{Handle: "node-admin"}); err == nil {
		t.Fatal("incomplete administrator fact was accepted")
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

func TestTavernAdapterBootstrapsCSRFAndResignsRetry(t *testing.T) {
	t.Parallel()
	const psk = "csrf-agent-secret"
	postCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/csrf-token":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "opaque"})
			http.SetCookie(w, &http.Cookie{Name: "session.sig", Value: "signed"})
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "csrf-value"})
		case r.Method == http.MethodPost:
			postCount++
			body, _ := io.ReadAll(r.Body)
			if postCount == 1 {
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
			if r.Header.Get("X-CSRF-Token") != "csrf-value" {
				t.Errorf("csrf header=%q", r.Header.Get("X-CSRF-Token"))
			}
			if _, err := r.Cookie("session"); err != nil {
				t.Errorf("session cookie missing: %v", err)
			}
			if err := protocol.VerifyRequest(r, psk, body); err != nil {
				t.Errorf("retry signature: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	agent, err := New(&config.AgentConfig{TavernURL: server.URL, AgentPSK: psk, NodeID: 4, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if err := agent.callTavernAdapter(context.Background(), "/api/stcontrol/internal/health", map[string]string{
		"escaped": "<script>&\u2028",
	}, &result); err != nil || !result.OK || postCount != 2 {
		t.Fatalf("result=%+v postCount=%d err=%v", result, postCount, err)
	}
}

func TestCollectUserStatusesUsesExactAdapterSessions(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(adapterSessionResponse{OK: true, Users: []protocol.UserStatus{{
			Handle: "alice", SessionID: "11111111-1111-4111-8111-111111111111",
			ActivityEpoch: 7, ControllerGeneration: 3, LoginMode: protocol.NodeModeManaged,
			IsOnline: true, LastActivity: 1000, LastPageHeartbeat: 900, LastRequest: 1000,
			InFlightReads: 1,
		}}})
	}))
	defer server.Close()
	agent, err := New(&config.AgentConfig{TavernURL: server.URL, AgentPSK: "secret", NodeID: 4, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	users, err := agent.collectUserStatuses(context.Background())
	if err != nil || len(users) != 1 || users[0].ActivityEpoch != 7 || users[0].InFlightReads != 1 {
		t.Fatalf("users=%+v err=%v", users, err)
	}
}
