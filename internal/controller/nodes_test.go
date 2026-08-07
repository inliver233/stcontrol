package controller

import (
	"database/sql"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func TestNodeRegistrableRequiresFreshNodeOwnedPolicy(t *testing.T) {
	t.Parallel()
	server := &Server{Cfg: &config.ControllerConfig{Node: config.NodePolicy{
		RegisterCPU: 50, RegisterMem: 50, RegisterDisk: 50,
	}}}
	node := &store.Node{
		Role: "compute", Status: "online", AllowRegister: true,
		RegistrationPolicyState: "open", RegistrationPolicyVersion: 4,
		RegistrationPolicyExpiresAt: sql.NullTime{Time: time.Now().UTC().Add(time.Minute), Valid: true},
	}
	if !server.nodeRegistrable(node) {
		t.Fatal("fresh open policy was rejected")
	}
	node.RegistrationPolicyState = "error"
	if server.nodeRegistrable(node) {
		t.Fatal("policy read error was accepted")
	}
	node.RegistrationPolicyState = "invitation_required"
	node.RegistrationPolicyExpiresAt.Time = time.Now().UTC().Add(-time.Second)
	if server.nodeRegistrable(node) {
		t.Fatal("expired invitation policy was accepted")
	}
}

func TestNormalizeRegistrationPolicyRejectsInvalidFreshnessAndDiagnostics(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	fact := normalizeRegistrationPolicy(protocol.RegistrationPolicyReport{
		State: "open", Version: 3, ExpiresAt: now.Add(time.Minute),
	}, now)
	if fact.State != "open" || fact.Version != 3 || fact.ErrorCode != "" {
		t.Fatalf("valid fact=%+v", fact)
	}
	fact = normalizeRegistrationPolicy(protocol.RegistrationPolicyReport{
		State: "open", Version: 3, ExpiresAt: now.Add(11 * time.Minute), ErrorCode: "sensitive detail",
	}, now)
	if fact.State != "error" || fact.ErrorCode != "invalid_policy_report" || !fact.ExpiresAt.Equal(now) {
		t.Fatalf("invalid fact=%+v", fact)
	}
}
