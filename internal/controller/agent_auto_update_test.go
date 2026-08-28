package controller

import (
	"database/sql"
	"testing"

	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func TestControllerAgentVersionOrdering(t *testing.T) {
	t.Parallel()
	if compareControllerAgentVersions("0.4.0", "0.3.9") != 1 ||
		compareControllerAgentVersions("0.4.0", "0.4.0") != 0 ||
		compareControllerAgentVersions("0.3.9", "0.4.0") != -1 {
		t.Fatal("unexpected Controller Agent version ordering")
	}
	for _, invalid := range []string{"", "v0.4.0", "0.4", "00.4.0", "0.4.x"} {
		if _, ok := parseControllerAgentVersion(invalid); ok {
			t.Fatalf("invalid Agent version accepted: %q", invalid)
		}
	}
}

func TestAgentAutoUpdateDoesNotGetBlockedByCapacityState(t *testing.T) {
	t.Parallel()
	base := &store.Node{
		ConnectivityState: "online", OperationalState: "active",
		CompatibilityState: "compatible", ControlMode: "managed", DesiredControlMode: "managed",
		AgentVersion:   sql.NullString{String: "0.4.6", Valid: true},
		TaskQueueDepth: 0,
	}
	policy := config.AgentAutoUpdatePolicy{Enabled: true, AllowOnlineUsers: true}
	for _, capacity := range []string{"open", "busy", "full", "unknown"} {
		node := *base
		node.CapacityState = capacity
		if !agentEligibleForAutoUpdate(&node, policy) {
			t.Fatalf("capacity state %q incorrectly blocked update", capacity)
		}
	}
	base.OnlineUsers = 1
	policy.AllowOnlineUsers = false
	if agentEligibleForAutoUpdate(base, policy) {
		t.Fatal("online users must remain a safety gate when disabled")
	}
	base.OnlineUsers = 0
	base.TaskQueueDepth = 1
	if agentEligibleForAutoUpdate(base, policy) {
		t.Fatal("active command queue must remain a safety gate")
	}
}
