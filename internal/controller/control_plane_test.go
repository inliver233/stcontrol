package controller

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"stcontrol/internal/protocol"
)

func TestNewOperationGateFailsClosedWithRetryHint(t *testing.T) {
	t.Parallel()
	server := &Server{}
	server.setControlPlaneGate(true, "node_reconciliation_required")
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "https://control.example/api/auth/login", nil)
	server.handleLogin(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") != "15" {
		t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

func TestNormalizeNodeControlModeRequiresIndependentActivationEvidence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	_, err := normalizeNodeControlMode(protocol.NodeControlModeReport{
		Mode: protocol.NodeModeIndependent, ModeGeneration: 3, ControllerGeneration: 5,
		ConsecutiveHeartbeatFails: 60, ConsecutiveHealthProbeFails: 60,
	}, now)
	if err == nil {
		t.Fatal("independent report without activation time was accepted")
	}
	fact, err := normalizeNodeControlMode(protocol.NodeControlModeReport{
		Mode: protocol.NodeModeIndependentDraining, ModeGeneration: 4, ControllerGeneration: 5,
		ReasonCode: "controller_recovered", IndependentSince: now.Add(-time.Minute),
		ActiveIndependentSessions: 1, PendingUserSyncs: 2,
		PendingUsers: []protocol.IndependentSyncUser{
			{Handle: "alice", Marker: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ChangedAt: now.Add(-time.Minute).UnixMilli(), Reason: "independent_write"},
			{Handle: "bob", Marker: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ChangedAt: now.Add(-time.Minute).UnixMilli(), Reason: "independent_write"},
		},
	}, now)
	if err != nil || fact.PendingUserSyncs != 2 {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}
}

func TestNormalizeNodeControlModeRejectsUnaccountedPendingMarkers(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	_, err := normalizeNodeControlMode(protocol.NodeControlModeReport{
		Mode: protocol.NodeModeIndependentDraining, ModeGeneration: 4, ControllerGeneration: 5,
		ReasonCode: "controller_recovered", PendingUserSyncs: 1,
	}, now)
	if err == nil {
		t.Fatal("pending count without an immutable marker was accepted")
	}
}
