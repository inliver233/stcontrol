package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func newStorageHeartbeatAgent(t *testing.T, controllerURL string) *Agent {
	t.Helper()
	a, err := New(&config.AgentConfig{
		ControllerURL: controllerURL, Role: "storage", NodeID: 9,
		AgentPSK: "heartbeat-lifecycle-secret", CredentialVersion: 1,
		ControllerGeneration: 1, DataDir: t.TempDir(), BackupDir: t.TempDir(),
		HeartbeatSec: 15, DiskQuotaBytes: 1 << 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestSendHeartbeatPublishesCapacityAndAppliesControllerPolicy(t *testing.T) {
	t.Parallel()
	var (
		mu       sync.Mutex
		received protocol.HeartbeatRequest
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/heartbeat" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.HeartbeatResponse{
			OK: true, ControllerGeneration: 1, DesiredMode: protocol.NodeModeManaged,
			ModeGeneration: 1, ExpectedDiskQuotaBytes: 512 << 20, QuotaPolicyVersion: 2,
		})
	}))
	defer server.Close()
	a := newStorageHeartbeatAgent(t, server.URL)
	a.sendHeartbeat(context.Background())

	mu.Lock()
	report := received
	mu.Unlock()
	if report.NodeID != 9 || report.AgentVersion != Version || report.TelemetrySource != "agent" ||
		report.Compatibility.State != "compatible" || report.ControlMode.Mode != protocol.NodeModeManaged {
		t.Fatalf("unexpected heartbeat report: %+v", report)
	}
	if a.runtimeDiskQuota() != 512<<20 || a.appliedQuotaVersion() != 2 {
		t.Fatalf("quota=%d version=%d", a.runtimeDiskQuota(), a.appliedQuotaVersion())
	}
	a.stateMu.Lock()
	lastSuccess := a.state.ControlMode.LastControllerSuccessAt
	a.stateMu.Unlock()
	if lastSuccess.IsZero() {
		t.Fatal("successful heartbeat did not persist controller success")
	}
}

func TestSendHeartbeatPersistsFailedHeartbeatAndHealthEvidence(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/heartbeat":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case "/api/health":
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	a := newStorageHeartbeatAgent(t, server.URL)
	a.sendHeartbeat(context.Background())

	a.stateMu.Lock()
	state := a.state.ControlMode
	a.stateMu.Unlock()
	if state.ConsecutiveHeartbeatFails != 1 || state.ConsecutiveHealthProbeFails != 1 ||
		state.ConsecutivePeerWitnessFails != 0 || state.OutageStartedAt.IsZero() {
		t.Fatalf("unexpected persisted failure evidence: %+v", state)
	}
}
