package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func TestActivityLeaseConfirmationsPersistRetryAndRejectRollback(t *testing.T) {
	t.Parallel()
	confirmedAt := time.Now().UTC().UnixMilli()
	expiresAt := confirmedAt + int64((15*time.Minute)/time.Millisecond)
	var calls int
	var received protocol.ApplyActivityLeaseConfirmationsRequest
	adapter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/stcontrol/internal/activity-leases/confirm" || r.Method != http.MethodPost {
			http.Error(w, "unexpected endpoint", http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(protocol.ApplyActivityLeaseConfirmationsResponse{
			OK: true, ConfirmedAt: received.ConfirmedAt, AppliedLeases: len(received.Leases),
		})
	}))
	defer adapter.Close()
	dataDir := t.TempDir()
	agent, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 9, AgentPSK: "controller-secret", TavernAdapterPSK: "adapter-secret",
		ControllerGeneration: 3, TavernURL: adapter.URL, DataDir: dataDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := protocol.HeartbeatResponse{
		OK: true, ControllerGeneration: 3, DesiredMode: protocol.NodeModeManaged, ModeGeneration: 1,
		ActivityLeaseConfirmedAt: confirmedAt,
		ActivityLeaseConfirmations: []protocol.ActivityLeaseConfirmation{{
			Handle: "alice", SessionID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			ActivityEpoch: 7, ControllerGeneration: 3, LeaseExpiresAt: expiresAt,
		}},
	}
	if err := agent.recordControllerSuccess(time.Now().UTC(), response); err != nil {
		t.Fatalf("record confirmation: %v", err)
	}
	if err := agent.syncTavernActivityLeases(context.Background()); err != nil {
		t.Fatalf("apply confirmation: %v", err)
	}
	if calls != 1 || received.ConfirmedAt != confirmedAt || len(received.Leases) != 1 ||
		received.Leases[0].SessionID != response.ActivityLeaseConfirmations[0].SessionID {
		t.Fatalf("calls=%d received=%+v", calls, received)
	}
	if err := agent.syncTavernActivityLeases(context.Background()); err != nil || calls != 1 {
		t.Fatalf("already-applied snapshot retried calls=%d err=%v", calls, err)
	}
	reloaded, err := New(agent.Cfg)
	if err != nil {
		t.Fatalf("reload durable confirmation: %v", err)
	}
	if reloaded.state.ActivityLeases.ConfirmedAt != confirmedAt ||
		reloaded.state.ActivityLeases.AdapterConfirmedAt != confirmedAt {
		t.Fatalf("reloaded activity leases=%+v", reloaded.state.ActivityLeases)
	}
	rollback := response
	rollback.ActivityLeaseConfirmedAt--
	if err := reloaded.recordControllerSuccess(time.Now().UTC(), rollback); err == nil {
		t.Fatal("confirmation time rollback was accepted")
	}
	reused := response
	reused.ActivityLeaseConfirmations = nil
	if err := reloaded.recordControllerSuccess(time.Now().UTC(), reused); err == nil {
		t.Fatal("same confirmation time with changed snapshot was accepted")
	}
}

func TestActivityLeaseConfirmationRetriesFailedAdapterDeliveryAfterRestart(t *testing.T) {
	t.Parallel()
	confirmedAt := time.Now().UTC().UnixMilli()
	var failDelivery atomic.Bool
	failDelivery.Store(true)
	var calls atomic.Int32
	adapter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if failDelivery.Load() {
			http.Error(w, "temporary adapter failure", http.StatusServiceUnavailable)
			return
		}
		var request protocol.ApplyActivityLeaseConfirmationsRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(protocol.ApplyActivityLeaseConfirmationsResponse{
			OK: true, ConfirmedAt: request.ConfirmedAt, AppliedLeases: len(request.Leases),
		})
	}))
	defer adapter.Close()
	cfg := &config.AgentConfig{
		Role: "compute", NodeID: 9, AgentPSK: "controller-secret", TavernAdapterPSK: "adapter-secret",
		ControllerGeneration: 3, TavernURL: adapter.URL, DataDir: t.TempDir(),
	}
	agent, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	response := protocol.HeartbeatResponse{
		OK: true, ControllerGeneration: 3, DesiredMode: protocol.NodeModeManaged, ModeGeneration: 1,
		ActivityLeaseConfirmedAt: confirmedAt,
		ActivityLeaseConfirmations: []protocol.ActivityLeaseConfirmation{{
			Handle: "alice", SessionID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			ActivityEpoch: 7, ControllerGeneration: 3, LeaseExpiresAt: confirmedAt + 120_000,
		}},
	}
	if err := agent.recordControllerSuccess(time.Now().UTC(), response); err != nil {
		t.Fatalf("record confirmation: %v", err)
	}
	if err := agent.syncTavernActivityLeases(context.Background()); err == nil {
		t.Fatal("temporary adapter failure was accepted")
	}
	if agent.state.ActivityLeases.AdapterConfirmedAt != 0 {
		t.Fatalf("failed delivery was marked applied: %+v", agent.state.ActivityLeases)
	}

	reloaded, err := New(cfg)
	if err != nil {
		t.Fatalf("reload pending confirmation: %v", err)
	}
	if reloaded.state.ActivityLeases.ConfirmedAt != confirmedAt ||
		reloaded.state.ActivityLeases.AdapterConfirmedAt != 0 {
		t.Fatalf("pending confirmation was not durable: %+v", reloaded.state.ActivityLeases)
	}
	failDelivery.Store(false)
	if err := reloaded.syncTavernActivityLeases(context.Background()); err != nil {
		t.Fatalf("retry pending confirmation: %v", err)
	}
	if calls.Load() != 2 || reloaded.state.ActivityLeases.AdapterConfirmedAt != confirmedAt {
		t.Fatalf("retry calls=%d state=%+v", calls.Load(), reloaded.state.ActivityLeases)
	}
}

func TestActivityLeaseConfirmationValidationRejectsUnboundedAndDuplicateGrants(t *testing.T) {
	t.Parallel()
	confirmedAt := time.Now().UTC().UnixMilli()
	base := protocol.ActivityLeaseConfirmation{
		Handle: "alice", SessionID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ActivityEpoch: 1, ControllerGeneration: 4, LeaseExpiresAt: confirmedAt + 60_000,
	}
	for name, leases := range map[string][]protocol.ActivityLeaseConfirmation{
		"duplicate": {base, base},
		"wrong_generation": {func() protocol.ActivityLeaseConfirmation {
			value := base
			value.ControllerGeneration = 3
			return value
		}()},
		"unbounded": {func() protocol.ActivityLeaseConfirmation {
			value := base
			value.LeaseExpiresAt = confirmedAt + (25 * time.Hour).Milliseconds()
			return value
		}()},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateAgentActivityLeaseState(agentActivityLeaseState{
				ControllerGeneration: 4, ConfirmedAt: confirmedAt, Leases: leases,
			}); err == nil {
				t.Fatal("invalid confirmation state was accepted")
			}
		})
	}
}
