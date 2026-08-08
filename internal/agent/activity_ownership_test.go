package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func newOwnershipTestAgent(t *testing.T, nodeID int64, dataDir, controllerURL, tavernURL string) *Agent {
	t.Helper()
	agent, err := New(&config.AgentConfig{
		Role: "compute", NodeID: nodeID, AgentPSK: "controller-secret",
		TavernAdapterPSK: "adapter-secret", ControllerGeneration: 4,
		ControllerURL: controllerURL, TavernURL: tavernURL, DataDir: dataDir,
		Disaster: config.AgentDisasterPolicy{
			UnreachableAfterSec: 10, IndependentAfterSec: 60, MinFailedHeartbeats: 3,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	agent.peerWitnessSecret = []byte(peerWitnessTestSecret)
	agent.stateMu.Lock()
	agent.state.ControlMode.Mode = protocol.NodeModeIndependent
	agent.state.ControlMode.ModeGeneration = 3
	agent.stateMu.Unlock()
	return agent
}

func healthyOwnershipAdapter(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/stcontrol/internal/health" {
			t.Errorf("adapter path=%q", r.URL.Path)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
}

func TestActivityOwnershipQuorumIsUniqueAndUserTakeoverUsesMajorityCAS(t *testing.T) {
	t.Parallel()
	controller := httptest.NewServer(http.NotFoundHandler())
	controllerURL := controller.URL
	controller.Close()
	adapterA := healthyOwnershipAdapter(t)
	defer adapterA.Close()
	adapterB := healthyOwnershipAdapter(t)
	defer adapterB.Close()
	dataA, dataB := t.TempDir(), t.TempDir()
	agentA := newOwnershipTestAgent(t, 11, dataA, controllerURL, adapterA.URL)
	agentB := newOwnershipTestAgent(t, 12, dataB, controllerURL, adapterB.URL)
	serverA := httptest.NewServer(agentA.Handler())
	defer serverA.Close()
	serverB := httptest.NewServer(agentB.Handler())
	defer serverB.Close()
	agentA.Cfg.Disaster.PeerWitnessURLs = []string{serverB.URL}
	agentB.Cfg.Disaster.PeerWitnessURLs = []string{serverA.URL}

	claim, err := makeActivityOwnershipClaim(
		"alice", 11, 4, 7, 0, "controller_grant", "", "", time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if accepted, err := agentA.applyActivityOwnershipClaim(claim, false); err != nil || !accepted {
		t.Fatalf("apply A accepted=%v err=%v", accepted, err)
	}
	if accepted, err := agentB.applyActivityOwnershipClaim(claim, false); err != nil || !accepted {
		t.Fatalf("apply B accepted=%v err=%v", accepted, err)
	}

	if decision := agentA.queryOwnershipQuorum(context.Background(), "alice"); !decision.OK || decision.Decision != "automatic" || decision.ClaimID != claim.ClaimID {
		t.Fatalf("owner decision=%+v", decision)
	}
	if decision := agentB.queryOwnershipQuorum(context.Background(), "alice"); !decision.OK || decision.Decision != "owner_available" {
		t.Fatalf("replica decision=%+v", decision)
	}

	// The last active Agent still answers, but its adapter has failed. The
	// replica may offer a risk confirmation; it still cannot switch ownership
	// until the majority compare-and-set accepts the exact parent claim.
	agentA.Cfg.TavernURL = "http://127.0.0.1:1"
	if decision := agentB.queryOwnershipQuorum(context.Background(), "alice"); !decision.OK || decision.Decision != "takeover_required" || decision.ClaimID != claim.ClaimID {
		t.Fatalf("failed-owner decision=%+v", decision)
	}
	operationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	type takeoverResult struct {
		response ownershipResolveResponse
		err      error
	}
	results := make(chan takeoverResult, 8)
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			response, err := agentB.performUserConfirmedTakeover(context.Background(), ownershipTakeoverRequest{
				Handle: "alice", ParentClaimID: claim.ClaimID, OperationID: operationID,
			})
			results <- takeoverResult{response: response, err: err}
		}()
	}
	group.Wait()
	close(results)
	for result := range results {
		if result.err != nil || !result.response.OK || result.response.Decision != "takeover_committed" {
			t.Fatalf("takeover=%+v err=%v", result.response, result.err)
		}
	}
	newClaim, found := agentB.currentActivityOwnership("alice")
	if !found || newClaim.OwnerNodeID != 12 || newClaim.TakeoverSequence != 1 ||
		newClaim.ParentClaimID != claim.ClaimID || newClaim.OperationID != operationID {
		t.Fatalf("new claim=%+v found=%v", newClaim, found)
	}
	if peerClaim, found := agentA.currentActivityOwnership("alice"); !found || peerClaim.ClaimID != newClaim.ClaimID {
		t.Fatalf("peer claim=%+v found=%v", peerClaim, found)
	}
	if decision := agentB.queryOwnershipQuorum(context.Background(), "alice"); !decision.OK || decision.Decision != "automatic" || decision.ClaimID != newClaim.ClaimID {
		t.Fatalf("post-takeover decision=%+v", decision)
	}

	// Exact operation replay is durable and does not create a second claim.
	reloadedB := newOwnershipTestAgent(t, 12, dataB, controllerURL, adapterB.URL)
	reloadedB.Cfg.Disaster.PeerWitnessURLs = []string{serverA.URL}
	replayed, err := reloadedB.performUserConfirmedTakeover(context.Background(), ownershipTakeoverRequest{
		Handle: "alice", ParentClaimID: claim.ClaimID, OperationID: operationID,
	})
	if err != nil || replayed.ClaimID != newClaim.ClaimID {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	report := reloadedB.controlModeReport()
	if len(report.ConfirmedTakeovers) != 1 ||
		report.ConfirmedTakeovers[0].OperationID != operationID ||
		report.ConfirmedTakeovers[0].ClaimID != newClaim.ClaimID ||
		report.ConfirmedTakeovers[0].ParentClaimID != claim.ClaimID {
		t.Fatalf("confirmed takeover report=%+v", report.ConfirmedTakeovers)
	}
	if err := reloadedB.recordControllerSuccess(time.Now().UTC(), protocol.HeartbeatResponse{
		OK: true, ControllerGeneration: 5,
		DesiredMode: protocol.NodeModeIndependentDraining, ModeGeneration: report.ModeGeneration + 1,
		AcknowledgedTakeoverOperations: []string{operationID},
	}); err != nil {
		t.Fatalf("acknowledge takeover: %v", err)
	}
	if len(reloadedB.state.OwnershipTakeovers) != 0 {
		t.Fatalf("acknowledged takeover journal=%+v", reloadedB.state.OwnershipTakeovers)
	}
	if retained, found := reloadedB.currentActivityOwnership("alice"); !found || retained.ClaimID != newClaim.ClaimID {
		t.Fatalf("acknowledgement removed current owner: %+v found=%v", retained, found)
	}
	audit, err := os.ReadFile(filepath.Join(dataB, "audit.jsonl"))
	if err != nil || strings.Count(string(audit), "user_confirmed_activity_takeover") != 1 ||
		strings.Contains(string(audit), "alice") {
		t.Fatalf("takeover audit=%q err=%v", audit, err)
	}
}

func TestActivityOwnershipSameEpochConflictFailsClosed(t *testing.T) {
	t.Parallel()
	controller := httptest.NewServer(http.NotFoundHandler())
	controllerURL := controller.URL
	controller.Close()
	adapterA := healthyOwnershipAdapter(t)
	defer adapterA.Close()
	adapterB := healthyOwnershipAdapter(t)
	defer adapterB.Close()
	agentA := newOwnershipTestAgent(t, 21, t.TempDir(), controllerURL, adapterA.URL)
	agentB := newOwnershipTestAgent(t, 22, t.TempDir(), controllerURL, adapterB.URL)
	serverB := httptest.NewServer(agentB.Handler())
	defer serverB.Close()
	agentA.Cfg.Disaster.PeerWitnessURLs = []string{serverB.URL}
	claimA, _ := makeActivityOwnershipClaim("alice", 21, 4, 9, 0, "controller_grant", "", "", time.Now().UTC())
	claimB, _ := makeActivityOwnershipClaim("alice", 22, 4, 9, 0, "controller_grant", "", "", time.Now().UTC())
	_, _ = agentA.applyActivityOwnershipClaim(claimA, false)
	_, _ = agentB.applyActivityOwnershipClaim(claimB, false)
	decision := agentA.queryOwnershipQuorum(context.Background(), "alice")
	if decision.OK || decision.Decision != "unavailable" || decision.ReasonCode != "ownership_fact_conflict" {
		t.Fatalf("conflicting decision=%+v", decision)
	}
}

func TestActivityOwnershipPeerEndpointRejectsReplay(t *testing.T) {
	t.Parallel()
	controller := httptest.NewServer(http.NotFoundHandler())
	defer controller.Close()
	adapter := healthyOwnershipAdapter(t)
	defer adapter.Close()
	witness := newOwnershipTestAgent(t, 31, t.TempDir(), controller.URL, adapter.URL)
	fingerprint, err := witness.controllerFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	claim, _ := makeActivityOwnershipClaim("alice", 30, 4, 3, 0, "controller_grant", "", "", time.Now().UTC())
	payload, _ := json.Marshal(ownershipPeerRequest{ControllerFingerprint: fingerprint, Claim: &claim})
	request := httptest.NewRequest(http.MethodPost, peerOwnershipObserveRoute, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	protocol.SignRequest(request, 30, peerWitnessTestSecret, payload)
	handler := witness.Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get(peerOwnershipResponseSig) == "" {
		t.Fatalf("first status=%d body=%s", response.Code, response.Body.String())
	}
	replay := request.Clone(context.Background())
	replay.Body = io.NopCloser(bytes.NewReader(payload))
	replay.ContentLength = int64(len(payload))
	replayed := httptest.NewRecorder()
	handler.ServeHTTP(replayed, replay)
	if replayed.Code != http.StatusUnauthorized {
		t.Fatalf("replay status=%d body=%s", replayed.Code, replayed.Body.String())
	}
}

func TestUserConfirmedTakeoverFailsWithoutPeerQuorum(t *testing.T) {
	t.Parallel()
	controller := httptest.NewServer(http.NotFoundHandler())
	controllerURL := controller.URL
	controller.Close()
	adapter := healthyOwnershipAdapter(t)
	defer adapter.Close()
	agent := newOwnershipTestAgent(t, 42, t.TempDir(), controllerURL, adapter.URL)
	agent.Cfg.Disaster.PeerWitnessURLs = []string{"http://127.0.0.1:1"}
	claim, _ := makeActivityOwnershipClaim("alice", 41, 4, 2, 0, "controller_grant", "", "", time.Now().UTC())
	_, _ = agent.applyActivityOwnershipClaim(claim, false)
	_, err := agent.performUserConfirmedTakeover(context.Background(), ownershipTakeoverRequest{
		Handle: "alice", ParentClaimID: claim.ClaimID,
		OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	})
	if err == nil {
		t.Fatal("takeover without a peer quorum succeeded")
	}
}

func TestPersistedOwnershipTakeoverRejectsAuditedButUncommittedState(t *testing.T) {
	t.Parallel()
	controller := httptest.NewServer(http.NotFoundHandler())
	defer controller.Close()
	adapter := healthyOwnershipAdapter(t)
	defer adapter.Close()
	dataDir := t.TempDir()
	agent := newOwnershipTestAgent(t, 51, dataDir, controller.URL, adapter.URL)
	parent, err := makeActivityOwnershipClaim(
		"alice", 50, 4, 2, 0, "controller_grant", "", "", time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	operationID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	claim, err := makeActivityOwnershipClaim(
		"alice", 51, 4, 2, 1, "user_confirmed_takeover", parent.ClaimID,
		operationID, time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	agent.stateMu.Lock()
	agent.state.OwnershipTakeovers[operationID] = ownershipTakeoverOperation{
		OperationID: operationID, ParentClaimID: parent.ClaimID, Claim: claim,
		Succeeded: false, Audited: true, UpdatedAt: time.Now().UTC().UnixMilli(),
	}
	if err := agent.saveRuntimeStateLocked(); err != nil {
		agent.stateMu.Unlock()
		t.Fatal(err)
	}
	agent.stateMu.Unlock()
	if _, err := New(agent.Cfg); err == nil || !strings.Contains(err.Error(), "invalid persisted activity ownership takeover") {
		t.Fatalf("tampered takeover state error=%v", err)
	}
}
