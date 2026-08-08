package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

const peerWitnessTestSecret = "0123456789abcdef0123456789abcdef"

func newPeerWitnessTestAgent(t *testing.T, nodeID int64, controllerURL string) *Agent {
	t.Helper()
	agent, err := New(&config.AgentConfig{
		Role: "compute", NodeID: nodeID, AgentPSK: "controller-agent-secret",
		ControllerURL: controllerURL, ControllerGeneration: 1, DataDir: t.TempDir(),
		Disaster: config.AgentDisasterPolicy{
			UnreachableAfterSec: 10, IndependentAfterSec: 60, MinFailedHeartbeats: 3,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	agent.peerWitnessSecret = []byte(peerWitnessTestSecret)
	return agent
}

func signedPeerWitnessRequest(t *testing.T, agent *Agent, requesterNodeID int64, fingerprint string) *http.Request {
	t.Helper()
	body, err := json.Marshal(peerWitnessRequest{ControllerFingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, peerWitnessRoute, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	protocol.SignRequest(request, requesterNodeID, peerWitnessTestSecret, body)
	return request
}

func TestPeerWitnessEndpointAuthenticatesBindsControllerAndRejectsReplay(t *testing.T) {
	t.Parallel()
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/health" {
			t.Errorf("controller path=%q", r.URL.Path)
		}
		protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	defer controller.Close()
	witness := newPeerWitnessTestAgent(t, 2, controller.URL)
	fingerprint, err := witness.controllerFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	handler := witness.Handler()
	badSignature := signedPeerWitnessRequest(t, witness, 1, fingerprint)
	badSignature.Header.Set(protocol.HeaderSignature, strings.Repeat("0", 64))
	badSignatureResponse := httptest.NewRecorder()
	handler.ServeHTTP(badSignatureResponse, badSignature)
	if badSignatureResponse.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature status=%d", badSignatureResponse.Code)
	}

	request := signedPeerWitnessRequest(t, witness, 1, fingerprint)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get(peerWitnessSignatureHeader) == "" ||
		!strings.Contains(response.Body.String(), `"controller_available":true`) {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}

	replay := request.Clone(context.Background())
	replay.Body = http.NoBody
	replay.ContentLength = request.ContentLength
	body, _ := json.Marshal(peerWitnessRequest{ControllerFingerprint: fingerprint})
	replay.Body = io.NopCloser(bytes.NewReader(body))
	replayed := httptest.NewRecorder()
	handler.ServeHTTP(replayed, replay)
	if replayed.Code != http.StatusUnauthorized {
		t.Fatalf("replay status=%d body=%s", replayed.Code, replayed.Body.String())
	}

	wrongController := signedPeerWitnessRequest(t, witness, 1, strings.Repeat("a", 64))
	wrongResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongResponse, wrongController)
	if wrongResponse.Code != http.StatusBadRequest {
		t.Fatalf("wrong fingerprint status=%d", wrongResponse.Code)
	}

	sameNode := signedPeerWitnessRequest(t, witness, witness.Cfg.NodeID, fingerprint)
	sameNodeResponse := httptest.NewRecorder()
	handler.ServeHTTP(sameNodeResponse, sameNode)
	if sameNodeResponse.Code != http.StatusUnauthorized {
		t.Fatalf("same-node witness status=%d", sameNodeResponse.Code)
	}

	query := signedPeerWitnessRequest(t, witness, 1, fingerprint)
	query.URL.RawQuery = "controller=other"
	queryResponse := httptest.NewRecorder()
	handler.ServeHTTP(queryResponse, query)
	if queryResponse.Code != http.StatusBadRequest {
		t.Fatalf("query status=%d", queryResponse.Code)
	}

	oversized := httptest.NewRequest(http.MethodPost, peerWitnessRoute, strings.NewReader(strings.Repeat("x", maxPeerWitnessRequestBytes+1)))
	oversized.Header.Set("Content-Type", "application/json")
	oversizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResponse, oversized)
	if oversizedResponse.Code != http.StatusBadRequest {
		t.Fatalf("oversized status=%d", oversizedResponse.Code)
	}
}

func TestPeerWitnessQuorumFailsClosedOnHealthDisagreementAndMissingPeers(t *testing.T) {
	t.Parallel()
	healthyController := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer healthyController.Close()
	witness := newPeerWitnessTestAgent(t, 2, healthyController.URL)
	witnessServer := httptest.NewServer(witness.Handler())
	defer witnessServer.Close()
	requester := newPeerWitnessTestAgent(t, 1, healthyController.URL)
	requester.Cfg.Disaster.PeerWitnessURLs = []string{witnessServer.URL}
	if requester.peerWitnessQuorumConfirmsLoss(context.Background()) {
		t.Fatal("a peer that reached the Controller incorrectly confirmed loss")
	}
	requester.Cfg.Disaster.PeerWitnessURLs = nil
	if requester.peerWitnessQuorumConfirmsLoss(context.Background()) {
		t.Fatal("an empty witness roster incorrectly confirmed loss")
	}
	requester.Cfg.Disaster.PeerWitnessURLs = []string{"http://127.0.0.1:1"}
	if requester.peerWitnessQuorumConfirmsLoss(context.Background()) {
		t.Fatal("an unreachable witness incorrectly confirmed loss")
	}
}

func TestPeerWitnessQuorumConfirmsSharedControllerLossAndDeduplicatesNodes(t *testing.T) {
	t.Parallel()
	closedController := httptest.NewServer(http.NotFoundHandler())
	controllerURL := closedController.URL
	closedController.Close()
	witness := newPeerWitnessTestAgent(t, 2, controllerURL)
	witnessOne := httptest.NewServer(witness.Handler())
	defer witnessOne.Close()
	requester := newPeerWitnessTestAgent(t, 1, controllerURL)
	requester.Cfg.Disaster.PeerWitnessURLs = []string{witnessOne.URL}
	if !requester.peerWitnessQuorumConfirmsLoss(context.Background()) {
		t.Fatal("signed peer witness did not confirm the shared Controller loss")
	}

	// Three configured peers need two distinct peer confirmations. Two URLs
	// backed by the same node identity count once; an unreachable third peer
	// cannot manufacture quorum.
	witnessTwo := httptest.NewServer(witness.Handler())
	defer witnessTwo.Close()
	requester.Cfg.Disaster.PeerWitnessURLs = []string{
		witnessOne.URL, witnessTwo.URL, "http://127.0.0.1:1",
	}
	if requester.peerWitnessQuorumConfirmsLoss(context.Background()) {
		t.Fatal("duplicate witness node identities manufactured quorum")
	}
}

func TestPeerWitnessPolicyRequiresTLSAndBoundedDistinctRoster(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		urls []string
	}{
		{name: "remote plaintext", urls: []string{"http://agent.example"}},
		{name: "credentials", urls: []string{"https://secret@agent.example"}},
		{name: "query", urls: []string{"https://agent.example?target=controller"}},
		{name: "path", urls: []string{"https://agent.example/private"}},
		{name: "duplicates", urls: []string{"https://agent.example", "https://agent.example/"}},
		{name: "too many", urls: []string{
			"https://a.example", "https://b.example", "https://c.example",
			"https://d.example", "https://e.example", "https://f.example",
			"https://g.example", "https://h.example", "https://i.example",
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := validatePeerWitnessPolicy(config.AgentDisasterPolicy{PeerWitnessURLs: test.urls}); err == nil {
				t.Fatalf("URLs accepted: %v", test.urls)
			}
		})
	}
	if endpoint, err := peerWitnessEndpoint("http://127.0.0.1:9100"); err != nil ||
		endpoint != "http://127.0.0.1:9100"+peerWitnessRoute {
		t.Fatalf("loopback endpoint=%q err=%v", endpoint, err)
	}
}

func TestPeerWitnessRosterCannotStartWithoutExternalSecret(t *testing.T) {
	t.Parallel()
	_, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 1, AgentPSK: "controller-secret",
		ControllerURL: "https://controller.example", DataDir: t.TempDir(),
		Disaster: config.AgentDisasterPolicy{
			PeerWitnessURLs:      []string{"https://peer.example"},
			PeerWitnessSecretEnv: "STCONTROL_TEST_MISSING_PEER_WITNESS_SECRET_61A4E4A7",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing witness secret error=%v", err)
	}
}

func TestPeerWitnessResponseRejectsStaleSignature(t *testing.T) {
	t.Parallel()
	controller := httptest.NewServer(http.NotFoundHandler())
	controllerURL := controller.URL
	controller.Close()
	requester := newPeerWitnessTestAgent(t, 1, controllerURL)
	fingerprint, err := requester.controllerFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := peerWitnessResponse{
			OK: true, WitnessNodeID: 2, ControllerFingerprint: fingerprint,
			ObservedAt: time.Now().Add(-2 * protocol.MaxClockSkew).UnixMilli(),
		}
		payload, _ := json.Marshal(body)
		timestamp := strconv.FormatInt(body.ObservedAt/1000, 10)
		w.Header().Set(peerWitnessTimestampHeader, timestamp)
		w.Header().Set(peerWitnessSignatureHeader, protocol.Sign(
			peerWitnessTestSecret, "RESPONSE", peerWitnessRoute, timestamp,
			r.Header.Get(protocol.HeaderNonce), payload,
		))
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	result := requester.probePeerWitness(context.Background(), server.URL, fingerprint)
	if result.valid {
		t.Fatal("stale signed witness response was accepted")
	}
}
