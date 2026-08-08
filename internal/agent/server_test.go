package agent

import (
	"bytes"
	"crypto/tls"
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

func TestAdapterTicketProxySeparatesLocalAndRotatedControllerCredentials(t *testing.T) {
	t.Parallel()
	const (
		adapterPSK    = "stable-local-adapter-secret"
		controllerPSK = "rotated-controller-secret"
		requestPath   = "/agent/tickets/redeem"
	)
	controllerCalls := 0
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/api/tickets/redeem" || r.Header.Get(protocol.HeaderAgentID) != "7" ||
			protocol.VerifyRequest(r, controllerPSK, body) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		controllerCalls++
		protocol.WriteJSON(w, http.StatusOK, map[string]any{
			"ok": true, "handle": "alice", "controller_generation": 9, "activity_epoch": 11,
		})
	}))
	defer controller.Close()
	agent, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 7, AgentPSK: controllerPSK, TavernAdapterPSK: adapterPSK,
		ControllerURL: controller.URL, DataDir: t.TempDir(), ControllerGeneration: 9,
	})
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"code":"opaque-one-use-code"}`)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "00112233445566778899aabbccddeeff"
	doRequest := func(secret string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, requestPath, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(protocol.HeaderAgentID, "7")
		request.Header.Set(protocol.HeaderTimestamp, timestamp)
		request.Header.Set(protocol.HeaderNonce, nonce)
		request.Header.Set(protocol.HeaderSignature,
			protocol.Sign(secret, http.MethodPost, requestPath, timestamp, nonce, body))
		response := httptest.NewRecorder()
		agent.Handler().ServeHTTP(response, request)
		return response
	}
	if response := doRequest(adapterPSK); response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"handle":"alice"`) {
		t.Fatalf("proxy response=%d %s", response.Code, response.Body.String())
	}
	if controllerCalls != 1 {
		t.Fatalf("controller calls=%d", controllerCalls)
	}
	if claim, found := agent.currentActivityOwnership("alice"); !found ||
		claim.OwnerNodeID != 7 || claim.ActivityEpoch != 11 || claim.ControllerGeneration != 9 {
		t.Fatalf("activity ownership claim=%+v found=%v", claim, found)
	}
	if response := doRequest(adapterPSK); response.Code != http.StatusUnauthorized {
		t.Fatalf("replayed adapter nonce status=%d", response.Code)
	}
	if controllerCalls != 1 {
		t.Fatalf("nonce replay reached controller: calls=%d", controllerCalls)
	}
}

func TestAgentListenerRequiresTLSOutsideLoopback(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*config.AgentConfig)
		wantErr bool
	}{
		{name: "loopback adapter"},
		{name: "remote plaintext listener", wantErr: true, mutate: func(cfg *config.AgentConfig) {
			cfg.Listen = ":9100"
		}},
		{name: "remote plaintext transfer URL", wantErr: true, mutate: func(cfg *config.AgentConfig) {
			cfg.TransferPublicURL = "http://agent.example"
		}},
		{name: "credential in URL", wantErr: true, mutate: func(cfg *config.AgentConfig) {
			cfg.TransferPublicURL = "https://secret@agent.example"
		}},
		{name: "ambiguous transfer path", wantErr: true, mutate: func(cfg *config.AgentConfig) {
			cfg.TransferPublicURL = "https://agent.example/data/../private"
		}},
		{name: "mux wildcard in transfer path", wantErr: true, mutate: func(cfg *config.AgentConfig) {
			cfg.TransferPublicURL = "https://agent.example/data/{scope}"
		}},
		{name: "certificate without key", wantErr: true, mutate: func(cfg *config.AgentConfig) {
			cfg.TLSCertFile = "agent.crt"
		}},
		{name: "direct TLS", mutate: func(cfg *config.AgentConfig) {
			cfg.Listen = ":9443"
			cfg.TransferPublicURL = "https://agent.example"
			cfg.TLSCertFile = "agent.crt"
			cfg.TLSKeyFile = "agent.key"
		}},
		{name: "loopback behind TLS proxy", mutate: func(cfg *config.AgentConfig) {
			cfg.TransferPublicURL = "https://agent.example"
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.DefaultAgent()
			if test.mutate != nil {
				test.mutate(cfg)
			}
			server, err := NewHTTPServer(cfg, http.NotFoundHandler())
			if (err != nil) != test.wantErr {
				t.Fatalf("server=%+v error=%v wantErr=%v", server, err, test.wantErr)
			}
		})
	}
}

func TestAgentHTTPServerPinsTLS13AndHeaderBounds(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultAgent()
	cfg.TLSCertFile = "agent.crt"
	cfg.TLSKeyFile = "agent.key"
	cfg.TransferPublicURL = "https://127.0.0.1:9443"
	server, err := NewHTTPServer(cfg, http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	if server.TLSConfig == nil || server.TLSConfig.MinVersion != tls.VersionTLS13 ||
		server.ReadHeaderTimeout <= 0 || server.IdleTimeout <= 0 || server.MaxHeaderBytes != 64<<10 {
		t.Fatalf("server=%+v tls=%+v", server, server.TLSConfig)
	}
}

func TestAgentTLSPreflightFailsBeforeServing(t *testing.T) {
	t.Parallel()
	if err := ValidateRuntimeTLSFiles(config.DefaultAgent()); err != nil {
		t.Fatalf("plaintext loopback preflight failed: %v", err)
	}
	cfg := config.DefaultAgent()
	cfg.TLSCertFile = "missing-agent.crt"
	cfg.TLSKeyFile = "missing-agent.key"
	if err := ValidateRuntimeTLSFiles(cfg); err == nil || strings.Contains(err.Error(), "missing-agent") {
		t.Fatalf("missing TLS pair error=%v", err)
	}
}

func TestAgentHandlerExposesOnlyHealthAndCapabilityDataPlane(t *testing.T) {
	t.Parallel()
	a := &Agent{Cfg: &config.AgentConfig{
		NodeID: 77, AgentPSK: "must-never-appear", TransferPublicURL: "https://agent.example/data",
	}}
	handler := a.Handler()
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/agent/health", nil))
	if health.Code != http.StatusOK || strings.Contains(health.Body.String(), "77") ||
		strings.Contains(health.Body.String(), "must-never-appear") {
		t.Fatalf("health status=%d body=%s", health.Code, health.Body.String())
	}

	for _, legacyPath := range []string{
		"/agent/provision-user", "/agent/set-password", "/agent/backup/start", "/agent/scan-existing",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, legacyPath, bytes.NewReader([]byte(`{}`))))
		if response.Code != http.StatusNotFound {
			t.Fatalf("legacy inbound control route %s returned %d", legacyPath, response.Code)
		}
	}

	invalid := httptest.NewRequest(
		http.MethodPost,
		"/data/transfer/v1/snapshots/11111111-1111-4111-8111-111111111111?capability=secret",
		bytes.NewReader([]byte("archive")),
	)
	invalid.Header.Set("Content-Type", "application/zstd")
	invalid.Header.Set("Authorization", "Bearer secret")
	invalid.Header.Set("X-Workflow-Id", "22222222-2222-4222-8222-222222222222")
	invalid.Header.Set("X-Archive-Sha256", strings.Repeat("a", 64))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, invalid)
	if response.Code != http.StatusBadRequest || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" ||
		strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("query capability status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAgentHandlerBoundsIncomingTransferConcurrencyBeforeReadingBody(t *testing.T) {
	t.Parallel()
	a := &Agent{Cfg: &config.AgentConfig{TransferPublicURL: "https://agent.example"}}
	handler := a.Handler()
	for range cap(a.transferSlots) {
		a.transferSlots <- struct{}{}
	}
	defer func() {
		for range cap(a.transferSlots) {
			<-a.transferSlots
		}
	}()
	request := httptest.NewRequest(
		http.MethodPost,
		"/transfer/v1/snapshots/11111111-1111-4111-8111-111111111111",
		bytes.NewReader([]byte("archive")),
	)
	request.Header.Set("Content-Type", "application/zstd")
	request.Header.Set("Authorization", "Bearer one-use-capability")
	request.Header.Set("X-Workflow-Id", "22222222-2222-4222-8222-222222222222")
	request.Header.Set("X-Archive-Sha256", strings.Repeat("a", 64))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "5" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}
