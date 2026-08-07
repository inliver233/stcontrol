package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

func TestRuntimeStatePersistsGenerationAndCompletedResult(t *testing.T) {
	t.Parallel()
	dataDir := t.TempDir()
	a, err := New(&config.AgentConfig{DataDir: dataDir, ControllerGeneration: 3})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	workerID, generation := a.commandIdentity()
	if len(workerID) < 16 || generation != 3 {
		t.Fatalf("worker=%q generation=%d", workerID, generation)
	}
	if !a.acceptGeneration(5) || a.acceptGeneration(4) {
		t.Fatal("generation fence did not reject rollback")
	}
	a.rememberResult("command-id", cachedCommandResult{
		Succeeded: true, Result: []byte(`{"ok":true}`), ControllerGeneration: 5,
		CompletedAt: time.Date(2026, 8, 7, 19, 0, 0, 0, time.UTC),
	})

	reloaded, err := New(&config.AgentConfig{DataDir: dataDir})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	reloadedWorker, reloadedGeneration := reloaded.commandIdentity()
	result, ok := reloaded.cachedResult("command-id")
	if reloadedWorker != workerID || reloadedGeneration != 5 || !ok || !result.Succeeded {
		t.Fatalf("worker=%q generation=%d result=%+v found=%v", reloadedWorker, reloadedGeneration, result, ok)
	}
}

func TestRuntimeStateRejectsCorruptFile(t *testing.T) {
	t.Parallel()
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "runtime-state.json"), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(&config.AgentConfig{DataDir: dataDir}); err == nil {
		t.Fatal("New accepted corrupt runtime state")
	}
}

func TestDecryptCommandAuthenticatesCiphertextAndDigest(t *testing.T) {
	t.Parallel()
	a := &Agent{Cfg: &config.AgentConfig{AgentPSK: "agent-secret"}}
	plaintext := []byte(`{"job_id":7}`)
	encoded, err := controlcrypto.Encrypt(controlcrypto.DeriveAgentCommandKey(a.Cfg.AgentPSK), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := json.Marshal(encryptedCommandEnvelope{Version: 1, Ciphertext: encoded})
	digest := sha256.Sum256(plaintext)
	command := protocol.AgentCommand{EncryptedPayload: envelope, PayloadSHA256: hex.EncodeToString(digest[:])}
	got, err := a.decryptCommand(command)
	if err != nil || string(got) != string(plaintext) {
		t.Fatalf("plaintext=%q err=%v", got, err)
	}
	command.PayloadSHA256 = hex.EncodeToString(make([]byte, 32))
	if _, err := a.decryptCommand(command); err == nil {
		t.Fatal("decryptCommand accepted mismatched digest")
	}
}

func TestExecuteScanExistingReturnsOnlySafeSummary(t *testing.T) {
	t.Parallel()
	tavernDir := t.TempDir()
	for _, name := range []string{"alice", "bob", "_cache", ".hidden"} {
		if err := os.MkdirAll(filepath.Join(tavernDir, "data", name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(tavernDir, "data", "alice", "settings.json"), []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{Cfg: &config.AgentConfig{AgentPSK: "agent-secret", TavernDir: tavernDir}}
	command := encryptedTestCommand(t, a.Cfg.AgentPSK, "scan_existing", []byte(`{}`))
	succeeded, raw := a.executeCommand(context.Background(), command)
	if !succeeded {
		t.Fatalf("result=%s", raw)
	}
	var result safeCommandResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Users) != 2 || result.Users[0].Handle != "alice" || result.Users[1].Handle != "bob" {
		t.Fatalf("users=%+v", result.Users)
	}
	if string(raw) == "" || jsonContainsKey(raw, "path") {
		t.Fatalf("unsafe result=%s", raw)
	}
}

func TestRegisterRequestDoesNotExposeCallbackAddress(t *testing.T) {
	t.Parallel()
	var request map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(protocol.RegisterAgentResponse{
			NodeID: 22, AgentPSK: "secret", CredentialVersion: 2, ControllerGeneration: 7,
		})
	}))
	defer server.Close()
	a, err := New(&config.AgentConfig{
		ControllerURL: server.URL, Role: "compute", TavernDir: t.TempDir(), DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RegisterToController(context.Background(), "one-use-token"); err != nil {
		t.Fatal(err)
	}
	if _, exists := request["agent_url"]; exists {
		t.Fatalf("registration leaked callback address: %+v", request)
	}
	if request["token"] != "one-use-token" || a.Cfg.NodeID != 22 || a.Cfg.ControllerGeneration != 7 {
		t.Fatalf("request=%+v config=%+v", request, a.Cfg)
	}
}

func TestControllerEndpointRequiresTLSOutsideLoopback(t *testing.T) {
	t.Parallel()
	a := &Agent{Cfg: &config.AgentConfig{ControllerURL: "http://controller.example"}}
	if _, err := a.controllerEndpoint("/api/agent/heartbeat"); err == nil {
		t.Fatal("insecure remote controller URL was accepted")
	}
	a.Cfg.ControllerURL = "https://controller.example/control"
	endpoint, err := a.controllerEndpoint("/api/agent/heartbeat")
	if err != nil || endpoint != "https://controller.example/control/api/agent/heartbeat" {
		t.Fatalf("endpoint=%q err=%v", endpoint, err)
	}
}

func encryptedTestCommand(t *testing.T, psk, commandType string, plaintext []byte) protocol.AgentCommand {
	t.Helper()
	encoded, err := controlcrypto.Encrypt(controlcrypto.DeriveAgentCommandKey(psk), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(encryptedCommandEnvelope{Version: 1, Ciphertext: encoded})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(plaintext)
	return protocol.AgentCommand{CommandType: commandType, EncryptedPayload: envelope, PayloadSHA256: hex.EncodeToString(digest[:])}
}

func jsonContainsKey(raw []byte, key string) bool {
	var object map[string]any
	_ = json.Unmarshal(raw, &object)
	_, ok := object[key]
	return ok
}
