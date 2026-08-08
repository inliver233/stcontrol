package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestConflictEvidencePagesDoNotEnterGeneralCommandCache(t *testing.T) {
	t.Parallel()
	if shouldCacheCommandResult("read_conflict_evidence_page") {
		t.Fatal("encrypted manifest page would be duplicated in runtime command cache")
	}
	if !shouldCacheCommandResult("capture_conflict_evidence") {
		t.Fatal("idempotent evidence capture receipt must remain restart-safe")
	}
}

func TestIndependentDrainingCommandAllowlistIsClosed(t *testing.T) {
	t.Parallel()
	for _, commandType := range []string{
		"start_snapshot", "start_relay_receive", "complete_independent_sync", "capture_conflict_evidence",
		"publish_conflict_resolution", "verify_replica_integrity",
	} {
		if !independentReconciliationCommand(commandType) {
			t.Errorf("reconciliation command %q was rejected", commandType)
		}
	}
	for _, commandType := range []string{"provision_user", "set_password", "restore_user_account", "scan_existing", ""} {
		if independentReconciliationCommand(commandType) {
			t.Errorf("ordinary command %q was allowed while draining", commandType)
		}
	}
}

func TestPrepareRestoreReceiveRequiresComputeRole(t *testing.T) {
	t.Parallel()
	payload, err := json.Marshal(protocol.PrepareSnapshotReceiveRequest{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, GlobalUserID: 70,
		Handle: "alice", DestinationKind: "restore", SourceNodeID: 8, ActivityEpoch: 4,
		CapabilityHash: strings.Repeat("a", 64), ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	compute, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 9, AgentPSK: "compute-secret", DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	succeeded, result := compute.executeCommand(
		context.Background(), encryptedTestCommand(t, compute.Cfg.AgentPSK, "prepare_snapshot_receive", payload),
	)
	if !succeeded {
		t.Fatalf("compute restore prepare failed: %s", result)
	}
	storage, err := New(&config.AgentConfig{
		Role: "storage", NodeID: 10, AgentPSK: "storage-secret", DataDir: t.TempDir(), BackupDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	succeeded, _ = storage.executeCommand(
		context.Background(), encryptedTestCommand(t, storage.Cfg.AgentPSK, "prepare_snapshot_receive", payload),
	)
	if succeeded {
		t.Fatal("storage node accepted a restore destination")
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

func TestDecryptCommandV2UsesKeyedPayloadAuthenticator(t *testing.T) {
	t.Parallel()
	a := &Agent{Cfg: &config.AgentConfig{AgentPSK: "agent-secret"}}
	plaintext := []byte(`{"invitation_code":"low-entropy"}`)
	key := controlcrypto.DeriveAgentCommandKey(a.Cfg.AgentPSK)
	encoded, err := controlcrypto.Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := json.Marshal(encryptedCommandEnvelope{Version: 2, Ciphertext: encoded})
	authenticator := hmac.New(sha256.New, controlcrypto.DeriveAgentCommandAuthKey(a.Cfg.AgentPSK))
	_, _ = authenticator.Write(plaintext)
	command := protocol.AgentCommand{
		EncryptedPayload: envelope, PayloadSHA256: hex.EncodeToString(authenticator.Sum(nil)),
	}
	got, err := a.decryptCommand(command)
	if err != nil || string(got) != string(plaintext) {
		t.Fatalf("plaintext=%q err=%v", got, err)
	}
	bareDigest := sha256.Sum256(plaintext)
	command.PayloadSHA256 = hex.EncodeToString(bareDigest[:])
	if _, err := a.decryptCommand(command); err == nil {
		t.Fatal("v2 command accepted an unkeyed payload digest")
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
	if result.Users[0].Source != "directory_fallback" || result.Users[0].AccountKind != "unknown" ||
		len(result.Users[0].DirectoryFingerprint) != 64 || result.Users[0].LocalUserID != "alice" {
		t.Fatalf("unsafe fallback classification=%+v", result.Users[0])
	}
	if string(raw) == "" || jsonContainsKey(raw, "path") {
		t.Fatalf("unsafe result=%s", raw)
	}
}

func TestScanExistingUsersUsesAdapterAndRedactsOAuthSubject(t *testing.T) {
	t.Parallel()
	const subject = "discord-stable-subject"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/stcontrol/internal/users/scan" {
			t.Errorf("path=%q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(adapterInventoryResponse{
			OK: true,
			Users: []adapterInventoryUser{{
				LocalUserID: "local-7", Handle: "alice", SizeBytes: 123,
				DirectoryFingerprint: strings.Repeat("a", 64), HasPassword: true, IsAdmin: true,
				OAuthIdentities: []adapterInventoryIdentity{{Provider: "discord", Subject: subject}},
			}},
		})
	}))
	defer server.Close()
	a, err := New(&config.AgentConfig{
		TavernURL: server.URL, AgentPSK: "agent-secret", NodeID: 12, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	users, err := a.ScanExistingUsers(context.Background())
	if err != nil || len(users) != 1 {
		t.Fatalf("users=%+v err=%v", users, err)
	}
	encoded, err := json.Marshal(users)
	if err != nil {
		t.Fatal(err)
	}
	wantFingerprint := controlcrypto.AgentInventoryFingerprint(
		"agent-secret", "oauth-subject", "discord", subject,
	)
	if users[0].Source != "adapter" || users[0].AccountKind != "mixed" || !users[0].IsAdmin ||
		len(users[0].Identities) != 1 || users[0].Identities[0].Fingerprint != wantFingerprint ||
		strings.Contains(string(encoded), subject) {
		t.Fatalf("unsafe adapter inventory=%s", encoded)
	}
}

func TestScanExistingUsersDoesNotFallbackAfterInvalidAdapterInventory(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(adapterInventoryResponse{OK: false})
	}))
	defer server.Close()
	tavernDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tavernDir, "data", "alice"), 0o700); err != nil {
		t.Fatal(err)
	}
	a, err := New(&config.AgentConfig{
		TavernURL: server.URL, TavernDir: tavernDir, AgentPSK: "agent-secret",
		NodeID: 12, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	users, err := a.ScanExistingUsers(context.Background())
	if !errors.Is(err, errInvalidAdapterInventory) || users != nil {
		t.Fatalf("users=%+v err=%v", users, err)
	}
}

func TestPasswordCommandPassesCommandOperationToAdapter(t *testing.T) {
	t.Parallel()
	operationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	var adapterRequest protocol.SetPasswordRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/stcontrol/internal/users/password" {
			t.Errorf("path=%q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&adapterRequest); err != nil {
			t.Errorf("decode: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer server.Close()
	a, err := New(&config.AgentConfig{
		TavernURL: server.URL, AgentPSK: "agent-secret", NodeID: 12, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	command := encryptedTestCommand(t, a.Cfg.AgentPSK, "set_password", []byte(`{
		"handle":"alice","password_hash":"node-hash","password_salt":"node-salt","version":4
	}`))
	command.OperationID = operationID
	succeeded, result := a.executeCommand(context.Background(), command)
	if !succeeded || adapterRequest.OperationID != operationID || adapterRequest.Version != 4 {
		t.Fatalf("succeeded=%v request=%+v result=%s", succeeded, adapterRequest, result)
	}
}

func TestProvisionCommandPassesStableRegistrationAndDeliveryOperations(t *testing.T) {
	t.Parallel()
	operationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	registrationID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	var adapterRequest protocol.ProvisionUserRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&adapterRequest); err != nil {
			t.Errorf("decode: %v", err)
		}
		_ = json.NewEncoder(w).Encode(protocol.ProvisionUserResponse{
			OK: true, Handle: "alice", LocalUserID: "local-alice",
		})
	}))
	defer server.Close()
	a, err := New(&config.AgentConfig{
		TavernURL: server.URL, AgentPSK: "agent-secret", NodeID: 12, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	command := encryptedTestCommand(t, a.Cfg.AgentPSK, "provision_user", []byte(`{
		"registration_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		"policy_version":7,"handle":"alice","name":"Alice",
		"password_hash":"node-hash","password_salt":"node-salt"
	}`))
	command.OperationID = operationID
	succeeded, result := a.executeCommand(context.Background(), command)
	if !succeeded || adapterRequest.OperationID != operationID ||
		adapterRequest.RegistrationID != registrationID || adapterRequest.PolicyVersion != 7 {
		t.Fatalf("succeeded=%v request=%+v result=%s", succeeded, adapterRequest, result)
	}
}

func TestRestoreAccountCommandUsesDedicatedIdempotentAdapterCapability(t *testing.T) {
	t.Parallel()
	operationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	var adapterRequest protocol.RestoreUserAccountRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/stcontrol/internal/users/restore" {
			t.Errorf("path=%s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&adapterRequest); err != nil {
			t.Errorf("decode: %v", err)
		}
		_ = json.NewEncoder(w).Encode(protocol.ProvisionUserResponse{
			OK: true, Handle: "alice", LocalUserID: "local-alice",
		})
	}))
	defer server.Close()
	a, err := New(&config.AgentConfig{
		Role: "compute", TavernURL: server.URL, AgentPSK: "agent-secret", NodeID: 12, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	command := encryptedTestCommand(t, a.Cfg.AgentPSK, "restore_user_account", []byte(`{
		"workflow_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		"global_user_id":70,"handle":"alice","name":"Alice","account_version":3,
		"password_hash":"node-hash","password_salt":"node-salt"
	}`))
	command.OperationID = operationID
	succeeded, result := a.executeCommand(context.Background(), command)
	if !succeeded || adapterRequest.OperationID != operationID ||
		adapterRequest.WorkflowID != "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" ||
		adapterRequest.AccountVersion != 3 {
		t.Fatalf("succeeded=%v request=%+v result=%s", succeeded, adapterRequest, result)
	}
}

func TestDefinitiveProvisionErrorAllowsOnlyNodeOwnedBusinessRejections(t *testing.T) {
	t.Parallel()
	for _, code := range []string{
		"invitation_invalid", "handle_conflict", "policy_changed", "registration_closed",
	} {
		if !definitiveProvisionError(code) {
			t.Errorf("code %q should be definitive", code)
		}
	}
	for _, code := range []string{
		"", "adapter_unavailable", "timeout", "internal_error", "unknown",
	} {
		if definitiveProvisionError(code) {
			t.Errorf("code %q must remain retryable", code)
		}
	}
}

func TestProvisionCommandDistinguishesDefinitiveRejectionFromUncertainFailure(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		response   protocol.ProvisionUserResponse
		statusCode int
		wantCode   string
	}{
		{
			name: "node owned invitation rejection",
			response: protocol.ProvisionUserResponse{
				OK: false, Error: "invitation_invalid",
			},
			statusCode: http.StatusOK,
			wantCode:   "provision_rejected",
		},
		{
			name:       "transport failure may have executed",
			statusCode: http.StatusServiceUnavailable,
			wantCode:   "provision_unavailable",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.statusCode)
				if test.statusCode == http.StatusOK {
					_ = json.NewEncoder(w).Encode(test.response)
				}
			}))
			defer server.Close()
			a, err := New(&config.AgentConfig{
				TavernURL: server.URL, AgentPSK: "agent-secret", NodeID: 12, DataDir: t.TempDir(),
			})
			if err != nil {
				t.Fatal(err)
			}
			command := encryptedTestCommand(t, a.Cfg.AgentPSK, "provision_user", []byte(`{
				"registration_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
				"policy_version":7,"handle":"alice","name":"Alice",
				"password_hash":"node-hash","password_salt":"node-salt"
			}`))
			command.OperationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			succeeded, raw := a.executeCommand(context.Background(), command)
			var result safeCommandResult
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			if succeeded || result.Code != test.wantCode {
				t.Fatalf("succeeded=%v result=%s", succeeded, raw)
			}
		})
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
