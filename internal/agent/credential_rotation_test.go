package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

func TestAgentPersistsConfirmsAndActivatesCredentialRotation(t *testing.T) {
	t.Parallel()
	const currentPSK = "current-controller-secret"
	const nextPSK = "next-controller-secret-with-enough-entropy"
	dataDir := t.TempDir()
	configPath := dataDir + "/agent.yaml"
	cfg := &config.AgentConfig{
		ControllerURL: serverURLPlaceholder, NodeID: 12, AgentPSK: currentPSK,
		TavernAdapterPSK: currentPSK, CredentialVersion: 1,
		ControllerGeneration: 4, DataDir: dataDir, ConfigPath: configPath,
	}
	var confirmed protocol.ConfirmAgentCredentialRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/api/agent/credentials/confirm" || protocol.VerifyRequest(r, nextPSK, body) != nil {
			t.Errorf("confirmation was not signed by pending credential")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := json.Unmarshal(body, &confirmed); err != nil || confirmed.CredentialVersion != 2 {
			t.Errorf("confirmation=%+v err=%v", confirmed, err)
		}
		protocol.WriteJSON(w, http.StatusOK, protocol.ConfirmAgentCredentialResponse{
			OK: true, CredentialVersion: 2, ControllerGeneration: 5,
		})
	}))
	defer server.Close()
	cfg.ControllerURL = server.URL
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := controlcrypto.Encrypt(
		controlcrypto.DeriveAgentCredentialRotationKey(currentPSK), []byte(nextPSK),
	)
	if err != nil {
		t.Fatal(err)
	}
	response := protocol.HeartbeatResponse{
		OK: true, ControllerGeneration: 5,
		CredentialRotation: &protocol.AgentCredentialRotationOffer{
			CredentialVersion: 2, ControllerGeneration: 5,
			EncryptedPSK: wrapped, ExpiresAt: time.Now().UTC().Add(time.Hour),
		},
	}
	if err := a.acceptControllerCredentialRotation(context.Background(), response); err != nil {
		t.Fatal(err)
	}
	psk, version := a.controllerCredential()
	if psk != nextPSK || version != 2 {
		t.Fatalf("psk=%q version=%d", psk, version)
	}
	loaded := &config.AgentConfig{}
	if err := config.Load(configPath, loaded); err != nil || loaded.AgentPSK != nextPSK ||
		loaded.TavernAdapterPSK != currentPSK || loaded.CredentialVersion != 2 {
		t.Fatalf("persisted config=%+v err=%v", loaded, err)
	}
	reloaded, err := New(a.Cfg)
	if err != nil {
		t.Fatal(err)
	}
	psk, version = reloaded.controllerCredential()
	if psk != nextPSK || version != 2 {
		t.Fatalf("reloaded psk=%q version=%d", psk, version)
	}
}

const serverURLPlaceholder = "http://127.0.0.1"

func TestAgentRejectsCredentialOfferEncryptedForDifferentCurrentSecret(t *testing.T) {
	t.Parallel()
	a, err := New(&config.AgentConfig{
		NodeID: 12, AgentPSK: "current", CredentialVersion: 1,
		ControllerGeneration: 4, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, _ := controlcrypto.Encrypt(
		controlcrypto.DeriveAgentCredentialRotationKey("attacker"), []byte("next-controller-secret-with-enough-entropy"),
	)
	err = a.acceptControllerCredentialRotation(context.Background(), protocol.HeartbeatResponse{
		ControllerGeneration: 5,
		CredentialRotation: &protocol.AgentCredentialRotationOffer{
			CredentialVersion: 2, ControllerGeneration: 5,
			EncryptedPSK: wrapped, ExpiresAt: time.Now().UTC().Add(time.Hour),
		},
	})
	if err == nil {
		t.Fatal("offer encrypted for another credential was accepted")
	}
}
