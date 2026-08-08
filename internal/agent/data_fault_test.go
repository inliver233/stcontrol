package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func TestFreezeUserDataCommandCallsOnlyTheScopedSignedAdapterEndpoint(t *testing.T) {
	t.Parallel()
	const psk = "data-fault-agent-secret"
	var captured protocol.FreezeUserDataRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/stcontrol/internal/data-faults/freeze" || r.Method != http.MethodPost {
			t.Errorf("unexpected adapter request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		if err := protocol.VerifyRequest(r, psk, body); err != nil {
			t.Errorf("verify signed request: %v", err)
		}
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Errorf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(protocol.FreezeUserDataResponse{OK: true, Frozen: true, Drained: true})
	}))
	defer server.Close()

	agent, err := New(&config.AgentConfig{
		Role: "compute", TavernURL: server.URL, AgentPSK: psk, NodeID: 12, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.FreezeUserDataRequest{
		FaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", GlobalUserID: 70,
		Handle: "alice", ActivityEpoch: 9,
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	command := encryptedTestCommand(t, psk, "freeze_user_data", payload)
	command.OperationID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	succeeded, result := agent.executeCommand(context.Background(), command)
	if !succeeded || string(result) != `{"ok":true}` {
		t.Fatalf("succeeded=%t result=%s", succeeded, result)
	}
	if captured.OperationID != command.OperationID || captured.FaultID != request.FaultID ||
		captured.GlobalUserID != request.GlobalUserID || captured.Handle != request.Handle ||
		captured.ActivityEpoch != request.ActivityEpoch {
		t.Fatalf("captured request=%+v", captured)
	}
}

func TestFreezeUserDataCommandFailsClosedForInvalidScopeRoleAndReceipt(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(protocol.FreezeUserDataResponse{OK: true, Frozen: true, Drained: false})
	}))
	defer server.Close()

	for _, test := range []struct {
		name    string
		role    string
		request protocol.FreezeUserDataRequest
		code    string
	}{
		{name: "invalid scope", role: "compute", request: protocol.FreezeUserDataRequest{FaultID: "not-a-uuid", GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9}, code: "invalid_command_payload"},
		{name: "storage role", role: "storage", request: protocol.FreezeUserDataRequest{FaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9}, code: "invalid_command_payload"},
		{name: "not drained", role: "compute", request: protocol.FreezeUserDataRequest{FaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9}, code: "user_data_freeze_failed"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			agent, err := New(&config.AgentConfig{
				Role: test.role, TavernURL: server.URL, AgentPSK: "secret", NodeID: 12,
				DataDir: t.TempDir(), BackupDir: t.TempDir(),
			})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(test.request)
			if err != nil {
				t.Fatal(err)
			}
			command := encryptedTestCommand(t, agent.Cfg.AgentPSK, "freeze_user_data", payload)
			command.OperationID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			succeeded, result := agent.executeCommand(context.Background(), command)
			if succeeded || !strings.Contains(string(result), `"code":"`+test.code+`"`) {
				t.Fatalf("succeeded=%t result=%s", succeeded, result)
			}
		})
	}
}
