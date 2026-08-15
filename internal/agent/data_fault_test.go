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
		_ = json.NewEncoder(w).Encode(protocol.FreezeUserDataResponse{
			OK: true, OperationID: captured.OperationID,
			ControllerGeneration: captured.ControllerGeneration,
			FaultID:              captured.FaultID, GlobalUserID: captured.GlobalUserID,
			Handle: captured.Handle, ActivityEpoch: captured.ActivityEpoch,
			Frozen: true, Drained: true,
		})
	}))
	defer server.Close()

	agent, err := New(&config.AgentConfig{
		Role: "compute", TavernURL: server.URL, AgentPSK: psk, NodeID: 12, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.FreezeUserDataRequest{
		OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ControllerGeneration: 5,
		FaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", GlobalUserID: 70,
		Handle: "alice", ActivityEpoch: 9,
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	command := encryptedTestCommand(t, psk, "freeze_user_data", payload)
	command.OperationID = request.OperationID
	command.ControllerGeneration = request.ControllerGeneration
	succeeded, result := agent.executeCommand(context.Background(), command)
	if !succeeded || !strings.Contains(string(result), `"user_data_freeze"`) {
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input protocol.FreezeUserDataRequest
		_ = json.NewDecoder(r.Body).Decode(&input)
		_ = json.NewEncoder(w).Encode(protocol.FreezeUserDataResponse{
			OK: true, OperationID: input.OperationID, ControllerGeneration: input.ControllerGeneration,
			FaultID: input.FaultID, GlobalUserID: input.GlobalUserID, Handle: input.Handle,
			ActivityEpoch: input.ActivityEpoch, Frozen: true, Drained: false,
		})
	}))
	defer server.Close()

	for _, test := range []struct {
		name    string
		role    string
		request protocol.FreezeUserDataRequest
		code    string
	}{
		{name: "invalid scope", role: "compute", request: protocol.FreezeUserDataRequest{OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ControllerGeneration: 5, FaultID: "not-a-uuid", GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9}, code: "invalid_command_payload"},
		{name: "storage role", role: "storage", request: protocol.FreezeUserDataRequest{OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ControllerGeneration: 5, FaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9}, code: "invalid_command_payload"},
		{name: "not drained", role: "compute", request: protocol.FreezeUserDataRequest{OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ControllerGeneration: 5, FaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9}, code: "user_data_freeze_failed"},
		{name: "operation mismatch", role: "compute", request: protocol.FreezeUserDataRequest{OperationID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", ControllerGeneration: 5, FaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9}, code: "invalid_command_payload"},
		{name: "generation mismatch", role: "compute", request: protocol.FreezeUserDataRequest{OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ControllerGeneration: 4, FaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9}, code: "invalid_command_payload"},
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
			command.ControllerGeneration = 5
			succeeded, result := agent.executeCommand(context.Background(), command)
			if succeeded || !strings.Contains(string(result), `"code":"`+test.code+`"`) {
				t.Fatalf("succeeded=%t result=%s", succeeded, result)
			}
		})
	}
}

func TestReleaseUserDataCommandCallsOnlyTheScopedSignedAdapterEndpoint(t *testing.T) {
	t.Parallel()
	const psk = "data-fault-release-agent-secret"
	var captured protocol.ReleaseUserDataRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/stcontrol/internal/data-faults/release" || r.Method != http.MethodPost {
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
		_ = json.NewEncoder(w).Encode(protocol.ReleaseUserDataResponse{
			OK: true, OperationID: captured.OperationID,
			ControllerGeneration: captured.ControllerGeneration,
			FaultID:              captured.FaultID, GlobalUserID: captured.GlobalUserID,
			Handle: captured.Handle, ActivityEpoch: captured.ActivityEpoch, Released: true,
		})
	}))
	defer server.Close()

	agent, err := New(&config.AgentConfig{
		Role: "compute", TavernURL: server.URL, AgentPSK: psk, NodeID: 12, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.ReleaseUserDataRequest{
		OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ControllerGeneration: 5,
		FaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", GlobalUserID: 70,
		Handle: "alice", ActivityEpoch: 9,
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	command := encryptedTestCommand(t, psk, "release_user_data", payload)
	command.OperationID = request.OperationID
	command.ControllerGeneration = request.ControllerGeneration
	succeeded, result := agent.executeCommand(context.Background(), command)
	if !succeeded || !strings.Contains(string(result), `"released":true`) {
		t.Fatalf("succeeded=%t result=%s", succeeded, result)
	}
	if captured.OperationID != command.OperationID || captured.FaultID != request.FaultID ||
		captured.GlobalUserID != request.GlobalUserID || captured.Handle != request.Handle ||
		captured.ActivityEpoch != request.ActivityEpoch {
		t.Fatalf("captured request=%+v", captured)
	}
}

func TestReleaseUserDataCommandFailsClosedForInvalidScopeRoleAndReceipt(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input protocol.ReleaseUserDataRequest
		_ = json.NewDecoder(r.Body).Decode(&input)
		_ = json.NewEncoder(w).Encode(protocol.ReleaseUserDataResponse{
			OK: true, OperationID: input.OperationID, ControllerGeneration: input.ControllerGeneration,
			FaultID: input.FaultID, GlobalUserID: input.GlobalUserID,
			Handle: input.Handle, ActivityEpoch: input.ActivityEpoch, Released: false,
		})
	}))
	defer server.Close()

	for _, test := range []struct {
		name    string
		role    string
		request protocol.ReleaseUserDataRequest
		code    string
	}{
		{name: "invalid scope", role: "compute", request: protocol.ReleaseUserDataRequest{OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ControllerGeneration: 5, FaultID: "not-a-uuid", GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9}, code: "invalid_command_payload"},
		{name: "storage role", role: "storage", request: protocol.ReleaseUserDataRequest{OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ControllerGeneration: 5, FaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9}, code: "invalid_command_payload"},
		{name: "not released", role: "compute", request: protocol.ReleaseUserDataRequest{OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ControllerGeneration: 5, FaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9}, code: "user_data_release_failed"},
		{name: "operation mismatch", role: "compute", request: protocol.ReleaseUserDataRequest{OperationID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", ControllerGeneration: 5, FaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9}, code: "invalid_command_payload"},
		{name: "generation mismatch", role: "compute", request: protocol.ReleaseUserDataRequest{OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ControllerGeneration: 4, FaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9}, code: "invalid_command_payload"},
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
			command := encryptedTestCommand(t, agent.Cfg.AgentPSK, "release_user_data", payload)
			command.OperationID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			command.ControllerGeneration = 5
			succeeded, result := agent.executeCommand(context.Background(), command)
			if succeeded || !strings.Contains(string(result), `"code":"`+test.code+`"`) {
				t.Fatalf("succeeded=%t result=%s", succeeded, result)
			}
		})
	}
}

func TestUserDataFaultAdapterReceiptsRejectOperationAndGenerationMismatch(t *testing.T) {
	t.Parallel()
	const (
		operationID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		faultID     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		generation  = int64(5)
	)
	for _, test := range []struct {
		name       string
		path       string
		generation int64
		operation  string
		freeze     bool
	}{
		{name: "freeze operation", path: "/api/stcontrol/internal/data-faults/freeze", operation: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", generation: generation, freeze: true},
		{name: "freeze generation", path: "/api/stcontrol/internal/data-faults/freeze", operation: operationID, generation: generation + 1, freeze: true},
		{name: "release operation", path: "/api/stcontrol/internal/data-faults/release", operation: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", generation: generation},
		{name: "release generation", path: "/api/stcontrol/internal/data-faults/release", operation: operationID, generation: generation + 1},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != test.path {
					t.Errorf("path=%q", r.URL.Path)
				}
				if test.freeze {
					_ = json.NewEncoder(w).Encode(protocol.FreezeUserDataResponse{
						OK: true, OperationID: test.operation, ControllerGeneration: test.generation,
						FaultID: faultID, GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9,
						Frozen: true, Drained: true,
					})
					return
				}
				_ = json.NewEncoder(w).Encode(protocol.ReleaseUserDataResponse{
					OK: true, OperationID: test.operation, ControllerGeneration: test.generation,
					FaultID: faultID, GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9,
					Released: true,
				})
			}))
			defer server.Close()
			a, err := New(&config.AgentConfig{
				Role: "compute", TavernURL: server.URL, AgentPSK: "secret", NodeID: 12,
				DataDir: t.TempDir(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if test.freeze {
				_, err = a.freezeUserData(context.Background(), protocol.FreezeUserDataRequest{
					OperationID: operationID, ControllerGeneration: generation, FaultID: faultID,
					GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9,
				})
			} else {
				_, err = a.releaseUserData(context.Background(), protocol.ReleaseUserDataRequest{
					OperationID: operationID, ControllerGeneration: generation, FaultID: faultID,
					GlobalUserID: 70, Handle: "alice", ActivityEpoch: 9,
				})
			}
			if err == nil {
				t.Fatal("mismatched adapter receipt was accepted")
			}
		})
	}
}
