package agent

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestExecuteCommandRejectsEveryUnsupportedOrMalformedFixedCapability(t *testing.T) {
	t.Parallel()
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 12, AgentPSK: "command-matrix-agent-secret", DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		commandType string
		payload     string
		code        string
	}{
		{"scan_existing_page", `{}`, "invalid_command_payload"},
		{"abort_backup", `{}`, "invalid_command_payload"},
		{"provision_user", `{`, "invalid_command_payload"},
		{"restore_user_account", `{`, "invalid_command_payload"},
		{"set_password", `{}`, "invalid_command_payload"},
		{"verify_node_admin", `{}`, "invalid_command_payload"},
		{"verify_local_user", `{}`, "invalid_command_payload"},
		{"complete_independent_sync", `{}`, "invalid_command_payload"},
		{"freeze_user_data", `{}`, "invalid_command_payload"},
		{"release_user_data", `{}`, "invalid_command_payload"},
		{"check_node_admin", `{}`, "invalid_command_payload"},
		{"prepare_snapshot_receive", `{}`, "invalid_command_payload"},
		{"start_snapshot", `{`, "invalid_command_payload"},
		{"start_relay_receive", `{`, "invalid_command_payload"},
		{"start_restore_transfer", `{`, "invalid_command_payload"},
		{"get_snapshot_receipt", `{}`, "invalid_command_payload"},
		{"receive_controller_backup", `{}`, "invalid_command_payload"},
		{"verify_replica_integrity_v2", `{`, "invalid_command_payload"},
		{"delete_snapshot_replica", `{}`, "invalid_command_payload"},
		{"capture_conflict_evidence", `{}`, "invalid_command_payload"},
		{"read_conflict_evidence_page", `{}`, "invalid_command_payload"},
		{"start_conflict_evidence_transfer", `{`, "invalid_command_payload"},
		{"prepare_conflict_resolution", `{`, "invalid_command_payload"},
		{"apply_conflict_resolution_decisions", `{`, "invalid_command_payload"},
		{"publish_conflict_resolution", `{`, "invalid_command_payload"},
		{"arbitrary_shell", `{}`, "unsupported_command"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.commandType, func(t *testing.T) {
			t.Parallel()
			command := encryptedTestCommand(t, a.Cfg.AgentPSK, test.commandType, []byte(test.payload))
			command.OperationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			succeeded, raw := a.executeCommand(context.Background(), command)
			var result safeCommandResult
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatalf("decode safe result: %v raw=%s", err, raw)
			}
			if succeeded || result.OK || result.Code != test.code {
				t.Fatalf("succeeded=%v result=%+v, want code %q", succeeded, result, test.code)
			}
		})
	}

	invalidEnvelope := protocol.AgentCommand{
		CommandType: "abort_backup", EncryptedPayload: json.RawMessage(`{"version":99}`),
	}
	succeeded, raw := a.executeCommand(context.Background(), invalidEnvelope)
	if succeeded || !bytes.Contains(raw, []byte(`"code":"invalid_command_payload"`)) {
		t.Fatalf("invalid envelope result: succeeded=%v raw=%s", succeeded, raw)
	}
}

func TestExecuteCommandMapsValidDownstreamFailuresToClosedStableCodes(t *testing.T) {
	t.Parallel()
	adapter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "adapter deliberately unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(adapter.Close)
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 12, AgentPSK: "command-downstream-agent-secret",
		TavernURL: adapter.URL, TavernDir: t.TempDir(), DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	const operationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const workflowID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	const faultID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	const markerID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	tests := []struct {
		name        string
		commandType string
		payload     string
		generation  int64
		wantCode    string
	}{
		{name: "restore account", commandType: "restore_user_account", payload: `{
			"workflow_id":"` + workflowID + `","global_user_id":70,"handle":"alice","name":"Alice",
			"account_version":3,"password_hash":"node-hash","password_salt":"node-salt"
		}`, wantCode: "account_restore_failed"},
		{name: "password", commandType: "set_password", payload: `{
			"handle":"alice","password_hash":"node-hash","password_salt":"node-salt","version":3
		}`, wantCode: "password_update_failed"},
		{name: "oauth", commandType: "set_oauth_identity", payload: `{
			"handle":"alice","provider":"discord","subject":"stable-subject","version":3
		}`, wantCode: "oauth_identity_update_failed"},
		{name: "node admin verification", commandType: "verify_node_admin", payload: `{
			"handle":"alice","password":"correct horse battery staple"
		}`, wantCode: "node_admin_verify_unavailable"},
		{name: "local user verification", commandType: "verify_local_user", payload: `{
			"handle":"alice","password":"correct horse battery staple"
		}`, wantCode: "local_user_verify_unavailable"},
		{name: "independent sync", commandType: "complete_independent_sync", payload: `{
			"operation_id":"` + operationID + `","handle":"alice","marker":"` + markerID + `"
		}`, wantCode: "independent_sync_completion_failed"},
		{name: "freeze", commandType: "freeze_user_data", payload: `{
			"operation_id":"` + operationID + `","controller_generation":7,"fault_id":"` + faultID + `",
			"global_user_id":70,"handle":"alice","activity_epoch":4
		}`, generation: 7, wantCode: "user_data_freeze_failed"},
		{name: "release", commandType: "release_user_data", payload: `{
			"operation_id":"` + operationID + `","controller_generation":7,"fault_id":"` + faultID + `",
			"global_user_id":70,"handle":"alice","activity_epoch":4
		}`, generation: 7, wantCode: "user_data_release_failed"},
		{name: "node admin status", commandType: "check_node_admin", payload: `{
			"handle":"alice"
		}`, wantCode: "node_admin_check_unavailable"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			command := encryptedTestCommand(t, a.Cfg.AgentPSK, test.commandType, []byte(test.payload))
			command.OperationID = operationID
			command.ControllerGeneration = test.generation
			succeeded, raw := a.executeCommand(context.Background(), command)
			var result safeCommandResult
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatalf("decode safe result: %v raw=%s", err, raw)
			}
			if succeeded || result.OK || result.Code != test.wantCode ||
				bytes.Contains(raw, []byte("adapter deliberately unavailable")) {
				t.Fatalf("succeeded=%v result=%s, want closed code %q", succeeded, raw, test.wantCode)
			}
		})
	}
}

func TestExecuteCommandMapsDurableArtifactMissesToClosedStableCodes(t *testing.T) {
	t.Parallel()
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 12, AgentPSK: "command-artifact-agent-secret",
		TavernDir: t.TempDir(), DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	const workflowID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const snapshotID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	command := encryptedTestCommand(t, a.Cfg.AgentPSK, "get_snapshot_receipt", []byte(`{
		"workflow_id":"`+workflowID+`","snapshot_id":"`+snapshotID+`"
	}`))
	succeeded, raw := a.executeCommand(context.Background(), command)
	var result safeCommandResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if succeeded || result.Code != "snapshot_receipt_unavailable" {
		t.Fatalf("missing receipt succeeded=%v result=%s", succeeded, raw)
	}
}

func TestExecuteCommandMapsValidWorkflowFailuresToClosedStableCodes(t *testing.T) {
	t.Parallel()
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 12, AgentPSK: "command-workflow-agent-secret",
		TavernDir: t.TempDir(), DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		commandType string
		payload     string
		wantCode    string
	}{
		{commandType: "start_snapshot", payload: `{}`, wantCode: "snapshot_failed"},
		{commandType: "start_relay_receive", payload: `{}`, wantCode: "relay_receive_failed"},
		{commandType: "start_restore_transfer", payload: `{}`, wantCode: "restore_transfer_failed"},
		{commandType: "verify_replica_integrity_v2", payload: `{}`, wantCode: "replica_integrity_unavailable"},
		{commandType: "start_conflict_evidence_transfer", payload: `{}`, wantCode: "conflict_evidence_transfer_failed"},
		{commandType: "prepare_conflict_resolution", payload: `{}`, wantCode: "conflict_resolution_prepare_failed"},
		{commandType: "apply_conflict_resolution_decisions", payload: `{}`, wantCode: "conflict_resolution_decisions_failed"},
		{commandType: "publish_conflict_resolution", payload: `{}`, wantCode: "conflict_resolution_publish_failed"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.commandType, func(t *testing.T) {
			command := encryptedTestCommand(t, a.Cfg.AgentPSK, test.commandType, []byte(test.payload))
			command.OperationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			succeeded, raw := a.executeCommand(context.Background(), command)
			var result safeCommandResult
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			if succeeded || result.Code != test.wantCode {
				t.Fatalf("succeeded=%v result=%s, want code %q", succeeded, raw, test.wantCode)
			}
		})
	}
}

func TestExecuteScanCommandsFailClosedWhenInventoryRootIsNotDirectory(t *testing.T) {
	t.Parallel()
	tavernDir := t.TempDir()
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 12, AgentPSK: "command-scan-failure-secret",
		TavernDir: tavernDir, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tavernDir, "data"), []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		commandType, payload string
	}{
		{commandType: "scan_existing", payload: `{}`},
		{commandType: "scan_existing_page", payload: `{"cursor":0,"limit":10}`},
	} {
		command := encryptedTestCommand(t, a.Cfg.AgentPSK, test.commandType, []byte(test.payload))
		succeeded, raw := a.executeCommand(context.Background(), command)
		var result safeCommandResult
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		if succeeded || result.Code != "scan_failed" {
			t.Fatalf("type=%s succeeded=%v result=%s", test.commandType, succeeded, raw)
		}
	}
}

func TestPollAndRunCommandReportsAndReusesDurableCachedResult(t *testing.T) {
	t.Parallel()
	const (
		psk       = "command-channel-agent-secret"
		commandID = "command-channel-id"
	)
	var (
		mu         sync.Mutex
		leaseCount int
		results    []protocol.FinishCommandRequest
	)
	resultReady := make(chan struct{}, 2)
	var command protocol.AgentCommand
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/agent/commands/lease":
			var request protocol.LeaseCommandRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.WorkerID == "" {
				t.Errorf("decode lease request: request=%+v err=%v", request, err)
			}
			mu.Lock()
			leaseCount++
			current := leaseCount
			mu.Unlock()
			w.Header().Set("X-Controller-Generation", "2")
			if current > 2 {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_ = json.NewEncoder(w).Encode(command)
		case r.URL.Path == "/api/agent/commands/"+commandID+"/ack":
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/agent/commands/"+commandID+"/result":
			var request protocol.FinishCommandRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode command result: %v", err)
			}
			mu.Lock()
			results = append(results, request)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			resultReady <- struct{}{}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	a, err := New(&config.AgentConfig{
		ControllerURL: server.URL, Role: "compute", NodeID: 12, AgentPSK: psk,
		ControllerGeneration: 1, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	command = encryptedTestCommand(t, psk, "abort_backup", []byte(`{"job_id":77}`))
	command.ID = commandID
	command.OperationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	command.ControllerGeneration = 2
	command.ExpiresAt = time.Now().UTC().Add(time.Minute)

	for attempt := 0; attempt < 2; attempt++ {
		if err := a.pollAndRunCommand(context.Background()); err != nil {
			t.Fatalf("poll attempt %d: %v", attempt+1, err)
		}
		select {
		case <-resultReady:
		case <-time.After(5 * time.Second):
			t.Fatalf("command result attempt %d was not reported", attempt+1)
		}
	}
	if err := a.pollAndRunCommand(context.Background()); err != nil {
		t.Fatalf("empty command poll: %v", err)
	}
	mu.Lock()
	gotResults := append([]protocol.FinishCommandRequest(nil), results...)
	mu.Unlock()
	if len(gotResults) != 2 || !gotResults[0].Succeeded || !gotResults[1].Succeeded ||
		gotResults[0].ControllerGeneration != 2 || gotResults[1].ControllerGeneration != 2 ||
		!bytes.Equal(gotResults[0].Result, gotResults[1].Result) {
		t.Fatalf("reported results=%+v", gotResults)
	}
	if _, ok := a.cachedResult(commandID); !ok {
		t.Fatal("successful fixed command result was not persisted")
	}
	audit, err := os.ReadFile(filepath.Join(a.Cfg.DataDir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read local command audit: %v", err)
	}
	if !bytes.Contains(audit, []byte(`"cached":true`)) || bytes.Contains(audit, []byte(psk)) {
		t.Fatalf("local command audit did not mark cache reuse or exposed credential: %s", audit)
	}
}

func TestPollAndRunCommandFailsClosedOnControllerAndGenerationErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		status     int
		generation string
		body       string
		want       string
	}{
		{name: "controller status", status: http.StatusServiceUnavailable, want: "status 503"},
		{name: "invalid generation", status: http.StatusNoContent, generation: "not-a-number", want: "generation rollback"},
		{name: "invalid command json", status: http.StatusOK, generation: "2", body: `{`, want: "decode command"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if test.generation != "" {
					w.Header().Set("X-Controller-Generation", test.generation)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			a, err := New(&config.AgentConfig{
				ControllerURL: server.URL, Role: "compute", NodeID: 12,
				AgentPSK: "command-error-agent-secret", ControllerGeneration: 1, DataDir: t.TempDir(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := a.pollAndRunCommand(context.Background()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestStartCommandLoopReturnsWhenPausedLoopIsCancelled(t *testing.T) {
	t.Parallel()
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 12, AgentPSK: "paused-command-agent-secret", DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	a.stateMu.Lock()
	a.state.ControlMode.Mode = protocol.NodeModeIndependent
	a.stateMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.StartCommandLoop(ctx)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled paused command loop did not stop")
	}
}
