package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func executeAgentTestCommand(
	t *testing.T,
	a *Agent,
	commandType string,
	payload any,
	operationID string,
) (bool, safeCommandResult) {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	command := encryptedTestCommand(t, a.Cfg.AgentPSK, commandType, encoded)
	command.OperationID = operationID
	succeeded, raw := a.executeCommand(context.Background(), command)
	var result safeCommandResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode %s result: %v raw=%s", commandType, err, raw)
	}
	return succeeded, result
}

func TestExecuteCommandSuccessfulAdapterVerificationCapabilities(t *testing.T) {
	t.Parallel()
	adapter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/stcontrol/internal/admin/verify", "/api/stcontrol/internal/admin/check":
			_ = json.NewEncoder(w).Encode(protocol.NodeAdminVerification{
				Handle: "alice", LocalUserID: "local-alice", IsAdmin: true, PermissionVersion: 4,
			})
		case "/api/stcontrol/internal/users/verify":
			_ = json.NewEncoder(w).Encode(protocol.VerifyLocalUserResponse{
				Handle: "alice", LocalUserID: "local-alice", Verified: true,
			})
		case "/api/stcontrol/internal/control/sync-complete":
			var request protocol.CompleteIndependentSyncRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode sync completion: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true, "handle": request.Handle, "marker": request.Marker,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(adapter.Close)
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 12, AgentPSK: "command-success-agent-secret",
		TavernURL: adapter.URL, DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	const operationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	tests := []struct {
		commandType string
		payload     any
		validate    func(safeCommandResult) bool
	}{
		{
			commandType: "verify_node_admin",
			payload:     protocol.VerifyNodeAdminRequest{Handle: "alice", Password: "correct password"},
			validate: func(result safeCommandResult) bool {
				return result.NodeAdmin != nil && result.NodeAdmin.IsAdmin && result.NodeAdmin.PermissionVersion == 4
			},
		},
		{
			commandType: "verify_local_user",
			payload:     protocol.VerifyLocalUserRequest{Handle: "alice", Password: "correct password"},
			validate: func(result safeCommandResult) bool {
				return result.LocalUserProof != nil && result.LocalUserProof.Verified && result.LocalUserProof.LocalUserID == "local-alice"
			},
		},
		{
			commandType: "check_node_admin",
			payload:     protocol.CheckNodeAdminRequest{Handle: "alice"},
			validate: func(result safeCommandResult) bool {
				return result.NodeAdmin != nil && result.NodeAdmin.IsAdmin
			},
		},
		{
			commandType: "complete_independent_sync",
			payload: protocol.CompleteIndependentSyncRequest{
				OperationID: operationID, Handle: "alice", Marker: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			},
			validate: func(result safeCommandResult) bool { return result.OK },
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.commandType, func(t *testing.T) {
			succeeded, result := executeAgentTestCommand(t, a, tc.commandType, tc.payload, operationID)
			if !succeeded || !result.OK || !tc.validate(result) {
				t.Fatalf("succeeded=%v result=%+v", succeeded, result)
			}
		})
	}
}

func TestExecuteCommandPreparesDirectAndRelaySnapshotReceivers(t *testing.T) {
	t.Parallel()
	const operationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	for _, relay := range []bool{false, true} {
		relay := relay
		name := "direct"
		if relay {
			name = "relay"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, err := New(&config.AgentConfig{
				Role: "compute", NodeID: 12, AgentPSK: "prepare-transfer-command-secret", DataDir: t.TempDir(),
			})
			if err != nil {
				t.Fatal(err)
			}
			request := protocol.PrepareSnapshotReceiveRequest{
				WorkflowID:   "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
				SnapshotID:   "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
				GlobalUserID: 70, Handle: "alice", DestinationKind: "hot_standby",
				SourceNodeID: 8, ActivityEpoch: 4, CapabilityHash: strings.Repeat("a", 64),
				ExpiresAt: time.Now().UTC().Add(time.Hour),
			}
			if relay {
				request.RelayTaskID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
			}
			succeeded, result := executeAgentTestCommand(t, a, "prepare_snapshot_receive", request, operationID)
			if !succeeded || !result.OK || (relay && result.RelayPublicKey == "") || (!relay && result.RelayPublicKey != "") {
				t.Fatalf("relay=%v succeeded=%v result=%+v", relay, succeeded, result)
			}
			transfer, ok := a.state.Transfers[request.SnapshotID]
			if !ok || transfer.State != "prepared" || transfer.TargetNodeID != a.Cfg.NodeID || transfer.ActivityEpoch != 4 {
				t.Fatalf("persisted transfer=%+v ok=%v", transfer, ok)
			}
		})
	}
}

func TestExecuteCommandReturnsPersistedSnapshotReceipt(t *testing.T) {
	t.Parallel()
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 12, AgentPSK: "receipt-command-secret", DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	const workflowID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const snapshotID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	receipt := protocol.SnapshotTransferReceipt{
		OK: true, SnapshotID: snapshotID, ManifestSHA256: strings.Repeat("a", 64),
		ArchiveSHA256: strings.Repeat("b", 64), FileCount: 2, TotalBytes: 30,
	}
	a.state.Transfers[snapshotID] = pendingTransfer{
		WorkflowID: workflowID, SnapshotID: snapshotID, State: "published", Receipt: &receipt,
	}
	succeeded, result := executeAgentTestCommand(t, a, "get_snapshot_receipt", map[string]string{
		"workflow_id": workflowID, "snapshot_id": snapshotID,
	}, "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	if !succeeded || !result.OK || result.Snapshot == nil || result.Snapshot.SnapshotID != snapshotID {
		t.Fatalf("succeeded=%v result=%+v", succeeded, result)
	}
}

func TestExecuteCommandPreparesControllerBackupIntent(t *testing.T) {
	t.Parallel()
	a, err := New(&config.AgentConfig{
		Role: "storage", NodeID: 12, AgentPSK: "controller-backup-command-secret",
		DataDir: t.TempDir(), BackupDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.PrepareControllerBackupRequest{
		OperationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ControllerGeneration: 4,
		CapabilityHash: strings.Repeat("a", 64), ExpiresAt: time.Now().UTC().Add(time.Hour), BackupKind: "full",
	}
	succeeded, result := executeAgentTestCommand(t, a, "receive_controller_backup", request, request.OperationID)
	intent := a.state.ControllerBackups[request.OperationID]
	if !succeeded || !result.OK || intent.State != "prepared" || intent.CapabilityHash != request.CapabilityHash {
		t.Fatalf("succeeded=%v result=%+v intent=%+v", succeeded, result, intent)
	}
}

func TestExecuteCommandFailsClosedWhenAbortCannotBePersisted(t *testing.T) {
	t.Parallel()
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 12, AgentPSK: "abort-command-secret", DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	a.Cfg.DataDir = "/dev/null"
	succeeded, result := executeAgentTestCommand(t, a, "abort_backup", map[string]int64{"job_id": 42},
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	if succeeded || result.OK || result.Code != "backup_cancel_failed" {
		t.Fatalf("succeeded=%v result=%+v", succeeded, result)
	}
}

func TestExecuteCommandRejectsWellFormedButInvalidCommandContracts(t *testing.T) {
	t.Parallel()
	a, err := New(&config.AgentConfig{
		Role: "storage", NodeID: 12, AgentPSK: "invalid-contract-command-secret",
		DataDir: t.TempDir(), BackupDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	const operationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	tests := []struct {
		commandType string
		payload     any
	}{
		{commandType: "scan_existing", payload: json.RawMessage(`{`)},
		{commandType: "provision_user", payload: map[string]string{"handle": "alice"}},
		{commandType: "restore_user_account", payload: protocol.RestoreUserAccountRequest{
			WorkflowID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", GlobalUserID: 70, Handle: "alice",
			Name: "Alice", AccountVersion: 3, PasswordHash: "hash", PasswordSalt: "salt",
		}},
		{commandType: "set_password", payload: protocol.SetPasswordRequest{Handle: "alice", Version: 3}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.commandType, func(t *testing.T) {
			var encoded []byte
			if raw, ok := tc.payload.(json.RawMessage); ok {
				encoded = raw
			} else {
				var encodeErr error
				encoded, encodeErr = json.Marshal(tc.payload)
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
			}
			command := encryptedTestCommand(t, a.Cfg.AgentPSK, tc.commandType, encoded)
			command.OperationID = operationID
			succeeded, raw := a.executeCommand(context.Background(), command)
			var result safeCommandResult
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			if succeeded || result.OK || result.Code != "invalid_command_payload" {
				t.Fatalf("succeeded=%v result=%+v", succeeded, result)
			}
		})
	}
}
