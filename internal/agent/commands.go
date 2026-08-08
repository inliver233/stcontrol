package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

type encryptedCommandEnvelope struct {
	Version    int    `json:"version"`
	Ciphertext string `json:"ciphertext"`
}

type safeCommandResult struct {
	OK                 bool                                `json:"ok"`
	Code               string                              `json:"code,omitempty"`
	LocalUserID        string                              `json:"local_user_id,omitempty"`
	Users              []protocol.ScanExistingUser         `json:"users,omitempty"`
	Snapshot           *protocol.SnapshotTransferReceipt   `json:"snapshot,omitempty"`
	ConflictEvidence   *protocol.ConflictEvidenceReceipt   `json:"conflict_evidence,omitempty"`
	ConflictResolution *protocol.ConflictResolutionReceipt `json:"conflict_resolution,omitempty"`
	NodeAdmin          *protocol.NodeAdminVerification     `json:"node_admin,omitempty"`
	LocalUserProof     *protocol.VerifyLocalUserResponse   `json:"local_user_proof,omitempty"`
	Ciphertext         string                              `json:"ciphertext,omitempty"`
	RelayPublicKey     string                              `json:"relay_public_key,omitempty"`
}

// StartCommandLoop maintains the Agent-initiated control channel. It never
// opens an inbound controller callback path.
func (a *Agent) StartCommandLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		if !a.commandChannelAllowed() {
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		if err := a.pollAndRunCommand(ctx); err != nil {
			log.Printf("命令通道暂不可用: %v", err)
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}

func (a *Agent) pollAndRunCommand(ctx context.Context) error {
	if !a.commandChannelAllowed() {
		return fmt.Errorf("controller commands paused by node control mode")
	}
	workerID, highestGeneration := a.commandIdentity()
	status, headers, data, err := a.doControllerRequest(ctx, http.MethodPost, "/api/agent/commands/lease", protocol.LeaseCommandRequest{
		WorkerID: workerID, HighestGeneration: highestGeneration,
	})
	if err != nil {
		return err
	}
	if rawGeneration := headers.Get("X-Controller-Generation"); rawGeneration != "" {
		generation, parseErr := strconv.ParseInt(rawGeneration, 10, 64)
		if parseErr != nil || !a.acceptGeneration(generation) {
			return fmt.Errorf("controller generation rollback rejected")
		}
	}
	if status == http.StatusNoContent {
		return nil
	}
	if status != http.StatusOK {
		return fmt.Errorf("command lease returned status %d", status)
	}
	var command protocol.AgentCommand
	if err := json.Unmarshal(data, &command); err != nil {
		return fmt.Errorf("decode command: %w", err)
	}
	if !a.acceptGeneration(command.ControllerGeneration) {
		return fmt.Errorf("stale command generation rejected")
	}
	if !a.commandAllowed(command.CommandType) {
		return fmt.Errorf("command %q is not allowed while node is draining", command.CommandType)
	}

	if err := a.callController(ctx, http.MethodPost, "/api/agent/commands/"+command.ID+"/ack", protocol.AckCommandRequest{
		WorkerID: workerID, ControllerGeneration: command.ControllerGeneration,
	}, nil); err != nil {
		return err
	}

	select {
	case a.commandSlots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	go func() {
		defer func() { <-a.commandSlots }()
		if err := a.executeAndReportCommand(ctx, workerID, command); err != nil && ctx.Err() == nil {
			log.Printf("命令结果暂未确认: %v", err)
		}
	}()
	return nil
}

func (a *Agent) executeAndReportCommand(ctx context.Context, workerID string, command protocol.AgentCommand) error {
	cacheResult := shouldCacheCommandResult(command.CommandType)
	result, ok := cachedCommandResult{}, false
	if cacheResult {
		result, ok = a.cachedResult(command.ID)
	}
	if !ok {
		succeeded, summary := a.executeCommand(ctx, command)
		result = cachedCommandResult{
			Succeeded: succeeded, Result: summary,
			ControllerGeneration: command.ControllerGeneration, CompletedAt: time.Now().UTC(),
		}
		if cacheResult {
			if err := a.rememberResult(command.ID, result); err != nil {
				return fmt.Errorf("persist command result: %w", err)
			}
		}
	}
	if err := a.appendLocalAudit(localAuditEvent{
		Event: "command_completed", CommandID: command.ID, OperationID: command.OperationID,
		CommandType: command.CommandType, ControllerGeneration: result.ControllerGeneration,
		Succeeded: &result.Succeeded, Cached: ok,
	}); err != nil {
		return fmt.Errorf("persist local command audit: %w", err)
	}
	payload := protocol.FinishCommandRequest{
		WorkerID: workerID, ControllerGeneration: result.ControllerGeneration,
		Succeeded: result.Succeeded, Result: result.Result,
	}
	backoff := time.Second
	for attempt := 0; attempt < 8; attempt++ {
		if err := a.callController(ctx, http.MethodPost, "/api/agent/commands/"+command.ID+"/result", payload, nil); err == nil {
			return nil
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
	return fmt.Errorf("controller did not confirm command result")
}

func shouldCacheCommandResult(commandType string) bool {
	return commandType != "read_conflict_evidence_page"
}

func (a *Agent) executeCommand(ctx context.Context, command protocol.AgentCommand) (bool, json.RawMessage) {
	plaintext, err := a.decryptCommand(command)
	if err != nil {
		return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
	}
	switch command.CommandType {
	case "scan_existing":
		var payload struct{}
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		users, err := a.ScanExistingUsers(ctx)
		if err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "scan_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, Users: users})
	case "abort_backup":
		var payload struct {
			JobID int64 `json:"job_id"`
		}
		if err := json.Unmarshal(plaintext, &payload); err != nil || payload.JobID <= 0 {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		a.AbortBackup(payload.JobID)
		return true, marshalSafeResult(safeCommandResult{OK: true})
	case "provision_user":
		var payload protocol.ProvisionUserRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		payload.OperationID = command.OperationID
		if !validProvisionRequest(payload) {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		provisioned, err := a.provisionUser(ctx, &payload)
		if err != nil {
			code := "provision_unavailable"
			if provisioned != nil && definitiveProvisionError(provisioned.Error) {
				code = "provision_rejected"
			}
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: code})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, LocalUserID: provisioned.LocalUserID})
	case "restore_user_account":
		var payload protocol.RestoreUserAccountRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		payload.OperationID = command.OperationID
		if a.Cfg.Role != "compute" || !validRestoreUserAccountRequest(payload) {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		restored, err := a.restoreUserAccount(ctx, &payload)
		if err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "account_restore_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, LocalUserID: restored.LocalUserID})
	case "set_password":
		var payload protocol.SetPasswordRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil || payload.Handle == "" ||
			payload.PasswordHash == "" || payload.PasswordSalt == "" || payload.Version <= 0 {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		payload.OperationID = command.OperationID
		if err := a.setPassword(ctx, &payload); err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "password_update_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true})
	case "verify_node_admin":
		var payload protocol.VerifyNodeAdminRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil || a.Cfg.Role != "compute" ||
			!validHandle(payload.Handle) || len(payload.Password) == 0 || len(payload.Password) > 256 {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		payload.OperationID = command.OperationID
		verification, err := a.verifyNodeAdmin(ctx, payload)
		if err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "node_admin_verify_unavailable"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, NodeAdmin: &verification})
	case "verify_local_user":
		var payload protocol.VerifyLocalUserRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil || a.Cfg.Role != "compute" ||
			!validHandle(payload.Handle) || len(payload.Password) == 0 || len(payload.Password) > 256 {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		payload.OperationID = command.OperationID
		verification, err := a.verifyLocalUser(ctx, payload)
		if err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "local_user_verify_unavailable"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, LocalUserProof: &verification})
	case "complete_independent_sync":
		var payload protocol.CompleteIndependentSyncRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil || a.Cfg.Role != "compute" ||
			!validUUID(payload.OperationID) || !validHandle(payload.Handle) || !validUUID(payload.Marker) {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		payload.OperationID = command.OperationID
		if err := a.completeIndependentSync(ctx, payload); err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "independent_sync_completion_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true})
	case "check_node_admin":
		var payload protocol.CheckNodeAdminRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil || a.Cfg.Role != "compute" ||
			!validHandle(payload.Handle) {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		verification, err := a.checkNodeAdmin(ctx, payload)
		if err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "node_admin_check_unavailable"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, NodeAdmin: &verification})
	case "prepare_snapshot_receive":
		var payload protocol.PrepareSnapshotReceiveRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil || !validUUID(payload.WorkflowID) ||
			!validUUID(payload.SnapshotID) || payload.GlobalUserID <= 0 || !validHandle(payload.Handle) || payload.SourceNodeID <= 0 ||
			payload.ActivityEpoch <= 0 || (payload.DestinationKind != "archive" && payload.DestinationKind != "hot_standby" && payload.DestinationKind != "restore" && payload.DestinationKind != "conflict_input") ||
			(payload.DestinationKind == "restore" && a.Cfg.Role != "compute") ||
			(payload.DestinationKind == "conflict_input" && a.Cfg.Role != "compute") ||
			!validCapabilityHash(payload.CapabilityHash) || !payload.ExpiresAt.After(time.Now().UTC()) ||
			payload.ExpiresAt.After(time.Now().UTC().Add(9*time.Hour)) {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		transfer := pendingTransfer{
			WorkflowID: payload.WorkflowID, SnapshotID: payload.SnapshotID, GlobalUserID: payload.GlobalUserID,
			TargetNodeID: a.Cfg.NodeID, Handle: payload.Handle,
			DestinationKind: payload.DestinationKind, SourceNodeID: payload.SourceNodeID,
			ActivityEpoch: payload.ActivityEpoch, CapabilityHash: payload.CapabilityHash, ExpiresAt: payload.ExpiresAt,
		}
		if payload.RelayTaskID != "" {
			publicKey, err := a.prepareRelayTransfer(transfer, payload.RelayTaskID)
			if err != nil {
				return false, marshalSafeResult(safeCommandResult{OK: false, Code: "prepare_transfer_failed"})
			}
			return true, marshalSafeResult(safeCommandResult{OK: true, RelayPublicKey: publicKey})
		}
		if err := a.prepareTransfer(transfer); err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "prepare_transfer_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true})
	case "start_snapshot":
		var payload protocol.StartSnapshotRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		receipt, err := a.RunSnapshot(ctx, payload)
		if err != nil {
			if isSnapshotDirectUnreachable(err) {
				return false, marshalSafeResult(safeCommandResult{OK: false, Code: "snapshot_direct_unreachable"})
			}
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "snapshot_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, Snapshot: &receipt})
	case "start_relay_receive":
		var payload protocol.StartRelayReceiveRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		receipt, err := a.RunRelayReceive(ctx, payload)
		if err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "relay_receive_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, Snapshot: &receipt})
	case "start_restore_transfer":
		var payload protocol.StartRestoreTransferRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		receipt, err := a.RunRestoreTransfer(ctx, payload)
		if err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "restore_transfer_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, Snapshot: &receipt})
	case "get_snapshot_receipt":
		var payload struct {
			WorkflowID string `json:"workflow_id"`
			SnapshotID string `json:"snapshot_id"`
		}
		if err := json.Unmarshal(plaintext, &payload); err != nil || !validUUID(payload.WorkflowID) || !validUUID(payload.SnapshotID) {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		receipt, ok := a.snapshotReceipt(payload.WorkflowID, payload.SnapshotID)
		if !ok {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "snapshot_receipt_unavailable"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, Snapshot: receipt})
	case "capture_conflict_evidence":
		var payload protocol.CaptureConflictEvidenceRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil || !validConflictEvidenceRequest(payload) {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		receipt, err := a.captureConflictEvidence(ctx, payload)
		if err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "conflict_evidence_capture_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, ConflictEvidence: &receipt})
	case "read_conflict_evidence_page":
		var payload protocol.ReadConflictEvidencePageRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil || !validConflictEvidencePageRequest(payload) {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		ciphertext, err := a.readConflictEvidencePage(payload)
		if err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "conflict_evidence_page_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, Ciphertext: ciphertext})
	case "start_conflict_evidence_transfer":
		var payload protocol.StartConflictEvidenceTransferRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		receipt, err := a.RunConflictEvidenceTransfer(ctx, payload)
		if err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "conflict_evidence_transfer_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, Snapshot: &receipt})
	case "prepare_conflict_resolution":
		var payload protocol.PrepareConflictResolutionRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil || a.Cfg.Role != "compute" {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		if err := a.prepareConflictResolution(ctx, payload); err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "conflict_resolution_prepare_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true})
	case "apply_conflict_resolution_decisions":
		var payload protocol.ApplyConflictResolutionDecisionsRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil || a.Cfg.Role != "compute" {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		if err := a.applyConflictResolutionDecisions(payload); err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "conflict_resolution_decisions_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true})
	case "publish_conflict_resolution":
		var payload protocol.PublishConflictResolutionRequest
		if err := json.Unmarshal(plaintext, &payload); err != nil || a.Cfg.Role != "compute" {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "invalid_command_payload"})
		}
		receipt, err := a.publishConflictResolution(ctx, payload.OperationID)
		if err != nil {
			return false, marshalSafeResult(safeCommandResult{OK: false, Code: "conflict_resolution_publish_failed"})
		}
		return true, marshalSafeResult(safeCommandResult{OK: true, ConflictResolution: &receipt})
	default:
		return false, marshalSafeResult(safeCommandResult{OK: false, Code: "unsupported_command"})
	}
}

func validConflictEvidenceRequest(req protocol.CaptureConflictEvidenceRequest) bool {
	if !validUUID(req.ConflictID) || !validUUID(req.EvidenceID) || req.GlobalUserID <= 0 ||
		!validHandle(req.Handle) {
		return false
	}
	switch req.SourceKind {
	case "archive":
		return validUUID(req.SourceSnapshotID) && validCapabilityHash(req.SourceManifestSHA256)
	case "active", "hot_standby":
		return req.SourceSnapshotID == "" || validUUID(req.SourceSnapshotID)
	default:
		return false
	}
}

func validConflictEvidencePageRequest(req protocol.ReadConflictEvidencePageRequest) bool {
	if !validUUID(req.ConflictID) || !validUUID(req.EvidenceID) || req.Cursor < 0 ||
		req.MaxBytes < 4<<10 || req.MaxBytes > 512<<10 {
		return false
	}
	key, err := base64.StdEncoding.DecodeString(req.ResponseKey)
	return err == nil && len(key) == 32
}

func definitiveProvisionError(code string) bool {
	switch code {
	case "invitation_invalid", "handle_conflict", "policy_changed", "registration_closed":
		return true
	default:
		return false
	}
}

func validCapabilityHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validProvisionRequest(req protocol.ProvisionUserRequest) bool {
	if !validUUID(req.OperationID) || !validUUID(req.RegistrationID) || req.PolicyVersion <= 0 ||
		req.Handle == "" || req.Name == "" {
		return false
	}
	passwordMode := req.PasswordHash != "" && req.PasswordSalt != "" && req.OAuthProvider == "" && req.OAuthSubject == ""
	oauthMode := req.PasswordHash == "" && req.PasswordSalt == "" &&
		(req.OAuthProvider == "discord" || req.OAuthProvider == "linuxdo") && req.OAuthSubject != ""
	return passwordMode || oauthMode
}

func validRestoreUserAccountRequest(req protocol.RestoreUserAccountRequest) bool {
	if !validUUID(req.OperationID) || !validUUID(req.WorkflowID) || req.GlobalUserID <= 0 ||
		!validHandle(req.Handle) || req.Name == "" || req.AccountVersion <= 0 {
		return false
	}
	passwordMode := req.PasswordHash != "" && req.PasswordSalt != "" &&
		req.OAuthProvider == "" && req.OAuthSubject == ""
	oauthMode := req.PasswordHash == "" && req.PasswordSalt == "" &&
		(req.OAuthProvider == "discord" || req.OAuthProvider == "linuxdo") && req.OAuthSubject != ""
	return passwordMode || oauthMode
}

func (a *Agent) decryptCommand(command protocol.AgentCommand) ([]byte, error) {
	var envelope encryptedCommandEnvelope
	if err := json.Unmarshal(command.EncryptedPayload, &envelope); err != nil ||
		(envelope.Version != 1 && envelope.Version != 2) || envelope.Ciphertext == "" {
		return nil, fmt.Errorf("invalid envelope")
	}
	psk, _ := a.controllerCredential()
	plaintext, err := controlcrypto.Decrypt(controlcrypto.DeriveAgentCommandKey(psk), envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	want, err := hex.DecodeString(command.PayloadSHA256)
	if err != nil || len(want) != sha256.Size {
		return nil, fmt.Errorf("invalid payload digest")
	}
	var got []byte
	if envelope.Version == 1 {
		digest := sha256.Sum256(plaintext)
		got = digest[:]
	} else {
		authenticator := hmac.New(sha256.New, controlcrypto.DeriveAgentCommandAuthKey(psk))
		_, _ = authenticator.Write(plaintext)
		got = authenticator.Sum(nil)
	}
	if !hmac.Equal(got, want) {
		return nil, fmt.Errorf("payload digest mismatch")
	}
	return plaintext, nil
}

func marshalSafeResult(result safeCommandResult) json.RawMessage {
	data, err := json.Marshal(result)
	if err != nil {
		return json.RawMessage(`{"ok":false,"code":"result_encoding_failed"}`)
	}
	return data
}
