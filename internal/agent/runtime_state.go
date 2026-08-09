package agent

import (
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

type cachedCommandResult struct {
	Succeeded            bool            `json:"succeeded"`
	Result               json.RawMessage `json:"result"`
	ControllerGeneration int64           `json:"controller_generation"`
	CompletedAt          time.Time       `json:"completed_at"`
}

type agentRuntimeState struct {
	WorkerID                string                                `json:"worker_id"`
	HighestGeneration       int64                                 `json:"highest_generation"`
	Completed               map[string]cachedCommandResult        `json:"completed"`
	Transfers               map[string]pendingTransfer            `json:"transfers"`
	ControlMode             agentControlModeState                 `json:"control_mode"`
	Credential              agentCredentialState                  `json:"controller_credential"`
	PendingIndependentUsers []protocol.IndependentSyncUser        `json:"pending_independent_users,omitempty"`
	ActivityOwnership       map[string]activityOwnershipClaim     `json:"activity_ownership,omitempty"`
	OwnershipTakeovers      map[string]ownershipTakeoverOperation `json:"ownership_takeovers,omitempty"`
	ActivityLeases          agentActivityLeaseState               `json:"activity_leases"`
}

type agentActivityLeaseState struct {
	ControllerGeneration int64                                `json:"controller_generation,omitempty"`
	ConfirmedAt          int64                                `json:"confirmed_at,omitempty"`
	Leases               []protocol.ActivityLeaseConfirmation `json:"leases,omitempty"`
	AdapterConfirmedAt   int64                                `json:"adapter_confirmed_at,omitempty"`
}

type agentCredentialState struct {
	CurrentPSK        string    `json:"current_psk"`
	CurrentVersion    int64     `json:"current_version"`
	CurrentGeneration int64     `json:"current_generation"`
	PendingPSK        string    `json:"pending_psk,omitempty"`
	PendingVersion    int64     `json:"pending_version,omitempty"`
	PendingGeneration int64     `json:"pending_generation,omitempty"`
	PendingExpiresAt  time.Time `json:"pending_expires_at,omitempty"`
}

type pendingTransfer struct {
	WorkflowID      string                            `json:"workflow_id"`
	SnapshotID      string                            `json:"snapshot_id"`
	GlobalUserID    int64                             `json:"global_user_id"`
	TargetNodeID    int64                             `json:"target_node_id"`
	Handle          string                            `json:"handle"`
	DestinationKind string                            `json:"destination_kind"`
	SourceNodeID    int64                             `json:"source_node_id"`
	ActivityEpoch   int64                             `json:"activity_epoch"`
	CapabilityHash  string                            `json:"capability_hash"`
	ExpiresAt       time.Time                         `json:"expires_at"`
	RelayTaskID     string                            `json:"relay_task_id,omitempty"`
	RelayPrivateKey string                            `json:"relay_private_key,omitempty"`
	RelayPublicKey  string                            `json:"relay_public_key,omitempty"`
	State           string                            `json:"state"`
	UpdatedAt       time.Time                         `json:"updated_at"`
	Receipt         *protocol.SnapshotTransferReceipt `json:"receipt,omitempty"`
}

func (a *Agent) runtimeStatePath() string {
	directory := a.Cfg.DataDir
	if directory == "" {
		directory = "./agent-data"
	}
	return filepath.Join(directory, "runtime-state.json")
}

func (a *Agent) loadRuntimeState() error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	path := a.runtimeStatePath()
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &a.state); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if a.state.Completed == nil {
		a.state.Completed = make(map[string]cachedCommandResult)
	}
	if a.state.Transfers == nil {
		a.state.Transfers = make(map[string]pendingTransfer)
	}
	if a.state.ActivityOwnership == nil {
		a.state.ActivityOwnership = make(map[string]activityOwnershipClaim)
	}
	if a.state.OwnershipTakeovers == nil {
		a.state.OwnershipTakeovers = make(map[string]ownershipTakeoverOperation)
	}
	for handle, claim := range a.state.ActivityOwnership {
		if handle != claim.Handle || validateActivityOwnershipClaim(claim) != nil {
			return fmt.Errorf("invalid persisted activity ownership claim")
		}
	}
	for operationID, operation := range a.state.OwnershipTakeovers {
		if operationID != operation.OperationID || !validUUID(operationID) ||
			validateActivityOwnershipClaim(operation.Claim) != nil ||
			operation.Claim.Kind != "user_confirmed_takeover" ||
			operation.Claim.OperationID != operationID || operation.UpdatedAt <= 0 ||
			(operation.Audited && !operation.Succeeded) ||
			operation.ParentClaimID == "" || operation.ParentClaimID != operation.Claim.ParentClaimID {
			return fmt.Errorf("invalid persisted activity ownership takeover")
		}
	}
	if err := validateAgentActivityLeaseState(a.state.ActivityLeases); err != nil {
		return fmt.Errorf("invalid persisted activity lease confirmations: %w", err)
	}
	if a.state.WorkerID == "" {
		workerID, err := newWorkerID()
		if err != nil {
			return err
		}
		a.state.WorkerID = workerID
	}
	if a.Cfg.ControllerGeneration > a.state.HighestGeneration {
		a.state.HighestGeneration = a.Cfg.ControllerGeneration
	}
	if a.state.Credential.CurrentPSK == "" && a.Cfg.AgentPSK != "" {
		a.state.Credential.CurrentPSK = a.Cfg.AgentPSK
		a.state.Credential.CurrentVersion = a.Cfg.CredentialVersion
		if a.state.Credential.CurrentVersion <= 0 {
			a.state.Credential.CurrentVersion = 1
		}
		a.state.Credential.CurrentGeneration = a.Cfg.ControllerGeneration
		if a.state.Credential.CurrentGeneration <= 0 {
			a.state.Credential.CurrentGeneration = 1
		}
	}
	if a.state.Credential.CurrentPSK != "" && a.state.Credential.CurrentVersion <= 0 {
		return fmt.Errorf("invalid persisted controller credential")
	}
	if a.state.Credential.PendingPSK != "" && (a.state.Credential.PendingVersion <= a.state.Credential.CurrentVersion ||
		a.state.Credential.PendingGeneration <= 0 || a.state.Credential.PendingExpiresAt.IsZero()) {
		return fmt.Errorf("invalid persisted pending controller credential")
	}
	if a.state.ControlMode.Mode == "" {
		a.state.ControlMode.Mode = protocol.NodeModeManaged
		a.state.ControlMode.AdapterMode = protocol.NodeModeManaged
		a.state.ControlMode.ModeGeneration = 1
		a.state.ControlMode.ChangedAt = time.Now().UTC()
	}
	// A runtime state written before peer-witness evidence existed must never
	// keep opening new native logins after upgrade. Move it to the restrictive
	// draining boundary; existing sessions and pending sync markers remain
	// durable and can be reconciled when the Controller returns.
	if a.state.ControlMode.Mode == protocol.NodeModeIndependent &&
		a.state.ControlMode.ConsecutivePeerWitnessFails <= 0 {
		a.state.ControlMode.Mode = protocol.NodeModeIndependentDraining
		a.state.ControlMode.ModeGeneration++
		a.state.ControlMode.ReasonCode = "legacy_independent_without_peer_witness"
		a.state.ControlMode.ChangedAt = time.Now().UTC()
		a.state.ControlMode.AdapterMode = ""
	}
	if a.state.ControlMode.ModeGeneration <= 0 || !validNodeControlMode(a.state.ControlMode.Mode) ||
		(a.state.ControlMode.AdapterMode != "" && !validNodeControlMode(a.state.ControlMode.AdapterMode)) {
		return fmt.Errorf("invalid persisted node control mode")
	}
	return a.saveRuntimeStateLocked()
}

func (a *Agent) controllerCredential() (string, int64) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.state.Credential.CurrentPSK == "" && a.Cfg != nil {
		version := a.Cfg.CredentialVersion
		if version <= 0 {
			version = 1
		}
		return a.Cfg.AgentPSK, version
	}
	return a.state.Credential.CurrentPSK, a.state.Credential.CurrentVersion
}

func (a *Agent) pendingControllerCredential() agentCredentialState {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	return a.state.Credential
}

func (a *Agent) persistInitialControllerCredential(psk string, version, generation int64) error {
	if psk == "" || version <= 0 || generation <= 0 {
		return fmt.Errorf("invalid initial controller credential")
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	a.state.Credential = agentCredentialState{
		CurrentPSK: psk, CurrentVersion: version, CurrentGeneration: generation,
	}
	if generation > a.state.HighestGeneration {
		a.state.HighestGeneration = generation
	}
	return a.saveRuntimeStateLocked()
}

func (a *Agent) persistPendingControllerCredential(psk string, version, generation int64, expiresAt time.Time) error {
	if psk == "" || version <= 0 || generation <= 0 || !expiresAt.After(time.Now().UTC()) {
		return fmt.Errorf("invalid pending controller credential")
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if version <= a.state.Credential.CurrentVersion {
		return fmt.Errorf("controller credential version rollback")
	}
	if a.state.Credential.PendingPSK != "" &&
		(a.state.Credential.PendingVersion != version || a.state.Credential.PendingPSK != psk) {
		return fmt.Errorf("conflicting pending controller credential")
	}
	a.state.Credential.PendingPSK = psk
	a.state.Credential.PendingVersion = version
	a.state.Credential.PendingGeneration = generation
	a.state.Credential.PendingExpiresAt = expiresAt
	return a.saveRuntimeStateLocked()
}

func (a *Agent) activatePendingControllerCredential(version, generation int64) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	credential := &a.state.Credential
	if credential.PendingPSK == "" || credential.PendingVersion != version ||
		credential.PendingGeneration != generation {
		if credential.CurrentVersion == version && credential.CurrentGeneration == generation {
			return nil
		}
		return fmt.Errorf("pending controller credential mismatch")
	}
	if a.Cfg != nil {
		a.Cfg.AgentPSK = credential.PendingPSK
		a.Cfg.CredentialVersion = credential.PendingVersion
		a.Cfg.ControllerGeneration = credential.PendingGeneration
		if a.Cfg.ConfigPath != "" {
			if err := config.Save(a.Cfg.ConfigPath, a.Cfg); err != nil {
				return fmt.Errorf("persist rotated controller credential: %w", err)
			}
		}
	}
	credential.CurrentPSK = credential.PendingPSK
	credential.CurrentVersion = credential.PendingVersion
	credential.CurrentGeneration = credential.PendingGeneration
	credential.PendingPSK = ""
	credential.PendingVersion = 0
	credential.PendingGeneration = 0
	credential.PendingExpiresAt = time.Time{}
	if generation > a.state.HighestGeneration {
		a.state.HighestGeneration = generation
	}
	return a.saveRuntimeStateLocked()
}

func (a *Agent) clearPendingControllerCredential(version int64) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.state.Credential.PendingVersion != version {
		return nil
	}
	a.state.Credential.PendingPSK = ""
	a.state.Credential.PendingVersion = 0
	a.state.Credential.PendingGeneration = 0
	a.state.Credential.PendingExpiresAt = time.Time{}
	return a.saveRuntimeStateLocked()
}

func (a *Agent) prepareTransfer(transfer pendingTransfer) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	return a.prepareTransferLocked(transfer)
}

func (a *Agent) prepareRelayTransfer(transfer pendingTransfer, taskID string) (string, error) {
	if !validUUID(taskID) {
		return "", fmt.Errorf("invalid relay task identity")
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if existing, ok := a.state.Transfers[transfer.SnapshotID]; ok &&
		existing.WorkflowID == transfer.WorkflowID && existing.CapabilityHash == transfer.CapabilityHash &&
		existing.State == "prepared" && existing.RelayTaskID == taskID &&
		existing.RelayPrivateKey != "" && existing.RelayPublicKey != "" {
		return existing.RelayPublicKey, nil
	}
	privateKey, publicKey, err := controlcrypto.GenerateRelayKeyPair()
	if err != nil {
		return "", err
	}
	transfer.RelayTaskID = taskID
	transfer.RelayPrivateKey = privateKey
	transfer.RelayPublicKey = publicKey
	if err := a.prepareTransferLocked(transfer); err != nil {
		return "", err
	}
	return publicKey, nil
}

func (a *Agent) prepareTransferLocked(transfer pendingTransfer) error {
	if existing, ok := a.state.Transfers[transfer.SnapshotID]; ok {
		sameCapability := existing.WorkflowID == transfer.WorkflowID && existing.CapabilityHash == transfer.CapabilityHash
		if sameCapability && existing.State == "prepared" {
			if sameTransferScope(existing, transfer) && existing.RelayTaskID == transfer.RelayTaskID &&
				existing.RelayPrivateKey == transfer.RelayPrivateKey && existing.RelayPublicKey == transfer.RelayPublicKey {
				return nil
			}
			if transfer.RelayTaskID == "" || !sameTransferScope(existing, transfer) {
				return fmt.Errorf("snapshot transfer identity already exists")
			}
		}
		replaceableExactRetry := sameTransferScope(existing, transfer) &&
			((existing.State == "failed" && !sameCapability) ||
				(existing.State == "prepared" && (!sameCapability || transfer.RelayTaskID != "")))
		retryableExpiredRestore := sameTransferScope(existing, transfer) &&
			existing.DestinationKind == "restore" && transfer.DestinationKind == "restore" &&
			existing.State == "consumed" && !existing.ExpiresAt.After(time.Now().UTC())
		replaceablePreparedRestore := sameTransferScope(existing, transfer) &&
			existing.DestinationKind == "restore" && transfer.DestinationKind == "restore" &&
			existing.State == "prepared" && !sameCapability
		replaceableExpiredPrepared := sameTransferScope(existing, transfer) && existing.State == "prepared" &&
			!existing.ExpiresAt.After(time.Now().UTC())
		if !replaceableExactRetry && !replaceableExpiredPrepared && !retryableExpiredRestore && !replaceablePreparedRestore {
			return fmt.Errorf("snapshot transfer identity already exists")
		}
	}
	transfer.State = "prepared"
	transfer.UpdatedAt = time.Now().UTC()
	a.state.Transfers[transfer.SnapshotID] = transfer
	return a.saveRuntimeStateLocked()
}

func sameTransferScope(left, right pendingTransfer) bool {
	return left.WorkflowID == right.WorkflowID && left.SnapshotID == right.SnapshotID &&
		left.GlobalUserID == right.GlobalUserID && left.TargetNodeID == right.TargetNodeID &&
		left.Handle == right.Handle && left.DestinationKind == right.DestinationKind &&
		left.SourceNodeID == right.SourceNodeID && left.ActivityEpoch == right.ActivityEpoch
}

func (a *Agent) relayTransfer(snapshotID, workflowID, taskID string) (pendingTransfer, error) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	transfer, ok := a.state.Transfers[snapshotID]
	if !ok || transfer.WorkflowID != workflowID || transfer.RelayTaskID != taskID ||
		transfer.RelayPrivateKey == "" || transfer.State != "prepared" {
		return pendingTransfer{}, fmt.Errorf("relay transfer state unavailable")
	}
	return transfer, nil
}

func (a *Agent) consumeTransfer(snapshotID, workflowID, token string, now time.Time) (pendingTransfer, error) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	transfer, ok := a.state.Transfers[snapshotID]
	if !ok || transfer.WorkflowID != workflowID || transfer.State != "prepared" || !transfer.ExpiresAt.After(now) {
		return pendingTransfer{}, fmt.Errorf("transfer capability unavailable")
	}
	want, err := hex.DecodeString(transfer.CapabilityHash)
	if err != nil || len(want) != sha256.Size {
		return pendingTransfer{}, fmt.Errorf("invalid transfer capability state")
	}
	got := sha256.Sum256([]byte(token))
	if !hmac.Equal(want, got[:]) {
		return pendingTransfer{}, fmt.Errorf("transfer capability rejected")
	}
	transfer.State = "consumed"
	transfer.UpdatedAt = now
	a.state.Transfers[snapshotID] = transfer
	if err := a.saveRuntimeStateLocked(); err != nil {
		return pendingTransfer{}, err
	}
	return transfer, nil
}

func (a *Agent) finishTransfer(snapshotID, state string) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	transfer, ok := a.state.Transfers[snapshotID]
	if !ok {
		return fmt.Errorf("transfer state not found")
	}
	transfer.State = state
	transfer.UpdatedAt = time.Now().UTC()
	a.state.Transfers[snapshotID] = transfer
	return a.saveRuntimeStateLocked()
}

func (a *Agent) publishTransfer(snapshotID string, receipt protocol.SnapshotTransferReceipt) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	transfer, ok := a.state.Transfers[snapshotID]
	if !ok || transfer.State != "consumed" {
		return fmt.Errorf("transfer state not consumable")
	}
	transfer.State = "published"
	transfer.Receipt = &receipt
	transfer.UpdatedAt = time.Now().UTC()
	a.state.Transfers[snapshotID] = transfer
	return a.saveRuntimeStateLocked()
}

func (a *Agent) snapshotReceipt(workflowID, snapshotID string) (*protocol.SnapshotTransferReceipt, bool) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	transfer, ok := a.state.Transfers[snapshotID]
	if !ok || transfer.WorkflowID != workflowID || transfer.State != "published" || transfer.Receipt == nil {
		return nil, false
	}
	receipt := *transfer.Receipt
	return &receipt, true
}

func (a *Agent) saveRuntimeStateLocked() error {
	path := a.runtimeStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(a.state, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".runtime-state-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func newWorkerID() (string, error) {
	data := make([]byte, 24)
	if _, err := cryptorand.Read(data); err != nil {
		return "", fmt.Errorf("generate worker identity: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func (a *Agent) commandIdentity() (string, int64) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	return a.state.WorkerID, a.state.HighestGeneration
}

func (a *Agent) acceptGeneration(generation int64) bool {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if generation < a.state.HighestGeneration {
		return false
	}
	if generation > a.state.HighestGeneration {
		previous := a.state.HighestGeneration
		a.state.HighestGeneration = generation
		if err := a.saveRuntimeStateLocked(); err != nil {
			a.state.HighestGeneration = previous
			return false
		}
	}
	return true
}

func (a *Agent) cachedResult(commandID string) (cachedCommandResult, bool) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	result, ok := a.state.Completed[commandID]
	return result, ok
}

func (a *Agent) rememberResult(commandID string, result cachedCommandResult) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	a.state.Completed[commandID] = result
	if len(a.state.Completed) > 1000 {
		type entry struct {
			id string
			at time.Time
		}
		entries := make([]entry, 0, len(a.state.Completed))
		for id, cached := range a.state.Completed {
			entries = append(entries, entry{id: id, at: cached.CompletedAt})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].at.Before(entries[j].at) })
		for _, old := range entries[:len(entries)-1000] {
			delete(a.state.Completed, old.id)
		}
	}
	return a.saveRuntimeStateLocked()
}
