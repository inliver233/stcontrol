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

	"stcontrol/internal/protocol"
)

type cachedCommandResult struct {
	Succeeded            bool            `json:"succeeded"`
	Result               json.RawMessage `json:"result"`
	ControllerGeneration int64           `json:"controller_generation"`
	CompletedAt          time.Time       `json:"completed_at"`
}

type agentRuntimeState struct {
	WorkerID          string                         `json:"worker_id"`
	HighestGeneration int64                          `json:"highest_generation"`
	Completed         map[string]cachedCommandResult `json:"completed"`
	Transfers         map[string]pendingTransfer     `json:"transfers"`
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
	return a.saveRuntimeStateLocked()
}

func (a *Agent) prepareTransfer(transfer pendingTransfer) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if existing, ok := a.state.Transfers[transfer.SnapshotID]; ok {
		sameCapability := existing.WorkflowID == transfer.WorkflowID && existing.CapabilityHash == transfer.CapabilityHash
		if sameCapability && existing.State == "prepared" {
			return nil
		}
		retryableExpiredRestore := existing.WorkflowID == transfer.WorkflowID &&
			existing.DestinationKind == "restore" && transfer.DestinationKind == "restore" &&
			existing.State == "consumed" && !existing.ExpiresAt.After(time.Now().UTC())
		replaceablePreparedRestore := existing.WorkflowID == transfer.WorkflowID &&
			existing.DestinationKind == "restore" && transfer.DestinationKind == "restore" &&
			existing.State == "prepared" && !sameCapability
		if sameCapability || (existing.State != "failed" &&
			!(existing.State == "prepared" && !existing.ExpiresAt.After(time.Now().UTC())) &&
			!retryableExpiredRestore && !replaceablePreparedRestore) {
			return fmt.Errorf("snapshot transfer identity already exists")
		}
	}
	transfer.State = "prepared"
	transfer.UpdatedAt = time.Now().UTC()
	a.state.Transfers[transfer.SnapshotID] = transfer
	return a.saveRuntimeStateLocked()
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
