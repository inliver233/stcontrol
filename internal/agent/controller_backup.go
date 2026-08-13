package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"stcontrol/internal/protocol"
)

// pendingControllerBackup is the one-use, capability-scoped intent armed by a
// receive_controller_backup command. The direct stream that follows is
// authenticated against this pending record (never ad-hoc plaintext HTTP).
type pendingControllerBackup struct {
	OperationID     string    `json:"operation_id"`
	BackupKind      string    `json:"backup_kind"`
	CapabilityHash  string    `json:"capability_hash"`
	ExpiresAt       time.Time `json:"expires_at"`
	ExpectedSHA256  string    `json:"expected_sha256,omitempty"`
	State           string    `json:"state"`
	UpdatedAt       time.Time `json:"updated_at"`
}

const controllerBackupDirName = "controller-backups"

func validControllerBackupState(state string) bool {
	return state == "prepared" || state == "consumed" || state == "failed" || state == "published"
}

func validatePendingControllerBackup(b pendingControllerBackup, kind string) error {
	if !validUUID(b.OperationID) || (kind != "" && b.BackupKind != kind) ||
		!validCapabilityHash(b.CapabilityHash) || b.ExpiresAt.IsZero() || b.UpdatedAt.IsZero() ||
		!validControllerBackupState(b.State) ||
		(b.ExpectedSHA256 != "" && !validCapabilityHash(b.ExpectedSHA256)) ||
		(b.State == "published" && b.ExpectedSHA256 == "") {
		return fmt.Errorf("invalid persisted controller backup intent")
	}
	if b.ExpectedSHA256 != "" && b.State != "published" && b.State != "consumed" {
		return fmt.Errorf("invalid controller backup intent state")
	}
	return nil
}

// prepareControllerBackup arms this node to receive one immutable controller
// disaster backup archive for the given operation. Idempotent for an exact
// capability retry within the same expiry window.
func (a *Agent) prepareControllerBackup(r protocol.PrepareControllerBackupRequest) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	now := time.Now().UTC()
	if existing, ok := a.state.ControllerBackups[r.OperationID]; ok {
		sameCapability := existing.ExpiresAt.Equal(r.ExpiresAt) &&
			existing.CapabilityHash == r.CapabilityHash &&
			existing.BackupKind == r.BackupKind && existing.ExpectedSHA256 == r.ExpectedSHA256
		if sameCapability && (existing.State == "prepared" || existing.State == "published") {
			return nil
		}
		// A later retry attempts a fresh capability; allow replacing any intent
		// that is not currently armed with a live unexpired capability, so an
		// in-flight run (or a post-receive DB write failure) is never permanently
		// wedged. The target stores each archive under the same immutable name,
		// so a newer successful publish simply supersedes the older one.
		if existing.State == "prepared" && existing.ExpiresAt.After(now) {
			return fmt.Errorf("controller backup intent already exists")
		}
	}
	b := pendingControllerBackup{
		OperationID: r.OperationID, BackupKind: r.BackupKind,
		CapabilityHash: r.CapabilityHash, ExpiresAt: r.ExpiresAt,
		ExpectedSHA256: r.ExpectedSHA256, State: "prepared", UpdatedAt: now,
	}
	a.state.ControllerBackups[r.OperationID] = b
	return a.saveRuntimeStateLocked()
}

// consumeControllerBackup validates the single-use bearer token against the
// pending intent and marks it consumed, mirroring consumeTransfer. Returns the
// armed intent so the receive path can verify sizes/hash before publishing.
func (a *Agent) consumeControllerBackup(operationID, token string, now time.Time) (pendingControllerBackup, error) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	b, ok := a.state.ControllerBackups[operationID]
	if !ok || b.State != "prepared" || !b.ExpiresAt.After(now) {
		return pendingControllerBackup{}, fmt.Errorf("controller backup capability unavailable")
	}
	want, err := hex.DecodeString(b.CapabilityHash)
	if err != nil || len(want) != sha256.Size {
		return pendingControllerBackup{}, fmt.Errorf("invalid controller backup capability state")
	}
	got := sha256.Sum256([]byte(token))
	if !hmac.Equal(want, got[:]) {
		return pendingControllerBackup{}, fmt.Errorf("controller backup capability rejected")
	}
	b.State = "consumed"
	b.UpdatedAt = now
	a.state.ControllerBackups[operationID] = b
	if err := a.saveRuntimeStateLocked(); err != nil {
		return pendingControllerBackup{}, err
	}
	return b, nil
}

func (a *Agent) finishControllerBackup(operationID, state string) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	b, ok := a.state.ControllerBackups[operationID]
	if !ok {
		return fmt.Errorf("controller backup intent not found")
	}
	b.State = state
	b.UpdatedAt = time.Now().UTC()
	a.state.ControllerBackups[operationID] = b
	return a.saveRuntimeStateLocked()
}
// ReceiveControllerBackup durably stores and verifies one controller disaster
// backup archive under BackupDir/controller-backups/<operation_id>/. It returns
// a receipt only after the sha256 and size are verified against the request,
// mirroring ReceiveSnapshot: the capability is consumed once and never reuses
// an ad-hoc HTTP path.
func (a *Agent) ReceiveControllerBackup(
	ctx context.Context, operationID, token, expectedSHA256 string, body io.Reader,
) (protocol.ControllerBackupReceipt, error) {
	if !validUUID(operationID) || !validCapabilityHash(expectedSHA256) ||
		a.Cfg == nil || a.Cfg.BackupDir == "" {
		return protocol.ControllerBackupReceipt{}, fmt.Errorf("invalid controller backup receive request")
	}
	now := time.Now().UTC()
	intent, err := a.consumeControllerBackup(operationID, token, now)
	if err != nil {
		return protocol.ControllerBackupReceipt{}, err
	}
	root := filepath.Join(a.Cfg.BackupDir, controllerBackupDirName, operationID)
	if err := os.MkdirAll(root, 0o700); err != nil {
		_ = a.finishControllerBackup(operationID, "failed")
		return protocol.ControllerBackupReceipt{}, fmt.Errorf("create controller backup target: %w", err)
	}
	archivePath := filepath.Join(root, "controller_backup.tar.zst")
	archive, err := os.OpenFile(archivePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		_ = a.finishControllerBackup(operationID, "failed")
		return protocol.ControllerBackupReceipt{}, err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(archive, io.TeeReader(io.LimitReader(body, maxSnapshotBytes+1), hash))
	syncErr := archive.Sync()
	closeErr := archive.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written <= 0 || written > maxSnapshotBytes {
		_ = a.finishControllerBackup(operationID, "failed")
		return protocol.ControllerBackupReceipt{}, fmt.Errorf("controller backup upload failed")
	}
	archiveDigest := hex.EncodeToString(hash.Sum(nil))
	wantDeparsed, decErr := hex.DecodeString(expectedSHA256)
	gotParsed, _ := hex.DecodeString(archiveDigest)
	if decErr != nil || len(wantDeparsed) != sha256.Size || !hmac.Equal(wantDeparsed, gotParsed) {
		_ = a.finishControllerBackup(operationID, "failed")
		return protocol.ControllerBackupReceipt{}, fmt.Errorf("controller backup digest mismatch")
	}
	if intent.ExpectedSHA256 != "" && intent.ExpectedSHA256 != archiveDigest {
		_ = a.finishControllerBackup(operationID, "failed")
		return protocol.ControllerBackupReceipt{}, fmt.Errorf("controller backup expected digest mismatch")
	}
	if err := a.finishControllerBackup(operationID, "published"); err != nil {
		return protocol.ControllerBackupReceipt{}, err
	}
	receipt := protocol.ControllerBackupReceipt{
		OK: true, OperationID: operationID, ArchiveSHA256: archiveDigest,
		TotalBytes: written,
		PublishedPath: filepath.ToSlash(filepath.Join(controllerBackupDirName, operationID, "controller_backup.tar.zst")),
	}
	return receipt, nil
}

