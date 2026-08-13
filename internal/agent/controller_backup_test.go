package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func newControllerBackupTestAgent(t *testing.T, role string) *Agent {
	t.Helper()
	root := t.TempDir()
	cfg := &config.AgentConfig{
		Role: role, NodeID: 9, Listen: "127.0.0.1:0",
		DataDir: filepath.Join(root, "state"), BackupDir: filepath.Join(root, "backups"),
		AgentPSK: "controller-backup-test-psk", CredentialVersion: 1, ControllerGeneration: 1,
	}
	a, err := New(cfg)
	if err != nil { t.Fatalf("New: %v", err) }
	return a
}

func controllerBackupPrepareReq(opID string, expires time.Time) protocol.PrepareControllerBackupRequest {
	capability := strings.Repeat("a", 64)
	return protocol.PrepareControllerBackupRequest{
		OperationID: opID, BackupKind: "full", ControllerGeneration: 1,
		CapabilityHash: capability, ExpiresAt: expires, ExpectedSHA256: strings.Repeat("b", 64),
	}
}

func TestPrepareControllerBackupArmsAndIdempotentlyReplays(t *testing.T) {
	a := newControllerBackupTestAgent(t, "storage")
	opID := "11111111-1111-4111-8111-111111111111"
	nonce := strings.Repeat("c", 16)
	exp := time.Now().UTC().Add(time.Hour)
	req := controllerBackupPrepareReq(opID, exp)
	req.CapabilityHash = nonce
	if err := a.prepareControllerBackup(req); err != nil { t.Fatalf("prepare: %v", err) }
	if err := a.prepareControllerBackup(req); err != nil { t.Fatalf("idempotent replay: %v", err) }

	// consume validates the one-use bearer capability.
	consumed, err := a.consumeControllerBackup(opID, "wrong", time.Now().UTC())
	if err == nil { t.Fatal("expected capability rejection") }
	_ = consumed
}

func TestPrepareControllerBackupAllowsRetryWithNewCapability(t *testing.T) {
	a := newControllerBackupTestAgent(t, "storage")
	opID := "33333333-3333-4333-8333-333333333333"
	exp := time.Now().UTC().Add(time.Hour)
	req := controllerBackupPrepareReq(opID, exp)
	if err := a.prepareControllerBackup(req); err != nil { t.Fatalf("prepare: %v", err) }

	// Simulate a prior attempt that was consumed (transfer began) then failed.
	if err := a.finishControllerBackup(opID, "consumed"); err != nil { t.Fatalf("finish consumed: %v", err) }
	retry := controllerBackupPrepareReq(opID, exp.Add(time.Minute))
	retry.CapabilityHash = strings.Repeat("d", 64)
	if err := a.prepareControllerBackup(retry); err != nil { t.Fatalf("retry replace: %v", err) }
}

func TestReceiveControllerBackupVerifiesAndStores(t *testing.T) {
	a := newControllerBackupTestAgent(t, "storage")
	opID := "44444444-4444-4444-8444-444444444444"
	payload := []byte("controller-state-archive-bytes")
	sum := sha256.Sum256(payload)
	capabilityToken := "one-use-controller-backup-bearer-token-0001"
	capabilityHash := sha256.Sum256([]byte(capabilityToken))

	req := controllerBackupPrepareReq(opID, time.Now().UTC().Add(time.Hour))
	req.CapabilityHash = hex.EncodeToString(capabilityHash[:])
	req.ExpectedSHA256 = hex.EncodeToString(sum[:])
	if err := a.prepareControllerBackup(req); err != nil { t.Fatalf("prepare: %v", err) }

	receipt, err := a.ReceiveControllerBackup(context.Background(), opID, capabilityToken, hex.EncodeToString(sum[:]), strings.NewReader(string(payload)))
	if err != nil { t.Fatalf("receive: %v", err) }
	if !receipt.OK || receipt.ArchiveSHA256 != hex.EncodeToString(sum[:]) || receipt.TotalBytes != int64(len(payload)) {
		t.Fatalf("receipt=%+v", receipt)
	}
	data, err := os.ReadFile(filepath.Join(a.Cfg.BackupDir, "controller-backups", opID, "controller_backup.tar.zst"))
	if err != nil { t.Fatalf("read stored archive: %v", err) }
	if string(data) != string(payload) { t.Fatalf("stored archive mismatch") }
}

func TestReceiveControllerBackupRejectsBadDigest(t *testing.T) {
	a := newControllerBackupTestAgent(t, "storage")
	opID := "55555555-5555-4555-8555-555555555555"
	payload := "data"
	token := "bearer-token-for-digest-mismatch-test"
	hash := sha256.Sum256([]byte(token))
	req := controllerBackupPrepareReq(opID, time.Now().UTC().Add(time.Hour))
	req.CapabilityHash = hex.EncodeToString(hash[:])
	if err := a.prepareControllerBackup(req); err != nil { t.Fatalf("prepare: %v", err) }
	// Capability is valid but the expected archive digest does not match the body.
	_, err := a.ReceiveControllerBackup(context.Background(), opID, token, strings.Repeat("0", 64), strings.NewReader(payload))
	if err == nil { t.Fatal("expected digest mismatch rejection") }
}
