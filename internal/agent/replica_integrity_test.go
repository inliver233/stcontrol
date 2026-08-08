package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func TestVerifyReplicaIntegrityRehashesPrivateArchive(t *testing.T) {
	t.Parallel()
	agent, request, dataPath := replicaIntegrityFixture(t)
	receipt, err := agent.VerifyReplicaIntegrity(context.Background(), request)
	if err != nil || receipt.SnapshotID != request.SnapshotID ||
		receipt.ManifestSHA256 != request.ManifestSHA256 || receipt.TotalBytes != request.TotalBytes {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	if err := os.WriteFile(dataPath, []byte("tampered-private-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.VerifyReplicaIntegrity(context.Background(), request); !errors.Is(err, errReplicaIntegrityMismatch) {
		t.Fatalf("tamper error=%v, want integrity mismatch", err)
	}
}

func TestVerifyReplicaIntegrityReturnsOnlySafeCommandFailure(t *testing.T) {
	t.Parallel()
	agent, request, dataPath := replicaIntegrityFixture(t)
	if err := os.WriteFile(dataPath, []byte("tampered-private-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	command := encryptedTestCommand(t, agent.Cfg.AgentPSK, "verify_replica_integrity", payload)
	command.OperationID = request.OperationID
	succeeded, result := agent.executeCommand(context.Background(), command)
	if succeeded || !strings.Contains(string(result), `"code":"replica_integrity_mismatch"`) ||
		strings.Contains(string(result), dataPath) || strings.Contains(string(result), "tampered-private-data") {
		t.Fatalf("unsafe or unexpected command result: %s", result)
	}
}

func TestVerifyReplicaIntegrityRejectsInvalidAndUnavailableRequests(t *testing.T) {
	t.Parallel()
	if _, err := (&Agent{}).VerifyReplicaIntegrity(context.Background(), protocol.VerifyReplicaIntegrityRequest{}); err == nil {
		t.Fatal("invalid request was accepted")
	}
	request := protocol.VerifyReplicaIntegrityRequest{
		OperationID: testWorkflowID, SnapshotID: testSnapshotID, Handle: "alice",
		ManifestSHA256: strings.Repeat("a", 64), ArchiveSHA256: strings.Repeat("b", 64),
	}
	if _, err := (&Agent{Cfg: &config.AgentConfig{}}).VerifyReplicaIntegrity(context.Background(), request); !errors.Is(err, errReplicaIntegrityUnavailable) {
		t.Fatalf("error=%v, want unavailable", err)
	}
}

func replicaIntegrityFixture(t *testing.T) (*Agent, protocol.VerifyReplicaIntegrityRequest, string) {
	t.Helper()
	backupRoot := t.TempDir()
	replicaRoot := filepath.Join(backupRoot, "replicas", "alice")
	if err := os.MkdirAll(filepath.Join(replicaRoot, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("private-user-data")
	dataPath := filepath.Join(replicaRoot, "nested", "settings.json")
	if err := os.WriteFile(dataPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	fileDigest := sha256.Sum256(content)
	manifest := protocol.SnapshotManifest{
		FormatVersion: 1, WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", SourceNodeID: 8, TargetNodeID: 9,
		Files: []protocol.ManifestEntry{{
			Path: "nested/settings.json", Size: int64(len(content)), SHA256: hex.EncodeToString(fileDigest[:]),
		}},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := sha256.Sum256(manifestJSON)
	archiveDigest := sha256.Sum256([]byte("immutable-compressed-archive"))
	receipt := protocol.SnapshotTransferReceipt{
		OK: true, SnapshotID: testSnapshotID, ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
		ArchiveSHA256: hex.EncodeToString(archiveDigest[:]), FileCount: 1, TotalBytes: int64(len(content)),
	}
	if err := writeArchiveReplicaMetadata(replicaRoot, manifest, receipt); err != nil {
		t.Fatal(err)
	}
	agent := &Agent{Cfg: &config.AgentConfig{
		NodeID: 9, BackupDir: backupRoot, AgentPSK: "replica-integrity-test-psk",
	}}
	return agent, protocol.VerifyReplicaIntegrityRequest{
		OperationID: testWorkflowID, SnapshotID: testSnapshotID, Handle: "alice",
		ManifestSHA256: receipt.ManifestSHA256, ArchiveSHA256: receipt.ArchiveSHA256,
		FileCount: receipt.FileCount, TotalBytes: receipt.TotalBytes,
	}, dataPath
}
