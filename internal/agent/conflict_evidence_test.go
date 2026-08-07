package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

const (
	testConflictID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	testEvidenceID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
)

func TestCaptureConflictEvidenceIsImmutableAndPagesAreEncrypted(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	tavernDir := filepath.Join(root, "tavern")
	dataRoot := filepath.Join(tavernDir, "data", "alice")
	if err := os.MkdirAll(filepath.Join(dataRoot, "chats"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataRoot, "settings.json"), []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataRoot, "chats", "one.jsonl"), []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	agent, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 8, TavernDir: tavernDir, DataDir: filepath.Join(root, "agent-state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	req := protocol.CaptureConflictEvidenceRequest{
		ConflictID: testConflictID, EvidenceID: testEvidenceID,
		GlobalUserID: 70, Handle: "alice", SourceKind: "active",
	}
	receipt, err := agent.captureConflictEvidence(context.Background(), req)
	if err != nil || receipt.FileCount != 2 || receipt.CaptureBasis != "frozen_live" ||
		len(receipt.EntriesSHA256) != 64 {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	users, _, err := agent.scanUserActivityAndSize()
	if err != nil || len(users) != 1 || users[0].Handle != "alice" {
		t.Fatalf("private evidence directory entered user telemetry: users=%+v err=%v", users, err)
	}
	responseKey, err := controlcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := agent.readConflictEvidencePage(protocol.ReadConflictEvidencePageRequest{
		ConflictID: testConflictID, EvidenceID: testEvidenceID,
		Cursor: 0, MaxBytes: 64 << 10, ResponseKey: responseKey,
	})
	if err != nil || ciphertext == "" || strings.Contains(ciphertext, "settings.json") {
		t.Fatalf("ciphertext leaks path or failed: %q err=%v", ciphertext, err)
	}
	key, err := controlcrypto.LoadKey(responseKey)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := controlcrypto.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	var page protocol.ConflictEvidencePage
	if err := json.Unmarshal(plaintext, &page); err != nil || !page.Complete || page.NextCursor != 2 ||
		len(page.Entries) != 2 || page.Entries[0].Path != "chats/one.jsonl" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	_, evidenceRoot, _, err := agent.conflictEvidencePaths(testConflictID, testEvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(evidenceRoot, "settings.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evidenceRoot, "settings.json"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.captureConflictEvidence(context.Background(), req); err == nil {
		t.Fatal("tampered immutable evidence was accepted on replay")
	}
}

func TestStorageConflictEvidenceRequiresMatchingArchiveManifest(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	backupRoot := filepath.Join(root, "backup")
	archiveRoot := filepath.Join(backupRoot, "replicas", "alice")
	if err := os.MkdirAll(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("archive-data")
	if err := os.WriteFile(filepath.Join(archiveRoot, "data.bin"), content, 0o400); err != nil {
		t.Fatal(err)
	}
	fileDigest := sha256.Sum256(content)
	manifest := protocol.SnapshotManifest{
		FormatVersion: 1, WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", SourceNodeID: 8, TargetNodeID: 9,
		ActivityEpoch: 4, CreatedAt: time.Now().UTC(),
		Files: []protocol.ManifestEntry{{Path: "data.bin", Size: int64(len(content)), SHA256: hex.EncodeToString(fileDigest[:])}},
	}
	manifestJSON, _ := json.Marshal(manifest)
	manifestDigest := sha256.Sum256(manifestJSON)
	receipt := protocol.SnapshotTransferReceipt{
		OK: true, SnapshotID: testSnapshotID, ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
		ArchiveSHA256: hex.EncodeToString(make([]byte, 32)), FileCount: 1, TotalBytes: int64(len(content)),
	}
	if err := writeArchiveReplicaMetadata(archiveRoot, manifest, receipt); err != nil {
		t.Fatal(err)
	}
	agent, err := New(&config.AgentConfig{
		Role: "storage", NodeID: 9, BackupDir: backupRoot, DataDir: filepath.Join(root, "agent-state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	req := protocol.CaptureConflictEvidenceRequest{
		ConflictID: testConflictID, EvidenceID: testEvidenceID, GlobalUserID: 70,
		Handle: "alice", SourceKind: "archive", SourceSnapshotID: testSnapshotID,
		SourceManifestSHA256: hex.EncodeToString(manifestDigest[:]),
	}
	got, err := agent.captureConflictEvidence(context.Background(), req)
	if err != nil || got.CaptureBasis != "verified_archive" || got.SourceSnapshotID != testSnapshotID {
		t.Fatalf("receipt=%+v err=%v", got, err)
	}
	req.EvidenceID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	req.SourceManifestSHA256 = hex.EncodeToString(make([]byte, 32))
	if _, err := agent.captureConflictEvidence(context.Background(), req); err == nil {
		t.Fatal("archive with mismatched controller manifest was accepted")
	}
}
