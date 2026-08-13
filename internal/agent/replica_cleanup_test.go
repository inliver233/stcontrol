package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

const testReplicaCleanupID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

func TestDeleteSnapshotReplicaCommandReturnsBoundReceipt(t *testing.T) {
	t.Parallel()
	backupRoot := t.TempDir()
	agent := &Agent{Cfg: &config.AgentConfig{
		Role: "storage", NodeID: 9, BackupDir: backupRoot, AgentPSK: "cleanup-command-secret",
	}}
	agent.state.ControlMode.Mode = protocol.NodeModeManaged
	replicaRoot := filepath.Join(backupRoot, "replicas", "alice")
	if err := os.MkdirAll(replicaRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeArchiveReplicaMetadata(replicaRoot, cleanupTestManifest(testSnapshotID, 9),
		protocol.SnapshotTransferReceipt{OK: true, SnapshotID: testSnapshotID}); err != nil {
		t.Fatal(err)
	}
	req := protocol.DeleteReplicaRequest{
		CleanupID: testReplicaCleanupID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", ReplicaKind: "archive",
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	succeeded, summary := agent.executeCommand(context.Background(),
		encryptedTestCommand(t, agent.Cfg.AgentPSK, "delete_snapshot_replica", payload))
	if !succeeded {
		t.Fatalf("delete command failed: %s", summary)
	}
	var result safeCommandResult
	if err := json.Unmarshal(summary, &result); err != nil || !result.OK || result.ReplicaCleanup == nil {
		t.Fatalf("cleanup command result=%s err=%v", summary, err)
	}
	assertDeleteReplicaReceipt(t, *result.ReplicaCleanup, req, 9, protocol.DeleteReplicaOutcomeDeleted)
}

func TestDeleteArchiveReplicaIsExactAndIdempotent(t *testing.T) {
	t.Parallel()
	backupRoot := t.TempDir()
	agent := &Agent{Cfg: &config.AgentConfig{Role: "storage", NodeID: 9, BackupDir: backupRoot}}
	agent.state.ControlMode.Mode = protocol.NodeModeManaged
	replicaRoot := filepath.Join(backupRoot, "replicas", "alice")
	if err := os.MkdirAll(replicaRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := cleanupTestManifest(testSnapshotID, 9)
	receipt := protocol.SnapshotTransferReceipt{OK: true, SnapshotID: testSnapshotID}
	if err := writeArchiveReplicaMetadata(replicaRoot, manifest, receipt); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(replicaRoot, "chat.json"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	req := protocol.DeleteReplicaRequest{
		CleanupID: testReplicaCleanupID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", ReplicaKind: "archive",
	}
	cleanupReceipt, err := agent.deleteSnapshotReplica(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	assertDeleteReplicaReceipt(t, cleanupReceipt, req, 9, protocol.DeleteReplicaOutcomeDeleted)
	if _, err := os.Stat(replicaRoot); !os.IsNotExist(err) {
		t.Fatalf("archive replica survived cleanup: %v", err)
	}
	cleanupReceipt, err = agent.deleteSnapshotReplica(context.Background(), req)
	if err != nil {
		t.Fatalf("idempotent cleanup replay failed: %v", err)
	}
	assertDeleteReplicaReceipt(t, cleanupReceipt, req, 9, protocol.DeleteReplicaOutcomeAlreadyAbsent)
}

func TestDelayedReplicaCleanupPreservesReplacement(t *testing.T) {
	t.Parallel()
	backupRoot := t.TempDir()
	agent := &Agent{Cfg: &config.AgentConfig{Role: "storage", NodeID: 9, BackupDir: backupRoot}}
	agent.state.ControlMode.Mode = protocol.NodeModeManaged
	replicaRoot := filepath.Join(backupRoot, "replicas", "alice")
	if err := os.MkdirAll(replicaRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	newSnapshotID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	if err := writeArchiveReplicaMetadata(replicaRoot, cleanupTestManifest(newSnapshotID, 9),
		protocol.SnapshotTransferReceipt{OK: true, SnapshotID: newSnapshotID}); err != nil {
		t.Fatal(err)
	}
	newFile := filepath.Join(replicaRoot, "new.json")
	if err := os.WriteFile(newFile, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	req := protocol.DeleteReplicaRequest{
		CleanupID: testReplicaCleanupID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", ReplicaKind: "archive",
	}
	cleanupReceipt, err := agent.deleteSnapshotReplica(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	assertDeleteReplicaReceipt(t, cleanupReceipt, req, 9, protocol.DeleteReplicaOutcomeSuperseded)
	if data, err := os.ReadFile(newFile); err != nil || string(data) != "new" {
		t.Fatalf("delayed cleanup removed replacement: %q err=%v", data, err)
	}
}

func TestReplicaCleanupFinishesCrashTombstoneWithoutDeletingNewFinal(t *testing.T) {
	t.Parallel()
	tavernRoot := t.TempDir()
	agent := &Agent{Cfg: &config.AgentConfig{Role: "compute", NodeID: 9, TavernDir: tavernRoot}}
	agent.state.ControlMode.Mode = protocol.NodeModeManaged
	dataRoot := filepath.Join(tavernRoot, "data")
	finalPath := filepath.Join(dataRoot, "alice")
	trashRoot := filepath.Join(dataRoot, ".stcontrol-cleanups")
	trashPath := filepath.Join(trashRoot, testReplicaCleanupID)
	for _, path := range []string{trashPath, finalPath} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeReplicaIdentityMetadata(trashPath, cleanupTestManifest(testSnapshotID, 9), "hot_standby"); err != nil {
		t.Fatal(err)
	}
	// The replacement may legitimately carry the same snapshot identity (for
	// example a replayed publication). Tombstone recovery must still never
	// continue into the newly-created final name.
	if err := writeReplicaIdentityMetadata(finalPath, cleanupTestManifest(testSnapshotID, 9), "hot_standby"); err != nil {
		t.Fatal(err)
	}
	newFile := filepath.Join(finalPath, "new.json")
	if err := os.WriteFile(newFile, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	req := protocol.DeleteReplicaRequest{
		CleanupID: testReplicaCleanupID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", ReplicaKind: "hot_standby",
	}
	cleanupReceipt, err := agent.deleteSnapshotReplica(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	assertDeleteReplicaReceipt(t, cleanupReceipt, req, 9, protocol.DeleteReplicaOutcomeDeleted)
	if _, err := os.Stat(trashPath); !os.IsNotExist(err) {
		t.Fatalf("crash tombstone survived replay: %v", err)
	}
	if data, err := os.ReadFile(newFile); err != nil || string(data) != "new" {
		t.Fatalf("tombstone replay removed new final: %q err=%v", data, err)
	}
}

func TestReplicaCleanupRejectsRoleAndUnidentifiedHotReplica(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	storage := &Agent{Cfg: &config.AgentConfig{Role: "storage", NodeID: 9, BackupDir: root, TavernDir: root}}
	storage.state.ControlMode.Mode = protocol.NodeModeManaged
	req := protocol.DeleteReplicaRequest{
		CleanupID: testReplicaCleanupID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", ReplicaKind: "hot_standby",
	}
	if _, err := storage.deleteSnapshotReplica(context.Background(), req); err == nil {
		t.Fatal("storage Agent accepted compute replica cleanup")
	}
	compute := &Agent{Cfg: &config.AgentConfig{Role: "compute", NodeID: 9, TavernDir: root}}
	compute.state.ControlMode.Mode = protocol.NodeModeManaged
	if err := os.MkdirAll(filepath.Join(root, "data", "alice"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := compute.deleteSnapshotReplica(context.Background(), req); err == nil {
		t.Fatal("compute Agent deleted a hot replica without exact publication identity")
	}
}

func TestReplicaCleanupRequiresManagedModeAndNoLocalWriter(t *testing.T) {
	t.Parallel()
	tavernRoot := t.TempDir()
	agent := &Agent{Cfg: &config.AgentConfig{Role: "compute", NodeID: 9, TavernDir: tavernRoot}}
	finalPath := filepath.Join(tavernRoot, "data", "alice")
	if err := os.MkdirAll(finalPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeReplicaIdentityMetadata(finalPath, cleanupTestManifest(testSnapshotID, 9), "hot_standby"); err != nil {
		t.Fatal(err)
	}
	req := protocol.DeleteReplicaRequest{
		CleanupID: testReplicaCleanupID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", ReplicaKind: "hot_standby",
	}
	agent.state.ControlMode.Mode = protocol.NodeModeIndependent
	if _, err := agent.deleteSnapshotReplica(context.Background(), req); err == nil {
		t.Fatal("independent Agent accepted destructive cleanup")
	}
	if _, err := os.Stat(finalPath); err != nil {
		t.Fatalf("mode fence mutated replica: %v", err)
	}

	agent.state.ControlMode.Mode = protocol.NodeModeManaged
	agent.state.ActivityLeases.Leases = []protocol.ActivityLeaseConfirmation{{
		Handle: "alice", SessionID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ActivityEpoch: 4, ControllerGeneration: 1,
		LeaseExpiresAt: time.Now().Add(time.Minute).UnixMilli(),
	}}
	if _, err := agent.deleteSnapshotReplica(context.Background(), req); err == nil {
		t.Fatal("Agent accepted cleanup with a live local writer lease")
	}
	if _, err := os.Stat(finalPath); err != nil {
		t.Fatalf("writer fence mutated replica: %v", err)
	}
}

func TestReplicaCleanupRejectsSymlinkedRootAndTombstoneRoot(t *testing.T) {
	t.Parallel()
	req := protocol.DeleteReplicaRequest{
		CleanupID: testReplicaCleanupID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", ReplicaKind: "archive",
	}

	t.Run("replica_root", func(t *testing.T) {
		backupRoot := t.TempDir()
		outside := t.TempDir()
		outsideReplica := filepath.Join(outside, "alice")
		if err := os.MkdirAll(outsideReplica, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writeArchiveReplicaMetadata(outsideReplica, cleanupTestManifest(testSnapshotID, 9),
			protocol.SnapshotTransferReceipt{OK: true, SnapshotID: testSnapshotID}); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(backupRoot, "replicas")); err != nil {
			t.Skipf("directory symlink unavailable: %v", err)
		}
		agent := &Agent{Cfg: &config.AgentConfig{Role: "storage", NodeID: 9, BackupDir: backupRoot}}
		agent.state.ControlMode.Mode = protocol.NodeModeManaged
		if _, err := agent.deleteSnapshotReplica(context.Background(), req); err == nil {
			t.Fatal("cleanup accepted a symlinked replica root")
		}
		if _, err := os.Stat(outsideReplica); err != nil {
			t.Fatalf("symlinked root target was mutated: %v", err)
		}
	})

	t.Run("tombstone_root", func(t *testing.T) {
		backupRoot := t.TempDir()
		replicaRoot := filepath.Join(backupRoot, "replicas", "alice")
		if err := os.MkdirAll(replicaRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writeArchiveReplicaMetadata(replicaRoot, cleanupTestManifest(testSnapshotID, 9),
			protocol.SnapshotTransferReceipt{OK: true, SnapshotID: testSnapshotID}); err != nil {
			t.Fatal(err)
		}
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(backupRoot, "replicas", ".stcontrol-cleanups")); err != nil {
			t.Skipf("directory symlink unavailable: %v", err)
		}
		agent := &Agent{Cfg: &config.AgentConfig{Role: "storage", NodeID: 9, BackupDir: backupRoot}}
		agent.state.ControlMode.Mode = protocol.NodeModeManaged
		if _, err := agent.deleteSnapshotReplica(context.Background(), req); err == nil {
			t.Fatal("cleanup accepted a symlinked tombstone root")
		}
		if _, err := os.Stat(replicaRoot); err != nil {
			t.Fatalf("symlinked tombstone root allowed replica mutation: %v", err)
		}
	})
}

func TestAgentStartupSweepsOnlyValidatedDetachedCleanupTombstones(t *testing.T) {
	t.Parallel()
	backupRoot := t.TempDir()
	stateRoot := t.TempDir()
	publicationRoot := filepath.Join(backupRoot, "replicas")
	tombstone := filepath.Join(publicationRoot, ".stcontrol-cleanups", testReplicaCleanupID)
	finalPath := filepath.Join(publicationRoot, "alice")
	for _, path := range []string{tombstone, finalPath} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manifest := cleanupTestManifest(testSnapshotID, 9)
	if err := writeArchiveReplicaMetadata(tombstone, manifest,
		protocol.SnapshotTransferReceipt{OK: true, SnapshotID: testSnapshotID}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tombstone, "old-private.json"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	liveFile := filepath.Join(finalPath, "live.json")
	if err := os.WriteFile(liveFile, []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := New(&config.AgentConfig{
		Role: "storage", NodeID: 9, BackupDir: backupRoot, DataDir: stateRoot,
		AgentPSK: "startup-cleanup-secret",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tombstone); !os.IsNotExist(err) {
		t.Fatalf("startup did not remove detached tombstone: %v", err)
	}
	if data, err := os.ReadFile(liveFile); err != nil || string(data) != "live" {
		t.Fatalf("startup cleanup touched final user directory: %q err=%v", data, err)
	}
}

func TestAgentStartupRejectsMalformedCleanupRootWithoutPartialDeletion(t *testing.T) {
	t.Parallel()
	backupRoot := t.TempDir()
	cleanupRoot := filepath.Join(backupRoot, "replicas", ".stcontrol-cleanups")
	validTombstone := filepath.Join(cleanupRoot, testReplicaCleanupID)
	invalidTombstone := filepath.Join(cleanupRoot, "not-a-cleanup-id")
	for _, path := range []string{validTombstone, invalidTombstone} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeArchiveReplicaMetadata(validTombstone, cleanupTestManifest(testSnapshotID, 9),
		protocol.SnapshotTransferReceipt{OK: true, SnapshotID: testSnapshotID}); err != nil {
		t.Fatal(err)
	}
	if _, err := New(&config.AgentConfig{
		Role: "storage", NodeID: 9, BackupDir: backupRoot, DataDir: t.TempDir(),
		AgentPSK: "startup-cleanup-secret",
	}); err == nil {
		t.Fatal("Agent accepted malformed cleanup tombstone state")
	}
	if _, err := os.Stat(validTombstone); err != nil {
		t.Fatalf("startup partially deleted tombstones before validation completed: %v", err)
	}
}

func assertDeleteReplicaReceipt(
	t *testing.T,
	receipt protocol.DeleteReplicaReceipt,
	req protocol.DeleteReplicaRequest,
	nodeID int64,
	outcome string,
) {
	t.Helper()
	if receipt.CleanupID != req.CleanupID || receipt.SnapshotID != req.SnapshotID ||
		receipt.GlobalUserID != req.GlobalUserID || receipt.Handle != req.Handle ||
		receipt.ReplicaKind != req.ReplicaKind || receipt.TargetNodeID != nodeID || receipt.Outcome != outcome {
		t.Fatalf("cleanup receipt=%+v request=%+v node=%d outcome=%q", receipt, req, nodeID, outcome)
	}
}

func cleanupTestManifest(snapshotID string, targetNodeID int64) protocol.SnapshotManifest {
	return protocol.SnapshotManifest{
		FormatVersion: 1, WorkflowID: testWorkflowID, SnapshotID: snapshotID,
		GlobalUserID: 70, Handle: "alice", SourceNodeID: 8, TargetNodeID: targetNodeID,
		ActivityEpoch: 4, CreatedAt: time.Now().UTC(),
	}
}
