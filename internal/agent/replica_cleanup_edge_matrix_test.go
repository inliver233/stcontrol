package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func cleanupEdgeRequest(kind string) protocol.DeleteReplicaRequest {
	return protocol.DeleteReplicaRequest{
		CleanupID: testReplicaCleanupID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", ReplicaKind: kind,
	}
}

func TestReplicaCleanupRejectsCancelledInvalidRoleAndUnsafeRoots(t *testing.T) {
	t.Parallel()
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := (&Agent{}).deleteSnapshotReplica(ctx, cleanupEdgeRequest("archive")); err == nil {
			t.Fatal("cancelled cleanup succeeded")
		}
	})
	t.Run("nil config", func(t *testing.T) {
		if _, err := (&Agent{}).deleteSnapshotReplica(context.Background(), cleanupEdgeRequest("archive")); err == nil {
			t.Fatal("nil-config cleanup succeeded")
		}
	})
	t.Run("archive on compute", func(t *testing.T) {
		a := &Agent{Cfg: &config.AgentConfig{Role: "compute", NodeID: 9, TavernDir: t.TempDir()}}
		if _, err := a.deleteSnapshotReplica(context.Background(), cleanupEdgeRequest("archive")); err == nil {
			t.Fatal("compute Agent accepted archive cleanup")
		}
	})
	t.Run("unknown kind", func(t *testing.T) {
		a := &Agent{Cfg: &config.AgentConfig{Role: "storage", NodeID: 9, BackupDir: t.TempDir()}}
		if _, err := a.deleteSnapshotReplica(context.Background(), cleanupEdgeRequest("unknown")); err == nil {
			t.Fatal("unknown cleanup kind succeeded")
		}
	})
	t.Run("missing publication root", func(t *testing.T) {
		a := &Agent{Cfg: &config.AgentConfig{Role: "storage", NodeID: 9, BackupDir: t.TempDir()}}
		receipt, err := a.deleteSnapshotReplica(context.Background(), cleanupEdgeRequest("archive"))
		if err != nil || receipt.Outcome != protocol.DeleteReplicaOutcomeAlreadyAbsent {
			t.Fatalf("receipt=%+v error=%v", receipt, err)
		}
	})
	t.Run("publication root is file", func(t *testing.T) {
		backup := t.TempDir()
		if err := os.WriteFile(filepath.Join(backup, "replicas"), []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		a := &Agent{Cfg: &config.AgentConfig{Role: "storage", NodeID: 9, BackupDir: backup}}
		if _, err := a.deleteSnapshotReplica(context.Background(), cleanupEdgeRequest("archive")); err == nil {
			t.Fatal("file publication root accepted")
		}
	})
}

func TestReplicaCleanupRejectsMalformedAndMismatchedTombstones(t *testing.T) {
	t.Parallel()
	t.Run("tombstone root is file", func(t *testing.T) {
		backup := t.TempDir()
		root := filepath.Join(backup, "replicas")
		finalPath := filepath.Join(root, "alice")
		if err := os.MkdirAll(finalPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writeArchiveReplicaMetadata(finalPath, cleanupTestManifest(testSnapshotID, 9),
			protocol.SnapshotTransferReceipt{OK: true, SnapshotID: testSnapshotID}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, ".stcontrol-cleanups"), []byte("invalid"), 0o600); err != nil {
			t.Fatal(err)
		}
		a := &Agent{Cfg: &config.AgentConfig{Role: "storage", NodeID: 9, BackupDir: backup}}
		if _, err := a.deleteSnapshotReplica(context.Background(), cleanupEdgeRequest("archive")); err == nil {
			t.Fatal("file tombstone root accepted")
		}
	})
	t.Run("tombstone is file", func(t *testing.T) {
		backup := t.TempDir()
		trashRoot := filepath.Join(backup, "replicas", ".stcontrol-cleanups")
		if err := os.MkdirAll(trashRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(trashRoot, testReplicaCleanupID), []byte("invalid"), 0o600); err != nil {
			t.Fatal(err)
		}
		a := &Agent{Cfg: &config.AgentConfig{Role: "storage", NodeID: 9, BackupDir: backup}}
		if _, err := a.deleteSnapshotReplica(context.Background(), cleanupEdgeRequest("archive")); err == nil {
			t.Fatal("file tombstone accepted")
		}
	})
	t.Run("tombstone identity mismatch", func(t *testing.T) {
		backup := t.TempDir()
		trashPath := filepath.Join(backup, "replicas", ".stcontrol-cleanups", testReplicaCleanupID)
		if err := os.MkdirAll(trashPath, 0o700); err != nil {
			t.Fatal(err)
		}
		otherSnapshot := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
		if err := writeArchiveReplicaMetadata(trashPath, cleanupTestManifest(otherSnapshot, 9),
			protocol.SnapshotTransferReceipt{OK: true, SnapshotID: otherSnapshot}); err != nil {
			t.Fatal(err)
		}
		a := &Agent{Cfg: &config.AgentConfig{Role: "storage", NodeID: 9, BackupDir: backup}}
		if _, err := a.deleteSnapshotReplica(context.Background(), cleanupEdgeRequest("archive")); err == nil {
			t.Fatal("mismatched tombstone accepted")
		}
	})
}

func TestReplicaCleanupFencesLocalOwnershipAndDetachedIdentity(t *testing.T) {
	t.Parallel()
	tavern := t.TempDir()
	finalPath := filepath.Join(tavern, "data", "alice")
	if err := os.MkdirAll(finalPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeReplicaIdentityMetadata(finalPath, cleanupTestManifest(testSnapshotID, 9), "hot_standby"); err != nil {
		t.Fatal(err)
	}
	a := &Agent{Cfg: &config.AgentConfig{Role: "compute", NodeID: 9, TavernDir: tavern}}
	a.state.ControlMode.Mode = protocol.NodeModeManaged
	a.state.ActivityOwnership = map[string]activityOwnershipClaim{"alice": {OwnerNodeID: 9}}
	if _, err := a.deleteSnapshotReplica(context.Background(), cleanupEdgeRequest("hot_standby")); err == nil {
		t.Fatal("cleanup crossed local ownership fence")
	}
	if _, err := os.Stat(finalPath); err != nil {
		t.Fatalf("ownership fence mutated replica: %v", err)
	}
	if err := (&Agent{Cfg: &config.AgentConfig{Role: "compute", NodeID: 0}}).
		validateDetachedReplicaTombstone(finalPath); err == nil {
		t.Fatal("detached tombstone accepted without node identity")
	}
	if err := a.validateDetachedReplicaTombstone(finalPath); err != nil {
		t.Fatalf("valid compute tombstone rejected: %v", err)
	}
}
