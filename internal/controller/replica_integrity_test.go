package controller

import (
	"encoding/hex"
	"testing"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func TestMatchingReplicaIntegrityReceiptBindsImmutableFacts(t *testing.T) {
	t.Parallel()
	manifest := make([]byte, 32)
	archive := make([]byte, 32)
	manifest[0], archive[0] = 1, 2
	task := store.ReplicaIntegrityTask{
		SnapshotID: integrityControllerSnapshotID, ManifestSHA256: manifest, ArchiveSHA256: archive,
		FileCount: 2, TotalBytes: 30,
	}
	receipt := &protocol.ReplicaIntegrityReceipt{
		SnapshotID: task.SnapshotID, ManifestSHA256: hex.EncodeToString(manifest),
		ArchiveSHA256: hex.EncodeToString(archive), FileCount: 2, TotalBytes: 30,
	}
	if !matchingReplicaIntegrityReceipt(receipt, task) {
		t.Fatal("matching receipt was rejected")
	}
	receipt.TotalBytes++
	if matchingReplicaIntegrityReceipt(receipt, task) {
		t.Fatal("receipt with mismatched immutable facts was accepted")
	}
	receipt.TotalBytes--
	receipt.ArchiveSHA256 = "not-hex"
	if matchingReplicaIntegrityReceipt(receipt, task) {
		t.Fatal("malformed digest was accepted")
	}
}

func TestReplicaIntegrityRetryDelayIsBounded(t *testing.T) {
	t.Parallel()
	if got := replicaIntegrityRetryDelay(1); got != 5*time.Minute {
		t.Fatalf("first delay=%v", got)
	}
	if got := replicaIntegrityRetryDelay(100); got != 6*time.Hour {
		t.Fatalf("bounded delay=%v", got)
	}
}

func TestReplicaIntegrityFailureCodesAreAllowlisted(t *testing.T) {
	t.Parallel()
	if got := safeReplicaIntegrityFailureCode("replica_integrity_mismatch"); got != "replica_integrity_mismatch" {
		t.Fatalf("known code=%q", got)
	}
	if got := safeReplicaIntegrityFailureCode("secret internal failure"); got != "agent_command_unavailable" {
		t.Fatalf("unknown code=%q", got)
	}
}

const integrityControllerSnapshotID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
