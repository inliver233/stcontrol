package controller

import (
	"testing"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func TestMatchingReplicaCleanupReceiptRequiresExactScopeAndKnownOutcome(t *testing.T) {
	t.Parallel()
	task := store.ReplicaCleanupTask{
		ID:           "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		SnapshotID:   "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		GlobalUserID: 70, NodeID: 9, Handle: "alice", ReplicaKind: "hot_standby",
	}
	base := protocol.DeleteReplicaReceipt{
		CleanupID: task.ID, SnapshotID: task.SnapshotID, GlobalUserID: task.GlobalUserID,
		Handle: task.Handle, ReplicaKind: task.ReplicaKind, TargetNodeID: task.NodeID,
	}
	for _, outcome := range []string{
		protocol.DeleteReplicaOutcomeDeleted,
		protocol.DeleteReplicaOutcomeAlreadyAbsent,
		protocol.DeleteReplicaOutcomeSuperseded,
	} {
		receipt := base
		receipt.Outcome = outcome
		if !matchingReplicaCleanupReceipt(&receipt, task) {
			t.Errorf("valid outcome %q was rejected", outcome)
		}
	}
	if matchingReplicaCleanupReceipt(nil, task) {
		t.Fatal("nil cleanup receipt was accepted")
	}

	tests := map[string]func(*protocol.DeleteReplicaReceipt){
		"cleanup": func(receipt *protocol.DeleteReplicaReceipt) {
			receipt.CleanupID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		},
		"snapshot": func(receipt *protocol.DeleteReplicaReceipt) {
			receipt.SnapshotID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		},
		"user":    func(receipt *protocol.DeleteReplicaReceipt) { receipt.GlobalUserID++ },
		"handle":  func(receipt *protocol.DeleteReplicaReceipt) { receipt.Handle = "bob" },
		"kind":    func(receipt *protocol.DeleteReplicaReceipt) { receipt.ReplicaKind = "archive" },
		"node":    func(receipt *protocol.DeleteReplicaReceipt) { receipt.TargetNodeID++ },
		"outcome": func(receipt *protocol.DeleteReplicaReceipt) { receipt.Outcome = "unknown" },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			receipt := base
			receipt.Outcome = protocol.DeleteReplicaOutcomeDeleted
			mutate(&receipt)
			if matchingReplicaCleanupReceipt(&receipt, task) {
				t.Fatalf("mismatched receipt was accepted: %+v", receipt)
			}
		})
	}
}
