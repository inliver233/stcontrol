package controller

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const (
	replicaIntegrityLeaseTTL = 9 * time.Hour
	replicaIntegrityInterval = 24 * time.Hour
)

func (s *Server) replicaIntegrityReconciler(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	s.reconcileReplicaIntegrity(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcileReplicaIntegrity(ctx)
		}
	}
}

func (s *Server) reconcileReplicaIntegrity(ctx context.Context) {
	if s.checkNewOperations() != nil {
		return
	}
	for {
		select {
		case s.replicaIntegritySlots <- struct{}{}:
		case <-ctx.Done():
			return
		default:
			return
		}
		operationID, err := newUUID()
		if err != nil {
			<-s.replicaIntegritySlots
			return
		}
		now := time.Now().UTC()
		task, err := s.Store.ClaimReplicaIntegrityTask(ctx, operationID, now, replicaIntegrityLeaseTTL)
		if err != nil || task == nil {
			<-s.replicaIntegritySlots
			return
		}
		go func(task store.ReplicaIntegrityTask) {
			defer func() { <-s.replicaIntegritySlots }()
			s.executeReplicaIntegrityTask(ctx, task)
		}(*task)
	}
}

func (s *Server) executeReplicaIntegrityTask(ctx context.Context, task store.ReplicaIntegrityTask) {
	node, err := s.Store.GetNodeByID(ctx, task.NodeID)
	if err != nil || !nodeReadyForManagedOperation(node) {
		s.failReplicaIntegrityTask(ctx, task, "node_unavailable", false)
		return
	}
	request := protocol.VerifyReplicaIntegrityRequest{
		OperationID: task.OperationID, SnapshotID: task.SnapshotID, Handle: task.Handle,
		ManifestSHA256: hex.EncodeToString(task.ManifestSHA256),
		ArchiveSHA256:  hex.EncodeToString(task.ArchiveSHA256),
		FileCount:      task.FileCount, TotalBytes: task.TotalBytes,
	}
	result, err := s.runAgentCommandWithOperation(
		ctx, node, "verify_replica_integrity", request, task.OperationID, snapshotWorkflowCommandTTL,
	)
	if err != nil {
		code := safeReplicaIntegrityFailureCode(agentCommandErrorCode(err))
		corrupt := code == "replica_integrity_mismatch"
		s.failReplicaIntegrityTask(ctx, task, code, corrupt)
		return
	}
	if !matchingReplicaIntegrityReceipt(result.ReplicaIntegrity, task) {
		s.failReplicaIntegrityTask(ctx, task, "receipt_mismatch", true)
		return
	}
	_ = s.Store.CompleteReplicaIntegrityTask(ctx, store.CompleteReplicaIntegrityParams{
		ReplicaID: task.ReplicaID, OperationID: task.OperationID, SnapshotID: task.SnapshotID,
		ManifestSHA256: task.ManifestSHA256, ArchiveSHA256: task.ArchiveSHA256,
		FileCount: task.FileCount, TotalBytes: task.TotalBytes,
		Now: time.Now().UTC(), NextCheckAfter: replicaIntegrityInterval,
	})
}

func safeReplicaIntegrityFailureCode(code string) string {
	switch code {
	case "replica_integrity_mismatch", "replica_integrity_unavailable", "invalid_command_payload":
		return code
	default:
		return "agent_command_unavailable"
	}
}

func (s *Server) failReplicaIntegrityTask(
	ctx context.Context,
	task store.ReplicaIntegrityTask,
	code string,
	corrupt bool,
) {
	_ = s.Store.FailReplicaIntegrityTask(
		ctx, task.ReplicaID, task.OperationID, code, corrupt, time.Now().UTC(),
		replicaIntegrityRetryDelay(task.Attempt),
	)
}

func matchingReplicaIntegrityReceipt(
	receipt *protocol.ReplicaIntegrityReceipt,
	task store.ReplicaIntegrityTask,
) bool {
	if receipt == nil || receipt.SnapshotID != task.SnapshotID ||
		receipt.FileCount != task.FileCount || receipt.TotalBytes != task.TotalBytes {
		return false
	}
	return matchingIntegrityDigest(receipt.ManifestSHA256, task.ManifestSHA256) &&
		matchingIntegrityDigest(receipt.ArchiveSHA256, task.ArchiveSHA256)
}

func matchingIntegrityDigest(value string, expected []byte) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == len(expected) && hmac.Equal(digest, expected)
}

func replicaIntegrityRetryDelay(attempt int) time.Duration {
	delay := 5 * time.Minute
	for current := 1; current < attempt && delay < 6*time.Hour; current++ {
		delay *= 2
	}
	if delay > 6*time.Hour {
		return 6 * time.Hour
	}
	return delay
}
