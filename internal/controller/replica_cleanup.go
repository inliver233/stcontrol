package controller

import (
	"context"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const (
	replicaCleanupLeaseTTL       = 5 * time.Minute
	replicaCleanupCommandTimeout = 2 * time.Minute
)

func (s *Server) replicaCleanupReconciler(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	s.reconcileReplicaCleanup(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcileReplicaCleanup(ctx)
		}
	}
}

func (s *Server) reconcileReplicaCleanup(ctx context.Context) {
	if s.checkNewOperations() != nil {
		return
	}
	now := time.Now().UTC()
	if _, err := s.Store.ScheduleReplicaCleanupTasks(ctx, now); err != nil {
		return
	}
	for {
		select {
		case s.replicaCleanupSlots <- struct{}{}:
		case <-ctx.Done():
			return
		default:
			return
		}
		operationID, err := newUUID()
		if err != nil {
			<-s.replicaCleanupSlots
			return
		}
		leaseOwner, err := newUUID()
		if err != nil {
			<-s.replicaCleanupSlots
			return
		}
		task, err := s.Store.ClaimReplicaCleanupTask(
			ctx, operationID, leaseOwner, time.Now().UTC(), replicaCleanupLeaseTTL,
		)
		if err != nil || task == nil {
			<-s.replicaCleanupSlots
			return
		}
		go func(task store.ReplicaCleanupTask) {
			defer func() { <-s.replicaCleanupSlots }()
			s.executeReplicaCleanupTask(ctx, task)
		}(*task)
	}
}

func (s *Server) executeReplicaCleanupTask(ctx context.Context, task store.ReplicaCleanupTask) {
	node, err := s.Store.GetNodeByID(ctx, task.NodeID)
	if err != nil || !nodeReadyForManagedOperation(node) ||
		(task.ReplicaKind == "archive" && node.Role != "storage") ||
		(task.ReplicaKind == "hot_standby" && node.Role != "compute") {
		s.retryReplicaCleanupTask(ctx, task, "node_unavailable")
		return
	}
	result, err := s.runAgentCommandWithOperation(
		ctx, node, "delete_snapshot_replica", protocol.DeleteReplicaRequest{
			CleanupID: task.ID, SnapshotID: task.SnapshotID, GlobalUserID: task.GlobalUserID,
			Handle: task.Handle, ReplicaKind: task.ReplicaKind,
		}, task.OperationID, replicaCleanupCommandTimeout,
	)
	if err != nil {
		code := safeReplicaCleanupFailureCode(agentCommandErrorCode(err))
		if code == "replica_identity_unavailable" {
			// Terminal: the target tree cannot be identity-verified (legacy
			// pre-identity-file replica).  Fail the task so the user's snapshot
			// and restore paths are not blocked forever, and surface the code.
			if failErr := s.Store.FailReplicaCleanupTask(
				ctx, task, code, time.Now().UTC(),
			); failErr != nil {
				// Keep the durable lease for expiry; a replay would fail the
				// same way and converge.
				return
			}
			return
		}
		s.retryReplicaCleanupTask(ctx, task, code)
		return
	}
	if !matchingReplicaCleanupReceipt(result.ReplicaCleanup, task) {
		s.retryReplicaCleanupTask(ctx, task, "receipt_mismatch")
		return
	}
	if err := s.Store.CompleteReplicaCleanupTask(
		ctx, task, result.ReplicaCleanup.Outcome, time.Now().UTC(),
	); err != nil {
		// The durable running lease is intentionally left for expiry. A new
		// worker will replay the idempotent, scope-bound Agent command.
		return
	}
}

func matchingReplicaCleanupReceipt(
	receipt *protocol.DeleteReplicaReceipt,
	task store.ReplicaCleanupTask,
) bool {
	if receipt == nil || receipt.CleanupID != task.ID || receipt.SnapshotID != task.SnapshotID ||
		receipt.GlobalUserID != task.GlobalUserID || receipt.Handle != task.Handle ||
		receipt.ReplicaKind != task.ReplicaKind || receipt.TargetNodeID != task.NodeID {
		return false
	}
	switch receipt.Outcome {
	case protocol.DeleteReplicaOutcomeDeleted, protocol.DeleteReplicaOutcomeAlreadyAbsent,
		protocol.DeleteReplicaOutcomeSuperseded:
		return true
	default:
		return false
	}
}

func (s *Server) retryReplicaCleanupTask(ctx context.Context, task store.ReplicaCleanupTask, code string) {
	_ = s.Store.RetryReplicaCleanupTask(
		ctx, task, code, time.Now().UTC(), replicaCleanupRetryDelay(task.Attempt),
	)
}

func safeReplicaCleanupFailureCode(code string) string {
	switch code {
	case "invalid_command_payload", "replica_cleanup_failed", "replica_identity_unavailable":
		return code
	default:
		return "agent_command_unavailable"
	}
}

func replicaCleanupRetryDelay(attempt int) time.Duration {
	delay := time.Minute
	for current := 1; current < attempt && delay < 6*time.Hour; current++ {
		delay *= 2
	}
	if delay > 6*time.Hour {
		return 6 * time.Hour
	}
	return delay
}
