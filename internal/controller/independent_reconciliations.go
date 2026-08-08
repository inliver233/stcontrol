package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func (s *Server) independentReconciliationReconciler(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	s.reconcileIndependentWrites(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcileIndependentWrites(ctx)
		}
	}
}

func (s *Server) reconcileIndependentWrites(ctx context.Context) {
	items, err := s.Store.ListIndependentReconciliationWork(ctx, 50, time.Now().UTC())
	if err != nil {
		return
	}
	for _, item := range items {
		item := item
		switch item.Action {
		case "snapshot":
			select {
			case s.snapshotSlots <- struct{}{}:
				go func() {
					defer func() { <-s.snapshotSlots }()
					_ = s.createIndependentReconciliationSnapshot(ctx, item)
				}()
			default:
				return
			}
		case "restart":
			_ = s.Store.RestartIndependentReconciliationSnapshot(
				ctx, item.ID, item.Marker, "snapshot_terminal_failure",
				time.Now().UTC(), independentRetryDelay(item.Attempt),
			)
		case "complete":
			if err := s.Store.BeginIndependentReconciliationCompletion(
				ctx, item.ID, item.Marker, time.Now().UTC(),
			); err != nil {
				continue
			}
			go s.completeIndependentReconciliation(ctx, item)
		case "execute":
			// The shared durable snapshot reconciler owns every non-terminal
			// workflow and has its own lease. Avoid a second scheduler here.
		}
	}
}

func (s *Server) createIndependentReconciliationSnapshot(
	ctx context.Context,
	item store.IndependentReconciliationWork,
) error {
	target := s.pickStorageRepairTarget(ctx, item.NodeID)
	if target == nil {
		return fmt.Errorf("no pure storage target for independent reconciliation")
	}
	job := &store.BackupJob{
		UserID: item.LegacyUserID, SrcNodeID: item.NodeID, DstNodeID: target.ID,
		Trigger: "independent_reconciliation", Status: "pending",
	}
	if err := s.Store.CreateBackupJob(ctx, job); err != nil {
		return err
	}
	workflowID, err := newUUID()
	if err != nil {
		return err
	}
	operationID := deriveWorkflowOperationID(item.ID, fmt.Sprintf("snapshot:%s:%d", item.Marker, item.Attempt))
	snapshotID, err := newUUID()
	if err != nil {
		return err
	}
	capabilityID, err := newUUID()
	if err != nil {
		return err
	}
	capability := deriveTransferCapability(s.secretKey, capabilityID)
	capabilityHash := sha256.Sum256([]byte(capability))
	now := time.Now().UTC()
	workflow, err := s.Store.CreateSnapshotWorkflow(ctx, store.CreateSnapshotWorkflowParams{
		WorkflowID: workflowID, OperationID: operationID, SnapshotID: snapshotID,
		CapabilityID: capabilityID, CapabilityHash: capabilityHash[:],
		LegacyBackupJobID: job.ID, LegacyUserID: item.LegacyUserID, GlobalUserID: item.GlobalUserID,
		SourceNodeID: item.NodeID, TargetNodeID: target.ID, DestinationKind: "archive",
		IndependentReconciliationID: item.ID, IndependentMarker: item.Marker,
		CapabilityExpires: now.Add(snapshotCapabilityTTL), Now: now,
	})
	if err != nil {
		_ = s.Store.UpdateBackupJobStatus(ctx, job.ID, "failed", 0, 0, 0, "独立模式对账快照创建失败")
		return err
	}
	return s.executeSnapshotWorkflow(ctx, workflow.WorkflowID)
}

func (s *Server) completeIndependentReconciliation(
	ctx context.Context,
	item store.IndependentReconciliationWork,
) {
	node, err := s.Store.GetNodeByID(ctx, item.NodeID)
	if err != nil || node == nil {
		_ = s.Store.RetryIndependentReconciliationCompletion(
			ctx, item.ID, item.Marker, "source_node_unavailable", time.Now().UTC(),
			independentRetryDelay(item.Attempt),
		)
		return
	}
	operationID := deriveWorkflowOperationID(
		item.ID, fmt.Sprintf("complete:%s:%d", item.Marker, item.Attempt),
	)
	_, err = s.runAgentCommandWithOperation(ctx, node, "complete_independent_sync", protocol.CompleteIndependentSyncRequest{
		OperationID: operationID, Handle: item.Handle, Marker: item.Marker,
	}, operationID, 90*time.Second)
	if err != nil {
		_ = s.Store.RetryIndependentReconciliationCompletion(
			ctx, item.ID, item.Marker, "adapter_completion_failed", time.Now().UTC(),
			independentRetryDelay(item.Attempt),
		)
		return
	}
	if err := s.Store.CompleteIndependentReconciliation(
		ctx, item.ID, item.Marker, time.Now().UTC(),
	); err != nil {
		return
	}
	_ = s.Store.Audit(ctx, "system", "independent-reconciliation-complete",
		fmt.Sprintf("node:%d/user:%d", item.NodeID, item.GlobalUserID), nil)
}

func independentRetryDelay(attempt int) time.Duration {
	delay := 15 * time.Second
	for current := 0; current < attempt && delay < 5*time.Minute; current++ {
		delay *= 2
	}
	if delay > 5*time.Minute {
		return 5 * time.Minute
	}
	return delay
}
