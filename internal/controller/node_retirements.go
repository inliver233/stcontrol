package controller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"stcontrol/internal/store"
)

const (
	nodeRetirementLeaseTTL = 2 * time.Minute
	nodeRetirementPoll     = 10 * time.Second
)

func (s *Server) nodeRetirementReconciler(ctx context.Context) {
	ticker := time.NewTicker(nodeRetirementPoll)
	defer ticker.Stop()
	s.resumeNodeRetirements(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.resumeNodeRetirements(ctx)
		}
	}
}

func (s *Server) resumeNodeRetirements(ctx context.Context) {
	ids, err := s.Store.ListSchedulableNodeRetirementIDs(ctx, 100)
	if err != nil {
		return
	}
	for _, id := range ids {
		select {
		case s.nodeRetirementSlots <- struct{}{}:
			go func(retirementID string) {
				defer func() { <-s.nodeRetirementSlots }()
				_ = s.executeNodeRetirement(ctx, retirementID)
			}(id)
		default:
			return
		}
	}
}

func (s *Server) executeNodeRetirement(ctx context.Context, retirementID string) error {
	if s.workflowWorkerID == "" {
		return fmt.Errorf("node retirement worker identity unavailable")
	}
	leaseOwnerID, err := newUUID()
	if err != nil {
		return err
	}
	eventID, err := newUUID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	claimed, err := s.Store.ClaimNodeRetirement(
		ctx, retirementID, leaseOwnerID, eventID, now, nodeRetirementLeaseTTL,
	)
	if err != nil || !claimed {
		return err
	}
	deferred := false
	defer func() {
		if deferred {
			return
		}
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Store.ReleaseNodeRetirement(releaseCtx, retirementID, leaseOwnerID)
	}()

	item, err := s.Store.GetNextNodeRetirementItem(ctx, retirementID, now)
	if err != nil {
		return err
	}
	if item == nil {
		finalEventID, err := newUUID()
		if err != nil {
			return err
		}
		_, err = s.Store.FinalizeNodeRetirement(ctx, retirementID, finalEventID, time.Now().UTC())
		return err
	}
	if item.UserBusy {
		return s.Store.RetryNodeRetirementItem(
			ctx, item.ID, "waiting_offline", "user_activity_not_drained", false,
			time.Now().UTC(), nodeRetirementRetryDelay(item.Attempt),
		)
	}

	switch item.ItemKind {
	case "authoritative_home", "archive_replica":
		deferred, err = s.reconcileNodeRetirementSnapshot(ctx, *item, leaseOwnerID)
		return err
	case "redundant_replica", "account_metadata":
		err := s.Store.CompleteNodeRetirementReplicaItem(ctx, item.ID, time.Now().UTC())
		if errors.Is(err, store.ErrNodeRetirementState) {
			return s.Store.RetryNodeRetirementItem(
				ctx, item.ID, "blocked", "replica_protection_unavailable", false,
				time.Now().UTC(), nodeRetirementRetryDelay(item.Attempt),
			)
		}
		return err
	default:
		return s.Store.RetryNodeRetirementItem(
			ctx, item.ID, "blocked", "retirement_item_kind_invalid", false,
			time.Now().UTC(), nodeRetirementRetryDelay(item.Attempt),
		)
	}
}

func (s *Server) reconcileNodeRetirementSnapshot(
	ctx context.Context,
	item store.NodeRetirementItemExecution,
	leaseOwnerID string,
) (bool, error) {
	if item.WorkflowID != "" {
		switch item.WorkflowState {
		case "succeeded":
			var completeErr error
			if item.ItemKind == "authoritative_home" {
				completeErr = s.Store.CompleteNodeRetirementHomeMigration(
					ctx, item.ID, item.WorkflowID, time.Now().UTC(),
				)
			} else {
				completeErr = s.Store.CompleteNodeRetirementReplicaItem(ctx, item.ID, time.Now().UTC())
			}
			if errors.Is(completeErr, store.ErrSnapshotUserActive) {
				return false, s.Store.RetryNodeRetirementItem(
					ctx, item.ID, "waiting_offline", "user_activity_not_drained", false,
					time.Now().UTC(), nodeRetirementRetryDelay(item.Attempt),
				)
			}
			if errors.Is(completeErr, store.ErrNodeRetirementState) {
				return false, s.Store.RetryNodeRetirementItem(
					ctx, item.ID, "blocked", "retirement_promotion_unavailable", false,
					time.Now().UTC(), nodeRetirementRetryDelay(item.Attempt),
				)
			}
			return false, completeErr
		case "failed", "cancelled":
			return false, s.Store.RetryNodeRetirementItem(
				ctx, item.ID, "retry_wait", "snapshot_workflow_terminal", true,
				time.Now().UTC(), nodeRetirementRetryDelay(item.Attempt),
			)
		default:
			err := s.Store.DeferNodeRetirement(
				ctx, item.RetirementID, leaseOwnerID, "snapshot_workflow_running",
				time.Now().UTC(), nodeRetirementPoll,
			)
			return err == nil, err
		}
	}

	source, target, destinationKind, trigger, code := s.selectNodeRetirementSnapshotPath(ctx, item)
	if source == nil || target == nil {
		if code == "" {
			code = "retirement_target_unavailable"
		}
		return false, s.Store.RetryNodeRetirementItem(
			ctx, item.ID, "blocked", code, false, time.Now().UTC(), nodeRetirementRetryDelay(item.Attempt),
		)
	}
	if err := s.createNodeRetirementSnapshotWorkflow(
		ctx, item, source.ID, target.ID, destinationKind, trigger,
	); err != nil {
		return false, s.Store.RetryNodeRetirementItem(
			ctx, item.ID, "retry_wait", "snapshot_workflow_create_failed", false,
			time.Now().UTC(), nodeRetirementRetryDelay(item.Attempt),
		)
	}
	// Snapshot execution has its own durable lease and shared bounded worker.
	// Releasing this short retirement lease prevents an Agent transfer from
	// monopolizing the retirement coordinator or creating a second executor.
	return false, nil
}

func (s *Server) selectNodeRetirementSnapshotPath(
	ctx context.Context,
	item store.NodeRetirementItemExecution,
) (source, target *store.Node, destinationKind, trigger, failureCode string) {
	nodes, err := s.Store.ListNodes(ctx)
	if err != nil {
		return nil, nil, "", "", "retirement_inventory_unavailable"
	}
	switch item.ItemKind {
	case "authoritative_home":
		source = findNode(nodes, item.NodeID)
		if !nodeCanServeRetirementSnapshot(source, item.NodeID) {
			return nil, nil, "", "", "retirement_source_unavailable"
		}
		for _, candidate := range orderedRetirementTargets(nodes, "compute", item.NodeID, 0) {
			available, err := s.Store.RetirementTargetAvailable(ctx, item.UserID, candidate.ID, item.Handle)
			if err == nil && available {
				return source, candidate, "hot_standby", "node_retirement", ""
			}
		}
		return source, nil, "", "", "retirement_target_unavailable"
	case "archive_replica":
		source = findNode(nodes, item.HomeNodeID)
		if !nodeReadyForManagedOperation(source) || source.Role != "compute" {
			return nil, nil, "", "", "retirement_home_unavailable"
		}
		targets := orderedRetirementTargets(nodes, "storage", item.NodeID, item.HomeNodeID)
		if len(targets) == 0 {
			return source, nil, "", "", "retirement_target_unavailable"
		}
		return source, targets[0], "archive", "node_retirement_storage", ""
	default:
		return nil, nil, "", "", "retirement_item_kind_invalid"
	}
}

func (s *Server) createNodeRetirementSnapshotWorkflow(
	ctx context.Context,
	item store.NodeRetirementItemExecution,
	sourceNodeID, targetNodeID int64,
	destinationKind, trigger string,
) error {
	workflowID := deriveWorkflowOperationID(item.ID, fmt.Sprintf("workflow:%d", item.Attempt))
	operationID := deriveWorkflowOperationID(item.ID, fmt.Sprintf("operation:%d", item.Attempt))
	snapshotID := deriveWorkflowOperationID(item.ID, fmt.Sprintf("snapshot:%d", item.Attempt))
	capabilityID := deriveWorkflowOperationID(item.ID, fmt.Sprintf("capability:%d", item.Attempt))
	capability := deriveTransferCapability(s.secretKey, capabilityID)
	capabilityHash := sha256.Sum256([]byte(capability))
	now := time.Now().UTC()
	_, err := s.Store.CreateSnapshotWorkflow(ctx, store.CreateSnapshotWorkflowParams{
		WorkflowID: workflowID, OperationID: operationID, SnapshotID: snapshotID,
		CapabilityID: capabilityID, CapabilityHash: capabilityHash[:],
		LegacyUserID: item.LegacyUserID, GlobalUserID: item.UserID,
		SourceNodeID: sourceNodeID, TargetNodeID: targetNodeID,
		DestinationKind: destinationKind, RetirementItemID: item.ID, RetirementTrigger: trigger,
		CapabilityExpires: now.Add(snapshotCapabilityTTL), Now: now,
	})
	return err
}

func orderedRetirementTargets(nodes []*store.Node, role string, excluded ...int64) []*store.Node {
	excludedIDs := make(map[int64]struct{}, len(excluded))
	for _, id := range excluded {
		excludedIDs[id] = struct{}{}
	}
	var targets []*store.Node
	for _, node := range nodes {
		if node == nil || node.Role != role || node.TransferURL == "" || !nodeAcceptsNewData(node) {
			continue
		}
		if _, skip := excludedIDs[node.ID]; skip {
			continue
		}
		if role == "storage" && !node.IsBackupTarget {
			continue
		}
		targets = append(targets, node)
	}
	for left := 0; left < len(targets); left++ {
		for right := left + 1; right < len(targets); right++ {
			if retirementTargetLess(targets[right], targets[left]) {
				targets[left], targets[right] = targets[right], targets[left]
			}
		}
	}
	return targets
}

func retirementTargetLess(left, right *store.Node) bool {
	if left.CapacityState != right.CapacityState {
		return left.CapacityState == "open"
	}
	return left.ID < right.ID
}

func findNode(nodes []*store.Node, id int64) *store.Node {
	for _, node := range nodes {
		if node != nil && node.ID == id {
			return node
		}
	}
	return nil
}

func nodeCanServeRetirementSnapshot(node *store.Node, retirementNodeID int64) bool {
	if node == nil || node.ID != retirementNodeID || node.Role != "compute" ||
		node.ConnectivityState != "online" || node.CompatibilityState != "compatible" ||
		node.ControlMode != "managed" || node.DesiredControlMode != "managed" {
		return false
	}
	return node.OperationalState == "draining" || node.OperationalState == "retiring"
}

func nodeRetirementRetryDelay(attempt int) time.Duration {
	delay := 15 * time.Second
	for current := 0; current < attempt && delay < 5*time.Minute; current++ {
		delay *= 2
	}
	if delay > 5*time.Minute {
		return 5 * time.Minute
	}
	return delay
}
