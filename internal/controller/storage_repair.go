package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

const storageRepairTaskLeaseTTL = 8 * time.Hour

func storageRepairMaxAttempts(cfg *config.ControllerConfig) int {
	maxAttempts := 3
	if cfg != nil && cfg.Backup.RetryMax > 0 {
		maxAttempts = cfg.Backup.RetryMax
	}
	if maxAttempts > 8 {
		maxAttempts = 8
	}
	return maxAttempts
}

func (s *Server) newStorageRepairExecutionParams(
	now time.Time,
) (store.CreateStorageRepairExecutionParams, error) {
	if s == nil || len(s.secretKey) == 0 || !isUUID(s.workflowWorkerID) {
		return store.CreateStorageRepairExecutionParams{}, fmt.Errorf("storage repair worker identity unavailable")
	}
	ids := make([]string, 6)
	for i := range ids {
		id, err := newUUID()
		if err != nil {
			return store.CreateStorageRepairExecutionParams{}, err
		}
		ids[i] = id
	}
	capability := deriveTransferCapability(s.secretKey, ids[5])
	capabilityHash := sha256.Sum256([]byte(capability))
	return store.CreateStorageRepairExecutionParams{
		ExecutionID: ids[0], LeaseOwner: ids[1],
		WorkflowID: ids[2], OperationID: ids[3], SnapshotID: ids[4], CapabilityID: ids[5],
		CapabilityHash: capabilityHash[:], CapabilityExpires: now.Add(snapshotCapabilityTTL),
		LeaseTTL: storageRepairTaskLeaseTTL, MaxAttempts: storageRepairMaxAttempts(s.Cfg), Now: now,
	}, nil
}

// scheduleStorageRepairs is called by the existing 30-second scheduler. It
// returns whether the repair pass was healthy, not whether work was launched.
// Only a healthy pass permits the caller to run ordinary offline backups; those
// backups independently skip users with an active repair intent. This keeps DB
// errors fail-closed without starving unrelated offline backups when there is
// simply no due repair or all execution slots are occupied.
func (s *Server) scheduleStorageRepairs(ctx context.Context) bool {
	if s == nil || s.Store == nil || s.snapshotSlots == nil {
		return false
	}
	now := time.Now().UTC()
	maxAttempts := storageRepairMaxAttempts(s.Cfg)
	if _, err := s.Store.ReconcileStorageRepairTasks(ctx, now, maxAttempts); err != nil {
		return false
	}
	// Closing the new-operation gate must not strand bytes reserved by an
	// already terminal workflow; only creation of new intents/claims is gated.
	if s.checkNewOperations() != nil {
		return false
	}
	if _, err := s.Store.ScheduleStorageRepairTasks(ctx, now); err != nil {
		return false
	}

	for {
		select {
		case s.snapshotSlots <- struct{}{}:
		default:
			return true
		}
		params, err := s.newStorageRepairExecutionParams(time.Now().UTC())
		if err != nil {
			<-s.snapshotSlots
			return false
		}
		execution, err := s.Store.ClaimAndCreateStorageRepair(ctx, params)
		if err != nil || execution == nil {
			<-s.snapshotSlots
			if err != nil {
				return false
			}
			return true
		}
		go func(workflowID string) {
			defer func() { <-s.snapshotSlots }()
			_ = s.executeSnapshotWorkflow(ctx, workflowID)
			_, _ = s.Store.ReconcileStorageRepairTasks(
				ctx, time.Now().UTC(), storageRepairMaxAttempts(s.Cfg),
			)
		}(execution.WorkflowID)
	}
}
