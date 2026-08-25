package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const (
	accountImportScanLeaseTTL = 2 * time.Minute
	accountImportResumeEvery  = 2 * time.Second
)

// importScanReconciler has two independent duties: unfinished workflows are
// always resumed, while creating periodic workflows remains operator
// controlled by import_scan.enabled. Accepted pages live in PostgreSQL, so a
// browser disconnect, reverse-proxy 502, or Controller restart cannot discard
// progress.
func (s *Server) importScanReconciler(ctx context.Context) {
	if s == nil || s.Store == nil || !isUUID(s.workflowWorkerID) {
		return
	}
	interval := 6 * time.Hour
	maxPerRun := 2
	enabled := false
	if s.Cfg != nil {
		enabled = s.Cfg.ImportScan.Enabled
		if s.Cfg.ImportScan.IntervalSec > 0 {
			interval = time.Duration(s.Cfg.ImportScan.IntervalSec) * time.Second
		}
		if s.Cfg.ImportScan.MaxNodesPerRun > 0 {
			maxPerRun = s.Cfg.ImportScan.MaxNodesPerRun
		}
	}
	_ = s.Store.AdoptAccountImportScans(ctx, time.Now().UTC())
	if enabled {
		s.scheduleImportScans(ctx, interval, maxPerRun)
	}
	resumeTicker := time.NewTicker(accountImportResumeEvery)
	defer resumeTicker.Stop()
	scheduleTicker := time.NewTicker(interval)
	defer scheduleTicker.Stop()
	s.resumeImportScans(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-resumeTicker.C:
			s.resumeImportScans(ctx)
		case <-scheduleTicker.C:
			if enabled {
				s.scheduleImportScans(ctx, interval, maxPerRun)
			}
		}
	}
}

func (s *Server) scheduleImportScans(ctx context.Context, interval time.Duration, maxPerRun int) {
	if s.checkNewOperations() != nil {
		return
	}
	ids, err := s.Store.ListUnscannedComputeNodes(ctx, time.Now().UTC().Add(-interval), maxPerRun)
	if err != nil {
		return
	}
	for _, nodeID := range ids {
		operationID, err := newUUID()
		if err != nil {
			return
		}
		_, _ = s.Store.CreateAccountImportScan(ctx, store.CreateAccountImportScanParams{
			OperationID: operationID, NodeID: nodeID, Now: time.Now().UTC(),
		})
	}
}

func (s *Server) resumeImportScans(ctx context.Context) {
	if s.checkNewOperations() != nil {
		return
	}
	available := cap(s.importScanSlots) - len(s.importScanSlots)
	if available <= 0 {
		return
	}
	ids, err := s.Store.ListDueAccountImportScans(ctx, time.Now().UTC(), available)
	if err != nil {
		return
	}
	for _, operationID := range ids {
		select {
		case s.importScanSlots <- struct{}{}:
			go func(id string) {
				defer func() { <-s.importScanSlots }()
				s.runAccountImportScanStep(ctx, id)
			}(operationID)
		default:
			return
		}
	}
}

func (s *Server) runAccountImportScanStep(ctx context.Context, operationID string) {
	now := time.Now().UTC()
	claimed, err := s.Store.ClaimAccountImportScan(
		ctx, operationID, s.workflowWorkerID, now, accountImportScanLeaseTTL,
	)
	if err != nil || !claimed {
		return
	}
	defer func() {
		_ = s.Store.ReleaseAccountImportScan(context.Background(), operationID, s.workflowWorkerID)
	}()
	workflow, err := s.Store.GetAccountImportScan(ctx, operationID)
	if err != nil || workflow == nil {
		return
	}
	if workflow.State == store.AccountImportScanInventoryComplete {
		s.finishAccountImportScan(ctx, workflow)
		return
	}
	node, err := s.Store.GetNodeByID(ctx, workflow.NodeID)
	if err != nil || !nodeReadyForManagedOperation(node) {
		s.deferAccountImportScan(ctx, workflow.OperationID, 30*time.Second)
		return
	}
	payload := protocol.ScanExistingPageRequest{
		Cursor: workflow.Cursor, Limit: accountInventoryPageUsers,
	}
	if workflow.InventoryRevision.Valid {
		payload.InventoryRevision = workflow.InventoryRevision.String
	}
	commandOperationID := deriveWorkflowOperationID(
		workflow.OperationID,
		fmt.Sprintf("durable-scan-page-%04d:g%d", workflow.CompletedPages, workflow.ControllerGeneration),
	)
	if _, err := s.enqueueAgentCommandAtGeneration(
		ctx, node, "scan_existing_page", payload, commandOperationID,
		workflow.ControllerGeneration, true,
	); err != nil {
		s.retryAccountImportScan(ctx, workflow, "enqueue_unavailable", err)
		return
	}
	result, err := s.waitAgentCommandSummary(ctx, commandOperationID, accountInventoryPollWait)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return
	}
	if err != nil || result.InventoryPage == nil {
		s.retryAccountImportScan(ctx, workflow, "adapter_unavailable", err)
		return
	}
	if err := validateDurableInventoryPage(workflow, *result.InventoryPage); err != nil {
		s.retryAccountImportScan(ctx, workflow, "invalid_inventory_page", err)
		return
	}
	if err := s.Store.AppendAccountImportScanPage(
		ctx, workflow.OperationID, s.workflowWorkerID, *result.InventoryPage, time.Now().UTC(),
	); err != nil {
		return
	}
}

func validateDurableInventoryPage(
	workflow *store.AccountImportScanWorkflow,
	page protocol.ScanExistingPageResult,
) error {
	if workflow == nil {
		return store.ErrInvalidAccountImport
	}
	var existing []protocol.ScanExistingUser
	if err := json.Unmarshal(workflow.InventoryUsers, &existing); err != nil {
		return err
	}
	scan := accountInventoryScan{users: existing}
	if workflow.InventoryRevision.Valid {
		scan.revision = workflow.InventoryRevision.String
		scan.total = int(workflow.TotalUsers.Int64)
		if len(existing) > 0 {
			scan.source = existing[0].Source
		}
	}
	_, err := scan.appendPage(workflow.Cursor, accountInventoryPageUsers, page)
	return err
}

func (s *Server) finishAccountImportScan(ctx context.Context, workflow *store.AccountImportScanWorkflow) {
	var users []protocol.ScanExistingUser
	if err := json.Unmarshal(workflow.InventoryUsers, &users); err != nil ||
		!workflow.TotalUsers.Valid || len(users) != int(workflow.TotalUsers.Int64) {
		s.deferAccountImportScan(ctx, workflow.OperationID, 30*time.Second)
		return
	}
	node, err := s.Store.GetNodeByID(ctx, workflow.NodeID)
	if err != nil || node == nil {
		s.deferAccountImportScan(ctx, workflow.OperationID, 30*time.Second)
		return
	}
	batchID := deriveWorkflowOperationID(workflow.OperationID, "account-import-batch")
	params, err := s.buildAccountImportBatch(
		ctx, node, batchID, workflow.OperationID, workflow.CreatedByAdminID.Int64,
		users, time.Now().UTC(),
	)
	if err != nil {
		s.deferAccountImportScan(ctx, workflow.OperationID, 30*time.Second)
		return
	}
	imported, err := s.Store.IngestAccountImportBatch(ctx, params)
	if err != nil || imported == nil {
		s.deferAccountImportScan(ctx, workflow.OperationID, 30*time.Second)
		return
	}
	if err := s.Store.CompleteAccountImportScan(
		ctx, workflow.OperationID, s.workflowWorkerID, imported.Batch.ID, time.Now().UTC(),
	); err != nil {
		return
	}
	detail, _ := json.Marshal(map[string]any{
		"node_id": workflow.NodeID, "candidates": imported.Batch.CandidateCount,
		"auto_linked": imported.Batch.AutoLinkedCount,
		"unresolved":  imported.Batch.UnresolvedCount,
		"automatic":   !workflow.CreatedByAdminID.Valid,
	})
	_ = s.Store.Audit(ctx, "system", "account-import-scan", node.Name, detail)
}

func (s *Server) deferAccountImportScan(ctx context.Context, operationID string, delay time.Duration) {
	now := time.Now().UTC()
	_ = s.Store.DeferAccountImportScan(
		ctx, operationID, s.workflowWorkerID, now.Add(delay), now,
	)
}

func (s *Server) retryAccountImportScan(
	ctx context.Context,
	workflow *store.AccountImportScanWorkflow,
	code string,
	cause error,
) {
	if workflow.Attempt >= 2 && (code == "adapter_unavailable" || code == "invalid_inventory_page") {
		now := time.Now().UTC()
		_ = s.Store.ResetAccountImportScan(
			ctx, workflow.OperationID, s.workflowWorkerID, code, now.Add(30*time.Second), now,
		)
		return
	}
	delay := 5 * time.Second
	for attempt := 0; attempt < workflow.Attempt && delay < 2*time.Minute; attempt++ {
		delay *= 2
	}
	if delay > 2*time.Minute {
		delay = 2 * time.Minute
	}
	summary := ""
	if cause != nil {
		summary = cause.Error()
	}
	now := time.Now().UTC()
	_ = s.Store.ScheduleAccountImportScanRetry(
		ctx, workflow.OperationID, s.workflowWorkerID, code, summary, now.Add(delay), now,
	)
}
