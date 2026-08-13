package controller

import (
	"context"
	"time"
)

// importScanReconciler optionally performs unattended legacy-account scans of
// compute nodes that have never been scanned or whose latest scan is older
// than the configured interval (R16).  It is disabled by default so operators
// keep full control; when enabled it is bounded per run and uses the same
// idempotent scan path as the admin button.
func (s *Server) importScanReconciler(ctx context.Context) {
	interval := 6 * time.Hour
	maxPerRun := 2
	if s != nil && s.Cfg != nil {
		policy := s.Cfg.ImportScan
		if policy.IntervalSec > 0 {
			interval = time.Duration(policy.IntervalSec) * time.Second
		}
		if policy.MaxNodesPerRun > 0 {
			maxPerRun = policy.MaxNodesPerRun
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	s.reconcileImportScans(ctx, maxPerRun)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcileImportScans(ctx, maxPerRun)
		}
	}
}

func (s *Server) reconcileImportScans(ctx context.Context, maxPerRun int) {
	if s == nil || s.Cfg == nil || !s.Cfg.ImportScan.Enabled || s.Store == nil {
		return
	}
	if s.checkNewOperations() != nil {
		return
	}
	olderThan := time.Now().UTC().Add(-time.Duration(s.Cfg.ImportScan.IntervalSec) * time.Second)
	ids, err := s.Store.ListUnscannedComputeNodes(ctx, olderThan, maxPerRun)
	if err != nil {
		return
	}
	for _, nodeID := range ids {
		if ctx.Err() != nil {
			return
		}
		node, err := s.Store.GetNodeByID(ctx, nodeID)
		if err != nil || !nodeReadyForManagedOperation(node) {
			continue
		}
		attemptID, err := newUUID()
		if err != nil {
			return
		}
		// Same idempotent inventory scan used by the admin button; failures are
		// simply retried on the next interval (no durable state needed).
		if _, err := s.scanAccountInventory(ctx, node, attemptID); err != nil {
			continue
		}
	}
}
