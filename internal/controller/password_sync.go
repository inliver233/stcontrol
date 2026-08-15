package controller

import (
	"context"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func (s *Server) passwordSyncReconciler(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	s.reconcilePendingPasswords(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcilePendingPasswords(ctx)
		}
	}
}

func (s *Server) reconcilePendingPasswords(ctx context.Context) {
	s.passwordSyncMu.Lock()
	defer s.passwordSyncMu.Unlock()
	syncs, err := s.Store.ListPendingPasswordSyncs(ctx, 20, time.Now().UTC())
	if err != nil {
		syncs = nil
	}
	_, _ = s.deliverPasswordSyncs(ctx, syncs)
	removals, err := s.Store.ListPendingPasswordRemovals(ctx, 20, time.Now().UTC())
	if err != nil {
		removals = nil
	}
	_, _ = s.deliverPasswordRemovals(ctx, removals)
	// Best-effort hygiene: for users whose password changes were just processed,
	// drop the stored previous-password verifier once every node account has
	// converged (or the fallback window elapsed), so the old password stops
	// being accepted anywhere. Login correctness never depends on this call
	// because PasswordFallbackHash applies the same convergence checks.
	now := time.Now().UTC()
	for _, sync := range syncs {
		if ctx.Err() != nil {
			break
		}
		_ = s.Store.ClearPasswordFallbackIfConverged(ctx, sync.GlobalUserID, now)
	}
}

func (s *Server) deliverPasswordSyncs(
	ctx context.Context,
	syncs []store.PendingPasswordSync,
) (synced, pending int) {
	for _, sync := range syncs {
		if ctx.Err() != nil {
			return synced, len(syncs) - synced
		}
		node, err := s.Store.GetNodeByID(ctx, sync.NodeID)
		if err != nil || node == nil || !nodeReadyForManagedOperation(node) {
			pending++
			continue
		}
		_, err = s.runAgentCommand(ctx, node, "set_password", protocol.SetPasswordRequest{
			Handle: sync.LocalHandle, PasswordHash: sync.PasswordHash,
			PasswordSalt: sync.PasswordSalt, Version: sync.Version,
		}, 45*time.Second)
		if err != nil {
			_ = s.Store.MarkNodeAccountError(ctx, sync.GlobalUserID, sync.NodeID, time.Now().UTC())
			pending++
			continue
		}
		if err := s.Store.ActivateNodeAccount(
			ctx, sync.LegacyUserID, sync.GlobalUserID, sync.NodeID, "", time.Now().UTC(),
		); err != nil {
			pending++
			continue
		}
		synced++
	}
	return synced, pending
}

// deliverPasswordRemovals pushes a remove-password command to each reachable
// node carrying a pending password-removal intent (created when the password
// identity was unbound). Only after a node confirms the local password was
// removed is the intent cleared; offline nodes keep their intent (updated_at
// backoff) until they return and the worker delivers the removal.
func (s *Server) deliverPasswordRemovals(
	ctx context.Context,
	removals []store.PendingPasswordRemoval,
) (synced, pending int) {
	for _, removal := range removals {
		if ctx.Err() != nil {
			return synced, len(removals) - synced
		}
		node, err := s.Store.GetNodeByID(ctx, removal.NodeID)
		if err != nil || node == nil || !nodeReadyForManagedOperation(node) {
			pending++
			continue
		}
		_, err = s.runAgentCommand(ctx, node, "set_password", protocol.SetPasswordRequest{
			Handle: removal.LocalHandle, Version: removal.Version, Remove: true,
		}, 45*time.Second)
		if err != nil {
			_ = s.Store.MarkPasswordRemovalError(
				ctx, removal.GlobalUserID, removal.NodeID, removal.Version, time.Now().UTC(),
			)
			pending++
			continue
		}
		if err := s.Store.ActivatePasswordRemoval(
			ctx, removal.GlobalUserID, removal.NodeID, removal.Version, time.Now().UTC(),
		); err != nil {
			pending++
			continue
		}
		synced++
	}
	return synced, pending
}
