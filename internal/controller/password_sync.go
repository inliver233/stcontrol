package controller

import (
	"context"
	"time"

	"stcontrol/internal/protocol"
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
		return
	}
	for _, sync := range syncs {
		if ctx.Err() != nil {
			return
		}
		node, err := s.Store.GetNodeByID(ctx, sync.NodeID)
		if err != nil || node == nil || node.Status != "online" {
			continue
		}
		_, err = s.runAgentCommand(ctx, node, "set_password", protocol.SetPasswordRequest{
			Handle: sync.LocalHandle, PasswordHash: sync.PasswordHash,
			PasswordSalt: sync.PasswordSalt, Version: sync.Version,
		}, 45*time.Second)
		if err != nil {
			_ = s.Store.MarkNodeAccountError(ctx, sync.GlobalUserID, sync.NodeID, time.Now().UTC())
			continue
		}
		_ = s.Store.ActivateNodeAccount(
			ctx, sync.LegacyUserID, sync.GlobalUserID, sync.NodeID, "", time.Now().UTC(),
		)
	}
}
