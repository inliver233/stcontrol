package controller

import (
	"context"
	"errors"
	"net/http"

	"stcontrol/internal/protocol"
)

var errControlPlaneNotReady = errors.New("control plane is not ready for new operations")

func (s *Server) setControlPlaneGate(blocked bool, reason string) {
	s.controlPlaneMu.Lock()
	defer s.controlPlaneMu.Unlock()
	s.newOperationsBlocked = blocked
	if blocked {
		s.controlPlaneReason = reason
	} else {
		s.controlPlaneReason = ""
	}
}

func (s *Server) controlPlaneGate() (bool, string) {
	s.controlPlaneMu.RLock()
	defer s.controlPlaneMu.RUnlock()
	return s.newOperationsBlocked, s.controlPlaneReason
}

func (s *Server) refreshControlPlaneGate(ctx context.Context) error {
	ready, err := s.Store.IsControlPlaneReady(ctx)
	if err != nil {
		s.setControlPlaneGate(true, "control_state_unavailable")
		return err
	}
	if ready {
		s.setControlPlaneGate(false, "")
	} else {
		s.setControlPlaneGate(true, "node_reconciliation_required")
	}
	return nil
}

func (s *Server) requireNewOperations(w http.ResponseWriter) bool {
	blocked, _ := s.controlPlaneGate()
	if !blocked {
		return true
	}
	w.Header().Set("Retry-After", "15")
	protocol.WriteError(w, http.StatusServiceUnavailable, "总控正在恢复对账，暂不接受新登录、选点、注册或备份")
	return false
}

func (s *Server) checkNewOperations() error {
	blocked, _ := s.controlPlaneGate()
	if blocked {
		return errControlPlaneNotReady
	}
	return nil
}
