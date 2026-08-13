package controller

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// handleAdminSetStorageRepairTarget lets an administrator steer the storage
// repair target for a user (Round 26).  target_node_id=0 clears the override
// and returns the task to deterministic auto-selection.
func (s *Server) handleAdminSetStorageRepairTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetNodeID int64 `json:"target_node_id"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || req.TargetNodeID < 0 {
		protocol.WriteError(w, http.StatusBadRequest, "目标节点无效")
		return
	}
	uuid := chi.URLParam(r, "uuid")
	user, err := s.Store.GetUserByUUID(r.Context(), uuid)
	if err != nil || user == nil || user.GlobalID <= 0 {
		protocol.WriteError(w, http.StatusNotFound, "用户不存在")
		return
	}
	now := time.Now().UTC()
	if err := s.Store.SetStorageRepairPreferredTarget(
		r.Context(), user.GlobalID, req.TargetNodeID, now,
	); err != nil {
		if err == sql.ErrNoRows {
			protocol.WriteError(w, http.StatusNotFound, "该用户当前没有待执行的存储修复任务")
			return
		}
		if err == store.ErrInvalidStorageRepairExecution {
			protocol.WriteError(w, http.StatusBadRequest, "目标必须是纯存储节点")
			return
		}
		protocol.WriteError(w, http.StatusServiceUnavailable, "设置修复目标失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
