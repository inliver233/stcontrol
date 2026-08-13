package controller

import (
	"net/http"
	"strconv"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// handleAdminListControllerBackups lists controller disaster backup runs,
// newest first, paged by a before cursor (Unix seconds on created_at).
func (s *Server) handleAdminListControllerBackups(w http.ResponseWriter, r *http.Request) {
	limit := 50
	var err error
	if raw := r.URL.Query().Get("limit"); raw != "" { limit, err = strconv.Atoi(raw) }
	if err != nil || limit <= 0 || limit > 100 {
		protocol.WriteError(w, http.StatusBadRequest, "分页参数无效");
		return
	}
	var beforeAt time.Time
	if raw := r.URL.Query().Get("before"); raw != "" {
		secs, parseErr := strconv.ParseInt(raw, 10, 64);
		if parseErr != nil || secs < 0 {
			protocol.WriteError(w, http.StatusBadRequest, "分页参数无效");
			return
		}
		beforeAt = time.Unix(secs, 0).UTC()
	}
	state := r.URL.Query().Get("state")
	params := store.ListControllerDisasterBackupPageParams{Limit: limit, BeforeAt: beforeAt, State: state}
	runs, err := s.Store.ListControllerDisasterBackupsPage(r.Context(), params)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "查询失败");
		return
	}
	hasMore := false;
	nextCursor := int64(0);
	if len(runs) == limit {
		hasMore = true;
		if len(runs) > 0 { nextCursor = runs[len(runs)-1].CreatedAt.Unix() }
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"backups": runs, "has_more": hasMore, "next_cursor": nextCursor,
	});
}

// handleAdminTriggerControllerBackup immediately runs the reconciler pass; it
// is idempotent (fresh successful or in-flight runs suppress a new schedule).
func (s *Server) handleAdminTriggerControllerBackup(w http.ResponseWriter, r *http.Request) {
	if !s.controllerBackupPolicy().Enabled {
		protocol.WriteError(w, http.StatusConflict, "总控灾备自动备份已禁用");
		return
	}
	s.reconcileControllerBackupOnce(r.Context())
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true});
}
