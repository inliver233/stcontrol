package controller

import (
	"net/http"
	"strconv"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// handleAdminListAuditEvents exposes the durable audit trail to
// administrators (R22 read side). Filters are strict and bounded; details are
// returned as JSONB so the console can render them without leaking payloads
// into logs.
func (s *Server) handleAdminListAuditEvents(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 200 {
			protocol.WriteError(w, http.StatusBadRequest, "分页参数无效")
			return
		}
		limit = parsed
	}
	var beforeID int64
	if raw := r.URL.Query().Get("before"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			protocol.WriteError(w, http.StatusBadRequest, "分页参数无效")
			return
		}
		beforeID = parsed
	}
	params := store.ListAuditEventsPageParams{
		BeforeID: beforeID, Limit: limit,
		ActorType:  r.URL.Query().Get("actor_type"),
		Action:     r.URL.Query().Get("action"),
		TargetType: r.URL.Query().Get("target_type"),
		Outcome:    r.URL.Query().Get("outcome"),
	}
	events, err := s.Store.ListAuditEventsPage(r.Context(), params)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "读取审计记录失败")
		return
	}
	hasMore := false
	nextCursor := int64(0)
	if len(events) == limit {
		hasMore = true
		if len(events) > 0 {
			nextCursor = events[len(events)-1].ID
		}
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"events": events, "has_more": hasMore, "next_cursor": nextCursor,
	})
}
