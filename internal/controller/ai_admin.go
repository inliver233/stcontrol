package controller

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// ai_admin.go exposes the read-only advisory view for the admin console
// (ai接入优化方案详细.md §7.1). AI suggestions never add action buttons; the
// existing deterministic APIs remain the only way to change anything.

// handleAdminListAIAdvisories returns the most recent validated advisories.
func (s *Server) handleAdminListAIAdvisories(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	rows, err := s.Store.ListRecentAIAdvisories(r.Context(), limit)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "list_ai_advisories_failed")
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"advisories": rows})
}

// handleAdminListAIAdvisoryRequests pages through AI request metadata.
func (s *Server) handleAdminListAIAdvisoryRequests(w http.ResponseWriter, r *http.Request) {
	var cursor int64
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			cursor = parsed
		}
	}
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	taskType := r.URL.Query().Get("task_type")
	rows, err := s.Store.ListAIAdvisoryRequestsPage(r.Context(), cursor, limit, taskType)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "list_ai_advisory_requests_failed")
		return
	}
	nextCursor := int64(0)
	if len(rows) == limit {
		nextCursor = rows[len(rows)-1].ID
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"requests": rows, "next_cursor": nextCursor})
}

// handleAdminAIStatus returns whether the AI supervisor is configured/enabled
// plus per-task totals (read-only).
func (s *Server) handleAdminAIStatus(w http.ResponseWriter, r *http.Request) {
	policy := s.Cfg.AISupervisor
	counts, err := s.Store.CountAIAdvisoryRequestsByTask(r.Context())
	if err != nil {
		counts = map[string]int64{}
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"enabled":     policy.Enabled,
		"mode":        policy.Mode,
		"provider":    policy.Provider,
		"model":       policy.Model,
		"task_counts": counts,
	})
}

// writeAdminJSON writes an admin-scoped JSON response.
func writeAdminJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeAdminError writes a minimal error envelope for admin endpoints.
func writeAdminError(w http.ResponseWriter, status int, code string) {
	writeAdminJSON(w, status, map[string]string{"error": code})
}
