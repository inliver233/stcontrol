package controller

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"stcontrol/internal/ai"
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
// plus per-task totals and decision-④ adoption visibility (read-only).
func (s *Server) handleAdminAIStatus(w http.ResponseWriter, r *http.Request) {
	policy := s.Cfg.AISupervisor
	counts, err := s.Store.CountAIAdvisoryRequestsByTask(r.Context())
	if err != nil {
		counts = map[string]int64{}
	}
	autoAdopted, err := s.Store.CountAIAdvisoryOutcomesSince(r.Context(), "auto_adopted", time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		autoAdopted = 0
	}
	accepted, err := s.Store.CountAIAdvisoryOutcomesSince(r.Context(), "accepted", time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		accepted = 0
	}
	latestSummary := ""
	if effect, err := s.Store.GetLatestAIAdoptionEffect(r.Context(), "inspection_summary", "cluster", time.Now().UTC()); err == nil && effect != nil {
		var payload struct {
			Note string `json:"note"`
		}
		if json.Unmarshal(effect.Payload, &payload) == nil {
			latestSummary = payload.Note
		}
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"enabled":                   policy.Enabled,
		"mode":                      policy.Mode,
		"provider":                  policy.Provider,
		"model":                     policy.Model,
		"task_counts":               counts,
		"auto_adopt_min_confidence": policy.AutoAdoptMinConfidence,
		"auto_adopted_24h":          autoAdopted,
		"accepted_24h":              accepted,
		"latest_cluster_summary":    latestSummary,
	})
}

// handleAdminAdoptAIAdvisory lets an operator manually apply one stored
// advisory through the same deterministic executor and hard gates as the
// auto_low_risk mode (decision ④ human-confirm path). Advisories without an
// executor (disaster/conflict/import/recovery suggestions) are refused;
// nothing here can bypass the validator whitelist.
func (s *Server) handleAdminAdoptAIAdvisory(w http.ResponseWriter, r *http.Request) {
	requestID, err := strconv.ParseInt(chi.URLParam(r, "requestID"), 10, 64)
	if err != nil || requestID <= 0 {
		writeAdminError(w, http.StatusBadRequest, "invalid_request_id")
		return
	}
	adv, err := s.Store.GetAIAdvisoryByRequestID(r.Context(), requestID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeAdminError(w, http.StatusNotFound, "advisory_not_found")
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "load_advisory_failed")
		return
	}
	if adv.ExpiresAt.Before(time.Now().UTC()) {
		writeAdminError(w, http.StatusConflict, "advisory_expired")
		return
	}
	req, err := s.Store.GetAIAdvisoryRequest(r.Context(), requestID)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "load_request_failed")
		return
	}
	task, err := ai.ParseTaskType(req.TaskType)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "unknown_task")
		return
	}
	// Rebuild the validated advisory view the gates reason over.
	parsed := &ai.Advisory{
		SchemaVersion: ai.SchemaVersion, TaskType: req.TaskType,
		ObservationID: observationIDFromJSON(req.ObservationJSON),
		Action:        adv.Action, CandidateRefs: adv.CandidateRefs,
		Confidence: adv.Confidence, Abstain: adv.Abstain,
		ReasonSummary: adv.ReasonSummary, EvidenceRefs: adv.EvidenceRefs,
		RiskFlags: adv.RiskFlags,
	}
	// Manual adoption still passes both gates: the executor only exists for
	// reversible kinds, and anything the validator marks human-confirm-only
	// with no executor is refused below.
	if adv.Abstain || !ai.AutoAdoptable(task, parsed) || ai.HumanConfirmRequired(task, parsed) {
		writeAdminError(w, http.StatusUnprocessableEntity, "advisory_not_adoptable")
		return
	}
	res, aerr := (&aiAdopter{srv: s}).Adopt(r.Context(), ai.AIAdvisoryRequestLike{
		ID: req.ID, TaskType: req.TaskType, ObservationJSON: req.ObservationJSON,
	}, parsed, adv.AdvisoryID)
	if aerr != nil {
		if errors.Is(aerr, ai.ErrAdoptionNotExecutable) {
			writeAdminError(w, http.StatusUnprocessableEntity, "adoption_not_executable")
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "adoption_failed")
		return
	}
	_ = s.Store.InsertAIAdvisoryOutcome(r.Context(), struct {
		RequestID        int64
		Decision         string
		ValidatorCode    string
		ActorType        string
		DeterministicRef string
		ObservedOutcome  string
	}{
		RequestID: requestID, Decision: "accepted", ActorType: "admin",
		DeterministicRef: res.EffectRef, ObservedOutcome: res.ObservedOutcome,
	})
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"ok": true, "deterministic_ref": res.EffectRef, "observed_outcome": res.ObservedOutcome,
	})
}

// writeAdminJSON writes an admin-scoped JSON response.
func writeAdminJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// observationIDFromJSON extracts obs_… from a stored observation payload so
// the adoption executor can re-derive pseudonymous refs deterministically.
func observationIDFromJSON(raw json.RawMessage) string {
	var obs struct {
		ObservationID string `json:"observation_id"`
	}
	_ = json.Unmarshal(raw, &obs)
	return obs.ObservationID
}

// writeAdminError writes a minimal error envelope for admin endpoints.
func writeAdminError(w http.ResponseWriter, status int, code string) {
	writeAdminJSON(w, status, map[string]string{"error": code})
}
