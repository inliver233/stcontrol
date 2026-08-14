package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ai_adoption.go persists decision-④ adoption effects (migration 0048).
// Effects are a reversible input cache for deterministic read paths only:
// the Agent never sees them, they are never Store truth, and rows expire with
// their advisory (15 minutes by default).

// AIAdoptionEffect mirrors ai_adoption_effects.
type AIAdoptionEffect struct {
	ID         int64           `json:"id"`
	RequestID  int64           `json:"request_id"`
	AdvisoryID int64           `json:"advisory_id"`
	EffectKind string          `json:"effect_kind"`
	TargetRef  string          `json:"target_ref"`
	Payload    json.RawMessage `json:"payload"`
	ExpiresAt  time.Time       `json:"expires_at"`
	CreatedAt  time.Time       `json:"created_at"`
}

// InsertAIAdoptionEffect durably records one applied adoption effect. It is
// idempotent per (request, effect kind): replays never duplicate rows.
func (s *Store) InsertAIAdoptionEffect(ctx context.Context, effect AIAdoptionEffect) error {
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO ai_adoption_effects (
			request_id, advisory_id, effect_kind, target_ref, payload, expires_at
		) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (request_id, effect_kind) DO NOTHING`,
		effect.RequestID, effect.AdvisoryID, effect.EffectKind, effect.TargetRef,
		[]byte(effect.Payload), effect.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert ai adoption effect: %w", err)
	}
	return nil
}

// GetLatestAIAdoptionEffect returns the newest unexpired effect of one kind
// with the given target, or nil when none is live.
func (s *Store) GetLatestAIAdoptionEffect(ctx context.Context, kind, target string, now time.Time) (*AIAdoptionEffect, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var e AIAdoptionEffect
	var payload []byte
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, request_id, advisory_id, effect_kind, target_ref, payload, expires_at, created_at
		FROM ai_adoption_effects
		WHERE effect_kind = $1 AND target_ref = $2 AND expires_at > $3
		ORDER BY created_at DESC
		LIMIT 1`, kind, target, now).
		Scan(&e.ID, &e.RequestID, &e.AdvisoryID, &e.EffectKind, &e.TargetRef,
			&payload, &e.ExpiresAt, &e.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get latest ai adoption effect: %w", err)
	}
	e.Payload = json.RawMessage(payload)
	return &e, nil
}

// ListActiveAIAdoptionEffects returns every unexpired effect of one kind
// (e.g. all live alert notes), newest first per target.
func (s *Store) ListActiveAIAdoptionEffects(ctx context.Context, kind string, now time.Time) ([]AIAdoptionEffect, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT DISTINCT ON (target_ref)
			id, request_id, advisory_id, effect_kind, target_ref, payload, expires_at, created_at
		FROM ai_adoption_effects
		WHERE effect_kind = $1 AND expires_at > $2
		ORDER BY target_ref, created_at DESC`, kind, now)
	if err != nil {
		return nil, fmt.Errorf("list active ai adoption effects: %w", err)
	}
	defer rows.Close()
	out := make([]AIAdoptionEffect, 0)
	for rows.Next() {
		var e AIAdoptionEffect
		var payload []byte
		if err := rows.Scan(&e.ID, &e.RequestID, &e.AdvisoryID, &e.EffectKind, &e.TargetRef,
			&payload, &e.ExpiresAt, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Payload = json.RawMessage(payload)
		out = append(out, e)
	}
	return out, rows.Err()
}

// StoredAIAdvisory is one persisted advisory decoded for adoption flows.
type StoredAIAdvisory struct {
	AdvisoryID    int64
	RequestID     int64
	Action        string
	CandidateRefs []string
	Confidence    float64
	Abstain       bool
	ReasonSummary string
	EvidenceRefs  []string
	RiskFlags     []string
	ExpiresAt     time.Time
}

// GetAIAdvisoryByRequestID loads the (single) advisory stored for a request.
func (s *Store) GetAIAdvisoryByRequestID(ctx context.Context, requestID int64) (*StoredAIAdvisory, error) {
	var adv StoredAIAdvisory
	var candidates, evidence, risks []byte
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, request_id, action, candidate_refs, confidence, abstain,
		       reason_summary, evidence_refs, risk_flags, expires_at
		FROM ai_advisories WHERE request_id = $1`, requestID).
		Scan(&adv.AdvisoryID, &adv.RequestID, &adv.Action, &candidates, &adv.Confidence,
			&adv.Abstain, &adv.ReasonSummary, &evidence, &risks, &adv.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("get ai advisory by request: %w", err)
	}
	_ = json.Unmarshal(candidates, &adv.CandidateRefs)
	_ = json.Unmarshal(evidence, &adv.EvidenceRefs)
	_ = json.Unmarshal(risks, &adv.RiskFlags)
	if adv.CandidateRefs == nil {
		adv.CandidateRefs = []string{}
	}
	if adv.EvidenceRefs == nil {
		adv.EvidenceRefs = []string{}
	}
	if adv.RiskFlags == nil {
		adv.RiskFlags = []string{}
	}
	return &adv, nil
}

// GetAIAdvisoryRequest loads one request row by id.
func (s *Store) GetAIAdvisoryRequest(ctx context.Context, requestID int64) (*AIAdvisoryRequest, error) {
	var r AIAdvisoryRequest
	var obs []byte
	var errorCode sql.NullString
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, task_type, schema_version, prompt_version, model_id,
		       observation_digest, observation_json, dedup_key,
		       requested_at, deadline_at, state, error_code
		FROM ai_advisory_requests WHERE id = $1`, requestID).
		Scan(&r.ID, &r.TaskType, &r.SchemaVersion, &r.PromptVersion,
			&r.ModelID, &r.ObservationDigest, &obs, &r.DedupKey,
			&r.RequestedAt, &r.DeadlineAt, &r.State, &errorCode)
	if err != nil {
		return nil, fmt.Errorf("get ai advisory request: %w", err)
	}
	r.ErrorCode = errorCode.String
	if len(obs) > 0 {
		r.ObservationJSON = json.RawMessage(obs)
	}
	return &r, nil
}

// CountAIAdvisoryOutcomesSince counts outcome rows of one decision since a
// time (auto_adopted adoption-rate visibility for the admin status panel).
func (s *Store) CountAIAdvisoryOutcomesSince(ctx context.Context, decision string, since time.Time) (int64, error) {
	var n int64
	err := s.DB.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM ai_advisory_outcomes
		WHERE decision = $1 AND decided_at >= $2`, decision, since).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count ai advisory outcomes: %w", err)
	}
	return n, nil
}

// AIOrderingHint is the decoded payload of an ordering effect row.
type AIOrderingHint struct {
	Order []int64 `json:"order"`
}

// AIOrderingHintFrom decodes an effect payload; ok is false for malformed rows.
func AIOrderingHintFrom(e *AIAdoptionEffect) (AIOrderingHint, bool) {
	if e == nil {
		return AIOrderingHint{}, false
	}
	var hint AIOrderingHint
	if err := json.Unmarshal(e.Payload, &hint); err != nil || len(hint.Order) == 0 {
		return AIOrderingHint{}, false
	}
	return hint, true
}
