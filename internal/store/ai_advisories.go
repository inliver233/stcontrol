package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// AI 监管层（Phase 0）持久事实。所有 AI 建议都是只读 advisory，不是 Store
// truth；Agent 不信任这些表。observation 只存脱敏投影或 digest。

// AIAdvisoryRequest mirrors ai_advisory_requests. json tags define the
// admin HTTP contract: the React AI page reads snake_case keys (advisory
// tables previously serialized Go field names, which the UI never matched).
type AIAdvisoryRequest struct {
	ID                int64           `json:"id"`
	TaskType          string          `json:"task_type"`
	SchemaVersion     string          `json:"schema_version"`
	PromptVersion     string          `json:"prompt_version"`
	ModelID           string          `json:"model_id"`
	ObservationDigest []byte          `json:"-"`
	ObservationJSON   json.RawMessage `json:"-"`
	DedupKey          string          `json:"dedup_key"`
	RequestedAt       time.Time       `json:"requested_at"`
	DeadlineAt        time.Time       `json:"deadline_at"`
	State             string          `json:"state"`
	ErrorCode         string          `json:"error_code"`
}

// AIAdvisory mirrors ai_advisories.
type AIAdvisory struct {
	ID                int64
	RequestID         int64
	Action            string
	CandidateRefs     []string
	Confidence        float64
	Abstain           bool
	ReasonSummary     string
	EvidenceRefs      []string
	RiskFlags         []string
	RequestedObs      []string
	RawResponseDigest []byte
	ExpiresAt         time.Time
	CreatedAt         time.Time
}

// InsertAIAdvisoryRequest durably records a queued AI request. Idempotent on
// dedup_key: a second insert for the same fact returns the existing row.
func (s *Store) InsertAIAdvisoryRequest(
	ctx context.Context,
	req AIAdvisoryRequest,
) (int64, error) {
	observationJSON := []byte("null")
	if len(req.ObservationJSON) > 0 {
		observationJSON = req.ObservationJSON
	}
	var id int64
	err := s.DB.QueryRowContext(ctx, `
		INSERT INTO ai_advisory_requests (
			task_type, schema_version, prompt_version, model_id,
			observation_digest, observation_json, dedup_key, deadline_at, state
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (dedup_key) DO UPDATE SET dedup_key = EXCLUDED.dedup_key
		RETURNING id`,
		req.TaskType, req.SchemaVersion, req.PromptVersion, req.ModelID,
		req.ObservationDigest, observationJSON, req.DedupKey, req.DeadlineAt, req.State,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert ai advisory request: %w", err)
	}
	return id, nil
}

// ListDueAIAdvisoryRequests returns queued requests whose deadline has not
// passed, oldest first, bounded for one worker pass.
func (s *Store) ListDueAIAdvisoryRequests(ctx context.Context, limit int) ([]AIAdvisoryRequest, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, task_type, schema_version, prompt_version, model_id,
		       observation_digest, observation_json, dedup_key,
		       requested_at, deadline_at, state, error_code
		FROM ai_advisory_requests
		WHERE state = 'queued' AND deadline_at > now()
		ORDER BY requested_at ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AIAdvisoryRequest, 0)
	for rows.Next() {
		var r AIAdvisoryRequest
		var obs []byte
		var errorCode sql.NullString
		if err := rows.Scan(&r.ID, &r.TaskType, &r.SchemaVersion, &r.PromptVersion,
			&r.ModelID, &r.ObservationDigest, &obs, &r.DedupKey,
			&r.RequestedAt, &r.DeadlineAt, &r.State, &errorCode); err != nil {
			return nil, err
		}
		r.ErrorCode = errorCode.String
		if len(obs) > 0 {
			r.ObservationJSON = json.RawMessage(obs)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkAIAdvisoryRequestState transitions a request to succeeded/failed.
func (s *Store) MarkAIAdvisoryRequestState(
	ctx context.Context,
	id int64,
	state string,
	errorCode string,
) error {
	res, err := s.DB.ExecContext(ctx, `
		UPDATE ai_advisory_requests
		SET state = $2, error_code = $3
		WHERE id = $1 AND state = 'queued'`, id, state, errorCode)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	return nil
}

// InsertAIAdvisory records a validated advisory for a request.
func (s *Store) InsertAIAdvisory(ctx context.Context, adv AIAdvisory) (int64, error) {
	candidates, _ := json.Marshal(adv.CandidateRefs)
	evidence, _ := json.Marshal(adv.EvidenceRefs)
	risks, _ := json.Marshal(adv.RiskFlags)
	requested, _ := json.Marshal(adv.RequestedObs)
	var id int64
	err := s.DB.QueryRowContext(ctx, `
		INSERT INTO ai_advisories (
			request_id, action, candidate_refs, confidence, abstain,
			reason_summary, evidence_refs, risk_flags, requested_obs,
			raw_response_digest, expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING id`,
		adv.RequestID, adv.Action, candidates, adv.Confidence, adv.Abstain,
		adv.ReasonSummary, evidence, risks, requested,
		adv.RawResponseDigest, adv.ExpiresAt,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert ai advisory: %w", err)
	}
	return id, nil
}

// InsertAIAdvisoryOutcome records accept/reject/show outcomes (the black box).
func (s *Store) InsertAIAdvisoryOutcome(ctx context.Context, outcome struct {
	RequestID        int64
	Decision         string
	ValidatorCode    string
	ActorType        string
	DeterministicRef string
	ObservedOutcome  string
}) error {
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO ai_advisory_outcomes (
			request_id, decision, validator_code, actor_type,
			deterministic_ref, observed_outcome
		) VALUES ($1,$2,$3,$4,$5,$6)`,
		outcome.RequestID, outcome.Decision, outcome.ValidatorCode,
		outcome.ActorType, outcome.DeterministicRef, outcome.ObservedOutcome)
	if err != nil {
		return fmt.Errorf("insert ai advisory outcome: %w", err)
	}
	return nil
}

// AIAdvisorySummary is the admin-facing join of one validated advisory with
// its request metadata. json tags are the HTTP contract read by the React AI
// page (previously the anonymous struct serialized Go field names like
// AdvisoryID/CreatedAt, which the UI's snake_case reads rendered as
// Invalid Date / NaN%).
type AIAdvisorySummary struct {
	RequestID     int64     `json:"request_id"`
	AdvisoryID    int64     `json:"advisory_id"`
	TaskType      string    `json:"task_type"`
	ModelID       string    `json:"model_id"`
	Action        string    `json:"action"`
	Confidence    float64   `json:"confidence"`
	Abstain       bool      `json:"abstain"`
	ReasonSummary string    `json:"reason_summary"`
	CreatedAt     time.Time `json:"created_at"`
}

// ListRecentAIAdvisories returns the most recent validated advisories joined
// with their request metadata, newest first.
func (s *Store) ListRecentAIAdvisories(ctx context.Context, limit int) ([]AIAdvisorySummary, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT a.request_id, a.id, r.task_type, r.model_id, a.action,
		       a.confidence, a.abstain, a.reason_summary, a.created_at
		FROM ai_advisories a
		JOIN ai_advisory_requests r ON r.id = a.request_id
		ORDER BY a.created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AIAdvisorySummary, 0)
	for rows.Next() {
		var v AIAdvisorySummary
		if err := rows.Scan(&v.RequestID, &v.AdvisoryID, &v.TaskType, &v.ModelID,
			&v.Action, &v.Confidence, &v.Abstain, &v.ReasonSummary, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ListAIAdvisoryRequestsPage pages through request metadata for the admin UI.
func (s *Store) ListAIAdvisoryRequestsPage(ctx context.Context, cursor int64, limit int, taskType string) ([]AIAdvisoryRequest, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, task_type, schema_version, prompt_version, model_id,
		       observation_digest, observation_json, dedup_key,
		       requested_at, deadline_at, state, error_code
		FROM ai_advisory_requests
		WHERE ($1 = 0 OR id < $1) AND ($2 = '' OR task_type = $2)
		ORDER BY id DESC
		LIMIT $3`, cursor, taskType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AIAdvisoryRequest, 0)
	for rows.Next() {
		var r AIAdvisoryRequest
		var obs []byte
		var errorCode sql.NullString
		if err := rows.Scan(&r.ID, &r.TaskType, &r.SchemaVersion, &r.PromptVersion,
			&r.ModelID, &r.ObservationDigest, &obs, &r.DedupKey,
			&r.RequestedAt, &r.DeadlineAt, &r.State, &errorCode); err != nil {
			return nil, err
		}
		r.ErrorCode = errorCode.String
		if len(obs) > 0 {
			r.ObservationJSON = json.RawMessage(obs)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountAIAdvisoryRequestsByTask returns per-task-type totals (admin overview).
func (s *Store) CountAIAdvisoryRequestsByTask(ctx context.Context) (map[string]int64, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT task_type, COUNT(*) FROM ai_advisory_requests GROUP BY task_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var task string
		var n int64
		if err := rows.Scan(&task, &n); err != nil {
			return nil, err
		}
		out[task] = n
	}
	return out, rows.Err()
}

// ExpireOverdueAIAdvisoryRequests moves queued requests whose deadline has
// passed into the terminal 'superseded' state (error_code='deadline_passed').
// Without this sweep such rows lingered in 'queued' forever because
// ListDueAIAdvisoryRequests filters deadline_at > now(). The 0046 state CHECK
// already allows 'superseded'.
func (s *Store) ExpireOverdueAIAdvisoryRequests(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE ai_advisory_requests SET state='superseded',error_code='deadline_passed'
		WHERE state='queued' AND deadline_at<=$1`, now)
	if err != nil {
		return 0, fmt.Errorf("expire overdue ai advisory requests: %w", err)
	}
	return result.RowsAffected()
}
