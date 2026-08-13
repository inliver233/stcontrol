package store

import (
	"context"
	"database/sql"
	"time"
)

// ai_observations.go adds the aggregate read queries the AI 监管层 phase
// workers need to build redacted observations. All queries return only
// allowlisted, aggregated facts (no identifiers, paths, keys or content).

// NodeControlModeEventSummary is one redacted control-mode transition fact.
type NodeControlModeEventSummary struct {
	NodeRef    int64
	Reported   string
	Desired    string
	ReasonCode string
	ObservedAt time.Time
}

// ListRecentNodeControlModeEvents returns the most recent control-mode
// transitions across all nodes (bounded, newest first).
func (s *Store) ListRecentNodeControlModeEvents(ctx context.Context, limit int) ([]NodeControlModeEventSummary, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT node_id, reported_mode, desired_mode, reason_code, observed_at
		FROM node_control_mode_events
		ORDER BY observed_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeControlModeEventSummary
	for rows.Next() {
		var e NodeControlModeEventSummary
		if err := rows.Scan(&e.NodeRef, &e.Reported, &e.Desired, &e.ReasonCode, &e.ObservedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ConflictAggregate is the per-conflict redacted metadata summary.
type ConflictAggregate struct {
	UserRef          int64
	State            string
	SourceCount      int64
	FileCount        int64
	TotalBytes       int64
	HasReadyEvidence bool
	UpdatedAt        time.Time
}

// ListOpenConflictAggregates returns metadata aggregates for non-terminal
// conflicts (bounded, newest first). No paths, digests or content.
func (s *Store) ListOpenConflictAggregates(ctx context.Context, limit int) ([]ConflictAggregate, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT c.user_id, c.state,
		       COUNT(s.conflict_id) AS source_count,
		       COALESCE(SUM(s.file_count), 0) AS file_count,
		       COALESCE(SUM(s.total_bytes), 0) AS total_bytes,
		       MAX(s.captured_at) AS captured_at,
		       c.updated_at
		FROM replica_conflicts c
		LEFT JOIN replica_conflict_sources s ON s.conflict_id = c.id
		WHERE c.state IN ('detected','inspecting','awaiting_decision','resolving')
		GROUP BY c.id, c.user_id, c.state, c.updated_at
		ORDER BY c.updated_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConflictAggregate
	for rows.Next() {
		var a ConflictAggregate
		var capturedAt sql.NullTime
		if err := rows.Scan(&a.UserRef, &a.State, &a.SourceCount, &a.FileCount,
			&a.TotalBytes, &capturedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		a.HasReadyEvidence = capturedAt.Valid
		out = append(out, a)
	}
	return out, rows.Err()
}

// RestoreWorkflowSummary is one redacted restore workflow fact (from the
// shared workflows table; restore_operations itself has no state).
type RestoreWorkflowSummary struct {
	WorkflowID string
	State      string
	Attempt    int
	ErrorCode  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ListRecentRestoreWorkflowSummaries returns the most recent restore workflows.
func (s *Store) ListRecentRestoreWorkflowSummaries(ctx context.Context, limit int) ([]RestoreWorkflowSummary, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id::text, state, attempt, error_code, created_at, updated_at
		FROM workflows
		WHERE workflow_type = 'restore'
		ORDER BY updated_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RestoreWorkflowSummary
	for rows.Next() {
		var w RestoreWorkflowSummary
		var code sql.NullString
		if err := rows.Scan(&w.WorkflowID, &w.State, &w.Attempt, &code, &w.CreatedAt, &w.UpdatedAt); err != nil {
			return nil, err
		}
		w.ErrorCode = code.String
		out = append(out, w)
	}
	return out, rows.Err()
}

// ImportCandidateSummary is one redacted import candidate fact.
type ImportCandidateSummary struct {
	BatchID     string
	Telemetry   string // adapter|directory_fallback
	AccountKind string
	Resolution  string
	SizeBucket  string
}

// ListUnresolvedImportCandidates returns unresolved candidates from the latest
// batches (bounded, newest first). Handles are NOT returned; the controller
// derives a per-observation pseudonym from batch_id.
func (s *Store) ListUnresolvedImportCandidates(ctx context.Context, limit int) ([]ImportCandidateSummary, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT batch_id::text, source, account_kind, resolution_state,
		       CASE
		         WHEN size_bytes <= 1024 THEN 'tiny'
		         WHEN size_bytes <= 1048576 THEN 'small'
		         WHEN size_bytes <= 1073741824 THEN 'medium'
		         ELSE 'large'
		       END AS size_bucket
		FROM account_import_candidates
		WHERE resolution_state IN ('claim_required','oauth_unmatched','identity_conflict','recovery_required')
		ORDER BY created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ImportCandidateSummary
	for rows.Next() {
		var c ImportCandidateSummary
		if err := rows.Scan(&c.BatchID, &c.Telemetry, &c.AccountKind, &c.Resolution, &c.SizeBucket); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountOpenAlertsBySeverity returns open alert counts per severity.
func (s *Store) CountOpenAlertsBySeverity(ctx context.Context) (map[string]int64, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT severity, COUNT(*) FROM alerts
		WHERE state = 'open'
		GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var severity string
		var n int64
		if err := rows.Scan(&severity, &n); err != nil {
			return nil, err
		}
		out[severity] = n
	}
	return out, rows.Err()
}
