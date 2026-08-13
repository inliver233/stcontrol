package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// ---------- R22: audit read side ----------
//
// The audit events are persisted as durable facts on every mutating workflow.
// Previously the console had no read side at all (audit was write-only).  This
// adds a paged, filterable query for administrators so security reviews can
// inspect who did what, when, and with which outcome — without exposing
// payloads (details remain JSONB, rendered by the admin UI).

// AuditEvent is one row of the durable audit trail.
type AuditEvent struct {
	ID                   int64           `json:"id"`
	OccurredAt           time.Time       `json:"occurred_at"`
	ActorType            string          `json:"actor_type"`
	ActorID              string          `json:"actor_id"`
	Action               string          `json:"action"`
	TargetType           string          `json:"target_type"`
	TargetID             string          `json:"target_id"`
	OperationID          sql.NullString  `json:"operation_id"`
	ControllerGeneration sql.NullInt64   `json:"controller_generation"`
	Outcome              string          `json:"outcome"`
	Detail               json.RawMessage `json:"detail"`
}

// ListAuditEventsPageParams mirrors the admin pagination pattern (newest first,
// cursor by id, optional filters).
type ListAuditEventsPageParams struct {
	BeforeID   int64
	Limit      int
	ActorType  string
	Action     string
	TargetType string
	Outcome    string
}

// ListAuditEventsPage returns one page of audit events, newest first.
func (s *Store) ListAuditEventsPage(
	ctx context.Context, p ListAuditEventsPageParams,
) ([]AuditEvent, error) {
	if p.Limit <= 0 || p.Limit > 200 {
		p.Limit = 50
	}
	query := `SELECT id,occurred_at,actor_type,COALESCE(actor_id,''),action,
	  target_type,COALESCE(target_id,''),operation_id::text,
	  controller_generation,outcome,COALESCE(detail,'{}'::jsonb)
	FROM audit_events WHERE ($1=0 OR id<$1)`
	args := []any{p.BeforeID}
	if p.ActorType != "" {
		args = append(args, p.ActorType)
		query += fmt.Sprintf(" AND actor_type=$%d", len(args))
	}
	if p.Action != "" {
		args = append(args, p.Action)
		query += fmt.Sprintf(" AND action=$%d", len(args))
	}
	if p.TargetType != "" {
		args = append(args, p.TargetType)
		query += fmt.Sprintf(" AND target_type=$%d", len(args))
	}
	if p.Outcome != "" {
		args = append(args, p.Outcome)
		query += fmt.Sprintf(" AND outcome=$%d", len(args))
	}
	query += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args)+1)
	args = append(args, p.Limit)
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditEvent, 0)
	for rows.Next() {
		var event AuditEvent
		var detail []byte
		if err := rows.Scan(
			&event.ID, &event.OccurredAt, &event.ActorType, &event.ActorID,
			&event.Action, &event.TargetType, &event.TargetID, &event.OperationID,
			&event.ControllerGeneration, &event.Outcome, &detail,
		); err != nil {
			return nil, err
		}
		event.Detail = detail
		out = append(out, event)
	}
	return out, rows.Err()
}
