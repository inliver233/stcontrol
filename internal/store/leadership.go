package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const controllerAdvisoryLockID int64 = 0x5354434f4e54524c // "STCONTRL"

// ControllerLeadership pins a PostgreSQL advisory lock to one dedicated
// connection. Losing that connection immediately invalidates leadership.
type ControllerLeadership struct {
	conn *sql.Conn
}

func (s *Store) TryAcquireControllerLeadership(ctx context.Context) (*ControllerLeadership, bool, error) {
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return nil, false, err
	}
	var acquired bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, controllerAdvisoryLockID).Scan(&acquired); err != nil {
		_ = conn.Close()
		return nil, false, err
	}
	if !acquired {
		_ = conn.Close()
		return nil, false, nil
	}
	return &ControllerLeadership{conn: conn}, true, nil
}

func (leadership *ControllerLeadership) Close() error {
	if leadership == nil || leadership.conn == nil {
		return nil
	}
	_, _ = leadership.conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, controllerAdvisoryLockID)
	return leadership.conn.Close()
}

func (leadership *ControllerLeadership) Watch(ctx context.Context) error {
	if leadership == nil || leadership.conn == nil {
		return fmt.Errorf("controller leadership is unavailable")
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			var one int
			if err := leadership.conn.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil || one != 1 {
				return fmt.Errorf("controller leadership connection lost: %w", err)
			}
		}
	}
}

// PromoteControllerEpoch is called only while the caller owns the leadership
// advisory lock. It fences every browser credential and ticket from the old
// generation while preserving Agent credentials long enough to reconcile and
// rotate them over their authenticated outbound channels.
func (s *Store) PromoteControllerEpoch(ctx context.Context, source string, now time.Time) (int64, error) {
	if source == "" || len(source) > 128 {
		return 0, fmt.Errorf("invalid controller promotion source")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var current, signingVersion int64
	if err := tx.QueryRowContext(ctx, `
		SELECT generation,signing_key_version FROM controller_epochs
		WHERE state='active' FOR UPDATE`).Scan(&current, &signingVersion); err != nil {
		return 0, err
	}
	var operationID, rebuildID string
	if err := tx.QueryRowContext(ctx,
		`SELECT gen_random_uuid()::text,gen_random_uuid()::text`).
		Scan(&operationID, &rebuildID); err != nil {
		return 0, err
	}
	next := current + 1
	if _, err := tx.ExecContext(ctx, `
		UPDATE controller_epochs SET state='revoked',revoked_at=$2
		WHERE generation=$1 AND state='active'`, current, now); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO controller_epochs (
		  generation,operation_id,controller_id,source,state,signing_key_version,activated_at
		) VALUES ($1,$2,gen_random_uuid(),$3,'active',$4,$5)`,
		next, operationID, source, signingVersion+1, now); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE controller_sessions SET revoked_at=COALESCE(revoked_at,$1)
		WHERE revoked_at IS NULL`, now); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE control_tickets SET revoked_at=COALESCE(revoked_at,$1)
		WHERE consumed_at IS NULL AND revoked_at IS NULL`, now); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE agent_credential_rotations SET state='revoked'
		WHERE state='pending' AND controller_generation=$1`, current); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE controller_rebuild_operations SET state='failed',
		  error_code='superseded_by_generation',completed_at=$1,updated_at=$1
		WHERE state IN ('reconciling','ready_with_deferred')`, now); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO controller_rebuild_operations (
		  id,operation_id,generation,previous_generation,source,state,
		  total_nodes,reconciled_nodes,started_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,'reconciling',0,0,$6,$6)`,
		rebuildID, operationID, next, current, source, now); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO controller_rebuild_nodes (
		  rebuild_id,node_id,previous_credential_generation,state,updated_at
		)
		SELECT $1,node.id,credential.controller_generation,
		  CASE WHEN node.connectivity_state='online' THEN 'awaiting_heartbeat' ELSE 'deferred' END,
		  $2
		FROM nodes node
		JOIN LATERAL (
		  SELECT controller_generation FROM agent_credentials
		  WHERE node_id=node.id AND revoked_at IS NULL
		    AND (expires_at IS NULL OR expires_at>$2)
		  ORDER BY credential_version DESC LIMIT 1
		) credential ON true
		WHERE node.role IN ('compute','storage')
		  AND node.operational_state NOT IN ('decommissioned','retired')`,
		rebuildID, now); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE nodes SET controller_generation=0,status='offline',connectivity_state='offline',
		  capacity_state='unknown',capacity_reason_code='controller_generation_promoted',
		  capacity_pressure_since=NULL,capacity_recovery_since=NULL,
		  capacity_cooldown_until=NULL,capacity_changed_at=$2
		WHERE id IN (
		  SELECT node_id FROM controller_rebuild_nodes WHERE rebuild_id=$1
		) OR (connectivity_state='online' AND controller_generation<>$3)`,
		rebuildID, now, next); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE controller_rebuild_operations rebuild SET
		  total_nodes=progress.total_nodes,
		  reconciled_nodes=progress.reconciled_nodes,
		  state=CASE
		    WHEN progress.total_nodes=progress.reconciled_nodes THEN 'succeeded'
		    WHEN progress.total_nodes=progress.ready_nodes THEN 'ready_with_deferred'
		    ELSE 'reconciling' END,
		  completed_at=CASE WHEN progress.total_nodes=progress.reconciled_nodes
		    THEN $2::timestamptz ELSE NULL END,
		  updated_at=$2::timestamptz
		FROM (
		  SELECT count(*)::int AS total_nodes,
		    count(*) FILTER (WHERE state='reconciled')::int AS reconciled_nodes,
		    count(*) FILTER (WHERE state IN ('reconciled','deferred'))::int AS ready_nodes
		  FROM controller_rebuild_nodes
		  WHERE rebuild_id=$1
		) progress WHERE rebuild.id=$1`, rebuildID, now); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  actor_type,action,target_type,target_id,operation_id,
		  controller_generation,outcome,detail
		) VALUES (
		  'controller','controller-generation-promoted','controller_epoch',$1::text,
		  $2,$1::bigint,'succeeded',jsonb_build_object(
		    'previous_generation',$3::bigint,'source',$4::text,
		    'rebuild_id',$5::text))`, next, operationID, current, source, rebuildID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}
