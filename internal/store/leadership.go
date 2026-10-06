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

// MarkCleanShutdown records that this process is stopping on purpose while it
// still leads generation. It runs on the leadership connection itself and
// requires that connection's session to hold the advisory lock, so a process
// that has already lost leadership (and might still be running) can never
// mark its generation as resumable.
func (leadership *ControllerLeadership) MarkCleanShutdown(ctx context.Context, generation int64, now time.Time) (bool, error) {
	if leadership == nil || leadership.conn == nil {
		return false, fmt.Errorf("controller leadership is unavailable")
	}
	if generation <= 0 {
		return false, fmt.Errorf("invalid controller generation")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// PostgreSQL reports a bigint advisory key as classid (high 32 bits) and
	// objid (low 32 bits) with objsubid 1.
	key := uint64(controllerAdvisoryLockID)
	lockHigh, lockLow := int64(key>>32), int64(key&0xffffffff)
	result, err := leadership.conn.ExecContext(ctx, `
		UPDATE controller_epochs SET clean_shutdown_at=$2
		WHERE generation=$1 AND state='active'
		  AND EXISTS (
		    SELECT 1 FROM pg_locks
		    WHERE locktype='advisory' AND granted AND pid=pg_backend_pid()
		      AND classid=$3::bigint::oid AND objid=$4::bigint::oid AND objsubid=1)`,
		generation, now, lockHigh, lockLow)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

// ResumeControllerEpoch continues the active generation when its previous
// leader recorded a clean shutdown no more than maxGap ago, keeping browser
// sessions, tickets, activity leases and Agent credentials valid across a
// planned restart. It is called only while the caller owns the leadership
// advisory lock. The record is consumed either way; without a usable one
// nothing else changes and the caller promotes a new generation instead.
func (s *Store) ResumeControllerEpoch(ctx context.Context, source string, maxGap time.Duration, now time.Time) (int64, bool, error) {
	if source == "" || len(source) > 128 || maxGap <= 0 {
		return 0, false, fmt.Errorf("invalid controller resume request")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var generation int64
	var cleanShutdownAt sql.NullTime
	if err := tx.QueryRowContext(ctx, `
		SELECT generation,clean_shutdown_at FROM controller_epochs
		WHERE state='active' FOR UPDATE`).Scan(&generation, &cleanShutdownAt); err != nil {
		if err == sql.ErrNoRows {
			return 0, false, nil
		}
		return 0, false, err
	}
	if !cleanShutdownAt.Valid {
		return 0, false, nil
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE controller_epochs SET clean_shutdown_at=NULL
		WHERE generation=$1 AND state='active'`, generation); err != nil {
		return 0, false, err
	}
	gap := now.Sub(cleanShutdownAt.Time)
	// The marker and now come from the same host clock; allow a little skew.
	resumed := gap >= -time.Minute && gap <= maxGap
	if resumed {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO audit_events (
			  actor_type,action,target_type,target_id,
			  controller_generation,outcome,detail
			) VALUES (
			  'controller','controller-generation-resumed','controller_epoch',$1::text,
			  $1::bigint,'succeeded',jsonb_build_object(
			    'source',$2::text,'clean_shutdown_at',$3::timestamptz))`,
			generation, source, cleanShutdownAt.Time); err != nil {
			return 0, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	if !resumed {
		return 0, false, nil
	}
	return generation, true, nil
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
