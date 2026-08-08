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
	next := current + 1
	if _, err := tx.ExecContext(ctx, `
		UPDATE controller_epochs SET state='revoked',revoked_at=$2 WHERE generation=$1 AND state='active';
		INSERT INTO controller_epochs (
		  generation,operation_id,controller_id,source,state,signing_key_version,activated_at
		) VALUES ($3,gen_random_uuid(),gen_random_uuid(),$4,'active',$5,$2);
		UPDATE controller_sessions SET revoked_at=COALESCE(revoked_at,$2) WHERE revoked_at IS NULL;
		UPDATE control_tickets SET revoked_at=COALESCE(revoked_at,$2) WHERE consumed_at IS NULL AND revoked_at IS NULL;
		UPDATE agent_credential_rotations SET state='revoked'
		WHERE state='pending' AND controller_generation=$1;
		UPDATE nodes SET controller_generation=0 WHERE role IN ('compute','storage')`,
		current, now, next, source, signingVersion+1); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}
