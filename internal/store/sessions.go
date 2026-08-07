package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrInvalidControllerSession = errors.New("invalid controller session input")

type CreateControllerSessionParams struct {
	ID        string
	UserID    *int64
	AdminID   *int64
	TokenHash []byte
	CSRFHash  []byte
	ExpiresAt time.Time
	Now       time.Time
}

type ControllerSession struct {
	ID                   string
	LegacyUserID         int64
	GlobalUserID         int64
	AdminID              int64
	Username             string
	IsAdmin              bool
	CSRFHash             []byte
	ExpiresAt            time.Time
	LastSeenAt           time.Time
	ControllerGeneration int64
}

// CreateControllerSession writes a user/admin session bound to the active
// controller generation. Exactly one principal kind must be supplied.
func (s *Store) CreateControllerSession(ctx context.Context, p CreateControllerSessionParams) (int64, error) {
	principals := 0
	if p.UserID != nil && *p.UserID > 0 {
		principals++
	}
	if p.AdminID != nil && *p.AdminID > 0 {
		principals++
	}
	if p.ID == "" || principals != 1 || len(p.TokenHash) != 32 || len(p.CSRFHash) != 32 ||
		p.ExpiresAt.IsZero() {
		return 0, ErrInvalidControllerSession
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	if !p.ExpiresAt.After(p.Now) {
		return 0, ErrInvalidControllerSession
	}

	var generation int64
	err := s.DB.QueryRowContext(ctx, `
		INSERT INTO controller_sessions (
		  id, user_id, admin_id, token_hash, csrf_hash, expires_at,
		  last_seen_at, created_at, controller_generation
		)
		SELECT $1,$2,$3,$4,$5,$6,$7,$7,generation
		FROM controller_epochs WHERE state='active'
		RETURNING controller_generation`,
		p.ID, p.UserID, p.AdminID, p.TokenHash, p.CSRFHash, p.ExpiresAt, p.Now).
		Scan(&generation)
	if err == sql.ErrNoRows {
		return 0, ErrNoActiveController
	}
	if err != nil {
		return 0, fmt.Errorf("create controller session: %w", err)
	}
	return generation, nil
}

// GetControllerSession resolves a raw-cookie digest to a live session. Sessions
// from a revoked controller generation fail closed.
func (s *Store) GetControllerSession(ctx context.Context, tokenHash []byte, now time.Time) (*ControllerSession, error) {
	if len(tokenHash) != 32 {
		return nil, ErrInvalidControllerSession
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var (
		out          ControllerSession
		legacyUserID sql.NullInt64
		globalUserID sql.NullInt64
		adminID      sql.NullInt64
		username     sql.NullString
	)
	err := s.DB.QueryRowContext(ctx, `
		SELECT s.id, gu.legacy_user_id, s.user_id, s.admin_id,
		  COALESCE(u.username, a.username), s.admin_id IS NOT NULL,
		  s.csrf_hash, s.expires_at, s.last_seen_at, s.controller_generation
		FROM controller_sessions s
		JOIN controller_epochs ce
		  ON ce.generation=s.controller_generation AND ce.state='active'
		LEFT JOIN global_users gu ON gu.id=s.user_id AND gu.status='active'
		LEFT JOIN users u ON u.id=gu.legacy_user_id AND u.status='active'
		LEFT JOIN admins a ON a.id=s.admin_id AND a.status='active'
		WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>$2
		  AND ((s.user_id IS NOT NULL AND u.id IS NOT NULL)
		    OR (s.admin_id IS NOT NULL AND a.id IS NOT NULL))`, tokenHash, now).
		Scan(&out.ID, &legacyUserID, &globalUserID, &adminID, &username, &out.IsAdmin,
			&out.CSRFHash, &out.ExpiresAt, &out.LastSeenAt, &out.ControllerGeneration)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get controller session: %w", err)
	}
	out.LegacyUserID = legacyUserID.Int64
	out.GlobalUserID = globalUserID.Int64
	out.AdminID = adminID.Int64
	out.Username = username.String
	return &out, nil
}

// GetConflictControllerSession resolves an otherwise valid user session only
// when both identity projections are conflict-frozen. It intentionally excludes
// admins and every other disabled state so callers can mount a recovery-only
// route without reopening normal account mutations.
func (s *Store) GetConflictControllerSession(ctx context.Context, tokenHash []byte, now time.Time) (*ControllerSession, error) {
	if len(tokenHash) != 32 {
		return nil, ErrInvalidControllerSession
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var out ControllerSession
	err := s.DB.QueryRowContext(ctx, `
		SELECT s.id,gu.legacy_user_id,s.user_id,0::bigint,u.username,false,
		  s.csrf_hash,s.expires_at,s.last_seen_at,s.controller_generation
		FROM controller_sessions s
		JOIN controller_epochs ce
		  ON ce.generation=s.controller_generation AND ce.state='active'
		JOIN global_users gu ON gu.id=s.user_id AND gu.status='conflict'
		JOIN users u ON u.id=gu.legacy_user_id AND u.status='conflict'
		JOIN replica_conflicts conflict ON conflict.user_id=gu.id
		  AND conflict.state NOT IN ('resolved','failed')
		WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>$2`, tokenHash, now).
		Scan(&out.ID, &out.LegacyUserID, &out.GlobalUserID, &out.AdminID, &out.Username,
			&out.IsAdmin, &out.CSRFHash, &out.ExpiresAt, &out.LastSeenAt,
			&out.ControllerGeneration)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get conflict controller session: %w", err)
	}
	return &out, nil
}

func (s *Store) TouchControllerSession(ctx context.Context, id string, now time.Time) error {
	if id == "" {
		return ErrInvalidControllerSession
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE controller_sessions SET last_seen_at=$2
		WHERE id=$1 AND revoked_at IS NULL AND expires_at>$2`, id, now)
	return err
}

func (s *Store) RevokeControllerSession(ctx context.Context, tokenHash []byte, now time.Time) error {
	if len(tokenHash) != 32 {
		return ErrInvalidControllerSession
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE controller_sessions SET revoked_at=COALESCE(revoked_at,$2)
		WHERE token_hash=$1`, tokenHash, now)
	return err
}

func (s *Store) CleanupControllerSessions(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		DELETE FROM controller_sessions
		WHERE expires_at<=$1 OR (revoked_at IS NOT NULL AND revoked_at<=$2)`,
		now, now.Add(-24*time.Hour))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
