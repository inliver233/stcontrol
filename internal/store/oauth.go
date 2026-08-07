package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidOAuthFlow = errors.New("invalid oauth flow input")
	ErrOAuthPendingBusy = errors.New("oauth enrollment is already processing")
)

func validOAuthProvider(provider string) bool {
	return provider == "discord" || provider == "linuxdo"
}

func (s *Store) CreateOAuthState(
	ctx context.Context,
	stateHash []byte,
	provider string,
	nodeID *int64,
	expiresAt, now time.Time,
) error {
	if len(stateHash) != 32 || !validOAuthProvider(provider) || expiresAt.IsZero() {
		return ErrInvalidOAuthFlow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !expiresAt.After(now) || (nodeID != nil && *nodeID <= 0) {
		return ErrInvalidOAuthFlow
	}
	result, err := s.DB.ExecContext(ctx, `
		INSERT INTO oauth_authorization_states (
		  state_hash, provider, node_id, controller_generation, expires_at, created_at
		)
		SELECT $1,$2,$3,generation,$4,$5
		FROM controller_epochs WHERE state='active'`, stateHash, provider, nodeID, expiresAt, now)
	if err != nil {
		return fmt.Errorf("create oauth state: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrNoActiveController
	}
	return nil
}

// ConsumeOAuthState atomically verifies provider, expiry, and active controller
// generation. The raw state is never stored.
func (s *Store) ConsumeOAuthState(
	ctx context.Context,
	stateHash []byte,
	provider string,
	now time.Time,
) (*int64, bool, error) {
	if len(stateHash) != 32 || !validOAuthProvider(provider) {
		return nil, false, ErrInvalidOAuthFlow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var nodeID sql.NullInt64
	err := s.DB.QueryRowContext(ctx, `
		UPDATE oauth_authorization_states AS state
		SET consumed_at=$3
		FROM controller_epochs AS epoch
		WHERE state.state_hash=$1 AND state.provider=$2
		  AND state.consumed_at IS NULL AND state.expires_at>$3
		  AND epoch.state='active' AND epoch.generation=state.controller_generation
		RETURNING state.node_id`, stateHash, provider, now).Scan(&nodeID)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("consume oauth state: %w", err)
	}
	if nodeID.Valid {
		value := nodeID.Int64
		return &value, true, nil
	}
	return nil, true, nil
}

type CreateOAuthPendingParams struct {
	ID              string
	TokenHash       []byte
	Provider        string
	ProviderSubject string
	DisplayName     string
	AvatarURL       string
	ExpiresAt       time.Time
	Now             time.Time
}

type OAuthPendingEnrollment struct {
	ID               string
	Provider         string
	ProviderSubject  string
	DisplayName      string
	AvatarURL        string
	ResultUserID     int64
	ClaimID          string
	AlreadyCompleted bool
}

func (s *Store) CreateOAuthPending(ctx context.Context, p CreateOAuthPendingParams) error {
	if p.ID == "" || len(p.TokenHash) != 32 || !validOAuthProvider(p.Provider) ||
		p.ProviderSubject == "" || p.DisplayName == "" || p.ExpiresAt.IsZero() {
		return ErrInvalidOAuthFlow
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	if !p.ExpiresAt.After(p.Now) {
		return ErrInvalidOAuthFlow
	}
	result, err := s.DB.ExecContext(ctx, `
		INSERT INTO oauth_pending_enrollments (
		  id, token_hash, provider, provider_subject, display_name, avatar_url,
		  state, controller_generation, expires_at, created_at, updated_at
		)
		SELECT $1,$2,$3,$4,$5,$6,'pending',generation,$7,$8,$8
		FROM controller_epochs WHERE state='active'`,
		p.ID, p.TokenHash, p.Provider, p.ProviderSubject, p.DisplayName,
		nullIfEmpty(p.AvatarURL), p.ExpiresAt, p.Now)
	if err != nil {
		return fmt.Errorf("create pending oauth enrollment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrNoActiveController
	}
	return nil
}

// ClaimOAuthPending leases an enrollment to one request. A completed record is
// replayed with its result so a lost HTTP response does not create a duplicate.
func (s *Store) ClaimOAuthPending(
	ctx context.Context,
	tokenHash []byte,
	claimID string,
	now time.Time,
	claimTTL time.Duration,
) (OAuthPendingEnrollment, bool, error) {
	if len(tokenHash) != 32 || claimID == "" || claimTTL <= 0 {
		return OAuthPendingEnrollment{}, false, ErrInvalidOAuthFlow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return OAuthPendingEnrollment{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		out         OAuthPendingEnrollment
		state       string
		avatar      sql.NullString
		storedClaim sql.NullString
		claimUntil  sql.NullTime
		resultUser  sql.NullInt64
	)
	err = tx.QueryRowContext(ctx, `
		SELECT pending.id, pending.provider, pending.provider_subject,
		  pending.display_name, pending.avatar_url, pending.state,
		  pending.claim_id, pending.claim_until, pending.result_user_id
		FROM oauth_pending_enrollments pending
		JOIN controller_epochs epoch
		  ON epoch.generation=pending.controller_generation AND epoch.state='active'
		WHERE pending.token_hash=$1 AND pending.expires_at>$2
		FOR UPDATE OF pending`, tokenHash, now).
		Scan(&out.ID, &out.Provider, &out.ProviderSubject, &out.DisplayName, &avatar,
			&state, &storedClaim, &claimUntil, &resultUser)
	if err == sql.ErrNoRows {
		return OAuthPendingEnrollment{}, false, nil
	}
	if err != nil {
		return OAuthPendingEnrollment{}, false, fmt.Errorf("get pending oauth enrollment: %w", err)
	}
	out.AvatarURL = avatar.String
	if state == "consumed" {
		if !resultUser.Valid {
			return OAuthPendingEnrollment{}, false, fmt.Errorf("consumed oauth enrollment missing result")
		}
		out.ResultUserID = resultUser.Int64
		out.AlreadyCompleted = true
		if err := tx.Commit(); err != nil {
			return OAuthPendingEnrollment{}, false, err
		}
		return out, true, nil
	}
	if state == "processing" && claimUntil.Valid && claimUntil.Time.After(now) {
		return OAuthPendingEnrollment{}, false, ErrOAuthPendingBusy
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE oauth_pending_enrollments
		SET state='processing', claim_id=$2, claim_until=$3, updated_at=$4
		WHERE id=$1`, out.ID, claimID, now.Add(claimTTL), now); err != nil {
		return OAuthPendingEnrollment{}, false, fmt.Errorf("claim oauth enrollment: %w", err)
	}
	out.ClaimID = claimID
	if err := tx.Commit(); err != nil {
		return OAuthPendingEnrollment{}, false, err
	}
	return out, true, nil
}

func (s *Store) CompleteOAuthPending(ctx context.Context, id, claimID string, userID int64, now time.Time) (bool, error) {
	if id == "" || claimID == "" || userID <= 0 {
		return false, ErrInvalidOAuthFlow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE oauth_pending_enrollments
		SET state='consumed', result_user_id=$3, consumed_at=$4,
		  claim_id=NULL, claim_until=NULL, updated_at=$4
		WHERE id=$1 AND claim_id=$2 AND state='processing' AND claim_until>$4`,
		id, claimID, userID, now)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

func (s *Store) ReleaseOAuthPending(ctx context.Context, id, claimID string, now time.Time) error {
	if id == "" || claimID == "" {
		return ErrInvalidOAuthFlow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE oauth_pending_enrollments
		SET state='pending', claim_id=NULL, claim_until=NULL, updated_at=$3
		WHERE id=$1 AND claim_id=$2 AND state='processing'`, id, claimID, now)
	return err
}

func (s *Store) CleanupOAuthArtifacts(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	stateResult, err := tx.ExecContext(ctx, `
		DELETE FROM oauth_authorization_states
		WHERE expires_at<=$1 OR (consumed_at IS NOT NULL AND consumed_at<=$2)`, now, now.Add(-time.Hour))
	if err != nil {
		return 0, err
	}
	pendingResult, err := tx.ExecContext(ctx, `
		DELETE FROM oauth_pending_enrollments
		WHERE expires_at<=$1 OR (consumed_at IS NOT NULL AND consumed_at<=$2)`, now, now.Add(-24*time.Hour))
	if err != nil {
		return 0, err
	}
	states, err := stateResult.RowsAffected()
	if err != nil {
		return 0, err
	}
	pendings, err := pendingResult.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return states + pendings, nil
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}
