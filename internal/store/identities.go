package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

var (
	ErrInvalidIdentity  = errors.New("invalid identity input")
	ErrIdentityConflict = errors.New("identity is already linked")
	ErrLastIdentity     = errors.New("cannot remove the last active identity")
)

type AuthIdentity struct {
	Provider        string    `json:"provider"`
	PasswordVersion int64     `json:"password_version,omitempty"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
}

func (s *Store) ListUserIdentities(ctx context.Context, globalUserID int64) ([]AuthIdentity, error) {
	if globalUserID <= 0 {
		return nil, ErrInvalidIdentity
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT provider,password_version,status,created_at
		FROM auth_identities WHERE user_id=$1 AND status='active'
		ORDER BY CASE provider WHEN 'password' THEN 1 WHEN 'discord' THEN 2 ELSE 3 END`, globalUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var identities []AuthIdentity
	for rows.Next() {
		var identity AuthIdentity
		if err := rows.Scan(&identity.Provider, &identity.PasswordVersion, &identity.Status, &identity.CreatedAt); err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	return identities, rows.Err()
}

func (s *Store) BindOAuthIdentity(
	ctx context.Context,
	globalUserID int64,
	provider, providerSubject string,
	now time.Time,
) error {
	if globalUserID <= 0 || !validOAuthProvider(provider) || providerSubject == "" {
		return ErrInvalidIdentity
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockIdentityUser(ctx, tx, globalUserID); err != nil {
		return err
	}
	if err := ensureIdentitySlot(ctx, tx, globalUserID, provider, providerSubject); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO auth_identities (user_id,provider,provider_subject,status,created_at,updated_at)
		VALUES ($1,$2,$3,'active',$4,$4)`, globalUserID, provider, providerSubject, now); err != nil {
		return identityInsertError("bind oauth identity", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE node_accounts SET
		  oauth_subjects=oauth_subjects || jsonb_build_object($2::text,$3::text),
		  account_version=account_version+1,updated_at=$4::timestamptz
		WHERE user_id=$1`, globalUserID, provider, providerSubject, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) BindPasswordIdentity(
	ctx context.Context,
	legacyUserID, globalUserID int64,
	passwordHash, nodePasswordHash, nodePasswordSalt string,
	now time.Time,
) error {
	if legacyUserID <= 0 || globalUserID <= 0 || passwordHash == "" ||
		nodePasswordHash == "" || nodePasswordSalt == "" {
		return ErrInvalidIdentity
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var handle string
	if err := tx.QueryRowContext(ctx, `
		SELECT legacy.username FROM global_users global_user
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		WHERE global_user.id=$1 AND legacy.id=$2 AND global_user.status='active'
		FOR UPDATE OF global_user`, globalUserID, legacyUserID).Scan(&handle); err != nil {
		if err == sql.ErrNoRows {
			return ErrInvalidIdentity
		}
		return err
	}
	if err := ensureIdentitySlot(ctx, tx, globalUserID, "password", handle); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO auth_identities (
		  user_id,provider,provider_subject,password_hash,password_version,status,created_at,updated_at
		) VALUES ($1,'password',$2,$3,1,'active',$4,$4)`, globalUserID, handle, passwordHash, now); err != nil {
		return identityInsertError("bind password identity", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET password_enc=NULL,password_hash=$2 WHERE id=$1`, legacyUserID, passwordHash); err != nil {
		return err
	}
	if err := stagePasswordMaterial(ctx, tx, globalUserID, nodePasswordHash, nodePasswordSalt, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UnbindUserIdentity(ctx context.Context, legacyUserID, globalUserID int64, provider string, now time.Time) error {
	if legacyUserID <= 0 || globalUserID <= 0 || (provider != "password" && !validOAuthProvider(provider)) {
		return ErrInvalidIdentity
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockIdentityUser(ctx, tx, globalUserID); err != nil {
		return err
	}
	var activeCount int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM auth_identities WHERE user_id=$1 AND status='active'`, globalUserID).Scan(&activeCount); err != nil {
		return err
	}
	if activeCount <= 1 {
		return ErrLastIdentity
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE auth_identities SET status='revoked',updated_at=$3
		WHERE user_id=$1 AND provider=$2 AND status='active'`, globalUserID, provider, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrInvalidIdentity
	}
	if provider == "password" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE node_accounts SET password_hash=NULL,password_salt=NULL,
			  password_material_version=password_material_version+1,
			  account_version=account_version+1,updated_at=$2
			WHERE user_id=$1`, globalUserID, now); err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
			UPDATE node_accounts SET oauth_subjects=oauth_subjects-$2,
			  account_version=account_version+1,updated_at=$3
			WHERE user_id=$1`, globalUserID, provider, now); err != nil {
			return err
		}
	}
	var nextProvider, nextSubject string
	var nextPassword sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT provider,provider_subject,password_hash
		FROM auth_identities WHERE user_id=$1 AND status='active'
		ORDER BY CASE provider WHEN 'password' THEN 1 WHEN 'discord' THEN 2 ELSE 3 END LIMIT 1`, globalUserID).
		Scan(&nextProvider, &nextSubject, &nextPassword); err != nil {
		return err
	}
	var oauthSubject any
	if nextProvider != "password" {
		oauthSubject = nextSubject
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE users SET auth_provider=$2,oauth_id=$3,password_enc=NULL,password_hash=$4
		WHERE id=$1 AND EXISTS (
		  SELECT 1 FROM global_users WHERE id=$5 AND legacy_user_id=$1
		)`, legacyUserID, nextProvider, oauthSubject, nextPassword, globalUserID)
	if err != nil {
		return err
	}
	rows, err = result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrInvalidIdentity
	}
	return tx.Commit()
}

func lockIdentityUser(ctx context.Context, tx *sql.Tx, globalUserID int64) error {
	var id int64
	if err := tx.QueryRowContext(ctx, `
		SELECT id FROM global_users WHERE id=$1 AND status='active' FOR UPDATE`, globalUserID).Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			return ErrInvalidIdentity
		}
		return err
	}
	return nil
}

func ensureIdentitySlot(ctx context.Context, tx *sql.Tx, globalUserID int64, provider, subject string) error {
	var count int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM auth_identities WHERE user_id=$1 AND status='active'`, globalUserID).Scan(&count); err != nil {
		return err
	}
	if count >= 3 {
		return ErrIdentityConflict
	}
	var ownerID int64
	err := tx.QueryRowContext(ctx, `
		SELECT user_id FROM auth_identities
		WHERE status IN ('active','pending') AND (provider=$2 AND provider_subject=$3 OR user_id=$1 AND provider=$2)
		LIMIT 1`, globalUserID, provider, subject).Scan(&ownerID)
	if err == nil {
		return ErrIdentityConflict
	}
	if err != sql.ErrNoRows {
		return err
	}
	return nil
}

func identityInsertError(operation string, err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return ErrIdentityConflict
	}
	return fmt.Errorf("%s: %w", operation, err)
}
