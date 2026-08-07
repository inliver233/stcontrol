package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidIdentityRecovery  = errors.New("invalid identity recovery input")
	ErrIdentityRecoveryConflict = errors.New("identity recovery operation conflicts with existing facts")
)

type RecoverUserPasswordIdentityParams struct {
	OperationID      string `json:"-"`
	UserUUID         string `json:"-"`
	AdminID          int64  `json:"-"`
	RequestDigest    []byte `json:"-"`
	PasswordHash     string `json:"-"`
	NodePasswordHash string `json:"-"`
	NodePasswordSalt string `json:"-"`
	Now              time.Time
}

type IdentityRecoveryResult struct {
	LegacyUserID    int64  `json:"-"`
	GlobalUserID    int64  `json:"-"`
	UserUUID        string `json:"user_uuid"`
	Username        string `json:"username"`
	UserStatus      string `json:"user_status"`
	PasswordVersion int64  `json:"password_version"`
	StagedNodeCount int    `json:"staged_node_count"`
	Replayed        bool   `json:"replayed"`
}

// RecoverUserPasswordIdentity atomically creates or resets a user's password
// identity, stages versioned node-compatible material, revokes every user
// session, and records the generation-bound idempotency fact. No reversible
// credential is accepted or persisted by this operation.
func (s *Store) RecoverUserPasswordIdentity(
	ctx context.Context,
	p RecoverUserPasswordIdentityParams,
) (IdentityRecoveryResult, error) {
	if !validUUIDText(p.OperationID) || !validUUIDText(p.UserUUID) || p.AdminID <= 0 ||
		len(p.RequestDigest) != 32 || p.PasswordHash == "" ||
		p.NodePasswordHash == "" || p.NodePasswordSalt == "" {
		return IdentityRecoveryResult{}, ErrInvalidIdentityRecovery
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return IdentityRecoveryResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		result         IdentityRecoveryResult
		existingAdmin  int64
		existingDigest []byte
	)
	err = tx.QueryRowContext(ctx, `
		SELECT recovery.admin_id,recovery.request_digest,recovery.password_version,
		  recovery.staged_node_count,global_user.id,global_user.legacy_user_id,
		  global_user.uuid::text,legacy.username,global_user.status
		FROM identity_recovery_operations recovery
		JOIN global_users global_user ON global_user.id=recovery.user_id
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		WHERE recovery.operation_id=$1
		FOR UPDATE OF recovery`, p.OperationID).Scan(
		&existingAdmin, &existingDigest, &result.PasswordVersion,
		&result.StagedNodeCount, &result.GlobalUserID, &result.LegacyUserID,
		&result.UserUUID, &result.Username, &result.UserStatus,
	)
	if err == nil {
		if existingAdmin != p.AdminID || !strings.EqualFold(result.UserUUID, p.UserUUID) ||
			!bytes.Equal(existingDigest, p.RequestDigest) {
			return IdentityRecoveryResult{}, ErrIdentityRecoveryConflict
		}
		if err := tx.Commit(); err != nil {
			return IdentityRecoveryResult{}, err
		}
		result.Replayed = true
		return result, nil
	}
	if err != sql.ErrNoRows {
		return IdentityRecoveryResult{}, err
	}

	var activeAdminID int64
	if err := tx.QueryRowContext(ctx, `
		SELECT id FROM admins WHERE id=$1 AND status='active' FOR UPDATE`, p.AdminID).
		Scan(&activeAdminID); err != nil {
		if err == sql.ErrNoRows {
			return IdentityRecoveryResult{}, ErrInvalidIdentityRecovery
		}
		return IdentityRecoveryResult{}, err
	}

	var globalStatus, legacyStatus string
	err = tx.QueryRowContext(ctx, `
		SELECT global_user.id,global_user.legacy_user_id,global_user.uuid::text,
		  legacy.username,global_user.status,legacy.status
		FROM global_users global_user
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		WHERE global_user.uuid=$1
		  AND global_user.status IN ('active','disabled','recovering')
		  AND legacy.status IN ('active','disabled','recovering')
		FOR UPDATE OF global_user,legacy`, p.UserUUID).Scan(
		&result.GlobalUserID, &result.LegacyUserID, &result.UserUUID,
		&result.Username, &globalStatus, &legacyStatus,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return IdentityRecoveryResult{}, ErrInvalidIdentityRecovery
		}
		return IdentityRecoveryResult{}, err
	}

	var identityID, currentVersion int64
	err = tx.QueryRowContext(ctx, `
		SELECT id,password_version FROM auth_identities
		WHERE user_id=$1 AND provider='password' AND status='active'
		FOR UPDATE`, result.GlobalUserID).Scan(&identityID, &currentVersion)
	switch {
	case err == nil:
		if err := tx.QueryRowContext(ctx, `
			UPDATE auth_identities
			SET password_hash=$2,password_version=GREATEST(password_version,0)+1,updated_at=$3
			WHERE id=$1 RETURNING password_version`, identityID, p.PasswordHash, p.Now).
			Scan(&result.PasswordVersion); err != nil {
			return IdentityRecoveryResult{}, err
		}
	case err == sql.ErrNoRows:
		if err := ensureIdentitySlot(ctx, tx, result.GlobalUserID, "password", result.Username); err != nil {
			if errors.Is(err, ErrIdentityConflict) {
				return IdentityRecoveryResult{}, ErrIdentityRecoveryConflict
			}
			return IdentityRecoveryResult{}, err
		}
		result.PasswordVersion = 1
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO auth_identities (
			  user_id,provider,provider_subject,password_hash,password_version,status,created_at,updated_at
			) VALUES ($1,'password',$2,$3,$4,'active',$5,$5)`,
			result.GlobalUserID, result.Username, p.PasswordHash, result.PasswordVersion, p.Now); err != nil {
			return IdentityRecoveryResult{}, identityInsertError("recover password identity", err)
		}
	default:
		return IdentityRecoveryResult{}, err
	}

	result.UserStatus = "active"
	if globalStatus == "disabled" || legacyStatus == "disabled" {
		result.UserStatus = "disabled"
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET password_enc=NULL,password_hash=$2,status=$3 WHERE id=$1`,
		result.LegacyUserID, p.PasswordHash, result.UserStatus); err != nil {
		return IdentityRecoveryResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE global_users SET status=$2,updated_at=$3 WHERE id=$1`,
		result.GlobalUserID, result.UserStatus, p.Now); err != nil {
		return IdentityRecoveryResult{}, err
	}
	staged, err := stagePasswordMaterialCount(
		ctx, tx, result.GlobalUserID, p.NodePasswordHash, p.NodePasswordSalt, p.Now,
	)
	if err != nil {
		return IdentityRecoveryResult{}, err
	}
	result.StagedNodeCount = int(staged)
	if _, err := tx.ExecContext(ctx, `
		UPDATE controller_sessions SET revoked_at=COALESCE(revoked_at,$2)
		WHERE user_id=$1 AND revoked_at IS NULL`, result.GlobalUserID, p.Now); err != nil {
		return IdentityRecoveryResult{}, err
	}

	var controllerGeneration int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO identity_recovery_operations (
		  operation_id,user_id,admin_id,request_digest,password_version,
		  staged_node_count,controller_generation,created_at
		)
		SELECT $1,$2,$3,$4,$5,$6,generation,$7
		FROM controller_epochs WHERE state='active'
		RETURNING controller_generation`, p.OperationID, result.GlobalUserID, p.AdminID,
		p.RequestDigest, result.PasswordVersion, result.StagedNodeCount, p.Now).
		Scan(&controllerGeneration)
	if err == sql.ErrNoRows {
		return IdentityRecoveryResult{}, ErrNoActiveController
	}
	if err != nil {
		return IdentityRecoveryResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  actor_type,actor_id,action,target_type,target_id,operation_id,
		  controller_generation,input_digest,outcome,detail
		) VALUES ('admin',$1::text,'identity-recovery','global_user',$2,$3,$4,$5,'succeeded',
		  jsonb_build_object('password_version',$6,'staged_node_count',$7))`,
		p.AdminID, result.UserUUID, p.OperationID, controllerGeneration,
		p.RequestDigest, result.PasswordVersion, result.StagedNodeCount); err != nil {
		return IdentityRecoveryResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return IdentityRecoveryResult{}, err
	}
	return result, nil
}

func validUUIDText(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil && len(decoded) == 16
}
