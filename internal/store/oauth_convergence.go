package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const oauthIdentitySyncBackoff = 2 * time.Minute

// stageOAuthIdentitySyncs records the identity change in the same transaction
// as the authoritative auth_identity/node_account update. A node that is
// offline at bind/unbind time therefore cannot miss the change permanently.
func stageOAuthIdentitySyncs(
	ctx context.Context,
	tx *sql.Tx,
	globalUserID int64,
	provider, subject string,
	desiredPresent bool,
	now time.Time,
) (int64, error) {
	result, err := tx.ExecContext(ctx, `
		INSERT INTO node_account_oauth_syncs (
		  global_user_id,node_id,provider,provider_subject,local_handle,
		  account_version,desired_present,state,attempt,created_at,updated_at
		)
		SELECT account.user_id,account.node_id,$2,$3,account.local_handle,
		  account.account_version,$4,'pending',0,$5,$5
		FROM node_accounts account
		WHERE account.user_id=$1
		ON CONFLICT (global_user_id,node_id,provider) DO UPDATE SET
		  provider_subject=EXCLUDED.provider_subject,
		  local_handle=EXCLUDED.local_handle,
		  account_version=EXCLUDED.account_version,
		  desired_present=EXCLUDED.desired_present,
		  state='pending',attempt=0,updated_at=EXCLUDED.updated_at`,
		globalUserID, provider, subject, desiredPresent, now)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ReconcileOAuthIdentitySyncIntents repairs intents for accounts created or
// replaced after an identity was originally bound. It also advances a pending
// exact-subject removal to the replacement account version. This is metadata
// reconciliation only; delivery remains bounded by ListPending... and the
// Controller worker.
func (s *Store) ReconcileOAuthIdentitySyncIntents(ctx context.Context, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO node_account_oauth_syncs (
		  global_user_id,node_id,provider,provider_subject,local_handle,
		  account_version,desired_present,state,attempt,created_at,updated_at
		)
		SELECT account.user_id,account.node_id,identity.provider,identity.provider_subject,
		  account.local_handle,account.account_version,true,'pending',0,$1,$1
		FROM node_accounts account
		JOIN auth_identities identity ON identity.user_id=account.user_id
		  AND identity.status='active' AND identity.provider IN ('discord','linuxdo')
		ON CONFLICT (global_user_id,node_id,provider) DO UPDATE SET
		  provider_subject=EXCLUDED.provider_subject,
		  local_handle=EXCLUDED.local_handle,
		  account_version=EXCLUDED.account_version,
		  desired_present=true,state='pending',attempt=0,updated_at=EXCLUDED.updated_at
		WHERE node_account_oauth_syncs.provider_subject IS DISTINCT FROM EXCLUDED.provider_subject
		   OR node_account_oauth_syncs.local_handle IS DISTINCT FROM EXCLUDED.local_handle
		   OR node_account_oauth_syncs.account_version IS DISTINCT FROM EXCLUDED.account_version
		   OR NOT node_account_oauth_syncs.desired_present`, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE node_account_oauth_syncs sync SET
		  local_handle=account.local_handle,
		  account_version=account.account_version,
		  state='pending',attempt=0,updated_at=$1
		FROM node_accounts account
		WHERE sync.global_user_id=account.user_id AND sync.node_id=account.node_id
		  AND NOT sync.desired_present
		  AND (sync.local_handle IS DISTINCT FROM account.local_handle
		    OR sync.account_version IS DISTINCT FROM account.account_version)
		  AND NOT EXISTS (
		    SELECT 1 FROM auth_identities identity
		    WHERE identity.user_id=sync.global_user_id AND identity.provider=sync.provider
		      AND identity.status='active'
		  )`, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListPendingOAuthIdentitySyncs(
	ctx context.Context,
	limit int,
	now time.Time,
) ([]PendingOAuthIdentitySync, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT sync.global_user_id,sync.node_id,sync.local_handle,sync.provider,
		  sync.provider_subject,sync.account_version,sync.desired_present
		FROM node_account_oauth_syncs sync
		JOIN node_accounts account ON account.user_id=sync.global_user_id
		  AND account.node_id=sync.node_id AND account.local_handle=sync.local_handle
		  AND account.account_version=sync.account_version AND account.status='active'
		JOIN nodes node ON node.id=sync.node_id AND node.role='compute'
		  AND node.status='online' AND node.connectivity_state='online'
		  AND node.controller_generation=(SELECT generation FROM controller_epochs WHERE state='active')
		WHERE sync.state='pending' AND sync.updated_at<=$2
		  AND ((sync.desired_present AND EXISTS (
		    SELECT 1 FROM auth_identities identity
		    WHERE identity.user_id=sync.global_user_id AND identity.provider=sync.provider
		      AND identity.provider_subject=sync.provider_subject AND identity.status='active'
		  )) OR (NOT sync.desired_present AND NOT EXISTS (
		    SELECT 1 FROM auth_identities identity
		    WHERE identity.user_id=sync.global_user_id AND identity.provider=sync.provider
		      AND identity.status='active'
		  )))
		ORDER BY sync.updated_at,sync.global_user_id,sync.node_id,sync.provider
		LIMIT $1`, limit, now.Add(-oauthIdentitySyncBackoff))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var syncs []PendingOAuthIdentitySync
	for rows.Next() {
		var sync PendingOAuthIdentitySync
		if err := rows.Scan(
			&sync.GlobalUserID, &sync.NodeID, &sync.LocalHandle, &sync.Provider,
			&sync.Subject, &sync.Version, &sync.DesiredPresent,
		); err != nil {
			return nil, err
		}
		syncs = append(syncs, sync)
	}
	return syncs, rows.Err()
}

func (s *Store) CompleteOAuthIdentitySync(
	ctx context.Context,
	sync PendingOAuthIdentitySync,
	now time.Time,
) error {
	if err := validatePendingOAuthIdentitySync(sync); err != nil {
		return err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE node_account_oauth_syncs SET state='completed',attempt=attempt+1,updated_at=$8
		WHERE global_user_id=$1 AND node_id=$2 AND provider=$3 AND provider_subject=$4
		  AND local_handle=$5 AND account_version=$6 AND desired_present=$7 AND state='pending'`,
		sync.GlobalUserID, sync.NodeID, sync.Provider, sync.Subject, sync.LocalHandle,
		sync.Version, sync.DesiredPresent, now)
	return err
}

func (s *Store) MarkOAuthIdentitySyncError(
	ctx context.Context,
	sync PendingOAuthIdentitySync,
	now time.Time,
) error {
	if err := validatePendingOAuthIdentitySync(sync); err != nil {
		return err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE node_account_oauth_syncs SET attempt=attempt+1,updated_at=$8
		WHERE global_user_id=$1 AND node_id=$2 AND provider=$3 AND provider_subject=$4
		  AND local_handle=$5 AND account_version=$6 AND desired_present=$7 AND state='pending'`,
		sync.GlobalUserID, sync.NodeID, sync.Provider, sync.Subject, sync.LocalHandle,
		sync.Version, sync.DesiredPresent, now)
	return err
}

func validatePendingOAuthIdentitySync(sync PendingOAuthIdentitySync) error {
	if sync.GlobalUserID <= 0 || sync.NodeID <= 0 || sync.LocalHandle == "" ||
		!validOAuthProvider(sync.Provider) || sync.Subject == "" || sync.Version <= 0 {
		return fmt.Errorf("invalid oauth identity sync")
	}
	return nil
}
