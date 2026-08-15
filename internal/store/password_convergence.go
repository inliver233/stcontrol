package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// passwordFallbackWindow bounds how long the immediately-previous password hash
// stays acceptable as a login fallback while the password-sync saga is
// incomplete. Even if a node never converges, the previous verifier is retired
// after this window so a rotated password does not remain acceptable forever.
const passwordFallbackWindow = 48 * time.Hour

// passwordRemovalBackoff ages pending removal intents before they are retried,
// mirroring the durable password-sync backoff used for set_password deliveries.
const passwordRemovalBackoff = 2 * time.Minute

// ErrPasswordRemovalNotPending marks a completion attempt for an intent that
// does not currently exist.
var ErrPasswordRemovalNotPending = errors.New("password removal intent is not pending")

// PasswordFallbackHash returns the immediately-previous password verifier to
// accept during login while the password-sync saga is incomplete, or "" if no
// fallback should be honored. The fallback is active only while every required
// condition holds:
//   - a previous hash has been staged (i.e. at least one password change since bind);
//   - the change is younger than passwordFallbackWindow; and
//   - at least one of the user's node accounts has not yet converged to the
//     newest staged material (status pending/error, outside provisioning flow).
//
// Once every node confirms the new version (all accounts active) or the window
// elapses, "" is returned and the previous verifier is effectively dropped.
func (s *Store) PasswordFallbackHash(ctx context.Context, globalUserID int64, now time.Time) (string, error) {
	if globalUserID <= 0 {
		return "", fmt.Errorf("invalid global user")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var previous sql.NullString
	var changedAt sql.NullTime
	var incomplete bool
	err := s.DB.QueryRowContext(ctx, `
		SELECT identity.previous_password_hash, identity.password_changed_at,
		  EXISTS(
		    SELECT 1 FROM node_accounts account
		    WHERE account.user_id=$1
		      AND account.status IN ('pending','error')
		      AND account.provisioning_workflow_id IS NULL
		  )
		FROM auth_identities identity
		WHERE identity.user_id=$1
		  AND identity.provider='password'
		  AND identity.status='active'`, globalUserID).
		Scan(&previous, &changedAt, &incomplete)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !previous.Valid || previous.String == "" || !changedAt.Valid || !incomplete {
		return "", nil
	}
	if now.Sub(changedAt.Time) > passwordFallbackWindow {
		return "", nil
	}
	return previous.String, nil
}

// ClearPasswordFallbackIfConverged permanently drops the previous-password
// fallback once every node account has converged (no pending/error account
// remains). It is a best-effort hygiene call from the password-sync worker;
// login correctness never depends on it because PasswordFallbackHash performs
// the same checks dynamically.
func (s *Store) ClearPasswordFallbackIfConverged(ctx context.Context, globalUserID int64, now time.Time) error {
	if globalUserID <= 0 {
		return fmt.Errorf("invalid global user")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE auth_identities identity
		SET previous_password_hash=NULL,
		  password_changed_at=NULL,
		  updated_at=$2
		WHERE identity.user_id=$1
		  AND identity.provider='password'
		  AND identity.status='active'
		  AND identity.previous_password_hash IS NOT NULL
		  AND NOT EXISTS(
		    SELECT 1 FROM node_accounts account
		    WHERE account.user_id=$1
		      AND account.status IN ('pending','error')
		      AND account.provisioning_workflow_id IS NULL
		  )`,
		globalUserID, now)
	return err
}

// stagePasswordRemovals records a durable password-removal intent for every of
// the user's node accounts so the password identity's unbind is pushed to all
// nodes, including those offline at the time. It is called inside the unbind
// transaction. Offline nodes keep their intent until they return and the worker
// delivers the removal.
func stagePasswordRemovals(ctx context.Context, tx *sql.Tx, globalUserID int64, now time.Time) (int64, error) {
	result, err := tx.ExecContext(ctx, `
		INSERT INTO node_account_password_removals (
		  global_user_id, node_id, local_handle, password_material_version, state, created_at, updated_at
		)
		SELECT user_id, node_id, local_handle, password_material_version, 'pending', $2, $2
		FROM node_accounts
		WHERE user_id=$1
		ON CONFLICT (global_user_id, node_id) DO UPDATE SET
		  local_handle=EXCLUDED.local_handle,
		  password_material_version=EXCLUDED.password_material_version,
		  state='pending', updated_at=EXCLUDED.updated_at`,
		globalUserID, now)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func clearPendingPasswordRemovals(ctx context.Context, tx *sql.Tx, globalUserID int64, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE node_account_password_removals
		SET state='completed', updated_at=$2
		WHERE global_user_id=$1 AND state='pending'`,
		globalUserID, now)
	return err
}

// ListPendingPasswordRemovals returns durable removal intents that are due for
// delivery. Row age mirrors the password-sync backoff so failures are retried
// without hammering an unhealthy node.
func (s *Store) ListPendingPasswordRemovals(ctx context.Context, limit int, now time.Time) ([]PendingPasswordRemoval, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT global_user.legacy_user_id, removal.global_user_id, removal.node_id,
		  removal.local_handle, removal.password_material_version
		FROM node_account_password_removals removal
		JOIN global_users global_user ON global_user.id=removal.global_user_id
		JOIN node_accounts account
		  ON account.user_id=removal.global_user_id AND account.node_id=removal.node_id
		  AND account.local_handle=removal.local_handle
		  AND account.password_material_version=removal.password_material_version
		  AND account.password_hash IS NULL AND account.password_salt IS NULL
		JOIN nodes node ON node.id=removal.node_id
		  AND node.status='online' AND node.connectivity_state='online'
		  AND node.controller_generation=(SELECT generation FROM controller_epochs WHERE state='active')
		WHERE removal.state='pending' AND removal.password_material_version>0
		  AND removal.updated_at<=$2
		ORDER BY removal.updated_at LIMIT $1`, limit, now.Add(-passwordRemovalBackoff))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var removals []PendingPasswordRemoval
	for rows.Next() {
		var removal PendingPasswordRemoval
		if err := rows.Scan(
			&removal.LegacyUserID, &removal.GlobalUserID, &removal.NodeID, &removal.LocalHandle, &removal.Version,
		); err != nil {
			return nil, err
		}
		removals = append(removals, removal)
	}
	return removals, rows.Err()
}

// ActivatePasswordRemoval marks a password-removal intent completed after the
// target node confirms the local password has been removed. It is idempotent:
// an intent that is already completed is harmless.
func (s *Store) ActivatePasswordRemoval(ctx context.Context, globalUserID, nodeID, version int64, now time.Time) error {
	if globalUserID <= 0 || nodeID <= 0 || version <= 0 {
		return fmt.Errorf("invalid password removal")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE node_account_password_removals
		SET state='completed', attempt=attempt+1, updated_at=$4
		WHERE global_user_id=$1 AND node_id=$2 AND password_material_version=$3
		  AND state='pending'`,
		globalUserID, nodeID, version, now)
	return err
}

// MarkPasswordRemovalError records a failed delivery attempt so the intent is
// retried after the worker backoff instead of being dropped.
func (s *Store) MarkPasswordRemovalError(ctx context.Context, globalUserID, nodeID, version int64, now time.Time) error {
	if globalUserID <= 0 || nodeID <= 0 || version <= 0 {
		return fmt.Errorf("invalid password removal")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE node_account_password_removals
		SET attempt=attempt+1, updated_at=$4
		WHERE global_user_id=$1 AND node_id=$2 AND password_material_version=$3
		  AND state='pending'`,
		globalUserID, nodeID, version, now)
	return err
}
