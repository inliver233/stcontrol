package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

var (
	ErrInvalidAccountImport  = errors.New("invalid account import inventory")
	ErrAccountImportConflict = errors.New("account import operation conflicts with existing inventory")
	ErrAccountClaimRejected  = errors.New("account import claim rejected")
)

const (
	maxAccountImportCandidates = 10_000
	MaxAccountImportPageSize   = 100
)

type OAuthIdentitySubject struct {
	GlobalUserID int64  `json:"-"`
	Provider     string `json:"-"`
	Subject      string `json:"-"`
}

type AccountImportIdentityFingerprint struct {
	Provider    string
	Fingerprint string
}

type AccountImportCandidateInput struct {
	ID                   string
	LocalUserID          string
	LocalHandle          string
	SizeBytes            int64
	DirectoryFingerprint string
	Source               string
	AccountKind          string
	Identities           []AccountImportIdentityFingerprint
	IsAdmin              bool
	MatchedGlobalUserIDs []int64
}

type CreateAccountImportBatchParams struct {
	ID               string
	OperationID      string
	NodeID           int64
	InventoryDigest  []byte
	Source           string
	CreatedByAdminID int64
	Candidates       []AccountImportCandidateInput
	Now              time.Time
}

type AccountImportBatch struct {
	ID              string    `json:"-"`
	NodeID          int64     `json:"node_id"`
	Source          string    `json:"source"`
	State           string    `json:"state"`
	CandidateCount  int       `json:"candidate_count"`
	AutoLinkedCount int       `json:"auto_linked_count"`
	UnresolvedCount int       `json:"unresolved_count"`
	ScannedAt       time.Time `json:"scanned_at"`
	CreatedAt       time.Time `json:"created_at"`
	Replayed        bool      `json:"replayed,omitempty"`
}

type AccountImportCandidate struct {
	ID                string   `json:"-"`
	LocalHandle       string   `json:"local_handle"`
	SizeBytes         int64    `json:"size_bytes"`
	Source            string   `json:"source"`
	AccountKind       string   `json:"account_kind"`
	IdentityProviders []string `json:"identity_providers"`
	IsAdmin           bool     `json:"is_admin"`
	ResolutionState   string   `json:"resolution_state"`
	MatchedUserUUID   string   `json:"matched_user_uuid,omitempty"`
	ReasonCode        string   `json:"-"`
}

type AccountImportResult struct {
	Batch               AccountImportBatch       `json:"batch"`
	Candidates          []AccountImportCandidate `json:"candidates"`
	CandidateOffset     int                      `json:"candidate_offset"`
	CandidateLimit      int                      `json:"candidate_limit"`
	NextCandidateOffset int                      `json:"next_candidate_offset,omitempty"`
	HasMore             bool                     `json:"has_more"`
}

type AccountImportClaimTarget struct {
	NodeID      int64  `json:"node_id"`
	NodeName    string `json:"node_name"`
	LocalHandle string `json:"local_handle"`
	AccountKind string `json:"account_kind"`
}

type CompleteAccountImportClaimParams struct {
	OperationID  string
	GlobalUserID int64
	NodeID       int64
	LocalHandle  string
	LocalUserID  string
	Now          time.Time
}

// AccountImportClaimOperationMatches reports whether a completed claim is an
// exact user/node replay. It lets the HTTP layer return the durable result after
// a lost response without asking the node to verify a password a second time.
func (s *Store) AccountImportClaimOperationMatches(
	ctx context.Context,
	operationID string,
	globalUserID, nodeID int64,
) (bool, error) {
	if operationID == "" || globalUserID <= 0 || nodeID <= 0 {
		return false, ErrAccountClaimRejected
	}
	var existingUserID, existingNodeID int64
	err := s.DB.QueryRowContext(ctx, `
		SELECT user_id,node_id FROM account_import_claim_operations
		WHERE operation_id=$1`, operationID).Scan(&existingUserID, &existingNodeID)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if existingUserID != globalUserID || existingNodeID != nodeID {
		return false, ErrAccountImportConflict
	}
	return true, nil
}

func (s *Store) ListAccountImportClaimTargets(ctx context.Context, globalUserID int64) ([]AccountImportClaimTarget, error) {
	if globalUserID <= 0 {
		return nil, ErrAccountClaimRejected
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT DISTINCT ON (candidate.node_id,candidate.local_user_id)
		  candidate.node_id,node.name,candidate.local_handle,candidate.account_kind
		FROM account_import_candidates candidate
		JOIN nodes node ON node.id=candidate.node_id
		JOIN global_users global_user ON global_user.id=$1
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		WHERE candidate.resolution_state='claim_required'
		  AND lower(candidate.local_handle)=lower(legacy.username)
		ORDER BY candidate.node_id,candidate.local_user_id,candidate.created_at DESC`, globalUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	targets := make([]AccountImportClaimTarget, 0)
	for rows.Next() {
		var target AccountImportClaimTarget
		if err := rows.Scan(&target.NodeID, &target.NodeName, &target.LocalHandle, &target.AccountKind); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}


// ResolveOAuthUnmatchedCandidates links account-import candidates that were
// classified oauth_unmatched (OAuth-only accounts needing OAuth login proof)
// once the user authenticates with the matching provider.  Idempotent: each
// candidate resolves at most once; conflicting node accounts or non-active
// users are skipped so a bad scan can never merge the wrong account.
func (s *Store) ResolveOAuthUnmatchedCandidates(
	ctx context.Context,
	provider, fingerprint string,
	globalUserID int64,
	now time.Time,
) (int64, error) {
	if provider == "" || fingerprint == "" || globalUserID <= 0 || now.IsZero() {
		return 0, ErrAccountClaimRejected
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var active bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM global_users WHERE id=$1 AND status='active')`,
		globalUserID).Scan(&active); err != nil {
		return 0, err
	}
	if !active {
		if err := tx.Commit(); err != nil {
			return 0, err
		}
		return 0, nil
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE account_import_candidates candidate
		SET resolution_state='auto_linked',matched_user_id=$3,reason_code='oauth_login_proof',updated_at=$4
		FROM account_import_batches batch
		WHERE candidate.batch_id=batch.id
		  AND candidate.resolution_state='oauth_unmatched'
		  AND candidate.identity_fingerprints->>$1=$2
		  AND NOT EXISTS (
		    SELECT 1 FROM node_accounts account
		    WHERE account.node_id=candidate.node_id
		      AND (account.user_id=$3 OR account.local_user_id=candidate.local_user_id)
		  )
		RETURNING candidate.id`,
		provider, fingerprint, globalUserID, now)
	if err != nil {
		return 0, err
	}
	resolved, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if resolved > 0 {
		if _, err := tx.ExecContext(ctx, `
			UPDATE account_import_batches SET auto_linked_count=auto_linked_count+$1,
			  unresolved_count=GREATEST(0,unresolved_count-$1),
			  state=CASE WHEN unresolved_count<=$1 THEN 'resolved' ELSE state END,updated_at=$2
			WHERE id IN (
			  SELECT batch_id FROM account_import_candidates
			  WHERE resolution_state='auto_linked' AND reason_code='oauth_login_proof' AND updated_at=$2
			)`, resolved, now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return resolved, nil
}

func (s *Store) CompleteAccountImportClaim(ctx context.Context, p CompleteAccountImportClaimParams) error {
	if p.OperationID == "" || p.GlobalUserID <= 0 || p.NodeID <= 0 || p.LocalHandle == "" || p.LocalUserID == "" {
		return ErrAccountClaimRejected
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var existingUserID, existingNodeID int64
	var existingLocalID string
	err = tx.QueryRowContext(ctx, `
		SELECT user_id,node_id,local_user_id FROM account_import_claim_operations
		WHERE operation_id=$1 FOR UPDATE`, p.OperationID).Scan(&existingUserID, &existingNodeID, &existingLocalID)
	if err == nil {
		if existingUserID != p.GlobalUserID || existingNodeID != p.NodeID || existingLocalID != p.LocalUserID {
			return ErrAccountImportConflict
		}
		return tx.Commit()
	}
	if err != sql.ErrNoRows {
		return err
	}
	var candidateID, batchID, candidateLocalID, candidateHandle string
	var isAdmin bool
	err = tx.QueryRowContext(ctx, `
		SELECT candidate.id,candidate.batch_id,candidate.local_user_id,candidate.local_handle,candidate.is_admin
		FROM account_import_candidates candidate
		WHERE candidate.node_id=$1 AND lower(candidate.local_handle)=lower($2)
		  AND candidate.resolution_state='claim_required'
		ORDER BY candidate.created_at DESC LIMIT 1 FOR UPDATE`, p.NodeID, p.LocalHandle).
		Scan(&candidateID, &batchID, &candidateLocalID, &candidateHandle, &isAdmin)
	if err != nil || candidateLocalID != p.LocalUserID {
		return ErrAccountClaimRejected
	}
	var legacyUserID int64
	var username, status string
	if err := tx.QueryRowContext(ctx, `
		SELECT global_user.legacy_user_id,legacy.username,global_user.status
		FROM global_users global_user JOIN users legacy ON legacy.id=global_user.legacy_user_id
		WHERE global_user.id=$1 FOR UPDATE`, p.GlobalUserID).Scan(&legacyUserID, &username, &status); err != nil ||
		status != "active" || !equalFoldASCII(username, candidateHandle) {
		return ErrAccountClaimRejected
	}
	var collision int
	err = tx.QueryRowContext(ctx, `
		SELECT 1 FROM node_accounts WHERE node_id=$1 AND (user_id=$2 OR local_user_id=$3) LIMIT 1 FOR UPDATE`,
		p.NodeID, p.GlobalUserID, p.LocalUserID).Scan(&collision)
	if err == nil {
		return ErrAccountClaimRejected
	}
	if err != sql.ErrNoRows {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO node_accounts (
		  user_id,node_id,local_handle,local_user_id,status,account_version,is_admin,verified_at,updated_at
		) VALUES ($1,$2,$3,$4,'active',1,$5,$6,$6)`,
		p.GlobalUserID, p.NodeID, candidateHandle, p.LocalUserID, isAdmin, p.Now); err != nil {
		return err
	}
	var homeNodeID sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT home_node_id FROM users WHERE id=$1 FOR UPDATE`, legacyUserID).Scan(&homeNodeID); err != nil {
		return err
	}
	kind, replicaState := "hot_standby", "stale"
	if !homeNodeID.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET home_node_id=$2 WHERE id=$1`, legacyUserID, p.NodeID); err != nil {
			return err
		}
		kind, replicaState = "home", "ready"
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,data_version,state,last_sync_at)
		VALUES ($1,$2,$3,0,$4,$5)
		ON CONFLICT (user_id,node_id) DO UPDATE SET kind=EXCLUDED.kind,state=EXCLUDED.state,last_sync_at=EXCLUDED.last_sync_at`,
		legacyUserID, p.NodeID, kind, replicaState, p.Now); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE account_import_candidates SET resolution_state='claimed',matched_user_id=$2,
		  reason_code='password_control_proof',updated_at=$3 WHERE id=$1`,
		candidateID, p.GlobalUserID, p.Now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrAccountClaimRejected
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE account_import_batches SET auto_linked_count=auto_linked_count+1,
		  unresolved_count=GREATEST(0,unresolved_count-1),
		  state=CASE WHEN unresolved_count<=1 THEN 'resolved' ELSE state END,updated_at=$2 WHERE id=$1`,
		batchID, p.Now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrAccountClaimRejected
	}
	result, err = tx.ExecContext(ctx, `
		INSERT INTO account_import_claim_operations (
		  operation_id,candidate_id,user_id,node_id,local_user_id,controller_generation,completed_at
		) SELECT $1,$2,$3,$4,$5,generation,$6 FROM controller_epochs WHERE state='active'`,
		p.OperationID, candidateID, p.GlobalUserID, p.NodeID, p.LocalUserID, p.Now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrNoActiveController
	}
	return tx.Commit()
}

func equalFoldASCII(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		l, r := left[index], right[index]
		if l >= 'A' && l <= 'Z' {
			l += 'a' - 'A'
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		if l != r {
			return false
		}
	}
	return true
}

func (s *Store) ListActiveOAuthIdentitySubjects(ctx context.Context) ([]OAuthIdentitySubject, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT user_id,provider,provider_subject
		FROM auth_identities
		WHERE provider IN ('discord','linuxdo') AND status='active'
		ORDER BY user_id,provider`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var identities []OAuthIdentitySubject
	for rows.Next() {
		var identity OAuthIdentitySubject
		if err := rows.Scan(&identity.GlobalUserID, &identity.Provider, &identity.Subject); err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	return identities, rows.Err()
}

func (s *Store) IngestAccountImportBatch(
	ctx context.Context,
	p CreateAccountImportBatchParams,
) (*AccountImportResult, error) {
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	if err := validateAccountImportBatch(p); err != nil {
		return nil, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var existingID string
	var existingNodeID int64
	var existingDigest []byte
	err = tx.QueryRowContext(ctx, `
		SELECT id,node_id,inventory_digest FROM account_import_batches
		WHERE operation_id=$1 FOR UPDATE`, p.OperationID).
		Scan(&existingID, &existingNodeID, &existingDigest)
	if err == nil {
		if existingNodeID != p.NodeID || !bytes.Equal(existingDigest, p.InventoryDigest) {
			return nil, ErrAccountImportConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		result, err := s.GetAccountImportBatch(ctx, existingID)
		if result != nil {
			result.Batch.Replayed = true
		}
		return result, err
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	var generation int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO account_import_batches (
		  id,operation_id,node_id,controller_generation,inventory_digest,source,state,
		  created_by_admin_id,scanned_at,created_at,updated_at
		)
		SELECT $1,$2,$3,generation,$4,$5,'review',$6,$7,$7,$7
		FROM controller_epochs WHERE state='active'
		RETURNING controller_generation`, p.ID, p.OperationID, p.NodeID, p.InventoryDigest,
		p.Source, p.CreatedByAdminID, p.Now).Scan(&generation)
	if err == sql.ErrNoRows {
		return nil, ErrNoActiveController
	}
	if err != nil {
		return nil, err
	}

	autoLinked := 0
	for _, candidate := range p.Candidates {
		state, matchedUserID, reason, err := classifyAndLinkImportCandidate(
			ctx, tx, p.NodeID, candidate, p.Now,
		)
		if err != nil {
			return nil, err
		}
		if state == "already_managed" || state == "auto_linked" {
			autoLinked++
		}
		fingerprint, _ := hex.DecodeString(candidate.DirectoryFingerprint)
		identities := make(map[string]string, len(candidate.Identities))
		for _, identity := range candidate.Identities {
			identities[identity.Provider] = identity.Fingerprint
		}
		encodedIdentities, err := json.Marshal(identities)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO account_import_candidates (
			  id,batch_id,node_id,local_user_id,local_handle,size_bytes,directory_fingerprint,
			  source,account_kind,identity_fingerprints,is_admin,resolution_state,
			  matched_user_id,reason_code,created_at,updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15,$15)`,
			candidate.ID, p.ID, p.NodeID, candidate.LocalUserID, candidate.LocalHandle,
			candidate.SizeBytes, fingerprint, candidate.Source, candidate.AccountKind,
			encodedIdentities, candidate.IsAdmin, state, nullInt64(matchedUserID), reason, p.Now); err != nil {
			return nil, err
		}
	}
	unresolved := len(p.Candidates) - autoLinked
	batchState := "review"
	if unresolved == 0 {
		batchState = "resolved"
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE account_import_batches
		SET state=$2,candidate_count=$3,auto_linked_count=$4,unresolved_count=$5,updated_at=$6
		WHERE id=$1`, p.ID, batchState, len(p.Candidates), autoLinked, unresolved, p.Now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	_ = generation
	return s.GetAccountImportBatch(ctx, p.ID)
}

func classifyAndLinkImportCandidate(
	ctx context.Context,
	tx *sql.Tx,
	nodeID int64,
	candidate AccountImportCandidateInput,
	now time.Time,
) (string, int64, string, error) {
	var existingUserID int64
	var existingLocalUserID sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT user_id,local_user_id FROM node_accounts
		WHERE node_id=$1 AND (local_handle=$2 OR local_user_id=$3)
		ORDER BY CASE WHEN local_user_id=$3 THEN 0 ELSE 1 END
		LIMIT 1 FOR UPDATE`, nodeID, candidate.LocalHandle, candidate.LocalUserID).
		Scan(&existingUserID, &existingLocalUserID)
	if err == nil {
		if existingLocalUserID.Valid && existingLocalUserID.String != candidate.LocalUserID {
			return "identity_conflict", 0, "local_handle_collision", nil
		}
		return "already_managed", existingUserID, "node_account_exists", nil
	}
	if err != sql.ErrNoRows {
		return "", 0, "", err
	}

	matchedIDs := uniquePositiveIDs(candidate.MatchedGlobalUserIDs)
	if len(matchedIDs) > 1 {
		return "identity_conflict", 0, "oauth_subjects_split", nil
	}
	if len(matchedIDs) == 1 {
		globalUserID := matchedIDs[0]
		var legacyUserID sql.NullInt64
		var status string
		if err := tx.QueryRowContext(ctx, `
			SELECT legacy_user_id,status FROM global_users WHERE id=$1 FOR UPDATE`, globalUserID).
			Scan(&legacyUserID, &status); err != nil {
			if err == sql.ErrNoRows {
				return "identity_conflict", 0, "matched_user_missing", nil
			}
			return "", 0, "", err
		}
		if !legacyUserID.Valid || (status != "active" && status != "recovering") {
			return "identity_conflict", 0, "matched_user_unavailable", nil
		}
		var otherHandle string
		err := tx.QueryRowContext(ctx, `
			SELECT local_handle FROM node_accounts WHERE user_id=$1 AND node_id=$2 FOR UPDATE`,
			globalUserID, nodeID).Scan(&otherHandle)
		if err == nil {
			return "identity_conflict", 0, "user_already_has_other_node_account", nil
		}
		if err != sql.ErrNoRows {
			return "", 0, "", err
		}
		var oauthSubjects []byte
		if err := tx.QueryRowContext(ctx, `
			SELECT COALESCE(jsonb_object_agg(provider,provider_subject),'{}'::jsonb)
			FROM auth_identities
			WHERE user_id=$1 AND provider IN ('discord','linuxdo') AND status='active'`, globalUserID).
			Scan(&oauthSubjects); err != nil {
			return "", 0, "", err
		}
		result, err := tx.ExecContext(ctx, `
			INSERT INTO node_accounts (
			  user_id,node_id,local_handle,local_user_id,status,account_version,
			  oauth_subjects,is_admin,verified_at,updated_at
			) VALUES ($1,$2,$3,$4,'active',1,$5::jsonb,$6,$7,$7)
			ON CONFLICT DO NOTHING`, globalUserID, nodeID, candidate.LocalHandle,
			candidate.LocalUserID, oauthSubjects, candidate.IsAdmin, now)
		if err != nil {
			return "", 0, "", err
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			return "", 0, "", err
		}
		if inserted != 1 {
			return "identity_conflict", 0, "node_account_race", nil
		}
		var homeNodeID int64
		if err := tx.QueryRowContext(ctx, `
			UPDATE users SET home_node_id=COALESCE(home_node_id,$2)
			WHERE id=$1 RETURNING home_node_id`, legacyUserID.Int64, nodeID).Scan(&homeNodeID); err != nil {
			return "", 0, "", err
		}
		replicaKind, replicaState := "hot_standby", "stale"
		if homeNodeID == nodeID {
			replicaKind, replicaState = "home", "ready"
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO user_replicas (user_id,node_id,kind,data_version,state,last_sync_at)
			VALUES ($1,$2,$3,0,$4,$5)
			ON CONFLICT (user_id,node_id) DO UPDATE
			SET kind=EXCLUDED.kind,state=EXCLUDED.state,last_sync_at=EXCLUDED.last_sync_at`,
			legacyUserID.Int64, nodeID, replicaKind, replicaState, now); err != nil {
			return "", 0, "", err
		}
		return "auto_linked", globalUserID, "oauth_subject_match", nil
	}

	var handleMatch int64
	err = tx.QueryRowContext(ctx, `
		SELECT global_user.id FROM users legacy
		JOIN global_users global_user ON global_user.legacy_user_id=legacy.id
		WHERE lower(legacy.username)=lower($1) AND global_user.status<>'deleted'
		ORDER BY global_user.id LIMIT 1`, candidate.LocalHandle).Scan(&handleMatch)
	if err == nil {
		// A same-name collision needs control proof, but the proof must match
		// the account's actual credentials: password accounts prove with the
		// node password (claim_required), OAuth-only accounts prove by logging
		// in with that provider (oauth_unmatched -> resolved on OAuth login).
		// Sending an OAuth-only account to the password-claim guard would leave
		// it permanently stuck.
		if candidate.AccountKind == "oauth" && len(candidate.Identities) > 0 {
			return "oauth_unmatched", 0, "same_handle_oauth_proof_required", nil
		}
		return "claim_required", 0, "same_handle_requires_control_proof", nil
	}
	if err != sql.ErrNoRows {
		return "", 0, "", err
	}
	if len(candidate.Identities) > 0 {
		return "oauth_unmatched", 0, "oauth_login_proof_required", nil
	}
	return "recovery_required", 0, "no_recoverable_identity", nil
}

func (s *Store) GetAccountImportBatch(ctx context.Context, batchID string) (*AccountImportResult, error) {
	return s.GetAccountImportBatchPage(ctx, batchID, 0, MaxAccountImportPageSize)
}

func (s *Store) GetAccountImportBatchPage(
	ctx context.Context,
	batchID string,
	offset, limit int,
) (*AccountImportResult, error) {
	if batchID == "" || offset < 0 || offset > maxAccountImportCandidates ||
		limit <= 0 || limit > MaxAccountImportPageSize {
		return nil, ErrInvalidAccountImport
	}
	result := AccountImportResult{CandidateOffset: offset, CandidateLimit: limit}
	err := s.DB.QueryRowContext(ctx, `
		SELECT id,node_id,source,state,candidate_count,auto_linked_count,unresolved_count,
		  scanned_at,created_at
		FROM account_import_batches WHERE id=$1`, batchID).
		Scan(&result.Batch.ID, &result.Batch.NodeID, &result.Batch.Source, &result.Batch.State,
			&result.Batch.CandidateCount, &result.Batch.AutoLinkedCount, &result.Batch.UnresolvedCount,
			&result.Batch.ScannedAt, &result.Batch.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT candidate.id,candidate.local_handle,candidate.size_bytes,candidate.source,
		  candidate.account_kind,candidate.identity_fingerprints,candidate.is_admin,
		  candidate.resolution_state,COALESCE(global_user.uuid::text,''),candidate.reason_code
		FROM account_import_candidates candidate
		LEFT JOIN global_users global_user ON global_user.id=candidate.matched_user_id
		WHERE candidate.batch_id=$1
		ORDER BY candidate.local_handle,candidate.id
		LIMIT $2 OFFSET $3`, batchID, limit+1, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		if len(result.Candidates) == limit {
			result.HasMore = true
			result.NextCandidateOffset = offset + limit
			break
		}
		var candidate AccountImportCandidate
		var identitiesJSON []byte
		if err := rows.Scan(&candidate.ID, &candidate.LocalHandle, &candidate.SizeBytes,
			&candidate.Source, &candidate.AccountKind, &identitiesJSON, &candidate.IsAdmin,
			&candidate.ResolutionState, &candidate.MatchedUserUUID, &candidate.ReasonCode); err != nil {
			return nil, err
		}
		var identities map[string]string
		if err := json.Unmarshal(identitiesJSON, &identities); err != nil {
			return nil, err
		}
		candidate.IdentityProviders = make([]string, 0, len(identities))
		for provider := range identities {
			candidate.IdentityProviders = append(candidate.IdentityProviders, provider)
		}
		sort.Strings(candidate.IdentityProviders)
		result.Candidates = append(result.Candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &result, nil
}


// ListUnscannedComputeNodes returns compute nodes that have never been
// scanned or whose latest successful scan is older than the given window,
// ordered by staleness.  Used by the optional unattended import scanner
// (R16); operators can keep scanning fully manual by leaving it disabled.
func (s *Store) ListUnscannedComputeNodes(ctx context.Context, olderThan time.Time, limit int) ([]int64, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT node.id FROM nodes node
		WHERE node.role='compute'
		  AND node.connectivity_state='online' AND node.operational_state='active'
		  AND node.compatibility_state='compatible' AND node.control_mode='managed'
		  AND node.desired_control_mode='managed'
		  AND NOT EXISTS (
		    SELECT 1 FROM account_import_batches batch
		    WHERE batch.node_id=node.id AND batch.state='review' AND batch.scanned_at>$2
		  )
		ORDER BY node.id LIMIT $1`, limit, olderThan)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) GetLatestAccountImportBatch(ctx context.Context, nodeID int64) (*AccountImportResult, error) {
	return s.GetLatestAccountImportBatchPage(ctx, nodeID, 0, MaxAccountImportPageSize)
}

func (s *Store) GetLatestAccountImportBatchPage(
	ctx context.Context,
	nodeID int64,
	offset, limit int,
) (*AccountImportResult, error) {
	if nodeID <= 0 {
		return nil, ErrInvalidAccountImport
	}
	var batchID string
	err := s.DB.QueryRowContext(ctx, `
		SELECT id FROM account_import_batches WHERE node_id=$1 ORDER BY created_at DESC LIMIT 1`, nodeID).
		Scan(&batchID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.GetAccountImportBatchPage(ctx, batchID, offset, limit)
}

func (s *Store) GetAccountImportBatchByOperation(
	ctx context.Context,
	operationID string,
	offset, limit int,
) (*AccountImportResult, error) {
	if operationID == "" {
		return nil, ErrInvalidAccountImport
	}
	var batchID string
	err := s.DB.QueryRowContext(ctx, `
		SELECT id FROM account_import_batches WHERE operation_id=$1`, operationID).Scan(&batchID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.GetAccountImportBatchPage(ctx, batchID, offset, limit)
}

func validateAccountImportBatch(p CreateAccountImportBatchParams) error {
	if p.ID == "" || p.OperationID == "" || p.NodeID <= 0 || len(p.InventoryDigest) != 32 ||
		(p.Source != "adapter" && p.Source != "directory_fallback" && p.Source != "mixed") ||
		p.CreatedByAdminID <= 0 || len(p.Candidates) > maxAccountImportCandidates {
		return ErrInvalidAccountImport
	}
	seen := make(map[string]struct{}, len(p.Candidates))
	for _, candidate := range p.Candidates {
		if candidate.ID == "" || candidate.LocalUserID == "" || len(candidate.LocalUserID) > 256 ||
			candidate.LocalHandle == "" || len(candidate.LocalHandle) > 128 || candidate.SizeBytes < 0 ||
			(candidate.Source != "adapter" && candidate.Source != "directory_fallback") ||
			(candidate.AccountKind != "password" && candidate.AccountKind != "oauth" &&
				candidate.AccountKind != "mixed" && candidate.AccountKind != "unknown") ||
			!validHexDigest(candidate.DirectoryFingerprint) || len(candidate.Identities) > 2 {
			return ErrInvalidAccountImport
		}
		if _, exists := seen[candidate.LocalUserID]; exists {
			return ErrInvalidAccountImport
		}
		seen[candidate.LocalUserID] = struct{}{}
		providers := make(map[string]struct{}, len(candidate.Identities))
		for _, identity := range candidate.Identities {
			if (identity.Provider != "discord" && identity.Provider != "linuxdo") ||
				!validHexDigest(identity.Fingerprint) {
				return ErrInvalidAccountImport
			}
			if _, exists := providers[identity.Provider]; exists {
				return ErrInvalidAccountImport
			}
			providers[identity.Provider] = struct{}{}
		}
		hasOAuth := len(candidate.Identities) > 0
		if (candidate.Source == "directory_fallback" &&
			(candidate.AccountKind != "unknown" || hasOAuth || candidate.IsAdmin)) ||
			((candidate.AccountKind == "oauth" || candidate.AccountKind == "mixed") != hasOAuth) {
			return ErrInvalidAccountImport
		}
	}
	return nil
}

func validHexDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func uniquePositiveIDs(values []int64) []int64 {
	seen := make(map[int64]struct{}, len(values))
	result := make([]int64, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func nullInt64(value int64) any {
	if value <= 0 {
		return nil
	}
	return value
}
