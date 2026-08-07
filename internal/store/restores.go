package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidRestoreWorkflow = errors.New("invalid restore workflow input")
	ErrRestoreUnavailable     = errors.New("restore source or target unavailable")
	ErrRestoreConflict        = errors.New("restore operation conflicts with existing facts")
)

type RestoreTarget struct {
	NodeID int64  `json:"node_id"`
	Name   string `json:"name"`
	Region string `json:"region"`
}

type CreateRestoreWorkflowParams struct {
	OperationID        string
	RequestDigest      []byte
	WorkflowID         string
	RestoreSnapshotID  string
	CapabilityID       string
	CapabilityHash     []byte
	GlobalUserID       int64
	TargetNodeID       int64
	ExpectedRecoveryAt time.Time
	CapabilityExpires  time.Time
	Now                time.Time
}

type RestoreWorkflowExecution struct {
	JobID                int64
	OperationID          string
	WorkflowID           string
	State                string
	Attempt              int
	GlobalUserID         int64
	LegacyUserID         int64
	Handle               string
	DisplayName          string
	SourceNodeID         int64
	TargetNodeID         int64
	SourceSnapshotID     string
	RestoreSnapshotID    string
	SourceManifestSHA256 []byte
	SourcePublishedAt    time.Time
	ActivityEpoch        int64
	ControllerGeneration int64
	CapabilityID         string
	CapabilityHash       []byte
	CapabilityExpires    time.Time
	CapabilityState      string
	TargetAccountStatus  string
	TargetLocalUserID    string
	AccountVersion       int64
	PasswordHash         string
	PasswordSalt         string
	OAuthProvider        string
	OAuthSubject         string
}

type RestoreOperationStatus struct {
	OperationID       string    `json:"operation_id"`
	State             string    `json:"state"`
	TargetNodeID      int64     `json:"target_node_id"`
	TargetNodeName    string    `json:"target_node_name"`
	SourcePublishedAt time.Time `json:"source_published_at"`
	ErrorSummary      string    `json:"error,omitempty"`
}

type CompleteRestoreWorkflowParams struct {
	WorkflowID        string
	RestoreSnapshotID string
	CapabilityHash    []byte
	ManifestSHA256    []byte
	ArchiveSHA256     []byte
	FileCount         int64
	TotalBytes        int64
	Now               time.Time
}

func (s *Store) ListRestoreTargets(ctx context.Context, globalUserID int64, limit int) ([]RestoreTarget, error) {
	if globalUserID <= 0 {
		return nil, ErrInvalidRestoreWorkflow
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT node.id,node.name,COALESCE(node.region,'')
		FROM user_protection_states protection
		JOIN global_users global_user ON global_user.id=protection.user_id AND global_user.status='active'
		JOIN users legacy ON legacy.id=global_user.legacy_user_id AND legacy.status='active'
		JOIN nodes node ON node.role='compute'
		  AND node.connectivity_state='online' AND node.operational_state='active'
		  AND node.compatibility_state='compatible' AND node.capacity_state IN ('open','busy')
		  AND node.transfer_url<>''
		WHERE protection.user_id=$1 AND protection.state='restore_required'
		  AND node.id<>COALESCE(protection.authoritative_node_id,0)
		  AND node.id<>COALESCE(protection.recovery_node_id,0)
		  AND NOT EXISTS (
		    SELECT 1 FROM replica_copies copy WHERE copy.user_id=protection.user_id
		      AND copy.node_id=node.id AND copy.state='conflict'
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM node_accounts account WHERE account.node_id=node.id
		      AND ((account.user_id=protection.user_id AND account.status IN ('disabled','conflict'))
		        OR (account.user_id<>protection.user_id AND account.local_handle=legacy.username))
		  )
		  AND (
		    EXISTS (SELECT 1 FROM node_accounts account WHERE account.user_id=protection.user_id
		      AND account.node_id=node.id AND account.status='active')
		    OR EXISTS (SELECT 1 FROM node_accounts account WHERE account.user_id=protection.user_id
		      AND account.password_hash IS NOT NULL AND account.password_salt IS NOT NULL)
		    OR EXISTS (SELECT 1 FROM auth_identities identity WHERE identity.user_id=protection.user_id
		      AND identity.status='active' AND identity.provider IN ('discord','linuxdo'))
		  )
		ORDER BY CASE node.capacity_state WHEN 'open' THEN 0 ELSE 1 END,node.id LIMIT $2`,
		globalUserID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var targets []RestoreTarget
	for rows.Next() {
		var target RestoreTarget
		if err := rows.Scan(&target.NodeID, &target.Name, &target.Region); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (s *Store) CreateRestoreWorkflow(
	ctx context.Context,
	p CreateRestoreWorkflowParams,
) (*RestoreWorkflowExecution, error) {
	if p.OperationID == "" || len(p.RequestDigest) != 32 || p.WorkflowID == "" ||
		p.RestoreSnapshotID == "" || p.CapabilityID == "" || len(p.CapabilityHash) != 32 ||
		p.GlobalUserID <= 0 || p.TargetNodeID <= 0 || p.ExpectedRecoveryAt.IsZero() {
		return nil, ErrInvalidRestoreWorkflow
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	if !p.CapabilityExpires.After(p.Now) {
		return nil, ErrInvalidRestoreWorkflow
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockGlobalUser(ctx, tx, p.GlobalUserID); err != nil {
		return nil, err
	}
	if replay, ok, err := getRestoreOperation(ctx, tx, p); err != nil {
		return nil, err
	} else if ok {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return replay, nil
	}

	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&generation); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNoActiveController
		}
		return nil, err
	}
	lease, found, err := getActivityLeaseForUpdate(ctx, tx, p.GlobalUserID)
	if err != nil {
		return nil, err
	}
	if found && (leaseBlocksNewWriter(lease, p.Now) || lease.InFlightReads != 0 || lease.InFlightWrites != 0 ||
		lease.State == "independent" || lease.State == "quiescing") {
		return nil, ErrReplicaTakeoverLeaseActive
	}
	var workflowActive bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM workflows WHERE user_id=$1
		    AND workflow_type IN ('snapshot','restore','conflict_resolution')
		    AND state NOT IN ('cancelled','failed','succeeded')
		)`, p.GlobalUserID).Scan(&workflowActive); err != nil {
		return nil, err
	}
	if workflowActive {
		return nil, ErrRestoreConflict
	}

	var execution RestoreWorkflowExecution
	var oldHomeNodeID int64
	err = tx.QueryRowContext(ctx, `
		SELECT global_user.legacy_user_id,legacy.username,global_user.display_name,legacy.home_node_id,
		  protection.recovery_node_id,protection.latest_recovery_snapshot_id::text,
		  protection.latest_recovery_at,snapshot.manifest_sha256,snapshot.activity_epoch
		FROM global_users global_user
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		JOIN user_protection_states protection ON protection.user_id=global_user.id
		JOIN replica_copies copy ON copy.user_id=global_user.id
		  AND copy.node_id=protection.recovery_node_id AND copy.snapshot_id=protection.latest_recovery_snapshot_id
		  AND copy.replica_kind='archive' AND copy.state='ready' AND copy.compatibility_state='compatible'
		JOIN snapshot_manifests snapshot ON snapshot.id=copy.snapshot_id AND snapshot.user_id=global_user.id
		  AND snapshot.state='immutable'
		JOIN nodes source ON source.id=copy.node_id AND source.role='storage'
		  AND source.connectivity_state='online' AND source.operational_state='active'
		  AND source.compatibility_state='compatible'
		WHERE global_user.id=$1 AND global_user.status='active' AND legacy.status='active'
		  AND protection.state='restore_required' AND protection.latest_recovery_at=$2
		FOR UPDATE OF global_user,legacy,protection,copy,snapshot`, p.GlobalUserID, p.ExpectedRecoveryAt).Scan(
		&execution.LegacyUserID, &execution.Handle, &execution.DisplayName, &oldHomeNodeID, &execution.SourceNodeID,
		&execution.SourceSnapshotID, &execution.SourcePublishedAt,
		&execution.SourceManifestSHA256, &execution.ActivityEpoch,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrRestoreUnavailable
		}
		return nil, err
	}
	if execution.SourceNodeID == p.TargetNodeID || oldHomeNodeID == p.TargetNodeID {
		return nil, ErrRestoreUnavailable
	}
	var targetID int64
	err = tx.QueryRowContext(ctx, `
		SELECT node.id FROM nodes node
		JOIN global_users global_user ON global_user.id=$1
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		WHERE node.id=$2 AND node.role='compute' AND node.connectivity_state='online'
		  AND node.operational_state='active' AND node.compatibility_state='compatible'
		  AND node.capacity_state IN ('open','busy') AND node.transfer_url<>''
		  AND NOT EXISTS (
		    SELECT 1 FROM replica_copies copy WHERE copy.user_id=$1 AND copy.node_id=$2 AND copy.state='conflict'
		  ) AND NOT EXISTS (
		    SELECT 1 FROM node_accounts account WHERE account.node_id=$2
		      AND ((account.user_id=$1 AND account.status IN ('disabled','conflict'))
		        OR (account.user_id<>$1 AND account.local_handle=legacy.username))
		  ) FOR SHARE OF node,global_user,legacy`, p.GlobalUserID, p.TargetNodeID).Scan(&targetID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrRestoreUnavailable
		}
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO workflows (
		  id,operation_id,workflow_type,state,user_id,source_node_id,target_node_id,
		  activity_epoch,controller_generation,created_at,updated_at
		) VALUES ($1,$2,'restore','scheduled',$3,$4,$5,$6,$7,$8,$8)`,
		p.WorkflowID, p.OperationID, p.GlobalUserID, execution.SourceNodeID,
		p.TargetNodeID, execution.ActivityEpoch, generation, p.Now); err != nil {
		return nil, err
	}
	accountProvisionRequired, err := prepareRestoreTargetAccount(
		ctx, tx, p.WorkflowID, p.GlobalUserID, p.TargetNodeID, execution.Handle, p.Now,
	)
	if err != nil {
		return nil, err
	}
	zeroDigest := make([]byte, 32)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO snapshot_manifests (
		  id,workflow_id,user_id,source_node_id,activity_epoch,format_version,
		  manifest_sha256,file_count,total_bytes,state,created_at
		) VALUES ($1,$2,$3,$4,$5,1,$6,0,0,'building',$7)`,
		p.RestoreSnapshotID, p.WorkflowID, p.GlobalUserID, execution.SourceNodeID,
		execution.ActivityEpoch, zeroDigest, p.Now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO snapshot_transfer_capabilities (
		  id,workflow_id,snapshot_id,source_node_id,target_node_id,token_hash,
		  state,controller_generation,expires_at,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,'prepared',$7,$8,$9)`,
		p.CapabilityID, p.WorkflowID, p.RestoreSnapshotID, execution.SourceNodeID,
		p.TargetNodeID, p.CapabilityHash, generation, p.CapabilityExpires, p.Now); err != nil {
		return nil, err
	}
	for _, step := range []string{"provision_account", "prepare_target", "transfer", "verify", "publish"} {
		stepState := "pending"
		if step == "provision_account" && !accountProvisionRequired {
			stepState = "succeeded"
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO workflow_steps (workflow_id,step_name,state,updated_at)
			VALUES ($1,$2,$3,$4)`, p.WorkflowID, step, stepState, p.Now); err != nil {
			return nil, err
		}
	}
	var jobID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO restore_operations (
		  operation_id,request_digest,workflow_id,user_id,source_node_id,target_node_id,
		  source_snapshot_id,restore_snapshot_id,source_published_at,acknowledged_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
		p.OperationID, p.RequestDigest, p.WorkflowID, p.GlobalUserID, execution.SourceNodeID,
		p.TargetNodeID, execution.SourceSnapshotID, p.RestoreSnapshotID,
		execution.SourcePublishedAt, p.Now).Scan(&jobID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,data_version,state)
		VALUES ($1,$2,'hot_standby',0,'syncing')
		ON CONFLICT (user_id,node_id) DO UPDATE SET kind='hot_standby',state='syncing'`,
		execution.LegacyUserID, p.TargetNodeID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  actor_type,actor_id,action,target_type,target_id,operation_id,
		  controller_generation,input_digest,outcome,detail
		) VALUES ('user',$1::text,'archive-restore','global_user',$1::text,$2,$3,$4,
		  'scheduled',jsonb_build_object('source_node_id',$5,'target_node_id',$6,
		    'source_snapshot_id',$7,'source_published_at',$8))`,
		p.GlobalUserID, p.OperationID, generation, p.RequestDigest,
		execution.SourceNodeID, p.TargetNodeID, execution.SourceSnapshotID, execution.SourcePublishedAt); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	execution.JobID = jobID
	execution.OperationID = p.OperationID
	execution.WorkflowID = p.WorkflowID
	execution.State = "scheduled"
	execution.GlobalUserID = p.GlobalUserID
	execution.TargetNodeID = p.TargetNodeID
	execution.RestoreSnapshotID = p.RestoreSnapshotID
	execution.ControllerGeneration = generation
	execution.CapabilityID = p.CapabilityID
	execution.CapabilityHash = p.CapabilityHash
	execution.CapabilityExpires = p.CapabilityExpires
	execution.CapabilityState = "prepared"
	if accountProvisionRequired {
		execution.TargetAccountStatus = "pending"
	} else {
		execution.TargetAccountStatus = "active"
	}
	return &execution, nil
}

func prepareRestoreTargetAccount(
	ctx context.Context,
	tx *sql.Tx,
	workflowID string,
	globalUserID, targetNodeID int64,
	handle string,
	now time.Time,
) (bool, error) {
	var status string
	err := tx.QueryRowContext(ctx, `
		SELECT status FROM node_accounts WHERE user_id=$1 AND node_id=$2 FOR UPDATE`,
		globalUserID, targetNodeID).Scan(&status)
	if err == nil && status == "active" {
		return false, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	if status == "disabled" || status == "conflict" {
		return false, ErrRestoreUnavailable
	}

	var passwordHash, passwordSalt sql.NullString
	var passwordVersion int64
	err = tx.QueryRowContext(ctx, `
		SELECT password_hash,password_salt,password_material_version
		FROM node_accounts
		WHERE user_id=$1 AND password_hash IS NOT NULL AND password_salt IS NOT NULL
		ORDER BY password_material_version DESC,updated_at DESC LIMIT 1`, globalUserID).
		Scan(&passwordHash, &passwordSalt, &passwordVersion)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	var oauthProvider, oauthSubject string
	if err == sql.ErrNoRows {
		err = tx.QueryRowContext(ctx, `
			SELECT provider,provider_subject FROM auth_identities
			WHERE user_id=$1 AND status='active' AND provider IN ('discord','linuxdo')
			ORDER BY CASE provider WHEN 'discord' THEN 0 ELSE 1 END LIMIT 1`, globalUserID).
			Scan(&oauthProvider, &oauthSubject)
		if err != nil {
			if err == sql.ErrNoRows {
				return false, ErrRestoreUnavailable
			}
			return false, err
		}
	}
	oauthSubjects := `{}`
	if oauthProvider != "" {
		encoded, err := json.Marshal(map[string]string{oauthProvider: oauthSubject})
		if err != nil {
			return false, err
		}
		oauthSubjects = string(encoded)
	}
	if err == sql.ErrNoRows {
		passwordVersion = 0
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO node_accounts (
		  user_id,node_id,local_handle,status,account_version,password_material_version,
		  password_hash,password_salt,oauth_subjects,provisioning_workflow_id,updated_at
		) VALUES ($1,$2,$3,'pending',1,$4,$5,$6,$7::jsonb,$8,$9)
		ON CONFLICT (user_id,node_id) DO UPDATE SET local_handle=EXCLUDED.local_handle,status='pending',
		  account_version=node_accounts.account_version+1,
		  password_material_version=EXCLUDED.password_material_version,
		  password_hash=EXCLUDED.password_hash,password_salt=EXCLUDED.password_salt,
		  oauth_subjects=EXCLUDED.oauth_subjects,
		  provisioning_workflow_id=EXCLUDED.provisioning_workflow_id,updated_at=EXCLUDED.updated_at`,
		globalUserID, targetNodeID, handle, passwordVersion,
		nullIfEmpty(passwordHash.String), nullIfEmpty(passwordSalt.String), oauthSubjects, workflowID, now); err != nil {
		return false, err
	}
	return true, nil
}

func getRestoreOperation(
	ctx context.Context,
	tx *sql.Tx,
	p CreateRestoreWorkflowParams,
) (*RestoreWorkflowExecution, bool, error) {
	var execution RestoreWorkflowExecution
	var userID, targetNodeID int64
	var digest []byte
	err := tx.QueryRowContext(ctx, `
		SELECT operation.request_digest,operation.user_id,operation.target_node_id,
		  operation.id,operation.workflow_id::text,workflow.state,workflow.attempt,
		  global_user.legacy_user_id,legacy.username,global_user.display_name,
		  operation.source_node_id,operation.source_snapshot_id::text,
		  operation.restore_snapshot_id::text,source_snapshot.manifest_sha256,
		  operation.source_published_at,workflow.activity_epoch,workflow.controller_generation,
		  capability.id::text,capability.token_hash,capability.expires_at,capability.state,
		  target_account.status,COALESCE(target_account.local_user_id,''),
		  target_account.account_version,COALESCE(target_account.password_hash,''),
		  COALESCE(target_account.password_salt,''),
		  CASE WHEN target_account.password_hash IS NOT NULL THEN ''
		    WHEN target_account.oauth_subjects ? 'discord' THEN 'discord'
		    WHEN target_account.oauth_subjects ? 'linuxdo' THEN 'linuxdo' ELSE '' END,
		  CASE WHEN target_account.password_hash IS NOT NULL THEN ''
		    WHEN target_account.oauth_subjects ? 'discord' THEN target_account.oauth_subjects->>'discord'
		    WHEN target_account.oauth_subjects ? 'linuxdo' THEN target_account.oauth_subjects->>'linuxdo' ELSE '' END
		FROM restore_operations operation
		JOIN workflows workflow ON workflow.id=operation.workflow_id
		JOIN global_users global_user ON global_user.id=workflow.user_id
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		JOIN snapshot_manifests source_snapshot ON source_snapshot.id=operation.source_snapshot_id
		JOIN node_accounts target_account ON target_account.user_id=operation.user_id
		  AND target_account.node_id=operation.target_node_id
		JOIN LATERAL (
		  SELECT id,token_hash,expires_at,state FROM snapshot_transfer_capabilities
		  WHERE workflow_id=workflow.id ORDER BY created_at DESC LIMIT 1
		) capability ON true
		WHERE operation.operation_id=$1`, p.OperationID).Scan(
		&digest, &userID, &targetNodeID, &execution.JobID, &execution.WorkflowID,
		&execution.State, &execution.Attempt, &execution.LegacyUserID, &execution.Handle, &execution.DisplayName,
		&execution.SourceNodeID, &execution.SourceSnapshotID, &execution.RestoreSnapshotID,
		&execution.SourceManifestSHA256, &execution.SourcePublishedAt,
		&execution.ActivityEpoch, &execution.ControllerGeneration,
		&execution.CapabilityID, &execution.CapabilityHash,
		&execution.CapabilityExpires, &execution.CapabilityState,
		&execution.TargetAccountStatus, &execution.TargetLocalUserID, &execution.AccountVersion,
		&execution.PasswordHash, &execution.PasswordSalt, &execution.OAuthProvider, &execution.OAuthSubject,
	)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if userID != p.GlobalUserID || targetNodeID != p.TargetNodeID ||
		!execution.SourcePublishedAt.Equal(p.ExpectedRecoveryAt) || !bytes.Equal(digest, p.RequestDigest) {
		return nil, false, ErrRestoreConflict
	}
	execution.OperationID = p.OperationID
	execution.GlobalUserID = userID
	execution.TargetNodeID = targetNodeID
	return &execution, true, nil
}

func (s *Store) GetRestoreWorkflowExecution(ctx context.Context, workflowID string) (*RestoreWorkflowExecution, error) {
	if workflowID == "" {
		return nil, ErrInvalidRestoreWorkflow
	}
	var execution RestoreWorkflowExecution
	err := s.DB.QueryRowContext(ctx, `
		SELECT operation.id,operation.operation_id::text,workflow.id::text,workflow.state,workflow.attempt,
		  workflow.user_id,global_user.legacy_user_id,legacy.username,global_user.display_name,
		  workflow.source_node_id,workflow.target_node_id,operation.source_snapshot_id::text,
		  operation.restore_snapshot_id::text,source_snapshot.manifest_sha256,
		  operation.source_published_at,workflow.activity_epoch,workflow.controller_generation,
		  capability.id::text,capability.token_hash,capability.expires_at,capability.state,
		  target_account.status,COALESCE(target_account.local_user_id,''),
		  target_account.account_version,COALESCE(target_account.password_hash,''),
		  COALESCE(target_account.password_salt,''),
		  CASE WHEN target_account.password_hash IS NOT NULL THEN ''
		    WHEN target_account.oauth_subjects ? 'discord' THEN 'discord'
		    WHEN target_account.oauth_subjects ? 'linuxdo' THEN 'linuxdo' ELSE '' END,
		  CASE WHEN target_account.password_hash IS NOT NULL THEN ''
		    WHEN target_account.oauth_subjects ? 'discord' THEN target_account.oauth_subjects->>'discord'
		    WHEN target_account.oauth_subjects ? 'linuxdo' THEN target_account.oauth_subjects->>'linuxdo' ELSE '' END
		FROM restore_operations operation
		JOIN workflows workflow ON workflow.id=operation.workflow_id
		JOIN global_users global_user ON global_user.id=workflow.user_id
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		JOIN snapshot_manifests source_snapshot ON source_snapshot.id=operation.source_snapshot_id
		JOIN node_accounts target_account ON target_account.user_id=operation.user_id
		  AND target_account.node_id=operation.target_node_id
		JOIN LATERAL (
		  SELECT id,token_hash,expires_at,state FROM snapshot_transfer_capabilities
		  WHERE workflow_id=workflow.id ORDER BY created_at DESC LIMIT 1
		) capability ON true
		WHERE workflow.id=$1`, workflowID).Scan(
		&execution.JobID, &execution.OperationID, &execution.WorkflowID, &execution.State, &execution.Attempt,
		&execution.GlobalUserID, &execution.LegacyUserID, &execution.Handle, &execution.DisplayName,
		&execution.SourceNodeID, &execution.TargetNodeID, &execution.SourceSnapshotID,
		&execution.RestoreSnapshotID, &execution.SourceManifestSHA256,
		&execution.SourcePublishedAt, &execution.ActivityEpoch, &execution.ControllerGeneration,
		&execution.CapabilityID, &execution.CapabilityHash, &execution.CapabilityExpires, &execution.CapabilityState,
		&execution.TargetAccountStatus, &execution.TargetLocalUserID, &execution.AccountVersion,
		&execution.PasswordHash, &execution.PasswordSalt, &execution.OAuthProvider, &execution.OAuthSubject,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &execution, err
}

func (s *Store) CompleteRestoreAccountProvision(
	ctx context.Context,
	workflowID string,
	accountVersion int64,
	localUserID string,
	now time.Time,
) error {
	if workflowID == "" || accountVersion <= 0 || localUserID == "" {
		return ErrInvalidRestoreWorkflow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var userID, targetNodeID int64
	var workflowState, accountStatus string
	var currentVersion int64
	var currentLocalUserID sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT workflow.user_id,workflow.target_node_id,workflow.state,
		  account.status,account.account_version,account.local_user_id
		FROM workflows workflow
		JOIN node_accounts account ON account.user_id=workflow.user_id
		  AND account.node_id=workflow.target_node_id
		WHERE workflow.id=$1 AND workflow.workflow_type='restore'
		FOR UPDATE OF workflow,account`, workflowID).Scan(
		&userID, &targetNodeID, &workflowState, &accountStatus, &currentVersion, &currentLocalUserID,
	)
	if err != nil {
		return err
	}
	if accountStatus == "active" {
		if currentVersion != accountVersion || (currentLocalUserID.Valid && currentLocalUserID.String != localUserID) {
			return ErrRestoreConflict
		}
		return tx.Commit()
	}
	if workflowState == "failed" || workflowState == "cancelled" || workflowState == "succeeded" ||
		accountStatus != "pending" || currentVersion != accountVersion {
		return ErrRestoreConflict
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE node_accounts SET status='active',local_user_id=$4,
		  provisioning_workflow_id=NULL,verified_at=$5,updated_at=$5
		WHERE user_id=$1 AND node_id=$2 AND account_version=$3 AND status='pending'`,
		userID, targetNodeID, accountVersion, localUserID, now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return err
	} else if rows != 1 {
		return ErrRestoreConflict
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE workflow_steps SET state='succeeded',finished_at=$2,updated_at=$2
		WHERE workflow_id=$1 AND step_name='provision_account' AND state<>'succeeded'`, workflowID, now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return err
	} else if rows != 1 {
		return ErrRestoreConflict
	}
	return tx.Commit()
}

func (s *Store) ListResumableRestoreWorkflowIDs(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id::text FROM workflows WHERE workflow_type='restore'
		  AND state IN ('scheduled','transferring','verifying','publishing','retry_wait')
		  AND (next_attempt_at IS NULL OR next_attempt_at<=now())
		ORDER BY updated_at LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) ClaimRestoreWorkflow(
	ctx context.Context,
	workflowID, workerID string,
	now time.Time,
	ttl time.Duration,
) (bool, error) {
	if workflowID == "" || workerID == "" || ttl <= 0 {
		return false, ErrInvalidRestoreWorkflow
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE workflows workflow SET lease_owner=$2,lease_until=$4,updated_at=$3
		FROM controller_epochs epoch
		WHERE workflow.id=$1 AND workflow.workflow_type='restore'
		  AND workflow.state NOT IN ('succeeded','cancelled','failed')
		  AND workflow.controller_generation=epoch.generation AND epoch.state='active'
		  AND (workflow.lease_until IS NULL OR workflow.lease_until<=$3)`,
		workflowID, workerID, now, now.Add(ttl))
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

func (s *Store) ResetRestoreTransferForRetry(ctx context.Context, workflowID string, now time.Time) error {
	if workflowID == "" {
		return ErrInvalidRestoreWorkflow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE workflows workflow SET state='transferring',updated_at=$2
		FROM controller_epochs epoch
		WHERE workflow.id=$1 AND workflow.workflow_type='restore'
		  AND workflow.state IN ('transferring','verifying')
		  AND workflow.controller_generation=epoch.generation AND epoch.state='active'`, workflowID, now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return err
	} else if rows != 1 {
		return ErrRestoreConflict
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflow_steps SET state='pending',finished_at=NULL,error_code=NULL,updated_at=$2
		WHERE workflow_id=$1 AND step_name IN ('transfer','verify','publish')`, workflowID, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetRestoreOperationStatus(
	ctx context.Context,
	globalUserID int64,
	operationID string,
) (*RestoreOperationStatus, error) {
	if globalUserID <= 0 || operationID == "" {
		return nil, ErrInvalidRestoreWorkflow
	}
	var status RestoreOperationStatus
	var errorSummary sql.NullString
	err := s.DB.QueryRowContext(ctx, `
		SELECT operation.operation_id::text,workflow.state,operation.target_node_id,target.name,
		  operation.source_published_at,workflow.error_summary
		FROM restore_operations operation
		JOIN workflows workflow ON workflow.id=operation.workflow_id
		JOIN nodes target ON target.id=operation.target_node_id
		WHERE operation.user_id=$1 AND operation.operation_id=$2`, globalUserID, operationID).Scan(
		&status.OperationID, &status.State, &status.TargetNodeID, &status.TargetNodeName,
		&status.SourcePublishedAt, &errorSummary,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	status.ErrorSummary = errorSummary.String
	return &status, err
}

func (s *Store) CompleteRestoreWorkflow(
	ctx context.Context,
	p CompleteRestoreWorkflowParams,
) error {
	if p.WorkflowID == "" || p.RestoreSnapshotID == "" || len(p.CapabilityHash) != 32 ||
		len(p.ManifestSHA256) != 32 || len(p.ArchiveSHA256) != 32 || p.FileCount < 0 || p.TotalBytes < 0 {
		return ErrInvalidRestoreWorkflow
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var state, globalUserStatus, legacyUserStatus string
	var operationID string
	var userID, legacyUserID, sourceNodeID, targetNodeID, oldHomeNodeID, generation int64
	var sourceSnapshotID string
	var sourcePublishedAt time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT workflow.state,global_user.status,legacy.status,operation.operation_id::text,
		  workflow.user_id,global_user.legacy_user_id,
		  operation.source_node_id,operation.target_node_id,legacy.home_node_id,
		  workflow.controller_generation,operation.source_snapshot_id::text,operation.source_published_at
		FROM workflows workflow
		JOIN restore_operations operation ON operation.workflow_id=workflow.id
		JOIN global_users global_user ON global_user.id=workflow.user_id
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		WHERE workflow.id=$1 AND operation.restore_snapshot_id=$2
		FOR UPDATE OF workflow,operation,global_user,legacy`, p.WorkflowID, p.RestoreSnapshotID).Scan(
		&state, &globalUserStatus, &legacyUserStatus, &operationID,
		&userID, &legacyUserID, &sourceNodeID, &targetNodeID,
		&oldHomeNodeID, &generation, &sourceSnapshotID, &sourcePublishedAt,
	)
	if err != nil {
		return err
	}
	if state == "succeeded" {
		return tx.Commit()
	}
	if state != "publishing" {
		return ErrRestoreConflict
	}
	if globalUserStatus != "active" || legacyUserStatus != "active" {
		return ErrRestoreConflict
	}
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&activeGeneration); err != nil {
		return err
	}
	if generation != activeGeneration {
		return ErrRestoreConflict
	}
	var verifiedSource string
	err = tx.QueryRowContext(ctx, `
		SELECT copy.snapshot_id::text FROM replica_copies copy
		JOIN snapshot_manifests snapshot ON snapshot.id=copy.snapshot_id AND snapshot.user_id=copy.user_id
		  AND snapshot.state='immutable'
		WHERE copy.user_id=$1 AND copy.node_id=$2 AND copy.snapshot_id=$3
		  AND copy.replica_kind='archive' AND copy.state='ready' AND copy.compatibility_state='compatible'
		  AND copy.published_at=$4 FOR SHARE OF copy,snapshot`,
		userID, sourceNodeID, sourceSnapshotID, sourcePublishedAt).Scan(&verifiedSource)
	if err != nil {
		return ErrRestoreUnavailable
	}
	var targetAccount int64
	err = tx.QueryRowContext(ctx, `
		SELECT account.id FROM node_accounts account
		JOIN nodes node ON node.id=account.node_id AND node.role='compute'
		  AND node.connectivity_state='online' AND node.operational_state='active'
		  AND node.compatibility_state='compatible'
		WHERE account.user_id=$1 AND account.node_id=$2 AND account.status='active'
		FOR SHARE OF account,node`, userID, targetNodeID).Scan(&targetAccount)
	if err != nil {
		return ErrRestoreUnavailable
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE snapshot_manifests SET manifest_sha256=$3,archive_sha256=$4,
		  file_count=$5,total_bytes=$6,state='immutable'
		WHERE id=$1 AND workflow_id=$2 AND state='building'`,
		p.RestoreSnapshotID, p.WorkflowID, p.ManifestSHA256, p.ArchiveSHA256, p.FileCount, p.TotalBytes)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrRestoreConflict
	}
	var dataVersion int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(data_version),0)+1 FROM user_replicas WHERE user_id=$1`, legacyUserID).Scan(&dataVersion); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE user_replicas SET kind='hot_standby',state='stale'
		WHERE user_id=$1 AND node_id=$2 AND kind='home'`, legacyUserID, oldHomeNodeID)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return err
	} else if rows != 1 {
		return ErrRestoreConflict
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE user_replicas SET kind='home',state='ready',data_version=$3,
		  checksum=$4,size_bytes=$5,last_sync_at=$6
		WHERE user_id=$1 AND node_id=$2`, legacyUserID, targetNodeID, dataVersion,
		fmt.Sprintf("%x", p.ManifestSHA256), p.TotalBytes, p.Now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return err
	} else if rows != 1 {
		return ErrRestoreConflict
	}
	result, err = tx.ExecContext(ctx, `UPDATE users SET home_node_id=$2 WHERE id=$1`, legacyUserID, targetNodeID)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return err
	} else if rows != 1 {
		return ErrRestoreConflict
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE replica_copies SET is_authoritative=false,
		  state=CASE WHEN node_id=$2 THEN 'stale' ELSE state END,updated_at=$3
		WHERE user_id=$1 AND (is_authoritative OR node_id=$2)`, userID, oldHomeNodeID, p.Now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO replica_copies (
		  id,user_id,node_id,snapshot_id,replica_kind,state,origin,is_authoritative,
		  compatibility_state,published_at,verified_at,created_at,updated_at
		) VALUES (gen_random_uuid(),$1,$2,$3,'active','ready','recovery',true,
		  'compatible',$4,$4,$4,$4)
		ON CONFLICT (user_id,node_id) DO UPDATE SET snapshot_id=EXCLUDED.snapshot_id,
		  replica_kind='active',state='ready',origin='recovery',is_authoritative=true,
		  compatibility_state='compatible',published_at=EXCLUDED.published_at,
		  verified_at=EXCLUDED.verified_at,updated_at=EXCLUDED.updated_at`,
		userID, targetNodeID, p.RestoreSnapshotID, p.Now); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE node_accounts SET status=CASE WHEN node_id=$2 THEN 'active' ELSE 'stale' END,
		  updated_at=$3 WHERE user_id=$1 AND node_id IN ($2,$4)`,
		userID, targetNodeID, p.Now, oldHomeNodeID)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return err
	} else if rows < 1 {
		return ErrRestoreConflict
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE user_activity_leases SET state='ended',lease_expires_at=$2,updated_at=$2
		WHERE user_id=$1`, userID, p.Now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE control_tickets SET revoked_at=COALESCE(revoked_at,$2)
		WHERE user_id=$1 AND consumed_at IS NULL`, userID, p.Now); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE snapshot_transfer_capabilities SET state='consumed',consumed_at=$2
		WHERE workflow_id=$1 AND token_hash=$3 AND state='prepared'`, p.WorkflowID, p.Now, p.CapabilityHash)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return err
	} else if rows != 1 {
		return ErrRestoreConflict
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE workflows SET state='succeeded',cleanup_state='succeeded',updated_at=$2,finished_at=$2
		WHERE id=$1 AND state='publishing'`, p.WorkflowID, p.Now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return err
	} else if rows != 1 {
		return ErrRestoreConflict
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflow_steps SET state='succeeded',finished_at=$2,updated_at=$2 WHERE workflow_id=$1`,
		p.WorkflowID, p.Now); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE restore_operations SET completed_at=$2 WHERE workflow_id=$1 AND completed_at IS NULL`, p.WorkflowID, p.Now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return err
	} else if rows != 1 {
		return ErrRestoreConflict
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_protection_states (
		  user_id,state,reason_code,authoritative_node_id,recovery_node_id,
		  latest_recovery_snapshot_id,latest_recovery_at,version,changed_at,evaluated_at
		) VALUES ($1,'unprotected','restore_completed_backup_required',$2,NULL,NULL,NULL,1,$3,$3)
		ON CONFLICT (user_id) DO UPDATE SET state='unprotected',
		  reason_code='restore_completed_backup_required',authoritative_node_id=$2,
		  recovery_node_id=NULL,latest_recovery_snapshot_id=NULL,latest_recovery_at=NULL,
		  version=user_protection_states.version+1,changed_at=$3,evaluated_at=$3`,
		userID, targetNodeID, p.Now); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  actor_type,actor_id,action,target_type,target_id,operation_id,
		  controller_generation,input_digest,outcome,detail
		) SELECT 'user',$1::text,'archive-restore','global_user',$1::text,$2,$3,
		  operation.request_digest,'succeeded',jsonb_build_object(
		    'source_node_id',$4,'target_node_id',$5,'source_snapshot_id',$6,
		    'source_published_at',$7,'restore_snapshot_id',$8)
		  FROM restore_operations operation WHERE operation.workflow_id=$9`,
		userID, operationID, generation, sourceNodeID, targetNodeID, sourceSnapshotID,
		sourcePublishedAt, p.RestoreSnapshotID, p.WorkflowID)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return err
	} else if rows != 1 {
		return ErrRestoreConflict
	}
	return tx.Commit()
}

func (s *Store) FailRestoreWorkflow(
	ctx context.Context,
	workflowID, errorCode, errorSummary string,
	now time.Time,
) error {
	if workflowID == "" || errorCode == "" {
		return ErrInvalidRestoreWorkflow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if len(errorSummary) > 512 {
		errorSummary = errorSummary[:512]
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var state, operationID string
	var userID, legacyUserID, targetNodeID, generation int64
	var requestDigest []byte
	err = tx.QueryRowContext(ctx, `
		SELECT workflow.state,operation.operation_id::text,workflow.user_id,
		  global_user.legacy_user_id,workflow.target_node_id,
		  workflow.controller_generation,operation.request_digest
		FROM workflows workflow
		JOIN restore_operations operation ON operation.workflow_id=workflow.id
		JOIN global_users global_user ON global_user.id=workflow.user_id
		WHERE workflow.id=$1 FOR UPDATE OF workflow,operation`, workflowID).Scan(
		&state, &operationID, &userID, &legacyUserID, &targetNodeID, &generation, &requestDigest,
	)
	if err != nil {
		return err
	}
	if state == "failed" {
		return tx.Commit()
	}
	if state == "succeeded" || state == "cancelled" {
		return ErrRestoreConflict
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE workflows SET state='failed',error_code=$2,error_summary=$3,
		  cleanup_state='pending',updated_at=$4,finished_at=$4,
		  lease_owner=NULL,lease_until=NULL
		WHERE id=$1 AND state NOT IN ('succeeded','cancelled','failed')`,
		workflowID, errorCode, nullIfEmpty(errorSummary), now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return err
	} else if rows != 1 {
		return ErrRestoreConflict
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflow_steps SET state='failed',error_code=$2,finished_at=$3,updated_at=$3
		WHERE workflow_id=$1 AND state<>'succeeded'`, workflowID, errorCode, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE snapshot_transfer_capabilities SET state='revoked'
		WHERE workflow_id=$1 AND state='prepared'`, workflowID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE snapshot_manifests SET state='invalid'
		WHERE workflow_id=$1 AND state='building'`, workflowID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE user_replicas SET state='error'
		WHERE user_id=$1 AND node_id=$2 AND kind='hot_standby' AND state='syncing'`,
		legacyUserID, targetNodeID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE node_accounts SET status='error',provisioning_workflow_id=NULL,updated_at=$3
		WHERE user_id=$1 AND node_id=$2 AND status='pending'`, userID, targetNodeID, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE restore_operations SET completed_at=COALESCE(completed_at,$2)
		WHERE workflow_id=$1`, workflowID, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  actor_type,actor_id,action,target_type,target_id,operation_id,
		  controller_generation,input_digest,outcome,detail
		) VALUES ('user',$1::text,'archive-restore','global_user',$1::text,$2,$3,$4,
		  'failed',jsonb_build_object('target_node_id',$5,'error_code',$6))`,
		userID, operationID, generation, requestDigest, targetNodeID, errorCode); err != nil {
		return err
	}
	return tx.Commit()
}
