package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidSnapshotWorkflow = errors.New("invalid snapshot workflow input")
	ErrSnapshotUserActive      = errors.New("snapshot user is active")
	ErrSnapshotStateConflict   = errors.New("snapshot workflow state conflict")
)

type CreateSnapshotWorkflowParams struct {
	WorkflowID                  string
	OperationID                 string
	SnapshotID                  string
	CapabilityID                string
	CapabilityHash              []byte
	LegacyBackupJobID           int64
	LegacyUserID                int64
	GlobalUserID                int64
	SourceNodeID                int64
	TargetNodeID                int64
	DestinationKind             string
	IndependentReconciliationID string
	IndependentMarker           string
	RetirementItemID            string
	RetirementTrigger           string
	CapabilityExpires           time.Time
	Now                         time.Time
}

type SnapshotWorkflow struct {
	WorkflowID           string
	SnapshotID           string
	ActivityEpoch        int64
	ControllerGeneration int64
}

type SnapshotWorkflowExecution struct {
	WorkflowID           string
	State                string
	Attempt              int
	SnapshotID           string
	ActivityEpoch        int64
	ControllerGeneration int64
	GlobalUserID         int64
	LegacyUserID         int64
	Handle               string
	SourceNodeID         int64
	TargetNodeID         int64
	CapabilityID         string
	CapabilityHash       []byte
	CapabilityExpires    time.Time
	CapabilityState      string
	LegacyBackupJobID    int64
	Trigger              string
	DestinationKind      string
	TransferMode         string
}

func (s *Store) CreateSnapshotWorkflow(ctx context.Context, p CreateSnapshotWorkflowParams) (SnapshotWorkflow, error) {
	retirementSnapshot := p.RetirementItemID != "" || p.RetirementTrigger != ""
	if p.WorkflowID == "" || p.OperationID == "" || p.SnapshotID == "" || p.CapabilityID == "" ||
		len(p.CapabilityHash) != 32 || (!retirementSnapshot && p.LegacyBackupJobID <= 0) || p.LegacyUserID <= 0 ||
		p.GlobalUserID <= 0 || p.SourceNodeID <= 0 || p.TargetNodeID <= 0 || p.SourceNodeID == p.TargetNodeID ||
		(p.DestinationKind != "archive" && p.DestinationKind != "hot_standby") {
		return SnapshotWorkflow{}, ErrInvalidSnapshotWorkflow
	}
	if retirementSnapshot && (!validUUIDText(p.RetirementItemID) || p.LegacyBackupJobID != 0 ||
		(p.RetirementTrigger != "node_retirement" && p.RetirementTrigger != "node_retirement_storage")) {
		return SnapshotWorkflow{}, ErrInvalidSnapshotWorkflow
	}
	independentReconciliation := p.IndependentReconciliationID != "" || p.IndependentMarker != ""
	if independentReconciliation && (p.IndependentReconciliationID == "" || p.IndependentMarker == "" ||
		p.DestinationKind != "archive") {
		return SnapshotWorkflow{}, ErrInvalidSnapshotWorkflow
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	if !p.CapabilityExpires.After(p.Now) {
		return SnapshotWorkflow{}, ErrInvalidSnapshotWorkflow
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return SnapshotWorkflow{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := tx.QueryRowContext(ctx, `SELECT id FROM global_users WHERE id=$1 FOR UPDATE`, p.GlobalUserID).Scan(new(int64)); err != nil {
		if err == sql.ErrNoRows {
			return SnapshotWorkflow{}, ErrInvalidSnapshotWorkflow
		}
		return SnapshotWorkflow{}, err
	}
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&generation); err != nil {
		if err == sql.ErrNoRows {
			return SnapshotWorkflow{}, ErrNoActiveController
		}
		return SnapshotWorkflow{}, err
	}
	legacyBackupJobID := p.LegacyBackupJobID
	if retirementSnapshot {
		var retirementNodeID, itemUserID, itemLegacyUserID, currentHomeNodeID, retirementGeneration int64
		var itemKind, itemState, operationState string
		err := tx.QueryRowContext(ctx, `
			SELECT operation.node_id,operation.state,item.user_id,COALESCE(item.legacy_user_id,0),
			  item.item_kind,item.state,COALESCE(legacy.home_node_id,0),operation.controller_generation
			FROM node_retirement_items item
			JOIN node_retirement_operations operation ON operation.id=item.retirement_id
			LEFT JOIN users legacy ON legacy.id=item.legacy_user_id
			WHERE item.id=$1 AND item.workflow_id IS NULL
			FOR UPDATE OF item,operation`, p.RetirementItemID).Scan(
			&retirementNodeID, &operationState, &itemUserID, &itemLegacyUserID, &itemKind, &itemState,
			&currentHomeNodeID, &retirementGeneration,
		)
		if err != nil {
			return SnapshotWorkflow{}, err
		}
		if itemUserID != p.GlobalUserID || itemLegacyUserID != p.LegacyUserID || operationState != "migrating" ||
			retirementGeneration != generation ||
			(itemState != "pending" && itemState != "waiting_offline" && itemState != "retry_wait" && itemState != "provisioning") ||
			(itemKind == "authoritative_home" && (retirementNodeID != p.SourceNodeID || p.DestinationKind != "hot_standby")) ||
			(itemKind == "archive_replica" && (retirementNodeID == p.SourceNodeID || currentHomeNodeID != p.SourceNodeID ||
				retirementNodeID == p.TargetNodeID || p.DestinationKind != "archive")) ||
			(itemKind != "authoritative_home" && itemKind != "archive_replica") {
			return SnapshotWorkflow{}, ErrNodeRetirementState
		}
		var sourceEligible, targetEligible bool
		if err := tx.QueryRowContext(ctx, `
			SELECT source.role='compute'
			    AND source.connectivity_state='online'
			    AND source.compatibility_state='compatible'
			    AND source.control_mode='managed' AND source.desired_control_mode='managed'
			    AND source.operational_state=CASE WHEN $3='authoritative_home' THEN 'retiring' ELSE 'active' END,
			  target.role=CASE WHEN $3='authoritative_home' THEN 'compute' ELSE 'storage' END
			    AND target.connectivity_state='online' AND target.operational_state='active'
			    AND target.compatibility_state='compatible'
			    AND target.control_mode='managed' AND target.desired_control_mode='managed'
			    AND target.capacity_state IN ('open','busy')
			    AND COALESCE(target.transfer_url,'')<>''
			    AND ($3='authoritative_home' OR target.is_backup_target)
			FROM nodes source CROSS JOIN nodes target
			WHERE source.id=$1 AND target.id=$2
			FOR SHARE OF source,target`, p.SourceNodeID, p.TargetNodeID, itemKind).Scan(
			&sourceEligible, &targetEligible,
		); err != nil {
			return SnapshotWorkflow{}, err
		}
		if !sourceEligible || !targetEligible {
			return SnapshotWorkflow{}, ErrNodeRetirementState
		}
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO backup_jobs (user_id,src_node_id,dst_node_id,trigger,status,created_at)
			VALUES ($1,$2,$3,$4,'pending',$5) RETURNING id`,
			p.LegacyUserID, p.SourceNodeID, p.TargetNodeID, p.RetirementTrigger, p.Now).
			Scan(&legacyBackupJobID); err != nil {
			return SnapshotWorkflow{}, err
		}
	}
	if independentReconciliation {
		var reconciliationUserID, reconciliationNodeID, reconciliationGeneration int64
		var reconciliationMarker, nodeMode string
		var activeIndependentSessions int
		err := tx.QueryRowContext(ctx, `
			SELECT reconciliation.user_id,reconciliation.node_id,reconciliation.marker::text,
			  reconciliation.controller_generation,node.control_mode,node.active_independent_sessions
			FROM independent_user_reconciliations reconciliation
			JOIN nodes node ON node.id=reconciliation.node_id
			WHERE reconciliation.id=$1::uuid AND reconciliation.state IN ('pending','retry_wait')
			  AND reconciliation.workflow_id IS NULL AND reconciliation.user_id IS NOT NULL
			FOR UPDATE OF reconciliation,node`, p.IndependentReconciliationID).Scan(
			&reconciliationUserID, &reconciliationNodeID, &reconciliationMarker,
			&reconciliationGeneration, &nodeMode, &activeIndependentSessions,
		)
		if err != nil || reconciliationUserID != p.GlobalUserID || reconciliationNodeID != p.SourceNodeID ||
			reconciliationMarker != p.IndependentMarker || reconciliationGeneration != generation ||
			nodeMode != NodeModeIndependentDraining || activeIndependentSessions != 0 {
			return SnapshotWorkflow{}, ErrIndependentReconciliationState
		}
		var targetEligible bool
		if err := tx.QueryRowContext(ctx, `
			SELECT role='storage' AND is_backup_target
			  AND connectivity_state='online' AND operational_state='active'
			  AND compatibility_state='compatible' AND capacity_state IN ('open','busy')
			  AND COALESCE(transfer_url,'')<>''
			FROM nodes WHERE id=$1 FOR SHARE`, p.TargetNodeID).Scan(&targetEligible); err != nil || !targetEligible {
			return SnapshotWorkflow{}, ErrIndependentReconciliationState
		}
	}
	activityEpoch := int64(1)
	var leaseEpoch, writerNodeID, inFlightReads, inFlightWrites int64
	var leaseExpires time.Time
	var leaseState string
	err = tx.QueryRowContext(ctx, `
		SELECT activity_epoch, writer_node_id, lease_expires_at, in_flight_reads, in_flight_writes, state
		FROM user_activity_leases WHERE user_id=$1 FOR UPDATE`, p.GlobalUserID).
		Scan(&leaseEpoch, &writerNodeID, &leaseExpires, &inFlightReads, &inFlightWrites, &leaseState)
	if err != nil && err != sql.ErrNoRows {
		return SnapshotWorkflow{}, err
	}
	if err == nil {
		activityEpoch = leaseEpoch
		if independentReconciliation {
			if writerNodeID != p.SourceNodeID || inFlightReads != 0 || inFlightWrites != 0 ||
				(leaseExpires.After(p.Now) && leaseState != "independent") || leaseState == "quiescing" {
				return SnapshotWorkflow{}, ErrSnapshotUserActive
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE user_activity_leases SET state='ended',lease_expires_at=$2,
				  in_flight_reads=0,in_flight_writes=0,updated_at=$2
				WHERE user_id=$1`, p.GlobalUserID, p.Now); err != nil {
				return SnapshotWorkflow{}, err
			}
		} else if writerNodeID != p.SourceNodeID || leaseExpires.After(p.Now) || inFlightReads != 0 || inFlightWrites != 0 ||
			leaseState == "independent" || leaseState == "quiescing" {
			return SnapshotWorkflow{}, ErrSnapshotUserActive
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO workflows (
		  id, operation_id, workflow_type, state, user_id, source_node_id,
		  target_node_id, activity_epoch, controller_generation, created_at, updated_at
		) VALUES ($1,$2,'snapshot','scheduled',$3,$4,$5,$6,$7,$8,$8)`,
		p.WorkflowID, p.OperationID, p.GlobalUserID, p.SourceNodeID, p.TargetNodeID,
		activityEpoch, generation, p.Now); err != nil {
		return SnapshotWorkflow{}, fmt.Errorf("create snapshot workflow: %w", err)
	}
	accountProvisionRequired := false
	if p.DestinationKind == "hot_standby" {
		var handle string
		if err := tx.QueryRowContext(ctx, `
			SELECT legacy.username FROM global_users global_user
			JOIN users legacy ON legacy.id=global_user.legacy_user_id
			WHERE global_user.id=$1 AND legacy.id=$2 FOR SHARE OF legacy`,
			p.GlobalUserID, p.LegacyUserID).Scan(&handle); err != nil {
			return SnapshotWorkflow{}, ErrInvalidSnapshotWorkflow
		}
		accountProvisionRequired, err = prepareWorkflowTargetAccount(
			ctx, tx, p.WorkflowID, p.GlobalUserID, p.TargetNodeID, handle, p.Now,
		)
		if err != nil {
			return SnapshotWorkflow{}, err
		}
	}
	steps := []string{"quiesce", "snapshot", "prepare_target", "transfer", "verify", "publish", "cleanup"}
	if p.DestinationKind == "hot_standby" {
		steps = append([]string{"provision_account"}, steps...)
	}
	for _, step := range steps {
		stepState := "pending"
		if step == "provision_account" && !accountProvisionRequired {
			stepState = "succeeded"
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO workflow_steps (workflow_id, step_name, state, updated_at)
			VALUES ($1,$2,$3,$4)`, p.WorkflowID, step, stepState, p.Now); err != nil {
			return SnapshotWorkflow{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO snapshot_manifests (
		  id, workflow_id, user_id, source_node_id, activity_epoch, format_version,
		  manifest_sha256, file_count, total_bytes, state, created_at
		) VALUES ($1,$2,$3,$4,$5,1,$6,0,0,'building',$7)`,
		p.SnapshotID, p.WorkflowID, p.GlobalUserID, p.SourceNodeID, activityEpoch, make([]byte, 32), p.Now); err != nil {
		return SnapshotWorkflow{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO snapshot_transfer_capabilities (
		  id, workflow_id, snapshot_id, source_node_id, target_node_id, token_hash,
		  state, controller_generation, expires_at, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,'prepared',$7,$8,$9)`,
		p.CapabilityID, p.WorkflowID, p.SnapshotID, p.SourceNodeID, p.TargetNodeID,
		p.CapabilityHash, generation, p.CapabilityExpires, p.Now); err != nil {
		return SnapshotWorkflow{}, err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE backup_jobs SET workflow_id=$2, snapshot_id=$3, activity_epoch=$4
		WHERE id=$1 AND user_id=$5 AND src_node_id=$6 AND dst_node_id=$7`,
		legacyBackupJobID, p.WorkflowID, p.SnapshotID, activityEpoch,
		p.LegacyUserID, p.SourceNodeID, p.TargetNodeID)
	if err != nil {
		return SnapshotWorkflow{}, err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return SnapshotWorkflow{}, err
		}
		return SnapshotWorkflow{}, ErrInvalidSnapshotWorkflow
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id, node_id, kind, data_version, state)
		VALUES ($1,$2,$3,0,'syncing')
		ON CONFLICT (user_id,node_id) DO UPDATE SET
		  kind=EXCLUDED.kind, state='syncing'`, p.LegacyUserID, p.TargetNodeID, p.DestinationKind); err != nil {
		return SnapshotWorkflow{}, err
	}
	if independentReconciliation {
		result, err := tx.ExecContext(ctx, `
			UPDATE independent_user_reconciliations
			SET state='snapshotting',workflow_id=$2,next_attempt_at=NULL,error_code=NULL,updated_at=$3
			WHERE id=$1::uuid AND state IN ('pending','retry_wait') AND workflow_id IS NULL`,
			p.IndependentReconciliationID, p.WorkflowID, p.Now)
		if err != nil {
			return SnapshotWorkflow{}, err
		}
		if rows, err := result.RowsAffected(); err != nil || rows != 1 {
			if err != nil {
				return SnapshotWorkflow{}, err
			}
			return SnapshotWorkflow{}, ErrIndependentReconciliationState
		}
	}
	if retirementSnapshot {
		result, err := tx.ExecContext(ctx, `
			UPDATE node_retirement_items SET target_node_id=$2,workflow_id=$3,
			  state='snapshotting',next_attempt_at=NULL,error_code=NULL,updated_at=$4
			WHERE id=$1 AND workflow_id IS NULL
			  AND state IN ('pending','waiting_offline','retry_wait','provisioning')`,
			p.RetirementItemID, p.TargetNodeID, p.WorkflowID, p.Now)
		if err != nil {
			return SnapshotWorkflow{}, err
		}
		if rows, err := result.RowsAffected(); err != nil || rows != 1 {
			if err != nil {
				return SnapshotWorkflow{}, err
			}
			return SnapshotWorkflow{}, ErrNodeRetirementState
		}
	}
	if err := tx.Commit(); err != nil {
		return SnapshotWorkflow{}, err
	}
	return SnapshotWorkflow{
		WorkflowID: p.WorkflowID, SnapshotID: p.SnapshotID,
		ActivityEpoch: activityEpoch, ControllerGeneration: generation,
	}, nil
}

func (s *Store) GetSnapshotWorkflowExecution(ctx context.Context, workflowID string) (*SnapshotWorkflowExecution, error) {
	if workflowID == "" {
		return nil, ErrInvalidSnapshotWorkflow
	}
	var execution SnapshotWorkflowExecution
	err := s.DB.QueryRowContext(ctx, `
		SELECT workflow.id, workflow.state, workflow.attempt, snapshot.id, workflow.activity_epoch,
		  workflow.controller_generation, workflow.user_id, global_user.legacy_user_id,
		  legacy_user.username, workflow.source_node_id, workflow.target_node_id,
		  capability.id, capability.token_hash, capability.expires_at, capability.state,
		  job.id,job.trigger,workflow.transfer_mode,
		  COALESCE(replica.kind, CASE WHEN target.role='storage' THEN 'archive' ELSE 'hot_standby' END)
		FROM workflows workflow
		JOIN snapshot_manifests snapshot ON snapshot.workflow_id=workflow.id
		JOIN global_users global_user ON global_user.id=workflow.user_id
		JOIN users legacy_user ON legacy_user.id=global_user.legacy_user_id
		JOIN nodes target ON target.id=workflow.target_node_id
		JOIN backup_jobs job ON job.workflow_id=workflow.id
		LEFT JOIN user_replicas replica
		  ON replica.user_id=global_user.legacy_user_id AND replica.node_id=workflow.target_node_id
		JOIN LATERAL (
		  SELECT id, token_hash, expires_at, state
		  FROM snapshot_transfer_capabilities
		  WHERE workflow_id=workflow.id ORDER BY created_at DESC LIMIT 1
		) capability ON true
		WHERE workflow.id=$1`, workflowID).
		Scan(
			&execution.WorkflowID, &execution.State, &execution.Attempt, &execution.SnapshotID, &execution.ActivityEpoch,
			&execution.ControllerGeneration, &execution.GlobalUserID, &execution.LegacyUserID,
			&execution.Handle, &execution.SourceNodeID, &execution.TargetNodeID,
			&execution.CapabilityID, &execution.CapabilityHash, &execution.CapabilityExpires,
			&execution.CapabilityState, &execution.LegacyBackupJobID, &execution.Trigger,
			&execution.TransferMode, &execution.DestinationKind,
		)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &execution, err
}

func (s *Store) ListResumableSnapshotWorkflowIDs(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id FROM workflows
		WHERE workflow_type='snapshot'
		  AND state IN ('scheduled','quiescing','drained','snapshotting','transferring','verifying','publishing','retry_wait')
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

func (s *Store) ClaimSnapshotWorkflow(
	ctx context.Context,
	workflowID, workerID string,
	now time.Time,
	ttl time.Duration,
) (bool, error) {
	if workflowID == "" || workerID == "" || ttl <= 0 {
		return false, ErrInvalidSnapshotWorkflow
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE workflows workflow SET lease_owner=$2, lease_until=$4, updated_at=$3
		FROM controller_epochs epoch
		WHERE workflow.id=$1 AND workflow.workflow_type='snapshot'
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

func (s *Store) ScheduleSnapshotRetry(
	ctx context.Context,
	workflowID, errorCode, errorSummary string,
	now time.Time,
	delay time.Duration,
) (int, error) {
	if workflowID == "" || errorCode == "" || delay <= 0 {
		return 0, ErrInvalidSnapshotWorkflow
	}
	if len(errorSummary) > 512 {
		errorSummary = errorSummary[:512]
	}
	var attempt int
	err := s.DB.QueryRowContext(ctx, `
		UPDATE workflows SET resume_state='quiescing', state='retry_wait', attempt=attempt+1,
		  next_attempt_at=$4, error_code=$2, error_summary=$3, updated_at=$5,
		  lease_owner=NULL, lease_until=NULL
		WHERE id=$1 AND state NOT IN ('succeeded','cancelled','failed','retry_wait')
		RETURNING attempt`, workflowID, errorCode, nullIfEmpty(errorSummary), now.Add(delay), now).Scan(&attempt)
	if err == sql.ErrNoRows {
		return 0, ErrSnapshotStateConflict
	}
	return attempt, err
}

// SwitchSnapshotWorkflowToRelay is a one-way durable transition. A workflow
// can use the relay only after the direct source command has returned the
// explicit connectivity failure code; later retries never silently switch
// back to direct and therefore cannot create two simultaneous data planes.
func (s *Store) SwitchSnapshotWorkflowToRelay(ctx context.Context, workflowID string, now time.Time) error {
	if workflowID == "" {
		return ErrInvalidSnapshotWorkflow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE workflows workflow SET transfer_mode='relay',updated_at=$2
		FROM controller_epochs epoch
		WHERE workflow.id=$1 AND workflow.workflow_type='snapshot'
		  AND workflow.transfer_mode IN ('direct','relay')
		  AND workflow.state NOT IN ('succeeded','cancelled','failed')
		  AND workflow.controller_generation=epoch.generation AND epoch.state='active'`, workflowID, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrSnapshotStateConflict
	}
	return nil
}

func (s *Store) ResumeSnapshotRetry(ctx context.Context, workflowID string, now time.Time) error {
	result, err := s.DB.ExecContext(ctx, `
		UPDATE workflows SET state=resume_state, resume_state=NULL, next_attempt_at=NULL,
		  updated_at=$2
		WHERE id=$1 AND state='retry_wait' AND resume_state IS NOT NULL
		  AND next_attempt_at<=$2`, workflowID, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrSnapshotStateConflict
	}
	return nil
}

func (s *Store) ReleaseSnapshotWorkflow(ctx context.Context, workflowID, workerID string) error {
	if workflowID == "" || workerID == "" {
		return ErrInvalidSnapshotWorkflow
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE workflows SET lease_owner=NULL, lease_until=NULL
		WHERE id=$1 AND lease_owner=$2`, workflowID, workerID)
	return err
}

func (s *Store) RotateSnapshotCapability(
	ctx context.Context,
	workflowID, capabilityID string,
	tokenHash []byte,
	expiresAt, now time.Time,
) error {
	if workflowID == "" || capabilityID == "" || len(tokenHash) != 32 || !expiresAt.After(now) {
		return ErrInvalidSnapshotWorkflow
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var snapshotID string
	var sourceNodeID, targetNodeID, generation int64
	if err := tx.QueryRowContext(ctx, `
		SELECT snapshot.id, workflow.source_node_id, workflow.target_node_id,
		  workflow.controller_generation
		FROM workflows workflow
		JOIN snapshot_manifests snapshot ON snapshot.workflow_id=workflow.id
		JOIN controller_epochs epoch
		  ON epoch.generation=workflow.controller_generation AND epoch.state='active'
		WHERE workflow.id=$1 AND workflow.state NOT IN ('succeeded','cancelled','failed')
		FOR UPDATE OF workflow`, workflowID).Scan(&snapshotID, &sourceNodeID, &targetNodeID, &generation); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE snapshot_transfer_capabilities SET state='revoked'
		WHERE workflow_id=$1 AND state='prepared'`, workflowID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO snapshot_transfer_capabilities (
		  id, workflow_id, snapshot_id, source_node_id, target_node_id, token_hash,
		  state, controller_generation, expires_at, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,'prepared',$7,$8,$9)`,
		capabilityID, workflowID, snapshotID, sourceNodeID, targetNodeID, tokenHash, generation, expiresAt, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetSnapshotWorkflowState(ctx context.Context, workflowID, fromState, toState string, now time.Time) error {
	if workflowID == "" || fromState == "" || toState == "" {
		return ErrInvalidSnapshotWorkflow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE workflows workflow SET state=$3, updated_at=$4
		FROM controller_epochs epoch
		WHERE workflow.id=$1 AND workflow.state=$2
		  AND workflow.controller_generation=epoch.generation AND epoch.state='active'`,
		workflowID, fromState, toState, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrSnapshotStateConflict
	}
	return nil
}

func (s *Store) SetSnapshotWorkflowProgress(
	ctx context.Context,
	workflowID, snapshotID string,
	nodeID int64,
	toState string,
	now time.Time,
) error {
	if workflowID == "" || snapshotID == "" || nodeID <= 0 {
		return ErrInvalidSnapshotWorkflow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var state string
	var sourceNodeID, targetNodeID, generation int64
	err = tx.QueryRowContext(ctx, `
		SELECT workflow.state, workflow.source_node_id, workflow.target_node_id,
		  workflow.controller_generation
		FROM workflows workflow
		JOIN snapshot_manifests snapshot ON snapshot.workflow_id=workflow.id AND snapshot.id=$2
		WHERE workflow.id=$1 FOR UPDATE OF workflow`, workflowID, snapshotID).
		Scan(&state, &sourceNodeID, &targetNodeID, &generation)
	if err != nil {
		return err
	}
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&activeGeneration); err != nil {
		return err
	}
	if generation != activeGeneration {
		return ErrSnapshotStateConflict
	}
	type transition struct {
		from  string
		actor int64
	}
	allowed := map[string]transition{
		"drained":      {from: "quiescing", actor: sourceNodeID},
		"snapshotting": {from: "drained", actor: sourceNodeID},
		"transferring": {from: "snapshotting", actor: sourceNodeID},
		"verifying":    {from: "transferring", actor: targetNodeID},
		"publishing":   {from: "verifying", actor: targetNodeID},
	}
	rule, ok := allowed[toState]
	if !ok || rule.from != state || rule.actor != nodeID {
		return ErrSnapshotStateConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE workflows SET state=$2, updated_at=$3 WHERE id=$1`, workflowID, toState, now); err != nil {
		return err
	}
	stepName := map[string]string{
		"drained": "quiesce", "snapshotting": "snapshot", "transferring": "transfer",
		"verifying": "verify", "publishing": "publish",
	}[toState]
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflow_steps SET state='succeeded', finished_at=$3, updated_at=$3
		WHERE workflow_id=$1 AND step_name=$2`, workflowID, stepName, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CompleteSnapshotWorkflowStep(ctx context.Context, workflowID, stepName string, now time.Time) error {
	if workflowID == "" || stepName == "" {
		return ErrInvalidSnapshotWorkflow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE workflow_steps SET state='succeeded', finished_at=$3, updated_at=$3
		WHERE workflow_id=$1 AND step_name=$2 AND state IN ('pending','running','retry_wait')`,
		workflowID, stepName, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		var state string
		if err := s.DB.QueryRowContext(ctx, `
			SELECT state FROM workflow_steps WHERE workflow_id=$1 AND step_name=$2`, workflowID, stepName).Scan(&state); err != nil {
			return err
		}
		if state == "succeeded" {
			return nil
		}
		return ErrSnapshotStateConflict
	}
	return nil
}

type CompleteSnapshotWorkflowParams struct {
	WorkflowID     string
	SnapshotID     string
	CapabilityHash []byte
	TargetNodeID   int64
	ReplicaKind    string
	ReplicaOrigin  string
	ManifestSHA256 []byte
	ArchiveSHA256  []byte
	FileCount      int64
	TotalBytes     int64
	Now            time.Time
}

func (s *Store) CompleteSnapshotWorkflow(ctx context.Context, p CompleteSnapshotWorkflowParams) (int64, error) {
	if p.WorkflowID == "" || p.SnapshotID == "" || len(p.CapabilityHash) != 32 || p.TargetNodeID <= 0 ||
		(p.ReplicaKind != "archive" && p.ReplicaKind != "hot_standby") || len(p.ManifestSHA256) != 32 ||
		(p.ReplicaOrigin != "configured" && p.ReplicaOrigin != "temporary_failure_protection" &&
			p.ReplicaOrigin != "migration") ||
		len(p.ArchiveSHA256) != 32 || p.FileCount < 0 || p.TotalBytes < 0 {
		return 0, ErrInvalidSnapshotWorkflow
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var userID, legacyUserID, generation int64
	var state string
	if err := tx.QueryRowContext(ctx, `
		SELECT workflow.user_id, global_user.legacy_user_id,
		  workflow.controller_generation, workflow.state
		FROM workflows workflow
		JOIN global_users global_user ON global_user.id=workflow.user_id
		WHERE workflow.id=$1 FOR UPDATE OF workflow`, p.WorkflowID).
		Scan(&userID, &legacyUserID, &generation, &state); err != nil {
		return 0, err
	}
	if state == "succeeded" {
		var dataVersion sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT data_version FROM backup_jobs WHERE workflow_id=$1`, p.WorkflowID).Scan(&dataVersion); err != nil {
			return 0, err
		}
		if !dataVersion.Valid {
			return 0, ErrSnapshotStateConflict
		}
		if err := tx.Commit(); err != nil {
			return 0, err
		}
		return dataVersion.Int64, nil
	}
	if state != "publishing" {
		return 0, ErrSnapshotStateConflict
	}
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&activeGeneration); err != nil {
		return 0, err
	}
	if generation != activeGeneration {
		return 0, ErrSnapshotStateConflict
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE snapshot_manifests SET manifest_sha256=$3, archive_sha256=$4,
		  file_count=$5, total_bytes=$6, state='immutable'
		WHERE id=$1 AND workflow_id=$2 AND state='building'`,
		p.SnapshotID, p.WorkflowID, p.ManifestSHA256, p.ArchiveSHA256, p.FileCount, p.TotalBytes)
	if err != nil {
		return 0, err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return 0, err
		}
		return 0, ErrSnapshotStateConflict
	}
	var oldSnapshotID sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT snapshot_id FROM replica_copies WHERE user_id=$1 AND node_id=$2 FOR UPDATE`, userID, p.TargetNodeID).
		Scan(&oldSnapshotID)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	var dataVersion int64
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(data_version),0)+1 FROM user_replicas WHERE user_id=(
		  SELECT legacy_user_id FROM global_users WHERE id=$1)`, userID).Scan(&dataVersion); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO replica_copies (
		  id, user_id, node_id, snapshot_id, replica_kind, state, origin,
		  is_authoritative, compatibility_state, published_at, verified_at, created_at, updated_at,
		  integrity_state,integrity_check_kind,integrity_checked_at,integrity_last_light_at,
		  integrity_last_deep_at,integrity_next_check_at,integrity_deep_check_at
		) VALUES (gen_random_uuid(),$1,$2,$3,$4,'ready',$5,false,'compatible',$6,$6,$6,$6,
		  'verified','deep',$6,$6,$6,$7,$8)
		ON CONFLICT (user_id,node_id) DO UPDATE SET
		  snapshot_id=EXCLUDED.snapshot_id, replica_kind=EXCLUDED.replica_kind,
		  state='ready', origin=EXCLUDED.origin, compatibility_state='compatible',
		  published_at=EXCLUDED.published_at, verified_at=EXCLUDED.verified_at,
		  integrity_state='verified', integrity_check_kind='deep',integrity_operation_id=NULL,
		  integrity_controller_generation=NULL, integrity_lease_until=NULL,
		  integrity_attempt=0, integrity_checked_at=EXCLUDED.integrity_checked_at,
		  integrity_last_light_at=EXCLUDED.integrity_last_light_at,
		  integrity_last_deep_at=EXCLUDED.integrity_last_deep_at,
		  integrity_next_check_at=EXCLUDED.integrity_next_check_at,
		  integrity_deep_check_at=EXCLUDED.integrity_deep_check_at,integrity_error_code=NULL,
		  updated_at=EXCLUDED.updated_at`, userID, p.TargetNodeID, p.SnapshotID, p.ReplicaKind,
		p.ReplicaOrigin, p.Now, p.Now.Add(ReplicaIntegrityLightInterval),
		p.Now.Add(ReplicaIntegrityDeepInterval)); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE alerts SET state='resolved',resolved_at=$3,last_seen_at=$3
		WHERE deduplication_key='replica-integrity:'||(
		  SELECT id::text FROM replica_copies WHERE user_id=$1 AND node_id=$2
		) AND state IN ('open','acknowledged')`, userID, p.TargetNodeID, p.Now); err != nil {
		return 0, err
	}
	if p.ReplicaKind == "archive" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE replica_copies SET state='stale',updated_at=$3
			WHERE user_id=$1 AND node_id<>$2 AND replica_kind='archive' AND state='ready'`,
			userID, p.TargetNodeID, p.Now); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE user_replicas SET state='stale'
			WHERE user_id=$1 AND node_id<>$2 AND kind='archive' AND state='ready'`,
			legacyUserID, p.TargetNodeID); err != nil {
			return 0, err
		}
	}
	if oldSnapshotID.Valid && oldSnapshotID.String != p.SnapshotID {
		if _, err := tx.ExecContext(ctx, `UPDATE snapshot_manifests SET state='deleted' WHERE id=$1`, oldSnapshotID.String); err != nil {
			return 0, err
		}
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE snapshot_transfer_capabilities SET state='consumed', consumed_at=$2
		WHERE workflow_id=$1 AND token_hash=$3 AND state='prepared'`,
		p.WorkflowID, p.Now, p.CapabilityHash)
	if err != nil {
		return 0, err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return 0, err
		}
		return 0, ErrSnapshotStateConflict
	}
	manifestHex := fmt.Sprintf("%x", p.ManifestSHA256)
	result, err = tx.ExecContext(ctx, `
		UPDATE backup_jobs SET status='done', data_version=$2, bytes=$3,
		  file_count=$4, error=NULL, finished_at=$5
		WHERE workflow_id=$1`, p.WorkflowID, dataVersion, p.TotalBytes, p.FileCount, p.Now)
	if err != nil {
		return 0, err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return 0, err
		}
		return 0, ErrSnapshotStateConflict
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE user_replicas SET state='ready', data_version=$3, checksum=$4,
		  size_bytes=$5, last_sync_at=$6
		WHERE user_id=$1 AND node_id=$2`,
		legacyUserID, p.TargetNodeID, dataVersion, manifestHex, p.TotalBytes, p.Now)
	if err != nil {
		return 0, err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return 0, err
		}
		return 0, ErrSnapshotStateConflict
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflows SET state='succeeded', cleanup_state='succeeded',
		  updated_at=$2, finished_at=$2 WHERE id=$1`, p.WorkflowID, p.Now); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflow_steps SET state='succeeded', finished_at=$2, updated_at=$2
		WHERE workflow_id=$1`, p.WorkflowID, p.Now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return dataVersion, nil
}

func (s *Store) FailSnapshotWorkflow(ctx context.Context, workflowID, errorCode, errorSummary string, now time.Time) error {
	if workflowID == "" || errorCode == "" {
		return ErrInvalidSnapshotWorkflow
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
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflows SET state='failed', error_code=$2, error_summary=$3,
		  cleanup_state='pending', updated_at=$4, finished_at=$4
		WHERE id=$1 AND state NOT IN ('succeeded','cancelled','failed')`,
		workflowID, errorCode, nullIfEmpty(errorSummary), now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE snapshot_transfer_capabilities SET state='revoked'
		WHERE workflow_id=$1 AND state='prepared'`, workflowID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CancelSnapshotWorkflow(ctx context.Context, workflowID, reason string, now time.Time) error {
	if workflowID == "" {
		return ErrInvalidSnapshotWorkflow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if len(reason) > 512 {
		reason = reason[:512]
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := cancelSnapshotWorkflowTx(ctx, tx, workflowID, reason, now); err != nil {
		return err
	}
	return tx.Commit()
}

func cancelSnapshotWorkflowTx(ctx context.Context, tx *sql.Tx, workflowID, reason string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflows SET state='cancelled', error_code='user_returned', error_summary=$2,
		  cleanup_state='pending', lease_owner=NULL, lease_until=NULL, updated_at=$3, finished_at=$3
		WHERE id=$1 AND state NOT IN ('succeeded','cancelled','failed')`, workflowID, nullIfEmpty(reason), now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflow_steps SET state='cancelled', finished_at=$2, updated_at=$2
		WHERE workflow_id=$1 AND state NOT IN ('succeeded','cancelled','failed')`, workflowID, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE snapshot_transfer_capabilities SET state='revoked'
		WHERE workflow_id=$1 AND state='prepared'`, workflowID); err != nil {
		return err
	}
	return nil
}
