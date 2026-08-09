package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrNodeRetirementConflict = errors.New("node retirement operation conflict")
	ErrNodeRetirementState    = errors.New("node retirement state conflict")
)

const nodeRetirementDependencyQuery = `
	SELECT EXISTS (
	  SELECT 1 FROM users WHERE home_node_id=$1 AND status='active'
	  UNION ALL
	  SELECT 1 FROM user_replicas
	  WHERE node_id=$1 AND state NOT IN ('empty','stale','error')
	  UNION ALL
	  SELECT 1 FROM replica_copies
	  WHERE node_id=$1 AND state NOT IN ('empty','stale','corrupt','deleting','error')
	  UNION ALL
	  SELECT 1 FROM node_accounts
	  WHERE node_id=$1 AND status IN ('pending','active','conflict')
	  UNION ALL
	  SELECT 1 FROM workflows
	  WHERE (source_node_id=$1 OR target_node_id=$1)
	    AND state NOT IN ('cancelled','failed','succeeded')
	  UNION ALL
	  SELECT 1 FROM backup_jobs
	  WHERE (src_node_id=$1 OR dst_node_id=$1) AND status IN ('pending','running')
	  UNION ALL
	  SELECT 1 FROM user_activity_leases
	  WHERE writer_node_id=$1 AND state<>'ended'
	  UNION ALL
	  SELECT 1 FROM independent_user_reconciliations
	  WHERE node_id=$1 AND state NOT IN ('succeeded','superseded','failed')
	  UNION ALL
	  SELECT 1 FROM relay_transfers
	  WHERE (source_node_id=$1 OR target_node_id=$1)
	    AND state NOT IN ('consumed','expired','failed')
	)`

type NodeRetirementStatus struct {
	ID                   string     `json:"id"`
	OperationID          string     `json:"operation_id"`
	NodeID               int64      `json:"node_id"`
	State                string     `json:"state"`
	ReasonCode           string     `json:"reason_code"`
	TotalItems           int        `json:"total_items"`
	PendingItems         int        `json:"pending_items"`
	WaitingItems         int        `json:"waiting_items"`
	RunningItems         int        `json:"running_items"`
	BlockedItems         int        `json:"blocked_items"`
	FailedItems          int        `json:"failed_items"`
	CompletedItems       int        `json:"completed_items"`
	ErrorCode            string     `json:"error_code,omitempty"`
	ControllerGeneration int64      `json:"controller_generation"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	CompletedAt          *time.Time `json:"completed_at,omitempty"`
}

type NodeRetirementItemExecution struct {
	ID                   string
	RetirementID         string
	OperationID          string
	NodeID               int64
	NodeRole             string
	OperationState       string
	ControllerGeneration int64
	ItemKind             string
	State                string
	Attempt              int
	UserID               int64
	LegacyUserID         int64
	Handle               string
	HomeNodeID           int64
	TargetNodeID         int64
	WorkflowID           string
	WorkflowState        string
	UserBusy             bool
}

func createNodeRetirementLocked(
	ctx context.Context,
	tx *sql.Tx,
	p TransitionNodeLifecycleParams,
	generation int64,
) error {
	var retirementID string
	err := tx.QueryRowContext(ctx, `
		INSERT INTO node_retirement_operations (
		  operation_id,node_id,requested_by_admin_id,reason_code,state,
		  controller_generation,created_at,updated_at
		) VALUES ($1,$2,$3,$4,'scheduled',$5,$6,$6)
		RETURNING id::text`, p.OperationID, p.NodeID, p.AdminID, p.ReasonCode, generation, p.Now).
		Scan(&retirementID)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		WITH node_role AS (
		  SELECT role FROM nodes WHERE id=$2
		), candidates AS (
		  SELECT global_user.id AS user_id,global_user.legacy_user_id,
		    CASE
		      WHEN legacy.home_node_id=$2 AND legacy.status='active' THEN 'authoritative_home'
		      WHEN (SELECT role FROM node_role)='storage' THEN 'archive_replica'
		      WHEN EXISTS (
		        SELECT 1 FROM replica_copies copy
		        WHERE copy.user_id=global_user.id AND copy.node_id=$2
		          AND copy.state NOT IN ('empty','stale','corrupt','deleting','error')
		      ) OR EXISTS (
		        SELECT 1 FROM user_replicas replica
		        WHERE replica.user_id=global_user.legacy_user_id AND replica.node_id=$2
		          AND replica.state NOT IN ('empty','stale','error')
		      ) THEN 'redundant_replica'
		      ELSE 'account_metadata'
		    END AS item_kind
		  FROM global_users global_user
		  LEFT JOIN users legacy ON legacy.id=global_user.legacy_user_id
		  WHERE (legacy.home_node_id=$2 AND legacy.status='active')
		    OR EXISTS (
		      SELECT 1 FROM replica_copies copy
		      WHERE copy.user_id=global_user.id AND copy.node_id=$2
		        AND copy.state NOT IN ('empty','stale','corrupt','deleting','error')
		    )
		    OR EXISTS (
		      SELECT 1 FROM user_replicas replica
		      WHERE replica.user_id=global_user.legacy_user_id AND replica.node_id=$2
		        AND replica.state NOT IN ('empty','stale','error')
		    )
		    OR EXISTS (
		      SELECT 1 FROM node_accounts account
		      WHERE account.user_id=global_user.id AND account.node_id=$2
		        AND account.status IN ('pending','active','conflict')
		    )
		)
		INSERT INTO node_retirement_items (
		  retirement_id,user_id,legacy_user_id,source_node_id,item_kind,state,created_at,updated_at
		)
		SELECT $1::uuid,user_id,legacy_user_id,$2,item_kind,'pending',$3,$3 FROM candidates`,
		retirementID, p.NodeID, p.Now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE node_retirement_operations operation SET state=CASE
		  WHEN EXISTS (SELECT 1 FROM node_retirement_items item WHERE item.retirement_id=operation.id)
		    THEN 'scheduled' ELSE 'verifying' END,updated_at=$2
		WHERE operation.id=$1`, retirementID, p.Now); err != nil {
		return err
	}
	return nil
}

func cancelNodeRetirementLocked(ctx context.Context, tx *sql.Tx, nodeID int64, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE node_retirement_operations SET state='cancelled',lease_owner=NULL,lease_until=NULL,
		  next_attempt_at=NULL,error_code='operator_cancelled',updated_at=$2
		WHERE node_id=$1 AND state NOT IN ('decommissioned','cancelled','failed')`, nodeID, now); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE node_retirement_items item SET state='superseded',completed_at=$2,updated_at=$2,
		  error_code='operator_cancelled'
		FROM node_retirement_operations operation
		WHERE item.retirement_id=operation.id AND operation.node_id=$1
		  AND operation.state='cancelled'
		  AND item.state NOT IN ('succeeded','superseded')`, nodeID, now)
	return err
}

func (s *Store) GetNodeRetirementStatus(ctx context.Context, nodeID int64) (*NodeRetirementStatus, error) {
	if nodeID <= 0 {
		return nil, ErrNodeRetirementConflict
	}
	var status NodeRetirementStatus
	var errorCode sql.NullString
	var completedAt sql.NullTime
	err := s.DB.QueryRowContext(ctx, `
		SELECT operation.id::text,operation.operation_id::text,operation.node_id,operation.state,
		  operation.reason_code,COUNT(item.id)::int,
		  COUNT(*) FILTER (WHERE item.state='pending')::int,
		  COUNT(*) FILTER (WHERE item.state IN ('waiting_offline','retry_wait'))::int,
		  COUNT(*) FILTER (WHERE item.state IN ('provisioning','snapshotting','promoting','verifying'))::int,
		  COUNT(*) FILTER (WHERE item.state='blocked')::int,
		  COUNT(*) FILTER (WHERE item.state='failed')::int,
		  COUNT(*) FILTER (WHERE item.state IN ('succeeded','superseded'))::int,
		  operation.error_code,operation.controller_generation,operation.created_at,
		  operation.updated_at,operation.completed_at
		FROM node_retirement_operations operation
		LEFT JOIN node_retirement_items item ON item.retirement_id=operation.id
		WHERE operation.node_id=$1
		GROUP BY operation.id
		ORDER BY operation.created_at DESC LIMIT 1`, nodeID).Scan(
		&status.ID, &status.OperationID, &status.NodeID, &status.State, &status.ReasonCode,
		&status.TotalItems, &status.PendingItems, &status.WaitingItems, &status.RunningItems,
		&status.BlockedItems, &status.FailedItems, &status.CompletedItems, &errorCode,
		&status.ControllerGeneration, &status.CreatedAt, &status.UpdatedAt, &completedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	status.ErrorCode = errorCode.String
	if completedAt.Valid {
		status.CompletedAt = &completedAt.Time
	}
	return &status, nil
}

func (s *Store) ListSchedulableNodeRetirementIDs(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id::text FROM node_retirement_operations
		WHERE state IN ('scheduled','migrating','retry_wait','verifying','blocked')
		  AND (next_attempt_at IS NULL OR next_attempt_at<=now())
		  AND (lease_until IS NULL OR lease_until<=now())
		ORDER BY updated_at,id LIMIT $1`, limit)
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

func (s *Store) ClaimNodeRetirement(
	ctx context.Context,
	retirementID, workerID, lifecycleEventID string,
	now time.Time,
	ttl time.Duration,
) (bool, error) {
	if !validUUIDText(retirementID) || !validUUIDText(workerID) || !validUUIDText(lifecycleEventID) || ttl <= 0 {
		return false, ErrNodeRetirementConflict
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var nodeID, generation int64
	var operationState, nodeState string
	var adminID sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT operation.node_id,operation.state,operation.controller_generation,
		  operation.requested_by_admin_id,node.operational_state
		FROM node_retirement_operations operation
		JOIN nodes node ON node.id=operation.node_id
		WHERE operation.id=$1
		  AND operation.state IN ('scheduled','migrating','retry_wait','verifying','blocked')
		  AND (operation.next_attempt_at IS NULL OR operation.next_attempt_at<=$2)
		  AND (operation.lease_until IS NULL OR operation.lease_until<=$2)
		FOR UPDATE OF operation,node`, retirementID, now).Scan(
		&nodeID, &operationState, &generation, &adminID, &nodeState,
	)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).
		Scan(&activeGeneration); err != nil || activeGeneration != generation {
		if err != nil {
			return false, err
		}
		return false, ErrNodeRetirementState
	}
	if nodeState != "draining" && nodeState != "retiring" {
		return false, ErrNodeRetirementState
	}
	if nodeState == "draining" {
		if _, err := tx.ExecContext(ctx, `UPDATE nodes SET operational_state='retiring' WHERE id=$1`, nodeID); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO node_lifecycle_events (
			  operation_id,node_id,from_state,to_state,reason_code,actor_admin_id,
			  controller_generation,created_at
			) VALUES ($1,$2,'draining','retiring','retirement_started',$3,$4,$5)`,
			lifecycleEventID, nodeID, nullInt64Value(adminID), generation, now); err != nil {
			return false, err
		}
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE node_retirement_operations SET state=CASE WHEN state='verifying' THEN state ELSE 'migrating' END,
		  lease_owner=$2,lease_until=$4,next_attempt_at=NULL,attempt=attempt+1,error_code=NULL,updated_at=$3
		WHERE id=$1`, retirementID, workerID, now, now.Add(ttl))
	if err != nil {
		return false, err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return false, err
		}
		return false, ErrNodeRetirementState
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) ReleaseNodeRetirement(ctx context.Context, retirementID, workerID string) error {
	if !validUUIDText(retirementID) || !validUUIDText(workerID) {
		return ErrNodeRetirementConflict
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE node_retirement_operations SET lease_owner=NULL,lease_until=NULL,updated_at=now()
		WHERE id=$1 AND lease_owner=$2`, retirementID, workerID)
	return err
}

func (s *Store) GetNextNodeRetirementItem(
	ctx context.Context,
	retirementID string,
	now time.Time,
) (*NodeRetirementItemExecution, error) {
	if !validUUIDText(retirementID) {
		return nil, ErrNodeRetirementConflict
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var item NodeRetirementItemExecution
	var legacyUserID, homeNodeID, targetNodeID sql.NullInt64
	var handle, workflowID, workflowState sql.NullString
	err := s.DB.QueryRowContext(ctx, `
		SELECT item.id::text,operation.id::text,operation.operation_id::text,
		  operation.node_id,node.role,operation.state,operation.controller_generation,
		  item.item_kind,item.state,item.attempt,item.user_id,item.legacy_user_id,
		  legacy.username,legacy.home_node_id,item.target_node_id,item.workflow_id::text,
		  workflow.state,
		  EXISTS (
		    SELECT 1 FROM user_activity_leases lease
		    WHERE lease.user_id=item.user_id AND lease.state<>'ended'
		      AND (lease.lease_expires_at>$2 OR lease.in_flight_reads>0 OR lease.in_flight_writes>0
		        OR lease.state IN ('quiescing','drained','independent','conflict'))
		  )
		FROM node_retirement_items item
		JOIN node_retirement_operations operation ON operation.id=item.retirement_id
		JOIN nodes node ON node.id=operation.node_id
		LEFT JOIN users legacy ON legacy.id=item.legacy_user_id
		LEFT JOIN workflows workflow ON workflow.id=item.workflow_id
		WHERE operation.id=$1
		  AND item.state NOT IN ('succeeded','superseded','failed')
		  AND (item.next_attempt_at IS NULL OR item.next_attempt_at<=$2)
		ORDER BY CASE item.item_kind
		  WHEN 'authoritative_home' THEN 0 WHEN 'archive_replica' THEN 1
		  WHEN 'redundant_replica' THEN 2 ELSE 3 END,item.created_at,item.id
		LIMIT 1`, retirementID, now).Scan(
		&item.ID, &item.RetirementID, &item.OperationID, &item.NodeID, &item.NodeRole,
		&item.OperationState, &item.ControllerGeneration, &item.ItemKind, &item.State,
		&item.Attempt, &item.UserID, &legacyUserID, &handle, &homeNodeID, &targetNodeID,
		&workflowID, &workflowState, &item.UserBusy,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	item.LegacyUserID = legacyUserID.Int64
	item.Handle = handle.String
	item.HomeNodeID = homeNodeID.Int64
	item.TargetNodeID = targetNodeID.Int64
	item.WorkflowID = workflowID.String
	item.WorkflowState = workflowState.String
	return &item, nil
}

func (s *Store) RetryNodeRetirementItem(
	ctx context.Context,
	itemID, state, errorCode string,
	clearWorkflow bool,
	now time.Time,
	delay time.Duration,
) error {
	if !validUUIDText(itemID) || (state != "waiting_offline" && state != "retry_wait" && state != "blocked") ||
		!ValidMachineReasonCode(errorCode) || delay <= 0 {
		return ErrNodeRetirementConflict
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
		UPDATE node_retirement_items item SET state=$2,error_code=$3,next_attempt_at=$4,
		  workflow_id=CASE WHEN $5 THEN NULL ELSE workflow_id END,
		  target_node_id=CASE WHEN $5 THEN NULL ELSE target_node_id END,
		  attempt=CASE WHEN $2='waiting_offline' THEN item.attempt ELSE item.attempt+1 END,updated_at=$6
		FROM node_retirement_operations operation
		WHERE item.id=$1 AND operation.id=item.retirement_id
		  AND operation.state IN ('migrating','retry_wait','blocked')
		  AND operation.controller_generation=(
		    SELECT generation FROM controller_epochs WHERE state='active'
		  )
		  AND item.state NOT IN ('succeeded','superseded','failed')`,
		itemID, state, errorCode, now.Add(delay), clearWorkflow, now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrNodeRetirementState
	}
	operationState := "retry_wait"
	if state == "blocked" {
		operationState = "blocked"
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE node_retirement_operations operation SET state=$2,error_code=$3,
		  next_attempt_at=$4,updated_at=$5
		FROM node_retirement_items item WHERE item.id=$1 AND operation.id=item.retirement_id`,
		itemID, operationState, errorCode, now.Add(delay), now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeferNodeRetirement(
	ctx context.Context,
	retirementID, workerID, errorCode string,
	now time.Time,
	delay time.Duration,
) error {
	if !validUUIDText(retirementID) || !validUUIDText(workerID) ||
		!ValidMachineReasonCode(errorCode) || delay <= 0 {
		return ErrNodeRetirementConflict
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE node_retirement_operations SET state='retry_wait',error_code=$3,
		  next_attempt_at=$4,lease_owner=NULL,lease_until=NULL,updated_at=$5
		WHERE id=$1 AND lease_owner=$2
		  AND controller_generation=(
		    SELECT generation FROM controller_epochs WHERE state='active'
		  )
		  AND state IN ('migrating','retry_wait','blocked')`,
		retirementID, workerID, errorCode, now.Add(delay), now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrNodeRetirementState
	}
	return nil
}

func (s *Store) RetirementTargetAvailable(ctx context.Context, userID, nodeID int64, handle string) (bool, error) {
	if userID <= 0 || nodeID <= 0 || handle == "" {
		return false, ErrNodeRetirementConflict
	}
	var available bool
	err := s.DB.QueryRowContext(ctx, `
		SELECT NOT EXISTS (
		  SELECT 1 FROM node_accounts account
		  WHERE account.node_id=$2 AND account.user_id=$1
		    AND account.status IN ('disabled','conflict')
		) AND NOT EXISTS (
		  SELECT 1 FROM node_accounts account
		  WHERE account.node_id=$2 AND lower(account.local_handle)=lower($3)
		    AND account.user_id<>$1 AND account.status IN ('pending','active','conflict')
		)`, userID, nodeID, handle).Scan(&available)
	return available, err
}

func nullInt64Value(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}

func (s *Store) CompleteNodeRetirementHomeMigration(
	ctx context.Context,
	itemID, workflowID string,
	now time.Time,
) error {
	if !validUUIDText(itemID) || !validUUIDText(workflowID) {
		return ErrNodeRetirementConflict
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var retirementID, operationID, itemKind, itemState, workflowState, globalStatus, legacyStatus string
	var userID, legacyUserID, sourceNodeID, targetNodeID, generation int64
	err = tx.QueryRowContext(ctx, `
		SELECT operation.id::text,operation.operation_id::text,item.item_kind,item.state,
		  workflow.state,global_user.status,legacy.status,item.user_id,item.legacy_user_id,
		  operation.node_id,item.target_node_id,operation.controller_generation
		FROM node_retirement_items item
		JOIN node_retirement_operations operation ON operation.id=item.retirement_id
		JOIN workflows workflow ON workflow.id=item.workflow_id
		JOIN global_users global_user ON global_user.id=item.user_id
		JOIN users legacy ON legacy.id=item.legacy_user_id
		WHERE item.id=$1 AND item.workflow_id=$2
		  AND operation.state='migrating' AND workflow.workflow_type='snapshot'
		FOR UPDATE OF item,operation,workflow,global_user,legacy`, itemID, workflowID).Scan(
		&retirementID, &operationID, &itemKind, &itemState, &workflowState, &globalStatus,
		&legacyStatus, &userID, &legacyUserID, &sourceNodeID, &targetNodeID, &generation,
	)
	if err != nil {
		return err
	}
	if itemKind != "authoritative_home" || workflowState != "succeeded" || globalStatus != "active" ||
		legacyStatus != "active" || targetNodeID <= 0 {
		return ErrNodeRetirementState
	}
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).
		Scan(&activeGeneration); err != nil || activeGeneration != generation {
		if err != nil {
			return err
		}
		return ErrNodeRetirementState
	}
	if itemState == "succeeded" {
		var committed bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
			  SELECT 1 FROM users legacy
			  JOIN user_replicas source_replica ON source_replica.user_id=legacy.id
			    AND source_replica.node_id=$3 AND source_replica.state='stale'
			  JOIN user_replicas target_replica ON target_replica.user_id=legacy.id
			    AND target_replica.node_id=$4 AND target_replica.kind='home' AND target_replica.state='ready'
			  JOIN replica_copies copy ON copy.user_id=$2 AND copy.node_id=$4
			    AND copy.snapshot_id=(SELECT id FROM snapshot_manifests WHERE workflow_id=$5)
			    AND copy.replica_kind='active' AND copy.state='ready' AND copy.is_authoritative
			  JOIN node_accounts source_account ON source_account.user_id=$2
			    AND source_account.node_id=$3 AND source_account.status='stale'
			  JOIN node_accounts target_account ON target_account.user_id=$2
			    AND target_account.node_id=$4 AND target_account.status='active'
			  WHERE legacy.id=$1 AND legacy.home_node_id=$4
			)`, legacyUserID, userID, sourceNodeID, targetNodeID, workflowID).Scan(&committed); err != nil {
			return err
		}
		if !committed {
			return ErrNodeRetirementState
		}
		return tx.Commit()
	}
	if itemState != "snapshotting" && itemState != "promoting" && itemState != "retry_wait" && itemState != "blocked" {
		return ErrNodeRetirementState
	}
	var currentHomeNodeID int64
	if err := tx.QueryRowContext(ctx, `SELECT home_node_id FROM users WHERE id=$1 FOR UPDATE`, legacyUserID).
		Scan(&currentHomeNodeID); err != nil || currentHomeNodeID != sourceNodeID {
		return ErrNodeRetirementState
	}
	var busy bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM user_activity_leases
		  WHERE user_id=$1 AND state<>'ended'
		    AND (lease_expires_at>$2 OR in_flight_reads>0 OR in_flight_writes>0))`, userID, now).Scan(&busy); err != nil {
		return err
	}
	if busy {
		return ErrSnapshotUserActive
	}
	var snapshotID string
	err = tx.QueryRowContext(ctx, `
		SELECT copy.snapshot_id::text
		FROM replica_copies copy
		JOIN snapshot_manifests snapshot ON snapshot.id=copy.snapshot_id
		  AND snapshot.workflow_id=$3 AND snapshot.user_id=copy.user_id AND snapshot.state='immutable'
		JOIN node_accounts account ON account.user_id=copy.user_id AND account.node_id=copy.node_id
		  AND account.status='active'
		JOIN nodes target ON target.id=copy.node_id AND target.role='compute'
		  AND target.connectivity_state='online' AND target.operational_state='active'
		  AND target.compatibility_state='compatible' AND target.control_mode='managed'
		  AND target.desired_control_mode='managed'
		WHERE copy.user_id=$1 AND copy.node_id=$2 AND copy.replica_kind='hot_standby'
		  AND copy.state='ready' AND copy.compatibility_state='compatible'
		FOR SHARE OF copy,snapshot,account,target`, userID, targetNodeID, workflowID).Scan(&snapshotID)
	if err != nil {
		return ErrNodeRetirementState
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE replica_copies SET is_authoritative=false,
		  state=CASE WHEN node_id=$2 THEN 'stale' ELSE state END,updated_at=$3
		WHERE user_id=$1 AND (is_authoritative OR node_id=$2)`, userID, sourceNodeID, now); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE replica_copies SET replica_kind='active',origin='migration',is_authoritative=true,
		  state='ready',compatibility_state='compatible',updated_at=$3
		WHERE user_id=$1 AND node_id=$2 AND snapshot_id=$4`, userID, targetNodeID, now, snapshotID)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrNodeRetirementState
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE user_replicas SET kind='hot_standby',state='stale' WHERE user_id=$1 AND node_id=$2`,
		legacyUserID, sourceNodeID)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrNodeRetirementState
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE user_replicas SET kind='home',state='ready' WHERE user_id=$1 AND node_id=$2`,
		legacyUserID, targetNodeID)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrNodeRetirementState
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET home_node_id=$2 WHERE id=$1`, legacyUserID, targetNodeID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE node_accounts SET status=CASE WHEN node_id=$2 THEN 'active' ELSE 'stale' END,
		  updated_at=$3 WHERE user_id=$1 AND node_id IN ($2,$4)`,
		userID, targetNodeID, now, sourceNodeID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE user_activity_leases SET state='ended',lease_expires_at=$2,updated_at=$2
		WHERE user_id=$1`, userID, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE control_tickets SET revoked_at=COALESCE(revoked_at,$2)
		WHERE user_id=$1 AND consumed_at IS NULL`, userID, now); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE node_retirement_items SET state='succeeded',completed_at=$2,updated_at=$2,error_code=NULL
		WHERE id=$1 AND state IN ('snapshotting','promoting')`, itemID, now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrNodeRetirementState
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  actor_type,action,target_type,target_id,operation_id,controller_generation,outcome,detail
		) VALUES ('system','node-retirement-home-migration','global_user',$1::text,$2,$3,'succeeded',
		  jsonb_build_object('retirement_id',$4::text,'source_node_id',$5::bigint,
		    'target_node_id',$6::bigint,'snapshot_id',$7::text))`,
		userID, operationID, generation, retirementID, sourceNodeID, targetNodeID, snapshotID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CompleteNodeRetirementReplicaItem(
	ctx context.Context,
	itemID string,
	now time.Time,
) error {
	if !validUUIDText(itemID) {
		return ErrNodeRetirementConflict
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var retirementID, operationID, kind, state string
	var userID, legacyUserID, sourceNodeID, targetNodeID, generation int64
	var workflowID, workflowState sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT operation.id::text,operation.operation_id::text,item.item_kind,item.state,
		  item.user_id,COALESCE(item.legacy_user_id,0),item.source_node_id,
		  COALESCE(item.target_node_id,0),operation.controller_generation,
		  item.workflow_id::text,workflow.state
		FROM node_retirement_items item
		JOIN node_retirement_operations operation ON operation.id=item.retirement_id
		LEFT JOIN workflows workflow ON workflow.id=item.workflow_id
		WHERE item.id=$1 AND operation.state='migrating' FOR UPDATE OF item,operation`, itemID).Scan(
		&retirementID, &operationID, &kind, &state, &userID, &legacyUserID, &sourceNodeID,
		&targetNodeID, &generation, &workflowID, &workflowState,
	)
	if err != nil {
		return err
	}
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).
		Scan(&activeGeneration); err != nil || activeGeneration != generation {
		if err != nil {
			return err
		}
		return ErrNodeRetirementState
	}
	if state == "succeeded" {
		var committed bool
		var workflowArg any
		if workflowID.Valid {
			workflowArg = workflowID.String
		}
		if err := tx.QueryRowContext(ctx, `
			SELECT NOT EXISTS (
			  SELECT 1 FROM users WHERE id=$2 AND home_node_id=$3 AND status='active'
			  UNION ALL
			  SELECT 1 FROM replica_copies WHERE user_id=$1 AND node_id=$3
			    AND state NOT IN ('empty','stale','corrupt','deleting','error')
			  UNION ALL
			  SELECT 1 FROM user_replicas WHERE user_id=$2 AND node_id=$3
			    AND state NOT IN ('empty','stale','error')
			  UNION ALL
			  SELECT 1 FROM node_accounts WHERE user_id=$1 AND node_id=$3
			    AND status IN ('pending','active','conflict')
			) AND (
			  $4::text<>'archive_replica' OR EXISTS (
			    SELECT 1 FROM replica_copies copy
			    JOIN snapshot_manifests snapshot ON snapshot.id=copy.snapshot_id
			      AND snapshot.workflow_id=$6::uuid AND snapshot.state='immutable'
			    WHERE copy.user_id=$1 AND copy.node_id=$5 AND copy.replica_kind='archive'
			      AND copy.state='ready' AND copy.compatibility_state='compatible'
			  )
			)`, userID, legacyUserID, sourceNodeID, kind, targetNodeID, workflowArg).
			Scan(&committed); err != nil {
			return err
		}
		if !committed {
			return ErrNodeRetirementState
		}
		return tx.Commit()
	}
	switch kind {
	case "archive_replica":
		if (state != "snapshotting" && state != "retry_wait" && state != "blocked") || !workflowID.Valid ||
			workflowState.String != "succeeded" || targetNodeID <= 0 {
			return ErrNodeRetirementState
		}
		var ready bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
			  SELECT 1 FROM replica_copies copy
			  JOIN snapshot_manifests snapshot ON snapshot.id=copy.snapshot_id
			    AND snapshot.workflow_id=$3 AND snapshot.state='immutable'
			  WHERE copy.user_id=$1 AND copy.node_id=$2 AND copy.replica_kind='archive'
			    AND copy.state='ready' AND copy.compatibility_state='compatible'
			)`, userID, targetNodeID, workflowID.String).Scan(&ready); err != nil || !ready {
			return ErrNodeRetirementState
		}
	case "redundant_replica":
		if workflowID.Valid || (state != "pending" && state != "retry_wait" && state != "blocked") {
			return ErrNodeRetirementState
		}
		var protected bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
			  SELECT 1 FROM users legacy JOIN nodes home ON home.id=legacy.home_node_id
			  WHERE legacy.id=$2 AND legacy.home_node_id<>$3 AND legacy.status='active'
			    AND home.connectivity_state='online' AND home.operational_state='active'
			    AND home.compatibility_state='compatible' AND home.control_mode='managed'
			    AND home.desired_control_mode='managed'
			) AND EXISTS (
			  SELECT 1 FROM replica_copies copy JOIN nodes archive ON archive.id=copy.node_id
			  JOIN snapshot_manifests snapshot ON snapshot.id=copy.snapshot_id AND snapshot.state='immutable'
			  WHERE copy.user_id=$1 AND copy.node_id<>$3 AND copy.replica_kind='archive'
			    AND copy.state='ready' AND copy.compatibility_state='compatible'
			    AND archive.connectivity_state='online' AND archive.operational_state='active'
			    AND archive.compatibility_state='compatible'
			)`, userID, legacyUserID, sourceNodeID).Scan(&protected); err != nil || !protected {
			return ErrNodeRetirementState
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE replica_copies SET state='stale',is_authoritative=false,updated_at=$3
			WHERE user_id=$1 AND node_id=$2`, userID, sourceNodeID, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE user_replicas SET state='stale' WHERE user_id=$1 AND node_id=$2`,
			legacyUserID, sourceNodeID); err != nil {
			return err
		}
	case "account_metadata":
		if workflowID.Valid || (state != "pending" && state != "retry_wait" && state != "blocked") {
			return ErrNodeRetirementState
		}
		var safe bool
		if err := tx.QueryRowContext(ctx, `
			SELECT NOT EXISTS (
			  SELECT 1 FROM users WHERE id=$2 AND home_node_id=$3 AND status='active'
			) AND NOT EXISTS (
			  SELECT 1 FROM replica_copies WHERE user_id=$1 AND node_id=$3
			    AND state NOT IN ('empty','stale','corrupt','deleting','error')
			) AND NOT EXISTS (
			  SELECT 1 FROM user_replicas WHERE user_id=$2 AND node_id=$3
			    AND state NOT IN ('empty','stale','error')
			)`, userID, legacyUserID, sourceNodeID).Scan(&safe); err != nil || !safe {
			return ErrNodeRetirementState
		}
	default:
		return ErrNodeRetirementState
	}
	var auditWorkflowID any
	if workflowID.Valid {
		auditWorkflowID = workflowID.String
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE node_accounts SET status='stale',updated_at=$3
		WHERE user_id=$1 AND node_id=$2 AND status IN ('pending','active','conflict')`,
		userID, sourceNodeID, now); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE node_retirement_items SET state='succeeded',completed_at=$2,updated_at=$2,error_code=NULL
		WHERE id=$1 AND state NOT IN ('succeeded','superseded','failed')`, itemID, now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrNodeRetirementState
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  actor_type,action,target_type,target_id,operation_id,controller_generation,outcome,detail
		) VALUES ('system','node-retirement-item','global_user',$1::text,$2,$3,'succeeded',
		  jsonb_build_object('retirement_id',$4::text,'item_kind',$5::text,'source_node_id',$6::bigint,
		    'target_node_id',NULLIF($7::bigint,0),'workflow_id',$8::text))`,
		userID, operationID, generation, retirementID, kind, sourceNodeID, targetNodeID,
		auditWorkflowID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) FinalizeNodeRetirement(
	ctx context.Context,
	retirementID, lifecycleEventID string,
	now time.Time,
) (bool, error) {
	if !validUUIDText(retirementID) || !validUUIDText(lifecycleEventID) {
		return false, ErrNodeRetirementConflict
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var nodeID, generation int64
	var state, nodeState, controlMode, desiredMode string
	var adminID sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT operation.node_id,operation.state,operation.controller_generation,
		  operation.requested_by_admin_id,node.operational_state,node.control_mode,node.desired_control_mode
		FROM node_retirement_operations operation JOIN nodes node ON node.id=operation.node_id
		WHERE operation.id=$1 FOR UPDATE OF operation,node`, retirementID).Scan(
		&nodeID, &state, &generation, &adminID, &nodeState, &controlMode, &desiredMode,
	)
	if err != nil {
		return false, err
	}
	if state == "decommissioned" && nodeState == "decommissioned" {
		return true, tx.Commit()
	}
	if (state != "migrating" && state != "verifying" && state != "blocked") || nodeState != "retiring" ||
		controlMode != "managed" || desiredMode != "managed" {
		return false, ErrNodeRetirementState
	}
	var unfinished bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM node_retirement_items
		  WHERE retirement_id=$1 AND state NOT IN ('succeeded','superseded'))`, retirementID).Scan(&unfinished); err != nil {
		return false, err
	}
	if unfinished {
		return false, ErrNodeRetirementState
	}
	var dependent bool
	if err := tx.QueryRowContext(ctx, nodeRetirementDependencyQuery, nodeID).Scan(&dependent); err != nil {
		return false, err
	}
	if dependent {
		if _, err := tx.ExecContext(ctx, `
			UPDATE node_retirement_operations SET state='blocked',error_code='retirement_dependencies_remaining',
			  next_attempt_at=$2,updated_at=$3 WHERE id=$1`, retirementID, now.Add(time.Minute), now); err != nil {
			return false, err
		}
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).
		Scan(&activeGeneration); err != nil || activeGeneration != generation {
		if err != nil {
			return false, err
		}
		return false, ErrNodeRetirementState
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE nodes SET operational_state='decommissioned',status='offline',
		  allow_register=false,is_backup_target=false WHERE id=$1`, nodeID); err != nil {
		return false, err
	}
	if err := revokeNodeAccessLocked(ctx, tx, nodeID, now); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO node_lifecycle_events (
		  operation_id,node_id,from_state,to_state,reason_code,actor_admin_id,
		  controller_generation,created_at
		) VALUES ($1,$2,'retiring','decommissioned','retirement_completed',$3,$4,$5)`,
		lifecycleEventID, nodeID, nullInt64Value(adminID), generation, now); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE node_retirement_operations SET state='decommissioned',lease_owner=NULL,lease_until=NULL,
		  next_attempt_at=NULL,error_code=NULL,updated_at=$2,completed_at=$2 WHERE id=$1`,
		retirementID, now); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  actor_type,action,target_type,target_id,operation_id,controller_generation,outcome,detail
		) SELECT 'system','node-retirement','node',$2::text,operation_id,$3,'succeeded',
		  jsonb_build_object('state','decommissioned')
		FROM node_retirement_operations WHERE id=$1`, retirementID, nodeID, generation); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func revokeNodeAccessLocked(ctx context.Context, tx *sql.Tx, nodeID int64, now time.Time) error {
	statements := []struct {
		query string
		args  []any
	}{
		{`UPDATE agent_credentials SET revoked_at=COALESCE(revoked_at,$2) WHERE node_id=$1`, []any{nodeID, now}},
		{`UPDATE agent_credential_rotations SET state='revoked' WHERE node_id=$1 AND state='pending'`, []any{nodeID}},
		{`DELETE FROM enrollment_tokens WHERE expected_node_id=$1 AND consumed_at IS NULL`, []any{nodeID}},
		{`UPDATE agent_commands SET state='expired',updated_at=$2
		 WHERE node_id=$1 AND state IN ('queued','leased','acked','running')`, []any{nodeID, now}},
		{`UPDATE admin_node_links SET state='revoked',revoked_at=COALESCE(revoked_at,$2),
		   updated_at=$2,last_error_code='node_retired' WHERE node_id=$1 AND state<>'revoked'`, []any{nodeID, now}},
		{`UPDATE control_tickets SET revoked_at=COALESCE(revoked_at,$2)
		 WHERE target_node_id=$1 AND consumed_at IS NULL`, []any{nodeID, now}},
		{`UPDATE tickets SET expires_at=LEAST(expires_at,$2) WHERE node_id=$1 AND used_at IS NULL`, []any{nodeID, now}},
		{`UPDATE snapshot_transfer_capabilities SET state='revoked'
		 WHERE (source_node_id=$1 OR target_node_id=$1) AND state='prepared'`, []any{nodeID}},
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	return nil
}
