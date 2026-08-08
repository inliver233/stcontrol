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
