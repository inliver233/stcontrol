package store

import (
	"context"
	"database/sql"
	"time"
)

type ControllerRebuildNodeStatus struct {
	NodeID                  int64      `json:"node_id"`
	NodeName                string     `json:"node_name"`
	Role                    string     `json:"role"`
	State                   string     `json:"state"`
	AuthenticatedGeneration int64      `json:"authenticated_generation,omitempty"`
	CredentialVersion       int64      `json:"credential_version,omitempty"`
	LastHeartbeatAt         *time.Time `json:"last_heartbeat_at,omitempty"`
	CredentialActivatedAt   *time.Time `json:"credential_activated_at,omitempty"`
	ReconciledAt            *time.Time `json:"reconciled_at,omitempty"`
}

type ControllerRebuildStatus struct {
	ID                 string                        `json:"id"`
	OperationID        string                        `json:"operation_id"`
	Generation         int64                         `json:"generation"`
	PreviousGeneration int64                         `json:"previous_generation"`
	Source             string                        `json:"source"`
	State              string                        `json:"state"`
	TotalNodes         int                           `json:"total_nodes"`
	ReconciledNodes    int                           `json:"reconciled_nodes"`
	ErrorCode          string                        `json:"error_code,omitempty"`
	StartedAt          time.Time                     `json:"started_at"`
	UpdatedAt          time.Time                     `json:"updated_at"`
	CompletedAt        *time.Time                    `json:"completed_at,omitempty"`
	Nodes              []ControllerRebuildNodeStatus `json:"nodes"`
}

func (s *Store) GetLatestControllerRebuild(ctx context.Context) (*ControllerRebuildStatus, error) {
	status := &ControllerRebuildStatus{}
	var errorCode sql.NullString
	var completedAt sql.NullTime
	err := s.DB.QueryRowContext(ctx, `
		SELECT id::text,operation_id::text,generation,previous_generation,source,
		  state,total_nodes,reconciled_nodes,error_code,started_at,updated_at,completed_at
		FROM controller_rebuild_operations
		ORDER BY generation DESC LIMIT 1`).Scan(
		&status.ID, &status.OperationID, &status.Generation, &status.PreviousGeneration,
		&status.Source, &status.State, &status.TotalNodes, &status.ReconciledNodes,
		&errorCode, &status.StartedAt, &status.UpdatedAt, &completedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	status.ErrorCode = errorCode.String
	if completedAt.Valid {
		value := completedAt.Time
		status.CompletedAt = &value
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT item.node_id,node.name,node.role,item.state,
		  item.authenticated_generation,item.credential_version,item.last_heartbeat_at,
		  item.credential_activated_at,item.reconciled_at
		FROM controller_rebuild_nodes item
		JOIN nodes node ON node.id=item.node_id
		WHERE item.rebuild_id=$1
		ORDER BY item.node_id LIMIT 1000`, status.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var node ControllerRebuildNodeStatus
		var authenticatedGeneration, credentialVersion sql.NullInt64
		var lastHeartbeatAt, credentialActivatedAt, reconciledAt sql.NullTime
		if err := rows.Scan(
			&node.NodeID, &node.NodeName, &node.Role, &node.State,
			&authenticatedGeneration, &credentialVersion, &lastHeartbeatAt,
			&credentialActivatedAt, &reconciledAt,
		); err != nil {
			return nil, err
		}
		node.AuthenticatedGeneration = authenticatedGeneration.Int64
		node.CredentialVersion = credentialVersion.Int64
		if lastHeartbeatAt.Valid {
			value := lastHeartbeatAt.Time
			node.LastHeartbeatAt = &value
		}
		if credentialActivatedAt.Valid {
			value := credentialActivatedAt.Time
			node.CredentialActivatedAt = &value
		}
		if reconciledAt.Valid {
			value := reconciledAt.Time
			node.ReconciledAt = &value
		}
		status.Nodes = append(status.Nodes, node)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return status, nil
}

func controllerRebuildAllowsOldCredentialLocked(
	ctx context.Context,
	tx *sql.Tx,
	nodeID, activeGeneration, authenticatedGeneration int64,
) (bool, error) {
	var allowed bool
	err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
		  SELECT 1
		  FROM controller_rebuild_operations rebuild
		  JOIN controller_rebuild_nodes item ON item.rebuild_id=rebuild.id
		  JOIN agent_credentials credential ON credential.node_id=item.node_id
		  WHERE rebuild.generation=$1 AND rebuild.state='reconciling'
		    AND item.node_id=$2 AND item.state<>'reconciled'
		    AND item.previous_credential_generation=$3
		    AND credential.controller_generation=$3
		    AND credential.revoked_at IS NULL
		)`, activeGeneration, nodeID, authenticatedGeneration).Scan(&allowed)
	return allowed, err
}

func markControllerRebuildHeartbeatLocked(
	ctx context.Context,
	tx *sql.Tx,
	nodeID, activeGeneration, authenticatedGeneration int64,
	reportedMode, desiredMode string,
	now time.Time,
) error {
	var rebuildID string
	err := tx.QueryRowContext(ctx, `
		UPDATE controller_rebuild_nodes item SET
		  state=CASE
		    WHEN item.state='reconciled' THEN item.state
		    WHEN $3=$2 AND $4='managed' AND $5='managed' THEN 'reconciled'
		    WHEN $3=$2 THEN 'draining'
		    WHEN item.state='rotation_pending' THEN item.state
		    ELSE 'heartbeat_verified' END,
		  authenticated_generation=$3,last_heartbeat_at=$6,
		  credential_activated_at=CASE WHEN $3=$2
		    THEN COALESCE(item.credential_activated_at,$6)
		    ELSE item.credential_activated_at END,
		  reconciled_at=CASE
		    WHEN $3=$2 AND $4='managed' AND $5='managed'
		    THEN COALESCE(item.reconciled_at,$6)
		    ELSE item.reconciled_at END,
		  updated_at=$6
		FROM controller_rebuild_operations rebuild
		WHERE rebuild.id=item.rebuild_id AND rebuild.generation=$2
		  AND rebuild.state='reconciling' AND item.node_id=$1
		RETURNING rebuild.id::text`,
		nodeID, activeGeneration, authenticatedGeneration, reportedMode, desiredMode, now).
		Scan(&rebuildID)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	return finishControllerRebuildIfReadyLocked(ctx, tx, rebuildID, now)
}

func markControllerRebuildRotationPendingLocked(
	ctx context.Context,
	tx *sql.Tx,
	nodeID, generation, credentialVersion int64,
	now time.Time,
) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE controller_rebuild_nodes item SET
		  state=CASE WHEN item.state IN ('reconciled','draining','credential_activated')
		    THEN item.state ELSE 'rotation_pending' END,
		  credential_version=$3,updated_at=$4
		FROM controller_rebuild_operations rebuild
		WHERE rebuild.id=item.rebuild_id AND rebuild.generation=$2
		  AND rebuild.state='reconciling' AND item.node_id=$1`,
		nodeID, generation, credentialVersion, now)
	return err
}

func markControllerRebuildCredentialActivatedLocked(
	ctx context.Context,
	tx *sql.Tx,
	nodeID, generation, credentialVersion int64,
	now time.Time,
) error {
	var rebuildID string
	err := tx.QueryRowContext(ctx, `
		UPDATE controller_rebuild_nodes item SET
		  state=CASE WHEN node.control_mode='managed'
		    AND node.desired_control_mode='managed'
		    THEN 'reconciled' ELSE 'draining' END,
		  authenticated_generation=$2,credential_version=$3,
		  credential_activated_at=COALESCE(item.credential_activated_at,$4),
		  reconciled_at=CASE WHEN node.control_mode='managed'
		    AND node.desired_control_mode='managed'
		    THEN COALESCE(item.reconciled_at,$4) ELSE NULL END,
		  updated_at=$4
		FROM controller_rebuild_operations rebuild,nodes node
		WHERE rebuild.id=item.rebuild_id AND rebuild.generation=$2
		  AND rebuild.state='reconciling' AND item.node_id=$1 AND node.id=item.node_id
		RETURNING rebuild.id::text`, nodeID, generation, credentialVersion, now).
		Scan(&rebuildID)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	return finishControllerRebuildIfReadyLocked(ctx, tx, rebuildID, now)
}

func finishControllerRebuildIfReadyLocked(
	ctx context.Context,
	tx *sql.Tx,
	rebuildID string,
	now time.Time,
) error {
	var total, reconciled int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*)::int,
		  count(*) FILTER (WHERE state='reconciled')::int
		FROM controller_rebuild_nodes WHERE rebuild_id=$1`, rebuildID).
		Scan(&total, &reconciled); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE controller_rebuild_operations SET total_nodes=$2,
		  reconciled_nodes=$3,updated_at=$4 WHERE id=$1`,
		rebuildID, total, reconciled, now); err != nil {
		return err
	}
	if total == 0 || reconciled != total {
		return nil
	}
	var operationID string
	var generation int64
	err := tx.QueryRowContext(ctx, `
		UPDATE controller_rebuild_operations SET state='succeeded',completed_at=$2,
		  updated_at=$2 WHERE id=$1 AND state='reconciling'
		RETURNING operation_id::text,generation`, rebuildID, now).
		Scan(&operationID, &generation)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  actor_type,action,target_type,target_id,operation_id,
		  controller_generation,outcome,detail
		) VALUES (
		  'controller','controller-rebuild-completed','controller_epoch',$2::text,
		  $3,$2::bigint,'succeeded',jsonb_build_object(
		    'rebuild_id',$1::text,'reconciled_nodes',$4::int))`,
		rebuildID, generation, operationID, reconciled)
	return err
}
