package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	storageRepairDefaultEstimate = int64(1 << 30)
	storageRepairMinimumEstimate = int64(64 << 20)
)

var ErrInvalidStorageRepairExecution = errors.New("invalid storage repair execution input")

// CreateStorageRepairExecutionParams contains the pre-generated, purpose-scoped
// identifiers required to create one repair workflow. The Store never persists
// the plaintext capability, only its digest.
type CreateStorageRepairExecutionParams struct {
	ExecutionID       string
	LeaseOwner        string
	WorkflowID        string
	OperationID       string
	SnapshotID        string
	CapabilityID      string
	CapabilityHash    []byte
	CapabilityExpires time.Time
	LeaseTTL          time.Duration
	MaxAttempts       int
	Now               time.Time
}

type StorageRepairExecution struct {
	TaskID               string
	WorkflowID           string
	SnapshotID           string
	LegacyBackupJobID    int64
	LegacyUserID         int64
	GlobalUserID         int64
	SourceNodeID         int64
	TargetNodeID         int64
	EstimatedBytes       int64
	ActivityEpoch        int64
	ControllerGeneration int64
}

// ListActiveStorageRepairUserIDs lets the ordinary offline-backup scheduler
// avoid bypassing a durable repair intent with the legacy fire-and-forget path.
func (s *Store) ListActiveStorageRepairUserIDs(ctx context.Context) (map[int64]struct{}, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT user_id FROM storage_repair_tasks
		WHERE state IN ('pending','retry_wait','workflow_running')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make(map[int64]struct{})
	for rows.Next() {
		var userID int64
		if err := rows.Scan(&userID); err != nil {
			return nil, err
		}
		users[userID] = struct{}{}
	}
	return users, rows.Err()
}

// ScheduleStorageRepairTasks projects eligible unprotected users into one
// durable active intent per user. It deliberately does not pick a target: the
// target and its byte reservation are chosen together in the serializable
// claim/create transaction.
func (s *Store) ScheduleStorageRepairTasks(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	// A separately published healthy archive makes a not-yet-running intent
	// obsolete. A running workflow owns its reservation until terminal and is
	// reconciled below rather than being cancelled underneath an Agent.
	if _, err := tx.ExecContext(ctx, `
		UPDATE storage_repair_tasks task SET state='cancelled',reserved_bytes=0,
		  workflow_id=NULL,last_error_code='protection_already_available',
		  finished_at=$1,updated_at=$1
		WHERE task.state IN ('pending','retry_wait') AND (
		  NOT EXISTS (
		    SELECT 1 FROM user_protection_states protection
		    WHERE protection.user_id=task.user_id
		      AND protection.state IN ('temporary','unprotected')
		  ) OR EXISTS (
		    SELECT 1 FROM replica_copies copy
		    JOIN snapshot_manifests snapshot ON snapshot.id=copy.snapshot_id
		      AND snapshot.user_id=task.user_id AND snapshot.state='immutable'
		    JOIN nodes node ON node.id=copy.node_id AND node.role='storage'
		      AND node.connectivity_state='online' AND node.operational_state='active'
		      AND node.compatibility_state='compatible' AND node.control_mode='managed'
		      AND node.desired_control_mode='managed'
		    JOIN user_replicas legacy_copy ON legacy_copy.user_id=task.legacy_user_id
		      AND legacy_copy.node_id=copy.node_id AND legacy_copy.kind='archive'
		      AND legacy_copy.state='ready'
		    WHERE copy.user_id=task.user_id AND copy.replica_kind='archive'
		      AND copy.state='ready' AND copy.compatibility_state='compatible'
		      AND copy.published_at IS NOT NULL AND copy.verified_at IS NOT NULL
		  )
		)`, now); err != nil {
		return 0, fmt.Errorf("cancel obsolete storage repair tasks: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO storage_repair_tasks (
		  user_id,legacy_user_id,source_node_id,estimated_bytes,reserved_bytes,
		  state,next_attempt_at,created_at,updated_at
		)
		SELECT global_user.id,legacy.id,legacy.home_node_id,
		  GREATEST(
		    COALESCE(NULLIF(home_replica.size_bytes,0),(
		      SELECT NULLIF(snapshot.total_bytes,0)
		      FROM snapshot_manifests snapshot
		      WHERE snapshot.user_id=global_user.id AND snapshot.state='immutable'
		      ORDER BY snapshot.created_at DESC,snapshot.id DESC LIMIT 1
		    ),$2::bigint),$3::bigint),
		  0,'pending',$1,$1,$1
		FROM user_protection_states protection
		JOIN global_users global_user ON global_user.id=protection.user_id
		  AND global_user.status='active'
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		  AND legacy.status='active' AND legacy.home_node_id IS NOT NULL
		JOIN nodes home ON home.id=legacy.home_node_id AND home.role='compute'
		  AND home.connectivity_state='online' AND home.operational_state='active'
		  AND home.compatibility_state='compatible' AND home.control_mode='managed'
		  AND home.desired_control_mode='managed'
		JOIN user_replicas home_replica ON home_replica.user_id=legacy.id
		  AND home_replica.node_id=legacy.home_node_id AND home_replica.kind='home'
		  AND home_replica.state='ready'
		WHERE protection.state IN ('temporary','unprotected')
		  AND NOT EXISTS (
		    SELECT 1 FROM replica_copies copy
		    JOIN snapshot_manifests snapshot ON snapshot.id=copy.snapshot_id
		      AND snapshot.user_id=global_user.id AND snapshot.state='immutable'
		    JOIN nodes archive ON archive.id=copy.node_id AND archive.role='storage'
		      AND archive.connectivity_state='online' AND archive.operational_state='active'
		      AND archive.compatibility_state='compatible' AND archive.control_mode='managed'
		      AND archive.desired_control_mode='managed'
		    JOIN user_replicas archive_legacy ON archive_legacy.user_id=legacy.id
		      AND archive_legacy.node_id=copy.node_id AND archive_legacy.kind='archive'
		      AND archive_legacy.state='ready'
		    WHERE copy.user_id=global_user.id AND copy.replica_kind='archive'
		      AND copy.state='ready' AND copy.compatibility_state='compatible'
		      AND copy.published_at IS NOT NULL AND copy.verified_at IS NOT NULL
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM user_activity_leases lease WHERE lease.user_id=global_user.id
		      AND (lease.lease_expires_at>$1 OR lease.in_flight_reads<>0 OR lease.in_flight_writes<>0
		        OR lease.state IN ('independent','quiescing','conflict'))
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM workflows workflow WHERE workflow.user_id=global_user.id
		      AND workflow.workflow_type IN ('snapshot','restore','conflict_resolution')
		      AND workflow.state NOT IN ('succeeded','cancelled','failed')
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM replica_conflicts conflict WHERE conflict.user_id=global_user.id
		      AND conflict.state NOT IN ('resolved','failed')
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM user_data_faults fault WHERE fault.user_id=global_user.id
		      AND fault.state<>'resolved'
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM replica_cleanup_tasks cleanup WHERE cleanup.user_id=global_user.id
		      AND cleanup.node_id=legacy.home_node_id
		      AND cleanup.state IN ('pending','running','retry_wait')
		  )
		ON CONFLICT DO NOTHING`, now, storageRepairDefaultEstimate, storageRepairMinimumEstimate)
	if err != nil {
		return 0, fmt.Errorf("schedule storage repair tasks: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	return rows, err
}

// ClaimAndCreateStorageRepair atomically claims a durable intent, chooses and
// reserves a capacity-eligible pure-storage target, revalidates every safety
// fence, and creates the legacy job plus all snapshot workflow facts. No Agent
// can observe an orphan job or an unreserved workflow.
func (s *Store) ClaimAndCreateStorageRepair(
	ctx context.Context,
	p CreateStorageRepairExecutionParams,
) (*StorageRepairExecution, error) {
	if !validUUIDText(p.ExecutionID) || !validUUIDText(p.LeaseOwner) ||
		!validUUIDText(p.WorkflowID) || !validUUIDText(p.OperationID) ||
		!validUUIDText(p.SnapshotID) || !validUUIDText(p.CapabilityID) ||
		len(p.CapabilityHash) != 32 || p.LeaseTTL <= 0 || p.MaxAttempts <= 0 {
		return nil, ErrInvalidStorageRepairExecution
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	if !p.CapabilityExpires.After(p.Now) {
		return nil, ErrInvalidStorageRepairExecution
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var out StorageRepairExecution
	var taskAttempt int
	err = tx.QueryRowContext(ctx, `
		SELECT task.id::text,task.legacy_user_id,task.user_id,task.source_node_id,
		  task.estimated_bytes,task.attempt
		FROM storage_repair_tasks task
		JOIN global_users global_user ON global_user.id=task.user_id
		  AND global_user.legacy_user_id=task.legacy_user_id AND global_user.status='active'
		JOIN users legacy ON legacy.id=task.legacy_user_id AND legacy.status='active'
		  AND legacy.home_node_id=task.source_node_id
		JOIN user_protection_states protection ON protection.user_id=task.user_id
		  AND protection.state IN ('temporary','unprotected')
		JOIN nodes home ON home.id=task.source_node_id AND home.role='compute'
		  AND home.connectivity_state='online' AND home.operational_state='active'
		  AND home.compatibility_state='compatible' AND home.control_mode='managed'
		  AND home.desired_control_mode='managed'
		JOIN user_replicas home_replica ON home_replica.user_id=task.legacy_user_id
		  AND home_replica.node_id=task.source_node_id AND home_replica.kind='home'
		  AND home_replica.state='ready'
		WHERE task.state IN ('pending','retry_wait') AND task.next_attempt_at<=$1
		  AND task.attempt<$2
		  AND NOT EXISTS (
		    SELECT 1 FROM replica_copies copy
		    JOIN snapshot_manifests snapshot ON snapshot.id=copy.snapshot_id
		      AND snapshot.user_id=task.user_id AND snapshot.state='immutable'
		    JOIN nodes archive ON archive.id=copy.node_id AND archive.role='storage'
		      AND archive.connectivity_state='online' AND archive.operational_state='active'
		      AND archive.compatibility_state='compatible' AND archive.control_mode='managed'
		      AND archive.desired_control_mode='managed'
		    JOIN user_replicas archive_legacy ON archive_legacy.user_id=task.legacy_user_id
		      AND archive_legacy.node_id=copy.node_id AND archive_legacy.kind='archive'
		      AND archive_legacy.state='ready'
		    WHERE copy.user_id=task.user_id AND copy.replica_kind='archive'
		      AND copy.state='ready' AND copy.compatibility_state='compatible'
		      AND copy.published_at IS NOT NULL AND copy.verified_at IS NOT NULL
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM workflows workflow WHERE workflow.user_id=task.user_id
		      AND workflow.workflow_type IN ('snapshot','restore','conflict_resolution')
		      AND workflow.state NOT IN ('succeeded','cancelled','failed')
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM replica_conflicts conflict WHERE conflict.user_id=task.user_id
		      AND conflict.state NOT IN ('resolved','failed')
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM user_data_faults fault WHERE fault.user_id=task.user_id
		      AND fault.state<>'resolved'
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM replica_cleanup_tasks cleanup WHERE cleanup.user_id=task.user_id
		      AND cleanup.node_id=task.source_node_id
		      AND cleanup.state IN ('pending','running','retry_wait')
		  )
		ORDER BY task.next_attempt_at,task.created_at,task.id
		FOR UPDATE OF task,global_user,legacy,home,home_replica SKIP LOCKED LIMIT 1`,
		p.Now, p.MaxAttempts).Scan(
		&out.TaskID, &out.LegacyUserID, &out.GlobalUserID, &out.SourceNodeID,
		&out.EstimatedBytes, &taskAttempt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim storage repair intent: %w", err)
	}

	if err := tx.QueryRowContext(ctx, `
		SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).
		Scan(&out.ControllerGeneration); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNoActiveController
		}
		return nil, err
	}

	// Lock and verify the exact offline writer epoch after claiming the intent.
	out.ActivityEpoch = 1
	var writerNodeID, inFlightReads, inFlightWrites int64
	var leaseExpires time.Time
	var leaseState string
	err = tx.QueryRowContext(ctx, `
		SELECT activity_epoch,writer_node_id,lease_expires_at,in_flight_reads,in_flight_writes,state
		FROM user_activity_leases WHERE user_id=$1 FOR UPDATE`, out.GlobalUserID).
		Scan(&out.ActivityEpoch, &writerNodeID, &leaseExpires, &inFlightReads, &inFlightWrites, &leaseState)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if err == nil && (writerNodeID != out.SourceNodeID || leaseExpires.After(p.Now) ||
		inFlightReads != 0 || inFlightWrites != 0 ||
		leaseState == "independent" || leaseState == "quiescing" || leaseState == "conflict") {
		return nil, nil
	}

	// Both real free space and configured quota are reduced by other active
	// reservations. Metrics must be recent so unknown capacity never becomes a
	// speculative target. Ordering is intentionally small and deterministic.
	err = tx.QueryRowContext(ctx, `
		SELECT node.id
		FROM nodes node
		WHERE node.id<>$1 AND node.role='storage' AND node.is_backup_target
		  AND node.connectivity_state='online' AND node.operational_state='active'
		  AND node.compatibility_state='compatible' AND node.control_mode='managed'
		  AND node.desired_control_mode='managed' AND node.capacity_state IN ('open','busy')
		  AND COALESCE(node.transfer_url,'')<>''
		  AND node.metrics_observed_at IS NOT NULL AND node.metrics_observed_at>=$3
		  AND node.disk_available_bytes IS NOT NULL AND node.disk_quota_bytes IS NOT NULL
		  AND node.allocated_disk_bytes IS NOT NULL
		  AND node.disk_available_bytes-COALESCE((
		    SELECT sum(reservation.reserved_bytes) FROM storage_repair_tasks reservation
		    WHERE reservation.target_node_id=node.id AND reservation.state='workflow_running'
		  ),0)>=$2
		  AND node.disk_quota_bytes-node.allocated_disk_bytes-COALESCE((
		    SELECT sum(reservation.reserved_bytes) FROM storage_repair_tasks reservation
		    WHERE reservation.target_node_id=node.id AND reservation.state='workflow_running'
		  ),0)>=$2
		  AND NOT EXISTS (
		    SELECT 1 FROM replica_cleanup_tasks cleanup
		    WHERE cleanup.user_id=$4 AND cleanup.node_id=node.id
		      AND cleanup.state IN ('pending','running','retry_wait')
		  )
		ORDER BY CASE node.capacity_state WHEN 'open' THEN 0 ELSE 1 END,
		  LEAST(node.disk_available_bytes,node.disk_quota_bytes-node.allocated_disk_bytes)-
		    COALESCE((SELECT sum(reservation.reserved_bytes)
		      FROM storage_repair_tasks reservation
		      WHERE reservation.target_node_id=node.id AND reservation.state='workflow_running'),0) DESC,
		  node.id
		FOR UPDATE OF node SKIP LOCKED LIMIT 1`,
		out.SourceNodeID, out.EstimatedBytes, p.Now.Add(-2*time.Minute), out.GlobalUserID).
		Scan(&out.TargetNodeID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("select storage repair target: %w", err)
	}

	if err := tx.QueryRowContext(ctx, `
		INSERT INTO backup_jobs (user_id,src_node_id,dst_node_id,trigger,status,created_at)
		VALUES ($1,$2,$3,'storage_repair','pending',$4) RETURNING id`,
		out.LegacyUserID, out.SourceNodeID, out.TargetNodeID, p.Now).
		Scan(&out.LegacyBackupJobID); err != nil {
		return nil, fmt.Errorf("create storage repair backup job: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO workflows (
		  id,operation_id,workflow_type,state,user_id,source_node_id,target_node_id,
		  activity_epoch,controller_generation,created_at,updated_at
		) VALUES ($1,$2,'snapshot','scheduled',$3,$4,$5,$6,$7,$8,$8)`,
		p.WorkflowID, p.OperationID, out.GlobalUserID, out.SourceNodeID, out.TargetNodeID,
		out.ActivityEpoch, out.ControllerGeneration, p.Now); err != nil {
		return nil, fmt.Errorf("create storage repair workflow: %w", err)
	}
	for _, step := range []string{"quiesce", "snapshot", "prepare_target", "transfer", "verify", "publish", "cleanup"} {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO workflow_steps (workflow_id,step_name,state,updated_at)
			VALUES ($1,$2,'pending',$3)`, p.WorkflowID, step, p.Now); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO snapshot_manifests (
		  id,workflow_id,user_id,source_node_id,activity_epoch,format_version,
		  manifest_sha256,file_count,total_bytes,state,created_at
		) VALUES ($1,$2,$3,$4,$5,1,$6,0,0,'building',$7)`,
		p.SnapshotID, p.WorkflowID, out.GlobalUserID, out.SourceNodeID,
		out.ActivityEpoch, make([]byte, 32), p.Now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO snapshot_transfer_capabilities (
		  id,workflow_id,snapshot_id,source_node_id,target_node_id,token_hash,
		  state,controller_generation,expires_at,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,'prepared',$7,$8,$9)`,
		p.CapabilityID, p.WorkflowID, p.SnapshotID, out.SourceNodeID, out.TargetNodeID,
		p.CapabilityHash, out.ControllerGeneration, p.CapabilityExpires, p.Now); err != nil {
		return nil, err
	}
	if result, err := tx.ExecContext(ctx, `
		UPDATE backup_jobs SET workflow_id=$2,snapshot_id=$3,activity_epoch=$4
		WHERE id=$1 AND user_id=$5 AND src_node_id=$6 AND dst_node_id=$7`,
		out.LegacyBackupJobID, p.WorkflowID, p.SnapshotID, out.ActivityEpoch,
		out.LegacyUserID, out.SourceNodeID, out.TargetNodeID); err != nil {
		return nil, err
	} else if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return nil, err
		}
		return nil, ErrInvalidStorageRepairExecution
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,data_version,state)
		VALUES ($1,$2,'archive',0,'syncing')
		ON CONFLICT (user_id,node_id) DO UPDATE SET
		  kind=CASE WHEN user_replicas.state='ready' THEN user_replicas.kind ELSE 'archive' END,
		  state=CASE WHEN user_replicas.state='ready' THEN 'ready' ELSE 'syncing' END`,
		out.LegacyUserID, out.TargetNodeID); err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE storage_repair_tasks SET state='workflow_running',attempt=attempt+1,
		  target_node_id=$2,reserved_bytes=estimated_bytes,execution_id=$3,
		  lease_owner=$4,lease_until=$5,controller_generation=$6,
		  workflow_id=$7,backup_job_id=$8,last_error_code=NULL,updated_at=$9
		WHERE id=$1 AND state IN ('pending','retry_wait') AND attempt=$10`,
		out.TaskID, out.TargetNodeID, p.ExecutionID, p.LeaseOwner, p.Now.Add(p.LeaseTTL),
		out.ControllerGeneration, p.WorkflowID, out.LegacyBackupJobID, p.Now, taskAttempt)
	if err != nil {
		return nil, err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return nil, err
		}
		return nil, ErrInvalidStorageRepairExecution
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  occurred_at,actor_type,actor_id,action,target_type,target_id,operation_id,
		  controller_generation,outcome,detail
		) VALUES ($1,'controller',$2::text,'storage-repair','global_user',$3::text,
		  $4,$5,'scheduled',jsonb_build_object(
		    'task_id',$6::text,'workflow_id',$7::text,'source_node_id',$8::bigint,
		    'target_node_id',$9::bigint,'estimated_bytes',$10::bigint,
		    'attempt',$11::bigint))`,
		p.Now, p.LeaseOwner, out.GlobalUserID, p.ExecutionID, out.ControllerGeneration,
		out.TaskID, p.WorkflowID, out.SourceNodeID, out.TargetNodeID, out.EstimatedBytes,
		taskAttempt+1); err != nil {
		return nil, fmt.Errorf("audit storage repair scheduling: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	out.WorkflowID = p.WorkflowID
	out.SnapshotID = p.SnapshotID
	return &out, nil
}

// ReconcileStorageRepairTasks releases reservations for terminal workflows and
// persists bounded exponential retry state. Because the backoff lives in the
// database, restarts cannot reset it or create a job every scheduler tick.
func (s *Store) ReconcileStorageRepairTasks(
	ctx context.Context,
	now time.Time,
	maxAttempts int,
) (int64, error) {
	if maxAttempts <= 0 {
		return 0, ErrInvalidStorageRepairExecution
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	// Record the exact execution identity and its final target before clearing
	// the lease. The same transaction changes the task out of workflow_running,
	// so a restart cannot duplicate this audit event.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  occurred_at,actor_type,actor_id,action,target_type,target_id,operation_id,
		  controller_generation,outcome,detail
		)
		SELECT $1,'controller',task.lease_owner::text,'storage-repair','global_user',
		  task.user_id::text,task.execution_id,task.controller_generation,
		  CASE WHEN workflow.state='succeeded' THEN 'succeeded'
		    WHEN task.attempt>=$2 THEN 'failed' ELSE 'retry_wait' END,
		  jsonb_build_object(
		    'task_id',task.id::text,'workflow_id',task.workflow_id::text,
		    'source_node_id',task.source_node_id,'target_node_id',task.target_node_id,
		    'estimated_bytes',task.estimated_bytes,'attempt',task.attempt,
		    'workflow_state',workflow.state,'error_code',workflow.error_code)
		FROM storage_repair_tasks task
		JOIN workflows workflow ON workflow.id=task.workflow_id
		WHERE task.state='workflow_running'
		  AND workflow.state IN ('succeeded','failed','cancelled')`, now, maxAttempts); err != nil {
		return 0, fmt.Errorf("audit terminal storage repair workflows: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE storage_repair_tasks task SET
		  state=CASE
		    WHEN workflow.state='succeeded' THEN 'succeeded'
		    WHEN task.attempt>=$2 THEN 'failed'
		    ELSE 'retry_wait' END,
		  reserved_bytes=0,last_target_node_id=task.target_node_id,target_node_id=NULL,
		  last_workflow_id=task.workflow_id,workflow_id=NULL,
		  lease_owner=NULL,lease_until=NULL,
		  last_error_code=CASE
		    WHEN workflow.state='succeeded' THEN NULL
		    WHEN workflow.error_code ~ '^[a-z][a-z0-9_]{0,63}$' THEN workflow.error_code
		    WHEN workflow.state='cancelled' THEN 'snapshot_workflow_cancelled'
		    ELSE 'snapshot_workflow_failed' END,
		  next_attempt_at=CASE WHEN workflow.state='succeeded' OR task.attempt>=$2 THEN $1::timestamptz
		    ELSE $1::timestamptz+make_interval(secs => LEAST(3600,
		      (30*power(2,LEAST(GREATEST(task.attempt-1,0),7)))::int)) END,
		  finished_at=CASE WHEN workflow.state='succeeded' OR task.attempt>=$2 THEN $1 ELSE NULL END,
		  updated_at=$1
		FROM workflows workflow
		WHERE task.state='workflow_running' AND workflow.id=task.workflow_id
		  AND workflow.state IN ('succeeded','failed','cancelled')`, now, maxAttempts)
	if err != nil {
		return 0, fmt.Errorf("reconcile terminal storage repair workflows: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  occurred_at,actor_type,action,target_type,target_id,operation_id,
		  controller_generation,outcome,detail
		)
		SELECT $1,'controller','storage-repair','global_user',task.user_id::text,
		  task.execution_id,task.controller_generation,'failed',jsonb_build_object(
		    'task_id',task.id::text,'last_workflow_id',task.last_workflow_id::text,
		    'last_target_node_id',task.last_target_node_id,
		    'estimated_bytes',task.estimated_bytes,'attempt',task.attempt,
		    'error_code','attempt_limit_reached')
		FROM storage_repair_tasks task
		WHERE task.state IN ('pending','retry_wait') AND task.attempt>=$2`,
		now, maxAttempts); err != nil {
		return 0, fmt.Errorf("audit exhausted storage repair tasks: %w", err)
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE storage_repair_tasks SET state='failed',last_error_code='attempt_limit_reached',
		  finished_at=$1,updated_at=$1
		WHERE state IN ('pending','retry_wait') AND attempt>=$2`, now, maxAttempts)
	if err != nil {
		return 0, fmt.Errorf("finalize exhausted storage repair tasks: %w", err)
	}
	exhausted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return rows + exhausted, nil
}
