package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidReplicaCleanup = errors.New("invalid replica cleanup")
	ErrReplicaCleanupFence   = errors.New("replica cleanup fence mismatch")
)

const (
	ReplicaCleanupStabilityWindow  = 10 * time.Minute
	ReplicaCleanupProjectionMaxAge = 2 * time.Minute
)

type ReplicaCleanupTask struct {
	ID                   string
	ReplicaID            string
	GlobalUserID         int64
	LegacyUserID         int64
	NodeID               int64
	SnapshotID           string
	Handle               string
	ReplicaKind          string
	ReasonCode           string
	Attempt              int
	OperationID          string
	ControllerGeneration int64
	LeaseOwner           string
}

// ScheduleReplicaCleanupTasks materializes physical cleanup only after a newer
// verified archive is current. Temporary compute replicas additionally wait
// for the protected projection to remain stable for the full safety window.
func (s *Store) ScheduleReplicaCleanupTasks(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		UPDATE replica_cleanup_tasks task SET state='cancelled',lease_owner=NULL,lease_until=NULL,
		  error_code='replica_scope_changed',updated_at=$1,finished_at=$1
		WHERE task.state IN ('pending','retry_wait') AND NOT EXISTS (
		  SELECT 1 FROM replica_copies copy
		  JOIN users legacy ON legacy.id=task.legacy_user_id
		  WHERE copy.id=task.replica_id AND copy.user_id=task.user_id AND copy.node_id=task.node_id
		    AND copy.snapshot_id=task.snapshot_id AND copy.replica_kind=task.replica_kind
		    AND NOT copy.is_authoritative AND legacy.home_node_id<>task.node_id
		)`, now); err != nil {
		return 0, err
	}
	archiveResult, err := tx.ExecContext(ctx, `
		INSERT INTO replica_cleanup_tasks (
		  id,replica_id,user_id,legacy_user_id,node_id,snapshot_id,handle,replica_kind,
		  reason_code,state,next_attempt_at,created_at,updated_at
		)
		SELECT gen_random_uuid(),copy.id,copy.user_id,global_user.legacy_user_id,copy.node_id,
		  copy.snapshot_id,legacy.username,'archive','superseded_archive','pending',$1,$1,$1
		FROM replica_copies copy
		JOIN global_users global_user ON global_user.id=copy.user_id
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		WHERE copy.replica_kind='archive' AND copy.state='stale' AND copy.snapshot_id IS NOT NULL
		  AND legacy.home_node_id<>copy.node_id
		  AND EXISTS (
		    SELECT 1 FROM replica_copies current
		    JOIN snapshot_manifests manifest ON manifest.id=current.snapshot_id
		    JOIN nodes current_node ON current_node.id=current.node_id
		    WHERE current.user_id=copy.user_id AND current.replica_kind='archive'
		      AND current.state='ready' AND current.integrity_state='verified'
		      AND manifest.state='immutable' AND current.id<>copy.id
		      AND current_node.role='storage' AND current_node.connectivity_state='online'
		      AND current_node.operational_state='active' AND current_node.compatibility_state='compatible'
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM workflows workflow WHERE workflow.user_id=copy.user_id
		      AND workflow.state NOT IN ('succeeded','cancelled','failed')
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM replica_conflicts conflict WHERE conflict.user_id=copy.user_id
		      AND conflict.state NOT IN ('resolved','failed')
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM user_data_faults fault WHERE fault.user_id=copy.user_id AND fault.state<>'resolved'
		  )
		ON CONFLICT (node_id,snapshot_id,replica_kind) DO UPDATE SET
		  state=CASE WHEN replica_cleanup_tasks.state IN ('cancelled','failed') THEN 'pending'
		    ELSE replica_cleanup_tasks.state END,
		  next_attempt_at=CASE WHEN replica_cleanup_tasks.state IN ('cancelled','failed') THEN EXCLUDED.next_attempt_at
		    ELSE replica_cleanup_tasks.next_attempt_at END,
		  error_code=CASE WHEN replica_cleanup_tasks.state IN ('cancelled','failed') THEN NULL
		    ELSE replica_cleanup_tasks.error_code END,
		  updated_at=EXCLUDED.updated_at`, now)
	if err != nil {
		return 0, err
	}
	hotResult, err := tx.ExecContext(ctx, `
		INSERT INTO replica_cleanup_tasks (
		  id,replica_id,user_id,legacy_user_id,node_id,snapshot_id,handle,replica_kind,
		  reason_code,state,next_attempt_at,created_at,updated_at
		)
		SELECT gen_random_uuid(),copy.id,copy.user_id,global_user.legacy_user_id,copy.node_id,
		  copy.snapshot_id,legacy.username,'hot_standby','stable_archive_available','pending',$1,$1,$1
		FROM replica_copies copy
		JOIN global_users global_user ON global_user.id=copy.user_id
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		JOIN user_protection_states protection ON protection.user_id=copy.user_id
		JOIN nodes home_node ON home_node.id=legacy.home_node_id
		WHERE copy.replica_kind='hot_standby' AND copy.state='ready' AND copy.snapshot_id IS NOT NULL
		  AND NOT copy.is_authoritative AND legacy.home_node_id<>copy.node_id
		  AND protection.state='protected' AND protection.changed_at<=$2 AND protection.evaluated_at>=$3
		  AND home_node.role='compute' AND home_node.connectivity_state='online'
		  AND home_node.operational_state='active' AND home_node.compatibility_state='compatible'
		  AND EXISTS (
		    SELECT 1 FROM user_replicas home
		    WHERE home.user_id=legacy.id AND home.node_id=legacy.home_node_id
		      AND home.kind='home' AND home.state='ready'
		  )
		  AND EXISTS (
		    SELECT 1 FROM replica_copies archive
		    JOIN snapshot_manifests manifest ON manifest.id=archive.snapshot_id
		    JOIN nodes archive_node ON archive_node.id=archive.node_id
		    WHERE archive.user_id=copy.user_id AND archive.replica_kind='archive'
		      AND archive.state='ready' AND archive.integrity_state='verified'
		      AND archive.published_at<=$2 AND manifest.state='immutable'
		      AND archive_node.role='storage' AND archive_node.connectivity_state='online'
		      AND archive_node.operational_state='active' AND archive_node.compatibility_state='compatible'
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM workflows workflow WHERE workflow.user_id=copy.user_id
		      AND workflow.state NOT IN ('succeeded','cancelled','failed')
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM replica_conflicts conflict WHERE conflict.user_id=copy.user_id
		      AND conflict.state NOT IN ('resolved','failed')
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM user_data_faults fault WHERE fault.user_id=copy.user_id AND fault.state<>'resolved'
		  )
		ON CONFLICT (node_id,snapshot_id,replica_kind) DO UPDATE SET
		  state=CASE WHEN replica_cleanup_tasks.state IN ('cancelled','failed') THEN 'pending'
		    ELSE replica_cleanup_tasks.state END,
		  next_attempt_at=CASE WHEN replica_cleanup_tasks.state IN ('cancelled','failed') THEN EXCLUDED.next_attempt_at
		    ELSE replica_cleanup_tasks.next_attempt_at END,
		  error_code=CASE WHEN replica_cleanup_tasks.state IN ('cancelled','failed') THEN NULL
		    ELSE replica_cleanup_tasks.error_code END,
		  updated_at=EXCLUDED.updated_at`, now, now.Add(-ReplicaCleanupStabilityWindow),
		now.Add(-ReplicaCleanupProjectionMaxAge))
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	archiveCount, _ := archiveResult.RowsAffected()
	hotCount, _ := hotResult.RowsAffected()
	return archiveCount + hotCount, nil
}

func (s *Store) ClaimReplicaCleanupTask(
	ctx context.Context,
	operationID, leaseOwner string,
	now time.Time,
	ttl time.Duration,
) (*ReplicaCleanupTask, error) {
	if operationID == "" || leaseOwner == "" || now.IsZero() || ttl <= 0 {
		return nil, ErrInvalidReplicaCleanup
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		UPDATE replica_cleanup_tasks SET state='retry_wait',operation_id=NULL,
		  controller_generation=NULL,lease_owner=NULL,lease_until=NULL,
		  error_code='lease_expired',next_attempt_at=$1,updated_at=$1
		WHERE state='running' AND lease_until<=$1`, now); err != nil {
		return nil, err
	}
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&generation); err != nil {
		return nil, err
	}
	var task ReplicaCleanupTask
	err = tx.QueryRowContext(ctx, `
		SELECT task.id::text,task.replica_id::text,task.user_id,task.legacy_user_id,
		  task.node_id,task.snapshot_id::text,task.handle,task.replica_kind,
		  task.reason_code,task.attempt
		FROM replica_cleanup_tasks task
		JOIN replica_copies copy ON copy.id=task.replica_id AND copy.user_id=task.user_id
		  AND copy.node_id=task.node_id AND copy.snapshot_id=task.snapshot_id
		  AND copy.replica_kind=task.replica_kind AND NOT copy.is_authoritative
		JOIN users legacy ON legacy.id=task.legacy_user_id AND legacy.home_node_id<>task.node_id
		JOIN nodes node ON node.id=task.node_id
		JOIN nodes home_node ON home_node.id=legacy.home_node_id
		WHERE task.state IN ('pending','retry_wait') AND task.next_attempt_at<=$1
		  AND node.connectivity_state='online' AND node.operational_state='active'
		  AND node.compatibility_state='compatible' AND node.control_mode='managed'
		  AND ((task.replica_kind='archive' AND copy.state IN ('stale','deleting') AND node.role='storage'
		      AND EXISTS (
		        SELECT 1 FROM replica_copies archive
		        JOIN snapshot_manifests manifest ON manifest.id=archive.snapshot_id
		        JOIN nodes archive_node ON archive_node.id=archive.node_id
		        WHERE archive.user_id=task.user_id AND archive.id<>copy.id
		          AND archive.replica_kind='archive' AND archive.state='ready'
		          AND archive.integrity_state='verified' AND manifest.state='immutable'
		          AND archive_node.role='storage' AND archive_node.connectivity_state='online'
		          AND archive_node.operational_state='active' AND archive_node.compatibility_state='compatible'
		      ))
		    OR (task.replica_kind='hot_standby' AND copy.state IN ('ready','deleting') AND node.role='compute'
		      AND home_node.role='compute' AND home_node.connectivity_state='online'
		      AND home_node.operational_state='active' AND home_node.compatibility_state='compatible'
		      AND EXISTS (
		        SELECT 1 FROM user_replicas home
		        WHERE home.user_id=legacy.id AND home.node_id=legacy.home_node_id
		          AND home.kind='home' AND home.state='ready'
		      )
		      AND EXISTS (
		        SELECT 1 FROM user_protection_states protection
		        WHERE protection.user_id=task.user_id AND protection.state='protected'
		          AND protection.changed_at<=$2 AND protection.evaluated_at>=$3
		      )
		      AND EXISTS (
		        SELECT 1 FROM replica_copies archive
		        JOIN snapshot_manifests manifest ON manifest.id=archive.snapshot_id
		        JOIN nodes archive_node ON archive_node.id=archive.node_id
		        WHERE archive.user_id=task.user_id AND archive.replica_kind='archive'
		          AND archive.state='ready' AND archive.integrity_state='verified'
		          AND archive.published_at<=$2 AND manifest.state='immutable'
		          AND archive_node.role='storage' AND archive_node.connectivity_state='online'
		          AND archive_node.operational_state='active' AND archive_node.compatibility_state='compatible'
		      )))
		  AND NOT EXISTS (
		    SELECT 1 FROM workflows workflow WHERE workflow.user_id=task.user_id
		      AND workflow.state NOT IN ('succeeded','cancelled','failed')
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM replica_conflicts conflict WHERE conflict.user_id=task.user_id
		      AND conflict.state NOT IN ('resolved','failed')
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM user_data_faults fault WHERE fault.user_id=task.user_id AND fault.state<>'resolved'
		  )
		ORDER BY task.next_attempt_at,task.created_at,task.id
		FOR UPDATE OF task SKIP LOCKED LIMIT 1`, now, now.Add(-ReplicaCleanupStabilityWindow),
		now.Add(-ReplicaCleanupProjectionMaxAge)).Scan(
		&task.ID, &task.ReplicaID, &task.GlobalUserID, &task.LegacyUserID,
		&task.NodeID, &task.SnapshotID, &task.Handle, &task.ReplicaKind,
		&task.ReasonCode, &task.Attempt,
	)
	if err == sql.ErrNoRows {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Serialize the destructive claim with snapshot/restore/takeover state
	// transitions.  The exact copy updates below then re-check the scope after
	// this lock is acquired, so a takeover that won the lock cannot be deleted
	// by a cleanup candidate selected from an older snapshot.
	if err := lockGlobalUser(ctx, tx, task.GlobalUserID); err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE replica_cleanup_tasks SET state='running',attempt=attempt+1,
		  operation_id=$2,controller_generation=$3,lease_owner=$4,lease_until=$5,
		  error_code=NULL,updated_at=$1 WHERE id=$6 AND state IN ('pending','retry_wait')`,
		now, operationID, generation, leaseOwner, now.Add(ttl), task.ID)
	if err != nil {
		return nil, err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return nil, err
		}
		return nil, ErrReplicaCleanupFence
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE replica_copies SET state='deleting',updated_at=$2
		WHERE id=$1 AND snapshot_id=$3 AND replica_kind=$4 AND NOT is_authoritative
		  AND state IN (CASE WHEN $4='archive' THEN 'stale' ELSE 'ready' END,'deleting')`,
		task.ReplicaID, now, task.SnapshotID, task.ReplicaKind)
	if err != nil {
		return nil, err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return nil, err
		}
		return nil, ErrReplicaCleanupFence
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE user_replicas SET state='deleting'
		WHERE user_id=$1 AND node_id=$2 AND kind=$3
		  AND state IN (CASE WHEN $3='archive' THEN 'stale' ELSE 'ready' END,'deleting')`,
		task.LegacyUserID, task.NodeID, task.ReplicaKind)
	if err != nil {
		return nil, err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return nil, err
		}
		return nil, ErrReplicaCleanupFence
	}
	task.Attempt++
	task.OperationID = operationID
	task.ControllerGeneration = generation
	task.LeaseOwner = leaseOwner
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *Store) CompleteReplicaCleanupTask(
	ctx context.Context,
	task ReplicaCleanupTask,
	agentOutcome string,
	now time.Time,
) error {
	if task.ID == "" || task.OperationID == "" || task.LeaseOwner == "" || task.SnapshotID == "" ||
		(agentOutcome != "deleted" && agentOutcome != "already_absent" && agentOutcome != "superseded") || now.IsZero() {
		return ErrInvalidReplicaCleanup
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&generation); err != nil {
		return err
	}
	if generation != task.ControllerGeneration {
		return ErrReplicaCleanupFence
	}
	var state string
	var operationID, leaseOwner sql.NullString
	var taskGeneration int64
	if err := tx.QueryRowContext(ctx, `
		SELECT state,operation_id::text,controller_generation,lease_owner
		FROM replica_cleanup_tasks WHERE id=$1 FOR UPDATE`, task.ID).Scan(
		&state, &operationID, &taskGeneration, &leaseOwner,
	); err != nil {
		return err
	}
	if state == "succeeded" && operationID.Valid && operationID.String == task.OperationID &&
		taskGeneration == task.ControllerGeneration {
		return tx.Commit()
	}
	if state != "running" || !operationID.Valid || operationID.String != task.OperationID ||
		taskGeneration != task.ControllerGeneration || !leaseOwner.Valid || leaseOwner.String != task.LeaseOwner {
		return ErrReplicaCleanupFence
	}
	result, err := tx.ExecContext(ctx, `
		DELETE FROM replica_copies WHERE id=$1 AND user_id=$2 AND node_id=$3
		  AND snapshot_id=$4 AND replica_kind=$5 AND state='deleting' AND NOT is_authoritative
		  AND NOT EXISTS (
		    SELECT 1 FROM global_users global_user
		    JOIN users legacy ON legacy.id=global_user.legacy_user_id
		    WHERE global_user.id=replica_copies.user_id AND legacy.home_node_id=replica_copies.node_id
		  )`,
		task.ReplicaID, task.GlobalUserID, task.NodeID, task.SnapshotID, task.ReplicaKind)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 1 {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM user_replicas replica USING users legacy
			WHERE replica.user_id=$1 AND replica.node_id=$2 AND replica.kind=$3 AND replica.state='deleting'
			  AND legacy.id=replica.user_id AND legacy.home_node_id<>replica.node_id`,
			task.LegacyUserID, task.NodeID, task.ReplicaKind); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE snapshot_manifests manifest SET state='deleted'
			WHERE manifest.id=$1 AND manifest.state='immutable'
			  AND NOT EXISTS (SELECT 1 FROM replica_copies copy WHERE copy.snapshot_id=manifest.id)
			  AND NOT EXISTS (
			    SELECT 1 FROM replica_conflict_sources source
			    JOIN replica_conflicts conflict ON conflict.id=source.conflict_id
			    WHERE source.snapshot_id=manifest.id AND conflict.state NOT IN ('resolved','failed')
			  )`, task.SnapshotID); err != nil {
			return err
		}
	}
	finalState := "succeeded"
	code := any(nil)
	if rows == 0 {
		finalState = "cancelled"
		code = "replica_scope_changed"
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE replica_cleanup_tasks SET state=$5,error_code=$6,agent_outcome=$7,
		  lease_owner=NULL,lease_until=NULL,updated_at=$8,finished_at=$8
		WHERE id=$1 AND operation_id=$2 AND controller_generation=$3 AND lease_owner=$4
		  AND state='running'`, task.ID, task.OperationID, task.ControllerGeneration,
		task.LeaseOwner, finalState, code, agentOutcome, now)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return err
		}
		return ErrReplicaCleanupFence
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  occurred_at,actor_type,action,target_type,target_id,operation_id,
		  controller_generation,outcome,detail
		) VALUES ($1,'controller','delete-snapshot-replica','global_user',$2::text,$3,$4,$5,
		  jsonb_build_object('cleanup_id',$6::text,'node_id',$7::bigint,'snapshot_id',$8::text,
		    'replica_kind',$9::text,'reason_code',$10::text,'agent_outcome',$11::text))`,
		now, task.GlobalUserID, task.OperationID, task.ControllerGeneration, finalState,
		task.ID, task.NodeID, task.SnapshotID, task.ReplicaKind, task.ReasonCode, agentOutcome); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RetryReplicaCleanupTask(
	ctx context.Context,
	task ReplicaCleanupTask,
	errorCode string,
	now time.Time,
	delay time.Duration,
) error {
	if task.ID == "" || task.OperationID == "" || task.LeaseOwner == "" || errorCode == "" || now.IsZero() || delay <= 0 {
		return ErrInvalidReplicaCleanup
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE replica_cleanup_tasks SET state='retry_wait',next_attempt_at=$5,
		  error_code=$6,lease_owner=NULL,lease_until=NULL,updated_at=$4
		WHERE id=$1 AND operation_id=$2 AND controller_generation=$3 AND lease_owner=$7
		  AND state='running'`, task.ID, task.OperationID, task.ControllerGeneration,
		now, now.Add(delay), errorCode, task.LeaseOwner)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: retry", ErrReplicaCleanupFence)
	}
	return tx.Commit()
}
