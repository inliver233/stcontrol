package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidIndependentReconciliation = errors.New("invalid independent reconciliation input")
	ErrIndependentReconciliationState   = errors.New("independent reconciliation state conflict")
)

// recordIndependentSyncFactsTx persists every immutable adapter marker. A fact
// disappearing from a later heartbeat is intentionally not interpreted as a
// successful synchronization; only CompleteIndependentReconciliation may do
// that after an immutable snapshot or an explicit conflict resolution.
func recordIndependentSyncFactsTx(
	ctx context.Context,
	tx *sql.Tx,
	nodeID, controllerGeneration int64,
	facts []IndependentSyncFact,
	now time.Time,
) error {
	if len(facts) == 0 {
		return nil
	}
	for _, fact := range facts {
		if _, err := tx.ExecContext(ctx, `
			UPDATE independent_user_reconciliations
			SET state='superseded',error_code='marker_changed',next_attempt_at=NULL,
			  updated_at=$4
			WHERE node_id=$1 AND local_handle=$2 AND marker<>$3::uuid
			  AND state NOT IN ('succeeded','superseded','failed')`,
			nodeID, fact.Handle, fact.Marker, now); err != nil {
			return fmt.Errorf("supersede changed independent marker: %w", err)
		}
		// A marker change during a snapshot invalidates that snapshot boundary.
		// Revoke its workflow before another fact can be scheduled.
		if _, err := tx.ExecContext(ctx, `
			UPDATE workflows workflow
			SET state='cancelled',error_code='independent_marker_changed',
			  error_summary='independent synchronization marker changed',
			  cleanup_state='pending',updated_at=$3,finished_at=$3
			FROM independent_user_reconciliations reconciliation
			WHERE reconciliation.workflow_id=workflow.id
			  AND reconciliation.node_id=$1 AND reconciliation.local_handle=$2
			  AND reconciliation.state='superseded'
			  AND workflow.state NOT IN ('succeeded','cancelled','failed')`,
			nodeID, fact.Handle, now); err != nil {
			return fmt.Errorf("cancel superseded independent snapshot: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE snapshot_transfer_capabilities capability SET state='revoked'
			FROM independent_user_reconciliations reconciliation
			WHERE reconciliation.workflow_id=capability.workflow_id
			  AND reconciliation.node_id=$1 AND reconciliation.local_handle=$2
			  AND reconciliation.state='superseded' AND capability.state='prepared'`,
			nodeID, fact.Handle); err != nil {
			return fmt.Errorf("revoke superseded independent transfer: %w", err)
		}

		var userID sql.NullInt64
		var legacyUserID sql.NullInt64
		var homeNodeID sql.NullInt64
		err := tx.QueryRowContext(ctx, `
			SELECT account.user_id,global_user.legacy_user_id,legacy.home_node_id
			FROM node_accounts account
			JOIN global_users global_user ON global_user.id=account.user_id
			LEFT JOIN users legacy ON legacy.id=global_user.legacy_user_id
			WHERE account.node_id=$1 AND account.local_handle=$2`, nodeID, fact.Handle).
			Scan(&userID, &legacyUserID, &homeNodeID)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("map independent synchronization user: %w", err)
		}
		state := "unmapped"
		if err == nil && userID.Valid {
			state = "pending"
			if !homeNodeID.Valid || homeNodeID.Int64 != nodeID {
				state = "conflict"
			}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO independent_user_reconciliations (
			  id,operation_id,node_id,user_id,local_handle,marker,changed_at,
			  reason_code,state,controller_generation,first_observed_at,
			  last_observed_at,updated_at
			) VALUES (gen_random_uuid(),gen_random_uuid(),$1,$2,$3,$4::uuid,$5,$6,$7,$8,$9,$9,$9)
			ON CONFLICT (node_id,local_handle,marker) DO UPDATE SET
			  user_id=COALESCE(independent_user_reconciliations.user_id,EXCLUDED.user_id),
			  state=CASE
			    WHEN independent_user_reconciliations.state='unmapped' AND EXCLUDED.user_id IS NOT NULL
			      THEN EXCLUDED.state
			    ELSE independent_user_reconciliations.state END,
			  last_observed_at=EXCLUDED.last_observed_at,updated_at=EXCLUDED.updated_at`,
			nodeID, nullableInt64Value(userID), fact.Handle, fact.Marker, fact.ChangedAt,
			fact.Reason, state, controllerGeneration, now); err != nil {
			return fmt.Errorf("record independent synchronization fact: %w", err)
		}
		if !userID.Valid {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO alerts (
				  id,deduplication_key,severity,state,category,node_id,summary,
				  first_seen_at,last_seen_at,notify_after,occurrence_count
				) VALUES (gen_random_uuid(),'independent-unmapped:'||$1::text||':'||$2,
				  'critical','open','independent_reconciliation',$1,
				  '独立模式用户无法映射到全局账户，已冻结自动回归',$3,$3,$3,1)
				ON CONFLICT (deduplication_key) DO UPDATE SET
				  state='open',last_seen_at=EXCLUDED.last_seen_at,resolved_at=NULL,
				  occurrence_count=alerts.occurrence_count+1`, nodeID, fact.Handle, now); err != nil {
				return fmt.Errorf("alert unmapped independent user: %w", err)
			}
		} else {
			if _, err := tx.ExecContext(ctx, `
				UPDATE alerts SET state='resolved',resolved_at=$3,last_seen_at=$3
				WHERE deduplication_key='independent-unmapped:'||$1::text||':'||$2
				  AND state<>'resolved'`, nodeID, fact.Handle, now); err != nil {
				return fmt.Errorf("resolve independent user mapping alert: %w", err)
			}
		}
	}

	// Any user independently changed on more than one node, or on a node that
	// is no longer its home, becomes a normal frozen replica conflict. The
	// existing evidence and explicit-resolution workflow then owns recovery.
	if _, err := tx.ExecContext(ctx, `
		WITH collided AS (
		  SELECT user_id FROM independent_user_reconciliations
		  WHERE user_id IS NOT NULL
		    AND state NOT IN ('succeeded','superseded','failed')
		  GROUP BY user_id HAVING count(DISTINCT node_id)>1
		)
		UPDATE independent_user_reconciliations reconciliation SET
		  state='conflict',error_code='multiple_independent_writers',updated_at=$1
		FROM collided WHERE reconciliation.user_id=collided.user_id
		  AND reconciliation.state NOT IN ('succeeded','superseded','failed')`, now); err != nil {
		return fmt.Errorf("freeze multiple independent writers: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflows workflow
		SET state='cancelled',error_code='multiple_independent_writers',
		  error_summary='multiple nodes reported independent writes',
		  cleanup_state='pending',updated_at=$1,finished_at=$1
		FROM independent_user_reconciliations reconciliation
		WHERE reconciliation.workflow_id=workflow.id AND reconciliation.state='conflict'
		  AND workflow.state NOT IN ('succeeded','cancelled','failed')`, now); err != nil {
		return fmt.Errorf("cancel conflicted independent snapshots: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE snapshot_transfer_capabilities capability SET state='revoked'
		FROM independent_user_reconciliations reconciliation
		WHERE reconciliation.workflow_id=capability.workflow_id
		  AND reconciliation.state='conflict' AND capability.state='prepared'`); err != nil {
		return fmt.Errorf("revoke conflicted independent transfers: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		WITH conflicted AS (
		  SELECT DISTINCT user_id FROM independent_user_reconciliations
		  WHERE user_id IS NOT NULL AND state='conflict'
		)
		UPDATE replica_copies copy SET state='conflict',is_authoritative=false,updated_at=$1
		FROM conflicted WHERE copy.user_id=conflicted.user_id`, now); err != nil {
		return fmt.Errorf("mark normalized replicas conflicted: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		WITH conflicted AS (
		  SELECT DISTINCT global_user.legacy_user_id AS user_id
		  FROM independent_user_reconciliations reconciliation
		  JOIN global_users global_user ON global_user.id=reconciliation.user_id
		  WHERE reconciliation.state='conflict' AND global_user.legacy_user_id IS NOT NULL
		)
		UPDATE user_replicas replica SET state='conflict'
		FROM conflicted WHERE replica.user_id=conflicted.user_id`); err != nil {
		return fmt.Errorf("mark legacy replicas conflicted: %w", err)
	}
	return nil
}

func nullableInt64Value(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}

type IndependentReconciliationWork struct {
	ID            string
	State         string
	Action        string
	Attempt       int
	NodeID        int64
	GlobalUserID  int64
	LegacyUserID  int64
	Handle        string
	Marker        string
	WorkflowID    sql.NullString
	WorkflowState sql.NullString
}

func (s *Store) ListIndependentReconciliationWork(
	ctx context.Context,
	limit int,
	now time.Time,
) ([]IndependentReconciliationWork, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT reconciliation.id::text,reconciliation.state,reconciliation.attempt,
		  reconciliation.node_id,reconciliation.user_id,global_user.legacy_user_id,
		  reconciliation.local_handle,reconciliation.marker::text,
		  reconciliation.workflow_id::text,workflow.state,
		  CASE
		    WHEN reconciliation.state IN ('pending','retry_wait') THEN 'snapshot'
		    WHEN reconciliation.state='snapshotting' AND workflow.state IN ('failed','cancelled') THEN 'restart'
		    WHEN reconciliation.state='snapshotting' AND workflow.state='succeeded' THEN 'complete'
		    WHEN reconciliation.state='snapshotting' THEN 'execute'
		    ELSE 'complete'
		  END AS action
		FROM independent_user_reconciliations reconciliation
		JOIN global_users global_user ON global_user.id=reconciliation.user_id
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		JOIN nodes node ON node.id=reconciliation.node_id
		LEFT JOIN workflows workflow ON workflow.id=reconciliation.workflow_id
		WHERE reconciliation.state IN (
		    'pending','snapshotting','completing','completion_retry','conflict','retry_wait'
		  )
		  AND (reconciliation.next_attempt_at IS NULL OR reconciliation.next_attempt_at<=$2)
		  AND node.control_mode='independent-draining'
		  AND node.active_independent_sessions=0
		  AND NOT EXISTS (
		    SELECT 1 FROM replica_conflicts open_conflict
		    WHERE open_conflict.user_id=reconciliation.user_id
		      AND open_conflict.state NOT IN ('resolved','failed')
		  )
		  AND (
		    reconciliation.state<>'conflict'
		    OR (
		      global_user.status='active'
		      AND EXISTS (
		        SELECT 1 FROM replica_conflicts resolved_conflict
		        WHERE resolved_conflict.user_id=reconciliation.user_id
		          AND resolved_conflict.state='resolved'
		          AND resolved_conflict.resolved_at>=reconciliation.first_observed_at
		      )
		      AND NOT EXISTS (
		        SELECT 1 FROM replica_conflicts conflict
		        WHERE conflict.user_id=reconciliation.user_id
		          AND conflict.state NOT IN ('resolved','failed')
		      )
		    )
		  )
		ORDER BY reconciliation.updated_at,reconciliation.id LIMIT $1`, limit, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var work []IndependentReconciliationWork
	for rows.Next() {
		var item IndependentReconciliationWork
		if err := rows.Scan(
			&item.ID, &item.State, &item.Attempt, &item.NodeID, &item.GlobalUserID,
			&item.LegacyUserID, &item.Handle, &item.Marker, &item.WorkflowID,
			&item.WorkflowState, &item.Action,
		); err != nil {
			return nil, err
		}
		work = append(work, item)
	}
	return work, rows.Err()
}

func (s *Store) BeginIndependentReconciliationCompletion(
	ctx context.Context,
	id, marker string,
	now time.Time,
) error {
	if id == "" || marker == "" {
		return ErrInvalidIndependentReconciliation
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE independent_user_reconciliations reconciliation
		SET state='completing',next_attempt_at=$3 + interval '2 minutes',error_code=NULL,updated_at=$3
		FROM nodes node
		WHERE reconciliation.id=$1::uuid AND reconciliation.marker=$2::uuid
		  AND node.id=reconciliation.node_id
		  AND node.control_mode='independent-draining'
		  AND node.active_independent_sessions=0
		  AND (
		    reconciliation.state NOT IN ('pending','retry_wait')
		    OR NOT EXISTS (
		      SELECT 1 FROM user_activity_leases lease
		      WHERE lease.user_id=reconciliation.user_id
		        AND (lease.writer_node_id<>reconciliation.node_id
		          OR lease.in_flight_reads<>0 OR lease.in_flight_writes<>0
		          OR lease.state='quiescing'
		          OR (lease.lease_expires_at>$2 AND lease.state<>'independent'))
		    )
		  )
		  AND (
		    (reconciliation.state IN ('snapshotting','completing','completion_retry')
		      AND EXISTS (
		        SELECT 1 FROM workflows workflow WHERE workflow.id=reconciliation.workflow_id
		          AND workflow.state='succeeded'
		      ))
		    OR (reconciliation.state IN ('conflict','completing','completion_retry')
		      AND EXISTS (
		        SELECT 1 FROM replica_conflicts resolved_conflict
		        WHERE resolved_conflict.user_id=reconciliation.user_id
		          AND resolved_conflict.state='resolved'
		          AND resolved_conflict.resolved_at>=reconciliation.first_observed_at
		      )
		      AND NOT EXISTS (
		        SELECT 1 FROM replica_conflicts conflict
		        WHERE conflict.user_id=reconciliation.user_id
		          AND conflict.state NOT IN ('resolved','failed')
		      ))
		  )`, id, marker, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrIndependentReconciliationState
	}
	return nil
}

func (s *Store) CompleteIndependentReconciliation(
	ctx context.Context,
	id, marker string,
	now time.Time,
) error {
	if id == "" || marker == "" {
		return ErrInvalidIndependentReconciliation
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE independent_user_reconciliations
		SET state='succeeded',error_code=NULL,next_attempt_at=NULL,
		  updated_at=$3,completed_at=$3
		WHERE id=$1::uuid AND marker=$2::uuid AND state='completing'`, id, marker, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrIndependentReconciliationState
	}
	return nil
}

func (s *Store) RetryIndependentReconciliationCompletion(
	ctx context.Context,
	id, marker, errorCode string,
	now time.Time,
	delay time.Duration,
) error {
	if id == "" || marker == "" || errorCode == "" || delay <= 0 {
		return ErrInvalidIndependentReconciliation
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE independent_user_reconciliations
		SET state=CASE WHEN attempt>=9 THEN 'failed' ELSE 'completion_retry' END,
		  attempt=attempt+1,error_code=$3,
		  next_attempt_at=CASE WHEN attempt>=9 THEN NULL ELSE $4 END,updated_at=$5
		WHERE id=$1::uuid AND marker=$2::uuid AND state='completing'`,
		id, marker, errorCode, now.Add(delay), now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrIndependentReconciliationState
	}
	return nil
}

func (s *Store) RestartIndependentReconciliationSnapshot(
	ctx context.Context,
	id, marker, errorCode string,
	now time.Time,
	delay time.Duration,
) error {
	if id == "" || marker == "" || errorCode == "" || delay <= 0 {
		return ErrInvalidIndependentReconciliation
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE independent_user_reconciliations reconciliation
		SET state=CASE WHEN reconciliation.attempt>=4 THEN 'failed' ELSE 'retry_wait' END,
		  workflow_id=NULL,attempt=reconciliation.attempt+1,error_code=$3,
		  next_attempt_at=CASE WHEN reconciliation.attempt>=4 THEN NULL ELSE $4 END,updated_at=$5
		FROM workflows workflow
		WHERE reconciliation.id=$1::uuid AND reconciliation.marker=$2::uuid
		  AND reconciliation.state='snapshotting' AND workflow.id=reconciliation.workflow_id
		  AND workflow.state IN ('failed','cancelled')`, id, marker, errorCode, now.Add(delay), now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrIndependentReconciliationState
	}
	return nil
}
