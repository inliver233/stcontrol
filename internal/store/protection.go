package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidReplicaTakeover     = errors.New("invalid replica takeover input")
	ErrReplicaTakeoverConflict    = errors.New("replica takeover conflicts with existing facts")
	ErrReplicaTakeoverUnavailable = errors.New("replica takeover is unavailable")
	ErrReplicaTakeoverLeaseActive = errors.New("source writer lease is still active")
)

type ProtectionReconcileResult struct {
	Evaluated int64
	Alerted   int64
	Resolved  int64
}

type UserProtectionState struct {
	UserID                   int64
	State                    string
	ReasonCode               string
	AuthoritativeNodeID      sql.NullInt64
	AuthoritativeNodeName    sql.NullString
	RecoveryNodeID           sql.NullInt64
	RecoveryNodeName         sql.NullString
	LatestRecoverySnapshotID sql.NullString
	LatestRecoveryAt         sql.NullTime
	ActiveWriterNodeID       sql.NullInt64
	ActiveWriterNodeName     sql.NullString
	Version                  int64
	ChangedAt                time.Time
	EvaluatedAt              time.Time
}

type ProtectionAlert struct {
	Severity    string    `json:"severity"`
	State       string    `json:"state"`
	Category    string    `json:"category"`
	UserUUID    string    `json:"user_uuid"`
	Username    string    `json:"username"`
	NodeName    string    `json:"node_name,omitempty"`
	Summary     string    `json:"summary"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

type StorageRepairCandidate struct {
	LegacyUserID int64
	GlobalUserID int64
	HomeNodeID   int64
}

type ConfirmReplicaTakeoverParams struct {
	OperationID        string
	RequestDigest      []byte
	GlobalUserID       int64
	TargetNodeID       int64
	ExpectedRecoveryAt time.Time
	Now                time.Time
}

type ReplicaTakeoverResult struct {
	SourceNodeID         int64
	TargetNodeID         int64
	SnapshotID           string
	SnapshotPublishedAt  time.Time
	ControllerGeneration int64
	Replayed             bool
}

// ReconcileProtectionStates projects live node/replica facts into a durable,
// user-scoped protection state and maintains delayed, deduplicated alerts.
func (s *Store) ReconcileProtectionStates(
	ctx context.Context,
	now time.Time,
	unprotectedGrace time.Duration,
) (ProtectionReconcileResult, error) {
	if unprotectedGrace <= 0 {
		return ProtectionReconcileResult{}, fmt.Errorf("invalid unprotected alert grace")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ProtectionReconcileResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	projection, err := tx.ExecContext(ctx, `
		WITH facts AS (
		  SELECT global_user.id AS user_id, legacy.home_node_id AS authoritative_node_id,
		    (authoritative.id IS NOT NULL AND authoritative.role='compute'
		      AND authoritative.connectivity_state='online'
		      AND authoritative.operational_state='active'
		      AND authoritative.compatibility_state='compatible'
		      AND EXISTS (
		        SELECT 1 FROM user_replicas home_replica
		        WHERE home_replica.user_id=legacy.id AND home_replica.node_id=legacy.home_node_id
		          AND home_replica.kind='home' AND home_replica.state='ready'
		      ) AND NOT EXISTS (
		        SELECT 1 FROM replica_copies authoritative_copy
		        WHERE authoritative_copy.user_id=global_user.id
		          AND authoritative_copy.node_id=legacy.home_node_id
		          AND NOT (authoritative_copy.replica_kind='active'
		            AND authoritative_copy.state='ready' AND authoritative_copy.is_authoritative)
		      )) AS authoritative_ready,
		    -- Conflict is intentionally latched. Only the explicit conflict-resolution
		    -- workflow may choose a source and unfreeze the account.
		    (COALESCE(previous.state='conflict',false) OR EXISTS (
		      SELECT 1 FROM user_replicas conflicting_legacy
		      WHERE conflicting_legacy.user_id=legacy.id AND conflicting_legacy.state='conflict'
		    ) OR EXISTS (
		      SELECT 1 FROM replica_copies conflicting_copy
		      WHERE conflicting_copy.user_id=global_user.id AND conflicting_copy.state='conflict'
		    )) AS has_conflict,
		    (EXISTS (
		      SELECT 1 FROM user_replicas corrupt_legacy
		      WHERE corrupt_legacy.user_id=legacy.id AND corrupt_legacy.node_id=legacy.home_node_id
		        AND corrupt_legacy.state='corrupt'
		    ) OR EXISTS (
		      SELECT 1 FROM replica_copies corrupt_copy
		      WHERE corrupt_copy.user_id=global_user.id AND corrupt_copy.node_id=legacy.home_node_id
		        AND corrupt_copy.state='corrupt'
		    )) AS authoritative_corrupt,
		    hot.node_id AS hot_node_id,hot.snapshot_id AS hot_snapshot_id,
		    hot.published_at AS hot_published_at,
		    archive.node_id AS archive_node_id,archive.snapshot_id AS archive_snapshot_id,
		    archive.published_at AS archive_published_at
		  FROM global_users global_user
		  JOIN users legacy ON legacy.id=global_user.legacy_user_id
		  LEFT JOIN user_protection_states previous ON previous.user_id=global_user.id
		  LEFT JOIN nodes authoritative ON authoritative.id=legacy.home_node_id
		  LEFT JOIN LATERAL (
		    SELECT replica.node_id,copy.snapshot_id,copy.published_at
		    FROM user_replicas replica
		    JOIN nodes node ON node.id=replica.node_id AND node.role='compute'
		      AND node.connectivity_state='online' AND node.operational_state='active'
		      AND node.compatibility_state='compatible'
		    JOIN replica_copies copy ON copy.user_id=global_user.id AND copy.node_id=replica.node_id
		      AND copy.replica_kind='hot_standby' AND copy.state='ready'
		      AND copy.compatibility_state='compatible'
		      AND copy.snapshot_id IS NOT NULL AND copy.published_at IS NOT NULL
		    JOIN node_accounts account ON account.user_id=global_user.id
		      AND account.node_id=replica.node_id AND account.status='active'
		    JOIN snapshot_manifests snapshot ON snapshot.id=copy.snapshot_id
		      AND snapshot.user_id=global_user.id AND snapshot.state='immutable'
		    WHERE replica.user_id=legacy.id AND replica.kind='hot_standby' AND replica.state='ready'
		      AND replica.last_sync_at IS NOT NULL
		    ORDER BY copy.published_at DESC,replica.node_id LIMIT 1
		  ) hot ON true
		  LEFT JOIN LATERAL (
		    SELECT replica.node_id,copy.snapshot_id,copy.published_at
		    FROM user_replicas replica
		    JOIN nodes node ON node.id=replica.node_id AND node.role='storage'
		      AND node.connectivity_state='online' AND node.operational_state='active'
		      AND node.compatibility_state='compatible'
		    JOIN replica_copies copy ON copy.user_id=global_user.id AND copy.node_id=replica.node_id
		      AND copy.replica_kind='archive' AND copy.state='ready'
		      AND copy.compatibility_state='compatible'
		      AND copy.snapshot_id IS NOT NULL AND copy.published_at IS NOT NULL
		    JOIN snapshot_manifests snapshot ON snapshot.id=copy.snapshot_id
		      AND snapshot.user_id=global_user.id AND snapshot.state='immutable'
		    WHERE replica.user_id=legacy.id AND replica.kind='archive' AND replica.state='ready'
		      AND replica.last_sync_at IS NOT NULL
		    ORDER BY copy.published_at DESC,replica.node_id LIMIT 1
		  ) archive ON true
		  WHERE global_user.status<>'deleted'
		), desired AS (
		  SELECT user_id,authoritative_node_id,
		    CASE
		      WHEN has_conflict THEN 'conflict'
		      WHEN authoritative_corrupt AND hot_node_id IS NOT NULL THEN 'takeover_available'
		      WHEN authoritative_corrupt AND archive_node_id IS NOT NULL THEN 'restore_required'
		      WHEN authoritative_corrupt THEN 'unavailable'
		      WHEN authoritative_ready AND archive_node_id IS NOT NULL THEN 'protected'
		      WHEN authoritative_ready AND hot_node_id IS NOT NULL THEN 'temporary'
		      WHEN authoritative_ready THEN 'unprotected'
		      WHEN hot_node_id IS NOT NULL THEN 'takeover_available'
		      WHEN archive_node_id IS NOT NULL THEN 'restore_required'
		      ELSE 'unavailable'
		    END AS state,
		    CASE
		      WHEN has_conflict THEN 'replica_conflict'
		      WHEN authoritative_corrupt THEN 'authoritative_corrupt'
		      WHEN authoritative_ready AND archive_node_id IS NOT NULL THEN 'healthy_archive'
		      WHEN authoritative_ready AND hot_node_id IS NOT NULL THEN 'temporary_compute_replica'
		      WHEN authoritative_ready THEN 'no_recovery_replica'
		      WHEN hot_node_id IS NOT NULL THEN 'hot_standby_ready'
		      WHEN archive_node_id IS NOT NULL THEN 'archive_restore_required'
		      ELSE 'no_recovery_replica'
		    END AS reason_code,
		    CASE WHEN has_conflict THEN NULL
		      WHEN (authoritative_corrupt OR NOT authoritative_ready) AND hot_node_id IS NOT NULL THEN hot_node_id
		      WHEN archive_node_id IS NOT NULL THEN archive_node_id ELSE hot_node_id END AS recovery_node_id,
		    CASE WHEN has_conflict THEN NULL
		      WHEN (authoritative_corrupt OR NOT authoritative_ready) AND hot_node_id IS NOT NULL THEN hot_snapshot_id
		      WHEN archive_node_id IS NOT NULL THEN archive_snapshot_id ELSE hot_snapshot_id END AS snapshot_id,
		    CASE WHEN has_conflict THEN NULL
		      WHEN (authoritative_corrupt OR NOT authoritative_ready) AND hot_node_id IS NOT NULL THEN hot_published_at
		      WHEN archive_node_id IS NOT NULL THEN archive_published_at ELSE hot_published_at END AS recovery_at
		  FROM facts
		)
		INSERT INTO user_protection_states (
		  user_id,state,reason_code,authoritative_node_id,recovery_node_id,
		  latest_recovery_snapshot_id,latest_recovery_at,version,changed_at,evaluated_at
		)
		SELECT user_id,state,reason_code,authoritative_node_id,recovery_node_id,
		  snapshot_id,recovery_at,1,$1,$1 FROM desired
		ON CONFLICT (user_id) DO UPDATE SET
		  state=EXCLUDED.state,reason_code=EXCLUDED.reason_code,
		  authoritative_node_id=EXCLUDED.authoritative_node_id,
		  recovery_node_id=EXCLUDED.recovery_node_id,
		  latest_recovery_snapshot_id=EXCLUDED.latest_recovery_snapshot_id,
		  latest_recovery_at=EXCLUDED.latest_recovery_at,
		  version=CASE WHEN user_protection_states.state IS DISTINCT FROM EXCLUDED.state
		      OR user_protection_states.reason_code IS DISTINCT FROM EXCLUDED.reason_code
		      OR user_protection_states.authoritative_node_id IS DISTINCT FROM EXCLUDED.authoritative_node_id
		      OR user_protection_states.recovery_node_id IS DISTINCT FROM EXCLUDED.recovery_node_id
		      OR user_protection_states.latest_recovery_snapshot_id IS DISTINCT FROM EXCLUDED.latest_recovery_snapshot_id
		      OR user_protection_states.latest_recovery_at IS DISTINCT FROM EXCLUDED.latest_recovery_at
		    THEN user_protection_states.version+1 ELSE user_protection_states.version END,
		  changed_at=CASE WHEN user_protection_states.state IS DISTINCT FROM EXCLUDED.state
		      OR user_protection_states.reason_code IS DISTINCT FROM EXCLUDED.reason_code
		      OR user_protection_states.authoritative_node_id IS DISTINCT FROM EXCLUDED.authoritative_node_id
		      OR user_protection_states.recovery_node_id IS DISTINCT FROM EXCLUDED.recovery_node_id
		      OR user_protection_states.latest_recovery_snapshot_id IS DISTINCT FROM EXCLUDED.latest_recovery_snapshot_id
		      OR user_protection_states.latest_recovery_at IS DISTINCT FROM EXCLUDED.latest_recovery_at
		    THEN EXCLUDED.changed_at ELSE user_protection_states.changed_at END,
		  evaluated_at=EXCLUDED.evaluated_at`, now)
	if err != nil {
		return ProtectionReconcileResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		WITH conflicted AS (
		  SELECT protection.user_id,global_user.legacy_user_id
		  FROM user_protection_states protection
		  JOIN global_users global_user ON global_user.id=protection.user_id
		  WHERE protection.state='conflict'
		), global_update AS (
		  UPDATE global_users global_user SET status='conflict',updated_at=$1
		  FROM conflicted WHERE global_user.id=conflicted.user_id AND global_user.status<>'conflict'
		  RETURNING global_user.id
		), legacy_update AS (
		  UPDATE users legacy SET status='conflict'
		  FROM conflicted WHERE legacy.id=conflicted.legacy_user_id AND legacy.status<>'conflict'
		  RETURNING legacy.id
		), ticket_update AS (
		  UPDATE control_tickets ticket SET revoked_at=COALESCE(ticket.revoked_at,$1)
		  FROM conflicted WHERE ticket.user_id=conflicted.user_id
		    AND ticket.consumed_at IS NULL AND ticket.revoked_at IS NULL
		  RETURNING ticket.jti
		), session_update AS (
		  UPDATE controller_sessions session SET revoked_at=COALESCE(session.revoked_at,$1)
		  FROM conflicted WHERE session.user_id=conflicted.user_id AND session.revoked_at IS NULL
		  RETURNING session.id
		)
		UPDATE user_activity_leases lease
		SET state='conflict',lease_expires_at=$1,updated_at=$1
		FROM conflicted WHERE lease.user_id=conflicted.user_id AND lease.state<>'conflict'`, now); err != nil {
		return ProtectionReconcileResult{}, err
	}
	alerted, err := tx.ExecContext(ctx, `
		INSERT INTO alerts (
		  id,deduplication_key,severity,state,category,user_id,node_id,summary,
		  first_seen_at,last_seen_at,notify_after,occurrence_count
		)
		SELECT gen_random_uuid(),'user-protection:'||protection.user_id::text,
		  CASE WHEN protection.state IN ('conflict','unavailable') THEN 'critical' ELSE 'warning' END,
		  'open','user_protection',protection.user_id,protection.authoritative_node_id,
		  CASE protection.state
		    WHEN 'temporary' THEN '用户仅有临时计算保护副本'
		    WHEN 'unprotected' THEN '用户当前没有可恢复副本'
		    WHEN 'takeover_available' THEN '家节点不可用，存在可确认接管的热备'
		    WHEN 'restore_required' THEN '家节点不可用，需要从存储副本恢复'
		    WHEN 'conflict' THEN '用户副本存在冲突，必须冻结并人工处理'
		    ELSE '用户家节点不可用且没有合格恢复副本' END,
		  $1,$1,CASE WHEN protection.state IN ('temporary','unprotected') THEN $2 ELSE $1 END,1
		FROM user_protection_states protection WHERE protection.state<>'protected'
		ON CONFLICT (deduplication_key) DO UPDATE SET
		  severity=EXCLUDED.severity,
		  state=CASE WHEN alerts.state='resolved' THEN 'open' ELSE alerts.state END,
		  node_id=EXCLUDED.node_id,summary=EXCLUDED.summary,last_seen_at=EXCLUDED.last_seen_at,
		  notify_after=CASE
		    WHEN EXCLUDED.notify_after<=EXCLUDED.last_seen_at THEN EXCLUDED.notify_after
		    WHEN alerts.state='resolved' THEN EXCLUDED.notify_after ELSE alerts.notify_after END,
		  resolved_at=NULL,
		  occurrence_count=alerts.occurrence_count+CASE WHEN alerts.state='resolved' THEN 1 ELSE 0 END`,
		now, now.Add(unprotectedGrace))
	if err != nil {
		return ProtectionReconcileResult{}, err
	}
	resolved, err := tx.ExecContext(ctx, `
		UPDATE alerts alert SET state='resolved',resolved_at=$1,last_seen_at=$1
		FROM user_protection_states protection
		WHERE alert.category='user_protection' AND alert.user_id=protection.user_id
		  AND alert.state<>'resolved' AND protection.state='protected'`, now)
	if err != nil {
		return ProtectionReconcileResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return ProtectionReconcileResult{}, err
	}
	evaluatedCount, _ := projection.RowsAffected()
	alertedCount, _ := alerted.RowsAffected()
	resolvedCount, _ := resolved.RowsAffected()
	return ProtectionReconcileResult{Evaluated: evaluatedCount, Alerted: alertedCount, Resolved: resolvedCount}, nil
}

func (s *Store) GetUserProtectionState(ctx context.Context, globalUserID int64) (*UserProtectionState, error) {
	if globalUserID <= 0 {
		return nil, fmt.Errorf("invalid global user")
	}
	var state UserProtectionState
	err := s.DB.QueryRowContext(ctx, `
		SELECT protection.user_id,protection.state,protection.reason_code,
		  protection.authoritative_node_id,authoritative.name,
		  protection.recovery_node_id,recovery.name,
		  protection.latest_recovery_snapshot_id::text,protection.latest_recovery_at,
		  active_lease.writer_node_id,active_writer.name,
		  protection.version,protection.changed_at,protection.evaluated_at
		FROM user_protection_states protection
		LEFT JOIN nodes authoritative ON authoritative.id=protection.authoritative_node_id
		LEFT JOIN nodes recovery ON recovery.id=protection.recovery_node_id
		LEFT JOIN controller_epochs active_controller ON active_controller.state='active'
		LEFT JOIN user_activity_leases active_lease ON active_lease.user_id=protection.user_id
		  AND active_lease.controller_generation=active_controller.generation
		  AND active_lease.state IN ('active','quiescing','drained','independent')
		  AND active_lease.lease_expires_at>now()
		LEFT JOIN nodes active_writer ON active_writer.id=active_lease.writer_node_id
		WHERE protection.user_id=$1`, globalUserID).Scan(
		&state.UserID, &state.State, &state.ReasonCode,
		&state.AuthoritativeNodeID, &state.AuthoritativeNodeName,
		&state.RecoveryNodeID, &state.RecoveryNodeName,
		&state.LatestRecoverySnapshotID, &state.LatestRecoveryAt,
		&state.ActiveWriterNodeID, &state.ActiveWriterNodeName,
		&state.Version, &state.ChangedAt, &state.EvaluatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &state, err
}

func (s *Store) ListVisibleProtectionAlerts(ctx context.Context, limit int, now time.Time) ([]ProtectionAlert, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT alert.severity,alert.state,alert.category,global_user.uuid::text,
		  legacy.username,COALESCE(node.name,''),alert.summary,alert.first_seen_at,alert.last_seen_at
		FROM alerts alert
		JOIN global_users global_user ON global_user.id=alert.user_id
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		LEFT JOIN nodes node ON node.id=alert.node_id
		WHERE alert.category='user_protection' AND alert.state IN ('open','acknowledged')
		  AND (alert.notify_after IS NULL OR alert.notify_after<=$2)
		ORDER BY CASE alert.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
		  alert.last_seen_at DESC LIMIT $1`, limit, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var alerts []ProtectionAlert
	for rows.Next() {
		var alert ProtectionAlert
		if err := rows.Scan(
			&alert.Severity, &alert.State, &alert.Category, &alert.UserUUID,
			&alert.Username, &alert.NodeName, &alert.Summary, &alert.FirstSeenAt, &alert.LastSeenAt,
		); err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}
	return alerts, rows.Err()
}

// ListStorageRepairCandidates returns users whose current writer is safe to
// snapshot but who have no healthy pure-storage protection. The workflow
// creation transaction rechecks the lease before any Agent mutation.
func (s *Store) ListStorageRepairCandidates(
	ctx context.Context,
	limit int,
	now time.Time,
) ([]StorageRepairCandidate, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT legacy.id,global_user.id,legacy.home_node_id
		FROM user_protection_states protection
		JOIN global_users global_user ON global_user.id=protection.user_id AND global_user.status='active'
		JOIN users legacy ON legacy.id=global_user.legacy_user_id AND legacy.status='active'
		JOIN nodes home ON home.id=legacy.home_node_id AND home.role='compute'
		  AND home.connectivity_state='online' AND home.operational_state='active'
		  AND home.compatibility_state='compatible'
		JOIN user_replicas home_replica ON home_replica.user_id=legacy.id
		  AND home_replica.node_id=legacy.home_node_id AND home_replica.kind='home'
		  AND home_replica.state='ready'
		WHERE protection.state IN ('temporary','unprotected')
		  AND NOT EXISTS (
		    SELECT 1 FROM replica_copies archive_copy
		    JOIN snapshot_manifests archive_snapshot ON archive_snapshot.id=archive_copy.snapshot_id
		      AND archive_snapshot.user_id=global_user.id AND archive_snapshot.state='immutable'
		    JOIN nodes archive_node ON archive_node.id=archive_copy.node_id AND archive_node.role='storage'
		      AND archive_node.connectivity_state='online' AND archive_node.operational_state='active'
		      AND archive_node.compatibility_state='compatible'
		    JOIN user_replicas archive_legacy ON archive_legacy.user_id=legacy.id
		      AND archive_legacy.node_id=archive_copy.node_id AND archive_legacy.kind='archive'
		      AND archive_legacy.state='ready'
		    WHERE archive_copy.user_id=global_user.id AND archive_copy.replica_kind='archive'
		      AND archive_copy.state='ready' AND archive_copy.compatibility_state='compatible'
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM user_activity_leases lease WHERE lease.user_id=global_user.id
		      AND (lease.lease_expires_at>$2 OR lease.in_flight_reads<>0 OR lease.in_flight_writes<>0
		        OR lease.state IN ('independent','quiescing'))
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM workflows workflow WHERE workflow.user_id=global_user.id
		      AND workflow.workflow_type='snapshot'
		      AND workflow.state NOT IN ('succeeded','cancelled','failed')
		  )
		ORDER BY protection.changed_at,protection.user_id LIMIT $1`, limit, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var candidates []StorageRepairCandidate
	for rows.Next() {
		var candidate StorageRepairCandidate
		if err := rows.Scan(&candidate.LegacyUserID, &candidate.GlobalUserID, &candidate.HomeNodeID); err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	return candidates, rows.Err()
}

// GetImmutableHotStandbyRecoveryPoint returns the exact recovery point that a
// user may acknowledge for a compute takeover. Missing or ineligible replicas
// return an invalid NullTime rather than a speculative legacy sync time.
func (s *Store) GetImmutableHotStandbyRecoveryPoint(
	ctx context.Context,
	globalUserID, nodeID int64,
) (sql.NullTime, error) {
	if globalUserID <= 0 || nodeID <= 0 {
		return sql.NullTime{}, fmt.Errorf("invalid hot standby recovery point input")
	}
	var publishedAt time.Time
	err := s.DB.QueryRowContext(ctx, `
		SELECT copy.published_at
		FROM replica_copies copy
		JOIN snapshot_manifests snapshot ON snapshot.id=copy.snapshot_id
		  AND snapshot.user_id=copy.user_id AND snapshot.state='immutable'
		JOIN node_accounts account ON account.user_id=copy.user_id AND account.node_id=copy.node_id
		  AND account.status='active'
		WHERE copy.user_id=$1 AND copy.node_id=$2 AND copy.replica_kind='hot_standby'
		  AND copy.state='ready' AND copy.compatibility_state='compatible'
		  AND copy.published_at IS NOT NULL`, globalUserID, nodeID).Scan(&publishedAt)
	if err == sql.ErrNoRows {
		return sql.NullTime{}, nil
	}
	if err != nil {
		return sql.NullTime{}, err
	}
	return sql.NullTime{Time: publishedAt, Valid: true}, nil
}

// ConfirmReplicaTakeover atomically promotes a verified immutable hot standby,
// fences an expired source lease, and marks the previous home replica stale.
func (s *Store) ConfirmReplicaTakeover(
	ctx context.Context,
	p ConfirmReplicaTakeoverParams,
) (ReplicaTakeoverResult, error) {
	if p.OperationID == "" || len(p.RequestDigest) != 32 || p.GlobalUserID <= 0 || p.TargetNodeID <= 0 ||
		p.ExpectedRecoveryAt.IsZero() {
		return ReplicaTakeoverResult{}, ErrInvalidReplicaTakeover
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ReplicaTakeoverResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockGlobalUser(ctx, tx, p.GlobalUserID); err != nil {
		return ReplicaTakeoverResult{}, err
	}
	if replay, ok, err := getReplicaTakeoverOperation(ctx, tx, p); err != nil {
		return ReplicaTakeoverResult{}, err
	} else if ok {
		replay.Replayed = true
		if err := tx.Commit(); err != nil {
			return ReplicaTakeoverResult{}, err
		}
		return replay, nil
	}

	var legacyUserID, sourceNodeID int64
	if err := tx.QueryRowContext(ctx, `
		SELECT global_user.legacy_user_id,legacy.home_node_id
		FROM global_users global_user
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		WHERE global_user.id=$1 AND global_user.status='active' AND legacy.status='active'
		  AND legacy.home_node_id IS NOT NULL
		FOR UPDATE OF global_user,legacy`, p.GlobalUserID).Scan(&legacyUserID, &sourceNodeID); err != nil {
		if err == sql.ErrNoRows {
			return ReplicaTakeoverResult{}, ErrReplicaTakeoverUnavailable
		}
		return ReplicaTakeoverResult{}, err
	}
	if sourceNodeID == p.TargetNodeID {
		return ReplicaTakeoverResult{}, ErrReplicaTakeoverUnavailable
	}
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&generation); err != nil {
		if err == sql.ErrNoRows {
			return ReplicaTakeoverResult{}, ErrNoActiveController
		}
		return ReplicaTakeoverResult{}, err
	}
	lease, found, err := getActivityLeaseForUpdate(ctx, tx, p.GlobalUserID)
	if err != nil {
		return ReplicaTakeoverResult{}, err
	}
	if found && leaseBlocksNewWriter(lease, p.Now) {
		return ReplicaTakeoverResult{}, ErrReplicaTakeoverLeaseActive
	}

	var result ReplicaTakeoverResult
	result.SourceNodeID = sourceNodeID
	result.TargetNodeID = p.TargetNodeID
	result.ControllerGeneration = generation
	if err := tx.QueryRowContext(ctx, `
		SELECT copy.snapshot_id::text,copy.published_at
		FROM user_replicas replica
		JOIN nodes node ON node.id=replica.node_id AND node.role='compute'
		  AND node.connectivity_state='online' AND node.operational_state='active'
		  AND node.compatibility_state='compatible'
		JOIN node_accounts account ON account.user_id=$2 AND account.node_id=replica.node_id
		  AND account.status='active'
		JOIN replica_copies copy ON copy.user_id=$2 AND copy.node_id=replica.node_id
		  AND copy.replica_kind='hot_standby' AND copy.state='ready'
		  AND copy.compatibility_state='compatible'
		  AND copy.snapshot_id IS NOT NULL AND copy.published_at IS NOT NULL
		JOIN snapshot_manifests snapshot ON snapshot.id=copy.snapshot_id
		  AND snapshot.user_id=$2 AND snapshot.state='immutable'
		WHERE replica.user_id=$1 AND replica.node_id=$3 AND replica.kind='hot_standby'
		  AND replica.state='ready' AND replica.last_sync_at IS NOT NULL
		  AND copy.published_at=$4
		FOR UPDATE OF replica,copy`, legacyUserID, p.GlobalUserID, p.TargetNodeID, p.ExpectedRecoveryAt).
		Scan(&result.SnapshotID, &result.SnapshotPublishedAt); err != nil {
		if err == sql.ErrNoRows {
			return ReplicaTakeoverResult{}, ErrReplicaTakeoverUnavailable
		}
		return ReplicaTakeoverResult{}, err
	}

	updated, err := tx.ExecContext(ctx, `
		UPDATE user_replicas SET kind='hot_standby',state='stale'
		WHERE user_id=$1 AND node_id=$2 AND kind='home'`, legacyUserID, sourceNodeID)
	if err != nil {
		return ReplicaTakeoverResult{}, err
	}
	if rows, err := updated.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return ReplicaTakeoverResult{}, err
		}
		return ReplicaTakeoverResult{}, ErrReplicaTakeoverUnavailable
	}
	updated, err = tx.ExecContext(ctx, `
		UPDATE user_replicas SET kind='home',state='ready'
		WHERE user_id=$1 AND node_id=$2 AND kind='hot_standby' AND state='ready'`, legacyUserID, p.TargetNodeID)
	if err != nil {
		return ReplicaTakeoverResult{}, err
	}
	if rows, err := updated.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return ReplicaTakeoverResult{}, err
		}
		return ReplicaTakeoverResult{}, ErrReplicaTakeoverUnavailable
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET home_node_id=$2 WHERE id=$1`, legacyUserID, p.TargetNodeID); err != nil {
		return ReplicaTakeoverResult{}, err
	}
	if found {
		if _, err := tx.ExecContext(ctx, `
			UPDATE user_activity_leases SET state='ended',lease_expires_at=$2,updated_at=$2
			WHERE user_id=$1`, p.GlobalUserID, p.Now); err != nil {
			return ReplicaTakeoverResult{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE control_tickets SET revoked_at=COALESCE(revoked_at,$2)
		WHERE user_id=$1 AND consumed_at IS NULL`, p.GlobalUserID, p.Now); err != nil {
		return ReplicaTakeoverResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE replica_copies SET is_authoritative=false,updated_at=$2
		WHERE user_id=$1 AND is_authoritative`, p.GlobalUserID, p.Now); err != nil {
		return ReplicaTakeoverResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO replica_copies (
		  id,user_id,node_id,replica_kind,state,origin,is_authoritative,
		  compatibility_state,created_at,updated_at
		) VALUES (gen_random_uuid(),$1,$2,'hot_standby','stale','primary',false,'unknown',$3,$3)
		ON CONFLICT (user_id,node_id) DO UPDATE SET
		  replica_kind='hot_standby',state='stale',origin='primary',is_authoritative=false,
		  updated_at=EXCLUDED.updated_at`, p.GlobalUserID, sourceNodeID, p.Now); err != nil {
		return ReplicaTakeoverResult{}, err
	}
	updated, err = tx.ExecContext(ctx, `
		UPDATE replica_copies SET replica_kind='active',state='ready',origin='recovery',
		  is_authoritative=true,updated_at=$4
		WHERE user_id=$1 AND node_id=$2 AND snapshot_id=$3 AND state='ready'`,
		p.GlobalUserID, p.TargetNodeID, result.SnapshotID, p.Now)
	if err != nil {
		return ReplicaTakeoverResult{}, err
	}
	if rows, err := updated.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return ReplicaTakeoverResult{}, err
		}
		return ReplicaTakeoverResult{}, ErrReplicaTakeoverUnavailable
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE node_accounts SET status=CASE WHEN node_id=$2 THEN 'active' ELSE 'stale' END,
		  updated_at=$3 WHERE user_id=$1 AND node_id IN ($2,$4)`,
		p.GlobalUserID, p.TargetNodeID, p.Now, sourceNodeID); err != nil {
		return ReplicaTakeoverResult{}, err
	}
	var previousEpoch any
	if found {
		previousEpoch = lease.ActivityEpoch
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO replica_takeover_operations (
		  operation_id,request_digest,user_id,source_node_id,target_node_id,snapshot_id,
		  snapshot_published_at,previous_activity_epoch,controller_generation,
		  acknowledged_at,completed_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)`,
		p.OperationID, p.RequestDigest, p.GlobalUserID, sourceNodeID, p.TargetNodeID,
		result.SnapshotID, result.SnapshotPublishedAt, previousEpoch, generation, p.Now); err != nil {
		return ReplicaTakeoverResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_protection_states (
		  user_id,state,reason_code,authoritative_node_id,recovery_node_id,
		  latest_recovery_snapshot_id,latest_recovery_at,version,changed_at,evaluated_at
		) VALUES ($1,'unprotected','takeover_completed_backup_required',$2,NULL,NULL,NULL,1,$3,$3)
		ON CONFLICT (user_id) DO UPDATE SET
		  state='unprotected',reason_code='takeover_completed_backup_required',
		  authoritative_node_id=EXCLUDED.authoritative_node_id,recovery_node_id=NULL,
		  latest_recovery_snapshot_id=NULL,latest_recovery_at=NULL,
		  version=user_protection_states.version+1,changed_at=$3,evaluated_at=$3`,
		p.GlobalUserID, p.TargetNodeID, p.Now); err != nil {
		return ReplicaTakeoverResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  actor_type,actor_id,action,target_type,target_id,operation_id,
		  controller_generation,input_digest,outcome,detail
		) VALUES ('user',$1::text,'replica-takeover','global_user',$1::text,$2,$3,$4,'succeeded',
		  jsonb_build_object('source_node_id',$5,'target_node_id',$6,'snapshot_published_at',$7))`,
		p.GlobalUserID, p.OperationID, generation, p.RequestDigest,
		sourceNodeID, p.TargetNodeID, result.SnapshotPublishedAt); err != nil {
		return ReplicaTakeoverResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return ReplicaTakeoverResult{}, err
	}
	return result, nil
}

func getReplicaTakeoverOperation(
	ctx context.Context,
	tx *sql.Tx,
	p ConfirmReplicaTakeoverParams,
) (ReplicaTakeoverResult, bool, error) {
	var result ReplicaTakeoverResult
	var userID, targetNodeID int64
	var digest []byte
	err := tx.QueryRowContext(ctx, `
		SELECT request_digest,user_id,source_node_id,target_node_id,snapshot_id::text,
		  snapshot_published_at,controller_generation
		FROM replica_takeover_operations WHERE operation_id=$1`, p.OperationID).Scan(
		&digest, &userID, &result.SourceNodeID, &targetNodeID, &result.SnapshotID,
		&result.SnapshotPublishedAt, &result.ControllerGeneration,
	)
	if err == sql.ErrNoRows {
		return ReplicaTakeoverResult{}, false, nil
	}
	if err != nil {
		return ReplicaTakeoverResult{}, false, err
	}
	if userID != p.GlobalUserID || targetNodeID != p.TargetNodeID || !bytes.Equal(digest, p.RequestDigest) {
		return ReplicaTakeoverResult{}, false, ErrReplicaTakeoverConflict
	}
	result.TargetNodeID = targetNodeID
	return result, true, nil
}
