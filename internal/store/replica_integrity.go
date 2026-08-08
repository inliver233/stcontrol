package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidReplicaIntegrity = errors.New("invalid replica integrity input")
	ErrReplicaIntegrityState   = errors.New("replica integrity state conflict")
)

const (
	ReplicaIntegrityLightInterval = 24 * time.Hour
	ReplicaIntegrityDeepInterval  = 30 * 24 * time.Hour
)

type ReplicaIntegrityTask struct {
	ReplicaID            string
	OperationID          string
	GlobalUserID         int64
	LegacyUserID         int64
	NodeID               int64
	SnapshotID           string
	Handle               string
	ManifestSHA256       []byte
	ArchiveSHA256        []byte
	FileCount            int64
	TotalBytes           int64
	CheckKind            string
	Attempt              int
	ControllerGeneration int64
}

func (s *Store) ClaimReplicaIntegrityTask(
	ctx context.Context,
	operationID string,
	now time.Time,
	leaseTTL time.Duration,
) (*ReplicaIntegrityTask, error) {
	if len(operationID) != 36 || leaseTTL <= 0 {
		return nil, ErrInvalidReplicaIntegrity
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var task ReplicaIntegrityTask
	err := s.DB.QueryRowContext(ctx, `
		WITH candidate AS (
		  SELECT copy.id,CASE WHEN copy.integrity_deep_check_at<=$2 THEN 'deep' ELSE 'light' END AS check_kind
		  FROM replica_copies copy
		  JOIN nodes node ON node.id=copy.node_id
		  JOIN snapshot_manifests snapshot ON snapshot.id=copy.snapshot_id
		    AND snapshot.user_id=copy.user_id AND snapshot.state='immutable'
		  WHERE copy.replica_kind='archive' AND copy.state='ready'
		    AND copy.compatibility_state='compatible'
		    AND node.connectivity_state='online' AND node.operational_state='active'
		    AND node.compatibility_state='compatible'
		    AND snapshot.archive_sha256 IS NOT NULL
		    AND copy.integrity_next_check_at<=$2
		    AND (copy.integrity_state IN ('due','verified','retry_wait')
		      OR (copy.integrity_state='checking' AND copy.integrity_lease_until<=$2))
		  ORDER BY copy.integrity_next_check_at,copy.id
		  FOR UPDATE OF copy SKIP LOCKED LIMIT 1
		), claimed AS (
		  UPDATE replica_copies copy SET integrity_state='checking',integrity_operation_id=$1,
		    integrity_controller_generation=epoch.generation,integrity_lease_until=$3,
		    integrity_check_kind=candidate.check_kind,
		    integrity_attempt=copy.integrity_attempt+1,integrity_error_code=NULL,updated_at=$2
		  FROM candidate,controller_epochs epoch
		  WHERE copy.id=candidate.id AND epoch.state='active'
		  RETURNING copy.id,copy.user_id,copy.node_id,copy.snapshot_id,copy.integrity_check_kind,
		    copy.integrity_attempt,copy.integrity_controller_generation
		)
		SELECT claimed.id::text,$1::text,claimed.user_id,global_user.legacy_user_id,
		  claimed.node_id,claimed.snapshot_id::text,legacy_user.username,
		  snapshot.manifest_sha256,snapshot.archive_sha256,snapshot.file_count,
		  snapshot.total_bytes,claimed.integrity_check_kind,
		  claimed.integrity_attempt,claimed.integrity_controller_generation
		FROM claimed
		JOIN global_users global_user ON global_user.id=claimed.user_id
		JOIN users legacy_user ON legacy_user.id=global_user.legacy_user_id
		JOIN snapshot_manifests snapshot ON snapshot.id=claimed.snapshot_id`,
		operationID, now, now.Add(leaseTTL)).Scan(
		&task.ReplicaID, &task.OperationID, &task.GlobalUserID, &task.LegacyUserID,
		&task.NodeID, &task.SnapshotID, &task.Handle, &task.ManifestSHA256,
		&task.ArchiveSHA256, &task.FileCount, &task.TotalBytes, &task.CheckKind, &task.Attempt,
		&task.ControllerGeneration,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim replica integrity task: %w", err)
	}
	return &task, nil
}

type CompleteReplicaIntegrityParams struct {
	ReplicaID      string
	OperationID    string
	SnapshotID     string
	ManifestSHA256 []byte
	ArchiveSHA256  []byte
	FileCount      int64
	TotalBytes     int64
	CheckKind      string
	Now            time.Time
	NextCheckAfter time.Duration
	NextDeepAfter  time.Duration
}

func (s *Store) CompleteReplicaIntegrityTask(ctx context.Context, p CompleteReplicaIntegrityParams) error {
	if len(p.ReplicaID) != 36 || len(p.OperationID) != 36 || len(p.SnapshotID) != 36 ||
		len(p.ManifestSHA256) != 32 || len(p.ArchiveSHA256) != 32 ||
		p.FileCount < 0 || p.TotalBytes < 0 || (p.CheckKind != "light" && p.CheckKind != "deep") ||
		p.NextCheckAfter <= 0 || p.NextDeepAfter <= 0 {
		return ErrInvalidReplicaIntegrity
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE replica_copies copy SET integrity_state='verified',integrity_checked_at=$8,
		  integrity_last_light_at=$8,
		  integrity_last_deep_at=CASE WHEN $7='deep' THEN $8 ELSE integrity_last_deep_at END,
		  integrity_deep_check_at=CASE WHEN $7='deep' THEN $10 ELSE integrity_deep_check_at END,
		  integrity_next_check_at=$9,integrity_lease_until=NULL,integrity_error_code=NULL,
		  verified_at=$8,updated_at=$8
		FROM snapshot_manifests snapshot,controller_epochs epoch
		WHERE copy.id=$1::uuid AND copy.integrity_operation_id=$2::uuid
		  AND copy.integrity_state='checking' AND copy.integrity_check_kind=$7
		  AND copy.integrity_lease_until>$8
		  AND copy.integrity_controller_generation=epoch.generation AND epoch.state='active'
		  AND copy.snapshot_id=$3::uuid AND snapshot.id=copy.snapshot_id
		  AND snapshot.state='immutable' AND snapshot.manifest_sha256=$4
		  AND snapshot.archive_sha256=$5 AND snapshot.file_count=$6
		  AND snapshot.total_bytes=$11 AND copy.state='ready'`,
		p.ReplicaID, p.OperationID, p.SnapshotID, p.ManifestSHA256, p.ArchiveSHA256,
		p.FileCount, p.CheckKind, p.Now, p.Now.Add(p.NextCheckAfter),
		p.Now.Add(p.NextDeepAfter), p.TotalBytes)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrReplicaIntegrityState
	}
	return nil
}

func (s *Store) EscalateReplicaIntegrityTask(
	ctx context.Context,
	replicaID, operationID, errorCode string,
	now time.Time,
) error {
	if len(replicaID) != 36 || len(operationID) != 36 || !ValidMachineReasonCode(errorCode) {
		return ErrInvalidReplicaIntegrity
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE replica_copies copy SET integrity_state='due',integrity_check_kind='deep',
		  integrity_checked_at=$4,integrity_next_check_at=$4,integrity_deep_check_at=$4,
		  integrity_lease_until=NULL,integrity_error_code=$3,updated_at=$4
		FROM controller_epochs epoch
		WHERE copy.id=$1::uuid AND copy.integrity_operation_id=$2::uuid
		  AND copy.integrity_state='checking' AND copy.integrity_check_kind='light'
		  AND copy.integrity_lease_until>$4
		  AND copy.integrity_controller_generation=epoch.generation AND epoch.state='active'`,
		replicaID, operationID, errorCode, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrReplicaIntegrityState
	}
	return nil
}

func (s *Store) FailReplicaIntegrityTask(
	ctx context.Context,
	replicaID, operationID, errorCode string,
	corrupt bool,
	now time.Time,
	retryAfter time.Duration,
) error {
	if len(replicaID) != 36 || len(operationID) != 36 || errorCode == "" || len(errorCode) > 128 || retryAfter <= 0 {
		return ErrInvalidReplicaIntegrity
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	state := "retry_wait"
	copyState := "ready"
	if corrupt {
		state = "corrupt"
		copyState = "corrupt"
	}
	var globalUserID, legacyUserID, nodeID int64
	err = tx.QueryRowContext(ctx, `
		UPDATE replica_copies copy SET integrity_state=$3,state=$4,integrity_checked_at=$5,
		  integrity_next_check_at=$6,integrity_lease_until=NULL,integrity_error_code=$7,updated_at=$5
		FROM global_users global_user,controller_epochs epoch
		WHERE copy.id=$1::uuid AND copy.integrity_operation_id=$2::uuid
		  AND copy.integrity_state='checking' AND copy.integrity_lease_until>$5
		  AND global_user.id=copy.user_id
		  AND (NOT $8::boolean OR copy.integrity_check_kind='deep')
		  AND copy.integrity_controller_generation=epoch.generation AND epoch.state='active'
		RETURNING copy.user_id,global_user.legacy_user_id,copy.node_id`,
		replicaID, operationID, state, copyState, now, now.Add(retryAfter), errorCode, corrupt).
		Scan(&globalUserID, &legacyUserID, &nodeID)
	if err == sql.ErrNoRows {
		return ErrReplicaIntegrityState
	}
	if err != nil {
		return err
	}
	if corrupt {
		if _, err := tx.ExecContext(ctx, `
			UPDATE user_replicas SET state='corrupt'
			WHERE user_id=$1 AND node_id=$2 AND kind='archive'`, legacyUserID, nodeID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO alerts (
			  id,deduplication_key,severity,state,category,user_id,node_id,summary,
			  first_seen_at,last_seen_at,notify_after,occurrence_count
			) VALUES (
			  gen_random_uuid(),'replica-integrity:'||$1::text,'critical','open',
			  'replica_integrity',$2,$3,'用户存储副本完整性校验失败',$4,$4,$4,1
			) ON CONFLICT (deduplication_key) DO UPDATE SET
			  state='open',severity='critical',last_seen_at=EXCLUDED.last_seen_at,
			  notify_after=EXCLUDED.notify_after,resolved_at=NULL,
			  occurrence_count=alerts.occurrence_count+1`, replicaID, globalUserID, nodeID, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}
