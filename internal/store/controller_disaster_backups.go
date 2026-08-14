package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Controller own-state backup state machine states.
const (
	ControllerBackupScheduled     = "scheduled"
	ControllerBackupSnapshotting  = "snapshotting"
	ControllerBackupTransferring  = "transferring"
	ControllerBackupVerifying     = "verifying"
	ControllerBackupPublishing    = "publishing"
	ControllerBackupSucceeded     = "succeeded"
	ControllerBackupSuperseded    = "superseded"
	ControllerBackupFailed        = "failed"
	ControllerBackupRetryWait     = "retry_wait"
	ControllerBackupCancelled     = "cancelled"
	ControllerBackupKindPGDump    = "pg_dump"
	ControllerBackupKindSnapshot  = "control_snapshot"
	ControllerBackupKindFull      = "full"
)

var ErrInvalidControllerDisasterBackup = errors.New("invalid controller disaster backup input")

// ControllerDisasterBackupRun is one durable, idempotent controller backup
// workflow intent. Only the lease-holding reconciler may mutate a claimed run.
type ControllerDisasterBackupRun struct {
	ID                   string          `json:"id"`
	OperationID          string          `json:"operation_id"`
	NodeID               int64           `json:"node_id"`
	NodeName             string          `json:"node_name,omitempty"`
	State                string          `json:"state"`
	ControllerGeneration int64           `json:"controller_generation,omitempty"`
	BackupKind           string          `json:"backup_kind"`
	PayloadFileName      string          `json:"payload_file_name,omitempty"`
	PayloadSizeBytes     int64           `json:"payload_size_bytes,omitempty"`
	PayloadSHA256        string          `json:"payload_sha256,omitempty"`
	Manifest             json.RawMessage `json:"manifest,omitempty"`
	Attempt              int             `json:"attempt"`
	NextAttemptAt        time.Time       `json:"next_attempt_at"`
	LeaseOwner           string          `json:"lease_owner,omitempty"`
	LeaseUntil           *time.Time      `json:"lease_until,omitempty"`
	ErrorCode            string          `json:"error_code,omitempty"`
	StartedAt            *time.Time      `json:"started_at,omitempty"`
	FinishedAt           *time.Time      `json:"finished_at,omitempty"`
	UpdatedAt            time.Time       `json:"updated_at"`
	CreatedAt            time.Time       `json:"created_at"`
}

// ScheduleControllerDisasterBackupParams configures one auto-backup pass.
// OperationID must be random so the unique index makes concurrent reconcilers
// idempotent across restarts.
type ScheduleControllerDisasterBackupParams struct {
	OperationID string
	BackupKind  string
	MaxAttempts int
	Interval    time.Duration
	LeaseOwner  string
	LeaseTTL    time.Duration
	Now         time.Time
}

// ClaimControllerDisasterBackupParams identifies a claimed run.
type ClaimControllerDisasterBackupParams struct {
	OperationID string
	LeaseOwner  string
	LeaseTTL    time.Duration
	MaxAttempts int
	Now         time.Time
}

// ScheduleControllerDisasterBackup atomically decides that the control plane
// needs a fresh disaster backup and, if so, picks an eligible pure-storage
// target and persists one idempotent run. It returns nil when the controller
// is already covered (an in-flight run exists, or a successful run is younger
// than the configured interval).
func (s *Store) ScheduleControllerDisasterBackup(
	ctx context.Context, p ScheduleControllerDisasterBackupParams,
) (*ControllerDisasterBackupRun, error) {
	if !validUUIDText(p.OperationID) || p.MaxAttempts <= 0 || p.Interval <= 0 ||
		p.LeaseOwner == "" || p.LeaseTTL <= 0 {
		return nil, ErrInvalidControllerDisasterBackup
	}
	if p.BackupKind == "" { p.BackupKind = ControllerBackupKindFull }
	if err := validControllerBackupKind(p.BackupKind); err != nil { return nil, err }
	if p.Now.IsZero() { p.Now = time.Now().UTC() }
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return nil, err }
	defer func() { _ = tx.Rollback() }()

	var generation int64
	if err := tx.QueryRowContext(ctx, `		SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&generation); err != nil {
		if err == sql.ErrNoRows { return nil, ErrNoActiveController }
		return nil, err
	}

	var covered bool
	if err := tx.QueryRowContext(ctx, `		SELECT EXISTS (
		  SELECT 1 FROM controller_disaster_backups backup
		  WHERE (backup.state IN ('scheduled','snapshotting','transferring','verifying','publishing','retry_wait')
		     OR (backup.state='succeeded' AND backup.created_at>=$1))
		)`, p.Now.Add(-p.Interval)).Scan(&covered); err != nil {
		return nil, err
	}
	if covered {
		if err := tx.Commit(); err != nil { return nil, err }
		return nil, nil
	}

	var nodeID int64
	var nodeName string
	err = tx.QueryRowContext(ctx, `		SELECT node.id,node.name
		FROM nodes node
		WHERE node.role='storage' AND node.is_backup_target
		  AND node.connectivity_state='online' AND node.operational_state='active'
		  AND node.compatibility_state='compatible' AND node.control_mode='managed'
		  AND node.desired_control_mode='managed' AND node.capacity_state IN ('open','busy')
		  AND COALESCE(node.transfer_url,'')<>''
		  AND node.metrics_observed_at IS NOT NULL AND node.metrics_observed_at>=$1
		  AND node.disk_available_bytes IS NOT NULL AND node.disk_quota_bytes IS NOT NULL
		ORDER BY CASE node.capacity_state WHEN 'open' THEN 0 ELSE 1 END,
		  LEAST(node.disk_available_bytes,node.disk_quota_bytes-node.allocated_disk_bytes) DESC,
		  node.id
		FOR UPDATE OF node SKIP LOCKED LIMIT 1`,
		p.Now.Add(-2*time.Minute)).Scan(&nodeID, &nodeName)
	if err == sql.ErrNoRows {
		if err := tx.Commit(); err != nil { return nil, err }
		return nil, sql.ErrNoRows
	}
	if err != nil { return nil, fmt.Errorf("select controller backup target: %w", err) }

	run := &ControllerDisasterBackupRun{OperationID: p.OperationID, NodeID: nodeID, NodeName: nodeName}
	err = tx.QueryRowContext(ctx, `		INSERT INTO controller_disaster_backups (
		  operation_id,node_id,state,controller_generation,backup_kind,
		  attempt,next_attempt_at,lease_owner,lease_until,started_at,updated_at
		)
		SELECT $1,$2,'scheduled',$3,$4,0,$5,$6,$7,$5,$5
		WHERE NOT EXISTS (
		  SELECT 1 FROM controller_disaster_backups backup
		  WHERE (backup.state IN ('scheduled','snapshotting','transferring','verifying','publishing','retry_wait')
		     OR (backup.state='succeeded' AND backup.created_at>=$5))
		)
		RETURNING id::text`,
		p.OperationID, nodeID, generation, p.BackupKind,
		p.Now, p.LeaseOwner, p.Now.Add(p.LeaseTTL)).Scan(&run.ID)
	if err == sql.ErrNoRows {
		if err := tx.Commit(); err != nil { return nil, err }
		return nil, nil
	}
	if err != nil { return nil, err }
	if _, err := tx.ExecContext(ctx, `		INSERT INTO audit_events (
		  occurred_at,actor_type,action,target_type,target_id,operation_id,
		  controller_generation,outcome,detail
		) VALUES ($1,'controller','controller-backup','controller_epoch',$2::text,
		  $3,$2::bigint,'scheduled',jsonb_build_object(
		    'node_id',$4::bigint,'backup_kind',$5::text))`,
		p.Now, generation, p.OperationID, nodeID, p.BackupKind); err != nil { return nil, err }
	if err := tx.Commit(); err != nil { return nil, err }
	run.ControllerGeneration = generation
	run.State = ControllerBackupScheduled
	run.BackupKind = p.BackupKind
	run.Attempt = 0
	run.NextAttemptAt = p.Now
	run.LeaseOwner = p.LeaseOwner
	leaseUntil := p.Now.Add(p.LeaseTTL)
	run.LeaseUntil = &leaseUntil
	run.StartedAt = &p.Now
	run.UpdatedAt = p.Now
	run.CreatedAt = p.Now
	return run, nil
}

// ClaimControllerDisasterBackup claims the run this reconciler just created by
// unique operation_id, increments the attempt, takes the lease, and revalidates
// the target is still an eligible pure-storage node.
func (s *Store) ClaimControllerDisasterBackup(
	ctx context.Context, p ClaimControllerDisasterBackupParams,
) (*ControllerDisasterBackupRun, error) {
	if !validUUIDText(p.OperationID) || !validUUIDText(p.LeaseOwner) ||
		p.LeaseTTL <= 0 || p.MaxAttempts <= 0 {
		return nil, ErrInvalidControllerDisasterBackup
	}
	if p.Now.IsZero() { p.Now = time.Now().UTC() }
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return nil, err }
	defer func() { _ = tx.Rollback() }()
	run := &ControllerDisasterBackupRun{}
	err = tx.QueryRowContext(ctx, `		SELECT id::text,node_id,state,controller_generation,backup_kind,attempt,next_attempt_at
		FROM controller_disaster_backups
		WHERE operation_id=$1 FOR UPDATE`, p.OperationID).Scan(
		&run.ID, &run.NodeID, &run.State, &run.ControllerGeneration, &run.BackupKind,
		&run.Attempt, &run.NextAttemptAt)
	if err != nil {
		if err == sql.ErrNoRows { return nil, tx.Commit() }
		return nil, err
	}
	if run.State != ControllerBackupScheduled && run.State != ControllerBackupRetryWait {
		_ = tx.Commit()
		return nil, nil
	}
	if run.Attempt >= p.MaxAttempts {
		_ = tx.Commit()
		return nil, nil
	}
	var leaseOwner sql.NullString
	var leaseUntil, startedAt, finishedAt sql.NullTime
	var newAttempt int
	err = tx.QueryRowContext(ctx, `		UPDATE controller_disaster_backups tgt SET
		  state='snapshotting',started_at=COALESCE(started_at,$4),
		  attempt=attempt+1,next_attempt_at=$4,lease_owner=$2,lease_until=$5,
		  updated_at=$4
		FROM nodes node
		WHERE tgt.id=$1 AND tgt.state IN ('scheduled','retry_wait')
		  AND tgt.attempt<$3
		  AND node.id=tgt.node_id AND node.role='storage' AND node.is_backup_target
		  AND node.connectivity_state='online' AND node.operational_state='active'
		  AND node.compatibility_state='compatible' AND node.control_mode='managed'
		  AND node.desired_control_mode='managed'
		  AND COALESCE(node.transfer_url,'')<>''
		RETURNING tgt.state,tgt.lease_owner::text,tgt.lease_until::text,
		  tgt.started_at::text,tgt.finished_at::text,tgt.attempt`,
		run.ID, p.LeaseOwner, p.MaxAttempts, p.Now, p.Now.Add(p.LeaseTTL)).
		Scan(&run.State, &leaseOwner, &leaseUntil, &startedAt, &finishedAt, &newAttempt)
	if err == sql.ErrNoRows {
		_ = tx.Commit()
		return nil, nil
	}
	if err != nil { return nil, err }
	if err := tx.Commit(); err != nil { return nil, err }
	run.Attempt = newAttempt
	run.LeaseOwner = leaseOwner.String
	if leaseUntil.Valid { v := leaseUntil.Time; run.LeaseUntil = &v }
	if startedAt.Valid { v := startedAt.Time; run.StartedAt = &v }
	if finishedAt.Valid { v := finishedAt.Time; run.FinishedAt = &v }
	return run, nil
}

// MarkControllerDisasterBackupProgress advances a claimed run through its
// workflow (snapshotting -> transferring -> verifying -> publishing).
func (s *Store) MarkControllerDisasterBackupProgress(ctx context.Context, operationID, state string) error {
	if !validUUIDText(operationID) { return ErrInvalidControllerDisasterBackup }
	_, err := s.DB.ExecContext(ctx, `		UPDATE controller_disaster_backups SET state=$2,updated_at=$3
		WHERE operation_id=$1`, operationID, state, time.Now().UTC())
	return err
}

// CompleteControllerDisasterBackup records the verified archive metadata and
// marks the run succeeded.
func (s *Store) CompleteControllerDisasterBackup(
	ctx context.Context, operationID, fileName, sha256Hex string, sizeBytes int64, manifest json.RawMessage,
) error {
	if !validUUIDText(operationID) || fileName == "" ||
		(sha256Hex != "" && len(sha256Hex) != 64) || sizeBytes <= 0 {
		return ErrInvalidControllerDisasterBackup
	}
	_, err := s.DB.ExecContext(ctx, `		UPDATE controller_disaster_backups SET
		  state='succeeded',payload_file_name=$2,payload_size_bytes=$3,
		  payload_sha256=decode($4,'hex'),manifest=$5,
		  error_code=NULL,
		  finished_at=COALESCE(finished_at,$6),updated_at=$6
		WHERE operation_id=$1`,
		operationID, fileName, sizeBytes, sha256Hex, manifest, time.Now().UTC())
	return err
}

// FailControllerDisasterBackup marks a run failed (attempt exhausted) or moves
// it to retry_wait with bounded exponential backoff kept in the DB.
func (s *Store) FailControllerDisasterBackup(
	ctx context.Context, operationID, errorCode string, maxAttempts int, now time.Time,
) error {
	if !validUUIDText(operationID) || errorCode == "" || maxAttempts <= 0 {
		return ErrInvalidControllerDisasterBackup
	}
	if now.IsZero() { now = time.Now().UTC() }
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return err }
	defer func() { _ = tx.Rollback() }()
	var attempt int
	if err := tx.QueryRowContext(ctx, `		SELECT attempt FROM controller_disaster_backups WHERE operation_id=$1 FOR UPDATE`, operationID).Scan(&attempt); err != nil { return err }
	nextAttemptAt := now.Add(controllerBackupBackoff(attempt))
	_, err = tx.ExecContext(ctx, `		UPDATE controller_disaster_backups SET
		  state=CASE WHEN $3>=$4 THEN 'failed' ELSE 'retry_wait' END,
		  lease_owner=NULL,lease_until=NULL,
		  error_code=$2,next_attempt_at=$5,
		  finished_at=CASE WHEN $3>=$4 THEN COALESCE(finished_at,$6) ELSE NULL END,
		  updated_at=$6
		WHERE operation_id=$1`,
		operationID, errorCode, attempt+1, maxAttempts, nextAttemptAt, now)
	if err != nil { return err }
	return tx.Commit()
}

// controllerBackupBackoff returns a bounded exponential backoff duration.
func controllerBackupBackoff(attempt int) time.Duration {
	if attempt < 0 { attempt = 0 }
	if attempt > 6 { attempt = 6 }
	seconds := 30 * (1 << attempt)
	if seconds > 3600 { seconds = 3600 }
	return time.Duration(seconds) * time.Second
}

// ReconcileControllerDisasterBackups keeps only the latest successful backup
// per node (R09-style), finalizes any attempts past the max as a safety net,
// and returns the total rows touched.
func (s *Store) ReconcileControllerDisasterBackups(ctx context.Context, now time.Time, maxAttempts int) (int64, error) {
	if maxAttempts <= 0 { return 0, ErrInvalidControllerDisasterBackup }
	if now.IsZero() { now = time.Now().UTC() }
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return 0, err }
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `		UPDATE controller_disaster_backups SET state='superseded',updated_at=$1
		WHERE state='succeeded' AND id IN (
		  SELECT id FROM (
		    SELECT id, rank() OVER (
		      PARTITION BY node_id ORDER BY created_at DESC, id DESC
		    ) AS rnk
		    FROM controller_disaster_backups WHERE state='succeeded'
		  ) ranked WHERE ranked.rnk>1
		)`, now)
	if err != nil { return 0, err }
	rows, err := result.RowsAffected()
	if err != nil { return 0, err }
	exhausted, err := tx.ExecContext(ctx, `		UPDATE controller_disaster_backups SET state='failed',
		  error_code='attempt_limit_reached',lease_owner=NULL,lease_until=NULL,
		  finished_at=COALESCE(finished_at,$1),updated_at=$1
		WHERE state IN ('scheduled','retry_wait') AND attempt>=$2`, now, maxAttempts)
	if err != nil { return 0, err }
	exhaustedRows, err := exhausted.RowsAffected()
	if err != nil { return 0, err }
	if err := tx.Commit(); err != nil { return 0, err }
	return rows + exhaustedRows, nil
}

// ListControllerDisasterBackupPageParams mirrors the admin pagination pattern
// (newest first, cursor by created_at).
type ListControllerDisasterBackupPageParams struct {
	BeforeAt time.Time
	Limit    int
	State    string
}

func (s *Store) ListControllerDisasterBackupsPage(
	ctx context.Context, p ListControllerDisasterBackupPageParams,
) ([]*ControllerDisasterBackupRun, error) {
	if p.Limit <= 0 || p.Limit > 100 { p.Limit = 50 }
	where := "WHERE (backup.created_at < $1 OR $1 IS NULL)"
	var beforeArg any
	if !p.BeforeAt.IsZero() { beforeArg = p.BeforeAt }
	args := []any{beforeArg}
	if p.State != "" {
		where += " AND backup.state=$2"
		args = append(args, p.State)
	}
	query := `SELECT backup.id::text,backup.operation_id::text,backup.node_id,node.name,
		  backup.state,backup.backup_kind,COALESCE(backup.payload_file_name,''),
		  COALESCE(backup.payload_size_bytes,0),COALESCE(backup.payload_sha256::text,''),
		  COALESCE(backup.error_code,''),backup.attempt,backup.next_attempt_at,
		  backup.started_at,backup.finished_at,backup.created_at,backup.updated_at
		FROM controller_disaster_backups backup
		JOIN nodes node ON node.id=backup.node_id` + where + " ORDER BY backup.created_at DESC, backup.id DESC LIMIT " + fmt.Sprintf("$%d", len(args)+1)
	args = append(args, p.Limit)
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []*ControllerDisasterBackupRun
	for rows.Next() {
		r := &ControllerDisasterBackupRun{}
		var startedAt, finishedAt sql.NullTime
		if err := rows.Scan(&r.ID, &r.OperationID, &r.NodeID, &r.NodeName,
			&r.State, &r.BackupKind, &r.PayloadFileName, &r.PayloadSizeBytes,
			&r.PayloadSHA256, &r.ErrorCode, &r.Attempt, &r.NextAttemptAt,
			&startedAt, &finishedAt, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		if startedAt.Valid { r.StartedAt = &startedAt.Time }
		if finishedAt.Valid { r.FinishedAt = &finishedAt.Time }
		out = append(out, r)
	}
	return out, rows.Err()
}

func validControllerBackupKind(kind string) error {
	switch kind {
	case ControllerBackupKindFull, ControllerBackupKindPGDump, ControllerBackupKindSnapshot:
		return nil
	default:
		return ErrInvalidControllerDisasterBackup
	}
}
