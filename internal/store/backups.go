package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrInvalidBackupJob  = errors.New("invalid backup job")
	ErrBackupJobTerminal = errors.New("backup job is already terminal")
)

// CreateBackupJob 创建备份任务。
func (s *Store) CreateBackupJob(ctx context.Context, j *BackupJob) error {
	return s.DB.QueryRowContext(ctx, `
	  INSERT INTO backup_jobs (user_id, src_node_id, dst_node_id, trigger, status)
	  VALUES ($1,$2,$3,$4,$5) RETURNING id, created_at`,
		j.UserID, j.SrcNodeID, j.DstNodeID, j.Trigger, j.Status,
	).Scan(&j.ID, &j.CreatedAt)
}

// GetBackupJob 查询任务。
func (s *Store) GetBackupJob(ctx context.Context, id int64) (*BackupJob, error) {
	j := &BackupJob{}
	err := s.DB.QueryRowContext(ctx, `
	  SELECT id, user_id, src_node_id, dst_node_id, trigger, status,
	    data_version, bytes, file_count, error, started_at, finished_at, created_at
	  FROM backup_jobs WHERE id=$1`, id).
		Scan(&j.ID, &j.UserID, &j.SrcNodeID, &j.DstNodeID, &j.Trigger, &j.Status,
			&j.DataVersion, &j.Bytes, &j.FileCount, &j.Error, &j.StartedAt, &j.FinishedAt, &j.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return j, err
}

// UpdateBackupJobStatus 更新任务状态。
func (s *Store) UpdateBackupJobStatus(ctx context.Context, id int64, status string, dataVersion, bytes int64, fileCount int, errMsg string) error {
	now := time.Now()
	var startedAt, finishedAt any
	if status == "running" {
		startedAt = now
	}
	if status == "done" || status == "failed" || status == "aborted" {
		finishedAt = now
	}
	_, err := s.DB.ExecContext(ctx, `
	  UPDATE backup_jobs SET status=$2, data_version=$3, bytes=$4, file_count=$5, error=$6,
	    started_at=COALESCE($7, started_at), finished_at=COALESCE($8, finished_at)
	  WHERE id=$1`,
		id, status, nullableInt64(dataVersion), nullableInt64(bytes),
		nullableInt32(int32(fileCount)), nullableString(errMsg), startedAt, finishedAt)
	return err
}

// AbortBackupJobAndSnapshotWorkflow records the user-facing job cancellation
// and revokes the durable snapshot workflow in the same serializable commit.
// This prevents a Controller crash between the two facts from resuming a
// snapshot after the Agent has already reopened the user's write gate.
func (s *Store) AbortBackupJobAndSnapshotWorkflow(
	ctx context.Context,
	id int64,
	reason string,
	now time.Time,
) error {
	if id <= 0 {
		return ErrInvalidBackupJob
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
	var status string
	var workflowID sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT status,workflow_id::text FROM backup_jobs WHERE id=$1 FOR UPDATE`, id).
		Scan(&status, &workflowID); err != nil {
		if err == sql.ErrNoRows {
			return ErrInvalidBackupJob
		}
		return err
	}
	if status == "done" || status == "failed" {
		return ErrBackupJobTerminal
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE backup_jobs SET status='aborted',error=$2,finished_at=COALESCE(finished_at,$3)
		WHERE id=$1`, id, nullableString(reason), now); err != nil {
		return err
	}
	if workflowID.Valid && workflowID.String != "" {
		if err := cancelSnapshotWorkflowTx(ctx, tx, workflowID.String, reason, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// FindRunningBackupForUserOnNode 查询某用户在某节点上是否有 running 备份任务。
func (s *Store) FindRunningBackupForUserOnNode(ctx context.Context, userID, nodeID int64) (*BackupJob, error) {
	j := &BackupJob{}
	err := s.DB.QueryRowContext(ctx, `
	  SELECT id, user_id, src_node_id, dst_node_id, trigger, status,
	    data_version, bytes, file_count, error, started_at, finished_at, created_at
	  FROM backup_jobs
	  WHERE user_id=$1 AND src_node_id=$2 AND status IN ('pending','running','verifying')
	  ORDER BY id DESC LIMIT 1`, userID, nodeID).
		Scan(&j.ID, &j.UserID, &j.SrcNodeID, &j.DstNodeID, &j.Trigger, &j.Status,
			&j.DataVersion, &j.Bytes, &j.FileCount, &j.Error, &j.StartedAt, &j.FinishedAt, &j.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return j, err
}

// ListBackupJobs 列出任务（管理后台）。
func (s *Store) ListBackupJobs(ctx context.Context, limit int) ([]*BackupJob, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `
	  SELECT id, user_id, src_node_id, dst_node_id, trigger, status,
	    data_version, bytes, file_count, error, started_at, finished_at, created_at
	  FROM backup_jobs ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*BackupJob
	for rows.Next() {
		j := &BackupJob{}
		if err := rows.Scan(&j.ID, &j.UserID, &j.SrcNodeID, &j.DstNodeID, &j.Trigger, &j.Status,
			&j.DataVersion, &j.Bytes, &j.FileCount, &j.Error, &j.StartedAt, &j.FinishedAt, &j.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func nullableInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
func nullableInt32(v int32) any {
	if v == 0 {
		return nil
	}
	return v
}
func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}
