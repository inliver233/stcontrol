package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

var ErrConflictEvidenceState = errors.New("conflict evidence state conflict")

type ConflictEvidenceTask struct {
	ConflictID           string
	EvidenceID           string
	GlobalUserID         int64
	Handle               string
	NodeID               int64
	NodeRole             string
	SourceKind           string
	SourceSnapshotID     sql.NullString
	SourceManifestSHA256 []byte
	Attempt              int
}

type ConflictEvidencePageRecord struct {
	PageIndex        int
	EntryCount       int
	EncryptedPayload string
	PlaintextSHA256  []byte
}

type CompleteConflictEvidenceParams struct {
	ConflictID          string
	EvidenceID          string
	WorkerID            string
	EntriesSHA256       []byte
	FileCount           int64
	TotalBytes          int64
	CaptureBasis        string
	Pages               []ConflictEvidencePageRecord
	CommandOperationIDs []string
	Now                 time.Time
}

// ConflictEvidenceFailedRearmWindow bounds how long a permanently-failed
// evidence capture stays dormant before the reconciler tries it again.  This
// gives a recovery path for transient infrastructure loss (e.g. a node that
// was down for longer than the retry budget) so a conflict-frozen user is not
// stuck forever.
const ConflictEvidenceFailedRearmWindow = 6 * time.Hour

func (s *Store) ListConflictEvidenceTasks(ctx context.Context, limit int, now time.Time) ([]ConflictEvidenceTask, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT conflict.id::text,source.evidence_id::text,conflict.user_id,legacy.username,
		  source.node_id,source.node_role,source.source_kind,source.snapshot_id::text,
		  source.manifest_sha256,source.evidence_attempt
		FROM replica_conflict_sources source
		JOIN replica_conflicts conflict ON conflict.id=source.conflict_id
		  AND conflict.state IN ('detected','inspecting')
		JOIN global_users global_user ON global_user.id=conflict.user_id AND global_user.status='conflict'
		JOIN users legacy ON legacy.id=global_user.legacy_user_id AND legacy.status='conflict'
		JOIN nodes node ON node.id=source.node_id
		  AND node.connectivity_state='online' AND node.operational_state='active'
		  AND node.compatibility_state='compatible'
		WHERE source.source_kind IN ('active','hot_standby','archive')
		  AND (source.evidence_state='pending'
		    OR (source.evidence_state='retry_wait' AND source.evidence_next_attempt_at<=$2)
		    OR (source.evidence_state='capturing' AND source.evidence_lease_until<=$2)
		    OR (source.evidence_state='failed' AND source.evidence_updated_at<=$3))
		ORDER BY conflict.detected_at,source.node_id LIMIT $1`, limit, now, now.Add(-ConflictEvidenceFailedRearmWindow))
	if err != nil {
		return nil, fmt.Errorf("list conflict evidence tasks: %w", err)
	}
	defer rows.Close()
	var tasks []ConflictEvidenceTask
	for rows.Next() {
		var task ConflictEvidenceTask
		if err := rows.Scan(
			&task.ConflictID, &task.EvidenceID, &task.GlobalUserID, &task.Handle,
			&task.NodeID, &task.NodeRole, &task.SourceKind, &task.SourceSnapshotID,
			&task.SourceManifestSHA256, &task.Attempt,
		); err != nil {
			return nil, fmt.Errorf("scan conflict evidence task: %w", err)
		}
		tasks = append(tasks, task)
	}
	return tasks, rows.Err()
}

func (s *Store) ClaimConflictEvidenceTask(
	ctx context.Context,
	evidenceID, workerID string,
	now time.Time,
	leaseTTL time.Duration,
) (int, bool, error) {
	if evidenceID == "" || workerID == "" || leaseTTL <= 0 {
		return 0, false, ErrConflictEvidenceState
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var conflictID string
	var attempt int
	err = tx.QueryRowContext(ctx, `
		UPDATE replica_conflict_sources source
		SET evidence_state='capturing',evidence_attempt=evidence_attempt+1,
		  evidence_lease_owner=$2,evidence_lease_until=$4,evidence_error_code=NULL,
		  evidence_next_attempt_at=NULL,evidence_updated_at=$3
		FROM replica_conflicts conflict
		WHERE source.evidence_id=$1 AND conflict.id=source.conflict_id
		  AND conflict.state IN ('detected','inspecting')
		  AND (source.evidence_state='pending'
		    OR (source.evidence_state='retry_wait' AND source.evidence_next_attempt_at<=$3)
		    OR (source.evidence_state='capturing' AND source.evidence_lease_until<=$3)
		    OR (source.evidence_state='failed' AND source.evidence_updated_at<=$4))
		RETURNING source.conflict_id::text,source.evidence_attempt`, evidenceID, workerID, now, now.Add(leaseTTL), now.Add(-ConflictEvidenceFailedRearmWindow)).
		Scan(&conflictID, &attempt)
	if err == sql.ErrNoRows {
		if err := tx.Commit(); err != nil {
			return 0, false, err
		}
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE replica_conflicts SET state='inspecting',version=version+1,updated_at=$2
		WHERE id=$1 AND state='detected'`, conflictID, now); err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return attempt, true, nil
}

func (s *Store) RetryConflictEvidenceTask(
	ctx context.Context,
	evidenceID, workerID, errorCode string,
	attempt int,
	now time.Time,
) error {
	if evidenceID == "" || workerID == "" || errorCode == "" || attempt <= 0 {
		return ErrConflictEvidenceState
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	state := "retry_wait"
	var next any = now.Add(time.Duration(1<<min(attempt, 8)) * time.Second)
	if attempt >= 5 {
		state = "failed"
		next = nil
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE replica_conflict_sources
		SET evidence_state=$3,evidence_error_code=$4,evidence_next_attempt_at=$5,
		  evidence_lease_owner=NULL,evidence_lease_until=NULL,evidence_updated_at=$6
		WHERE evidence_id=$1 AND evidence_lease_owner=$2 AND evidence_state='capturing'`,
		evidenceID, workerID, state, errorCode, next, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflictEvidenceState
	}
	return nil
}

func (s *Store) CompleteConflictEvidence(ctx context.Context, p CompleteConflictEvidenceParams) error {
	if p.ConflictID == "" || p.EvidenceID == "" || p.WorkerID == "" ||
		len(p.EntriesSHA256) != 32 || p.FileCount < 0 || p.TotalBytes < 0 ||
		(p.CaptureBasis != "verified_archive" && p.CaptureBasis != "frozen_live") || len(p.Pages) == 0 ||
		len(p.CommandOperationIDs) != len(p.Pages) {
		return ErrConflictEvidenceState
	}
	var entries int64
	for index, page := range p.Pages {
		if page.PageIndex != index || page.EntryCount < 0 || page.EncryptedPayload == "" ||
			len(page.PlaintextSHA256) != 32 {
			return ErrConflictEvidenceState
		}
		entries += int64(page.EntryCount)
	}
	if entries != p.FileCount {
		return ErrConflictEvidenceState
	}
	if p.FileCount == 0 && (len(p.Pages) != 1 || p.Pages[0].EntryCount != 0) {
		return ErrConflictEvidenceState
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var userID int64
	err = tx.QueryRowContext(ctx, `
		SELECT conflict.user_id
		FROM replica_conflict_sources source
		JOIN replica_conflicts conflict ON conflict.id=source.conflict_id
		WHERE conflict.id=$1 AND source.evidence_id=$2
		  AND source.evidence_state='capturing' AND source.evidence_lease_owner=$3
		  AND conflict.state='inspecting'
		FOR UPDATE OF source,conflict`, p.ConflictID, p.EvidenceID, p.WorkerID).Scan(&userID)
	if err == sql.ErrNoRows {
		return ErrConflictEvidenceState
	}
	if err != nil {
		return err
	}
	for _, page := range p.Pages {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO replica_conflict_manifest_pages (
			  evidence_id,page_index,entry_count,encrypted_payload,plaintext_sha256,created_at
			) VALUES ($1,$2,$3,$4,$5,$6)`, p.EvidenceID, page.PageIndex,
			page.EntryCount, page.EncryptedPayload, page.PlaintextSHA256, p.Now); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE replica_conflict_sources
		SET evidence_state='ready',evidence_capture_basis=$3,evidence_entries_sha256=$4,
		  evidence_file_count=$5,evidence_total_bytes=$6,evidence_error_code=NULL,
		  evidence_lease_owner=NULL,evidence_lease_until=NULL,evidence_updated_at=$7
		WHERE evidence_id=$1 AND evidence_lease_owner=$2 AND evidence_state='capturing'`,
		p.EvidenceID, p.WorkerID, p.CaptureBasis, p.EntriesSHA256,
		p.FileCount, p.TotalBytes, p.Now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrConflictEvidenceState
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE replica_conflicts conflict
		SET state=CASE WHEN NOT EXISTS (
		    SELECT 1 FROM replica_conflict_sources source
		    WHERE source.conflict_id=conflict.id AND source.evidence_state<>'ready'
		  ) THEN 'awaiting_decision' ELSE 'inspecting' END,
		  version=version+1,updated_at=$2
		WHERE conflict.id=$1`, p.ConflictID, p.Now); err != nil {
		return err
	}
	redactedResult := []byte(`{"ok":true,"code":"evidence_ingested"}`)
	redactedDigest := sha256.Sum256(redactedResult)
	redacted, err := tx.ExecContext(ctx, `
		UPDATE agent_commands
		SET result_summary=$2,result_digest=$3,updated_at=$4
		WHERE operation_id=ANY($1) AND state='succeeded'`,
		pq.Array(p.CommandOperationIDs), redactedResult, redactedDigest[:], p.Now)
	if err != nil {
		return err
	}
	if rows, err := redacted.RowsAffected(); err != nil || rows != int64(len(p.CommandOperationIDs)) {
		if err != nil {
			return err
		}
		return ErrConflictEvidenceState
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  occurred_at,actor_type,actor_id,action,target_type,target_id,outcome,detail
		) VALUES ($5,'system',NULL,'conflict-evidence-captured','user',$1::text,'succeeded',
		  jsonb_build_object('conflict_id',$2::text,'evidence_id',$3::text,'file_count',$4::bigint))`,
		userID, p.ConflictID, p.EvidenceID, p.FileCount, p.Now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) LoadConflictEvidencePages(
	ctx context.Context,
	conflictID string,
	nodeID int64,
) ([]string, error) {
	if conflictID == "" || nodeID <= 0 {
		return nil, ErrConflictEvidenceState
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT page.encrypted_payload
		FROM replica_conflict_sources source
		JOIN replica_conflicts conflict ON conflict.id=source.conflict_id
		JOIN replica_conflict_manifest_pages page ON page.evidence_id=source.evidence_id
		WHERE conflict.id=$1 AND source.node_id=$2 AND source.evidence_state='ready'
		ORDER BY page.page_index`, conflictID, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pages []string
	for rows.Next() {
		var ciphertext string
		if err := rows.Scan(&ciphertext); err != nil {
			return nil, err
		}
		pages = append(pages, ciphertext)
	}
	return pages, rows.Err()
}
