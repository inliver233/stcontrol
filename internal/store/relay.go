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
	ErrInvalidRelayTransfer = errors.New("invalid relay transfer input")
	ErrRelayTransferState   = errors.New("relay transfer state conflict")
)

type RelayTransfer struct {
	ID                   string
	WorkflowID           string
	SnapshotID           string
	SourceNodeID         int64
	TargetNodeID         int64
	Attempt              int
	State                string
	ControllerGeneration int64
	MaxCiphertextBytes   int64
	PlaintextBytes       sql.NullInt64
	CiphertextBytes      sql.NullInt64
	ArchiveSHA256        []byte
	CiphertextSHA256     []byte
	StoragePath          sql.NullString
	ExpiresAt            time.Time
}

type CreateRelayTransferParams struct {
	ID                 string
	WorkflowID         string
	SnapshotID         string
	SourceNodeID       int64
	TargetNodeID       int64
	Attempt            int
	UploadTokenHash    []byte
	DownloadTokenHash  []byte
	MaxCiphertextBytes int64
	ExpiresAt          time.Time
	Now                time.Time
}

func (s *Store) CreateRelayTransfer(ctx context.Context, p CreateRelayTransferParams) (*RelayTransfer, error) {
	if p.ID == "" || p.WorkflowID == "" || p.SnapshotID == "" || p.SourceNodeID <= 0 ||
		p.TargetNodeID <= 0 || p.SourceNodeID == p.TargetNodeID || p.Attempt < 0 ||
		len(p.UploadTokenHash) != 32 || len(p.DownloadTokenHash) != 32 ||
		p.MaxCiphertextBytes <= 0 {
		return nil, ErrInvalidRelayTransfer
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	if !p.ExpiresAt.After(p.Now) {
		return nil, ErrInvalidRelayTransfer
	}
	var out RelayTransfer
	err := scanRelayTransfer(s.DB.QueryRowContext(ctx, `
		INSERT INTO relay_transfers (
		  id,workflow_id,snapshot_id,source_node_id,target_node_id,attempt,state,
		  upload_token_hash,download_token_hash,controller_generation,
		  max_ciphertext_bytes,expires_at,created_at,updated_at
		)
		SELECT $1,$2,$3,$4,$5,$6,'prepared',$7,$8,workflow.controller_generation,
		  $9,$10,$11,$11
		FROM workflows workflow
		JOIN snapshot_manifests snapshot ON snapshot.workflow_id=workflow.id AND snapshot.id=$3
		JOIN controller_epochs epoch
		  ON epoch.generation=workflow.controller_generation AND epoch.state='active'
		WHERE workflow.id=$2 AND workflow.source_node_id=$4 AND workflow.target_node_id=$5
		  AND workflow.attempt=$6 AND workflow.transfer_mode='relay'
		  AND workflow.state NOT IN ('succeeded','cancelled','failed')
		ON CONFLICT (workflow_id,attempt) DO NOTHING
		RETURNING id::text,workflow_id::text,snapshot_id::text,source_node_id,target_node_id,
		  attempt,state,controller_generation,max_ciphertext_bytes,plaintext_bytes,
		  ciphertext_bytes,archive_sha256,ciphertext_sha256,storage_path,expires_at`,
		p.ID, p.WorkflowID, p.SnapshotID, p.SourceNodeID, p.TargetNodeID, p.Attempt,
		p.UploadTokenHash, p.DownloadTokenHash, p.MaxCiphertextBytes, p.ExpiresAt, p.Now), &out)
	if err == nil {
		return &out, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("create relay transfer: %w", err)
	}
	var uploadHash, downloadHash []byte
	err = scanRelayTransferAndHashes(s.DB.QueryRowContext(ctx, `
		SELECT id::text,workflow_id::text,snapshot_id::text,source_node_id,target_node_id,
		  attempt,state,controller_generation,max_ciphertext_bytes,plaintext_bytes,
		  ciphertext_bytes,archive_sha256,ciphertext_sha256,storage_path,expires_at,
		  upload_token_hash,download_token_hash
		FROM relay_transfers WHERE workflow_id=$1 AND attempt=$2`, p.WorkflowID, p.Attempt),
		&out, &uploadHash, &downloadHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrRelayTransferState
		}
		return nil, err
	}
	if out.ID != p.ID || out.SnapshotID != p.SnapshotID || out.SourceNodeID != p.SourceNodeID ||
		out.TargetNodeID != p.TargetNodeID || out.MaxCiphertextBytes != p.MaxCiphertextBytes ||
		!bytes.Equal(uploadHash, p.UploadTokenHash) ||
		!bytes.Equal(downloadHash, p.DownloadTokenHash) {
		return nil, ErrRelayTransferState
	}
	return &out, nil
}

// rowScanner keeps the long relay projection identical across QueryRow calls.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanRelayTransfer(row rowScanner, out *RelayTransfer) error {
	return row.Scan(
		&out.ID, &out.WorkflowID, &out.SnapshotID, &out.SourceNodeID, &out.TargetNodeID,
		&out.Attempt, &out.State, &out.ControllerGeneration, &out.MaxCiphertextBytes,
		&out.PlaintextBytes, &out.CiphertextBytes, &out.ArchiveSHA256,
		&out.CiphertextSHA256, &out.StoragePath, &out.ExpiresAt,
	)
}

func scanRelayTransferAndHashes(row rowScanner, out *RelayTransfer, uploadHash, downloadHash *[]byte) error {
	return row.Scan(
		&out.ID, &out.WorkflowID, &out.SnapshotID, &out.SourceNodeID, &out.TargetNodeID,
		&out.Attempt, &out.State, &out.ControllerGeneration, &out.MaxCiphertextBytes,
		&out.PlaintextBytes, &out.CiphertextBytes, &out.ArchiveSHA256,
		&out.CiphertextSHA256, &out.StoragePath, &out.ExpiresAt, uploadHash, downloadHash,
	)
}

func (s *Store) ClaimRelayUpload(
	ctx context.Context,
	id string,
	uploadTokenHash []byte,
	plaintextBytes, ciphertextBytes int64,
	archiveSHA256 []byte,
	now time.Time,
	leaseTTL time.Duration,
) (*RelayTransfer, error) {
	if id == "" || len(uploadTokenHash) != 32 || plaintextBytes <= 0 || ciphertextBytes <= 0 ||
		len(archiveSHA256) != 32 || leaseTTL <= 0 {
		return nil, ErrInvalidRelayTransfer
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var out RelayTransfer
	row := s.DB.QueryRowContext(ctx, `
		UPDATE relay_transfers relay SET state='uploading',plaintext_bytes=$3,
		  archive_sha256=$5,upload_lease_until=$7,updated_at=$6
		FROM controller_epochs epoch
		WHERE relay.id=$1::uuid AND relay.upload_token_hash=$2
		  AND relay.controller_generation=epoch.generation AND epoch.state='active'
		  AND relay.expires_at>$6 AND $4<=relay.max_ciphertext_bytes
		  AND (relay.state='prepared' OR (relay.state='uploading' AND relay.upload_lease_until<=$6))
		  AND (relay.plaintext_bytes IS NULL OR relay.plaintext_bytes=$3)
		  AND (relay.archive_sha256 IS NULL OR relay.archive_sha256=$5)
		RETURNING relay.id::text,relay.workflow_id::text,relay.snapshot_id::text,
		  relay.source_node_id,relay.target_node_id,relay.attempt,relay.state,
		  relay.controller_generation,relay.max_ciphertext_bytes,relay.plaintext_bytes,
		  relay.ciphertext_bytes,relay.archive_sha256,relay.ciphertext_sha256,
		  relay.storage_path,relay.expires_at`,
		id, uploadTokenHash, plaintextBytes, ciphertextBytes, archiveSHA256, now, now.Add(leaseTTL))
	err := scanRelayTransfer(row, &out)
	if err == nil {
		return &out, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	// A response may be lost after the ciphertext was durably published. An
	// exact retry receives the stored fact rather than opening a second spool.
	err = scanRelayTransfer(s.DB.QueryRowContext(ctx, `
		SELECT relay.id::text,relay.workflow_id::text,relay.snapshot_id::text,
		  relay.source_node_id,relay.target_node_id,relay.attempt,relay.state,
		  relay.controller_generation,relay.max_ciphertext_bytes,relay.plaintext_bytes,
		  relay.ciphertext_bytes,relay.archive_sha256,relay.ciphertext_sha256,
		  relay.storage_path,relay.expires_at
		FROM relay_transfers relay JOIN controller_epochs epoch
		  ON epoch.generation=relay.controller_generation AND epoch.state='active'
		WHERE relay.id=$1::uuid AND relay.upload_token_hash=$2
		  AND relay.state IN ('stored','downloading','consumed') AND relay.expires_at>$6
		  AND relay.plaintext_bytes=$3 AND relay.ciphertext_bytes=$4 AND relay.archive_sha256=$5`,
		id, uploadTokenHash, plaintextBytes, ciphertextBytes, archiveSHA256, now), &out)
	if err == sql.ErrNoRows {
		return nil, ErrRelayTransferState
	}
	return &out, err
}

func (s *Store) CompleteRelayUpload(
	ctx context.Context,
	id string,
	uploadTokenHash, ciphertextSHA256 []byte,
	ciphertextBytes int64,
	storagePath string,
	now time.Time,
) error {
	if id == "" || len(uploadTokenHash) != 32 || len(ciphertextSHA256) != 32 ||
		ciphertextBytes <= 0 || storagePath == "" {
		return ErrInvalidRelayTransfer
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE relay_transfers relay SET state='stored',ciphertext_bytes=$3,ciphertext_sha256=$4,
		  storage_path=$5,upload_lease_until=NULL,updated_at=$6
		FROM controller_epochs epoch
		WHERE relay.id=$1::uuid AND relay.upload_token_hash=$2 AND relay.state='uploading'
		  AND relay.controller_generation=epoch.generation AND epoch.state='active'
		  AND relay.expires_at>$6 AND relay.upload_lease_until>$6
		  AND relay.ciphertext_bytes IS NULL`,
		id, uploadTokenHash, ciphertextBytes, ciphertextSHA256, storagePath, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrRelayTransferState
	}
	return nil
}

func (s *Store) ReleaseRelayUpload(ctx context.Context, id string, uploadTokenHash []byte, now time.Time) error {
	if id == "" || len(uploadTokenHash) != 32 {
		return ErrInvalidRelayTransfer
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE relay_transfers relay SET state='prepared',plaintext_bytes=NULL,archive_sha256=NULL,
		  upload_lease_until=NULL,updated_at=$3
		FROM controller_epochs epoch
		WHERE relay.id=$1::uuid AND relay.upload_token_hash=$2 AND relay.state='uploading'
		  AND relay.controller_generation=epoch.generation AND epoch.state='active'`, id, uploadTokenHash, now)
	return err
}

func (s *Store) ClaimRelayDownload(
	ctx context.Context,
	id string,
	downloadTokenHash []byte,
	now time.Time,
	leaseTTL time.Duration,
) (*RelayTransfer, error) {
	if id == "" || len(downloadTokenHash) != 32 || leaseTTL <= 0 {
		return nil, ErrInvalidRelayTransfer
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var out RelayTransfer
	err := scanRelayTransfer(s.DB.QueryRowContext(ctx, `
		UPDATE relay_transfers relay SET state='downloading',download_lease_until=$4,updated_at=$3
		FROM controller_epochs epoch
		WHERE relay.id=$1::uuid AND relay.download_token_hash=$2
		  AND relay.controller_generation=epoch.generation AND epoch.state='active'
		  AND relay.expires_at>$3
		  AND (relay.state='stored' OR (relay.state='downloading' AND relay.download_lease_until<=$3))
		RETURNING relay.id::text,relay.workflow_id::text,relay.snapshot_id::text,
		  relay.source_node_id,relay.target_node_id,relay.attempt,relay.state,
		  relay.controller_generation,relay.max_ciphertext_bytes,relay.plaintext_bytes,
		  relay.ciphertext_bytes,relay.archive_sha256,relay.ciphertext_sha256,
		  relay.storage_path,relay.expires_at`, id, downloadTokenHash, now, now.Add(leaseTTL)), &out)
	if err == sql.ErrNoRows {
		return nil, ErrRelayTransferState
	}
	return &out, err
}

func (s *Store) ReleaseRelayDownload(ctx context.Context, id string, downloadTokenHash []byte, now time.Time) error {
	if id == "" || len(downloadTokenHash) != 32 {
		return ErrInvalidRelayTransfer
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE relay_transfers relay SET state='stored',download_lease_until=NULL,updated_at=$3
		FROM controller_epochs epoch
		WHERE relay.id=$1::uuid AND relay.download_token_hash=$2 AND relay.state='downloading'
		  AND relay.controller_generation=epoch.generation AND epoch.state='active'`, id, downloadTokenHash, now)
	return err
}

func (s *Store) CompleteRelayDownload(
	ctx context.Context,
	id string,
	downloadTokenHash []byte,
	now time.Time,
) (string, error) {
	if id == "" || len(downloadTokenHash) != 32 {
		return "", ErrInvalidRelayTransfer
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var path string
	err := s.DB.QueryRowContext(ctx, `
		UPDATE relay_transfers relay SET state='consumed',download_lease_until=NULL,
		  updated_at=$3,consumed_at=$3
		FROM controller_epochs epoch
		WHERE relay.id=$1::uuid AND relay.download_token_hash=$2 AND relay.state='downloading'
		  AND relay.controller_generation=epoch.generation AND epoch.state='active'
		  AND relay.expires_at>$3 AND relay.download_lease_until>$3
		RETURNING relay.storage_path`, id, downloadTokenHash, now).Scan(&path)
	if err == sql.ErrNoRows {
		return "", ErrRelayTransferState
	}
	return path, err
}

type ExpiredRelayTransfer struct {
	ID          string
	StoragePath sql.NullString
}

func (s *Store) ExpireRelayTransfers(ctx context.Context, now time.Time, limit int) ([]ExpiredRelayTransfer, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		SELECT id::text,storage_path FROM relay_transfers
		WHERE expires_at<=$1 AND state NOT IN ('consumed','expired','failed')
		ORDER BY expires_at FOR UPDATE SKIP LOCKED LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	var expired []ExpiredRelayTransfer
	for rows.Next() {
		var item ExpiredRelayTransfer
		if err := rows.Scan(&item.ID, &item.StoragePath); err != nil {
			_ = rows.Close()
			return nil, err
		}
		expired = append(expired, item)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, item := range expired {
		if _, err := tx.ExecContext(ctx, `
			UPDATE relay_transfers SET state='expired',upload_lease_until=NULL,
			  download_lease_until=NULL,updated_at=$2 WHERE id=$1::uuid`, item.ID, now); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return expired, nil
}
