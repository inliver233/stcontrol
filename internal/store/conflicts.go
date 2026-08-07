package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type ReplicaConflict struct {
	ID                   string                  `json:"id"`
	State                string                  `json:"state"`
	ProtectionVersion    int64                   `json:"protection_version"`
	ControllerGeneration sql.NullInt64           `json:"-"`
	Version              int64                   `json:"version"`
	DetectedAt           time.Time               `json:"detected_at"`
	UpdatedAt            time.Time               `json:"updated_at"`
	Sources              []ReplicaConflictSource `json:"sources"`
}

type ReplicaConflictSource struct {
	NodeID             int64          `json:"node_id"`
	NodeName           string         `json:"node_name"`
	NodeRole           string         `json:"node_role"`
	SnapshotID         sql.NullString `json:"-"`
	SourceKind         string         `json:"source_kind"`
	ReplicaState       string         `json:"replica_state"`
	IsAuthoritative    bool           `json:"is_authoritative"`
	ManifestSHA256     []byte         `json:"-"`
	FileCount          sql.NullInt64  `json:"-"`
	TotalBytes         sql.NullInt64  `json:"-"`
	PublishedAt        sql.NullTime   `json:"-"`
	LegacyDataVersion  sql.NullInt64  `json:"-"`
	LegacyChecksum     sql.NullString `json:"-"`
	CapturedAt         time.Time      `json:"captured_at"`
	EvidenceID         string         `json:"-"`
	EvidenceState      string         `json:"evidence_state"`
	EvidenceBasis      sql.NullString `json:"-"`
	EvidenceSHA256     []byte         `json:"-"`
	EvidenceFileCount  sql.NullInt64  `json:"-"`
	EvidenceTotalBytes sql.NullInt64  `json:"-"`
}

type PublicReplicaConflictSource struct {
	NodeID              int64      `json:"node_id"`
	NodeName            string     `json:"node_name"`
	NodeRole            string     `json:"node_role"`
	SourceKind          string     `json:"source_kind"`
	ReplicaState        string     `json:"replica_state"`
	IsAuthoritative     bool       `json:"is_authoritative"`
	SourceSnapshotState string     `json:"source_snapshot_state"`
	EvidenceState       string     `json:"evidence_state"`
	CaptureBasis        string     `json:"capture_basis,omitempty"`
	FileCount           *int64     `json:"file_count,omitempty"`
	TotalBytes          *int64     `json:"total_bytes,omitempty"`
	PublishedAt         *time.Time `json:"published_at,omitempty"`
	LegacyDataVersion   *int64     `json:"legacy_data_version,omitempty"`
}

func (source ReplicaConflictSource) Public() PublicReplicaConflictSource {
	out := PublicReplicaConflictSource{
		NodeID: source.NodeID, NodeName: source.NodeName, NodeRole: source.NodeRole,
		SourceKind: source.SourceKind, ReplicaState: source.ReplicaState,
		IsAuthoritative: source.IsAuthoritative, SourceSnapshotState: "live_capture_required",
		EvidenceState: source.EvidenceState,
	}
	if source.SnapshotID.Valid && len(source.ManifestSHA256) == 32 {
		out.SourceSnapshotState = "immutable"
	}
	if source.EvidenceBasis.Valid {
		out.CaptureBasis = source.EvidenceBasis.String
	}
	if source.EvidenceFileCount.Valid {
		value := source.EvidenceFileCount.Int64
		out.FileCount = &value
	}
	if source.EvidenceTotalBytes.Valid {
		value := source.EvidenceTotalBytes.Int64
		out.TotalBytes = &value
	}
	if source.PublishedAt.Valid {
		value := source.PublishedAt.Time
		out.PublishedAt = &value
	}
	if source.LegacyDataVersion.Valid {
		value := source.LegacyDataVersion.Int64
		out.LegacyDataVersion = &value
	}
	return out
}

// GetOpenReplicaConflict returns only the source facts frozen when the open
// case was detected. Later replica changes cannot silently rewrite evidence.
func (s *Store) GetOpenReplicaConflict(ctx context.Context, globalUserID int64) (*ReplicaConflict, error) {
	if globalUserID <= 0 {
		return nil, fmt.Errorf("invalid conflict user")
	}
	var out ReplicaConflict
	err := s.DB.QueryRowContext(ctx, `
		SELECT id::text,state,protection_version,controller_generation,version,
		  detected_at,updated_at
		FROM replica_conflicts
		WHERE user_id=$1 AND state NOT IN ('resolved','failed')`, globalUserID).
		Scan(&out.ID, &out.State, &out.ProtectionVersion, &out.ControllerGeneration,
			&out.Version, &out.DetectedAt, &out.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get replica conflict: %w", err)
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT node_id,node_name,node_role,snapshot_id::text,source_kind,replica_state,
		  is_authoritative,manifest_sha256,file_count,total_bytes,published_at,
		  legacy_data_version,legacy_checksum,captured_at,evidence_id::text,evidence_state,
		  evidence_capture_basis,evidence_entries_sha256,evidence_file_count,evidence_total_bytes
		FROM replica_conflict_sources WHERE conflict_id=$1
		ORDER BY is_authoritative DESC,published_at DESC NULLS LAST,node_id`, out.ID)
	if err != nil {
		return nil, fmt.Errorf("list replica conflict sources: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var source ReplicaConflictSource
		if err := rows.Scan(
			&source.NodeID, &source.NodeName, &source.NodeRole, &source.SnapshotID,
			&source.SourceKind, &source.ReplicaState, &source.IsAuthoritative,
			&source.ManifestSHA256, &source.FileCount, &source.TotalBytes,
			&source.PublishedAt, &source.LegacyDataVersion, &source.LegacyChecksum,
			&source.CapturedAt, &source.EvidenceID, &source.EvidenceState,
			&source.EvidenceBasis, &source.EvidenceSHA256, &source.EvidenceFileCount,
			&source.EvidenceTotalBytes,
		); err != nil {
			return nil, fmt.Errorf("scan replica conflict source: %w", err)
		}
		out.Sources = append(out.Sources, source)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list replica conflict sources: %w", err)
	}
	return &out, nil
}
