package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidConflictResolution = errors.New("invalid conflict resolution")
	ErrConflictResolutionState   = errors.New("conflict resolution state conflict")
	ErrConflictResolutionReplay  = errors.New("conflict resolution operation conflict")
)

type ConflictResolutionDecision struct {
	Path         string
	SourceNodeID int64
	Action       string
}

type ConflictResolutionTransferInput struct {
	EvidenceID     string
	SourceNodeID   int64
	CapabilityID   string
	CapabilityHash []byte
	ExpiresAt      time.Time
}

type CreateConflictResolutionParams struct {
	OperationID             string
	RequestDigest           []byte
	WorkflowID              string
	ConflictID              string
	ResultSnapshotID        string
	GlobalUserID            int64
	BaseNodeID              int64
	ExpectedConflictVersion int64
	DefaultAction           string
	Decisions               []ConflictResolutionDecision
	Transfers               []ConflictResolutionTransferInput
	Now                     time.Time
}

type ConflictResolutionSource struct {
	NodeID           int64
	NodeRole         string
	EvidenceID       string
	EntriesSHA256    []byte
	TransferState    string
	CapabilityID     string
	CapabilityHash   []byte
	CapabilityExpiry time.Time
}

type ConflictResolutionExecution struct {
	OperationID          string
	RequestDigest        []byte
	WorkflowID           string
	State                string
	Attempt              int
	ConflictID           string
	ConflictVersion      int64
	GlobalUserID         int64
	LegacyUserID         int64
	Handle               string
	BaseNodeID           int64
	ResultSnapshotID     string
	ActivityEpoch        int64
	ControllerGeneration int64
	DefaultAction        string
	Decisions            []ConflictResolutionDecision
	Sources              []ConflictResolutionSource
}

type ConflictResolutionStatus struct {
	OperationID  string `json:"operation_id"`
	State        string `json:"state"`
	BaseNodeID   int64  `json:"base_node_id"`
	BaseNodeName string `json:"base_node_name"`
	ErrorSummary string `json:"error,omitempty"`
}

type CompleteConflictResolutionParams struct {
	WorkflowID       string
	OperationID      string
	ConflictID       string
	ResultSnapshotID string
	EntriesSHA256    []byte
	FileCount        int64
	TotalBytes       int64
	Now              time.Time
}

func (s *Store) CreateConflictResolution(
	ctx context.Context,
	p CreateConflictResolutionParams,
) (*ConflictResolutionExecution, error) {
	if p.OperationID == "" || len(p.RequestDigest) != 32 || p.WorkflowID == "" ||
		p.ConflictID == "" || p.ResultSnapshotID == "" || p.GlobalUserID <= 0 ||
		p.BaseNodeID <= 0 || p.ExpectedConflictVersion <= 0 || len(p.Decisions) > 100000 ||
		(p.DefaultAction != "use_base" && p.DefaultAction != "preserve_all_originals") {
		return nil, ErrInvalidConflictResolution
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	seenPaths := make(map[string]bool, len(p.Decisions))
	for _, decision := range p.Decisions {
		if decision.Path == "" || len(decision.Path) > 4096 || decision.SourceNodeID <= 0 ||
			(decision.Action != "use_source" && decision.Action != "preserve_both") || seenPaths[decision.Path] {
			return nil, ErrInvalidConflictResolution
		}
		seenPaths[decision.Path] = true
	}
	seenEvidence := make(map[string]bool, len(p.Transfers))
	for _, transfer := range p.Transfers {
		if transfer.EvidenceID == "" || transfer.SourceNodeID <= 0 || transfer.SourceNodeID == p.BaseNodeID ||
			transfer.CapabilityID == "" || len(transfer.CapabilityHash) != 32 ||
			!transfer.ExpiresAt.After(p.Now) || seenEvidence[transfer.EvidenceID] {
			return nil, ErrInvalidConflictResolution
		}
		seenEvidence[transfer.EvidenceID] = true
	}

	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if replay, found, err := getConflictResolutionReplay(ctx, tx, p); err != nil {
		return nil, err
	} else if found {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return replay, nil
	}
	if err := lockGlobalUser(ctx, tx, p.GlobalUserID); err != nil {
		return nil, err
	}
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&generation); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNoActiveController
		}
		return nil, err
	}
	var legacyUserID, conflictVersion, activityEpoch int64
	var handle string
	err = tx.QueryRowContext(ctx, `
		SELECT global_user.legacy_user_id,legacy.username,conflict.version,
		  COALESCE(lease.activity_epoch,1)
		FROM replica_conflicts conflict
		JOIN global_users global_user ON global_user.id=conflict.user_id AND global_user.status='conflict'
		JOIN users legacy ON legacy.id=global_user.legacy_user_id AND legacy.status='conflict'
		LEFT JOIN user_activity_leases lease ON lease.user_id=global_user.id
		WHERE conflict.id=$1 AND conflict.user_id=$2 AND conflict.state='awaiting_decision'
		  AND conflict.version=$3
		  AND NOT EXISTS (SELECT 1 FROM replica_conflict_sources source
		    WHERE source.conflict_id=conflict.id AND source.evidence_state<>'ready')
		  AND (lease.user_id IS NULL OR (lease.state='conflict'
		    AND lease.in_flight_reads=0 AND lease.in_flight_writes=0))
		FOR UPDATE OF conflict,global_user,legacy`, p.ConflictID, p.GlobalUserID, p.ExpectedConflictVersion).
		Scan(&legacyUserID, &handle, &conflictVersion, &activityEpoch)
	if err == sql.ErrNoRows {
		return nil, ErrConflictResolutionState
	}
	if err != nil {
		return nil, err
	}
	var existingResolution bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM conflict_resolution_operations
		WHERE conflict_id=$1)`, p.ConflictID).Scan(&existingResolution); err != nil {
		return nil, err
	}
	if existingResolution {
		return nil, ErrConflictResolutionState
	}
	var baseEvidenceID string
	err = tx.QueryRowContext(ctx, `
		SELECT source.evidence_id::text FROM replica_conflict_sources source
		JOIN nodes node ON node.id=source.node_id
		WHERE source.conflict_id=$1 AND source.node_id=$2 AND source.evidence_state='ready'
		  AND source.node_role='compute' AND node.role='compute'
		  AND node.connectivity_state='online' AND node.operational_state='active'
		  AND node.compatibility_state='compatible' AND node.transfer_url<>''
		FOR SHARE OF source,node`, p.ConflictID, p.BaseNodeID).Scan(&baseEvidenceID)
	if err == sql.ErrNoRows {
		return nil, ErrConflictResolutionState
	}
	if err != nil {
		return nil, err
	}
	var sourceCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM replica_conflict_sources WHERE conflict_id=$1`, p.ConflictID).Scan(&sourceCount); err != nil {
		return nil, err
	}
	if sourceCount < 2 || len(p.Transfers) != sourceCount-1 {
		return nil, ErrConflictResolutionState
	}
	for _, transfer := range p.Transfers {
		var valid bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (SELECT 1 FROM replica_conflict_sources
			  WHERE conflict_id=$1 AND evidence_id=$2 AND node_id=$3
			    AND node_id<>$4 AND evidence_state='ready')`,
			p.ConflictID, transfer.EvidenceID, transfer.SourceNodeID, p.BaseNodeID).Scan(&valid); err != nil || !valid {
			if err != nil {
				return nil, err
			}
			return nil, ErrConflictResolutionState
		}
	}
	for _, decision := range p.Decisions {
		var sourceExists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM replica_conflict_sources
			WHERE conflict_id=$1 AND node_id=$2 AND evidence_state='ready')`,
			p.ConflictID, decision.SourceNodeID).Scan(&sourceExists); err != nil || !sourceExists {
			if err != nil {
				return nil, err
			}
			return nil, ErrConflictResolutionState
		}
	}
	var workflowActive bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM workflows WHERE user_id=$1
		AND workflow_type IN ('snapshot','restore','conflict_resolution')
		AND state NOT IN ('cancelled','failed','succeeded'))`, p.GlobalUserID).Scan(&workflowActive); err != nil {
		return nil, err
	}
	if workflowActive {
		return nil, ErrConflictResolutionState
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO workflows (
		  id,operation_id,workflow_type,state,user_id,source_node_id,target_node_id,
		  activity_epoch,controller_generation,created_at,updated_at
		) VALUES ($1,$2,'conflict_resolution','scheduled',$3,$4,$4,$5,$6,$7,$7)`,
		p.WorkflowID, p.OperationID, p.GlobalUserID, p.BaseNodeID, activityEpoch, generation, p.Now); err != nil {
		return nil, err
	}
	zeroDigest := make([]byte, 32)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO snapshot_manifests (
		  id,workflow_id,user_id,source_node_id,activity_epoch,format_version,
		  manifest_sha256,file_count,total_bytes,state,created_at
		) VALUES ($1,$2,$3,$4,$5,1,$6,0,0,'building',$7)`,
		p.ResultSnapshotID, p.WorkflowID, p.GlobalUserID, p.BaseNodeID, activityEpoch, zeroDigest, p.Now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO conflict_resolution_operations (
		  operation_id,request_digest,workflow_id,conflict_id,user_id,base_node_id,
		  result_snapshot_id,expected_conflict_version,default_action,decision_count,acknowledged_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		p.OperationID, p.RequestDigest, p.WorkflowID, p.ConflictID, p.GlobalUserID,
		p.BaseNodeID, p.ResultSnapshotID, p.ExpectedConflictVersion, p.DefaultAction,
		len(p.Decisions), p.Now); err != nil {
		return nil, err
	}
	for _, decision := range p.Decisions {
		pathDigest := sha256.Sum256([]byte(decision.Path))
		if _, err := tx.ExecContext(ctx, `INSERT INTO conflict_resolution_decisions
			(operation_id,path,path_sha256,source_node_id,action) VALUES ($1,$2,$3,$4,$5)`,
			p.OperationID, decision.Path, pathDigest[:], decision.SourceNodeID, decision.Action); err != nil {
			return nil, err
		}
	}
	for _, transfer := range p.Transfers {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO conflict_resolution_transfers (
			  operation_id,evidence_id,source_node_id,target_node_id,capability_id,
			  capability_hash,state,expires_at,updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,'prepared',$7,$8)`,
			p.OperationID, transfer.EvidenceID, transfer.SourceNodeID, p.BaseNodeID,
			transfer.CapabilityID, transfer.CapabilityHash, transfer.ExpiresAt, p.Now); err != nil {
			return nil, err
		}
	}
	for _, step := range []string{"transfer_evidence", "prepare", "apply_decisions", "publish", "finalize"} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO workflow_steps (workflow_id,step_name,state,updated_at)
			VALUES ($1,$2,'pending',$3)`, p.WorkflowID, step, p.Now); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE replica_conflicts
		SET state='resolving',version=version+1,updated_at=$2 WHERE id=$1`, p.ConflictID, p.Now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  occurred_at,actor_type,actor_id,action,target_type,target_id,operation_id,
		  controller_generation,input_digest,outcome,detail
		) VALUES ($8,'user',$1::text,'resolve-replica-conflict','global_user',$1::text,$2,
		  $3,$4,'scheduled',jsonb_build_object('conflict_id',$5,'base_node_id',$6,'decision_count',$7))`,
		p.GlobalUserID, p.OperationID, generation, p.RequestDigest, p.ConflictID,
		p.BaseNodeID, len(p.Decisions), p.Now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &ConflictResolutionExecution{
		OperationID: p.OperationID, RequestDigest: p.RequestDigest, WorkflowID: p.WorkflowID,
		State: "scheduled", ConflictID: p.ConflictID, ConflictVersion: conflictVersion + 1,
		GlobalUserID: p.GlobalUserID, LegacyUserID: legacyUserID, Handle: handle,
		BaseNodeID: p.BaseNodeID, ResultSnapshotID: p.ResultSnapshotID,
		ActivityEpoch: activityEpoch, ControllerGeneration: generation,
		DefaultAction: p.DefaultAction, Decisions: p.Decisions,
	}, nil
}

func getConflictResolutionReplay(
	ctx context.Context,
	tx *sql.Tx,
	p CreateConflictResolutionParams,
) (*ConflictResolutionExecution, bool, error) {
	var execution ConflictResolutionExecution
	var userID, baseNodeID int64
	err := tx.QueryRowContext(ctx, `
		SELECT operation.request_digest,operation.user_id,operation.base_node_id,
		  operation.workflow_id::text,workflow.state,workflow.attempt,operation.conflict_id::text,
		  conflict.version,global_user.legacy_user_id,legacy.username,
		  operation.result_snapshot_id::text,workflow.activity_epoch,workflow.controller_generation,
		  operation.default_action
		FROM conflict_resolution_operations operation
		JOIN workflows workflow ON workflow.id=operation.workflow_id
		JOIN replica_conflicts conflict ON conflict.id=operation.conflict_id
		JOIN global_users global_user ON global_user.id=operation.user_id
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		WHERE operation.operation_id=$1`, p.OperationID).Scan(
		&execution.RequestDigest, &userID, &baseNodeID, &execution.WorkflowID,
		&execution.State, &execution.Attempt, &execution.ConflictID, &execution.ConflictVersion,
		&execution.LegacyUserID, &execution.Handle, &execution.ResultSnapshotID,
		&execution.ActivityEpoch, &execution.ControllerGeneration, &execution.DefaultAction,
	)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if userID != p.GlobalUserID || baseNodeID != p.BaseNodeID || execution.ConflictID != p.ConflictID ||
		!bytes.Equal(execution.RequestDigest, p.RequestDigest) {
		return nil, false, ErrConflictResolutionReplay
	}
	execution.OperationID = p.OperationID
	execution.GlobalUserID = userID
	execution.BaseNodeID = baseNodeID
	return &execution, true, nil
}

func (s *Store) GetConflictResolutionExecution(ctx context.Context, workflowID string) (*ConflictResolutionExecution, error) {
	if workflowID == "" {
		return nil, ErrInvalidConflictResolution
	}
	var out ConflictResolutionExecution
	err := s.DB.QueryRowContext(ctx, `
		SELECT operation.operation_id::text,operation.request_digest,workflow.id::text,
		  workflow.state,workflow.attempt,operation.conflict_id::text,conflict.version,
		  workflow.user_id,global_user.legacy_user_id,legacy.username,operation.base_node_id,
		  operation.result_snapshot_id::text,workflow.activity_epoch,workflow.controller_generation,
		  operation.default_action
		FROM conflict_resolution_operations operation
		JOIN workflows workflow ON workflow.id=operation.workflow_id
		JOIN replica_conflicts conflict ON conflict.id=operation.conflict_id
		JOIN global_users global_user ON global_user.id=workflow.user_id
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		WHERE workflow.id=$1`, workflowID).Scan(
		&out.OperationID, &out.RequestDigest, &out.WorkflowID, &out.State, &out.Attempt,
		&out.ConflictID, &out.ConflictVersion, &out.GlobalUserID, &out.LegacyUserID,
		&out.Handle, &out.BaseNodeID, &out.ResultSnapshotID, &out.ActivityEpoch,
		&out.ControllerGeneration, &out.DefaultAction,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT source.node_id,source.node_role,source.evidence_id::text,source.evidence_entries_sha256,
		  COALESCE(transfer.state,''),COALESCE(transfer.capability_id::text,''),
		  transfer.capability_hash,transfer.expires_at
		FROM replica_conflict_sources source
		LEFT JOIN conflict_resolution_transfers transfer
		  ON transfer.operation_id=$2 AND transfer.evidence_id=source.evidence_id
		WHERE source.conflict_id=$1 ORDER BY source.node_id`, out.ConflictID, out.OperationID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var source ConflictResolutionSource
		var capabilityHash []byte
		var expiry sql.NullTime
		if err := rows.Scan(&source.NodeID, &source.NodeRole, &source.EvidenceID, &source.EntriesSHA256,
			&source.TransferState, &source.CapabilityID, &capabilityHash, &expiry); err != nil {
			_ = rows.Close()
			return nil, err
		}
		source.CapabilityHash = capabilityHash
		if expiry.Valid {
			source.CapabilityExpiry = expiry.Time
		}
		out.Sources = append(out.Sources, source)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	decisionRows, err := s.DB.QueryContext(ctx, `SELECT path,source_node_id,action
		FROM conflict_resolution_decisions WHERE operation_id=$1 ORDER BY path`, out.OperationID)
	if err != nil {
		return nil, err
	}
	defer decisionRows.Close()
	for decisionRows.Next() {
		var decision ConflictResolutionDecision
		if err := decisionRows.Scan(&decision.Path, &decision.SourceNodeID, &decision.Action); err != nil {
			return nil, err
		}
		out.Decisions = append(out.Decisions, decision)
	}
	return &out, decisionRows.Err()
}

func (s *Store) GetConflictResolutionExecutionByOperation(ctx context.Context, operationID string) (*ConflictResolutionExecution, error) {
	if operationID == "" {
		return nil, ErrInvalidConflictResolution
	}
	var workflowID string
	err := s.DB.QueryRowContext(ctx, `SELECT workflow_id::text FROM conflict_resolution_operations
		WHERE operation_id=$1`, operationID).Scan(&workflowID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.GetConflictResolutionExecution(ctx, workflowID)
}

func (s *Store) ListResumableConflictResolutionIDs(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id::text FROM workflows
		WHERE workflow_type='conflict_resolution'
		  AND state IN ('scheduled','transferring','publishing','retry_wait')
		  AND (next_attempt_at IS NULL OR next_attempt_at<=now())
		ORDER BY updated_at LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) ClaimConflictResolution(ctx context.Context, workflowID, workerID string, now time.Time, ttl time.Duration) (bool, error) {
	if workflowID == "" || workerID == "" || ttl <= 0 {
		return false, ErrInvalidConflictResolution
	}
	result, err := s.DB.ExecContext(ctx, `UPDATE workflows workflow
		SET lease_owner=$2,lease_until=$4,updated_at=$3 FROM controller_epochs epoch
		WHERE workflow.id=$1 AND workflow.workflow_type='conflict_resolution'
		  AND workflow.state NOT IN ('succeeded','cancelled','failed')
		  AND workflow.controller_generation=epoch.generation AND epoch.state='active'
		  AND (workflow.lease_until IS NULL OR workflow.lease_until<=$3)`,
		workflowID, workerID, now, now.Add(ttl))
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

func (s *Store) MarkConflictResolutionTransferComplete(
	ctx context.Context,
	operationID, evidenceID string,
	capabilityHash []byte,
	now time.Time,
) error {
	if operationID == "" || evidenceID == "" || len(capabilityHash) != 32 {
		return ErrInvalidConflictResolution
	}
	result, err := s.DB.ExecContext(ctx, `UPDATE conflict_resolution_transfers transfer
		SET state='consumed',completed_at=$4,updated_at=$4
		FROM conflict_resolution_operations operation,workflows workflow,controller_epochs epoch
		WHERE transfer.operation_id=$1 AND transfer.evidence_id=$2
		  AND transfer.capability_hash=$3 AND transfer.state='prepared'
		  AND operation.operation_id=transfer.operation_id AND workflow.id=operation.workflow_id
		  AND workflow.state NOT IN ('failed','cancelled','succeeded')
		  AND epoch.generation=workflow.controller_generation AND epoch.state='active'`,
		operationID, evidenceID, capabilityHash, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		var state string
		if err := s.DB.QueryRowContext(ctx, `SELECT state FROM conflict_resolution_transfers
			WHERE operation_id=$1 AND evidence_id=$2 AND capability_hash=$3`,
			operationID, evidenceID, capabilityHash).Scan(&state); err == nil && state == "consumed" {
			return nil
		}
		return ErrConflictResolutionState
	}
	return nil
}

func (s *Store) RotateConflictResolutionTransfer(
	ctx context.Context,
	operationID, evidenceID, capabilityID string,
	capabilityHash []byte,
	expiresAt, now time.Time,
) error {
	if operationID == "" || evidenceID == "" || capabilityID == "" || len(capabilityHash) != 32 || !expiresAt.After(now) {
		return ErrInvalidConflictResolution
	}
	result, err := s.DB.ExecContext(ctx, `UPDATE conflict_resolution_transfers transfer
		SET capability_id=$3,capability_hash=$4,state='prepared',attempt=attempt+1,
		  expires_at=$5,completed_at=NULL,updated_at=$6
		FROM conflict_resolution_operations operation,workflows workflow,controller_epochs epoch
		WHERE transfer.operation_id=$1 AND transfer.evidence_id=$2
		  AND operation.operation_id=transfer.operation_id AND workflow.id=operation.workflow_id
		  AND workflow.state NOT IN ('failed','cancelled','succeeded')
		  AND epoch.generation=workflow.controller_generation AND epoch.state='active'`,
		operationID, evidenceID, capabilityID, capabilityHash, expiresAt, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrConflictResolutionState
	}
	return nil
}

func (s *Store) MarkConflictResolutionPublishing(ctx context.Context, workflowID string, now time.Time) error {
	if workflowID == "" {
		return ErrInvalidConflictResolution
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE workflows workflow SET state='publishing',updated_at=$2
		FROM controller_epochs epoch WHERE workflow.id=$1 AND workflow.workflow_type='conflict_resolution'
		  AND workflow.state IN ('scheduled','transferring')
		  AND workflow.controller_generation=epoch.generation AND epoch.state='active'
		  AND NOT EXISTS (SELECT 1 FROM conflict_resolution_operations operation
		    JOIN conflict_resolution_transfers transfer ON transfer.operation_id=operation.operation_id
		    WHERE operation.workflow_id=workflow.id AND transfer.state<>'consumed')`, workflowID, now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		var state string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM workflows WHERE id=$1`, workflowID).Scan(&state); err == nil && state == "publishing" {
			return tx.Commit()
		}
		return ErrConflictResolutionState
	}
	if _, err := tx.ExecContext(ctx, `UPDATE workflow_steps SET state='succeeded',finished_at=$2,updated_at=$2
		WHERE workflow_id=$1 AND step_name IN ('transfer_evidence','prepare','apply_decisions')`, workflowID, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetConflictResolutionStatus(ctx context.Context, userID int64, operationID string) (*ConflictResolutionStatus, error) {
	if userID <= 0 || operationID == "" {
		return nil, ErrInvalidConflictResolution
	}
	var out ConflictResolutionStatus
	var errorSummary sql.NullString
	err := s.DB.QueryRowContext(ctx, `SELECT operation.operation_id::text,workflow.state,
		operation.base_node_id,node.name,workflow.error_summary
		FROM conflict_resolution_operations operation
		JOIN workflows workflow ON workflow.id=operation.workflow_id
		JOIN nodes node ON node.id=operation.base_node_id
		WHERE operation.user_id=$1 AND operation.operation_id=$2`, userID, operationID).Scan(
		&out.OperationID, &out.State, &out.BaseNodeID, &out.BaseNodeName, &errorSummary)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	out.ErrorSummary = errorSummary.String
	return &out, err
}

func (s *Store) CompleteConflictResolution(ctx context.Context, p CompleteConflictResolutionParams) error {
	if p.WorkflowID == "" || p.OperationID == "" || p.ConflictID == "" || p.ResultSnapshotID == "" ||
		len(p.EntriesSHA256) != 32 || p.FileCount < 0 || p.FileCount > 100000 ||
		p.TotalBytes < 0 || p.TotalBytes > int64(1<<40) {
		return ErrInvalidConflictResolution
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var state, globalStatus, legacyStatus, conflictState string
	var userID, legacyUserID, baseNodeID, generation, activityEpoch int64
	err = tx.QueryRowContext(ctx, `
		SELECT workflow.state,global_user.status,legacy.status,conflict.state,
		  workflow.user_id,global_user.legacy_user_id,operation.base_node_id,
		  workflow.controller_generation,workflow.activity_epoch
		FROM workflows workflow
		JOIN conflict_resolution_operations operation ON operation.workflow_id=workflow.id
		JOIN replica_conflicts conflict ON conflict.id=operation.conflict_id
		JOIN global_users global_user ON global_user.id=workflow.user_id
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		WHERE workflow.id=$1 AND operation.operation_id=$2 AND operation.conflict_id=$3
		  AND operation.result_snapshot_id=$4
		FOR UPDATE OF workflow,operation,conflict,global_user,legacy`,
		p.WorkflowID, p.OperationID, p.ConflictID, p.ResultSnapshotID).Scan(
		&state, &globalStatus, &legacyStatus, &conflictState, &userID, &legacyUserID,
		&baseNodeID, &generation, &activityEpoch)
	if err != nil {
		return err
	}
	if state == "succeeded" && conflictState == "resolved" {
		return tx.Commit()
	}
	if state != "publishing" || globalStatus != "conflict" || legacyStatus != "conflict" || conflictState != "resolving" {
		return ErrConflictResolutionState
	}
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&activeGeneration); err != nil {
		return err
	}
	if activeGeneration != generation {
		return ErrConflictResolutionState
	}
	var preservedSourceCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM replica_conflict_sources
		WHERE conflict_id=$1 AND evidence_state='ready'`, p.ConflictID).Scan(&preservedSourceCount); err != nil {
		return err
	}
	if preservedSourceCount < 2 {
		return ErrConflictResolutionState
	}
	result, err := tx.ExecContext(ctx, `UPDATE snapshot_manifests
		SET manifest_sha256=$3,file_count=$4,total_bytes=$5,state='immutable'
		WHERE id=$1 AND workflow_id=$2 AND state='building'`, p.ResultSnapshotID,
		p.WorkflowID, p.EntriesSHA256, p.FileCount, p.TotalBytes)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrConflictResolutionState
	}
	if _, err := tx.ExecContext(ctx, `UPDATE replica_copies SET is_authoritative=false,
		state=CASE WHEN state='conflict' THEN 'stale' ELSE state END,updated_at=$2 WHERE user_id=$1`, userID, p.Now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO replica_copies (
		id,user_id,node_id,snapshot_id,replica_kind,state,origin,is_authoritative,
		compatibility_state,published_at,verified_at,created_at,updated_at
		) VALUES (gen_random_uuid(),$1,$2,$3,'active','ready','recovery',true,'compatible',$4,$4,$4,$4)
		ON CONFLICT (user_id,node_id) DO UPDATE SET snapshot_id=EXCLUDED.snapshot_id,
		replica_kind='active',state='ready',origin='recovery',is_authoritative=true,
		compatibility_state='compatible',published_at=EXCLUDED.published_at,
		verified_at=EXCLUDED.verified_at,updated_at=EXCLUDED.updated_at`,
		userID, baseNodeID, p.ResultSnapshotID, p.Now); err != nil {
		return err
	}
	manifestHex := fmt.Sprintf("%x", p.EntriesSHA256)
	if _, err := tx.ExecContext(ctx, `UPDATE user_replicas SET state='stale' WHERE user_id=$1`, legacyUserID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_replicas
		(user_id,node_id,kind,data_version,state,last_sync_at,checksum,size_bytes)
		VALUES ($1,$2,'primary',1,'ready',$3,$4,$5)
		ON CONFLICT (user_id,node_id) DO UPDATE SET kind='primary',data_version=user_replicas.data_version+1,
		state='ready',last_sync_at=EXCLUDED.last_sync_at,checksum=EXCLUDED.checksum,size_bytes=EXCLUDED.size_bytes`,
		legacyUserID, baseNodeID, p.Now, manifestHex, p.TotalBytes); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET status='active',home_node_id=$2,
		data_version=data_version+1,checksum=$3 WHERE id=$1`, legacyUserID, baseNodeID, manifestHex); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE global_users SET status='active',updated_at=$2 WHERE id=$1`, userID, p.Now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_activity_leases SET writer_node_id=$2,state='ended',
		lease_expires_at=$3,in_flight_reads=0,in_flight_writes=0,updated_at=$3
		WHERE user_id=$1 AND activity_epoch=$4`, userID, baseNodeID, p.Now, activityEpoch); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_protection_states SET state='unprotected',
		reason_code='conflict_resolved',authoritative_node_id=$2,recovery_node_id=NULL,
		latest_recovery_snapshot_id=NULL,latest_recovery_at=NULL,version=version+1,
		changed_at=$3,evaluated_at=$3 WHERE user_id=$1`, userID, baseNodeID, p.Now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE replica_conflicts SET state='resolved',version=version+1,
		updated_at=$2,resolved_at=$2 WHERE id=$1`, p.ConflictID, p.Now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE conflict_resolution_operations SET completed_at=$2
		WHERE operation_id=$1`, p.OperationID, p.Now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE workflows SET state='succeeded',error_code=NULL,
		error_summary=NULL,next_attempt_at=NULL,lease_owner=NULL,lease_until=NULL,
		updated_at=$2,finished_at=$2 WHERE id=$1`, p.WorkflowID, p.Now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE workflow_steps SET state='succeeded',
		finished_at=COALESCE(finished_at,$2),updated_at=$2 WHERE workflow_id=$1`, p.WorkflowID, p.Now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM controller_sessions WHERE user_id=$1`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events (
		occurred_at,actor_type,actor_id,action,target_type,target_id,operation_id,
		controller_generation,outcome,detail
		) VALUES ($8,'system',NULL,'resolve-replica-conflict','global_user',$1::text,$2,$3,
		'succeeded',jsonb_build_object('conflict_id',$4,'base_node_id',$5,
		'result_snapshot_id',$6,'preserved_source_count',$7))`, userID, p.OperationID,
		generation, p.ConflictID, baseNodeID, p.ResultSnapshotID, preservedSourceCount, p.Now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) FailConflictResolution(ctx context.Context, workflowID, code, summary string, now time.Time) error {
	if workflowID == "" || code == "" {
		return ErrInvalidConflictResolution
	}
	if len(summary) > 512 {
		summary = summary[:512]
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var conflictID string
	err = tx.QueryRowContext(ctx, `UPDATE workflows workflow SET state='failed',error_code=$2,
		error_summary=$3,lease_owner=NULL,lease_until=NULL,updated_at=$4,finished_at=$4
		FROM conflict_resolution_operations operation
		WHERE workflow.id=$1 AND operation.workflow_id=workflow.id
		  AND workflow.state NOT IN ('succeeded','cancelled','failed')
		RETURNING operation.conflict_id::text`, workflowID, code, nullIfEmpty(summary), now).Scan(&conflictID)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE replica_conflicts SET state='awaiting_decision',
		version=version+1,updated_at=$2 WHERE id=$1 AND state='resolving'`, conflictID, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE snapshot_manifests SET state='invalid'
		WHERE workflow_id=$1 AND state='building'`, workflowID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE conflict_resolution_transfers SET state='revoked',updated_at=$2
		WHERE operation_id=(SELECT operation_id FROM conflict_resolution_operations WHERE workflow_id=$1)
		  AND state='prepared'`, workflowID, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RestartConflictResolution(
	ctx context.Context,
	userID int64,
	operationID string,
	now time.Time,
) (*ConflictResolutionStatus, error) {
	if userID <= 0 || operationID == "" {
		return nil, ErrInvalidConflictResolution
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var workflowID, conflictID, snapshotID, conflictState, nodeName string
	var baseNodeID, generation int64
	err = tx.QueryRowContext(ctx, `
		SELECT operation.workflow_id::text,operation.conflict_id::text,
		  operation.result_snapshot_id::text,operation.base_node_id,node.name,
		  conflict.state,workflow.controller_generation
		FROM conflict_resolution_operations operation
		JOIN workflows workflow ON workflow.id=operation.workflow_id AND workflow.state='failed'
		JOIN replica_conflicts conflict ON conflict.id=operation.conflict_id
		JOIN global_users global_user ON global_user.id=operation.user_id AND global_user.status='conflict'
		JOIN users legacy ON legacy.id=global_user.legacy_user_id AND legacy.status='conflict'
		JOIN nodes node ON node.id=operation.base_node_id
		WHERE operation.user_id=$1 AND operation.operation_id=$2
		FOR UPDATE OF workflow,conflict,global_user,legacy,node`, userID, operationID).Scan(
		&workflowID, &conflictID, &snapshotID, &baseNodeID, &nodeName, &conflictState, &generation)
	if err == sql.ErrNoRows {
		return nil, ErrConflictResolutionState
	}
	if err != nil {
		return nil, err
	}
	if conflictState != "awaiting_decision" {
		return nil, ErrConflictResolutionState
	}
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&activeGeneration); err != nil {
		return nil, err
	}
	if generation != activeGeneration {
		return nil, ErrConflictResolutionState
	}
	zeroDigest := make([]byte, 32)
	result, err := tx.ExecContext(ctx, `UPDATE snapshot_manifests
		SET manifest_sha256=$2,file_count=0,total_bytes=0,state='building'
		WHERE id=$1 AND state='invalid'`, snapshotID, zeroDigest)
	if err != nil {
		return nil, err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return nil, err
		}
		return nil, ErrConflictResolutionState
	}
	if _, err := tx.ExecContext(ctx, `UPDATE workflows SET state='scheduled',resume_state=NULL,
		attempt=0,next_attempt_at=NULL,error_code=NULL,error_summary=NULL,finished_at=NULL,
		lease_owner=NULL,lease_until=NULL,updated_at=$2 WHERE id=$1`, workflowID, now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE workflow_steps SET state='pending',attempt=0,
		lease_owner=NULL,lease_until=NULL,error_code=NULL,started_at=NULL,finished_at=NULL,updated_at=$2
		WHERE workflow_id=$1`, workflowID, now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE replica_conflicts SET state='resolving',version=version+1,
		updated_at=$2 WHERE id=$1`, conflictID, now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events (
		occurred_at,actor_type,actor_id,action,target_type,target_id,operation_id,
		controller_generation,outcome,detail
		) VALUES ($6,'user',$1::text,'retry-conflict-resolution','global_user',$1::text,$2,$3,
		'scheduled',jsonb_build_object('conflict_id',$4,'base_node_id',$5))`,
		userID, operationID, generation, conflictID, baseNodeID, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &ConflictResolutionStatus{
		OperationID: operationID, State: "scheduled", BaseNodeID: baseNodeID, BaseNodeName: nodeName,
	}, nil
}
