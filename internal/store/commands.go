package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidAgentCommand  = errors.New("invalid agent command input")
	ErrAgentCommandConflict = errors.New("agent command state conflict")
)

type EnqueueAgentCommandParams struct {
	ID               string
	OperationID      string
	NodeID           int64
	CommandType      string
	EncryptedPayload json.RawMessage
	PayloadSHA256    []byte
	ExpiresAt        time.Time
	Now              time.Time
	// ExpectedControllerGeneration fences a workflow claim to the same active
	// controller epoch before the command can become visible to an Agent. Zero
	// keeps the legacy "bind whichever epoch is active" behaviour.
	ExpectedControllerGeneration int64
	// RequeueRetryableTerminal permits an exact failed/expired command to be
	// made visible again with a fresh delivery ID. Callers must opt in only when
	// the remote operation is itself idempotent for OperationID and scope.
	RequeueRetryableTerminal bool
}

func (s *Store) EnqueueAgentCommand(ctx context.Context, p EnqueueAgentCommandParams) (int64, error) {
	if p.ID == "" || p.OperationID == "" || p.NodeID <= 0 || p.CommandType == "" ||
		!json.Valid(p.EncryptedPayload) || len(p.PayloadSHA256) != 32 || p.ExpiresAt.IsZero() ||
		p.ExpectedControllerGeneration < 0 {
		return 0, ErrInvalidAgentCommand
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	if !p.ExpiresAt.After(p.Now) {
		return 0, ErrInvalidAgentCommand
	}
	var generation int64
	err := s.DB.QueryRowContext(ctx, `
		INSERT INTO agent_commands (
		  id, operation_id, node_id, command_type, payload, payload_sha256,
		  state, controller_generation, expires_at, created_at, updated_at
		)
		SELECT $1,$2,$3,$4,$5,$6,'queued',generation,$7,$8,$8
		FROM controller_epochs
		WHERE state='active' AND ($9::bigint=0 OR generation=$9)
		ON CONFLICT (operation_id) DO UPDATE SET
		  id=EXCLUDED.id,payload=EXCLUDED.payload,state='queued',attempt=0,
		  lease_owner=NULL,lease_until=NULL,result_summary=NULL,result_digest=NULL,
		  expires_at=EXCLUDED.expires_at,updated_at=EXCLUDED.updated_at
		WHERE agent_commands.node_id=EXCLUDED.node_id
		  AND agent_commands.command_type=EXCLUDED.command_type
		  AND agent_commands.payload_sha256=EXCLUDED.payload_sha256
		  AND agent_commands.controller_generation=EXCLUDED.controller_generation
		  AND $10::boolean
		  AND agent_commands.state IN ('failed','expired')
		RETURNING controller_generation`,
		p.ID, p.OperationID, p.NodeID, p.CommandType, p.EncryptedPayload,
		p.PayloadSHA256, p.ExpiresAt, p.Now, p.ExpectedControllerGeneration,
		p.RequeueRetryableTerminal).Scan(&generation)
	if err == sql.ErrNoRows {
		var existingNodeID int64
		var existingType, existingState string
		var existingDigest []byte
		err = s.DB.QueryRowContext(ctx, `
			SELECT node_id, command_type, payload_sha256, controller_generation,state
			FROM agent_commands WHERE operation_id=$1`, p.OperationID).
			Scan(&existingNodeID, &existingType, &existingDigest, &generation, &existingState)
		if err == sql.ErrNoRows {
			return 0, ErrNoActiveController
		}
		if err != nil {
			return 0, fmt.Errorf("load idempotent agent command: %w", err)
		}
		if existingNodeID != p.NodeID || existingType != p.CommandType ||
			!bytes.Equal(existingDigest, p.PayloadSHA256) ||
			(p.ExpectedControllerGeneration > 0 && generation != p.ExpectedControllerGeneration) {
			return 0, ErrAgentCommandConflict
		}
		_ = existingState // exact non-terminal/succeeded replay remains idempotent
		return generation, nil
	}
	if err != nil {
		return 0, fmt.Errorf("enqueue agent command: %w", err)
	}
	return generation, nil
}

type AgentCommandLease struct {
	ID                   string          `json:"id"`
	OperationID          string          `json:"operation_id"`
	CommandType          string          `json:"command_type"`
	EncryptedPayload     json.RawMessage `json:"encrypted_payload"`
	PayloadSHA256        []byte          `json:"-"`
	Attempt              int             `json:"attempt"`
	ControllerGeneration int64           `json:"controller_generation"`
	LeaseUntil           time.Time       `json:"lease_until"`
	ExpiresAt            time.Time       `json:"expires_at"`
}

func (s *Store) LeaseAgentCommand(
	ctx context.Context,
	nodeID int64,
	workerID string,
	now time.Time,
	leaseTTL time.Duration,
) (*AgentCommandLease, error) {
	if nodeID <= 0 || workerID == "" || leaseTTL <= 0 {
		return nil, ErrInvalidAgentCommand
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var command AgentCommandLease
	err = tx.QueryRowContext(ctx, `
		SELECT command.id, command.operation_id, command.command_type, command.payload,
		  command.payload_sha256, command.attempt, command.controller_generation,
		  command.expires_at
		FROM agent_commands command
		JOIN controller_epochs epoch
		  ON epoch.generation=command.controller_generation AND epoch.state='active'
		JOIN nodes node ON node.id=command.node_id
		WHERE command.node_id=$1
		  AND node.controller_generation=epoch.generation
		  AND (
		    node.control_mode='managed'
		    OR (node.control_mode='independent-draining' AND command.command_type IN (
		      'prepare_snapshot_receive','start_snapshot','start_relay_receive','get_snapshot_receipt',
		      'complete_independent_sync','capture_conflict_evidence',
		      'read_conflict_evidence_page','start_conflict_evidence_transfer',
		      'prepare_conflict_resolution','apply_conflict_resolution_decisions',
		      'publish_conflict_resolution','freeze_user_data','release_user_data'
		    ))
		  )
		  AND ((command.state='queued' AND command.expires_at>$2)
		    OR (command.state IN ('leased','acked','running') AND command.lease_until<=$2))
		ORDER BY command.created_at
		FOR UPDATE OF command SKIP LOCKED LIMIT 1`, nodeID, now).
		Scan(&command.ID, &command.OperationID, &command.CommandType, &command.EncryptedPayload,
			&command.PayloadSHA256, &command.Attempt, &command.ControllerGeneration, &command.ExpiresAt)
	if err == sql.ErrNoRows {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("select agent command: %w", err)
	}
	command.Attempt++
	command.LeaseUntil = now.Add(leaseTTL)
	if _, err := tx.ExecContext(ctx, `
		UPDATE agent_commands
		SET state='leased', lease_owner=$2, lease_until=$3,
		  attempt=$4, updated_at=$5
		WHERE id=$1`, command.ID, workerID, command.LeaseUntil, command.Attempt, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &command, nil
}

func (s *Store) AckAgentCommand(
	ctx context.Context,
	id string,
	nodeID int64,
	workerID string,
	generation int64,
	now time.Time,
	runTTL time.Duration,
) (bool, error) {
	if id == "" || nodeID <= 0 || workerID == "" || generation <= 0 || runTTL <= 0 {
		return false, ErrInvalidAgentCommand
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE agent_commands
		SET state='running', lease_until=$6, updated_at=$5
		WHERE id=$1 AND node_id=$2 AND lease_owner=$3
		  AND controller_generation=$4 AND state='leased' AND lease_until>$5`,
		id, nodeID, workerID, generation, now, now.Add(runTTL))
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

type FinishAgentCommandParams struct {
	ID                   string
	NodeID               int64
	WorkerID             string
	ControllerGeneration int64
	Succeeded            bool
	ResultSummary        json.RawMessage
	ResultDigest         []byte
	Now                  time.Time
}

func (s *Store) FinishAgentCommand(ctx context.Context, p FinishAgentCommandParams) (bool, error) {
	if p.ID == "" || p.NodeID <= 0 || p.WorkerID == "" || p.ControllerGeneration <= 0 ||
		!json.Valid(p.ResultSummary) || len(p.ResultDigest) != 32 {
		return false, ErrInvalidAgentCommand
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	state := "failed"
	if p.Succeeded {
		state = "succeeded"
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE agent_commands
		SET state=$5, result_summary=$6, result_digest=$7,
		  lease_owner=NULL, lease_until=NULL, updated_at=$8
		WHERE id=$1 AND node_id=$2 AND lease_owner=$3
		  AND controller_generation=$4 AND state IN ('leased','acked','running')`,
		p.ID, p.NodeID, p.WorkerID, p.ControllerGeneration, state,
		p.ResultSummary, p.ResultDigest, p.Now)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

type AgentCommandResult struct {
	State         string
	ResultSummary json.RawMessage
	UpdatedAt     time.Time
}

func (s *Store) GetAgentCommandResult(ctx context.Context, operationID string) (*AgentCommandResult, error) {
	if operationID == "" {
		return nil, ErrInvalidAgentCommand
	}
	var out AgentCommandResult
	err := s.DB.QueryRowContext(ctx, `
		WITH expired AS (
		  UPDATE agent_commands SET state='expired',updated_at=now()
		  WHERE operation_id=$1 AND state='queued' AND expires_at<=now()
		  RETURNING operation_id
		)
		SELECT state, COALESCE(result_summary,'{}'::jsonb), updated_at
		FROM agent_commands WHERE operation_id=$1`, operationID).
		Scan(&out.State, &out.ResultSummary, &out.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &out, err
}
