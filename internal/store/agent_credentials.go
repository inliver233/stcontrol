package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrAgentCredentialRotation = errors.New("agent credential rotation rejected")
)

const agentCredentialMaxAge = 30 * 24 * time.Hour

type AgentAuthenticationCredential struct {
	ID                   string
	Ciphertext           []byte
	CredentialVersion    int64
	ControllerGeneration int64
	Pending              bool
}

type AgentCredentialRotation struct {
	ID                   string
	CredentialVersion    int64
	Ciphertext           []byte
	ControllerGeneration int64
	ExpiresAt            time.Time
}

type EnsureAgentCredentialRotationParams struct {
	ID                   string
	OperationID          string
	NodeID               int64
	ProposedCiphertext   []byte
	ControllerGeneration int64
	Now                  time.Time
	ExpiresAt            time.Time
}

// ListAgentAuthenticationCredentials returns the active credential plus a
// bounded pending successor. A pending secret may only be used by the HTTP
// middleware on the confirmation route.
func (s *Store) ListAgentAuthenticationCredentials(
	ctx context.Context,
	nodeID int64,
	now time.Time,
) ([]AgentAuthenticationCredential, error) {
	if nodeID <= 0 || now.IsZero() {
		return nil, ErrAgentCredentialRotation
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id::text,secret_ciphertext,credential_version,controller_generation,false
		FROM agent_credentials
		WHERE node_id=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>$2)
		UNION ALL
		SELECT id::text,secret_ciphertext,credential_version,controller_generation,true
		FROM agent_credential_rotations
		WHERE node_id=$1 AND state='pending' AND expires_at>$2
		ORDER BY credential_version DESC`, nodeID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	credentials := make([]AgentAuthenticationCredential, 0, 2)
	for rows.Next() {
		var credential AgentAuthenticationCredential
		if err := rows.Scan(&credential.ID, &credential.Ciphertext, &credential.CredentialVersion,
			&credential.ControllerGeneration, &credential.Pending); err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	return credentials, rows.Err()
}

// EnsureAgentCredentialRotation creates at most one pending successor. It
// rotates immediately after a controller generation change and otherwise at
// least every 30 days.
func (s *Store) EnsureAgentCredentialRotation(
	ctx context.Context,
	p EnsureAgentCredentialRotationParams,
) (*AgentCredentialRotation, error) {
	if p.ID == "" || p.OperationID == "" || p.NodeID <= 0 || len(p.ProposedCiphertext) == 0 ||
		p.ControllerGeneration <= 0 || p.Now.IsZero() || !p.ExpiresAt.After(p.Now) ||
		p.ExpiresAt.After(p.Now.Add(25*time.Hour)) {
		return nil, ErrAgentCredentialRotation
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var nodeState string
	if err := tx.QueryRowContext(ctx, `SELECT operational_state FROM nodes WHERE id=$1 FOR UPDATE`, p.NodeID).
		Scan(&nodeState); err != nil {
		return nil, err
	}
	if nodeState == "retired" || nodeState == "decommissioned" {
		return nil, ErrAgentCredentialRotation
	}
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).
		Scan(&activeGeneration); err != nil {
		return nil, err
	}
	if activeGeneration != p.ControllerGeneration {
		return nil, ErrAgentCredentialRotation
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE agent_credential_rotations SET state='expired'
		WHERE node_id=$1 AND state='pending' AND expires_at<=$2`, p.NodeID, p.Now); err != nil {
		return nil, err
	}
	rotation := &AgentCredentialRotation{}
	err = tx.QueryRowContext(ctx, `
		SELECT id::text,credential_version,secret_ciphertext,controller_generation,expires_at
		FROM agent_credential_rotations WHERE node_id=$1 AND state='pending' FOR UPDATE`, p.NodeID).
		Scan(&rotation.ID, &rotation.CredentialVersion, &rotation.Ciphertext,
			&rotation.ControllerGeneration, &rotation.ExpiresAt)
	if err == nil {
		if rotation.ControllerGeneration != activeGeneration || !rotation.ExpiresAt.After(p.Now) {
			return nil, ErrAgentCredentialRotation
		}
		if err := markControllerRebuildRotationPendingLocked(
			ctx, tx, p.NodeID, activeGeneration, rotation.CredentialVersion, p.Now,
		); err != nil {
			return nil, err
		}
		return rotation, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	var currentVersion, currentGeneration int64
	var createdAt time.Time
	if err := tx.QueryRowContext(ctx, `
		SELECT credential_version,controller_generation,created_at
		FROM agent_credentials
		WHERE node_id=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>$2)
		ORDER BY credential_version DESC LIMIT 1 FOR UPDATE`, p.NodeID, p.Now).
		Scan(&currentVersion, &currentGeneration, &createdAt); err != nil {
		return nil, err
	}
	if currentGeneration == activeGeneration && createdAt.After(p.Now.Add(-agentCredentialMaxAge)) {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	var version int64
	if err := tx.QueryRowContext(ctx, `
		SELECT GREATEST(
		  COALESCE((SELECT MAX(credential_version) FROM agent_credentials WHERE node_id=$1),0),
		  COALESCE((SELECT MAX(credential_version) FROM agent_credential_rotations WHERE node_id=$1),0)
		)+1`, p.NodeID).Scan(&version); err != nil {
		return nil, err
	}
	if version <= currentVersion {
		return nil, fmt.Errorf("invalid next agent credential version")
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO agent_credential_rotations (
		  id,operation_id,node_id,credential_version,secret_ciphertext,
		  controller_generation,state,expires_at,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$8)`,
		p.ID, p.OperationID, p.NodeID, version, p.ProposedCiphertext,
		activeGeneration, p.ExpiresAt, p.Now); err != nil {
		return nil, err
	}
	if err := markControllerRebuildRotationPendingLocked(
		ctx, tx, p.NodeID, activeGeneration, version, p.Now,
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &AgentCredentialRotation{
		ID: p.ID, CredentialVersion: version, Ciphertext: p.ProposedCiphertext,
		ControllerGeneration: activeGeneration, ExpiresAt: p.ExpiresAt,
	}, nil
}

func (s *Store) ActivateAgentCredentialRotation(
	ctx context.Context,
	nodeID, credentialVersion int64,
	now time.Time,
) (int64, error) {
	if nodeID <= 0 || credentialVersion <= 0 || now.IsZero() {
		return 0, ErrAgentCredentialRotation
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var activeGeneration int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).
		Scan(&activeGeneration); err != nil {
		return 0, err
	}
	var rotationID string
	var ciphertext []byte
	var rotationGeneration int64
	var state string
	var expiresAt time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT id::text,secret_ciphertext,controller_generation,state,expires_at
		FROM agent_credential_rotations
		WHERE node_id=$1 AND credential_version=$2 FOR UPDATE`, nodeID, credentialVersion).
		Scan(&rotationID, &ciphertext, &rotationGeneration, &state, &expiresAt)
	if err != nil {
		return 0, ErrAgentCredentialRotation
	}
	if state == "activated" {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1 FROM agent_credentials WHERE node_id=$1 AND credential_version=$2 AND revoked_at IS NULL
		)`, nodeID, credentialVersion).Scan(&exists); err != nil || !exists {
			return 0, ErrAgentCredentialRotation
		}
		if err := markControllerRebuildCredentialActivatedLocked(
			ctx, tx, nodeID, activeGeneration, credentialVersion, now,
		); err != nil {
			return 0, err
		}
		return activeGeneration, tx.Commit()
	}
	if state != "pending" || !expiresAt.After(now) || rotationGeneration != activeGeneration {
		return 0, ErrAgentCredentialRotation
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE agent_credentials SET revoked_at=COALESCE(revoked_at,$2)
		WHERE node_id=$1 AND revoked_at IS NULL`, nodeID, now); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO agent_credentials (
		  id,node_id,credential_version,credential_type,secret_ciphertext,
		  controller_generation,created_at
		) VALUES ($1,$2,$3,'hmac',$4,$5,$6)`,
		rotationID, nodeID, credentialVersion, ciphertext, activeGeneration, now); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE agent_credential_rotations SET state='activated',confirmed_at=$2
		WHERE id=$1`, rotationID, now); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE nodes SET controller_generation=$2 WHERE id=$1`,
		nodeID, activeGeneration); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE agent_commands SET state='expired',updated_at=$2
		WHERE node_id=$1 AND state IN ('queued','leased','acked','running')`,
		nodeID, now); err != nil {
		return 0, err
	}
	if err := markControllerRebuildCredentialActivatedLocked(
		ctx, tx, nodeID, activeGeneration, credentialVersion, now,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return activeGeneration, nil
}
