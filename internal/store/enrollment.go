package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidEnrollment  = errors.New("invalid agent enrollment input")
	ErrEnrollmentRejected = errors.New("agent enrollment rejected")
)

type CreateEnrollmentTokenParams struct {
	ID                  string
	OperationID         string
	TokenHash           []byte
	ExpectedNodeID      int64
	ExpectedRole        string
	ExpectedFingerprint string
	ExpiresAt           time.Time
	CreatedByAdminID    *int64
	Now                 time.Time
}

func (s *Store) CreateEnrollmentToken(ctx context.Context, p CreateEnrollmentTokenParams) error {
	if p.ID == "" || p.OperationID == "" || len(p.TokenHash) != 32 || p.ExpectedNodeID <= 0 ||
		(p.ExpectedRole != "compute" && p.ExpectedRole != "storage" && p.ExpectedRole != "passive_controller") ||
		p.ExpiresAt.IsZero() {
		return ErrInvalidEnrollment
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	if !p.ExpiresAt.After(p.Now) {
		return ErrInvalidEnrollment
	}
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO enrollment_tokens (
		  id, operation_id, token_hash, expected_node_id, expected_role,
		  expected_fingerprint, expires_at, created_by_admin_id, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		p.ID, p.OperationID, p.TokenHash, p.ExpectedNodeID, p.ExpectedRole,
		nullIfEmpty(p.ExpectedFingerprint), p.ExpiresAt, p.CreatedByAdminID, p.Now)
	if err != nil {
		return fmt.Errorf("create enrollment token: %w", err)
	}
	return nil
}

type EnrollAgentParams struct {
	TokenHash            []byte
	PresentedRole        string
	PresentedFingerprint string
	CredentialID         string
	CredentialCiphertext []byte
	AgentVersion         string
	TavernVersion        string
	BaseURLGuess         string
	Now                  time.Time
}

type AgentEnrollment struct {
	NodeID               int64
	CredentialVersion    int64
	ControllerGeneration int64
}

// EnrollAgent consumes a node-scoped token and rotates the encrypted Agent
// credential in one serializable transaction.
func (s *Store) EnrollAgent(ctx context.Context, p EnrollAgentParams) (AgentEnrollment, error) {
	if len(p.TokenHash) != 32 || p.CredentialID == "" || len(p.CredentialCiphertext) == 0 ||
		(p.PresentedRole != "compute" && p.PresentedRole != "storage" && p.PresentedRole != "passive_controller") {
		return AgentEnrollment{}, ErrInvalidEnrollment
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return AgentEnrollment{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		tokenID             string
		nodeID              sql.NullInt64
		expectedRole        string
		expectedFingerprint sql.NullString
	)
	err = tx.QueryRowContext(ctx, `
		SELECT id, expected_node_id, expected_role, expected_fingerprint
		FROM enrollment_tokens
		WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at>$2
		FOR UPDATE`, p.TokenHash, p.Now).
		Scan(&tokenID, &nodeID, &expectedRole, &expectedFingerprint)
	if err == sql.ErrNoRows {
		return AgentEnrollment{}, ErrEnrollmentRejected
	}
	if err != nil {
		return AgentEnrollment{}, fmt.Errorf("lock enrollment token: %w", err)
	}
	if !nodeID.Valid || expectedRole != p.PresentedRole ||
		(expectedFingerprint.Valid && expectedFingerprint.String != p.PresentedFingerprint) {
		return AgentEnrollment{}, ErrEnrollmentRejected
	}

	var nodeRole string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM nodes WHERE id=$1 FOR UPDATE`, nodeID.Int64).Scan(&nodeRole); err != nil {
		if err == sql.ErrNoRows {
			return AgentEnrollment{}, ErrEnrollmentRejected
		}
		return AgentEnrollment{}, fmt.Errorf("lock enrollment node: %w", err)
	}
	if nodeRole != expectedRole {
		return AgentEnrollment{}, ErrEnrollmentRejected
	}

	var generation int64
	if err := tx.QueryRowContext(ctx, `
		SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&generation); err != nil {
		if err == sql.ErrNoRows {
			return AgentEnrollment{}, ErrNoActiveController
		}
		return AgentEnrollment{}, err
	}
	var version int64
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(credential_version),0)+1
		FROM agent_credentials WHERE node_id=$1`, nodeID.Int64).Scan(&version); err != nil {
		return AgentEnrollment{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE agent_credentials SET revoked_at=$2
		WHERE node_id=$1 AND revoked_at IS NULL`, nodeID.Int64, p.Now); err != nil {
		return AgentEnrollment{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO agent_credentials (
		  id, node_id, credential_version, credential_type, secret_ciphertext,
		  controller_generation, created_at
		) VALUES ($1,$2,$3,'hmac',$4,$5,$6)`,
		p.CredentialID, nodeID.Int64, version, p.CredentialCiphertext, generation, p.Now); err != nil {
		return AgentEnrollment{}, fmt.Errorf("insert agent credential: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE enrollment_tokens
		SET consumed_at=$2, consumed_node_id=$3
		WHERE id=$1`, tokenID, p.Now, nodeID.Int64); err != nil {
		return AgentEnrollment{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE nodes
		SET agent_version=$2, tavern_version=$3,
		  controller_generation=$4, connectivity_state='online',
		  operational_state='active', status='online', last_seen_at=$5,
		  base_url=CASE WHEN base_url='' THEN $6 ELSE base_url END
		WHERE id=$1`, nodeID.Int64, p.AgentVersion, p.TavernVersion, generation, p.Now, p.BaseURLGuess); err != nil {
		return AgentEnrollment{}, err
	}
	if err := tx.Commit(); err != nil {
		return AgentEnrollment{}, err
	}
	return AgentEnrollment{NodeID: nodeID.Int64, CredentialVersion: version, ControllerGeneration: generation}, nil
}

func (s *Store) GetActiveAgentCredential(ctx context.Context, nodeID int64) ([]byte, int64, int64, error) {
	if nodeID <= 0 {
		return nil, 0, 0, ErrInvalidEnrollment
	}
	var ciphertext []byte
	var version, generation int64
	err := s.DB.QueryRowContext(ctx, `
		SELECT credential.secret_ciphertext, credential.credential_version,
		  credential.controller_generation
		FROM agent_credentials credential
		WHERE credential.node_id=$1 AND credential.revoked_at IS NULL
		  AND (credential.expires_at IS NULL OR credential.expires_at>now())
		ORDER BY credential.credential_version DESC LIMIT 1`, nodeID).
		Scan(&ciphertext, &version, &generation)
	if err == sql.ErrNoRows {
		return nil, 0, 0, nil
	}
	if err != nil {
		return nil, 0, 0, err
	}
	return ciphertext, version, generation, nil
}

func (s *Store) GetActiveControllerGeneration(ctx context.Context) (int64, error) {
	var generation int64
	err := s.DB.QueryRowContext(ctx, `
		SELECT generation FROM controller_epochs WHERE state='active'`).Scan(&generation)
	if err == sql.ErrNoRows {
		return 0, ErrNoActiveController
	}
	return generation, err
}
