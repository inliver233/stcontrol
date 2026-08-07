package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrInvalidAgentNonce = errors.New("invalid agent nonce input")

// ConsumeAgentNonce records a signed request nonce once. Expired rows are
// opportunistically removed in the same statement so replay protection remains
// durable without unbounded table growth.
func (s *Store) ConsumeAgentNonce(
	ctx context.Context,
	nodeID int64,
	nonce string,
	signedAt, expiresAt time.Time,
) (bool, error) {
	if nodeID <= 0 || nonce == "" || signedAt.IsZero() || !expiresAt.After(signedAt) {
		return false, ErrInvalidAgentNonce
	}
	digest := sha256.Sum256([]byte(nonce))
	var inserted int
	err := s.DB.QueryRowContext(ctx, `
		WITH cleanup AS (
		  DELETE FROM agent_request_nonces WHERE expires_at<=now()
		)
		INSERT INTO agent_request_nonces (node_id, nonce_hash, signed_at, expires_at)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (node_id, nonce_hash) DO NOTHING
		RETURNING 1`, nodeID, digest[:], signedAt, expiresAt).Scan(&inserted)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("consume agent nonce: %w", err)
	}
	return inserted == 1, nil
}
