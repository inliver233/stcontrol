package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidLoginHandoff     = errors.New("invalid login handoff input")
	ErrLoginHandoffUnavailable = errors.New("login handoff unavailable")
	ErrNoActiveController      = errors.New("no active controller generation")
	ErrStaleControllerLease    = errors.New("activity lease belongs to a stale controller generation")
)

// CreateLoginHandoffParams contains the security facts needed to create a
// browser-to-node login handoff. SecretHash is a SHA-256 digest; the browser
// secret itself is never persisted.
type CreateLoginHandoffParams struct {
	OperationID     string
	JTI             string
	SecretHash      []byte
	UserID          int64
	RequestedNodeID int64
	SessionID       string
	Issuer          string
	Subject         string
	KeyID           string
	TicketTTL       time.Duration
	LeaseTTL        time.Duration
	Now             time.Time
}

// LoginHandoff is the durable result returned for both first execution and an
// idempotent retry of the same operation.
type LoginHandoff struct {
	OperationID          string
	JTI                  string
	UserID               int64
	TargetNodeID         int64
	NodeBaseURL          string
	Subject              string
	SessionID            string
	ActivityEpoch        int64
	ControllerGeneration int64
	ExpiresAt            time.Time
	Acquired             bool
	Existing             bool
	Replayed             bool
}

// CreateLoginHandoff establishes/preserves the single-writer lease and inserts
// its one-use ticket in the same serializable transaction. A committed lease
// can therefore never exist without the corresponding handoff result.
func (s *Store) CreateLoginHandoff(ctx context.Context, p CreateLoginHandoffParams) (LoginHandoff, error) {
	if p.OperationID == "" || p.JTI == "" || len(p.SecretHash) != 32 || p.UserID <= 0 ||
		p.RequestedNodeID <= 0 || p.SessionID == "" || p.Issuer == "" || p.Subject == "" ||
		p.KeyID == "" || p.TicketTTL <= 0 || p.LeaseTTL <= 0 {
		return LoginHandoff{}, ErrInvalidLoginHandoff
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}

	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return LoginHandoff{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := lockGlobalUser(ctx, tx, p.UserID); err != nil {
		return LoginHandoff{}, err
	}

	var generation int64
	if err := tx.QueryRowContext(ctx, `
		SELECT generation FROM controller_epochs
		WHERE state='active' FOR SHARE`).Scan(&generation); err != nil {
		if err == sql.ErrNoRows {
			return LoginHandoff{}, ErrNoActiveController
		}
		return LoginHandoff{}, fmt.Errorf("get active controller generation: %w", err)
	}

	leaseParams := AcquireActivityLeaseParams{
		OperationID:          p.OperationID,
		UserID:               p.UserID,
		WriterNodeID:         p.RequestedNodeID,
		SessionID:            p.SessionID,
		ControllerGeneration: generation,
		TTL:                  p.LeaseTTL,
		Now:                  p.Now,
	}
	leaseResult, replayed, err := acquireActivityLeaseLocked(ctx, tx, leaseParams)
	if err != nil {
		return LoginHandoff{}, err
	}

	if replayed {
		handoff, err := getLoginHandoffByOperation(ctx, tx, p.OperationID, p.UserID, p.RequestedNodeID, p.Now)
		if err != nil {
			return LoginHandoff{}, err
		}
		handoff.Replayed = true
		if err := tx.Commit(); err != nil {
			return LoginHandoff{}, err
		}
		return handoff, nil
	}

	if leaseResult.Lease.ControllerGeneration != generation {
		return LoginHandoff{}, ErrStaleControllerLease
	}
	targetNodeID := leaseResult.Lease.WriterNodeID
	var nodeBaseURL string
	if err := tx.QueryRowContext(ctx, `
		SELECT base_url FROM nodes
		WHERE id=$1 AND role='compute' AND status='online' AND connectivity_state='online'
		  AND compatibility_state='compatible' AND control_mode='managed'
		  AND desired_control_mode='managed'
		  AND (operational_state='active'
		    OR ($2 AND operational_state IN ('draining','retiring')))
		FOR SHARE`, targetNodeID, leaseResult.Existing).Scan(&nodeBaseURL); err != nil {
		if err == sql.ErrNoRows {
			return LoginHandoff{}, ErrLoginHandoffUnavailable
		}
		return LoginHandoff{}, fmt.Errorf("get login handoff node: %w", err)
	}

	expiresAt := p.Now.Add(p.TicketTTL)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO control_tickets (
		  jti, operation_id, secret_hash, ticket_type, issuer, audience, subject,
		  user_id, target_node_id, session_id, activity_epoch, key_id,
		  controller_generation, issued_at, not_before, expires_at
		) VALUES ($1,$2,$3,'user_login',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14)`,
		p.JTI, p.OperationID, p.SecretHash, p.Issuer, nodeBaseURL, p.Subject,
		p.UserID, targetNodeID, leaseResult.Lease.SessionID, leaseResult.Lease.ActivityEpoch,
		p.KeyID, generation, p.Now, expiresAt); err != nil {
		return LoginHandoff{}, fmt.Errorf("insert login handoff ticket: %w", err)
	}

	handoff := LoginHandoff{
		OperationID:          p.OperationID,
		JTI:                  p.JTI,
		UserID:               p.UserID,
		TargetNodeID:         targetNodeID,
		NodeBaseURL:          nodeBaseURL,
		Subject:              p.Subject,
		SessionID:            leaseResult.Lease.SessionID,
		ActivityEpoch:        leaseResult.Lease.ActivityEpoch,
		ControllerGeneration: generation,
		ExpiresAt:            expiresAt,
		Acquired:             leaseResult.Acquired,
		Existing:             leaseResult.Existing,
	}
	if err := tx.Commit(); err != nil {
		return LoginHandoff{}, err
	}
	return handoff, nil
}

func getLoginHandoffByOperation(
	ctx context.Context,
	tx *sql.Tx,
	operationID string,
	userID, requestedNodeID int64,
	now time.Time,
) (LoginHandoff, error) {
	var handoff LoginHandoff
	var outcome string
	err := tx.QueryRowContext(ctx, `
		SELECT t.operation_id, t.jti, t.user_id, t.target_node_id, n.base_url,
		  t.subject, t.session_id, t.activity_epoch, t.controller_generation,
		  t.expires_at, o.outcome
		FROM control_tickets t
		JOIN nodes n ON n.id=t.target_node_id
		JOIN activity_lease_operations o ON o.operation_id=t.operation_id
		WHERE t.operation_id=$1 AND o.user_id=$2 AND o.requested_node_id=$3
		  AND t.ticket_type='user_login' AND t.consumed_at IS NULL
		  AND t.revoked_at IS NULL AND t.expires_at>$4`,
		operationID, userID, requestedNodeID, now).
		Scan(&handoff.OperationID, &handoff.JTI, &handoff.UserID, &handoff.TargetNodeID,
			&handoff.NodeBaseURL, &handoff.Subject, &handoff.SessionID, &handoff.ActivityEpoch,
			&handoff.ControllerGeneration, &handoff.ExpiresAt, &outcome)
	if err == sql.ErrNoRows {
		return LoginHandoff{}, ErrLoginHandoffUnavailable
	}
	if err != nil {
		return LoginHandoff{}, fmt.Errorf("get login handoff retry: %w", err)
	}
	handoff.Acquired = outcome == "acquired"
	handoff.Existing = outcome == "existing"
	return handoff, nil
}

// LoginRedemption is the minimum identity and fencing context a node needs to
// establish its local session.
type LoginRedemption struct {
	UserID               int64  `json:"user_id"`
	Handle               string `json:"handle"`
	SessionID            string `json:"session_id"`
	ActivityEpoch        int64  `json:"activity_epoch"`
	ControllerGeneration int64  `json:"controller_generation"`
}

// ConsumeLoginHandoff atomically consumes a ticket only when the authenticated
// node, active controller generation, and live writer lease all match. The
// corresponding lease is renewed as part of the same statement.
func (s *Store) ConsumeLoginHandoff(
	ctx context.Context,
	jti string,
	secretHash []byte,
	nodeID int64,
	now time.Time,
	leaseTTL time.Duration,
) (LoginRedemption, bool, error) {
	if jti == "" || len(secretHash) != 32 || nodeID <= 0 || leaseTTL <= 0 {
		return LoginRedemption{}, false, ErrInvalidLoginHandoff
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var out LoginRedemption
	err := s.DB.QueryRowContext(ctx, `
		WITH consumed AS (
		  UPDATE control_tickets AS t
		  SET consumed_at=$4, consumed_by_node_id=$2
		  FROM user_activity_leases AS l, controller_epochs AS ce
		  WHERE t.jti=$1 AND t.target_node_id=$2 AND t.secret_hash=$3
		    AND t.ticket_type='user_login' AND t.not_before<=$4 AND t.expires_at>$4
		    AND t.consumed_at IS NULL AND t.revoked_at IS NULL
		    AND ce.state='active' AND ce.generation=t.controller_generation
		    AND l.user_id=t.user_id AND l.writer_node_id=t.target_node_id
		    AND l.session_id=t.session_id AND l.activity_epoch=t.activity_epoch
		    AND l.controller_generation=t.controller_generation
		    AND l.state='active' AND l.lease_expires_at>$4
		  RETURNING t.user_id, t.subject, t.target_node_id, t.session_id,
		    t.activity_epoch, t.controller_generation
		)
		UPDATE user_activity_leases AS l
		SET last_request_at=$4, lease_expires_at=$5, updated_at=$4
		FROM consumed AS c
		WHERE l.user_id=c.user_id AND l.writer_node_id=c.target_node_id
		  AND l.session_id=c.session_id AND l.activity_epoch=c.activity_epoch
		  AND l.controller_generation=c.controller_generation
		RETURNING c.user_id, c.subject, c.session_id, c.activity_epoch, c.controller_generation`,
		jti, nodeID, secretHash, now, now.Add(leaseTTL)).
		Scan(&out.UserID, &out.Handle, &out.SessionID, &out.ActivityEpoch, &out.ControllerGeneration)
	if err == sql.ErrNoRows {
		return LoginRedemption{}, false, nil
	}
	if err != nil {
		return LoginRedemption{}, false, fmt.Errorf("consume login handoff: %w", err)
	}
	return out, true, nil
}
