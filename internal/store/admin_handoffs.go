package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidAdminHandoff     = errors.New("invalid admin handoff")
	ErrAdminHandoffUnavailable = errors.New("admin handoff unavailable")
)

type CreateAdminHandoffParams struct {
	OperationID string
	JTI         string
	SecretHash  []byte
	AdminID     int64
	NodeID      int64
	Issuer      string
	KeyID       string
	TicketTTL   time.Duration
	Now         time.Time
}

type AdminHandoff struct {
	OperationID          string
	JTI                  string
	AdminID              int64
	TargetNodeID         int64
	NodeBaseURL          string
	LocalHandle          string
	PermissionVersion    int64
	ControllerGeneration int64
	ExpiresAt            time.Time
	Replayed             bool
}

type AdminHandoffRedemption struct {
	AdminID              int64  `json:"admin_id"`
	LocalHandle          string `json:"local_handle"`
	PermissionVersion    int64  `json:"permission_version"`
	ControllerGeneration int64  `json:"controller_generation"`
}

func (s *Store) CreateAdminHandoff(ctx context.Context, p CreateAdminHandoffParams) (AdminHandoff, error) {
	if !validUUIDText(p.OperationID) || !validUUIDText(p.JTI) || len(p.SecretHash) != 32 || p.AdminID <= 0 ||
		p.NodeID <= 0 || p.Issuer == "" || p.KeyID == "" || p.TicketTTL <= 0 {
		return AdminHandoff{}, ErrInvalidAdminHandoff
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return AdminHandoff{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if replay, found, err := getAdminHandoffByOperation(ctx, tx, p.OperationID, p.AdminID, p.NodeID, p.Now); err != nil {
		return AdminHandoff{}, err
	} else if found {
		replay.Replayed = true
		if err := tx.Commit(); err != nil {
			return AdminHandoff{}, err
		}
		return replay, nil
	}
	var handoff AdminHandoff
	err = tx.QueryRowContext(ctx, `
		SELECT epoch.generation,node.base_url,link.local_handle,link.permission_version
		FROM controller_epochs epoch,admins admin,admin_node_links link,nodes node
		WHERE epoch.state='active' AND admin.id=$1 AND admin.status='active'
		  AND link.admin_id=admin.id AND link.node_id=$2 AND link.state='verified'
		  AND link.revoked_at IS NULL AND link.last_verified_at>$3
		  AND node.id=link.node_id AND node.role='compute'
		  AND node.connectivity_state='online' AND node.operational_state='active'
		  AND node.controller_generation=epoch.generation
		  AND node.compatibility_state='compatible' AND node.base_url<>''
		FOR SHARE OF epoch,admin,link,node`, p.AdminID, p.NodeID, p.Now.Add(-2*time.Minute)).Scan(
		&handoff.ControllerGeneration, &handoff.NodeBaseURL, &handoff.LocalHandle, &handoff.PermissionVersion)
	if err == sql.ErrNoRows {
		return AdminHandoff{}, ErrAdminHandoffUnavailable
	}
	if err != nil {
		return AdminHandoff{}, err
	}
	handoff.OperationID = p.OperationID
	handoff.JTI = p.JTI
	handoff.AdminID = p.AdminID
	handoff.TargetNodeID = p.NodeID
	handoff.ExpiresAt = p.Now.Add(p.TicketTTL)
	if _, err := tx.ExecContext(ctx, `INSERT INTO control_tickets (
		jti,operation_id,secret_hash,ticket_type,issuer,audience,subject,admin_id,
		target_node_id,key_id,controller_generation,issued_at,not_before,expires_at
		) VALUES ($1,$2,$3,'node_admin',$4,$5,$6,$7,$8,$9,$10,$11,$11,$12)`,
		p.JTI, p.OperationID, p.SecretHash, p.Issuer, handoff.NodeBaseURL,
		handoff.LocalHandle, p.AdminID, p.NodeID, p.KeyID, handoff.ControllerGeneration,
		p.Now, handoff.ExpiresAt); err != nil {
		return AdminHandoff{}, fmt.Errorf("insert admin handoff: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events (
		occurred_at,actor_type,actor_id,action,target_type,target_id,operation_id,
		controller_generation,outcome,detail
		) VALUES ($6,'admin',$1::text,'node-admin-handoff','node',$2::text,$3,$4,
		'issued',jsonb_build_object('expires_at',$5::timestamptz))`, p.AdminID, p.NodeID,
		p.OperationID, handoff.ControllerGeneration, handoff.ExpiresAt, p.Now); err != nil {
		return AdminHandoff{}, err
	}
	if err := tx.Commit(); err != nil {
		return AdminHandoff{}, err
	}
	return handoff, nil
}

func getAdminHandoffByOperation(
	ctx context.Context,
	tx *sql.Tx,
	operationID string,
	adminID, nodeID int64,
	now time.Time,
) (AdminHandoff, bool, error) {
	var out AdminHandoff
	err := tx.QueryRowContext(ctx, `SELECT ticket.operation_id::text,ticket.jti::text,
		ticket.admin_id,ticket.target_node_id,node.base_url,ticket.subject,
		link.permission_version,ticket.controller_generation,ticket.expires_at
		FROM control_tickets ticket
		JOIN nodes node ON node.id=ticket.target_node_id
		JOIN admin_node_links link ON link.admin_id=ticket.admin_id AND link.node_id=ticket.target_node_id
		WHERE ticket.operation_id=$1 AND ticket.admin_id=$2 AND ticket.target_node_id=$3
		  AND ticket.ticket_type='node_admin' AND ticket.consumed_at IS NULL
		  AND ticket.revoked_at IS NULL AND ticket.expires_at>$4`, operationID, adminID, nodeID, now).Scan(
		&out.OperationID, &out.JTI, &out.AdminID, &out.TargetNodeID, &out.NodeBaseURL,
		&out.LocalHandle, &out.PermissionVersion, &out.ControllerGeneration, &out.ExpiresAt)
	if err == sql.ErrNoRows {
		return AdminHandoff{}, false, nil
	}
	if err != nil {
		return AdminHandoff{}, false, err
	}
	return out, true, nil
}

func (s *Store) ConsumeAdminHandoff(
	ctx context.Context,
	jti string,
	secretHash []byte,
	nodeID int64,
	expectedIssuer, expectedKeyID string,
	now time.Time,
) (AdminHandoffRedemption, bool, error) {
	if !validUUIDText(jti) || len(secretHash) != 32 || nodeID <= 0 ||
		expectedIssuer == "" || expectedKeyID == "" {
		return AdminHandoffRedemption{}, false, ErrInvalidAdminHandoff
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var out AdminHandoffRedemption
	err := s.DB.QueryRowContext(ctx, `WITH consumed AS (
		UPDATE control_tickets ticket SET consumed_at=$4,consumed_by_node_id=$2
		FROM controller_epochs epoch,admins admin,admin_node_links link,nodes node
		WHERE ticket.jti=$1 AND ticket.target_node_id=$2 AND ticket.secret_hash=$3
		  AND ticket.ticket_type='node_admin' AND ticket.not_before<=$4 AND ticket.expires_at>$4
		  AND ticket.issued_at<=$4 AND ticket.issuer=$5 AND ticket.key_id=$6
		  AND ticket.consumed_at IS NULL AND ticket.revoked_at IS NULL
		  AND epoch.state='active' AND epoch.generation=ticket.controller_generation
		  AND node.id=ticket.target_node_id AND node.base_url=ticket.audience
		  AND admin.id=ticket.admin_id AND admin.status='active'
		  AND link.admin_id=ticket.admin_id AND link.node_id=ticket.target_node_id
		  AND link.local_handle=ticket.subject AND link.state='verified' AND link.revoked_at IS NULL
		RETURNING ticket.admin_id,ticket.subject,ticket.controller_generation
		) SELECT consumed.admin_id,consumed.subject,link.permission_version,
		  consumed.controller_generation FROM consumed
		JOIN admin_node_links link ON link.admin_id=consumed.admin_id AND link.node_id=$2`,
		jti, nodeID, secretHash, now, expectedIssuer, expectedKeyID).Scan(&out.AdminID, &out.LocalHandle,
		&out.PermissionVersion, &out.ControllerGeneration)
	if err == sql.ErrNoRows {
		return AdminHandoffRedemption{}, false, nil
	}
	if err != nil {
		return AdminHandoffRedemption{}, false, err
	}
	return out, true, nil
}
