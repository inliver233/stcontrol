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
	ErrInvalidAdminNodeLink     = errors.New("invalid admin node link")
	ErrAdminNodeLinkConflict    = errors.New("admin node link operation conflict")
	ErrAdminNodeLinkRejected    = errors.New("node administrator verification rejected")
	ErrAdminNodeLinkUnavailable = errors.New("verified node administrator link unavailable")
)

type AdminNodeLink struct {
	NodeID            int64      `json:"node_id"`
	NodeName          string     `json:"node_name"`
	NodeBaseURL       string     `json:"node_base_url,omitempty"`
	NodeState         string     `json:"node_state"`
	LocalHandle       string     `json:"local_handle,omitempty"`
	State             string     `json:"state"`
	PermissionVersion int64      `json:"permission_version,omitempty"`
	LastVerifiedAt    *time.Time `json:"last_verified_at,omitempty"`
	LastErrorCode     string     `json:"last_error_code,omitempty"`
}

type CompleteAdminNodeVerificationParams struct {
	OperationID       string
	RequestDigest     []byte
	AdminID           int64
	NodeID            int64
	LocalHandle       string
	LocalUserID       string
	IsAdmin           bool
	PermissionVersion int64
	Now               time.Time
}

func (s *Store) ListAdminNodeLinks(ctx context.Context, adminID int64) ([]AdminNodeLink, error) {
	if adminID <= 0 {
		return nil, ErrInvalidAdminNodeLink
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT node.id,node.name,node.base_url,
		  CASE WHEN node.connectivity_state='online' AND node.operational_state='active'
		    AND node.compatibility_state='compatible' THEN 'available'
		    WHEN node.connectivity_state='offline' THEN 'offline'
		    WHEN node.operational_state<>'active' THEN node.operational_state ELSE 'incompatible' END,
		  COALESCE(link.local_handle,''),COALESCE(link.state,'unlinked'),
		  COALESCE(link.permission_version,0),link.last_verified_at,COALESCE(link.last_error_code,'')
		FROM nodes node
		JOIN admins admin ON admin.id=$1 AND admin.status='active'
		LEFT JOIN admin_node_links link ON link.admin_id=admin.id AND link.node_id=node.id
		WHERE node.role='compute' AND node.operational_state<>'retired'
		ORDER BY node.name,node.id`, adminID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var links []AdminNodeLink
	for rows.Next() {
		var link AdminNodeLink
		var verified sql.NullTime
		if err := rows.Scan(&link.NodeID, &link.NodeName, &link.NodeBaseURL, &link.NodeState,
			&link.LocalHandle, &link.State, &link.PermissionVersion, &verified, &link.LastErrorCode); err != nil {
			return nil, err
		}
		if verified.Valid {
			value := verified.Time
			link.LastVerifiedAt = &value
		}
		links = append(links, link)
	}
	return links, rows.Err()
}

func (s *Store) CompleteAdminNodeVerification(
	ctx context.Context,
	p CompleteAdminNodeVerificationParams,
) (*AdminNodeLink, error) {
	if p.OperationID == "" || len(p.RequestDigest) != 32 || p.AdminID <= 0 || p.NodeID <= 0 ||
		!validLocalHandle(p.LocalHandle) || (p.IsAdmin && (p.LocalUserID == "" || p.PermissionVersion <= 0)) {
		return nil, ErrInvalidAdminNodeLink
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var existingDigest []byte
	var existingAdminID, existingNodeID int64
	var outcome string
	err = tx.QueryRowContext(ctx, `SELECT request_digest,admin_id,node_id,outcome
		FROM admin_node_link_operations WHERE operation_id=$1`, p.OperationID).
		Scan(&existingDigest, &existingAdminID, &existingNodeID, &outcome)
	if err == nil {
		if existingAdminID != p.AdminID || existingNodeID != p.NodeID || !bytes.Equal(existingDigest, p.RequestDigest) {
			return nil, ErrAdminNodeLinkConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		if outcome != "verified" {
			return nil, ErrAdminNodeLinkRejected
		}
		return s.GetVerifiedAdminNodeLink(ctx, p.AdminID, p.NodeID)
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	var generation int64
	err = tx.QueryRowContext(ctx, `SELECT epoch.generation FROM controller_epochs epoch,admins admin,nodes node
		WHERE epoch.state='active' AND admin.id=$1 AND admin.status='active'
		  AND node.id=$2 AND node.role='compute'`, p.AdminID, p.NodeID).Scan(&generation)
	if err == sql.ErrNoRows {
		return nil, ErrAdminNodeLinkUnavailable
	}
	if err != nil {
		return nil, err
	}
	resultOutcome := "rejected"
	var localUserID any
	var permissionVersion any
	var errorCode any = "not_node_admin"
	if p.IsAdmin {
		resultOutcome = "verified"
		localUserID = p.LocalUserID
		permissionVersion = p.PermissionVersion
		errorCode = nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO admin_node_link_operations (
		operation_id,request_digest,admin_id,node_id,local_handle,outcome,result_local_user_id,
		permission_version,error_code,controller_generation,completed_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		p.OperationID, p.RequestDigest, p.AdminID, p.NodeID, p.LocalHandle, resultOutcome,
		localUserID, permissionVersion, errorCode, generation, p.Now); err != nil {
		return nil, err
	}
	if p.IsAdmin {
		if _, err := tx.ExecContext(ctx, `INSERT INTO admin_node_links (
			admin_id,node_id,local_handle,local_user_id,state,permission_version,
			last_verified_at,revoked_at,last_error_code,created_at,updated_at
			) VALUES ($1,$2,$3,$4,'verified',$5,$6,NULL,NULL,$6,$6)
			ON CONFLICT (admin_id,node_id) DO UPDATE SET local_handle=EXCLUDED.local_handle,
			local_user_id=EXCLUDED.local_user_id,state='verified',permission_version=EXCLUDED.permission_version,
			last_verified_at=EXCLUDED.last_verified_at,revoked_at=NULL,last_error_code=NULL,
			updated_at=EXCLUDED.updated_at`, p.AdminID, p.NodeID, p.LocalHandle,
			p.LocalUserID, p.PermissionVersion, p.Now); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events (
		occurred_at,actor_type,actor_id,action,target_type,target_id,operation_id,
		controller_generation,input_digest,outcome,detail
		) VALUES ($9,'admin',$1::text,'verify-node-admin','node',$2::text,$3,$4,$5,$6,
		jsonb_build_object('local_handle',$7::text,'permission_version',$8::bigint))`, p.AdminID, p.NodeID,
		p.OperationID, generation, p.RequestDigest, resultOutcome, p.LocalHandle,
		p.PermissionVersion, p.Now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if !p.IsAdmin {
		return nil, ErrAdminNodeLinkRejected
	}
	return s.GetVerifiedAdminNodeLink(ctx, p.AdminID, p.NodeID)
}

func (s *Store) GetVerifiedAdminNodeLink(ctx context.Context, adminID, nodeID int64) (*AdminNodeLink, error) {
	if adminID <= 0 || nodeID <= 0 {
		return nil, ErrInvalidAdminNodeLink
	}
	var out AdminNodeLink
	var verified time.Time
	err := s.DB.QueryRowContext(ctx, `SELECT node.id,node.name,node.base_url,
		'available',link.local_handle,link.state,link.permission_version,
		link.last_verified_at,COALESCE(link.last_error_code,'')
		FROM admin_node_links link
		JOIN admins admin ON admin.id=link.admin_id AND admin.status='active'
		JOIN nodes node ON node.id=link.node_id AND node.role='compute'
		WHERE link.admin_id=$1 AND link.node_id=$2 AND link.state='verified'
		  AND link.revoked_at IS NULL`, adminID, nodeID).Scan(
		&out.NodeID, &out.NodeName, &out.NodeBaseURL, &out.NodeState, &out.LocalHandle,
		&out.State, &out.PermissionVersion, &verified, &out.LastErrorCode)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out.LastVerifiedAt = &verified
	return &out, nil
}

func (s *Store) ConfirmAdminNodeLink(
	ctx context.Context,
	adminID, nodeID int64,
	localUserID string,
	permissionVersion int64,
	now time.Time,
) error {
	if adminID <= 0 || nodeID <= 0 || localUserID == "" || permissionVersion <= 0 {
		return ErrInvalidAdminNodeLink
	}
	result, err := s.DB.ExecContext(ctx, `UPDATE admin_node_links link
		SET permission_version=$4,last_verified_at=$5,last_error_code=NULL,updated_at=$5
		FROM admins admin,nodes node
		WHERE link.admin_id=$1 AND link.node_id=$2 AND link.local_user_id=$3
		  AND link.state='verified' AND link.revoked_at IS NULL
		  AND admin.id=link.admin_id AND admin.status='active'
		  AND node.id=link.node_id AND node.role='compute'
		  AND node.connectivity_state='online' AND node.operational_state='active'
		  AND node.compatibility_state='compatible'`, adminID, nodeID, localUserID, permissionVersion, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrAdminNodeLinkUnavailable
	}
	return nil
}

func (s *Store) MarkAdminNodeLinkStale(ctx context.Context, adminID, nodeID int64, reason string, now time.Time) error {
	if adminID <= 0 || nodeID <= 0 || reason == "" {
		return ErrInvalidAdminNodeLink
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE admin_node_links SET state='stale',
		last_error_code=$3,updated_at=$4 WHERE admin_id=$1 AND node_id=$2 AND state='verified'`,
		adminID, nodeID, reason, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE control_tickets SET revoked_at=COALESCE(revoked_at,$3)
		WHERE admin_id=$1 AND target_node_id=$2 AND ticket_type='node_admin'
		  AND consumed_at IS NULL AND revoked_at IS NULL`, adminID, nodeID, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeAdminNodeLink(ctx context.Context, adminID, nodeID int64, now time.Time) error {
	if adminID <= 0 || nodeID <= 0 {
		return ErrInvalidAdminNodeLink
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE admin_node_links SET state='revoked',
		revoked_at=$3,updated_at=$3 WHERE admin_id=$1 AND node_id=$2 AND state<>'revoked'`,
		adminID, nodeID, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return ErrAdminNodeLinkUnavailable
	}
	if _, err = tx.ExecContext(ctx, `UPDATE control_tickets SET revoked_at=COALESCE(revoked_at,$3)
		WHERE admin_id=$1 AND target_node_id=$2 AND ticket_type='node_admin'
		  AND consumed_at IS NULL AND revoked_at IS NULL`, adminID, nodeID, now); err != nil {
		return err
	}
	return tx.Commit()
}

func validLocalHandle(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func (link AdminNodeLink) ValidateForHandoff() error {
	if link.NodeID <= 0 || link.NodeBaseURL == "" || !validLocalHandle(link.LocalHandle) ||
		link.State != "verified" || link.PermissionVersion <= 0 || link.LastVerifiedAt == nil {
		return fmt.Errorf("invalid verified node administrator link")
	}
	return nil
}
