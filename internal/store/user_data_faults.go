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
	ErrInvalidUserDataFault               = errors.New("invalid user data fault input")
	ErrUserDataFaultNotFound              = errors.New("user data fault not found")
	ErrUserDataFaultOperationConflict     = errors.New("user data fault operation conflict")
	ErrUserDataFaultAlreadyOpen           = errors.New("user already has an open data fault")
	ErrUserDataFaultHomeConflict          = errors.New("reported home node does not match authoritative home")
	ErrUserDataFaultAuthoritativeConflict = errors.New("user has conflicting authoritative replicas")
	ErrUserDataFaultState                 = errors.New("user data fault state conflict")
)

var userDataFaultReasonCodes = map[string]bool{
	"authoritative_integrity_mismatch": true,
	"user_directory_missing":           true,
	"user_directory_unreadable":        true,
	"user_database_corrupt":            true,
}

type ReportUserDataFaultParams struct {
	OperationID        string
	RequestDigest      []byte
	UserUUID           string
	ExpectedHomeNodeID int64
	ReasonCode         string
	AdminID            int64
	Now                time.Time
}

type UserDataFaultStatus struct {
	ID                    string     `json:"id"`
	OperationID           string     `json:"operation_id"`
	UserUUID              string     `json:"user_uuid"`
	UserID                int64      `json:"-"`
	NodeID                int64      `json:"node_id"`
	ReasonCode            string     `json:"reason_code"`
	State                 string     `json:"state"`
	ActivityEpoch         int64      `json:"activity_epoch"`
	ControllerGeneration  int64      `json:"controller_generation"`
	FreezeOperationID     string     `json:"freeze_operation_id,omitempty"`
	Attempt               int        `json:"attempt"`
	ProtectionState       string     `json:"protection_state,omitempty"`
	ErrorCode             string     `json:"error_code,omitempty"`
	ReportedAt            time.Time  `json:"reported_at"`
	FrozenAt              *time.Time `json:"frozen_at,omitempty"`
	ResolvedAt            *time.Time `json:"resolved_at,omitempty"`
	ResolutionKind        string     `json:"resolution_kind,omitempty"`
	ResolutionOperationID string     `json:"resolution_operation_id,omitempty"`
	UpdatedAt             time.Time  `json:"updated_at"`
	Replayed              bool       `json:"replayed"`

	localHandle       string
	reportedByAdminID int64
}

type userDataFaultScanner interface {
	Scan(dest ...any) error
}

const userDataFaultStatusColumns = `
	SELECT fault.id::text,fault.operation_id::text,global_user.uuid::text,
	  fault.user_id,fault.node_id,fault.reason_code,fault.state,fault.activity_epoch,
	  fault.controller_generation,fault.freeze_operation_id::text,fault.attempt,
	  fault.protection_state,fault.error_code,fault.reported_at,fault.frozen_at,
	  fault.resolved_at,fault.resolution_kind,fault.resolution_operation_id::text,
	  fault.updated_at,fault.local_handle,fault.reported_by_admin_id
	FROM user_data_faults fault
	JOIN global_users global_user ON global_user.id=fault.user_id`

func scanUserDataFaultStatus(scanner userDataFaultScanner, status *UserDataFaultStatus) error {
	var freezeOperationID, protectionState, errorCode sql.NullString
	var frozenAt, resolvedAt sql.NullTime
	var resolutionKind, resolutionOperationID sql.NullString
	if err := scanner.Scan(
		&status.ID, &status.OperationID, &status.UserUUID, &status.UserID,
		&status.NodeID, &status.ReasonCode, &status.State, &status.ActivityEpoch,
		&status.ControllerGeneration, &freezeOperationID, &status.Attempt,
		&protectionState, &errorCode, &status.ReportedAt, &frozenAt, &resolvedAt,
		&resolutionKind, &resolutionOperationID, &status.UpdatedAt,
		&status.localHandle, &status.reportedByAdminID,
	); err != nil {
		return err
	}
	status.FreezeOperationID = freezeOperationID.String
	status.ProtectionState = protectionState.String
	status.ErrorCode = errorCode.String
	status.ResolutionKind = resolutionKind.String
	status.ResolutionOperationID = resolutionOperationID.String
	if frozenAt.Valid {
		value := frozenAt.Time
		status.FrozenAt = &value
	}
	if resolvedAt.Valid {
		value := resolvedAt.Time
		status.ResolvedAt = &value
	}
	return nil
}

func (s *Store) ReportUserDataFault(
	ctx context.Context,
	p ReportUserDataFaultParams,
) (*UserDataFaultStatus, error) {
	if !validUUIDText(p.OperationID) || !validUUIDText(p.UserUUID) ||
		len(p.RequestDigest) != 32 || p.ExpectedHomeNodeID <= 0 || p.AdminID <= 0 ||
		!userDataFaultReasonCodes[p.ReasonCode] {
		return nil, ErrInvalidUserDataFault
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	existing := &UserDataFaultStatus{}
	err = scanUserDataFaultStatus(tx.QueryRowContext(ctx,
		userDataFaultStatusColumns+` WHERE fault.operation_id=$1 FOR UPDATE OF fault`,
		p.OperationID), existing)
	if err == nil {
		var existingDigest []byte
		if err := tx.QueryRowContext(ctx,
			`SELECT request_digest FROM user_data_faults WHERE id=$1`, existing.ID).
			Scan(&existingDigest); err != nil {
			return nil, err
		}
		if existing.UserUUID != p.UserUUID || existing.NodeID != p.ExpectedHomeNodeID ||
			existing.ReasonCode != p.ReasonCode || existing.reportedByAdminID != p.AdminID ||
			!bytes.Equal(existingDigest, p.RequestDigest) {
			return nil, ErrUserDataFaultOperationConflict
		}
		existing.Replayed = true
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return existing, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	var globalUserID, legacyUserID int64
	var homeNodeID sql.NullInt64
	var username, nodeRole, localHandle string
	var activityEpoch int64
	err = tx.QueryRowContext(ctx, `
		SELECT global_user.id,legacy_user.id,legacy_user.home_node_id,legacy_user.username,
		  node.role,COALESCE(account.local_handle,legacy_user.username),
		  COALESCE(activity.activity_epoch,1)
		FROM global_users global_user
		JOIN users legacy_user ON legacy_user.id=global_user.legacy_user_id
		LEFT JOIN nodes node ON node.id=legacy_user.home_node_id
		LEFT JOIN node_accounts account ON account.user_id=global_user.id
		  AND account.node_id=legacy_user.home_node_id
		LEFT JOIN user_activity_leases activity ON activity.user_id=global_user.id
		WHERE global_user.uuid=$1 AND global_user.status='active' AND legacy_user.status='active'
		FOR UPDATE OF global_user,legacy_user`, p.UserUUID).Scan(
		&globalUserID, &legacyUserID, &homeNodeID, &username, &nodeRole,
		&localHandle, &activityEpoch,
	)
	if err == sql.ErrNoRows {
		return nil, ErrUserDataFaultNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = username
	if !homeNodeID.Valid || homeNodeID.Int64 != p.ExpectedHomeNodeID || nodeRole != "compute" {
		return nil, ErrUserDataFaultHomeConflict
	}
	var conflictingAuthoritative bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM replica_copies
		  WHERE user_id=$1 AND is_authoritative AND node_id<>$2
		)`, globalUserID, homeNodeID.Int64).Scan(&conflictingAuthoritative); err != nil {
		return nil, err
	}
	if conflictingAuthoritative {
		return nil, ErrUserDataFaultAuthoritativeConflict
	}
	var openFaultID string
	err = tx.QueryRowContext(ctx, `
		SELECT id::text FROM user_data_faults
		WHERE user_id=$1 AND state<>'resolved' FOR UPDATE`, globalUserID).Scan(&openFaultID)
	if err == nil {
		return nil, ErrUserDataFaultAlreadyOpen
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	var generation int64
	if err := tx.QueryRowContext(ctx,
		`SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).Scan(&generation); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNoActiveController
		}
		return nil, err
	}

	var faultID string
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO user_data_faults (
		  operation_id,request_digest,user_id,legacy_user_id,node_id,local_handle,
		  reason_code,state,activity_epoch,controller_generation,
		  reported_by_admin_id,reported_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,'reported',$8,$9,$10,$11,$11)
		RETURNING id::text`, p.OperationID, p.RequestDigest, globalUserID, legacyUserID,
		homeNodeID.Int64, localHandle, p.ReasonCode, activityEpoch, generation,
		p.AdminID, p.Now).Scan(&faultID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,state,last_sync_at)
		VALUES ($1,$2,'home','corrupt',$3)
		ON CONFLICT (user_id,node_id) DO UPDATE SET
		  kind='home',state='corrupt',last_sync_at=$3`, legacyUserID, homeNodeID.Int64, p.Now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO replica_copies (
		  id,user_id,node_id,snapshot_id,replica_kind,state,origin,is_authoritative,
		  compatibility_state,integrity_state,integrity_error_code,created_at,updated_at
		) VALUES (
		  gen_random_uuid(),$1,$2,NULL,'active','corrupt','primary',true,
		  'compatible','corrupt',$3,$4,$4
		) ON CONFLICT (user_id,node_id) DO UPDATE SET
		  snapshot_id=NULL,replica_kind='active',state='corrupt',origin='primary',
		  is_authoritative=true,integrity_state='corrupt',integrity_operation_id=NULL,
		  integrity_lease_until=NULL,integrity_error_code=$3,updated_at=$4`,
		globalUserID, homeNodeID.Int64, p.ReasonCode, p.Now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE user_activity_leases SET state='ended',lease_expires_at=$2,
		  in_flight_reads=0,in_flight_writes=0,updated_at=$2
		WHERE user_id=$1 AND state<>'ended'`, globalUserID, p.Now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE control_tickets SET revoked_at=$2
		WHERE user_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL`, globalUserID, p.Now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE tickets SET used_at=$2
		WHERE user_id=$1 AND used_at IS NULL`, legacyUserID, p.Now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO alerts (
		  id,deduplication_key,severity,state,category,user_id,node_id,summary,
		  first_seen_at,last_seen_at,notify_after,occurrence_count
		) VALUES (
		  gen_random_uuid(),'user-data-fault:'||$1::text,'critical','open',
		  'user_data_fault',$1::bigint,$2::bigint,'用户权威数据故障：写入已关闭，等待冻结与恢复判定',
		  $3,$3,$3,1
		) ON CONFLICT (deduplication_key) DO UPDATE SET
		  state='open',severity='critical',node_id=EXCLUDED.node_id,
		  last_seen_at=EXCLUDED.last_seen_at,notify_after=EXCLUDED.notify_after,
		  resolved_at=NULL,occurrence_count=alerts.occurrence_count+1`,
		globalUserID, homeNodeID.Int64, p.Now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  actor_type,actor_id,action,target_type,target_id,operation_id,
		  controller_generation,input_digest,outcome,detail
		) VALUES (
		  'admin',$1::text,'user-data-fault-reported','user',$2::text,$3,$4,$5,
		  'succeeded',jsonb_build_object(
		    'fault_id',$6::text,'node_id',$7::bigint,'reason_code',$8::text,
		    'activity_epoch',$9::bigint,'state','reported'))`,
		p.AdminID, globalUserID, p.OperationID, generation, p.RequestDigest,
		faultID, homeNodeID.Int64, p.ReasonCode, activityEpoch); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetUserDataFaultByID(ctx, faultID)
}

func (s *Store) GetUserDataFaultByID(ctx context.Context, faultID string) (*UserDataFaultStatus, error) {
	if !validUUIDText(faultID) {
		return nil, ErrInvalidUserDataFault
	}
	status := &UserDataFaultStatus{}
	err := scanUserDataFaultStatus(s.DB.QueryRowContext(ctx,
		userDataFaultStatusColumns+` WHERE fault.id=$1`, faultID), status)
	if err == sql.ErrNoRows {
		return nil, ErrUserDataFaultNotFound
	}
	if err != nil {
		return nil, err
	}
	return status, nil
}

func (s *Store) GetUserDataFaultByUserUUID(ctx context.Context, userUUID string) (*UserDataFaultStatus, error) {
	if !validUUIDText(userUUID) {
		return nil, ErrInvalidUserDataFault
	}
	status := &UserDataFaultStatus{}
	err := scanUserDataFaultStatus(s.DB.QueryRowContext(ctx,
		userDataFaultStatusColumns+`
		WHERE global_user.uuid=$1 ORDER BY fault.reported_at DESC,fault.id DESC LIMIT 1`,
		userUUID), status)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return status, nil
}

func (s *Store) ListSchedulableUserDataFaultIDs(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id::text FROM user_data_faults
		WHERE (
		  state='reported'
		  OR (state='retry_wait' AND next_attempt_at<=now())
		  OR (state='freezing' AND lease_until<=now())
		)
		ORDER BY updated_at,id LIMIT $1`, limit)
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

type UserDataFaultTask struct {
	ID                   string
	OperationID          string
	GlobalUserID         int64
	UserUUID             string
	NodeID               int64
	Handle               string
	ActivityEpoch        int64
	Attempt              int
	ControllerGeneration int64
}

func (s *Store) ClaimUserDataFault(
	ctx context.Context,
	faultID, freezeOperationID, workerID string,
	now time.Time,
	leaseTTL time.Duration,
) (*UserDataFaultTask, error) {
	if !validUUIDText(faultID) || !validUUIDText(freezeOperationID) ||
		!validUUIDText(workerID) || leaseTTL <= 0 {
		return nil, ErrInvalidUserDataFault
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var task UserDataFaultTask
	err := s.DB.QueryRowContext(ctx, `
		WITH active_epoch AS (
		  SELECT generation FROM controller_epochs WHERE state='active'
		), candidate AS (
		  SELECT fault.id FROM user_data_faults fault
		  WHERE fault.id=$1::uuid AND (
		    fault.state='reported'
		    OR (fault.state='retry_wait' AND fault.next_attempt_at<=$4)
		    OR (fault.state='freezing' AND fault.lease_until<=$4)
		  )
		  FOR UPDATE
		), claimed AS (
		  UPDATE user_data_faults fault SET
		    state='freezing',
		    freeze_operation_id=CASE
		      WHEN fault.controller_generation<>epoch.generation
		        OR fault.freeze_operation_id IS NULL THEN $2::uuid
		      ELSE fault.freeze_operation_id END,
		    controller_generation=epoch.generation,lease_owner=$3::uuid,
		    lease_until=$5,attempt=fault.attempt+1,next_attempt_at=NULL,
		    error_code=NULL,updated_at=$4
		  FROM candidate,active_epoch epoch
		  WHERE fault.id=candidate.id
		  RETURNING fault.id,fault.freeze_operation_id,fault.user_id,fault.node_id,
		    fault.local_handle,fault.activity_epoch,fault.attempt,fault.controller_generation
		)
		SELECT claimed.id::text,claimed.freeze_operation_id::text,claimed.user_id,
		  global_user.uuid::text,claimed.node_id,claimed.local_handle,
		  claimed.activity_epoch,claimed.attempt,claimed.controller_generation
		FROM claimed JOIN global_users global_user ON global_user.id=claimed.user_id`,
		faultID, freezeOperationID, workerID, now, now.Add(leaseTTL)).Scan(
		&task.ID, &task.OperationID, &task.GlobalUserID, &task.UserUUID,
		&task.NodeID, &task.Handle, &task.ActivityEpoch, &task.Attempt,
		&task.ControllerGeneration,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim user data fault: %w", err)
	}
	return &task, nil
}

func (s *Store) CompleteUserDataFaultFreeze(
	ctx context.Context,
	faultID, freezeOperationID, workerID string,
	now time.Time,
) (*UserDataFaultStatus, error) {
	if !validUUIDText(faultID) || !validUUIDText(freezeOperationID) || !validUUIDText(workerID) {
		return nil, ErrInvalidUserDataFault
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var userID, generation int64
	var state, protectionState string
	err = tx.QueryRowContext(ctx, `
		WITH active_epoch AS (
		  SELECT generation FROM controller_epochs WHERE state='active'
		), updated AS (
		  UPDATE user_data_faults fault SET
		    state=CASE WHEN protection.state IN ('takeover_available','restore_required')
		      THEN 'recovery_available' ELSE 'recovery_unavailable' END,
		    protection_state=CASE WHEN protection.state IN (
		      'takeover_available','restore_required','unavailable','conflict'
		    ) THEN protection.state ELSE 'unavailable' END,
		    frozen_at=$4,lease_owner=NULL,lease_until=NULL,next_attempt_at=NULL,
		    error_code=NULL,updated_at=$4
		  FROM active_epoch epoch,user_protection_states protection
		  WHERE fault.id=$1::uuid AND fault.freeze_operation_id=$2::uuid
		    AND fault.lease_owner=$3::uuid AND fault.state='freezing'
		    AND fault.lease_until>$4 AND fault.user_id=protection.user_id
		    AND fault.controller_generation=epoch.generation
		  RETURNING fault.user_id,fault.state,fault.protection_state,
		    fault.controller_generation
		)
		SELECT user_id,state,protection_state,controller_generation FROM updated`,
		faultID, freezeOperationID, workerID, now).Scan(
		&userID, &state, &protectionState, &generation,
	)
	if err == sql.ErrNoRows {
		return nil, ErrUserDataFaultState
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
		  actor_type,action,target_type,target_id,operation_id,
		  controller_generation,outcome,detail
		) VALUES (
		  'system','user-data-fault-frozen','user',$1::text,$2,$3,'succeeded',
		  jsonb_build_object(
		    'fault_id',$4::text,'state',$5::text,'protection_state',$6::text))`,
		userID, freezeOperationID, generation, faultID, state, protectionState); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetUserDataFaultByID(ctx, faultID)
}

func (s *Store) RetryUserDataFault(
	ctx context.Context,
	faultID, freezeOperationID, workerID, errorCode string,
	now time.Time,
	retryAfter time.Duration,
) error {
	if !validUUIDText(faultID) || !validUUIDText(freezeOperationID) ||
		!validUUIDText(workerID) || !ValidMachineReasonCode(errorCode) || retryAfter <= 0 {
		return ErrInvalidUserDataFault
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE user_data_faults fault SET state='retry_wait',lease_owner=NULL,
		  lease_until=NULL,next_attempt_at=$5,error_code=$4,updated_at=$6
		FROM controller_epochs epoch
		WHERE fault.id=$1::uuid AND fault.freeze_operation_id=$2::uuid
		  AND fault.lease_owner=$3::uuid AND fault.state='freezing'
		  AND fault.lease_until>$6 AND fault.controller_generation=epoch.generation
		  AND epoch.state='active'`, faultID, freezeOperationID, workerID,
		errorCode, now.Add(retryAfter), now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrUserDataFaultState
	}
	return nil
}

func requireUserDataFaultRecoveryReadyLocked(ctx context.Context, tx *sql.Tx, userID int64) error {
	var state string
	err := tx.QueryRowContext(ctx, `
		SELECT state FROM user_data_faults
		WHERE user_id=$1 AND state<>'resolved' FOR UPDATE`, userID).Scan(&state)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if state != "recovery_available" {
		return ErrUserDataFaultState
	}
	return nil
}

func resolveUserDataFaultLocked(
	ctx context.Context,
	tx *sql.Tx,
	userID int64,
	resolutionKind, resolutionOperationID string,
	now time.Time,
) error {
	if resolutionKind != "takeover" && resolutionKind != "restore" ||
		!validUUIDText(resolutionOperationID) {
		return ErrInvalidUserDataFault
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE user_data_faults SET state='resolved',resolution_kind=$2,
		  resolution_operation_id=$3::uuid,resolved_at=$4,updated_at=$4,
		  error_code=NULL,next_attempt_at=NULL
		WHERE user_id=$1 AND state='recovery_available'`, userID,
		resolutionKind, resolutionOperationID, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return nil
	}
	if rows != 1 {
		return ErrUserDataFaultState
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE alerts SET state='resolved',resolved_at=$2,last_seen_at=$2
		WHERE deduplication_key='user-data-fault:'||$1::text
		  AND state IN ('open','acknowledged')`, userID, now); err != nil {
		return err
	}
	return nil
}
