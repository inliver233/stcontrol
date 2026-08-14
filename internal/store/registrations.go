package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/lib/pq"
)

var (
	ErrInvalidRegistration            = errors.New("invalid registration workflow input")
	ErrRegistrationConflict           = errors.New("registration request conflicts with existing facts")
	ErrRegistrationNodeUnavailable    = errors.New("selected node registration policy is unavailable")
	ErrRegistrationInvitationRequired = errors.New("selected node requires an invitation")
	ErrRegistrationStateConflict      = errors.New("registration workflow state conflict")
)

type CreateRegistrationWorkflowParams struct {
	WorkflowID           string
	OperationID          string
	RequestDigest        []byte
	PendingTokenHash     []byte
	ClientExpiresAt      time.Time
	NodeID               int64
	PolicyVersion        int64
	LocalHandle          string
	DisplayName          string
	AuthProvider         string
	PasswordHash         string
	PasswordMaterialHash string
	PasswordMaterialSalt string
	OAuthSubject         string
	AvatarURL            string
	InvitationCiphertext string
	Now                  time.Time
}

type RegistrationWorkflow struct {
	WorkflowID   string
	OperationID  string
	State        string
	LocalHandle  string
	ResultUserID int64
	Replayed     bool
}

type RegistrationWorkflowStatus struct {
	WorkflowID   string
	OperationID  string
	State        string
	LocalHandle  string
	ErrorCode    string
	ResultUserID int64
}

type RegistrationWorkflowExecution struct {
	WorkflowID           string
	State                string
	Attempt              int
	NextAttemptAt        sql.NullTime
	ControllerGeneration int64
	NodeID               int64
	NodeName             string
	NodeStatus           string
	NodePolicyState      string
	NodePolicyVersion    int64
	NodePolicyExpiresAt  sql.NullTime
	PolicyVersion        int64
	LocalHandle          string
	DisplayName          string
	AuthProvider         string
	PasswordHash         sql.NullString
	PasswordMaterialHash sql.NullString
	PasswordMaterialSalt sql.NullString
	OAuthSubject         sql.NullString
	AvatarURL            sql.NullString
	InvitationCiphertext sql.NullString
}

func (s *Store) CreateRegistrationWorkflow(
	ctx context.Context,
	p CreateRegistrationWorkflowParams,
) (RegistrationWorkflow, error) {
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	if err := validateRegistrationWorkflowParams(p); err != nil {
		return RegistrationWorkflow{}, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return RegistrationWorkflow{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var existing RegistrationWorkflow
	var existingDigest []byte
	var resultUserID sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT workflow.id,workflow.operation_id,workflow.state,registration.local_handle,
		  registration.result_user_id,registration.request_digest
		FROM workflows workflow
		JOIN registration_workflows registration ON registration.workflow_id=workflow.id
		WHERE workflow.operation_id=$1 FOR UPDATE OF workflow,registration`, p.OperationID).
		Scan(&existing.WorkflowID, &existing.OperationID, &existing.State, &existing.LocalHandle,
			&resultUserID, &existingDigest)
	if err == nil {
		if !bytes.Equal(existingDigest, p.RequestDigest) {
			return RegistrationWorkflow{}, ErrRegistrationConflict
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE registration_workflows
			SET pending_token_hash=$2,client_expires_at=$3,updated_at=$4
			WHERE workflow_id=$1`, existing.WorkflowID, p.PendingTokenHash, p.ClientExpiresAt, p.Now); err != nil {
			return RegistrationWorkflow{}, err
		}
		if err := tx.Commit(); err != nil {
			return RegistrationWorkflow{}, err
		}
		existing.ResultUserID = resultUserID.Int64
		existing.Replayed = true
		return existing, nil
	}
	if err != sql.ErrNoRows {
		return RegistrationWorkflow{}, err
	}

	var role, nodeStatus, connectivityState, operationalState, compatibilityState, capacityState string
	var controlMode, desiredControlMode, policyState string
	var allowRegister bool
	var policyVersion int64
	var policyExpiresAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT role,status,connectivity_state,operational_state,compatibility_state,capacity_state,
		  control_mode,desired_control_mode,allow_register,registration_policy_state,
		  registration_policy_version,registration_policy_expires_at
		FROM nodes WHERE id=$1 FOR SHARE`, p.NodeID).
		Scan(&role, &nodeStatus, &connectivityState, &operationalState, &compatibilityState, &capacityState,
			&controlMode, &desiredControlMode, &allowRegister, &policyState, &policyVersion, &policyExpiresAt)
	if err == sql.ErrNoRows {
		return RegistrationWorkflow{}, ErrRegistrationNodeUnavailable
	}
	if err != nil {
		return RegistrationWorkflow{}, err
	}
	if role != "compute" || nodeStatus != "online" || connectivityState != "online" ||
		operationalState != "active" || compatibilityState != "compatible" ||
		(capacityState != "open" && capacityState != "busy") ||
		controlMode != "managed" || desiredControlMode != "managed" || !allowRegister ||
		(policyState != "open" && policyState != "invitation_required") ||
		policyVersion != p.PolicyVersion || !policyExpiresAt.Valid || !policyExpiresAt.Time.After(p.Now) {
		return RegistrationWorkflow{}, ErrRegistrationNodeUnavailable
	}
	if policyState == "invitation_required" && p.InvitationCiphertext == "" {
		return RegistrationWorkflow{}, ErrRegistrationInvitationRequired
	}
	var occupied int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE username=$1`, p.LocalHandle).Scan(&occupied)
	if err == nil {
		return RegistrationWorkflow{}, ErrRegistrationConflict
	}
	if err != sql.ErrNoRows {
		return RegistrationWorkflow{}, err
	}

	var generation int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO workflows (
		  id,operation_id,workflow_type,state,target_node_id,controller_generation,created_at,updated_at
		)
		SELECT $1,$2,'registration','scheduled',$3,generation,$4,$4
		FROM controller_epochs WHERE state='active'
		RETURNING controller_generation`, p.WorkflowID, p.OperationID, p.NodeID, p.Now).Scan(&generation)
	if err == sql.ErrNoRows {
		return RegistrationWorkflow{}, ErrNoActiveController
	}
	if err != nil {
		return RegistrationWorkflow{}, registrationInsertError(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO registration_workflows (
		  workflow_id,request_digest,pending_token_hash,client_expires_at,
		  local_handle,display_name,auth_provider,password_hash,
		  password_material_hash,password_material_salt,oauth_subject,avatar_url,
		  invitation_ciphertext,registration_policy_version,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)`,
		p.WorkflowID, p.RequestDigest, p.PendingTokenHash, p.ClientExpiresAt,
		p.LocalHandle, p.DisplayName, p.AuthProvider, nullIfEmpty(p.PasswordHash),
		nullIfEmpty(p.PasswordMaterialHash), nullIfEmpty(p.PasswordMaterialSalt),
		nullIfEmpty(p.OAuthSubject), nullIfEmpty(p.AvatarURL), nullIfEmpty(p.InvitationCiphertext),
		p.PolicyVersion, p.Now); err != nil {
		return RegistrationWorkflow{}, registrationInsertError(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO workflow_steps (workflow_id,step_name,state,updated_at)
		VALUES ($1,'provision_user','pending',$2)`, p.WorkflowID, p.Now); err != nil {
		return RegistrationWorkflow{}, err
	}
	if err := tx.Commit(); err != nil {
		return RegistrationWorkflow{}, err
	}
	return RegistrationWorkflow{
		WorkflowID: p.WorkflowID, OperationID: p.OperationID, State: "scheduled", LocalHandle: p.LocalHandle,
	}, nil
}

func (s *Store) GetRegistrationWorkflowStatus(
	ctx context.Context,
	pendingTokenHash []byte,
	now time.Time,
) (*RegistrationWorkflowStatus, error) {
	if len(pendingTokenHash) != 32 {
		return nil, ErrInvalidRegistration
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var out RegistrationWorkflowStatus
	var errorCode sql.NullString
	var resultUserID sql.NullInt64
	err := s.DB.QueryRowContext(ctx, `
		SELECT workflow.id,workflow.operation_id,workflow.state,registration.local_handle,
		  workflow.error_code,registration.result_user_id
		FROM workflows workflow
		JOIN registration_workflows registration ON registration.workflow_id=workflow.id
		WHERE registration.pending_token_hash=$1
		  AND registration.client_expires_at>$2`, pendingTokenHash, now).
		Scan(&out.WorkflowID, &out.OperationID, &out.State, &out.LocalHandle, &errorCode, &resultUserID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out.ErrorCode = errorCode.String
	out.ResultUserID = resultUserID.Int64
	return &out, nil
}

func (s *Store) GetRegistrationWorkflowExecution(
	ctx context.Context,
	workflowID string,
) (*RegistrationWorkflowExecution, error) {
	if workflowID == "" {
		return nil, ErrInvalidRegistration
	}
	var out RegistrationWorkflowExecution
	err := s.DB.QueryRowContext(ctx, `
		SELECT workflow.id,workflow.state,workflow.attempt,workflow.next_attempt_at,
		  workflow.controller_generation,workflow.target_node_id,node.name,node.status,
		  node.registration_policy_state,node.registration_policy_version,
		  node.registration_policy_expires_at,registration.registration_policy_version,
		  registration.local_handle,registration.display_name,registration.auth_provider,
		  registration.password_hash,registration.password_material_hash,
		  registration.password_material_salt,registration.oauth_subject,registration.avatar_url,
		  registration.invitation_ciphertext
		FROM workflows workflow
		JOIN registration_workflows registration ON registration.workflow_id=workflow.id
		JOIN nodes node ON node.id=workflow.target_node_id
		WHERE workflow.id=$1 AND workflow.workflow_type='registration'`, workflowID).
		Scan(&out.WorkflowID, &out.State, &out.Attempt, &out.NextAttemptAt,
			&out.ControllerGeneration, &out.NodeID, &out.NodeName, &out.NodeStatus,
			&out.NodePolicyState, &out.NodePolicyVersion, &out.NodePolicyExpiresAt, &out.PolicyVersion,
			&out.LocalHandle, &out.DisplayName, &out.AuthProvider, &out.PasswordHash,
			&out.PasswordMaterialHash, &out.PasswordMaterialSalt, &out.OAuthSubject,
			&out.AvatarURL, &out.InvitationCiphertext)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &out, err
}

func (s *Store) ListRunnableRegistrationWorkflowIDs(
	ctx context.Context,
	limit int,
	now time.Time,
) ([]string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT workflow.id
		FROM workflows workflow
		JOIN controller_epochs epoch
		  ON epoch.generation=workflow.controller_generation AND epoch.state='active'
		WHERE workflow.workflow_type='registration'
		  AND (workflow.state='scheduled'
		    OR (workflow.state='retry_wait' AND workflow.next_attempt_at<=$2))
		  AND (workflow.lease_until IS NULL OR workflow.lease_until<=$2)
		ORDER BY workflow.created_at LIMIT $1`, limit, now)
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

func (s *Store) ClaimRegistrationWorkflow(
	ctx context.Context,
	workflowID, workerID string,
	now time.Time,
	ttl time.Duration,
) (bool, error) {
	if workflowID == "" || workerID == "" || ttl <= 0 {
		return false, ErrInvalidRegistration
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE workflows workflow
		SET lease_owner=$2,lease_until=$4,updated_at=$3
		FROM controller_epochs epoch
		WHERE workflow.id=$1 AND workflow.workflow_type='registration'
		  AND workflow.controller_generation=epoch.generation AND epoch.state='active'
		  AND (workflow.state='scheduled'
		    OR (workflow.state='retry_wait' AND workflow.next_attempt_at<=$3))
		  AND (workflow.lease_until IS NULL OR workflow.lease_until<=$3)`,
		workflowID, workerID, now, now.Add(ttl))
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		if err == nil {
			err = tx.Commit()
		}
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflow_steps SET state='running',started_at=COALESCE(started_at,$2),updated_at=$2
		WHERE workflow_id=$1 AND step_name='provision_user' AND state IN ('pending','retry_wait','running')`,
		workflowID, now); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) ReleaseRegistrationWorkflow(ctx context.Context, workflowID, workerID string) error {
	if workflowID == "" || workerID == "" {
		return ErrInvalidRegistration
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE workflows SET lease_owner=NULL,lease_until=NULL
		WHERE id=$1 AND workflow_type='registration' AND lease_owner=$2`, workflowID, workerID)
	return err
}

func (s *Store) ScheduleRegistrationRetry(
	ctx context.Context,
	workflowID, workerID, errorCode string,
	nextAttemptAt, now time.Time,
) (int, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if workflowID == "" || workerID == "" || errorCode == "" || !nextAttemptAt.After(now) {
		return 0, ErrInvalidRegistration
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var attempt int
	err = tx.QueryRowContext(ctx, `
		UPDATE workflows SET state='retry_wait',attempt=attempt+1,next_attempt_at=$4,
		  error_code=$3,error_summary=NULL,lease_owner=NULL,lease_until=NULL,updated_at=$5
		WHERE id=$1 AND workflow_type='registration' AND lease_owner=$2 AND lease_until>$5
		  AND state NOT IN ('succeeded','failed','cancelled')
		RETURNING attempt`, workflowID, workerID, errorCode, nextAttemptAt, now).Scan(&attempt)
	if err == sql.ErrNoRows {
		return 0, ErrRegistrationStateConflict
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflow_steps SET state='retry_wait',attempt=attempt+1,error_code=$2,updated_at=$3
		WHERE workflow_id=$1 AND step_name='provision_user'`, workflowID, errorCode, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return attempt, nil
}


// RegistrationReservationTTL bounds how long a pending registration may hold a
// username.  After this window the reservation is released (and the workflow
// failed as reservation_expired) so a stuck or abandoned request cannot occupy
// a handle forever (R15).
const RegistrationReservationTTL = 24 * time.Hour

// ReleaseExpiredRegistrationReservations fails workflows whose handle
// reservation has been pending for longer than RegistrationReservationTTL and
// releases the handle.  Returns the number of reservations released.
func (s *Store) ReleaseExpiredRegistrationReservations(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE workflows workflow SET state='failed',error_code='reservation_expired',
		  error_summary=NULL,lease_owner=NULL,lease_until=NULL,finished_at=$2,updated_at=$2
		FROM registration_workflows registration
		WHERE registration.workflow_id=workflow.id
		  AND registration.reservation_state='pending'
		  AND workflow.workflow_type='registration'
		  AND workflow.state NOT IN ('succeeded','failed','cancelled')
		  AND workflow.created_at<=$1`, now.Add(-RegistrationReservationTTL), now)
	if err != nil {
		return 0, err
	}
	released, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if released > 0 {
		if _, err := tx.ExecContext(ctx, `
			UPDATE registration_workflows SET reservation_state='released',updated_at=$1
			WHERE reservation_state='pending' AND workflow_id IN (
			  SELECT id FROM workflows WHERE workflow_type='registration' AND state='failed'
			    AND error_code='reservation_expired')`, now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return released, nil
}
func (s *Store) FailRegistrationWorkflow(
	ctx context.Context,
	workflowID, workerID, errorCode string,
	now time.Time,
) error {
	if workflowID == "" || workerID == "" || errorCode == "" {
		return ErrInvalidRegistration
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE workflows SET state='failed',error_code=$3,error_summary=NULL,
		  lease_owner=NULL,lease_until=NULL,finished_at=$4,updated_at=$4
		WHERE id=$1 AND workflow_type='registration' AND lease_owner=$2 AND lease_until>$4
		  AND state NOT IN ('succeeded','failed','cancelled')`, workflowID, workerID, errorCode, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrRegistrationStateConflict
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE registration_workflows SET reservation_state='released',
		  password_hash=NULL,password_material_hash=NULL,password_material_salt=NULL,
		  oauth_subject=NULL,invitation_ciphertext=NULL,updated_at=$2
		WHERE workflow_id=$1`, workflowID, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflow_steps SET state='failed',error_code=$2,finished_at=$3,updated_at=$3
		WHERE workflow_id=$1 AND step_name='provision_user'`, workflowID, errorCode, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CompleteRegistrationWorkflow(
	ctx context.Context,
	workflowID, workerID, localUserID string,
	now time.Time,
) (*User, error) {
	if workflowID == "" || workerID == "" || localUserID == "" {
		return nil, ErrInvalidRegistration
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var state, handle, displayName, provider string
	var passwordHash, materialHash, materialSalt, oauthSubject, avatarURL sql.NullString
	var nodeID, generation, activeGeneration int64
	var resultUserID sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT workflow.state,workflow.target_node_id,workflow.controller_generation,
		  COALESCE((SELECT generation FROM controller_epochs WHERE state='active'),0),
		  registration.local_handle,registration.display_name,registration.auth_provider,
		  registration.password_hash,registration.password_material_hash,
		  registration.password_material_salt,registration.oauth_subject,registration.avatar_url,
		  registration.result_user_id
		FROM workflows workflow
		JOIN registration_workflows registration ON registration.workflow_id=workflow.id
		WHERE workflow.id=$1 AND workflow.workflow_type='registration'
		  AND (workflow.state='succeeded' OR (workflow.lease_owner=$2 AND workflow.lease_until>$3))
		FOR UPDATE OF workflow,registration`, workflowID, workerID, now).
		Scan(&state, &nodeID, &generation, &activeGeneration, &handle, &displayName, &provider,
			&passwordHash, &materialHash, &materialSalt, &oauthSubject, &avatarURL, &resultUserID)
	if err == sql.ErrNoRows {
		return nil, ErrRegistrationStateConflict
	}
	if err != nil {
		return nil, err
	}
	if state == "succeeded" && resultUserID.Valid {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return s.GetUserByID(ctx, resultUserID.Int64)
	}
	if (state != "scheduled" && state != "retry_wait") || generation != activeGeneration {
		return nil, ErrRegistrationStateConflict
	}

	user := &User{
		Username: handle, DisplayName: displayName, PasswordHash: passwordHash,
		AuthProvider: provider, OAuthID: oauthSubject, AvatarURL: avatarURL,
		HomeNodeID: sql.NullInt64{Int64: nodeID, Valid: true}, Status: "active",
	}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO users (username,display_name,password_enc,password_hash,
		  auth_provider,oauth_id,avatar_url,email,home_node_id,status)
		VALUES ($1,$2,NULL,$3,$4,$5,$6,NULL,$7,'active')
		RETURNING id,uuid,created_at`, handle, displayName, passwordHash, provider,
		oauthSubject, avatarURL, nodeID).Scan(&user.ID, &user.UUID, &user.CreatedAt)
	if err != nil {
		return nil, registrationInsertError(err)
	}
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO global_users (uuid,legacy_user_id,display_name,status,created_at,updated_at)
		VALUES ($1,$2,$3,'active',$4,$4) RETURNING id`,
		user.UUID, user.ID, displayName, user.CreatedAt).Scan(&user.GlobalID); err != nil {
		return nil, err
	}
	providerSubject := handle
	var identityPassword any
	if provider == "password" {
		providerSubject = handle
		identityPassword = passwordHash.String
	} else {
		providerSubject = oauthSubject.String
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO auth_identities (
		  user_id,provider,provider_subject,password_hash,status,created_at,updated_at
		) VALUES ($1,$2,$3,$4,'active',$5,$5)`,
		user.GlobalID, provider, providerSubject, identityPassword, user.CreatedAt); err != nil {
		return nil, registrationInsertError(err)
	}
	var nodePasswordHash, nodePasswordSalt any
	oauthSubjects := `{}`
	passwordVersion := int64(0)
	if provider == "password" {
		nodePasswordHash = materialHash.String
		nodePasswordSalt = materialSalt.String
		passwordVersion = 1
	} else {
		encoded, err := json.Marshal(map[string]string{provider: oauthSubject.String})
		if err != nil {
			return nil, err
		}
		oauthSubjects = string(encoded)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO node_accounts (
		  user_id,node_id,local_handle,local_user_id,status,account_version,
		  password_material_version,password_hash,password_salt,oauth_subjects,updated_at
		) VALUES ($1,$2,$3,$4,'active',1,$5,$6,$7,$8::jsonb,$9)`,
		user.GlobalID, nodeID, handle, localUserID, passwordVersion,
		nodePasswordHash, nodePasswordSalt, oauthSubjects, now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,data_version,state,last_sync_at)
		VALUES ($1,$2,'home',0,'ready',$3)
		ON CONFLICT (user_id,node_id) DO UPDATE
		SET kind='home',state='ready',last_sync_at=EXCLUDED.last_sync_at`, user.ID, nodeID, now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflows SET user_id=$2,state='succeeded',error_code=NULL,error_summary=NULL,
		  lease_owner=NULL,lease_until=NULL,next_attempt_at=NULL,finished_at=$3,updated_at=$3
		WHERE id=$1`, workflowID, user.GlobalID, now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE registration_workflows SET reservation_state='published',local_user_id=$2,
		  result_user_id=$3,password_hash=NULL,password_material_hash=NULL,
		  password_material_salt=NULL,oauth_subject=NULL,invitation_ciphertext=NULL,updated_at=$4
		WHERE workflow_id=$1`, workflowID, localUserID, user.ID, now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE workflow_steps SET state='succeeded',error_code=NULL,finished_at=$2,updated_at=$2
		WHERE workflow_id=$1 AND step_name='provision_user'`, workflowID, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return user, nil
}

func validateRegistrationWorkflowParams(p CreateRegistrationWorkflowParams) error {
	passwordMode := p.AuthProvider == "password" && p.PasswordHash != "" &&
		p.PasswordMaterialHash != "" && p.PasswordMaterialSalt != "" && p.OAuthSubject == ""
	oauthMode := (p.AuthProvider == "discord" || p.AuthProvider == "linuxdo") &&
		p.PasswordHash == "" && p.PasswordMaterialHash == "" && p.PasswordMaterialSalt == "" &&
		p.OAuthSubject != ""
	if p.WorkflowID == "" || p.OperationID == "" || len(p.RequestDigest) != 32 ||
		len(p.PendingTokenHash) != 32 || p.NodeID <= 0 || p.PolicyVersion <= 0 ||
		p.LocalHandle == "" || p.DisplayName == "" || p.ClientExpiresAt.IsZero() ||
		(!passwordMode && !oauthMode) {
		return ErrInvalidRegistration
	}
	if !p.Now.IsZero() && !p.ClientExpiresAt.After(p.Now) {
		return ErrInvalidRegistration
	}
	return nil
}

func registrationInsertError(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return ErrRegistrationConflict
	}
	return err
}
