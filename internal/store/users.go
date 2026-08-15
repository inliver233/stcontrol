package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// CreateUser 创建用户。
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	err = tx.QueryRowContext(ctx, `
	  INSERT INTO users (username, display_name, password_enc, password_hash,
	    auth_provider, oauth_id, avatar_url, email, home_node_id, status)
	  VALUES ($1,$2,NULL,$3,$4,$5,$6,$7,$8,$9)
	  RETURNING id, uuid, created_at`,
		u.Username, u.DisplayName, u.PasswordHash,
		u.AuthProvider, u.OAuthID, u.AvatarURL, u.Email, u.HomeNodeID, u.Status,
	).Scan(&u.ID, &u.UUID, &u.CreatedAt)
	if err != nil {
		return err
	}

	if err := tx.QueryRowContext(ctx, `
	  INSERT INTO global_users (uuid, legacy_user_id, display_name, status, created_at, updated_at)
	  VALUES ($1,$2,$3,$4,$5,$5) RETURNING id`,
		u.UUID, u.ID, u.DisplayName, u.Status, u.CreatedAt).Scan(&u.GlobalID); err != nil {
		return fmt.Errorf("create global user: %w", err)
	}

	providerSubject := u.Username
	var passwordHash any
	if u.AuthProvider == "password" {
		if !u.PasswordHash.Valid {
			return fmt.Errorf("password identity requires a password hash")
		}
		passwordHash = u.PasswordHash.String
	} else {
		if !u.OAuthID.Valid || u.OAuthID.String == "" {
			return fmt.Errorf("%s identity requires a provider subject", u.AuthProvider)
		}
		providerSubject = u.OAuthID.String
	}
	if _, err := tx.ExecContext(ctx, `
	  INSERT INTO auth_identities (user_id, provider, provider_subject, password_hash)
	  VALUES ($1,$2,$3,$4)`,
		u.GlobalID, u.AuthProvider, providerSubject, passwordHash); err != nil {
		return fmt.Errorf("create auth identity: %w", err)
	}

	if u.HomeNodeID.Valid {
		nodeAccountStatus := "active"
		if u.Status == "recovering" {
			nodeAccountStatus = "pending"
		}
		if _, err := tx.ExecContext(ctx, `
		  INSERT INTO node_accounts (user_id, node_id, local_handle, status)
		  VALUES ($1,$2,$3,$4)`, u.GlobalID, u.HomeNodeID.Int64, u.Username, nodeAccountStatus); err != nil {
			return fmt.Errorf("create node account mapping: %w", err)
		}
	}
	return tx.Commit()
}

// SetNodeAccountProvisioning records desired node-local authentication
// material before dispatch. It returns the fenced password material version.
func (s *Store) SetNodeAccountProvisioning(
	ctx context.Context,
	globalUserID, nodeID int64,
	passwordHash, passwordSalt, oauthProvider, oauthSubject string,
	now time.Time,
) (int64, error) {
	passwordMode := passwordHash != "" && passwordSalt != "" && oauthProvider == "" && oauthSubject == ""
	oauthMode := passwordHash == "" && passwordSalt == "" &&
		(oauthProvider == "discord" || oauthProvider == "linuxdo") && oauthSubject != ""
	if globalUserID <= 0 || nodeID <= 0 || (!passwordMode && !oauthMode) {
		return 0, fmt.Errorf("invalid node account material")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var hashValue, saltValue any
	var oauthValue any
	if passwordMode {
		hashValue = passwordHash
		saltValue = passwordSalt
	} else {
		oauthJSON, err := json.Marshal(map[string]string{oauthProvider: oauthSubject})
		if err != nil {
			return 0, err
		}
		oauthValue = string(oauthJSON)
	}
	var version int64
	err := s.DB.QueryRowContext(ctx, `
		UPDATE node_accounts
		SET status='pending', password_hash=$3, password_salt=$4,
		  oauth_subjects=CASE WHEN $5 IS NULL THEN oauth_subjects ELSE oauth_subjects || $5::jsonb END,
		  password_material_version=CASE WHEN $3 IS NULL
		    THEN password_material_version ELSE password_material_version+1 END,
		  account_version=account_version+1, updated_at=$6
		WHERE user_id=$1 AND node_id=$2
		RETURNING password_material_version`,
		globalUserID, nodeID, hashValue, saltValue, oauthValue, now).Scan(&version)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("node account mapping not found")
	}
	return version, err
}

func (s *Store) ActivateNodeAccount(
	ctx context.Context,
	legacyUserID, globalUserID, nodeID int64,
	localUserID string,
	now time.Time,
) error {
	if legacyUserID <= 0 || globalUserID <= 0 || nodeID <= 0 {
		return fmt.Errorf("invalid node account activation")
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
		UPDATE node_accounts SET status='active', local_user_id=COALESCE($3, local_user_id),
		  verified_at=$4, updated_at=$4
		WHERE user_id=$1 AND node_id=$2 AND status IN ('pending','error','active')`,
		globalUserID, nodeID, nullIfEmpty(localUserID), now)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return fmt.Errorf("node account mapping not found")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET status='active' WHERE id=$1`, legacyUserID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE global_users SET status='active', updated_at=$2 WHERE id=$1`, globalUserID, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) MarkNodeAccountError(ctx context.Context, globalUserID, nodeID int64, now time.Time) error {
	if globalUserID <= 0 || nodeID <= 0 {
		return fmt.Errorf("invalid node account")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE node_accounts SET status='error', updated_at=$3
		WHERE user_id=$1 AND node_id=$2`, globalUserID, nodeID, now)
	return err
}

func (s *Store) ListUserNodeAccounts(ctx context.Context, globalUserID int64) ([]UserNodeAccount, error) {
	if globalUserID <= 0 {
		return nil, fmt.Errorf("invalid global user")
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT account.node_id,account.local_handle,node.status,account.password_material_version
		FROM node_accounts account
		JOIN nodes node ON node.id=account.node_id
		WHERE account.user_id=$1 AND account.status IN ('active','pending','error')
		ORDER BY account.node_id`, globalUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []UserNodeAccount
	for rows.Next() {
		var account UserNodeAccount
		if err := rows.Scan(
			&account.NodeID, &account.LocalHandle, &account.NodeStatus, &account.PasswordMaterialVersion,
		); err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

func (s *Store) ListPendingPasswordSyncs(ctx context.Context, limit int, now time.Time) ([]PendingPasswordSync, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT global_user.legacy_user_id,account.user_id,account.node_id,account.local_handle,
		  account.password_hash,account.password_salt,account.password_material_version
		FROM node_accounts account
		JOIN global_users global_user ON global_user.id=account.user_id AND global_user.status='active'
		JOIN nodes node ON node.id=account.node_id AND node.status='online'
		WHERE account.status IN ('pending','error')
		  AND account.provisioning_workflow_id IS NULL
		  AND account.password_hash IS NOT NULL AND account.password_salt IS NOT NULL
		  AND account.updated_at<=$2
		ORDER BY account.updated_at LIMIT $1`, limit, now.Add(-2*time.Minute))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var syncs []PendingPasswordSync
	for rows.Next() {
		var sync PendingPasswordSync
		if err := rows.Scan(
			&sync.LegacyUserID, &sync.GlobalUserID, &sync.NodeID, &sync.LocalHandle,
			&sync.PasswordHash, &sync.PasswordSalt, &sync.Version,
		); err != nil {
			return nil, err
		}
		syncs = append(syncs, sync)
	}
	return syncs, rows.Err()
}

// ListPendingPasswordSyncsForUser returns the exact durable material staged by
// the authoritative transaction. Immediate delivery and operation replay must
// use this result rather than newly derived in-memory salts.
func (s *Store) ListPendingPasswordSyncsForUser(ctx context.Context, globalUserID int64) ([]PendingPasswordSync, error) {
	if globalUserID <= 0 {
		return nil, fmt.Errorf("invalid global user")
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT global_user.legacy_user_id,account.user_id,account.node_id,account.local_handle,
		  account.password_hash,account.password_salt,account.password_material_version
		FROM node_accounts account
		JOIN global_users global_user ON global_user.id=account.user_id
		WHERE account.user_id=$1 AND account.status IN ('pending','error')
		  AND account.provisioning_workflow_id IS NULL
		  AND account.password_hash IS NOT NULL AND account.password_salt IS NOT NULL
		ORDER BY account.node_id`, globalUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var syncs []PendingPasswordSync
	for rows.Next() {
		var sync PendingPasswordSync
		if err := rows.Scan(
			&sync.LegacyUserID, &sync.GlobalUserID, &sync.NodeID, &sync.LocalHandle,
			&sync.PasswordHash, &sync.PasswordSalt, &sync.Version,
		); err != nil {
			return nil, err
		}
		syncs = append(syncs, sync)
	}
	return syncs, rows.Err()
}

// GetUserByUsername 按用户名查找。
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	u := &User{}
	err := s.DB.QueryRowContext(ctx, `
	  SELECT u.id, COALESCE(gu.id,0), u.uuid, u.username, u.display_name, u.password_enc, identity.password_hash,
	    u.auth_provider, u.oauth_id, u.avatar_url, u.email, u.home_node_id, u.status, u.created_at
	  FROM users u
	  LEFT JOIN global_users gu ON gu.legacy_user_id=u.id
	  LEFT JOIN auth_identities identity
	    ON identity.user_id=gu.id AND identity.provider='password' AND identity.status='active'
	  WHERE username=$1`, username).
		Scan(&u.ID, &u.GlobalID, &u.UUID, &u.Username, &u.DisplayName, &u.PasswordEnc, &u.PasswordHash,
			&u.AuthProvider, &u.OAuthID, &u.AvatarURL, &u.Email, &u.HomeNodeID, &u.Status, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// GetUserByOAuth 按 OAuth 身份查找。
func (s *Store) GetUserByOAuth(ctx context.Context, provider, oauthID string) (*User, error) {
	u := &User{}
	err := s.DB.QueryRowContext(ctx, `
	  SELECT u.id, gu.id, u.uuid, u.username, u.display_name, u.password_enc, password_identity.password_hash,
	    u.auth_provider, u.oauth_id, u.avatar_url, u.email, u.home_node_id, u.status, u.created_at
	  FROM auth_identities identity
	  JOIN global_users gu ON gu.id=identity.user_id
	  JOIN users u ON u.id=gu.legacy_user_id
	  LEFT JOIN auth_identities password_identity
	    ON password_identity.user_id=gu.id AND password_identity.provider='password' AND password_identity.status='active'
	  WHERE identity.provider=$1 AND identity.provider_subject=$2 AND identity.status='active'`, provider, oauthID).
		Scan(&u.ID, &u.GlobalID, &u.UUID, &u.Username, &u.DisplayName, &u.PasswordEnc, &u.PasswordHash,
			&u.AuthProvider, &u.OAuthID, &u.AvatarURL, &u.Email, &u.HomeNodeID, &u.Status, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// GetUserByID 按 ID 查找。
func (s *Store) GetUserByID(ctx context.Context, id int64) (*User, error) {
	u := &User{}
	err := s.DB.QueryRowContext(ctx, `
	  SELECT u.id, COALESCE(gu.id,0), u.uuid, u.username, u.display_name, u.password_enc, identity.password_hash,
	    u.auth_provider, u.oauth_id, u.avatar_url, u.email, u.home_node_id, u.status, u.created_at
	  FROM users u
	  LEFT JOIN global_users gu ON gu.legacy_user_id=u.id
	  LEFT JOIN auth_identities identity
	    ON identity.user_id=gu.id AND identity.provider='password' AND identity.status='active'
	  WHERE u.id=$1`, id).
		Scan(&u.ID, &u.GlobalID, &u.UUID, &u.Username, &u.DisplayName, &u.PasswordEnc, &u.PasswordHash,
			&u.AuthProvider, &u.OAuthID, &u.AvatarURL, &u.Email, &u.HomeNodeID, &u.Status, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// GetUserByUUID 按全局 UUID 查找（管理员按 uuid 定位用户）。
func (s *Store) GetUserByUUID(ctx context.Context, uuid string) (*User, error) {
	if uuid == "" {
		return nil, nil
	}
	u := &User{}
	err := s.DB.QueryRowContext(ctx, `
	  SELECT u.id, COALESCE(gu.id,0), u.uuid, u.username, u.display_name, u.password_enc, identity.password_hash,
	    u.auth_provider, u.oauth_id, u.avatar_url, u.email, u.home_node_id, u.status, u.created_at
	  FROM users u
	  JOIN global_users gu ON gu.legacy_user_id=u.id
	  LEFT JOIN auth_identities identity
	    ON identity.user_id=gu.id AND identity.provider='password' AND identity.status='active'
	  WHERE gu.uuid=$1`, uuid).
		Scan(&u.ID, &u.GlobalID, &u.UUID, &u.Username, &u.DisplayName, &u.PasswordEnc, &u.PasswordHash,
			&u.AuthProvider, &u.OAuthID, &u.AvatarURL, &u.Email, &u.HomeNodeID, &u.Status, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// DeleteUser 删除用户（注册回滚用）。
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM global_users WHERE legacy_user_id=$1`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// SetUserHomeNode 设置家节点。
func (s *Store) SetUserHomeNode(ctx context.Context, userID, nodeID int64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET home_node_id=$2 WHERE id=$1`, userID, nodeID)
	return err
}

// UpdateUserStatus 更新用户状态。
func (s *Store) UpdateUserStatus(ctx context.Context, userID int64, status string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET status=$2 WHERE id=$1`, userID, status)
	return err
}

// UpdateUserPassword 更新总控验证 hash。可逆密码列始终清空。
func (s *Store) UpdateUserPassword(
	ctx context.Context,
	userID int64,
	passwordHash, nodePasswordHash, nodePasswordSalt string,
	now time.Time,
) error {
	if userID <= 0 || passwordHash == "" || nodePasswordHash == "" || nodePasswordSalt == "" {
		return fmt.Errorf("invalid password material")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET password_enc=NULL, password_hash=$2 WHERE id=$1`,
		userID, passwordHash); err != nil {
		return err
	}
	var globalUserID int64
	err = tx.QueryRowContext(ctx, `
	  UPDATE auth_identities
	  SET password_hash=$2, password_version=password_version+1,
	    previous_password_hash=password_hash, password_changed_at=$3, updated_at=$3
	  WHERE user_id=(SELECT id FROM global_users WHERE legacy_user_id=$1)
	    AND provider='password' AND status='active'
	  RETURNING user_id`, userID, passwordHash, now).Scan(&globalUserID)
	if err == sql.ErrNoRows {
		return fmt.Errorf("active password identity not found")
	}
	if err != nil {
		return err
	}
	if err := stagePasswordMaterial(ctx, tx, globalUserID, nodePasswordHash, nodePasswordSalt, now); err != nil {
		return err
	}
	return tx.Commit()
}

func stagePasswordMaterial(
	ctx context.Context,
	tx *sql.Tx,
	globalUserID int64,
	passwordHash, passwordSalt string,
	now time.Time,
) error {
	_, err := stagePasswordMaterialCount(ctx, tx, globalUserID, passwordHash, passwordSalt, now)
	return err
}

func stagePasswordMaterialCount(
	ctx context.Context,
	tx *sql.Tx,
	globalUserID int64,
	passwordHash, passwordSalt string,
	now time.Time,
) (int64, error) {
	result, err := tx.ExecContext(ctx, `
		UPDATE node_accounts
		SET status='pending',password_hash=$2,password_salt=$3,
		  password_material_version=password_material_version+1,
		  account_version=account_version+1,updated_at=$4
		WHERE user_id=$1 AND status IN ('active','pending','error')`,
		globalUserID, passwordHash, passwordSalt, now)
	if err != nil {
		return 0, err
	}
	if err := clearPendingPasswordRemovals(ctx, tx, globalUserID, now); err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ListUsers 列出全部用户（管理后台）。
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.DB.QueryContext(ctx, `
	  SELECT u.id, COALESCE(gu.id,0), u.uuid, u.username, u.display_name, u.password_enc, u.password_hash,
	    auth_provider, oauth_id, avatar_url, email, home_node_id, status, created_at
	  FROM users u LEFT JOIN global_users gu ON gu.legacy_user_id=u.id ORDER BY u.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.GlobalID, &u.UUID, &u.Username, &u.DisplayName, &u.PasswordEnc, &u.PasswordHash,
			&u.AuthProvider, &u.OAuthID, &u.AvatarURL, &u.Email, &u.HomeNodeID, &u.Status, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
