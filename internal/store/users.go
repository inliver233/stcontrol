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
	oauthSubjects := map[string]string{}
	if passwordMode {
		hashValue = passwordHash
		saltValue = passwordSalt
	} else {
		oauthSubjects[oauthProvider] = oauthSubject
	}
	oauthJSON, err := json.Marshal(oauthSubjects)
	if err != nil {
		return 0, err
	}
	var version int64
	err = s.DB.QueryRowContext(ctx, `
		UPDATE node_accounts
		SET status='pending', password_hash=$3, password_salt=$4,
		  oauth_subjects=$5,
		  password_material_version=CASE WHEN $3 IS NULL
		    THEN password_material_version ELSE password_material_version+1 END,
		  account_version=account_version+1, updated_at=$6
		WHERE user_id=$1 AND node_id=$2
		RETURNING password_material_version`,
		globalUserID, nodeID, hashValue, saltValue, oauthJSON, now).Scan(&version)
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

// GetUserByUsername 按用户名查找。
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	u := &User{}
	err := s.DB.QueryRowContext(ctx, `
	  SELECT u.id, COALESCE(gu.id,0), u.uuid, u.username, u.display_name, u.password_enc, u.password_hash,
	    auth_provider, oauth_id, avatar_url, email, home_node_id, status, created_at
	  FROM users u LEFT JOIN global_users gu ON gu.legacy_user_id=u.id WHERE username=$1`, username).
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
	  SELECT u.id, COALESCE(gu.id,0), u.uuid, u.username, u.display_name, u.password_enc, u.password_hash,
	    auth_provider, oauth_id, avatar_url, email, home_node_id, status, created_at
	  FROM users u LEFT JOIN global_users gu ON gu.legacy_user_id=u.id
	  WHERE auth_provider=$1 AND oauth_id=$2`, provider, oauthID).
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
	  SELECT u.id, COALESCE(gu.id,0), u.uuid, u.username, u.display_name, u.password_enc, u.password_hash,
	    auth_provider, oauth_id, avatar_url, email, home_node_id, status, created_at
	  FROM users u LEFT JOIN global_users gu ON gu.legacy_user_id=u.id WHERE u.id=$1`, id).
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
func (s *Store) UpdateUserPassword(ctx context.Context, userID int64, passwordHash string) error {
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
	result, err := tx.ExecContext(ctx, `
	  UPDATE auth_identities
	  SET password_hash=$2, password_version=password_version+1, updated_at=now()
	  WHERE user_id=(SELECT id FROM global_users WHERE legacy_user_id=$1)
	    AND provider='password' AND status='active'`, userID, passwordHash)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("active password identity not found")
	}
	return tx.Commit()
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
