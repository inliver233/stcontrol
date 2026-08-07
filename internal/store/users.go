package store

import (
	"context"
	"database/sql"
)

// CreateUser 创建用户。
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	return s.DB.QueryRowContext(ctx, `
	  INSERT INTO users (username, display_name, password_enc, password_hash,
	    auth_provider, oauth_id, avatar_url, email, home_node_id, status)
	  VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	  RETURNING id, uuid, created_at`,
		u.Username, u.DisplayName, u.PasswordEnc, u.PasswordHash,
		u.AuthProvider, u.OAuthID, u.AvatarURL, u.Email, u.HomeNodeID, u.Status,
	).Scan(&u.ID, &u.UUID, &u.CreatedAt)
}

// GetUserByUsername 按用户名查找。
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	u := &User{}
	err := s.DB.QueryRowContext(ctx, `
	  SELECT id, uuid, username, display_name, password_enc, password_hash,
	    auth_provider, oauth_id, avatar_url, email, home_node_id, status, created_at
	  FROM users WHERE username=$1`, username).
		Scan(&u.ID, &u.UUID, &u.Username, &u.DisplayName, &u.PasswordEnc, &u.PasswordHash,
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
	  SELECT id, uuid, username, display_name, password_enc, password_hash,
	    auth_provider, oauth_id, avatar_url, email, home_node_id, status, created_at
	  FROM users WHERE auth_provider=$1 AND oauth_id=$2`, provider, oauthID).
		Scan(&u.ID, &u.UUID, &u.Username, &u.DisplayName, &u.PasswordEnc, &u.PasswordHash,
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
	  SELECT id, uuid, username, display_name, password_enc, password_hash,
	    auth_provider, oauth_id, avatar_url, email, home_node_id, status, created_at
	  FROM users WHERE id=$1`, id).
		Scan(&u.ID, &u.UUID, &u.Username, &u.DisplayName, &u.PasswordEnc, &u.PasswordHash,
			&u.AuthProvider, &u.OAuthID, &u.AvatarURL, &u.Email, &u.HomeNodeID, &u.Status, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// DeleteUser 删除用户（注册回滚用）。
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, id)
	return err
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

// UpdateUserPassword 更新密码（总控 hash + 加密明文）。
func (s *Store) UpdateUserPassword(ctx context.Context, userID int64, passwordEnc, passwordHash string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE users SET password_enc=$2, password_hash=$3 WHERE id=$1`,
		userID, passwordEnc, passwordHash)
	return err
}

// ListUsers 列出全部用户（管理后台）。
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.DB.QueryContext(ctx, `
	  SELECT id, uuid, username, display_name, password_enc, password_hash,
	    auth_provider, oauth_id, avatar_url, email, home_node_id, status, created_at
	  FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.UUID, &u.Username, &u.DisplayName, &u.PasswordEnc, &u.PasswordHash,
			&u.AuthProvider, &u.OAuthID, &u.AvatarURL, &u.Email, &u.HomeNodeID, &u.Status, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
