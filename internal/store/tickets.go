package store

import (
	"context"
	"database/sql"
	"time"
)

// CreateTicket 记录票据。
func (s *Store) CreateTicket(ctx context.Context, t *Ticket) error {
	_, err := s.DB.ExecContext(ctx, `
	  INSERT INTO tickets (jti, user_id, node_id, expires_at) VALUES ($1,$2,$3,$4)`,
		t.JTI, t.UserID, t.NodeID, t.ExpiresAt)
	return err
}

// ConsumeTicket 核销票据：仅当存在、未使用、未过期时标记 used_at 并返回所属用户/节点。
// 返回 (userID, nodeID, ok, err)。ok=false 表示票据无效/已用/过期。
func (s *Store) ConsumeTicket(ctx context.Context, jti string, now time.Time) (int64, int64, bool, error) {
	res, err := s.DB.ExecContext(ctx, `
	  UPDATE tickets SET used_at=$2
	  WHERE jti=$1 AND used_at IS NULL AND expires_at > $2`, jti, now)
	if err != nil {
		return 0, 0, false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return 0, 0, false, err
	}
	var userID, nodeID int64
	err = s.DB.QueryRowContext(ctx, `SELECT user_id, node_id FROM tickets WHERE jti=$1`, jti).
		Scan(&userID, &nodeID)
	if err == sql.ErrNoRows {
		return 0, 0, false, nil
	}
	return userID, nodeID, err == nil, err
}

// ---------- 注册令牌（一次性, 子控注册用） ----------

// CreateRegisterToken 创建一次性注册令牌。
func (s *Store) CreateRegisterToken(ctx context.Context, token, note string, expiresAt time.Time) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO register_tokens (token, note, expires_at) VALUES ($1,$2,$3) ON CONFLICT (token) DO NOTHING`,
		token, note, expiresAt)
	return err
}

// ConsumeRegisterToken 核销注册令牌（存在、未用、未过期则标记 used 并返回 true）。
func (s *Store) ConsumeRegisterToken(ctx context.Context, token string) (bool, error) {
	res, err := s.DB.ExecContext(ctx, `
	  UPDATE register_tokens SET used=true
	  WHERE token=$1 AND used=false AND (expires_at IS NULL OR expires_at > now())`, token)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// Audit 写审计日志。
func (s *Store) Audit(ctx context.Context, actor, action, target string, detail []byte) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO audit_logs (actor, action, target, detail) VALUES ($1,$2,$3,$4)`,
		actor, action, target, detail)
	return err
}
