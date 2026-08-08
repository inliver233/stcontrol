package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrInvalidAdmin = errors.New("invalid admin input")
	ErrLastAdmin    = errors.New("cannot disable the last active admin")
)

type Admin struct {
	ID              int64      `json:"id"`
	UUID            string     `json:"uuid"`
	Username        string     `json:"username"`
	PasswordHash    string     `json:"-"`
	PasswordVersion int64      `json:"password_version"`
	Status          string     `json:"status"`
	CreatedBy       *int64     `json:"created_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`
	DisabledAt      *time.Time `json:"disabled_at,omitempty"`
}

func (s *Store) HasActiveAdmin(ctx context.Context) (bool, error) {
	var exists bool
	err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM admins WHERE status='active')`).Scan(&exists)
	return exists, err
}

// BootstrapAdmin creates exactly one initial administrator. The table lock
// closes the race between two controllers starting against an empty database.
func (s *Store) BootstrapAdmin(ctx context.Context, username, passwordHash string, now time.Time) (bool, error) {
	if !validAdminUsername(username) || passwordHash == "" {
		return false, ErrInvalidAdmin
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `LOCK TABLE admins IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return false, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&count); err != nil {
		return false, err
	}
	if count != 0 {
		return false, tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO admins (uuid,username,password_hash,status,created_at,updated_at)
		VALUES (gen_random_uuid(),$1,$2,'active',$3,$3)`, username, passwordHash, now); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) GetAdminByUsername(ctx context.Context, username string) (*Admin, error) {
	if !validAdminUsername(username) {
		return nil, nil
	}
	admin := &Admin{}
	var createdBy sql.NullInt64
	var lastLogin, disabled sql.NullTime
	err := s.DB.QueryRowContext(ctx, `
		SELECT id,uuid::text,username,password_hash,password_version,status,created_by,
		  created_at,updated_at,last_login_at,disabled_at
		FROM admins WHERE username=$1`, username).
		Scan(&admin.ID, &admin.UUID, &admin.Username, &admin.PasswordHash, &admin.PasswordVersion,
			&admin.Status, &createdBy, &admin.CreatedAt, &admin.UpdatedAt, &lastLogin, &disabled)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	admin.CreatedBy = adminNullableInt64(createdBy)
	admin.LastLoginAt = adminNullableTime(lastLogin)
	admin.DisabledAt = adminNullableTime(disabled)
	return admin, nil
}

func (s *Store) RecordAdminLogin(ctx context.Context, adminID int64, now time.Time) error {
	if adminID <= 0 {
		return ErrInvalidAdmin
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE admins SET last_login_at=$2,updated_at=$2 WHERE id=$1 AND status='active'`, adminID, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrInvalidAdmin
	}
	return nil
}

func (s *Store) ListAdmins(ctx context.Context) ([]*Admin, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id,uuid::text,username,password_version,status,created_by,
		  created_at,updated_at,last_login_at,disabled_at
		FROM admins ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var admins []*Admin
	for rows.Next() {
		admin := &Admin{}
		var createdBy sql.NullInt64
		var lastLogin, disabled sql.NullTime
		if err := rows.Scan(&admin.ID, &admin.UUID, &admin.Username, &admin.PasswordVersion,
			&admin.Status, &createdBy, &admin.CreatedAt, &admin.UpdatedAt, &lastLogin, &disabled); err != nil {
			return nil, err
		}
		admin.CreatedBy = adminNullableInt64(createdBy)
		admin.LastLoginAt = adminNullableTime(lastLogin)
		admin.DisabledAt = adminNullableTime(disabled)
		admins = append(admins, admin)
	}
	return admins, rows.Err()
}

func (s *Store) CreateAdmin(ctx context.Context, username, passwordHash string, createdBy int64, now time.Time) (*Admin, error) {
	if !validAdminUsername(username) || passwordHash == "" || createdBy <= 0 {
		return nil, ErrInvalidAdmin
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	admin := &Admin{Username: username, Status: "active", PasswordVersion: 1, CreatedBy: &createdBy}
	err := s.DB.QueryRowContext(ctx, `
		INSERT INTO admins (uuid,username,password_hash,status,created_by,created_at,updated_at)
		SELECT gen_random_uuid(),$1,$2,'active',$3,$4,$4
		WHERE EXISTS (SELECT 1 FROM admins WHERE id=$3 AND status='active')
		RETURNING id,uuid::text,created_at,updated_at`, username, passwordHash, createdBy, now).
		Scan(&admin.ID, &admin.UUID, &admin.CreatedAt, &admin.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrInvalidAdmin
	}
	if err != nil {
		return nil, err
	}
	return admin, nil
}

func (s *Store) SetAdminStatus(ctx context.Context, adminID int64, status string, now time.Time) error {
	if adminID <= 0 || (status != "active" && status != "disabled") {
		return ErrInvalidAdmin
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM admins WHERE id=$1 FOR UPDATE`, adminID).Scan(&current); err != nil {
		if err == sql.ErrNoRows {
			return ErrInvalidAdmin
		}
		return err
	}
	if status == "disabled" && current != "disabled" {
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins WHERE status='active'`).Scan(&active); err != nil {
			return err
		}
		if active <= 1 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE admins SET status=$2,disabled_at=CASE WHEN $2='disabled' THEN $3 ELSE NULL END,
		  updated_at=$3 WHERE id=$1`, adminID, status, now); err != nil {
		return err
	}
	if status == "disabled" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE controller_sessions SET revoked_at=COALESCE(revoked_at,$2)
			WHERE admin_id=$1 AND revoked_at IS NULL`, adminID, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE admin_node_links SET state='revoked',revoked_at=COALESCE(revoked_at,$2),
			  updated_at=$2 WHERE admin_id=$1 AND state<>'revoked'`, adminID, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE control_tickets SET revoked_at=COALESCE(revoked_at,$2)
			WHERE admin_id=$1 AND ticket_type='node_admin'
			  AND consumed_at IS NULL AND revoked_at IS NULL`, adminID, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ResetAdminPassword(ctx context.Context, adminID int64, passwordHash string, now time.Time) error {
	if adminID <= 0 || passwordHash == "" {
		return ErrInvalidAdmin
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
		UPDATE admins SET password_hash=$2,password_version=password_version+1,updated_at=$3
		WHERE id=$1`, adminID, passwordHash, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrInvalidAdmin
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE controller_sessions SET revoked_at=COALESCE(revoked_at,$2)
		WHERE admin_id=$1 AND revoked_at IS NULL`, adminID, now); err != nil {
		return err
	}
	return tx.Commit()
}

func validAdminUsername(username string) bool {
	if len(username) < 3 || len(username) > 32 {
		return false
	}
	for _, char := range username {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func adminNullableInt64(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	out := value.Int64
	return &out
}

func adminNullableTime(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	out := value.Time
	return &out
}
