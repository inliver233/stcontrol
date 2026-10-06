package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lib/pq"
)

var (
	ErrInvalidPasskeyInput   = errors.New("invalid passkey input")
	ErrPasskeyLimit          = errors.New("passkey limit reached")
	ErrPasskeyExists         = errors.New("passkey already registered")
	ErrPasskeyNotFound       = errors.New("passkey not found")
	ErrPasskeyCeremonyFailed = errors.New("passkey ceremony expired, used or unknown")
)

const (
	PasskeyMaxPerUserLimit = 10
	passkeyNameMaxRunes    = 40
	passkeyDefaultName     = "通行密钥"
)

// PasskeySettings are the administrator's switches for passkeys.
type PasskeySettings struct {
	Enabled           bool      `json:"enabled"`
	AllowRegistration bool      `json:"allow_registration"`
	ShowOnLoginPage   bool      `json:"show_on_login_page"`
	MaxPerUser        int       `json:"max_per_user"`
	UserVerification  string    `json:"user_verification"`
	LoginButtonText   string    `json:"login_button_text"`
	LoginHintText     string    `json:"login_hint_text"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// NormalizePasskeySettings trims text and rejects values the table would refuse.
func NormalizePasskeySettings(settings PasskeySettings) (PasskeySettings, error) {
	settings.LoginButtonText = strings.TrimSpace(settings.LoginButtonText)
	settings.LoginHintText = strings.TrimSpace(settings.LoginHintText)
	switch {
	case settings.MaxPerUser < 1 || settings.MaxPerUser > PasskeyMaxPerUserLimit,
		settings.UserVerification != "required" && settings.UserVerification != "preferred" &&
			settings.UserVerification != "discouraged",
		settings.LoginButtonText == "" || utf8.RuneCountInString(settings.LoginButtonText) > 24,
		utf8.RuneCountInString(settings.LoginHintText) > 80:
		return PasskeySettings{}, ErrInvalidPasskeyInput
	}
	return settings, nil
}

// NormalizePasskeyName returns a display name for a passkey.
func NormalizePasskeyName(name string) string {
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		return passkeyDefaultName
	}
	if utf8.RuneCountInString(name) > passkeyNameMaxRunes {
		name = string([]rune(name)[:passkeyNameMaxRunes])
	}
	return name
}

// UserPasskey is one registered passkey.
type UserPasskey struct {
	ID           int64      `json:"id"`
	UserID       int64      `json:"-"`
	CredentialID []byte     `json:"-"`
	Credential   []byte     `json:"-"`
	Name         string     `json:"name"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

type sqlExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertPasskeyAudit(ctx context.Context, db sqlExecer, actorType, actorID, action, targetID, outcome string, detail map[string]any) error {
	encoded, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	var actor, target any
	if actorID != "" {
		actor = actorID
	}
	if targetID != "" {
		target = targetID
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO audit_events (
		  actor_type,actor_id,action,target_type,target_id,controller_generation,outcome,detail
		) VALUES ($1,$2,$3,'passkey',$4,
		  (SELECT generation FROM controller_epochs WHERE state='active'),$5,$6::jsonb)`,
		actorType, actor, action, target, outcome, string(encoded))
	return err
}

// GetPasskeySettings reads the administrator's settings.
func (s *Store) GetPasskeySettings(ctx context.Context) (PasskeySettings, error) {
	var settings PasskeySettings
	err := s.DB.QueryRowContext(ctx, `
		SELECT enabled,allow_registration,show_on_login_page,max_per_user,user_verification,
		  login_button_text,login_hint_text,updated_at
		FROM passkey_settings WHERE id=1`).Scan(
		&settings.Enabled, &settings.AllowRegistration, &settings.ShowOnLoginPage, &settings.MaxPerUser,
		&settings.UserVerification, &settings.LoginButtonText, &settings.LoginHintText, &settings.UpdatedAt)
	return settings, err
}

// UpdatePasskeySettings stores new settings and records who changed them.
func (s *Store) UpdatePasskeySettings(ctx context.Context, settings PasskeySettings, adminID int64, now time.Time) (PasskeySettings, error) {
	settings, err := NormalizePasskeySettings(settings)
	if err != nil {
		return PasskeySettings{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return PasskeySettings{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var admin any
	if adminID > 0 {
		admin = adminID
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE passkey_settings SET enabled=$1,allow_registration=$2,show_on_login_page=$3,
		  max_per_user=$4,user_verification=$5,login_button_text=$6,login_hint_text=$7,
		  updated_at=$8,updated_by_admin_id=$9
		WHERE id=1`,
		settings.Enabled, settings.AllowRegistration, settings.ShowOnLoginPage, settings.MaxPerUser,
		settings.UserVerification, settings.LoginButtonText, settings.LoginHintText, now, admin); err != nil {
		return PasskeySettings{}, err
	}
	actor := ""
	if adminID > 0 {
		actor = fmt.Sprint(adminID)
	}
	if err := insertPasskeyAudit(ctx, tx, "admin", actor, "passkey-settings-updated", "", "succeeded", map[string]any{
		"enabled": settings.Enabled, "allow_registration": settings.AllowRegistration,
		"show_on_login_page": settings.ShowOnLoginPage, "max_per_user": settings.MaxPerUser,
		"user_verification": settings.UserVerification,
	}); err != nil {
		return PasskeySettings{}, err
	}
	if err := tx.Commit(); err != nil {
		return PasskeySettings{}, err
	}
	settings.UpdatedAt = now
	return settings, nil
}

// CreatePasskeyCeremony stores a challenge for a registration (userID > 0) or a
// sign-in (userID 0) and drops expired ones.
func (s *Store) CreatePasskeyCeremony(ctx context.Context, id, purpose string, userID int64, session []byte, expiresAt, now time.Time) error {
	if !validUUIDText(id) || (purpose == "register") != (userID > 0) || (purpose != "register" && purpose != "login") ||
		len(session) == 0 || !expiresAt.After(now) {
		return ErrInvalidPasskeyInput
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM passkey_ceremonies WHERE expires_at<=$1`, now); err != nil {
		return err
	}
	var user any
	if userID > 0 {
		user = userID
	}
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO passkey_ceremonies (id,purpose,user_id,session,expires_at,created_at)
		VALUES ($1,$2,$3,$4::jsonb,$5,$6)`, id, purpose, user, string(session), expiresAt, now)
	return err
}

// ConsumePasskeyCeremony returns a ceremony's challenge exactly once.
func (s *Store) ConsumePasskeyCeremony(ctx context.Context, id, purpose string, userID int64, now time.Time) ([]byte, error) {
	if !validUUIDText(id) {
		return nil, ErrPasskeyCeremonyFailed
	}
	var session string
	err := s.DB.QueryRowContext(ctx, `
		DELETE FROM passkey_ceremonies
		WHERE id=$1 AND purpose=$2 AND COALESCE(user_id,0)=$3 AND expires_at>$4
		RETURNING session::text`, id, purpose, userID, now).Scan(&session)
	if err == sql.ErrNoRows {
		return nil, ErrPasskeyCeremonyFailed
	}
	if err != nil {
		return nil, err
	}
	return []byte(session), nil
}

const userPasskeyColumns = `id,user_id,credential_id,credential::text,name,created_at,last_used_at`

func scanUserPasskey(row interface{ Scan(...any) error }) (UserPasskey, error) {
	var passkey UserPasskey
	var credential string
	var lastUsed sql.NullTime
	if err := row.Scan(&passkey.ID, &passkey.UserID, &passkey.CredentialID, &credential,
		&passkey.Name, &passkey.CreatedAt, &lastUsed); err != nil {
		return UserPasskey{}, err
	}
	passkey.Credential = []byte(credential)
	if lastUsed.Valid {
		at := lastUsed.Time
		passkey.LastUsedAt = &at
	}
	return passkey, nil
}

// ListUserPasskeys returns a user's passkeys, oldest first.
func (s *Store) ListUserPasskeys(ctx context.Context, userID int64) ([]UserPasskey, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT `+userPasskeyColumns+` FROM user_passkeys
		WHERE user_id=$1 ORDER BY created_at,id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	passkeys := make([]UserPasskey, 0)
	for rows.Next() {
		passkey, err := scanUserPasskey(rows)
		if err != nil {
			return nil, err
		}
		passkeys = append(passkeys, passkey)
	}
	return passkeys, rows.Err()
}

// AddUserPasskeyParams describes a verified new passkey.
type AddUserPasskeyParams struct {
	UserID       int64
	CredentialID []byte
	Credential   []byte
	Name         string
	MaxPerUser   int
	Now          time.Time
}

// AddUserPasskey stores a verified passkey unless the user already has the
// maximum. The user row lock serializes concurrent additions.
func (s *Store) AddUserPasskey(ctx context.Context, p AddUserPasskeyParams) (UserPasskey, error) {
	if p.UserID <= 0 || len(p.CredentialID) == 0 || len(p.CredentialID) > 1023 || !json.Valid(p.Credential) ||
		p.MaxPerUser < 1 || p.MaxPerUser > PasskeyMaxPerUserLimit {
		return UserPasskey{}, ErrInvalidPasskeyInput
	}
	if p.Now.IsZero() {
		p.Now = time.Now().UTC()
	}
	name := NormalizePasskeyName(p.Name)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return UserPasskey{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var lockedID int64
	if err := tx.QueryRowContext(ctx, `
		SELECT id FROM global_users WHERE id=$1 AND status='active' FOR UPDATE`, p.UserID).Scan(&lockedID); err != nil {
		if err == sql.ErrNoRows {
			return UserPasskey{}, ErrGlobalUserNotFound
		}
		return UserPasskey{}, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM user_passkeys WHERE user_id=$1`, p.UserID).Scan(&count); err != nil {
		return UserPasskey{}, err
	}
	if count >= p.MaxPerUser {
		return UserPasskey{}, ErrPasskeyLimit
	}
	passkey, err := scanUserPasskey(tx.QueryRowContext(ctx, `
		INSERT INTO user_passkeys (user_id,credential_id,credential,name,created_at)
		VALUES ($1,$2,$3::jsonb,$4,$5)
		RETURNING `+userPasskeyColumns, p.UserID, p.CredentialID, string(p.Credential), name, p.Now))
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return UserPasskey{}, ErrPasskeyExists
		}
		return UserPasskey{}, err
	}
	if err := insertPasskeyAudit(ctx, tx, "user", fmt.Sprint(p.UserID), "passkey-registered",
		fmt.Sprint(passkey.ID), "succeeded", map[string]any{"name": name}); err != nil {
		return UserPasskey{}, err
	}
	if err := tx.Commit(); err != nil {
		return UserPasskey{}, err
	}
	return passkey, nil
}

// PasskeyOwner is the passkey a sign-in presented and its owner.
type PasskeyOwner struct {
	Passkey  UserPasskey
	UserUUID string
}

// GetPasskeyOwner finds a passkey by credential ID together with its owner's
// global UUID (the passkey's user handle).
func (s *Store) GetPasskeyOwner(ctx context.Context, credentialID []byte) (*PasskeyOwner, error) {
	if len(credentialID) == 0 || len(credentialID) > 1023 {
		return nil, nil
	}
	var owner PasskeyOwner
	var credential string
	var lastUsed sql.NullTime
	err := s.DB.QueryRowContext(ctx, `
		SELECT passkey.id,passkey.user_id,passkey.credential_id,passkey.credential::text,passkey.name,
		  passkey.created_at,passkey.last_used_at,global_user.uuid::text
		FROM user_passkeys passkey JOIN global_users global_user ON global_user.id=passkey.user_id
		WHERE passkey.credential_id=$1`, credentialID).Scan(
		&owner.Passkey.ID, &owner.Passkey.UserID, &owner.Passkey.CredentialID, &credential, &owner.Passkey.Name,
		&owner.Passkey.CreatedAt, &lastUsed, &owner.UserUUID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	owner.Passkey.Credential = []byte(credential)
	if lastUsed.Valid {
		at := lastUsed.Time
		owner.Passkey.LastUsedAt = &at
	}
	return &owner, nil
}

// RecordPasskeyLogin stores the credential's updated counters after a
// verified sign-in and audits it.
func (s *Store) RecordPasskeyLogin(ctx context.Context, passkeyID, userID int64, credential []byte, now time.Time) error {
	if passkeyID <= 0 || userID <= 0 || !json.Valid(credential) {
		return ErrInvalidPasskeyInput
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var name string
	err = tx.QueryRowContext(ctx, `
		UPDATE user_passkeys SET credential=$3::jsonb,last_used_at=$4
		WHERE id=$1 AND user_id=$2 RETURNING name`, passkeyID, userID, string(credential), now).Scan(&name)
	if err == sql.ErrNoRows {
		return ErrPasskeyNotFound
	}
	if err != nil {
		return err
	}
	// The name is kept with the event so the sign-in list still says which
	// passkey it was after the passkey is removed.
	if err := insertPasskeyAudit(ctx, tx, "user", fmt.Sprint(userID), "passkey-login",
		fmt.Sprint(passkeyID), "succeeded", map[string]any{"name": name}); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordPasskeyLoginFailure audits a rejected sign-in attempt. passkey is the
// presented passkey when it exists (its owner is then recorded too).
func (s *Store) RecordPasskeyLoginFailure(ctx context.Context, reason string, passkey *UserPasskey) error {
	if passkey == nil || passkey.UserID <= 0 {
		return insertPasskeyAudit(ctx, s.DB, "system", "", "passkey-login", "", "failed", map[string]any{"reason": reason})
	}
	return insertPasskeyAudit(ctx, s.DB, "user", fmt.Sprint(passkey.UserID), "passkey-login", fmt.Sprint(passkey.ID), "failed",
		map[string]any{"reason": reason, "name": passkey.Name})
}

// RenameUserPasskey changes the display name of one of the user's passkeys.
func (s *Store) RenameUserPasskey(ctx context.Context, userID, passkeyID int64, name string) (UserPasskey, error) {
	passkey, err := scanUserPasskey(s.DB.QueryRowContext(ctx, `
		UPDATE user_passkeys SET name=$3 WHERE id=$1 AND user_id=$2
		RETURNING `+userPasskeyColumns, passkeyID, userID, NormalizePasskeyName(name)))
	if err == sql.ErrNoRows {
		return UserPasskey{}, ErrPasskeyNotFound
	}
	return passkey, err
}

// DeletePasskey removes a passkey. userID > 0 limits it to that user's own
// passkeys; adminID > 0 records an administrator removal.
func (s *Store) DeletePasskey(ctx context.Context, passkeyID, userID, adminID int64) error {
	if passkeyID <= 0 || (userID <= 0) == (adminID <= 0) {
		return ErrInvalidPasskeyInput
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var owner int64
	var name string
	err = tx.QueryRowContext(ctx, `
		DELETE FROM user_passkeys WHERE id=$1 AND ($2=0 OR user_id=$2)
		RETURNING user_id,name`, passkeyID, userID).Scan(&owner, &name)
	if err == sql.ErrNoRows {
		return ErrPasskeyNotFound
	}
	if err != nil {
		return err
	}
	actorType, actorID := "user", fmt.Sprint(userID)
	if adminID > 0 {
		actorType, actorID = "admin", fmt.Sprint(adminID)
	}
	if err := insertPasskeyAudit(ctx, tx, actorType, actorID, "passkey-removed", fmt.Sprint(passkeyID), "succeeded",
		map[string]any{"user_id": owner, "name": name}); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteAllUserPasskeys removes every passkey of one user (administrator).
func (s *Store) DeleteAllUserPasskeys(ctx context.Context, userUUID string, adminID int64) (int64, error) {
	if !validUUIDText(userUUID) || adminID <= 0 {
		return 0, ErrInvalidPasskeyInput
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		DELETE FROM user_passkeys WHERE user_id=(SELECT id FROM global_users WHERE uuid=$1::uuid)`, userUUID)
	if err != nil {
		return 0, err
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if removed > 0 {
		if err := insertPasskeyAudit(ctx, tx, "admin", fmt.Sprint(adminID), "passkey-removed", "", "succeeded",
			map[string]any{"user_uuid": userUUID, "count": removed}); err != nil {
			return 0, err
		}
	}
	return removed, tx.Commit()
}

// PasskeyDay counts passkey activity on one UTC day.
type PasskeyDay struct {
	Day          string `json:"day"`
	Registered   int    `json:"registered"`
	LoginSuccess int    `json:"login_success"`
	LoginFailure int    `json:"login_failure"`
}

// PasskeyUserSummary lists one user's passkeys for administrators.
type PasskeyUserSummary struct {
	UUID        string        `json:"uuid"`
	Username    string        `json:"username"`
	DisplayName string        `json:"display_name"`
	Passkeys    []UserPasskey `json:"passkeys"`
}

// PasskeyLogin is one passkey sign-in attempt.
type PasskeyLogin struct {
	At          time.Time `json:"at"`
	OK          bool      `json:"ok"`
	Reason      string    `json:"reason,omitempty"`
	Username    string    `json:"username,omitempty"`
	DisplayName string    `json:"display_name,omitempty"`
	PasskeyName string    `json:"passkey_name,omitempty"`
}

// PasskeyOverview summarizes passkey use for the administrator page.
type PasskeyOverview struct {
	UsersWithPasskeys int                  `json:"users_with_passkeys"`
	TotalPasskeys     int                  `json:"total_passkeys"`
	Users             []PasskeyUserSummary `json:"users"`
	Days              []PasskeyDay         `json:"days"`
	RecentLogins      []PasskeyLogin       `json:"recent_logins"`
}

const passkeyRecentLogins = 50

// GetPasskeyOverview lists users with passkeys and the last days of activity.
func (s *Store) GetPasskeyOverview(ctx context.Context, days int, now time.Time) (PasskeyOverview, error) {
	if days < 1 || days > 90 {
		days = 21
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	overview := PasskeyOverview{
		Users: make([]PasskeyUserSummary, 0), Days: make([]PasskeyDay, 0, days),
		RecentLogins: make([]PasskeyLogin, 0, passkeyRecentLogins),
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT global_user.uuid::text,COALESCE(legacy.username,''),
		  COALESCE(NULLIF(legacy.display_name,''),global_user.display_name,''),
		  passkey.id,passkey.name,passkey.created_at,passkey.last_used_at
		FROM user_passkeys passkey
		JOIN global_users global_user ON global_user.id=passkey.user_id
		LEFT JOIN users legacy ON legacy.id=global_user.legacy_user_id
		ORDER BY global_user.id,passkey.created_at,passkey.id`)
	if err != nil {
		return PasskeyOverview{}, err
	}
	defer rows.Close()
	index := map[string]int{}
	for rows.Next() {
		var uuid, username, displayName string
		var passkey UserPasskey
		var lastUsed sql.NullTime
		if err := rows.Scan(&uuid, &username, &displayName, &passkey.ID, &passkey.Name, &passkey.CreatedAt, &lastUsed); err != nil {
			return PasskeyOverview{}, err
		}
		if lastUsed.Valid {
			at := lastUsed.Time
			passkey.LastUsedAt = &at
		}
		position, ok := index[uuid]
		if !ok {
			position = len(overview.Users)
			index[uuid] = position
			overview.Users = append(overview.Users, PasskeyUserSummary{
				UUID: uuid, Username: username, DisplayName: displayName, Passkeys: make([]UserPasskey, 0, 1),
			})
		}
		overview.Users[position].Passkeys = append(overview.Users[position].Passkeys, passkey)
		overview.TotalPasskeys++
	}
	if err := rows.Err(); err != nil {
		return PasskeyOverview{}, err
	}
	overview.UsersWithPasskeys = len(overview.Users)

	first := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -(days - 1))
	byDay := map[string]*PasskeyDay{}
	for day := 0; day < days; day++ {
		key := first.AddDate(0, 0, day).Format("2006-01-02")
		overview.Days = append(overview.Days, PasskeyDay{Day: key})
	}
	for i := range overview.Days {
		byDay[overview.Days[i].Day] = &overview.Days[i]
	}
	activity, err := s.DB.QueryContext(ctx, `
		SELECT to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD'),action,outcome,count(*)
		FROM audit_events
		WHERE target_type='passkey' AND occurred_at>=$1
		  AND action IN ('passkey-registered','passkey-login')
		GROUP BY 1,2,3`, first)
	if err != nil {
		return PasskeyOverview{}, err
	}
	defer activity.Close()
	for activity.Next() {
		var day, action, outcome string
		var count int
		if err := activity.Scan(&day, &action, &outcome, &count); err != nil {
			return PasskeyOverview{}, err
		}
		entry := byDay[day]
		if entry == nil {
			continue
		}
		switch {
		case action == "passkey-registered":
			entry.Registered += count
		case outcome == "succeeded":
			entry.LoginSuccess += count
		default:
			entry.LoginFailure += count
		}
	}
	if err := activity.Err(); err != nil {
		return PasskeyOverview{}, err
	}

	logins, err := s.DB.QueryContext(ctx, `
		SELECT event.occurred_at, event.outcome='succeeded', COALESCE(event.detail->>'reason',''),
		  COALESCE(legacy.username,''),
		  COALESCE(NULLIF(legacy.display_name,''),global_user.display_name,''),
		  COALESCE(NULLIF(event.detail->>'name',''),passkey.name,'')
		FROM audit_events event
		LEFT JOIN global_users global_user ON global_user.id=CASE
		  WHEN event.actor_type='user' AND event.actor_id ~ '^[0-9]{1,18}$' THEN event.actor_id::bigint END
		LEFT JOIN users legacy ON legacy.id=global_user.legacy_user_id
		LEFT JOIN user_passkeys passkey ON passkey.id=CASE
		  WHEN event.target_id ~ '^[0-9]{1,18}$' THEN event.target_id::bigint END
		WHERE event.target_type='passkey' AND event.action='passkey-login'
		ORDER BY event.occurred_at DESC, event.id DESC
		LIMIT $1`, passkeyRecentLogins)
	if err != nil {
		return PasskeyOverview{}, err
	}
	defer logins.Close()
	for logins.Next() {
		var login PasskeyLogin
		if err := logins.Scan(&login.At, &login.OK, &login.Reason, &login.Username, &login.DisplayName, &login.PasskeyName); err != nil {
			return PasskeyOverview{}, err
		}
		overview.RecentLogins = append(overview.RecentLogins, login)
	}
	return overview, logins.Err()
}
