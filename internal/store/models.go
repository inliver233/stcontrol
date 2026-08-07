package store

import (
	"database/sql"
	"time"
)

// User 总控用户。
type User struct {
	ID           int64          `json:"id"`
	GlobalID     int64          `json:"-"`
	UUID         string         `json:"uuid"`
	Username     string         `json:"username"`
	DisplayName  string         `json:"display_name"`
	PasswordEnc  sql.NullString `json:"-"` // 仅兼容 demo 旧列；新代码禁止写入可逆密码。
	PasswordHash sql.NullString `json:"-"`
	AuthProvider string         `json:"auth_provider"`
	OAuthID      sql.NullString `json:"-"`
	AvatarURL    sql.NullString `json:"avatar_url"`
	Email        sql.NullString `json:"-"`
	HomeNodeID   sql.NullInt64  `json:"home_node_id"`
	Status       string         `json:"status"`
	CreatedAt    time.Time      `json:"created_at"`
}

// Node 节点。
type Node struct {
	ID                           int64           `json:"id"`
	Name                         string          `json:"name"`
	Role                         string          `json:"role"`
	BaseURL                      string          `json:"base_url"`
	TransferURL                  string          `json:"-"`
	Region                       sql.NullString  `json:"region"`
	CPUPct                       sql.NullFloat64 `json:"cpu_pct"`
	MemPct                       sql.NullFloat64 `json:"mem_pct"`
	DiskPct                      sql.NullFloat64 `json:"disk_pct"`
	AgentVersion                 sql.NullString  `json:"agent_version"`
	TavernVersion                sql.NullString  `json:"tavern_version"`
	LastSeenAt                   sql.NullTime    `json:"last_seen_at"`
	Status                       string          `json:"status"`
	AllowRegister                bool            `json:"allow_register"`
	IsBackupTarget               bool            `json:"is_backup_target"`
	RegistrationPolicyState      string          `json:"registration_policy_state"`
	RegistrationPolicyVersion    int64           `json:"registration_policy_version"`
	RegistrationPolicyExpiresAt  sql.NullTime    `json:"registration_policy_expires_at"`
	RegistrationPolicyObservedAt sql.NullTime    `json:"registration_policy_observed_at"`
	RegistrationPolicyErrorCode  sql.NullString  `json:"registration_policy_error_code"`
	CreatedAt                    time.Time       `json:"created_at"`
}

type NodeRegistrationPolicy struct {
	State      string
	Version    int64
	ExpiresAt  time.Time
	ObservedAt time.Time
	ErrorCode  string
}

// UserReplica 用户在某节点的副本。
type UserReplica struct {
	ID          int64
	UserID      int64
	NodeID      int64
	Kind        string // home|hot_standby|archive
	DataVersion int64
	State       string // empty|syncing|ready|stale|error
	LastSyncAt  sql.NullTime
	Checksum    sql.NullString
	SizeBytes   sql.NullInt64
}

type UserNodeAccount struct {
	NodeID                  int64
	LocalHandle             string
	NodeStatus              string
	PasswordMaterialVersion int64
}

type PendingPasswordSync struct {
	LegacyUserID int64
	GlobalUserID int64
	NodeID       int64
	LocalHandle  string
	PasswordHash string
	PasswordSalt string
	Version      int64
}

// Ticket 一次性票据。
type Ticket struct {
	ID        int64
	JTI       string
	UserID    int64
	NodeID    int64
	ExpiresAt time.Time
	UsedAt    sql.NullTime
	CreatedAt time.Time
}

// BackupJob 备份任务。
type BackupJob struct {
	ID          int64
	UserID      int64
	SrcNodeID   int64
	DstNodeID   int64
	Trigger     string
	Status      string
	DataVersion sql.NullInt64
	Bytes       sql.NullInt64
	FileCount   sql.NullInt32
	Error       sql.NullString
	StartedAt   sql.NullTime
	FinishedAt  sql.NullTime
	CreatedAt   time.Time
}
