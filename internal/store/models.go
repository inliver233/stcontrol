package store

import (
	"database/sql"
	"time"
)

// User 总控用户。
type User struct {
	ID           int64
	UUID         string
	Username     string
	DisplayName  string
	PasswordEnc  sql.NullString // AES-GCM 加密的明文密码(账号密码用户)
	PasswordHash sql.NullString // bcrypt, 总控登录校验
	AuthProvider string
	OAuthID      sql.NullString
	AvatarURL    sql.NullString
	Email        sql.NullString
	HomeNodeID   sql.NullInt64
	Status       string
	CreatedAt    time.Time
}

// Node 节点。
type Node struct {
	ID             int64
	Name           string
	Role           string
	BaseURL        string
	AgentURL       string
	AgentPSK       string
	Region         sql.NullString
	CPUPct         sql.NullFloat64
	MemPct         sql.NullFloat64
	DiskPct        sql.NullFloat64
	AgentVersion   sql.NullString
	TavernVersion  sql.NullString
	LastSeenAt     sql.NullTime
	Status         string
	AllowRegister  bool
	IsBackupTarget bool
	CreatedAt      time.Time
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
