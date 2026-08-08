// Package protocol 定义总控与子控之间的通信协议、数据结构与 HMAC 签名机制。
// 所有总控↔子控的请求都带 X-Agent-Id / X-Timestamp / X-Nonce / X-Signature 头，
// 签名 = HMAC-SHA256(psk, method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + bodySHA256)。
package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	HeaderAgentID   = "X-Agent-Id"
	HeaderTimestamp = "X-Timestamp"
	HeaderNonce     = "X-Nonce"
	HeaderSignature = "X-Signature"

	// MaxClockSkew 允许的最大时钟偏移，超出视为重放/伪造。
	MaxClockSkew = 60 * time.Second
)

// ---------- 通用响应 ----------

// APIError 是统一错误响应。
type APIError struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// WriteJSON 写出 JSON 响应。
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// WriteError 写出错误响应。
func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, APIError{Error: msg})
}

// ---------- 心跳 / 节点信息 ----------

// UserStatus 描述节点上某用户的在线状态（供总控判断离线触发备份）。
type UserStatus struct {
	Handle               string `json:"handle"`
	SessionID            string `json:"session_id,omitempty"`
	ActivityEpoch        int64  `json:"activity_epoch,omitempty"`
	ControllerGeneration int64  `json:"controller_generation,omitempty"`
	LoginMode            string `json:"login_mode,omitempty"`
	Ended                bool   `json:"ended,omitempty"`
	IsOnline             bool   `json:"is_online"`
	LastActivity         int64  `json:"last_activity"` // Unix 毫秒
	LastPageHeartbeat    int64  `json:"last_page_heartbeat,omitempty"`
	LastRequest          int64  `json:"last_request,omitempty"`
	InFlightReads        int    `json:"in_flight_reads,omitempty"`
	InFlightWrites       int    `json:"in_flight_writes,omitempty"`
}

// HeartbeatRequest 子控定期上报。
type HeartbeatRequest struct {
	NodeID             int64                    `json:"node_id"`
	AgentVersion       string                   `json:"agent_version"`
	TavernVersion      string                   `json:"tavern_version"`
	CPUPct             float64                  `json:"cpu_pct"`
	MemPct             float64                  `json:"mem_pct"`
	DiskPct            float64                  `json:"disk_pct"`
	MetricsValid       bool                     `json:"metrics_valid"`
	DiskTotalBytes     int64                    `json:"disk_total_bytes"`
	DiskAvailableBytes int64                    `json:"disk_available_bytes"`
	DiskQuotaBytes     int64                    `json:"disk_quota_bytes"`
	AllocatedDiskBytes int64                    `json:"allocated_disk_bytes"`
	OnlineUsers        int                      `json:"online_users"`
	TaskQueueDepth     int                      `json:"task_queue_depth"`
	TelemetrySource    string                   `json:"telemetry_source"`
	Compatibility      NodeCompatibilityReport  `json:"compatibility"`
	TransferURL        string                   `json:"transfer_url,omitempty"`
	RegistrationPolicy RegistrationPolicyReport `json:"registration_policy"`
	Users              []UserStatus             `json:"users,omitempty"`
	ControlMode        NodeControlModeReport    `json:"control_mode"`
}

const (
	NodeModeManaged               = "managed"
	NodeModeControllerUnreachable = "controller-unreachable"
	NodeModeIndependent           = "independent"
	NodeModeIndependentDraining   = "independent-draining"
)

// NodeControlModeReport is the Agent's durable, generation-fenced view of the
// local access mode. Session counts are supplied by the loopback adapter and
// let the Controller keep recovery in independent-draining until every
// disaster session has logged out and its user data has been reconciled.
type NodeControlModeReport struct {
	Mode                        string                `json:"mode"`
	ModeGeneration              int64                 `json:"mode_generation"`
	ControllerGeneration        int64                 `json:"controller_generation"`
	ReasonCode                  string                `json:"reason_code"`
	ConsecutiveHeartbeatFails   int                   `json:"consecutive_heartbeat_failures"`
	ConsecutiveHealthProbeFails int                   `json:"consecutive_health_probe_failures"`
	OutageStartedAt             time.Time             `json:"outage_started_at,omitempty"`
	LastControllerSuccessAt     time.Time             `json:"last_controller_success_at,omitempty"`
	IndependentSince            time.Time             `json:"independent_since,omitempty"`
	ActiveIndependentSessions   int                   `json:"active_independent_sessions"`
	PendingUserSyncs            int                   `json:"pending_user_syncs"`
	PendingUsers                []IndependentSyncUser `json:"pending_users,omitempty"`
}

type IndependentSyncUser struct {
	Handle    string `json:"handle"`
	Marker    string `json:"marker"`
	ChangedAt int64  `json:"changed_at"`
	Reason    string `json:"reason"`
}

type CompleteIndependentSyncRequest struct {
	OperationID string `json:"operation_id"`
	Handle      string `json:"handle"`
	Marker      string `json:"marker"`
}

type HeartbeatResponse struct {
	OK                   bool                          `json:"ok"`
	ControllerGeneration int64                         `json:"controller_generation"`
	DesiredMode          string                        `json:"desired_mode"`
	ModeGeneration       int64                         `json:"mode_generation"`
	CredentialRotation   *AgentCredentialRotationOffer `json:"credential_rotation,omitempty"`
}

type AgentCredentialRotationOffer struct {
	CredentialVersion    int64     `json:"credential_version"`
	ControllerGeneration int64     `json:"controller_generation"`
	EncryptedPSK         string    `json:"encrypted_psk"`
	ExpiresAt            time.Time `json:"expires_at"`
}

type ConfirmAgentCredentialRequest struct {
	CredentialVersion int64 `json:"credential_version"`
}

type ConfirmAgentCredentialResponse struct {
	OK                   bool  `json:"ok"`
	CredentialVersion    int64 `json:"credential_version"`
	ControllerGeneration int64 `json:"controller_generation"`
}

type ApplyNodeControlModeRequest struct {
	Mode                 string    `json:"mode"`
	ModeGeneration       int64     `json:"mode_generation"`
	ControllerGeneration int64     `json:"controller_generation"`
	ReasonCode           string    `json:"reason_code"`
	ChangedAt            time.Time `json:"changed_at"`
}

type ApplyNodeControlModeResponse struct {
	OK                        bool   `json:"ok"`
	AppliedMode               string `json:"applied_mode"`
	ModeGeneration            int64  `json:"mode_generation"`
	ActiveIndependentSessions int    `json:"active_independent_sessions"`
	PendingUserSyncs          int    `json:"pending_user_syncs"`
}

type NodeCompatibilityReport struct {
	State       string `json:"state"`
	Fingerprint string `json:"fingerprint"`
	ErrorCode   string `json:"error_code,omitempty"`
}

// RegistrationPolicyReport is a fresh read of the node-owned registration
// policy. The Controller treats every unrecognized, stale, or error report as
// fail-closed and never infers policy from its own invitation tables.
type RegistrationPolicyReport struct {
	State     string    `json:"state"`
	Version   int64     `json:"version"`
	ExpiresAt time.Time `json:"expires_at"`
	ErrorCode string    `json:"error_code,omitempty"`
}

// NodeInfo 子控探测到的节点自身信息（注册/心跳时上报）。
type NodeInfo struct {
	TavernVersion string `json:"tavern_version"`
	TavernPort    int    `json:"tavern_port"`
	DataRoot      string `json:"data_root"`
	BaseURLGuess  string `json:"base_url_guess"` // 探测到的对外域名(可能为空)
	OS            string `json:"os"`
	Arch          string `json:"arch"`
}

// ---------- 注册 / 接管 ----------

// RegisterAgentRequest 子控首次向总控注册（携带一次性令牌）。
type RegisterAgentRequest struct {
	Token       string   `json:"token"` // 一次性注册令牌
	Role        string   `json:"role"`  // compute|storage
	Fingerprint string   `json:"fingerprint"`
	Info        NodeInfo `json:"info"`
}

// RegisterAgentResponse 总控返回分配的身份。
type RegisterAgentResponse struct {
	NodeID               int64  `json:"node_id"`
	AgentPSK             string `json:"agent_psk"` // 该节点专属预共享密钥
	CredentialVersion    int64  `json:"credential_version"`
	ControllerGeneration int64  `json:"controller_generation"`
}

// NodeFingerprint returns a stable, non-secret enrollment fingerprint from
// facts the Agent can probe before it owns a credential.
func NodeFingerprint(info NodeInfo) string {
	value := info.OS + "\n" + info.Arch + "\n" + info.DataRoot + "\n" + info.TavernVersion
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type LeaseCommandRequest struct {
	WorkerID          string `json:"worker_id"`
	HighestGeneration int64  `json:"highest_generation"`
}

type AgentCommand struct {
	ID                   string          `json:"id"`
	OperationID          string          `json:"operation_id"`
	CommandType          string          `json:"command_type"`
	EncryptedPayload     json.RawMessage `json:"encrypted_payload"`
	PayloadSHA256        string          `json:"payload_sha256"`
	Attempt              int             `json:"attempt"`
	ControllerGeneration int64           `json:"controller_generation"`
	LeaseUntil           time.Time       `json:"lease_until"`
	ExpiresAt            time.Time       `json:"expires_at"`
}

type AckCommandRequest struct {
	WorkerID             string `json:"worker_id"`
	ControllerGeneration int64  `json:"controller_generation"`
}

type FinishCommandRequest struct {
	WorkerID             string          `json:"worker_id"`
	ControllerGeneration int64           `json:"controller_generation"`
	Succeeded            bool            `json:"succeeded"`
	Result               json.RawMessage `json:"result"`
}

// MaxAccountInventoryUsers keeps a single durable command result below the
// authenticated 1 MiB result limit. Larger nodes require paged inventory.
const MaxAccountInventoryUsers = 500

// ScanExistingIdentity is a node-keyed fingerprint of an OAuth stable subject.
// The raw provider subject never leaves the Agent's process.
type ScanExistingIdentity struct {
	Provider    string `json:"provider"`
	Fingerprint string `json:"fingerprint"`
}

// ScanExistingUser 子控扫描到的安全既有账号摘要。
type ScanExistingUser struct {
	LocalUserID          string                 `json:"local_user_id"`
	Handle               string                 `json:"handle"`
	Size                 int64                  `json:"size_bytes"`
	DirectoryFingerprint string                 `json:"directory_fingerprint"`
	Source               string                 `json:"source"`
	AccountKind          string                 `json:"account_kind"`
	Identities           []ScanExistingIdentity `json:"identities,omitempty"`
	IsAdmin              bool                   `json:"is_admin"`
}

// ---------- 代注册 ----------

// ProvisionUserRequest 总控下发：在节点上创建用户。
type ProvisionUserRequest struct {
	OperationID    string `json:"operation_id"`
	RegistrationID string `json:"registration_id"`
	PolicyVersion  int64  `json:"policy_version"`
	Handle         string `json:"handle"`
	Name           string `json:"name"`
	PasswordHash   string `json:"password_hash,omitempty"`
	PasswordSalt   string `json:"password_salt,omitempty"`
	OAuthProvider  string `json:"oauth_provider,omitempty"`
	OAuthSubject   string `json:"oauth_subject,omitempty"`
	InvitationCode string `json:"invitation_code,omitempty"`
}

// ProvisionUserResponse 子控返回代注册结果。
type ProvisionUserResponse struct {
	OK          bool   `json:"ok"`
	Handle      string `json:"handle,omitempty"`
	LocalUserID string `json:"local_user_id,omitempty"`
	Error       string `json:"error,omitempty"`
}

type RestoreUserAccountRequest struct {
	OperationID    string `json:"operation_id"`
	WorkflowID     string `json:"workflow_id"`
	GlobalUserID   int64  `json:"global_user_id"`
	Handle         string `json:"handle"`
	Name           string `json:"name"`
	AccountVersion int64  `json:"account_version"`
	PasswordHash   string `json:"password_hash,omitempty"`
	PasswordSalt   string `json:"password_salt,omitempty"`
	OAuthProvider  string `json:"oauth_provider,omitempty"`
	OAuthSubject   string `json:"oauth_subject,omitempty"`
}

type VerifyNodeAdminRequest struct {
	OperationID string `json:"operation_id"`
	Handle      string `json:"handle"`
	Password    string `json:"password"`
}

type CheckNodeAdminRequest struct {
	Handle string `json:"handle"`
}

type NodeAdminVerification struct {
	Handle            string `json:"handle"`
	LocalUserID       string `json:"local_user_id,omitempty"`
	IsAdmin           bool   `json:"is_admin"`
	PermissionVersion int64  `json:"permission_version,omitempty"`
}

type SetPasswordRequest struct {
	OperationID  string `json:"operation_id"`
	Handle       string `json:"handle"`
	PasswordHash string `json:"password_hash"`
	PasswordSalt string `json:"password_salt"`
	Version      int64  `json:"version"`
}

type VerifyLocalUserRequest struct {
	OperationID string `json:"operation_id"`
	Handle      string `json:"handle"`
	Password    string `json:"password"`
}

type VerifyLocalUserResponse struct {
	Handle      string `json:"handle"`
	LocalUserID string `json:"local_user_id,omitempty"`
	Verified    bool   `json:"verified"`
}

// ---------- 备份 ----------

type PrepareSnapshotReceiveRequest struct {
	WorkflowID      string    `json:"workflow_id"`
	SnapshotID      string    `json:"snapshot_id"`
	GlobalUserID    int64     `json:"global_user_id"`
	Handle          string    `json:"handle"`
	DestinationKind string    `json:"destination_kind"`
	SourceNodeID    int64     `json:"source_node_id"`
	ActivityEpoch   int64     `json:"activity_epoch"`
	CapabilityHash  string    `json:"capability_hash"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type StartSnapshotRequest struct {
	JobID              int64     `json:"job_id"`
	WorkflowID         string    `json:"workflow_id"`
	SnapshotID         string    `json:"snapshot_id"`
	GlobalUserID       int64     `json:"global_user_id"`
	Handle             string    `json:"handle"`
	ActivityEpoch      int64     `json:"activity_epoch"`
	TargetNodeID       int64     `json:"target_node_id"`
	TargetTransferURL  string    `json:"target_transfer_url"`
	TransferCapability string    `json:"transfer_capability"`
	CapabilityExpires  time.Time `json:"capability_expires"`
	DestinationKind    string    `json:"destination_kind"`
}

type StartRestoreTransferRequest struct {
	JobID                int64     `json:"job_id"`
	WorkflowID           string    `json:"workflow_id"`
	SourceSnapshotID     string    `json:"source_snapshot_id"`
	RestoreSnapshotID    string    `json:"restore_snapshot_id"`
	SourceManifestSHA256 string    `json:"source_manifest_sha256"`
	GlobalUserID         int64     `json:"global_user_id"`
	Handle               string    `json:"handle"`
	ActivityEpoch        int64     `json:"activity_epoch"`
	TargetNodeID         int64     `json:"target_node_id"`
	TargetTransferURL    string    `json:"target_transfer_url"`
	TransferCapability   string    `json:"transfer_capability"`
	CapabilityExpires    time.Time `json:"capability_expires"`
}

type SnapshotManifest struct {
	FormatVersion int             `json:"format_version"`
	WorkflowID    string          `json:"workflow_id"`
	SnapshotID    string          `json:"snapshot_id"`
	GlobalUserID  int64           `json:"global_user_id"`
	Handle        string          `json:"handle"`
	SourceNodeID  int64           `json:"source_node_id"`
	TargetNodeID  int64           `json:"target_node_id"`
	ActivityEpoch int64           `json:"activity_epoch"`
	CreatedAt     time.Time       `json:"created_at"`
	Files         []ManifestEntry `json:"files"`
}

type SnapshotTransferReceipt struct {
	OK             bool   `json:"ok"`
	SnapshotID     string `json:"snapshot_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	ArchiveSHA256  string `json:"archive_sha256"`
	FileCount      int64  `json:"file_count"`
	TotalBytes     int64  `json:"total_bytes"`
}

type SnapshotProgressRequest struct {
	WorkflowID string `json:"workflow_id"`
	SnapshotID string `json:"snapshot_id"`
	State      string `json:"state"`
}

// ManifestEntry 单个文件的校验条目。
type ManifestEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ---------- 冲突证据 ----------

type CaptureConflictEvidenceRequest struct {
	ConflictID           string `json:"conflict_id"`
	EvidenceID           string `json:"evidence_id"`
	GlobalUserID         int64  `json:"global_user_id"`
	Handle               string `json:"handle"`
	SourceKind           string `json:"source_kind"`
	SourceSnapshotID     string `json:"source_snapshot_id,omitempty"`
	SourceManifestSHA256 string `json:"source_manifest_sha256,omitempty"`
}

type ConflictEvidenceReceipt struct {
	EvidenceID       string `json:"evidence_id"`
	EntriesSHA256    string `json:"entries_sha256"`
	FileCount        int64  `json:"file_count"`
	TotalBytes       int64  `json:"total_bytes"`
	CaptureBasis     string `json:"capture_basis"`
	SourceSnapshotID string `json:"source_snapshot_id,omitempty"`
}

type ReadConflictEvidencePageRequest struct {
	ConflictID  string `json:"conflict_id"`
	EvidenceID  string `json:"evidence_id"`
	Cursor      int    `json:"cursor"`
	MaxBytes    int    `json:"max_bytes"`
	ResponseKey string `json:"response_key"`
}

type ConflictEvidencePage struct {
	EvidenceID string          `json:"evidence_id"`
	Cursor     int             `json:"cursor"`
	NextCursor int             `json:"next_cursor"`
	Complete   bool            `json:"complete"`
	Entries    []ManifestEntry `json:"entries"`
}

type StartConflictEvidenceTransferRequest struct {
	ConflictID         string    `json:"conflict_id"`
	EvidenceID         string    `json:"evidence_id"`
	GlobalUserID       int64     `json:"global_user_id"`
	Handle             string    `json:"handle"`
	TargetNodeID       int64     `json:"target_node_id"`
	TargetTransferURL  string    `json:"target_transfer_url"`
	TransferCapability string    `json:"transfer_capability"`
	CapabilityExpires  time.Time `json:"capability_expires"`
}

type ConflictResolutionSource struct {
	NodeID        int64  `json:"node_id"`
	EvidenceID    string `json:"evidence_id"`
	EntriesSHA256 string `json:"entries_sha256"`
}

type PrepareConflictResolutionRequest struct {
	OperationID       string                     `json:"operation_id"`
	ConflictID        string                     `json:"conflict_id"`
	ResultID          string                     `json:"result_id"`
	GlobalUserID      int64                      `json:"global_user_id"`
	Handle            string                     `json:"handle"`
	BaseNodeID        int64                      `json:"base_node_id"`
	DefaultAction     string                     `json:"default_action"`
	DecisionPageCount int                        `json:"decision_page_count"`
	DecisionCount     int                        `json:"decision_count"`
	Sources           []ConflictResolutionSource `json:"sources"`
}

type ConflictResolutionDecision struct {
	Path         string `json:"path"`
	SourceNodeID int64  `json:"source_node_id"`
	Action       string `json:"action"`
}

type ApplyConflictResolutionDecisionsRequest struct {
	OperationID string                       `json:"operation_id"`
	PageIndex   int                          `json:"page_index"`
	Decisions   []ConflictResolutionDecision `json:"decisions"`
}

type PublishConflictResolutionRequest struct {
	OperationID string `json:"operation_id"`
}

type ConflictResolutionReceipt struct {
	OperationID      string `json:"operation_id"`
	ConflictID       string `json:"conflict_id"`
	ResultID         string `json:"result_id"`
	EntriesSHA256    string `json:"entries_sha256"`
	FileCount        int64  `json:"file_count"`
	TotalBytes       int64  `json:"total_bytes"`
	PreservedSources int    `json:"preserved_sources"`
}

// ---------- HMAC 签名 ----------

// bodyHash 计算请求体的 SHA256 hex。
func bodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// canonicalString 拼接待签名串。
func canonicalString(method, path, timestamp, nonce string, body []byte) string {
	return method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + bodyHash(body)
}

// Sign 计算 HMAC-SHA256 签名（hex）。
func Sign(psk, method, path, timestamp, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write([]byte(canonicalString(method, path, timestamp, nonce, body)))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignRequest 为出站请求设置签名头。body 为即将发送的字节（GET 可为 nil）。
func SignRequest(req *http.Request, agentID int64, psk string, body []byte) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := randomNonce()
	sig := Sign(psk, req.Method, req.URL.Path, ts, nonce, body)
	req.Header.Set(HeaderAgentID, strconv.FormatInt(agentID, 10))
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, sig)
}

// VerifyRequest 校验入站请求签名。body 为已读取的请求体字节。
// 返回错误描述（空为通过）。调用方需自行保证 body 可被重复读取（中间件已处理）。
func VerifyRequest(r *http.Request, psk string, body []byte) error {
	ts := r.Header.Get(HeaderTimestamp)
	nonce := r.Header.Get(HeaderNonce)
	sig := r.Header.Get(HeaderSignature)
	if ts == "" || nonce == "" || sig == "" {
		return fmt.Errorf("missing signature headers")
	}
	nonceBytes, err := hex.DecodeString(nonce)
	if err != nil || len(nonceBytes) != 16 {
		return fmt.Errorf("invalid nonce")
	}
	// 防重放: 时间戳必须在允许偏移内
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp")
	}
	if d := time.Since(time.Unix(tsInt, 0)); d > MaxClockSkew || d < -MaxClockSkew {
		return fmt.Errorf("timestamp out of range")
	}
	expect := Sign(psk, r.Method, r.URL.Path, ts, nonce, body)
	if !hmac.Equal([]byte(expect), []byte(sig)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// randomNonce 生成随机 nonce。
func randomNonce() string {
	b := make([]byte, 16)
	rndRead(b)
	return hex.EncodeToString(b)
}
