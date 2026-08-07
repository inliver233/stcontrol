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
	Handle       string `json:"handle"`
	IsOnline     bool   `json:"is_online"`
	LastActivity int64  `json:"last_activity"` // Unix 毫秒
}

// HeartbeatRequest 子控定期上报。
type HeartbeatRequest struct {
	NodeID        int64        `json:"node_id"`
	AgentVersion  string       `json:"agent_version"`
	TavernVersion string       `json:"tavern_version"`
	CPUPct        float64      `json:"cpu_pct"`
	MemPct        float64      `json:"mem_pct"`
	DiskPct       float64      `json:"disk_pct"`
	Users         []UserStatus `json:"users,omitempty"`
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
	Token    string   `json:"token"` // 一次性注册令牌
	Name     string   `json:"name"`
	Role     string   `json:"role"` // compute|storage
	Info     NodeInfo `json:"info"`
	AgentURL string   `json:"agent_url"` // 子控回调地址
}

// RegisterAgentResponse 总控返回分配的身份。
type RegisterAgentResponse struct {
	NodeID   int64  `json:"node_id"`
	AgentPSK string `json:"agent_psk"` // 该节点专属预共享密钥
}

// ScanExistingUser 子控扫描到的既有用户目录。
type ScanExistingUser struct {
	Handle string `json:"handle"`
	Size   int64  `json:"size_bytes"`
}

// ---------- 代注册 ----------

// ProvisionUserRequest 总控下发：在节点上创建用户。
type ProvisionUserRequest struct {
	Handle         string `json:"handle"`
	Name           string `json:"name"`
	Password       string `json:"password"`                  // 账号密码用户为真实密码, OAuth 用户为随机占位
	InvitationCode string `json:"invitation_code,omitempty"` // 若节点要求
}

// ProvisionUserResponse 子控返回代注册结果。
type ProvisionUserResponse struct {
	OK     bool   `json:"ok"`
	Handle string `json:"handle,omitempty"`
	Error  string `json:"error,omitempty"`
}

// ---------- 备份 ----------

// BackupStartRequest 总控下发给源节点：开始备份。
type BackupStartRequest struct {
	JobID       int64  `json:"job_id"`
	UserID      int64  `json:"user_id"`
	Handle      string `json:"handle"`
	DstAgentURL string `json:"dst_agent_url"` // 目标子控地址
	DstNodePSK  string `json:"dst_node_psk"`  // 与目标子控签名用的 PSK(由总控转发)
	DstNodeID   int64  `json:"dst_node_id"`
	DstKind     string `json:"dst_kind"` // hot_standby|archive
}

// BackupStatusResponse 备份进度/结果。
type BackupStatusResponse struct {
	JobID       int64  `json:"job_id"`
	Status      string `json:"status"` // running|verifying|done|aborted|failed
	Bytes       int64  `json:"bytes"`
	FileCount   int    `json:"file_count"`
	Checksum    string `json:"checksum,omitempty"`
	Error       string `json:"error,omitempty"`
	DataVersion int64  `json:"data_version,omitempty"`
}

// BackupReceiveMeta 目标节点接收备份时的元信息（通过查询参数或头传递）。
type BackupReceiveMeta struct {
	JobID      int64  `json:"job_id"`
	Handle     string `json:"handle"`
	DstKind    string `json:"dst_kind"`
	Manifest   string `json:"manifest"`    // SHA256 清单(JSON, 见 ManifestEntry)
	DataVer    int64  `json:"data_version"`
}

// ManifestEntry 单个文件的校验条目。
type ManifestEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
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
