package controller

import (
	"context"
	stdsha256 "crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// handleAgentRegister consumes a pre-created node-scoped enrollment token and
// rotates an encrypted Agent credential. The controller never needs agent_url.
func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var req protocol.RegisterAgentRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	ctx := r.Context()
	if req.Token == "" || req.Fingerprint == "" || req.Fingerprint != protocol.NodeFingerprint(req.Info) {
		protocol.WriteError(w, http.StatusForbidden, "注册令牌无效或已过期")
		return
	}
	psk, err := crypto.RandomPassword(48)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成密钥失败")
		return
	}
	if req.Role != "compute" && req.Role != "storage" {
		protocol.WriteError(w, http.StatusForbidden, "注册令牌与节点角色不匹配")
		return
	}
	credentialID, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成凭据失败")
		return
	}
	ciphertext, err := crypto.Encrypt(s.secretKey, []byte(psk))
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "加密凭据失败")
		return
	}
	tokenHash := stdsha256.Sum256([]byte(req.Token))
	enrollment, err := s.Store.EnrollAgent(ctx, store.EnrollAgentParams{
		TokenHash: tokenHash[:], PresentedRole: req.Role,
		PresentedFingerprint: req.Fingerprint, CredentialID: credentialID,
		CredentialCiphertext: []byte(ciphertext), AgentVersion: req.Info.OS + "/" + req.Info.Arch,
		TavernVersion: req.Info.TavernVersion, BaseURLGuess: req.Info.BaseURLGuess,
		Now: time.Now().UTC(),
	})
	if err != nil {
		protocol.WriteError(w, http.StatusForbidden, "注册令牌无效或已过期")
		return
	}
	_ = s.Store.Audit(ctx, "agent", "enroll", req.Role, nil)

	protocol.WriteJSON(w, http.StatusOK, protocol.RegisterAgentResponse{
		NodeID: enrollment.NodeID, AgentPSK: psk,
		CredentialVersion:    enrollment.CredentialVersion,
		ControllerGeneration: enrollment.ControllerGeneration,
	})
}

func validateAgentTransferURL(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid transfer URL")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback) {
		return "", fmt.Errorf("transfer URL must use HTTPS")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String(), nil
}

// handleAgentHeartbeat 接收子控心跳（更新负载、版本、用户在线状态）。
func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	node := currentNode(r)
	if node == nil {
		protocol.WriteError(w, http.StatusUnauthorized, "未知节点")
		return
	}
	var req protocol.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	ctx := r.Context()
	transferURL, err := validateAgentTransferURL(req.TransferURL)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "数据面地址无效")
		return
	}

	if err := s.Store.UpdateNodeHeartbeat(ctx, node.ID, req.CPUPct, req.MemPct, req.DiskPct,
		req.TavernVersion, req.AgentVersion, transferURL); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "更新心跳失败")
		return
	}

	// 处理用户在线状态 → 供离线备份调度参考
	s.trackUserActivity(node.ID, req.Users)

	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------- 离线备份调度辅助 ----------

// trackUserActivity 记录节点上用户的在线状态（内存态, 供调度器用）。
func (s *Server) trackUserActivity(nodeID int64, users []protocol.UserStatus) {
	// 简化: 存入内存 map, 调度器读取。
	s.actMu.Lock()
	defer s.actMu.Unlock()
	if s.activity == nil {
		s.activity = make(map[int64]map[string]protocol.UserStatus)
	}
	m := s.activity[nodeID]
	if m == nil {
		m = make(map[string]protocol.UserStatus)
		s.activity[nodeID] = m
	}
	for _, u := range users {
		m[u.Handle] = u
	}
}

// ---------- 后台任务 ----------

// nodeWatchdog 定期把超时未心跳的节点标记为 offline。
func (s *Server) nodeWatchdog(ctx context.Context) {
	timeout := time.Duration(s.Cfg.Node.HeartbeatTimeoutSec) * time.Second
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.Store.MarkStaleNodesOffline(ctx, timeout)
		}
	}
}

// backupScheduler 扫描离线用户并触发备份（详见 backup.go 的完整实现）。
func (s *Server) backupScheduler(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scheduleOfflineBackups(ctx)
		}
	}
}
