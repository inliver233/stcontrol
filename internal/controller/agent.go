package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// handleAgentRegister 子控首次注册：核销一次性令牌 → 分配 node_id + agent_psk。
func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var req protocol.RegisterAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	ctx := r.Context()

	ok, err := s.Store.ConsumeRegisterToken(ctx, req.Token)
	if err != nil || !ok {
		protocol.WriteError(w, http.StatusForbidden, "注册令牌无效或已过期")
		return
	}

	psk, err := crypto.RandomPassword(48)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成密钥失败")
		return
	}
	role := req.Role
	if role != "compute" && role != "storage" {
		role = "compute"
	}
	name := req.Name
	if name == "" {
		name = "节点-" + psk[:6]
	}

	node := &store.Node{
		Name:      name,
		Role:      role,
		BaseURL:   req.Info.BaseURLGuess, // 可能为空, 由管理员后台补
		AgentURL:  req.AgentURL,
		AgentPSK:  psk,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	if err := s.Store.CreateNode(ctx, node); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "创建节点失败")
		return
	}
	_ = s.Store.Audit(ctx, "agent", "register", name, nil)

	protocol.WriteJSON(w, http.StatusOK, protocol.RegisterAgentResponse{
		NodeID:   node.ID,
		AgentPSK: psk,
	})
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

	if err := s.Store.UpdateNodeHeartbeat(ctx, node.ID, req.CPUPct, req.MemPct, req.DiskPct,
		req.TavernVersion, req.AgentVersion); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "更新心跳失败")
		return
	}

	// 处理用户在线状态 → 供离线备份调度参考
	s.trackUserActivity(node.ID, req.Users)

	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleBackupReport 子控上报备份进度/结果。
func (s *Server) handleBackupReport(w http.ResponseWriter, r *http.Request) {
	node := currentNode(r)
	if node == nil {
		protocol.WriteError(w, http.StatusUnauthorized, "未知节点")
		return
	}
	var rep protocol.BackupStatusResponse
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	ctx := r.Context()

	_ = s.Store.UpdateBackupJobStatus(ctx, rep.JobID, rep.Status, rep.DataVersion, rep.Bytes, rep.FileCount, rep.Error)

	// 备份成功 → 更新目标节点副本状态
	if rep.Status == "done" {
		if job, _ := s.Store.GetBackupJob(ctx, rep.JobID); job != nil {
			_ = s.Store.UpdateReplicaState(ctx, job.UserID, job.DstNodeID, "ready",
				rep.DataVersion, rep.Checksum, rep.Bytes)
		}
	} else if rep.Status == "failed" || rep.Status == "aborted" {
		if job, _ := s.Store.GetBackupJob(ctx, rep.JobID); job != nil {
			_ = s.Store.UpdateReplicaState(ctx, job.UserID, job.DstNodeID, "error", 0, "", 0)
		}
	}

	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleScanExistingReport 子控上报扫描到的既有用户（接管老节点用）。
func (s *Server) handleScanExistingReport(w http.ResponseWriter, r *http.Request) {
	node := currentNode(r)
	if node == nil {
		protocol.WriteError(w, http.StatusUnauthorized, "未知节点")
		return
	}
	var req struct {
		Users []protocol.ScanExistingUser `json:"users"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	// 记录到审计, 管理后台可据此导入
	detail, _ := json.Marshal(req.Users)
	_ = s.Store.Audit(r.Context(), "agent", "scan-existing", node.Name, detail)
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(req.Users)})
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
