package controller

import (
	"encoding/json"
	"net/http"
	"time"

	"stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// handleLoginRedirect 用户选定节点后, 签发一次性票据并返回跳转 URL。
func (s *Server) handleLoginRedirect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID int64 `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	ctx := r.Context()
	userID, _ := CurrentUser(r)

	user, err := s.Store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		protocol.WriteError(w, http.StatusUnauthorized, "用户不存在")
		return
	}
	node, err := s.Store.GetNodeByID(ctx, req.NodeID)
	if err != nil || node == nil {
		protocol.WriteError(w, http.StatusBadRequest, "节点不存在")
		return
	}

	// 校验该节点对当前用户可用
	replica, err := s.Store.GetReplica(ctx, userID, node.ID)
	if err != nil || replica == nil {
		protocol.WriteError(w, http.StatusForbidden, "该节点不是你的可用节点")
		return
	}
	if replica.Kind == "archive" {
		protocol.WriteError(w, http.StatusForbidden, "存储节点不可登录")
		return
	}
	if node.Status != "online" {
		protocol.WriteError(w, http.StatusConflict, "该节点当前离线")
		return
	}
	if replica.Kind == "hot_standby" && replica.State != "ready" {
		protocol.WriteError(w, http.StatusConflict, "备用节点尚未同步完成")
		return
	}

	// 若有进行中的备份任务 → 中止(不阻塞用户登录)
	if s.Cfg.Backup.AbortOnLogin {
		if job, _ := s.Store.FindRunningBackupForUserOnNode(ctx, userID, node.ID); job != nil {
			_ = s.agent.abortBackup(ctx, node.ID, node.AgentPSK, node.AgentURL, job.ID)
			_ = s.Store.UpdateBackupJobStatus(ctx, job.ID, "aborted", 0, 0, 0, "用户登录,中止备份")
		}
	}

	// 生成票据
	jti := randToken()
	ttl := time.Duration(s.Cfg.Ticket.TTLSec) * time.Second
	secret := crypto.DeriveTicketSecret(node.AgentPSK)
	token, err := crypto.IssueTicket(secret, user.Username, node.BaseURL, jti, ttl)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "票据签发失败")
		return
	}
	if err := s.Store.CreateTicket(ctx, &store.Ticket{
		JTI: jti, UserID: userID, NodeID: node.ID,
		ExpiresAt: time.Now().Add(ttl),
	}); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "票据记录失败")
		return
	}

	redirectURL := node.BaseURL + "/federated-login?ticket=" + token
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "redirect_url": redirectURL,
	})
}

// handleTicketVerify 节点调用: 核销票据。节点用其 PSK 对请求签名。
// 这里不强制 agentAuth 中间件, 而是手动校验(因为 body 含 jti + node_id)。
func (s *Server) handleTicketVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		JTI    string `json:"jti"`
		NodeID int64  `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	ctx := r.Context()

	userID, nodeID, ok, err := s.Store.ConsumeTicket(ctx, req.JTI, time.Now())
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "核销失败")
		return
	}
	if !ok || nodeID != req.NodeID {
		protocol.WriteError(w, http.StatusForbidden, "票据无效、已使用或已过期")
		return
	}
	user, err := s.Store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		protocol.WriteError(w, http.StatusForbidden, "用户不存在")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "handle": user.Username, "user_id": userID,
	})
}
