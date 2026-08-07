package controller

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// handleAdminOverview 仪表盘总览。
func (s *Server) handleAdminOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	nodes, _ := s.Store.ListNodes(ctx)
	users, _ := s.Store.ListUsers(ctx)
	jobs, _ := s.Store.ListBackupJobs(ctx, 200)

	online, offline, full := 0, 0, 0
	for _, n := range nodes {
		switch n.Status {
		case "online":
			online++
		case "offline":
			offline++
		}
		if !s.nodeRegistrable(n) && n.Role == "compute" {
			full++
		}
	}
	running, failed := 0, 0
	for _, j := range jobs {
		switch j.Status {
		case "running", "pending", "verifying":
			running++
		case "failed":
			failed++
		}
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"nodes":          len(nodes),
		"nodes_online":   online,
		"nodes_offline":  offline,
		"nodes_full":     full,
		"users":          len(users),
		"backup_running": running,
		"backup_failed":  failed,
	})
}

// handleAdminListNodes 列出节点。
func (s *Server) handleAdminListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.Store.ListNodes(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "查询失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"nodes": nodes})
}

// handleAdminCreateNode 手动添加节点（通常由子控注册自动创建, 这里用于预创建/导入）。
func (s *Server) handleAdminCreateNode(w http.ResponseWriter, r *http.Request) {
	var n store.Node
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if n.Name == "" {
		protocol.WriteError(w, http.StatusBadRequest, "节点名称不能为空")
		return
	}
	if n.Role != "compute" && n.Role != "storage" {
		n.Role = "compute"
	}
	if n.AgentPSK == "" {
		psk, _ := crypto.RandomPassword(48)
		n.AgentPSK = psk
	}
	n.Status = "pending"
	if err := s.Store.CreateNode(r.Context(), &n); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "创建节点失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "id": n.ID})
}

// handleAdminUpdateNode 更新节点配置。
func (s *Server) handleAdminUpdateNode(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var n store.Node
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if _, err := parseID(id); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "非法节点 ID")
		return
	}
	nid, _ := parseID(id)
	n.ID = nid
	if err := s.Store.UpdateNodeSettings(r.Context(), &n); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "更新失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAdminNodeRegisterToken 为节点生成一次性注册令牌 + 安装命令。
func (s *Server) handleAdminNodeRegisterToken(w http.ResponseWriter, r *http.Request) {
	token, err := randomBearerToken()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成令牌失败")
		return
	}
	expires := time.Now().Add(24 * time.Hour)
	if err := s.Store.CreateRegisterToken(r.Context(), token, "admin 生成", expires); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成令牌失败")
		return
	}
	installCmd := "curl -sSL " + s.Cfg.PublicURL + "/install.sh | bash -s -- --controller " +
		s.Cfg.PublicURL + " --token " + token + " --role compute"
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"token": token, "expires_at": expires, "install_cmd": installCmd,
	})
}

// handleAdminScanExisting 让子控扫描既有用户。
func (s *Server) handleAdminScanExisting(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	nid, err := parseID(id)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "非法节点 ID")
		return
	}
	node, err := s.Store.GetNodeByID(r.Context(), nid)
	if err != nil || node == nil {
		protocol.WriteError(w, http.StatusNotFound, "节点不存在")
		return
	}
	users, err := s.agent.scanExisting(r.Context(), node.ID, node.AgentPSK, node.AgentURL)
	if err != nil {
		protocol.WriteError(w, http.StatusBadGateway, "扫描失败: "+err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"users": users})
}

// handleAdminListUsers 列出用户。
func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Store.ListUsers(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "查询失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"users": users})
}

// handleAdminTriggerBackup 手动触发某用户备份。
func (s *Server) handleAdminTriggerBackup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	uid, err := parseID(id)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "非法用户 ID")
		return
	}
	user, err := s.Store.GetUserByID(r.Context(), uid)
	if err != nil || user == nil {
		protocol.WriteError(w, http.StatusNotFound, "用户不存在")
		return
	}
	if !user.HomeNodeID.Valid {
		protocol.WriteError(w, http.StatusBadRequest, "用户未绑定家节点")
		return
	}
	if err := s.TriggerUserBackup(r.Context(), uid, user.HomeNodeID.Int64, "manual"); err != nil {
		protocol.WriteError(w, http.StatusBadGateway, "触发备份失败: "+err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAdminDisableUser 禁用用户。
func (s *Server) handleAdminDisableUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	uid, err := parseID(id)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "非法用户 ID")
		return
	}
	if err := s.Store.UpdateUserStatus(r.Context(), uid, "disabled"); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "操作失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAdminListBackups 列出备份任务。
func (s *Server) handleAdminListBackups(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.Store.ListBackupJobs(r.Context(), 200)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "查询失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"backups": jobs})
}

// handleAdminAbortBackup 中止备份任务。
func (s *Server) handleAdminAbortBackup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	jid, err := parseID(id)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "非法任务 ID")
		return
	}
	job, err := s.Store.GetBackupJob(r.Context(), jid)
	if err != nil || job == nil {
		protocol.WriteError(w, http.StatusNotFound, "任务不存在")
		return
	}
	node, err := s.Store.GetNodeByID(r.Context(), job.SrcNodeID)
	if err == nil && node != nil {
		_ = s.agent.abortBackup(r.Context(), node.ID, node.AgentPSK, node.AgentURL, job.ID)
	}
	_ = s.Store.UpdateBackupJobStatus(r.Context(), job.ID, "aborted", 0, 0, 0, "管理员中止")
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAdminCreateInvitation 创建邀请码。
func (s *Server) handleAdminCreateInvitation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code      string     `json:"code"`
		MaxUses   int        `json:"max_uses"`
		NodeID    *int64     `json:"node_id"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.Code == "" {
		code, err := randomHexToken(6)
		if err != nil {
			protocol.WriteError(w, http.StatusInternalServerError, "生成邀请码失败")
			return
		}
		req.Code = code
	}
	if req.MaxUses <= 0 {
		req.MaxUses = 1
	}
	if err := s.Store.CreateInvitation(r.Context(), req.Code, req.MaxUses, req.NodeID, req.ExpiresAt); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "创建失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "code": req.Code})
}

func parseID(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}
