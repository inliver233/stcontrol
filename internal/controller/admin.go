package controller

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// handleAdminOverview 仪表盘总览。
func (s *Server) handleAdminOverview(w http.ResponseWriter, r *http.Request) {
	counts, err := s.Store.GetAdminOverviewCounts(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "总览统计暂不可用")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, counts)
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
	if n.Name == "" {
		protocol.WriteError(w, http.StatusBadRequest, "节点配置无效")
		return
	}
	if err := s.Store.UpdateNodeSettings(r.Context(), &n); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "更新失败")
		return
	}
	detail, _ := json.Marshal(map[string]any{
		"allow_register": n.AllowRegister, "is_backup_target": n.IsBackupTarget,
	})
	if sess := currentSession(r); sess != nil {
		_ = s.Store.Audit(r.Context(), sess.Username, "node-settings", id, detail)
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type nodeLifecycleRequest struct {
	OperationID     string `json:"operation_id"`
	State           string `json:"state"`
	ReasonCode      string `json:"reason_code"`
	AcknowledgeRisk bool   `json:"acknowledge_risk"`
}

func (s *Server) handleAdminTransitionNodeLifecycle(w http.ResponseWriter, r *http.Request) {
	if !s.requireNewOperations(w) {
		return
	}
	nodeID, err := parseID(chi.URLParam(r, "id"))
	var req nodeLifecycleRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&req) != nil || !isUUID(req.OperationID) ||
		(req.State != "active" && req.State != "maintenance" && req.State != "draining" &&
			req.State != "degraded" && req.State != "failed" && req.State != "retired") ||
		len(req.ReasonCode) == 0 || len(req.ReasonCode) > 128 ||
		((req.State == "failed" || req.State == "retired") && !req.AcknowledgeRisk) {
		protocol.WriteError(w, http.StatusBadRequest, "节点生命周期请求无效")
		return
	}
	sess := currentSession(r)
	if sess == nil || sess.AdminID <= 0 {
		protocol.WriteError(w, http.StatusUnauthorized, "管理员会话无效")
		return
	}
	state, err := s.Store.TransitionNodeLifecycle(r.Context(), store.TransitionNodeLifecycleParams{
		OperationID: req.OperationID, NodeID: nodeID, ToState: req.State,
		ReasonCode: req.ReasonCode, AdminID: sess.AdminID, Now: time.Now().UTC(),
	})
	if err != nil {
		if errors.Is(err, store.ErrNodeLifecycleBlocked) {
			protocol.WriteError(w, http.StatusConflict, "节点仍承载活动用户或副本，必须先排空/迁移")
			return
		}
		protocol.WriteError(w, http.StatusServiceUnavailable, "节点生命周期更新失败")
		return
	}
	detail, _ := json.Marshal(map[string]string{"state": state, "reason_code": req.ReasonCode})
	_ = s.Store.Audit(r.Context(), sess.Username, "node-lifecycle", chi.URLParam(r, "id"), detail)
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "state": state})
}

// handleAdminNodeRegisterToken 为节点生成一次性注册令牌 + 安装命令。
func (s *Server) handleAdminNodeRegisterToken(w http.ResponseWriter, r *http.Request) {
	nodeID, err := parseID(chi.URLParam(r, "id"))
	if err != nil || nodeID <= 0 {
		protocol.WriteError(w, http.StatusBadRequest, "非法节点 ID")
		return
	}
	node, err := s.Store.GetNodeByID(r.Context(), nodeID)
	if err != nil || node == nil || (node.Role != "compute" && node.Role != "storage") {
		protocol.WriteError(w, http.StatusNotFound, "节点不存在")
		return
	}
	token, err := randomBearerToken()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成令牌失败")
		return
	}
	tokenID, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成令牌失败")
		return
	}
	operationID, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成令牌失败")
		return
	}
	now := time.Now().UTC()
	expires := now.Add(15 * time.Minute)
	tokenHash := sha256.Sum256([]byte(token))
	if err := s.Store.CreateEnrollmentToken(r.Context(), store.CreateEnrollmentTokenParams{
		ID: tokenID, OperationID: operationID, TokenHash: tokenHash[:],
		ExpectedNodeID: node.ID, ExpectedRole: node.Role, ExpiresAt: expires, Now: now,
	}); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成令牌失败")
		return
	}
	installCmd := "curl -sSL " + s.Cfg.PublicURL + "/install.sh | bash -s -- --controller " +
		s.Cfg.PublicURL + " --token " + token + " --role " + node.Role
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"token": token, "expires_at": expires, "install_cmd": installCmd,
	})
}

// handleAdminListUsers 列出用户。
func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	limit, cursor, err := parseAdminPage(r, "after")
	query := r.URL.Query().Get("q")
	status := r.URL.Query().Get("status")
	if err != nil || len(query) > 128 {
		protocol.WriteError(w, http.StatusBadRequest, "分页或筛选参数无效")
		return
	}
	page, err := s.Store.ListUsersPage(r.Context(), store.UserPageParams{
		AfterID: cursor, Limit: limit, Query: query, Status: status,
	})
	if err != nil {
		if errors.Is(err, store.ErrInvalidAdminPage) {
			protocol.WriteError(w, http.StatusBadRequest, "分页或筛选参数无效")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, "查询失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"users": page.Users, "has_more": page.HasMore, "next_cursor": page.NextCursor,
	})
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
	limit, cursor, err := parseAdminPage(r, "before")
	status := r.URL.Query().Get("status")
	userID := int64(0)
	if raw := r.URL.Query().Get("user_id"); raw != "" {
		userID, err = strconv.ParseInt(raw, 10, 64)
	}
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "分页或筛选参数无效")
		return
	}
	page, err := s.Store.ListBackupJobsPage(r.Context(), store.BackupPageParams{
		BeforeID: cursor, Limit: limit, Status: status, UserID: userID,
	})
	if err != nil {
		if errors.Is(err, store.ErrInvalidAdminPage) {
			protocol.WriteError(w, http.StatusBadRequest, "分页或筛选参数无效")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, "查询失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"backups": page.Jobs, "has_more": page.HasMore, "next_cursor": page.NextCursor,
	})
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
	if err != nil || node == nil {
		protocol.WriteError(w, http.StatusConflict, "源节点不可用")
		return
	}
	if _, err := s.runAgentCommand(r.Context(), node, "abort_backup", map[string]int64{"job_id": job.ID}, 30*time.Second); err != nil {
		protocol.WriteError(w, http.StatusBadGateway, "中止命令未被节点确认")
		return
	}
	if err := s.Store.UpdateBackupJobStatus(r.Context(), job.ID, "aborted", 0, 0, 0, "管理员中止"); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "更新任务状态失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func parseID(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

func parseAdminPage(r *http.Request, cursorName string) (int, int64, error) {
	limit := 50
	var err error
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
	}
	if err != nil || limit <= 0 || limit > 100 {
		return 0, 0, store.ErrInvalidAdminPage
	}
	cursor := int64(0)
	if raw := r.URL.Query().Get(cursorName); raw != "" {
		cursor, err = strconv.ParseInt(raw, 10, 64)
	}
	if err != nil || cursor < 0 {
		return 0, 0, store.ErrInvalidAdminPage
	}
	return limit, cursor, nil
}
