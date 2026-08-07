package controller

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

type registerRequest struct {
	Username       string `json:"username"`
	DisplayName    string `json:"display_name"`
	Password       string `json:"password"`
	NodeID         int64  `json:"node_id"`
	InvitationCode string `json:"invitation_code"`
}

// handleRegister 账号密码注册。
// 流程: 规范化 handle → 校验节点可注册 → 校验邀请码 → 总控建用户 → 代注册到节点 → 绑定家节点。
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	ctx := r.Context()

	handle := NormalizeHandle(req.Username)
	if !isValidHandle(handle) {
		protocol.WriteError(w, http.StatusBadRequest, "用户名无效（3-32位，仅小写字母、数字、横杠）")
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = handle
	}
	if len(req.Password) < 6 {
		protocol.WriteError(w, http.StatusBadRequest, "密码至少 6 位")
		return
	}

	// 校验节点可注册
	node, err := s.Store.GetNodeByID(ctx, req.NodeID)
	if err != nil || node == nil {
		protocol.WriteError(w, http.StatusBadRequest, "节点不存在")
		return
	}
	if !s.nodeRegistrable(node) {
		protocol.WriteError(w, http.StatusConflict, "该节点当前不可注册（满员或离线）")
		return
	}

	// 校验用户名未被占用
	existing, err := s.Store.GetUserByUsername(ctx, handle)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "查询失败")
		return
	}
	if existing != nil {
		protocol.WriteError(w, http.StatusConflict, "用户名已存在")
		return
	}

	// 校验邀请码（如果节点要求 / 用户提供了）
	if req.InvitationCode != "" {
		ok, reason, err := s.Store.ValidateInvitation(ctx, req.InvitationCode, node.ID)
		if err != nil {
			protocol.WriteError(w, http.StatusInternalServerError, "邀请码校验失败")
			return
		}
		if !ok {
			protocol.WriteError(w, http.StatusBadRequest, reason)
			return
		}
	}

	// 生成总控侧不可逆验证凭据。节点兼容的 scrypt 材料由后续账号供应协议产生，
	// 总控不保存可逆明文密码。
	pwHash, err := crypto.HashPassword(req.Password)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "密码哈希失败")
		return
	}
	// 代注册到节点
	provReq := &protocol.ProvisionUserRequest{
		Handle:         handle,
		Name:           displayName,
		Password:       req.Password, // 节点密码 = 用户密码
		InvitationCode: req.InvitationCode,
	}
	if _, err := s.agent.provisionUser(ctx, node.ID, node.AgentPSK, node.AgentURL, provReq); err != nil {
		protocol.WriteError(w, http.StatusBadGateway, "在节点上创建账号失败: "+err.Error())
		return
	}

	// 总控建用户
	user := &store.User{
		Username:     handle,
		DisplayName:  displayName,
		PasswordHash: sql.NullString{String: pwHash, Valid: true},
		AuthProvider: "password",
		HomeNodeID:   sql.NullInt64{Int64: node.ID, Valid: true},
		Status:       "active",
	}
	if err := s.Store.CreateUser(ctx, user); err != nil {
		protocol.WriteError(w, http.StatusConflict, "创建用户失败（用户名可能已被占用）")
		return
	}

	// 绑定家节点副本
	_ = s.Store.UpsertReplica(ctx, &store.UserReplica{
		UserID: user.ID, NodeID: node.ID, Kind: "home", DataVersion: 0, State: "ready",
	})

	_ = s.Store.Audit(ctx, handle, "register", node.Name, nil)

	// 自动登录
	if err := s.createUserSession(w, r, user); err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "创建会话失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "username": handle, "display_name": displayName,
	})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleLogin 账号密码登录。
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	ctx := r.Context()
	handle := NormalizeHandle(req.Username)

	user, err := s.Store.GetUserByUsername(ctx, handle)
	if err != nil || user == nil {
		protocol.WriteError(w, http.StatusForbidden, "用户名或密码错误")
		return
	}
	if user.Status != "active" {
		protocol.WriteError(w, http.StatusForbidden, "账号已被禁用")
		return
	}
	if !user.PasswordHash.Valid || !crypto.CheckPassword(user.PasswordHash.String, req.Password) {
		protocol.WriteError(w, http.StatusForbidden, "用户名或密码错误")
		return
	}

	if err := s.createUserSession(w, r, user); err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "创建会话失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "username": user.Username, "display_name": user.DisplayName,
	})
}

// handleLogout 登出。
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.destroySession(w, r); err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "注销会话失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
