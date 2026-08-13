package controller

import (
	"encoding/json"
	"net/http"

	"stcontrol/internal/protocol"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleLogin 账号密码登录。
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.validMutationOrigin(r) {
		protocol.WriteError(w, http.StatusForbidden, "请求来源无效")
		return
	}
	if !s.requireNewOperations(w) {
		return
	}
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	ctx := r.Context()
	handle := NormalizeHandle(req.Username)

	user, err := s.Store.GetUserByUsername(ctx, handle)
	if err != nil || user == nil {
		if s.loginLockout != nil {
			s.loginLockout.recordFailure(handle)
		}
		protocol.WriteError(w, http.StatusForbidden, "用户名或密码错误")
		return
	}
	if user.Status != "active" && user.Status != "conflict" {
		protocol.WriteError(w, http.StatusForbidden, "账号已被禁用")
		return
	}
	if !s.passwordMatches(r.Context(), user, req.Password) {
		if s.loginLockout != nil {
			s.loginLockout.recordFailure(handle)
		}
		protocol.WriteError(w, http.StatusForbidden, "用户名或密码错误")
		return
	}

	if s.loginLockout != nil {
		s.loginLockout.recordSuccess(handle)
	}
	if err := s.createUserSession(w, r, user); err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "创建会话失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "username": user.Username, "display_name": user.DisplayName,
		"recovery_required": user.Status == "conflict",
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
