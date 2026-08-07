package controller

import (
	"encoding/json"
	"net/http"
	"time"

	"stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

// handleMe 当前用户信息。
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if sess := currentSession(r); sess != nil && sess.IsAdmin {
		protocol.WriteJSON(w, http.StatusOK, map[string]any{
			"username": sess.Username, "display_name": sess.Username,
			"auth_provider": "admin", "avatar_url": "", "home_node_id": 0,
			"is_admin": true,
		})
		return
	}
	userID, _ := CurrentUser(r)
	user, err := s.Store.GetUserByID(r.Context(), userID)
	if err != nil || user == nil {
		protocol.WriteError(w, http.StatusUnauthorized, "用户不存在")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"username":      user.Username,
		"display_name":  user.DisplayName,
		"auth_provider": user.AuthProvider,
		"avatar_url":    user.AvatarURL.String,
		"home_node_id":  user.HomeNodeID.Int64,
		"is_admin":      false,
	})
}

// handleChangePassword 修改密码（同步到节点）。
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if len(req.NewPassword) < 8 {
		protocol.WriteError(w, http.StatusBadRequest, "新密码至少 8 位")
		return
	}
	ctx := r.Context()
	userID, _ := CurrentUser(r)
	user, err := s.Store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		protocol.WriteError(w, http.StatusUnauthorized, "用户不存在")
		return
	}
	if !user.PasswordHash.Valid {
		protocol.WriteError(w, http.StatusBadRequest, "请先绑定密码登录方式")
		return
	}
	// 校验旧密码
	if user.PasswordHash.Valid && !crypto.CheckPassword(user.PasswordHash.String, req.OldPassword) {
		protocol.WriteError(w, http.StatusForbidden, "原密码错误")
		return
	}

	// Commit the authoritative verifier and all node-local desired material in one
	// transaction before delivery. A crash can therefore be reconciled from facts.
	pwHash, err := crypto.HashPassword(req.NewPassword)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "密码哈希失败")
		return
	}
	nodePasswordHash, nodePasswordSalt, err := crypto.SillyTavernPasswordMaterial(req.NewPassword)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "密码材料生成失败")
		return
	}
	s.passwordSyncMu.Lock()
	defer s.passwordSyncMu.Unlock()
	now := time.Now().UTC()
	if err := s.Store.UpdateUserPassword(
		ctx, userID, pwHash, nodePasswordHash, nodePasswordSalt, now,
	); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "更新密码失败")
		return
	}
	synced, pending, syncErr := s.synchronizePasswordToNodes(ctx, user, nodePasswordHash, nodePasswordSalt)
	if syncErr != nil || pending > 0 {
		protocol.WriteJSON(w, http.StatusAccepted, map[string]any{
			"ok": true, "node_sync": "pending", "synced_nodes": synced, "pending_nodes": pending,
		})
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "node_sync": "active", "synced_nodes": synced, "pending_nodes": 0,
	})
}
