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
	if len(req.NewPassword) < 6 {
		protocol.WriteError(w, http.StatusBadRequest, "新密码至少 6 位")
		return
	}
	ctx := r.Context()
	userID, _ := CurrentUser(r)
	user, err := s.Store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		protocol.WriteError(w, http.StatusUnauthorized, "用户不存在")
		return
	}
	if user.AuthProvider != "password" {
		protocol.WriteError(w, http.StatusBadRequest, "OAuth 账号无需设置密码")
		return
	}
	// 校验旧密码
	if user.PasswordHash.Valid && !crypto.CheckPassword(user.PasswordHash.String, req.OldPassword) {
		protocol.WriteError(w, http.StatusForbidden, "原密码错误")
		return
	}

	// Update the authoritative verifier first. Managed nodes reject their native
	// password route, so a lagging node copy cannot become an alternate login.
	pwHash, err := crypto.HashPassword(req.NewPassword)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "密码哈希失败")
		return
	}
	if err := s.Store.UpdateUserPassword(ctx, userID, pwHash); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "更新密码失败")
		return
	}
	nodePasswordHash, nodePasswordSalt, err := crypto.SillyTavernPasswordMaterial(req.NewPassword)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "密码材料生成失败")
		return
	}
	if user.HomeNodeID.Valid {
		node, err := s.Store.GetNodeByID(ctx, user.HomeNodeID.Int64)
		if err == nil && node != nil && node.Status == "online" {
			version, err := s.Store.SetNodeAccountProvisioning(
				ctx, user.GlobalID, node.ID, nodePasswordHash, nodePasswordSalt, "", "", time.Now().UTC(),
			)
			if err != nil {
				protocol.WriteError(w, http.StatusInternalServerError, "记录节点密码版本失败")
				return
			}
			if _, err := s.runAgentCommand(ctx, node, "set_password", protocol.SetPasswordRequest{
				Handle: user.Username, PasswordHash: nodePasswordHash, PasswordSalt: nodePasswordSalt, Version: version,
			}, 45*time.Second); err != nil {
				_ = s.Store.MarkNodeAccountError(ctx, user.GlobalID, node.ID, time.Now().UTC())
				protocol.WriteError(w, http.StatusServiceUnavailable, "密码已更新，节点同步待重试")
				return
			}
			if err := s.Store.ActivateNodeAccount(ctx, user.ID, user.GlobalID, node.ID, "", time.Now().UTC()); err != nil {
				protocol.WriteError(w, http.StatusInternalServerError, "节点密码状态更新失败")
				return
			}
		}
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
