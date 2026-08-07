package controller

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if !s.validMutationOrigin(r) {
		protocol.WriteError(w, http.StatusForbidden, "请求来源无效")
		return
	}
	var req loginRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	username := strings.ToLower(strings.TrimSpace(req.Username))
	admin, err := s.Store.GetAdminByUsername(r.Context(), username)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "管理员认证暂不可用")
		return
	}
	passwordHash := s.dummyPasswordHash
	if admin != nil {
		passwordHash = admin.PasswordHash
	}
	passwordValid := crypto.CheckPassword(passwordHash, req.Password)
	if admin == nil || admin.Status != "active" || !passwordValid {
		protocol.WriteError(w, http.StatusForbidden, "用户名或密码错误")
		return
	}
	if err := s.Store.RecordAdminLogin(r.Context(), admin.ID, time.Now().UTC()); err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "管理员认证暂不可用")
		return
	}
	if err := s.createAdminSession(w, r, admin); err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "创建会话失败")
		return
	}
	_ = s.Store.Audit(r.Context(), admin.Username, "admin-login", "controller", nil)
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "username": admin.Username, "is_admin": true})
}

func (s *Server) handleAdminListAdmins(w http.ResponseWriter, r *http.Request) {
	admins, err := s.Store.ListAdmins(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "查询管理员失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"admins": admins})
}

func (s *Server) handleAdminCreateAdmin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || len(req.Password) < 12 {
		protocol.WriteError(w, http.StatusBadRequest, "管理员用户名无效或密码少于 12 位")
		return
	}
	username := strings.ToLower(strings.TrimSpace(req.Username))
	passwordHash, err := crypto.HashPassword(req.Password)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "密码哈希失败")
		return
	}
	sess := currentSession(r)
	if sess == nil || sess.AdminID <= 0 {
		protocol.WriteError(w, http.StatusForbidden, "需要管理员权限")
		return
	}
	admin, err := s.Store.CreateAdmin(r.Context(), username, passwordHash, sess.AdminID, time.Now().UTC())
	if err != nil {
		protocol.WriteError(w, http.StatusConflict, "管理员用户名已存在或创建者无效")
		return
	}
	_ = s.Store.Audit(r.Context(), sess.Username, "admin-create", admin.Username, nil)
	protocol.WriteJSON(w, http.StatusCreated, admin)
}

func (s *Server) handleAdminSetAdminStatus(w http.ResponseWriter, r *http.Request) {
	adminID, err := parseID(chi.URLParam(r, "id"))
	var req struct {
		Status string `json:"status"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&req) != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.Store.SetAdminStatus(r.Context(), adminID, req.Status, time.Now().UTC()); err != nil {
		if errors.Is(err, store.ErrLastAdmin) {
			protocol.WriteError(w, http.StatusConflict, "不能禁用最后一名有效管理员")
			return
		}
		protocol.WriteError(w, http.StatusBadRequest, "管理员状态更新失败")
		return
	}
	sess := currentSession(r)
	_ = s.Store.Audit(r.Context(), sess.Username, "admin-status", chi.URLParam(r, "id"), nil)
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAdminResetPassword(w http.ResponseWriter, r *http.Request) {
	adminID, err := parseID(chi.URLParam(r, "id"))
	var req struct {
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&req) != nil || len(req.Password) < 12 {
		protocol.WriteError(w, http.StatusBadRequest, "新密码至少 12 位")
		return
	}
	passwordHash, err := crypto.HashPassword(req.Password)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "密码哈希失败")
		return
	}
	if err := s.Store.ResetAdminPassword(r.Context(), adminID, passwordHash, time.Now().UTC()); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "管理员密码重置失败")
		return
	}
	sess := currentSession(r)
	_ = s.Store.Audit(r.Context(), sess.Username, "admin-password-reset", chi.URLParam(r, "id"), nil)
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
