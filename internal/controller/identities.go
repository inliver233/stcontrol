package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func (s *Server) handleListIdentities(w http.ResponseWriter, r *http.Request) {
	sess := currentSession(r)
	if sess == nil || sess.IsAdmin || sess.GlobalUserID <= 0 {
		protocol.WriteError(w, http.StatusForbidden, "用户身份不可用")
		return
	}
	identities, err := s.Store.ListUserIdentities(r.Context(), sess.GlobalUserID)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "查询登录方式失败")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"identities": identities, "can_unbind": len(identities) > 1,
		"supported": []string{"password", "discord", "linuxdo"},
	})
}

func (s *Server) handleBeginOAuthIdentityBinding(w http.ResponseWriter, r *http.Request) {
	sess := currentSession(r)
	provider := chi.URLParam(r, "provider")
	cfg, enabled := s.oauthProviderConfig(provider)
	if sess == nil || sess.IsAdmin || sess.GlobalUserID <= 0 || !enabled {
		protocol.WriteError(w, http.StatusBadRequest, "该登录方式不可绑定")
		return
	}
	identities, err := s.Store.ListUserIdentities(r.Context(), sess.GlobalUserID)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "查询登录方式失败")
		return
	}
	for _, identity := range identities {
		if identity.Provider == provider {
			protocol.WriteError(w, http.StatusConflict, "该登录方式已绑定")
			return
		}
	}
	if len(identities) >= 3 {
		protocol.WriteError(w, http.StatusConflict, "已达到三种登录方式上限")
		return
	}
	state, err := randomBearerToken()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "OAuth 状态生成失败")
		return
	}
	stateHash := sha256.Sum256([]byte(state))
	now := time.Now().UTC()
	if err := s.Store.CreateOAuthBindingState(
		r.Context(), stateHash[:], provider, sess.GlobalUserID, sess.ID, now.Add(oauthStateTTL), now,
	); err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "OAuth 绑定状态保存失败")
		return
	}
	authURL, err := oauthAuthorizationURL(provider, cfg, state)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "OAuth 配置无效")
		return
	}
	setHandoffNoStoreHeaders(w)
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"authorization_url": authURL, "expires_at": now.Add(oauthStateTTL)})
}

func (s *Server) handleBindPasswordIdentity(w http.ResponseWriter, r *http.Request) {
	sess := currentSession(r)
	if sess == nil || sess.IsAdmin || sess.UserID <= 0 || sess.GlobalUserID <= 0 {
		protocol.WriteError(w, http.StatusForbidden, "用户身份不可用")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || len(req.Password) < 8 {
		protocol.WriteError(w, http.StatusBadRequest, "密码至少 8 位")
		return
	}
	passwordHash, err := crypto.HashPassword(req.Password)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "密码哈希失败")
		return
	}
	nodeHash, nodeSalt, err := crypto.SillyTavernPasswordMaterial(req.Password)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "密码材料生成失败")
		return
	}
	now := time.Now().UTC()
	s.passwordSyncMu.Lock()
	defer s.passwordSyncMu.Unlock()
	if err := s.Store.BindPasswordIdentity(
		r.Context(), sess.UserID, sess.GlobalUserID, passwordHash, nodeHash, nodeSalt, now,
	); err != nil {
		if errors.Is(err, store.ErrIdentityConflict) {
			protocol.WriteError(w, http.StatusConflict, "密码登录方式已绑定")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, "绑定密码登录失败")
		return
	}
	_ = s.Store.Audit(r.Context(), sess.Username, "identity-bind", "password", nil)

	user := &store.User{ID: sess.UserID, GlobalID: sess.GlobalUserID, Username: sess.Username}
	synced, pending, syncErr := s.synchronizePasswordToNodes(r.Context(), user, nodeHash, nodeSalt)
	if syncErr != nil || pending > 0 {
		protocol.WriteJSON(w, http.StatusAccepted, map[string]any{
			"ok": true, "node_sync": "pending", "synced_nodes": synced, "pending_nodes": pending,
		})
		return
	}
	protocol.WriteJSON(w, http.StatusCreated, map[string]any{
		"ok": true, "node_sync": "active", "synced_nodes": synced, "pending_nodes": 0,
	})
}

func (s *Server) synchronizePasswordToNodes(
	ctx context.Context,
	user *store.User,
	passwordHash, passwordSalt string,
) (synced, pending int, err error) {
	accounts, err := s.Store.ListUserNodeAccounts(ctx, user.GlobalID)
	if err != nil {
		return 0, 0, err
	}
	for _, account := range accounts {
		node, nodeErr := s.Store.GetNodeByID(ctx, account.NodeID)
		if nodeErr != nil || node == nil || !nodeReadyForManagedOperation(node) {
			pending++
			continue
		}
		if _, commandErr := s.runAgentCommand(ctx, node, "set_password", protocol.SetPasswordRequest{
			Handle: account.LocalHandle, PasswordHash: passwordHash, PasswordSalt: passwordSalt,
			Version: account.PasswordMaterialVersion,
		}, 45*time.Second); commandErr != nil {
			_ = s.Store.MarkNodeAccountError(ctx, user.GlobalID, node.ID, time.Now().UTC())
			pending++
			continue
		}
		if activateErr := s.Store.ActivateNodeAccount(ctx, user.ID, user.GlobalID, node.ID, "", time.Now().UTC()); activateErr != nil {
			pending++
			continue
		}
		synced++
	}
	return synced, pending, nil
}

func (s *Server) handleUnbindIdentity(w http.ResponseWriter, r *http.Request) {
	sess := currentSession(r)
	provider := chi.URLParam(r, "provider")
	if sess == nil || sess.IsAdmin || sess.UserID <= 0 || sess.GlobalUserID <= 0 {
		protocol.WriteError(w, http.StatusForbidden, "用户身份不可用")
		return
	}
	if err := s.Store.UnbindUserIdentity(
		r.Context(), sess.UserID, sess.GlobalUserID, provider, time.Now().UTC(),
	); err != nil {
		switch {
		case errors.Is(err, store.ErrLastIdentity):
			protocol.WriteError(w, http.StatusConflict, "至少保留一种登录方式")
		case errors.Is(err, store.ErrInvalidIdentity):
			protocol.WriteError(w, http.StatusBadRequest, "登录方式不存在")
		default:
			protocol.WriteError(w, http.StatusInternalServerError, "解绑登录方式失败")
		}
		return
	}
	_ = s.Store.Audit(r.Context(), sess.Username, "identity-unbind", provider, nil)
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
