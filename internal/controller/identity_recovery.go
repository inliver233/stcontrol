package controller

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

type identityRecoveryDigestInput struct {
	OperationID string `json:"operation_id"`
	UserUUID    string `json:"user_uuid"`
	AdminID     int64  `json:"admin_id"`
	Password    string `json:"password"`
}

func (s *Server) handleAdminRecoverUserIdentity(w http.ResponseWriter, r *http.Request) {
	setHandoffNoStoreHeaders(w)
	sess := currentSession(r)
	if sess == nil || !sess.IsAdmin || sess.AdminID <= 0 {
		protocol.WriteError(w, http.StatusForbidden, "需要管理员权限")
		return
	}
	userUUID := strings.ToLower(chi.URLParam(r, "uuid"))
	var req struct {
		OperationID string `json:"operation_id"`
		Password    string `json:"password"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || !isUUID(userUUID) || !isUUID(req.OperationID) {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if len(req.Password) < 8 || len([]byte(req.Password)) > 72 {
		protocol.WriteError(w, http.StatusBadRequest, "新密码须为 8 至 72 字节")
		return
	}
	requestDigest, err := s.identityRecoveryRequestDigest(identityRecoveryDigestInput{
		OperationID: req.OperationID, UserUUID: userUUID,
		AdminID: sess.AdminID, Password: req.Password,
	})
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "恢复请求摘要生成失败")
		return
	}
	passwordHash, err := controlcrypto.HashPassword(req.Password)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "密码哈希失败")
		return
	}
	nodeHash, nodeSalt, err := controlcrypto.SillyTavernPasswordMaterial(req.Password)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "密码材料生成失败")
		return
	}

	s.passwordSyncMu.Lock()
	defer s.passwordSyncMu.Unlock()
	result, err := s.Store.RecoverUserPasswordIdentity(
		r.Context(), store.RecoverUserPasswordIdentityParams{
			OperationID: req.OperationID, UserUUID: userUUID, AdminID: sess.AdminID,
			RequestDigest: requestDigest, PasswordHash: passwordHash,
			NodePasswordHash: nodeHash, NodePasswordSalt: nodeSalt, Now: time.Now().UTC(),
		},
	)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrIdentityRecoveryConflict), errors.Is(err, store.ErrIdentityConflict):
			protocol.WriteError(w, http.StatusConflict, "重复操作与已保存的恢复请求不一致")
		case errors.Is(err, store.ErrInvalidIdentityRecovery):
			protocol.WriteError(w, http.StatusNotFound, "全局用户不存在或当前状态不可恢复")
		case errors.Is(err, store.ErrNoActiveController):
			protocol.WriteError(w, http.StatusServiceUnavailable, "当前没有可写主控，请稍后使用同一操作重试")
		default:
			protocol.WriteError(w, http.StatusServiceUnavailable, "身份恢复暂不可用，请使用同一操作重试")
		}
		return
	}

	pending := result.StagedNodeCount
	synced := 0
	if result.UserStatus == "active" {
		syncs, listErr := s.Store.ListPendingPasswordSyncsForUser(r.Context(), result.GlobalUserID)
		if listErr != nil {
			protocol.WriteError(w, http.StatusServiceUnavailable, "恢复已安全保存；节点同步状态暂不可用，请使用同一操作重试")
			return
		}
		synced, pending = s.deliverPasswordSyncs(r.Context(), syncs)
	}
	status := http.StatusOK
	nodeSync := "active"
	if pending > 0 {
		status = http.StatusAccepted
		nodeSync = "pending"
	}
	protocol.WriteJSON(w, status, map[string]any{
		"ok": true, "identity_recovered": true, "sessions_revoked": true,
		"user_uuid": result.UserUUID, "username": result.Username,
		"user_status": result.UserStatus, "password_version": result.PasswordVersion,
		"node_sync": nodeSync, "synced_nodes": synced, "pending_nodes": pending,
		"staged_nodes": result.StagedNodeCount, "replayed": result.Replayed,
	})
}

func (s *Server) identityRecoveryRequestDigest(value identityRecoveryDigestInput) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.secretKey)
	_, _ = mac.Write([]byte("stcontrol-identity-recovery-request:v1\n"))
	_, _ = mac.Write(encoded)
	return mac.Sum(nil), nil
}
