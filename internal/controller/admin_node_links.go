package controller

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

type verifyAdminNodeLinkRequest struct {
	OperationID string `json:"operation_id"`
	Handle      string `json:"handle"`
	Password    string `json:"password"`
}

type createAdminHandoffRequest struct {
	OperationID string `json:"operation_id"`
}

type adminHandoffResponse struct {
	OK           bool      `json:"ok"`
	PostURL      string    `json:"post_url"`
	FieldName    string    `json:"field_name"`
	Code         string    `json:"code"`
	ExpiresAt    time.Time `json:"expires_at"`
	TargetNodeID int64     `json:"target_node_id"`
}

func (s *Server) handleAdminNodeLinks(w http.ResponseWriter, r *http.Request) {
	sess := currentSession(r)
	if sess == nil || sess.AdminID <= 0 {
		protocol.WriteError(w, http.StatusForbidden, "需要管理员权限")
		return
	}
	links, err := s.Store.ListAdminNodeLinks(r.Context(), sess.AdminID)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "节点管理员关联暂不可用")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"links": links})
}

func (s *Server) handleVerifyAdminNodeLink(w http.ResponseWriter, r *http.Request) {
	nodeID, err := parseID(chi.URLParam(r, "id"))
	var req verifyAdminNodeLinkRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&req) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		!isUUID(req.OperationID) || !validAdminLocalHandle(req.Handle) ||
		len(req.Password) == 0 || len(req.Password) > 256 {
		protocol.WriteError(w, http.StatusBadRequest, "请输入有效的节点管理员账号和密码")
		return
	}
	sess := currentSession(r)
	if sess == nil || sess.AdminID <= 0 {
		protocol.WriteError(w, http.StatusForbidden, "需要管理员权限")
		return
	}
	node, err := s.Store.GetNodeByID(r.Context(), nodeID)
	if err != nil || node == nil || node.Role != "compute" || !nodeReadyForManagedOperation(node) {
		protocol.WriteError(w, http.StatusConflict, "节点当前不可验证管理员账号")
		return
	}
	digest, err := s.adminNodeVerificationDigest(sess.AdminID, nodeID, req.Handle, req.Password)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成验证请求失败")
		return
	}
	result, err := s.runAgentCommandWithOperation(r.Context(), node, "verify_node_admin",
		protocol.VerifyNodeAdminRequest{OperationID: req.OperationID, Handle: req.Handle, Password: req.Password},
		req.OperationID, 90*time.Second)
	if err != nil || result.NodeAdmin == nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "节点管理员验证暂不可用")
		return
	}
	verification := result.NodeAdmin
	validResult := verification.Handle == req.Handle && validAdminLocalHandle(verification.Handle) &&
		(!verification.IsAdmin || (validAdminLocalUserID(verification.LocalUserID) && verification.PermissionVersion > 0))
	if !validResult {
		protocol.WriteError(w, http.StatusServiceUnavailable, "节点返回了无效的管理员验证结果")
		return
	}
	link, err := s.Store.CompleteAdminNodeVerification(r.Context(), store.CompleteAdminNodeVerificationParams{
		OperationID: req.OperationID, RequestDigest: digest, AdminID: sess.AdminID,
		NodeID: nodeID, LocalHandle: req.Handle, LocalUserID: verification.LocalUserID,
		IsAdmin: verification.IsAdmin, PermissionVersion: verification.PermissionVersion,
		Now: time.Now().UTC(),
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrAdminNodeLinkRejected):
			protocol.WriteError(w, http.StatusForbidden, "账号密码错误，或该账号已不是节点管理员")
		case errors.Is(err, store.ErrAdminNodeLinkConflict):
			protocol.WriteError(w, http.StatusConflict, "重复验证操作与原请求不一致")
		default:
			protocol.WriteError(w, http.StatusConflict, "节点管理员关联保存失败")
		}
		return
	}
	protocol.WriteJSON(w, http.StatusOK, link)
}

func (s *Server) handleRevokeAdminNodeLink(w http.ResponseWriter, r *http.Request) {
	nodeID, err := parseID(chi.URLParam(r, "id"))
	sess := currentSession(r)
	if err != nil || sess == nil || sess.AdminID <= 0 {
		protocol.WriteError(w, http.StatusBadRequest, "节点或管理员身份无效")
		return
	}
	if err := s.Store.RevokeAdminNodeLink(r.Context(), sess.AdminID, nodeID, time.Now().UTC()); err != nil {
		protocol.WriteError(w, http.StatusConflict, "节点管理员关联已失效或不存在")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleCreateAdminHandoff(w http.ResponseWriter, r *http.Request) {
	setHandoffNoStoreHeaders(w)
	nodeID, err := parseID(chi.URLParam(r, "id"))
	var req createAdminHandoffRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&req) != nil || decoder.Decode(&struct{}{}) != io.EOF || !isUUID(req.OperationID) {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	sess := currentSession(r)
	if sess == nil || sess.AdminID <= 0 {
		protocol.WriteError(w, http.StatusForbidden, "需要管理员权限")
		return
	}
	link, err := s.Store.GetVerifiedAdminNodeLink(r.Context(), sess.AdminID, nodeID)
	if err != nil || link == nil || link.ValidateForHandoff() != nil {
		protocol.WriteError(w, http.StatusForbidden, "请先验证该节点的原生管理员账号")
		return
	}
	node, err := s.Store.GetNodeByID(r.Context(), nodeID)
	if err != nil || node == nil || node.Role != "compute" || !nodeReadyForManagedOperation(node) {
		protocol.WriteError(w, http.StatusConflict, "节点当前不可进入原生后台")
		return
	}
	result, err := s.runAgentCommandWithOperation(r.Context(), node, "check_node_admin",
		protocol.CheckNodeAdminRequest{Handle: link.LocalHandle},
		deriveWorkflowOperationID(req.OperationID, "recheck-node-admin"), 45*time.Second)
	if err != nil || result.NodeAdmin == nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "节点管理员权限复核暂不可用")
		return
	}
	verification := result.NodeAdmin
	if !verification.IsAdmin || verification.Handle != link.LocalHandle ||
		!validAdminLocalUserID(verification.LocalUserID) || verification.PermissionVersion <= 0 {
		_ = s.Store.MarkAdminNodeLinkStale(r.Context(), sess.AdminID, nodeID, "permission_revoked", time.Now().UTC())
		protocol.WriteError(w, http.StatusForbidden, "该节点账号已不是管理员，请重新验证")
		return
	}
	if err := s.Store.ConfirmAdminNodeLink(r.Context(), sess.AdminID, nodeID,
		verification.LocalUserID, verification.PermissionVersion, time.Now().UTC()); err != nil {
		protocol.WriteError(w, http.StatusConflict, "节点管理员关联已变化，请重新验证")
		return
	}
	jti, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "安全随机数生成失败")
		return
	}
	secret := deriveAdminHandoffSecret(s.secretKey, jti)
	secretHash := sha256.Sum256(secret)
	issuer := strings.TrimRight(s.Cfg.PublicURL, "/")
	handoff, err := s.Store.CreateAdminHandoff(r.Context(), store.CreateAdminHandoffParams{
		OperationID: req.OperationID, JTI: jti, SecretHash: secretHash[:],
		AdminID: sess.AdminID, NodeID: nodeID, Issuer: issuer, KeyID: handoffKeyID,
		TicketTTL: time.Minute, Now: time.Now().UTC(),
	})
	if err != nil {
		protocol.WriteError(w, http.StatusConflict, "节点管理员跳转票据创建失败")
		return
	}
	secret = deriveAdminHandoffSecret(s.secretKey, handoff.JTI)
	code := handoff.JTI + "." + base64.RawURLEncoding.EncodeToString(secret)
	protocol.WriteJSON(w, http.StatusOK, adminHandoffResponse{
		OK: true, PostURL: strings.TrimRight(handoff.NodeBaseURL, "/") + "/api/users/me?stcontrol_handoff=admin",
		FieldName: loginHandoffField, Code: code, ExpiresAt: handoff.ExpiresAt, TargetNodeID: nodeID,
	})
}

func (s *Server) handleAdminTicketRedeem(w http.ResponseWriter, r *http.Request) {
	setHandoffNoStoreHeaders(w)
	node := currentNode(r)
	if node == nil {
		protocol.WriteError(w, http.StatusUnauthorized, "节点认证失败")
		return
	}
	var req redeemLoginHandoffRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		strings.TrimSpace(req.Code) == "" {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	jti, suppliedSecret, ok := parseLoginHandoffCode(req.Code)
	if !ok || !hmac.Equal(suppliedSecret, deriveAdminHandoffSecret(s.secretKey, jti)) {
		protocol.WriteError(w, http.StatusForbidden, "管理员跳转短码无效、已使用或已过期")
		return
	}
	secretHash := sha256.Sum256(suppliedSecret)
	redemption, consumed, err := s.Store.ConsumeAdminHandoff(
		r.Context(), jti, secretHash[:], node.ID,
		strings.TrimRight(s.Cfg.PublicURL, "/"), handoffKeyID, time.Now().UTC(),
	)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "管理员跳转短码核销失败")
		return
	}
	if !consumed {
		protocol.WriteError(w, http.StatusForbidden, "管理员跳转短码无效、已使用或已过期")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "admin_id": redemption.AdminID, "handle": redemption.LocalHandle,
		"permission_version":    redemption.PermissionVersion,
		"controller_generation": redemption.ControllerGeneration,
	})
}

func (s *Server) adminNodeVerificationDigest(adminID, nodeID int64, handle, password string) ([]byte, error) {
	encoded, err := json.Marshal(struct {
		AdminID  int64  `json:"admin_id"`
		NodeID   int64  `json:"node_id"`
		Handle   string `json:"handle"`
		Password string `json:"password"`
	}{adminID, nodeID, handle, password})
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.secretKey)
	_, _ = mac.Write([]byte("stcontrol-admin-node-verification:v1\n"))
	_, _ = mac.Write(encoded)
	return mac.Sum(nil), nil
}

func deriveAdminHandoffSecret(key []byte, jti string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("stcontrol-admin-handoff:v1:" + jti))
	return mac.Sum(nil)
}

func validAdminLocalHandle(value string) bool {
	return validSafeAdminString(value, 128)
}

func validAdminLocalUserID(value string) bool {
	return validSafeAdminString(value, 256)
}

func validSafeAdminString(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}
