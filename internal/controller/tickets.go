package controller

import (
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const (
	loginHandoffField = "stcontrol_code"
	activityLeaseTTL  = 15 * time.Minute
	handoffKeyID      = "controller-master-v1"
)

type loginHandoffRequest struct {
	NodeID      int64  `json:"node_id"`
	OperationID string `json:"operation_id"`
}

type loginHandoffResponse struct {
	OK             bool      `json:"ok"`
	PostURL        string    `json:"post_url"`
	FieldName      string    `json:"field_name"`
	Code           string    `json:"code"`
	ExpiresAt      time.Time `json:"expires_at"`
	TargetNodeID   int64     `json:"target_node_id"`
	ExistingWriter bool      `json:"existing_writer"`
}

// handleLoginRedirect preserves the legacy API path while implementing the
// confirmed protocol: an opaque, one-use code returned to the browser and sent
// to the selected node in a POST body. No credential is placed in a URL.
func (s *Server) handleLoginRedirect(w http.ResponseWriter, r *http.Request) {
	setHandoffNoStoreHeaders(w)
	if !s.requireNewOperations(w) {
		return
	}
	var req loginHandoffRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || !isUUID(req.OperationID) || req.NodeID <= 0 {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	ctx := r.Context()
	legacyUserID, _ := CurrentUser(r)
	user, err := s.Store.GetUserByID(ctx, legacyUserID)
	if err != nil || user == nil || user.GlobalID <= 0 || user.Status != "active" {
		protocol.WriteError(w, http.StatusUnauthorized, "用户不存在或不可用")
		return
	}
	node, err := s.Store.GetNodeByID(ctx, req.NodeID)
	if err != nil || node == nil {
		protocol.WriteError(w, http.StatusBadRequest, "节点不存在")
		return
	}

	// The legacy replica table remains the compatibility read model until the
	// snapshot workflow cut-over. It authorizes which node the user may request.
	replica, err := s.Store.GetReplica(ctx, legacyUserID, node.ID)
	if err != nil || replica == nil {
		protocol.WriteError(w, http.StatusForbidden, "该节点不是你的可用节点")
		return
	}
	if replica.Kind == "archive" {
		protocol.WriteError(w, http.StatusForbidden, "存储节点不可登录")
		return
	}
	if !replicaIsCurrentHome(user, node, replica) {
		protocol.WriteError(w, http.StatusConflict, "备用节点必须先确认接管风险")
		return
	}
	if !nodeReadyForManagedOperation(node) {
		protocol.WriteError(w, http.StatusConflict, "该节点当前离线")
		return
	}
	// Backup mutation must stop before a writer lease is handed to the browser.
	// The abort is delivered over the Agent-initiated command channel.
	if s.Cfg.Backup.AbortOnLogin {
		if job, _ := s.Store.FindRunningBackupForUserOnNode(ctx, legacyUserID, node.ID); job != nil {
			if _, err := s.runAgentCommand(ctx, node, "abort_backup", map[string]int64{"job_id": job.ID}, 15*time.Second); err != nil {
				protocol.WriteError(w, http.StatusConflict, "节点正在结束备份，请稍后重试")
				return
			}
			if err := s.Store.UpdateBackupJobStatus(ctx, job.ID, "aborted", 0, 0, 0, "用户登录,中止备份"); err != nil {
				protocol.WriteError(w, http.StatusInternalServerError, "备份状态更新失败")
				return
			}
		}
	}

	jti, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "安全随机数生成失败")
		return
	}
	sessionID, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "安全随机数生成失败")
		return
	}
	secret := deriveLoginHandoffSecret(s.secretKey, jti)
	secretHash := sha256.Sum256(secret)
	ticketTTL := time.Duration(s.Cfg.Ticket.TTLSec) * time.Second
	if ticketTTL <= 0 {
		ticketTTL = time.Minute
	}
	issuer := strings.TrimRight(s.Cfg.PublicURL, "/")

	handoff, err := s.Store.CreateLoginHandoff(ctx, store.CreateLoginHandoffParams{
		OperationID:     req.OperationID,
		JTI:             jti,
		SecretHash:      secretHash[:],
		UserID:          user.GlobalID,
		RequestedNodeID: node.ID,
		SessionID:       sessionID,
		Issuer:          issuer,
		Subject:         user.Username,
		KeyID:           handoffKeyID,
		TicketTTL:       ticketTTL,
		LeaseTTL:        activityLeaseTTL,
		Now:             time.Now().UTC(),
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrLoginHandoffUnavailable), errors.Is(err, store.ErrStaleControllerLease):
			protocol.WriteError(w, http.StatusConflict, "当前活动会话暂不可交接")
		case errors.Is(err, store.ErrNoActiveController):
			protocol.WriteError(w, http.StatusServiceUnavailable, "总控当前为只读状态")
		default:
			protocol.WriteError(w, http.StatusInternalServerError, "登录交接创建失败")
		}
		return
	}

	// On an idempotent retry the store returns the original JTI. Re-derivation
	// reproduces the same code without ever storing its bearer secret.
	secret = deriveLoginHandoffSecret(s.secretKey, handoff.JTI)
	code := handoff.JTI + "." + base64.RawURLEncoding.EncodeToString(secret)
	// SillyTavern's existing anonymous CSRF exemption is limited to
	// /api/users/me. The kind is non-secret; the opaque one-use credential
	// remains only in the POST body.
	postURL := strings.TrimRight(handoff.NodeBaseURL, "/") + "/api/users/me?stcontrol_handoff=user"
	protocol.WriteJSON(w, http.StatusOK, loginHandoffResponse{
		OK:             true,
		PostURL:        postURL,
		FieldName:      loginHandoffField,
		Code:           code,
		ExpiresAt:      handoff.ExpiresAt,
		TargetNodeID:   handoff.TargetNodeID,
		ExistingWriter: handoff.Existing,
	})
}

func replicaIsCurrentHome(user *store.User, node *store.Node, replica *store.UserReplica) bool {
	return user != nil && node != nil && replica != nil && user.HomeNodeID.Valid &&
		user.HomeNodeID.Int64 == node.ID && replica.NodeID == node.ID &&
		replica.Kind == "home" && replica.State == "ready"
}

type redeemLoginHandoffRequest struct {
	Code string `json:"code"`
}

// handleTicketRedeem is reachable only behind agentAuthMiddleware. The node
// identity comes from the authenticated context and is never trusted from JSON.
func (s *Server) handleTicketRedeem(w http.ResponseWriter, r *http.Request) {
	setHandoffNoStoreHeaders(w)
	node := currentNode(r)
	if node == nil {
		protocol.WriteError(w, http.StatusUnauthorized, "节点认证失败")
		return
	}
	var req redeemLoginHandoffRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	jti, suppliedSecret, ok := parseLoginHandoffCode(req.Code)
	if !ok {
		protocol.WriteError(w, http.StatusForbidden, "登录短码无效、已使用或已过期")
		return
	}
	expectedSecret := deriveLoginHandoffSecret(s.secretKey, jti)
	if !hmac.Equal(suppliedSecret, expectedSecret) {
		protocol.WriteError(w, http.StatusForbidden, "登录短码无效、已使用或已过期")
		return
	}
	secretHash := sha256.Sum256(suppliedSecret)
	redemption, consumed, err := s.Store.ConsumeLoginHandoff(
		r.Context(), jti, secretHash[:], node.ID, time.Now().UTC(), activityLeaseTTL,
	)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "登录短码核销失败")
		return
	}
	if !consumed {
		protocol.WriteError(w, http.StatusForbidden, "登录短码无效、已使用或已过期")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":                    true,
		"handle":                redemption.Handle,
		"user_id":               redemption.UserID,
		"session_id":            redemption.SessionID,
		"activity_epoch":        redemption.ActivityEpoch,
		"controller_generation": redemption.ControllerGeneration,
	})
}

func deriveLoginHandoffSecret(key []byte, jti string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("stcontrol-login-handoff:v1:" + jti))
	return mac.Sum(nil)
}

func parseLoginHandoffCode(code string) (string, []byte, bool) {
	jti, encoded, found := strings.Cut(code, ".")
	if !found || !isUUID(jti) || encoded == "" {
		return "", nil, false
	}
	secret, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(secret) != sha256.Size {
		return "", nil, false
	}
	return jti, secret, true
}

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := cryptorand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:]), nil
}

func isUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil && len(decoded) == 16
}

func setHandoffNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
}
