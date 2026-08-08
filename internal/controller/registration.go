package controller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const (
	registrationPendingCookie = "stcontrol_registration"
	registrationClientTTL     = 30 * time.Minute
	registrationLeaseTTL      = 2 * time.Minute
	registrationMaxAttempts   = 5
)

type registerRequest struct {
	OperationID    string `json:"operation_id"`
	Username       string `json:"username"`
	DisplayName    string `json:"display_name"`
	Password       string `json:"password"`
	NodeID         int64  `json:"node_id"`
	InvitationCode string `json:"invitation_code"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	setHandoffNoStoreHeaders(w)
	if !s.validMutationOrigin(r) {
		protocol.WriteError(w, http.StatusForbidden, "请求来源无效")
		return
	}
	if !s.requireNewOperations(w) {
		return
	}
	var req registerRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || !isUUID(req.OperationID) || req.NodeID <= 0 {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	handle := NormalizeHandle(req.Username)
	if !isValidHandle(handle) {
		protocol.WriteError(w, http.StatusBadRequest, "用户名无效（3-32位，仅小写字母、数字、横杠）")
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = handle
	}
	if len(displayName) > 128 {
		protocol.WriteError(w, http.StatusBadRequest, "昵称过长")
		return
	}
	if len(req.Password) < 8 {
		protocol.WriteError(w, http.StatusBadRequest, "密码至少 8 位")
		return
	}
	if len(req.InvitationCode) > 256 {
		protocol.WriteError(w, http.StatusBadRequest, "邀请码格式错误")
		return
	}
	node, err := s.Store.GetNodeByID(r.Context(), req.NodeID)
	if err != nil || node == nil {
		protocol.WriteError(w, http.StatusBadRequest, "节点不存在")
		return
	}
	if !s.nodeRegistrable(node) {
		protocol.WriteError(w, http.StatusConflict, "该节点当前不可注册")
		return
	}
	if node.RegistrationPolicyState == "invitation_required" && req.InvitationCode == "" {
		protocol.WriteError(w, http.StatusBadRequest, "该节点需要邀请码")
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
	workflow, pendingToken, err := s.createRegistrationWorkflow(r.Context(), registrationStartInput{
		OperationID: req.OperationID, Node: node, LocalHandle: handle, DisplayName: displayName,
		AuthProvider: "password", PasswordHash: passwordHash,
		PasswordMaterialHash: nodeHash, PasswordMaterialSalt: nodeSalt,
		InvitationCode: req.InvitationCode, CredentialProof: req.Password,
	})
	if err != nil {
		s.writeRegistrationStartError(w, err)
		return
	}
	s.setRegistrationPendingCookie(w, r, pendingToken)
	pendingHash := sha256.Sum256([]byte(pendingToken))
	status, err := s.Store.GetRegistrationWorkflowStatus(r.Context(), pendingHash[:], time.Now().UTC())
	if err != nil || status == nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "注册状态暂不可用")
		return
	}
	if status.State == "succeeded" || status.State == "failed" || status.State == "cancelled" {
		s.writeRegistrationStatus(w, r, status)
		return
	}
	s.queueRegistrationWorkflow(context.WithoutCancel(r.Context()), workflow.WorkflowID)
	protocol.WriteJSON(w, http.StatusAccepted, map[string]any{"ok": true, "state": "pending"})
}

func (s *Server) writeRegistrationStartError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrRegistrationInvitationRequired):
		protocol.WriteError(w, http.StatusBadRequest, "该节点需要邀请码")
	case errors.Is(err, store.ErrRegistrationNodeUnavailable):
		protocol.WriteError(w, http.StatusConflict, "节点注册策略已变化，请刷新后重试")
	case errors.Is(err, store.ErrRegistrationConflict):
		protocol.WriteError(w, http.StatusConflict, "用户名已被占用，或重复请求内容不一致")
	case errors.Is(err, store.ErrNoActiveController):
		protocol.WriteError(w, http.StatusServiceUnavailable, "总控当前为只读状态")
	default:
		protocol.WriteError(w, http.StatusServiceUnavailable, "创建注册任务失败")
	}
}

type registrationStartInput struct {
	OperationID          string
	Node                 *store.Node
	LocalHandle          string
	DisplayName          string
	AuthProvider         string
	PasswordHash         string
	PasswordMaterialHash string
	PasswordMaterialSalt string
	OAuthSubject         string
	AvatarURL            string
	InvitationCode       string
	CredentialProof      string
}

type registrationDigestInput struct {
	OperationID     string `json:"operation_id"`
	NodeID          int64  `json:"node_id"`
	PolicyVersion   int64  `json:"policy_version"`
	LocalHandle     string `json:"local_handle"`
	DisplayName     string `json:"display_name"`
	AuthProvider    string `json:"auth_provider"`
	CredentialProof string `json:"credential_proof"`
	InvitationCode  string `json:"invitation_code"`
}

func (s *Server) createRegistrationWorkflow(
	ctx context.Context,
	input registrationStartInput,
) (store.RegistrationWorkflow, string, error) {
	if input.Node == nil || !isUUID(input.OperationID) || input.LocalHandle == "" || input.DisplayName == "" {
		return store.RegistrationWorkflow{}, "", store.ErrInvalidRegistration
	}
	workflowID, err := newUUID()
	if err != nil {
		return store.RegistrationWorkflow{}, "", err
	}
	pendingToken, err := randomBearerToken()
	if err != nil {
		return store.RegistrationWorkflow{}, "", err
	}
	pendingTokenHash := sha256.Sum256([]byte(pendingToken))
	requestDigest, err := s.registrationRequestDigest(registrationDigestInput{
		OperationID: input.OperationID, NodeID: input.Node.ID,
		PolicyVersion: input.Node.RegistrationPolicyVersion,
		LocalHandle:   input.LocalHandle, DisplayName: input.DisplayName,
		AuthProvider: input.AuthProvider, CredentialProof: input.CredentialProof,
		InvitationCode: input.InvitationCode,
	})
	if err != nil {
		return store.RegistrationWorkflow{}, "", err
	}
	var invitationCiphertext string
	if input.InvitationCode != "" {
		invitationCiphertext, err = controlcrypto.Encrypt(s.registrationSecretKey(), []byte(input.InvitationCode))
		if err != nil {
			return store.RegistrationWorkflow{}, "", err
		}
	}
	now := time.Now().UTC()
	workflow, err := s.Store.CreateRegistrationWorkflow(ctx, store.CreateRegistrationWorkflowParams{
		WorkflowID: workflowID, OperationID: input.OperationID,
		RequestDigest: requestDigest, PendingTokenHash: pendingTokenHash[:],
		ClientExpiresAt: now.Add(registrationClientTTL), NodeID: input.Node.ID,
		PolicyVersion: input.Node.RegistrationPolicyVersion,
		LocalHandle:   input.LocalHandle, DisplayName: input.DisplayName,
		AuthProvider: input.AuthProvider, PasswordHash: input.PasswordHash,
		PasswordMaterialHash: input.PasswordMaterialHash,
		PasswordMaterialSalt: input.PasswordMaterialSalt,
		OAuthSubject:         input.OAuthSubject, AvatarURL: input.AvatarURL,
		InvitationCiphertext: invitationCiphertext, Now: now,
	})
	if err != nil {
		return store.RegistrationWorkflow{}, "", err
	}
	return workflow, pendingToken, nil
}

func (s *Server) registrationRequestDigest(value registrationDigestInput) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.secretKey)
	_, _ = mac.Write([]byte("stcontrol-registration-request:v1\n"))
	_, _ = mac.Write(encoded)
	return mac.Sum(nil), nil
}

func (s *Server) registrationSecretKey() []byte {
	mac := hmac.New(sha256.New, s.secretKey)
	_, _ = mac.Write([]byte("stcontrol-registration-secret:v1"))
	return mac.Sum(nil)
}

func (s *Server) handleRegistrationStatus(w http.ResponseWriter, r *http.Request) {
	setHandoffNoStoreHeaders(w)
	cookie, err := r.Cookie(registrationPendingCookie)
	if err != nil || cookie.Value == "" {
		protocol.WriteError(w, http.StatusUnauthorized, "没有待处理的注册")
		return
	}
	tokenHash := sha256.Sum256([]byte(cookie.Value))
	status, err := s.Store.GetRegistrationWorkflowStatus(r.Context(), tokenHash[:], time.Now().UTC())
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "注册状态暂不可用")
		return
	}
	if status == nil {
		s.clearRegistrationPendingCookie(w, r)
		protocol.WriteError(w, http.StatusUnauthorized, "注册状态已失效")
		return
	}
	s.writeRegistrationStatus(w, r, status)
}

func (s *Server) writeRegistrationStatus(
	w http.ResponseWriter,
	r *http.Request,
	status *store.RegistrationWorkflowStatus,
) {
	if status == nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "注册状态暂不可用")
		return
	}
	switch status.State {
	case "succeeded":
		user, err := s.Store.GetUserByID(r.Context(), status.ResultUserID)
		if err != nil || user == nil || user.Status != "active" {
			protocol.WriteError(w, http.StatusServiceUnavailable, "注册结果暂不可用")
			return
		}
		if err := s.createUserSession(w, r, user); err != nil {
			protocol.WriteError(w, http.StatusServiceUnavailable, "创建会话失败")
			return
		}
		s.clearRegistrationPendingCookie(w, r)
		protocol.WriteJSON(w, http.StatusOK, map[string]any{
			"ok": true, "state": "succeeded", "username": user.Username,
		})
	case "failed", "cancelled":
		s.clearRegistrationPendingCookie(w, r)
		protocol.WriteJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "state": "failed", "error": registrationFailureMessage(status.ErrorCode),
		})
	case "retry_wait":
		protocol.WriteJSON(w, http.StatusAccepted, map[string]any{"ok": true, "state": "retrying"})
	default:
		protocol.WriteJSON(w, http.StatusAccepted, map[string]any{"ok": true, "state": "pending"})
	}
}

func registrationFailureMessage(code string) string {
	switch code {
	case "policy_changed":
		return "节点注册策略已变化，请重新选择节点并提交"
	case "node_rejected":
		return "节点拒绝了注册，请检查用户名或邀请码后重试"
	case "node_unavailable", "retry_exhausted":
		return "节点长时间不可用，请重新选择节点"
	case "identity_conflict":
		return "用户名或第三方身份已被占用"
	default:
		return "注册未完成，请重新提交"
	}
}

func (s *Server) setRegistrationPendingCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: registrationPendingCookie, Value: token, Path: "/api/auth/registration",
		HttpOnly: true, Secure: s.secureCookies(r), SameSite: http.SameSiteStrictMode,
		MaxAge: int(registrationClientTTL.Seconds()),
	})
}

func (s *Server) clearRegistrationPendingCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: registrationPendingCookie, Value: "", Path: "/api/auth/registration",
		HttpOnly: true, Secure: s.secureCookies(r), SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

func (s *Server) queueRegistrationWorkflow(ctx context.Context, workflowID string) {
	select {
	case s.registrationSlots <- struct{}{}:
		go func() {
			defer func() { <-s.registrationSlots }()
			runCtx, cancel := context.WithTimeout(ctx, registrationLeaseTTL)
			defer cancel()
			_ = s.executeRegistrationWorkflow(runCtx, workflowID)
		}()
	default:
		// The durable reconciler will pick the scheduled workflow up.
	}
}

func (s *Server) executeRegistrationWorkflow(ctx context.Context, workflowID string) error {
	now := time.Now().UTC()
	claimed, err := s.Store.ClaimRegistrationWorkflow(
		ctx, workflowID, s.workflowWorkerID, now, registrationLeaseTTL,
	)
	if err != nil || !claimed {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.Store.ReleaseRegistrationWorkflow(cleanupCtx, workflowID, s.workflowWorkerID)
	}()
	execution, err := s.Store.GetRegistrationWorkflowExecution(ctx, workflowID)
	if err != nil || execution == nil {
		return err
	}
	now = time.Now().UTC()
	if execution.NodePolicyVersion != execution.PolicyVersion {
		return s.failRegistrationTransition(ctx, workflowID, "policy_changed")
	}
	if execution.NodeStatus != "online" ||
		(execution.NodePolicyState != "open" && execution.NodePolicyState != "invitation_required") ||
		!execution.NodePolicyExpiresAt.Valid || !execution.NodePolicyExpiresAt.Time.After(now) {
		return s.retryRegistrationTransition(ctx, execution, "node_unavailable")
	}
	node, err := s.Store.GetNodeByID(ctx, execution.NodeID)
	if err != nil || node == nil {
		return s.retryRegistrationTransition(ctx, execution, "node_unavailable")
	}
	var invitationCode string
	if execution.InvitationCiphertext.Valid {
		plaintext, err := controlcrypto.Decrypt(s.registrationSecretKey(), execution.InvitationCiphertext.String)
		if err != nil {
			return s.failRegistrationTransition(ctx, workflowID, "internal_error")
		}
		invitationCode = string(plaintext)
		for i := range plaintext {
			plaintext[i] = 0
		}
	}
	payload := protocol.ProvisionUserRequest{
		RegistrationID: execution.WorkflowID, PolicyVersion: execution.PolicyVersion,
		Handle: execution.LocalHandle, Name: execution.DisplayName,
		InvitationCode: invitationCode,
	}
	if execution.AuthProvider == "password" {
		payload.PasswordHash = execution.PasswordMaterialHash.String
		payload.PasswordSalt = execution.PasswordMaterialSalt.String
	} else {
		payload.OAuthProvider = execution.AuthProvider
		payload.OAuthSubject = execution.OAuthSubject.String
	}
	commandOperationID := deriveWorkflowOperationID(
		execution.WorkflowID, fmt.Sprintf("provision-user:%d", execution.Attempt),
	)
	if _, err := s.enqueueAgentCommand(ctx, node, "provision_user", payload, commandOperationID); err != nil {
		return s.retryRegistrationTransition(ctx, execution, "command_enqueue_failed")
	}
	result, err := s.waitAgentCommand(ctx, commandOperationID, 45*time.Second)
	if err != nil {
		return s.retryRegistrationTransition(ctx, execution, "command_timeout")
	}
	var summary agentCommandSummary
	if result == nil || json.Unmarshal(result.ResultSummary, &summary) != nil {
		return s.retryRegistrationTransition(ctx, execution, "command_uncertain")
	}
	if result.State != "succeeded" || !summary.OK {
		switch summary.Code {
		case "provision_rejected":
			return s.failRegistrationTransition(ctx, workflowID, "node_rejected")
		case "invalid_command_payload":
			return s.failRegistrationTransition(ctx, workflowID, "internal_error")
		default:
			return s.retryRegistrationTransition(ctx, execution, "command_uncertain")
		}
	}
	if summary.LocalUserID == "" {
		return s.retryRegistrationTransition(ctx, execution, "command_uncertain")
	}
	user, err := s.Store.CompleteRegistrationWorkflow(
		ctx, workflowID, s.workflowWorkerID, summary.LocalUserID, time.Now().UTC(),
	)
	if err != nil {
		if errors.Is(err, store.ErrRegistrationConflict) {
			return s.failRegistrationTransition(ctx, workflowID, "identity_conflict")
		}
		return s.retryRegistrationTransition(ctx, execution, "publish_failed")
	}
	_ = s.Store.Audit(ctx, execution.LocalHandle, "register", execution.NodeName, nil)
	_ = user
	return nil
}

func (s *Server) retryRegistrationTransition(
	ctx context.Context,
	execution *store.RegistrationWorkflowExecution,
	errorCode string,
) error {
	transitionCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	terminalWhenExhausted := errorCode == "node_unavailable" || errorCode == "command_enqueue_failed"
	if terminalWhenExhausted && execution.Attempt+1 >= registrationMaxAttempts {
		terminalCode := "retry_exhausted"
		if errorCode == "node_unavailable" {
			terminalCode = "node_unavailable"
		}
		return s.Store.FailRegistrationWorkflow(
			transitionCtx, execution.WorkflowID, s.workflowWorkerID, terminalCode, time.Now().UTC(),
		)
	}
	delay := 5 * time.Second * time.Duration(1<<min(execution.Attempt, 4))
	now := time.Now().UTC()
	_, err := s.Store.ScheduleRegistrationRetry(
		transitionCtx, execution.WorkflowID, s.workflowWorkerID, errorCode, now.Add(delay), now,
	)
	return err
}

func (s *Server) failRegistrationTransition(ctx context.Context, workflowID, errorCode string) error {
	transitionCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return s.Store.FailRegistrationWorkflow(
		transitionCtx, workflowID, s.workflowWorkerID, errorCode, time.Now().UTC(),
	)
}

func (s *Server) registrationWorkflowReconciler(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		ids, err := s.Store.ListRunnableRegistrationWorkflowIDs(ctx, 20, time.Now().UTC())
		if err == nil {
			for _, id := range ids {
				s.queueRegistrationWorkflow(ctx, id)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
