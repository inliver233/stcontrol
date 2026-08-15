package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"

	"github.com/go-chi/chi/v5"
)

const (
	userDataFaultLeaseTTL     = 2 * time.Minute
	userDataFaultCommandTTL   = 45 * time.Second
	userDataFaultPollInterval = 5 * time.Second
)

type reportUserDataFaultRequest struct {
	OperationID        string `json:"operation_id"`
	ExpectedHomeNodeID int64  `json:"expected_home_node_id"`
	ReasonCode         string `json:"reason_code"`
	AcknowledgeRisk    bool   `json:"acknowledge_risk"`
}

func (s *Server) handleAdminReportUserDataFault(w http.ResponseWriter, r *http.Request) {
	if !s.requireNewOperations(w) {
		return
	}
	userUUID := chi.URLParam(r, "uuid")
	var req reportUserDataFaultRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		!isUUID(userUUID) || !isUUID(req.OperationID) || req.ExpectedHomeNodeID <= 0 ||
		!userDataFaultReasonCode(req.ReasonCode) || !req.AcknowledgeRisk {
		protocol.WriteError(w, http.StatusBadRequest, "必须确认用户权威数据故障将立即关闭该用户写入")
		return
	}
	sess := currentSession(r)
	if sess == nil || sess.AdminID <= 0 || !sess.IsAdmin {
		protocol.WriteError(w, http.StatusUnauthorized, "管理员会话无效")
		return
	}
	digest, err := userDataFaultRequestDigest(userUUID, req)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成故障请求摘要失败")
		return
	}
	status, err := s.Store.ReportUserDataFault(r.Context(), store.ReportUserDataFaultParams{
		OperationID: req.OperationID, RequestDigest: digest, UserUUID: userUUID,
		ExpectedHomeNodeID: req.ExpectedHomeNodeID, ReasonCode: req.ReasonCode,
		AdminID: sess.AdminID, Now: time.Now().UTC(),
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrInvalidUserDataFault):
			protocol.WriteError(w, http.StatusBadRequest, "用户数据故障请求无效")
		case errors.Is(err, store.ErrUserDataFaultNotFound):
			protocol.WriteError(w, http.StatusNotFound, "用户不存在或不可报告")
		case errors.Is(err, store.ErrUserDataFaultOperationConflict),
			errors.Is(err, store.ErrUserDataFaultAlreadyOpen),
			errors.Is(err, store.ErrUserDataFaultHomeConflict),
			errors.Is(err, store.ErrUserDataFaultAuthoritativeConflict),
			errors.Is(err, store.ErrUserDataFaultState):
			protocol.WriteError(w, http.StatusConflict, "用户数据故障事实已变化，请刷新后重新确认")
		default:
			protocol.WriteError(w, http.StatusServiceUnavailable, "用户数据故障暂无法持久化")
		}
		return
	}

	// The database transaction has already closed tickets, ended the writer
	// lease and marked the authoritative replica corrupt. Make one bounded
	// immediate attempt to establish the matching node-local gate; the durable
	// reconciler resumes it after timeout, process restart or generation change.
	s.runUserDataFaultOnce(r.Context(), status.ID)
	if current, getErr := s.Store.GetUserDataFaultByID(r.Context(), status.ID); getErr == nil {
		status = current
	}
	code := http.StatusAccepted
	if status.State == "recovery_available" || status.State == "recovery_unavailable" ||
		status.State == "resolved" {
		code = http.StatusOK
	}
	protocol.WriteJSON(w, code, status)
}

func (s *Server) handleAdminUserDataFaultStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.Store.GetUserDataFaultByUserUUID(r.Context(), chi.URLParam(r, "uuid"))
	if err != nil {
		if errors.Is(err, store.ErrInvalidUserDataFault) {
			protocol.WriteError(w, http.StatusBadRequest, "用户标识无效")
			return
		}
		protocol.WriteError(w, http.StatusServiceUnavailable, "读取用户数据故障状态失败")
		return
	}
	if status == nil {
		protocol.WriteError(w, http.StatusNotFound, "该用户没有数据故障记录")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, status)
}

func userDataFaultRequestDigest(userUUID string, req reportUserDataFaultRequest) ([]byte, error) {
	encoded, err := json.Marshal(struct {
		UserUUID           string `json:"user_uuid"`
		ExpectedHomeNodeID int64  `json:"expected_home_node_id"`
		ReasonCode         string `json:"reason_code"`
		Acknowledged       bool   `json:"acknowledged"`
	}{userUUID, req.ExpectedHomeNodeID, req.ReasonCode, req.AcknowledgeRisk})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}

func userDataFaultReasonCode(value string) bool {
	switch value {
	case "authoritative_integrity_mismatch", "user_directory_missing",
		"user_directory_unreadable", "user_database_corrupt":
		return true
	default:
		return false
	}
}

func (s *Server) userDataFaultReconciler(ctx context.Context) {
	ticker := time.NewTicker(userDataFaultPollInterval)
	defer ticker.Stop()
	s.reconcileUserDataFaults(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcileUserDataFaults(ctx)
		}
	}
}

func (s *Server) reconcileUserDataFaults(ctx context.Context) {
	ids, err := s.Store.ListSchedulableUserDataFaultIDs(ctx, 100)
	if err != nil {
		return
	}
	releaseIDs, err := s.Store.ListSchedulableUserDataFaultReleaseIDs(ctx, 100)
	if err != nil {
		return
	}
	s.userDataFaultScheduleMu.Lock()
	defer s.userDataFaultScheduleMu.Unlock()
	preferRelease := s.userDataFaultReleaseNext
	for len(ids) > 0 || len(releaseIDs) > 0 {
		kind, id, nextPreference := nextUserDataFaultWork(ids, releaseIDs, preferRelease)
		started := false
		if kind == "freeze" {
			started = s.startUserDataFault(ctx, id)
		} else {
			started = s.startUserDataFaultRelease(ctx, id)
		}
		if !started {
			return
		}
		if kind == "freeze" {
			ids = ids[1:]
		} else {
			releaseIDs = releaseIDs[1:]
		}
		preferRelease = nextPreference
		s.userDataFaultReleaseNext = preferRelease
	}
}

func nextUserDataFaultWork(
	freezeIDs, releaseIDs []string,
	preferRelease bool,
) (kind, id string, nextPreference bool) {
	switch {
	case len(freezeIDs) > 0 && len(releaseIDs) > 0 && preferRelease:
		return "release", releaseIDs[0], false
	case len(freezeIDs) > 0 && len(releaseIDs) > 0:
		return "freeze", freezeIDs[0], true
	case len(releaseIDs) > 0:
		return "release", releaseIDs[0], preferRelease
	case len(freezeIDs) > 0:
		return "freeze", freezeIDs[0], preferRelease
	default:
		return "", "", preferRelease
	}
}

func (s *Server) startUserDataFault(ctx context.Context, faultID string) bool {
	if s.userDataFaultSlots == nil {
		return false
	}
	select {
	case s.userDataFaultSlots <- struct{}{}:
	case <-ctx.Done():
		return false
	default:
		return false
	}
	go func() {
		defer func() { <-s.userDataFaultSlots }()
		s.claimAndExecuteUserDataFault(ctx, faultID)
	}()
	return true
}

func (s *Server) runUserDataFaultOnce(ctx context.Context, faultID string) {
	if s.userDataFaultSlots == nil {
		return
	}
	select {
	case s.userDataFaultSlots <- struct{}{}:
		defer func() { <-s.userDataFaultSlots }()
	case <-ctx.Done():
		return
	default:
		return
	}
	s.claimAndExecuteUserDataFault(ctx, faultID)
}

func (s *Server) startUserDataFaultRelease(ctx context.Context, faultID string) bool {
	if s.userDataFaultSlots == nil {
		return false
	}
	select {
	case s.userDataFaultSlots <- struct{}{}:
	case <-ctx.Done():
		return false
	default:
		return false
	}
	go func() {
		defer func() { <-s.userDataFaultSlots }()
		s.claimAndExecuteUserDataFaultRelease(ctx, faultID)
	}()
	return true
}

func (s *Server) claimAndExecuteUserDataFault(ctx context.Context, faultID string) {
	operationID, err := newUUID()
	if err != nil {
		return
	}
	task, err := s.Store.ClaimUserDataFault(
		ctx, faultID, operationID, s.workflowWorkerID,
		time.Now().UTC(), userDataFaultLeaseTTL,
	)
	if err != nil || task == nil {
		return
	}
	s.executeUserDataFault(ctx, *task)
}

func (s *Server) claimAndExecuteUserDataFaultRelease(ctx context.Context, faultID string) {
	operationID, err := newUUID()
	if err != nil {
		return
	}
	task, err := s.Store.ClaimUserDataFaultRelease(
		ctx, faultID, operationID, s.workflowWorkerID,
		time.Now().UTC(), userDataFaultLeaseTTL,
	)
	if err != nil || task == nil {
		return
	}
	s.executeUserDataFaultRelease(ctx, *task)
}

func (s *Server) executeUserDataFault(ctx context.Context, task store.UserDataFaultTask) {
	node, err := s.Store.GetNodeByID(ctx, task.NodeID)
	if err != nil || !nodeAcceptsUserDataFreeze(node) {
		s.retryUserDataFault(ctx, task, "agent_unavailable")
		return
	}
	result, err := s.runRetryableAgentCommandWithOperationAtGeneration(
		ctx, node, "freeze_user_data", protocol.FreezeUserDataRequest{
			OperationID: task.OperationID, ControllerGeneration: task.ControllerGeneration,
			FaultID:      task.ID,
			GlobalUserID: task.GlobalUserID, Handle: task.Handle,
			ActivityEpoch: task.ActivityEpoch,
		}, task.OperationID, task.ControllerGeneration, userDataFaultCommandTTL,
	)
	if err != nil {
		s.retryUserDataFault(ctx, task, safeUserDataFaultFailureCode(agentCommandErrorCode(err)))
		return
	}
	if !matchingUserDataFreezeReceipt(result.UserDataFreeze, task) {
		s.retryUserDataFault(ctx, task, "receipt_mismatch")
		return
	}
	if _, err := s.Store.ReconcileProtectionStates(
		ctx, time.Now().UTC(), s.protectionAlertGrace(),
	); err != nil {
		s.retryUserDataFault(ctx, task, "protection_projection_unavailable")
		return
	}
	_, _ = s.Store.CompleteUserDataFaultFreeze(
		ctx, task.ID, task.OperationID, s.workflowWorkerID, time.Now().UTC(),
	)
}

func (s *Server) executeUserDataFaultRelease(ctx context.Context, task store.UserDataFaultReleaseTask) {
	node, err := s.Store.GetNodeByID(ctx, task.NodeID)
	if err != nil || !nodeAcceptsUserDataFreeze(node) {
		s.retryUserDataFaultRelease(ctx, task, "agent_unavailable")
		return
	}
	result, err := s.runRetryableAgentCommandWithOperationAtGeneration(
		ctx, node, "release_user_data", protocol.ReleaseUserDataRequest{
			OperationID: task.OperationID, ControllerGeneration: task.ControllerGeneration,
			FaultID:      task.ID,
			GlobalUserID: task.GlobalUserID, Handle: task.Handle,
			ActivityEpoch: task.ActivityEpoch,
		}, task.OperationID, task.ControllerGeneration, userDataFaultCommandTTL,
	)
	if err != nil {
		s.retryUserDataFaultRelease(ctx, task, safeUserDataFaultFailureCode(agentCommandErrorCode(err)))
		return
	}
	if !matchingUserDataReleaseReceipt(result.UserDataRelease, task) {
		s.retryUserDataFaultRelease(ctx, task, "receipt_mismatch")
		return
	}
	if err := s.Store.CompleteUserDataFaultRelease(
		ctx, task.ID, task.OperationID, s.workflowWorkerID, time.Now().UTC(),
	); err != nil {
		return
	}
}

func (s *Server) retryUserDataFault(
	ctx context.Context,
	task store.UserDataFaultTask,
	code string,
) {
	_ = s.Store.RetryUserDataFault(
		ctx, task.ID, task.OperationID, s.workflowWorkerID, code,
		time.Now().UTC(), userDataFaultRetryDelay(task.Attempt),
	)
}

func (s *Server) retryUserDataFaultRelease(
	ctx context.Context,
	task store.UserDataFaultReleaseTask,
	code string,
) {
	_ = s.Store.RetryUserDataFaultRelease(
		ctx, task.ID, task.OperationID, s.workflowWorkerID, code,
		time.Now().UTC(), userDataFaultRetryDelay(task.Attempt),
	)
}

func matchingUserDataReleaseReceipt(
	receipt *protocol.ReleaseUserDataResponse,
	task store.UserDataFaultReleaseTask,
) bool {
	return receipt != nil && receipt.OK && receipt.Released &&
		receipt.OperationID == task.OperationID &&
		receipt.ControllerGeneration == task.ControllerGeneration && receipt.FaultID == task.ID &&
		receipt.GlobalUserID == task.GlobalUserID && receipt.Handle == task.Handle &&
		receipt.ActivityEpoch == task.ActivityEpoch
}

func matchingUserDataFreezeReceipt(
	receipt *protocol.FreezeUserDataResponse,
	task store.UserDataFaultTask,
) bool {
	return receipt != nil && receipt.OK && receipt.Frozen && receipt.Drained &&
		receipt.OperationID == task.OperationID &&
		receipt.ControllerGeneration == task.ControllerGeneration && receipt.FaultID == task.ID &&
		receipt.GlobalUserID == task.GlobalUserID && receipt.Handle == task.Handle &&
		receipt.ActivityEpoch == task.ActivityEpoch
}

func nodeAcceptsUserDataFreeze(node *store.Node) bool {
	if node == nil || node.Role != "compute" || node.ConnectivityState != "online" ||
		node.CompatibilityState != "compatible" || node.OperationalState == "decommissioned" {
		return false
	}
	return node.ControlMode == "managed" || node.ControlMode == "independent-draining"
}

func safeUserDataFaultFailureCode(code string) string {
	switch code {
	case "invalid_command_payload", "user_data_freeze_failed", "user_data_release_failed":
		return code
	default:
		return "agent_command_unavailable"
	}
}

func userDataFaultRetryDelay(attempt int) time.Duration {
	delay := 5 * time.Second
	for current := 1; current < attempt && delay < 5*time.Minute; current++ {
		delay *= 2
	}
	if delay > 5*time.Minute {
		return 5 * time.Minute
	}
	return delay
}
