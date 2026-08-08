package controller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

type startArchiveRestoreRequest struct {
	OperationID         string `json:"operation_id"`
	TargetNodeID        int64  `json:"target_node_id"`
	ExpectedRecoveryAt  string `json:"expected_recovery_at"`
	AcknowledgeDataLoss bool   `json:"acknowledge_data_loss"`
}

type publicRestoreStatus struct {
	OperationID      string    `json:"operation_id"`
	State            string    `json:"state"`
	TargetNodeID     int64     `json:"target_node_id"`
	TargetNodeName   string    `json:"target_node_name"`
	LatestRecoveryAt time.Time `json:"latest_recovery_at"`
	Error            string    `json:"error,omitempty"`
}

func (s *Server) handleRestoreTargets(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentActiveGlobalUser(r)
	if !ok {
		protocol.WriteError(w, http.StatusUnauthorized, "用户不存在或不可用")
		return
	}
	targets, err := s.Store.ListRestoreTargets(r.Context(), user.GlobalID, 50)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "恢复目标暂不可用")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{"targets": targets})
}

func (s *Server) handleStartArchiveRestore(w http.ResponseWriter, r *http.Request) {
	var req startArchiveRestoreRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		!isUUID(req.OperationID) || req.TargetNodeID <= 0 || !req.AcknowledgeDataLoss {
		protocol.WriteError(w, http.StatusBadRequest, "必须确认恢复点之后的数据可能丢失")
		return
	}
	recoveryAt, err := time.Parse(time.RFC3339Nano, req.ExpectedRecoveryAt)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "恢复时间已失效，请刷新后重新确认")
		return
	}
	user, ok := s.currentActiveGlobalUser(r)
	if !ok {
		protocol.WriteError(w, http.StatusUnauthorized, "用户不存在或不可用")
		return
	}
	requestDigest, err := s.archiveRestoreDigest(
		user.GlobalID, req.TargetNodeID, recoveryAt, req.AcknowledgeDataLoss,
	)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成恢复请求失败")
		return
	}
	workflowID, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成恢复任务失败")
		return
	}
	restoreSnapshotID, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成恢复任务失败")
		return
	}
	capabilityID, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成恢复任务失败")
		return
	}
	capability := deriveTransferCapability(s.secretKey, capabilityID)
	capabilityHash := sha256.Sum256([]byte(capability))
	now := time.Now().UTC()
	execution, err := s.Store.CreateRestoreWorkflow(r.Context(), store.CreateRestoreWorkflowParams{
		OperationID: req.OperationID, RequestDigest: requestDigest,
		WorkflowID: workflowID, RestoreSnapshotID: restoreSnapshotID,
		CapabilityID: capabilityID, CapabilityHash: capabilityHash[:],
		GlobalUserID: user.GlobalID, TargetNodeID: req.TargetNodeID,
		ExpectedRecoveryAt: recoveryAt, CapabilityExpires: now.Add(15 * time.Minute), Now: now,
	})
	if err != nil {
		s.writeArchiveRestoreError(w, err)
		return
	}
	s.queueRestoreWorkflow(context.WithoutCancel(r.Context()), execution.WorkflowID)
	status, err := s.Store.GetRestoreOperationStatus(r.Context(), user.GlobalID, req.OperationID)
	if err != nil || status == nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "恢复已安全排队，状态暂不可用")
		return
	}
	code := http.StatusAccepted
	if status.State == "succeeded" {
		code = http.StatusOK
	}
	protocol.WriteJSON(w, code, publicArchiveRestoreStatus(status))
}

func (s *Server) handleArchiveRestoreStatus(w http.ResponseWriter, r *http.Request) {
	operationID := chi.URLParam(r, "operationID")
	if !isUUID(operationID) {
		protocol.WriteError(w, http.StatusBadRequest, "恢复操作 ID 无效")
		return
	}
	user, ok := s.currentActiveGlobalUser(r)
	if !ok {
		protocol.WriteError(w, http.StatusUnauthorized, "用户不存在或不可用")
		return
	}
	status, err := s.Store.GetRestoreOperationStatus(r.Context(), user.GlobalID, operationID)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "恢复状态暂不可用")
		return
	}
	if status == nil {
		protocol.WriteError(w, http.StatusNotFound, "恢复操作不存在")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, publicArchiveRestoreStatus(status))
}

func (s *Server) currentActiveGlobalUser(r *http.Request) (*store.User, bool) {
	legacyUserID, ok := CurrentUser(r)
	if !ok || legacyUserID <= 0 || s.Store == nil {
		return nil, false
	}
	user, err := s.Store.GetUserByID(r.Context(), legacyUserID)
	return user, err == nil && user != nil && user.GlobalID > 0 && user.Status == "active"
}

func publicArchiveRestoreStatus(status *store.RestoreOperationStatus) publicRestoreStatus {
	state := status.State
	switch state {
	case "scheduled", "quiescing", "drained", "snapshotting":
		state = "preparing"
	case "retry_wait":
		state = "retrying"
	case "cancelled":
		state = "failed"
	}
	return publicRestoreStatus{
		OperationID: status.OperationID, State: state,
		TargetNodeID: status.TargetNodeID, TargetNodeName: status.TargetNodeName,
		LatestRecoveryAt: status.SourcePublishedAt, Error: status.ErrorSummary,
	}
}

func (s *Server) writeArchiveRestoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrUserDataFaultState):
		protocol.WriteError(w, http.StatusConflict, "节点冻结尚未确认，暂不能创建恢复任务")
	case errors.Is(err, store.ErrReplicaTakeoverLeaseActive):
		protocol.WriteError(w, http.StatusConflict, "旧节点写入租约仍在有效期内，请稍后重试")
	case errors.Is(err, store.ErrRestoreUnavailable):
		protocol.WriteError(w, http.StatusConflict, "恢复点、账号材料或目标节点已不再可用")
	case errors.Is(err, store.ErrRestoreConflict):
		protocol.WriteError(w, http.StatusConflict, "该操作与已有恢复记录不一致")
	case errors.Is(err, store.ErrNoActiveController):
		protocol.WriteError(w, http.StatusServiceUnavailable, "总控当前为只读状态")
	default:
		protocol.WriteError(w, http.StatusInternalServerError, "恢复任务创建失败")
	}
}

func (s *Server) archiveRestoreDigest(
	globalUserID, targetNodeID int64,
	recoveryAt time.Time,
	acknowledged bool,
) ([]byte, error) {
	encoded, err := json.Marshal(struct {
		UserID       int64  `json:"user_id"`
		TargetNodeID int64  `json:"target_node_id"`
		RecoveryAt   string `json:"recovery_at"`
		Acknowledged bool   `json:"acknowledged"`
	}{globalUserID, targetNodeID, recoveryAt.UTC().Format(time.RFC3339Nano), acknowledged})
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.secretKey)
	_, _ = mac.Write([]byte("stcontrol-archive-restore:v1\n"))
	_, _ = mac.Write(encoded)
	return mac.Sum(nil), nil
}

func (s *Server) queueRestoreWorkflow(ctx context.Context, workflowID string) {
	if s.workflowWorkerID == "" {
		return
	}
	select {
	case s.snapshotSlots <- struct{}{}:
		go func() {
			defer func() { <-s.snapshotSlots }()
			runCtx, cancel := context.WithTimeout(ctx, time.Hour)
			defer cancel()
			_ = s.executeRestoreWorkflow(runCtx, workflowID)
		}()
	default:
		// The durable reconciler will resume the workflow.
	}
}

func (s *Server) executeRestoreWorkflow(ctx context.Context, workflowID string) error {
	if s.workflowWorkerID == "" {
		return fmt.Errorf("restore worker identity unavailable")
	}
	claimed, err := s.Store.ClaimRestoreWorkflow(
		ctx, workflowID, s.workflowWorkerID, time.Now().UTC(), time.Hour,
	)
	if err != nil || !claimed {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.Store.ReleaseSnapshotWorkflow(cleanupCtx, workflowID, s.workflowWorkerID)
	}()
	execution, err := s.Store.GetRestoreWorkflowExecution(ctx, workflowID)
	if err != nil || execution == nil {
		return err
	}
	if execution.State == "retry_wait" {
		if err := s.Store.ResumeSnapshotRetry(ctx, workflowID, time.Now().UTC()); err != nil {
			return err
		}
		execution, err = s.Store.GetRestoreWorkflowExecution(ctx, workflowID)
		if err != nil || execution == nil {
			return err
		}
	}
	source, err := s.Store.GetNodeByID(ctx, execution.SourceNodeID)
	if err != nil || source == nil || source.Role != "storage" {
		return s.retryRestoreWorkflow(ctx, execution, "source_unavailable", "纯存储恢复源暂不可用", err)
	}
	target, err := s.Store.GetNodeByID(ctx, execution.TargetNodeID)
	if err != nil || target == nil || target.Role != "compute" || target.TransferURL == "" {
		return s.retryRestoreWorkflow(ctx, execution, "target_unavailable", "目标计算节点暂不可用", err)
	}
	if execution.State == "publishing" {
		receipt, err := s.loadRestoreReceipt(ctx, execution, target)
		if err != nil {
			return s.retryRestoreWorkflow(ctx, execution, "receipt_unavailable", "目标发布回执暂不可用", err)
		}
		return s.completeRestoreExecution(ctx, execution, receipt)
	}
	if execution.TargetAccountStatus != "active" {
		if err := s.restoreTargetAccount(ctx, execution, target); err != nil {
			return s.retryRestoreWorkflow(ctx, execution, "account_provision_failed", "目标账号供应暂未完成", err)
		}
		execution, err = s.Store.GetRestoreWorkflowExecution(ctx, workflowID)
		if err != nil || execution == nil {
			return err
		}
	}
	if execution.CapabilityState != "prepared" || !execution.CapabilityExpires.After(time.Now().UTC()) {
		if err := s.rotateRestoreCapability(ctx, execution); err != nil {
			return s.retryRestoreWorkflow(ctx, execution, "capability_rotate_failed", "传输授权轮换失败", err)
		}
		execution, err = s.Store.GetRestoreWorkflowExecution(ctx, workflowID)
		if err != nil || execution == nil {
			return err
		}
	}
	capability := deriveTransferCapability(s.secretKey, execution.CapabilityID)
	derivedHash := sha256.Sum256([]byte(capability))
	if !hmac.Equal(derivedHash[:], execution.CapabilityHash) {
		s.failRestoreWorkflow(ctx, execution.WorkflowID, "capability_key_mismatch", "控制面密钥无法恢复传输授权")
		return fmt.Errorf("restore capability key mismatch")
	}
	prepareOperationID := deriveWorkflowOperationID(execution.WorkflowID, "prepare-restore:"+execution.CapabilityID)
	if _, err := s.runAgentCommandWithOperation(ctx, target, "prepare_snapshot_receive", protocol.PrepareSnapshotReceiveRequest{
		WorkflowID: execution.WorkflowID, SnapshotID: execution.RestoreSnapshotID,
		GlobalUserID: execution.GlobalUserID, Handle: execution.Handle, DestinationKind: "restore",
		SourceNodeID: execution.SourceNodeID, ActivityEpoch: execution.ActivityEpoch,
		CapabilityHash: hex.EncodeToString(execution.CapabilityHash), ExpiresAt: execution.CapabilityExpires,
	}, prepareOperationID, 45*time.Second); err != nil {
		if s.restoreCommandDefinitivelyFailed(ctx, prepareOperationID) {
			if rotateErr := s.rotateRestoreCapability(ctx, execution); rotateErr != nil {
				return rotateErr
			}
		}
		return s.retryRestoreWorkflow(ctx, execution, "target_prepare_failed", "目标节点未确认恢复准备", err)
	}
	if err := s.Store.CompleteSnapshotWorkflowStep(
		ctx, execution.WorkflowID, "prepare_target", time.Now().UTC(),
	); err != nil {
		return err
	}
	if execution.State == "scheduled" {
		if err := s.Store.SetSnapshotWorkflowState(
			ctx, execution.WorkflowID, "scheduled", "transferring", time.Now().UTC(),
		); err != nil {
			return err
		}
		execution.State = "transferring"
	}
	commandOperationID := deriveWorkflowOperationID(
		execution.WorkflowID, "start-restore:"+execution.CapabilityID,
	)
	result, runErr := s.runAgentCommandWithOperation(ctx, source, "start_restore_transfer", protocol.StartRestoreTransferRequest{
		JobID: execution.JobID, WorkflowID: execution.WorkflowID,
		SourceSnapshotID: execution.SourceSnapshotID, RestoreSnapshotID: execution.RestoreSnapshotID,
		SourceManifestSHA256: hex.EncodeToString(execution.SourceManifestSHA256),
		GlobalUserID:         execution.GlobalUserID, Handle: execution.Handle, ActivityEpoch: execution.ActivityEpoch,
		TargetNodeID: execution.TargetNodeID, TargetTransferURL: target.TransferURL,
		TransferCapability: capability, CapabilityExpires: execution.CapabilityExpires,
	}, commandOperationID, 45*time.Minute)
	if runErr != nil || result.Snapshot == nil {
		latest, _ := s.Store.GetRestoreWorkflowExecution(ctx, workflowID)
		if latest != nil && latest.State == "publishing" {
			receipt, receiptErr := s.loadRestoreReceipt(ctx, latest, target)
			if receiptErr == nil {
				return s.completeRestoreExecution(ctx, latest, receipt)
			}
		}
		if s.restoreCommandDefinitivelyFailed(ctx, commandOperationID) {
			if latest != nil && (latest.State == "transferring" || latest.State == "verifying") {
				if err := s.Store.ResetRestoreTransferForRetry(ctx, workflowID, time.Now().UTC()); err != nil {
					return err
				}
				if err := s.rotateRestoreCapability(ctx, latest); err != nil {
					return err
				}
			}
		}
		return s.retryRestoreWorkflow(ctx, execution, "restore_transfer_failed", "恢复传输或验证未完成", runErr)
	}
	return s.completeRestoreExecution(ctx, execution, result.Snapshot)
}

func (s *Server) restoreTargetAccount(
	ctx context.Context,
	execution *store.RestoreWorkflowExecution,
	target *store.Node,
) error {
	request := protocol.RestoreUserAccountRequest{
		WorkflowID: execution.WorkflowID, GlobalUserID: execution.GlobalUserID,
		Handle: execution.Handle, Name: execution.DisplayName, AccountVersion: execution.AccountVersion,
		PasswordHash: execution.PasswordHash, PasswordSalt: execution.PasswordSalt,
		OAuthProvider: execution.OAuthProvider, OAuthSubject: execution.OAuthSubject,
	}
	result, err := s.runAgentCommandWithOperation(
		ctx, target, "restore_user_account", request,
		deriveWorkflowOperationID(execution.WorkflowID, fmt.Sprintf("restore-account:%d:%d", execution.AccountVersion, execution.Attempt)),
		90*time.Second,
	)
	if err != nil || result.LocalUserID == "" {
		if err != nil {
			return err
		}
		return fmt.Errorf("restored account identity missing")
	}
	return s.Store.CompleteRestoreAccountProvision(
		ctx, execution.WorkflowID, execution.AccountVersion, result.LocalUserID, time.Now().UTC(),
	)
}

func (s *Server) loadRestoreReceipt(
	ctx context.Context,
	execution *store.RestoreWorkflowExecution,
	target *store.Node,
) (*protocol.SnapshotTransferReceipt, error) {
	result, err := s.runAgentCommandWithOperation(ctx, target, "get_snapshot_receipt", map[string]string{
		"workflow_id": execution.WorkflowID, "snapshot_id": execution.RestoreSnapshotID,
	}, deriveWorkflowOperationID(execution.WorkflowID, fmt.Sprintf(
		"restore-receipt:%s:%d", execution.CapabilityID, execution.Attempt,
	)), 45*time.Second)
	if err != nil || result.Snapshot == nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("restore receipt missing")
	}
	return result.Snapshot, nil
}

func (s *Server) completeRestoreExecution(
	ctx context.Context,
	execution *store.RestoreWorkflowExecution,
	receipt *protocol.SnapshotTransferReceipt,
) error {
	if receipt == nil || receipt.SnapshotID != execution.RestoreSnapshotID {
		return fmt.Errorf("restore receipt scope mismatch")
	}
	manifestDigest, err := decodeSnapshotDigest(receipt.ManifestSHA256)
	if err != nil {
		return err
	}
	archiveDigest, err := decodeSnapshotDigest(receipt.ArchiveSHA256)
	if err != nil {
		return err
	}
	if err := s.Store.CompleteRestoreWorkflow(ctx, store.CompleteRestoreWorkflowParams{
		WorkflowID: execution.WorkflowID, RestoreSnapshotID: execution.RestoreSnapshotID,
		CapabilityHash: execution.CapabilityHash, ManifestSHA256: manifestDigest,
		ArchiveSHA256: archiveDigest, FileCount: receipt.FileCount,
		TotalBytes: receipt.TotalBytes, Now: time.Now().UTC(),
	}); err != nil {
		return err
	}
	_, _ = s.Store.ReconcileProtectionStates(ctx, time.Now().UTC(), s.protectionAlertGrace())
	return nil
}

func (s *Server) rotateRestoreCapability(ctx context.Context, execution *store.RestoreWorkflowExecution) error {
	capabilityID, err := newUUID()
	if err != nil {
		return err
	}
	capability := deriveTransferCapability(s.secretKey, capabilityID)
	digest := sha256.Sum256([]byte(capability))
	now := time.Now().UTC()
	return s.Store.RotateSnapshotCapability(
		ctx, execution.WorkflowID, capabilityID, digest[:], now.Add(15*time.Minute), now,
	)
}

func (s *Server) restoreCommandDefinitivelyFailed(ctx context.Context, operationID string) bool {
	result, err := s.Store.GetAgentCommandResult(ctx, operationID)
	return err == nil && result != nil && (result.State == "failed" || result.State == "cancelled" || result.State == "expired")
}

func (s *Server) retryRestoreWorkflow(
	ctx context.Context,
	execution *store.RestoreWorkflowExecution,
	code, summary string,
	cause error,
) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	delay := 5 * time.Second
	for i := 0; i < execution.Attempt && delay < 5*time.Minute; i++ {
		delay *= 2
	}
	attempt, err := s.Store.ScheduleSnapshotRetry(
		ctx, execution.WorkflowID, code, summary, time.Now().UTC(), delay,
	)
	if err != nil {
		return err
	}
	maxAttempts := 3
	if s.Cfg != nil && s.Cfg.Backup.RetryMax > 0 {
		maxAttempts = s.Cfg.Backup.RetryMax
	}
	if attempt >= maxAttempts {
		s.failRestoreWorkflow(ctx, execution.WorkflowID, code, summary)
	}
	if cause != nil {
		return cause
	}
	return fmt.Errorf("%s", code)
}

func (s *Server) failRestoreWorkflow(ctx context.Context, workflowID, code, summary string) {
	failureCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = s.Store.FailRestoreWorkflow(failureCtx, workflowID, code, summary, time.Now().UTC())
}

func (s *Server) restoreWorkflowReconciler(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	s.resumeRestoreWorkflows(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.resumeRestoreWorkflows(ctx)
		}
	}
}

func (s *Server) resumeRestoreWorkflows(ctx context.Context) {
	ids, err := s.Store.ListResumableRestoreWorkflowIDs(ctx, 100)
	if err != nil {
		return
	}
	for _, id := range ids {
		s.queueRestoreWorkflow(ctx, id)
	}
}
