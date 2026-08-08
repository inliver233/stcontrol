package controller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

type snapshotRelayExecution struct {
	TaskID        string
	Endpoint      string
	UploadToken   string
	DownloadToken string
}

func (s *Server) relayAvailable() bool {
	return s.Cfg != nil && s.Cfg.Relay.Listen != "" && s.Cfg.Relay.PublicURL != "" &&
		s.Cfg.Relay.MaxBytes > 0 && s.Cfg.Relay.RetentionMin > 0
}

func (s *Server) prepareSnapshotRelay(
	ctx context.Context,
	execution *store.SnapshotWorkflowExecution,
) (snapshotRelayExecution, error) {
	if !s.relayAvailable() || execution == nil || execution.TransferMode != "relay" {
		return snapshotRelayExecution{}, fmt.Errorf("encrypted snapshot relay is unavailable")
	}
	taskID := deriveWorkflowOperationID(execution.WorkflowID, fmt.Sprintf("relay-task:%d", execution.Attempt))
	uploadToken := deriveRelayBearer(s.secretKey, taskID, "upload")
	downloadToken := deriveRelayBearer(s.secretKey, taskID, "download")
	uploadHash := sha256.Sum256([]byte(uploadToken))
	downloadHash := sha256.Sum256([]byte(downloadToken))
	now := time.Now().UTC()
	transfer, err := s.Store.CreateRelayTransfer(ctx, store.CreateRelayTransferParams{
		ID: taskID, WorkflowID: execution.WorkflowID, SnapshotID: execution.SnapshotID,
		SourceNodeID: execution.SourceNodeID, TargetNodeID: execution.TargetNodeID,
		Attempt: execution.Attempt, UploadTokenHash: uploadHash[:], DownloadTokenHash: downloadHash[:],
		MaxCiphertextBytes: s.Cfg.Relay.MaxBytes,
		ExpiresAt:          now.Add(time.Duration(s.Cfg.Relay.RetentionMin) * time.Minute), Now: now,
	})
	if err != nil {
		return snapshotRelayExecution{}, err
	}
	if transfer == nil || transfer.ID != taskID || !transfer.ExpiresAt.After(now) ||
		transfer.State == "expired" || transfer.State == "failed" {
		return snapshotRelayExecution{}, fmt.Errorf("encrypted snapshot relay task is not usable")
	}
	endpoint, err := snapshotRelayEndpoint(s.Cfg.Relay.PublicURL, taskID)
	if err != nil {
		return snapshotRelayExecution{}, err
	}
	return snapshotRelayExecution{
		TaskID: taskID, Endpoint: endpoint,
		UploadToken: uploadToken, DownloadToken: downloadToken,
	}, nil
}

func (s *Server) executeRelaySnapshotWorkflow(
	ctx context.Context,
	execution *store.SnapshotWorkflowExecution,
	source, target *store.Node,
	capability, capabilityHashHex string,
) error {
	relay, err := s.prepareSnapshotRelay(ctx, execution)
	if err != nil {
		return s.retrySnapshotWorkflow(ctx, execution, "relay_prepare_failed", "加密中转任务准备失败", err)
	}
	prepareResult, err := s.runAgentCommandWithOperation(
		ctx, target, "prepare_snapshot_receive", protocol.PrepareSnapshotReceiveRequest{
			WorkflowID: execution.WorkflowID, SnapshotID: execution.SnapshotID,
			GlobalUserID: execution.GlobalUserID, Handle: execution.Handle,
			DestinationKind: execution.DestinationKind, SourceNodeID: execution.SourceNodeID,
			ActivityEpoch: execution.ActivityEpoch, CapabilityHash: capabilityHashHex,
			ExpiresAt: execution.CapabilityExpires, RelayTaskID: relay.TaskID,
		}, deriveWorkflowOperationID(execution.WorkflowID, fmt.Sprintf(
			"prepare-relay-target:%s:%d", execution.CapabilityID, execution.Attempt,
		)), 45*time.Second,
	)
	if err != nil || prepareResult.RelayPublicKey == "" {
		return s.retrySnapshotWorkflow(ctx, execution, "relay_target_prepare_failed", "目标节点未确认加密中转接收准备", err)
	}
	if err := s.Store.CompleteSnapshotWorkflowStep(ctx, execution.WorkflowID, "prepare_target", time.Now().UTC()); err != nil {
		return err
	}
	_ = s.Store.UpdateBackupJobStatus(ctx, execution.LegacyBackupJobID, "running", 0, 0, 0, "")
	receivePayload := protocol.StartRelayReceiveRequest{
		WorkflowID: execution.WorkflowID, SnapshotID: execution.SnapshotID, RelayTaskID: relay.TaskID,
		RelayDownloadURL: relay.Endpoint, RelayDownloadToken: relay.DownloadToken,
		TransferCapability: capability, CapabilityExpires: execution.CapabilityExpires,
	}
	receiveOperationID := deriveWorkflowOperationID(
		execution.WorkflowID, fmt.Sprintf("receive-relay:%s:%d", relay.TaskID, execution.Attempt),
	)
	if _, err := s.enqueueAgentCommand(ctx, target, "start_relay_receive", receivePayload, receiveOperationID); err != nil {
		return s.retrySnapshotWorkflow(ctx, execution, "relay_receiver_enqueue_failed", "目标节点加密中转接收任务排队失败", err)
	}
	sourceResult, sourceErr := s.runAgentCommandWithOperation(
		ctx, source, "start_snapshot", protocol.StartSnapshotRequest{
			JobID: execution.LegacyBackupJobID, WorkflowID: execution.WorkflowID,
			SnapshotID: execution.SnapshotID, GlobalUserID: execution.GlobalUserID,
			Handle: execution.Handle, ActivityEpoch: execution.ActivityEpoch,
			TargetNodeID: execution.TargetNodeID, TransferCapability: capability,
			CapabilityExpires: execution.CapabilityExpires, DestinationKind: execution.DestinationKind,
			TransferMode: "relay", RelayTaskID: relay.TaskID, RelayUploadURL: relay.Endpoint,
			RelayUploadToken: relay.UploadToken, RelayTargetKey: prepareResult.RelayPublicKey,
		}, deriveWorkflowOperationID(execution.WorkflowID, fmt.Sprintf(
			"start-relay-source:%s:%d", relay.TaskID, execution.Attempt,
		)), snapshotWorkflowCommandTTL,
	)
	if sourceErr != nil || sourceResult.Snapshot == nil || !sourceResult.Snapshot.RelayPending {
		return s.recoverOrRetryRelaySnapshot(ctx, execution, target, "relay_upload_failed", "源节点未完成加密中转上传", sourceErr)
	}
	targetResult, targetErr := s.runAgentCommandWithOperation(
		ctx, target, "start_relay_receive", receivePayload, receiveOperationID, snapshotWorkflowCommandTTL,
	)
	if targetErr != nil || targetResult.Snapshot == nil {
		return s.recoverOrRetryRelaySnapshot(ctx, execution, target, "relay_receive_failed", "目标节点未完成加密中转接收", targetErr)
	}
	if !matchingRelayReceipts(sourceResult.Snapshot, targetResult.Snapshot) {
		return s.retrySnapshotWorkflow(ctx, execution, "relay_receipt_mismatch", "加密中转两端回执不一致", nil)
	}
	return s.completeSnapshotExecution(ctx, execution, targetResult.Snapshot)
}

func (s *Server) recoverOrRetryRelaySnapshot(
	ctx context.Context,
	execution *store.SnapshotWorkflowExecution,
	target *store.Node,
	code, summary string,
	cause error,
) error {
	latest, _ := s.Store.GetSnapshotWorkflowExecution(ctx, execution.WorkflowID)
	if latest != nil && latest.State == "publishing" {
		if receipt, err := s.loadPublishedSnapshotReceipt(ctx, latest, target); err == nil {
			return s.completeSnapshotExecution(ctx, latest, receipt)
		}
	}
	return s.retrySnapshotWorkflow(ctx, execution, code, summary, cause)
}

func matchingRelayReceipts(source, target *protocol.SnapshotTransferReceipt) bool {
	return source != nil && target != nil && source.RelayPending && !target.RelayPending &&
		source.SnapshotID == target.SnapshotID && source.ManifestSHA256 == target.ManifestSHA256 &&
		source.ArchiveSHA256 == target.ArchiveSHA256 && source.FileCount == target.FileCount &&
		source.TotalBytes == target.TotalBytes
}

func deriveRelayBearer(key []byte, taskID, purpose string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("stcontrol-relay-bearer:v1:" + purpose + ":" + taskID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func snapshotRelayEndpoint(publicURL, taskID string) (string, error) {
	base, err := url.Parse(publicURL)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" ||
		(base.Scheme != "https" && base.Scheme != "http") || !isUUID(taskID) {
		return "", fmt.Errorf("invalid encrypted relay public URL")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/relay/v1/transfers/" + taskID
	return base.String(), nil
}
