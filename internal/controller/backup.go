package controller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const (
	snapshotCapabilityTTL      = 8 * time.Hour
	snapshotWorkflowLeaseTTL   = 30 * time.Second
	snapshotWorkflowLeaseRenew = 10 * time.Second
	snapshotWorkflowCommandTTL = 8 * time.Hour
)

// scheduleOfflineBackups 扫描所有用户副本, 找出"已离线且数据有变化、配置了备份目标"的用户, 触发备份。
// 触发条件: 家节点在线 + 用户在节点上 isOnline=false 且 lastActivity 超过保护期 + 当前无 running 备份。
func (s *Server) scheduleOfflineBackups(ctx context.Context) {
	if s.checkNewOperations() != nil {
		return
	}
	grace := time.Duration(s.Cfg.Backup.OfflineGraceMin) * time.Minute
	nowMs := time.Now().UnixMilli()

	s.actMu.Lock()
	activity := make(map[int64]map[string]protocol.UserStatus, len(s.activity))
	for nodeID, nodeFacts := range s.activity {
		copied := make(map[string]protocol.UserStatus, len(nodeFacts))
		for handle, fact := range nodeFacts {
			copied[handle] = fact
		}
		activity[nodeID] = copied
	}
	s.actMu.Unlock()

	storageRepairUsers, err := s.Store.ListActiveStorageRepairUserIDs(ctx)
	if err != nil {
		return
	}
	users, err := s.Store.ListUsers(ctx)
	if err != nil {
		return
	}
	for _, u := range users {
		if u.Status != "active" || !u.HomeNodeID.Valid {
			continue
		}
		if _, repairing := storageRepairUsers[u.GlobalID]; repairing {
			continue
		}
		nodeID := u.HomeNodeID.Int64
		// 找到家节点上该用户的在线状态
		st, ok := activity[nodeID][u.Username]
		if !ok {
			continue
		}
		if st.IsOnline {
			continue // 在线不备份
		}
		if nowMs-st.LastActivity < grace.Milliseconds() {
			continue // 离线时间不足保护期
		}
		// 已有 running 备份则跳过
		if job, _ := s.Store.FindRunningBackupForUserOnNode(ctx, u.ID, nodeID); job != nil {
			continue
		}
		// 触发备份
		_ = s.TriggerUserBackup(ctx, u.ID, nodeID, "offline")
	}
}

// TriggerUserBackup 为某用户在家节点触发一次备份到配置的备份目标。
// 目标选择: 优先该用户已配置的热备/存储副本; 否则系统默认存储节点。
func (s *Server) TriggerUserBackup(ctx context.Context, userID, srcNodeID int64, trigger string) error {
	if err := s.checkNewOperations(); err != nil {
		return err
	}
	if trigger == "storage_repair" {
		return fmt.Errorf("storage repair must be created by the durable repair reconciler")
	}
	user, err := s.Store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return err
	}
	srcNode, err := s.Store.GetNodeByID(ctx, srcNodeID)
	if err != nil || srcNode == nil {
		return err
	}

	dstNode, dstKind := s.pickBackupTarget(ctx, userID, srcNodeID)
	if dstNode == nil {
		return nil // 无可用备份目标, 跳过
	}

	if dstNode.TransferURL == "" {
		return fmt.Errorf("目标节点未提供 HTTPS 快照数据面")
	}

	// The legacy job remains a compatibility read model. Durable workflow,
	// snapshot, and capability facts are created before either Agent mutates.
	job := &store.BackupJob{
		UserID: userID, SrcNodeID: srcNodeID, DstNodeID: dstNode.ID,
		Trigger: trigger, Status: "pending",
	}
	if err := s.Store.CreateBackupJob(ctx, job); err != nil {
		return err
	}
	workflowID, err := newUUID()
	if err != nil {
		return err
	}
	operationID, err := newUUID()
	if err != nil {
		return err
	}
	snapshotID, err := newUUID()
	if err != nil {
		return err
	}
	capabilityID, err := newUUID()
	if err != nil {
		return err
	}
	capability := deriveTransferCapability(s.secretKey, capabilityID)
	capabilityHash := sha256.Sum256([]byte(capability))
	now := time.Now().UTC()
	capabilityExpires := now.Add(snapshotCapabilityTTL)
	workflow, err := s.Store.CreateSnapshotWorkflow(ctx, store.CreateSnapshotWorkflowParams{
		WorkflowID: workflowID, OperationID: operationID, SnapshotID: snapshotID,
		CapabilityID: capabilityID, CapabilityHash: capabilityHash[:],
		LegacyBackupJobID: job.ID, LegacyUserID: user.ID, GlobalUserID: user.GlobalID,
		SourceNodeID: srcNode.ID, TargetNodeID: dstNode.ID,
		DestinationKind:   dstKind,
		CapabilityExpires: capabilityExpires, Now: now,
	})
	if err != nil {
		_ = s.Store.UpdateBackupJobStatus(ctx, job.ID, "failed", 0, 0, 0, "快照工作流创建失败")
		return err
	}

	return s.executeSnapshotWorkflow(ctx, workflow.WorkflowID)
}

func (s *Server) executeSnapshotWorkflow(ctx context.Context, workflowID string) (resultErr error) {
	if s.workflowWorkerID == "" {
		return fmt.Errorf("snapshot worker identity unavailable")
	}
	leaseOwnerID, err := newUUID()
	if err != nil {
		return fmt.Errorf("create snapshot lease identity: %w", err)
	}
	claimed, err := s.Store.ClaimSnapshotWorkflow(ctx, workflowID, leaseOwnerID, time.Now().UTC(), snapshotWorkflowLeaseTTL)
	if err != nil || !claimed {
		return err
	}
	workflowCtx, cancelWorkflow := context.WithCancel(ctx)
	leaseDone := make(chan error, 1)
	go func() {
		leaseDone <- s.maintainSnapshotWorkflowLease(
			workflowCtx, cancelWorkflow, workflowID, leaseOwnerID,
		)
	}()
	defer func() {
		cancelWorkflow()
		if leaseErr := <-leaseDone; leaseErr != nil &&
			(resultErr == nil || errors.Is(resultErr, context.Canceled) || errors.Is(resultErr, context.DeadlineExceeded)) {
			resultErr = leaseErr
		}
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer releaseCancel()
		_ = s.Store.ReleaseSnapshotWorkflow(releaseCtx, workflowID, leaseOwnerID)
	}()
	ctx = workflowCtx
	execution, err := s.Store.GetSnapshotWorkflowExecution(ctx, workflowID)
	if err != nil || execution == nil {
		return err
	}
	if execution.State == "retry_wait" {
		if err := s.Store.ResumeSnapshotRetry(ctx, workflowID, time.Now().UTC()); err != nil {
			return err
		}
		execution, err = s.Store.GetSnapshotWorkflowExecution(ctx, workflowID)
		if err != nil || execution == nil {
			return err
		}
	}
	source, err := s.Store.GetNodeByID(ctx, execution.SourceNodeID)
	if err != nil || source == nil {
		return s.retrySnapshotWorkflow(ctx, execution, "source_unavailable", "源节点不可用", err)
	}
	target, err := s.Store.GetNodeByID(ctx, execution.TargetNodeID)
	if err != nil || target == nil || target.TransferURL == "" {
		return s.retrySnapshotWorkflow(ctx, execution, "target_unavailable", "目标数据面不可用", err)
	}
	if execution.DestinationKind == "hot_standby" {
		account, err := s.Store.GetWorkflowTargetAccountProvision(ctx, execution.WorkflowID)
		if err != nil || account == nil {
			return s.retrySnapshotWorkflow(ctx, execution, "target_account_unavailable", "目标账号准备事实不可用", err)
		}
		if account.Status == "pending" {
			if err := s.provisionSnapshotTargetAccount(ctx, execution, account, target); err != nil {
				return s.retrySnapshotWorkflow(ctx, execution, "target_account_provision_failed", "目标账号供应未完成", err)
			}
			account, err = s.Store.GetWorkflowTargetAccountProvision(ctx, execution.WorkflowID)
			if err != nil || account == nil {
				return s.retrySnapshotWorkflow(ctx, execution, "target_account_unavailable", "目标账号供应回执不可用", err)
			}
		}
		if account.Status != "active" {
			return s.retrySnapshotWorkflow(ctx, execution, "target_account_not_active", "目标账号尚未就绪", nil)
		}
	}
	if execution.State == "scheduled" {
		if err := s.Store.SetSnapshotWorkflowState(ctx, execution.WorkflowID, "scheduled", "quiescing", time.Now().UTC()); err != nil {
			return err
		}
		execution.State = "quiescing"
	}

	if execution.State == "publishing" {
		receipt, err := s.loadPublishedSnapshotReceipt(ctx, execution, target)
		if err != nil {
			return s.retrySnapshotWorkflow(ctx, execution, "receipt_unavailable", "目标发布回执暂不可用", err)
		}
		return s.completeSnapshotExecution(ctx, execution, receipt)
	}
	if execution.CapabilityState != "prepared" || !execution.CapabilityExpires.After(time.Now().UTC().Add(2*time.Minute)) {
		if execution.State != "quiescing" || execution.CapabilityState == "consumed" {
			return s.retrySnapshotWorkflow(ctx, execution, "capability_expired", "传输授权已过期", nil)
		}
		if err := s.rotateSnapshotExecutionCapability(ctx, execution); err != nil {
			return s.retrySnapshotWorkflow(ctx, execution, "capability_rotate_failed", "传输授权轮换失败", err)
		}
		execution, err = s.Store.GetSnapshotWorkflowExecution(ctx, workflowID)
		if err != nil || execution == nil {
			return err
		}
	}
	capability := deriveTransferCapability(s.secretKey, execution.CapabilityID)
	derivedHash := sha256.Sum256([]byte(capability))
	if !hmac.Equal(derivedHash[:], execution.CapabilityHash) {
		job := snapshotExecutionJob(execution)
		s.failSnapshotWorkflow(ctx, job, workflowID, "capability_key_mismatch", "控制面密钥无法恢复传输授权")
		return fmt.Errorf("snapshot capability key mismatch")
	}
	capabilityHashHex := hex.EncodeToString(execution.CapabilityHash)
	if execution.TransferMode == "relay" {
		return s.executeRelaySnapshotWorkflow(ctx, execution, source, target, capability, capabilityHashHex)
	}
	if _, err := s.runAgentCommandWithOperation(ctx, target, "prepare_snapshot_receive", protocol.PrepareSnapshotReceiveRequest{
		WorkflowID: execution.WorkflowID, SnapshotID: execution.SnapshotID, GlobalUserID: execution.GlobalUserID,
		Handle: execution.Handle, DestinationKind: execution.DestinationKind, SourceNodeID: execution.SourceNodeID,
		ActivityEpoch: execution.ActivityEpoch, CapabilityHash: capabilityHashHex, ExpiresAt: execution.CapabilityExpires,
	}, deriveWorkflowOperationID(execution.WorkflowID, fmt.Sprintf("prepare-target:%s:%d", execution.CapabilityID, execution.Attempt)), 45*time.Second); err != nil {
		return s.retrySnapshotWorkflow(ctx, execution, "target_prepare_failed", "目标节点未确认接收准备", err)
	}
	if err := s.Store.CompleteSnapshotWorkflowStep(ctx, execution.WorkflowID, "prepare_target", time.Now().UTC()); err != nil {
		return err
	}
	_ = s.Store.UpdateBackupJobStatus(ctx, execution.LegacyBackupJobID, "running", 0, 0, 0, "")
	result, runErr := s.runAgentCommandWithOperation(ctx, source, "start_snapshot", protocol.StartSnapshotRequest{
		JobID: execution.LegacyBackupJobID, WorkflowID: execution.WorkflowID, SnapshotID: execution.SnapshotID,
		GlobalUserID: execution.GlobalUserID, Handle: execution.Handle, ActivityEpoch: execution.ActivityEpoch,
		TargetNodeID: execution.TargetNodeID, TargetTransferURL: target.TransferURL,
		TransferCapability: capability, CapabilityExpires: execution.CapabilityExpires,
		DestinationKind: execution.DestinationKind,
	}, deriveWorkflowOperationID(execution.WorkflowID, fmt.Sprintf("start-source:%s:%d", execution.CapabilityID, execution.Attempt)), snapshotWorkflowCommandTTL)
	if runErr != nil || result.Snapshot == nil {
		latest, _ := s.Store.GetSnapshotWorkflowExecution(ctx, workflowID)
		if latest != nil && latest.State == "publishing" {
			receipt, receiptErr := s.loadPublishedSnapshotReceipt(ctx, latest, target)
			if receiptErr == nil {
				return s.completeSnapshotExecution(ctx, latest, receipt)
			}
		}
		if agentCommandErrorCode(runErr) == "snapshot_direct_unreachable" && s.relayAvailable() {
			if err := s.Store.SwitchSnapshotWorkflowToRelay(ctx, workflowID, time.Now().UTC()); err != nil {
				return s.retrySnapshotWorkflow(ctx, execution, "relay_switch_failed", "直连失败且无法切换加密中转", err)
			}
			execution.TransferMode = "relay"
			return s.retrySnapshotWorkflow(ctx, execution, "direct_unreachable_relay_queued", "节点直连失败，已排队使用端到端加密中转", runErr)
		}
		return s.retrySnapshotWorkflow(ctx, execution, "snapshot_failed", "源或目标节点未完成快照", runErr)
	}
	if result.Snapshot.RelayPending {
		return s.retrySnapshotWorkflow(ctx, execution, "unexpected_relay_receipt", "直连传输返回了无效中转回执", nil)
	}
	return s.completeSnapshotExecution(ctx, execution, result.Snapshot)
}

func (s *Server) maintainSnapshotWorkflowLease(
	ctx context.Context,
	cancel context.CancelFunc,
	workflowID, workerID string,
) error {
	return s.maintainSnapshotWorkflowLeaseWithTiming(
		ctx, cancel, workflowID, workerID, snapshotWorkflowLeaseRenew, snapshotWorkflowLeaseTTL,
	)
}

func (s *Server) maintainSnapshotWorkflowLeaseWithTiming(
	ctx context.Context,
	cancel context.CancelFunc,
	workflowID, workerID string,
	renewEvery, leaseTTL time.Duration,
) error {
	ticker := time.NewTicker(renewEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			renewTimeout := renewEvery / 2
			if renewTimeout < time.Second {
				renewTimeout = time.Second
			}
			renewCtx, renewCancel := context.WithTimeout(ctx, renewTimeout)
			err := s.Store.RenewSnapshotWorkflow(
				renewCtx, workflowID, workerID, now.UTC(), leaseTTL,
			)
			renewCancel()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				cancel()
				return fmt.Errorf("snapshot workflow lease renewal failed: %w", err)
			}
		}
	}
}

func (s *Server) loadPublishedSnapshotReceipt(
	ctx context.Context,
	execution *store.SnapshotWorkflowExecution,
	target *store.Node,
) (*protocol.SnapshotTransferReceipt, error) {
	result, err := s.runAgentCommandWithOperation(ctx, target, "get_snapshot_receipt", map[string]string{
		"workflow_id": execution.WorkflowID, "snapshot_id": execution.SnapshotID,
	}, deriveWorkflowOperationID(execution.WorkflowID, fmt.Sprintf("target-receipt:%s:%d", execution.CapabilityID, execution.Attempt)), 45*time.Second)
	if err != nil || result.Snapshot == nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("snapshot receipt missing")
	}
	return result.Snapshot, nil
}

func (s *Server) completeSnapshotExecution(
	ctx context.Context,
	execution *store.SnapshotWorkflowExecution,
	receipt *protocol.SnapshotTransferReceipt,
) error {
	if receipt == nil || receipt.RelayPending || receipt.SnapshotID != execution.SnapshotID {
		return fmt.Errorf("snapshot receipt scope mismatch")
	}
	manifestDigest, err := decodeSnapshotDigest(receipt.ManifestSHA256)
	if err != nil {
		return err
	}
	archiveDigest, err := decodeSnapshotDigest(receipt.ArchiveSHA256)
	if err != nil {
		return err
	}
	_, err = s.Store.CompleteSnapshotWorkflow(ctx, store.CompleteSnapshotWorkflowParams{
		WorkflowID: execution.WorkflowID, SnapshotID: execution.SnapshotID,
		CapabilityHash: execution.CapabilityHash, TargetNodeID: execution.TargetNodeID,
		ReplicaKind: execution.DestinationKind, ReplicaOrigin: snapshotReplicaOrigin(execution.Trigger),
		ManifestSHA256: manifestDigest, ArchiveSHA256: archiveDigest,
		FileCount: receipt.FileCount, TotalBytes: receipt.TotalBytes, Now: time.Now().UTC(),
	})
	return err
}

func snapshotReplicaOrigin(trigger string) string {
	if trigger == "storage_repair" {
		return "automatic_repair"
	}
	if trigger == "node_retirement" || trigger == "node_retirement_storage" {
		return "migration"
	}
	return "configured"
}

func (s *Server) provisionSnapshotTargetAccount(
	ctx context.Context,
	execution *store.SnapshotWorkflowExecution,
	account *store.WorkflowTargetAccountProvision,
	target *store.Node,
) error {
	request := protocol.RestoreUserAccountRequest{
		WorkflowID: account.WorkflowID, GlobalUserID: account.GlobalUserID,
		Handle: account.Handle, Name: account.DisplayName, AccountVersion: account.AccountVersion,
		PasswordHash: account.PasswordHash, PasswordSalt: account.PasswordSalt,
		OAuthProvider: account.OAuthProvider, OAuthSubject: account.OAuthSubject,
	}
	result, err := s.runAgentCommandWithOperation(
		ctx, target, "restore_user_account", request,
		deriveWorkflowOperationID(account.WorkflowID, fmt.Sprintf("snapshot-account:%d:%d", account.AccountVersion, execution.Attempt)),
		90*time.Second,
	)
	if err != nil || result.LocalUserID == "" {
		if err != nil {
			return err
		}
		return fmt.Errorf("snapshot target account identity missing")
	}
	return s.Store.CompleteWorkflowTargetAccountProvision(
		ctx, account.WorkflowID, account.AccountVersion, result.LocalUserID, time.Now().UTC(),
	)
}

func (s *Server) rotateSnapshotExecutionCapability(ctx context.Context, execution *store.SnapshotWorkflowExecution) error {
	capabilityID, err := newUUID()
	if err != nil {
		return err
	}
	capability := deriveTransferCapability(s.secretKey, capabilityID)
	digest := sha256.Sum256([]byte(capability))
	now := time.Now().UTC()
	return s.Store.RotateSnapshotCapability(
		ctx, execution.WorkflowID, capabilityID, digest[:], now.Add(snapshotCapabilityTTL), now,
	)
}

func (s *Server) retrySnapshotWorkflow(
	ctx context.Context,
	execution *store.SnapshotWorkflowExecution,
	code, summary string,
	cause error,
) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	job := snapshotExecutionJob(execution)
	current, err := s.Store.GetBackupJob(ctx, job.ID)
	if err != nil {
		return err
	}
	if current != nil && current.Status == "aborted" {
		if err := s.Store.CancelSnapshotWorkflow(ctx, execution.WorkflowID, "用户恢复使用，取消未发布快照", time.Now().UTC()); err != nil {
			return err
		}
		return fmt.Errorf("snapshot workflow aborted")
	}
	delay := 5 * time.Second
	for i := 0; i < execution.Attempt && delay < 5*time.Minute; i++ {
		delay *= 2
	}
	attempt, err := s.Store.ScheduleSnapshotRetry(ctx, execution.WorkflowID, code, summary, time.Now().UTC(), delay)
	if err != nil {
		return err
	}
	maxAttempts := s.Cfg.Backup.RetryMax
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	if attempt >= maxAttempts {
		s.failSnapshotWorkflow(ctx, job, execution.WorkflowID, code, summary)
	}
	if cause != nil {
		return cause
	}
	return fmt.Errorf("%s", code)
}

func snapshotExecutionJob(execution *store.SnapshotWorkflowExecution) *store.BackupJob {
	return &store.BackupJob{
		ID: execution.LegacyBackupJobID, UserID: execution.LegacyUserID,
		SrcNodeID: execution.SourceNodeID, DstNodeID: execution.TargetNodeID,
	}
}

func (s *Server) snapshotWorkflowReconciler(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	s.resumeSnapshotWorkflows(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.resumeSnapshotWorkflows(ctx)
		}
	}
}

func (s *Server) resumeSnapshotWorkflows(ctx context.Context) {
	ids, err := s.Store.ListResumableSnapshotWorkflowIDs(ctx, 100)
	if err != nil {
		return
	}
	for _, id := range ids {
		select {
		case s.snapshotSlots <- struct{}{}:
			go func(workflowID string) {
				defer func() { <-s.snapshotSlots }()
				_ = s.executeSnapshotWorkflow(ctx, workflowID)
			}(id)
		default:
			return
		}
	}
}

func (s *Server) failSnapshotWorkflow(ctx context.Context, job *store.BackupJob, workflowID, code, summary string) {
	if current, _ := s.Store.GetBackupJob(ctx, job.ID); current != nil && current.Status == "aborted" {
		_ = s.Store.CancelSnapshotWorkflow(ctx, workflowID, "用户恢复使用，取消未发布快照", time.Now().UTC())
		return
	}
	_ = s.Store.FailSnapshotWorkflow(ctx, workflowID, code, summary, time.Now().UTC())
}

func decodeSnapshotDigest(value string) ([]byte, error) {
	digest, err := hex.DecodeString(value)
	if err != nil || len(digest) != sha256.Size {
		return nil, fmt.Errorf("invalid snapshot digest")
	}
	return digest, nil
}

func deriveTransferCapability(key []byte, capabilityID string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("stcontrol-snapshot-transfer:v1:" + capabilityID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func deriveWorkflowOperationID(workflowID, step string) string {
	digest := sha256.Sum256([]byte("stcontrol-workflow-operation:v1:" + workflowID + ":" + step))
	digest[6] = (digest[6] & 0x0f) | 0x40
	digest[8] = (digest[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(digest[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}

// pickBackupTarget 为用户选备份目标。
// 优先: 该用户已存在且 ready 的 archive，其次 hot_standby；绝不把
// stale/deleting/error 物理目录重新选为新发布目标。
// 否则: 系统内第一台 is_backup_target 且在线的节点。
func (s *Server) pickBackupTarget(ctx context.Context, userID, srcNodeID int64) (*store.Node, string) {
	replicas, _ := s.Store.ListReplicasByUser(ctx, userID)
	for _, kind := range []string{"archive", "hot_standby"} {
		for _, rep := range replicas {
			if rep.Kind != kind || rep.State != "ready" {
				continue
			}
			if rep.NodeID == srcNodeID {
				continue
			}
			n, err := s.Store.GetNodeByID(ctx, rep.NodeID)
			if err == nil && n != nil && nodeAcceptsNewData(n) &&
				((kind == "archive" && n.Role == "storage") || (kind == "hot_standby" && n.Role == "compute")) {
				return n, rep.Kind
			}
		}
	}
	// 默认存储节点
	nodes, _ := s.Store.ListNodes(ctx)
	for _, n := range nodes {
		if n.ID == srcNodeID {
			continue
		}
		if n.IsBackupTarget && nodeAcceptsNewData(n) {
			kind := "archive"
			if n.Role == "compute" {
				kind = "hot_standby"
			}
			return n, kind
		}
	}
	return nil, ""
}

func (s *Server) pickStorageRepairTarget(ctx context.Context, srcNodeID int64) *store.Node {
	nodes, err := s.Store.ListNodes(ctx)
	if err != nil {
		return nil
	}
	return chooseStorageRepairTarget(nodes, srcNodeID)
}

func chooseStorageRepairTarget(nodes []*store.Node, srcNodeID int64) *store.Node {
	var best *store.Node
	for _, node := range nodes {
		if node == nil || node.ID == srcNodeID || node.Role != "storage" || !node.IsBackupTarget ||
			node.TransferURL == "" || !nodeAcceptsNewData(node) {
			continue
		}
		if best == nil || (best.CapacityState == "busy" && node.CapacityState == "open") ||
			(best.CapacityState == node.CapacityState && node.ID < best.ID) {
			best = node
		}
	}
	return best
}
