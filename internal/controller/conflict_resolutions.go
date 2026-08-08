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
	"sort"
	"time"

	"github.com/go-chi/chi/v5"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

type conflictResolutionDecisionRequest struct {
	Path         string `json:"path"`
	SourceNodeID int64  `json:"source_node_id"`
	Action       string `json:"action"`
}

type startConflictResolutionRequest struct {
	OperationID             string                              `json:"operation_id"`
	ExpectedConflictVersion int64                               `json:"expected_conflict_version"`
	BaseNodeID              int64                               `json:"base_node_id"`
	DefaultAction           string                              `json:"default_action"`
	AcknowledgeFreeze       bool                                `json:"acknowledge_freeze"`
	Decisions               []conflictResolutionDecisionRequest `json:"decisions"`
}

type publicConflictResolutionStatus struct {
	OperationID  string `json:"operation_id"`
	State        string `json:"state"`
	BaseNodeID   int64  `json:"base_node_id"`
	BaseNodeName string `json:"base_node_name"`
	Error        string `json:"error,omitempty"`
}

func (s *Server) handleStartConflictResolution(w http.ResponseWriter, r *http.Request) {
	var req startConflictResolutionRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		!isUUID(req.OperationID) || req.ExpectedConflictVersion <= 0 || req.BaseNodeID <= 0 ||
		!req.AcknowledgeFreeze || len(req.Decisions) > 100000 ||
		(req.DefaultAction != "use_base" && req.DefaultAction != "preserve_all_originals") {
		protocol.WriteError(w, http.StatusBadRequest, "必须确认冲突处理会继续冻结写入，并选择有效的主来源")
		return
	}
	sess := currentSession(r)
	if sess == nil || sess.GlobalUserID <= 0 || sess.IsAdmin {
		protocol.WriteError(w, http.StatusUnauthorized, "需要冲突恢复认证")
		return
	}
	conflict, err := s.Store.GetOpenReplicaConflict(r.Context(), sess.GlobalUserID)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "读取冲突事实失败")
		return
	}
	if conflict == nil || conflict.State != "awaiting_decision" || conflict.Version != req.ExpectedConflictVersion {
		protocol.WriteError(w, http.StatusConflict, "冲突证据或版本已变化，请刷新后重新确认")
		return
	}
	entriesByNode, err := s.loadAllConflictEvidence(r.Context(), conflict)
	if err != nil {
		protocol.WriteError(w, http.StatusConflict, "冲突证据尚未完整验证")
		return
	}
	decisions, err := validateConflictResolutionChoices(conflict, entriesByNode, req)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	requestDigest, err := s.conflictResolutionDigest(sess.GlobalUserID, conflict.ID, req, decisions)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成冲突处理请求失败")
		return
	}
	workflowID, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成冲突处理任务失败")
		return
	}
	resultSnapshotID, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成冲突处理任务失败")
		return
	}
	now := time.Now().UTC()
	transfers := make([]store.ConflictResolutionTransferInput, 0, len(conflict.Sources)-1)
	for _, source := range conflict.Sources {
		if source.NodeID == req.BaseNodeID {
			continue
		}
		capabilityID, err := newUUID()
		if err != nil {
			protocol.WriteError(w, http.StatusInternalServerError, "生成证据传输授权失败")
			return
		}
		capability := deriveTransferCapability(s.secretKey, capabilityID)
		digest := sha256.Sum256([]byte(capability))
		transfers = append(transfers, store.ConflictResolutionTransferInput{
			EvidenceID: source.EvidenceID, SourceNodeID: source.NodeID,
			CapabilityID: capabilityID, CapabilityHash: digest[:], ExpiresAt: now.Add(15 * time.Minute),
		})
	}
	execution, err := s.Store.CreateConflictResolution(r.Context(), store.CreateConflictResolutionParams{
		OperationID: req.OperationID, RequestDigest: requestDigest, WorkflowID: workflowID,
		ConflictID: conflict.ID, ResultSnapshotID: resultSnapshotID, GlobalUserID: sess.GlobalUserID,
		BaseNodeID: req.BaseNodeID, ExpectedConflictVersion: req.ExpectedConflictVersion,
		DefaultAction: req.DefaultAction, Decisions: decisions, Transfers: transfers, Now: now,
	})
	if err != nil {
		s.writeConflictResolutionError(w, err)
		return
	}
	s.queueConflictResolution(context.WithoutCancel(r.Context()), execution.WorkflowID)
	status, err := s.Store.GetConflictResolutionStatus(r.Context(), sess.GlobalUserID, req.OperationID)
	if err != nil || status == nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "冲突处理已安全排队，状态暂不可用")
		return
	}
	protocol.WriteJSON(w, http.StatusAccepted, publicConflictResolution(status))
}

func (s *Server) handleConflictResolutionStatus(w http.ResponseWriter, r *http.Request) {
	operationID := chi.URLParam(r, "operationID")
	if !isUUID(operationID) {
		protocol.WriteError(w, http.StatusBadRequest, "冲突处理操作 ID 无效")
		return
	}
	sess := currentSession(r)
	if sess == nil || sess.GlobalUserID <= 0 || sess.IsAdmin {
		protocol.WriteError(w, http.StatusUnauthorized, "需要冲突恢复认证")
		return
	}
	status, err := s.Store.GetConflictResolutionStatus(r.Context(), sess.GlobalUserID, operationID)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "冲突处理状态暂不可用")
		return
	}
	if status == nil {
		protocol.WriteError(w, http.StatusNotFound, "冲突处理操作不存在")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, publicConflictResolution(status))
}

func (s *Server) handleRetryConflictResolution(w http.ResponseWriter, r *http.Request) {
	operationID := chi.URLParam(r, "operationID")
	if !isUUID(operationID) {
		protocol.WriteError(w, http.StatusBadRequest, "冲突处理操作 ID 无效")
		return
	}
	sess := currentSession(r)
	if sess == nil || sess.GlobalUserID <= 0 || sess.IsAdmin {
		protocol.WriteError(w, http.StatusUnauthorized, "需要冲突恢复认证")
		return
	}
	_, err := s.Store.RestartConflictResolution(r.Context(), sess.GlobalUserID, operationID, time.Now().UTC())
	if err != nil {
		s.writeConflictResolutionError(w, err)
		return
	}
	executionStatus, err := s.Store.GetConflictResolutionStatus(r.Context(), sess.GlobalUserID, operationID)
	if err != nil || executionStatus == nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "冲突处理已重新排队，状态暂不可用")
		return
	}
	execution, err := s.Store.GetConflictResolutionExecutionByOperation(r.Context(), operationID)
	if err == nil && execution != nil {
		s.queueConflictResolution(context.WithoutCancel(r.Context()), execution.WorkflowID)
	}
	protocol.WriteJSON(w, http.StatusAccepted, publicConflictResolution(executionStatus))
}

func publicConflictResolution(status *store.ConflictResolutionStatus) publicConflictResolutionStatus {
	state := status.State
	switch state {
	case "scheduled", "transferring":
		state = "preparing"
	case "publishing":
		state = "publishing"
	case "retry_wait":
		state = "retrying"
	case "cancelled":
		state = "failed"
	}
	return publicConflictResolutionStatus{
		OperationID: status.OperationID, State: state, BaseNodeID: status.BaseNodeID,
		BaseNodeName: status.BaseNodeName, Error: status.ErrorSummary,
	}
}

func (s *Server) loadAllConflictEvidence(
	ctx context.Context,
	conflict *store.ReplicaConflict,
) (map[int64]map[string]protocol.ManifestEntry, error) {
	out := make(map[int64]map[string]protocol.ManifestEntry, len(conflict.Sources))
	for _, source := range conflict.Sources {
		if source.EvidenceState != "ready" {
			return nil, fmt.Errorf("conflict evidence incomplete")
		}
		entries, err := s.loadConflictEvidenceEntries(ctx, conflict.ID, source)
		if err != nil {
			return nil, err
		}
		byPath := make(map[string]protocol.ManifestEntry, len(entries))
		for _, entry := range entries {
			byPath[entry.Path] = entry
		}
		out[source.NodeID] = byPath
	}
	return out, nil
}

func validateConflictResolutionChoices(
	conflict *store.ReplicaConflict,
	entriesByNode map[int64]map[string]protocol.ManifestEntry,
	req startConflictResolutionRequest,
) ([]store.ConflictResolutionDecision, error) {
	baseIsCompute := false
	for _, source := range conflict.Sources {
		if source.NodeID == req.BaseNodeID && source.NodeRole == "compute" {
			baseIsCompute = true
		}
	}
	if !baseIsCompute {
		return nil, fmt.Errorf("主来源必须是可恢复写入的计算节点")
	}
	decisions := make(map[string]store.ConflictResolutionDecision, len(req.Decisions))
	for _, item := range req.Decisions {
		if item.Path == "" || len(item.Path) > 4096 || item.SourceNodeID <= 0 ||
			(item.Action != "use_source" && item.Action != "preserve_both") {
			return nil, fmt.Errorf("存在无效的逐文件选择")
		}
		if _, exists := decisions[item.Path]; exists {
			return nil, fmt.Errorf("同一路径不能重复选择")
		}
		decisions[item.Path] = store.ConflictResolutionDecision{
			Path: item.Path, SourceNodeID: item.SourceNodeID, Action: item.Action,
		}
	}
	allPaths := make(map[string]struct{})
	for _, entries := range entriesByNode {
		for path := range entries {
			allPaths[path] = struct{}{}
		}
	}
	for path := range allPaths {
		versions := make(map[string]struct{})
		for _, source := range conflict.Sources {
			if entry, ok := entriesByNode[source.NodeID][path]; ok {
				versions[entry.SHA256+fmt.Sprintf(":%d", entry.Size)] = struct{}{}
			}
		}
		decision, hasDecision := decisions[path]
		if len(versions) <= 1 {
			if hasDecision {
				return nil, fmt.Errorf("只有同路径内容不同时才需要逐文件选择")
			}
			continue
		}
		if hasDecision {
			if _, present := entriesByNode[decision.SourceNodeID][path]; !present {
				return nil, fmt.Errorf("所选来源不包含该路径")
			}
			continue
		}
		if _, baseHasPath := entriesByNode[req.BaseNodeID][path]; !baseHasPath {
			return nil, fmt.Errorf("有同路径冲突未包含主来源，必须逐项选择")
		}
	}
	for path := range decisions {
		if _, exists := allPaths[path]; !exists {
			return nil, fmt.Errorf("逐文件选择包含不存在的路径")
		}
	}
	out := make([]store.ConflictResolutionDecision, 0, len(decisions))
	for _, decision := range decisions {
		out = append(out, decision)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (s *Server) conflictResolutionDigest(
	userID int64,
	conflictID string,
	req startConflictResolutionRequest,
	decisions []store.ConflictResolutionDecision,
) ([]byte, error) {
	encoded, err := json.Marshal(struct {
		UserID        int64                              `json:"user_id"`
		ConflictID    string                             `json:"conflict_id"`
		Version       int64                              `json:"version"`
		BaseNodeID    int64                              `json:"base_node_id"`
		DefaultAction string                             `json:"default_action"`
		Acknowledge   bool                               `json:"acknowledge"`
		Decisions     []store.ConflictResolutionDecision `json:"decisions"`
	}{userID, conflictID, req.ExpectedConflictVersion, req.BaseNodeID, req.DefaultAction,
		req.AcknowledgeFreeze, decisions})
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.secretKey)
	_, _ = mac.Write([]byte("stcontrol-conflict-resolution:v1\n"))
	_, _ = mac.Write(encoded)
	return mac.Sum(nil), nil
}

func (s *Server) writeConflictResolutionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrConflictResolutionState):
		protocol.WriteError(w, http.StatusConflict, "冲突证据、节点状态或冻结状态已变化")
	case errors.Is(err, store.ErrConflictResolutionReplay):
		protocol.WriteError(w, http.StatusConflict, "重复操作与已保存的冲突处理请求不一致")
	case errors.Is(err, store.ErrNoActiveController):
		protocol.WriteError(w, http.StatusServiceUnavailable, "总控当前为只读状态")
	default:
		protocol.WriteError(w, http.StatusInternalServerError, "创建冲突处理任务失败")
	}
}

func (s *Server) queueConflictResolution(ctx context.Context, workflowID string) {
	if s.workflowWorkerID == "" {
		return
	}
	select {
	case s.snapshotSlots <- struct{}{}:
		go func() {
			defer func() { <-s.snapshotSlots }()
			runCtx, cancel := context.WithTimeout(ctx, 2*time.Hour)
			defer cancel()
			_ = s.executeConflictResolution(runCtx, workflowID)
		}()
	default:
		// The durable reconciler will resume this operation.
	}
}

func (s *Server) executeConflictResolution(ctx context.Context, workflowID string) error {
	if s.workflowWorkerID == "" {
		return fmt.Errorf("conflict resolution worker unavailable")
	}
	claimed, err := s.Store.ClaimConflictResolution(ctx, workflowID, s.workflowWorkerID, time.Now().UTC(), 2*time.Hour)
	if err != nil || !claimed {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.Store.ReleaseSnapshotWorkflow(cleanupCtx, workflowID, s.workflowWorkerID)
	}()
	execution, err := s.Store.GetConflictResolutionExecution(ctx, workflowID)
	if err != nil || execution == nil {
		return err
	}
	if execution.State == "retry_wait" {
		if err := s.Store.ResumeSnapshotRetry(ctx, workflowID, time.Now().UTC()); err != nil {
			return err
		}
		execution, err = s.Store.GetConflictResolutionExecution(ctx, workflowID)
		if err != nil || execution == nil {
			return err
		}
	}
	base, err := s.Store.GetNodeByID(ctx, execution.BaseNodeID)
	if err != nil || base == nil || base.Role != "compute" || base.TransferURL == "" {
		return s.retryConflictResolution(ctx, execution, "base_unavailable", "主计算节点暂不可用", err)
	}
	for _, source := range execution.Sources {
		if source.NodeID == execution.BaseNodeID || source.TransferState == "consumed" {
			continue
		}
		if err := s.transferConflictResolutionSource(ctx, execution, source, base); err != nil {
			return s.retryConflictResolution(ctx, execution, "evidence_transfer_failed", "冲突原始证据传输未完成", err)
		}
	}
	pageCount := (len(execution.Decisions) + 99) / 100
	sources := make([]protocol.ConflictResolutionSource, 0, len(execution.Sources))
	for _, source := range execution.Sources {
		sources = append(sources, protocol.ConflictResolutionSource{
			NodeID: source.NodeID, EvidenceID: source.EvidenceID,
			EntriesSHA256: hex.EncodeToString(source.EntriesSHA256),
		})
	}
	prepareOperationID := deriveWorkflowOperationID(execution.WorkflowID, "prepare-resolution")
	if _, err := s.runAgentCommandWithOperation(ctx, base, "prepare_conflict_resolution", protocol.PrepareConflictResolutionRequest{
		OperationID: execution.OperationID, ConflictID: execution.ConflictID,
		ResultID: execution.ResultSnapshotID, GlobalUserID: execution.GlobalUserID,
		Handle: execution.Handle, BaseNodeID: execution.BaseNodeID, DefaultAction: execution.DefaultAction,
		DecisionPageCount: pageCount, DecisionCount: len(execution.Decisions), Sources: sources,
	}, prepareOperationID, 10*time.Minute); err != nil {
		return s.retryConflictResolution(ctx, execution, "resolution_prepare_failed", "主节点未能验证全部原始证据", err)
	}
	for pageIndex := 0; pageIndex < pageCount; pageIndex++ {
		start := pageIndex * 100
		end := min(start+100, len(execution.Decisions))
		page := make([]protocol.ConflictResolutionDecision, 0, end-start)
		for _, decision := range execution.Decisions[start:end] {
			page = append(page, protocol.ConflictResolutionDecision{
				Path: decision.Path, SourceNodeID: decision.SourceNodeID, Action: decision.Action,
			})
		}
		if _, err := s.runAgentCommandWithOperation(ctx, base, "apply_conflict_resolution_decisions",
			protocol.ApplyConflictResolutionDecisionsRequest{
				OperationID: execution.OperationID, PageIndex: pageIndex, Decisions: page,
			}, deriveWorkflowOperationID(execution.WorkflowID, fmt.Sprintf("resolution-decisions:%d", pageIndex)),
			2*time.Minute); err != nil {
			return s.retryConflictResolution(ctx, execution, "resolution_decisions_failed", "逐文件冲突选择未完整下发", err)
		}
	}
	if execution.State != "publishing" {
		if err := s.Store.MarkConflictResolutionPublishing(ctx, execution.WorkflowID, time.Now().UTC()); err != nil {
			return err
		}
	}
	result, err := s.runAgentCommandWithOperation(ctx, base, "publish_conflict_resolution",
		protocol.PublishConflictResolutionRequest{OperationID: execution.OperationID},
		deriveWorkflowOperationID(execution.WorkflowID, "publish-resolution"), 60*time.Minute)
	if err != nil || result.ConflictResolution == nil {
		return s.retryConflictResolution(ctx, execution, "resolution_publish_failed", "冲突结果未能原子发布", err)
	}
	receipt := result.ConflictResolution
	if receipt.OperationID != execution.OperationID || receipt.ConflictID != execution.ConflictID ||
		receipt.ResultID != execution.ResultSnapshotID || receipt.PreservedSources != len(execution.Sources) {
		return s.retryConflictResolution(ctx, execution, "resolution_receipt_invalid", "冲突结果回执与任务不匹配", nil)
	}
	digest, err := decodeSnapshotDigest(receipt.EntriesSHA256)
	if err != nil {
		return s.retryConflictResolution(ctx, execution, "resolution_receipt_invalid", "冲突结果摘要无效", err)
	}
	if err := s.Store.CompleteConflictResolution(ctx, store.CompleteConflictResolutionParams{
		WorkflowID: execution.WorkflowID, OperationID: execution.OperationID,
		ConflictID: execution.ConflictID, ResultSnapshotID: execution.ResultSnapshotID,
		EntriesSHA256: digest, FileCount: receipt.FileCount, TotalBytes: receipt.TotalBytes,
		Now: time.Now().UTC(),
	}); err != nil {
		return err
	}
	_, _ = s.Store.ReconcileProtectionStates(ctx, time.Now().UTC(), s.protectionAlertGrace())
	return nil
}

func (s *Server) transferConflictResolutionSource(
	ctx context.Context,
	execution *store.ConflictResolutionExecution,
	source store.ConflictResolutionSource,
	base *store.Node,
) error {
	sourceNode, err := s.Store.GetNodeByID(ctx, source.NodeID)
	if err != nil || sourceNode == nil || (sourceNode.Role != "compute" && sourceNode.Role != "storage") {
		return fmt.Errorf("conflict source unavailable: %w", err)
	}
	if source.TransferState != "prepared" || source.CapabilityID == "" || len(source.CapabilityHash) != 32 || !source.CapabilityExpiry.After(time.Now().UTC()) {
		if err := s.rotateConflictResolutionTransfer(ctx, execution, source); err != nil {
			return err
		}
		latest, err := s.Store.GetConflictResolutionExecution(ctx, execution.WorkflowID)
		if err != nil || latest == nil {
			return err
		}
		for _, candidate := range latest.Sources {
			if candidate.EvidenceID == source.EvidenceID {
				source = candidate
				break
			}
		}
	}
	capability := deriveTransferCapability(s.secretKey, source.CapabilityID)
	digest := sha256.Sum256([]byte(capability))
	if !hmac.Equal(digest[:], source.CapabilityHash) {
		return fmt.Errorf("conflict transfer capability mismatch")
	}
	prepareOperationID := deriveWorkflowOperationID(execution.WorkflowID, "prepare-evidence:"+source.CapabilityID)
	if _, err := s.runAgentCommandWithOperation(ctx, base, "prepare_snapshot_receive", protocol.PrepareSnapshotReceiveRequest{
		WorkflowID: execution.ConflictID, SnapshotID: source.EvidenceID,
		GlobalUserID: execution.GlobalUserID, Handle: execution.Handle, DestinationKind: "conflict_input",
		SourceNodeID: source.NodeID, ActivityEpoch: 1,
		CapabilityHash: hex.EncodeToString(source.CapabilityHash), ExpiresAt: source.CapabilityExpiry,
	}, prepareOperationID, 45*time.Second); err != nil {
		if recovered := s.recoverConflictTransferReceipt(ctx, execution, source, base); recovered {
			return nil
		}
		return err
	}
	result, err := s.runAgentCommandWithOperation(ctx, sourceNode, "start_conflict_evidence_transfer",
		protocol.StartConflictEvidenceTransferRequest{
			ConflictID: execution.ConflictID, EvidenceID: source.EvidenceID,
			GlobalUserID: execution.GlobalUserID, Handle: execution.Handle,
			TargetNodeID: execution.BaseNodeID, TargetTransferURL: base.TransferURL,
			TransferCapability: capability, CapabilityExpires: source.CapabilityExpiry,
		}, deriveWorkflowOperationID(execution.WorkflowID, "transfer-evidence:"+source.CapabilityID), 55*time.Minute)
	if err != nil || result.Snapshot == nil {
		if recovered := s.recoverConflictTransferReceipt(ctx, execution, source, base); recovered {
			return nil
		}
		_ = s.rotateConflictResolutionTransfer(context.WithoutCancel(ctx), execution, source)
		if err != nil {
			return err
		}
		return fmt.Errorf("conflict transfer receipt missing")
	}
	if result.Snapshot.SnapshotID != source.EvidenceID {
		return fmt.Errorf("conflict transfer receipt scope mismatch")
	}
	return s.Store.MarkConflictResolutionTransferComplete(ctx, execution.OperationID,
		source.EvidenceID, source.CapabilityHash, time.Now().UTC())
}

func (s *Server) recoverConflictTransferReceipt(
	ctx context.Context,
	execution *store.ConflictResolutionExecution,
	source store.ConflictResolutionSource,
	base *store.Node,
) bool {
	result, err := s.runAgentCommandWithOperation(ctx, base, "get_snapshot_receipt", map[string]string{
		"workflow_id": execution.ConflictID, "snapshot_id": source.EvidenceID,
	}, deriveWorkflowOperationID(execution.WorkflowID, "evidence-receipt:"+source.CapabilityID), 45*time.Second)
	if err != nil || result.Snapshot == nil || result.Snapshot.SnapshotID != source.EvidenceID {
		return false
	}
	return s.Store.MarkConflictResolutionTransferComplete(ctx, execution.OperationID,
		source.EvidenceID, source.CapabilityHash, time.Now().UTC()) == nil
}

func (s *Server) rotateConflictResolutionTransfer(
	ctx context.Context,
	execution *store.ConflictResolutionExecution,
	source store.ConflictResolutionSource,
) error {
	capabilityID, err := newUUID()
	if err != nil {
		return err
	}
	capability := deriveTransferCapability(s.secretKey, capabilityID)
	digest := sha256.Sum256([]byte(capability))
	now := time.Now().UTC()
	return s.Store.RotateConflictResolutionTransfer(ctx, execution.OperationID, source.EvidenceID,
		capabilityID, digest[:], now.Add(15*time.Minute), now)
}

func (s *Server) retryConflictResolution(
	ctx context.Context,
	execution *store.ConflictResolutionExecution,
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
	attempt, err := s.Store.ScheduleSnapshotRetry(ctx, execution.WorkflowID, code, summary, time.Now().UTC(), delay)
	if err != nil {
		return err
	}
	maxAttempts := 5
	if s.Cfg != nil && s.Cfg.Backup.RetryMax > 0 {
		maxAttempts = max(s.Cfg.Backup.RetryMax, 5)
	}
	if attempt >= maxAttempts {
		_ = s.Store.FailConflictResolution(context.WithoutCancel(ctx), execution.WorkflowID, code, summary, time.Now().UTC())
	}
	if cause != nil {
		return cause
	}
	return fmt.Errorf("%s", code)
}

func (s *Server) conflictResolutionReconciler(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	s.resumeConflictResolutions(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.resumeConflictResolutions(ctx)
		}
	}
}

func (s *Server) resumeConflictResolutions(ctx context.Context) {
	ids, err := s.Store.ListResumableConflictResolutionIDs(ctx, 100)
	if err != nil {
		return
	}
	for _, id := range ids {
		s.queueConflictResolution(ctx, id)
	}
}
