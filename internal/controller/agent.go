package controller

import (
	"context"
	stdsha256 "crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// handleAgentRegister consumes a pre-created node-scoped enrollment token and
// rotates an encrypted Agent credential. The controller never needs agent_url.
func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var req protocol.RegisterAgentRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	ctx := r.Context()
	if req.Token == "" || req.Fingerprint == "" || req.Fingerprint != protocol.NodeFingerprint(req.Info) {
		protocol.WriteError(w, http.StatusForbidden, "注册令牌无效或已过期")
		return
	}
	psk, err := crypto.RandomPassword(48)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成密钥失败")
		return
	}
	if req.Role != "compute" && req.Role != "storage" {
		protocol.WriteError(w, http.StatusForbidden, "注册令牌与节点角色不匹配")
		return
	}
	credentialID, err := newUUID()
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "生成凭据失败")
		return
	}
	ciphertext, err := crypto.Encrypt(s.secretKey, []byte(psk))
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "加密凭据失败")
		return
	}
	tokenHash := stdsha256.Sum256([]byte(req.Token))
	enrollment, err := s.Store.EnrollAgent(ctx, store.EnrollAgentParams{
		TokenHash: tokenHash[:], PresentedRole: req.Role,
		PresentedFingerprint: req.Fingerprint, CredentialID: credentialID,
		CredentialCiphertext: []byte(ciphertext), AgentVersion: req.Info.OS + "/" + req.Info.Arch,
		TavernVersion: req.Info.TavernVersion, BaseURLGuess: req.Info.BaseURLGuess,
		Now: time.Now().UTC(),
	})
	if err != nil {
		protocol.WriteError(w, http.StatusForbidden, "注册令牌无效或已过期")
		return
	}
	_ = s.Store.Audit(ctx, "agent", "enroll", req.Role, nil)

	protocol.WriteJSON(w, http.StatusOK, protocol.RegisterAgentResponse{
		NodeID: enrollment.NodeID, AgentPSK: psk,
		CredentialVersion:    enrollment.CredentialVersion,
		ControllerGeneration: enrollment.ControllerGeneration,
	})
}

func validateAgentTransferURL(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid transfer URL")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback) {
		return "", fmt.Errorf("transfer URL must use HTTPS")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String(), nil
}

// handleAgentHeartbeat 接收子控心跳（更新负载、版本、用户在线状态）。
func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	node := currentNode(r)
	if node == nil {
		protocol.WriteError(w, http.StatusUnauthorized, "未知节点")
		return
	}
	var req protocol.HeartbeatRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	ctx := r.Context()
	now := time.Now().UTC()
	if err := validateActivityObservation(now, req.ActivityObservedAt); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "用户活动观察时间无效")
		return
	}
	modeFact, err := normalizeNodeControlMode(req.ControlMode, now)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "节点控制模式报告无效")
		return
	}
	transferURL, err := validateAgentTransferURL(req.TransferURL)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "数据面地址无效")
		return
	}

	policy := normalizeRegistrationPolicy(req.RegistrationPolicy, now)
	if policy.State == "error" && policy.Version < node.RegistrationPolicyVersion {
		policy.Version = node.RegistrationPolicyVersion
	}
	facts := normalizeHeartbeatFacts(req, transferURL, policy, now)
	if err := s.Store.UpdateNodeHeartbeat(ctx, node.ID, facts, s.nodeCapacityPolicy()); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "更新心跳失败")
		return
	}
	decision, err := s.Store.ReconcileNodeControlModeAuthenticated(
		ctx, node.ID, modeFact, currentAgentCredentialGeneration(r),
	)
	if err != nil {
		protocol.WriteError(w, http.StatusConflict, "节点控制模式世代冲突")
		return
	}

	// 处理用户在线状态 → 供离线备份调度参考
	leaseConfirmations, err := s.trackUserActivity(ctx, node.ID, facts.TelemetrySource, req.Users, now)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "更新用户活动租约失败")
		return
	}
	if modeFact.Mode != protocol.NodeModeManaged || decision.DesiredMode != protocol.NodeModeManaged {
		leaseConfirmations = nil
	}
	if req.ActivityObservedAt == 0 {
		// Rolling-upgrade compatibility: an older Agent may still renew the
		// PostgreSQL lease, but it receives no causally ordered local grant. Its
		// existing adapter deadline therefore expires closed instead of being
		// extended from an observation whose time is unknown.
		leaseConfirmations = nil
	}
	if modeFact.Mode != protocol.NodeModeManaged || decision.DesiredMode != protocol.NodeModeManaged {
		s.setControlPlaneGate(true, "node_reconciliation_required")
	} else if blocked, _ := s.controlPlaneGate(); blocked {
		// Only a database-wide reconciliation may reopen the gate; one managed
		// heartbeat cannot prove that every other node has recovered.
		_ = s.refreshControlPlaneGate(ctx)
	}
	_, _, currentPSK := currentAgentCredential(r)
	rotation, err := s.agentCredentialRotationOffer(ctx, node, currentPSK, decision.ControllerGeneration, now)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "节点凭据轮换暂不可用")
		return
	}

	acknowledgedTakeovers := make([]string, 0, len(req.ControlMode.ConfirmedTakeovers))
	for _, takeover := range req.ControlMode.ConfirmedTakeovers {
		acknowledgedTakeovers = append(acknowledgedTakeovers, takeover.OperationID)
	}
	// Node quota policy: echo the administrator's expected quota + version so
	// the Agent can validate and apply it, then report the effective value back.
	protocol.WriteJSON(w, http.StatusOK, protocol.HeartbeatResponse{
		OK: true, ControllerGeneration: decision.ControllerGeneration,
		DesiredMode: decision.DesiredMode, ModeGeneration: decision.ModeGeneration,
		AcknowledgedTakeoverOperations: acknowledgedTakeovers,
		CredentialRotation:             rotation,
		ActivityLeaseConfirmedAt:       req.ActivityObservedAt,
		ActivityLeaseConfirmations:     leaseConfirmations,
		ExpectedDiskQuotaBytes:         node.ExpectedDiskQuotaBytes,
		QuotaPolicyVersion:             node.QuotaPolicyVersion,
	})
}

func validateActivityObservation(now time.Time, observedAt int64) error {
	if observedAt == 0 {
		return nil
	}
	observed := time.UnixMilli(observedAt).UTC()
	if observedAt < 0 || observed.After(now.Add(time.Minute)) || observed.Before(now.Add(-5*time.Minute)) {
		return fmt.Errorf("activity observation is outside the accepted clock window")
	}
	return nil
}

func (s *Server) agentCredentialRotationOffer(
	ctx context.Context,
	node *store.Node,
	currentPSK string,
	controllerGeneration int64,
	now time.Time,
) (*protocol.AgentCredentialRotationOffer, error) {
	if node == nil || currentPSK == "" || controllerGeneration <= 0 {
		return nil, store.ErrAgentCredentialRotation
	}
	newPSK, err := crypto.RandomPassword(48)
	if err != nil {
		return nil, err
	}
	ciphertext, err := crypto.Encrypt(s.secretKey, []byte(newPSK))
	if err != nil {
		return nil, err
	}
	rotationID, err := newUUID()
	if err != nil {
		return nil, err
	}
	operationID, err := newUUID()
	if err != nil {
		return nil, err
	}
	rotation, err := s.Store.EnsureAgentCredentialRotation(ctx, store.EnsureAgentCredentialRotationParams{
		ID: rotationID, OperationID: operationID, NodeID: node.ID,
		ProposedCiphertext: []byte(ciphertext), ControllerGeneration: controllerGeneration,
		Now: now, ExpiresAt: now.Add(24 * time.Hour),
	})
	if err != nil || rotation == nil {
		return nil, err
	}
	plaintext, err := crypto.Decrypt(s.secretKey, string(rotation.Ciphertext))
	if err != nil {
		return nil, err
	}
	wrapped, err := crypto.Encrypt(crypto.DeriveAgentCredentialRotationKey(currentPSK), plaintext)
	if err != nil {
		return nil, err
	}
	return &protocol.AgentCredentialRotationOffer{
		CredentialVersion:    rotation.CredentialVersion,
		ControllerGeneration: rotation.ControllerGeneration,
		EncryptedPSK:         wrapped, ExpiresAt: rotation.ExpiresAt,
	}, nil
}

func (s *Server) handleAgentConfirmCredential(w http.ResponseWriter, r *http.Request) {
	var req protocol.ConfirmAgentCredentialRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	matchedVersion, _, _ := currentAgentCredential(r)
	if decoder.Decode(&req) != nil || req.CredentialVersion <= 0 || req.CredentialVersion != matchedVersion {
		protocol.WriteError(w, http.StatusBadRequest, "凭据轮换确认无效")
		return
	}
	node := currentNode(r)
	if node == nil {
		protocol.WriteError(w, http.StatusUnauthorized, "未知节点")
		return
	}
	generation, err := s.Store.ActivateAgentCredentialRotation(
		r.Context(), node.ID, req.CredentialVersion, time.Now().UTC(),
	)
	if err != nil {
		protocol.WriteError(w, http.StatusConflict, "凭据轮换已失效，请等待重新协商")
		return
	}
	_ = s.refreshControlPlaneGate(r.Context())
	_ = s.Store.Audit(r.Context(), "agent", "credential-rotated", fmt.Sprintf("node:%d", node.ID), nil)
	protocol.WriteJSON(w, http.StatusOK, protocol.ConfirmAgentCredentialResponse{
		OK: true, CredentialVersion: req.CredentialVersion, ControllerGeneration: generation,
	})
}

func normalizeNodeControlMode(report protocol.NodeControlModeReport, now time.Time) (store.NodeControlModeFact, error) {
	fact := store.NodeControlModeFact{
		Mode: report.Mode, ModeGeneration: report.ModeGeneration,
		ControllerGeneration: report.ControllerGeneration, ReasonCode: report.ReasonCode,
		ConsecutiveHeartbeatFails:   report.ConsecutiveHeartbeatFails,
		ConsecutiveHealthProbeFails: report.ConsecutiveHealthProbeFails,
		ConsecutivePeerWitnessFails: report.ConsecutivePeerWitnessFails,
		OutageStartedAt:             report.OutageStartedAt,
		ConfirmedOutageStartedAt:    report.ConfirmedOutageStartedAt,
		LastControllerSuccessAt:     report.LastControllerSuccessAt,
		IndependentSince:            report.IndependentSince,
		ActiveIndependentSessions:   report.ActiveIndependentSessions,
		PendingUserSyncs:            report.PendingUserSyncs, ObservedAt: now,
	}
	if report.Mode != protocol.NodeModeManaged && report.Mode != protocol.NodeModeControllerUnreachable &&
		report.Mode != protocol.NodeModeIndependent && report.Mode != protocol.NodeModeIndependentDraining {
		return store.NodeControlModeFact{}, fmt.Errorf("invalid node control mode")
	}
	if report.ModeGeneration <= 0 || report.ControllerGeneration <= 0 ||
		report.ConsecutiveHeartbeatFails < 0 || report.ConsecutiveHealthProbeFails < 0 ||
		report.ConsecutivePeerWitnessFails < 0 ||
		report.ActiveIndependentSessions < 0 || report.PendingUserSyncs < 0 ||
		len(report.ReasonCode) > 128 || strings.ContainsAny(report.ReasonCode, "\r\n") {
		return store.NodeControlModeFact{}, fmt.Errorf("invalid node control mode evidence")
	}
	if report.Mode == protocol.NodeModeIndependent &&
		(report.IndependentSince.IsZero() || report.ConfirmedOutageStartedAt.IsZero() ||
			report.ConsecutivePeerWitnessFails <= 0) {
		return store.NodeControlModeFact{}, fmt.Errorf("independent mode is missing activation time")
	}
	if len(report.PendingUsers) != report.PendingUserSyncs || len(report.PendingUsers) > 500 {
		return store.NodeControlModeFact{}, fmt.Errorf("pending independent synchronization count mismatch")
	}
	seenHandles := make(map[string]struct{}, len(report.PendingUsers))
	seenMarkers := make(map[string]struct{}, len(report.PendingUsers))
	for _, pending := range report.PendingUsers {
		changedAt := time.UnixMilli(pending.ChangedAt).UTC()
		if !isValidHandle(pending.Handle) || NormalizeHandle(pending.Handle) != pending.Handle ||
			!isUUID(pending.Marker) || pending.ChangedAt <= 0 || changedAt.After(now.Add(time.Minute)) ||
			pending.Reason == "" || len(pending.Reason) > 128 || strings.TrimSpace(pending.Reason) != pending.Reason ||
			strings.ContainsAny(pending.Reason, "\r\n") {
			return store.NodeControlModeFact{}, fmt.Errorf("invalid pending independent synchronization fact")
		}
		if _, exists := seenHandles[pending.Handle]; exists {
			return store.NodeControlModeFact{}, fmt.Errorf("duplicate pending independent synchronization handle")
		}
		if _, exists := seenMarkers[pending.Marker]; exists {
			return store.NodeControlModeFact{}, fmt.Errorf("duplicate pending independent synchronization marker")
		}
		seenHandles[pending.Handle] = struct{}{}
		seenMarkers[pending.Marker] = struct{}{}
		fact.PendingUsers = append(fact.PendingUsers, store.IndependentSyncFact{
			Handle: pending.Handle, Marker: pending.Marker, ChangedAt: changedAt, Reason: pending.Reason,
		})
	}
	if len(report.ConfirmedTakeovers) > 1000 {
		return store.NodeControlModeFact{}, fmt.Errorf("too many confirmed independent takeovers")
	}
	seenTakeoverOperations := make(map[string]struct{}, len(report.ConfirmedTakeovers))
	seenTakeoverClaims := make(map[string]struct{}, len(report.ConfirmedTakeovers))
	for _, takeover := range report.ConfirmedTakeovers {
		confirmedAt := time.UnixMilli(takeover.ConfirmedAt).UTC()
		parentDigest, parentErr := hex.DecodeString(takeover.ParentClaimID)
		claimDigest, claimErr := hex.DecodeString(takeover.ClaimID)
		if !isUUID(takeover.OperationID) || !isValidHandle(takeover.Handle) ||
			NormalizeHandle(takeover.Handle) != takeover.Handle || parentErr != nil || claimErr != nil ||
			len(parentDigest) != stdsha256.Size || len(claimDigest) != stdsha256.Size ||
			strings.ToLower(takeover.ParentClaimID) != takeover.ParentClaimID ||
			strings.ToLower(takeover.ClaimID) != takeover.ClaimID ||
			takeover.ParentClaimID == takeover.ClaimID || takeover.ControllerGeneration <= 0 ||
			takeover.ControllerGeneration > report.ControllerGeneration || takeover.ActivityEpoch <= 0 ||
			takeover.TakeoverSequence <= 0 || takeover.ConfirmedAt <= 0 ||
			confirmedAt.After(now.Add(time.Minute)) {
			return store.NodeControlModeFact{}, fmt.Errorf("invalid confirmed independent takeover")
		}
		if _, exists := seenTakeoverOperations[takeover.OperationID]; exists {
			return store.NodeControlModeFact{}, fmt.Errorf("duplicate confirmed independent takeover operation")
		}
		if _, exists := seenTakeoverClaims[takeover.ClaimID]; exists {
			return store.NodeControlModeFact{}, fmt.Errorf("duplicate confirmed independent takeover claim")
		}
		seenTakeoverOperations[takeover.OperationID] = struct{}{}
		seenTakeoverClaims[takeover.ClaimID] = struct{}{}
		fact.ConfirmedTakeovers = append(fact.ConfirmedTakeovers, store.IndependentTakeoverFact{
			OperationID: takeover.OperationID, Handle: takeover.Handle,
			ParentClaimID: takeover.ParentClaimID, ClaimID: takeover.ClaimID,
			ControllerGeneration: takeover.ControllerGeneration,
			ActivityEpoch:        takeover.ActivityEpoch, TakeoverSequence: takeover.TakeoverSequence,
			ConfirmedAt: confirmedAt,
		})
	}
	return fact, nil
}

func normalizeHeartbeatFacts(
	req protocol.HeartbeatRequest,
	transferURL string,
	registrationPolicy store.NodeRegistrationPolicy,
	now time.Time,
) store.NodeHeartbeatFacts {
	metricsValid := req.MetricsValid && finitePercent(req.CPUPct) && finitePercent(req.MemPct) &&
		finitePercent(req.DiskPct) && req.DiskTotalBytes > 0 && req.DiskAvailableBytes >= 0 &&
		req.DiskAvailableBytes <= req.DiskTotalBytes && req.DiskQuotaBytes > 0 &&
		req.DiskQuotaBytes <= req.DiskTotalBytes &&
		req.AllocatedDiskBytes >= 0 && req.OnlineUsers >= 0 && req.OnlineUsers <= 1_000_000 &&
		req.TaskQueueDepth >= 0 && req.TaskQueueDepth <= 1_000_000
	telemetrySource := req.TelemetrySource
	if telemetrySource != "adapter" && telemetrySource != "directory_fallback" && telemetrySource != "agent" {
		telemetrySource = "unavailable"
		metricsValid = false
	}
	fallbackFingerprint := stdsha256.Sum256([]byte(
		"stcontrol-node-compatibility-fallback:v1\n" + req.AgentVersion + "\n" + req.TavernVersion,
	))
	compatibilityState := req.Compatibility.State
	compatibilityReason := req.Compatibility.ErrorCode
	fingerprint := req.Compatibility.Fingerprint
	decodedFingerprint, fingerprintErr := hex.DecodeString(fingerprint)
	if fingerprintErr != nil || len(decodedFingerprint) != stdsha256.Size {
		fingerprint = hex.EncodeToString(fallbackFingerprint[:])
		compatibilityState = "unknown"
		compatibilityReason = "invalid_report"
	}
	if compatibilityState != "compatible" && compatibilityState != "incompatible" && compatibilityState != "unknown" {
		compatibilityState = "unknown"
		compatibilityReason = "invalid_report"
	}
	switch compatibilityReason {
	case "", "adapter_unavailable", "version_unsupported", "missing_capability", "invalid_health", "invalid_report":
	default:
		compatibilityReason = "invalid_report"
		compatibilityState = "unknown"
	}
	if (compatibilityState == "compatible" && compatibilityReason != "") ||
		(compatibilityState != "compatible" && compatibilityReason == "") {
		compatibilityState = "unknown"
		compatibilityReason = "invalid_report"
	}
	return store.NodeHeartbeatFacts{
		CPUPct: req.CPUPct, MemPct: req.MemPct, DiskPct: req.DiskPct,
		MetricsValid: metricsValid, DiskTotalBytes: req.DiskTotalBytes,
		DiskAvailableBytes: req.DiskAvailableBytes, DiskQuotaBytes: req.DiskQuotaBytes,
		AllocatedDiskBytes: req.AllocatedDiskBytes, OnlineUsers: req.OnlineUsers,
		TaskQueueDepth: req.TaskQueueDepth, TelemetrySource: telemetrySource,
		TavernVersion: req.TavernVersion, AgentVersion: req.AgentVersion, TransferURL: transferURL,
		CompatibilityState: compatibilityState, CompatibilityReasonCode: compatibilityReason,
		CompatibilityFingerprint: fingerprint, RegistrationPolicy: registrationPolicy, ObservedAt: now,
	}
}

func finitePercent(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 100
}

func (s *Server) nodeCapacityPolicy() store.NodeCapacityPolicy {
	configured := s.Cfg.Node
	defaults := config.DefaultController().Node
	positiveFloat := func(value, fallback float64) float64 {
		if value <= 0 || value >= 100 {
			return fallback
		}
		return value
	}
	positiveInt := func(value, fallback int) int {
		if value <= 0 {
			return fallback
		}
		return value
	}
	cpuBusy := positiveFloat(configured.RegisterCPU, defaults.RegisterCPU)
	memBusy := positiveFloat(configured.RegisterMem, defaults.RegisterMem)
	diskBusy := positiveFloat(configured.RegisterDisk, defaults.RegisterDisk)
	hard := positiveFloat(configured.AllocationHardPct, defaults.AllocationHardPct)
	if hard <= cpuBusy || hard <= memBusy || hard <= diskBusy {
		cpuBusy = defaults.RegisterCPU
		memBusy = defaults.RegisterMem
		diskBusy = defaults.RegisterDisk
		hard = defaults.AllocationHardPct
	}
	minDisk := configured.MinDiskFreeBytes
	if minDisk <= 0 {
		minDisk = defaults.MinDiskFreeBytes
	}
	return store.NodeCapacityPolicy{
		CPUBusyPct: cpuBusy, MemBusyPct: memBusy, DiskBusyPct: diskBusy, HardPct: hard,
		Window:            time.Duration(positiveInt(configured.CapacityWindowSec, defaults.CapacityWindowSec)) * time.Second,
		Sustain:           time.Duration(positiveInt(configured.CapacitySustainSec, defaults.CapacitySustainSec)) * time.Second,
		Recovery:          time.Duration(positiveInt(configured.CapacityRecoverySec, defaults.CapacityRecoverySec)) * time.Second,
		Cooldown:          time.Duration(positiveInt(configured.CapacityCooldownSec, defaults.CapacityCooldownSec)) * time.Second,
		MinDiskFreeBytes:  minDisk,
		MaxOnlineUsers:    positiveInt(configured.MaxOnlineUsers, defaults.MaxOnlineUsers),
		MaxTaskQueueDepth: positiveInt(configured.MaxTaskQueueDepth, defaults.MaxTaskQueueDepth),
	}
}

func normalizeRegistrationPolicy(
	report protocol.RegistrationPolicyReport,
	now time.Time,
) store.NodeRegistrationPolicy {
	fact := store.NodeRegistrationPolicy{
		State: report.State, Version: report.Version, ExpiresAt: report.ExpiresAt,
		ObservedAt: now, ErrorCode: report.ErrorCode,
	}
	validState := report.State == "open" || report.State == "invitation_required" || report.State == "closed"
	if validState && report.Version > 0 && report.ExpiresAt.After(now) &&
		!report.ExpiresAt.After(now.Add(10*time.Minute)) {
		fact.ErrorCode = ""
		return fact
	}
	fact.State = "error"
	if fact.Version < 0 {
		fact.Version = 0
	}
	fact.ExpiresAt = now
	switch report.ErrorCode {
	case "adapter_unavailable", "invalid_policy":
		fact.ErrorCode = report.ErrorCode
	default:
		fact.ErrorCode = "invalid_policy_report"
	}
	return fact
}

// ---------- 离线备份调度辅助 ----------

// trackUserActivity 记录节点上用户的在线状态（内存态, 供调度器用）。
func (s *Server) trackUserActivity(
	ctx context.Context,
	nodeID int64,
	telemetrySource string,
	users []protocol.UserStatus,
	now time.Time,
) ([]protocol.ActivityLeaseConfirmation, error) {
	// Directory mtimes and Agent-local fallbacks cannot prove that every page,
	// request, or write has stopped. Remove scheduling facts for this node and
	// leave its durable lease untouched until authoritative adapter telemetry
	// returns. Missing facts therefore fail closed instead of triggering backup.
	if telemetrySource != "adapter" {
		s.actMu.Lock()
		delete(s.activity, nodeID)
		s.actMu.Unlock()
		return nil, nil
	}
	if len(users) == 0 {
		s.actMu.Lock()
		if s.activity == nil {
			s.activity = make(map[int64]map[string]protocol.UserStatus)
		}
		s.activity[nodeID] = map[string]protocol.UserStatus{}
		s.actMu.Unlock()
		return nil, nil
	}
	leaseTTL := s.activityLeaseTTL()
	activeGeneration, err := s.Store.GetActiveControllerGeneration(ctx)
	if err != nil {
		return nil, err
	}
	aggregated := make(map[string]protocol.UserStatus)
	confirmations := make([]protocol.ActivityLeaseConfirmation, 0)
	confirmedHandles := make(map[string]struct{})
	for _, u := range users {
		normalized, pageAt, requestAt, ok := normalizeUserActivityStatus(u, now, leaseTTL)
		if !ok {
			continue
		}
		authoritative := u.LoginMode == protocol.NodeModeManaged && isUUID(u.SessionID) &&
			u.ActivityEpoch > 0 && u.ControllerGeneration == activeGeneration
		if authoritative {
			user, err := s.Store.GetUserByUsername(ctx, u.Handle)
			if err != nil {
				return nil, fmt.Errorf("resolve activity user %s: %w", u.Handle, err)
			}
			authoritative = user != nil && user.GlobalID > 0
			if authoritative && u.Ended {
				matched, err := s.Store.EndActivityLease(ctx, user.GlobalID, nodeID, u.SessionID,
					u.ActivityEpoch, u.ControllerGeneration, now)
				if err != nil {
					return nil, fmt.Errorf("end activity lease for %s: %w", u.Handle, err)
				}
				authoritative = matched
				if !matched {
					lease, err := s.Store.GetActivityLease(ctx, user.GlobalID)
					if err != nil {
						return nil, fmt.Errorf("read ended activity lease for %s: %w", u.Handle, err)
					}
					authoritative = lease != nil && lease.WriterNodeID == nodeID &&
						lease.SessionID == u.SessionID && lease.ActivityEpoch == u.ActivityEpoch &&
						lease.ControllerGeneration == u.ControllerGeneration && lease.State == "ended"
				}
			} else if authoritative {
				leaseExpiresAt, matched, err := s.Store.UpdateActivityLeaseTelemetry(ctx, store.ActivityLeaseTelemetry{
					UserID: user.GlobalID, WriterNodeID: nodeID, SessionID: u.SessionID,
					ActivityEpoch: u.ActivityEpoch, ControllerGeneration: u.ControllerGeneration,
					LastPageHeartbeatAt: pageAt, LastRequestAt: requestAt,
					InFlightReads: u.InFlightReads, InFlightWrites: u.InFlightWrites,
					Online: normalized.IsOnline, Now: now, TTL: leaseTTL,
				})
				if err != nil {
					return nil, fmt.Errorf("update activity telemetry for %s: %w", u.Handle, err)
				}
				authoritative = matched
				if matched && normalized.IsOnline && leaseExpiresAt.After(now) {
					if _, exists := confirmedHandles[u.Handle]; !exists {
						confirmedHandles[u.Handle] = struct{}{}
						confirmations = append(confirmations, protocol.ActivityLeaseConfirmation{
							Handle: u.Handle, SessionID: u.SessionID, ActivityEpoch: u.ActivityEpoch,
							ControllerGeneration: u.ControllerGeneration,
							LeaseExpiresAt:       leaseExpiresAt.UnixMilli(),
						})
					}
				}
			}
		}
		if !authoritative {
			// A stale session/generation or unknown login mode cannot prove
			// offline. It also cannot extend the durable lease.
			normalized.IsOnline = true
			normalized.LastActivity = now.UnixMilli()
		}

		current := aggregated[u.Handle]
		current.Handle = u.Handle
		current.IsOnline = current.IsOnline || normalized.IsOnline
		if normalized.LastActivity > current.LastActivity {
			current.LastActivity = normalized.LastActivity
		}
		current.InFlightReads += u.InFlightReads
		current.InFlightWrites += u.InFlightWrites
		aggregated[u.Handle] = current
	}

	s.actMu.Lock()
	defer s.actMu.Unlock()
	if s.activity == nil {
		s.activity = make(map[int64]map[string]protocol.UserStatus)
	}
	// Each adapter response is a complete point-in-time snapshot. Replacing the
	// node map prevents an old offline or online entry from surviving forever;
	// absence itself is not treated as offline by the scheduler.
	s.activity[nodeID] = aggregated
	return confirmations, nil
}

func normalizeUserActivityStatus(
	u protocol.UserStatus,
	now time.Time,
	leaseTTL time.Duration,
) (protocol.UserStatus, time.Time, time.Time, bool) {
	if u.Handle == "" || len(u.Handle) > 128 || u.LastActivity < 0 || u.LastPageHeartbeat < 0 ||
		u.LastRequest < 0 || u.InFlightReads < 0 || u.InFlightWrites < 0 ||
		u.InFlightReads > 1_000_000 || u.InFlightWrites > 1_000_000 || leaseTTL <= 0 {
		return protocol.UserStatus{}, time.Time{}, time.Time{}, false
	}
	activityAt, activityOK := reportedActivityTime(u.LastActivity, now)
	pageAt, pageOK := reportedActivityTime(u.LastPageHeartbeat, now)
	requestAt, requestOK := reportedActivityTime(u.LastRequest, now)
	u.IsOnline = !u.Ended && (u.InFlightReads > 0 || u.InFlightWrites > 0 ||
		(pageOK && now.Sub(pageAt) <= leaseTTL) || (requestOK && now.Sub(requestAt) <= leaseTTL))
	if !activityOK || u.LastPageHeartbeat > 0 && !pageOK || u.LastRequest > 0 && !requestOK {
		// Invalid/future activity can never prove the offline grace elapsed.
		u.IsOnline = true
		u.LastActivity = now.UnixMilli()
	} else {
		u.LastActivity = activityAt.UnixMilli()
	}
	return u, pageAt, requestAt, true
}

func reportedActivityTime(value int64, now time.Time) (time.Time, bool) {
	if value <= 0 {
		return time.Time{}, false
	}
	reported := time.UnixMilli(value).UTC()
	if reported.After(now.Add(time.Minute)) {
		return time.Time{}, false
	}
	return reported, true
}

// ---------- 后台任务 ----------

// nodeWatchdog 定期把超时未心跳的节点标记为 offline。
func (s *Server) nodeWatchdog(ctx context.Context) {
	timeoutSec := s.Cfg.Node.HeartbeatTimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = config.DefaultController().Node.HeartbeatTimeoutSec
	}
	timeout := time.Duration(timeoutSec) * time.Second
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	s.runNodeMaintenance(ctx, timeout)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runNodeMaintenance(ctx, timeout)
		}
	}
}

func (s *Server) runNodeMaintenance(ctx context.Context, timeout time.Duration) {
	now := time.Now().UTC()
	_ = s.Store.MarkStaleNodesOffline(ctx, timeout)
	_, _ = s.Store.CleanupNodeMetricSamples(ctx, now.Add(-24*time.Hour))
	_, _ = s.Store.ReconcileProtectionStates(ctx, now, s.protectionAlertGrace())
}

// backupScheduler 扫描离线用户并触发备份（详见 backup.go 的完整实现）。
func (s *Server) backupScheduler(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	if s.scheduleStorageRepairs(ctx) {
		s.scheduleOfflineBackups(ctx)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.scheduleStorageRepairs(ctx) {
				s.scheduleOfflineBackups(ctx)
			}
		}
	}
}
