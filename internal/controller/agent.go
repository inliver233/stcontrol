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
	transferURL, err := validateAgentTransferURL(req.TransferURL)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "数据面地址无效")
		return
	}

	now := time.Now().UTC()
	policy := normalizeRegistrationPolicy(req.RegistrationPolicy, now)
	if policy.State == "error" && policy.Version < node.RegistrationPolicyVersion {
		policy.Version = node.RegistrationPolicyVersion
	}
	facts := normalizeHeartbeatFacts(req, transferURL, policy, now)
	if err := s.Store.UpdateNodeHeartbeat(ctx, node.ID, facts, s.nodeCapacityPolicy()); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "更新心跳失败")
		return
	}

	// 处理用户在线状态 → 供离线备份调度参考
	s.trackUserActivity(node.ID, req.Users)

	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
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
func (s *Server) trackUserActivity(nodeID int64, users []protocol.UserStatus) {
	// 简化: 存入内存 map, 调度器读取。
	s.actMu.Lock()
	defer s.actMu.Unlock()
	if s.activity == nil {
		s.activity = make(map[int64]map[string]protocol.UserStatus)
	}
	m := s.activity[nodeID]
	if m == nil {
		m = make(map[string]protocol.UserStatus)
		s.activity[nodeID] = m
	}
	for _, u := range users {
		m[u.Handle] = u
	}
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.Store.MarkStaleNodesOffline(ctx, timeout)
			_, _ = s.Store.CleanupNodeMetricSamples(ctx, time.Now().UTC().Add(-24*time.Hour))
		}
	}
}

// backupScheduler 扫描离线用户并触发备份（详见 backup.go 的完整实现）。
func (s *Server) backupScheduler(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scheduleOfflineBackups(ctx)
		}
	}
}
