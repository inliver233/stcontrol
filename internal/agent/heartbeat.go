package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

// StartHeartbeat 启动心跳循环（定期上报负载与用户在线状态）。
func (a *Agent) StartHeartbeat(ctx context.Context) {
	interval := time.Duration(a.Cfg.HeartbeatSec) * time.Second
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// 立即上报一次
	a.sendHeartbeat(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sendHeartbeat(ctx)
		}
	}
}

// sendHeartbeat 采集并上报一次心跳。
func (a *Agent) sendHeartbeat(ctx context.Context) {
	if err := a.resumeControllerCredentialRotation(ctx); err != nil && ctx.Err() == nil {
		log.Printf("Agent 凭据轮换确认尚未完成: %v", err)
	}
	// Retry the local mode application before reporting facts. A persisted mode
	// transition therefore survives either process restarting midway through
	// the Controller/adapter handshake.
	if err := a.syncTavernControlMode(ctx); err != nil && ctx.Err() == nil {
		log.Printf("节点控制模式尚未应用: %v", err)
	}
	if err := a.syncTavernActivityLeases(ctx); err != nil && ctx.Err() == nil {
		log.Printf("用户活动租约确认尚未应用: %v", err)
	}
	probedInfo, _ := ProbeTavern(a.Cfg.TavernDir)
	var info protocol.NodeInfo
	if probedInfo != nil {
		info = *probedInfo
	}
	var (
		metrics                   CapacityMetrics
		metricsErr, allocationErr error
		users                     []protocol.UserStatus
		allocatedBytes            int64
		telemetrySource           string
		registrationPolicy        protocol.RegistrationPolicyReport
		compatibility             protocol.NodeCompatibilityReport
		wait                      sync.WaitGroup
	)
	wait.Add(4)
	go func() {
		defer wait.Done()
		metrics, metricsErr = CollectCapacityMetrics(a.capacityMetricsPath())
	}()
	go func() {
		defer wait.Done()
		users, allocatedBytes, telemetrySource, allocationErr = a.managedCapacityFacts(ctx)
	}()
	go func() {
		defer wait.Done()
		registrationPolicy = a.registrationPolicy(ctx)
	}()
	go func() {
		defer wait.Done()
		compatibility = a.compatibilityReport(ctx, info)
	}()
	wait.Wait()
	activityObservedAt := time.Now().UTC().UnixMilli()
	metricsValid := metricsErr == nil && allocationErr == nil
	onlineUsers := 0
	for _, user := range users {
		if user.IsOnline {
			onlineUsers++
		}
	}
	diskQuota := a.Cfg.DiskQuotaBytes
	if metricsValid && (diskQuota <= 0 || diskQuota > metrics.DiskTotalBytes) {
		diskQuota = metrics.DiskTotalBytes
	}
	reqBody := protocol.HeartbeatRequest{
		NodeID:             a.Cfg.NodeID,
		AgentVersion:       Version,
		TavernVersion:      info.TavernVersion,
		CPUPct:             metrics.CPUPct,
		MemPct:             metrics.MemPct,
		DiskPct:            metrics.DiskPct,
		MetricsValid:       metricsValid,
		DiskTotalBytes:     metrics.DiskTotalBytes,
		DiskAvailableBytes: metrics.DiskAvailableBytes,
		DiskQuotaBytes:     diskQuota,
		AllocatedDiskBytes: allocatedBytes,
		OnlineUsers:        onlineUsers,
		TaskQueueDepth:     len(a.commandSlots),
		TelemetrySource:    telemetrySource,
		Compatibility:      compatibility,
		TransferURL:        a.Cfg.TransferPublicURL,
		RegistrationPolicy: registrationPolicy,
		ActivityObservedAt: activityObservedAt,
		Users:              users,
		ControlMode:        a.controlModeReport(),
	}
	var response protocol.HeartbeatResponse
	if err := a.callController(ctx, http.MethodPost, "/api/agent/heartbeat", reqBody, &response); err != nil {
		if ctx.Err() != nil {
			return
		}
		healthProbeFailed := !a.controllerHealthAvailable(ctx)
		peerQuorumConfirmed := false
		if healthProbeFailed {
			peerQuorumConfirmed = a.peerWitnessQuorumConfirmsLoss(ctx)
		}
		if stateErr := a.recordControllerFailure(time.Now().UTC(), healthProbeFailed, peerQuorumConfirmed); stateErr != nil {
			log.Printf("持久化总控失联状态失败: %v", stateErr)
		}
		if modeErr := a.syncTavernControlMode(ctx); modeErr != nil {
			log.Printf("应用总控失联模式失败: %v", modeErr)
		}
		log.Printf("心跳上报失败: %v", err)
		return
	}
	if err := a.recordControllerSuccess(time.Now().UTC(), response); err != nil {
		log.Printf("心跳响应被世代门禁拒绝: %v", err)
		return
	}
	if err := a.acceptControllerCredentialRotation(ctx, response); err != nil {
		log.Printf("Agent 凭据轮换提议被拒绝: %v", err)
	}
	if err := a.syncTavernControlMode(ctx); err != nil {
		log.Printf("应用总控恢复模式失败: %v", err)
	}
	if err := a.syncTavernActivityLeases(ctx); err != nil {
		log.Printf("应用总控活动租约确认失败: %v", err)
	}
}

func (a *Agent) controllerHealthAvailable(ctx context.Context) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	endpoint, err := a.controllerEndpoint("/api/health")
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func (a *Agent) capacityMetricsPath() string {
	if a.Cfg.Role == "storage" && a.Cfg.BackupDir != "" {
		return a.Cfg.BackupDir
	}
	return a.dataRoot()
}

func (a *Agent) managedCapacityFacts(ctx context.Context) ([]protocol.UserStatus, int64, string, error) {
	if a.Cfg.Role == "storage" {
		size, err := directorySize(a.Cfg.BackupDir)
		return nil, size, "agent", err
	}
	fallback, size, sizeErr := a.scanUserActivityAndSize()
	users, adapterErr := a.collectUserStatuses(ctx)
	if adapterErr == nil {
		return users, size, "adapter", sizeErr
	}
	return fallback, size, "directory_fallback", sizeErr
}

// callController 向总控发起签名请求。respOut 若非 nil 则解析 JSON 响应。
func (a *Agent) callController(ctx context.Context, method, path string, body any, respOut any) error {
	status, _, data, err := a.doControllerRequest(ctx, method, path, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("controller returned status %d", status)
	}
	if respOut != nil && len(data) > 0 {
		return json.Unmarshal(data, respOut)
	}
	return nil
}

func (a *Agent) doControllerRequest(ctx context.Context, method, path string, body any) (int, http.Header, []byte, error) {
	psk, _ := a.controllerCredential()
	return a.doControllerRequestWithPSK(ctx, method, path, body, psk)
}

func (a *Agent) doControllerRequestWithPSK(
	ctx context.Context,
	method, path string,
	body any,
	psk string,
) (int, http.Header, []byte, error) {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return 0, nil, nil, err
		}
	}
	endpoint, err := a.controllerEndpoint(path)
	if err != nil {
		return 0, nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if psk == "" {
		return 0, nil, nil, fmt.Errorf("controller credential unavailable")
	}
	protocol.SignRequest(req, a.Cfg.NodeID, psk, payload)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, resp.Header.Clone(), data, nil
}

func (a *Agent) acceptControllerCredentialRotation(
	ctx context.Context,
	response protocol.HeartbeatResponse,
) error {
	offer := response.CredentialRotation
	if offer == nil {
		return nil
	}
	currentPSK, currentVersion := a.controllerCredential()
	if offer.CredentialVersion <= currentVersion || offer.ControllerGeneration != response.ControllerGeneration ||
		offer.ControllerGeneration <= 0 || !offer.ExpiresAt.After(time.Now().UTC()) ||
		offer.ExpiresAt.After(time.Now().UTC().Add(25*time.Hour)) || offer.EncryptedPSK == "" {
		return fmt.Errorf("invalid controller credential rotation offer")
	}
	plaintext, err := controlcrypto.Decrypt(
		controlcrypto.DeriveAgentCredentialRotationKey(currentPSK), offer.EncryptedPSK,
	)
	if err != nil || len(plaintext) < 32 || len(plaintext) > 128 {
		return fmt.Errorf("decrypt controller credential rotation offer")
	}
	if err := a.persistPendingControllerCredential(
		string(plaintext), offer.CredentialVersion, offer.ControllerGeneration, offer.ExpiresAt,
	); err != nil {
		return err
	}
	return a.resumeControllerCredentialRotation(ctx)
}

func (a *Agent) resumeControllerCredentialRotation(ctx context.Context) error {
	credential := a.pendingControllerCredential()
	if credential.PendingPSK == "" {
		return nil
	}
	if !credential.PendingExpiresAt.After(time.Now().UTC()) {
		return a.clearPendingControllerCredential(credential.PendingVersion)
	}
	status, _, data, err := a.doControllerRequestWithPSK(
		ctx, http.MethodPost, "/api/agent/credentials/confirm",
		protocol.ConfirmAgentCredentialRequest{CredentialVersion: credential.PendingVersion},
		credential.PendingPSK,
	)
	if err != nil {
		return err
	}
	if status == http.StatusConflict || status == http.StatusGone {
		return a.clearPendingControllerCredential(credential.PendingVersion)
	}
	if status != http.StatusOK {
		return fmt.Errorf("credential confirmation returned status %d", status)
	}
	var response protocol.ConfirmAgentCredentialResponse
	if err := json.Unmarshal(data, &response); err != nil || !response.OK ||
		response.CredentialVersion != credential.PendingVersion ||
		response.ControllerGeneration != credential.PendingGeneration {
		return fmt.Errorf("invalid credential confirmation response")
	}
	return a.activatePendingControllerCredential(
		response.CredentialVersion, response.ControllerGeneration,
	)
}

func (a *Agent) controllerEndpoint(path string) (string, error) {
	base, err := url.Parse(a.Cfg.ControllerURL)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return "", fmt.Errorf("invalid controller URL")
	}
	host := base.Hostname()
	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
	if base.Scheme != "https" && !(base.Scheme == "http" && loopback) {
		return "", fmt.Errorf("controller URL must use HTTPS")
	}
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("invalid controller path")
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	return base.String(), nil
}
