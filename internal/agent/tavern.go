package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"stcontrol/internal/protocol"
)

const tavernAdapterBodyLimit = 1 << 20

type adapterRegistrationPolicy struct {
	OK      bool   `json:"ok"`
	Mode    string `json:"mode"`
	Version int64  `json:"version"`
}

type adapterHealth struct {
	OK              bool     `json:"ok"`
	ProtocolVersion int      `json:"protocol_version"`
	TavernVersion   string   `json:"tavern_version"`
	Capabilities    []string `json:"capabilities"`
}

var requiredAdapterCapabilities = []string{
	"activity_leases", "login_handoff", "password_update", "registration_policy",
	"snapshot_boundary", "user_provision", "write_gate",
}

// collectUserStatuses is replaced by the authenticated adapter's session
// telemetry when managed-mode integration is enabled. Disk activity remains a
// conservative fallback during upgrade.
func (a *Agent) collectUserStatuses() []protocol.UserStatus {
	return a.scanUserActivityFromDisk()
}

func (a *Agent) provisionUser(ctx context.Context, req *protocol.ProvisionUserRequest) (*protocol.ProvisionUserResponse, error) {
	var out protocol.ProvisionUserResponse
	if err := a.callTavernAdapter(ctx, "/api/stcontrol/internal/users/provision", req, &out); err != nil {
		return nil, err
	}
	if !out.OK {
		return &out, fmt.Errorf("node adapter rejected user provisioning")
	}
	return &out, nil
}

func (a *Agent) setPassword(ctx context.Context, req *protocol.SetPasswordRequest) error {
	var out struct {
		OK bool `json:"ok"`
	}
	if err := a.callTavernAdapter(ctx, "/api/stcontrol/internal/users/password", req, &out); err != nil {
		return err
	}
	if !out.OK {
		return fmt.Errorf("node adapter rejected password update")
	}
	return nil
}

func (a *Agent) registrationPolicy(ctx context.Context) protocol.RegistrationPolicyReport {
	now := time.Now().UTC()
	report := protocol.RegistrationPolicyReport{
		State: "error", ExpiresAt: now, ErrorCode: "adapter_unavailable",
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var response adapterRegistrationPolicy
	if err := a.callTavernAdapter(
		probeCtx, "/api/stcontrol/internal/registration-policy", struct{}{}, &response,
	); err != nil {
		return report
	}
	if !response.OK || response.Version <= 0 ||
		(response.Mode != "open" && response.Mode != "invitation_required" && response.Mode != "closed") {
		report.ErrorCode = "invalid_policy"
		return report
	}
	freshness := 3 * time.Duration(a.Cfg.HeartbeatSec) * time.Second
	if freshness < time.Minute {
		freshness = time.Minute
	}
	if freshness > 5*time.Minute {
		freshness = 5 * time.Minute
	}
	return protocol.RegistrationPolicyReport{
		State: response.Mode, Version: response.Version, ExpiresAt: now.Add(freshness),
	}
}

func (a *Agent) compatibilityReport(ctx context.Context, info protocol.NodeInfo) protocol.NodeCompatibilityReport {
	base := []string{a.Cfg.Role, Version, info.OS, info.Arch, info.TavernVersion}
	if a.Cfg.Role == "storage" {
		return protocol.NodeCompatibilityReport{
			State: "compatible", Fingerprint: compatibilityFingerprint(append(base, "agent-storage-v1")...),
		}
	}
	report := protocol.NodeCompatibilityReport{
		State: "unknown", Fingerprint: compatibilityFingerprint(base...), ErrorCode: "adapter_unavailable",
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var health adapterHealth
	if err := a.callTavernAdapter(probeCtx, "/api/stcontrol/internal/health", struct{}{}, &health); err != nil {
		return report
	}
	capabilities := append([]string(nil), health.Capabilities...)
	sort.Strings(capabilities)
	report.Fingerprint = compatibilityFingerprint(append(base,
		fmt.Sprintf("protocol:%d", health.ProtocolVersion), strings.Join(capabilities, ","))...)
	if !health.OK || health.ProtocolVersion != 1 || !safeInventoryString(health.TavernVersion, 128) ||
		(info.TavernVersion != "" && health.TavernVersion != "" && info.TavernVersion != health.TavernVersion) {
		report.State = "incompatible"
		report.ErrorCode = "version_unsupported"
		return report
	}
	capabilitySet := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if capability == "" || len(capability) > 64 {
			report.State = "incompatible"
			report.ErrorCode = "invalid_health"
			return report
		}
		if _, exists := capabilitySet[capability]; exists {
			report.State = "incompatible"
			report.ErrorCode = "invalid_health"
			return report
		}
		capabilitySet[capability] = struct{}{}
	}
	for _, required := range requiredAdapterCapabilities {
		if _, ok := capabilitySet[required]; !ok {
			report.State = "incompatible"
			report.ErrorCode = "missing_capability"
			return report
		}
	}
	report.State = "compatible"
	report.ErrorCode = ""
	return report
}

func compatibilityFingerprint(values ...string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("stcontrol-node-compatibility:v1\n"))
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func (a *Agent) callTavernAdapter(ctx context.Context, path string, body any, out any) error {
	base, err := url.Parse(a.Cfg.TavernURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.User != nil || base.RawQuery != "" {
		return fmt.Errorf("invalid local SillyTavern URL")
	}
	host := base.Hostname()
	ip := net.ParseIP(host)
	if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("SillyTavern adapter must use a loopback URL")
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	protocol.SignRequest(req, a.Cfg.NodeID, a.Cfg.AgentPSK, payload)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("call node adapter: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, tavernAdapterBodyLimit))
	if err != nil {
		return fmt.Errorf("read node adapter response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("node adapter returned status %d", resp.StatusCode)
	}
	if out != nil && len(responseBody) != 0 {
		if err := json.Unmarshal(responseBody, out); err != nil {
			return fmt.Errorf("decode node adapter response: %w", err)
		}
	}
	return nil
}
