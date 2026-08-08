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
	OK                     bool     `json:"ok"`
	ProtocolVersion        int      `json:"protocol_version"`
	TavernVersion          string   `json:"tavern_version"`
	Capabilities           []string `json:"capabilities"`
	IntegrationFingerprint string   `json:"integration_fingerprint"`
}

type adapterSessionResponse struct {
	OK    bool                  `json:"ok"`
	Users []protocol.UserStatus `json:"users"`
}

var requiredAdapterCapabilities = []string{
	"account_restore", "activity_leases", "local_account_proof", "login_handoff", "node_admin_handoff", "node_admin_verify", "password_update", "registration_policy",
	"snapshot_boundary", "user_provision", "write_gate", "control_mode",
}

func (a *Agent) verifyLocalUser(ctx context.Context, req protocol.VerifyLocalUserRequest) (protocol.VerifyLocalUserResponse, error) {
	var out protocol.VerifyLocalUserResponse
	if err := a.callTavernAdapter(ctx, "/api/stcontrol/internal/users/verify", req, &out); err != nil {
		return protocol.VerifyLocalUserResponse{}, err
	}
	if out.Handle != req.Handle || (out.Verified && out.LocalUserID == "") {
		return protocol.VerifyLocalUserResponse{}, fmt.Errorf("invalid local user verification")
	}
	return out, nil
}

func (a *Agent) verifyNodeAdmin(
	ctx context.Context,
	req protocol.VerifyNodeAdminRequest,
) (protocol.NodeAdminVerification, error) {
	var out protocol.NodeAdminVerification
	if err := a.callTavernAdapter(ctx, "/api/stcontrol/internal/admin/verify", req, &out); err != nil {
		return protocol.NodeAdminVerification{}, err
	}
	if out.Handle != req.Handle || (out.IsAdmin && (out.LocalUserID == "" || out.PermissionVersion <= 0)) {
		return protocol.NodeAdminVerification{}, fmt.Errorf("invalid node administrator verification")
	}
	return out, nil
}

func (a *Agent) checkNodeAdmin(
	ctx context.Context,
	req protocol.CheckNodeAdminRequest,
) (protocol.NodeAdminVerification, error) {
	var out protocol.NodeAdminVerification
	if err := a.callTavernAdapter(ctx, "/api/stcontrol/internal/admin/check", req, &out); err != nil {
		return protocol.NodeAdminVerification{}, err
	}
	if out.Handle != req.Handle || (out.IsAdmin && (out.LocalUserID == "" || out.PermissionVersion <= 0)) {
		return protocol.NodeAdminVerification{}, fmt.Errorf("invalid node administrator status")
	}
	return out, nil
}

// collectUserStatuses is replaced by the authenticated adapter's session
// telemetry when managed-mode integration is enabled. Disk activity remains a
// conservative fallback during upgrade.
func (a *Agent) collectUserStatuses(ctx context.Context) ([]protocol.UserStatus, error) {
	var response adapterSessionResponse
	if err := a.callTavernAdapter(ctx, "/api/stcontrol/internal/sessions", struct{}{}, &response); err != nil {
		return nil, err
	}
	if !response.OK || len(response.Users) > protocol.MaxAccountInventoryUsers {
		return nil, fmt.Errorf("invalid adapter session telemetry")
	}
	seen := make(map[string]struct{}, len(response.Users))
	for _, user := range response.Users {
		if !safeInventoryString(user.Handle, 128) || !validUUID(user.SessionID) || user.ActivityEpoch < 0 ||
			user.ControllerGeneration < 0 || user.LastActivity < 0 || user.LastPageHeartbeat < 0 ||
			user.LastRequest < 0 || user.InFlightReads < 0 || user.InFlightWrites < 0 ||
			(user.LoginMode != protocol.NodeModeManaged && user.LoginMode != protocol.NodeModeIndependent) {
			return nil, fmt.Errorf("invalid adapter session telemetry")
		}
		if _, exists := seen[user.SessionID]; exists {
			return nil, fmt.Errorf("duplicate adapter session telemetry")
		}
		seen[user.SessionID] = struct{}{}
	}
	return response.Users, nil
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

func (a *Agent) restoreUserAccount(
	ctx context.Context,
	req *protocol.RestoreUserAccountRequest,
) (*protocol.ProvisionUserResponse, error) {
	var out protocol.ProvisionUserResponse
	if err := a.callTavernAdapter(ctx, "/api/stcontrol/internal/users/restore", req, &out); err != nil {
		return nil, err
	}
	if !out.OK || out.Handle != req.Handle || out.LocalUserID == "" {
		return &out, fmt.Errorf("node adapter rejected account restore")
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
		fmt.Sprintf("protocol:%d", health.ProtocolVersion), strings.Join(capabilities, ","),
		health.IntegrationFingerprint)...)
	if !health.OK || health.ProtocolVersion != 1 || !safeInventoryString(health.TavernVersion, 128) ||
		!validInventoryDigest(health.IntegrationFingerprint) ||
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
	status, responseBody, err := a.postTavernAdapter(ctx, base, path, payload, "", nil)
	if err != nil {
		return err
	}
	// The upstream application protects every anonymous POST. Bootstrap its
	// cookie-backed CSRF token only when that middleware actually rejected the
	// first request; standalone adapter tests and deployments with CSRF disabled
	// incur no extra round trip.
	if status == http.StatusForbidden && bytes.Contains(bytes.ToLower(responseBody), []byte("csrf")) {
		token, cookies, csrfErr := a.fetchTavernCSRF(ctx, base)
		if csrfErr != nil {
			return csrfErr
		}
		status, responseBody, err = a.postTavernAdapter(ctx, base, path, payload, token, cookies)
		if err != nil {
			return err
		}
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("node adapter returned status %d", status)
	}
	if out != nil && len(responseBody) != 0 {
		if err := json.Unmarshal(responseBody, out); err != nil {
			return fmt.Errorf("decode node adapter response: %w", err)
		}
	}
	return nil
}

func (a *Agent) postTavernAdapter(
	ctx context.Context,
	base *url.URL,
	path string,
	payload []byte,
	csrfToken string,
	cookies []*http.Cookie,
) (int, []byte, error) {
	target := *base
	target.Path = strings.TrimRight(target.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if csrfToken != "" {
		req.Header.Set("X-CSRF-Token", csrfToken)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
	}
	protocol.SignRequest(req, a.Cfg.NodeID, a.Cfg.AgentPSK, payload)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("call node adapter: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, tavernAdapterBodyLimit+1))
	if err != nil {
		return 0, nil, fmt.Errorf("read node adapter response: %w", err)
	}
	if len(responseBody) > tavernAdapterBodyLimit {
		return 0, nil, fmt.Errorf("node adapter response too large")
	}
	return resp.StatusCode, responseBody, nil
}

func (a *Agent) fetchTavernCSRF(ctx context.Context, base *url.URL) (string, []*http.Cookie, error) {
	target := *base
	target.Path = strings.TrimRight(target.Path, "/") + "/csrf-token"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("fetch node adapter csrf token: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(body) > 4096 || resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("fetch node adapter csrf token failed")
	}
	var result struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(body, &result) != nil || result.Token == "" || len(result.Token) > 256 || len(resp.Cookies()) == 0 {
		return "", nil, fmt.Errorf("invalid node adapter csrf response")
	}
	return result.Token, resp.Cookies(), nil
}
