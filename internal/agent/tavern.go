package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"stcontrol/internal/protocol"
)

const tavernAdapterBodyLimit = 1 << 20

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
