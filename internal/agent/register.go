package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"stcontrol/internal/protocol"
)

// RegisterToController 子控首次向总控注册（用一次性、节点/角色限定令牌）。
// 成功后回填到配置。
func (a *Agent) RegisterToController(ctx context.Context, token string) error {
	info, err := ProbeTavern(a.Cfg.TavernDir)
	if err != nil {
		info = &protocol.NodeInfo{}
	}

	reqBody := protocol.RegisterAgentRequest{
		Token: token, Role: a.Cfg.Role, Info: *info,
		Fingerprint: protocol.NodeFingerprint(*info),
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	endpoint, err := a.controllerEndpoint("/api/agent/register")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("连接总控失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("总控拒绝注册: 状态 %d", resp.StatusCode)
	}

	var out protocol.RegisterAgentResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	a.Cfg.NodeID = out.NodeID
	a.Cfg.AgentPSK = out.AgentPSK
	a.Cfg.CredentialVersion = out.CredentialVersion
	a.Cfg.ControllerGeneration = out.ControllerGeneration
	return nil
}
