package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"stcontrol/internal/protocol"
)

// RegisterToController 子控首次向总控注册（用一次性令牌）, 获取 node_id + agent_psk。
// 成功后回填到配置。
func (a *Agent) RegisterToController(ctx context.Context, token, name, agentURL string) error {
	info, err := ProbeTavern(a.Cfg.TavernDir)
	if err != nil {
		info = &protocol.NodeInfo{}
	}

	reqBody := protocol.RegisterAgentRequest{
		Token:    token,
		Name:     name,
		Role:     a.Cfg.Role,
		Info:     *info,
		AgentURL: agentURL,
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	url := a.Cfg.ControllerURL + "/api/agent/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
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
	return nil
}
