package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

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
	info, _ := ProbeTavern(a.Cfg.TavernDir)
	cpu, mem, disk, _ := CollectMetrics(a.Cfg.TavernDir)
	users := a.collectUserStatuses()

	reqBody := protocol.HeartbeatRequest{
		NodeID:        a.Cfg.NodeID,
		AgentVersion:  Version,
		TavernVersion: info.TavernVersion,
		CPUPct:        cpu,
		MemPct:        mem,
		DiskPct:       disk,
		Users:         users,
	}
	if err := a.callController(ctx, http.MethodPost, "/api/agent/heartbeat", reqBody, nil); err != nil {
		log.Printf("心跳上报失败: %v", err)
	}
}

// callController 向总控发起签名请求。respOut 若非 nil 则解析 JSON 响应。
func (a *Agent) callController(ctx context.Context, method, path string, body any, respOut any) error {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	url := a.Cfg.ControllerURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	protocol.SignRequest(req, a.Cfg.NodeID, a.Cfg.AgentPSK, payload)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if respOut != nil {
		return json.NewDecoder(resp.Body).Decode(respOut)
	}
	return nil
}
