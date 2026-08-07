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
	protocol.SignRequest(req, a.Cfg.NodeID, a.Cfg.AgentPSK, payload)

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
