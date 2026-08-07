package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"stcontrol/internal/protocol"
)

// collectUserStatuses 从酒馆收集各用户在线状态。
// 通过酒馆的内部接口（若有）或系统监控端点获取; 当前实现读取酒馆 data 目录活动推断,
// 并尝试调用酒馆提供的在线状态 API（需要管理员凭据时降级为空）。
func (a *Agent) collectUserStatuses() []protocol.UserStatus {
	// TODO: 与酒馆对接 systemMonitor 的真实在线状态。
	// 现阶段: 读取 data 目录下用户目录的最近修改时间作为 lastActivity 近似,
	// isOnline 无法精确判断时由总控依据心跳间隔推断。
	return a.scanUserActivityFromDisk()
}

// provisionUser 在节点本地调用酒馆 /api/users/register 代注册用户。
func (a *Agent) provisionUser(ctx context.Context, req *protocol.ProvisionUserRequest) (*protocol.ProvisionUserResponse, error) {
	body := map[string]string{
		"handle":          req.Handle,
		"name":            req.Name,
		"password":        req.Password,
		"confirmPassword": req.Password,
	}
	if req.InvitationCode != "" {
		body["invitationCode"] = req.InvitationCode
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	url := a.Cfg.TavernURL + "/api/users/register"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("调用酒馆注册接口失败: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		// 酒馆返回 {error: "..."}
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &e)
		errMsg := e.Error
		if errMsg == "" {
			errMsg = fmt.Sprintf("酒馆返回状态 %d", resp.StatusCode)
		}
		return &protocol.ProvisionUserResponse{OK: false, Error: errMsg}, nil
	}
	return &protocol.ProvisionUserResponse{OK: true, Handle: req.Handle}, nil
}

// setPassword 修改节点用户密码（总控改密同步用）。
// 注意: 酒馆需有对应接口; 若无则通过管理员接口实现。此处调用酒馆管理员改密端点。
func (a *Agent) setPassword(ctx context.Context, handle, newPassword string) error {
	// TODO: 与酒馆对接真实的改密接口（需要管理员凭据或专用内部接口）。
	// 现阶段返回未实现, 由后续酒馆改造补充专用接口。
	return fmt.Errorf("节点改密接口尚未实现(需酒馆配合)")
}
