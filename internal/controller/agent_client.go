package controller

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

// agentClient 总控调用子控的 HTTP 客户端（带 HMAC 签名）。
type agentClient struct {
	http *http.Client
}

func newAgentClient() *agentClient {
	return &agentClient{
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// callAgent 向子控发起签名请求。body 为任意可 JSON 编码的结构（GET 传 nil）。
// 返回响应体字节。
func (c *agentClient) callAgent(ctx context.Context, nodeID int64, psk, agentURL, method, path string, body any) ([]byte, int, error) {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
	}
	url := agentURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	protocol.SignRequest(req, nodeID, psk, payload)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

// provisionUser 让子控在节点上代注册用户。
func (c *agentClient) provisionUser(ctx context.Context, nodeID int64, psk, agentURL string, req *protocol.ProvisionUserRequest) (*protocol.ProvisionUserResponse, error) {
	data, status, err := c.callAgent(ctx, nodeID, psk, agentURL, http.MethodPost, "/agent/provision-user", req)
	if err != nil {
		return nil, fmt.Errorf("调用子控失败: %w", err)
	}
	var out protocol.ProvisionUserResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("子控响应解析失败 (status %d): %s", status, string(data))
	}
	if status != http.StatusOK || !out.OK {
		if out.Error == "" {
			out.Error = fmt.Sprintf("子控返回状态 %d", status)
		}
		return &out, fmt.Errorf("%s", out.Error)
	}
	return &out, nil
}

// startBackup 让源节点子控开始备份。
func (c *agentClient) startBackup(ctx context.Context, srcNodeID int64, psk, agentURL string, req *protocol.BackupStartRequest) error {
	_, status, err := c.callAgent(ctx, srcNodeID, psk, agentURL, http.MethodPost, "/agent/backup/start", req)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusAccepted {
		return fmt.Errorf("子控拒绝备份请求, 状态 %d", status)
	}
	return nil
}

// abortBackup 让子控中止备份。
func (c *agentClient) abortBackup(ctx context.Context, nodeID int64, psk, agentURL string, jobID int64) error {
	body := map[string]int64{"job_id": jobID}
	_, status, err := c.callAgent(ctx, nodeID, psk, agentURL, http.MethodPost, "/agent/backup/abort", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("中止备份失败, 状态 %d", status)
	}
	return nil
}

// scanExisting 让子控扫描既有用户。
func (c *agentClient) scanExisting(ctx context.Context, nodeID int64, psk, agentURL string) ([]protocol.ScanExistingUser, error) {
	data, status, err := c.callAgent(ctx, nodeID, psk, agentURL, http.MethodGet, "/agent/scan-existing", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("扫描失败, 状态 %d: %s", status, string(data))
	}
	var out struct {
		Users []protocol.ScanExistingUser `json:"users"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out.Users, nil
}
