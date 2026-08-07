// Package agent 实现子控（探针/备份引擎）。
package agent

import (
	"context"
	"net/http"
	"sync"
	"time"

	"stcontrol/internal/config"
)

// Agent 子控。
type Agent struct {
	Cfg *config.AgentConfig

	// 进行中的备份任务 jobID -> 取消函数
	mu       sync.Mutex
	backupJobs map[int64]context.CancelFunc

	httpClient *http.Client
}

// New 创建子控。
func New(cfg *config.AgentConfig) *Agent {
	return &Agent{
		Cfg:        cfg,
		backupJobs: make(map[int64]context.CancelFunc),
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

// Version 子控版本。
const Version = "0.1.0"
