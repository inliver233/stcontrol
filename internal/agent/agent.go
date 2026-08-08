// Package agent 实现子控（探针/备份引擎）。
package agent

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"stcontrol/internal/config"
)

// Agent 子控。
type Agent struct {
	Cfg *config.AgentConfig

	// 进行中的备份任务 jobID -> 取消函数
	mu         sync.Mutex
	backupJobs map[int64]context.CancelFunc

	httpClient     *http.Client
	commandSlots   chan struct{}
	transferSlots  chan struct{}
	stateMu        sync.Mutex
	auditMu        sync.Mutex
	adapterNonceMu sync.Mutex
	adapterNonces  map[string]time.Time
	state          agentRuntimeState
}

// New 创建子控。
func New(cfg *config.AgentConfig) (*Agent, error) {
	if cfg == nil {
		return nil, fmt.Errorf("agent config is required")
	}
	if cfg.TavernAdapterPSK == "" {
		cfg.TavernAdapterPSK = cfg.AgentPSK
	}
	if cfg.Role == "storage" {
		if cfg.BackupDir == "" {
			return nil, fmt.Errorf("storage agent backup directory is required")
		}
		if err := os.MkdirAll(cfg.BackupDir, 0o700); err != nil {
			return nil, fmt.Errorf("create storage backup directory: %w", err)
		}
	}
	agent := &Agent{
		Cfg:        cfg,
		backupJobs: make(map[int64]context.CancelFunc),
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		commandSlots:  make(chan struct{}, 8),
		transferSlots: make(chan struct{}, 4),
		adapterNonces: make(map[string]time.Time),
	}
	if err := agent.loadRuntimeState(); err != nil {
		return nil, fmt.Errorf("load agent runtime state: %w", err)
	}
	return agent, nil
}

func (a *Agent) adapterPSK() string {
	if a == nil || a.Cfg == nil {
		return ""
	}
	if a.Cfg.TavernAdapterPSK != "" {
		return a.Cfg.TavernAdapterPSK
	}
	return a.Cfg.AgentPSK
}

// Version 子控版本。
const Version = "0.2.0"
