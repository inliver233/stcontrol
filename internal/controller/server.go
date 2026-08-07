// Package controller 实现总控 HTTP 服务。
package controller

import (
	"context"
	"net/http"
	"sync"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// Server 总控服务。
type Server struct {
	Cfg       *config.ControllerConfig
	Store     *store.Store
	secretKey []byte // 用户凭据 AES 密钥

	// 节点上用户在线状态（离线备份调度用）
	actMu    sync.Mutex
	activity map[int64]map[string]protocol.UserStatus

	agent *agentClient
}

type session struct {
	ID                   string
	UserID               int64
	GlobalUserID         int64
	AdminID              int64
	Username             string
	IsAdmin              bool
	CSRFHash             []byte
	ExpiresAt            time.Time
	LastSeenAt           time.Time
	ControllerGeneration int64
}

// New 创建总控服务。
func New(cfg *config.ControllerConfig, st *store.Store, secretKey []byte) *Server {
	return &Server{
		Cfg:       cfg,
		Store:     st,
		secretKey: secretKey,
		activity:  make(map[int64]map[string]protocol.UserStatus),
		agent:     newAgentClient(),
	}
}

// context key
type ctxKey string

const ctxUser ctxKey = "stcontrol-user"

// CurrentUser 从请求上下文取当前登录用户 ID。
func CurrentUser(r *http.Request) (int64, bool) {
	v := r.Context().Value(ctxUser)
	if v == nil {
		return 0, false
	}
	id, ok := v.(int64)
	return id, ok
}

// Handler 返回根路由。
func (s *Server) Handler() http.Handler {
	r := newRouter()
	s.routes(r)
	return r
}

// Run 启动后台任务（节点离线检测、备份调度）+ HTTP 服务。
func (s *Server) Run(ctx context.Context) error {
	go s.nodeWatchdog(ctx)
	go s.backupScheduler(ctx)
	go s.sessionJanitor(ctx)

	srv := &http.Server{
		Addr:              s.Cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	return srv.ListenAndServe()
}
