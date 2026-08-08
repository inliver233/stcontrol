// Package controller 实现总控 HTTP 服务。
package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// Server 总控服务。
type Server struct {
	Cfg                  *config.ControllerConfig
	Store                *store.Store
	secretKey            []byte // 用户凭据 AES 密钥
	workflowWorkerID     string
	snapshotSlots        chan struct{}
	registrationSlots    chan struct{}
	passwordSyncMu       sync.Mutex
	controlPlaneMu       sync.RWMutex
	newOperationsBlocked bool
	controlPlaneReason   string

	// 节点上用户在线状态（离线备份调度用）
	actMu    sync.Mutex
	activity map[int64]map[string]protocol.UserStatus

	oauthHTTP         *http.Client
	dummyPasswordHash string
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
	workerID, _ := newUUID()
	dummyPasswordHash, _ := controlcrypto.HashPassword("stcontrol-dummy-password-never-used")
	return &Server{
		Cfg:               cfg,
		Store:             st,
		secretKey:         secretKey,
		workflowWorkerID:  workerID,
		snapshotSlots:     make(chan struct{}, 4),
		registrationSlots: make(chan struct{}, 8),
		activity:          make(map[int64]map[string]protocol.UserStatus),
		oauthHTTP: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		dummyPasswordHash: dummyPasswordHash,
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

func currentSession(r *http.Request) *session {
	sess, _ := r.Context().Value(ctxKey("stcontrol-session")).(*session)
	return sess
}

// Handler 返回根路由。
func (s *Server) Handler() http.Handler {
	r := newRouter()
	s.routes(r)
	return r
}

// Run 启动后台任务（节点离线检测、备份调度）+ HTTP 服务。
func (s *Server) Run(ctx context.Context) error {
	if err := s.refreshControlPlaneGate(ctx); err != nil {
		return fmt.Errorf("initialize control-plane operation gate: %w", err)
	}
	var relay *relayDataPlane
	var relayServer *http.Server
	if s.Cfg.Relay.Listen != "" {
		if err := validateRelayListenerConfig(s.Cfg.Relay); err != nil {
			return err
		}
		var err error
		relay, err = s.relayDataPlane()
		if err != nil {
			return err
		}
		relayServer = &http.Server{
			Addr: s.Cfg.Relay.Listen, Handler: relay.Handler(),
			ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
			MaxHeaderBytes: 32 << 10,
		}
		if s.Cfg.Relay.TLSCertFile != "" {
			relayServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		}
	}

	go s.nodeWatchdog(ctx)
	go s.backupScheduler(ctx)
	go s.sessionJanitor(ctx)
	go s.snapshotWorkflowReconciler(ctx)
	go s.restoreWorkflowReconciler(ctx)
	go s.conflictEvidenceReconciler(ctx)
	go s.conflictResolutionReconciler(ctx)
	go s.passwordSyncReconciler(ctx)
	go s.registrationWorkflowReconciler(ctx)
	go s.independentReconciliationReconciler(ctx)

	controlServer := &http.Server{
		Addr:              s.Cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	servers := []*http.Server{controlServer}
	if relayServer != nil {
		servers = append(servers, relayServer)
	}
	errCh := make(chan error, 2)
	go func() { errCh <- controlServer.ListenAndServe() }()

	if relayServer != nil {
		go relayCleanupLoop(ctx, relay)
		go func() {
			if s.Cfg.Relay.TLSCertFile != "" {
				errCh <- relayServer.ListenAndServeTLS(s.Cfg.Relay.TLSCertFile, s.Cfg.Relay.TLSKeyFile)
				return
			}
			errCh <- relayServer.ListenAndServe()
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, server := range servers {
		_ = server.Shutdown(shutdownCtx)
	}
	if runErr == nil || errors.Is(runErr, http.ErrServerClosed) {
		return nil
	}
	return runErr
}
