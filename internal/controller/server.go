// Package controller 实现总控 HTTP 服务。
package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// Server 总控服务。
type Server struct {
	Cfg                   *config.ControllerConfig
	Store                 *store.Store
	secretKey             []byte // 用户凭据 AES 密钥
	workflowWorkerID      string
	snapshotSlots         chan struct{}
	replicaIntegritySlots chan struct{}
	nodeRetirementSlots   chan struct{}
	userDataFaultSlots    chan struct{}
	registrationSlots     chan struct{}
	passwordSyncMu        sync.Mutex
	controlPlaneMu        sync.RWMutex
	newOperationsBlocked  bool
	controlPlaneReason    string

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
		Cfg:                   cfg,
		Store:                 st,
		secretKey:             secretKey,
		workflowWorkerID:      workerID,
		snapshotSlots:         make(chan struct{}, 4),
		replicaIntegritySlots: make(chan struct{}, 2),
		nodeRetirementSlots:   make(chan struct{}, 2),
		userDataFaultSlots:    make(chan struct{}, 2),
		registrationSlots:     make(chan struct{}, 8),
		activity:              make(map[int64]map[string]protocol.UserStatus),
		oauthHTTP: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		dummyPasswordHash: dummyPasswordHash,
	}
}

func (s *Server) activityLeaseTTL() time.Duration {
	seconds := 0
	if s != nil && s.Cfg != nil {
		seconds = s.Cfg.Activity.LeaseTTLSec
	}
	if seconds <= 0 {
		seconds = config.DefaultController().Activity.LeaseTTLSec
	}
	return time.Duration(seconds) * time.Second
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
	if err := ValidateRuntimeConfig(s.Cfg); err != nil {
		return err
	}
	if err := ValidateRuntimeTLSFiles(s.Cfg); err != nil {
		return err
	}
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
	go s.replicaIntegrityReconciler(ctx)
	go s.restoreWorkflowReconciler(ctx)
	go s.conflictEvidenceReconciler(ctx)
	go s.conflictResolutionReconciler(ctx)
	go s.passwordSyncReconciler(ctx)
	go s.registrationWorkflowReconciler(ctx)
	go s.independentReconciliationReconciler(ctx)
	go s.nodeRetirementReconciler(ctx)
	go s.userDataFaultReconciler(ctx)

	controlServer := newControlHTTPServer(s.Cfg, s.Handler())
	servers := []*http.Server{controlServer}
	if relayServer != nil {
		servers = append(servers, relayServer)
	}
	errCh := make(chan error, 2)
	go func() {
		if s.Cfg.TLSCertFile != "" {
			errCh <- controlServer.ListenAndServeTLS(s.Cfg.TLSCertFile, s.Cfg.TLSKeyFile)
			return
		}
		errCh <- controlServer.ListenAndServe()
	}()

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

// ValidateRuntimeConfig rejects insecure listeners before the process opens a
// database connection or logs any configured endpoint.
func ValidateRuntimeConfig(cfg *config.ControllerConfig) error {
	if err := validateControlListenerConfig(cfg); err != nil {
		return err
	}
	if cfg.Activity.LeaseTTLSec < 60 || cfg.Activity.LeaseTTLSec > 24*60*60 {
		return fmt.Errorf("activity lease TTL must be between 60 and 86400 seconds")
	}
	if cfg.Backup.OfflineGraceMin < 1 || cfg.Backup.OfflineGraceMin > 24*60 {
		return fmt.Errorf("offline backup grace must be between 1 and 1440 minutes")
	}
	if cfg.Relay.Listen != "" {
		return validateRelayListenerConfig(cfg.Relay)
	}
	return nil
}

// ValidateRuntimeTLSFiles loads all configured server pairs before database
// initialization or background reconciliation begins.
func ValidateRuntimeTLSFiles(cfg *config.ControllerConfig) error {
	if cfg == nil {
		return fmt.Errorf("controller configuration is required")
	}
	pairs := []struct {
		name string
		cert string
		key  string
	}{
		{name: "control", cert: cfg.TLSCertFile, key: cfg.TLSKeyFile},
		{name: "relay", cert: cfg.Relay.TLSCertFile, key: cfg.Relay.TLSKeyFile},
	}
	for _, pair := range pairs {
		if pair.cert == "" {
			continue
		}
		if _, err := tls.LoadX509KeyPair(pair.cert, pair.key); err != nil {
			return fmt.Errorf("%s TLS certificate/key cannot be loaded", pair.name)
		}
	}
	return nil
}

func newControlHTTPServer(cfg *config.ControllerConfig, handler http.Handler) *http.Server {
	server := &http.Server{
		Addr: cfg.Listen, Handler: handler,
		ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 90 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	if cfg.TLSCertFile != "" {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	return server
}

// validateControlListenerConfig makes plaintext an explicit loopback-only
// development/reverse-proxy mode. A directly exposed listener must terminate
// TLS itself; the advertised URL may only be plaintext on loopback.
func validateControlListenerConfig(cfg *config.ControllerConfig) error {
	if cfg == nil || cfg.Listen == "" || cfg.PublicURL == "" {
		return fmt.Errorf("control listener and public URL are required")
	}
	publicURL, err := url.Parse(cfg.PublicURL)
	if err != nil || publicURL.Host == "" || publicURL.User != nil || publicURL.RawQuery != "" ||
		publicURL.Fragment != "" || (publicURL.Scheme != "http" && publicURL.Scheme != "https") {
		return fmt.Errorf("invalid control public URL")
	}
	publicLoopback := loopbackHost(publicURL.Hostname())
	if publicURL.Scheme != "https" && !publicLoopback {
		return fmt.Errorf("control public URL must use HTTPS")
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("invalid control listener: %w", err)
	}
	listenerLoopback := loopbackHost(host)
	hasCert := strings.TrimSpace(cfg.TLSCertFile) != ""
	hasKey := strings.TrimSpace(cfg.TLSKeyFile) != ""
	if hasCert != hasKey {
		return fmt.Errorf("control TLS certificate and key must be configured together")
	}
	if !listenerLoopback && !hasCert {
		return fmt.Errorf("non-loopback control listener requires TLS")
	}
	if hasCert && publicURL.Scheme != "https" {
		return fmt.Errorf("TLS control listener requires an HTTPS public URL")
	}
	return nil
}

func loopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
