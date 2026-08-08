package agent

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

var archiveDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Handler exposes only a minimal health probe and the capability-scoped data
// plane. Controller operations are deliberately absent: Agents receive every
// privileged command over their authenticated outbound command channel.
func (a *Agent) Handler() http.Handler {
	if a.transferSlots == nil {
		a.transferSlots = make(chan struct{}, 4)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /agent/health", func(w http.ResponseWriter, _ *http.Request) {
		protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST "+a.snapshotTransferRoute()+"/{snapshotID}", a.handleSnapshotTransfer)
	return mux
}

func (a *Agent) snapshotTransferRoute() string {
	basePath := ""
	if a != nil && a.Cfg != nil && a.Cfg.TransferPublicURL != "" {
		if parsed, err := url.Parse(a.Cfg.TransferPublicURL); err == nil {
			basePath = strings.TrimRight(parsed.Path, "/")
		}
	}
	return path.Clean("/" + strings.TrimLeft(basePath+"/transfer/v1/snapshots", "/"))
}

func (a *Agent) handleSnapshotTransfer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.RawQuery != "" || r.ContentLength <= 0 || r.ContentLength > maxSnapshotBytes ||
		r.Header.Get("Content-Type") != "application/zstd" {
		protocol.WriteJSON(w, http.StatusBadRequest, protocol.APIError{
			Error: "快照传输请求无效", Code: "invalid_snapshot_transfer",
		})
		return
	}
	snapshotID := r.PathValue("snapshotID")
	workflowID := r.Header.Get("X-Workflow-Id")
	archiveDigest := r.Header.Get("X-Archive-Sha256")
	authorization := r.Header.Get("Authorization")
	if !validUUID(snapshotID) || !validUUID(workflowID) || !archiveDigestPattern.MatchString(archiveDigest) ||
		!strings.HasPrefix(authorization, "Bearer ") || len(authorization) <= len("Bearer ") ||
		len(authorization) > len("Bearer ")+512 || strings.TrimSpace(authorization) != authorization {
		protocol.WriteJSON(w, http.StatusBadRequest, protocol.APIError{
			Error: "快照传输请求无效", Code: "invalid_snapshot_transfer",
		})
		return
	}
	select {
	case a.transferSlots <- struct{}{}:
		defer func() { <-a.transferSlots }()
	default:
		w.Header().Set("Retry-After", "5")
		protocol.WriteJSON(w, http.StatusTooManyRequests, protocol.APIError{
			Error: "快照传输并发已满", Code: "snapshot_transfer_busy",
		})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSnapshotBytes)
	receipt, err := a.ReceiveSnapshot(
		r.Context(), workflowID, snapshotID,
		strings.TrimPrefix(authorization, "Bearer "), archiveDigest, r.Body,
	)
	if err != nil {
		protocol.WriteJSON(w, http.StatusUnprocessableEntity, protocol.APIError{
			Error: "快照传输未通过验证", Code: "snapshot_transfer_rejected",
		})
		return
	}
	protocol.WriteJSON(w, http.StatusOK, receipt)
}

// NewHTTPServer constructs the privileged Agent/data-plane listener. Plain
// HTTP is deliberately limited to loopback so a deployment must either use a
// local TLS reverse proxy or configure a certificate for direct exposure.
func NewHTTPServer(cfg *config.AgentConfig, handler http.Handler) (*http.Server, error) {
	if err := ValidateRuntimeConfig(cfg); err != nil {
		return nil, err
	}
	server := &http.Server{
		Addr: cfg.Listen, Handler: handler,
		ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 90 * time.Second,
		MaxHeaderBytes: 64 << 10,
	}
	if cfg.TLSCertFile != "" {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	return server, nil
}

// ValidateRuntimeConfig rejects an insecure or ambiguous Agent data-plane
// address before heartbeat and command workers are started.
func ValidateRuntimeConfig(cfg *config.AgentConfig) error {
	return validateAgentListenerConfig(cfg)
}

// ValidateRuntimeTLSFiles loads the configured pair before any command worker
// starts. ListenAndServeTLS loads it again when binding, but this preflight
// prevents a broken or unreadable pair from briefly running privileged work.
func ValidateRuntimeTLSFiles(cfg *config.AgentConfig) error {
	if cfg == nil || cfg.TLSCertFile == "" {
		return nil
	}
	if _, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
		return fmt.Errorf("agent TLS certificate/key cannot be loaded")
	}
	return nil
}

func validateAgentListenerConfig(cfg *config.AgentConfig) error {
	if cfg == nil || cfg.Listen == "" {
		return fmt.Errorf("agent listener is required")
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("invalid agent listener: %w", err)
	}
	hasCert := strings.TrimSpace(cfg.TLSCertFile) != ""
	hasKey := strings.TrimSpace(cfg.TLSKeyFile) != ""
	if hasCert != hasKey {
		return fmt.Errorf("agent TLS certificate and key must be configured together")
	}
	if !isLoopbackListenerHost(host) && !hasCert {
		return fmt.Errorf("non-loopback agent listener requires TLS")
	}
	if cfg.TransferPublicURL == "" {
		return nil
	}
	publicURL, err := url.Parse(cfg.TransferPublicURL)
	if err != nil || publicURL.Host == "" || publicURL.User != nil || publicURL.RawQuery != "" ||
		publicURL.Fragment != "" || (publicURL.Scheme != "http" && publicURL.Scheme != "https") {
		return fmt.Errorf("invalid agent transfer public URL")
	}
	basePath := publicURL.Path
	cleanPath := path.Clean(basePath)
	if strings.ContainsAny(basePath, "{}\\") ||
		(basePath != "" && basePath != "/" && strings.TrimSuffix(basePath, "/") != cleanPath) {
		return fmt.Errorf("invalid agent transfer public URL path")
	}
	if publicURL.Scheme != "https" && !isLoopbackListenerHost(publicURL.Hostname()) {
		return fmt.Errorf("agent transfer public URL must use HTTPS")
	}
	if hasCert && publicURL.Scheme != "https" {
		return fmt.Errorf("TLS agent listener requires an HTTPS transfer public URL")
	}
	return nil
}

func isLoopbackListenerHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
