package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const relayContentType = "application/vnd.stcontrol.relay.v1"

type relayTransferStore interface {
	ClaimRelayUpload(context.Context, string, []byte, int64, int64, []byte, time.Time, time.Duration) (*store.RelayTransfer, error)
	CompleteRelayUpload(context.Context, string, []byte, []byte, int64, string, time.Time) error
	ReleaseRelayUpload(context.Context, string, []byte, time.Time) error
	ClaimRelayDownload(context.Context, string, []byte, time.Time, time.Duration) (*store.RelayTransfer, error)
	ReleaseRelayDownload(context.Context, string, []byte, time.Time) error
	CompleteRelayDownload(context.Context, string, []byte, time.Time) (string, error)
	ExpireRelayTransfers(context.Context, time.Time, int) ([]store.ExpiredRelayTransfer, error)
}

type relayDataPlane struct {
	store     relayTransferStore
	root      string
	maxBytes  int64
	retention time.Duration
	slots     chan struct{}
}

func newRelayDataPlane(cfg configRelayView, transferStore relayTransferStore) (*relayDataPlane, error) {
	if transferStore == nil || cfg.DataDir == "" || cfg.MaxBytes <= 0 || cfg.RetentionMin <= 0 ||
		cfg.MaxConcurrent <= 0 || cfg.MaxConcurrent > 128 {
		return nil, fmt.Errorf("invalid encrypted relay configuration")
	}
	root, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve relay data directory: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create relay data directory: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("restrict relay data directory: %w", err)
	}
	return &relayDataPlane{
		store: transferStore, root: root, maxBytes: cfg.MaxBytes,
		retention: time.Duration(cfg.RetentionMin) * time.Minute,
		slots:     make(chan struct{}, cfg.MaxConcurrent),
	}, nil
}

// configRelayView avoids coupling handler tests to every Controller setting.
type configRelayView struct {
	DataDir       string
	MaxBytes      int64
	RetentionMin  int
	MaxConcurrent int
}

func (s *Server) relayDataPlane() (*relayDataPlane, error) {
	return newRelayDataPlane(configRelayView{
		DataDir: s.Cfg.Relay.DataDir, MaxBytes: s.Cfg.Relay.MaxBytes,
		RetentionMin: s.Cfg.Relay.RetentionMin, MaxConcurrent: s.Cfg.Relay.MaxConcurrent,
	}, s.Store)
}

func (relay *relayDataPlane) Handler() http.Handler {
	router := chi.NewRouter()
	router.Put("/relay/v1/transfers/{id}", relay.handleUpload)
	router.Get("/relay/v1/transfers/{id}", relay.handleDownload)
	router.Post("/relay/v1/transfers/{id}/complete", relay.handleComplete)
	return router
}

func (relay *relayDataPlane) acquire(w http.ResponseWriter, r *http.Request) bool {
	select {
	case relay.slots <- struct{}{}:
		return true
	case <-r.Context().Done():
		return false
	default:
		w.Header().Set("Retry-After", "5")
		protocol.WriteError(w, http.StatusServiceUnavailable, "加密中转当前繁忙")
		return false
	}
}

func (relay *relayDataPlane) release() { <-relay.slots }

func (relay *relayDataPlane) handleUpload(w http.ResponseWriter, r *http.Request) {
	relayHeaders(w)
	if !relay.acquire(w, r) {
		return
	}
	defer relay.release()
	id := chi.URLParam(r, "id")
	tokenHash, ok := relayBearerHash(r)
	plaintextBytes, plainErr := strconv.ParseInt(r.Header.Get("X-Plaintext-Length"), 10, 64)
	archiveSHA256, hashErr := hex.DecodeString(r.Header.Get("X-Archive-Sha256"))
	if !ok || !isUUID(id) || plainErr != nil || plaintextBytes <= 0 || hashErr != nil ||
		len(archiveSHA256) != sha256.Size || r.Header.Get("Content-Type") != relayContentType ||
		r.ContentLength <= 0 || r.ContentLength > relay.maxBytes {
		protocol.WriteError(w, http.StatusForbidden, "中转上传授权无效")
		return
	}
	expectedCiphertextBytes, err := controlcrypto.RelayCiphertextSize(plaintextBytes)
	if err != nil || expectedCiphertextBytes != r.ContentLength {
		protocol.WriteError(w, http.StatusRequestEntityTooLarge, "中转密文大小无效")
		return
	}
	now := time.Now().UTC()
	transfer, err := relay.store.ClaimRelayUpload(
		r.Context(), id, tokenHash, plaintextBytes, r.ContentLength,
		archiveSHA256, now, relay.retention,
	)
	if err != nil || transfer == nil || transfer.WorkflowID != r.Header.Get("X-Workflow-Id") ||
		transfer.SnapshotID != r.Header.Get("X-Snapshot-Id") || r.ContentLength > transfer.MaxCiphertextBytes {
		protocol.WriteError(w, http.StatusForbidden, "中转上传授权无效")
		return
	}
	if transfer.State == "stored" || transfer.State == "downloading" || transfer.State == "consumed" {
		w.Header().Set("Connection", "close")
		_ = r.Body.Close()
		protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "state": transfer.State})
		return
	}
	temporary, err := os.CreateTemp(relay.root, ".relay-upload-*.ciphertext")
	if err != nil {
		_ = relay.store.ReleaseRelayUpload(r.Context(), id, tokenHash, time.Now().UTC())
		protocol.WriteError(w, http.StatusInsufficientStorage, "中转暂存不可用")
		return
	}
	path := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = relay.store.ReleaseRelayUpload(r.Context(), id, tokenHash, time.Now().UTC())
		protocol.WriteError(w, http.StatusInsufficientStorage, "中转暂存不可用")
		return
	}
	hash := sha256.New()
	r.Body = http.MaxBytesReader(w, r.Body, expectedCiphertextBytes)
	written, copyErr := io.Copy(temporary, io.TeeReader(r.Body, hash))
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	directorySyncErr := syncRelayDirectory(relay.root)
	if copyErr != nil || syncErr != nil || closeErr != nil || directorySyncErr != nil || written != expectedCiphertextBytes {
		_ = relay.store.ReleaseRelayUpload(r.Context(), id, tokenHash, time.Now().UTC())
		protocol.WriteError(w, http.StatusUnprocessableEntity, "中转密文上传不完整")
		return
	}
	if err := relay.store.CompleteRelayUpload(
		r.Context(), id, tokenHash, hash.Sum(nil), written, path, time.Now().UTC(),
	); err != nil {
		_ = relay.store.ReleaseRelayUpload(r.Context(), id, tokenHash, time.Now().UTC())
		protocol.WriteError(w, http.StatusConflict, "中转上传状态冲突")
		return
	}
	keep = true
	protocol.WriteJSON(w, http.StatusCreated, map[string]any{"ok": true, "state": "stored"})
}

func (relay *relayDataPlane) handleDownload(w http.ResponseWriter, r *http.Request) {
	relayHeaders(w)
	if !relay.acquire(w, r) {
		return
	}
	defer relay.release()
	id := chi.URLParam(r, "id")
	tokenHash, ok := relayBearerHash(r)
	if !ok || !isUUID(id) {
		protocol.WriteError(w, http.StatusForbidden, "中转下载授权无效")
		return
	}
	transfer, err := relay.store.ClaimRelayDownload(r.Context(), id, tokenHash, time.Now().UTC(), relay.retention)
	if err != nil || transfer == nil || !transfer.StoragePath.Valid || !transfer.CiphertextBytes.Valid ||
		!transfer.PlaintextBytes.Valid || len(transfer.ArchiveSHA256) != sha256.Size ||
		len(transfer.CiphertextSHA256) != sha256.Size {
		w.Header().Set("Retry-After", "2")
		protocol.WriteError(w, http.StatusTooEarly, "中转密文尚未就绪")
		return
	}
	path, err := relay.safeSpoolPath(transfer.StoragePath.String)
	if err != nil {
		_ = relay.store.ReleaseRelayDownload(r.Context(), id, tokenHash, time.Now().UTC())
		protocol.WriteError(w, http.StatusUnprocessableEntity, "中转密文状态无效")
		return
	}
	file, err := os.Open(path)
	if err != nil {
		_ = relay.store.ReleaseRelayDownload(r.Context(), id, tokenHash, time.Now().UTC())
		protocol.WriteError(w, http.StatusGone, "中转密文不可用")
		return
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Mode()&os.ModeSymlink != 0 ||
		stat.Size() != transfer.CiphertextBytes.Int64 {
		_ = relay.store.ReleaseRelayDownload(r.Context(), id, tokenHash, time.Now().UTC())
		protocol.WriteError(w, http.StatusUnprocessableEntity, "中转密文完整性异常")
		return
	}
	w.Header().Set("Content-Type", relayContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	w.Header().Set("X-Workflow-Id", transfer.WorkflowID)
	w.Header().Set("X-Snapshot-Id", transfer.SnapshotID)
	w.Header().Set("X-Plaintext-Length", strconv.FormatInt(transfer.PlaintextBytes.Int64, 10))
	w.Header().Set("X-Archive-Sha256", hex.EncodeToString(transfer.ArchiveSHA256))
	w.Header().Set("X-Ciphertext-Sha256", hex.EncodeToString(transfer.CiphertextSHA256))
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, file); err != nil {
		_ = relay.store.ReleaseRelayDownload(context.Background(), id, tokenHash, time.Now().UTC())
	}
}

func (relay *relayDataPlane) handleComplete(w http.ResponseWriter, r *http.Request) {
	relayHeaders(w)
	id := chi.URLParam(r, "id")
	tokenHash, ok := relayBearerHash(r)
	if !ok || !isUUID(id) {
		protocol.WriteError(w, http.StatusForbidden, "中转完成授权无效")
		return
	}
	path, err := relay.store.CompleteRelayDownload(r.Context(), id, tokenHash, time.Now().UTC())
	if err != nil {
		protocol.WriteError(w, http.StatusConflict, "中转完成状态冲突")
		return
	}
	if safePath, err := relay.safeSpoolPath(path); err == nil {
		_ = os.Remove(safePath)
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (relay *relayDataPlane) Cleanup(ctx context.Context) {
	expired, err := relay.store.ExpireRelayTransfers(ctx, time.Now().UTC(), 200)
	if err == nil {
		for _, item := range expired {
			if item.StoragePath.Valid {
				if path, err := relay.safeSpoolPath(item.StoragePath.String); err == nil {
					_ = os.Remove(path)
				}
			}
		}
	}
	entries, err := os.ReadDir(relay.root)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-2 * relay.retention)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".relay-upload-") {
			continue
		}
		path := filepath.Join(relay.root, entry.Name())
		if info, err := entry.Info(); err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(path)
		}
	}
}

func (relay *relayDataPlane) safeSpoolPath(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty relay spool path")
	}
	path, err := filepath.Abs(raw)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(relay.root, path)
	if err != nil || relative == "." || relative == ".." || filepath.IsAbs(relative) ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("relay spool path escaped data directory")
	}
	return path, nil
}

func relayBearerHash(r *http.Request) ([]byte, bool) {
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || len(token) < 32 || len(token) > 256 || strings.TrimSpace(token) != token {
		return nil, false
	}
	digest := sha256.Sum256([]byte(token))
	return digest[:], true
}

func relayHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func syncRelayDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validateRelayListenerConfig(cfg config.RelayConfig) error {
	listenHost, _, listenErr := net.SplitHostPort(cfg.Listen)
	if listenErr != nil {
		return fmt.Errorf("encrypted relay listener is invalid: %w", listenErr)
	}
	parsed, err := url.Parse(cfg.PublicURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return fmt.Errorf("encrypted relay public_url is invalid")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	publicLoopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
	if parsed.Scheme != "https" && !publicLoopback {
		return fmt.Errorf("encrypted relay public_url must use HTTPS")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return fmt.Errorf("encrypted relay TLS certificate and key must be configured together")
	}
	if cfg.TLSCertFile != "" && parsed.Scheme != "https" {
		return fmt.Errorf("TLS relay listener requires an HTTPS public_url")
	}
	if cfg.TLSCertFile == "" {
		listenIP := net.ParseIP(listenHost)
		if !(strings.EqualFold(listenHost, "localhost") || (listenIP != nil && listenIP.IsLoopback())) {
			return fmt.Errorf("unencrypted relay listener must bind loopback")
		}
	}
	return nil
}

func relayCleanupLoop(ctx context.Context, relay *relayDataPlane) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	relay.Cleanup(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			relay.Cleanup(ctx)
		}
	}
}
