package controller

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
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

const (
	relayContentType      = "application/vnd.stcontrol.relay.v1"
	relayDownloadLeaseTTL = 2 * time.Minute
	relayPartBytes        = int64(16 << 20)
)

type relayTransferStore interface {
	ClaimRelayUpload(context.Context, string, []byte, int64, int64, []byte, time.Time, time.Duration) (*store.RelayTransfer, error)
	ClaimRelayMultipartUpload(context.Context, string, []byte, int64, int64, []byte, time.Time, time.Duration) (*store.RelayTransfer, error)
	CompleteRelayUpload(context.Context, string, []byte, []byte, int64, string, time.Time) error
	ReleaseRelayUpload(context.Context, string, []byte, time.Time) error
	ClaimRelayDownload(context.Context, string, []byte, time.Time, time.Duration) (*store.RelayTransfer, error)
	ContinueRelayDownload(context.Context, string, []byte, time.Time, time.Duration) (*store.RelayTransfer, error)
	ClampRelayDownloadLease(context.Context, string, []byte, time.Time, time.Duration) error
	RenewRelayDownload(context.Context, string, []byte, time.Time, time.Duration) (bool, error)
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
	router.Post("/relay/v1/transfers/{id}/multipart/start", relay.handleMultipartStart)
	router.Put("/relay/v1/transfers/{id}/multipart/parts/{part}", relay.handleMultipartUploadPart)
	router.Post("/relay/v1/transfers/{id}/multipart/complete", relay.handleMultipartUploadComplete)
	router.Get("/relay/v1/transfers/{id}/multipart/manifest", relay.handleMultipartDownloadManifest)
	router.Get("/relay/v1/transfers/{id}/multipart/parts/{part}", relay.handleMultipartDownloadPart)
	router.Post("/relay/v1/transfers/{id}/renew", relay.handleRenewDownload)
	router.Post("/relay/v1/transfers/{id}/complete", relay.handleComplete)
	return router
}

type relayUploadMetadata struct {
	id              string
	tokenHash       []byte
	uploadSession   string
	workflowID      string
	snapshotID      string
	plaintextBytes  int64
	ciphertextBytes int64
	archiveSHA256   []byte
}

type relayMultipartPart struct {
	Index  int    `json:"index"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type relayMultipartStartResponse struct {
	OK              bool                 `json:"ok"`
	State           string               `json:"state"`
	PartBytes       int64                `json:"part_bytes"`
	PartCount       int                  `json:"part_count"`
	CiphertextBytes int64                `json:"ciphertext_bytes"`
	Received        []relayMultipartPart `json:"received,omitempty"`
}

type relayMultipartManifest struct {
	OK               bool   `json:"ok"`
	WorkflowID       string `json:"workflow_id"`
	SnapshotID       string `json:"snapshot_id"`
	PlaintextBytes   int64  `json:"plaintext_bytes"`
	CiphertextBytes  int64  `json:"ciphertext_bytes"`
	ArchiveSHA256    string `json:"archive_sha256"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
	PartBytes        int64  `json:"part_bytes"`
	PartCount        int    `json:"part_count"`
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
	if err != nil || transfer == nil || relayTransportScope(transfer) != r.Header.Get("X-Workflow-Id") ||
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

func (relay *relayDataPlane) handleMultipartStart(w http.ResponseWriter, r *http.Request) {
	relayHeaders(w)
	if !relay.acquire(w, r) {
		return
	}
	defer relay.release()
	metadata, transfer, ok := relay.claimMultipartUpload(w, r)
	if !ok {
		return
	}
	response := relayMultipartStartResponse{
		OK: true, State: transfer.State, PartBytes: relayPartBytes,
		PartCount: relayPartCount(metadata.ciphertextBytes), CiphertextBytes: metadata.ciphertextBytes,
	}
	if transfer.State == "stored" || transfer.State == "downloading" || transfer.State == "consumed" {
		protocol.WriteJSON(w, http.StatusOK, response)
		return
	}
	dir, err := relay.ensureMultipartDir(metadata.id, metadata.uploadSession)
	if err != nil {
		protocol.WriteError(w, http.StatusInsufficientStorage, "中转分片暂存不可用")
		return
	}
	received, err := relay.receivedMultipartParts(dir, metadata.ciphertextBytes)
	if err != nil {
		protocol.WriteError(w, http.StatusUnprocessableEntity, "中转分片状态无效")
		return
	}
	response.Received = received
	protocol.WriteJSON(w, http.StatusOK, response)
}

func (relay *relayDataPlane) handleMultipartUploadPart(w http.ResponseWriter, r *http.Request) {
	relayHeaders(w)
	if !relay.acquire(w, r) {
		return
	}
	defer relay.release()
	metadata, transfer, ok := relay.claimMultipartUpload(w, r)
	if !ok {
		return
	}
	if transfer.State == "stored" || transfer.State == "downloading" || transfer.State == "consumed" {
		protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "state": transfer.State})
		return
	}
	part, err := strconv.Atoi(chi.URLParam(r, "part"))
	expectedBytes, sizeOK := relayPartSize(metadata.ciphertextBytes, part)
	partDigest, digestErr := hex.DecodeString(r.Header.Get("X-Part-Sha256"))
	if err != nil || !sizeOK || digestErr != nil || len(partDigest) != sha256.Size ||
		r.ContentLength != expectedBytes || expectedBytes > relayPartBytes {
		protocol.WriteError(w, http.StatusForbidden, "中转分片授权无效")
		return
	}
	dir, err := relay.ensureMultipartDir(metadata.id, metadata.uploadSession)
	if err != nil {
		protocol.WriteError(w, http.StatusInsufficientStorage, "中转分片暂存不可用")
		return
	}
	path := relayMultipartPartPath(dir, part)
	if matches, err := relayPartMatches(path, expectedBytes, partDigest); err != nil {
		protocol.WriteError(w, http.StatusUnprocessableEntity, "中转分片状态无效")
		return
	} else if matches {
		protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "state": "received", "part": part})
		return
	}
	temporary, err := os.CreateTemp(dir, ".part-upload-*")
	if err != nil {
		protocol.WriteError(w, http.StatusInsufficientStorage, "中转分片暂存不可用")
		return
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		protocol.WriteError(w, http.StatusInsufficientStorage, "中转分片暂存不可用")
		return
	}
	hash := sha256.New()
	r.Body = http.MaxBytesReader(w, r.Body, expectedBytes)
	written, copyErr := io.Copy(temporary, io.TeeReader(r.Body, hash))
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != expectedBytes ||
		!equalRelayDigest(hash.Sum(nil), partDigest) {
		protocol.WriteError(w, http.StatusUnprocessableEntity, "中转分片上传不完整")
		return
	}
	// Hard-link publication is no-replace and therefore keeps duplicate
	// requests idempotent without allowing a different ciphertext generation
	// to overwrite an already acknowledged part.
	linked := false
	if err := os.Link(temporaryPath, path); err != nil {
		if matches, matchErr := relayPartMatches(path, expectedBytes, partDigest); matchErr != nil || !matches {
			protocol.WriteError(w, http.StatusConflict, "中转分片内容冲突")
			return
		}
	} else {
		linked = true
	}
	if err := syncRelayDirectory(dir); err != nil {
		if linked {
			_ = os.Remove(path)
		}
		protocol.WriteError(w, http.StatusInsufficientStorage, "中转分片暂存不可用")
		return
	}
	protocol.WriteJSON(w, http.StatusCreated, map[string]any{"ok": true, "state": "received", "part": part})
}

func (relay *relayDataPlane) handleMultipartUploadComplete(w http.ResponseWriter, r *http.Request) {
	relayHeaders(w)
	if !relay.acquire(w, r) {
		return
	}
	defer relay.release()
	metadata, transfer, ok := relay.claimMultipartUpload(w, r)
	if !ok {
		return
	}
	wantDigest, digestErr := hex.DecodeString(r.Header.Get("X-Ciphertext-Sha256"))
	if digestErr != nil || len(wantDigest) != sha256.Size {
		protocol.WriteError(w, http.StatusForbidden, "中转分片完成授权无效")
		return
	}
	if transfer.State == "stored" || transfer.State == "downloading" || transfer.State == "consumed" {
		if !equalRelayDigest(transfer.CiphertextSHA256, wantDigest) {
			protocol.WriteError(w, http.StatusConflict, "中转分片完成摘要冲突")
			return
		}
		protocol.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "state": transfer.State})
		return
	}
	dir, err := relay.ensureMultipartDir(metadata.id, metadata.uploadSession)
	if err != nil {
		protocol.WriteError(w, http.StatusInsufficientStorage, "中转分片暂存不可用")
		return
	}
	temporary, err := os.CreateTemp(relay.root, ".relay-upload-*.ciphertext")
	if err != nil {
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
		protocol.WriteError(w, http.StatusInsufficientStorage, "中转暂存不可用")
		return
	}
	hash := sha256.New()
	var written int64
	for part := 0; part < relayPartCount(metadata.ciphertextBytes); part++ {
		expectedBytes, _ := relayPartSize(metadata.ciphertextBytes, part)
		file, err := os.Open(relayMultipartPartPath(dir, part))
		if err != nil {
			protocol.WriteError(w, http.StatusTooEarly, "中转分片尚未全部就绪")
			return
		}
		stat, statErr := file.Stat()
		if statErr != nil || !stat.Mode().IsRegular() || stat.Mode()&os.ModeSymlink != 0 || stat.Size() != expectedBytes {
			_ = file.Close()
			protocol.WriteError(w, http.StatusUnprocessableEntity, "中转分片完整性异常")
			return
		}
		count, copyErr := io.Copy(io.MultiWriter(temporary, hash), file)
		closeErr := file.Close()
		written += count
		if copyErr != nil || closeErr != nil || count != expectedBytes {
			protocol.WriteError(w, http.StatusUnprocessableEntity, "中转分片读取不完整")
			return
		}
	}
	if written != metadata.ciphertextBytes || !equalRelayDigest(hash.Sum(nil), wantDigest) {
		protocol.WriteError(w, http.StatusUnprocessableEntity, "中转分片组合摘要不匹配")
		return
	}
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	directorySyncErr := syncRelayDirectory(relay.root)
	if syncErr != nil || closeErr != nil || directorySyncErr != nil {
		protocol.WriteError(w, http.StatusInsufficientStorage, "中转暂存不可用")
		return
	}
	if err := relay.store.CompleteRelayUpload(
		r.Context(), metadata.id, metadata.tokenHash, wantDigest, written, path, time.Now().UTC(),
	); err != nil {
		protocol.WriteError(w, http.StatusConflict, "中转分片完成状态冲突")
		return
	}
	keep = true
	_ = os.RemoveAll(dir)
	protocol.WriteJSON(w, http.StatusCreated, map[string]any{"ok": true, "state": "stored"})
}

func (relay *relayDataPlane) handleMultipartDownloadManifest(w http.ResponseWriter, r *http.Request) {
	relayHeaders(w)
	if !relay.acquire(w, r) {
		return
	}
	defer relay.release()
	id := chi.URLParam(r, "id")
	tokenHash, ok := relayBearerHash(r)
	if !ok || !isUUID(id) {
		protocol.WriteError(w, http.StatusForbidden, "中转分片下载授权无效")
		return
	}
	now := time.Now().UTC()
	transfer, err := relay.store.ClaimRelayDownload(r.Context(), id, tokenHash, now, relayDownloadLeaseTTL)
	if errors.Is(err, store.ErrRelayTransferState) {
		// The manifest response may have been lost after the download lease was
		// claimed. The same bearer can immediately resume instead of waiting for
		// the lease to expire and restarting the whole ciphertext download.
		transfer, err = relay.store.ContinueRelayDownload(
			r.Context(), id, tokenHash, now, relayDownloadLeaseTTL,
		)
	}
	if errors.Is(err, store.ErrRelayTransferTerminal) {
		protocol.WriteError(w, http.StatusGone, "中转任务已结束")
		return
	}
	if err != nil || !validStoredRelayTransfer(transfer) {
		w.Header().Set("Retry-After", "2")
		protocol.WriteError(w, http.StatusTooEarly, "中转密文尚未就绪")
		return
	}
	if _, err := relay.validRelayStoragePath(transfer); err != nil {
		_ = relay.store.ReleaseRelayDownload(r.Context(), id, tokenHash, time.Now().UTC())
		protocol.WriteError(w, http.StatusUnprocessableEntity, "中转密文完整性异常")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, relayMultipartManifest{
		OK: true, WorkflowID: relayTransportScope(transfer), SnapshotID: transfer.SnapshotID,
		PlaintextBytes: transfer.PlaintextBytes.Int64, CiphertextBytes: transfer.CiphertextBytes.Int64,
		ArchiveSHA256:    hex.EncodeToString(transfer.ArchiveSHA256),
		CiphertextSHA256: hex.EncodeToString(transfer.CiphertextSHA256),
		PartBytes:        relayPartBytes, PartCount: relayPartCount(transfer.CiphertextBytes.Int64),
	})
}

func (relay *relayDataPlane) handleMultipartDownloadPart(w http.ResponseWriter, r *http.Request) {
	relayHeaders(w)
	if !relay.acquire(w, r) {
		return
	}
	defer relay.release()
	id := chi.URLParam(r, "id")
	tokenHash, ok := relayBearerHash(r)
	part, partErr := strconv.Atoi(chi.URLParam(r, "part"))
	if !ok || !isUUID(id) || partErr != nil {
		protocol.WriteError(w, http.StatusForbidden, "中转分片下载授权无效")
		return
	}
	transfer, err := relay.store.ContinueRelayDownload(
		r.Context(), id, tokenHash, time.Now().UTC(), relayDownloadLeaseTTL,
	)
	if err != nil || !validStoredRelayTransfer(transfer) {
		protocol.WriteError(w, http.StatusConflict, "中转分片下载租约已失效")
		return
	}
	partBytes, sizeOK := relayPartSize(transfer.CiphertextBytes.Int64, part)
	if !sizeOK {
		protocol.WriteError(w, http.StatusNotFound, "中转分片不存在")
		return
	}
	path, err := relay.validRelayStoragePath(transfer)
	if err != nil {
		protocol.WriteError(w, http.StatusUnprocessableEntity, "中转密文完整性异常")
		return
	}
	file, err := os.Open(path)
	if err != nil {
		protocol.WriteError(w, http.StatusGone, "中转密文不可用")
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", relayContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(partBytes, 10))
	w.Header().Set("X-Part-Index", strconv.Itoa(part))
	w.Header().Set("X-Part-Offset", strconv.FormatInt(int64(part)*relayPartBytes, 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.CopyN(w, io.NewSectionReader(file, int64(part)*relayPartBytes, partBytes), partBytes)
}

func (relay *relayDataPlane) claimMultipartUpload(
	w http.ResponseWriter,
	r *http.Request,
) (relayUploadMetadata, *store.RelayTransfer, bool) {
	metadata, ok := relay.parseMultipartUploadMetadata(r)
	if !ok {
		protocol.WriteError(w, http.StatusForbidden, "中转分片上传授权无效")
		return relayUploadMetadata{}, nil, false
	}
	transfer, err := relay.store.ClaimRelayMultipartUpload(
		r.Context(), metadata.id, metadata.tokenHash, metadata.plaintextBytes,
		metadata.ciphertextBytes, metadata.archiveSHA256, time.Now().UTC(), relay.retention,
	)
	if err != nil || transfer == nil || relayTransportScope(transfer) != metadata.workflowID ||
		transfer.SnapshotID != metadata.snapshotID || metadata.ciphertextBytes > transfer.MaxCiphertextBytes {
		protocol.WriteError(w, http.StatusForbidden, "中转分片上传授权无效")
		return relayUploadMetadata{}, nil, false
	}
	return metadata, transfer, true
}

func (relay *relayDataPlane) parseMultipartUploadMetadata(r *http.Request) (relayUploadMetadata, bool) {
	id := chi.URLParam(r, "id")
	tokenHash, tokenOK := relayBearerHash(r)
	plaintextBytes, plainErr := strconv.ParseInt(r.Header.Get("X-Plaintext-Length"), 10, 64)
	ciphertextBytes, cipherErr := strconv.ParseInt(r.Header.Get("X-Ciphertext-Length"), 10, 64)
	archiveSHA256, hashErr := hex.DecodeString(r.Header.Get("X-Archive-Sha256"))
	uploadSession := r.Header.Get("X-Relay-Upload-Session")
	sessionBytes, sessionErr := hex.DecodeString(uploadSession)
	if !tokenOK || !isUUID(id) || plainErr != nil || plaintextBytes <= 0 || cipherErr != nil ||
		ciphertextBytes <= 0 || ciphertextBytes > relay.maxBytes || hashErr != nil ||
		len(archiveSHA256) != sha256.Size || r.Header.Get("Content-Type") != relayContentType ||
		r.Header.Get("X-Workflow-Id") == "" || r.Header.Get("X-Snapshot-Id") == "" ||
		sessionErr != nil || len(sessionBytes) != 16 || uploadSession != strings.ToLower(uploadSession) {
		return relayUploadMetadata{}, false
	}
	expectedCiphertextBytes, err := controlcrypto.RelayCiphertextSize(plaintextBytes)
	if err != nil || expectedCiphertextBytes != ciphertextBytes {
		return relayUploadMetadata{}, false
	}
	return relayUploadMetadata{
		id: id, tokenHash: tokenHash, uploadSession: uploadSession,
		workflowID: r.Header.Get("X-Workflow-Id"),
		snapshotID: r.Header.Get("X-Snapshot-Id"), plaintextBytes: plaintextBytes,
		ciphertextBytes: ciphertextBytes, archiveSHA256: archiveSHA256,
	}, true
}

func relayPartCount(ciphertextBytes int64) int {
	if ciphertextBytes <= 0 {
		return 0
	}
	return int((ciphertextBytes + relayPartBytes - 1) / relayPartBytes)
}

func relayPartSize(ciphertextBytes int64, part int) (int64, bool) {
	count := relayPartCount(ciphertextBytes)
	if part < 0 || part >= count {
		return 0, false
	}
	offset := int64(part) * relayPartBytes
	remaining := ciphertextBytes - offset
	if remaining > relayPartBytes {
		remaining = relayPartBytes
	}
	return remaining, remaining > 0
}

func (relay *relayDataPlane) ensureMultipartDir(id, uploadSession string) (string, error) {
	sessionBytes, err := hex.DecodeString(uploadSession)
	if !isUUID(id) || err != nil || len(sessionBytes) != 16 || uploadSession != strings.ToLower(uploadSession) {
		return "", errors.New("invalid multipart relay id")
	}
	dir := filepath.Join(relay.root, ".relay-upload-"+id+"-"+uploadSession+".parts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("unsafe multipart relay directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func relayMultipartPartPath(dir string, part int) string {
	return filepath.Join(dir, fmt.Sprintf("%08d.part", part))
}

func relayPartMatches(path string, expectedBytes int64, expectedDigest []byte) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != expectedBytes {
		return false, errors.New("invalid relay part")
	}
	digest, err := relayFileSHA256(path)
	if err != nil {
		return false, err
	}
	return equalRelayDigest(digest, expectedDigest), nil
}

func (relay *relayDataPlane) receivedMultipartParts(dir string, ciphertextBytes int64) ([]relayMultipartPart, error) {
	parts := make([]relayMultipartPart, 0)
	for part := 0; part < relayPartCount(ciphertextBytes); part++ {
		expectedBytes, _ := relayPartSize(ciphertextBytes, part)
		path := relayMultipartPartPath(dir, part)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != expectedBytes {
			return nil, errors.New("invalid relay part")
		}
		digest, err := relayFileSHA256(path)
		if err != nil {
			return nil, err
		}
		parts = append(parts, relayMultipartPart{
			Index: part, Bytes: expectedBytes, SHA256: hex.EncodeToString(digest),
		})
	}
	return parts, nil
}

func relayFileSHA256(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func equalRelayDigest(left, right []byte) bool {
	return len(left) == sha256.Size && len(right) == sha256.Size &&
		subtle.ConstantTimeCompare(left, right) == 1
}

func validStoredRelayTransfer(transfer *store.RelayTransfer) bool {
	return transfer != nil && transfer.StoragePath.Valid && transfer.CiphertextBytes.Valid &&
		transfer.PlaintextBytes.Valid && len(transfer.ArchiveSHA256) == sha256.Size &&
		len(transfer.CiphertextSHA256) == sha256.Size
}

func (relay *relayDataPlane) validRelayStoragePath(transfer *store.RelayTransfer) (string, error) {
	if !validStoredRelayTransfer(transfer) {
		return "", errors.New("incomplete relay transfer")
	}
	path, err := relay.safeSpoolPath(transfer.StoragePath.String)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() != transfer.CiphertextBytes.Int64 {
		return "", errors.New("invalid relay storage path")
	}
	return path, nil
}

func relayTransportScope(transfer *store.RelayTransfer) string {
	if transfer == nil {
		return ""
	}
	if transfer.TransportScopeID != "" {
		return transfer.TransportScopeID
	}
	return transfer.WorkflowID
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
	now := time.Now().UTC()
	leaseTTL := relay.retention
	if compareControllerAgentVersions(
		r.Header.Get("X-STControl-Agent-Version"), minimumSelfUpdatingAgentVersion,
	) >= 0 {
		leaseTTL = relayDownloadLeaseTTL
		if err := relay.store.ClampRelayDownloadLease(r.Context(), id, tokenHash, now, leaseTTL); err != nil {
			protocol.WriteError(w, http.StatusServiceUnavailable, "中转下载恢复暂不可用")
			return
		}
	}
	transfer, err := relay.store.ClaimRelayDownload(r.Context(), id, tokenHash, now, leaseTTL)
	if errors.Is(err, store.ErrRelayTransferTerminal) {
		protocol.WriteError(w, http.StatusGone, "中转任务已结束")
		return
	}
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
	w.Header().Set("X-Workflow-Id", relayTransportScope(transfer))
	w.Header().Set("X-Snapshot-Id", transfer.SnapshotID)
	w.Header().Set("X-Plaintext-Length", strconv.FormatInt(transfer.PlaintextBytes.Int64, 10))
	w.Header().Set("X-Archive-Sha256", hex.EncodeToString(transfer.ArchiveSHA256))
	w.Header().Set("X-Ciphertext-Sha256", hex.EncodeToString(transfer.CiphertextSHA256))
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, file); err != nil {
		_ = relay.store.ReleaseRelayDownload(context.Background(), id, tokenHash, time.Now().UTC())
	}
}

func (relay *relayDataPlane) handleRenewDownload(w http.ResponseWriter, r *http.Request) {
	relayHeaders(w)
	id := chi.URLParam(r, "id")
	tokenHash, ok := relayBearerHash(r)
	if !ok || !isUUID(id) {
		protocol.WriteError(w, http.StatusForbidden, "中转续期授权无效")
		return
	}
	renewed, err := relay.store.RenewRelayDownload(
		r.Context(), id, tokenHash, time.Now().UTC(), relayDownloadLeaseTTL,
	)
	if err != nil {
		protocol.WriteError(w, http.StatusServiceUnavailable, "中转续期暂不可用")
		return
	}
	if !renewed {
		protocol.WriteError(w, http.StatusConflict, "中转下载租约已失效")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
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
		if !strings.HasPrefix(entry.Name(), ".relay-upload-") {
			continue
		}
		path := filepath.Join(relay.root, entry.Name())
		if info, err := entry.Info(); err == nil && info.ModTime().Before(cutoff) {
			if entry.IsDir() && strings.HasSuffix(entry.Name(), ".parts") {
				_ = os.RemoveAll(path)
			} else if !entry.IsDir() {
				_ = os.Remove(path)
			}
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

// validateEmbeddedRelayConfig allows the encrypted relay to share the
// Controller's existing HTTPS origin. Storage Agents then need only outbound
// access to the Controller and never need a public listener, domain or TLS
// certificate of their own.
func validateEmbeddedRelayConfig(controlPublicURL string, cfg config.RelayConfig) error {
	controlURL, controlErr := url.Parse(controlPublicURL)
	relayURL, relayErr := url.Parse(cfg.PublicURL)
	if controlErr != nil || relayErr != nil || controlURL.Host == "" || relayURL.Host == "" ||
		controlURL.User != nil || relayURL.User != nil || controlURL.RawQuery != "" || relayURL.RawQuery != "" ||
		controlURL.Fragment != "" || relayURL.Fragment != "" ||
		controlURL.Scheme != relayURL.Scheme || !strings.EqualFold(controlURL.Host, relayURL.Host) ||
		strings.TrimRight(controlURL.Path, "/") != strings.TrimRight(relayURL.Path, "/") {
		return fmt.Errorf("embedded encrypted relay public_url must match the Controller public URL")
	}
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		return fmt.Errorf("embedded encrypted relay uses the Controller TLS listener")
	}
	if cfg.DataDir == "" || cfg.MaxBytes <= 0 || cfg.RetentionMin <= 0 ||
		cfg.MaxConcurrent <= 0 || cfg.MaxConcurrent > 128 {
		return fmt.Errorf("embedded encrypted relay configuration is invalid")
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
