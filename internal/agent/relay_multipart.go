package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

const (
	relayMultipartPartBytes = int64(16 << 20)
	relayMultipartAttempts  = 8
)

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
	Received        []relayMultipartPart `json:"received"`
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

func (a *Agent) streamSnapshotRelay(
	ctx context.Context,
	req protocol.StartSnapshotRequest,
	archivePath string,
	archiveDigest [32]byte,
) error {
	endpoint, err := relayTransferEndpoint(req.RelayUploadURL, req.RelayTaskID)
	if err != nil {
		return err
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	stat, err := archive.Stat()
	_ = archive.Close()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() <= 0 || stat.Size() > maxSnapshotBytes {
		return fmt.Errorf("invalid snapshot archive size")
	}
	ciphertextBytes, err := controlcrypto.RelayCiphertextSize(stat.Size())
	if err != nil {
		return err
	}
	sessionBytes := make([]byte, 16)
	rndRead(sessionBytes)
	uploadSession := hex.EncodeToString(sessionBytes)
	start, supported, err := beginRelayMultipartUpload(
		ctx, endpoint, req, stat.Size(), ciphertextBytes, archiveDigest, uploadSession,
	)
	if !supported {
		return a.streamSnapshotRelayLegacy(ctx, req, archivePath, archiveDigest)
	}
	if err != nil {
		return err
	}
	if start.State == "stored" || start.State == "downloading" || start.State == "consumed" {
		return nil
	}
	if !start.OK || start.State != "uploading" || start.PartBytes != relayMultipartPartBytes ||
		start.PartCount != relayMultipartPartCount(ciphertextBytes) || start.CiphertextBytes != ciphertextBytes {
		return fmt.Errorf("invalid relay multipart start response")
	}
	received := make(map[int]relayMultipartPart, len(start.Received))
	for _, part := range start.Received {
		if part.Index < 0 || part.Index >= start.PartCount || part.Bytes <= 0 ||
			!validCapabilityHash(part.SHA256) {
			return fmt.Errorf("invalid relay multipart resume state")
		}
		if _, duplicate := received[part.Index]; duplicate {
			return fmt.Errorf("duplicate relay multipart resume part")
		}
		received[part.Index] = part
	}

	archive, err = os.Open(archivePath)
	if err != nil {
		return err
	}
	defer archive.Close()
	uploadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	reader, writer := io.Pipe()
	encryptionDone := make(chan error, 1)
	go func() {
		_, encryptErr := controlcrypto.EncryptRelayStream(
			uploadCtx, writer, archive, req.RelayTargetKey,
			controlcrypto.RelayCipherContext{
				TaskID: req.RelayTaskID, WorkflowID: req.WorkflowID, SnapshotID: req.SnapshotID,
			},
		)
		_ = writer.CloseWithError(encryptErr)
		encryptionDone <- encryptErr
	}()
	waited := false
	defer func() {
		if !waited {
			cancel()
			_ = reader.CloseWithError(context.Canceled)
			<-encryptionDone
		}
	}()

	fullHash := sha256.New()
	buffer := make([]byte, relayMultipartPartBytes)
	for part := 0; part < start.PartCount; part++ {
		partBytes, _ := relayMultipartSize(ciphertextBytes, part)
		chunk := buffer[:int(partBytes)]
		if _, err := io.ReadFull(reader, chunk); err != nil {
			return fmt.Errorf("read encrypted relay part %d: %w", part, err)
		}
		_, _ = fullHash.Write(chunk)
		partHash := sha256.Sum256(chunk)
		if existing, ok := received[part]; ok && existing.Bytes == partBytes &&
			existing.SHA256 == hex.EncodeToString(partHash[:]) {
			continue
		}
		if err := uploadRelayMultipartPart(
			uploadCtx, endpoint, req, stat.Size(), ciphertextBytes, archiveDigest,
			uploadSession, part, chunk, partHash,
		); err != nil {
			return err
		}
	}
	encryptErr := <-encryptionDone
	waited = true
	if encryptErr != nil {
		return fmt.Errorf("encrypt relay snapshot: %w", encryptErr)
	}
	if err := completeRelayMultipartUpload(
		ctx, endpoint, req, stat.Size(), ciphertextBytes, archiveDigest, uploadSession, fullHash.Sum(nil),
	); err != nil {
		return err
	}
	return nil
}

func beginRelayMultipartUpload(
	ctx context.Context,
	endpoint string,
	req protocol.StartSnapshotRequest,
	plaintextBytes, ciphertextBytes int64,
	archiveDigest [32]byte,
	uploadSession string,
) (relayMultipartStartResponse, bool, error) {
	var out relayMultipartStartResponse
	backoff := 250 * time.Millisecond
	for attempt := 0; attempt < relayMultipartAttempts; attempt++ {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/multipart/start", nil)
		if err != nil {
			return out, true, err
		}
		setRelayMultipartUploadHeaders(httpReq, req, plaintextBytes, ciphertextBytes, archiveDigest, uploadSession)
		resp, requestErr := snapshotHTTPClient().Do(httpReq)
		if requestErr == nil {
			data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed ||
				resp.StatusCode == http.StatusNotImplemented {
				return out, false, nil
			}
			if readErr == nil && resp.StatusCode == http.StatusOK {
				if err := json.Unmarshal(data, &out); err != nil {
					return out, true, fmt.Errorf("decode relay multipart start: %w", err)
				}
				return out, true, nil
			}
			if readErr != nil {
				requestErr = readErr
			} else if !retryableRelayMultipartStatus(resp.StatusCode) {
				return out, true, fmt.Errorf("relay multipart start returned status %d", resp.StatusCode)
			}
		}
		if attempt == relayMultipartAttempts-1 {
			if requestErr != nil {
				return out, true, fmt.Errorf("relay multipart start failed: %w", requestErr)
			}
			return out, true, fmt.Errorf("relay multipart start retry budget exhausted")
		}
		if err := waitRelayMultipartBackoff(ctx, backoff); err != nil {
			return out, true, err
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
	return out, true, fmt.Errorf("relay multipart start failed")
}

func uploadRelayMultipartPart(
	ctx context.Context,
	endpoint string,
	req protocol.StartSnapshotRequest,
	plaintextBytes, ciphertextBytes int64,
	archiveDigest [32]byte,
	uploadSession string,
	part int,
	data []byte,
	digest [32]byte,
) error {
	backoff := 250 * time.Millisecond
	for attempt := 0; attempt < relayMultipartAttempts; attempt++ {
		httpReq, err := http.NewRequestWithContext(
			ctx, http.MethodPut, endpoint+"/multipart/parts/"+strconv.Itoa(part), bytes.NewReader(data),
		)
		if err != nil {
			return err
		}
		httpReq.ContentLength = int64(len(data))
		setRelayMultipartUploadHeaders(httpReq, req, plaintextBytes, ciphertextBytes, archiveDigest, uploadSession)
		httpReq.Header.Set("X-Part-Sha256", hex.EncodeToString(digest[:]))
		resp, requestErr := snapshotHTTPClient().Do(httpReq)
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
				return nil
			}
			if !retryableRelayMultipartStatus(resp.StatusCode) {
				return fmt.Errorf("relay multipart part %d returned status %d", part, resp.StatusCode)
			}
		}
		if attempt == relayMultipartAttempts-1 {
			if requestErr != nil {
				return fmt.Errorf("relay multipart part %d failed: %w", part, requestErr)
			}
			return fmt.Errorf("relay multipart part %d retry budget exhausted", part)
		}
		if err := waitRelayMultipartBackoff(ctx, backoff); err != nil {
			return err
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
	return fmt.Errorf("relay multipart part %d failed", part)
}

func completeRelayMultipartUpload(
	ctx context.Context,
	endpoint string,
	req protocol.StartSnapshotRequest,
	plaintextBytes, ciphertextBytes int64,
	archiveDigest [32]byte,
	uploadSession string,
	ciphertextDigest []byte,
) error {
	backoff := 250 * time.Millisecond
	for attempt := 0; attempt < relayMultipartAttempts; attempt++ {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/multipart/complete", nil)
		if err != nil {
			return err
		}
		setRelayMultipartUploadHeaders(httpReq, req, plaintextBytes, ciphertextBytes, archiveDigest, uploadSession)
		httpReq.Header.Set("X-Ciphertext-Sha256", hex.EncodeToString(ciphertextDigest))
		resp, requestErr := snapshotHTTPClient().Do(httpReq)
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
				return nil
			}
			if !retryableRelayMultipartStatus(resp.StatusCode) && resp.StatusCode != http.StatusTooEarly {
				return fmt.Errorf("complete relay multipart upload returned status %d", resp.StatusCode)
			}
		}
		if attempt == relayMultipartAttempts-1 {
			if requestErr != nil {
				return fmt.Errorf("complete relay multipart upload: %w", requestErr)
			}
			return fmt.Errorf("complete relay multipart upload retry budget exhausted")
		}
		if err := waitRelayMultipartBackoff(ctx, backoff); err != nil {
			return err
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
	return fmt.Errorf("complete relay multipart upload failed")
}

func setRelayMultipartUploadHeaders(
	httpReq *http.Request,
	req protocol.StartSnapshotRequest,
	plaintextBytes, ciphertextBytes int64,
	archiveDigest [32]byte,
	uploadSession string,
) {
	httpReq.Header.Set("Content-Type", "application/vnd.stcontrol.relay.v1")
	httpReq.Header.Set("Authorization", "Bearer "+req.RelayUploadToken)
	httpReq.Header.Set("X-Workflow-Id", req.WorkflowID)
	httpReq.Header.Set("X-Snapshot-Id", req.SnapshotID)
	httpReq.Header.Set("X-Plaintext-Length", strconv.FormatInt(plaintextBytes, 10))
	httpReq.Header.Set("X-Ciphertext-Length", strconv.FormatInt(ciphertextBytes, 10))
	httpReq.Header.Set("X-Archive-Sha256", hex.EncodeToString(archiveDigest[:]))
	httpReq.Header.Set("X-Relay-Upload-Session", uploadSession)
}

func retryableRelayMultipartStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests ||
		status == http.StatusBadGateway || status == http.StatusServiceUnavailable ||
		status == http.StatusGatewayTimeout
}

func waitRelayMultipartBackoff(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func relayMultipartPartCount(ciphertextBytes int64) int {
	if ciphertextBytes <= 0 {
		return 0
	}
	return int((ciphertextBytes + relayMultipartPartBytes - 1) / relayMultipartPartBytes)
}

func relayMultipartSize(ciphertextBytes int64, part int) (int64, bool) {
	count := relayMultipartPartCount(ciphertextBytes)
	if part < 0 || part >= count {
		return 0, false
	}
	offset := int64(part) * relayMultipartPartBytes
	remaining := ciphertextBytes - offset
	if remaining > relayMultipartPartBytes {
		remaining = relayMultipartPartBytes
	}
	return remaining, remaining > 0
}

func pullRelayCiphertext(
	ctx context.Context,
	endpoint, token string,
	expiresAt time.Time,
) (*http.Response, error) {
	manifest, supported, err := pullRelayMultipartManifest(ctx, endpoint, token, expiresAt)
	if !supported {
		return pullRelayCiphertextLegacy(ctx, endpoint, token, expiresAt)
	}
	if err != nil {
		return nil, err
	}
	header := make(http.Header)
	header.Set("Content-Type", "application/vnd.stcontrol.relay.v1")
	header.Set("X-Workflow-Id", manifest.WorkflowID)
	header.Set("X-Snapshot-Id", manifest.SnapshotID)
	header.Set("X-Plaintext-Length", strconv.FormatInt(manifest.PlaintextBytes, 10))
	header.Set("X-Archive-Sha256", manifest.ArchiveSHA256)
	header.Set("X-Ciphertext-Sha256", manifest.CiphertextSHA256)
	return &http.Response{
		StatusCode: http.StatusOK, Header: header, ContentLength: manifest.CiphertextBytes,
		Body: &relayMultipartDownloadReader{
			ctx: ctx, endpoint: endpoint, token: token, expiresAt: expiresAt,
			ciphertextBytes: manifest.CiphertextBytes, partCount: manifest.PartCount,
		},
	}, nil
}

func pullRelayMultipartManifest(
	ctx context.Context,
	endpoint, token string,
	expiresAt time.Time,
) (relayMultipartManifest, bool, error) {
	var out relayMultipartManifest
	backoff := time.Second
	for {
		if !expiresAt.IsZero() && !expiresAt.After(time.Now().UTC()) {
			return out, true, fmt.Errorf("relay receive capability expired")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/multipart/manifest", nil)
		if err != nil {
			return out, true, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-STControl-Agent-Version", Version)
		resp, requestErr := snapshotHTTPClient().Do(req)
		if requestErr == nil {
			data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed ||
				resp.StatusCode == http.StatusNotImplemented {
				return out, false, nil
			}
			if readErr == nil && resp.StatusCode == http.StatusOK {
				if err := json.Unmarshal(data, &out); err != nil || !out.OK ||
					out.PartBytes != relayMultipartPartBytes || out.PartCount != relayMultipartPartCount(out.CiphertextBytes) ||
					out.PlaintextBytes <= 0 || out.CiphertextBytes <= 0 || !validCapabilityHash(out.ArchiveSHA256) ||
					!validCapabilityHash(out.CiphertextSHA256) {
					return out, true, fmt.Errorf("invalid relay multipart manifest")
				}
				return out, true, nil
			}
			if readErr != nil {
				requestErr = readErr
			} else if resp.StatusCode != http.StatusTooEarly && resp.StatusCode != http.StatusServiceUnavailable &&
				resp.StatusCode != http.StatusBadGateway && resp.StatusCode != http.StatusGatewayTimeout {
				return out, true, fmt.Errorf("relay multipart manifest returned status %d", resp.StatusCode)
			}
		}
		if err := waitRelayMultipartBackoff(ctx, backoff); err != nil {
			if requestErr != nil {
				return out, true, fmt.Errorf("relay multipart manifest: %w", requestErr)
			}
			return out, true, err
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

type relayMultipartDownloadReader struct {
	ctx             context.Context
	endpoint        string
	token           string
	expiresAt       time.Time
	ciphertextBytes int64
	partCount       int
	part            int
	current         *bytes.Reader
	closed          bool
}

func (reader *relayMultipartDownloadReader) Read(destination []byte) (int, error) {
	if reader.closed {
		return 0, io.ErrClosedPipe
	}
	for reader.current == nil || reader.current.Len() == 0 {
		if reader.part >= reader.partCount {
			return 0, io.EOF
		}
		data, err := downloadRelayMultipartPart(
			reader.ctx, reader.endpoint, reader.token, reader.expiresAt,
			reader.ciphertextBytes, reader.part,
		)
		if err != nil {
			return 0, err
		}
		reader.part++
		reader.current = bytes.NewReader(data)
	}
	return reader.current.Read(destination)
}

func (reader *relayMultipartDownloadReader) Close() error {
	reader.closed = true
	reader.current = nil
	return nil
}

func downloadRelayMultipartPart(
	ctx context.Context,
	endpoint, token string,
	expiresAt time.Time,
	ciphertextBytes int64,
	part int,
) ([]byte, error) {
	expectedBytes, ok := relayMultipartSize(ciphertextBytes, part)
	if !ok {
		return nil, fmt.Errorf("invalid relay multipart part")
	}
	backoff := 250 * time.Millisecond
	for attempt := 0; attempt < relayMultipartAttempts; attempt++ {
		if !expiresAt.IsZero() && !expiresAt.After(time.Now().UTC()) {
			return nil, fmt.Errorf("relay receive capability expired")
		}
		req, err := http.NewRequestWithContext(
			ctx, http.MethodGet, endpoint+"/multipart/parts/"+strconv.Itoa(part), nil,
		)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, requestErr := snapshotHTTPClient().Do(req)
		if requestErr == nil {
			data, readErr := io.ReadAll(io.LimitReader(resp.Body, expectedBytes+1))
			_ = resp.Body.Close()
			if readErr == nil && resp.StatusCode == http.StatusOK && resp.ContentLength == expectedBytes &&
				int64(len(data)) == expectedBytes && resp.Header.Get("Content-Type") == "application/vnd.stcontrol.relay.v1" &&
				resp.Header.Get("X-Part-Index") == strconv.Itoa(part) {
				return data, nil
			}
			if readErr != nil {
				requestErr = readErr
			} else if !retryableRelayMultipartStatus(resp.StatusCode) {
				return nil, fmt.Errorf("relay multipart download part %d returned status %d", part, resp.StatusCode)
			}
		}
		if attempt == relayMultipartAttempts-1 {
			if requestErr != nil {
				return nil, fmt.Errorf("relay multipart download part %d: %w", part, requestErr)
			}
			return nil, fmt.Errorf("relay multipart download part %d retry budget exhausted", part)
		}
		if err := waitRelayMultipartBackoff(ctx, backoff); err != nil {
			return nil, err
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
	return nil, fmt.Errorf("relay multipart download part %d failed", part)
}
