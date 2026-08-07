package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/shirou/gopsutil/v3/disk"
	"stcontrol/internal/protocol"
)

const (
	snapshotManifestPath = ".stcontrol/manifest.json"
	maxSnapshotFiles     = 100_000
	maxSnapshotBytes     = int64(100 << 30)
	maxSnapshotFileBytes = int64(10 << 30)
	maxManifestBytes     = int64(32 << 20)
	maxDecoderWindow     = uint64(64 << 20)
)

type snapshotGateRequest struct {
	WorkflowID    string `json:"workflow_id"`
	SnapshotID    string `json:"snapshot_id"`
	GlobalUserID  int64  `json:"global_user_id"`
	Handle        string `json:"handle"`
	ActivityEpoch int64  `json:"activity_epoch"`
}

type snapshotGateResponse struct {
	OK          bool   `json:"ok"`
	Drained     bool   `json:"drained"`
	FreezeToken string `json:"freeze_token"`
}

type snapshotReleaseRequest struct {
	WorkflowID    string `json:"workflow_id"`
	SnapshotID    string `json:"snapshot_id"`
	Handle        string `json:"handle"`
	ActivityEpoch int64  `json:"activity_epoch"`
	FreezeToken   string `json:"freeze_token"`
}

func (a *Agent) RunSnapshot(ctx context.Context, req protocol.StartSnapshotRequest) (protocol.SnapshotTransferReceipt, error) {
	if runtime.GOOS != "linux" {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("snapshot publication is enabled only on Linux")
	}
	if err := validateStartSnapshotRequest(req); err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	snapshotCtx, cancel := context.WithCancel(ctx)
	if !a.registerSnapshotJob(req.JobID, cancel) {
		cancel()
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("snapshot job already running")
	}
	defer func() {
		cancel()
		a.unregisterSnapshotJob(req.JobID)
	}()

	gate, err := a.quiesceSnapshotUser(snapshotCtx, req)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	released := false
	defer func() {
		if !released {
			releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer releaseCancel()
			_ = a.releaseSnapshotUser(releaseCtx, req, gate.FreezeToken)
		}
	}()
	if err := a.reportSnapshotProgress(snapshotCtx, req.WorkflowID, req.SnapshotID, "drained"); err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	if err := a.reportSnapshotProgress(snapshotCtx, req.WorkflowID, req.SnapshotID, "snapshotting"); err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	taskRoot, err := a.sourceSnapshotTaskPath(req.WorkflowID, req.SnapshotID)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	if err := resetTaskDirectory(taskRoot); err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	defer removeTaskDirectory(taskRoot)
	snapshotDir := filepath.Join(taskRoot, "immutable")
	manifest, totalBytes, err := a.copySnapshotTree(snapshotCtx, req, snapshotDir)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	manifestDigest := sha256.Sum256(manifestJSON)
	archivePath := filepath.Join(taskRoot, "snapshot.tar.zst")
	if err := createSnapshotArchive(snapshotCtx, archivePath, snapshotDir, manifestJSON, manifest.Files); err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	archiveDigest, err := hashFile(archivePath)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	if err := a.releaseSnapshotUser(snapshotCtx, req, gate.FreezeToken); err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	released = true
	if err := a.reportSnapshotProgress(snapshotCtx, req.WorkflowID, req.SnapshotID, "transferring"); err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}

	receipt, err := a.streamSnapshot(snapshotCtx, req, archivePath, archiveDigest)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	if receipt.SnapshotID != req.SnapshotID || receipt.ManifestSHA256 != hex.EncodeToString(manifestDigest[:]) ||
		receipt.ArchiveSHA256 != hex.EncodeToString(archiveDigest[:]) ||
		receipt.FileCount != int64(len(manifest.Files)) || receipt.TotalBytes != totalBytes {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("target receipt mismatch")
	}
	return receipt, nil
}

func (a *Agent) reportSnapshotProgress(ctx context.Context, workflowID, snapshotID, state string) error {
	return a.callController(ctx, http.MethodPost, "/api/agent/snapshots/progress", protocol.SnapshotProgressRequest{
		WorkflowID: workflowID, SnapshotID: snapshotID, State: state,
	}, nil)
}

func validateStartSnapshotRequest(req protocol.StartSnapshotRequest) error {
	if req.JobID <= 0 || !validUUID(req.WorkflowID) || !validUUID(req.SnapshotID) || req.GlobalUserID <= 0 ||
		!validHandle(req.Handle) || req.ActivityEpoch <= 0 || req.TargetNodeID <= 0 ||
		req.TransferCapability == "" || !req.CapabilityExpires.After(time.Now().UTC()) ||
		(req.DestinationKind != "archive" && req.DestinationKind != "hot_standby") {
		return fmt.Errorf("invalid snapshot request")
	}
	return nil
}

func (a *Agent) registerSnapshotJob(jobID int64, cancel context.CancelFunc) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.backupJobs[jobID]; exists {
		return false
	}
	a.backupJobs[jobID] = cancel
	return true
}

func (a *Agent) unregisterSnapshotJob(jobID int64) {
	a.mu.Lock()
	delete(a.backupJobs, jobID)
	a.mu.Unlock()
}

func (a *Agent) AbortBackup(jobID int64) {
	a.mu.Lock()
	cancel := a.backupJobs[jobID]
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (a *Agent) quiesceSnapshotUser(ctx context.Context, req protocol.StartSnapshotRequest) (snapshotGateResponse, error) {
	var out snapshotGateResponse
	err := a.callTavernAdapter(ctx, "/api/stcontrol/internal/snapshots/quiesce", snapshotGateRequest{
		WorkflowID: req.WorkflowID, SnapshotID: req.SnapshotID, GlobalUserID: req.GlobalUserID,
		Handle: req.Handle, ActivityEpoch: req.ActivityEpoch,
	}, &out)
	if err != nil || !out.OK || !out.Drained || out.FreezeToken == "" {
		return snapshotGateResponse{}, fmt.Errorf("user quiesce failed")
	}
	return out, nil
}

func (a *Agent) releaseSnapshotUser(ctx context.Context, req protocol.StartSnapshotRequest, freezeToken string) error {
	var out struct {
		OK bool `json:"ok"`
	}
	err := a.callTavernAdapter(ctx, "/api/stcontrol/internal/snapshots/release", snapshotReleaseRequest{
		WorkflowID: req.WorkflowID, SnapshotID: req.SnapshotID, Handle: req.Handle,
		ActivityEpoch: req.ActivityEpoch, FreezeToken: freezeToken,
	}, &out)
	if err != nil || !out.OK {
		return fmt.Errorf("user write gate release failed")
	}
	return nil
}

func (a *Agent) sourceSnapshotTaskPath(workflowID, snapshotID string) (string, error) {
	if !validUUID(workflowID) || !validUUID(snapshotID) {
		return "", fmt.Errorf("invalid task identity")
	}
	root := filepath.Join(a.Cfg.DataDir, "snapshot-tasks")
	return filepath.Join(root, workflowID, snapshotID), nil
}

func (a *Agent) copySnapshotTree(ctx context.Context, req protocol.StartSnapshotRequest, destination string) (protocol.SnapshotManifest, int64, error) {
	source := filepath.Join(a.dataRoot(), req.Handle)
	info, err := os.Lstat(source)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return protocol.SnapshotManifest{}, 0, fmt.Errorf("invalid user data root")
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return protocol.SnapshotManifest{}, 0, err
	}
	manifest := protocol.SnapshotManifest{
		FormatVersion: 1, WorkflowID: req.WorkflowID, SnapshotID: req.SnapshotID,
		GlobalUserID: req.GlobalUserID, Handle: req.Handle, SourceNodeID: a.Cfg.NodeID,
		TargetNodeID: req.TargetNodeID, ActivityEpoch: req.ActivityEpoch, CreatedAt: time.Now().UTC(),
	}
	var total int64
	err = filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !safeArchivePath(rel) {
			return fmt.Errorf("unsafe snapshot path")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("unsupported snapshot file type")
		}
		target := filepath.Join(destination, filepath.FromSlash(rel))
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if info.Size() > maxSnapshotFileBytes || total+info.Size() > maxSnapshotBytes || len(manifest.Files) >= maxSnapshotFiles {
			return fmt.Errorf("snapshot size limit exceeded")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		sourceFile, err := os.Open(path)
		if err != nil {
			return err
		}
		targetFile, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
		if err != nil {
			_ = sourceFile.Close()
			return err
		}
		hash := sha256.New()
		written, copyErr := io.Copy(targetFile, io.TeeReader(io.LimitReader(sourceFile, info.Size()+1), hash))
		closeErr := targetFile.Close()
		_ = sourceFile.Close()
		if copyErr != nil || closeErr != nil || written != info.Size() {
			return fmt.Errorf("snapshot source changed during copy")
		}
		manifest.Files = append(manifest.Files, protocol.ManifestEntry{
			Path: rel, Size: written, SHA256: hex.EncodeToString(hash.Sum(nil)),
		})
		total += written
		return nil
	})
	if err != nil {
		return protocol.SnapshotManifest{}, 0, err
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	return manifest, total, nil
}

func createSnapshotArchive(ctx context.Context, archivePath, snapshotDir string, manifestJSON []byte, files []protocol.ManifestEntry) error {
	archive, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encoder, err := zstd.NewWriter(archive, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(3)))
	if err != nil {
		_ = archive.Close()
		return err
	}
	tarWriter := tar.NewWriter(encoder)
	fail := func(cause error) error {
		_ = tarWriter.Close()
		_ = encoder.Close()
		_ = archive.Close()
		_ = os.Remove(archivePath)
		return cause
	}
	if err := tarWriter.WriteHeader(&tar.Header{Name: snapshotManifestPath, Mode: 0o400, Size: int64(len(manifestJSON)), Typeflag: tar.TypeReg}); err != nil {
		return fail(err)
	}
	if _, err := tarWriter.Write(manifestJSON); err != nil {
		return fail(err)
	}
	for _, entry := range files {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		path := filepath.Join(snapshotDir, filepath.FromSlash(entry.Path))
		file, err := os.Open(path)
		if err != nil {
			return fail(err)
		}
		if err := tarWriter.WriteHeader(&tar.Header{Name: entry.Path, Mode: 0o600, Size: entry.Size, Typeflag: tar.TypeReg}); err != nil {
			_ = file.Close()
			return fail(err)
		}
		written, err := io.Copy(tarWriter, file)
		_ = file.Close()
		if err != nil || written != entry.Size {
			return fail(fmt.Errorf("immutable snapshot changed during archive"))
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = encoder.Close()
		_ = archive.Close()
		return err
	}
	if err := encoder.Close(); err != nil {
		_ = archive.Close()
		return err
	}
	if err := archive.Sync(); err != nil {
		_ = archive.Close()
		return err
	}
	return archive.Close()
}

func (a *Agent) streamSnapshot(ctx context.Context, req protocol.StartSnapshotRequest, archivePath string, archiveDigest [32]byte) (protocol.SnapshotTransferReceipt, error) {
	endpoint, err := snapshotTransferEndpoint(req.TargetTransferURL, req.SnapshotID)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	defer archive.Close()
	stat, err := archive.Stat()
	if err != nil || stat.Size() <= 0 || stat.Size() > maxSnapshotBytes {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("invalid snapshot archive size")
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, archive)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	httpReq.ContentLength = stat.Size()
	httpReq.Header.Set("Content-Type", "application/zstd")
	httpReq.Header.Set("Authorization", "Bearer "+req.TransferCapability)
	httpReq.Header.Set("X-Workflow-Id", req.WorkflowID)
	httpReq.Header.Set("X-Archive-Sha256", hex.EncodeToString(archiveDigest[:]))
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("snapshot target returned status %d", resp.StatusCode)
	}
	var receipt protocol.SnapshotTransferReceipt
	if err := json.Unmarshal(data, &receipt); err != nil || !receipt.OK {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("invalid snapshot target receipt")
	}
	return receipt, nil
}

func snapshotTransferEndpoint(raw, snapshotID string) (string, error) {
	base, err := url.Parse(raw)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || !validUUID(snapshotID) {
		return "", fmt.Errorf("invalid transfer target")
	}
	host := base.Hostname()
	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
	if base.Scheme != "https" && !(base.Scheme == "http" && loopback) {
		return "", fmt.Errorf("snapshot transfer requires HTTPS")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/transfer/v1/snapshots/" + snapshotID
	return base.String(), nil
}

func (a *Agent) ReceiveSnapshot(ctx context.Context, workflowID, snapshotID, token, expectedArchiveHash string, body io.Reader) (protocol.SnapshotTransferReceipt, error) {
	if runtime.GOOS != "linux" {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("snapshot publication is enabled only on Linux")
	}
	transfer, err := a.consumeTransfer(snapshotID, workflowID, token, time.Now().UTC())
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	taskRoot, finalPath, err := a.targetSnapshotPaths(transfer)
	if err != nil {
		_ = a.finishTransfer(snapshotID, "failed")
		return protocol.SnapshotTransferReceipt{}, err
	}
	if err := resetTaskDirectory(taskRoot); err != nil {
		_ = a.finishTransfer(snapshotID, "failed")
		return protocol.SnapshotTransferReceipt{}, err
	}
	defer removeTaskDirectory(taskRoot)
	archivePath := filepath.Join(taskRoot, "incoming.tar.zst")
	archive, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(archive, io.TeeReader(io.LimitReader(body, maxSnapshotBytes+1), hash))
	syncErr := archive.Sync()
	closeErr := archive.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written <= 0 || written > maxSnapshotBytes {
		_ = a.finishTransfer(snapshotID, "failed")
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("snapshot upload failed")
	}
	archiveDigest := hash.Sum(nil)
	expectedDigest, err := hex.DecodeString(expectedArchiveHash)
	if err != nil || len(expectedDigest) != sha256.Size || !hmac.Equal(expectedDigest, archiveDigest) {
		_ = a.finishTransfer(snapshotID, "failed")
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("snapshot archive digest mismatch")
	}
	if err := a.reportSnapshotProgress(ctx, workflowID, snapshotID, "verifying"); err != nil {
		_ = a.finishTransfer(snapshotID, "failed")
		return protocol.SnapshotTransferReceipt{}, err
	}
	receipt, err := extractVerifyAndPublish(ctx, archivePath, taskRoot, finalPath, transfer, archiveDigest, func() error {
		return a.reportSnapshotProgress(ctx, workflowID, snapshotID, "publishing")
	})
	if err != nil {
		_ = a.finishTransfer(snapshotID, "failed")
		return protocol.SnapshotTransferReceipt{}, err
	}
	if err := a.publishTransfer(snapshotID, receipt); err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	return receipt, nil
}

func (a *Agent) targetSnapshotPaths(transfer pendingTransfer) (taskRoot, finalPath string, err error) {
	if !validUUID(transfer.WorkflowID) || !validUUID(transfer.SnapshotID) || !validHandle(transfer.Handle) {
		return "", "", fmt.Errorf("invalid transfer state")
	}
	var root string
	if transfer.DestinationKind == "archive" {
		root = a.Cfg.BackupDir
		finalPath = filepath.Join(root, "replicas", transfer.Handle)
	} else if transfer.DestinationKind == "hot_standby" {
		root = a.dataRoot()
		finalPath = filepath.Join(root, transfer.Handle)
	} else {
		return "", "", fmt.Errorf("invalid destination kind")
	}
	taskRoot = filepath.Join(root, ".stcontrol-tasks", transfer.WorkflowID, transfer.SnapshotID)
	return taskRoot, finalPath, nil
}

func extractVerifyAndPublish(
	ctx context.Context,
	archivePath, taskRoot, finalPath string,
	transfer pendingTransfer,
	archiveDigest []byte,
	beforePublish func() error,
) (protocol.SnapshotTransferReceipt, error) {
	archive, err := os.Open(archivePath)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	defer archive.Close()
	archiveInfo, err := archive.Stat()
	if err != nil || archiveInfo.Size() <= 0 {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("invalid snapshot archive")
	}
	decoder, err := zstd.NewReader(archive, zstd.WithDecoderMaxMemory(maxDecoderWindow), zstd.WithDecoderMaxWindow(maxDecoderWindow))
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	defer decoder.Close()
	tarReader := tar.NewReader(decoder)
	header, err := tarReader.Next()
	if err != nil || header.Name != snapshotManifestPath || header.Typeflag != tar.TypeReg ||
		header.Size <= 0 || header.Size > maxManifestBytes {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("invalid snapshot manifest entry")
	}
	manifestJSON, err := io.ReadAll(io.LimitReader(tarReader, maxManifestBytes+1))
	if err != nil || int64(len(manifestJSON)) != header.Size {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("invalid snapshot manifest")
	}
	decoderJSON := json.NewDecoder(bytes.NewReader(manifestJSON))
	decoderJSON.DisallowUnknownFields()
	var manifest protocol.SnapshotManifest
	if err := decoderJSON.Decode(&manifest); err != nil || !manifestMatchesTransfer(manifest, transfer) {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("snapshot manifest scope mismatch")
	}
	expected := make(map[string]protocol.ManifestEntry, len(manifest.Files))
	var declaredTotal int64
	for _, entry := range manifest.Files {
		if !safeArchivePath(entry.Path) || entry.Path == snapshotManifestPath || entry.Size < 0 ||
			entry.Size > maxSnapshotFileBytes || declaredTotal+entry.Size > maxSnapshotBytes || len(expected) >= maxSnapshotFiles {
			return protocol.SnapshotTransferReceipt{}, fmt.Errorf("invalid manifest file entry")
		}
		digest, err := hex.DecodeString(entry.SHA256)
		if err != nil || len(digest) != sha256.Size {
			return protocol.SnapshotTransferReceipt{}, fmt.Errorf("invalid manifest digest")
		}
		if _, exists := expected[entry.Path]; exists {
			return protocol.SnapshotTransferReceipt{}, fmt.Errorf("duplicate manifest path")
		}
		expected[entry.Path] = entry
		declaredTotal += entry.Size
	}
	if declaredTotal > 1<<30 && declaredTotal/archiveInfo.Size() > 200 {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("snapshot expansion ratio limit exceeded")
	}
	if err := ensureSnapshotDiskCapacity(filepath.Dir(finalPath), declaredTotal); err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	staging := filepath.Join(taskRoot, "staging")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	seen := make(map[string]bool, len(expected))
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return protocol.SnapshotTransferReceipt{}, err
		}
		if err := ctx.Err(); err != nil {
			return protocol.SnapshotTransferReceipt{}, err
		}
		if header.Typeflag != tar.TypeReg || !safeArchivePath(header.Name) {
			return protocol.SnapshotTransferReceipt{}, fmt.Errorf("unsupported archive entry")
		}
		entry, ok := expected[header.Name]
		if !ok || seen[header.Name] || header.Size != entry.Size {
			return protocol.SnapshotTransferReceipt{}, fmt.Errorf("archive differs from manifest")
		}
		target := filepath.Join(staging, filepath.FromSlash(header.Name))
		if !isSubPath(staging, target) {
			return protocol.SnapshotTransferReceipt{}, fmt.Errorf("archive path escaped staging")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return protocol.SnapshotTransferReceipt{}, err
		}
		file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return protocol.SnapshotTransferReceipt{}, err
		}
		hash := sha256.New()
		written, copyErr := io.Copy(file, io.TeeReader(tarReader, hash))
		closeErr := file.Close()
		want, _ := hex.DecodeString(entry.SHA256)
		if copyErr != nil || closeErr != nil || written != entry.Size || !hmac.Equal(hash.Sum(nil), want) {
			return protocol.SnapshotTransferReceipt{}, fmt.Errorf("snapshot file verification failed")
		}
		seen[header.Name] = true
	}
	if len(seen) != len(expected) {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("snapshot files missing")
	}
	if beforePublish == nil || beforePublish() != nil {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("snapshot publish fencing failed")
	}
	if err := publishSnapshotDirectory(staging, finalPath, taskRoot); err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	manifestDigest := sha256.Sum256(manifestJSON)
	return protocol.SnapshotTransferReceipt{
		OK: true, SnapshotID: transfer.SnapshotID,
		ManifestSHA256: hex.EncodeToString(manifestDigest[:]), ArchiveSHA256: hex.EncodeToString(archiveDigest),
		FileCount: int64(len(manifest.Files)), TotalBytes: declaredTotal,
	}, nil
}

func ensureSnapshotDiskCapacity(path string, snapshotBytes int64) error {
	usage, err := disk.Usage(path)
	if err != nil {
		return fmt.Errorf("read snapshot disk capacity: %w", err)
	}
	reserve := snapshotBytes / 10
	if reserve < 1<<30 {
		reserve = 1 << 30
	}
	required := uint64(snapshotBytes + reserve)
	if usage.Free < required {
		return fmt.Errorf("insufficient snapshot disk capacity")
	}
	return nil
}

func manifestMatchesTransfer(manifest protocol.SnapshotManifest, transfer pendingTransfer) bool {
	return manifest.FormatVersion == 1 && manifest.WorkflowID == transfer.WorkflowID &&
		manifest.SnapshotID == transfer.SnapshotID && manifest.Handle == transfer.Handle &&
		manifest.GlobalUserID == transfer.GlobalUserID && manifest.SourceNodeID == transfer.SourceNodeID &&
		manifest.TargetNodeID == transfer.TargetNodeID && manifest.ActivityEpoch == transfer.ActivityEpoch
}

func publishSnapshotDirectory(staging, finalPath, taskRoot string) error {
	if !isSubPath(filepath.Dir(finalPath), finalPath) || !isSubPath(filepath.Dir(taskRoot), taskRoot) {
		return fmt.Errorf("unsafe publish path")
	}
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o700); err != nil {
		return err
	}
	previous := filepath.Join(taskRoot, "previous")
	hadPrevious := false
	if _, err := os.Lstat(finalPath); err == nil {
		if err := os.Rename(finalPath, previous); err != nil {
			return err
		}
		hadPrevious = true
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(staging, finalPath); err != nil {
		if hadPrevious {
			_ = os.Rename(previous, finalPath)
		}
		return err
	}
	if hadPrevious {
		removeTaskDirectory(previous)
	}
	return nil
}

func hashFile(path string) ([32]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out, nil
}

func resetTaskDirectory(path string) error {
	if path == "" || filepath.Clean(path) == "." || filepath.Dir(path) == path {
		return fmt.Errorf("unsafe task directory")
	}
	removeTaskDirectory(path)
	return os.MkdirAll(path, 0o700)
}

func removeTaskDirectory(path string) {
	_ = filepath.Walk(path, func(current string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			_ = os.Chmod(current, 0o700)
		}
		return nil
	})
	_ = os.RemoveAll(path)
}

func safeArchivePath(path string) bool {
	return path != "" && filepath.IsLocal(filepath.FromSlash(path)) && path == filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) &&
		!strings.HasPrefix(path, ".stcontrol/")
}

func validHandle(handle string) bool {
	if len(handle) < 1 || len(handle) > 64 || handle == "." || handle == ".." {
		return false
	}
	for _, char := range handle {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil && len(decoded) == 16
}

func isSubPath(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	return err == nil && (rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." && !filepath.IsAbs(rel)))
}
