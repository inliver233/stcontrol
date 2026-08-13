package controller

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const controllerBackupReconcileInterval = 5 * time.Minute
const controllerBackupLeaseTTL = 6 * time.Hour
const controllerBackupManifestName = "controller_manifest.json"
const controllerBackupPgDumpName = "controller_postgres_dump.sql"
const controllerBackupConfigName = "controller.yaml"

func (s *Server) controllerBackupPolicy() config.ControllerDisasterBackupPolicy {
	if s == nil || s.Cfg == nil || (s.Cfg.ControllerBackup == (config.ControllerDisasterBackupPolicy{})) { return config.DefaultController().ControllerBackup }
	return s.Cfg.ControllerBackup
}
func controllerBackupInterval(policy config.ControllerDisasterBackupPolicy) time.Duration { if policy.IntervalSec > 0 { return time.Duration(policy.IntervalSec) * time.Second }; return 24 * time.Hour }
func controllerBackupMaxAttempts(policy config.ControllerDisasterBackupPolicy) int {
	if policy.RetryMax > 0 {
		if policy.RetryMax < 8 {
			return policy.RetryMax
		}
		return 8
	}
	return 3
}

func (s *Server) controllerBackupReconciler(ctx context.Context) {
	policy := s.controllerBackupPolicy()
	if !policy.Enabled { return }
	interval := controllerBackupReconcileInterval
	if interval < time.Minute { interval = time.Minute }
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	s.reconcileControllerBackupOnce(ctx)
	for {
		select {
		case <-ctx.Done(): return
		case <-ticker.C: s.reconcileControllerBackupOnce(ctx)
		}
	}
}

func (s *Server) reconcileControllerBackupOnce(ctx context.Context) {
	if s == nil || s.Store == nil || len(s.secretKey) == 0 || !isUUID(s.workflowWorkerID) { return }
	policy := s.controllerBackupPolicy()
	if !policy.Enabled { return }
	now := time.Now().UTC()
	maxAttempts := controllerBackupMaxAttempts(policy)
	if _, err := s.Store.ReconcileControllerDisasterBackups(ctx, now, maxAttempts); err != nil { return }
	if s.checkNewOperations() != nil { return }
	operationID, err := newUUID()
	if err != nil { return }
	kind := store.ControllerBackupKindSnapshot
	if policy.PgDump { kind = store.ControllerBackupKindFull }
	run, err := s.Store.ScheduleControllerDisasterBackup(ctx, store.ScheduleControllerDisasterBackupParams{
		OperationID: operationID, BackupKind: kind, MaxAttempts: maxAttempts,
		Interval: controllerBackupInterval(policy), LeaseOwner: s.workflowWorkerID,
		LeaseTTL: controllerBackupLeaseTTL, Now: now,
	})
	if err != nil || run == nil { return }
	if err := s.executeControllerBackup(ctx, run); err != nil { return }
}

func (s *Server) executeControllerBackup(ctx context.Context, run *store.ControllerDisasterBackupRun) error {
	maxAttempts := controllerBackupMaxAttempts(s.controllerBackupPolicy())
	claimed, err := s.Store.ClaimControllerDisasterBackup(ctx, store.ClaimControllerDisasterBackupParams{
		OperationID: run.OperationID, LeaseOwner: s.workflowWorkerID,
		LeaseTTL: controllerBackupLeaseTTL, MaxAttempts: maxAttempts, Now: time.Now().UTC(),
	})
	if err != nil { return err }
	if claimed == nil { return nil }

	now := time.Now().UTC()
	fail := func(code string) { _ = s.Store.FailControllerDisasterBackup(ctx, claimed.OperationID, code, maxAttempts, now) }
	target, err := s.Store.GetNodeByID(ctx, claimed.NodeID)
	if err != nil || target == nil || target.TransferURL == "" { fail("target_unavailable"); return fmt.Errorf("controller backup target unavailable") }

	tempDir, err := os.MkdirTemp("", "ctrl-backup-")
	if err != nil { fail("temp_dir_failed"); return err }
	defer os.RemoveAll(tempDir)

	if err := s.Store.MarkControllerDisasterBackupProgress(ctx, claimed.OperationID, store.ControllerBackupSnapshotting); err != nil { return err }

	var pgDumpPath string
	if claimed.BackupKind == store.ControllerBackupKindFull || claimed.BackupKind == store.ControllerBackupKindPGDump {
		if s.Cfg != nil && s.Cfg.DatabaseURL != "" {
			pgDumpPath = filepath.Join(tempDir, controllerBackupPgDumpName)
			if err := runPgDump(ctx, s.Cfg.DatabaseURL, pgDumpPath); err != nil { fail("pg_dump_failed"); return fmt.Errorf("pg_dump failed: %w", err) }
		}
	}

	configPath := ""
	if s.ConfigPath != "" { if info, statErr := os.Stat(s.ConfigPath); statErr == nil && !info.IsDir() { configPath = s.ConfigPath } }

	manifestState := map[string]any{
		"operation_id": claimed.OperationID,
		"controller_generation": claimed.ControllerGeneration,
		"backup_kind": claimed.BackupKind,
		"created_at": now.Format(time.RFC3339Nano),
		"db_dump": map[string]any{"enabled": pgDumpPath != "", "name": controllerBackupPgDumpName},
		"config_file": configPath != "",
	}
	manifestJSON, err := json.Marshal(manifestState)
	if err != nil { fail("manifest_failed"); return err }

	archivePath := filepath.Join(tempDir, "controller_backup.tar.zst")
	if err := buildControllerBackupArchive(ctx, archivePath, pgDumpPath, configPath, manifestJSON); err != nil { fail("archive_failed"); return err }
	archiveDigest, err := controllerFileSHA256(archivePath)
	if err != nil { fail("archive_hash_failed"); return err }
	archiveSize, err := controllerFileSize(archivePath)
	if err != nil { fail("archive_hash_failed"); return err }

	capabilityID, err := newUUID()
	if err != nil { fail("capability_failed"); return err }
	capability := deriveTransferCapability(s.secretKey, capabilityID)
	capabilityHash := sha256.Sum256([]byte(capability))
	expiresAt := now.Add(snapshotCapabilityTTL)

	if err := s.Store.MarkControllerDisasterBackupProgress(ctx, claimed.OperationID, store.ControllerBackupTransferring); err != nil { return err }
	if _, err := s.runAgentCommandWithOperation(ctx, target, "receive_controller_backup", protocol.PrepareControllerBackupRequest{
		OperationID: claimed.OperationID, BackupKind: claimed.BackupKind,
		ControllerGeneration: claimed.ControllerGeneration, CapabilityHash: hex.EncodeToString(capabilityHash[:]),
		ExpiresAt: expiresAt, ExpectedSHA256: archiveDigest,
	}, deriveWorkflowOperationID(claimed.OperationID, "receive-controller-backup"), 60*time.Second); err != nil { fail("target_prepare_failed"); return fmt.Errorf("prepare controller backup target: %w", err) }

	if err := s.Store.MarkControllerDisasterBackupProgress(ctx, claimed.OperationID, store.ControllerBackupVerifying); err != nil { return err }
	receipt, err := streamControllerBackup(ctx, target.TransferURL, claimed.OperationID, capability, archiveDigest, archivePath, archiveSize)
	if err != nil || receipt == nil || !receipt.OK { fail("transfer_failed"); return fmt.Errorf("stream controller backup: %w", err) }
	if receipt.ArchiveSHA256 != archiveDigest || receipt.TotalBytes != archiveSize { fail("verify_failed"); return fmt.Errorf("controller backup verification mismatch") }

	if err := s.Store.MarkControllerDisasterBackupProgress(ctx, claimed.OperationID, store.ControllerBackupPublishing); err != nil { return err }
	if err := s.Store.CompleteControllerDisasterBackup(ctx, claimed.OperationID, "controller_backup.tar.zst", archiveDigest, archiveSize, json.RawMessage(manifestJSON)); err != nil {
		// The archive is durably stored on the target; only the DB metadata write
		// failed. Move the run to retry/failed so it is not wedged in publishing.
		fail("complete_failed")
		return err
	}
	return nil
}

// runPgDump dumps the control database to a plain SQL file. The password is
// delivered via the PGPASSWORD environment variable (never on the command
// line). On hosts without pg_dump in PATH, this returns an explicit error so
// the workflow marks itself failed with a retryable backoff.
func runPgDump(ctx context.Context, dsn, outPath string) error {
	parsed, err := url.Parse(dsn)
	if err != nil { return fmt.Errorf("invalid database url: %w", err) }
	host := parsed.Hostname()
	if host == "" { host = "127.0.0.1" }
	port := parsed.Port()
	if port == "" { port = "5432" }
	dbName := strings.TrimPrefix(parsed.Path, "/")
	if dbName == "" { return fmt.Errorf("database name missing from url") }
	if parsed.User == nil { return fmt.Errorf("database user missing from url") }
	password := ""
	if parsed.User != nil { password, _ = parsed.User.Password() }
	pgDump, err := exec.LookPath("pg_dump")
	if err != nil { return fmt.Errorf("pg_dump not found in PATH: %w", err) }
	cmd := exec.CommandContext(ctx, pgDump, "-h", host, "-p", port, "-U", parsed.User.Username(), "--no-owner", "--no-privileges", "-d", dbName)
	cmd.Env = append(os.Environ(), "PGPASSWORD="+password)
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil { return err }
	cmd.Stdout = out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	closeErr := out.Close()
	if err != nil { return fmt.Errorf("pg_dump exited: %v: %s", err, strings.TrimSpace(stderr.String())) }
	return closeErr
}

// buildControllerBackupArchive writes a tar.zst archive containing the
// manifest plus (optionally) the postgres dump and the controller config file.
func buildControllerBackupArchive(ctx context.Context, archivePath, pgDumpPath, configPath string, manifestJSON []byte) error {
	archive, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil { return err }
	encoder, err := zstd.NewWriter(archive, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(3)))
	if err != nil { _ = archive.Close(); return err }
	tw := tar.NewWriter(encoder)
	fail := func(cause error) error { _ = tw.Close(); _ = encoder.Close(); _ = archive.Close(); _ = os.Remove(archivePath); return cause }
	if err := tw.WriteHeader(&tar.Header{Name: controllerBackupManifestName, Mode: 0o400, Size: int64(len(manifestJSON)), Typeflag: tar.TypeReg}); err != nil { return fail(err) }
	if _, err := tw.Write(manifestJSON); err != nil { return fail(err) }
	for name, path := range map[string]string{controllerBackupPgDumpName: pgDumpPath, controllerBackupConfigName: configPath} {
		if path == "" { continue }
		info, err := os.Stat(path)
		if err != nil || info.IsDir() { return fail(fmt.Errorf("controller backup payload missing: %s", path)) }
		file, err := os.Open(path)
		if err != nil { return fail(err) }
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: info.Size(), Typeflag: tar.TypeReg}); err != nil { _ = file.Close(); return fail(err) }
		written, err := io.Copy(tw, file)
		_ = file.Close()
		if err != nil || written != info.Size() { return fail(fmt.Errorf("controller backup payload changed during archive")) }
	}
	if err := tw.Close(); err != nil { _ = encoder.Close(); _ = archive.Close(); return err }
	if err := encoder.Close(); err != nil { _ = archive.Close(); return err }
	if err := archive.Sync(); err != nil { _ = archive.Close(); return err }
	return archive.Close()
}

func controllerFileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil { return "", err }
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
func controllerFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil { return 0, err }
	return info.Size(), nil
}

// streamControllerBackup POSTs the archive to the target storage node over the
// capability-bound transfer endpoint, mirroring snapshot direct transfer. The
// one-use bearer capability and the expected sha256 are validated on the
// target; idempotent replay is safe because the target roots each archive at
// controller-backups/<operation_id>/ with the immutable name.
func streamControllerBackup(ctx context.Context, targetTransferURL, operationID, capability, sha256Hex, archivePath string, size int64) (*protocol.ControllerBackupReceipt, error) {
	endpoint, err := controllerBackupTransferEndpoint(targetTransferURL, operationID)
	if err != nil { return nil, err }
	archive, err := os.Open(archivePath)
	if err != nil { return nil, err }
	defer archive.Close()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, archive)
	if err != nil { return nil, err }
	httpReq.ContentLength = size
	httpReq.Header.Set("Content-Type", "application/zstd")
	httpReq.Header.Set("Authorization", "Bearer "+capability)
	httpReq.Header.Set("X-Archive-Sha256", sha256Hex)
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(httpReq)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil { return nil, err }
	if resp.StatusCode != http.StatusOK { return nil, fmt.Errorf("controller backup target returned status %d", resp.StatusCode) }
	var receipt protocol.ControllerBackupReceipt
	if err := json.Unmarshal(data, &receipt); err != nil || !receipt.OK { return nil, fmt.Errorf("invalid controller backup target receipt") }
	return &receipt, nil
}

func controllerBackupTransferEndpoint(raw, operationID string) (string, error) {
	base, err := url.Parse(raw)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || !isUUID(operationID) {
		return "", fmt.Errorf("invalid controller backup target")
	}
	host := base.Hostname()
	ipAddr := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || (ipAddr != nil && ipAddr.IsLoopback())
	if base.Scheme != "https" && !(base.Scheme == "http" && loopback) { return "", fmt.Errorf("controller backup transfer requires HTTPS") }
	base.Path = strings.TrimRight(base.Path, "/") + "/transfer/v1/controller-backups/" + operationID
	return base.String(), nil
}
