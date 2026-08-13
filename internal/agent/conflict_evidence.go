package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
)

const conflictEvidenceMetadataPath = ".stcontrol-conflict.json"

type conflictEvidenceMetadata struct {
	FormatVersion    int                      `json:"format_version"`
	ConflictID       string                   `json:"conflict_id"`
	EvidenceID       string                   `json:"evidence_id"`
	GlobalUserID     int64                    `json:"global_user_id"`
	Handle           string                   `json:"handle"`
	NodeID           int64                    `json:"node_id"`
	SourceKind       string                   `json:"source_kind"`
	CapturedAt       time.Time                `json:"captured_at"`
	CaptureBasis     string                   `json:"capture_basis"`
	SourceSnapshotID string                   `json:"source_snapshot_id,omitempty"`
	EntriesSHA256    string                   `json:"entries_sha256"`
	FileCount        int64                    `json:"file_count"`
	TotalBytes       int64                    `json:"total_bytes"`
	Files            []protocol.ManifestEntry `json:"files"`
}

func (a *Agent) captureConflictEvidence(
	ctx context.Context,
	req protocol.CaptureConflictEvidenceRequest,
) (protocol.ConflictEvidenceReceipt, error) {
	base, finalPath, taskRoot, err := a.conflictEvidencePaths(req.ConflictID, req.EvidenceID)
	if err != nil {
		return protocol.ConflictEvidenceReceipt{}, err
	}
	if existing, err := readConflictEvidenceMetadata(finalPath); err == nil {
		if !conflictEvidenceScopeMatches(existing, req, a.Cfg.NodeID) {
			return protocol.ConflictEvidenceReceipt{}, fmt.Errorf("conflict evidence identity collision")
		}
		if err := verifyConflictEvidence(ctx, finalPath, existing.Files); err != nil {
			return protocol.ConflictEvidenceReceipt{}, err
		}
		return conflictEvidenceReceipt(existing), nil
	} else if !os.IsNotExist(err) {
		return protocol.ConflictEvidenceReceipt{}, err
	}

	sourceRoot, captureBasis, err := a.conflictEvidenceSource(ctx, req)
	if err != nil {
		return protocol.ConflictEvidenceReceipt{}, err
	}
	expectedFiles, expectedBytes, err := measureConflictEvidenceTree(ctx, sourceRoot)
	if err != nil {
		return protocol.ConflictEvidenceReceipt{}, err
	}
	if err := ensureSnapshotDiskCapacity(base, expectedBytes); err != nil {
		return protocol.ConflictEvidenceReceipt{}, err
	}
	if err := resetTaskDirectory(taskRoot); err != nil {
		return protocol.ConflictEvidenceReceipt{}, err
	}
	defer removeTaskDirectory(taskRoot)
	staging := filepath.Join(taskRoot, "staging")
	files, totalBytes, err := copyConflictEvidenceTree(ctx, sourceRoot, staging)
	if err != nil {
		return protocol.ConflictEvidenceReceipt{}, err
	}
	if len(files) != expectedFiles || totalBytes != expectedBytes {
		return protocol.ConflictEvidenceReceipt{}, fmt.Errorf("conflict source changed during capture")
	}
	entriesJSON, err := json.Marshal(files)
	if err != nil {
		return protocol.ConflictEvidenceReceipt{}, err
	}
	entriesDigest := sha256.Sum256(entriesJSON)
	metadata := conflictEvidenceMetadata{
		FormatVersion: 1, ConflictID: req.ConflictID, EvidenceID: req.EvidenceID,
		GlobalUserID: req.GlobalUserID, Handle: req.Handle, NodeID: a.Cfg.NodeID,
		SourceKind: req.SourceKind,
		CapturedAt: time.Now().UTC(), CaptureBasis: captureBasis,
		SourceSnapshotID: req.SourceSnapshotID,
		EntriesSHA256:    hex.EncodeToString(entriesDigest[:]),
		FileCount:        int64(len(files)), TotalBytes: totalBytes, Files: files,
	}
	if err := writeConflictEvidenceMetadata(staging, metadata); err != nil {
		return protocol.ConflictEvidenceReceipt{}, err
	}
	if err := publishImmutableConflictEvidence(staging, finalPath); err != nil {
		return protocol.ConflictEvidenceReceipt{}, err
	}
	return conflictEvidenceReceipt(metadata), nil
}

func measureConflictEvidenceTree(ctx context.Context, source string) (int, int64, error) {
	count := 0
	var total int64
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
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
		if rel == archiveMetadataPath || rel == replicaIdentityPath {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if skip, err := controllerReplicaMetadataEntry(rel, info); skip || err != nil {
				return err
			}
		}
		if !safeArchivePath(rel) {
			return fmt.Errorf("unsafe conflict evidence path")
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("unsupported conflict evidence file type")
		}
		if info.IsDir() {
			return nil
		}
		if info.Size() > maxSnapshotFileBytes || total > maxSnapshotBytes-info.Size() ||
			count >= maxSnapshotFiles {
			return fmt.Errorf("conflict evidence size limit exceeded")
		}
		count++
		total += info.Size()
		return nil
	})
	return count, total, err
}

func (a *Agent) conflictEvidenceSource(
	ctx context.Context,
	req protocol.CaptureConflictEvidenceRequest,
) (string, string, error) {
	switch req.SourceKind {
	case "archive":
		if a.Cfg.Role != "storage" {
			return "", "", fmt.Errorf("archive evidence requires storage role")
		}
		root := filepath.Join(a.Cfg.BackupDir, "replicas", req.Handle)
		metadata, err := readArchiveReplicaMetadata(root)
		if err != nil {
			return "", "", err
		}
		manifestJSON, err := json.Marshal(metadata.Manifest)
		if err != nil {
			return "", "", err
		}
		digest := sha256.Sum256(manifestJSON)
		want, err := hex.DecodeString(req.SourceManifestSHA256)
		if err != nil || len(want) != sha256.Size ||
			metadata.Manifest.SnapshotID != req.SourceSnapshotID ||
			metadata.Manifest.GlobalUserID != req.GlobalUserID ||
			metadata.Manifest.Handle != req.Handle ||
			!hmac.Equal(want, digest[:]) {
			return "", "", fmt.Errorf("archive conflict evidence scope mismatch")
		}
		if _, err := verifyArchiveReplica(ctx, root, metadata.Manifest.Files); err != nil {
			return "", "", err
		}
		return root, "verified_archive", nil
	case "active", "hot_standby":
		if a.Cfg.Role != "compute" {
			return "", "", fmt.Errorf("live evidence requires compute role")
		}
		root := filepath.Join(a.dataRoot(), req.Handle)
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", "", fmt.Errorf("conflict source is unavailable")
		}
		return root, "frozen_live", nil
	default:
		return "", "", fmt.Errorf("unsupported conflict evidence source")
	}
}

func (a *Agent) conflictEvidencePaths(conflictID, evidenceID string) (base, finalPath, taskRoot string, err error) {
	if !validUUID(conflictID) || !validUUID(evidenceID) {
		return "", "", "", fmt.Errorf("invalid conflict evidence identity")
	}
	base = a.dataRoot()
	if a.Cfg.Role == "storage" {
		base = a.Cfg.BackupDir
	}
	if base == "" {
		return "", "", "", fmt.Errorf("conflict evidence root is unavailable")
	}
	root := filepath.Join(base, ".stcontrol-conflicts", conflictID)
	finalPath = filepath.Join(root, evidenceID)
	taskRoot = filepath.Join(base, ".stcontrol-conflict-tasks", conflictID, evidenceID)
	if !isSubPath(base, finalPath) || !isSubPath(base, taskRoot) {
		return "", "", "", fmt.Errorf("unsafe conflict evidence path")
	}
	return base, finalPath, taskRoot, nil
}

func copyConflictEvidenceTree(
	ctx context.Context,
	source, destination string,
) ([]protocol.ManifestEntry, int64, error) {
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return nil, 0, err
	}
	files := make([]protocol.ManifestEntry, 0)
	var total int64
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
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
		if rel == archiveMetadataPath || rel == replicaIdentityPath {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if skip, err := controllerReplicaMetadataEntry(rel, info); skip || err != nil {
				return err
			}
		}
		if !safeArchivePath(rel) {
			return fmt.Errorf("unsafe conflict evidence path")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("unsupported conflict evidence file type")
		}
		target := filepath.Join(destination, filepath.FromSlash(rel))
		if !isSubPath(destination, target) {
			return fmt.Errorf("conflict evidence path escaped")
		}
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if info.Size() > maxSnapshotFileBytes || total > maxSnapshotBytes-info.Size() ||
			len(files) >= maxSnapshotFiles {
			return fmt.Errorf("conflict evidence size limit exceeded")
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
			return fmt.Errorf("conflict source changed during capture")
		}
		files = append(files, protocol.ManifestEntry{
			Path: rel, Size: written, SHA256: hex.EncodeToString(hash.Sum(nil)),
		})
		total += written
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, total, nil
}

func writeConflictEvidenceMetadata(root string, metadata conflictEvidenceMetadata) error {
	data, err := json.Marshal(metadata)
	if err != nil || int64(len(data)) > maxManifestBytes+(1<<20) {
		return fmt.Errorf("conflict evidence metadata too large")
	}
	path := filepath.Join(root, conflictEvidenceMetadataPath)
	if !isSubPath(root, path) {
		return fmt.Errorf("unsafe conflict evidence metadata path")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func readConflictEvidenceMetadata(root string) (conflictEvidenceMetadata, error) {
	path := filepath.Join(root, conflictEvidenceMetadataPath)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > maxManifestBytes+(1<<20) {
		if err != nil {
			return conflictEvidenceMetadata{}, err
		}
		return conflictEvidenceMetadata{}, fmt.Errorf("invalid conflict evidence metadata")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return conflictEvidenceMetadata{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var metadata conflictEvidenceMetadata
	if err := decoder.Decode(&metadata); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		metadata.FormatVersion != 1 || !validUUID(metadata.ConflictID) || !validUUID(metadata.EvidenceID) ||
		metadata.GlobalUserID <= 0 || !validHandle(metadata.Handle) || metadata.NodeID <= 0 ||
		(metadata.SourceKind != "active" && metadata.SourceKind != "hot_standby" && metadata.SourceKind != "archive") ||
		metadata.FileCount != int64(len(metadata.Files)) || metadata.FileCount > maxSnapshotFiles ||
		metadata.TotalBytes < 0 || metadata.TotalBytes > maxSnapshotBytes || !validCapabilityHash(metadata.EntriesSHA256) {
		return conflictEvidenceMetadata{}, fmt.Errorf("invalid conflict evidence metadata")
	}
	entriesJSON, err := json.Marshal(metadata.Files)
	if err != nil {
		return conflictEvidenceMetadata{}, err
	}
	digest := sha256.Sum256(entriesJSON)
	want, _ := hex.DecodeString(metadata.EntriesSHA256)
	if !hmac.Equal(want, digest[:]) {
		return conflictEvidenceMetadata{}, fmt.Errorf("conflict evidence manifest mismatch")
	}
	return metadata, nil
}

func verifyConflictEvidence(ctx context.Context, root string, files []protocol.ManifestEntry) error {
	expected := make(map[string]protocol.ManifestEntry, len(files))
	var declaredTotal int64
	for _, entry := range files {
		if !safeArchivePath(entry.Path) || entry.Size < 0 || entry.Size > maxSnapshotFileBytes ||
			declaredTotal > maxSnapshotBytes-entry.Size || len(expected) >= maxSnapshotFiles {
			return fmt.Errorf("invalid conflict evidence manifest")
		}
		if _, exists := expected[entry.Path]; exists || !validCapabilityHash(entry.SHA256) {
			return fmt.Errorf("invalid conflict evidence manifest")
		}
		expected[entry.Path] = entry
		declaredTotal += entry.Size
	}
	seen := make(map[string]bool, len(expected))
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == conflictEvidenceMetadataPath {
			return nil
		}
		if !safeArchivePath(rel) {
			return fmt.Errorf("unsafe conflict evidence path")
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("unsupported conflict evidence file type")
		}
		if info.IsDir() {
			return nil
		}
		want, ok := expected[rel]
		if !ok || seen[rel] || info.Size() != want.Size {
			return fmt.Errorf("conflict evidence differs from manifest")
		}
		digest, err := hashFile(path)
		if err != nil || !hmac.Equal([]byte(hex.EncodeToString(digest[:])), []byte(want.SHA256)) {
			return fmt.Errorf("conflict evidence differs from manifest")
		}
		seen[rel] = true
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("conflict evidence files missing")
	}
	return nil
}

func publishImmutableConflictEvidence(staging, finalPath string) error {
	if !isSubPath(filepath.Dir(finalPath), finalPath) {
		return fmt.Errorf("unsafe conflict evidence publish path")
	}
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o700); err != nil {
		return err
	}
	if _, err := os.Lstat(finalPath); err == nil {
		return fmt.Errorf("conflict evidence already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Rename(staging, finalPath)
}

func conflictEvidenceScopeMatches(
	metadata conflictEvidenceMetadata,
	req protocol.CaptureConflictEvidenceRequest,
	nodeID int64,
) bool {
	return metadata.ConflictID == req.ConflictID && metadata.EvidenceID == req.EvidenceID &&
		metadata.GlobalUserID == req.GlobalUserID && metadata.Handle == req.Handle &&
		metadata.NodeID == nodeID && metadata.SourceKind == req.SourceKind &&
		metadata.SourceSnapshotID == req.SourceSnapshotID
}

func conflictEvidenceReceipt(metadata conflictEvidenceMetadata) protocol.ConflictEvidenceReceipt {
	return protocol.ConflictEvidenceReceipt{
		EvidenceID: metadata.EvidenceID, EntriesSHA256: metadata.EntriesSHA256,
		FileCount: metadata.FileCount, TotalBytes: metadata.TotalBytes,
		CaptureBasis: metadata.CaptureBasis, SourceSnapshotID: metadata.SourceSnapshotID,
	}
}

func (a *Agent) readConflictEvidencePage(req protocol.ReadConflictEvidencePageRequest) (string, error) {
	_, root, _, err := a.conflictEvidencePaths(req.ConflictID, req.EvidenceID)
	if err != nil {
		return "", err
	}
	metadata, err := readConflictEvidenceMetadata(root)
	if err != nil || metadata.ConflictID != req.ConflictID || metadata.EvidenceID != req.EvidenceID ||
		metadata.NodeID != a.Cfg.NodeID || req.Cursor > len(metadata.Files) {
		return "", fmt.Errorf("conflict evidence page unavailable")
	}
	page := protocol.ConflictEvidencePage{
		EvidenceID: req.EvidenceID, Cursor: req.Cursor, NextCursor: req.Cursor,
	}
	used := 256
	for index := req.Cursor; index < len(metadata.Files); index++ {
		entryJSON, err := json.Marshal(metadata.Files[index])
		if err != nil {
			return "", err
		}
		if used+len(entryJSON)+1 > req.MaxBytes {
			if len(page.Entries) == 0 {
				return "", fmt.Errorf("conflict evidence entry exceeds page limit")
			}
			break
		}
		page.Entries = append(page.Entries, metadata.Files[index])
		page.NextCursor = index + 1
		used += len(entryJSON) + 1
	}
	page.Complete = page.NextCursor == len(metadata.Files)
	plaintext, err := json.Marshal(page)
	if err != nil || len(plaintext) > req.MaxBytes {
		return "", fmt.Errorf("conflict evidence page limit exceeded")
	}
	key, err := controlcrypto.LoadKey(req.ResponseKey)
	if err != nil {
		return "", err
	}
	return controlcrypto.Encrypt(key, plaintext)
}
