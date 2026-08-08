package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"stcontrol/internal/protocol"
)

var (
	errReplicaIntegrityMismatch    = errors.New("replica integrity mismatch")
	errReplicaIntegrityUnavailable = errors.New("replica integrity unavailable")
)

func (a *Agent) VerifyReplicaIntegrity(
	ctx context.Context,
	req protocol.VerifyReplicaIntegrityRequest,
) (protocol.ReplicaIntegrityReceipt, error) {
	if !validUUID(req.OperationID) || !validUUID(req.SnapshotID) || !validHandle(req.Handle) ||
		!validCapabilityHash(req.ManifestSHA256) || !validCapabilityHash(req.ArchiveSHA256) ||
		req.FileCount < 0 || req.FileCount > maxSnapshotFiles || req.TotalBytes < 0 || req.TotalBytes > maxSnapshotBytes {
		return protocol.ReplicaIntegrityReceipt{}, fmt.Errorf("invalid replica integrity request")
	}
	if a.Cfg == nil || a.Cfg.BackupDir == "" {
		return protocol.ReplicaIntegrityReceipt{}, errReplicaIntegrityUnavailable
	}
	root, err := filepath.Abs(a.Cfg.BackupDir)
	if err != nil {
		return protocol.ReplicaIntegrityReceipt{}, errReplicaIntegrityUnavailable
	}
	replicaRoot := filepath.Join(root, "replicas", req.Handle)
	if !isSubPath(root, replicaRoot) {
		return protocol.ReplicaIntegrityReceipt{}, fmt.Errorf("%w: unsafe replica root", errReplicaIntegrityMismatch)
	}
	info, err := os.Lstat(replicaRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return protocol.ReplicaIntegrityReceipt{}, fmt.Errorf("%w: replica root unavailable", errReplicaIntegrityMismatch)
	}
	metadata, err := readArchiveReplicaMetadata(replicaRoot)
	if err != nil {
		return protocol.ReplicaIntegrityReceipt{}, fmt.Errorf("%w: metadata", errReplicaIntegrityMismatch)
	}
	manifestJSON, err := json.Marshal(metadata.Manifest)
	if err != nil {
		return protocol.ReplicaIntegrityReceipt{}, fmt.Errorf("%w: invalid manifest", errReplicaIntegrityMismatch)
	}
	manifestDigest := sha256.Sum256(manifestJSON)
	if metadata.FormatVersion != 1 || metadata.Manifest.SnapshotID != req.SnapshotID ||
		metadata.Manifest.Handle != req.Handle || metadata.Manifest.TargetNodeID != a.Cfg.NodeID ||
		metadata.Receipt.SnapshotID != req.SnapshotID || !metadata.Receipt.OK ||
		!strings.EqualFold(hex.EncodeToString(manifestDigest[:]), req.ManifestSHA256) ||
		!strings.EqualFold(metadata.Receipt.ManifestSHA256, req.ManifestSHA256) ||
		!strings.EqualFold(metadata.Receipt.ArchiveSHA256, req.ArchiveSHA256) ||
		metadata.Receipt.FileCount != req.FileCount || metadata.Receipt.TotalBytes != req.TotalBytes ||
		int64(len(metadata.Manifest.Files)) != req.FileCount {
		return protocol.ReplicaIntegrityReceipt{}, fmt.Errorf("%w: metadata scope", errReplicaIntegrityMismatch)
	}
	totalBytes, err := verifyArchiveReplica(ctx, replicaRoot, metadata.Manifest.Files)
	if err != nil {
		if ctx.Err() != nil {
			return protocol.ReplicaIntegrityReceipt{}, errReplicaIntegrityUnavailable
		}
		return protocol.ReplicaIntegrityReceipt{}, fmt.Errorf("%w: file tree", errReplicaIntegrityMismatch)
	}
	if totalBytes != req.TotalBytes {
		return protocol.ReplicaIntegrityReceipt{}, fmt.Errorf("%w: total bytes", errReplicaIntegrityMismatch)
	}
	return protocol.ReplicaIntegrityReceipt{
		SnapshotID: req.SnapshotID, ManifestSHA256: req.ManifestSHA256,
		ArchiveSHA256: req.ArchiveSHA256, FileCount: req.FileCount, TotalBytes: req.TotalBytes,
	}, nil
}
