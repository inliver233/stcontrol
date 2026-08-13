package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"stcontrol/internal/protocol"
)

// errReplicaIdentityUnavailable marks a cleanup target whose identity file is
// missing or invalid.  The Controller treats this as terminal (fail, don't
// retry) so an unverifiable legacy replica cannot block the user forever.
var errReplicaIdentityUnavailable = errors.New("replica identity unavailable")

func (a *Agent) deleteSnapshotReplica(
	ctx context.Context,
	req protocol.DeleteReplicaRequest,
) (protocol.DeleteReplicaReceipt, error) {
	a.replicaMutationMu.Lock()
	defer a.replicaMutationMu.Unlock()
	receipt := protocol.DeleteReplicaReceipt{
		CleanupID: req.CleanupID, SnapshotID: req.SnapshotID, GlobalUserID: req.GlobalUserID,
		Handle: req.Handle, ReplicaKind: req.ReplicaKind,
	}
	if err := ctx.Err(); err != nil {
		return receipt, err
	}
	if a.Cfg == nil || a.Cfg.NodeID <= 0 || !validUUID(req.CleanupID) || !validUUID(req.SnapshotID) ||
		req.GlobalUserID <= 0 || !validHandle(req.Handle) {
		return receipt, fmt.Errorf("invalid replica cleanup request")
	}
	receipt.TargetNodeID = a.Cfg.NodeID
	var root, finalPath string
	switch req.ReplicaKind {
	case "archive":
		if a.Cfg.Role != "storage" {
			return receipt, fmt.Errorf("replica cleanup role mismatch")
		}
		root = filepath.Join(a.Cfg.BackupDir, "replicas")
		finalPath = filepath.Join(root, req.Handle)
	case "hot_standby":
		if a.Cfg.Role != "compute" {
			return receipt, fmt.Errorf("replica cleanup role mismatch")
		}
		root = a.dataRoot()
		finalPath = filepath.Join(root, req.Handle)
	default:
		return receipt, fmt.Errorf("invalid replica cleanup kind")
	}
	canonicalRoot, err := canonicalReplicaCleanupRoot(root)
	if err != nil {
		if os.IsNotExist(err) {
			receipt.Outcome = protocol.DeleteReplicaOutcomeAlreadyAbsent
			return receipt, nil
		}
		return receipt, err
	}
	root = canonicalRoot
	finalPath = filepath.Join(root, req.Handle)
	if root == "" || !isSubPath(root, finalPath) {
		return receipt, fmt.Errorf("unsafe replica cleanup path")
	}
	trashRoot := filepath.Join(root, ".stcontrol-cleanups")
	trashPath := filepath.Join(trashRoot, req.CleanupID)
	if !isSubPath(root, trashRoot) || !isSubPath(trashRoot, trashPath) {
		return receipt, fmt.Errorf("unsafe replica cleanup tombstone")
	}
	if trashInfo, err := os.Lstat(trashRoot); err == nil {
		if !trashInfo.IsDir() || trashInfo.Mode()&os.ModeSymlink != 0 {
			return receipt, fmt.Errorf("invalid replica cleanup tombstone root")
		}
	} else if !os.IsNotExist(err) {
		return receipt, fmt.Errorf("inspect replica cleanup tombstone root failed")
	}

	// A crash after the atomic rename leaves only the tombstone. Finish that
	// exact deletion first; a replacement at finalPath is deliberately ignored.
	if info, err := os.Lstat(trashPath); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return receipt, fmt.Errorf("invalid replica cleanup tombstone")
		}
		matches, err := replicaTreeMatchesCleanup(trashPath, req, a.Cfg.NodeID)
		if err != nil || !matches {
			return receipt, fmt.Errorf("replica cleanup tombstone identity mismatch")
		}
		if err := removeReplicaTree(trashPath); err != nil {
			return receipt, fmt.Errorf("remove replica cleanup tombstone failed")
		}
		if err := syncSnapshotDirectory(trashRoot); err != nil {
			return receipt, fmt.Errorf("sync replica cleanup tombstone failed")
		}
		// The old final name was already detached before this tombstone was
		// created. Anything now present at finalPath is a later publication.
		receipt.Outcome = protocol.DeleteReplicaOutcomeDeleted
		return receipt, nil
	} else if !os.IsNotExist(err) {
		return receipt, fmt.Errorf("inspect replica cleanup tombstone failed")
	}

	info, err := os.Lstat(finalPath)
	if os.IsNotExist(err) {
		receipt.Outcome = protocol.DeleteReplicaOutcomeAlreadyAbsent
		return receipt, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return receipt, fmt.Errorf("invalid replica cleanup destination")
	}
	matches, err := replicaTreeMatchesCleanup(finalPath, req, a.Cfg.NodeID)
	if err != nil {
		return receipt, err
	}
	if !matches {
		// A newer publication won the path before this delayed command arrived.
		// Treat it as an idempotent no-op and never remove the replacement.
		receipt.Outcome = protocol.DeleteReplicaOutcomeSuperseded
		return receipt, nil
	}
	superseded := false
	err = func() error {
		a.stateMu.Lock()
		defer a.stateMu.Unlock()
		if err := a.replicaCleanupMutationAllowedLocked(req, time.Now().UTC()); err != nil {
			return err
		}
		// Revalidate while both the publication mutex and control-mode lock are
		// held; neither a local replacement nor an independent-mode transition can
		// cross the destructive namespace mutation.
		matches, err = replicaTreeMatchesCleanup(finalPath, req, a.Cfg.NodeID)
		if err != nil {
			return err
		}
		if !matches {
			superseded = true
			return nil
		}
		if err := os.MkdirAll(trashRoot, 0o700); err != nil {
			return fmt.Errorf("create replica cleanup tombstone failed")
		}
		trashInfo, err := os.Lstat(trashRoot)
		if err != nil || !trashInfo.IsDir() || trashInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("invalid replica cleanup tombstone root")
		}
		if err := os.Rename(finalPath, trashPath); err != nil {
			return fmt.Errorf("atomically isolate replica for cleanup failed")
		}
		if err := syncSnapshotDirectory(root); err != nil {
			return fmt.Errorf("sync replica cleanup publication root failed")
		}
		if err := syncSnapshotDirectory(trashRoot); err != nil {
			return fmt.Errorf("sync replica cleanup tombstone root failed")
		}
		return nil
	}()
	if err != nil {
		return receipt, err
	}
	if superseded {
		receipt.Outcome = protocol.DeleteReplicaOutcomeSuperseded
		return receipt, nil
	}
	if err := removeReplicaTree(trashPath); err != nil {
		return receipt, fmt.Errorf("remove isolated replica failed")
	}
	if err := syncSnapshotDirectory(trashRoot); err != nil {
		return receipt, fmt.Errorf("sync replica cleanup completion failed")
	}
	receipt.Outcome = protocol.DeleteReplicaOutcomeDeleted
	return receipt, nil
}

// replicaCleanupMutationAllowedLocked is evaluated while stateMu and the
// replica publication mutex are both held. It prevents a destructive rename
// from crossing a local failover transition or a live local writer grant.
func (a *Agent) replicaCleanupMutationAllowedLocked(req protocol.DeleteReplicaRequest, now time.Time) error {
	if a.state.ControlMode.Mode != protocol.NodeModeManaged {
		return fmt.Errorf("replica cleanup requires managed mode")
	}
	if req.ReplicaKind != "hot_standby" {
		return nil
	}
	for _, lease := range a.state.ActivityLeases.Leases {
		if lease.Handle == req.Handle && lease.LeaseExpiresAt > now.UnixMilli() {
			return fmt.Errorf("replica cleanup blocked by local writer lease")
		}
	}
	if claim, exists := a.state.ActivityOwnership[req.Handle]; exists && claim.OwnerNodeID == a.Cfg.NodeID {
		return fmt.Errorf("replica cleanup blocked by local ownership claim")
	}
	return nil
}

func canonicalReplicaCleanupRoot(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("invalid replica cleanup root")
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("invalid replica cleanup root")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(absolute) {
		return "", fmt.Errorf("replica cleanup root contains a symbolic link")
	}
	return absolute, nil
}

// recoverReplicaCleanupTombstones completes only deletions that were already
// atomically detached from a public replica name. The private root and every
// child are validated before the first removal so malformed or symlinked state
// makes startup fail closed without touching user directories.
func (a *Agent) recoverReplicaCleanupTombstones() error {
	if a.Cfg == nil || (a.Cfg.Role != "compute" && a.Cfg.Role != "storage") {
		return nil
	}
	var publicationRoot string
	if a.Cfg.Role == "storage" {
		publicationRoot = filepath.Join(a.Cfg.BackupDir, "replicas")
	} else {
		publicationRoot = a.dataRoot()
	}
	root, err := canonicalReplicaCleanupRoot(publicationRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	cleanupRoot := filepath.Join(root, ".stcontrol-cleanups")
	canonicalCleanupRoot, err := canonicalReplicaCleanupRoot(cleanupRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !isSubPath(root, canonicalCleanupRoot) {
		return fmt.Errorf("invalid replica cleanup tombstone root")
	}
	entries, err := os.ReadDir(canonicalCleanupRoot)
	if err != nil {
		return fmt.Errorf("read replica cleanup tombstones failed")
	}
	tombstones := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !validUUID(entry.Name()) {
			return fmt.Errorf("invalid replica cleanup tombstone name")
		}
		path := filepath.Join(canonicalCleanupRoot, entry.Name())
		canonicalPath, err := canonicalReplicaCleanupRoot(path)
		if err != nil || !isSubPath(canonicalCleanupRoot, canonicalPath) {
			return fmt.Errorf("invalid replica cleanup tombstone")
		}
		if err := a.validateDetachedReplicaTombstone(canonicalPath); err != nil {
			return err
		}
		tombstones = append(tombstones, canonicalPath)
	}
	for _, tombstone := range tombstones {
		if err := removeReplicaTree(tombstone); err != nil {
			return fmt.Errorf("remove replica cleanup tombstone failed")
		}
	}
	if len(tombstones) > 0 {
		if err := syncSnapshotDirectory(canonicalCleanupRoot); err != nil {
			return fmt.Errorf("sync replica cleanup tombstone root failed")
		}
	}
	return nil
}

func (a *Agent) validateDetachedReplicaTombstone(root string) error {
	if a.Cfg.NodeID <= 0 {
		return fmt.Errorf("invalid replica cleanup node identity")
	}
	if a.Cfg.Role == "storage" {
		metadata, err := readArchiveReplicaMetadata(root)
		if err != nil || metadata.FormatVersion != 1 || !validUUID(metadata.Manifest.WorkflowID) ||
			!validUUID(metadata.Manifest.SnapshotID) || metadata.Manifest.GlobalUserID <= 0 ||
			!validHandle(metadata.Manifest.Handle) || metadata.Manifest.TargetNodeID != a.Cfg.NodeID ||
			!metadata.Receipt.OK || metadata.Receipt.SnapshotID != metadata.Manifest.SnapshotID {
			return fmt.Errorf("invalid archive cleanup tombstone identity")
		}
		return nil
	}
	metadata, err := readReplicaIdentityMetadata(root)
	if err != nil || metadata.FormatVersion != 1 || !validUUID(metadata.SnapshotID) ||
		metadata.GlobalUserID <= 0 || !validHandle(metadata.Handle) || metadata.TargetNodeID != a.Cfg.NodeID ||
		metadata.ReplicaKind != "hot_standby" {
		return fmt.Errorf("invalid compute cleanup tombstone identity")
	}
	return nil
}

func replicaTreeMatchesCleanup(root string, req protocol.DeleteReplicaRequest, nodeID int64) (bool, error) {
	if req.ReplicaKind == "archive" {
		metadata, err := readArchiveReplicaMetadata(root)
		if err != nil {
			return false, fmt.Errorf("archive replica identity unavailable")
		}
		return metadata.FormatVersion == 1 && metadata.Manifest.SnapshotID == req.SnapshotID &&
			metadata.Manifest.GlobalUserID == req.GlobalUserID && metadata.Manifest.Handle == req.Handle &&
			metadata.Manifest.TargetNodeID == nodeID, nil
	}
	metadata, err := readReplicaIdentityMetadata(root)
	if err != nil {
		// A legacy tree published before the identity-file feature cannot be
		// verified and must NEVER be deleted blindly.  Surface a distinct
		// sentinel so the Controller fails the cleanup task terminally instead
		// of retrying forever (which would block this user's snapshots).
		return false, fmt.Errorf("%w: %v", errReplicaIdentityUnavailable, err)
	}
	return metadata.FormatVersion == 1 && metadata.SnapshotID == req.SnapshotID &&
		metadata.GlobalUserID == req.GlobalUserID && metadata.Handle == req.Handle &&
		metadata.ReplicaKind == req.ReplicaKind && metadata.TargetNodeID == nodeID, nil
}

func readReplicaIdentityMetadata(root string) (replicaIdentityMetadata, error) {
	var metadata replicaIdentityMetadata
	path := filepath.Join(root, replicaIdentityPath)
	if !isSubPath(root, path) {
		return metadata, fmt.Errorf("unsafe replica identity path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 4<<10 {
		return metadata, fmt.Errorf("replica identity unavailable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return metadata, fmt.Errorf("replica identity unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return replicaIdentityMetadata{}, fmt.Errorf("invalid replica identity")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return replicaIdentityMetadata{}, fmt.Errorf("invalid replica identity")
	}
	return metadata, nil
}

func removeReplicaTree(path string) error {
	if err := filepath.Walk(path, func(current string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.Chmod(current, 0o700)
		}
		return nil
	}); err != nil {
		return err
	}
	return os.RemoveAll(path)
}
