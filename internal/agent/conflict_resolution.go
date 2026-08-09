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
	"runtime"
	"sort"
	"time"

	"stcontrol/internal/protocol"
)

const conflictResolutionMaxSources = 20

type conflictResolutionPlan struct {
	FormatVersion     int                                 `json:"format_version"`
	OperationID       string                              `json:"operation_id"`
	ConflictID        string                              `json:"conflict_id"`
	ResultID          string                              `json:"result_id"`
	GlobalUserID      int64                               `json:"global_user_id"`
	Handle            string                              `json:"handle"`
	BaseNodeID        int64                               `json:"base_node_id"`
	DefaultAction     string                              `json:"default_action"`
	DecisionPageCount int                                 `json:"decision_page_count"`
	DecisionCount     int                                 `json:"decision_count"`
	Sources           []protocol.ConflictResolutionSource `json:"sources"`
}

type conflictResolutionSourceData struct {
	Root   string
	Files  []protocol.ManifestEntry
	ByPath map[string]protocol.ManifestEntry
}

type conflictResolutionSelectedFile struct {
	NodeID     int64
	SourcePath string
	Entry      protocol.ManifestEntry
}

const conflictPreservedDirectory = "conflict-preserved"

func (a *Agent) RunConflictEvidenceTransfer(
	ctx context.Context,
	req protocol.StartConflictEvidenceTransferRequest,
) (protocol.SnapshotTransferReceipt, error) {
	if runtime.GOOS != "linux" || !validUUID(req.ConflictID) || !validUUID(req.EvidenceID) ||
		req.GlobalUserID <= 0 || !validHandle(req.Handle) || req.TargetNodeID <= 0 ||
		req.TargetNodeID == a.Cfg.NodeID || req.TargetTransferURL == "" ||
		req.TransferCapability == "" || !req.CapabilityExpires.After(time.Now().UTC()) {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("invalid conflict evidence transfer request")
	}
	_, sourceRoot, _, err := a.conflictEvidencePaths(req.ConflictID, req.EvidenceID)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	metadata, err := readConflictEvidenceMetadata(sourceRoot)
	if err != nil || metadata.ConflictID != req.ConflictID || metadata.EvidenceID != req.EvidenceID ||
		metadata.GlobalUserID != req.GlobalUserID || metadata.Handle != req.Handle || metadata.NodeID != a.Cfg.NodeID {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("conflict evidence transfer scope mismatch")
	}
	if err := verifyConflictEvidence(ctx, sourceRoot, metadata.Files); err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	manifest := protocol.SnapshotManifest{
		FormatVersion: 1, WorkflowID: req.ConflictID, SnapshotID: req.EvidenceID,
		GlobalUserID: req.GlobalUserID, Handle: req.Handle, SourceNodeID: a.Cfg.NodeID,
		TargetNodeID: req.TargetNodeID, ActivityEpoch: 1, CreatedAt: time.Now().UTC(),
		Files: metadata.Files,
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	manifestDigest := sha256.Sum256(manifestJSON)
	taskRoot, err := a.sourceSnapshotTaskPath(req.ConflictID, req.EvidenceID)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	if err := resetTaskDirectory(taskRoot); err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	defer removeTaskDirectory(taskRoot)
	archivePath := filepath.Join(taskRoot, "conflict-evidence.tar.zst")
	if err := createSnapshotArchive(ctx, archivePath, sourceRoot, manifestJSON, manifest.Files); err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	archiveDigest, err := hashFile(archivePath)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	receipt, err := a.streamSnapshot(ctx, protocol.StartSnapshotRequest{
		WorkflowID: req.ConflictID, SnapshotID: req.EvidenceID,
		TargetTransferURL: req.TargetTransferURL, TransferCapability: req.TransferCapability,
		CapabilityExpires: req.CapabilityExpires, DestinationKind: "conflict_input",
	}, archivePath, archiveDigest)
	if err != nil {
		return protocol.SnapshotTransferReceipt{}, err
	}
	if receipt.SnapshotID != req.EvidenceID ||
		receipt.ManifestSHA256 != hex.EncodeToString(manifestDigest[:]) ||
		receipt.ArchiveSHA256 != hex.EncodeToString(archiveDigest[:]) ||
		receipt.FileCount != metadata.FileCount || receipt.TotalBytes != metadata.TotalBytes {
		return protocol.SnapshotTransferReceipt{}, fmt.Errorf("conflict evidence target receipt mismatch")
	}
	return receipt, nil
}

func (a *Agent) prepareConflictResolution(ctx context.Context, req protocol.PrepareConflictResolutionRequest) error {
	if !validUUID(req.OperationID) || !validUUID(req.ConflictID) || !validUUID(req.ResultID) ||
		req.GlobalUserID <= 0 || !validHandle(req.Handle) || req.BaseNodeID != a.Cfg.NodeID ||
		(req.DefaultAction != "use_base" && req.DefaultAction != "preserve_all_originals") ||
		req.DecisionPageCount < 0 || req.DecisionPageCount > 1000 || req.DecisionCount < 0 ||
		(req.DecisionCount == 0) != (req.DecisionPageCount == 0) ||
		len(req.Sources) < 2 || len(req.Sources) > conflictResolutionMaxSources {
		return fmt.Errorf("invalid conflict resolution plan")
	}
	seenNodes := make(map[int64]bool, len(req.Sources))
	seenEvidence := make(map[string]bool, len(req.Sources))
	hasBase := false
	for _, source := range req.Sources {
		if source.NodeID <= 0 || !validUUID(source.EvidenceID) || !validCapabilityHash(source.EntriesSHA256) ||
			seenNodes[source.NodeID] || seenEvidence[source.EvidenceID] {
			return fmt.Errorf("invalid conflict resolution source")
		}
		seenNodes[source.NodeID] = true
		seenEvidence[source.EvidenceID] = true
		hasBase = hasBase || source.NodeID == req.BaseNodeID
		if _, err := a.loadConflictResolutionSource(ctx, req.ConflictID, req.GlobalUserID, req.Handle, source); err != nil {
			return err
		}
	}
	if !hasBase {
		return fmt.Errorf("conflict resolution base source missing")
	}
	plan := conflictResolutionPlan{
		FormatVersion: 1, OperationID: req.OperationID, ConflictID: req.ConflictID,
		ResultID: req.ResultID, GlobalUserID: req.GlobalUserID, Handle: req.Handle,
		BaseNodeID: req.BaseNodeID, DefaultAction: req.DefaultAction,
		DecisionPageCount: req.DecisionPageCount, DecisionCount: req.DecisionCount,
		Sources: req.Sources,
	}
	data, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	root, err := a.conflictResolutionPlanRoot(req.OperationID)
	if err != nil {
		return err
	}
	path := filepath.Join(root, "plan.json")
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("conflict resolution plan collision")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return writePrivateFileAtomic(path, data)
}

func (a *Agent) applyConflictResolutionDecisions(req protocol.ApplyConflictResolutionDecisionsRequest) error {
	if !validUUID(req.OperationID) || req.PageIndex < 0 || len(req.Decisions) == 0 || len(req.Decisions) > 100 {
		return fmt.Errorf("invalid conflict resolution decisions")
	}
	plan, root, err := a.readConflictResolutionPlan(req.OperationID)
	if err != nil || req.PageIndex >= plan.DecisionPageCount {
		return fmt.Errorf("conflict resolution plan unavailable")
	}
	allowedSources := make(map[int64]bool, len(plan.Sources))
	for _, source := range plan.Sources {
		allowedSources[source.NodeID] = true
	}
	seen := make(map[string]bool, len(req.Decisions))
	for _, decision := range req.Decisions {
		if !safeArchivePath(decision.Path) || !allowedSources[decision.SourceNodeID] ||
			(decision.Action != "use_source" && decision.Action != "preserve_both") || seen[decision.Path] {
			return fmt.Errorf("invalid conflict resolution decision")
		}
		seen[decision.Path] = true
	}
	data, err := json.Marshal(req.Decisions)
	if err != nil {
		return err
	}
	path := filepath.Join(root, "decisions", fmt.Sprintf("%06d.json", req.PageIndex))
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("conflict decision page collision")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return writePrivateFileAtomic(path, data)
}

func (a *Agent) publishConflictResolution(ctx context.Context, operationID string) (protocol.ConflictResolutionReceipt, error) {
	if runtime.GOOS != "linux" || !validUUID(operationID) {
		return protocol.ConflictResolutionReceipt{}, fmt.Errorf("invalid conflict resolution publication")
	}
	plan, planRoot, err := a.readConflictResolutionPlan(operationID)
	if err != nil {
		return protocol.ConflictResolutionReceipt{}, err
	}
	receiptPath := filepath.Join(planRoot, "receipt.json")
	if receipt, err := readConflictResolutionReceipt(receiptPath); err == nil {
		if receipt.OperationID != plan.OperationID || receipt.ConflictID != plan.ConflictID ||
			receipt.ResultID != plan.ResultID {
			return protocol.ConflictResolutionReceipt{}, fmt.Errorf("conflict resolution receipt collision")
		}
		return receipt, nil
	} else if !os.IsNotExist(err) {
		return protocol.ConflictResolutionReceipt{}, err
	}
	decisions, err := readConflictResolutionDecisions(planRoot, plan)
	if err != nil {
		return protocol.ConflictResolutionReceipt{}, err
	}
	sources := make(map[int64]conflictResolutionSourceData, len(plan.Sources))
	for _, source := range plan.Sources {
		data, err := a.loadConflictResolutionSource(ctx, plan.ConflictID, plan.GlobalUserID, plan.Handle, source)
		if err != nil {
			return protocol.ConflictResolutionReceipt{}, err
		}
		sources[source.NodeID] = data
	}
	selected, usedDecisions, err := buildConflictResolutionSelection(plan, sources, decisions)
	if err != nil || usedDecisions != len(decisions) {
		return protocol.ConflictResolutionReceipt{}, fmt.Errorf("conflict resolution decisions do not match evidence")
	}
	if len(selected) > maxSnapshotFiles {
		return protocol.ConflictResolutionReceipt{}, fmt.Errorf("conflict resolution exceeds file limit")
	}
	var totalBytes int64
	for _, selectedFile := range selected {
		if totalBytes > maxSnapshotBytes-selectedFile.Entry.Size {
			return protocol.ConflictResolutionReceipt{}, fmt.Errorf("conflict resolution exceeds size limit")
		}
		totalBytes += selectedFile.Entry.Size
	}
	dataRoot := a.dataRoot()
	if err := ensureSnapshotDiskCapacity(dataRoot, totalBytes); err != nil {
		return protocol.ConflictResolutionReceipt{}, err
	}
	taskRoot := filepath.Join(dataRoot, ".stcontrol-resolution-tasks", plan.OperationID)
	if err := resetTaskDirectory(taskRoot); err != nil {
		return protocol.ConflictResolutionReceipt{}, err
	}
	defer removeTaskDirectory(taskRoot)
	staging := filepath.Join(taskRoot, "staging")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return protocol.ConflictResolutionReceipt{}, err
	}
	resultEntries := make([]protocol.ManifestEntry, 0, len(selected))
	for _, selectedFile := range selected {
		source := sources[selectedFile.NodeID]
		if err := copyConflictResolutionFile(source.Root, staging, selectedFile.SourcePath, selectedFile.Entry); err != nil {
			return protocol.ConflictResolutionReceipt{}, err
		}
		resultEntries = append(resultEntries, selectedFile.Entry)
	}
	entriesJSON, err := json.Marshal(resultEntries)
	if err != nil {
		return protocol.ConflictResolutionReceipt{}, err
	}
	digest := sha256.Sum256(entriesJSON)
	finalPath := filepath.Join(dataRoot, plan.Handle)
	if err := publishSnapshotDirectory(staging, finalPath, taskRoot); err != nil {
		return protocol.ConflictResolutionReceipt{}, err
	}
	receipt := protocol.ConflictResolutionReceipt{
		OperationID: plan.OperationID, ConflictID: plan.ConflictID, ResultID: plan.ResultID,
		EntriesSHA256: hex.EncodeToString(digest[:]), FileCount: int64(len(resultEntries)),
		TotalBytes: totalBytes, PreservedSources: len(plan.Sources),
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return protocol.ConflictResolutionReceipt{}, err
	}
	if err := writePrivateFileAtomic(receiptPath, data); err != nil {
		return protocol.ConflictResolutionReceipt{}, err
	}
	return receipt, nil
}

func (a *Agent) conflictResolutionPlanRoot(operationID string) (string, error) {
	if !validUUID(operationID) {
		return "", fmt.Errorf("invalid conflict resolution identity")
	}
	base := a.dataRoot()
	root := filepath.Join(base, ".stcontrol-resolution-plans", operationID)
	if !isSubPath(base, root) {
		return "", fmt.Errorf("unsafe conflict resolution path")
	}
	return root, nil
}

func (a *Agent) readConflictResolutionPlan(operationID string) (conflictResolutionPlan, string, error) {
	root, err := a.conflictResolutionPlanRoot(operationID)
	if err != nil {
		return conflictResolutionPlan{}, "", err
	}
	var plan conflictResolutionPlan
	if err := readStrictPrivateJSON(filepath.Join(root, "plan.json"), &plan, 1<<20); err != nil ||
		plan.FormatVersion != 1 || plan.OperationID != operationID || !validUUID(plan.ConflictID) ||
		!validUUID(plan.ResultID) || plan.GlobalUserID <= 0 || !validHandle(plan.Handle) ||
		plan.BaseNodeID != a.Cfg.NodeID || len(plan.Sources) < 2 || len(plan.Sources) > conflictResolutionMaxSources {
		return conflictResolutionPlan{}, "", fmt.Errorf("invalid conflict resolution plan")
	}
	return plan, root, nil
}

func (a *Agent) loadConflictResolutionSource(
	ctx context.Context,
	conflictID string,
	globalUserID int64,
	handle string,
	source protocol.ConflictResolutionSource,
) (conflictResolutionSourceData, error) {
	var root string
	var files []protocol.ManifestEntry
	if source.NodeID == a.Cfg.NodeID {
		_, localRoot, _, err := a.conflictEvidencePaths(conflictID, source.EvidenceID)
		if err != nil {
			return conflictResolutionSourceData{}, err
		}
		metadata, err := readConflictEvidenceMetadata(localRoot)
		if err != nil || metadata.ConflictID != conflictID || metadata.EvidenceID != source.EvidenceID ||
			metadata.GlobalUserID != globalUserID || metadata.Handle != handle || metadata.NodeID != source.NodeID ||
			!stringsEqualDigest(metadata.EntriesSHA256, source.EntriesSHA256) {
			return conflictResolutionSourceData{}, fmt.Errorf("local conflict evidence scope mismatch")
		}
		if err := verifyConflictEvidence(ctx, localRoot, metadata.Files); err != nil {
			return conflictResolutionSourceData{}, err
		}
		root = localRoot
		files = metadata.Files
	} else {
		remoteRoot := filepath.Join(a.dataRoot(), ".stcontrol-conflict-inputs", conflictID, source.EvidenceID)
		if !isSubPath(a.dataRoot(), remoteRoot) {
			return conflictResolutionSourceData{}, fmt.Errorf("unsafe remote conflict evidence path")
		}
		metadata, err := readArchiveReplicaMetadata(remoteRoot)
		if err != nil || metadata.Manifest.WorkflowID != conflictID ||
			metadata.Manifest.SnapshotID != source.EvidenceID || metadata.Manifest.GlobalUserID != globalUserID ||
			metadata.Manifest.Handle != handle || metadata.Manifest.SourceNodeID != source.NodeID ||
			metadata.Manifest.TargetNodeID != a.Cfg.NodeID || metadata.Manifest.ActivityEpoch != 1 {
			return conflictResolutionSourceData{}, fmt.Errorf("remote conflict evidence scope mismatch")
		}
		entriesJSON, err := json.Marshal(metadata.Manifest.Files)
		if err != nil {
			return conflictResolutionSourceData{}, err
		}
		digest := sha256.Sum256(entriesJSON)
		if !stringsEqualDigest(hex.EncodeToString(digest[:]), source.EntriesSHA256) {
			return conflictResolutionSourceData{}, fmt.Errorf("remote conflict evidence digest mismatch")
		}
		if _, err := verifyArchiveReplica(ctx, remoteRoot, metadata.Manifest.Files); err != nil {
			return conflictResolutionSourceData{}, err
		}
		root = remoteRoot
		files = metadata.Manifest.Files
	}
	byPath := make(map[string]protocol.ManifestEntry, len(files))
	for _, entry := range files {
		if _, exists := byPath[entry.Path]; exists {
			return conflictResolutionSourceData{}, fmt.Errorf("duplicate conflict evidence path")
		}
		byPath[entry.Path] = entry
	}
	return conflictResolutionSourceData{Root: root, Files: files, ByPath: byPath}, nil
}

func buildConflictResolutionSelection(
	plan conflictResolutionPlan,
	sources map[int64]conflictResolutionSourceData,
	decisions map[string]protocol.ConflictResolutionDecision,
) ([]conflictResolutionSelectedFile, int, error) {
	allPaths := make(map[string]struct{})
	for _, source := range plan.Sources {
		data, ok := sources[source.NodeID]
		if !ok {
			return nil, 0, fmt.Errorf("conflict resolution source unavailable")
		}
		for path := range data.ByPath {
			allPaths[path] = struct{}{}
		}
	}
	paths := make([]string, 0, len(allPaths))
	for path := range allPaths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	selected := make([]conflictResolutionSelectedFile, 0, len(paths))
	reservedPaths := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		reservedPaths[path] = struct{}{}
	}
	usedDecisions := 0
	for _, path := range paths {
		versions := make(map[string]struct{})
		presentNodes := make([]int64, 0, len(plan.Sources))
		for _, source := range plan.Sources {
			if entry, ok := sources[source.NodeID].ByPath[path]; ok {
				presentNodes = append(presentNodes, source.NodeID)
				versions[entry.SHA256+":"+fmt.Sprintf("%d", entry.Size)] = struct{}{}
			}
		}
		chosenNodeID := int64(0)
		decision, hasDecision := decisions[path]
		if len(versions) == 1 {
			if hasDecision {
				return nil, 0, fmt.Errorf("decision targets a non-conflicting path")
			}
			if _, ok := sources[plan.BaseNodeID].ByPath[path]; ok {
				chosenNodeID = plan.BaseNodeID
			} else if len(presentNodes) > 0 {
				chosenNodeID = presentNodes[0]
			}
		} else if hasDecision {
			if _, ok := sources[decision.SourceNodeID].ByPath[path]; !ok ||
				(decision.Action != "use_source" && decision.Action != "preserve_both") {
				return nil, 0, fmt.Errorf("decision source does not contain path")
			}
			chosenNodeID = decision.SourceNodeID
			usedDecisions++
		} else if _, ok := sources[plan.BaseNodeID].ByPath[path]; ok {
			chosenNodeID = plan.BaseNodeID
		} else {
			return nil, 0, fmt.Errorf("base source does not contain conflicting path")
		}
		entry, ok := sources[chosenNodeID].ByPath[path]
		if !ok {
			return nil, 0, fmt.Errorf("conflict resolution selection unavailable")
		}
		selected = append(selected, conflictResolutionSelectedFile{NodeID: chosenNodeID, SourcePath: entry.Path, Entry: entry})
		preserveAll := (hasDecision && decision.Action == "preserve_both") ||
			(!hasDecision && plan.DefaultAction == "preserve_all_originals")
		if !preserveAll || len(versions) <= 1 {
			continue
		}
		preservedVersions := map[string]struct{}{entry.SHA256 + ":" + fmt.Sprintf("%d", entry.Size): {}}
		for _, source := range plan.Sources {
			alternate, ok := sources[source.NodeID].ByPath[path]
			if !ok {
				continue
			}
			version := alternate.SHA256 + ":" + fmt.Sprintf("%d", alternate.Size)
			if _, exists := preservedVersions[version]; exists {
				continue
			}
			preservedPath, err := conflictPreservedPath(plan.ConflictID, source.NodeID, path, reservedPaths)
			if err != nil {
				return nil, 0, err
			}
			sourcePath := alternate.Path
			alternate.Path = preservedPath
			selected = append(selected, conflictResolutionSelectedFile{NodeID: source.NodeID, SourcePath: sourcePath, Entry: alternate})
			preservedVersions[version] = struct{}{}
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Entry.Path < selected[j].Entry.Path })
	return selected, usedDecisions, nil
}

func conflictPreservedPath(conflictID string, nodeID int64, original string, reserved map[string]struct{}) (string, error) {
	if !validUUID(conflictID) || nodeID <= 0 || !safeArchivePath(original) {
		return "", fmt.Errorf("invalid preserved conflict file")
	}
	base := fmt.Sprintf("%s/%s/source-%d/%s", conflictPreservedDirectory, conflictID, nodeID, original)
	for suffix := 0; suffix < 1000; suffix++ {
		candidate := base
		if suffix > 0 {
			candidate = fmt.Sprintf("%s.copy-%d", base, suffix)
		}
		if !safeArchivePath(candidate) {
			return "", fmt.Errorf("invalid preserved conflict path")
		}
		if _, exists := reserved[candidate]; exists {
			continue
		}
		reserved[candidate] = struct{}{}
		return candidate, nil
	}
	return "", fmt.Errorf("preserved conflict path collision")
}

func readConflictResolutionDecisions(
	planRoot string,
	plan conflictResolutionPlan,
) (map[string]protocol.ConflictResolutionDecision, error) {
	out := make(map[string]protocol.ConflictResolutionDecision, plan.DecisionCount)
	count := 0
	for pageIndex := 0; pageIndex < plan.DecisionPageCount; pageIndex++ {
		var page []protocol.ConflictResolutionDecision
		path := filepath.Join(planRoot, "decisions", fmt.Sprintf("%06d.json", pageIndex))
		if err := readStrictPrivateJSON(path, &page, 1<<20); err != nil || len(page) == 0 || len(page) > 100 {
			return nil, fmt.Errorf("conflict decision page unavailable")
		}
		for _, decision := range page {
			if !safeArchivePath(decision.Path) || decision.SourceNodeID <= 0 ||
				(decision.Action != "use_source" && decision.Action != "preserve_both") {
				return nil, fmt.Errorf("invalid conflict resolution decision")
			}
			if _, exists := out[decision.Path]; exists {
				return nil, fmt.Errorf("duplicate conflict resolution decision")
			}
			out[decision.Path] = decision
			count++
		}
	}
	if count != plan.DecisionCount {
		return nil, fmt.Errorf("conflict resolution decision count mismatch")
	}
	return out, nil
}

func copyConflictResolutionFile(sourceRoot, destination, sourceRelativePath string, entry protocol.ManifestEntry) error {
	if !safeArchivePath(sourceRelativePath) || !safeArchivePath(entry.Path) || entry.Size < 0 || !validCapabilityHash(entry.SHA256) {
		return fmt.Errorf("invalid conflict resolution file")
	}
	sourcePath := filepath.Join(sourceRoot, filepath.FromSlash(sourceRelativePath))
	targetPath := filepath.Join(destination, filepath.FromSlash(entry.Path))
	if !isSubPath(sourceRoot, sourcePath) || !isSubPath(destination, targetPath) {
		return fmt.Errorf("conflict resolution path escaped")
	}
	info, err := os.Lstat(sourcePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != entry.Size {
		return fmt.Errorf("conflict resolution source changed")
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		return err
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	target, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		return err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(target, io.TeeReader(io.LimitReader(source, entry.Size+1), hash))
	closeErr := target.Close()
	want, _ := hex.DecodeString(entry.SHA256)
	if copyErr != nil || closeErr != nil || written != entry.Size || !hmac.Equal(hash.Sum(nil), want) {
		return fmt.Errorf("conflict resolution file verification failed")
	}
	return nil
}

func writePrivateFileAtomic(path string, data []byte) error {
	if path == "" || len(data) == 0 {
		return fmt.Errorf("invalid private state file")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".private-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func readStrictPrivateJSON(path string, out any, maxBytes int64) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > maxBytes {
		if err != nil {
			return err
		}
		return fmt.Errorf("invalid private state file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("invalid private state JSON")
	}
	return nil
}

func readConflictResolutionReceipt(path string) (protocol.ConflictResolutionReceipt, error) {
	var receipt protocol.ConflictResolutionReceipt
	if err := readStrictPrivateJSON(path, &receipt, 64<<10); err != nil {
		if os.IsNotExist(err) {
			return protocol.ConflictResolutionReceipt{}, err
		}
		return protocol.ConflictResolutionReceipt{}, fmt.Errorf("invalid conflict resolution receipt")
	}
	if !validUUID(receipt.OperationID) || !validUUID(receipt.ConflictID) || !validUUID(receipt.ResultID) ||
		!validCapabilityHash(receipt.EntriesSHA256) || receipt.FileCount < 0 || receipt.TotalBytes < 0 ||
		receipt.PreservedSources < 2 {
		return protocol.ConflictResolutionReceipt{}, fmt.Errorf("invalid conflict resolution receipt")
	}
	return receipt, nil
}

func stringsEqualDigest(left, right string) bool {
	leftBytes, leftErr := hex.DecodeString(left)
	rightBytes, rightErr := hex.DecodeString(right)
	return leftErr == nil && rightErr == nil && len(leftBytes) == sha256.Size &&
		len(rightBytes) == sha256.Size && hmac.Equal(leftBytes, rightBytes)
}
