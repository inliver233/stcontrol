//go:build linux

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func TestConflictResolutionCommandsPublishAtomicallyAndReplayReceipt(t *testing.T) {
	const (
		operationID      = "81000000-0000-4000-8000-000000000001"
		conflictID       = "81000000-0000-4000-8000-000000000002"
		resultID         = "81000000-0000-4000-8000-000000000003"
		baseEvidenceID   = "81000000-0000-4000-8000-000000000004"
		remoteEvidenceID = "81000000-0000-4000-8000-000000000005"
	)
	root := t.TempDir()
	tavernDir := filepath.Join(root, "tavern")
	userRoot := filepath.Join(tavernDir, "data", "alice")
	if err := os.MkdirAll(userRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	writeConflictResolutionTestFile(t, userRoot, "shared.txt", []byte("base shared"))
	writeConflictResolutionTestFile(t, userRoot, "base-only.txt", []byte("base only"))
	a, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 8, TavernDir: tavernDir,
		DataDir: filepath.Join(root, "agent-state"), AgentPSK: "conflict-resolution-agent-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	baseReceipt, err := a.captureConflictEvidence(context.Background(), protocol.CaptureConflictEvidenceRequest{
		ConflictID: conflictID, EvidenceID: baseEvidenceID, GlobalUserID: 70,
		Handle: "alice", SourceKind: "active",
	})
	if err != nil {
		t.Fatalf("capture base evidence: %v", err)
	}

	remoteRoot := filepath.Join(a.dataRoot(), ".stcontrol-conflict-inputs", conflictID, remoteEvidenceID)
	if err := os.MkdirAll(remoteRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	remoteEntries := []protocol.ManifestEntry{
		writeConflictResolutionTestFile(t, remoteRoot, "remote-only.txt", []byte("remote only")),
		writeConflictResolutionTestFile(t, remoteRoot, "shared.txt", []byte("remote shared")),
	}
	remoteEntriesJSON, err := json.Marshal(remoteEntries)
	if err != nil {
		t.Fatal(err)
	}
	remoteEntriesDigest := sha256.Sum256(remoteEntriesJSON)
	remoteEntriesSHA := hex.EncodeToString(remoteEntriesDigest[:])
	manifest := protocol.SnapshotManifest{
		FormatVersion: 1, WorkflowID: conflictID, SnapshotID: remoteEvidenceID,
		GlobalUserID: 70, Handle: "alice", SourceNodeID: 9, TargetNodeID: 8,
		ActivityEpoch: 1, CreatedAt: time.Now().UTC(), Files: remoteEntries,
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := sha256.Sum256(manifestJSON)
	if err := writeArchiveReplicaMetadata(remoteRoot, manifest, protocol.SnapshotTransferReceipt{
		OK: true, SnapshotID: remoteEvidenceID,
		ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
		ArchiveSHA256:  hex.EncodeToString(make([]byte, sha256.Size)),
		FileCount:      int64(len(remoteEntries)),
		TotalBytes:     int64(len("remote only") + len("remote shared")),
	}); err != nil {
		t.Fatalf("write remote evidence metadata: %v", err)
	}

	prepare := protocol.PrepareConflictResolutionRequest{
		OperationID: operationID, ConflictID: conflictID, ResultID: resultID,
		GlobalUserID: 70, Handle: "alice", BaseNodeID: 8,
		DefaultAction: "use_base", DecisionPageCount: 1, DecisionCount: 1,
		Sources: []protocol.ConflictResolutionSource{
			{NodeID: 8, EvidenceID: baseEvidenceID, EntriesSHA256: baseReceipt.EntriesSHA256},
			{NodeID: 9, EvidenceID: remoteEvidenceID, EntriesSHA256: remoteEntriesSHA},
		},
	}
	assertConflictResolutionCommand(t, a, "prepare_conflict_resolution", operationID, prepare, true)
	assertConflictResolutionCommand(t, a, "prepare_conflict_resolution", operationID, prepare, true)
	conflictingPrepare := prepare
	conflictingPrepare.DefaultAction = "preserve_all_originals"
	assertConflictResolutionCommand(t, a, "prepare_conflict_resolution", operationID, conflictingPrepare, false)

	decisions := protocol.ApplyConflictResolutionDecisionsRequest{
		OperationID: operationID, PageIndex: 0,
		Decisions: []protocol.ConflictResolutionDecision{{
			Path: "shared.txt", SourceNodeID: 9, Action: "preserve_both",
		}},
	}
	assertConflictResolutionCommand(t, a, "apply_conflict_resolution_decisions", operationID, decisions, true)
	assertConflictResolutionCommand(t, a, "apply_conflict_resolution_decisions", operationID, decisions, true)
	conflictingDecisions := decisions
	conflictingDecisions.Decisions = append([]protocol.ConflictResolutionDecision(nil), decisions.Decisions...)
	conflictingDecisions.Decisions[0].SourceNodeID = 8
	assertConflictResolutionCommand(t, a, "apply_conflict_resolution_decisions", operationID, conflictingDecisions, false)

	publishPayload := protocol.PublishConflictResolutionRequest{OperationID: operationID}
	first := assertConflictResolutionCommand(t, a, "publish_conflict_resolution", operationID, publishPayload, true)
	if first.ConflictResolution == nil || first.ConflictResolution.FileCount != 4 ||
		first.ConflictResolution.PreservedSources != 2 || first.ConflictResolution.ResultID != resultID {
		t.Fatalf("published receipt=%+v", first.ConflictResolution)
	}
	second := assertConflictResolutionCommand(t, a, "publish_conflict_resolution", operationID, publishPayload, true)
	if second.ConflictResolution == nil || *second.ConflictResolution != *first.ConflictResolution {
		t.Fatalf("replayed receipt=%+v, want %+v", second.ConflictResolution, first.ConflictResolution)
	}
	assertConflictResolutionTestContent(t, userRoot, "shared.txt", "remote shared")
	assertConflictResolutionTestContent(t, userRoot, "base-only.txt", "base only")
	assertConflictResolutionTestContent(t, userRoot, "remote-only.txt", "remote only")
	preserved := filepath.Join(
		conflictPreservedDirectory, conflictID, "source-8", "shared.txt",
	)
	assertConflictResolutionTestContent(t, userRoot, preserved, "base shared")

	planRoot, err := a.conflictResolutionPlanRoot(operationID)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(planRoot, "receipt.json")
	if err := os.Chmod(receiptPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPath, []byte(`{"operation_id":"81000000-0000-4000-8000-000000000099"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	assertConflictResolutionCommand(t, a, "publish_conflict_resolution", operationID, publishPayload, false)
}

func assertConflictResolutionCommand(
	t *testing.T,
	a *Agent,
	commandType, operationID string,
	payload any,
	wantSucceeded bool,
) safeCommandResult {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	command := encryptedTestCommand(t, a.Cfg.AgentPSK, commandType, encoded)
	command.OperationID = operationID
	succeeded, raw := a.executeCommand(context.Background(), command)
	var result safeCommandResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode %s result: %v raw=%s", commandType, err, raw)
	}
	if succeeded != wantSucceeded || result.OK != wantSucceeded {
		if commandType == "publish_conflict_resolution" && wantSucceeded {
			_, directErr := a.publishConflictResolution(context.Background(), operationID)
			t.Fatalf("%s succeeded=%v result=%+v raw=%s direct_err=%v", commandType, succeeded, result, raw, directErr)
		}
		t.Fatalf("%s succeeded=%v result=%+v raw=%s", commandType, succeeded, result, raw)
	}
	return result
}

func writeConflictResolutionTestFile(
	t *testing.T,
	root, relative string,
	content []byte,
) protocol.ManifestEntry {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return protocol.ManifestEntry{
		Path: relative, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
	}
}

func assertConflictResolutionTestContent(t *testing.T, root, relative, want string) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil || string(got) != want {
		t.Fatalf("read %s: got=%q want=%q err=%v", relative, got, want, err)
	}
}
