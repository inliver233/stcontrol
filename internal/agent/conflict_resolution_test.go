package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

func TestCopyConflictResolutionFileCanPublishUnderPreservedPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("original conflict version")
	if err := os.WriteFile(filepath.Join(source, "same.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	entry := protocol.ManifestEntry{
		Path: "conflict-preserved/case/source-8/same.json", Size: int64(len(content)),
		SHA256: hex.EncodeToString(digest[:]),
	}
	if err := copyConflictResolutionFile(source, destination, "same.json", entry); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(destination, filepath.FromSlash(entry.Path)))
	if err != nil || string(got) != string(content) {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestBuildConflictResolutionSelectionMergesDisjointAndChoosesSamePath(t *testing.T) {
	t.Parallel()
	plan := conflictResolutionPlan{
		ConflictID: testConflictID,
		BaseNodeID: 8,
		Sources:    []protocol.ConflictResolutionSource{{NodeID: 8}, {NodeID: 9}},
	}
	sources := map[int64]conflictResolutionSourceData{
		8: {ByPath: map[string]protocol.ManifestEntry{
			"same.json":  {Path: "same.json", Size: 4, SHA256: strings.Repeat("1", 64)},
			"only-a.txt": {Path: "only-a.txt", Size: 5, SHA256: strings.Repeat("2", 64)},
		}},
		9: {ByPath: map[string]protocol.ManifestEntry{
			"same.json":  {Path: "same.json", Size: 6, SHA256: strings.Repeat("3", 64)},
			"only-b.txt": {Path: "only-b.txt", Size: 7, SHA256: strings.Repeat("4", 64)},
		}},
	}
	selected, used, err := buildConflictResolutionSelection(plan, sources, map[string]protocol.ConflictResolutionDecision{
		"same.json": {Path: "same.json", SourceNodeID: 9, Action: "preserve_both"},
	})
	if err != nil || used != 1 || len(selected) != 4 {
		t.Fatalf("selected=%+v used=%d err=%v", selected, used, err)
	}
	if len(selected) != 4 || selected[0].Entry.Path != "conflict-preserved/"+testConflictID+"/source-8/same.json" ||
		selected[0].NodeID != 8 || selected[1].Entry.Path != "only-a.txt" || selected[1].NodeID != 8 ||
		selected[2].Entry.Path != "only-b.txt" || selected[2].NodeID != 9 ||
		selected[3].Entry.Path != "same.json" || selected[3].NodeID != 9 {
		t.Fatalf("unexpected selection=%+v", selected)
	}
	if _, _, err := buildConflictResolutionSelection(plan, sources, map[string]protocol.ConflictResolutionDecision{
		"only-a.txt": {Path: "only-a.txt", SourceNodeID: 8, Action: "use_source"},
	}); err == nil {
		t.Fatal("decision for a non-conflicting path was accepted")
	}
}

func TestConflictResolutionDecisionPagesArePrivateAndImmutable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	agent, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 8, TavernDir: filepath.Join(root, "tavern"),
		DataDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	operationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	planRoot, err := agent.conflictResolutionPlanRoot(operationID)
	if err != nil {
		t.Fatal(err)
	}
	plan := conflictResolutionPlan{
		FormatVersion: 1, OperationID: operationID,
		ConflictID: testConflictID, ResultID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		GlobalUserID: 70, Handle: "alice", BaseNodeID: 8,
		DefaultAction: "use_base", DecisionPageCount: 1, DecisionCount: 1,
		Sources: []protocol.ConflictResolutionSource{
			{NodeID: 8, EvidenceID: testEvidenceID, EntriesSHA256: strings.Repeat("1", 64)},
			{NodeID: 9, EvidenceID: "ffffffff-ffff-4fff-8fff-ffffffffffff", EntriesSHA256: strings.Repeat("2", 64)},
		},
	}
	data, _ := json.Marshal(plan)
	if err := writePrivateFileAtomic(filepath.Join(planRoot, "plan.json"), data); err != nil {
		t.Fatal(err)
	}
	req := protocol.ApplyConflictResolutionDecisionsRequest{
		OperationID: operationID, PageIndex: 0,
		Decisions: []protocol.ConflictResolutionDecision{{Path: "chats/one.jsonl", SourceNodeID: 9, Action: "preserve_both"}},
	}
	if err := agent.applyConflictResolutionDecisions(req); err != nil {
		t.Fatal(err)
	}
	decisionPath := filepath.Join(planRoot, "decisions", "000000.json")
	info, err := os.Stat(decisionPath)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		t.Fatalf("decision page permissions=%v err=%v", info.Mode().Perm(), err)
	}
	req.Decisions[0].SourceNodeID = 8
	if err := agent.applyConflictResolutionDecisions(req); err == nil {
		t.Fatal("decision page was overwritten with different content")
	}
	decisions, err := readConflictResolutionDecisions(planRoot, plan)
	if err != nil || decisions["chats/one.jsonl"].SourceNodeID != 9 {
		t.Fatalf("decisions=%+v err=%v", decisions, err)
	}
	if _, err := agent.RunConflictEvidenceTransfer(context.Background(), protocol.StartConflictEvidenceTransferRequest{}); err == nil {
		t.Fatal("invalid conflict evidence transfer was accepted")
	}
}

func newTestConflictResolutionAgent(t *testing.T) *Agent {
	t.Helper()
	root := t.TempDir()
	agent, err := New(&config.AgentConfig{
		Role: "compute", NodeID: 8, TavernDir: filepath.Join(root, "tavern"),
		DataDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	agent.state.ControlMode.Mode = protocol.NodeModeManaged
	return agent
}

func TestConflictResolutionPublishAllowedWithoutActiveLease(t *testing.T) {
	t.Parallel()
	agent := newTestConflictResolutionAgent(t)
	if err := agent.conflictResolutionPublishAllowedLocked("alice", time.Now().UTC()); err != nil {
		t.Fatalf("no-lease publish refused: %v", err)
	}
	// An expired lease must not block publication either.
	agent.state.ActivityLeases.Leases = []protocol.ActivityLeaseConfirmation{{
		Handle: "alice", SessionID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ActivityEpoch: 4, ControllerGeneration: 1,
		LeaseExpiresAt: time.Now().Add(-time.Minute).UnixMilli(),
	}}
	if err := agent.conflictResolutionPublishAllowedLocked("alice", time.Now().UTC()); err != nil {
		t.Fatalf("expired-lease publish refused: %v", err)
	}
}

func TestConflictResolutionPublishBlockedByActiveWriterLease(t *testing.T) {
	t.Parallel()
	agent := newTestConflictResolutionAgent(t)
	agent.state.ActivityLeases.Leases = []protocol.ActivityLeaseConfirmation{{
		Handle: "alice", SessionID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ActivityEpoch: 4, ControllerGeneration: 1,
		LeaseExpiresAt: time.Now().Add(time.Minute).UnixMilli(),
	}}
	if err := agent.conflictResolutionPublishAllowedLocked("alice", time.Now().UTC()); err == nil {
		t.Fatal("publish with a live writer lease was accepted")
	}
	// A lease for a different handle is irrelevant and must not block.
	agent.state.ActivityLeases.Leases[0].Handle = "bob"
	if err := agent.conflictResolutionPublishAllowedLocked("alice", time.Now().UTC()); err != nil {
		t.Fatalf("unrelated lease blocked publish: %v", err)
	}
}

func TestConflictResolutionPublishAllowsOnlyMatchingLocalSessionEpoch(t *testing.T) {
	t.Parallel()
	agent := newTestConflictResolutionAgent(t)
	agent.state.ActivityOwnership = map[string]activityOwnershipClaim{
		"alice": {Handle: "alice", OwnerNodeID: 8, ActivityEpoch: 4},
	}
	agent.state.ActivityLeases.Leases = []protocol.ActivityLeaseConfirmation{{
		Handle: "alice", SessionID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ActivityEpoch: 4, ControllerGeneration: 1,
		LeaseExpiresAt: time.Now().Add(time.Minute).UnixMilli(),
	}}
	if err := agent.conflictResolutionPublishAllowedLocked("alice", time.Now().UTC()); err != nil {
		t.Fatalf("publish matching the current local session epoch refused: %v", err)
	}
	// A newer session epoch means new writes since resolution capture: refuse.
	agent.state.ActivityLeases.Leases[0].ActivityEpoch = 5
	if err := agent.conflictResolutionPublishAllowedLocked("alice", time.Now().UTC()); err == nil {
		t.Fatal("publish over a newer writer session epoch was accepted")
	}
}
