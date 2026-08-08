package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func TestControllerConflictEvidenceAndResolutionThroughDurableCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller conflict PostgreSQL integration is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated Controller conflict store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	secretKey := []byte("0123456789abcdef0123456789abcdef")
	generation, err := st.GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatalf("read conflict Controller generation: %v", err)
	}
	base := createControllerBackupNode(t, ctx, st, "conflict-base", "compute", false, generation)
	source := createControllerBackupNode(t, ctx, st, "conflict-source", "compute", false, generation)
	psks := map[int64]string{
		base.ID:   "controller-conflict-base-agent-psk",
		source.ID: "controller-conflict-source-agent-psk",
	}
	for nodeID, psk := range psks {
		seedControllerBackupCredential(t, ctx, st, secretKey, nodeID, generation, psk)
	}
	user := createControllerBackupUser(t, ctx, st, base.ID, "conflict-user")
	seedControllerReplicaConflict(t, ctx, st, user, base.ID, source.ID, generation)

	entries := map[int64][]protocol.ManifestEntry{
		base.ID:   controllerConflictEntries(base.ID),
		source.ID: controllerConflictEntries(source.ID),
	}
	harness := newControllerConflictCommandHarness(ctx, st, base.ID, source.ID, psks, entries)
	t.Cleanup(harness.stop)
	cfg := config.DefaultController()
	cfg.Backup.RetryMax = 5
	server := New(cfg, st, secretKey)

	if _, err := st.ReconcileProtectionStates(ctx, time.Now().UTC(), time.Minute); err != nil {
		t.Fatalf("detect and freeze replica conflict: %v", err)
	}
	conflict, err := st.GetOpenReplicaConflict(ctx, user.GlobalID)
	if err != nil || conflict == nil || conflict.State != "detected" || len(conflict.Sources) != 2 {
		t.Fatalf("initial durable conflict=%+v err=%v", conflict, err)
	}
	var frozenGlobal, frozenLegacy, leaseState string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT global_user.status,legacy.status,lease.state
		FROM global_users global_user
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		JOIN user_activity_leases lease ON lease.user_id=global_user.id
		WHERE global_user.id=$1`, user.GlobalID).Scan(&frozenGlobal, &frozenLegacy, &leaseState); err != nil {
		t.Fatalf("query frozen conflict identity: %v", err)
	}
	if frozenGlobal != "conflict" || frozenLegacy != "conflict" || leaseState != "conflict" {
		t.Fatalf("conflict did not freeze identity: global=%s legacy=%s lease=%s", frozenGlobal, frozenLegacy, leaseState)
	}

	tasks, err := st.ListConflictEvidenceTasks(ctx, 20, time.Now().UTC())
	if err != nil || len(tasks) != 2 {
		t.Fatalf("list conflict evidence tasks: count=%d err=%v", len(tasks), err)
	}
	for _, task := range tasks {
		if err := server.executeConflictEvidenceTask(ctx, task); err != nil {
			t.Fatalf("capture node %d conflict evidence: %v", task.NodeID, err)
		}
	}
	conflict, err = st.GetOpenReplicaConflict(ctx, user.GlobalID)
	if err != nil || conflict == nil || conflict.State != "awaiting_decision" {
		t.Fatalf("verified conflict evidence=%+v err=%v", conflict, err)
	}
	for _, conflictSource := range conflict.Sources {
		if conflictSource.EvidenceState != "ready" || conflictSource.EvidenceFileCount.Int64 != 101 {
			t.Fatalf("source evidence not ready: %+v", conflictSource)
		}
		pages, err := st.LoadConflictEvidencePages(ctx, conflict.ID, conflictSource.NodeID)
		if err != nil || len(pages) != 2 {
			t.Fatalf("load encrypted evidence pages for node %d: count=%d err=%v", conflictSource.NodeID, len(pages), err)
		}
		for _, encrypted := range pages {
			if strings.Contains(encrypted, "chats/shared-") {
				t.Fatal("conflict path leaked into at-rest encrypted page")
			}
		}
		loaded, err := server.loadConflictEvidenceEntries(ctx, conflict.ID, conflictSource)
		if err != nil || len(loaded) != 101 {
			t.Fatalf("decrypt stored conflict evidence for node %d: count=%d err=%v", conflictSource.NodeID, len(loaded), err)
		}
	}
	var redactedPages, leakedPages int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE result_summary='{"ok":true,"code":"evidence_ingested"}'::jsonb),
		       count(*) FILTER (WHERE result_summary::text LIKE '%chats/shared-%')
		FROM agent_commands WHERE command_type='read_conflict_evidence_page'`).Scan(&redactedPages, &leakedPages); err != nil {
		t.Fatalf("query redacted evidence command results: %v", err)
	}
	if redactedPages != 4 || leakedPages != 0 {
		t.Fatalf("evidence command redaction: redacted=%d leaked=%d", redactedPages, leakedPages)
	}

	operationID, err := newUUID()
	if err != nil {
		t.Fatalf("create conflict resolution operation: %v", err)
	}
	request := startConflictResolutionRequest{
		OperationID: operationID, ExpectedConflictVersion: conflict.Version,
		BaseNodeID: base.ID, DefaultAction: "preserve_all_originals", AcknowledgeFreeze: true,
		Decisions: make([]conflictResolutionDecisionRequest, 0, 101),
	}
	for _, entry := range entries[source.ID] {
		request.Decisions = append(request.Decisions, conflictResolutionDecisionRequest{
			Path: entry.Path, SourceNodeID: source.ID, Action: "preserve_both",
		})
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal conflict resolution request: %v", err)
	}
	for range cap(server.snapshotSlots) {
		server.snapshotSlots <- struct{}{}
	}
	httpRequest := httptest.NewRequest(http.MethodPost, "/api/conflicts/resolve", bytes.NewReader(body))
	httpRequest = httpRequest.WithContext(context.WithValue(
		httpRequest.Context(), ctxKey("stcontrol-session"),
		&session{UserID: user.ID, GlobalUserID: user.GlobalID, Username: user.Username},
	))
	recorder := httptest.NewRecorder()
	server.handleStartConflictResolution(recorder, httpRequest)
	for range cap(server.snapshotSlots) {
		<-server.snapshotSlots
	}
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("start confirmed conflict resolution: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	execution, err := st.GetConflictResolutionExecutionByOperation(ctx, operationID)
	if err != nil || execution == nil || execution.State != "scheduled" || len(execution.Decisions) != 101 {
		t.Fatalf("durable conflict resolution=%+v err=%v", execution, err)
	}
	restarted := New(cfg, st, secretKey)
	if restarted.workflowWorkerID == server.workflowWorkerID {
		t.Fatal("conflict resolution restart reused worker identity")
	}
	if err := restarted.executeConflictResolution(ctx, execution.WorkflowID); err != nil {
		t.Fatalf("execute durable conflict resolution: %v", err)
	}
	assertControllerConflictResolved(t, ctx, st, user, base.ID, source.ID, operationID, execution)
	if errs := harness.errors(); len(errs) > 0 {
		t.Fatalf("durable conflict Agent command harness errors: %v", errs)
	}
}

func seedControllerReplicaConflict(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	user *store.User,
	baseNodeID, sourceNodeID, generation int64,
) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO node_accounts (user_id,node_id,local_handle,status,updated_at)
		VALUES ($1,$2,$3,'active',$4)`, user.GlobalID, sourceNodeID, user.Username, now); err != nil {
		t.Fatalf("create conflict source node account: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,data_version,state,last_sync_at,checksum,size_bytes)
		VALUES ($1,$2,'home',7,'conflict',$4,'base-conflict',4096),
		       ($1,$3,'hot_standby',8,'conflict',$4,'source-conflict',4096)`,
		user.ID, baseNodeID, sourceNodeID, now); err != nil {
		t.Fatalf("seed conflicting replicas: %v", err)
	}
	if _, err := st.AcquireActivityLease(ctx, store.AcquireActivityLeaseParams{
		OperationID: "a1000000-0000-4000-8000-000000000001",
		UserID:      user.GlobalID, WriterNodeID: baseNodeID,
		SessionID:            "a1000000-0000-4000-8000-000000000002",
		ControllerGeneration: generation, TTL: 15 * time.Minute, Now: now,
	}); err != nil {
		t.Fatalf("seed writer lease before conflict: %v", err)
	}
}

func controllerConflictEntries(nodeID int64) []protocol.ManifestEntry {
	entries := make([]protocol.ManifestEntry, 0, 101)
	for index := 0; index < 101; index++ {
		path := fmt.Sprintf("chats/shared-%03d.jsonl", index)
		digest := sha256.Sum256([]byte(fmt.Sprintf("node:%d:path:%s", nodeID, path)))
		entries = append(entries, protocol.ManifestEntry{
			Path: path, Size: int64(index + 1), SHA256: hex.EncodeToString(digest[:]),
		})
	}
	return entries
}

type controllerConflictCommandHarness struct {
	store        *store.Store
	baseNodeID   int64
	sourceNodeID int64
	psks         map[int64]string
	entries      map[int64][]protocol.ManifestEntry

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu                 sync.Mutex
	evidenceEntries    map[string][]protocol.ManifestEntry
	transferReceipts   map[string]*protocol.SnapshotTransferReceipt
	preparedResolution map[string]protocol.PrepareConflictResolutionRequest
	decisionPages      map[string]map[int]int
	errs               []error
}

func newControllerConflictCommandHarness(
	parent context.Context,
	st *store.Store,
	baseNodeID, sourceNodeID int64,
	psks map[int64]string,
	entries map[int64][]protocol.ManifestEntry,
) *controllerConflictCommandHarness {
	ctx, cancel := context.WithCancel(parent)
	harness := &controllerConflictCommandHarness{
		store: st, baseNodeID: baseNodeID, sourceNodeID: sourceNodeID,
		psks: psks, entries: entries, ctx: ctx, cancel: cancel,
		evidenceEntries:    make(map[string][]protocol.ManifestEntry),
		transferReceipts:   make(map[string]*protocol.SnapshotTransferReceipt),
		preparedResolution: make(map[string]protocol.PrepareConflictResolutionRequest),
		decisionPages:      make(map[string]map[int]int),
	}
	for _, nodeID := range []int64{baseNodeID, sourceNodeID} {
		harness.wg.Add(1)
		go harness.runWorker(nodeID)
	}
	return harness
}

func (h *controllerConflictCommandHarness) stop() {
	h.cancel()
	h.wg.Wait()
}

func (h *controllerConflictCommandHarness) recordError(err error) {
	if err == nil {
		return
	}
	h.mu.Lock()
	h.errs = append(h.errs, err)
	h.mu.Unlock()
}

func (h *controllerConflictCommandHarness) errors() []error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]error(nil), h.errs...)
}

func (h *controllerConflictCommandHarness) runWorker(nodeID int64) {
	defer h.wg.Done()
	workerID := fmt.Sprintf("conflict-agent-worker-%d", nodeID)
	for {
		select {
		case <-h.ctx.Done():
			return
		default:
		}
		lease, err := h.store.LeaseAgentCommand(h.ctx, nodeID, workerID, time.Now().UTC(), time.Minute)
		if err != nil {
			if h.ctx.Err() == nil {
				h.recordError(fmt.Errorf("lease conflict command on node %d: %w", nodeID, err))
			}
			return
		}
		if lease == nil {
			select {
			case <-h.ctx.Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		ok, err := h.store.AckAgentCommand(
			h.ctx, lease.ID, nodeID, workerID, lease.ControllerGeneration,
			time.Now().UTC(), time.Minute,
		)
		if err != nil || !ok {
			h.recordError(fmt.Errorf("ack conflict command %s: ok=%v err=%w", lease.ID, ok, err))
			continue
		}
		plaintext, handleErr := decryptControllerBackupCommand(lease, h.psks[nodeID])
		summary := agentCommandSummary{}
		succeeded := false
		if handleErr == nil {
			summary, succeeded, handleErr = h.handleCommand(nodeID, lease.CommandType, plaintext)
		}
		if handleErr != nil {
			h.recordError(handleErr)
			summary = agentCommandSummary{OK: false, Code: "test_agent_error"}
		}
		result, err := json.Marshal(summary)
		if err != nil {
			h.recordError(fmt.Errorf("marshal conflict command result: %w", err))
			continue
		}
		digest := sha256.Sum256(result)
		ok, err = h.store.FinishAgentCommand(h.ctx, store.FinishAgentCommandParams{
			ID: lease.ID, NodeID: nodeID, WorkerID: workerID,
			ControllerGeneration: lease.ControllerGeneration, Succeeded: succeeded,
			ResultSummary: result, ResultDigest: digest[:], Now: time.Now().UTC(),
		})
		if err != nil || !ok {
			h.recordError(fmt.Errorf("finish conflict command %s: ok=%v err=%w", lease.ID, ok, err))
		}
	}
}

func (h *controllerConflictCommandHarness) handleCommand(
	nodeID int64,
	commandType string,
	plaintext []byte,
) (agentCommandSummary, bool, error) {
	switch commandType {
	case "capture_conflict_evidence":
		var request protocol.CaptureConflictEvidenceRequest
		if err := json.Unmarshal(plaintext, &request); err != nil || request.EvidenceID == "" || request.Handle != "conflict-user" {
			return agentCommandSummary{}, false, fmt.Errorf("decode conflict evidence capture: %w", err)
		}
		entries := append([]protocol.ManifestEntry(nil), h.entries[nodeID]...)
		encoded, err := json.Marshal(entries)
		if err != nil {
			return agentCommandSummary{}, false, err
		}
		digest := sha256.Sum256(encoded)
		var total int64
		for _, entry := range entries {
			total += entry.Size
		}
		h.mu.Lock()
		h.evidenceEntries[request.EvidenceID] = entries
		h.mu.Unlock()
		return agentCommandSummary{OK: true, ConflictEvidence: &protocol.ConflictEvidenceReceipt{
			EvidenceID: request.EvidenceID, EntriesSHA256: hex.EncodeToString(digest[:]),
			FileCount: int64(len(entries)), TotalBytes: total, CaptureBasis: "frozen_live",
		}}, true, nil

	case "read_conflict_evidence_page":
		var request protocol.ReadConflictEvidencePageRequest
		if err := json.Unmarshal(plaintext, &request); err != nil || request.MaxBytes != conflictEvidencePageBytes {
			return agentCommandSummary{}, false, fmt.Errorf("decode conflict evidence page request: %w", err)
		}
		responseKey, err := base64.StdEncoding.DecodeString(request.ResponseKey)
		if err != nil || len(responseKey) != sha256.Size {
			return agentCommandSummary{}, false, fmt.Errorf("decode conflict evidence response key: %w", err)
		}
		h.mu.Lock()
		entries := append([]protocol.ManifestEntry(nil), h.evidenceEntries[request.EvidenceID]...)
		h.mu.Unlock()
		if request.Cursor < 0 || request.Cursor > len(entries) {
			return agentCommandSummary{}, false, fmt.Errorf("invalid evidence cursor %d", request.Cursor)
		}
		end := min(request.Cursor+60, len(entries))
		page := protocol.ConflictEvidencePage{
			EvidenceID: request.EvidenceID, Cursor: request.Cursor, NextCursor: end,
			Complete: end == len(entries), Entries: entries[request.Cursor:end],
		}
		encoded, err := json.Marshal(page)
		if err != nil {
			return agentCommandSummary{}, false, err
		}
		ciphertext, err := controlcrypto.Encrypt(responseKey, encoded)
		if err != nil {
			return agentCommandSummary{}, false, err
		}
		return agentCommandSummary{OK: true, Ciphertext: ciphertext}, true, nil

	case "prepare_snapshot_receive":
		if nodeID != h.baseNodeID {
			return agentCommandSummary{}, false, fmt.Errorf("conflict input prepared on non-base node")
		}
		var request protocol.PrepareSnapshotReceiveRequest
		if err := json.Unmarshal(plaintext, &request); err != nil || request.DestinationKind != "conflict_input" {
			return agentCommandSummary{}, false, fmt.Errorf("decode conflict input prepare: %w", err)
		}
		return agentCommandSummary{OK: true}, true, nil

	case "start_conflict_evidence_transfer":
		if nodeID != h.sourceNodeID {
			return agentCommandSummary{}, false, fmt.Errorf("conflict evidence transferred by unexpected node")
		}
		var request protocol.StartConflictEvidenceTransferRequest
		if err := json.Unmarshal(plaintext, &request); err != nil || request.TargetNodeID != h.baseNodeID {
			return agentCommandSummary{}, false, fmt.Errorf("decode conflict evidence transfer: %w", err)
		}
		receipt := controllerBackupSnapshotReceipt(request.EvidenceID, false)
		h.mu.Lock()
		h.transferReceipts[request.EvidenceID] = receipt
		h.mu.Unlock()
		return agentCommandSummary{OK: false, Code: "response_lost"}, false, nil

	case "get_snapshot_receipt":
		if nodeID != h.baseNodeID {
			return agentCommandSummary{}, false, fmt.Errorf("conflict receipt requested from non-base node")
		}
		var request struct {
			SnapshotID string `json:"snapshot_id"`
		}
		if err := json.Unmarshal(plaintext, &request); err != nil {
			return agentCommandSummary{}, false, err
		}
		h.mu.Lock()
		receipt := h.transferReceipts[request.SnapshotID]
		h.mu.Unlock()
		if receipt == nil {
			return agentCommandSummary{OK: false, Code: "receipt_missing"}, false, nil
		}
		return agentCommandSummary{OK: true, Snapshot: receipt}, true, nil

	case "prepare_conflict_resolution":
		if nodeID != h.baseNodeID {
			return agentCommandSummary{}, false, fmt.Errorf("resolution prepared on non-base node")
		}
		var request protocol.PrepareConflictResolutionRequest
		if err := json.Unmarshal(plaintext, &request); err != nil || len(request.Sources) != 2 ||
			request.DecisionCount != 101 || request.DecisionPageCount != 2 {
			return agentCommandSummary{}, false, fmt.Errorf("decode conflict resolution prepare: %w", err)
		}
		h.mu.Lock()
		h.preparedResolution[request.OperationID] = request
		h.decisionPages[request.OperationID] = make(map[int]int)
		h.mu.Unlock()
		return agentCommandSummary{OK: true}, true, nil

	case "apply_conflict_resolution_decisions":
		var request protocol.ApplyConflictResolutionDecisionsRequest
		if err := json.Unmarshal(plaintext, &request); err != nil || request.PageIndex < 0 || request.PageIndex > 1 {
			return agentCommandSummary{}, false, fmt.Errorf("decode conflict decision page: %w", err)
		}
		want := 100
		if request.PageIndex == 1 {
			want = 1
		}
		if len(request.Decisions) != want {
			return agentCommandSummary{}, false, fmt.Errorf("decision page %d count=%d want=%d", request.PageIndex, len(request.Decisions), want)
		}
		h.mu.Lock()
		pages := h.decisionPages[request.OperationID]
		if pages != nil {
			pages[request.PageIndex] = len(request.Decisions)
		}
		h.mu.Unlock()
		if pages == nil {
			return agentCommandSummary{}, false, fmt.Errorf("decision page arrived before prepare")
		}
		return agentCommandSummary{OK: true}, true, nil

	case "publish_conflict_resolution":
		var request protocol.PublishConflictResolutionRequest
		if err := json.Unmarshal(plaintext, &request); err != nil {
			return agentCommandSummary{}, false, err
		}
		h.mu.Lock()
		prepared, ok := h.preparedResolution[request.OperationID]
		pages := h.decisionPages[request.OperationID]
		h.mu.Unlock()
		if !ok || len(pages) != 2 {
			return agentCommandSummary{}, false, fmt.Errorf("resolution published before all decision pages")
		}
		digest := sha256.Sum256([]byte("resolved:" + request.OperationID))
		return agentCommandSummary{OK: true, ConflictResolution: &protocol.ConflictResolutionReceipt{
			OperationID: request.OperationID, ConflictID: prepared.ConflictID,
			ResultID: prepared.ResultID, EntriesSHA256: hex.EncodeToString(digest[:]),
			FileCount: 202, TotalBytes: 8192, PreservedSources: len(prepared.Sources),
		}}, true, nil
	default:
		return agentCommandSummary{}, false, fmt.Errorf("unexpected conflict Agent command %q", commandType)
	}
}

func assertControllerConflictResolved(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	user *store.User,
	baseNodeID, sourceNodeID int64,
	operationID string,
	execution *store.ConflictResolutionExecution,
) {
	t.Helper()
	status, err := st.GetConflictResolutionStatus(ctx, user.GlobalID, operationID)
	if err != nil || status == nil || status.State != "succeeded" {
		t.Fatalf("conflict resolution status=%+v err=%v", status, err)
	}
	var conflictState, workflowState, globalStatus, legacyStatus, leaseState string
	var baseKind, baseState, sourceState, manifestState, protectionState, reasonCode string
	var authoritativeCopies, audits int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT conflict.state,workflow.state,global_user.status,legacy.status,lease.state,
		       base.kind,base.state,source.state,manifest.state,protection.state,protection.reason_code,
		       (SELECT count(*) FROM replica_copies copy WHERE copy.user_id=global_user.id
		          AND copy.node_id=$3 AND copy.snapshot_id=operation.result_snapshot_id
		          AND copy.state='ready' AND copy.is_authoritative),
		       (SELECT count(*) FROM audit_events audit WHERE audit.operation_id=$4
		          AND audit.action='resolve-replica-conflict' AND audit.outcome='succeeded')
		FROM conflict_resolution_operations operation
		JOIN workflows workflow ON workflow.id=operation.workflow_id
		JOIN replica_conflicts conflict ON conflict.id=operation.conflict_id
		JOIN global_users global_user ON global_user.id=operation.user_id
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		JOIN user_activity_leases lease ON lease.user_id=global_user.id
		JOIN user_replicas base ON base.user_id=legacy.id AND base.node_id=$3
		JOIN user_replicas source ON source.user_id=legacy.id AND source.node_id=$5
		JOIN snapshot_manifests manifest ON manifest.id=operation.result_snapshot_id
		JOIN user_protection_states protection ON protection.user_id=global_user.id
		WHERE operation.workflow_id=$1 AND operation.operation_id=$2`,
		execution.WorkflowID, operationID, baseNodeID, operationID, sourceNodeID).Scan(
		&conflictState, &workflowState, &globalStatus, &legacyStatus, &leaseState,
		&baseKind, &baseState, &sourceState, &manifestState, &protectionState, &reasonCode,
		&authoritativeCopies, &audits,
	); err != nil {
		t.Fatalf("query resolved conflict facts: %v", err)
	}
	if conflictState != "resolved" || workflowState != "succeeded" ||
		globalStatus != "active" || legacyStatus != "active" || leaseState != "ended" ||
		baseKind != "home" || baseState != "ready" || sourceState != "stale" ||
		manifestState != "immutable" || protectionState != "unprotected" || reasonCode != "no_recovery_replica" ||
		authoritativeCopies != 1 || audits != 1 {
		t.Fatalf("resolved conflict facts: conflict=%s workflow=%s identity=%s/%s lease=%s base=%s/%s source=%s manifest=%s protection=%s/%s authoritative=%d audits=%d",
			conflictState, workflowState, globalStatus, legacyStatus, leaseState, baseKind, baseState,
			sourceState, manifestState, protectionState, reasonCode, authoritativeCopies, audits)
	}
	var recoveredTransfers, decisionCommands int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE command_type='get_snapshot_receipt' AND state='succeeded'),
		       count(*) FILTER (WHERE command_type='apply_conflict_resolution_decisions' AND state='succeeded')
		FROM agent_commands`).Scan(&recoveredTransfers, &decisionCommands); err != nil {
		t.Fatalf("query conflict command completion: %v", err)
	}
	if recoveredTransfers != 1 || decisionCommands != 2 {
		t.Fatalf("conflict durable command history: recovered=%d decision_pages=%d", recoveredTransfers, decisionCommands)
	}
}
