package controller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"
	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

const controllerBackupPostgresDSNEnv = "STCONTROL_TEST_POSTGRES_DSN"

// TestControllerSnapshotWorkflowThroughDurableAgentCommands exercises the
// Controller backup orchestration without bypassing the durable Agent command
// queue. The opt-in real PostgreSQL path covers normal completion, a lost
// source response after target publication, and a retry resumed by a new
// Controller worker.
func TestControllerSnapshotWorkflowThroughDurableAgentCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller backup PostgreSQL integration is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated Controller backup store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	secretKey := []byte("0123456789abcdef0123456789abcdef")
	generation, err := st.GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatalf("read active Controller generation: %v", err)
	}
	source := createControllerBackupNode(t, ctx, st, "snapshot-source", "compute", false, generation)
	target := createControllerBackupNode(t, ctx, st, "snapshot-target", "storage", true, generation)
	psks := map[int64]string{
		source.ID: "controller-backup-source-agent-psk",
		target.ID: "controller-backup-target-agent-psk",
	}
	for nodeID, psk := range psks {
		seedControllerBackupCredential(t, ctx, st, secretKey, nodeID, generation, psk)
	}

	harness := newControllerBackupCommandHarness(ctx, st, source.ID, target.ID, psks)
	t.Cleanup(harness.stop)
	cfg := config.DefaultController()
	cfg.Backup.RetryMax = 3
	server := New(cfg, st, secretKey)

	t.Run("normal publish is atomic and replay is idempotent", func(t *testing.T) {
		user := createControllerBackupUser(t, ctx, st, source.ID, "backup-normal")
		if err := server.TriggerUserBackup(ctx, user.ID, source.ID, "offline"); err != nil {
			t.Fatalf("trigger normal durable backup: %v", err)
		}
		workflowID := controllerBackupWorkflowID(t, ctx, st, user.GlobalID)
		assertControllerBackupPublished(t, ctx, st, workflowID, user.GlobalID, target.ID)

		before := controllerBackupCommandCount(t, ctx, st)
		if err := server.executeSnapshotWorkflow(ctx, workflowID); err != nil {
			t.Fatalf("replay completed snapshot workflow: %v", err)
		}
		after := controllerBackupCommandCount(t, ctx, st)
		if after != before {
			t.Fatalf("completed workflow replay enqueued commands: before=%d after=%d", before, after)
		}
	})

	t.Run("published receipt survives lost source response", func(t *testing.T) {
		user := createControllerBackupUser(t, ctx, st, source.ID, "backup-lost-receipt")
		if err := server.TriggerUserBackup(ctx, user.ID, source.ID, "offline"); err != nil {
			t.Fatalf("recover published snapshot receipt: %v", err)
		}
		workflowID := controllerBackupWorkflowID(t, ctx, st, user.GlobalID)
		assertControllerBackupPublished(t, ctx, st, workflowID, user.GlobalID, target.ID)
		execution, err := st.GetSnapshotWorkflowExecution(ctx, workflowID)
		if err != nil || execution == nil {
			t.Fatalf("load response-loss execution: execution=%+v err=%v", execution, err)
		}
		startOperationID := deriveWorkflowOperationID(
			workflowID, fmt.Sprintf("start-source:%s:%d", execution.CapabilityID, execution.Attempt),
		)
		receiptOperationID := deriveWorkflowOperationID(
			workflowID, fmt.Sprintf("target-receipt:%s:%d", execution.CapabilityID, execution.Attempt),
		)

		var failedSource, succeededReceipt int
		if err := st.DB.QueryRowContext(ctx, `
			SELECT count(*) FILTER (WHERE operation_id=$1 AND node_id=$3 AND command_type='start_snapshot' AND state='failed'),
			       count(*) FILTER (WHERE operation_id=$2 AND node_id=$4 AND command_type='get_snapshot_receipt' AND state='succeeded')
			FROM agent_commands`, startOperationID, receiptOperationID, source.ID, target.ID).
			Scan(&failedSource, &succeededReceipt); err != nil {
			t.Fatalf("query response-loss command history: %v", err)
		}
		if failedSource != 1 || succeededReceipt != 1 {
			t.Fatalf("response-loss recovery history: failed_source=%d succeeded_receipt=%d", failedSource, succeededReceipt)
		}
	})

	t.Run("new Controller worker resumes failed prepare", func(t *testing.T) {
		user := createControllerBackupUser(t, ctx, st, source.ID, "backup-retry")
		if err := server.TriggerUserBackup(ctx, user.ID, source.ID, "offline"); err == nil {
			t.Fatal("first target prepare unexpectedly succeeded")
		}
		workflowID := controllerBackupWorkflowID(t, ctx, st, user.GlobalID)
		execution, err := st.GetSnapshotWorkflowExecution(ctx, workflowID)
		if err != nil || execution == nil || execution.State != "retry_wait" || execution.Attempt != 1 {
			t.Fatalf("retry facts after failed target prepare: execution=%+v err=%v", execution, err)
		}
		if _, err := st.DB.ExecContext(ctx, `
			UPDATE workflows SET next_attempt_at=now()-interval '1 second' WHERE id=$1`, workflowID); err != nil {
			t.Fatalf("advance deterministic snapshot retry: %v", err)
		}

		restarted := New(cfg, st, secretKey)
		if restarted.workflowWorkerID == server.workflowWorkerID {
			t.Fatal("Controller restart reused snapshot worker identity")
		}
		if err := restarted.executeSnapshotWorkflow(ctx, workflowID); err != nil {
			t.Fatalf("resume snapshot through new Controller worker: %v", err)
		}
		assertControllerBackupPublished(t, ctx, st, workflowID, user.GlobalID, target.ID)
		execution, err = st.GetSnapshotWorkflowExecution(ctx, workflowID)
		if err != nil || execution == nil {
			t.Fatalf("load completed retry execution: execution=%+v err=%v", execution, err)
		}
		failedPrepareOperationID := deriveWorkflowOperationID(
			workflowID, fmt.Sprintf("prepare-target:%s:%d", execution.CapabilityID, 0),
		)
		succeededPrepareOperationID := deriveWorkflowOperationID(
			workflowID, fmt.Sprintf("prepare-target:%s:%d", execution.CapabilityID, 1),
		)

		var failedPrepare, succeededPrepare, replicas int
		if err := st.DB.QueryRowContext(ctx, `
			SELECT count(*) FILTER (WHERE operation_id=$1 AND command_type='prepare_snapshot_receive' AND state='failed'),
			       count(*) FILTER (WHERE operation_id=$2 AND command_type='prepare_snapshot_receive' AND state='succeeded')
			FROM agent_commands`, failedPrepareOperationID, succeededPrepareOperationID).
			Scan(&failedPrepare, &succeededPrepare); err != nil {
			t.Fatalf("query retry command history: %v", err)
		}
		if err := st.DB.QueryRowContext(ctx, `
			SELECT count(*) FROM replica_copies WHERE user_id=$1 AND node_id=$2 AND state='ready'`,
			user.GlobalID, target.ID).Scan(&replicas); err != nil {
			t.Fatalf("query retry replica result: %v", err)
		}
		if failedPrepare != 1 || succeededPrepare != 1 || replicas != 1 {
			t.Fatalf("retry convergence: failed_prepare=%d succeeded_prepare=%d replicas=%d", failedPrepare, succeededPrepare, replicas)
		}
	})

	if errs := harness.errors(); len(errs) > 0 {
		t.Fatalf("durable Agent command harness errors: %v", errs)
	}
}

type controllerBackupCommandHarness struct {
	store        *store.Store
	sourceNodeID int64
	targetNodeID int64
	psks         map[int64]string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu                 sync.Mutex
	receipts           map[string]*protocol.SnapshotTransferReceipt
	failedRetryPrepare bool
	errs               []error
}

func newControllerBackupCommandHarness(
	parent context.Context,
	st *store.Store,
	sourceNodeID, targetNodeID int64,
	psks map[int64]string,
) *controllerBackupCommandHarness {
	ctx, cancel := context.WithCancel(parent)
	harness := &controllerBackupCommandHarness{
		store: st, sourceNodeID: sourceNodeID, targetNodeID: targetNodeID,
		psks: psks, ctx: ctx, cancel: cancel,
		receipts: make(map[string]*protocol.SnapshotTransferReceipt),
	}
	for _, nodeID := range []int64{sourceNodeID, targetNodeID} {
		harness.wg.Add(1)
		go harness.runWorker(nodeID)
	}
	return harness
}

func (h *controllerBackupCommandHarness) stop() {
	h.cancel()
	h.wg.Wait()
}

func (h *controllerBackupCommandHarness) errors() []error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]error(nil), h.errs...)
}

func (h *controllerBackupCommandHarness) recordError(err error) {
	if err == nil {
		return
	}
	h.mu.Lock()
	h.errs = append(h.errs, err)
	h.mu.Unlock()
}

func (h *controllerBackupCommandHarness) runWorker(nodeID int64) {
	defer h.wg.Done()
	workerID := fmt.Sprintf("backup-agent-worker-%d", nodeID)
	for {
		select {
		case <-h.ctx.Done():
			return
		default:
		}
		lease, err := h.store.LeaseAgentCommand(h.ctx, nodeID, workerID, time.Now().UTC(), time.Minute)
		if err != nil {
			if h.ctx.Err() == nil {
				h.recordError(fmt.Errorf("lease node %d command: %w", nodeID, err))
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
			h.recordError(fmt.Errorf("ack node %d command %s: ok=%v err=%w", nodeID, lease.ID, ok, err))
			continue
		}
		summary, succeeded, handleErr := h.handleCommand(nodeID, lease)
		if handleErr != nil {
			h.recordError(handleErr)
			summary = agentCommandSummary{OK: false, Code: "test_agent_error"}
			succeeded = false
		}
		result, err := json.Marshal(summary)
		if err != nil {
			h.recordError(fmt.Errorf("marshal command %s result: %w", lease.ID, err))
			continue
		}
		digest := sha256.Sum256(result)
		ok, err = h.store.FinishAgentCommand(h.ctx, store.FinishAgentCommandParams{
			ID: lease.ID, NodeID: nodeID, WorkerID: workerID,
			ControllerGeneration: lease.ControllerGeneration, Succeeded: succeeded,
			ResultSummary: result, ResultDigest: digest[:], Now: time.Now().UTC(),
		})
		if err != nil || !ok {
			h.recordError(fmt.Errorf("finish node %d command %s: ok=%v err=%w", nodeID, lease.ID, ok, err))
		}
	}
}

func (h *controllerBackupCommandHarness) handleCommand(
	nodeID int64,
	lease *store.AgentCommandLease,
) (agentCommandSummary, bool, error) {
	plaintext, err := decryptControllerBackupCommand(lease, h.psks[nodeID])
	if err != nil {
		return agentCommandSummary{}, false, err
	}
	switch lease.CommandType {
	case "prepare_snapshot_receive":
		if nodeID != h.targetNodeID {
			return agentCommandSummary{}, false, fmt.Errorf("prepare command leased by non-target node %d", nodeID)
		}
		var request protocol.PrepareSnapshotReceiveRequest
		if err := json.Unmarshal(plaintext, &request); err != nil || request.WorkflowID == "" || request.SnapshotID == "" {
			return agentCommandSummary{}, false, fmt.Errorf("decode prepare snapshot command: %w", err)
		}
		h.mu.Lock()
		fail := request.Handle == "backup-retry" && !h.failedRetryPrepare
		if fail {
			h.failedRetryPrepare = true
		}
		h.mu.Unlock()
		if fail {
			return agentCommandSummary{OK: false, Code: "target_prepare_failed"}, false, nil
		}
		return agentCommandSummary{OK: true}, true, nil

	case "start_snapshot":
		if nodeID != h.sourceNodeID {
			return agentCommandSummary{}, false, fmt.Errorf("start command leased by non-source node %d", nodeID)
		}
		var request protocol.StartSnapshotRequest
		if err := json.Unmarshal(plaintext, &request); err != nil || request.WorkflowID == "" || request.SnapshotID == "" {
			return agentCommandSummary{}, false, fmt.Errorf("decode start snapshot command: %w", err)
		}
		progress := []struct {
			nodeID int64
			state  string
		}{
			{h.sourceNodeID, "drained"},
			{h.sourceNodeID, "snapshotting"},
			{h.sourceNodeID, "transferring"},
			{h.targetNodeID, "verifying"},
			{h.targetNodeID, "publishing"},
		}
		now := time.Now().UTC()
		for index, step := range progress {
			if err := h.store.SetSnapshotWorkflowProgress(
				h.ctx, request.WorkflowID, request.SnapshotID, step.nodeID,
				step.state, now.Add(time.Duration(index)*time.Millisecond),
			); err != nil {
				return agentCommandSummary{}, false, fmt.Errorf("persist %s progress: %w", step.state, err)
			}
		}
		manifestDigest := sha256.Sum256([]byte("manifest:" + request.SnapshotID))
		archiveDigest := sha256.Sum256([]byte("archive:" + request.SnapshotID))
		receipt := &protocol.SnapshotTransferReceipt{
			OK: true, SnapshotID: request.SnapshotID,
			ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
			ArchiveSHA256:  hex.EncodeToString(archiveDigest[:]),
			FileCount:      3, TotalBytes: 4096,
		}
		h.mu.Lock()
		h.receipts[request.WorkflowID] = receipt
		h.mu.Unlock()
		if request.Handle == "backup-lost-receipt" {
			return agentCommandSummary{OK: false, Code: "response_lost"}, false, nil
		}
		return agentCommandSummary{OK: true, Snapshot: receipt}, true, nil

	case "get_snapshot_receipt":
		if nodeID != h.targetNodeID {
			return agentCommandSummary{}, false, fmt.Errorf("receipt command leased by non-target node %d", nodeID)
		}
		var request struct {
			WorkflowID string `json:"workflow_id"`
			SnapshotID string `json:"snapshot_id"`
		}
		if err := json.Unmarshal(plaintext, &request); err != nil {
			return agentCommandSummary{}, false, fmt.Errorf("decode receipt command: %w", err)
		}
		h.mu.Lock()
		receipt := h.receipts[request.WorkflowID]
		h.mu.Unlock()
		if receipt == nil || receipt.SnapshotID != request.SnapshotID {
			return agentCommandSummary{OK: false, Code: "receipt_missing"}, false, nil
		}
		return agentCommandSummary{OK: true, Snapshot: receipt}, true, nil
	default:
		return agentCommandSummary{}, false, fmt.Errorf("unexpected durable Agent command %q", lease.CommandType)
	}
}

func decryptControllerBackupCommand(lease *store.AgentCommandLease, psk string) ([]byte, error) {
	if lease == nil || psk == "" {
		return nil, fmt.Errorf("command lease or Agent PSK missing")
	}
	var envelope encryptedCommandEnvelope
	if err := json.Unmarshal(lease.EncryptedPayload, &envelope); err != nil || envelope.Version != 2 || envelope.Ciphertext == "" {
		return nil, fmt.Errorf("decode encrypted command envelope: %w", err)
	}
	plaintext, err := controlcrypto.Decrypt(controlcrypto.DeriveAgentCommandKey(psk), envelope.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt Agent command: %w", err)
	}
	authenticator := hmac.New(sha256.New, controlcrypto.DeriveAgentCommandAuthKey(psk))
	_, _ = authenticator.Write(plaintext)
	if !hmac.Equal(authenticator.Sum(nil), lease.PayloadSHA256) {
		return nil, fmt.Errorf("Agent command HMAC mismatch")
	}
	return plaintext, nil
}

func createControllerBackupNode(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	name, role string,
	backupTarget bool,
	generation int64,
) *store.Node {
	t.Helper()
	node := &store.Node{
		Name: name, Role: role, BaseURL: "https://" + name + ".example/control",
		TransferURL: "https://" + name + ".example/data", Region: sql.NullString{String: "test", Valid: true},
		Status: "online", IsBackupTarget: backupTarget,
	}
	if err := st.CreateNode(ctx, node); err != nil {
		t.Fatalf("create %s node: %v", name, err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET status='online', connectivity_state='online', operational_state='active',
		  control_mode='managed', desired_control_mode='managed', capacity_state='open',
		  compatibility_state='compatible', controller_generation=$2, last_seen_at=now()
		WHERE id=$1`, node.ID, generation); err != nil {
		t.Fatalf("make %s node eligible: %v", name, err)
	}
	return node
}

func seedControllerBackupCredential(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	secretKey []byte,
	nodeID, generation int64,
	psk string,
) {
	t.Helper()
	ciphertext, err := controlcrypto.Encrypt(secretKey, []byte(psk))
	if err != nil {
		t.Fatalf("encrypt node %d Agent credential: %v", nodeID, err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO agent_credentials (
		  id,node_id,credential_version,credential_type,secret_ciphertext,
		  controller_generation,created_at
		) VALUES (gen_random_uuid(),$1,1,'hmac',$2,$3,now())`,
		nodeID, []byte(ciphertext), generation); err != nil {
		t.Fatalf("seed node %d Agent credential: %v", nodeID, err)
	}
}

func createControllerBackupUser(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	sourceNodeID int64,
	handle string,
) *store.User {
	t.Helper()
	user := &store.User{
		Username: handle, DisplayName: handle,
		PasswordHash: sql.NullString{String: "controller-backup-test-password-hash", Valid: true},
		AuthProvider: "password", HomeNodeID: sql.NullInt64{Int64: sourceNodeID, Valid: true},
		Status: "active",
	}
	if err := st.CreateUser(ctx, user); err != nil {
		t.Fatalf("create backup user %s: %v", handle, err)
	}
	return user
}

func controllerBackupWorkflowID(t *testing.T, ctx context.Context, st *store.Store, globalUserID int64) string {
	t.Helper()
	var workflowID string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT id FROM workflows
		WHERE user_id=$1 AND workflow_type='snapshot'
		ORDER BY created_at DESC LIMIT 1`, globalUserID).Scan(&workflowID); err != nil {
		t.Fatalf("query user %d snapshot workflow: %v", globalUserID, err)
	}
	return workflowID
}

func controllerBackupCommandCount(t *testing.T, ctx context.Context, st *store.Store) int {
	t.Helper()
	var count int
	if err := st.DB.QueryRowContext(ctx, `SELECT count(*) FROM agent_commands`).Scan(&count); err != nil {
		t.Fatalf("count Agent commands: %v", err)
	}
	return count
}

func assertControllerBackupPublished(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	workflowID string,
	globalUserID, targetNodeID int64,
) {
	t.Helper()
	execution, err := st.GetSnapshotWorkflowExecution(ctx, workflowID)
	if err != nil || execution == nil || execution.State != "succeeded" || execution.CapabilityState != "consumed" {
		t.Fatalf("completed snapshot execution=%+v err=%v", execution, err)
	}
	var jobStatus, replicaState, manifestState, capabilityState string
	var manifestBytes, archiveBytes, fileCount, totalBytes int64
	if err := st.DB.QueryRowContext(ctx, `
		SELECT job.status,copy.state,manifest.state,capability.state,
		       octet_length(manifest.manifest_sha256),octet_length(manifest.archive_sha256),
		       manifest.file_count,manifest.total_bytes
		FROM workflows workflow
		JOIN backup_jobs job ON job.workflow_id=workflow.id
		JOIN snapshot_manifests manifest ON manifest.workflow_id=workflow.id
		JOIN snapshot_transfer_capabilities capability ON capability.workflow_id=workflow.id
		JOIN replica_copies copy ON copy.user_id=workflow.user_id
		  AND copy.node_id=workflow.target_node_id AND copy.snapshot_id=manifest.id
		WHERE workflow.id=$1 AND workflow.user_id=$2 AND workflow.target_node_id=$3`,
		workflowID, globalUserID, targetNodeID).Scan(
		&jobStatus, &replicaState, &manifestState, &capabilityState,
		&manifestBytes, &archiveBytes, &fileCount, &totalBytes,
	); err != nil {
		t.Fatalf("query published snapshot facts: %v", err)
	}
	if jobStatus != "done" || replicaState != "ready" || manifestState != "immutable" || capabilityState != "consumed" ||
		manifestBytes != sha256.Size || archiveBytes != sha256.Size || fileCount != 3 || totalBytes != 4096 {
		t.Fatalf("published snapshot facts: job=%s replica=%s manifest=%s capability=%s digests=%d/%d files=%d bytes=%d",
			jobStatus, replicaState, manifestState, capabilityState, manifestBytes, archiveBytes, fileCount, totalBytes)
	}
}

func newControllerBackupPostgresSchema(t *testing.T) (string, func()) {
	t.Helper()
	baseDSN := strings.TrimSpace(os.Getenv(controllerBackupPostgresDSNEnv))
	if baseDSN == "" {
		t.Skipf("set %s to run real PostgreSQL Controller backup tests", controllerBackupPostgresDSNEnv)
	}
	parsed, err := url.Parse(baseDSN)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatalf("%s must be a PostgreSQL URL: %v", controllerBackupPostgresDSNEnv, err)
	}
	adminDB, err := sql.Open("postgres", baseDSN)
	if err != nil {
		t.Fatalf("open PostgreSQL Controller backup database: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := adminDB.PingContext(ctx); err != nil {
		_ = adminDB.Close()
		t.Fatalf("ping PostgreSQL Controller backup database: %v", err)
	}
	schema := fmt.Sprintf("stcontrol_controller_backup_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := adminDB.ExecContext(ctx, `CREATE SCHEMA `+pq.QuoteIdentifier(schema)); err != nil {
		_ = adminDB.Close()
		t.Fatalf("create PostgreSQL Controller backup schema: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	query.Set("application_name", "stcontrol-controller-backup")
	parsed.RawQuery = query.Encode()
	return parsed.String(), func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := adminDB.ExecContext(cleanupCtx, `DROP SCHEMA `+pq.QuoteIdentifier(schema)+` CASCADE`); err != nil {
			t.Errorf("drop PostgreSQL Controller backup schema: %v", err)
		}
		_ = adminDB.Close()
	}
}
