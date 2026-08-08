package controller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

// TestControllerArchiveRestoreThroughDurableAgentCommands proves the R07/R19
// recovery path against real PostgreSQL. It starts from a genuinely published
// immutable archive, provisions the missing target account through the fixed
// Agent command whitelist, and simulates the storage Agent losing its response
// only after the target has atomically published the restored snapshot. A new
// Controller worker must recover solely from durable state and the target
// receipt without replaying a second restore.
func TestControllerArchiveRestoreThroughDurableAgentCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller restore PostgreSQL integration is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated Controller restore store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	secretKey := []byte("0123456789abcdef0123456789abcdef")
	generation, err := st.GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatalf("read restore Controller generation: %v", err)
	}
	home := createControllerBackupNode(t, ctx, st, "restore-old-home", "compute", false, generation)
	archive := createControllerBackupNode(t, ctx, st, "restore-archive", "storage", true, generation)
	target := createControllerBackupNode(t, ctx, st, "restore-new-home", "compute", false, generation)
	psks := map[int64]string{
		home.ID:    "controller-restore-home-agent-psk",
		archive.ID: "controller-restore-archive-agent-psk",
		target.ID:  "controller-restore-target-agent-psk",
	}
	for nodeID, psk := range psks {
		seedControllerBackupCredential(t, ctx, st, secretKey, nodeID, generation, psk)
	}

	cfg := config.DefaultController()
	cfg.Backup.RetryMax = 3
	server := New(cfg, st, secretKey)
	user := createControllerBackupUser(t, ctx, st, home.ID, "restore-user")

	// Produce the recovery point through the complete durable snapshot path
	// rather than fabricating a manifest or a ready archive row.
	backupHarness := newControllerBackupCommandHarness(ctx, st, home.ID, archive.ID, psks)
	if err := server.TriggerUserBackup(ctx, user.ID, home.ID, "offline"); err != nil {
		backupHarness.stop()
		t.Fatalf("publish archive used for restore: %v", err)
	}
	backupWorkflowID := controllerBackupWorkflowID(t, ctx, st, user.GlobalID)
	assertControllerBackupPublished(t, ctx, st, backupWorkflowID, user.GlobalID, archive.ID)
	backupHarness.stop()
	if errs := backupHarness.errors(); len(errs) > 0 {
		t.Fatalf("archive creation Agent command harness errors: %v", errs)
	}

	var sourceSnapshotID string
	var recoveryAt time.Time
	if err := st.DB.QueryRowContext(ctx, `
		SELECT copy.snapshot_id::text,copy.published_at
		FROM replica_copies copy
		JOIN snapshot_manifests manifest ON manifest.id=copy.snapshot_id
		WHERE copy.user_id=$1 AND copy.node_id=$2 AND copy.replica_kind='archive'
		  AND copy.state='ready' AND manifest.state='immutable'`,
		user.GlobalID, archive.ID).Scan(&sourceSnapshotID, &recoveryAt); err != nil {
		t.Fatalf("load published archive recovery point: %v", err)
	}
	seedControllerArchiveRestoreFacts(t, ctx, st, user, home.ID, archive.ID, sourceSnapshotID, recoveryAt)

	// Keep the HTTP handler from launching its in-process goroutine so that the
	// durable job is deliberately picked up by a distinct Controller identity.
	for range cap(server.snapshotSlots) {
		server.snapshotSlots <- struct{}{}
	}
	operationID, err := newUUID()
	if err != nil {
		t.Fatalf("generate restore operation ID: %v", err)
	}
	body, err := json.Marshal(startArchiveRestoreRequest{
		OperationID: operationID, TargetNodeID: target.ID,
		ExpectedRecoveryAt:  recoveryAt.UTC().Format(time.RFC3339Nano),
		AcknowledgeDataLoss: true,
	})
	if err != nil {
		t.Fatalf("marshal confirmed restore request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/users/me/restore", bytes.NewReader(body))
	requestContext := context.WithValue(request.Context(), ctxUser, user.ID)
	request = request.WithContext(context.WithValue(
		requestContext, ctxKey("stcontrol-session"),
		&session{UserID: user.ID, GlobalUserID: user.GlobalID, Username: user.Username},
	))
	recorder := httptest.NewRecorder()
	server.handleStartArchiveRestore(recorder, request)
	for range cap(server.snapshotSlots) {
		<-server.snapshotSlots
	}
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("start confirmed archive restore: status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	var workflowID string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT workflow_id::text FROM restore_operations WHERE operation_id=$1`, operationID).
		Scan(&workflowID); err != nil {
		t.Fatalf("load durable restore workflow: %v", err)
	}
	execution, err := st.GetRestoreWorkflowExecution(ctx, workflowID)
	if err != nil || execution == nil || execution.State != "scheduled" ||
		execution.SourceSnapshotID != sourceSnapshotID || execution.TargetAccountStatus != "pending" {
		t.Fatalf("scheduled restore execution=%+v err=%v", execution, err)
	}

	restoreHarness := newControllerBackupCommandHarness(ctx, st, archive.ID, target.ID, psks)
	t.Cleanup(restoreHarness.stop)
	restarted := New(cfg, st, secretKey)
	if restarted.workflowWorkerID == server.workflowWorkerID {
		t.Fatal("Controller restart reused restore worker identity")
	}
	if err := restarted.executeRestoreWorkflow(ctx, workflowID); err != nil {
		t.Fatalf("resume archive restore through new Controller worker: %v", err)
	}
	assertControllerArchiveRestoreCompleted(
		t, ctx, st, user, home.ID, archive.ID, target.ID,
		operationID, workflowID, sourceSnapshotID,
	)

	before := controllerBackupCommandCount(t, ctx, st)
	if err := server.executeRestoreWorkflow(ctx, workflowID); err != nil {
		t.Fatalf("replay completed restore workflow: %v", err)
	}
	if after := controllerBackupCommandCount(t, ctx, st); after != before {
		t.Fatalf("completed restore replay enqueued commands: before=%d after=%d", before, after)
	}
	if errs := restoreHarness.errors(); len(errs) > 0 {
		t.Fatalf("restore Agent command harness errors: %v", errs)
	}
}

func seedControllerArchiveRestoreFacts(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	user *store.User,
	homeNodeID, archiveNodeID int64,
	sourceSnapshotID string,
	recoveryAt time.Time,
) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (
		  user_id,node_id,kind,data_version,state,last_sync_at,checksum,size_bytes
		) VALUES ($1,$2,'home',9,'corrupt',$3,'corrupt-old-home',4096)
		ON CONFLICT (user_id,node_id) DO UPDATE SET kind='home',data_version=9,
		  state='corrupt',last_sync_at=$3,checksum='corrupt-old-home',size_bytes=4096`,
		user.ID, homeNodeID, now); err != nil {
		t.Fatalf("seed corrupt legacy home replica: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE node_accounts SET local_user_id='old-home-local',status='active',
		  account_version=1,password_material_version=1,
		  password_hash='restore-password-hash',password_salt='restore-password-salt',
		  verified_at=$3,updated_at=$3
		WHERE user_id=$1 AND node_id=$2`, user.GlobalID, homeNodeID, now); err != nil {
		t.Fatalf("seed recoverable source account material: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO replica_copies (
		  id,user_id,node_id,snapshot_id,replica_kind,state,origin,is_authoritative,
		  compatibility_state,published_at,verified_at,created_at,updated_at
		) VALUES (gen_random_uuid(),$1,$2,$3,'active','corrupt','primary',true,
		  'compatible',$4,$4,$5,$5)
		ON CONFLICT (user_id,node_id) DO UPDATE SET snapshot_id=EXCLUDED.snapshot_id,
		  replica_kind='active',state='corrupt',origin='primary',is_authoritative=true,
		  compatibility_state='compatible',published_at=EXCLUDED.published_at,
		  verified_at=EXCLUDED.verified_at,updated_at=EXCLUDED.updated_at`,
		user.GlobalID, homeNodeID, sourceSnapshotID, recoveryAt, now); err != nil {
		t.Fatalf("seed corrupt normalized home replica: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_protection_states (
		  user_id,state,reason_code,authoritative_node_id,recovery_node_id,
		  latest_recovery_snapshot_id,latest_recovery_at,version,changed_at,evaluated_at
		) VALUES ($1,'restore_required','authoritative_corrupt',$2,$3,$4,$5,1,$6,$6)
		ON CONFLICT (user_id) DO UPDATE SET state='restore_required',
		  reason_code='authoritative_corrupt',authoritative_node_id=$2,recovery_node_id=$3,
		  latest_recovery_snapshot_id=$4,latest_recovery_at=$5,
		  version=user_protection_states.version+1,changed_at=$6,evaluated_at=$6`,
		user.GlobalID, homeNodeID, archiveNodeID, sourceSnapshotID, recoveryAt, now); err != nil {
		t.Fatalf("publish restore-required protection projection: %v", err)
	}
}

func assertControllerArchiveRestoreCompleted(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	user *store.User,
	homeNodeID, archiveNodeID, targetNodeID int64,
	operationID, workflowID, sourceSnapshotID string,
) {
	t.Helper()
	execution, err := st.GetRestoreWorkflowExecution(ctx, workflowID)
	if err != nil || execution == nil || execution.State != "succeeded" ||
		execution.CapabilityState != "consumed" || execution.TargetAccountStatus != "active" ||
		execution.TargetLocalUserID != "restored-local-restore-user" {
		t.Fatalf("completed restore execution=%+v err=%v", execution, err)
	}

	var currentHome int64
	var oldKind, oldState, targetKind, targetState string
	var targetAccountStatus, targetLocalUserID, passwordHash, passwordSalt string
	var sourceCopyState, sourceManifestState, restoreManifestState string
	var targetCopyKind, targetCopyState, targetCopyOrigin string
	var targetAuthoritative, sourceImmutable bool
	if err := st.DB.QueryRowContext(ctx, `SELECT home_node_id FROM users WHERE id=$1`, user.ID).
		Scan(&currentHome); err != nil {
		t.Fatalf("query restored legacy home: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT old.kind,old.state,target.kind,target.state
		FROM user_replicas old
		JOIN user_replicas target ON target.user_id=old.user_id
		WHERE old.user_id=$1 AND old.node_id=$2 AND target.node_id=$3`,
		user.ID, homeNodeID, targetNodeID).Scan(&oldKind, &oldState, &targetKind, &targetState); err != nil {
		t.Fatalf("query restored legacy replicas: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT status,local_user_id,password_hash,password_salt
		FROM node_accounts WHERE user_id=$1 AND node_id=$2`, user.GlobalID, targetNodeID).
		Scan(&targetAccountStatus, &targetLocalUserID, &passwordHash, &passwordSalt); err != nil {
		t.Fatalf("query restored target account: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT copy.state,manifest.state,(manifest.state='immutable')
		FROM replica_copies copy JOIN snapshot_manifests manifest ON manifest.id=copy.snapshot_id
		WHERE copy.user_id=$1 AND copy.node_id=$2 AND copy.snapshot_id=$3`,
		user.GlobalID, archiveNodeID, sourceSnapshotID).
		Scan(&sourceCopyState, &sourceManifestState, &sourceImmutable); err != nil {
		t.Fatalf("query immutable recovery source after restore: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT manifest.state,copy.replica_kind,copy.state,copy.origin,copy.is_authoritative
		FROM restore_operations operation
		JOIN snapshot_manifests manifest ON manifest.id=operation.restore_snapshot_id
		JOIN replica_copies copy ON copy.snapshot_id=manifest.id AND copy.node_id=operation.target_node_id
		WHERE operation.workflow_id=$1`, workflowID).
		Scan(&restoreManifestState, &targetCopyKind, &targetCopyState, &targetCopyOrigin, &targetAuthoritative); err != nil {
		t.Fatalf("query atomically published restore snapshot: %v", err)
	}
	if currentHome != targetNodeID || oldKind != "hot_standby" || oldState != "stale" ||
		targetKind != "home" || targetState != "ready" ||
		targetAccountStatus != "active" || targetLocalUserID != "restored-local-restore-user" ||
		passwordHash != "restore-password-hash" || passwordSalt != "restore-password-salt" ||
		sourceCopyState != "ready" || sourceManifestState != "immutable" || !sourceImmutable ||
		restoreManifestState != "immutable" || targetCopyKind != "active" || targetCopyState != "ready" ||
		targetCopyOrigin != "recovery" || !targetAuthoritative {
		t.Fatalf("restore convergence: home=%d old=%s/%s target=%s/%s account=%s/%s material=%t/%t source=%s/%s/%t restored=%s/%s/%s/%s/%t",
			currentHome, oldKind, oldState, targetKind, targetState,
			targetAccountStatus, targetLocalUserID,
			passwordHash == "restore-password-hash", passwordSalt == "restore-password-salt",
			sourceCopyState, sourceManifestState, sourceImmutable,
			restoreManifestState, targetCopyKind, targetCopyState, targetCopyOrigin, targetAuthoritative)
	}

	var scheduledAudit, succeededAudit int
	var failedTransfer, receiptRecovery, accountCommands int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE outcome='scheduled'),
		       count(*) FILTER (WHERE outcome='succeeded')
		FROM audit_events WHERE action='archive-restore' AND operation_id=$1`, operationID).
		Scan(&scheduledAudit, &succeededAudit); err != nil {
		t.Fatalf("query restore audit chain: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE operation_id=$1 AND command_type='start_restore_transfer' AND state='failed'),
		       count(*) FILTER (WHERE operation_id=$2 AND command_type='get_snapshot_receipt' AND state='succeeded'),
		       count(*) FILTER (WHERE operation_id=$3 AND command_type='restore_user_account' AND state='succeeded')
		FROM agent_commands`,
		deriveWorkflowOperationID(workflowID, "start-restore:"+execution.CapabilityID),
		deriveWorkflowOperationID(workflowID, fmt.Sprintf(
			"restore-receipt:%s:%d", execution.CapabilityID, execution.Attempt,
		)),
		deriveWorkflowOperationID(workflowID, fmt.Sprintf(
			"restore-account:%d:%d", execution.AccountVersion, execution.Attempt,
		))).
		Scan(&failedTransfer, &receiptRecovery, &accountCommands); err != nil {
		t.Fatalf("query restore command recovery history: %v", err)
	}
	if scheduledAudit != 1 || succeededAudit != 1 || failedTransfer != 1 ||
		receiptRecovery != 1 || accountCommands != 1 {
		t.Fatalf("restore durable history: audits=%d/%d transfer_failed=%d receipt=%d account=%d",
			scheduledAudit, succeededAudit, failedTransfer, receiptRecovery, accountCommands)
	}

	var protectionState string
	var protectionHome sql.NullInt64
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state,authoritative_node_id FROM user_protection_states WHERE user_id=$1`, user.GlobalID).
		Scan(&protectionState, &protectionHome); err != nil {
		t.Fatalf("query post-restore protection state: %v", err)
	}
	if protectionState != "protected" || !protectionHome.Valid || protectionHome.Int64 != targetNodeID {
		t.Fatalf("post-restore protection=%s authoritative=%+v", protectionState, protectionHome)
	}
}
