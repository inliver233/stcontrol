package controller

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func TestControllerIndependentReconciliationSnapshotsAndCompletesAfterRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller independent-reconciliation PostgreSQL integration is disabled in short mode")
	}
	ctx, st, generation, _ := newControllerRetirementStore(t)
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	source := createControllerBackupNode(t, ctx, st, "independent-controller-source", "compute", false, generation)
	target := createControllerBackupNode(t, ctx, st, "independent-controller-storage", "storage", true, generation)
	psks := map[int64]string{
		source.ID: "independent-controller-source-psk",
		target.ID: "independent-controller-storage-psk",
	}
	for nodeID, psk := range psks {
		seedControllerBackupCredential(t, ctx, st, secretKey, nodeID, generation, psk)
	}
	user := createControllerBackupUser(t, ctx, st, source.ID, "independent-retry-user")
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,state,last_sync_at)
		VALUES ($1,$2,'home','ready',now())`, user.ID, source.ID); err != nil {
		t.Fatalf("seed independent home replica: %v", err)
	}
	marker := "84000000-0000-4000-8000-000000000001"
	makeControllerIndependentDraining(t, ctx, st, generation, source.ID, user.Username, marker)

	harness := newControllerBackupCommandHarness(ctx, st, source.ID, target.ID, psks)
	t.Cleanup(harness.stop)
	server := New(config.DefaultController(), st, secretKey)
	server.reconcileIndependentWrites(ctx)
	workflowID := waitControllerIndependentWorkflow(
		t, ctx, st, source.ID, marker, "snapshotting", "succeeded", 10*time.Second,
	)
	assertControllerBackupPublished(t, ctx, st, workflowID, user.GlobalID, target.ID)
	completionWork, err := st.ListIndependentReconciliationWork(ctx, 50, time.Now().UTC())
	if err != nil || len(completionWork) != 1 || completionWork[0].Action != "complete" {
		t.Fatalf("load independent completion work=%+v err=%v", completionWork, err)
	}
	server.reconcileIndependentWrites(ctx)
	waitControllerIndependentState(t, ctx, st, source.ID, marker, "completion_retry", 10*time.Second)
	var attempt int
	var errorCode string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT attempt,error_code FROM independent_user_reconciliations
		WHERE node_id=$1 AND marker=$2`, source.ID, marker).Scan(&attempt, &errorCode); err != nil ||
		attempt != 1 || errorCode != "adapter_completion_failed" {
		t.Fatalf("independent completion retry attempt=%d code=%q err=%v", attempt, errorCode, err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE independent_user_reconciliations SET next_attempt_at=now()-interval '1 second'
		WHERE node_id=$1 AND marker=$2`, source.ID, marker); err != nil {
		t.Fatalf("advance independent completion retry: %v", err)
	}
	restarted := New(config.DefaultController(), st, secretKey)
	restarted.reconcileIndependentWrites(ctx)
	waitControllerIndependentState(t, ctx, st, source.ID, marker, "succeeded", 5*time.Second)
	var completionCommands, completionAudits int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT
		  (SELECT count(*) FROM agent_commands WHERE command_type='complete_independent_sync'),
		  (SELECT count(*) FROM audit_logs WHERE action='independent-reconciliation-complete'
		     AND target=$1)`, "node:"+int64Text(source.ID)+"/user:"+int64Text(user.GlobalID)).Scan(
		&completionCommands, &completionAudits,
	); err != nil || completionCommands != 2 || completionAudits != 1 {
		t.Fatalf("independent completion commands=%d audits=%d err=%v", completionCommands, completionAudits, err)
	}
	if errs := harness.errors(); len(errs) > 0 {
		t.Fatalf("independent durable Agent harness errors: %v", errs)
	}

	now := time.Now().UTC()
	decision, err := st.ReconcileNodeControlMode(ctx, source.ID,
		controllerDisasterFact(generation, 3, store.NodeModeIndependentDraining, now, 0, nil))
	if err != nil || decision.DesiredMode != store.NodeModeManaged || decision.ModeGeneration != 4 {
		t.Fatalf("completed independent drain decision=%+v err=%v", decision, err)
	}
	if _, err := st.ReconcileNodeControlMode(ctx, source.ID,
		controllerDisasterFact(generation, 4, store.NodeModeManaged, now.Add(time.Second), 0, nil)); err != nil {
		t.Fatalf("apply managed mode after independent completion: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	restarted.independentReconciliationReconciler(cancelled)
	if got := independentRetryDelay(100); got != 5*time.Minute {
		t.Fatalf("bounded independent retry=%v", got)
	}
}

func TestControllerIndependentReconciliationRestartsTerminalSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller independent-reconciliation PostgreSQL integration is disabled in short mode")
	}
	ctx, st, generation, _ := newControllerRetirementStore(t)
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	source := createControllerBackupNode(t, ctx, st, "independent-terminal-source", "compute", false, generation)
	target := createControllerBackupNode(t, ctx, st, "independent-terminal-storage", "storage", true, generation)
	user := createControllerBackupUser(t, ctx, st, source.ID, "independent-terminal-user")
	marker := "84100000-0000-4000-8000-000000000001"
	makeControllerIndependentDraining(t, ctx, st, generation, source.ID, user.Username, marker)
	var reconciliationID string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT id::text FROM independent_user_reconciliations
		WHERE node_id=$1 AND marker=$2`, source.ID, marker).Scan(&reconciliationID); err != nil {
		t.Fatalf("load terminal independent reconciliation: %v", err)
	}
	workflowID, err := newUUID()
	if err != nil {
		t.Fatalf("create terminal independent workflow ID: %v", err)
	}
	operationID, err := newUUID()
	if err != nil {
		t.Fatalf("create terminal independent operation ID: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO workflows (
		  id,operation_id,workflow_type,state,user_id,source_node_id,target_node_id,
		  activity_epoch,controller_generation,attempt,error_code,cleanup_state,created_at,updated_at,finished_at
		) VALUES ($1,$2,'snapshot','failed',$3,$4,$5,1,$6,1,'test_terminal','pending',now(),now(),now())`,
		workflowID, operationID, user.GlobalID, source.ID, target.ID, generation); err != nil {
		t.Fatalf("seed failed independent snapshot: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE independent_user_reconciliations SET state='snapshotting',workflow_id=$2
		WHERE id=$1`, reconciliationID, workflowID); err != nil {
		t.Fatalf("bind failed independent snapshot: %v", err)
	}
	server := New(config.DefaultController(), st, secretKey)
	restartWork, err := st.ListIndependentReconciliationWork(ctx, 50, time.Now().UTC())
	if err != nil || len(restartWork) != 1 || restartWork[0].Action != "restart" {
		t.Fatalf("load terminal independent work=%+v err=%v", restartWork, err)
	}
	server.reconcileIndependentWrites(ctx)
	var state string
	var errorCode, clearedWorkflow sql.NullString
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state,error_code,workflow_id::text FROM independent_user_reconciliations
		WHERE id=$1`, reconciliationID).Scan(&state, &errorCode, &clearedWorkflow); err != nil ||
		state != "retry_wait" || errorCode.String != "snapshot_terminal_failure" || clearedWorkflow.Valid {
		t.Fatalf("terminal independent restart state=%q code=%q workflow=%+v err=%v",
			state, errorCode.String, clearedWorkflow, err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE independent_user_reconciliations SET next_attempt_at=now()-interval '1 second' WHERE id=$1`,
		reconciliationID); err != nil {
		t.Fatalf("advance independent snapshot retry: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET capacity_state='full' WHERE id=$1`, target.ID); err != nil {
		t.Fatalf("close independent storage target: %v", err)
	}
	work, err := st.ListIndependentReconciliationWork(ctx, 50, time.Now().UTC())
	if err != nil || len(work) != 1 || work[0].Action != "snapshot" {
		t.Fatalf("load independent snapshot retry work=%+v err=%v", work, err)
	}
	if err := server.createIndependentReconciliationSnapshot(ctx, work[0]); err == nil {
		t.Fatal("independent snapshot retry accepted a full storage target")
	}
	var jobs int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM backup_jobs WHERE trigger='independent_reconciliation' AND user_id=$1`,
		user.ID).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatalf("unavailable independent target jobs=%d err=%v", jobs, err)
	}
}

func makeControllerIndependentDraining(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	generation, nodeID int64,
	handle, marker string,
) {
	t.Helper()
	now := time.Now().UTC()
	pending := []store.IndependentSyncFact{{
		Handle: handle, Marker: marker, ChangedAt: now.Add(-time.Minute), Reason: "independent_write",
	}}
	decision, err := st.ReconcileNodeControlMode(ctx, nodeID,
		controllerDisasterFact(generation, 2, store.NodeModeIndependent, now, 1, pending))
	if err != nil || decision.DesiredMode != store.NodeModeIndependentDraining || decision.ModeGeneration != 3 {
		t.Fatalf("enter independent draining decision=%+v err=%v", decision, err)
	}
	decision, err = st.ReconcileNodeControlMode(ctx, nodeID,
		controllerDisasterFact(generation, 3, store.NodeModeIndependentDraining, now.Add(time.Second), 0, pending))
	if err != nil || decision.DesiredMode != store.NodeModeIndependentDraining {
		t.Fatalf("apply independent draining decision=%+v err=%v", decision, err)
	}
}

func waitControllerIndependentWorkflow(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	nodeID int64,
	marker, wantReconciliationState, wantWorkflowState string,
	timeout time.Duration,
) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var reconciliationState, workflowID, workflowState string
		err := st.DB.QueryRowContext(ctx, `
			SELECT reconciliation.state,reconciliation.workflow_id::text,workflow.state
			FROM independent_user_reconciliations reconciliation
			JOIN workflows workflow ON workflow.id=reconciliation.workflow_id
			WHERE reconciliation.node_id=$1 AND reconciliation.marker=$2`, nodeID, marker).Scan(
			&reconciliationState, &workflowID, &workflowState,
		)
		if err == nil && reconciliationState == wantReconciliationState && workflowState == wantWorkflowState {
			return workflowID
		}
		if time.Now().After(deadline) {
			t.Fatalf("independent workflow state=%q/%q want=%q/%q id=%q err=%v",
				reconciliationState, workflowState, wantReconciliationState, wantWorkflowState, workflowID, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitControllerIndependentState(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	nodeID int64,
	marker, want string,
	timeout time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var state string
		err := st.DB.QueryRowContext(ctx, `
			SELECT state FROM independent_user_reconciliations WHERE node_id=$1 AND marker=$2`,
			nodeID, marker).Scan(&state)
		if err == nil && state == want {
			return
		}
		if time.Now().After(deadline) {
			var commandFacts sql.NullString
			_ = st.DB.QueryRowContext(ctx, `
				SELECT string_agg(command_type||':'||state,',' ORDER BY created_at)
				FROM agent_commands`).Scan(&commandFacts)
			t.Fatalf("independent reconciliation state=%q want=%q err=%v commands=%q",
				state, want, err, commandFacts.String)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func int64Text(value int64) string {
	return fmt.Sprintf("%d", value)
}
