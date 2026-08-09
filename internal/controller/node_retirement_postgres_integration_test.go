package controller

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func TestControllerNodeRetirementConvergesThroughDurableAgentCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller node-retirement PostgreSQL integration is disabled in short mode")
	}
	ctx, st, generation, adminID := newControllerRetirementStore(t)
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	source := createControllerBackupNode(t, ctx, st, "retirement-controller-source", "compute", false, generation)
	target := createControllerBackupNode(t, ctx, st, "retirement-controller-target", "compute", false, generation)
	psks := map[int64]string{
		source.ID: "retirement-controller-source-psk",
		target.ID: "retirement-controller-target-psk",
	}
	for nodeID, psk := range psks {
		seedControllerBackupCredential(t, ctx, st, secretKey, nodeID, generation, psk)
	}
	user := createControllerBackupUser(t, ctx, st, source.ID, "retirement-controller-user")
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE node_accounts SET password_hash='retirement-password-hash',
		  password_salt='retirement-password-salt',password_material_version=1
		WHERE user_id=$1 AND node_id=$2`, user.GlobalID, source.ID); err != nil {
		t.Fatalf("seed retirement account material: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,state)
		VALUES ($1,$2,'home','ready')`, user.ID, source.ID); err != nil {
		t.Fatalf("seed retirement home replica: %v", err)
	}

	harness := newControllerBackupCommandHarness(ctx, st, source.ID, target.ID, psks)
	t.Cleanup(harness.stop)
	cfg := config.DefaultController()
	cfg.Backup.RetryMax = 3
	server := New(cfg, st, secretKey)
	status := startControllerRetirement(t, ctx, st, source.ID, adminID)

	if err := server.executeNodeRetirement(ctx, status.ID); err != nil {
		t.Fatalf("create retirement snapshot workflow: %v", err)
	}
	workflowID := controllerBackupWorkflowID(t, ctx, st, user.GlobalID)
	var retirementItemState string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state FROM node_retirement_items
		WHERE retirement_id=$1 AND workflow_id=$2`, status.ID, workflowID).Scan(&retirementItemState); err != nil || retirementItemState != "snapshotting" {
		t.Fatalf("durable retirement snapshot binding state=%q err=%v", retirementItemState, err)
	}

	// A second coordinator pass must observe the durable running workflow and
	// defer rather than creating a duplicate transfer.
	if err := server.executeNodeRetirement(ctx, status.ID); err != nil {
		t.Fatalf("defer running retirement snapshot: %v", err)
	}
	status = controllerRetirementStatus(t, ctx, st, source.ID)
	if status.State != "retry_wait" || status.ErrorCode != "snapshot_workflow_running" {
		t.Fatalf("running retirement defer status=%+v", status)
	}

	if err := server.executeSnapshotWorkflow(ctx, workflowID); err != nil {
		t.Fatalf("execute retirement snapshot through durable Agent commands: %v", err)
	}
	assertControllerBackupPublished(t, ctx, st, workflowID, user.GlobalID, target.ID)
	makeControllerRetirementDue(t, ctx, st, status.ID, false)
	if err := server.executeNodeRetirement(ctx, status.ID); err != nil {
		t.Fatalf("promote retirement snapshot target: %v", err)
	}
	status = controllerRetirementStatus(t, ctx, st, source.ID)
	if status.CompletedItems != 1 || status.TotalItems != 1 {
		t.Fatalf("completed retirement item status=%+v", status)
	}
	if err := server.executeNodeRetirement(ctx, status.ID); err != nil {
		t.Fatalf("finalize drained node: %v", err)
	}
	status = controllerRetirementStatus(t, ctx, st, source.ID)
	if status.State != "decommissioned" || status.CompletedAt == nil {
		t.Fatalf("final retirement status=%+v", status)
	}
	var nodeState string
	var allowRegister, backupTarget bool
	var activeCredentials int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT node.operational_state,node.allow_register,node.is_backup_target,
		  (SELECT count(*) FROM agent_credentials credential
		   WHERE credential.node_id=node.id AND credential.revoked_at IS NULL)
		FROM nodes node WHERE node.id=$1`, source.ID).Scan(
		&nodeState, &allowRegister, &backupTarget, &activeCredentials,
	); err != nil || nodeState != "decommissioned" || allowRegister || backupTarget || activeCredentials != 0 {
		t.Fatalf("decommissioned access facts state=%q register=%v backup=%v credentials=%d err=%v",
			nodeState, allowRegister, backupTarget, activeCredentials, err)
	}
	if err := server.executeNodeRetirement(ctx, status.ID); err != nil {
		t.Fatalf("replay completed retirement: %v", err)
	}
	if errs := harness.errors(); len(errs) > 0 {
		t.Fatalf("retirement durable Agent harness errors: %v", errs)
	}
}

func TestControllerNodeRetirementFailureModesRemainDurable(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller node-retirement PostgreSQL integration is disabled in short mode")
	}

	t.Run("empty retirement resumes in the bounded reconciler", func(t *testing.T) {
		ctx, st, generation, adminID := newControllerRetirementStore(t)
		node := createControllerBackupNode(t, ctx, st, "retirement-empty-controller", "compute", false, generation)
		status := startControllerRetirement(t, ctx, st, node.ID, adminID)
		if status.TotalItems != 0 || status.State != "verifying" {
			t.Fatalf("empty retirement status=%+v", status)
		}
		if err := (&Server{Store: st}).executeNodeRetirement(ctx, status.ID); err == nil {
			t.Fatal("retirement executor accepted an empty worker identity")
		}
		server := New(config.DefaultController(), st, []byte("0123456789abcdef0123456789abcdef"))
		server.resumeNodeRetirements(ctx)
		deadline := time.Now().Add(5 * time.Second)
		for {
			status = controllerRetirementStatus(t, ctx, st, node.ID)
			if status.State == "decommissioned" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("background retirement did not converge: %+v", status)
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		server.nodeRetirementReconciler(cancelled)
	})

	t.Run("account-only mapping is retired before finalization", func(t *testing.T) {
		ctx, st, generation, adminID := newControllerRetirementStore(t)
		home := createControllerBackupNode(t, ctx, st, "retirement-account-home", "compute", false, generation)
		source := createControllerBackupNode(t, ctx, st, "retirement-account-source", "compute", false, generation)
		user := createControllerBackupUser(t, ctx, st, home.ID, "retirement-account-only")
		if _, err := st.DB.ExecContext(ctx, `
			INSERT INTO node_accounts (user_id,node_id,local_handle,status)
			VALUES ($1,$2,$3,'active')`, user.GlobalID, source.ID, user.Username); err != nil {
			t.Fatalf("seed account-only retirement mapping: %v", err)
		}
		status := startControllerRetirement(t, ctx, st, source.ID, adminID)
		server := New(config.DefaultController(), st, []byte("0123456789abcdef0123456789abcdef"))
		if err := server.executeNodeRetirement(ctx, status.ID); err != nil {
			t.Fatalf("retire account-only mapping: %v", err)
		}
		var accountState, itemKind, itemState string
		if err := st.DB.QueryRowContext(ctx, `
			SELECT account.status,item.item_kind,item.state
			FROM node_accounts account JOIN node_retirement_items item
			  ON item.user_id=account.user_id AND item.source_node_id=account.node_id
			WHERE account.user_id=$1 AND account.node_id=$2`, user.GlobalID, source.ID).Scan(
			&accountState, &itemKind, &itemState,
		); err != nil || accountState != "stale" || itemKind != "account_metadata" || itemState != "succeeded" {
			t.Fatalf("account retirement account=%q kind=%q item=%q err=%v", accountState, itemKind, itemState, err)
		}
		if err := server.executeNodeRetirement(ctx, status.ID); err != nil {
			t.Fatalf("finalize account-only retirement: %v", err)
		}
		if got := controllerRetirementStatus(t, ctx, st, source.ID); got.State != "decommissioned" {
			t.Fatalf("account-only final status=%+v", got)
		}
	})

	t.Run("active user waits and missing target blocks", func(t *testing.T) {
		ctx, st, generation, adminID := newControllerRetirementStore(t)
		source := createControllerBackupNode(t, ctx, st, "retirement-busy-source", "compute", false, generation)
		user := createControllerBackupUser(t, ctx, st, source.ID, "retirement-busy-user")
		now := time.Now().UTC()
		if _, err := st.DB.ExecContext(ctx, `
			INSERT INTO user_activity_leases (
			  user_id,writer_node_id,session_id,activity_epoch,state,lease_expires_at,
			  last_page_heartbeat_at,last_request_at,controller_generation,updated_at
			) VALUES ($1,$2,$3,1,'active',$4,$5,$5,$6,$5)`,
			user.GlobalID, source.ID, "82000000-0000-4000-8000-000000000001",
			now.Add(time.Hour), now, generation); err != nil {
			t.Fatalf("seed active retirement lease: %v", err)
		}
		status := startControllerRetirement(t, ctx, st, source.ID, adminID)
		server := New(config.DefaultController(), st, []byte("0123456789abcdef0123456789abcdef"))
		if err := server.executeNodeRetirement(ctx, status.ID); err != nil {
			t.Fatalf("defer busy retirement user: %v", err)
		}
		status = controllerRetirementStatus(t, ctx, st, source.ID)
		if status.State != "retry_wait" || status.WaitingItems != 1 || status.ErrorCode != "user_activity_not_drained" {
			t.Fatalf("busy retirement status=%+v", status)
		}
		if _, err := st.DB.ExecContext(ctx, `
			UPDATE user_activity_leases SET state='ended',lease_expires_at=now(),updated_at=now()
			WHERE user_id=$1`, user.GlobalID); err != nil {
			t.Fatalf("end active retirement lease: %v", err)
		}
		makeControllerRetirementDue(t, ctx, st, status.ID, true)
		if err := server.executeNodeRetirement(ctx, status.ID); err != nil {
			t.Fatalf("record unavailable retirement target: %v", err)
		}
		status = controllerRetirementStatus(t, ctx, st, source.ID)
		if status.State != "blocked" || status.BlockedItems != 1 || status.ErrorCode != "retirement_target_unavailable" {
			t.Fatalf("missing-target retirement status=%+v", status)
		}
	})

	t.Run("terminal snapshot is cleared before bounded reselection", func(t *testing.T) {
		ctx, st, generation, adminID := newControllerRetirementStore(t)
		source := createControllerBackupNode(t, ctx, st, "retirement-retry-source", "compute", false, generation)
		target := createControllerBackupNode(t, ctx, st, "retirement-retry-target", "compute", false, generation)
		user := createControllerBackupUser(t, ctx, st, source.ID, "retirement-terminal-user")
		if _, err := st.DB.ExecContext(ctx, `
			UPDATE node_accounts SET password_hash='retry-password-hash',password_salt='retry-password-salt',
			  password_material_version=1 WHERE user_id=$1 AND node_id=$2`, user.GlobalID, source.ID); err != nil {
			t.Fatalf("seed terminal workflow account material: %v", err)
		}
		status := startControllerRetirement(t, ctx, st, source.ID, adminID)
		server := New(config.DefaultController(), st, []byte("0123456789abcdef0123456789abcdef"))
		if err := server.executeNodeRetirement(ctx, status.ID); err != nil {
			t.Fatalf("create terminal retirement workflow: %v", err)
		}
		workflowID := controllerBackupWorkflowID(t, ctx, st, user.GlobalID)
		if _, err := st.DB.ExecContext(ctx, `UPDATE workflows SET state='failed' WHERE id=$1`, workflowID); err != nil {
			t.Fatalf("mark retirement workflow terminal: %v", err)
		}
		if err := server.executeNodeRetirement(ctx, status.ID); err != nil {
			t.Fatalf("retry terminal retirement workflow: %v", err)
		}
		var itemState, errorCode string
		var clearedWorkflow sql.NullString
		if err := st.DB.QueryRowContext(ctx, `
			SELECT state,error_code,workflow_id::text FROM node_retirement_items
			WHERE retirement_id=$1`, status.ID).Scan(&itemState, &errorCode, &clearedWorkflow); err != nil ||
			itemState != "retry_wait" || errorCode != "snapshot_workflow_terminal" || clearedWorkflow.Valid {
			t.Fatalf("terminal workflow retry item=%q code=%q workflow=%+v err=%v",
				itemState, errorCode, clearedWorkflow, err)
		}
		if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET capacity_state='full' WHERE id=$1`, target.ID); err != nil {
			t.Fatalf("close terminal retry target: %v", err)
		}
		makeControllerRetirementDue(t, ctx, st, status.ID, true)
		if err := server.executeNodeRetirement(ctx, status.ID); err != nil {
			t.Fatalf("block terminal retry without a target: %v", err)
		}
		status = controllerRetirementStatus(t, ctx, st, source.ID)
		if status.State != "blocked" || status.ErrorCode != "retirement_target_unavailable" {
			t.Fatalf("terminal retry reselection status=%+v", status)
		}
	})

	t.Run("snapshot creation failure is persisted for restart", func(t *testing.T) {
		ctx, st, generation, adminID := newControllerRetirementStore(t)
		source := createControllerBackupNode(t, ctx, st, "retirement-create-fail-source", "compute", false, generation)
		_ = createControllerBackupNode(t, ctx, st, "retirement-create-fail-target", "compute", false, generation)
		user := createControllerBackupUser(t, ctx, st, source.ID, "retirement-create-fail-user")
		status := startControllerRetirement(t, ctx, st, source.ID, adminID)
		server := New(config.DefaultController(), st, []byte("0123456789abcdef0123456789abcdef"))
		if err := server.executeNodeRetirement(ctx, status.ID); err != nil {
			t.Fatalf("persist retirement workflow creation failure: %v", err)
		}
		status = controllerRetirementStatus(t, ctx, st, source.ID)
		var workflows int
		if err := st.DB.QueryRowContext(ctx, `SELECT count(*) FROM workflows WHERE user_id=$1`, user.GlobalID).Scan(&workflows); err != nil {
			t.Fatalf("count rolled-back retirement workflows: %v", err)
		}
		if status.State != "retry_wait" || status.ErrorCode != "snapshot_workflow_create_failed" || workflows != 0 {
			t.Fatalf("snapshot creation failure status=%+v workflows=%d", status, workflows)
		}
	})
}

func newControllerRetirementStore(t *testing.T) (context.Context, *store.Store, int64, int64) {
	t.Helper()
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated Controller retirement store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	generation, err := st.GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatalf("read Controller generation for retirement: %v", err)
	}
	var adminID int64
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO admins (uuid,username,password_hash,status)
		VALUES (gen_random_uuid(),'retirement-controller-admin','test-hash','active')
		RETURNING id`).Scan(&adminID); err != nil {
		t.Fatalf("create Controller retirement administrator: %v", err)
	}
	return ctx, st, generation, adminID
}

func startControllerRetirement(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	nodeID, adminID int64,
) *store.NodeRetirementStatus {
	t.Helper()
	operationID, err := newUUID()
	if err != nil {
		t.Fatalf("create Controller retirement operation ID: %v", err)
	}
	state, err := st.TransitionNodeLifecycle(ctx, store.TransitionNodeLifecycleParams{
		OperationID: operationID, NodeID: nodeID, ToState: "draining",
		ReasonCode: "operator_draining", AdminID: adminID, Now: time.Now().UTC(),
	})
	if err != nil || state != "draining" {
		t.Fatalf("start Controller retirement state=%q err=%v", state, err)
	}
	return controllerRetirementStatus(t, ctx, st, nodeID)
}

func controllerRetirementStatus(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	nodeID int64,
) *store.NodeRetirementStatus {
	t.Helper()
	status, err := st.GetNodeRetirementStatus(ctx, nodeID)
	if err != nil || status == nil {
		t.Fatalf("load Controller retirement status for node %d: status=%+v err=%v", nodeID, status, err)
	}
	return status
}

func makeControllerRetirementDue(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	retirementID string,
	includeItems bool,
) {
	t.Helper()
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE node_retirement_operations SET next_attempt_at=now()-interval '1 second'
		WHERE id=$1`, retirementID); err != nil {
		t.Fatalf("advance Controller retirement operation: %v", err)
	}
	if includeItems {
		if _, err := st.DB.ExecContext(ctx, `
			UPDATE node_retirement_items SET next_attempt_at=now()-interval '1 second'
			WHERE retirement_id=$1 AND state NOT IN ('succeeded','superseded','failed')`, retirementID); err != nil {
			t.Fatalf("advance Controller retirement items: %v", err)
		}
	}
}
