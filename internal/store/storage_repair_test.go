package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func storageRepairExecutionParams(now time.Time) CreateStorageRepairExecutionParams {
	return CreateStorageRepairExecutionParams{
		ExecutionID:       "11111111-1111-4111-8111-111111111111",
		LeaseOwner:        "22222222-2222-4222-8222-222222222222",
		WorkflowID:        "33333333-3333-4333-8333-333333333333",
		OperationID:       "44444444-4444-4444-8444-444444444444",
		SnapshotID:        "55555555-5555-4555-8555-555555555555",
		CapabilityID:      "66666666-6666-4666-8666-666666666666",
		CapabilityHash:    make([]byte, 32),
		CapabilityExpires: now.Add(8 * time.Hour),
		LeaseTTL:          8 * time.Hour,
		MaxAttempts:       3,
		Now:               now,
	}
}

func TestListActiveStorageRepairUserIDsFencesLegacyOfflineScheduler(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`(?s)SELECT user_id FROM storage_repair_tasks.*state IN \('pending','retry_wait','workflow_running'\)`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow(int64(70)).AddRow(int64(71)))
	users, err := st.ListActiveStorageRepairUserIDs(context.Background())
	if err != nil || len(users) != 2 {
		t.Fatalf("users=%v err=%v", users, err)
	}
	if _, ok := users[70]; !ok {
		t.Fatal("active storage repair user was not fenced")
	}
	assertMockExpectations(t, mock)
}

func TestScheduleStorageRepairTasksPersistsOneFencedIntent(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(`(?s)UPDATE storage_repair_tasks task SET state='cancelled'.*task.state IN \('pending','retry_wait'\).*JOIN user_replicas legacy_copy.*copy.replica_kind='archive'.*copy.verified_at IS NOT NULL`).
		WithArgs(now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO storage_repair_tasks.*home_replica.size_bytes.*JOIN user_replicas archive_legacy.*copy.verified_at IS NOT NULL.*workflow.workflow_type IN \('snapshot','restore','conflict_resolution'\).*FROM replica_conflicts conflict.*FROM user_data_faults fault.*ON CONFLICT DO NOTHING`).
		WithArgs(now, int64(1<<30), int64(64<<20)).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()
	created, err := st.ScheduleStorageRepairTasks(context.Background(), now)
	if err != nil || created != 2 {
		t.Fatalf("created=%d err=%v", created, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimAndCreateStorageRepairReturnsNilWithoutDueIntent(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := storageRepairExecutionParams(time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC))
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)FROM storage_repair_tasks task.*task.attempt<\$2.*FOR UPDATE OF task,global_user,legacy,home,home_replica SKIP LOCKED`).
		WithArgs(p.Now, p.MaxAttempts).
		WillReturnRows(sqlmock.NewRows([]string{"id", "legacy_user_id", "user_id", "source_node_id", "estimated_bytes", "attempt"}))
	mock.ExpectRollback()
	execution, err := st.ClaimAndCreateStorageRepair(context.Background(), p)
	if err != nil || execution != nil {
		t.Fatalf("execution=%+v err=%v", execution, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimAndCreateStorageRepairAtomicallyReservesAndCreatesWorkflow(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := storageRepairExecutionParams(time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC))
	taskID := "77777777-7777-4777-8777-777777777777"
	estimated := int64(512 << 20)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)FROM storage_repair_tasks task.*JOIN user_replicas archive_legacy.*copy.verified_at IS NOT NULL.*workflow.workflow_type IN \('snapshot','restore','conflict_resolution'\).*FOR UPDATE OF task,global_user,legacy,home,home_replica SKIP LOCKED`).
		WithArgs(p.Now, p.MaxAttempts).
		WillReturnRows(sqlmock.NewRows([]string{"id", "legacy_user_id", "user_id", "source_node_id", "estimated_bytes", "attempt", "preferred_target_node_id"}).
			AddRow(taskID, int64(7), int64(70), int64(8), estimated, 1, nil))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
	mock.ExpectQuery(`(?s)FROM user_activity_leases WHERE user_id=\$1 FOR UPDATE`).
		WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"activity_epoch", "writer_node_id", "lease_expires_at", "in_flight_reads", "in_flight_writes", "state"}))
	mock.ExpectQuery(`(?s)FROM nodes node.*node.role='storage'.*disk_available_bytes-COALESCE.*disk_quota_bytes-node.allocated_disk_bytes-COALESCE.*FOR UPDATE OF node SKIP LOCKED`).
		WithArgs(int64(8), estimated, p.Now.Add(-2*time.Minute), int64(70), nil).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(9)))
	mock.ExpectQuery(`(?s)INSERT INTO backup_jobs.*'storage_repair'.*RETURNING id`).
		WithArgs(int64(7), int64(8), int64(9), p.Now).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(23)))
	mock.ExpectExec(`INSERT INTO workflows`).
		WithArgs(p.WorkflowID, p.OperationID, int64(70), int64(8), int64(9), int64(1), int64(4), p.Now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	for _, step := range []string{"quiesce", "snapshot", "prepare_target", "transfer", "verify", "publish", "cleanup"} {
		mock.ExpectExec(`INSERT INTO workflow_steps`).WithArgs(p.WorkflowID, step, p.Now).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectExec(`INSERT INTO snapshot_manifests`).
		WithArgs(p.SnapshotID, p.WorkflowID, int64(70), int64(8), int64(1), make([]byte, 32), p.Now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO snapshot_transfer_capabilities`).
		WithArgs(p.CapabilityID, p.WorkflowID, p.SnapshotID, int64(8), int64(9), p.CapabilityHash, int64(4), p.CapabilityExpires, p.Now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE backup_jobs SET workflow_id`).
		WithArgs(int64(23), p.WorkflowID, p.SnapshotID, int64(1), int64(7), int64(8), int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO user_replicas.*CASE WHEN user_replicas.state='ready'.*THEN 'ready' ELSE 'syncing' END`).WithArgs(int64(7), int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE storage_repair_tasks SET state='workflow_running'.*reserved_bytes=estimated_bytes.*WHERE id=\$1`).
		WithArgs(taskID, int64(9), p.ExecutionID, p.LeaseOwner, p.Now.Add(p.LeaseTTL), int64(4), p.WorkflowID, int64(23), p.Now, 1).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO audit_events.*'storage-repair'.*'scheduled'.*'estimated_bytes',\$10::bigint`).
		WithArgs(p.Now, p.LeaseOwner, int64(70), p.ExecutionID, int64(4), taskID, p.WorkflowID,
			int64(8), int64(9), estimated, 2).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	execution, err := st.ClaimAndCreateStorageRepair(context.Background(), p)
	if err != nil || execution == nil || execution.TaskID != taskID || execution.WorkflowID != p.WorkflowID ||
		execution.TargetNodeID != 9 || execution.LegacyBackupJobID != 23 || execution.EstimatedBytes != estimated ||
		execution.ControllerGeneration != 4 || execution.ActivityEpoch != 1 {
		t.Fatalf("execution=%+v err=%v", execution, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimAndCreateStorageRepairDoesNotCreateJobWithoutReservedCapacity(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := storageRepairExecutionParams(time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC))
	mock.ExpectBegin()
	mock.ExpectQuery(`FROM storage_repair_tasks task`).WithArgs(p.Now, p.MaxAttempts).
		WillReturnRows(sqlmock.NewRows([]string{"id", "legacy_user_id", "user_id", "source_node_id", "estimated_bytes", "attempt", "preferred_target_node_id"}).
			AddRow("77777777-7777-4777-8777-777777777777", int64(7), int64(70), int64(8), int64(1<<30), 0, nil))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
	mock.ExpectQuery(`FROM user_activity_leases`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"activity_epoch", "writer_node_id", "lease_expires_at", "in_flight_reads", "in_flight_writes", "state"}))
	mock.ExpectQuery(`FROM nodes node`).WithArgs(int64(8), int64(1<<30), p.Now.Add(-2*time.Minute), int64(70), nil).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectRollback()
	execution, err := st.ClaimAndCreateStorageRepair(context.Background(), p)
	if err != nil || execution != nil {
		t.Fatalf("execution=%+v err=%v", execution, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimAndCreateStorageRepairRejectsAWriterThatCameBack(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := storageRepairExecutionParams(time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC))
	mock.ExpectBegin()
	mock.ExpectQuery(`FROM storage_repair_tasks task`).WithArgs(p.Now, p.MaxAttempts).
		WillReturnRows(sqlmock.NewRows([]string{"id", "legacy_user_id", "user_id", "source_node_id", "estimated_bytes", "attempt", "preferred_target_node_id"}).
			AddRow("77777777-7777-4777-8777-777777777777", int64(7), int64(70), int64(8), int64(1<<30), 0, nil))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
	mock.ExpectQuery(`FROM user_activity_leases`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"activity_epoch", "writer_node_id", "lease_expires_at", "in_flight_reads", "in_flight_writes", "state"}).
			AddRow(int64(9), int64(8), p.Now.Add(time.Minute), int64(0), int64(0), "active"))
	mock.ExpectRollback()
	execution, err := st.ClaimAndCreateStorageRepair(context.Background(), p)
	if err != nil || execution != nil {
		t.Fatalf("execution=%+v err=%v", execution, err)
	}
	assertMockExpectations(t, mock)
}

func TestReconcileStorageRepairTasksReleasesReservationWithDurableBackoff(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(`(?s)INSERT INTO audit_events.*task.lease_owner::text.*'storage-repair'.*'target_node_id',task.target_node_id.*workflow.state IN \('succeeded','failed','cancelled'\)`).
		WithArgs(now, 3).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`(?s)UPDATE storage_repair_tasks task SET.*reserved_bytes=0,last_target_node_id=task.target_node_id,target_node_id=NULL.*lease_owner=NULL,lease_until=NULL.*make_interval.*workflow.state IN \('succeeded','failed','cancelled'\)`).
		WithArgs(now, 3).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`(?s)INSERT INTO audit_events.*'last_target_node_id',task.last_target_node_id.*'attempt_limit_reached'.*task.attempt>=\$2`).
		WithArgs(now, 3).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE storage_repair_tasks SET state='failed'.*attempt>=\$2`).
		WithArgs(now, 3).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	count, err := st.ReconcileStorageRepairTasks(context.Background(), now, 3)
	if err != nil || count != 3 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimAndCreateStorageRepairRejectsInvalidIdentityBeforeTransaction(t *testing.T) {
	t.Parallel()
	st, _, closeDB := newMockStore(t)
	defer closeDB()
	p := storageRepairExecutionParams(time.Now().UTC())
	p.ExecutionID = "not-a-uuid"
	if execution, err := st.ClaimAndCreateStorageRepair(context.Background(), p); execution != nil ||
		!errors.Is(err, ErrInvalidStorageRepairExecution) {
		t.Fatalf("execution=%+v err=%v", execution, err)
	}
	if _, err := st.ReconcileStorageRepairTasks(context.Background(), p.Now, 0); !errors.Is(err, ErrInvalidStorageRepairExecution) {
		t.Fatalf("invalid max attempts error=%v", err)
	}
}
func TestSetStorageRepairPreferredTargetValidatesAndPersists(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 14, 2, 0, 0, 0, time.UTC)

	// Non-storage node is rejected before any mutation.
	mock.ExpectQuery(`SELECT EXISTS \(SELECT 1 FROM nodes WHERE id=\$1 AND role='storage'\)`).
		WithArgs(int64(9)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if err := st.SetStorageRepairPreferredTarget(context.Background(), 70, 9, now); err != ErrInvalidStorageRepairExecution {
		t.Fatalf("err=%v", err)
	}
	assertMockExpectations(t, mock)

	// Valid storage target persists the override.
	mock.ExpectQuery(`SELECT EXISTS \(SELECT 1 FROM nodes WHERE id=\$1 AND role='storage'\)`).
		WithArgs(int64(9)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec(`UPDATE storage_repair_tasks SET preferred_target_node_id=\$2,updated_at=\$3`).
		WithArgs(int64(70), int64(9), now).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.SetStorageRepairPreferredTarget(context.Background(), 70, 9, now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)

	// Clearing (0) writes NULL.
	mock.ExpectExec(`UPDATE storage_repair_tasks SET preferred_target_node_id=\$2,updated_at=\$3`).
		WithArgs(int64(70), nil, now).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.SetStorageRepairPreferredTarget(context.Background(), 70, 0, now); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)

	// No pending task surfaces ErrNoRows.
	mock.ExpectQuery(`SELECT EXISTS \(SELECT 1 FROM nodes WHERE id=\$1 AND role='storage'\)`).
		WithArgs(int64(9)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec(`UPDATE storage_repair_tasks SET preferred_target_node_id=\$2,updated_at=\$3`).
		WithArgs(int64(70), int64(9), now).WillReturnResult(sqlmock.NewResult(0, 0))
	if err := st.SetStorageRepairPreferredTarget(context.Background(), 70, 9, now); err != sql.ErrNoRows {
		t.Fatalf("err=%v", err)
	}
	assertMockExpectations(t, mock)

	// Invalid inputs are rejected before touching the database.
	if err := st.SetStorageRepairPreferredTarget(context.Background(), 0, 9, now); err != ErrInvalidStorageRepairExecution {
		t.Fatalf("err=%v", err)
	}
	if err := st.SetStorageRepairPreferredTarget(context.Background(), 70, -1, now); err != ErrInvalidStorageRepairExecution {
		t.Fatalf("err=%v", err)
	}
}

// This acceptance test is skipped by the fast suite unless a real PostgreSQL
// DSN is supplied. It exercises the 0039 CHECK/partial-unique indexes and the
// terminal retry update against PostgreSQL rather than sqlmock.
func TestPostgresStorageRepairTaskTerminalConstraints(t *testing.T) {
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	defer cleanupSchema()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated PostgreSQL store: %v", err)
	}
	defer st.Close()

	now := time.Now().UTC().Truncate(time.Microsecond)
	sourceNodeID := insertIntegrationNode(t, st, "storage-repair-source")
	targetNodeID := insertIntegrationNode(t, st, "storage-repair-target")
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET role='storage',is_backup_target=true,transfer_url=$2,
		  control_mode='managed',desired_control_mode='managed'
		WHERE id=$1`, targetNodeID, "https://storage-repair-target.example/transfer"); err != nil {
		t.Fatalf("prepare storage target: %v", err)
	}
	var legacyUserID, globalUserID int64
	var userUUID string
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO users (uuid,username,display_name,home_node_id,status)
		VALUES (gen_random_uuid(),'storage-repair-user','Storage Repair User',$1,'active')
		RETURNING id,uuid::text`, sourceNodeID).Scan(&legacyUserID, &userUUID); err != nil {
		t.Fatalf("insert legacy repair user: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO global_users (uuid,legacy_user_id,display_name,status,created_at,updated_at)
		VALUES ($1,$2,'Storage Repair User','active',$3,$3) RETURNING id`,
		userUUID, legacyUserID, now).Scan(&globalUserID); err != nil {
		t.Fatalf("insert global repair user: %v", err)
	}
	generation, err := st.GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatalf("read controller generation: %v", err)
	}

	taskID := "71000000-0000-4000-8000-000000000001"
	workflowID := "71000000-0000-4000-8000-000000000002"
	executionID := "71000000-0000-4000-8000-000000000003"
	leaseOwner := "71000000-0000-4000-8000-000000000004"
	estimated := int64(256 << 20)
	insertTerminalWorkflow := func(workflow, operation string) int64 {
		t.Helper()
		if _, err := st.DB.ExecContext(ctx, `
			INSERT INTO workflows (
			  id,operation_id,workflow_type,state,user_id,source_node_id,target_node_id,
			  activity_epoch,controller_generation,created_at,updated_at,finished_at
			) VALUES ($1,$2,'snapshot','failed',$3,$4,$5,1,$6,$7,$7,$7)`,
			workflow, operation, globalUserID, sourceNodeID, targetNodeID, generation, now); err != nil {
			t.Fatalf("insert terminal workflow: %v", err)
		}
		var jobID int64
		if err := st.DB.QueryRowContext(ctx, `
			INSERT INTO backup_jobs (
			  user_id,src_node_id,dst_node_id,trigger,status,workflow_id,created_at
			) VALUES ($1,$2,$3,'storage_repair','failed',$4,$5) RETURNING id`,
			legacyUserID, sourceNodeID, targetNodeID, workflow, now).Scan(&jobID); err != nil {
			t.Fatalf("insert repair job: %v", err)
		}
		return jobID
	}
	jobID := insertTerminalWorkflow(workflowID, "71000000-0000-4000-8000-000000000005")
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO storage_repair_tasks (
		  id,user_id,legacy_user_id,source_node_id,target_node_id,
		  estimated_bytes,reserved_bytes,state,attempt,next_attempt_at,
		  execution_id,lease_owner,lease_until,controller_generation,
		  workflow_id,backup_job_id,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$6,'workflow_running',1,$7,$8,$9,$10,$11,$12,$13,$7,$7)`,
		taskID, globalUserID, legacyUserID, sourceNodeID, targetNodeID, estimated,
		now, executionID, leaseOwner, now.Add(time.Hour), generation, workflowID, jobID); err != nil {
		t.Fatalf("insert running repair task: %v", err)
	}

	if changed, err := st.ReconcileStorageRepairTasks(ctx, now, 3); err != nil || changed != 1 {
		t.Fatalf("first terminal reconcile changed=%d err=%v", changed, err)
	}
	var state string
	var reserved int64
	var target sql.NullInt64
	var lastTarget sql.NullInt64
	var owner sql.NullString
	var lease sql.NullTime
	var currentWorkflow sql.NullString
	var lastWorkflow sql.NullString
	var nextAttempt time.Time
	var finished sql.NullTime
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state,reserved_bytes,target_node_id,last_target_node_id,lease_owner::text,
		  lease_until,workflow_id::text,last_workflow_id::text,next_attempt_at,finished_at
		FROM storage_repair_tasks WHERE id=$1`, taskID).Scan(
		&state, &reserved, &target, &lastTarget, &owner, &lease,
		&currentWorkflow, &lastWorkflow, &nextAttempt, &finished,
	); err != nil {
		t.Fatalf("read retried repair task: %v", err)
	}
	if state != "retry_wait" || reserved != 0 || target.Valid || !lastTarget.Valid ||
		lastTarget.Int64 != targetNodeID || owner.Valid || lease.Valid || currentWorkflow.Valid ||
		!lastWorkflow.Valid || lastWorkflow.String != workflowID || !nextAttempt.After(now) || finished.Valid {
		t.Fatalf("invalid retry facts state=%s reserved=%d target=%v lastTarget=%v owner=%v lease=%v workflow=%v last=%v next=%s finished=%v",
			state, reserved, target, lastTarget, owner, lease, currentWorkflow, lastWorkflow, nextAttempt, finished)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO storage_repair_tasks (
		  user_id,legacy_user_id,source_node_id,estimated_bytes,state,next_attempt_at,created_at,updated_at
		) VALUES ($1,$2,$3,1,'pending',$4,$4,$4)`,
		globalUserID, legacyUserID, sourceNodeID, now); err == nil {
		t.Fatal("partial unique index accepted a second active repair intent")
	}

	secondWorkflowID := "71000000-0000-4000-8000-000000000006"
	secondExecutionID := "71000000-0000-4000-8000-000000000007"
	secondLeaseOwner := "71000000-0000-4000-8000-000000000008"
	secondJobID := insertTerminalWorkflow(secondWorkflowID, "71000000-0000-4000-8000-000000000009")
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE storage_repair_tasks SET state='workflow_running',attempt=3,
		  target_node_id=$2,reserved_bytes=estimated_bytes,execution_id=$3,
		  lease_owner=$4,lease_until=$5,controller_generation=$6,
		  workflow_id=$7,backup_job_id=$8,updated_at=$9
		WHERE id=$1`, taskID, targetNodeID, secondExecutionID, secondLeaseOwner,
		now.Add(time.Hour), generation, secondWorkflowID, secondJobID, now); err != nil {
		t.Fatalf("prepare exhausted repair attempt: %v", err)
	}
	if changed, err := st.ReconcileStorageRepairTasks(ctx, now.Add(time.Second), 3); err != nil || changed != 1 {
		t.Fatalf("final terminal reconcile changed=%d err=%v", changed, err)
	}
	var auditCount int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM audit_events
		WHERE action='storage-repair' AND target_type='global_user' AND target_id=$1::text`,
		globalUserID).Scan(&auditCount); err != nil {
		t.Fatalf("read repair audit events: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state,reserved_bytes,target_node_id,last_target_node_id,
		  lease_owner::text,lease_until,workflow_id::text,finished_at
		FROM storage_repair_tasks WHERE id=$1`, taskID).Scan(
		&state, &reserved, &target, &lastTarget, &owner, &lease, &currentWorkflow, &finished,
	); err != nil {
		t.Fatalf("read failed repair task: %v", err)
	}
	if state != "failed" || reserved != 0 || target.Valid || !lastTarget.Valid ||
		lastTarget.Int64 != targetNodeID || owner.Valid || lease.Valid || currentWorkflow.Valid ||
		!finished.Valid || auditCount != 2 {
		t.Fatalf("invalid terminal facts state=%s reserved=%d target=%v lastTarget=%v owner=%v lease=%v workflow=%v finished=%v audits=%d",
			state, reserved, target, lastTarget, owner, lease, currentWorkflow, finished, auditCount)
	}
}
