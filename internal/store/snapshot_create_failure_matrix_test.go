package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func expectSnapshotCreateIdentityAndGeneration(
	mock sqlmock.Sqlmock,
	p CreateSnapshotWorkflowParams,
) {
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.GlobalUserID))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(3)))
}

func expectSnapshotCreateNormalPrefix(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
	expectSnapshotCreateIdentityAndGeneration(mock, p)
	mock.ExpectQuery(`(?s)SELECT source.role='compute'.*FROM nodes source CROSS JOIN nodes target`).
		WithArgs(p.SourceNodeID, p.TargetNodeID, p.DestinationKind, p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"source_eligible", "target_eligible"}).AddRow(true, true))
	mock.ExpectQuery(`(?s)SELECT EXISTS \(.*FROM replica_cleanup_tasks cleanup`).
		WithArgs(p.GlobalUserID, p.SourceNodeID, p.TargetNodeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery(`SELECT activity_epoch, writer_node_id, lease_expires_at`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{
			"activity_epoch", "writer_node_id", "lease_expires_at", "in_flight_reads", "in_flight_writes", "state",
		}))
}

func expectSnapshotCreateWorkflowInsert(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
	mock.ExpectExec(`INSERT INTO workflows`).
		WithArgs(p.WorkflowID, p.OperationID, p.GlobalUserID, p.SourceNodeID, p.TargetNodeID, int64(1), int64(3), p.Now).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectSnapshotCreateSteps(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
	for _, step := range []string{"quiesce", "snapshot", "prepare_target", "transfer", "verify", "publish", "cleanup"} {
		mock.ExpectExec(`INSERT INTO workflow_steps`).WithArgs(p.WorkflowID, step, "pending", p.Now).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
}

func expectSnapshotCreateManifest(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
	mock.ExpectExec(`INSERT INTO snapshot_manifests`).
		WithArgs(p.SnapshotID, p.WorkflowID, p.GlobalUserID, p.SourceNodeID, int64(1), make([]byte, 32), p.Now).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectSnapshotCreateCapability(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
	mock.ExpectExec(`INSERT INTO snapshot_transfer_capabilities`).
		WithArgs(
			p.CapabilityID, p.WorkflowID, p.SnapshotID, p.SourceNodeID, p.TargetNodeID,
			p.CapabilityHash, int64(3), p.CapabilityExpires, p.Now,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectSnapshotCreateBackupUpdate(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams, result sql.Result) {
	mock.ExpectExec(`UPDATE backup_jobs SET workflow_id`).
		WithArgs(
			p.LegacyBackupJobID, p.WorkflowID, p.SnapshotID, int64(1),
			p.LegacyUserID, p.SourceNodeID, p.TargetNodeID,
		).
		WillReturnResult(result)
}

func TestCreateSnapshotWorkflowRejectsInvalidScopeMatrix(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*CreateSnapshotWorkflowParams)
	}{
		{name: "same source and target", mutate: func(p *CreateSnapshotWorkflowParams) { p.TargetNodeID = p.SourceNodeID }},
		{name: "invalid retirement identity", mutate: func(p *CreateSnapshotWorkflowParams) {
			p.LegacyBackupJobID = 0
			p.RetirementItemID = "not-a-uuid"
			p.RetirementTrigger = "node_retirement"
		}},
		{name: "partial independent reconciliation", mutate: func(p *CreateSnapshotWorkflowParams) {
			p.IndependentReconciliationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		}},
		{name: "expired capability", mutate: func(p *CreateSnapshotWorkflowParams) { p.CapabilityExpires = now }},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := snapshotWorkflowParams(now)
			tc.mutate(&p)
			if _, err := st.CreateSnapshotWorkflow(context.Background(), p); !errors.Is(err, ErrInvalidSnapshotWorkflow) {
				t.Fatalf("error=%v, want ErrInvalidSnapshotWorkflow", err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestCreateSnapshotWorkflowFencesTransactionalPreconditions(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 8, 5, 0, 0, time.UTC)
	injected := errors.New("injected snapshot create failure")
	tests := []struct {
		name    string
		setup   func(sqlmock.Sqlmock, CreateSnapshotWorkflowParams)
		wantErr error
	}{
		{
			name: "begin failure",
			setup: func(mock sqlmock.Sqlmock, _ CreateSnapshotWorkflowParams) {
				mock.ExpectBegin().WillReturnError(injected)
			},
			wantErr: injected,
		},
		{
			name: "unknown global user",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.GlobalUserID).WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			},
			wantErr: ErrInvalidSnapshotWorkflow,
		},
		{
			name: "global user read failure",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.GlobalUserID).WillReturnError(injected)
				mock.ExpectRollback()
			},
			wantErr: injected,
		},
		{
			name: "no active controller",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.GlobalUserID).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.GlobalUserID))
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			},
			wantErr: ErrNoActiveController,
		},
		{
			name: "controller generation read failure",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.GlobalUserID).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.GlobalUserID))
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).WillReturnError(injected)
				mock.ExpectRollback()
			},
			wantErr: injected,
		},
		{
			name: "node eligibility read failure",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateIdentityAndGeneration(mock, p)
				mock.ExpectQuery(`(?s)SELECT source.role='compute'.*FROM nodes source CROSS JOIN nodes target`).
					WithArgs(p.SourceNodeID, p.TargetNodeID, p.DestinationKind, p.GlobalUserID).
					WillReturnError(injected)
				mock.ExpectRollback()
			},
			wantErr: injected,
		},
		{
			name: "ineligible target",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateIdentityAndGeneration(mock, p)
				mock.ExpectQuery(`(?s)SELECT source.role='compute'.*FROM nodes source CROSS JOIN nodes target`).
					WithArgs(p.SourceNodeID, p.TargetNodeID, p.DestinationKind, p.GlobalUserID).
					WillReturnRows(sqlmock.NewRows([]string{"source_eligible", "target_eligible"}).AddRow(true, false))
				mock.ExpectRollback()
			},
			wantErr: ErrInvalidSnapshotWorkflow,
		},
		{
			name: "cleanup query failure",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateIdentityAndGeneration(mock, p)
				mock.ExpectQuery(`(?s)SELECT source.role='compute'.*FROM nodes source CROSS JOIN nodes target`).
					WillReturnRows(sqlmock.NewRows([]string{"source_eligible", "target_eligible"}).AddRow(true, true))
				mock.ExpectQuery(`(?s)SELECT EXISTS \(.*FROM replica_cleanup_tasks cleanup`).WillReturnError(injected)
				mock.ExpectRollback()
			},
			wantErr: injected,
		},
		{
			name: "cleanup collision",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateIdentityAndGeneration(mock, p)
				mock.ExpectQuery(`(?s)SELECT source.role='compute'.*FROM nodes source CROSS JOIN nodes target`).
					WillReturnRows(sqlmock.NewRows([]string{"source_eligible", "target_eligible"}).AddRow(true, true))
				mock.ExpectQuery(`(?s)SELECT EXISTS \(.*FROM replica_cleanup_tasks cleanup`).
					WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
				mock.ExpectRollback()
			},
			wantErr: ErrSnapshotStateConflict,
		},
		{
			name: "lease read failure",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateIdentityAndGeneration(mock, p)
				mock.ExpectQuery(`(?s)SELECT source.role='compute'.*FROM nodes source CROSS JOIN nodes target`).
					WillReturnRows(sqlmock.NewRows([]string{"source_eligible", "target_eligible"}).AddRow(true, true))
				mock.ExpectQuery(`(?s)SELECT EXISTS \(.*FROM replica_cleanup_tasks cleanup`).
					WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
				mock.ExpectQuery(`SELECT activity_epoch, writer_node_id, lease_expires_at`).WillReturnError(injected)
				mock.ExpectRollback()
			},
			wantErr: injected,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := snapshotWorkflowParams(now)
			tc.setup(mock, p)
			_, err := st.CreateSnapshotWorkflow(context.Background(), p)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error=%v, want %v", err, tc.wantErr)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestCreateSnapshotWorkflowRollsBackEveryDurableWriteFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 8, 10, 0, 0, time.UTC)
	injected := errors.New("injected snapshot write failure")
	tests := []struct {
		name  string
		setup func(sqlmock.Sqlmock, CreateSnapshotWorkflowParams)
	}{
		{
			name: "workflow insert",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateNormalPrefix(mock, p)
				mock.ExpectExec(`INSERT INTO workflows`).WillReturnError(injected)
			},
		},
		{
			name: "workflow step insert",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateNormalPrefix(mock, p)
				expectSnapshotCreateWorkflowInsert(mock, p)
				mock.ExpectExec(`INSERT INTO workflow_steps`).WithArgs(p.WorkflowID, "quiesce", "pending", p.Now).
					WillReturnError(injected)
			},
		},
		{
			name: "manifest insert",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateNormalPrefix(mock, p)
				expectSnapshotCreateWorkflowInsert(mock, p)
				expectSnapshotCreateSteps(mock, p)
				mock.ExpectExec(`INSERT INTO snapshot_manifests`).WillReturnError(injected)
			},
		},
		{
			name: "capability insert",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateNormalPrefix(mock, p)
				expectSnapshotCreateWorkflowInsert(mock, p)
				expectSnapshotCreateSteps(mock, p)
				expectSnapshotCreateManifest(mock, p)
				mock.ExpectExec(`INSERT INTO snapshot_transfer_capabilities`).WillReturnError(injected)
			},
		},
		{
			name: "backup update",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateNormalPrefix(mock, p)
				expectSnapshotCreateWorkflowInsert(mock, p)
				expectSnapshotCreateSteps(mock, p)
				expectSnapshotCreateManifest(mock, p)
				expectSnapshotCreateCapability(mock, p)
				mock.ExpectExec(`UPDATE backup_jobs SET workflow_id`).WillReturnError(injected)
			},
		},
		{
			name: "backup affected rows unavailable",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateNormalPrefix(mock, p)
				expectSnapshotCreateWorkflowInsert(mock, p)
				expectSnapshotCreateSteps(mock, p)
				expectSnapshotCreateManifest(mock, p)
				expectSnapshotCreateCapability(mock, p)
				expectSnapshotCreateBackupUpdate(mock, p, sqlmock.NewErrorResult(injected))
			},
		},
		{
			name: "backup binding lost",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateNormalPrefix(mock, p)
				expectSnapshotCreateWorkflowInsert(mock, p)
				expectSnapshotCreateSteps(mock, p)
				expectSnapshotCreateManifest(mock, p)
				expectSnapshotCreateCapability(mock, p)
				expectSnapshotCreateBackupUpdate(mock, p, sqlmock.NewResult(0, 0))
			},
		},
		{
			name: "replica projection",
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateNormalPrefix(mock, p)
				expectSnapshotCreateWorkflowInsert(mock, p)
				expectSnapshotCreateSteps(mock, p)
				expectSnapshotCreateManifest(mock, p)
				expectSnapshotCreateCapability(mock, p)
				expectSnapshotCreateBackupUpdate(mock, p, sqlmock.NewResult(0, 1))
				mock.ExpectExec(`INSERT INTO user_replicas`).WillReturnError(injected)
			},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := snapshotWorkflowParams(now)
			tc.setup(mock, p)
			mock.ExpectRollback()
			if _, err := st.CreateSnapshotWorkflow(context.Background(), p); err == nil {
				t.Fatal("durable write failure was accepted")
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestCreateSnapshotWorkflowRejectsRetirementAndIndependentFacts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 8, 15, 0, 0, time.UTC)
	injected := errors.New("injected special snapshot failure")
	tests := []struct {
		name    string
		params  func() CreateSnapshotWorkflowParams
		setup   func(sqlmock.Sqlmock, CreateSnapshotWorkflowParams)
		wantErr error
	}{
		{
			name: "retirement item query failure",
			params: func() CreateSnapshotWorkflowParams {
				p := snapshotWorkflowParams(now)
				p.LegacyBackupJobID = 0
				p.RetirementItemID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
				p.RetirementTrigger = "node_retirement"
				p.DestinationKind = "hot_standby"
				return p
			},
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateIdentityAndGeneration(mock, p)
				mock.ExpectQuery(`FROM node_retirement_items item`).WithArgs(p.RetirementItemID).WillReturnError(injected)
				mock.ExpectRollback()
			},
			wantErr: injected,
		},
		{
			name: "retirement item identity mismatch",
			params: func() CreateSnapshotWorkflowParams {
				p := snapshotWorkflowParams(now)
				p.LegacyBackupJobID = 0
				p.RetirementItemID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
				p.RetirementTrigger = "node_retirement"
				p.DestinationKind = "hot_standby"
				return p
			},
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateIdentityAndGeneration(mock, p)
				mock.ExpectQuery(`FROM node_retirement_items item`).WithArgs(p.RetirementItemID).
					WillReturnRows(sqlmock.NewRows([]string{
						"node_id", "operation_state", "user_id", "legacy_user_id", "kind", "state", "home", "generation",
					}).AddRow(p.SourceNodeID, "migrating", p.GlobalUserID+1, p.LegacyUserID,
						"authoritative_home", "pending", p.SourceNodeID, int64(3)))
				mock.ExpectRollback()
			},
			wantErr: ErrNodeRetirementState,
		},
		{
			name: "independent reconciliation state mismatch",
			params: func() CreateSnapshotWorkflowParams {
				p := snapshotWorkflowParams(now)
				p.IndependentReconciliationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
				p.IndependentMarker = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
				return p
			},
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateIdentityAndGeneration(mock, p)
				mock.ExpectQuery(`FROM independent_user_reconciliations reconciliation`).
					WithArgs(p.IndependentReconciliationID).
					WillReturnRows(sqlmock.NewRows([]string{
						"user_id", "node_id", "marker", "generation", "mode", "sessions",
					}).AddRow(p.GlobalUserID, p.SourceNodeID, "wrong-marker", int64(3), NodeModeIndependentDraining, 0))
				mock.ExpectRollback()
			},
			wantErr: ErrIndependentReconciliationState,
		},
		{
			name: "independent target unavailable",
			params: func() CreateSnapshotWorkflowParams {
				p := snapshotWorkflowParams(now)
				p.IndependentReconciliationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
				p.IndependentMarker = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
				return p
			},
			setup: func(mock sqlmock.Sqlmock, p CreateSnapshotWorkflowParams) {
				expectSnapshotCreateIdentityAndGeneration(mock, p)
				mock.ExpectQuery(`FROM independent_user_reconciliations reconciliation`).
					WillReturnRows(sqlmock.NewRows([]string{
						"user_id", "node_id", "marker", "generation", "mode", "sessions",
					}).AddRow(p.GlobalUserID, p.SourceNodeID, p.IndependentMarker, int64(3), NodeModeIndependentDraining, 0))
				mock.ExpectQuery(`SELECT role='storage' AND is_backup_target`).WithArgs(p.TargetNodeID).
					WillReturnRows(sqlmock.NewRows([]string{"eligible"}).AddRow(false))
				mock.ExpectRollback()
			},
			wantErr: ErrIndependentReconciliationState,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := tc.params()
			tc.setup(mock, p)
			_, err := st.CreateSnapshotWorkflow(context.Background(), p)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error=%v, want %v", err, tc.wantErr)
			}
			assertMockExpectations(t, mock)
		})
	}
}
