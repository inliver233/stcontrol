package store

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

const (
	restoreCompletionOperationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	restoreCompletionSourceID    = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
)

func restoreCompletionParams(now time.Time) CompleteRestoreWorkflowParams {
	return CompleteRestoreWorkflowParams{
		WorkflowID:        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		RestoreSnapshotID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		CapabilityHash:    bytes.Repeat([]byte{2}, 32),
		ManifestSHA256:    bytes.Repeat([]byte{4}, 32),
		ArchiveSHA256:     bytes.Repeat([]byte{5}, 32),
		FileCount:         3,
		TotalBytes:        120,
		Now:               now,
	}
}

func expectRestoreCompletionHeader(
	mock sqlmock.Sqlmock,
	p CompleteRestoreWorkflowParams,
	state, globalStatus, legacyStatus string,
	workflowGeneration int64,
) {
	mock.ExpectQuery(`(?s)SELECT workflow.state,global_user.status,legacy.status.*FROM workflows workflow`).
		WithArgs(p.WorkflowID, p.RestoreSnapshotID).
		WillReturnRows(sqlmock.NewRows([]string{
			"state", "global_status", "legacy_status", "operation_id", "user_id", "legacy_user_id",
			"source_node_id", "target_node_id", "home_node_id", "generation", "source_snapshot_id", "published_at",
		}).AddRow(state, globalStatus, legacyStatus, restoreCompletionOperationID,
			int64(70), int64(7), int64(10), int64(9), int64(8), workflowGeneration,
			restoreCompletionSourceID, p.Now.Add(-2*time.Hour)))
}

func expectRestoreCompletionReadyThroughAccounts(mock sqlmock.Sqlmock, p CompleteRestoreWorkflowParams) {
	expectRestoreCompletionHeader(mock, p, "publishing", "active", "active", 4)
	mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("recovery_available"))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
	mock.ExpectQuery(`SELECT user_id, writer_node_id`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
	mock.ExpectQuery(`(?s)SELECT copy.snapshot_id::text FROM replica_copies copy.*copy.published_at=\$4`).
		WithArgs(int64(70), int64(10), restoreCompletionSourceID, p.Now.Add(-2*time.Hour)).
		WillReturnRows(sqlmock.NewRows([]string{"snapshot_id"}).AddRow(restoreCompletionSourceID))
	mock.ExpectQuery(`(?s)SELECT account.id FROM node_accounts account.*account.status='active'`).
		WithArgs(int64(70), int64(9)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(22)))
}

func TestCompleteRestoreWorkflowRejectsInvalidResultMetadata(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 2, 0, 0, 0, time.UTC)
	valid := restoreCompletionParams(now)
	tests := map[string]func(*CompleteRestoreWorkflowParams){
		"missing workflow":       func(p *CompleteRestoreWorkflowParams) { p.WorkflowID = "" },
		"missing snapshot":       func(p *CompleteRestoreWorkflowParams) { p.RestoreSnapshotID = "" },
		"capability digest":      func(p *CompleteRestoreWorkflowParams) { p.CapabilityHash = p.CapabilityHash[:31] },
		"manifest digest":        func(p *CompleteRestoreWorkflowParams) { p.ManifestSHA256 = p.ManifestSHA256[:31] },
		"archive digest":         func(p *CompleteRestoreWorkflowParams) { p.ArchiveSHA256 = p.ArchiveSHA256[:31] },
		"negative file count":    func(p *CompleteRestoreWorkflowParams) { p.FileCount = -1 },
		"negative archive bytes": func(p *CompleteRestoreWorkflowParams) { p.TotalBytes = -1 },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := valid
			mutate(&p)
			if err := (&Store{}).CompleteRestoreWorkflow(context.Background(), p); !errors.Is(err, ErrInvalidRestoreWorkflow) {
				t.Fatalf("err=%v, want ErrInvalidRestoreWorkflow", err)
			}
		})
	}
}

func TestCompleteRestoreWorkflowFencesInvalidWorkflowStateAndGeneration(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 2, 5, 0, 0, time.UTC)
	tests := []struct {
		name               string
		state              string
		globalStatus       string
		legacyStatus       string
		workflowGeneration int64
		activeGeneration   int64
		want               error
	}{
		{name: "already complete is idempotent", state: "succeeded", globalStatus: "active", legacyStatus: "active", workflowGeneration: 4},
		{name: "wrong workflow state", state: "transferring", globalStatus: "active", legacyStatus: "active", workflowGeneration: 4, want: ErrRestoreConflict},
		{name: "disabled global identity", state: "publishing", globalStatus: "disabled", legacyStatus: "active", workflowGeneration: 4, want: ErrRestoreConflict},
		{name: "disabled legacy identity", state: "publishing", globalStatus: "active", legacyStatus: "disabled", workflowGeneration: 4, want: ErrRestoreConflict},
		{name: "stale controller generation", state: "publishing", globalStatus: "active", legacyStatus: "active", workflowGeneration: 3, activeGeneration: 4, want: ErrRestoreConflict},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := restoreCompletionParams(now)
			mock.ExpectBegin()
			expectRestoreCompletionHeader(mock, p, tc.state, tc.globalStatus, tc.legacyStatus, tc.workflowGeneration)
			if tc.state == "succeeded" {
				mock.ExpectCommit()
			} else {
				if tc.state == "publishing" && tc.globalStatus == "active" && tc.legacyStatus == "active" {
					mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(int64(70)).
						WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("recovery_available"))
					mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
						WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(tc.activeGeneration))
				}
				mock.ExpectRollback()
			}
			err := st.CompleteRestoreWorkflow(context.Background(), p)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v, want %v", err, tc.want)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestCompleteRestoreWorkflowPropagatesTransactionalPreconditionFailures(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 2, 10, 0, 0, time.UTC)
	sentinel := errors.New("database unavailable")
	tests := []struct {
		name  string
		setup func(sqlmock.Sqlmock, CompleteRestoreWorkflowParams)
		want  error
	}{
		{
			name: "begin",
			setup: func(mock sqlmock.Sqlmock, _ CompleteRestoreWorkflowParams) {
				mock.ExpectBegin().WillReturnError(sentinel)
			},
			want: sentinel,
		},
		{
			name: "workflow lookup",
			setup: func(mock sqlmock.Sqlmock, p CompleteRestoreWorkflowParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`(?s)SELECT workflow.state,global_user.status,legacy.status.*FROM workflows workflow`).
					WithArgs(p.WorkflowID, p.RestoreSnapshotID).WillReturnError(sentinel)
				mock.ExpectRollback()
			},
			want: sentinel,
		},
		{
			name: "fault not recoverable",
			setup: func(mock sqlmock.Sqlmock, p CompleteRestoreWorkflowParams) {
				mock.ExpectBegin()
				expectRestoreCompletionHeader(mock, p, "publishing", "active", "active", 4)
				mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(int64(70)).
					WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("detected"))
				mock.ExpectRollback()
			},
			want: ErrUserDataFaultState,
		},
		{
			name: "fault lookup",
			setup: func(mock sqlmock.Sqlmock, p CompleteRestoreWorkflowParams) {
				mock.ExpectBegin()
				expectRestoreCompletionHeader(mock, p, "publishing", "active", "active", 4)
				mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(int64(70)).WillReturnError(sentinel)
				mock.ExpectRollback()
			},
			want: sentinel,
		},
		{
			name: "active generation lookup",
			setup: func(mock sqlmock.Sqlmock, p CompleteRestoreWorkflowParams) {
				mock.ExpectBegin()
				expectRestoreCompletionHeader(mock, p, "publishing", "active", "active", 4)
				mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(int64(70)).
					WillReturnRows(sqlmock.NewRows([]string{"state"}))
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).WillReturnError(sentinel)
				mock.ExpectRollback()
			},
			want: sentinel,
		},
		{
			name: "writer lease lookup",
			setup: func(mock sqlmock.Sqlmock, p CompleteRestoreWorkflowParams) {
				mock.ExpectBegin()
				expectRestoreCompletionHeader(mock, p, "publishing", "active", "active", 4)
				mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(int64(70)).
					WillReturnRows(sqlmock.NewRows([]string{"state"}))
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
					WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
				mock.ExpectQuery(`SELECT user_id, writer_node_id`).WithArgs(int64(70)).WillReturnError(sentinel)
				mock.ExpectRollback()
			},
			want: sentinel,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := restoreCompletionParams(now)
			tc.setup(mock, p)
			err := st.CompleteRestoreWorkflow(context.Background(), p)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v, want %v", err, tc.want)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestCompleteRestoreWorkflowRequiresVerifiedSourceAndEligibleTarget(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 2, 15, 0, 0, time.UTC)
	for _, missing := range []string{"source", "target"} {
		missing := missing
		t.Run(missing, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := restoreCompletionParams(now)
			mock.ExpectBegin()
			expectRestoreCompletionHeader(mock, p, "publishing", "active", "active", 4)
			mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(int64(70)).
				WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("recovery_available"))
			mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
				WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
			mock.ExpectQuery(`SELECT user_id, writer_node_id`).WithArgs(int64(70)).
				WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
			source := mock.ExpectQuery(`(?s)SELECT copy.snapshot_id::text FROM replica_copies copy.*copy.published_at=\$4`).
				WithArgs(int64(70), int64(10), restoreCompletionSourceID, p.Now.Add(-2*time.Hour))
			if missing == "source" {
				source.WillReturnError(sql.ErrNoRows)
			} else {
				source.WillReturnRows(sqlmock.NewRows([]string{"snapshot_id"}).AddRow(restoreCompletionSourceID))
				mock.ExpectQuery(`(?s)SELECT account.id FROM node_accounts account.*account.status='active'`).
					WithArgs(int64(70), int64(9)).WillReturnError(sql.ErrNoRows)
			}
			mock.ExpectRollback()
			if err := st.CompleteRestoreWorkflow(context.Background(), p); !errors.Is(err, ErrRestoreUnavailable) {
				t.Fatalf("err=%v, want ErrRestoreUnavailable", err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func expectRestoreCompletionPublishUntil(
	mock sqlmock.Sqlmock,
	p CompleteRestoreWorkflowParams,
	stop string,
) {
	expectRestoreCompletionReadyThroughAccounts(mock, p)
	if expectRestoreMutation(mock, `UPDATE snapshot_manifests`, stop, "snapshot", p.RestoreSnapshotID,
		p.WorkflowID, p.ManifestSHA256, p.ArchiveSHA256, p.FileCount, p.TotalBytes) {
		return
	}
	mock.ExpectQuery(`SELECT COALESCE\(MAX\(data_version\),0\)\+1`).WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"data_version"}).AddRow(int64(6)))
	if expectRestoreMutation(mock, `UPDATE user_replicas SET kind='hot_standby'`, stop, "old home", int64(7), int64(8)) {
		return
	}
	if expectRestoreMutation(mock, `UPDATE user_replicas SET kind='home'`, stop, "target home",
		int64(7), int64(9), int64(6), "0404040404040404040404040404040404040404040404040404040404040404", p.TotalBytes, p.Now) {
		return
	}
	if expectRestoreMutation(mock, `UPDATE users SET home_node_id`, stop, "legacy home", int64(7), int64(9)) {
		return
	}
	mock.ExpectExec(`UPDATE replica_copies SET is_authoritative=false`).WithArgs(int64(70), int64(8), p.Now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO replica_copies`).WithArgs(int64(70), int64(9), p.RestoreSnapshotID, p.Now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if expectRestoreMutation(mock, `UPDATE node_accounts`, stop, "node accounts", int64(70), int64(9), p.Now, int64(8)) {
		return
	}
	mock.ExpectExec(`UPDATE user_activity_leases`).WithArgs(int64(70), p.Now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE control_tickets`).WithArgs(int64(70), p.Now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if expectRestoreMutation(mock, `UPDATE snapshot_transfer_capabilities`, stop, "capability", p.WorkflowID, p.Now, p.CapabilityHash) {
		return
	}
	if expectRestoreMutation(mock, `UPDATE workflows SET state='succeeded'`, stop, "workflow", p.WorkflowID, p.Now) {
		return
	}
	mock.ExpectExec(`UPDATE workflow_steps SET state='succeeded'`).WithArgs(p.WorkflowID, p.Now).
		WillReturnResult(sqlmock.NewResult(0, 5))
	if expectRestoreMutation(mock, `UPDATE restore_operations SET completed_at`, stop, "operation", p.WorkflowID, p.Now) {
		return
	}
}

func expectRestoreMutation(mock sqlmock.Sqlmock, expression, stop, stage string, args ...driver.Value) bool {
	expected := mock.ExpectExec(expression).WithArgs(args...)
	if stop == stage {
		expected.WillReturnResult(sqlmock.NewResult(0, 0))
		return true
	}
	expected.WillReturnResult(sqlmock.NewResult(0, 1))
	return false
}

func TestCompleteRestoreWorkflowRollsBackEveryFencedPublishMutation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 2, 20, 0, 0, time.UTC)
	stages := []string{
		"snapshot", "old home", "target home", "legacy home", "node accounts",
		"capability", "workflow", "operation",
	}
	for _, stage := range stages {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := restoreCompletionParams(now)
			mock.ExpectBegin()
			expectRestoreCompletionPublishUntil(mock, p, stage)
			mock.ExpectRollback()
			if err := st.CompleteRestoreWorkflow(context.Background(), p); !errors.Is(err, ErrRestoreConflict) {
				t.Fatalf("stage=%q err=%v, want ErrRestoreConflict", stage, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func expectRestoreInjectedExec(
	mock sqlmock.Sqlmock,
	expression, stage, current string,
	injected error,
	args ...driver.Value,
) bool {
	expected := mock.ExpectExec(expression).WithArgs(args...)
	switch stage {
	case current + " exec":
		expected.WillReturnError(injected)
		return true
	case current + " rows":
		expected.WillReturnResult(sqlmock.NewErrorResult(injected))
		return true
	default:
		expected.WillReturnResult(sqlmock.NewResult(0, 1))
		return false
	}
}

func expectRestoreCompletionInjectedFailure(
	mock sqlmock.Sqlmock,
	p CompleteRestoreWorkflowParams,
	stage string,
	injected error,
) {
	expectRestoreCompletionReadyThroughAccounts(mock, p)
	if expectRestoreInjectedExec(mock, `UPDATE snapshot_manifests`, stage, "snapshot", injected,
		p.RestoreSnapshotID, p.WorkflowID, p.ManifestSHA256, p.ArchiveSHA256, p.FileCount, p.TotalBytes) {
		return
	}
	dataVersion := mock.ExpectQuery(`SELECT COALESCE\(MAX\(data_version\),0\)\+1`).WithArgs(int64(7))
	if stage == "data version query" {
		dataVersion.WillReturnError(injected)
		return
	}
	dataVersion.WillReturnRows(sqlmock.NewRows([]string{"data_version"}).AddRow(int64(6)))
	if expectRestoreInjectedExec(mock, `UPDATE user_replicas SET kind='hot_standby'`, stage, "old home", injected,
		int64(7), int64(8)) {
		return
	}
	if expectRestoreInjectedExec(mock, `UPDATE user_replicas SET kind='home'`, stage, "target home", injected,
		int64(7), int64(9), int64(6),
		"0404040404040404040404040404040404040404040404040404040404040404", p.TotalBytes, p.Now) {
		return
	}
	if expectRestoreInjectedExec(mock, `UPDATE users SET home_node_id`, stage, "legacy home", injected,
		int64(7), int64(9)) {
		return
	}
	if expectRestoreInjectedExec(mock, `UPDATE replica_copies SET is_authoritative=false`, stage, "old copies", injected,
		int64(70), int64(8), p.Now) {
		return
	}
	if expectRestoreInjectedExec(mock, `INSERT INTO replica_copies`, stage, "new copy", injected,
		int64(70), int64(9), p.RestoreSnapshotID, p.Now) {
		return
	}
	if expectRestoreInjectedExec(mock, `UPDATE node_accounts`, stage, "node accounts", injected,
		int64(70), int64(9), p.Now, int64(8)) {
		return
	}
	if expectRestoreInjectedExec(mock, `UPDATE user_activity_leases`, stage, "lease", injected,
		int64(70), p.Now) {
		return
	}
	if expectRestoreInjectedExec(mock, `UPDATE control_tickets`, stage, "tickets", injected,
		int64(70), p.Now) {
		return
	}
	if expectRestoreInjectedExec(mock, `UPDATE snapshot_transfer_capabilities`, stage, "capability", injected,
		p.WorkflowID, p.Now, p.CapabilityHash) {
		return
	}
	if expectRestoreInjectedExec(mock, `UPDATE workflows SET state='succeeded'`, stage, "workflow", injected,
		p.WorkflowID, p.Now) {
		return
	}
	if expectRestoreInjectedExec(mock, `UPDATE workflow_steps SET state='succeeded'`, stage, "steps", injected,
		p.WorkflowID, p.Now) {
		return
	}
	if expectRestoreInjectedExec(mock, `UPDATE restore_operations SET completed_at`, stage, "operation", injected,
		p.WorkflowID, p.Now) {
		return
	}
	if expectRestoreInjectedExec(mock, `INSERT INTO user_protection_states`, stage, "protection", injected,
		int64(70), int64(9), p.Now) {
		return
	}
	if expectRestoreInjectedExec(mock, `UPDATE user_data_faults SET state='resolved'`, stage, "resolve fault", injected,
		int64(70), "restore", restoreCompletionOperationID, p.Now) {
		return
	}
	if expectRestoreInjectedExec(mock, `UPDATE alerts SET state='resolved'`, stage, "resolve alert", injected,
		int64(70), p.Now) {
		return
	}
	if expectRestoreInjectedExec(mock, `INSERT INTO audit_events`, stage, "audit", injected,
		int64(70), restoreCompletionOperationID, int64(4), int64(10), int64(9),
		restoreCompletionSourceID, p.Now.Add(-2*time.Hour), p.RestoreSnapshotID, p.WorkflowID) {
		return
	}
	panic("unhandled restore completion failure stage: " + stage)
}

func TestCompleteRestoreWorkflowPropagatesEveryPublishWriteFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 8, 40, 0, 0, time.UTC)
	injected := errors.New("injected restore publish failure")
	stages := []string{
		"snapshot exec", "snapshot rows", "data version query",
		"old home exec", "old home rows", "target home exec", "target home rows",
		"legacy home exec", "legacy home rows", "old copies exec", "new copy exec",
		"node accounts exec", "node accounts rows", "lease exec", "tickets exec",
		"capability exec", "capability rows", "workflow exec", "workflow rows",
		"steps exec", "operation exec", "operation rows", "protection exec",
		"resolve fault exec", "resolve alert exec", "audit exec", "audit rows",
	}
	for _, stage := range stages {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := restoreCompletionParams(now)
			mock.ExpectBegin()
			expectRestoreCompletionInjectedFailure(mock, p, stage, injected)
			mock.ExpectRollback()
			if err := st.CompleteRestoreWorkflow(context.Background(), p); !errors.Is(err, injected) {
				t.Fatalf("stage=%q error=%v, want injected failure", stage, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}
