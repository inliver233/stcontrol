package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func snapshotCompletionParams(now time.Time) CompleteSnapshotWorkflowParams {
	return CompleteSnapshotWorkflowParams{
		WorkflowID: "workflow", SnapshotID: "snapshot", CapabilityHash: make([]byte, 32),
		TargetNodeID: 9, ReplicaKind: "hot_standby", ReplicaOrigin: "configured",
		ManifestSHA256: make([]byte, 32), ArchiveSHA256: make([]byte, 32),
		FileCount: 2, TotalBytes: 30, Now: now,
	}
}

func expectSnapshotCompletionHeader(
	mock sqlmock.Sqlmock,
	p CompleteSnapshotWorkflowParams,
	state string,
	workflowGeneration int64,
) {
	mock.ExpectQuery(`SELECT workflow.user_id, global_user.legacy_user_id`).WithArgs(p.WorkflowID).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "legacy_user_id", "controller_generation", "state"}).
			AddRow(int64(70), int64(7), workflowGeneration, state))
}

func expectSnapshotCompletionPublishPrefix(mock sqlmock.Sqlmock, p CompleteSnapshotWorkflowParams) {
	mock.ExpectBegin()
	expectSnapshotCompletionHeader(mock, p, "publishing", 3)
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(3)))
	mock.ExpectExec(`UPDATE snapshot_manifests`).
		WithArgs(p.SnapshotID, p.WorkflowID, p.ManifestSHA256, p.ArchiveSHA256, p.FileCount, p.TotalBytes).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT snapshot_id FROM replica_copies`).WithArgs(int64(70), p.TargetNodeID).
		WillReturnRows(sqlmock.NewRows([]string{"snapshot_id"}))
	mock.ExpectQuery(`SELECT COALESCE\(MAX\(data_version\),0\)\+1`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"data_version"}).AddRow(int64(5)))
	mock.ExpectExec(`UPDATE replica_cleanup_tasks SET state='cancelled'`).WithArgs(int64(70), p.TargetNodeID, p.Now).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`(?s)SELECT EXISTS \(.*FROM replica_cleanup_tasks.*state='running'`).
		WithArgs(int64(70), p.TargetNodeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec(`INSERT INTO replica_copies`).
		WithArgs(int64(70), p.TargetNodeID, p.SnapshotID, p.ReplicaKind, p.ReplicaOrigin, p.Now,
			p.Now.Add(ReplicaIntegrityLightInterval), p.Now.Add(ReplicaIntegrityDeepInterval)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE alerts SET state='resolved'`).WithArgs(int64(70), p.TargetNodeID, p.Now).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func TestCompleteSnapshotWorkflowFencesStateAndControllerGeneration(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 5, 0, 0, 0, time.UTC)
	tests := []struct {
		name               string
		state              string
		workflowGeneration int64
		activeGeneration   int64
		dataVersion        any
	}{
		{name: "completed workflow without published version", state: "succeeded", workflowGeneration: 3, dataVersion: nil},
		{name: "wrong workflow state", state: "verifying", workflowGeneration: 3},
		{name: "stale controller generation", state: "publishing", workflowGeneration: 2, activeGeneration: 3},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := snapshotCompletionParams(now)
			mock.ExpectBegin()
			expectSnapshotCompletionHeader(mock, p, tc.state, tc.workflowGeneration)
			if tc.state == "succeeded" {
				mock.ExpectQuery(`SELECT data_version FROM backup_jobs`).WithArgs(p.WorkflowID).
					WillReturnRows(sqlmock.NewRows([]string{"data_version"}).AddRow(tc.dataVersion))
			} else if tc.state == "publishing" {
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
					WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(tc.activeGeneration))
			}
			mock.ExpectRollback()
			if _, err := st.CompleteSnapshotWorkflow(context.Background(), p); !errors.Is(err, ErrSnapshotStateConflict) {
				t.Fatalf("err=%v, want ErrSnapshotStateConflict", err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestCompleteSnapshotWorkflowRejectsLostManifestFence(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := snapshotCompletionParams(time.Date(2026, 8, 24, 5, 5, 0, 0, time.UTC))
	mock.ExpectBegin()
	expectSnapshotCompletionHeader(mock, p, "publishing", 3)
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(3)))
	mock.ExpectExec(`UPDATE snapshot_manifests`).
		WithArgs(p.SnapshotID, p.WorkflowID, p.ManifestSHA256, p.ArchiveSHA256, p.FileCount, p.TotalBytes).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()
	if _, err := st.CompleteSnapshotWorkflow(context.Background(), p); !errors.Is(err, ErrSnapshotStateConflict) {
		t.Fatalf("err=%v, want ErrSnapshotStateConflict", err)
	}
	assertMockExpectations(t, mock)
}

func TestCompleteSnapshotWorkflowPropagatesReadAndCleanupFailures(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 5, 10, 0, 0, time.UTC)
	sentinel := errors.New("snapshot metadata unavailable")
	for _, stage := range []string{"begin", "workflow", "generation", "old snapshot", "data version", "cleanup cancel", "cleanup running"} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := snapshotCompletionParams(now)
			if stage == "begin" {
				mock.ExpectBegin().WillReturnError(sentinel)
			} else {
				mock.ExpectBegin()
				if stage == "workflow" {
					mock.ExpectQuery(`SELECT workflow.user_id, global_user.legacy_user_id`).WithArgs(p.WorkflowID).
						WillReturnError(sentinel)
				} else {
					expectSnapshotCompletionHeader(mock, p, "publishing", 3)
					if stage == "generation" {
						mock.ExpectQuery(`SELECT generation FROM controller_epochs`).WillReturnError(sentinel)
					} else {
						mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
							WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(3)))
						mock.ExpectExec(`UPDATE snapshot_manifests`).
							WithArgs(p.SnapshotID, p.WorkflowID, p.ManifestSHA256, p.ArchiveSHA256, p.FileCount, p.TotalBytes).
							WillReturnResult(sqlmock.NewResult(0, 1))
						if stage == "old snapshot" {
							mock.ExpectQuery(`SELECT snapshot_id FROM replica_copies`).WithArgs(int64(70), p.TargetNodeID).
								WillReturnError(sentinel)
						} else {
							mock.ExpectQuery(`SELECT snapshot_id FROM replica_copies`).WithArgs(int64(70), p.TargetNodeID).
								WillReturnRows(sqlmock.NewRows([]string{"snapshot_id"}))
							if stage == "data version" {
								mock.ExpectQuery(`SELECT COALESCE\(MAX\(data_version\),0\)\+1`).WithArgs(int64(70)).
									WillReturnError(sentinel)
							} else {
								mock.ExpectQuery(`SELECT COALESCE\(MAX\(data_version\),0\)\+1`).WithArgs(int64(70)).
									WillReturnRows(sqlmock.NewRows([]string{"data_version"}).AddRow(int64(5)))
								cleanup := mock.ExpectExec(`UPDATE replica_cleanup_tasks SET state='cancelled'`).
									WithArgs(int64(70), p.TargetNodeID, p.Now)
								if stage == "cleanup cancel" {
									cleanup.WillReturnError(sentinel)
								} else {
									cleanup.WillReturnResult(sqlmock.NewResult(0, 0))
									mock.ExpectQuery(`(?s)SELECT EXISTS \(.*FROM replica_cleanup_tasks.*state='running'`).
										WithArgs(int64(70), p.TargetNodeID).WillReturnError(sentinel)
								}
							}
						}
					}
				}
				mock.ExpectRollback()
			}
			if _, err := st.CompleteSnapshotWorkflow(context.Background(), p); !errors.Is(err, sentinel) {
				t.Fatalf("stage=%q err=%v, want sentinel", stage, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestCompleteSnapshotWorkflowRollsBackFencedPublicationRows(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 5, 15, 0, 0, time.UTC)
	for _, stage := range []string{"capability", "backup job", "replica projection"} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := snapshotCompletionParams(now)
			expectSnapshotCompletionPublishPrefix(mock, p)
			capabilityRows := int64(1)
			if stage == "capability" {
				capabilityRows = 0
			}
			mock.ExpectExec(`UPDATE snapshot_transfer_capabilities`).WithArgs(p.WorkflowID, p.Now, p.CapabilityHash).
				WillReturnResult(sqlmock.NewResult(0, capabilityRows))
			if stage != "capability" {
				backupRows := int64(1)
				if stage == "backup job" {
					backupRows = 0
				}
				mock.ExpectExec(`UPDATE backup_jobs SET status='done'`).
					WithArgs(p.WorkflowID, int64(5), p.TotalBytes, p.FileCount, p.Now).
					WillReturnResult(sqlmock.NewResult(0, backupRows))
				if stage == "replica projection" {
					mock.ExpectExec(`UPDATE user_replicas SET state='ready'`).
						WithArgs(int64(7), p.TargetNodeID, int64(5), strings.Repeat("0", 64), p.TotalBytes, p.Now).
						WillReturnResult(sqlmock.NewResult(0, 0))
				}
			}
			mock.ExpectRollback()
			if _, err := st.CompleteSnapshotWorkflow(context.Background(), p); !errors.Is(err, ErrSnapshotStateConflict) {
				t.Fatalf("stage=%q err=%v, want ErrSnapshotStateConflict", stage, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}
