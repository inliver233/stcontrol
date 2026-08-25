package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func conflictResolutionCreateParams(now time.Time) CreateConflictResolutionParams {
	return CreateConflictResolutionParams{
		OperationID:      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		RequestDigest:    bytes.Repeat([]byte{1}, 32),
		WorkflowID:       "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		ConflictID:       "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		ResultSnapshotID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		GlobalUserID:     70, BaseNodeID: 9, ExpectedConflictVersion: 4,
		DefaultAction: "use_base", Now: now,
	}
}

func expectConflictResolutionReplayRow(
	mock sqlmock.Sqlmock,
	p CreateConflictResolutionParams,
	storedUserID, storedBaseNodeID int64,
	storedDigest []byte,
) {
	mock.ExpectQuery(`(?s)SELECT operation.request_digest,operation.user_id,operation.base_node_id.*FROM conflict_resolution_operations operation`).
		WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{
			"request_digest", "user_id", "base_node_id", "workflow_id", "state", "attempt",
			"conflict_id", "conflict_version", "legacy_user_id", "handle", "result_snapshot_id",
			"activity_epoch", "controller_generation", "default_action",
		}).AddRow(storedDigest, storedUserID, storedBaseNodeID, p.WorkflowID, "scheduled", 1,
			p.ConflictID, int64(5), int64(7), "alice", p.ResultSnapshotID, int64(3), int64(4), p.DefaultAction))
}

func TestCreateConflictResolutionReplaysOnlyExactOperation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 7, 0, 0, 0, time.UTC)
	for _, conflict := range []bool{false, true} {
		conflict := conflict
		name := "exact"
		if conflict {
			name = "conflicting scope"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := conflictResolutionCreateParams(now)
			storedBaseNodeID := p.BaseNodeID
			if conflict {
				storedBaseNodeID++
			}
			mock.ExpectBegin()
			expectConflictResolutionReplayRow(mock, p, p.GlobalUserID, storedBaseNodeID, p.RequestDigest)
			if conflict {
				mock.ExpectRollback()
			} else {
				mock.ExpectCommit()
			}
			execution, err := st.CreateConflictResolution(context.Background(), p)
			if conflict {
				if !errors.Is(err, ErrConflictResolutionReplay) || execution != nil {
					t.Fatalf("execution=%+v err=%v, want replay conflict", execution, err)
				}
			} else if err != nil || execution == nil || execution.WorkflowID != p.WorkflowID ||
				execution.ConflictVersion != 5 || execution.LegacyUserID != 7 {
				t.Fatalf("execution=%+v err=%v", execution, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestDeferConflictResolutionPreservesAttemptBudget(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 25, 12, 30, 0, 0, time.UTC)
	workflowID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	mock.ExpectBegin()
	mock.ExpectExec(`(?s)UPDATE workflows workflow SET next_attempt_at=.*workflow_type='conflict_resolution'.*workflow.state='scheduled'`).
		WithArgs(workflowID, "source_upgrade_pending", "等待冲突来源 Agent 安全升级", now.Add(time.Minute), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE relay_transfers.*expires_at=LEAST\(expires_at,\$2\).*workflow_id=\$1`).
		WithArgs(workflowID, now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()
	if err := st.DeferConflictResolution(
		context.Background(), workflowID, "source_upgrade_pending",
		"等待冲突来源 Agent 安全升级", now, time.Minute,
	); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestAdoptStaleConflictResolutionFencesRelayAndRebindsGeneration(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 25, 13, 5, 0, 0, time.UTC)
	workflowID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)WITH active AS.*SELECT workflow.id::text,active.generation,EXISTS.*FOR UPDATE OF workflow SKIP LOCKED`).
		WithArgs(100).
		WillReturnRows(sqlmock.NewRows([]string{"id", "generation", "had_relay"}).
			AddRow(workflowID, int64(38), true))
	mock.ExpectExec(`(?s)UPDATE workflows SET.*controller_generation=\$2,state='scheduled'.*attempt=attempt\+\$3`).
		WithArgs(workflowID, int64(38), 1, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE replica_conflicts conflict.*controller_generation=\$2`).
		WithArgs(workflowID, int64(38), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE relay_transfers.*expires_at=LEAST\(expires_at,\$2\)`).
		WithArgs(workflowID, now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`(?s)UPDATE workflow_steps SET state='pending'.*attempt=attempt\+\$2`).
		WithArgs(workflowID, 1, now).
		WillReturnResult(sqlmock.NewResult(0, 5))
	mock.ExpectCommit()
	adopted, err := st.AdoptStaleConflictResolutions(context.Background(), now, 100)
	if err != nil || adopted != 1 {
		t.Fatalf("adopted=%d err=%v", adopted, err)
	}
	assertMockExpectations(t, mock)
}

func conflictResolutionCompletionParams(now time.Time) CompleteConflictResolutionParams {
	return CompleteConflictResolutionParams{
		WorkflowID:       "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		OperationID:      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ConflictID:       "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		ResultSnapshotID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		EntriesSHA256:    bytes.Repeat([]byte{3}, 32), FileCount: 4, TotalBytes: 120, Now: now,
	}
}

func expectConflictResolutionCompletionHeader(
	mock sqlmock.Sqlmock,
	p CompleteConflictResolutionParams,
	workflowState, globalStatus, legacyStatus, conflictState string,
	generation int64,
) {
	mock.ExpectQuery(`(?s)SELECT workflow.state,global_user.status,legacy.status,conflict.state.*FROM workflows workflow`).
		WithArgs(p.WorkflowID, p.OperationID, p.ConflictID, p.ResultSnapshotID).
		WillReturnRows(sqlmock.NewRows([]string{
			"workflow_state", "global_status", "legacy_status", "conflict_state", "user_id",
			"legacy_user_id", "base_node_id", "generation", "activity_epoch",
		}).AddRow(workflowState, globalStatus, legacyStatus, conflictState,
			int64(70), int64(7), int64(9), generation, int64(3)))
}

func TestCompleteConflictResolutionFencesLifecycleAndManifest(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 7, 5, 0, 0, time.UTC)
	tests := []struct {
		name          string
		workflowState string
		globalStatus  string
		legacyStatus  string
		conflictState string
		generation    int64
		activeGen     int64
		preserved     int
		manifestRows  int64
		idempotent    bool
	}{
		{name: "exact completed replay", workflowState: "succeeded", globalStatus: "active", legacyStatus: "active", conflictState: "resolved", generation: 4, idempotent: true},
		{name: "workflow not publishing", workflowState: "transferring", globalStatus: "conflict", legacyStatus: "conflict", conflictState: "resolving", generation: 4},
		{name: "identity no longer conflicted", workflowState: "publishing", globalStatus: "active", legacyStatus: "conflict", conflictState: "resolving", generation: 4},
		{name: "stale controller generation", workflowState: "publishing", globalStatus: "conflict", legacyStatus: "conflict", conflictState: "resolving", generation: 3, activeGen: 4},
		{name: "insufficient preserved sources", workflowState: "publishing", globalStatus: "conflict", legacyStatus: "conflict", conflictState: "resolving", generation: 4, activeGen: 4, preserved: 1},
		{name: "manifest fence lost", workflowState: "publishing", globalStatus: "conflict", legacyStatus: "conflict", conflictState: "resolving", generation: 4, activeGen: 4, preserved: 2, manifestRows: 0},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := conflictResolutionCompletionParams(now)
			mock.ExpectBegin()
			expectConflictResolutionCompletionHeader(mock, p, tc.workflowState, tc.globalStatus,
				tc.legacyStatus, tc.conflictState, tc.generation)
			if tc.idempotent {
				mock.ExpectCommit()
			} else {
				ready := tc.workflowState == "publishing" && tc.globalStatus == "conflict" &&
					tc.legacyStatus == "conflict" && tc.conflictState == "resolving"
				if ready {
					mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
						WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(tc.activeGen))
					if tc.activeGen == tc.generation {
						mock.ExpectQuery(`SELECT count\(\*\) FROM replica_conflict_sources`).WithArgs(p.ConflictID).
							WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(tc.preserved))
						if tc.preserved >= 2 {
							mock.ExpectExec(`UPDATE snapshot_manifests`).
								WithArgs(p.ResultSnapshotID, p.WorkflowID, p.EntriesSHA256, p.FileCount, p.TotalBytes).
								WillReturnResult(sqlmock.NewResult(0, tc.manifestRows))
						}
					}
				}
				mock.ExpectRollback()
			}
			err := st.CompleteConflictResolution(context.Background(), p)
			if tc.idempotent {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrConflictResolutionState) {
				t.Fatalf("err=%v, want ErrConflictResolutionState", err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestMarkConflictResolutionPublishingIsAtomicAndIdempotent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 7, 10, 0, 0, time.UTC)
	for _, state := range []string{"first publish", "replay", "transfer incomplete"} {
		state := state
		t.Run(state, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			mock.ExpectBegin()
			rows := int64(1)
			if state != "first publish" {
				rows = 0
			}
			mock.ExpectExec(`UPDATE workflows workflow SET state='publishing'`).WithArgs("workflow", now).
				WillReturnResult(sqlmock.NewResult(0, rows))
			if state == "first publish" {
				mock.ExpectExec(`UPDATE workflow_steps SET state='succeeded'`).WithArgs("workflow", now).
					WillReturnResult(sqlmock.NewResult(0, 3))
				mock.ExpectCommit()
			} else {
				storedState := "publishing"
				if state == "transfer incomplete" {
					storedState = "transferring"
				}
				mock.ExpectQuery(`SELECT state FROM workflows`).WithArgs("workflow").
					WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow(storedState))
				if state == "replay" {
					mock.ExpectCommit()
				} else {
					mock.ExpectRollback()
				}
			}
			err := st.MarkConflictResolutionPublishing(context.Background(), "workflow", now)
			if state == "transfer incomplete" {
				if !errors.Is(err, ErrConflictResolutionState) {
					t.Fatalf("err=%v, want ErrConflictResolutionState", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestRestartConflictResolutionRearmsFailedWorkflowAtomically(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 24, 7, 15, 0, 0, time.UTC)
	operationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	workflowID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	conflictID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	snapshotID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT operation.workflow_id::text,operation.conflict_id::text.*FROM conflict_resolution_operations operation`).
		WithArgs(int64(70), operationID).
		WillReturnRows(sqlmock.NewRows([]string{
			"workflow_id", "conflict_id", "snapshot_id", "base_node_id", "node_name", "conflict_state", "generation",
		}).AddRow(workflowID, conflictID, snapshotID, int64(9), "compute-b", "awaiting_decision", int64(4)))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
	mock.ExpectExec(`UPDATE snapshot_manifests`).WithArgs(snapshotID, make([]byte, 32)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflows SET state='scheduled'`).WithArgs(workflowID, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE workflow_steps SET state='pending'`).WithArgs(workflowID, now).
		WillReturnResult(sqlmock.NewResult(0, 5))
	mock.ExpectExec(`UPDATE replica_conflicts SET state='resolving'`).WithArgs(conflictID, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).
		WithArgs(int64(70), operationID, int64(4), conflictID, int64(9), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	status, err := st.RestartConflictResolution(context.Background(), 70, operationID, now)
	if err != nil || status == nil || status.State != "scheduled" || status.BaseNodeID != 9 || status.BaseNodeName != "compute-b" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	assertMockExpectations(t, mock)
}

func TestRestartConflictResolutionFencesConflictAndGeneration(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 7, 20, 0, 0, time.UTC)
	for _, stage := range []string{"missing", "conflict state", "generation", "manifest"} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			mock.ExpectBegin()
			query := mock.ExpectQuery(`(?s)SELECT operation.workflow_id::text,operation.conflict_id::text.*FROM conflict_resolution_operations operation`).
				WithArgs(int64(70), "operation")
			if stage == "missing" {
				query.WillReturnRows(sqlmock.NewRows([]string{"workflow_id"}))
			} else {
				conflictState := "awaiting_decision"
				if stage == "conflict state" {
					conflictState = "resolved"
				}
				query.WillReturnRows(sqlmock.NewRows([]string{
					"workflow_id", "conflict_id", "snapshot_id", "base_node_id", "node_name", "conflict_state", "generation",
				}).AddRow("workflow", "conflict", "snapshot", int64(9), "compute-b", conflictState, int64(4)))
				if stage != "conflict state" {
					activeGeneration := int64(4)
					if stage == "generation" {
						activeGeneration = 5
					}
					mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
						WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(activeGeneration))
					if stage == "manifest" {
						mock.ExpectExec(`UPDATE snapshot_manifests`).WithArgs("snapshot", make([]byte, 32)).
							WillReturnResult(sqlmock.NewResult(0, 0))
					}
				}
			}
			mock.ExpectRollback()
			status, err := st.RestartConflictResolution(context.Background(), 70, "operation", now)
			if status != nil || !errors.Is(err, ErrConflictResolutionState) {
				t.Fatalf("stage=%q status=%+v err=%v", stage, status, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}
