package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

const (
	testDataFaultID        = "11111111-1111-4111-8111-111111111111"
	testDataFaultOperation = "22222222-2222-4222-8222-222222222222"
	testDataFaultUserUUID  = "33333333-3333-4333-8333-333333333333"
	testDataFaultFreezeOp  = "44444444-4444-4444-8444-444444444444"
	testDataFaultWorker    = "55555555-5555-4555-8555-555555555555"
	testDataFaultReleaseOp = "66666666-6666-4666-8666-666666666666"
)

func dataFaultStatusRows(now time.Time, state string) *sqlmock.Rows {
	return dataFaultStatusRowsWithRelease(now, state, "not_required")
}

func dataFaultStatusRowsWithRelease(now time.Time, state, releaseState string) *sqlmock.Rows {
	var freezeOperation any
	var protectionState any
	var frozenAt any
	var resolvedAt any
	var resolutionKind any
	var resolutionOperationID any
	var releaseOperation any
	var releaseAttempt int
	var releaseLeaseOwner any
	var releaseLeaseUntil any
	var releaseNextAttemptAt any
	var releaseErrorCode any
	var releaseReleasedAt any
	var releaseGeneration any
	if state == "freezing" || state == "recovery_available" {
		freezeOperation = testDataFaultFreezeOp
	}
	if state == "recovery_available" {
		protectionState = "takeover_available"
		frozenAt = now
	}
	if state == "resolved" {
		freezeOperation = testDataFaultFreezeOp
		protectionState = "takeover_available"
		frozenAt = now.Add(-time.Minute)
		resolvedAt = now
		resolutionKind = "takeover"
		resolutionOperationID = testDataFaultOperation
	}
	switch releaseState {
	case "pending":
		releaseNextAttemptAt = now
	case "releasing":
		releaseOperation = testDataFaultReleaseOp
		releaseAttempt = 2
		releaseLeaseOwner = testDataFaultWorker
		releaseLeaseUntil = now.Add(time.Minute)
		releaseGeneration = int64(5)
	case "retry_wait":
		releaseOperation = testDataFaultReleaseOp
		releaseAttempt = 2
		releaseNextAttemptAt = now.Add(time.Minute)
		releaseErrorCode = "agent_unavailable"
		releaseGeneration = int64(5)
	case "released":
		releaseOperation = testDataFaultReleaseOp
		releaseAttempt = 2
		releaseReleasedAt = now
		releaseGeneration = int64(5)
	}
	return sqlmock.NewRows([]string{
		"id", "operation_id", "user_uuid", "user_id", "node_id", "reason_code",
		"state", "activity_epoch", "controller_generation", "freeze_operation_id",
		"attempt", "protection_state", "error_code", "reported_at", "frozen_at",
		"resolved_at", "resolution_kind", "resolution_operation_id", "release_state",
		"release_operation_id", "release_attempt", "release_lease_owner",
		"release_lease_until", "release_next_attempt_at", "release_error_code",
		"release_released_at", "release_controller_generation", "updated_at",
		"local_handle", "reported_by_admin_id",
	}).AddRow(
		testDataFaultID, testDataFaultOperation, testDataFaultUserUUID, int64(70), int64(8),
		"user_database_corrupt", state, int64(6), int64(4), freezeOperation, 1,
		protectionState, nil, now.Add(-time.Minute), frozenAt, resolvedAt, resolutionKind,
		resolutionOperationID, releaseState, releaseOperation, releaseAttempt,
		releaseLeaseOwner, releaseLeaseUntil, releaseNextAttemptAt, releaseErrorCode,
		releaseReleasedAt, releaseGeneration, now, "alice", int64(9),
	)
}

func TestReportUserDataFaultReplaysOnlyExactAdminRequest(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 1, 0, 0, 0, time.UTC)
	digest := bytes.Repeat([]byte{7}, 32)
	params := ReportUserDataFaultParams{
		OperationID: testDataFaultOperation, RequestDigest: digest,
		UserUUID: testDataFaultUserUUID, ExpectedHomeNodeID: 8,
		ReasonCode: "user_database_corrupt", AdminID: 9, Now: now,
	}

	t.Run("exact replay", func(t *testing.T) {
		st, mock, closeDB := newMockStore(t)
		defer closeDB()
		mock.ExpectBegin()
		mock.ExpectQuery(`FROM user_data_faults fault.*fault.operation_id=\$1`).
			WithArgs(testDataFaultOperation).WillReturnRows(dataFaultStatusRows(now, "reported"))
		mock.ExpectQuery(`SELECT request_digest FROM user_data_faults`).
			WithArgs(testDataFaultID).WillReturnRows(sqlmock.NewRows([]string{"digest"}).AddRow(digest))
		mock.ExpectCommit()
		status, err := st.ReportUserDataFault(context.Background(), params)
		if err != nil || status == nil || !status.Replayed || status.ID != testDataFaultID {
			t.Fatalf("status=%+v err=%v", status, err)
		}
		assertMockExpectations(t, mock)
	})

	t.Run("digest mismatch", func(t *testing.T) {
		st, mock, closeDB := newMockStore(t)
		defer closeDB()
		mock.ExpectBegin()
		mock.ExpectQuery(`FROM user_data_faults fault.*fault.operation_id=\$1`).
			WithArgs(testDataFaultOperation).WillReturnRows(dataFaultStatusRows(now, "reported"))
		mock.ExpectQuery(`SELECT request_digest FROM user_data_faults`).
			WithArgs(testDataFaultID).WillReturnRows(sqlmock.NewRows([]string{"digest"}).AddRow(digest))
		mock.ExpectRollback()
		changed := params
		changed.RequestDigest = bytes.Repeat([]byte{8}, 32)
		_, err := st.ReportUserDataFault(context.Background(), changed)
		if !errors.Is(err, ErrUserDataFaultOperationConflict) {
			t.Fatalf("error=%v", err)
		}
		assertMockExpectations(t, mock)
	})
}

func TestClaimUserDataFaultIsGenerationFencedAndPreservesTaskScope(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 1, 10, 0, 0, time.UTC)
	mock.ExpectQuery(`(?s)WITH active_epoch AS .*FOR UPDATE.*UPDATE user_data_faults fault SET.*controller_generation=epoch.generation`).
		WithArgs(testDataFaultID, testDataFaultFreezeOp, testDataFaultWorker, now, now.Add(time.Minute)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "operation_id", "user_id", "user_uuid", "node_id", "handle",
			"activity_epoch", "attempt", "generation",
		}).AddRow(testDataFaultID, testDataFaultFreezeOp, int64(70), testDataFaultUserUUID,
			int64(8), "alice", int64(6), 2, int64(5)))
	task, err := st.ClaimUserDataFault(
		context.Background(), testDataFaultID, testDataFaultFreezeOp,
		testDataFaultWorker, now, time.Minute,
	)
	if err != nil || task == nil || task.Handle != "alice" || task.ActivityEpoch != 6 ||
		task.ControllerGeneration != 5 || task.OperationID != testDataFaultFreezeOp {
		t.Fatalf("task=%+v err=%v", task, err)
	}
	assertMockExpectations(t, mock)
}

func TestCompleteUserDataFaultFreezePublishesRecoveryOnlyAfterProjection(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 1, 20, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)WITH active_epoch AS .*user_protection_states protection.*fault.lease_until>\$4`).
		WithArgs(testDataFaultID, testDataFaultFreezeOp, testDataFaultWorker, now).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "state", "protection", "generation"}).
			AddRow(int64(70), "recovery_available", "takeover_available", int64(5)))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		int64(70), testDataFaultFreezeOp, int64(5), testDataFaultID,
		"recovery_available", "takeover_available",
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectQuery(`FROM user_data_faults fault.*fault.id=\$1`).
		WithArgs(testDataFaultID).WillReturnRows(dataFaultStatusRows(now, "recovery_available"))
	status, err := st.CompleteUserDataFaultFreeze(
		context.Background(), testDataFaultID, testDataFaultFreezeOp,
		testDataFaultWorker, now,
	)
	if err != nil || status == nil || status.State != "recovery_available" ||
		status.ProtectionState != "takeover_available" || status.FrozenAt == nil {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	assertMockExpectations(t, mock)
}

func TestRetryUserDataFaultNeverReopensWrites(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 1, 30, 0, 0, time.UTC)
	mock.ExpectExec(`UPDATE user_data_faults fault SET state='retry_wait'`).WithArgs(
		testDataFaultID, testDataFaultFreezeOp, testDataFaultWorker,
		"agent_unavailable", now.Add(30*time.Second), now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.RetryUserDataFault(
		context.Background(), testDataFaultID, testDataFaultFreezeOp,
		testDataFaultWorker, "agent_unavailable", now, 30*time.Second,
	); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestListSchedulableUserDataFaultReleaseIDsIncludesDueAndExpiredWork(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`SELECT id::text FROM user_data_faults.*release_state='pending'.*release_state='retry_wait'.*release_state='releasing'`).
		WithArgs(3).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).
			AddRow(testDataFaultID).
			AddRow("77777777-7777-4777-8777-777777777777").
			AddRow("88888888-8888-4888-8888-888888888888"))
	ids, err := st.ListSchedulableUserDataFaultReleaseIDs(context.Background(), 3)
	if err != nil || len(ids) != 3 || ids[0] != testDataFaultID {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimUserDataFaultReleaseIsGenerationFencedAndRotatesOperation(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 1, 40, 0, 0, time.UTC)
	mock.ExpectQuery(`(?s)WITH active_epoch AS .*release_state='releasing'.*release_operation_id=CASE.*release_controller_generation=epoch.generation`).
		WithArgs(testDataFaultID, testDataFaultReleaseOp, testDataFaultWorker, now, now.Add(time.Minute)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "operation_id", "user_id", "user_uuid", "node_id", "handle",
			"activity_epoch", "attempt", "generation",
		}).AddRow(testDataFaultID, testDataFaultReleaseOp, int64(70), testDataFaultUserUUID,
			int64(8), "alice", int64(6), 3, int64(5)))
	task, err := st.ClaimUserDataFaultRelease(
		context.Background(), testDataFaultID, testDataFaultReleaseOp,
		testDataFaultWorker, now, time.Minute,
	)
	if err != nil || task == nil || task.OperationID != testDataFaultReleaseOp ||
		task.ActivityEpoch != 6 || task.ControllerGeneration != 5 || task.Attempt != 3 {
		t.Fatalf("task=%+v err=%v", task, err)
	}
	assertMockExpectations(t, mock)
}

func TestClaimUserDataFaultReleaseReturnsNilWhenListedCandidateLosesRace(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 1, 45, 0, 0, time.UTC)
	mock.ExpectQuery(`(?s)WITH active_epoch AS .*candidate AS .*FOR UPDATE.*claimed AS`).
		WithArgs(testDataFaultID, testDataFaultReleaseOp, testDataFaultWorker, now, now.Add(time.Minute)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "operation_id", "user_id", "user_uuid", "node_id", "handle",
			"activity_epoch", "attempt", "generation",
		}))
	task, err := st.ClaimUserDataFaultRelease(
		context.Background(), testDataFaultID, testDataFaultReleaseOp,
		testDataFaultWorker, now, time.Minute,
	)
	if err != nil || task != nil {
		t.Fatalf("task=%+v err=%v", task, err)
	}
	assertMockExpectations(t, mock)
}

func TestCompleteUserDataFaultReleaseIsExactAndIdempotent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 1, 50, 0, 0, time.UTC)

	t.Run("completed release audits once", func(t *testing.T) {
		st, mock, closeDB := newMockStore(t)
		defer closeDB()
		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).
			WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(5)))
		mock.ExpectQuery(`SELECT state,release_state,release_operation_id::text,release_controller_generation,\s+release_lease_owner::text,user_id\s+FROM user_data_faults WHERE id=\$1 FOR UPDATE`).
			WithArgs(testDataFaultID).
			WillReturnRows(sqlmock.NewRows([]string{
				"state", "release_state", "release_operation_id", "release_controller_generation",
				"release_lease_owner", "user_id",
			}).AddRow("resolved", "releasing", testDataFaultReleaseOp, int64(5), testDataFaultWorker, int64(70)))
		mock.ExpectExec(`UPDATE user_data_faults SET release_state='released'`).
			WithArgs(testDataFaultID, testDataFaultReleaseOp, int64(5), testDataFaultWorker, now).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
			now, int64(70), testDataFaultReleaseOp, int64(5), testDataFaultID,
		).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		if err := st.CompleteUserDataFaultRelease(
			context.Background(), testDataFaultID, testDataFaultReleaseOp, testDataFaultWorker, now,
		); err != nil {
			t.Fatal(err)
		}
		assertMockExpectations(t, mock)
	})

	t.Run("already released exact replay is harmless", func(t *testing.T) {
		st, mock, closeDB := newMockStore(t)
		defer closeDB()
		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT generation FROM controller_epochs WHERE state='active' FOR SHARE`).
			WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(9)))
		mock.ExpectQuery(`SELECT state,release_state,release_operation_id::text,release_controller_generation,\s+release_lease_owner::text,user_id\s+FROM user_data_faults WHERE id=\$1 FOR UPDATE`).
			WithArgs(testDataFaultID).
			WillReturnRows(sqlmock.NewRows([]string{
				"state", "release_state", "release_operation_id", "release_controller_generation",
				"release_lease_owner", "user_id",
			}).AddRow("resolved", "released", testDataFaultReleaseOp, int64(5), nil, int64(70)))
		mock.ExpectCommit()
		if err := st.CompleteUserDataFaultRelease(
			context.Background(), testDataFaultID, testDataFaultReleaseOp, testDataFaultWorker, now,
		); err != nil {
			t.Fatal(err)
		}
		assertMockExpectations(t, mock)
	})
}

func TestRetryUserDataFaultReleaseKeepsTaskDurable(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 9, 2, 0, 0, 0, time.UTC)
	mock.ExpectExec(`UPDATE user_data_faults fault SET release_state='retry_wait'`).
		WithArgs(
			testDataFaultID, testDataFaultReleaseOp, testDataFaultWorker,
			"agent_unavailable", now.Add(45*time.Second), now,
		).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.RetryUserDataFaultRelease(
		context.Background(), testDataFaultID, testDataFaultReleaseOp,
		testDataFaultWorker, "agent_unavailable", now, 45*time.Second,
	); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestResolveUserDataFaultSchedulesReleaseDurably(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	ctx := context.Background()
	now := time.Date(2026, 8, 9, 2, 10, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE user_data_faults SET state='resolved',resolution_kind=\$2,.*release_state='pending'.*release_next_attempt_at=\$4`).
		WithArgs(int64(70), "takeover", testDataFaultOperation, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE alerts SET state='resolved'`).
		WithArgs(int64(70), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := st.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := resolveUserDataFaultLocked(ctx, tx, 70, "takeover", testDataFaultOperation, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestUserDataFaultReleaseMigrationBackfillsHistoricalResolvedGateBesideOpenFault(t *testing.T) {
	t.Parallel()
	sqlText, err := os.ReadFile(filepath.Join("migrations", "0051_user_data_fault_release.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"ADD COLUMN IF NOT EXISTS release_state",
		"WITH ranked_resolved AS",
		"row_number() OVER",
		"release_state='pending'",
		"'superseded'",
		"ck_user_data_fault_release_scope",
		"ck_user_data_fault_release_shape",
		"release_operation_id IS NULL AND release_controller_generation IS NULL",
		"uq_user_data_fault_release_open",
		"state='resolved' AND release_state NOT IN ('released','superseded')",
		"uq_user_data_fault_release_operation",
		"idx_user_data_fault_release_schedulable",
	} {
		if !strings.Contains(string(sqlText), required) {
			t.Fatalf("migration missing %q", required)
		}
	}
	if strings.Contains(string(sqlText), "has_open_fault") ||
		strings.Contains(string(sqlText), "DROP INDEX IF EXISTS uq_user_data_fault_open") {
		t.Fatal("migration would discard a still-owned resolved gate or collapse it with an existing open fault")
	}
	baseText, err := os.ReadFile(filepath.Join("migrations", "0033_user_data_faults.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(baseText), "WHERE state<>'resolved'") {
		t.Fatal("open-fault uniqueness must remain independent from resolved-gate release uniqueness")
	}
}

func TestUserDataFaultPublicMethodsRejectInvalidScope(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	ctx := context.Background()
	if _, err := st.ReportUserDataFault(ctx, ReportUserDataFaultParams{}); !errors.Is(err, ErrInvalidUserDataFault) {
		t.Fatalf("report error=%v", err)
	}
	if _, err := st.GetUserDataFaultByID(ctx, "bad"); !errors.Is(err, ErrInvalidUserDataFault) {
		t.Fatalf("get error=%v", err)
	}
	if _, err := st.GetUserDataFaultByUserUUID(ctx, "bad"); !errors.Is(err, ErrInvalidUserDataFault) {
		t.Fatalf("get user error=%v", err)
	}
	if _, err := st.ClaimUserDataFault(ctx, "bad", "bad", "bad", time.Time{}, time.Second); !errors.Is(err, ErrInvalidUserDataFault) {
		t.Fatalf("claim error=%v", err)
	}
	if _, err := st.CompleteUserDataFaultFreeze(ctx, "bad", "bad", "bad", time.Time{}); !errors.Is(err, ErrInvalidUserDataFault) {
		t.Fatalf("complete error=%v", err)
	}
	if err := st.RetryUserDataFault(ctx, "bad", "bad", "bad", "bad", time.Time{}, 0); !errors.Is(err, ErrInvalidUserDataFault) {
		t.Fatalf("retry error=%v", err)
	}
	if _, err := st.ClaimUserDataFaultRelease(ctx, "bad", "bad", "bad", time.Time{}, time.Second); !errors.Is(err, ErrInvalidUserDataFault) {
		t.Fatalf("claim release error=%v", err)
	}
	if err := st.CompleteUserDataFaultRelease(ctx, "bad", "bad", "bad", time.Time{}); !errors.Is(err, ErrInvalidUserDataFault) {
		t.Fatalf("complete release error=%v", err)
	}
	if err := st.RetryUserDataFaultRelease(ctx, "bad", "bad", "bad", "bad", time.Time{}, 0); !errors.Is(err, ErrInvalidUserDataFault) {
		t.Fatalf("retry release error=%v", err)
	}
	assertMockExpectations(t, mock)
}
