package store

import (
	"bytes"
	"context"
	"errors"
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
)

func dataFaultStatusRows(now time.Time, state string) *sqlmock.Rows {
	var freezeOperation any
	var protectionState any
	var frozenAt any
	if state == "freezing" || state == "recovery_available" {
		freezeOperation = testDataFaultFreezeOp
	}
	if state == "recovery_available" {
		protectionState = "takeover_available"
		frozenAt = now
	}
	return sqlmock.NewRows([]string{
		"id", "operation_id", "user_uuid", "user_id", "node_id", "reason_code",
		"state", "activity_epoch", "controller_generation", "freeze_operation_id",
		"attempt", "protection_state", "error_code", "reported_at", "frozen_at",
		"resolved_at", "resolution_kind", "resolution_operation_id", "updated_at",
		"local_handle", "reported_by_admin_id",
	}).AddRow(
		testDataFaultID, testDataFaultOperation, testDataFaultUserUUID, int64(70), int64(8),
		"user_database_corrupt", state, int64(6), int64(4), freezeOperation, 1,
		protectionState, nil, now.Add(-time.Minute), frozenAt, nil, nil, nil, now,
		"alice", int64(9),
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
	assertMockExpectations(t, mock)
}
