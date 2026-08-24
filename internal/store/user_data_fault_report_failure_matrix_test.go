package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func reportFaultParams(now time.Time) ReportUserDataFaultParams {
	return ReportUserDataFaultParams{
		OperationID: testDataFaultOperation, RequestDigest: bytes.Repeat([]byte{7}, 32),
		UserUUID: testDataFaultUserUUID, ExpectedHomeNodeID: 8,
		ReasonCode: "user_database_corrupt", AdminID: 9, Now: now,
	}
}

func expectNewDataFaultPrefix(mock sqlmock.Sqlmock, p ReportUserDataFaultParams) {
	mock.ExpectBegin()
	mock.ExpectQuery(`FROM user_data_faults fault.*fault.operation_id=\$1`).WithArgs(p.OperationID).
		WillReturnError(sql.ErrNoRows)
}

func expectReportDataFaultFailureAt(
	mock sqlmock.Sqlmock,
	p ReportUserDataFaultParams,
	stage string,
	injected error,
) {
	expectNewDataFaultPrefix(mock, p)
	mock.ExpectQuery(`SELECT global_user.id,legacy_user.id`).WithArgs(p.UserUUID).
		WillReturnRows(sqlmock.NewRows([]string{
			"global_user_id", "legacy_user_id", "home_node_id", "username", "node_role", "local_handle", "activity_epoch",
		}).AddRow(int64(70), int64(7), int64(8), "alice", "compute", "local-alice", int64(6)))
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(int64(70), int64(8)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery(`SELECT id::text FROM user_data_faults`).WithArgs(int64(70)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
	insertFault := mock.ExpectQuery(`INSERT INTO user_data_faults`).WithArgs(
		p.OperationID, p.RequestDigest, int64(70), int64(7), int64(8), "local-alice",
		p.ReasonCode, int64(6), int64(4), p.AdminID, p.Now,
	)
	if stage == "fault" {
		insertFault.WillReturnError(injected)
		return
	}
	insertFault.WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(testDataFaultID))
	legacyReplica := mock.ExpectExec(`INSERT INTO user_replicas`).WithArgs(int64(7), int64(8), p.Now)
	if stage == "legacy replica" {
		legacyReplica.WillReturnError(injected)
		return
	}
	legacyReplica.WillReturnResult(sqlmock.NewResult(0, 1))
	copy := mock.ExpectExec(`INSERT INTO replica_copies`).WithArgs(int64(70), int64(8), p.ReasonCode, p.Now)
	if stage == "replica copy" {
		copy.WillReturnError(injected)
		return
	}
	copy.WillReturnResult(sqlmock.NewResult(0, 1))
	activity := mock.ExpectExec(`UPDATE user_activity_leases`).WithArgs(int64(70), p.Now)
	if stage == "activity lease" {
		activity.WillReturnError(injected)
		return
	}
	activity.WillReturnResult(sqlmock.NewResult(0, 1))
	control := mock.ExpectExec(`UPDATE control_tickets`).WithArgs(int64(70), p.Now)
	if stage == "control tickets" {
		control.WillReturnError(injected)
		return
	}
	control.WillReturnResult(sqlmock.NewResult(0, 1))
	legacyTickets := mock.ExpectExec(`UPDATE tickets`).WithArgs(int64(7), p.Now)
	if stage == "legacy tickets" {
		legacyTickets.WillReturnError(injected)
		return
	}
	legacyTickets.WillReturnResult(sqlmock.NewResult(0, 1))
	alert := mock.ExpectExec(`INSERT INTO alerts`).WithArgs(int64(70), int64(8), p.Now)
	if stage == "alert" {
		alert.WillReturnError(injected)
		return
	}
	alert.WillReturnResult(sqlmock.NewResult(0, 1))
	audit := mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		p.AdminID, int64(70), p.OperationID, int64(4), p.RequestDigest,
		testDataFaultID, int64(8), p.ReasonCode, int64(6),
	)
	if stage == "audit" {
		audit.WillReturnError(injected)
		return
	}
	audit.WillReturnResult(sqlmock.NewResult(0, 1))
	if stage != "commit" {
		panic("unhandled user data fault failure stage: " + stage)
	}
	mock.ExpectCommit().WillReturnError(injected)
}

func TestReportUserDataFaultFencesReplayAndPreconditionFailures(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 9, 25, 0, 0, time.UTC)
	injected := errors.New("injected user data fault failure")
	for _, tc := range []struct {
		name  string
		setup func(sqlmock.Sqlmock, ReportUserDataFaultParams)
		want  error
	}{
		{
			name: "begin",
			setup: func(mock sqlmock.Sqlmock, _ ReportUserDataFaultParams) {
				mock.ExpectBegin().WillReturnError(injected)
			},
			want: injected,
		},
		{
			name: "operation lookup",
			setup: func(mock sqlmock.Sqlmock, p ReportUserDataFaultParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`FROM user_data_faults fault.*fault.operation_id=\$1`).WithArgs(p.OperationID).
					WillReturnError(injected)
				mock.ExpectRollback()
			},
			want: injected,
		},
		{
			name: "replay digest lookup",
			setup: func(mock sqlmock.Sqlmock, p ReportUserDataFaultParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`FROM user_data_faults fault.*fault.operation_id=\$1`).
					WillReturnRows(dataFaultStatusRows(now, "reported"))
				mock.ExpectQuery(`SELECT request_digest FROM user_data_faults`).WithArgs(testDataFaultID).
					WillReturnError(injected)
				mock.ExpectRollback()
			},
			want: injected,
		},
		{
			name: "replay commit",
			setup: func(mock sqlmock.Sqlmock, p ReportUserDataFaultParams) {
				mock.ExpectBegin()
				mock.ExpectQuery(`FROM user_data_faults fault.*fault.operation_id=\$1`).
					WillReturnRows(dataFaultStatusRows(now, "reported"))
				mock.ExpectQuery(`SELECT request_digest FROM user_data_faults`).WithArgs(testDataFaultID).
					WillReturnRows(sqlmock.NewRows([]string{"digest"}).AddRow(p.RequestDigest))
				mock.ExpectCommit().WillReturnError(injected)
			},
			want: injected,
		},
		{
			name: "user missing",
			setup: func(mock sqlmock.Sqlmock, p ReportUserDataFaultParams) {
				expectNewDataFaultPrefix(mock, p)
				mock.ExpectQuery(`SELECT global_user.id,legacy_user.id`).WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			},
			want: ErrUserDataFaultNotFound,
		},
		{
			name: "user lookup",
			setup: func(mock sqlmock.Sqlmock, p ReportUserDataFaultParams) {
				expectNewDataFaultPrefix(mock, p)
				mock.ExpectQuery(`SELECT global_user.id,legacy_user.id`).WillReturnError(injected)
				mock.ExpectRollback()
			},
			want: injected,
		},
		{
			name: "home mismatch",
			setup: func(mock sqlmock.Sqlmock, p ReportUserDataFaultParams) {
				expectNewDataFaultPrefix(mock, p)
				mock.ExpectQuery(`SELECT global_user.id,legacy_user.id`).WillReturnRows(sqlmock.NewRows([]string{
					"global_user_id", "legacy_user_id", "home_node_id", "username", "node_role", "local_handle", "activity_epoch",
				}).AddRow(int64(70), int64(7), nil, "alice", "compute", "alice", int64(1)))
				mock.ExpectRollback()
			},
			want: ErrUserDataFaultHomeConflict,
		},
		{
			name: "authoritative lookup",
			setup: func(mock sqlmock.Sqlmock, p ReportUserDataFaultParams) {
				expectNewDataFaultPrefix(mock, p)
				mock.ExpectQuery(`SELECT global_user.id,legacy_user.id`).WillReturnRows(sqlmock.NewRows([]string{
					"global_user_id", "legacy_user_id", "home_node_id", "username", "node_role", "local_handle", "activity_epoch",
				}).AddRow(int64(70), int64(7), int64(8), "alice", "compute", "alice", int64(1)))
				mock.ExpectQuery(`SELECT EXISTS`).WillReturnError(injected)
				mock.ExpectRollback()
			},
			want: injected,
		},
		{
			name: "authoritative conflict",
			setup: func(mock sqlmock.Sqlmock, p ReportUserDataFaultParams) {
				expectNewDataFaultPrefix(mock, p)
				mock.ExpectQuery(`SELECT global_user.id,legacy_user.id`).WillReturnRows(sqlmock.NewRows([]string{
					"global_user_id", "legacy_user_id", "home_node_id", "username", "node_role", "local_handle", "activity_epoch",
				}).AddRow(int64(70), int64(7), int64(8), "alice", "compute", "alice", int64(1)))
				mock.ExpectQuery(`SELECT EXISTS`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
				mock.ExpectRollback()
			},
			want: ErrUserDataFaultAuthoritativeConflict,
		},
		{
			name: "open fault",
			setup: func(mock sqlmock.Sqlmock, p ReportUserDataFaultParams) {
				expectNewDataFaultPrefix(mock, p)
				mock.ExpectQuery(`SELECT global_user.id,legacy_user.id`).WillReturnRows(sqlmock.NewRows([]string{
					"global_user_id", "legacy_user_id", "home_node_id", "username", "node_role", "local_handle", "activity_epoch",
				}).AddRow(int64(70), int64(7), int64(8), "alice", "compute", "alice", int64(1)))
				mock.ExpectQuery(`SELECT EXISTS`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
				mock.ExpectQuery(`SELECT id::text FROM user_data_faults`).WillReturnRows(
					sqlmock.NewRows([]string{"id"}).AddRow(testDataFaultID))
				mock.ExpectRollback()
			},
			want: ErrUserDataFaultAlreadyOpen,
		},
		{
			name: "open fault lookup",
			setup: func(mock sqlmock.Sqlmock, p ReportUserDataFaultParams) {
				expectNewDataFaultPrefix(mock, p)
				mock.ExpectQuery(`SELECT global_user.id,legacy_user.id`).WillReturnRows(sqlmock.NewRows([]string{
					"global_user_id", "legacy_user_id", "home_node_id", "username", "node_role", "local_handle", "activity_epoch",
				}).AddRow(int64(70), int64(7), int64(8), "alice", "compute", "alice", int64(1)))
				mock.ExpectQuery(`SELECT EXISTS`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
				mock.ExpectQuery(`SELECT id::text FROM user_data_faults`).WillReturnError(injected)
				mock.ExpectRollback()
			},
			want: injected,
		},
		{
			name: "no active controller",
			setup: func(mock sqlmock.Sqlmock, p ReportUserDataFaultParams) {
				expectNewDataFaultPrefix(mock, p)
				mock.ExpectQuery(`SELECT global_user.id,legacy_user.id`).WillReturnRows(sqlmock.NewRows([]string{
					"global_user_id", "legacy_user_id", "home_node_id", "username", "node_role", "local_handle", "activity_epoch",
				}).AddRow(int64(70), int64(7), int64(8), "alice", "compute", "alice", int64(1)))
				mock.ExpectQuery(`SELECT EXISTS`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
				mock.ExpectQuery(`SELECT id::text FROM user_data_faults`).WillReturnError(sql.ErrNoRows)
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			},
			want: ErrNoActiveController,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := reportFaultParams(now)
			tc.setup(mock, p)
			_, err := st.ReportUserDataFault(context.Background(), p)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
			assertMockExpectations(t, mock)
		})
	}
}

func TestReportUserDataFaultRollsBackEveryDurableMutationFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 9, 30, 0, 0, time.UTC)
	injected := errors.New("injected user data fault failure")
	for _, stage := range []string{
		"fault", "legacy replica", "replica copy", "activity lease", "control tickets",
		"legacy tickets", "alert", "audit", "commit",
	} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			st, mock, closeDB := newMockStore(t)
			defer closeDB()
			p := reportFaultParams(now)
			expectReportDataFaultFailureAt(mock, p, stage, injected)
			if stage != "commit" {
				mock.ExpectRollback()
			}
			_, err := st.ReportUserDataFault(context.Background(), p)
			if !errors.Is(err, injected) {
				t.Fatalf("stage=%q error=%v", stage, err)
			}
			assertMockExpectations(t, mock)
		})
	}
}
