package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func controllerBackupScheduleParams(now time.Time) ScheduleControllerDisasterBackupParams {
	return ScheduleControllerDisasterBackupParams{
		OperationID: "11111111-1111-4111-8111-111111111111",
		BackupKind: ControllerBackupKindFull,
		MaxAttempts: 3,
		Interval: 24 * time.Hour,
		LeaseOwner: "22222222-2222-4222-8222-222222222222",
		LeaseTTL: 6 * time.Hour,
		Now: now,
	}
}

func TestScheduleControllerDisasterBackupSkipsWhenCovered(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT generation FROM controller_epochs.*FOR SHARE`).WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*controller_disaster_backups.*succeeded.*created_at`).WithArgs(now.Add(-24*time.Hour)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectCommit()
	run, err := st.ScheduleControllerDisasterBackup(context.Background(), controllerBackupScheduleParams(now))
	if err != nil { t.Fatalf("err=%v", err) }
	if run != nil { t.Fatalf("expected nil run when covered") }
	assertMockExpectations(t, mock)
}

func TestScheduleControllerDisasterBackupCreatesRunOnEligibleTarget(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT generation FROM controller_epochs.*FOR SHARE`).WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*controller_disaster_backups`).WithArgs(now.Add(-24*time.Hour)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery(`(?s)SELECT node.id,node.name.*role=.*storage.*is_backup_target.*FOR UPDATE OF node SKIP LOCKED`).
		WithArgs(now.Add(-2*time.Minute)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(int64(9), "storage-9"))
	mock.ExpectQuery(`(?s)INSERT INTO controller_disaster_backups.*NOT EXISTS.*RETURNING id::text`).
		WithArgs("11111111-1111-4111-8111-111111111111", int64(9), int64(7), "full", now, "22222222-2222-4222-8222-222222222222", now.Add(6*time.Hour)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("33333333-3333-4333-8333-333333333333"))
	mock.ExpectExec(`(?s)INSERT INTO audit_events.*controller-backup`).
		WithArgs(now, int64(7), "11111111-1111-4111-8111-111111111111", int64(9), "full").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	run, err := st.ScheduleControllerDisasterBackup(context.Background(), controllerBackupScheduleParams(now))
	if err != nil { t.Fatalf("err=%v", err) }
	if run == nil || run.NodeID != 9 || run.State != ControllerBackupScheduled || run.ControllerGeneration != 7 { t.Fatalf("unexpected run: %+v", run) }
	assertMockExpectations(t, mock)
}

func TestScheduleControllerDisasterBackupReturnsNoRowsWithoutEligibleNode(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT generation FROM controller_epochs.*FOR SHARE`).WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(7)))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*controller_disaster_backups`).WithArgs(now.Add(-24*time.Hour)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery(`(?s)SELECT node.id,node.name.*FOR UPDATE OF node SKIP LOCKED`).
		WithArgs(now.Add(-2*time.Minute)).WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()
	run, err := st.ScheduleControllerDisasterBackup(context.Background(), controllerBackupScheduleParams(now))
	if err != sql.ErrNoRows { t.Fatalf("expected ErrNoRows, got %v", err) }
	if run != nil { t.Fatalf("expected nil run") }
	assertMockExpectations(t, mock)
}

func TestClaimControllerDisasterBackupClaimsScheduledRun(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	params := ClaimControllerDisasterBackupParams{OperationID: "11111111-1111-4111-8111-111111111111", LeaseOwner: "22222222-2222-4222-8222-222222222222", LeaseTTL: 6 * time.Hour, MaxAttempts: 3, Now: now}
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id::text,node_id,state.*FROM controller_disaster_backups.*FOR UPDATE`).WithArgs("11111111-1111-4111-8111-111111111111").
		WillReturnRows(sqlmock.NewRows([]string{"id", "node_id", "state", "controller_generation", "backup_kind", "attempt", "next_attempt_at"}).
		AddRow("33333333-3333-4333-8333-333333333333", int64(9), "scheduled", int64(7), "full", 0, now))
	mock.ExpectQuery(`(?s)UPDATE controller_disaster_backups tgt SET.*FROM nodes node.*RETURNING tgt.state,tgt.lease_owner::text`).
		WithArgs("33333333-3333-4333-8333-333333333333", "22222222-2222-4222-8222-222222222222", 3, now, now.Add(6*time.Hour)).
		WillReturnRows(sqlmock.NewRows([]string{"state", "lease_owner", "lease_until", "started_at", "finished_at", "attempt"}).
		AddRow("snapshotting", "22222222-2222-4222-8222-222222222222", now.Add(6*time.Hour), now, nil, 1))
	mock.ExpectCommit()
	run, err := st.ClaimControllerDisasterBackup(context.Background(), params)
	if err != nil { t.Fatalf("err=%v", err) }
	if run == nil || run.State != ControllerBackupSnapshotting || run.Attempt != 1 { t.Fatalf("unexpected run: %+v", run) }
	assertMockExpectations(t, mock)
}

func TestClaimControllerDisasterBackupNoRowsNil(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	params := ClaimControllerDisasterBackupParams{OperationID: "11111111-1111-4111-8111-111111111111", LeaseOwner: "22222222-2222-4222-8222-222222222222", LeaseTTL: 6 * time.Hour, MaxAttempts: 3, Now: now}
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id::text,node_id,state.*FOR UPDATE`).WithArgs("11111111-1111-4111-8111-111111111111").WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()
	run, err := st.ClaimControllerDisasterBackup(context.Background(), params)
	if err != nil { t.Fatalf("err=%v", err) }
	if run != nil { t.Fatalf("expected nil run") }
	assertMockExpectations(t, mock)
}

func TestCompleteControllerDisasterBackupPersistsMetadata(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	manifest := json.RawMessage(`{"db_dump":true}`)
	shaHex := strings.Repeat("a", 64)
	mock.ExpectExec(`(?s)UPDATE controller_disaster_backups SET.*state=.succeeded.*payload_sha256=decode`).
		WithArgs("11111111-1111-4111-8111-111111111111", "controller_backup.tar.zst", int64(12345), shaHex, manifest, sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	err := st.CompleteControllerDisasterBackup(context.Background(), "11111111-1111-4111-8111-111111111111", "controller_backup.tar.zst", shaHex, 12345, manifest)
	if err != nil { t.Fatalf("err=%v", err) }
	assertMockExpectations(t, mock)
}

func TestCompleteControllerDisasterBackupRejectsBadInput(t *testing.T) {
	t.Parallel()
	st, _, closeDB := newMockStore(t)
	defer closeDB()
	err := st.CompleteControllerDisasterBackup(context.Background(), "11111111-1111-4111-8111-111111111111", "", "aa", 0, nil)
	if !errors.Is(err, ErrInvalidControllerDisasterBackup) { t.Fatalf("expected invalid input error, got %v", err) }
}
func TestFailControllerDisasterBackupMovesToRetryWait(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT attempt FROM controller_disaster_backups.*FOR UPDATE`).WithArgs("11111111-1111-4111-8111-111111111111").WillReturnRows(sqlmock.NewRows([]string{"attempt"}).AddRow(1))
	mock.ExpectExec(`(?s)UPDATE controller_disaster_backups SET.*state=CASE WHEN.*retry_wait`).
		WithArgs("11111111-1111-4111-8111-111111111111", "target_unavailable", 2, 3, now.Add(60*time.Second), now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	err := st.FailControllerDisasterBackup(context.Background(), "11111111-1111-4111-8111-111111111111", "target_unavailable", 3, now)
	if err != nil { t.Fatalf("err=%v", err) }
	assertMockExpectations(t, mock)
}

func TestFailControllerDisasterBackupMovesToFailedAtMaxAttempts(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT attempt FROM controller_disaster_backups.*FOR UPDATE`).WithArgs("11111111-1111-4111-8111-111111111111").WillReturnRows(sqlmock.NewRows([]string{"attempt"}).AddRow(3))
	mock.ExpectExec(`(?s)UPDATE controller_disaster_backups SET.*state=CASE WHEN.*failed`).
		WithArgs("11111111-1111-4111-8111-111111111111", "pg_dump_failed", 4, 3, now.Add(240*time.Second), now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	err := st.FailControllerDisasterBackup(context.Background(), "11111111-1111-4111-8111-111111111111", "pg_dump_failed", 3, now)
	if err != nil { t.Fatalf("err=%v", err) }
	assertMockExpectations(t, mock)
}

func TestReconcileControllerDisasterBackupsSupersedesOlderPerNode(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(`(?s)UPDATE controller_disaster_backups SET state=.superseded.*rank.*rnk>1`).WithArgs(now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE controller_disaster_backups SET state=.failed.*attempt_limit_reached`).WithArgs(now, 3).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	touched, err := st.ReconcileControllerDisasterBackups(context.Background(), now, 3)
	if err != nil { t.Fatalf("err=%v", err) }
	if touched != 1 { t.Fatalf("expected touched=1, got %d", touched) }
	assertMockExpectations(t, mock)
}

func TestMarkControllerDisasterBackupProgressTransitions(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectExec(`(?s)UPDATE controller_disaster_backups SET state=\$2,updated_at=\$3.*WHERE operation_id=\$1`).
		WithArgs("11111111-1111-4111-8111-111111111111", "snapshotting", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	err := st.MarkControllerDisasterBackupProgress(context.Background(), "11111111-1111-4111-8111-111111111111", ControllerBackupSnapshotting)
	if err != nil { t.Fatalf("err=%v", err) }
	assertMockExpectations(t, mock)
}