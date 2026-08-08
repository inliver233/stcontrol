package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

const (
	leaseColumns = "user_id,writer_node_id,session_id,activity_epoch,state,lease_expires_at,last_page_heartbeat_at,last_request_at,in_flight_reads,in_flight_writes,controller_generation,updated_at"
	opColumns    = "outcome,result_writer_node_id,result_session_id,result_activity_epoch"
)

func TestAcquireActivityLeaseRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	store := &Store{}
	_, err := store.AcquireActivityLease(context.Background(), AcquireActivityLeaseParams{})
	if !errors.Is(err, ErrInvalidLeaseInput) {
		t.Fatalf("AcquireActivityLease error=%v, want ErrInvalidLeaseInput", err)
	}
}

func TestUpdateActivityLeaseTelemetryUsesFullGenerationFence(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 1, 2, 3, 0, time.UTC)
	page := now.Add(-time.Minute)
	request := now.Add(-time.Second)
	mock.ExpectExec(`UPDATE user_activity_leases`).
		WithArgs(int64(70), int64(8), "11111111-1111-4111-8111-111111111111", int64(4), now,
			page, request, 2, 1, true, now.Add(15*time.Minute), int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := store.UpdateActivityLeaseTelemetry(context.Background(), ActivityLeaseTelemetry{
		UserID: 70, WriterNodeID: 8, SessionID: "11111111-1111-4111-8111-111111111111",
		ActivityEpoch: 4, ControllerGeneration: 9, LastPageHeartbeatAt: page, LastRequestAt: request,
		InFlightReads: 2, InFlightWrites: 1, Online: true, Now: now, TTL: 15 * time.Minute,
	})
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAcquireActivityLeaseCreatesFirstWriter(t *testing.T) {
	t.Parallel()

	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	p := AcquireActivityLeaseParams{
		OperationID:          "11111111-1111-4111-8111-111111111111",
		UserID:               10,
		WriterNodeID:         20,
		SessionID:            "22222222-2222-4222-8222-222222222222",
		ControllerGeneration: 3,
		TTL:                  15 * time.Minute,
		Now:                  now,
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users WHERE id=\$1 FOR UPDATE`).
		WithArgs(p.UserID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.UserID))
	mock.ExpectQuery(`SELECT outcome, result_writer_node_id, result_session_id, result_activity_epoch FROM activity_lease_operations`).
		WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows(splitColumns(opColumns)))
	mock.ExpectQuery(`SELECT user_id, writer_node_id, session_id, activity_epoch, state, lease_expires_at`).
		WithArgs(p.UserID).
		WillReturnRows(sqlmock.NewRows(splitColumns(leaseColumns)))
	mock.ExpectExec(`INSERT INTO user_activity_leases`).
		WithArgs(p.UserID, p.WriterNodeID, p.SessionID, int64(1), now.Add(p.TTL), now, p.ControllerGeneration).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`INSERT INTO activity_lease_operations`).
		WithArgs(p.OperationID, p.UserID, p.WriterNodeID, p.SessionID, "acquired",
			p.WriterNodeID, p.SessionID, int64(1), now).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	result, err := store.AcquireActivityLease(context.Background(), p)
	if err != nil {
		t.Fatalf("AcquireActivityLease: %v", err)
	}
	if !result.Acquired || result.Existing {
		t.Fatalf("unexpected result flags: %+v", result)
	}
	if result.Lease.WriterNodeID != p.WriterNodeID || result.Lease.ActivityEpoch != 1 || result.Lease.State != "active" {
		t.Fatalf("unexpected lease: %+v", result.Lease)
	}
	assertMockExpectations(t, mock)
}

func TestAcquireActivityLeasePreservesExistingWriter(t *testing.T) {
	t.Parallel()

	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	p := AcquireActivityLeaseParams{
		OperationID:          "33333333-3333-4333-8333-333333333333",
		UserID:               10,
		WriterNodeID:         30,
		SessionID:            "44444444-4444-4444-8444-444444444444",
		ControllerGeneration: 3,
		TTL:                  15 * time.Minute,
		Now:                  now,
	}
	existingSession := "55555555-5555-4555-8555-555555555555"
	expires := now.Add(5 * time.Minute)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users WHERE id=\$1 FOR UPDATE`).
		WithArgs(p.UserID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.UserID))
	mock.ExpectQuery(`SELECT outcome, result_writer_node_id, result_session_id, result_activity_epoch FROM activity_lease_operations`).
		WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows(splitColumns(opColumns)))
	mock.ExpectQuery(`SELECT user_id, writer_node_id, session_id, activity_epoch, state, lease_expires_at`).
		WithArgs(p.UserID).
		WillReturnRows(sqlmock.NewRows(splitColumns(leaseColumns)).AddRow(
			p.UserID, int64(20), existingSession, int64(7), "active", expires, now, now,
			0, 1, int64(3), now,
		))
	mock.ExpectExec(`INSERT INTO activity_lease_operations`).
		WithArgs(p.OperationID, p.UserID, p.WriterNodeID, p.SessionID, "existing",
			int64(20), existingSession, int64(7), now).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	result, err := store.AcquireActivityLease(context.Background(), p)
	if err != nil {
		t.Fatalf("AcquireActivityLease: %v", err)
	}
	if result.Acquired || !result.Existing {
		t.Fatalf("unexpected result flags: %+v", result)
	}
	if result.Lease.WriterNodeID != 20 || result.Lease.SessionID != existingSession || result.Lease.ActivityEpoch != 7 {
		t.Fatalf("existing writer was not preserved: %+v", result.Lease)
	}
	assertMockExpectations(t, mock)
}

func TestAcquireActivityLeaseReplaysOperationResult(t *testing.T) {
	t.Parallel()

	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := AcquireActivityLeaseParams{
		OperationID:          "66666666-6666-4666-8666-666666666666",
		UserID:               10,
		WriterNodeID:         20,
		SessionID:            "77777777-7777-4777-8777-777777777777",
		ControllerGeneration: 3,
		TTL:                  15 * time.Minute,
		Now:                  time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC),
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users WHERE id=\$1 FOR UPDATE`).
		WithArgs(p.UserID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.UserID))
	mock.ExpectQuery(`SELECT outcome, result_writer_node_id, result_session_id, result_activity_epoch FROM activity_lease_operations`).
		WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows(splitColumns(opColumns)).AddRow("acquired", p.WriterNodeID, p.SessionID, int64(9)))
	mock.ExpectCommit()

	result, err := store.AcquireActivityLease(context.Background(), p)
	if err != nil {
		t.Fatalf("AcquireActivityLease: %v", err)
	}
	if !result.Acquired || result.Lease.ActivityEpoch != 9 {
		t.Fatalf("unexpected replay result: %+v", result)
	}
	assertMockExpectations(t, mock)
}

func TestRenewAndEndActivityLeaseAreFenced(t *testing.T) {
	t.Parallel()

	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

	mock.ExpectExec(`UPDATE user_activity_leases SET lease_expires_at=\$7`).
		WithArgs(int64(10), int64(20), "session", int64(4), int64(2), now, now.Add(time.Minute)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := store.RenewActivityLease(context.Background(), 10, 20, "session", 4, 2, now, time.Minute)
	if err != nil || !ok {
		t.Fatalf("RenewActivityLease ok=%v err=%v", ok, err)
	}

	mock.ExpectExec(`UPDATE user_activity_leases SET state='ended'`).
		WithArgs(int64(10), int64(20), "session", int64(4), int64(2), now).
		WillReturnResult(sqlmock.NewResult(0, 0))
	ok, err = store.EndActivityLease(context.Background(), 10, 20, "session", 4, 2, now)
	if err != nil || ok {
		t.Fatalf("EndActivityLease ok=%v err=%v, want stale false", ok, err)
	}
	assertMockExpectations(t, mock)
}

func newMockStore(t *testing.T) (*Store, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	return &Store{DB: db}, mock, func() { _ = db.Close() }
}

func assertMockExpectations(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func splitColumns(csv string) []string {
	var columns []string
	start := 0
	for i := 0; i <= len(csv); i++ {
		if i == len(csv) || csv[i] == ',' {
			columns = append(columns, csv[start:i])
			start = i + 1
		}
	}
	return columns
}
