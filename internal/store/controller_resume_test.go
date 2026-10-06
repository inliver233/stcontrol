package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestAcquireActivityLeaseRenewsStaleGenerationOnItsWriter(t *testing.T) {
	t.Parallel()

	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)
	p := AcquireActivityLeaseParams{
		OperationID:          "66666666-6666-4666-8666-666666666666",
		UserID:               10,
		WriterNodeID:         30,
		SessionID:            "77777777-7777-4777-8777-777777777777",
		ControllerGeneration: 68,
		TTL:                  15 * time.Minute,
		ExistingWriterOnly:   true,
		Now:                  now,
	}
	oldSession := "88888888-8888-4888-8888-888888888888"

	expectRenewalPrefix := func() {
		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT id FROM global_users WHERE id=\$1 FOR UPDATE`).
			WithArgs(p.UserID).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.UserID))
		mock.ExpectQuery(`FROM activity_lease_operations`).
			WithArgs(p.OperationID).
			WillReturnRows(sqlmock.NewRows(splitColumns(opColumns)))
		mock.ExpectQuery(`SELECT user_id, writer_node_id, session_id, activity_epoch, state, lease_expires_at`).
			WithArgs(p.UserID).
			WillReturnRows(sqlmock.NewRows(splitColumns(leaseColumns)).AddRow(
				p.UserID, int64(20), oldSession, int64(7), "active", now.Add(10*time.Minute), now, now,
				0, 0, int64(67), now,
			))
	}
	expectRenewalPrefix()
	mock.ExpectExec(`(?s)UPDATE user_activity_leases SET.*WHERE user_id=\$1 AND writer_node_id=\$2 AND activity_epoch=\$8\s+AND controller_generation=\$9 AND state='active'`).
		WithArgs(p.UserID, int64(20), p.SessionID, int64(8), now.Add(15*time.Minute), now, int64(68), int64(7), int64(67)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO activity_lease_operations`).
		WithArgs(p.OperationID, p.UserID, p.WriterNodeID, p.SessionID, "renewed",
			int64(20), p.SessionID, int64(8), now).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	result, err := store.AcquireActivityLease(context.Background(), p)
	if err != nil {
		t.Fatalf("AcquireActivityLease: %v", err)
	}
	if result.Acquired || !result.Existing || result.Lease.WriterNodeID != 20 ||
		result.Lease.ActivityEpoch != 8 || result.Lease.ControllerGeneration != 68 || result.Lease.SessionID != p.SessionID {
		t.Fatalf("renewed lease=%+v", result)
	}
	assertMockExpectations(t, mock)

	// A lease that changed under the row lock is never silently overwritten.
	expectRenewalPrefix()
	mock.ExpectExec(`UPDATE user_activity_leases SET`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()
	if _, err := store.AcquireActivityLease(context.Background(), p); err == nil {
		t.Fatal("renewal of a changed lease must fail")
	}
	assertMockExpectations(t, mock)
}

func TestResumeControllerEpochContinuesRecentCleanShutdown(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)
	stoppedAt := now.Add(-40 * time.Second)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT generation,clean_shutdown_at FROM controller_epochs\s+WHERE state='active' FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"generation", "clean_shutdown_at"}).AddRow(int64(67), stoppedAt))
	mock.ExpectExec(`UPDATE controller_epochs SET clean_shutdown_at=NULL`).WithArgs(int64(67)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO audit_events.*controller-generation-resumed`).
		WithArgs(int64(67), "controller-clean-restart", stoppedAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	generation, resumed, err := store.ResumeControllerEpoch(context.Background(), "controller-clean-restart", 10*time.Minute, now)
	if err != nil || !resumed || generation != 67 {
		t.Fatalf("generation=%d resumed=%v err=%v", generation, resumed, err)
	}
	assertMockExpectations(t, mock)
}

func TestResumeControllerEpochPromotesWithoutUsableRecord(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)

	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	// No record (a crash or a lost lock): nothing changes.
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT generation,clean_shutdown_at FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation", "clean_shutdown_at"}).AddRow(int64(67), nil))
	mock.ExpectRollback()
	if generation, resumed, err := store.ResumeControllerEpoch(context.Background(), "controller-clean-restart", 10*time.Minute, now); err != nil || resumed || generation != 0 {
		t.Fatalf("missing record: generation=%d resumed=%v err=%v", generation, resumed, err)
	}
	// A record older than the window (or from the future) is cleared without resuming.
	for _, stoppedAt := range []time.Time{now.Add(-11 * time.Minute), now.Add(2 * time.Minute)} {
		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT generation,clean_shutdown_at FROM controller_epochs`).
			WillReturnRows(sqlmock.NewRows([]string{"generation", "clean_shutdown_at"}).AddRow(int64(67), stoppedAt))
		mock.ExpectExec(`UPDATE controller_epochs SET clean_shutdown_at=NULL`).WithArgs(int64(67)).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		if generation, resumed, err := store.ResumeControllerEpoch(context.Background(), "controller-clean-restart", 10*time.Minute, now); err != nil || resumed || generation != 0 {
			t.Fatalf("record at %s: generation=%d resumed=%v err=%v", stoppedAt, generation, resumed, err)
		}
	}
	// No active generation at all: the caller promotes (and reports it there).
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT generation,clean_shutdown_at FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation", "clean_shutdown_at"}))
	mock.ExpectRollback()
	if _, resumed, err := store.ResumeControllerEpoch(context.Background(), "controller-clean-restart", 10*time.Minute, now); err != nil || resumed {
		t.Fatalf("no active generation: resumed=%v err=%v", resumed, err)
	}
	assertMockExpectations(t, mock)

	for _, bad := range []struct {
		source string
		gap    time.Duration
	}{{"", time.Minute}, {"x", 0}} {
		if _, _, err := store.ResumeControllerEpoch(context.Background(), bad.source, bad.gap, now); err == nil {
			t.Fatalf("invalid resume request %+v accepted", bad)
		}
	}
}

func TestMarkCleanShutdownRequiresTheLeadershipLock(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT pg_try_advisory_lock`).WithArgs(controllerAdvisoryLockID).
		WillReturnRows(sqlmock.NewRows([]string{"acquired"}).AddRow(true))
	leadership, acquired, err := store.TryAcquireControllerLeadership(context.Background())
	if err != nil || !acquired {
		t.Fatalf("acquire: acquired=%v err=%v", acquired, err)
	}
	high, low := int64(0x5354434f), int64(0x4e54524c)
	mock.ExpectExec(`(?s)UPDATE controller_epochs SET clean_shutdown_at=\$2.*FROM pg_locks.*pid=pg_backend_pid\(\)`).
		WithArgs(int64(67), now, high, low).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if marked, err := leadership.MarkCleanShutdown(context.Background(), 67, now); err != nil || !marked {
		t.Fatalf("mark: marked=%v err=%v", marked, err)
	}
	mock.ExpectExec(`UPDATE controller_epochs SET clean_shutdown_at`).
		WithArgs(int64(67), now, high, low).
		WillReturnResult(sqlmock.NewResult(0, 0))
	if marked, err := leadership.MarkCleanShutdown(context.Background(), 67, now); err != nil || marked {
		t.Fatalf("mark without the lock: marked=%v err=%v", marked, err)
	}
	if _, err := leadership.MarkCleanShutdown(context.Background(), 0, now); err == nil {
		t.Fatal("invalid generation accepted")
	}
	var missing *ControllerLeadership
	if _, err := missing.MarkCleanShutdown(context.Background(), 67, now); err == nil {
		t.Fatal("missing leadership accepted")
	}
	assertMockExpectations(t, mock)
}
