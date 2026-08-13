package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func TestNewStorageRepairExecutionParamsUsesUniquePurposeScopedFacts(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultController()
	server := &Server{
		Cfg: cfg, secretKey: []byte("durable-storage-repair-secret"),
		workflowWorkerID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
	}
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	p, err := server.newStorageRepairExecutionParams(now)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{p.ExecutionID, p.LeaseOwner, p.WorkflowID, p.OperationID, p.SnapshotID, p.CapabilityID}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !isUUID(id) || seen[id] {
			t.Fatalf("invalid or reused repair identity %q", id)
		}
		seen[id] = true
	}
	capability := deriveTransferCapability(server.secretKey, p.CapabilityID)
	expected := snapshotCapabilityDigest(capability)
	if !bytes.Equal(p.CapabilityHash, expected) || p.LeaseOwner == server.workflowWorkerID ||
		p.LeaseTTL != storageRepairTaskLeaseTTL || !p.CapabilityExpires.Equal(now.Add(snapshotCapabilityTTL)) {
		t.Fatalf("params=%+v", p)
	}
}

func snapshotCapabilityDigest(capability string) []byte {
	digest := sha256Sum([]byte(capability))
	return digest[:]
}

func sha256Sum(value []byte) [32]byte {
	// Kept behind a tiny helper so the test compares bytes rather than the
	// capability plaintext or its printable representation.
	return sha256.Sum256(value)
}

func TestStorageRepairMaxAttemptsIsBounded(t *testing.T) {
	t.Parallel()
	if got := storageRepairMaxAttempts(nil); got != 3 {
		t.Fatalf("default max=%d", got)
	}
	cfg := config.DefaultController()
	cfg.Backup.RetryMax = 100
	if got := storageRepairMaxAttempts(cfg); got != 8 {
		t.Fatalf("bounded max=%d", got)
	}
}

func TestTriggerUserBackupCannotBypassDurableStorageRepairIntent(t *testing.T) {
	t.Parallel()
	server := &Server{}
	err := server.TriggerUserBackup(nil, 1, 2, "storage_repair")
	if err == nil || !strings.Contains(err.Error(), "durable repair reconciler") {
		t.Fatalf("error=%v", err)
	}
}

func TestScheduleStorageRepairsFailsClosedOnDatabaseError(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{
		Cfg: config.DefaultController(), Store: &store.Store{DB: db},
		secretKey: []byte("repair-secret"), workflowWorkerID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		snapshotSlots: make(chan struct{}, 1),
	}
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(sqlmock.AnyArg(), 3).
		WillReturnError(errors.New("database unavailable"))
	mock.ExpectRollback()
	if server.scheduleStorageRepairs(context.Background()) {
		t.Fatal("failed repair pass allowed ordinary offline fallback")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestScheduleStorageRepairsReportsHealthyWhenNothingIsDue(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{
		Cfg: config.DefaultController(), Store: &store.Store{DB: db},
		secretKey: []byte("repair-secret"), workflowWorkerID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		snapshotSlots: make(chan struct{}, 1),
	}
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(sqlmock.AnyArg(), 3).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE storage_repair_tasks task SET`).WithArgs(sqlmock.AnyArg(), 3).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(sqlmock.AnyArg(), 3).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE storage_repair_tasks SET state='failed'`).WithArgs(sqlmock.AnyArg(), 3).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE storage_repair_tasks task SET state='cancelled'`).WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO storage_repair_tasks`).
		WithArgs(sqlmock.AnyArg(), int64(1<<30), int64(64<<20)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectQuery(`FROM storage_repair_tasks task`).WithArgs(sqlmock.AnyArg(), 3).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "legacy_user_id", "user_id", "source_node_id", "estimated_bytes", "attempt",
		}))
	mock.ExpectRollback()
	if !server.scheduleStorageRepairs(context.Background()) {
		t.Fatal("healthy no-op repair pass suppressed unrelated offline backups")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
