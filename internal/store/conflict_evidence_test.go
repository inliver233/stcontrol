package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestListAndClaimConflictEvidenceTask(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 15, 0, 0, 0, time.UTC)
	manifest := bytes.Repeat([]byte{1}, 32)
	mock.ExpectQuery(`(?s)FROM replica_conflict_sources source.*conflict.state IN.*source.evidence_state='pending'`).
		WithArgs(20, now).
		WillReturnRows(sqlmock.NewRows([]string{
			"conflict", "evidence", "user", "handle", "node", "role", "kind", "snapshot", "manifest", "attempt",
		}).AddRow("cccccccc-cccc-4ccc-8ccc-cccccccccccc", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
			int64(70), "alice", int64(9), "storage", "archive",
			"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", manifest, 0))
	tasks, err := store.ListConflictEvidenceTasks(context.Background(), 0, now)
	if err != nil || len(tasks) != 1 || tasks[0].NodeID != 9 || !tasks[0].SourceSnapshotID.Valid {
		t.Fatalf("tasks=%+v err=%v", tasks, err)
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)UPDATE replica_conflict_sources source.*evidence_lease_owner.*RETURNING source.conflict_id`).
		WithArgs(tasks[0].EvidenceID, "worker", now, now.Add(time.Hour)).
		WillReturnRows(sqlmock.NewRows([]string{"conflict_id", "attempt"}).
			AddRow(tasks[0].ConflictID, 1))
	mock.ExpectExec(`UPDATE replica_conflicts SET state='inspecting'`).
		WithArgs(tasks[0].ConflictID, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	attempt, claimed, err := store.ClaimConflictEvidenceTask(
		context.Background(), tasks[0].EvidenceID, "worker", now, time.Hour,
	)
	if err != nil || !claimed || attempt != 1 {
		t.Fatalf("attempt=%d claimed=%v err=%v", attempt, claimed, err)
	}
	assertMockExpectations(t, mock)
}

func TestRetryConflictEvidenceTaskUsesBoundedTerminalAttempts(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 15, 10, 0, 0, time.UTC)
	mock.ExpectExec(`UPDATE replica_conflict_sources`).
		WithArgs("evidence", "worker", "retry_wait", "capture_unavailable", now.Add(4*time.Second), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.RetryConflictEvidenceTask(
		context.Background(), "evidence", "worker", "capture_unavailable", 2, now,
	); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(`UPDATE replica_conflict_sources`).
		WithArgs("evidence", "worker", "failed", "capture_unavailable", nil, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.RetryConflictEvidenceTask(
		context.Background(), "evidence", "worker", "capture_unavailable", 5, now,
	); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestCompleteConflictEvidenceAtomicallyStoresEncryptedPages(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 15, 20, 0, 0, time.UTC)
	conflictID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	evidenceID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	digest := bytes.Repeat([]byte{2}, 32)
	p := CompleteConflictEvidenceParams{
		ConflictID: conflictID, EvidenceID: evidenceID, WorkerID: "worker",
		EntriesSHA256: digest, FileCount: 2, TotalBytes: 40, CaptureBasis: "frozen_live", Now: now,
		Pages: []ConflictEvidencePageRecord{
			{PageIndex: 0, EntryCount: 1, EncryptedPayload: "cipher-one", PlaintextSHA256: digest},
			{PageIndex: 1, EntryCount: 1, EncryptedPayload: "cipher-two", PlaintextSHA256: digest},
		},
		CommandOperationIDs: []string{"op-one", "op-two"},
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)FROM replica_conflict_sources source.*FOR UPDATE OF source,conflict`).
		WithArgs(conflictID, evidenceID, "worker").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow(int64(70)))
	for _, page := range p.Pages {
		mock.ExpectExec(`INSERT INTO replica_conflict_manifest_pages`).
			WithArgs(evidenceID, page.PageIndex, page.EntryCount, page.EncryptedPayload, page.PlaintextSHA256, now).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectExec(`UPDATE replica_conflict_sources`).
		WithArgs(evidenceID, "worker", "frozen_live", digest, int64(2), int64(40), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE replica_conflicts conflict.*awaiting_decision`).
		WithArgs(conflictID, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE agent_commands.*result_summary`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`INSERT INTO audit_events`).
		WithArgs(int64(70), conflictID, evidenceID, int64(2), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := store.CompleteConflictEvidence(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}

func TestLoadConflictEvidencePagesAndInputValidation(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`(?s)FROM replica_conflict_sources source.*source.evidence_state='ready'`).
		WithArgs("conflict", int64(8)).
		WillReturnRows(sqlmock.NewRows([]string{"encrypted_payload"}).AddRow("one").AddRow("two"))
	pages, err := store.LoadConflictEvidencePages(context.Background(), "conflict", 8)
	if err != nil || len(pages) != 2 || pages[1] != "two" {
		t.Fatalf("pages=%v err=%v", pages, err)
	}
	if err := store.CompleteConflictEvidence(context.Background(), CompleteConflictEvidenceParams{}); !errors.Is(err, ErrConflictEvidenceState) {
		t.Fatalf("invalid complete error=%v", err)
	}
	if _, _, err := store.ClaimConflictEvidenceTask(context.Background(), "", "", time.Time{}, 0); !errors.Is(err, ErrConflictEvidenceState) {
		t.Fatalf("invalid claim error=%v", err)
	}
	assertMockExpectations(t, mock)
}
