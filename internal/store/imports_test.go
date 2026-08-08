package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func importBatchParams(now time.Time) CreateAccountImportBatchParams {
	return CreateAccountImportBatchParams{
		ID:          "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		NodeID:      12, InventoryDigest: bytes.Repeat([]byte{1}, 32), Source: "directory_fallback",
		CreatedByAdminID: 5, Now: now,
		Candidates: []AccountImportCandidateInput{{
			ID:          "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
			LocalUserID: "alice", LocalHandle: "alice", SizeBytes: 123,
			DirectoryFingerprint: strings.Repeat("a", 64),
			Source:               "directory_fallback", AccountKind: "unknown",
		}},
	}
}

func expectImportBatchRead(
	mock sqlmock.Sqlmock,
	p CreateAccountImportBatchParams,
	state, resolution string,
	autoLinked int,
	matchedUUID string,
	reason string,
) {
	mock.ExpectQuery(`SELECT id,node_id,source,state,candidate_count`).WithArgs(p.ID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "node_id", "source", "state", "candidate_count", "auto_linked_count",
			"unresolved_count", "scanned_at", "created_at",
		}).AddRow(p.ID, p.NodeID, p.Source, state, 1, autoLinked, 1-autoLinked, p.Now, p.Now))
	mock.ExpectQuery(`SELECT candidate.id,candidate.local_handle`).WithArgs(p.ID, 101, 0).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "local_handle", "size_bytes", "source", "account_kind", "identity_fingerprints",
			"is_admin", "resolution_state", "matched_user_uuid", "reason_code",
		}).AddRow(p.Candidates[0].ID, p.Candidates[0].LocalHandle, p.Candidates[0].SizeBytes,
			p.Candidates[0].Source, p.Candidates[0].AccountKind, []byte(`{}`), false,
			resolution, matchedUUID, reason))
}

func TestIngestAccountImportSameHandleRequiresProofAndReturnsSafeInventory(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 3, 5, 0, 0, time.UTC)
	p := importBatchParams(now)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id,node_id,inventory_digest`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "node_id", "inventory_digest"}))
	mock.ExpectQuery(`INSERT INTO account_import_batches`).WithArgs(
		p.ID, p.OperationID, p.NodeID, p.InventoryDigest, p.Source, p.CreatedByAdminID, now,
	).WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(3)))
	mock.ExpectQuery(`SELECT user_id,local_user_id FROM node_accounts`).WithArgs(
		p.NodeID, "alice", "alice",
	).WillReturnRows(sqlmock.NewRows([]string{"user_id", "local_user_id"}))
	mock.ExpectQuery(`SELECT global_user.id FROM users legacy`).WithArgs("alice").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
	mock.ExpectExec(`INSERT INTO account_import_candidates`).WithArgs(
		p.Candidates[0].ID, p.ID, p.NodeID, "alice", "alice", int64(123), bytes.Repeat([]byte{0xaa}, 32),
		"directory_fallback", "unknown", []byte(`{}`), false, "claim_required", nil,
		"same_handle_requires_control_proof", now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE account_import_batches`).WithArgs(p.ID, "review", 1, 0, 1, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	expectImportBatchRead(mock, p, "review", "claim_required", 0, "", "same_handle_requires_control_proof")
	result, err := st.IngestAccountImportBatch(context.Background(), p)
	if err != nil || result == nil || result.Batch.UnresolvedCount != 1 ||
		result.Candidates[0].ResolutionState != "claim_required" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	encoded, err := json.Marshal(result)
	if err != nil || bytes.Contains(encoded, []byte("local_user_id")) ||
		bytes.Contains(encoded, []byte(strings.Repeat("a", 64))) {
		t.Fatalf("unsafe result=%s err=%v", encoded, err)
	}
	assertMockExpectations(t, mock)
}

func TestIngestAccountImportAutoLinksUniqueOAuthIdentity(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 3, 10, 0, 0, time.UTC)
	p := importBatchParams(now)
	p.Source = "adapter"
	p.Candidates[0].Source = "adapter"
	p.Candidates[0].AccountKind = "oauth"
	p.Candidates[0].Identities = []AccountImportIdentityFingerprint{{
		Provider: "discord", Fingerprint: strings.Repeat("b", 64),
	}}
	p.Candidates[0].MatchedGlobalUserIDs = []int64{70}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id,node_id,inventory_digest`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "node_id", "inventory_digest"}))
	mock.ExpectQuery(`INSERT INTO account_import_batches`).WithArgs(
		p.ID, p.OperationID, p.NodeID, p.InventoryDigest, p.Source, p.CreatedByAdminID, now,
	).WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(3)))
	mock.ExpectQuery(`SELECT user_id,local_user_id FROM node_accounts`).WithArgs(
		p.NodeID, "alice", "alice",
	).WillReturnRows(sqlmock.NewRows([]string{"user_id", "local_user_id"}))
	mock.ExpectQuery(`SELECT legacy_user_id,status FROM global_users`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"legacy_user_id", "status"}).AddRow(int64(7), "active"))
	mock.ExpectQuery(`SELECT local_handle FROM node_accounts`).WithArgs(int64(70), p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"local_handle"}))
	mock.ExpectQuery(`SELECT COALESCE\(jsonb_object_agg`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"oauth_subjects"}).AddRow([]byte(`{"discord":"stable-subject"}`)))
	mock.ExpectExec(`INSERT INTO node_accounts`).WithArgs(
		int64(70), p.NodeID, "alice", "alice", []byte(`{"discord":"stable-subject"}`), false, now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`UPDATE users SET home_node_id`).WithArgs(int64(7), p.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"home_node_id"}).AddRow(p.NodeID))
	mock.ExpectExec(`INSERT INTO user_replicas`).WithArgs(int64(7), p.NodeID, "home", "ready", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO account_import_candidates`).WithArgs(
		p.Candidates[0].ID, p.ID, p.NodeID, "alice", "alice", int64(123), bytes.Repeat([]byte{0xaa}, 32),
		"adapter", "oauth", []byte(`{"discord":"`+strings.Repeat("b", 64)+`"}`), false,
		"auto_linked", int64(70), "oauth_subject_match", now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE account_import_batches`).WithArgs(p.ID, "resolved", 1, 1, 0, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectQuery(`SELECT id,node_id,source,state,candidate_count`).WithArgs(p.ID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "node_id", "source", "state", "candidate_count", "auto_linked_count",
			"unresolved_count", "scanned_at", "created_at",
		}).AddRow(p.ID, p.NodeID, p.Source, "resolved", 1, 1, 0, now, now))
	mock.ExpectQuery(`SELECT candidate.id,candidate.local_handle`).WithArgs(p.ID, 101, 0).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "local_handle", "size_bytes", "source", "account_kind", "identity_fingerprints",
			"is_admin", "resolution_state", "matched_user_uuid", "reason_code",
		}).AddRow(p.Candidates[0].ID, "alice", int64(123), "adapter", "oauth",
			[]byte(`{"discord":"`+strings.Repeat("b", 64)+`"}`), false, "auto_linked",
			"dddddddd-dddd-4ddd-8ddd-dddddddddddd", "oauth_subject_match"))
	result, err := st.IngestAccountImportBatch(context.Background(), p)
	if err != nil || result == nil || result.Batch.AutoLinkedCount != 1 ||
		result.Candidates[0].MatchedUserUUID == "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	assertMockExpectations(t, mock)
}

func TestIngestAccountImportRejectsOperationDigestReuse(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 3, 15, 0, 0, time.UTC)
	p := importBatchParams(now)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id,node_id,inventory_digest`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "node_id", "inventory_digest"}).
			AddRow("existing", p.NodeID, bytes.Repeat([]byte{9}, 32)))
	mock.ExpectRollback()
	_, err := st.IngestAccountImportBatch(context.Background(), p)
	if !errors.Is(err, ErrAccountImportConflict) {
		t.Fatalf("error=%v, want conflict", err)
	}
	assertMockExpectations(t, mock)
}

func TestLatestAccountImportBatchReturnsSafeEmptyCandidateList(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 3, 20, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT id FROM account_import_batches`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("batch-id"))
	mock.ExpectQuery(`SELECT id,node_id,source,state,candidate_count`).WithArgs("batch-id").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "node_id", "source", "state", "candidate_count", "auto_linked_count",
			"unresolved_count", "scanned_at", "created_at",
		}).AddRow("batch-id", int64(12), "adapter", "resolved", 0, 0, 0, now, now))
	mock.ExpectQuery(`SELECT candidate.id,candidate.local_handle`).WithArgs("batch-id", 101, 0).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "local_handle", "size_bytes", "source", "account_kind", "identity_fingerprints",
			"is_admin", "resolution_state", "matched_user_uuid", "reason_code",
		}))
	result, err := st.GetLatestAccountImportBatch(context.Background(), 12)
	if err != nil || result == nil || result.Batch.CandidateCount != 0 || result.Candidates != nil {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	assertMockExpectations(t, mock)
}

func TestOAuthIdentitySubjectModelNeverSerializesRawSubject(t *testing.T) {
	t.Parallel()
	encoded, err := json.Marshal(OAuthIdentitySubject{
		GlobalUserID: 70, Provider: "discord", Subject: "sensitive-stable-subject",
	})
	if err != nil || string(encoded) != `{}` {
		t.Fatalf("encoded=%s err=%v", encoded, err)
	}
}

func TestAccountImportCandidatePagesAreBoundedAndStable(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 3, 30, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT id,node_id,source,state,candidate_count`).WithArgs("batch-id").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "node_id", "source", "state", "candidate_count", "auto_linked_count",
			"unresolved_count", "scanned_at", "created_at",
		}).AddRow("batch-id", int64(12), "adapter", "review", 10, 0, 10, now, now))
	rows := sqlmock.NewRows([]string{
		"id", "local_handle", "size_bytes", "source", "account_kind", "identity_fingerprints",
		"is_admin", "resolution_state", "matched_user_uuid", "reason_code",
	}).AddRow("candidate-5", "user-005", int64(5), "adapter", "password", []byte(`{}`), false, "recovery_required", "", "proof_required").
		AddRow("candidate-6", "user-006", int64(6), "adapter", "password", []byte(`{}`), false, "recovery_required", "", "proof_required").
		AddRow("candidate-7", "user-007", int64(7), "adapter", "password", []byte(`{}`), false, "recovery_required", "", "proof_required")
	mock.ExpectQuery(`SELECT candidate.id,candidate.local_handle`).WithArgs("batch-id", 3, 5).
		WillReturnRows(rows)
	result, err := st.GetAccountImportBatchPage(context.Background(), "batch-id", 5, 2)
	if err != nil || result == nil || len(result.Candidates) != 2 || !result.HasMore ||
		result.CandidateOffset != 5 || result.CandidateLimit != 2 || result.NextCandidateOffset != 7 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	assertMockExpectations(t, mock)
}

func TestAccountImportCapacityBoundIsTenThousand(t *testing.T) {
	t.Parallel()
	p := importBatchParams(time.Now().UTC())
	p.Candidates = make([]AccountImportCandidateInput, 10_001)
	if err := validateAccountImportBatch(p); !errors.Is(err, ErrInvalidAccountImport) {
		t.Fatalf("oversized inventory error=%v", err)
	}
	if _, err := (&Store{}).GetAccountImportBatchPage(context.Background(), "batch", 0, 101); !errors.Is(err, ErrInvalidAccountImport) {
		t.Fatalf("unbounded page error=%v", err)
	}
}

func TestCompleteAccountImportClaimRequiresExactNodeProof(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 4, 0, 0, 0, time.UTC)
	p := CompleteAccountImportClaimParams{
		OperationID: "11111111-1111-4111-8111-111111111111", GlobalUserID: 70, NodeID: 12,
		LocalHandle: "alice", LocalUserID: "local-alice", Now: now,
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT user_id,node_id,local_user_id FROM account_import_claim_operations`).WithArgs(p.OperationID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT candidate.id,candidate.batch_id`).WithArgs(p.NodeID, p.LocalHandle).
		WillReturnRows(sqlmock.NewRows([]string{"id", "batch_id", "local_user_id", "local_handle", "is_admin"}).
			AddRow("candidate-id", "batch-id", p.LocalUserID, p.LocalHandle, false))
	mock.ExpectQuery(`SELECT global_user.legacy_user_id`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"legacy_user_id", "username", "status"}).AddRow(int64(8), "alice", "active"))
	mock.ExpectQuery(`SELECT 1 FROM node_accounts`).WithArgs(p.NodeID, p.GlobalUserID, p.LocalUserID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`INSERT INTO node_accounts`).WithArgs(p.GlobalUserID, p.NodeID, p.LocalHandle, p.LocalUserID, false, now).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(`SELECT home_node_id FROM users`).WithArgs(int64(8)).
		WillReturnRows(sqlmock.NewRows([]string{"home_node_id"}).AddRow(nil))
	mock.ExpectExec(`UPDATE users SET home_node_id`).WithArgs(int64(8), p.NodeID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO user_replicas`).WithArgs(int64(8), p.NodeID, "home", "ready", now).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`(?s)UPDATE account_import_candidates.*INSERT INTO account_import_claim_operations`).
		WithArgs("candidate-id", p.GlobalUserID, now, "batch-id", p.OperationID, p.NodeID, p.LocalUserID).
		WillReturnResult(sqlmock.NewResult(1, 3))
	mock.ExpectCommit()
	if err := st.CompleteAccountImportClaim(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	assertMockExpectations(t, mock)
}
