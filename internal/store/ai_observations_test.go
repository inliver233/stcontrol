package store

import (
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestListRecentNodeControlModeEvents(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := &Store{DB: db}
	now := time.Now().UTC()
	mock.ExpectQuery(`(?s)SELECT\s+node_id,\s+reported_mode,\s+desired_mode,\s+reason_code,\s+observed_at\s+FROM\s+node_control_mode_events`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{
			"node_id", "reported_mode", "desired_mode", "reason_code", "observed_at",
		}).AddRow(1, "independent", "independent", "sustained_outage", now))
	rows, err := st.ListRecentNodeControlModeEvents(ctx(), 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].Reported != "independent" || rows[0].ReasonCode != "sustained_outage" {
		t.Fatalf("rows=%+v", rows)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet: %v", err)
	}
}

func TestListOpenConflictAggregates(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := &Store{DB: db}
	now := time.Now().UTC()
	mock.ExpectQuery(`(?s)SELECT\s+c\.user_id,\s+c\.state,\s+COUNT\(s\.conflict_id\)\s+AS\s+source_count`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{
			"user_id", "state", "source_count", "file_count", "total_bytes", "captured_at", "updated_at",
		}).AddRow(7, "awaiting_decision", int64(2), int64(120), int64(4096), now, now))
	rows, err := st.ListOpenConflictAggregates(ctx(), 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].SourceCount != 2 || !rows[0].HasReadyEvidence {
		t.Fatalf("rows=%+v", rows)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet: %v", err)
	}
}

func TestListRecentRestoreWorkflowSummaries(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := &Store{DB: db}
	now := time.Now().UTC()
	mock.ExpectQuery(`(?s)SELECT\s+id::text,\s+state,\s+attempt,\s+error_code,\s+created_at,\s+updated_at\s+FROM\s+workflows\s+WHERE\s+workflow_type\s+=\s+'restore'`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "state", "attempt", "error_code", "created_at", "updated_at",
		}).AddRow("11111111-1111-4111-8111-111111111111", "retry_wait", 2, "timeout", now, now))
	rows, err := st.ListRecentRestoreWorkflowSummaries(ctx(), 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].State != "retry_wait" || rows[0].Attempt != 2 || rows[0].ErrorCode != "timeout" {
		t.Fatalf("rows=%+v", rows)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet: %v", err)
	}
}

func TestListUnresolvedImportCandidates(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := &Store{DB: db}
	mock.ExpectQuery(`(?s)SELECT\s+batch_id::text,\s+source,\s+account_kind,\s+resolution_state`).
		WillReturnRows(sqlmock.NewRows([]string{
			"batch_id", "source", "account_kind", "resolution_state", "size_bucket",
		}).AddRow("22222222-2222-4222-8222-222222222222", "adapter", "password", "claim_required", "small"))
	rows, err := st.ListUnresolvedImportCandidates(ctx(), 50)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].Resolution != "claim_required" || rows[0].SizeBucket != "small" {
		t.Fatalf("rows=%+v", rows)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet: %v", err)
	}
}

func TestCountOpenAlertsBySeverity(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := &Store{DB: db}
	mock.ExpectQuery(`(?s)SELECT\s+severity,\s+COUNT\(\*\)\s+FROM\s+alerts\s+WHERE\s+state\s+=\s+'open'`).
		WillReturnRows(sqlmock.NewRows([]string{"severity", "count"}).
			AddRow("warning", int64(3)).AddRow("critical", int64(1)))
	counts, err := st.CountOpenAlertsBySeverity(ctx())
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if counts["warning"] != 3 || counts["critical"] != 1 {
		t.Fatalf("counts=%+v", counts)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet: %v", err)
	}
}
