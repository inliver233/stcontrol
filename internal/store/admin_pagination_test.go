package store

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestListUsersPageUsesBoundedCursorAndFilters(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 23, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT user_account.id,COALESCE\(global_user.id,0\)`).WithArgs(
		int64(10), "ali", "active", 3,
	).WillReturnRows(sqlmock.NewRows([]string{
		"id", "global_id", "uuid", "username", "display_name", "auth_provider",
		"avatar_url", "home_node_id", "status", "created_at",
	}).AddRow(11, 101, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "alice", "Alice", "password", nil, 3, "active", now).
		AddRow(12, 102, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "alicia", "Alicia", "discord", nil, 4, "active", now).
		AddRow(13, 103, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "aline", "Aline", "linuxdo", nil, 5, "active", now))
	page, err := st.ListUsersPage(context.Background(), UserPageParams{
		AfterID: 10, Limit: 2, Query: " ali ", Status: "active",
	})
	if err != nil || len(page.Users) != 2 || !page.HasMore || page.NextCursor != 12 || page.Users[0].PasswordHash.Valid {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	assertMockExpectations(t, mock)
}

func TestListBackupJobsPageUsesDescendingCursor(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 23, 0, 0, 0, time.UTC)
	columns := []string{
		"id", "user_id", "src_node_id", "dst_node_id", "trigger", "status",
		"data_version", "bytes", "file_count", "error", "started_at", "finished_at", "created_at",
		"workflow_state", "attempt", "next_attempt_at", "cleanup_state", "error_code", "error_summary", "can_abort",
	}
	mock.ExpectQuery(`FROM backup_jobs job`).WithArgs(int64(math.MaxInt64), "failed", int64(7), 2).
		WillReturnRows(sqlmock.NewRows(columns).
			AddRow(20, 7, 1, 2, "offline", "failed", nil, nil, nil, "network", now, now, now,
				"failed", 3, nil, "pending", "network_error", "network unavailable", false).
			AddRow(19, 7, 1, 2, "offline", "failed", nil, nil, nil, "network", now, now, now,
				"", 0, nil, "", "", "", false))
	page, err := st.ListBackupJobsPage(context.Background(), BackupPageParams{
		Limit: 1, Status: "failed", UserID: 7,
	})
	if err != nil || len(page.Jobs) != 1 || !page.HasMore || page.NextCursor != 20 ||
		page.Jobs[0].WorkflowState != "failed" || page.Jobs[0].CanAbort {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	assertMockExpectations(t, mock)
}

func TestListBackupJobsPageExposesSafeRetryPhaseAndBackendAbortDecision(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 23, 15, 0, 0, time.UTC)
	next := now.Add(time.Minute)
	columns := []string{
		"id", "user_id", "src_node_id", "dst_node_id", "trigger", "status",
		"data_version", "bytes", "file_count", "error", "started_at", "finished_at", "created_at",
		"workflow_state", "attempt", "next_attempt_at", "cleanup_state", "error_code", "error_summary", "can_abort",
	}
	mock.ExpectQuery(`LEFT JOIN workflows`).WithArgs(int64(math.MaxInt64), "running", int64(0), 3).
		WillReturnRows(sqlmock.NewRows(columns).AddRow(
			21, 7, 1, 2, "offline", "running", nil, nil, nil, nil, now, nil, now,
			"retry_wait", 2, next, "not_required", "target_unavailable", "target unavailable", true,
		))
	page, err := st.ListBackupJobsPage(context.Background(), BackupPageParams{Limit: 2, Status: "running"})
	if err != nil || len(page.Jobs) != 1 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	job := page.Jobs[0]
	if job.WorkflowState != "retry_wait" || job.Attempt != 2 || job.NextAttemptAt == nil ||
		!job.NextAttemptAt.Equal(next) || job.CleanupState != "not_required" ||
		job.ErrorCode != "target_unavailable" || !job.CanAbort {
		t.Fatalf("retry job=%+v", job)
	}
	assertMockExpectations(t, mock)
}

func TestAdminPagesRejectUnboundedOrUnknownFilters(t *testing.T) {
	t.Parallel()
	st := &Store{}
	if _, err := st.ListUsersPage(context.Background(), UserPageParams{Limit: 101}); !errors.Is(err, ErrInvalidAdminPage) {
		t.Fatalf("users error=%v", err)
	}
	if _, err := st.ListBackupJobsPage(context.Background(), BackupPageParams{Limit: 50, Status: "secret"}); !errors.Is(err, ErrInvalidAdminPage) {
		t.Fatalf("backups error=%v", err)
	}
}

func TestGetAdminOverviewCountsUsesDatabaseAggregation(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`SELECT COUNT\(\*\)`).WillReturnRows(sqlmock.NewRows([]string{
		"nodes", "online", "offline", "full", "busy", "maintenance", "fault",
		"users", "backup_running", "backup_failed",
	}).AddRow(10, 7, 2, 1, 2, 1, 3, 10_000, 8, 1))
	counts, err := st.GetAdminOverviewCounts(context.Background())
	if err != nil || counts.Users != 10_000 || counts.NodesOnline != 7 || counts.BackupRunning != 8 {
		t.Fatalf("counts=%+v err=%v", counts, err)
	}
	assertMockExpectations(t, mock)
}
