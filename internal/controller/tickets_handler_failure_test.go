package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func loginRedirectNodeRows(
	now time.Time,
	role, connectivity, operational, compatibility, controlMode, desiredControlMode string,
) *sqlmock.Rows {
	columns := []string{
		"id", "name", "role", "base_url", "transfer_url", "region",
		"cpu_pct", "mem_pct", "disk_pct", "agent_version", "tavern_version", "last_seen_at", "status",
		"connectivity_state", "operational_state", "control_mode", "control_mode_generation",
		"desired_control_mode", "desired_mode_generation", "capacity_state", "capacity_reason_code",
		"capacity_changed_at", "capacity_cooldown_until", "compatibility_state", "compatibility_reason_code",
		"compatibility_fingerprint", "compatibility_reported_at", "metrics_observed_at",
		"cpu_window_avg", "cpu_window_peak", "mem_window_avg", "mem_window_peak",
		"disk_window_avg", "disk_window_peak", "disk_total_bytes", "disk_available_bytes",
		"disk_quota_bytes", "expected_disk_quota_bytes", "quota_policy_version", "quota_sync_state",
		"quota_sync_at", "quota_sync_error_code", "allocated_disk_bytes", "online_users", "task_queue_depth", "telemetry_source",
		"client_latency_ms", "client_latency_observed_at",
		"allow_register", "recommendation_weight", "is_backup_target", "registration_policy_state",
		"registration_policy_version", "registration_policy_expires_at",
		"registration_policy_observed_at", "registration_policy_error_code", "created_at",
	}
	return sqlmock.NewRows(columns).AddRow(
		int64(9), "compute-b", role, "https://compute-b.example", "", "hk",
		10.0, 20.0, 30.0, "agent", "tavern", now, "online",
		connectivity, operational, controlMode, int64(4), desiredControlMode, int64(4),
		"open", nil, now, nil, compatibility, nil, "fingerprint", now, now,
		10.0, 20.0, 10.0, 20.0, 30.0, 30.0,
		int64(200<<30), int64(100<<30), int64(180<<30), int64(0), int64(0), "synced", nil, nil,
		int64(20<<30), 0, 0, "adapter", nil, nil,
		true, 0, false, "open", int64(1), now.Add(time.Minute), now, nil, now,
	)
}

func expectLoginRedirectUser(mock sqlmock.Sqlmock, now time.Time, status string, globalID int64) {
	expectLoginRedirectUserAtHome(mock, now, status, globalID, 8)
}

func expectLoginRedirectUserAtHome(
	mock sqlmock.Sqlmock,
	now time.Time,
	status string,
	globalID, homeNodeID int64,
) {
	mock.ExpectQuery(`(?s)SELECT u.id, COALESCE\(gu.id,0\).*FROM users u`).WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "global_id", "uuid", "username", "display_name", "password_enc", "password_hash",
			"auth_provider", "oauth_id", "avatar_url", "email", "home_node_id", "status", "created_at",
		}).AddRow(int64(7), globalID, "11111111-1111-4111-8111-111111111111", "alice", "Alice",
			nil, nil, "password", nil, nil, nil, homeNodeID, status, now))
}

func expectLoginRedirectNode(mock sqlmock.Sqlmock, now time.Time, connectivity string) {
	mock.ExpectQuery(`(?s)SELECT .*connectivity_state.*capacity_state.* FROM nodes WHERE id=\$1`).WithArgs(int64(9)).
		WillReturnRows(loginRedirectNodeRows(now, "compute", connectivity, "active", "compatible", "managed", "managed"))
}

func loginRedirectRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/login/redirect", strings.NewReader(body))
	return request.WithContext(context.WithValue(request.Context(), ctxUser, int64(7)))
}

func newLoginRedirectTestServer(t *testing.T) (*Server, sqlmock.Sqlmock) {
	t.Helper()
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	cfg := config.DefaultController()
	cfg.Backup.AbortOnLogin = false
	return New(cfg, &store.Store{DB: database}, []byte("01234567890123456789012345678901")), mock
}

func assertLoginRedirectResponse(t *testing.T, recorder *httptest.ResponseRecorder, wantStatus int) {
	t.Helper()
	if recorder.Code != wantStatus {
		t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), wantStatus)
	}
	if got := recorder.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Fatalf("Cache-Control=%q, handoff responses must never be cached", got)
	}
}

func TestHandleLoginRedirectRejectsBeforeCredentialIssuance(t *testing.T) {
	t.Parallel()
	validBody := `{"node_id":9,"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}`
	now := time.Date(2026, 8, 24, 4, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		body       string
		setup      func(*Server, sqlmock.Sqlmock)
		wantStatus int
	}{
		{
			name: "control plane recovery gate",
			body: validBody,
			setup: func(server *Server, _ sqlmock.Sqlmock) {
				server.setControlPlaneGate(true, "reconciliation_required")
			},
			wantStatus: http.StatusServiceUnavailable,
		},
		{name: "malformed request", body: `{"node_id":9,"operation_id":"not-a-uuid"}`, wantStatus: http.StatusBadRequest},
		{
			name: "unknown user",
			body: validBody,
			setup: func(_ *Server, mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`(?s)SELECT u.id, COALESCE\(gu.id,0\).*FROM users u`).WithArgs(int64(7)).
					WillReturnError(sql.ErrNoRows)
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "unlinked global identity",
			body: validBody,
			setup: func(_ *Server, mock sqlmock.Sqlmock) {
				expectLoginRedirectUser(mock, now, "active", 0)
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "disabled user",
			body: validBody,
			setup: func(_ *Server, mock sqlmock.Sqlmock) {
				expectLoginRedirectUser(mock, now, "disabled", 70)
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "unknown node",
			body: validBody,
			setup: func(_ *Server, mock sqlmock.Sqlmock) {
				expectLoginRedirectUser(mock, now, "active", 70)
				mock.ExpectQuery(`(?s)SELECT .*connectivity_state.*capacity_state.* FROM nodes WHERE id=\$1`).
					WithArgs(int64(9)).WillReturnError(sql.ErrNoRows)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "replica not owned",
			body: validBody,
			setup: func(_ *Server, mock sqlmock.Sqlmock) {
				expectLoginRedirectUser(mock, now, "active", 70)
				expectLoginRedirectNode(mock, now, "online")
				mock.ExpectQuery(`FROM user_replicas WHERE user_id=\$1 AND node_id=\$2`).
					WithArgs(int64(7), int64(9)).WillReturnError(sql.ErrNoRows)
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "archive cannot accept login",
			body: validBody,
			setup: func(_ *Server, mock sqlmock.Sqlmock) {
				expectLoginRedirectUser(mock, now, "active", 70)
				expectLoginRedirectNode(mock, now, "online")
				mock.ExpectQuery(`FROM user_replicas WHERE user_id=\$1 AND node_id=\$2`).
					WithArgs(int64(7), int64(9)).WillReturnRows(sqlmock.NewRows([]string{
					"id", "user_id", "node_id", "kind", "data_version", "state", "last_sync_at", "checksum", "size_bytes",
				}).AddRow(int64(1), int64(7), int64(9), "archive", int64(3), "ready", now, "sum", int64(10)))
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "stale standby requires takeover",
			body: validBody,
			setup: func(_ *Server, mock sqlmock.Sqlmock) {
				expectLoginRedirectUser(mock, now, "active", 70)
				expectLoginRedirectNode(mock, now, "online")
				mock.ExpectQuery(`FROM user_replicas WHERE user_id=\$1 AND node_id=\$2`).
					WithArgs(int64(7), int64(9)).WillReturnRows(sqlmock.NewRows([]string{
					"id", "user_id", "node_id", "kind", "data_version", "state", "last_sync_at", "checksum", "size_bytes",
				}).AddRow(int64(1), int64(7), int64(9), "hot_standby", int64(3), "stale", now, "sum", int64(10)))
			},
			wantStatus: http.StatusConflict,
		},
		{
			name: "offline ready standby",
			body: validBody,
			setup: func(_ *Server, mock sqlmock.Sqlmock) {
				expectLoginRedirectUser(mock, now, "active", 70)
				expectLoginRedirectNode(mock, now, "offline")
				mock.ExpectQuery(`FROM user_replicas WHERE user_id=\$1 AND node_id=\$2`).
					WithArgs(int64(7), int64(9)).WillReturnRows(sqlmock.NewRows([]string{
					"id", "user_id", "node_id", "kind", "data_version", "state", "last_sync_at", "checksum", "size_bytes",
				}).AddRow(int64(1), int64(7), int64(9), "hot_standby", int64(3), "ready", now, "sum", int64(10)))
			},
			wantStatus: http.StatusConflict,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server, mock := newLoginRedirectTestServer(t)
			if tc.setup != nil {
				tc.setup(server, mock)
			}
			recorder := httptest.NewRecorder()
			server.handleLoginRedirect(recorder, loginRedirectRequest(t, tc.body))
			assertLoginRedirectResponse(t, recorder, tc.wantStatus)
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func expectLoginRedirectAuthorizedReplica(
	mock sqlmock.Sqlmock,
	now time.Time,
	replicaKind string,
) {
	homeNodeID := int64(8)
	if replicaKind == "home" {
		homeNodeID = 9
	}
	expectLoginRedirectUserAtHome(mock, now, "active", 70, homeNodeID)
	expectLoginRedirectNode(mock, now, "online")
	mock.ExpectQuery(`FROM user_replicas WHERE user_id=\$1 AND node_id=\$2`).
		WithArgs(int64(7), int64(9)).WillReturnRows(sqlmock.NewRows([]string{
		"id", "user_id", "node_id", "kind", "data_version", "state", "last_sync_at", "checksum", "size_bytes",
	}).AddRow(int64(1), int64(7), int64(9), replicaKind, int64(3), "ready", now, "sum", int64(10)))
}

func expectLoginHandoffTransactionPrefix(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
}

func expectNewLoginLeasePrefix(mock sqlmock.Sqlmock, generation int64) {
	expectLoginHandoffTransactionPrefix(mock)
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(generation))
	mock.ExpectQuery(`FROM activity_lease_operations WHERE operation_id=\$1`).
		WithArgs("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
	mock.ExpectQuery(`SELECT user_id, writer_node_id`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
}

func TestHandleLoginRedirectMapsDurableHandoffFailures(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 4, 10, 0, 0, time.UTC)
	validBody := `{"node_id":9,"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}`
	sentinel := errors.New("handoff persistence failed")
	tests := []struct {
		name       string
		replica    string
		setup      func(sqlmock.Sqlmock)
		wantStatus int
	}{
		{
			name:    "standby without existing writer",
			replica: "hot_standby",
			setup: func(mock sqlmock.Sqlmock) {
				expectNewLoginLeasePrefix(mock, 4)
				mock.ExpectRollback()
			},
			wantStatus: http.StatusConflict,
		},
		{
			name:    "no active controller",
			replica: "home",
			setup: func(mock sqlmock.Sqlmock) {
				expectLoginHandoffTransactionPrefix(mock)
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			},
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:    "transaction unavailable",
			replica: "home",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin().WillReturnError(sentinel)
			},
			wantStatus: http.StatusInternalServerError,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server, mock := newLoginRedirectTestServer(t)
			expectLoginRedirectAuthorizedReplica(mock, now, tc.replica)
			tc.setup(mock)
			recorder := httptest.NewRecorder()
			server.handleLoginRedirect(recorder, loginRedirectRequest(t, validBody))
			assertLoginRedirectResponse(t, recorder, tc.wantStatus)
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHandleLoginRedirectReturnsOpaquePostBodyCredential(t *testing.T) {
	t.Parallel()
	server, mock := newLoginRedirectTestServer(t)
	now := time.Date(2026, 8, 24, 4, 20, 0, 0, time.UTC)
	expectLoginRedirectAuthorizedReplica(mock, now, "home")
	expectNewLoginLeasePrefix(mock, 4)
	mock.ExpectExec(`INSERT INTO user_activity_leases`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO activity_lease_operations`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT base_url FROM nodes`).WithArgs(int64(9), false).
		WillReturnRows(sqlmock.NewRows([]string{"base_url"}).AddRow("https://compute-b.example/"))
	mock.ExpectExec(`INSERT INTO control_tickets`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	recorder := httptest.NewRecorder()
	server.handleLoginRedirect(recorder, loginRedirectRequest(t,
		`{"node_id":9,"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}`))
	assertLoginRedirectResponse(t, recorder, http.StatusOK)
	var response loginHandoffResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.PostURL != "https://compute-b.example/api/users/me?stcontrol_handoff=user" ||
		response.FieldName != loginHandoffField || response.TargetNodeID != 9 || response.ExistingWriter {
		t.Fatalf("response=%+v", response)
	}
	if _, _, ok := parseLoginHandoffCode(response.Code); !ok {
		t.Fatalf("invalid opaque handoff code %q", response.Code)
	}
	if strings.Contains(response.PostURL, response.Code) {
		t.Fatal("one-use handoff credential leaked into URL")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
