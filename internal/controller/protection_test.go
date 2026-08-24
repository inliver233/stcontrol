package controller

import (
	"bytes"
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

func TestPublicProtectionStateUsesSafeProductLanguage(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	tests := []struct {
		state string
		label string
	}{
		{state: "protected", label: "已保护"},
		{state: "temporary", label: "临时保护"},
		{state: "unprotected", label: "未保护"},
		{state: "takeover_available", label: "可接管"},
		{state: "restore_required", label: "需要恢复"},
		{state: "conflict", label: "冲突已冻结"},
		{state: "unavailable", label: "暂不可恢复"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.state, func(t *testing.T) {
			t.Parallel()
			response := publicProtectionState(&store.UserProtectionState{
				State: test.state, Version: 3,
				AuthoritativeNodeID: sql.NullInt64{Int64: 8, Valid: true},
				RecoveryNodeID:      sql.NullInt64{Int64: 9, Valid: true},
				ActiveWriterNodeID:  sql.NullInt64{Int64: 8, Valid: true},
				LatestRecoveryAt:    sql.NullTime{Time: now, Valid: true},
			})
			if response.Label != test.label || response.Risk == "" || response.Version != 3 {
				t.Fatalf("response=%+v", response)
			}
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"reason_code", "snapshot_id", "operation_id"} {
				if strings.Contains(string(encoded), forbidden) {
					t.Fatalf("public response leaked %q: %s", forbidden, encoded)
				}
			}
		})
	}
}

func TestReplicaTakeoverDigestBindsUserTargetAndAcknowledgement(t *testing.T) {
	t.Parallel()
	server := &Server{secretKey: bytes.Repeat([]byte{1}, 32)}
	recoveryAt := time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)
	first, err := server.replicaTakeoverDigest(70, 9, recoveryAt, true)
	second, err2 := server.replicaTakeoverDigest(70, 9, recoveryAt, true)
	userChanged, _ := server.replicaTakeoverDigest(71, 9, recoveryAt, true)
	targetChanged, _ := server.replicaTakeoverDigest(70, 10, recoveryAt, true)
	recoveryChanged, _ := server.replicaTakeoverDigest(70, 9, recoveryAt.Add(time.Minute), true)
	ackChanged, _ := server.replicaTakeoverDigest(70, 9, recoveryAt, false)
	if err != nil || err2 != nil || !bytes.Equal(first, second) || bytes.Equal(first, userChanged) ||
		bytes.Equal(first, targetChanged) || bytes.Equal(first, recoveryChanged) ||
		bytes.Equal(first, ackChanged) || len(first) != 32 {
		t.Fatalf("digest binding failed err=%v err2=%v", err, err2)
	}
}

func TestConfirmReplicaTakeoverRequiresExplicitRiskAcknowledgement(t *testing.T) {
	t.Parallel()
	server := &Server{Cfg: config.DefaultController()}
	req := httptest.NewRequest(http.MethodPost, "/api/users/me/takeover", strings.NewReader(`{
		"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"target_node_id":9,
		"acknowledge_data_loss":false
	}`))
	recorder := httptest.NewRecorder()
	server.handleConfirmReplicaTakeover(recorder, req)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "确认") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestConfirmReplicaTakeoverRejectsMissingRecoveryPointBeforeStoreAccess(t *testing.T) {
	t.Parallel()
	server := &Server{Cfg: config.DefaultController()}
	req := httptest.NewRequest(http.MethodPost, "/api/users/me/takeover", strings.NewReader(`{
		"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"target_node_id":9,
		"acknowledge_data_loss":true
	}`))
	recorder := httptest.NewRecorder()
	server.handleConfirmReplicaTakeover(recorder, req)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "恢复时间") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestProtectionAlertGraceFallsBackSafely(t *testing.T) {
	t.Parallel()
	for _, server := range []*Server{{}, {Cfg: &config.ControllerConfig{}}} {
		if got := server.protectionAlertGrace(); got != time.Hour {
			t.Fatalf("grace=%v", got)
		}
	}
}

func newConfirmTakeoverHTTPRequest(t *testing.T, recoveryAt time.Time) *http.Request {
	t.Helper()
	body := `{"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","target_node_id":9,` +
		`"expected_recovery_at":"` + recoveryAt.Format(time.RFC3339Nano) + `","acknowledge_data_loss":true}`
	request := httptest.NewRequest(http.MethodPost, "/api/users/me/takeover", strings.NewReader(body))
	return request.WithContext(context.WithValue(request.Context(), ctxUser, int64(7)))
}

func expectTakeoverHandlerStoreStart(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(70)))
}

func expectTakeoverHandlerNoReplay(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`FROM replica_takeover_operations`).WithArgs("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").
		WillReturnRows(sqlmock.NewRows([]string{"request_digest"}))
}

func expectTakeoverHandlerIdentity(mock sqlmock.Sqlmock, sourceNodeID int64) {
	mock.ExpectQuery(`SELECT global_user.legacy_user_id`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{"legacy_user_id", "home_node_id"}).AddRow(int64(7), sourceNodeID))
}

func TestHandleConfirmReplicaTakeoverMapsFencedStoreOutcomes(t *testing.T) {
	t.Parallel()
	recoveryAt := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	sentinel := errors.New("takeover persistence unavailable")
	tests := []struct {
		name       string
		setup      func(sqlmock.Sqlmock)
		wantStatus int
	}{
		{
			name: "data freeze incomplete",
			setup: func(mock sqlmock.Sqlmock) {
				expectTakeoverHandlerStoreStart(mock)
				expectTakeoverHandlerNoReplay(mock)
				expectTakeoverHandlerIdentity(mock, 8)
				mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(int64(70)).
					WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("freezing"))
				mock.ExpectRollback()
			},
			wantStatus: http.StatusConflict,
		},
		{
			name: "writer lease active",
			setup: func(mock sqlmock.Sqlmock) {
				expectTakeoverHandlerStoreStart(mock)
				expectTakeoverHandlerNoReplay(mock)
				expectTakeoverHandlerIdentity(mock, 8)
				mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(int64(70)).
					WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("recovery_available"))
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
					WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
				mock.ExpectQuery(`SELECT user_id, writer_node_id`).WithArgs(int64(70)).
					WillReturnRows(sqlmock.NewRows([]string{
						"user_id", "writer_node_id", "session_id", "activity_epoch", "state", "lease_expires_at",
						"last_page", "last_request", "reads", "writes", "generation", "updated_at",
					}).AddRow(int64(70), int64(8), "session", int64(3), "active", recoveryAt.Add(time.Hour),
						recoveryAt, recoveryAt, 0, 0, int64(4), recoveryAt))
				mock.ExpectRollback()
			},
			wantStatus: http.StatusConflict,
		},
		{
			name: "takeover target unavailable",
			setup: func(mock sqlmock.Sqlmock) {
				expectTakeoverHandlerStoreStart(mock)
				expectTakeoverHandlerNoReplay(mock)
				mock.ExpectQuery(`SELECT global_user.legacy_user_id`).WithArgs(int64(70)).WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			},
			wantStatus: http.StatusConflict,
		},
		{
			name: "idempotency conflict",
			setup: func(mock sqlmock.Sqlmock) {
				expectTakeoverHandlerStoreStart(mock)
				mock.ExpectQuery(`FROM replica_takeover_operations`).WithArgs("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").
					WillReturnRows(sqlmock.NewRows([]string{
						"request_digest", "user_id", "source", "target", "snapshot", "published", "generation",
					}).AddRow(bytes.Repeat([]byte{9}, 32), int64(70), int64(8), int64(9), "snapshot", recoveryAt, int64(4)))
				mock.ExpectRollback()
			},
			wantStatus: http.StatusConflict,
		},
		{
			name: "no active controller",
			setup: func(mock sqlmock.Sqlmock) {
				expectTakeoverHandlerStoreStart(mock)
				expectTakeoverHandlerNoReplay(mock)
				expectTakeoverHandlerIdentity(mock, 8)
				mock.ExpectQuery(`SELECT state FROM user_data_faults`).WithArgs(int64(70)).
					WillReturnRows(sqlmock.NewRows([]string{"state"}))
				mock.ExpectQuery(`SELECT generation FROM controller_epochs`).WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
			},
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name: "unexpected persistence failure",
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
			server, mock := phaseTestServer(t)
			expectLoginRedirectUser(mock, recoveryAt, "active", 70)
			tc.setup(mock)
			recorder := httptest.NewRecorder()
			server.handleConfirmReplicaTakeover(recorder, newConfirmTakeoverHTTPRequest(t, recoveryAt))
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), tc.wantStatus)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHandleConfirmReplicaTakeoverReturnsExactReplay(t *testing.T) {
	t.Parallel()
	recoveryAt := time.Date(2026, 8, 24, 10, 10, 0, 0, time.UTC)
	server, mock := phaseTestServer(t)
	expectLoginRedirectUser(mock, recoveryAt, "active", 70)
	digest, err := server.replicaTakeoverDigest(70, 9, recoveryAt, true)
	if err != nil {
		t.Fatal(err)
	}
	expectTakeoverHandlerStoreStart(mock)
	mock.ExpectQuery(`FROM replica_takeover_operations`).WithArgs("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").
		WillReturnRows(sqlmock.NewRows([]string{
			"request_digest", "user_id", "source", "target", "snapshot", "published", "generation",
		}).AddRow(digest, int64(70), int64(8), int64(9), "snapshot", recoveryAt, int64(4)))
	mock.ExpectCommit()
	// Reconciliation is best-effort after the takeover is already committed.
	mock.ExpectBegin().WillReturnError(errors.New("projection refresh delayed"))
	recorder := httptest.NewRecorder()
	server.handleConfirmReplicaTakeover(recorder, newConfirmTakeoverHTTPRequest(t, recoveryAt))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"replayed":true`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
