package controller

import (
	"context"
	"database/sql"
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

const restoreHandlerOperation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

func authenticatedRestoreRequest(method, target, body string) *http.Request {
	req := adminRouteRequest(method, target, body, "", "")
	return req.WithContext(context.WithValue(req.Context(), ctxUser, int64(7)))
}

func TestRestoreHandlersFenceAuthenticationAndStoreFailures(t *testing.T) {
	t.Parallel()
	injected := errors.New("injected restore handler failure")
	validBody := `{"operation_id":"` + restoreHandlerOperation + `","target_node_id":9,"expected_recovery_at":"2026-08-24T09:55:00Z","acknowledge_data_loss":true}`
	for _, tc := range []struct {
		name   string
		kind   string
		auth   bool
		body   string
		setup  func(sqlmock.Sqlmock)
		status int
	}{
		{name: "targets unauthenticated", kind: "targets", status: http.StatusUnauthorized},
		{
			name: "targets unavailable", kind: "targets", auth: true,
			setup: func(mock sqlmock.Sqlmock) {
				expectActiveImportUser(mock)
				mock.ExpectQuery(`FROM user_protection_states protection`).WillReturnError(injected)
			},
			status: http.StatusServiceUnavailable,
		},
		{name: "start invalid recovery time", kind: "start", body: strings.Replace(validBody, "2026-08-24T09:55:00Z", "invalid", 1), auth: true, status: http.StatusBadRequest},
		{name: "start unauthenticated", kind: "start", body: validBody, status: http.StatusUnauthorized},
		{
			name: "start transaction unavailable", kind: "start", body: validBody, auth: true,
			setup: func(mock sqlmock.Sqlmock) {
				expectActiveImportUser(mock)
				mock.ExpectBegin().WillReturnError(injected)
			},
			status: http.StatusInternalServerError,
		},
		{name: "status invalid operation", kind: "status", auth: true, status: http.StatusBadRequest},
		{name: "status unauthenticated", kind: "status-valid", status: http.StatusUnauthorized},
		{
			name: "status unavailable", kind: "status-valid", auth: true,
			setup: func(mock sqlmock.Sqlmock) {
				expectActiveImportUser(mock)
				mock.ExpectQuery(`FROM restore_operations operation`).WithArgs(int64(70), restoreHandlerOperation).WillReturnError(injected)
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "status absent", kind: "status-valid", auth: true,
			setup: func(mock sqlmock.Sqlmock) {
				expectActiveImportUser(mock)
				mock.ExpectQuery(`FROM restore_operations operation`).WillReturnError(sql.ErrNoRows)
			},
			status: http.StatusNotFound,
		},
		{
			name: "status succeeds", kind: "status-valid", auth: true,
			setup: func(mock sqlmock.Sqlmock) {
				expectActiveImportUser(mock)
				mock.ExpectQuery(`FROM restore_operations operation`).WillReturnRows(sqlmock.NewRows([]string{
					"operation_id", "state", "target_node_id", "target_name", "published_at", "error_summary",
				}).AddRow(restoreHandlerOperation, "succeeded", int64(9), "compute-b", time.Now().UTC(), nil))
			},
			status: http.StatusOK,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			server := &Server{
				Cfg: config.DefaultController(), Store: &store.Store{DB: db},
				secretKey: []byte("0123456789abcdef0123456789abcdef"), snapshotSlots: make(chan struct{}, 1),
			}
			if tc.setup != nil {
				tc.setup(mock)
			}
			operation := "invalid"
			if tc.kind == "status-valid" {
				operation = restoreHandlerOperation
			}
			target := "/api/users/me/restore/" + operation
			var req *http.Request
			if tc.auth {
				req = authenticatedRestoreRequest(http.MethodPost, target, tc.body)
			} else {
				req = adminRouteRequest(http.MethodPost, target, tc.body, "", "")
			}
			if tc.kind == "status" || tc.kind == "status-valid" {
				req = adminRouteRequest(http.MethodGet, target, "", "operationID", operation)
				if tc.auth {
					req = req.WithContext(context.WithValue(req.Context(), ctxUser, int64(7)))
				}
			}
			recorder := httptest.NewRecorder()
			switch tc.kind {
			case "targets":
				server.handleRestoreTargets(recorder, req)
			case "start":
				server.handleStartArchiveRestore(recorder, req)
			default:
				server.handleArchiveRestoreStatus(recorder, req)
			}
			if recorder.Code != tc.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
