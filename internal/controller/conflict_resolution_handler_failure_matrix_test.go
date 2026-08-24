package controller

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

const conflictHandlerOperation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

func conflictSessionRequest(method, target, body, operationID string, authenticated bool) *http.Request {
	req := adminRouteRequest(method, target, body, "operationID", operationID)
	if authenticated {
		req = req.WithContext(context.WithValue(req.Context(), ctxKey("stcontrol-session"), &session{
			ID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", UserID: 7, GlobalUserID: 70, Username: "alice",
		}))
	}
	return req
}

func TestConflictResolutionHandlersFenceInputAuthenticationAndMissingState(t *testing.T) {
	t.Parallel()
	injected := errors.New("injected conflict handler failure")
	validBody := `{"operation_id":"` + conflictHandlerOperation + `","expected_conflict_version":2,"base_node_id":8,"default_action":"use_base","acknowledge_freeze":true}`
	for _, tc := range []struct {
		name   string
		kind   string
		auth   bool
		body   string
		opID   string
		setup  func(sqlmock.Sqlmock)
		status int
	}{
		{name: "start invalid", kind: "start", body: `{}`, status: http.StatusBadRequest},
		{name: "start unauthenticated", kind: "start", body: validBody, status: http.StatusUnauthorized},
		{
			name: "start conflict lookup", kind: "start", auth: true, body: validBody,
			setup:  func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`FROM replica_conflicts`).WillReturnError(injected) },
			status: http.StatusServiceUnavailable,
		},
		{
			name: "start conflict absent", kind: "start", auth: true, body: validBody,
			setup:  func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`FROM replica_conflicts`).WillReturnError(sql.ErrNoRows) },
			status: http.StatusConflict,
		},
		{name: "status invalid operation", kind: "status", opID: "invalid", status: http.StatusBadRequest},
		{name: "status unauthenticated", kind: "status", opID: conflictHandlerOperation, status: http.StatusUnauthorized},
		{
			name: "status unavailable", kind: "status", auth: true, opID: conflictHandlerOperation,
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`FROM conflict_resolution_operations`).WillReturnError(injected)
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "status absent", kind: "status", auth: true, opID: conflictHandlerOperation,
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`FROM conflict_resolution_operations`).WillReturnError(sql.ErrNoRows)
			},
			status: http.StatusNotFound,
		},
		{name: "retry invalid operation", kind: "retry", opID: "invalid", status: http.StatusBadRequest},
		{name: "retry unauthenticated", kind: "retry", opID: conflictHandlerOperation, status: http.StatusUnauthorized},
		{
			name: "retry store failure", kind: "retry", auth: true, opID: conflictHandlerOperation,
			setup:  func(mock sqlmock.Sqlmock) { mock.ExpectBegin().WillReturnError(injected) },
			status: http.StatusInternalServerError,
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
			server := &Server{Cfg: config.DefaultController(), Store: &store.Store{DB: db}, secretKey: []byte(strings.Repeat("k", 32))}
			if tc.setup != nil {
				tc.setup(mock)
			}
			req := conflictSessionRequest(http.MethodPost, "/api/conflicts/resolve", tc.body, tc.opID, tc.auth)
			recorder := httptest.NewRecorder()
			switch tc.kind {
			case "start":
				server.handleStartConflictResolution(recorder, req)
			case "status":
				server.handleConflictResolutionStatus(recorder, req)
			case "retry":
				server.handleRetryConflictResolution(recorder, req)
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
