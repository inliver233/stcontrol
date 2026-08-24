package controller

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

const importClaimOperation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

func importUserRequest(method, target, body string, authenticated bool) *http.Request {
	req := adminRouteRequest(method, target, body, "", "")
	if authenticated {
		req = req.WithContext(context.WithValue(req.Context(), ctxUser, int64(7)))
	}
	return req
}

func expectActiveImportUser(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`FROM users u`).WithArgs(int64(7)).WillReturnRows(oauthUserRows("active"))
}

func TestImportClaimHandlersFenceAuthenticationReplayAndTargetFailures(t *testing.T) {
	t.Parallel()
	injected := errors.New("injected account import handler failure")
	validBody := `{"operation_id":"` + importClaimOperation + `","node_id":12,"password":"node-password"}`
	for _, tc := range []struct {
		name   string
		list   bool
		auth   bool
		body   string
		setup  func(sqlmock.Sqlmock)
		status int
	}{
		{name: "list unauthenticated", list: true, status: http.StatusUnauthorized},
		{
			name: "list user lookup", list: true, auth: true,
			setup:  func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`FROM users u`).WillReturnError(injected) },
			status: http.StatusServiceUnavailable,
		},
		{
			name: "list target lookup", list: true, auth: true,
			setup: func(mock sqlmock.Sqlmock) {
				expectActiveImportUser(mock)
				mock.ExpectQuery(`SELECT DISTINCT ON`).WillReturnError(injected)
			},
			status: http.StatusServiceUnavailable,
		},
		{name: "claim invalid", body: `{}`, status: http.StatusBadRequest},
		{name: "claim unauthenticated", body: validBody, status: http.StatusUnauthorized},
		{
			name: "claim user unavailable", auth: true, body: validBody,
			setup:  func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`FROM users u`).WillReturnError(injected) },
			status: http.StatusUnauthorized,
		},
		{
			name: "claim conflicting replay", auth: true, body: validBody,
			setup: func(mock sqlmock.Sqlmock) {
				expectActiveImportUser(mock)
				mock.ExpectQuery(`FROM account_import_claim_operations`).WithArgs(importClaimOperation).
					WillReturnRows(sqlmock.NewRows([]string{"user_id", "node_id"}).AddRow(int64(80), int64(12)))
			},
			status: http.StatusConflict,
		},
		{
			name: "claim replay lookup", auth: true, body: validBody,
			setup: func(mock sqlmock.Sqlmock) {
				expectActiveImportUser(mock)
				mock.ExpectQuery(`FROM account_import_claim_operations`).WillReturnError(injected)
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "claim exact replay", auth: true, body: validBody,
			setup: func(mock sqlmock.Sqlmock) {
				expectActiveImportUser(mock)
				mock.ExpectQuery(`FROM account_import_claim_operations`).
					WillReturnRows(sqlmock.NewRows([]string{"user_id", "node_id"}).AddRow(int64(70), int64(12)))
			},
			status: http.StatusOK,
		},
		{
			name: "claim targets unavailable", auth: true, body: validBody,
			setup: func(mock sqlmock.Sqlmock) {
				expectActiveImportUser(mock)
				mock.ExpectQuery(`FROM account_import_claim_operations`).WillReturnError(sql.ErrNoRows)
				mock.ExpectQuery(`SELECT DISTINCT ON`).WillReturnError(injected)
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "claim target absent", auth: true, body: validBody,
			setup: func(mock sqlmock.Sqlmock) {
				expectActiveImportUser(mock)
				mock.ExpectQuery(`FROM account_import_claim_operations`).WillReturnError(sql.ErrNoRows)
				mock.ExpectQuery(`SELECT DISTINCT ON`).WillReturnRows(
					sqlmock.NewRows([]string{"node_id", "name", "handle", "account_kind"}))
			},
			status: http.StatusConflict,
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
			server := &Server{Cfg: config.DefaultController(), Store: &store.Store{DB: db}}
			if tc.setup != nil {
				tc.setup(mock)
			}
			recorder := httptest.NewRecorder()
			if tc.list {
				server.handleListMyAccountImportClaims(recorder,
					importUserRequest(http.MethodGet, "/api/imports/claims", "", tc.auth))
			} else {
				server.handleClaimImportedAccount(recorder,
					importUserRequest(http.MethodPost, "/api/imports/claim", tc.body, tc.auth))
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

func TestAdminImportHandlersFencePathBodyAndReadFailures(t *testing.T) {
	t.Parallel()
	injected := errors.New("injected admin import failure")
	for _, tc := range []struct {
		name   string
		latest bool
		target string
		body   string
		nodeID string
		setup  func(sqlmock.Sqlmock)
		status int
	}{
		{name: "scan invalid node", target: "/api/admin/nodes/x/import-scan", body: `{}`, nodeID: "x", status: http.StatusBadRequest},
		{name: "scan invalid body", target: "/api/admin/nodes/12/import-scan", body: `{}`, nodeID: "12", status: http.StatusBadRequest},
		{
			name: "scan missing node", target: "/api/admin/nodes/12/import-scan", nodeID: "12",
			body:   `{"operation_id":"` + importClaimOperation + `"}`,
			setup:  func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`FROM nodes WHERE id=\$1`).WillReturnError(injected) },
			status: http.StatusNotFound,
		},
		{name: "latest invalid node", latest: true, target: "/api/admin/nodes/x/imports", nodeID: "x", status: http.StatusBadRequest},
		{name: "latest invalid page", latest: true, target: "/api/admin/nodes/12/imports?offset=-1", nodeID: "12", status: http.StatusBadRequest},
		{
			name: "latest lookup", latest: true, target: "/api/admin/nodes/12/imports", nodeID: "12",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT id FROM account_import_batches`).WillReturnError(injected)
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "latest absent", latest: true, target: "/api/admin/nodes/12/imports", nodeID: "12",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT id FROM account_import_batches`).WillReturnError(sql.ErrNoRows)
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
			server := &Server{Cfg: config.DefaultController(), Store: &store.Store{DB: db}}
			if tc.setup != nil {
				tc.setup(mock)
			}
			req := adminRouteRequest(http.MethodPost, tc.target, tc.body, "id", tc.nodeID)
			recorder := httptest.NewRecorder()
			if tc.latest {
				server.handleAdminLatestAccountImport(recorder, req)
			} else {
				server.handleAdminScanExisting(recorder, req)
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
