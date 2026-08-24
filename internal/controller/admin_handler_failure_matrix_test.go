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
	"github.com/go-chi/chi/v5"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func adminRouteRequest(method, target, body, name, value string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if name == "" {
		return req
	}
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add(name, value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
}

func TestAdminHandlersRejectInvalidInputsBeforeStoreAccess(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		run    func(*Server, http.ResponseWriter)
		status int
	}{
		{
			name: "create malformed",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminCreateNode(w, adminRouteRequest(http.MethodPost, "/api/admin/nodes", `{`, "", ""))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "create unnamed",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminCreateNode(w, adminRouteRequest(http.MethodPost, "/api/admin/nodes", `{"role":"compute"}`, "", ""))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "update malformed",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminUpdateNode(w, adminRouteRequest(http.MethodPut, "/api/admin/nodes/12", `{`, "id", "12"))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "update invalid id",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminUpdateNode(w, adminRouteRequest(http.MethodPut, "/api/admin/nodes/x", `{"name":"node"}`, "id", "x"))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "update unnamed",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminUpdateNode(w, adminRouteRequest(http.MethodPut, "/api/admin/nodes/12", `{}`, "id", "12"))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "update negative quota",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminUpdateNode(w, adminRouteRequest(http.MethodPut, "/api/admin/nodes/12", `{"name":"node","expected_disk_quota_bytes":-1}`, "id", "12"))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "lifecycle invalid",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminTransitionNodeLifecycle(w, adminRouteRequest(http.MethodPost, "/api/admin/nodes/12/lifecycle", `{}`, "id", "12"))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "lifecycle missing session",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminTransitionNodeLifecycle(w, adminRouteRequest(http.MethodPost, "/api/admin/nodes/12/lifecycle",
					`{"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","state":"maintenance","reason_code":"operator_maintenance"}`, "id", "12"))
			},
			status: http.StatusUnauthorized,
		},
		{
			name: "retirement invalid id",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminNodeRetirementStatus(w, adminRouteRequest(http.MethodGet, "/api/admin/nodes/x/retirement", "", "id", "x"))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "enrollment invalid id",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminNodeRegisterToken(w, adminRouteRequest(http.MethodPost, "/api/admin/nodes/x/token", "", "id", "x"))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "users invalid page",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminListUsers(w, adminRouteRequest(http.MethodGet, "/api/admin/users?limit=0", "", "", ""))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "users oversized query",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminListUsers(w, adminRouteRequest(http.MethodGet, "/api/admin/users?q="+strings.Repeat("x", 129), "", "", ""))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "backup invalid user",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminTriggerBackup(w, adminRouteRequest(http.MethodPost, "/api/admin/users/x/backup", "", "id", "x"))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "disable invalid user",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminDisableUser(w, adminRouteRequest(http.MethodPost, "/api/admin/users/x/disable", "", "id", "x"))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "backups invalid filter",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminListBackups(w, adminRouteRequest(http.MethodGet, "/api/admin/backups?user_id=x", "", "", ""))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "abort invalid job",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminAbortBackup(w, adminRouteRequest(http.MethodPost, "/api/admin/backups/x/abort", "", "id", "x"))
			},
			status: http.StatusBadRequest,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			server := &Server{Cfg: config.DefaultController(), Store: &store.Store{DB: db}}
			recorder := httptest.NewRecorder()
			tc.run(server, recorder)
			if recorder.Code != tc.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAdminReadHandlersReturnStableUnavailableAndNotFoundResponses(t *testing.T) {
	t.Parallel()
	injected := errors.New("injected admin read failure")
	for _, tc := range []struct {
		name   string
		setup  func(sqlmock.Sqlmock)
		run    func(*Server, http.ResponseWriter)
		status int
	}{
		{
			name: "overview unavailable", setup: func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`SELECT`).WillReturnError(injected) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminOverview(w, adminRouteRequest(http.MethodGet, "/api/admin", "", "", ""))
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "rebuild unavailable", setup: func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`SELECT`).WillReturnError(injected) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminControllerRebuild(w, adminRouteRequest(http.MethodGet, "/api/admin/rebuild", "", "", ""))
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "rebuild absent", setup: func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`SELECT`).WillReturnError(sql.ErrNoRows) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminControllerRebuild(w, adminRouteRequest(http.MethodGet, "/api/admin/rebuild", "", "", ""))
			},
			status: http.StatusOK,
		},
		{
			name: "nodes unavailable", setup: func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`SELECT`).WillReturnError(injected) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminListNodes(w, adminRouteRequest(http.MethodGet, "/api/admin/nodes", "", "", ""))
			},
			status: http.StatusInternalServerError,
		},
		{
			name: "retirement unavailable", setup: func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`SELECT`).WillReturnError(injected) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminNodeRetirementStatus(w, adminRouteRequest(http.MethodGet, "/api/admin/nodes/12/retirement", "", "id", "12"))
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "retirement absent", setup: func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`SELECT`).WillReturnError(sql.ErrNoRows) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminNodeRetirementStatus(w, adminRouteRequest(http.MethodGet, "/api/admin/nodes/12/retirement", "", "id", "12"))
			},
			status: http.StatusNotFound,
		},
		{
			name: "compatibility unavailable", setup: func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`SELECT`).WillReturnError(injected) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminNodeCompatibilityIncidentStatus(w, adminRouteRequest(http.MethodGet, "/api/admin/nodes/12/compatibility", "", "id", "12"))
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "compatibility absent", setup: func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`SELECT`).WillReturnError(sql.ErrNoRows) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminNodeCompatibilityIncidentStatus(w, adminRouteRequest(http.MethodGet, "/api/admin/nodes/12/compatibility", "", "id", "12"))
			},
			status: http.StatusNotFound,
		},
		{
			name: "enrollment node missing", setup: func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`SELECT`).WillReturnError(injected) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminNodeRegisterToken(w, adminRouteRequest(http.MethodPost, "/api/admin/nodes/12/token", "", "id", "12"))
			},
			status: http.StatusNotFound,
		},
		{
			name: "backup user missing", setup: func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`SELECT`).WillReturnError(injected) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminTriggerBackup(w, adminRouteRequest(http.MethodPost, "/api/admin/users/7/backup", "", "id", "7"))
			},
			status: http.StatusNotFound,
		},
		{
			name: "abort job missing", setup: func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`SELECT`).WillReturnError(injected) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminAbortBackup(w, adminRouteRequest(http.MethodPost, "/api/admin/backups/7/abort", "", "id", "7"))
			},
			status: http.StatusNotFound,
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
			tc.setup(mock)
			recorder := httptest.NewRecorder()
			tc.run(server, recorder)
			if recorder.Code != tc.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
