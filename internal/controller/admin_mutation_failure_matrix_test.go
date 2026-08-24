package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func TestAdminMutationAndPageHandlersMapStoreFailures(t *testing.T) {
	t.Parallel()
	injected := errors.New("injected admin mutation failure")
	for _, tc := range []struct {
		name   string
		setup  func(sqlmock.Sqlmock)
		run    func(*Server, http.ResponseWriter)
		status int
	}{
		{
			name:  "create node",
			setup: func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`INSERT INTO nodes`).WillReturnError(injected) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminCreateNode(w, adminRouteRequest(http.MethodPost, "/api/admin/nodes", `{"name":"node-a","role":"compute"}`, "", ""))
			}, status: http.StatusInternalServerError,
		},
		{
			name:  "update node settings",
			setup: func(mock sqlmock.Sqlmock) { mock.ExpectExec(`UPDATE nodes SET name`).WillReturnError(injected) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminUpdateNode(w, adminRouteRequest(http.MethodPut, "/api/admin/nodes/12", `{"name":"node-a"}`, "id", "12"))
			}, status: http.StatusInternalServerError,
		},
		{
			name: "update node quota",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`UPDATE nodes SET name`).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectBegin().WillReturnError(injected)
			},
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminUpdateNode(w, adminRouteRequest(http.MethodPut, "/api/admin/nodes/12", `{"name":"node-a","expected_disk_quota_bytes":1000}`, "id", "12"))
			}, status: http.StatusInternalServerError,
		},
		{
			name:  "lifecycle transition",
			setup: func(mock sqlmock.Sqlmock) { mock.ExpectBegin().WillReturnError(injected) },
			run: func(server *Server, w http.ResponseWriter) {
				req := adminRouteRequest(http.MethodPost, "/api/admin/nodes/12/lifecycle",
					`{"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","state":"maintenance","reason_code":"operator_maintenance"}`, "id", "12")
				req = req.WithContext(context.WithValue(req.Context(), ctxKey("stcontrol-session"), &session{AdminID: 9, IsAdmin: true}))
				server.handleAdminTransitionNodeLifecycle(w, req)
			}, status: http.StatusServiceUnavailable,
		},
		{
			name:  "users query",
			setup: func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`FROM users user_account`).WillReturnError(injected) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminListUsers(w, adminRouteRequest(http.MethodGet, "/api/admin/users", "", "", ""))
			}, status: http.StatusInternalServerError,
		},
		{
			name: "users invalid status",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminListUsers(w, adminRouteRequest(http.MethodGet, "/api/admin/users?status=secret", "", "", ""))
			}, status: http.StatusBadRequest,
		},
		{
			name:  "disable user",
			setup: func(mock sqlmock.Sqlmock) { mock.ExpectExec(`UPDATE users SET status`).WillReturnError(injected) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminDisableUser(w, adminRouteRequest(http.MethodPost, "/api/admin/users/7/disable", "", "id", "7"))
			}, status: http.StatusInternalServerError,
		},
		{
			name:  "backups query",
			setup: func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`FROM backup_jobs job`).WillReturnError(injected) },
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminListBackups(w, adminRouteRequest(http.MethodGet, "/api/admin/backups", "", "", ""))
			}, status: http.StatusInternalServerError,
		},
		{
			name: "backups invalid status",
			run: func(server *Server, w http.ResponseWriter) {
				server.handleAdminListBackups(w, adminRouteRequest(http.MethodGet, "/api/admin/backups?status=secret", "", "", ""))
			}, status: http.StatusBadRequest,
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
