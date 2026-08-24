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

func TestRegistrationStatusHandlersFenceExpiredAndUnavailableResults(t *testing.T) {
	t.Parallel()
	injected := errors.New("injected registration status failure")
	for _, tc := range []struct {
		name   string
		direct *store.RegistrationWorkflowStatus
		setup  func(sqlmock.Sqlmock)
		status int
	}{
		{
			name: "lookup unavailable",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`FROM workflows workflow`).WillReturnError(injected)
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "expired",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`FROM workflows workflow`).WillReturnError(sql.ErrNoRows)
			},
			status: http.StatusUnauthorized,
		},
		{name: "nil direct status", direct: &store.RegistrationWorkflowStatus{}, status: http.StatusServiceUnavailable},
		{
			name: "succeeded result unavailable", direct: &store.RegistrationWorkflowStatus{State: "succeeded", ResultUserID: 7},
			setup:  func(mock sqlmock.Sqlmock) { mock.ExpectQuery(`FROM users u`).WillReturnError(injected) },
			status: http.StatusServiceUnavailable,
		},
		{
			name: "succeeded session unavailable", direct: &store.RegistrationWorkflowStatus{State: "succeeded", ResultUserID: 7},
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`FROM users u`).WillReturnRows(oauthUserRows("active"))
				mock.ExpectQuery(`INSERT INTO controller_sessions`).WillReturnError(injected)
			},
			status: http.StatusServiceUnavailable,
		},
		{name: "terminal failure", direct: &store.RegistrationWorkflowStatus{State: "failed", ErrorCode: "policy_changed"}, status: http.StatusConflict},
		{name: "cancelled", direct: &store.RegistrationWorkflowStatus{State: "cancelled", ErrorCode: "identity_conflict"}, status: http.StatusConflict},
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
			req := httptest.NewRequest(http.MethodGet, "https://control.example/api/auth/registration", nil)
			recorder := httptest.NewRecorder()
			if tc.direct != nil {
				if tc.name == "nil direct status" {
					server.writeRegistrationStatus(recorder, req, nil)
				} else {
					server.writeRegistrationStatus(recorder, req, tc.direct)
				}
			} else {
				req.AddCookie(&http.Cookie{Name: registrationPendingCookie, Value: "pending-token"})
				server.handleRegistrationStatus(recorder, req)
			}
			if recorder.Code != tc.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if registrationFailureMessage("node_unavailable") == "" || registrationFailureMessage("unknown") == "" {
		t.Fatal("registration failure mapping returned an empty message")
	}
}

func adminFaultRequest(body string, authenticated bool) *http.Request {
	req := adminRouteRequest(http.MethodPost,
		"/api/admin/users/33333333-3333-4333-8333-333333333333/data-fault", body,
		"uuid", "33333333-3333-4333-8333-333333333333")
	if authenticated {
		req = req.WithContext(context.WithValue(req.Context(), ctxKey("stcontrol-session"), &session{
			ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", AdminID: 9, Username: "admin", IsAdmin: true,
		}))
	}
	return req
}

func TestAdminUserDataFaultHandlersMapValidationAndDurableConflicts(t *testing.T) {
	t.Parallel()
	validBody := `{"operation_id":"22222222-2222-4222-8222-222222222222","expected_home_node_id":8,"reason_code":"user_database_corrupt","acknowledge_risk":true}`
	for _, tc := range []struct {
		name   string
		body   string
		auth   bool
		err    error
		status int
	}{
		{name: "invalid body", body: `{}`, status: http.StatusBadRequest},
		{name: "missing admin session", body: validBody, status: http.StatusUnauthorized},
		{name: "invalid durable request", body: validBody, auth: true, err: store.ErrInvalidUserDataFault, status: http.StatusBadRequest},
		{name: "user missing", body: validBody, auth: true, err: store.ErrUserDataFaultNotFound, status: http.StatusNotFound},
		{name: "fact conflict", body: validBody, auth: true, err: store.ErrUserDataFaultHomeConflict, status: http.StatusConflict},
		{name: "store unavailable", body: validBody, auth: true, err: errors.New("database unavailable"), status: http.StatusServiceUnavailable},
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
			if tc.err != nil {
				mock.ExpectBegin().WillReturnError(tc.err)
			}
			recorder := httptest.NewRecorder()
			server.handleAdminReportUserDataFault(recorder, adminFaultRequest(tc.body, tc.auth))
			if recorder.Code != tc.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAdminUserDataFaultStatusMapsInvalidUnavailableAndAbsent(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		uuid   string
		setup  func(sqlmock.Sqlmock)
		status int
	}{
		{name: "invalid UUID", uuid: "invalid", status: http.StatusBadRequest},
		{
			name: "lookup unavailable", uuid: "33333333-3333-4333-8333-333333333333",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`FROM user_data_faults fault`).WillReturnError(errors.New("lookup failed"))
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "absent", uuid: "33333333-3333-4333-8333-333333333333",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`FROM user_data_faults fault`).WillReturnError(sql.ErrNoRows)
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
			server := &Server{Store: &store.Store{DB: db}}
			if tc.setup != nil {
				tc.setup(mock)
			}
			req := adminRouteRequest(http.MethodGet, "/api/admin/users/"+tc.uuid+"/data-fault", "", "uuid", tc.uuid)
			recorder := httptest.NewRecorder()
			server.handleAdminUserDataFaultStatus(recorder, req)
			if recorder.Code != tc.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
