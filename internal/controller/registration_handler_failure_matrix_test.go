package controller

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func TestHandleRegisterRejectsInvalidBrowserInputsAndMissingNode(t *testing.T) {
	t.Parallel()
	validOperation := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	for _, tc := range []struct {
		name      string
		body      string
		crossSite bool
		setup     func(sqlmock.Sqlmock)
		status    int
	}{
		{name: "cross-site", body: `{}`, crossSite: true, status: http.StatusForbidden},
		{name: "malformed JSON", body: `{`, status: http.StatusBadRequest},
		{name: "invalid operation", body: `{"operation_id":"bad","username":"alice","password":"password-1","node_id":12}`, status: http.StatusBadRequest},
		{name: "invalid handle", body: `{"operation_id":"` + validOperation + `","username":"a","password":"password-1","node_id":12}`, status: http.StatusBadRequest},
		{name: "display name too long", body: `{"operation_id":"` + validOperation + `","username":"alice","display_name":"` + strings.Repeat("x", 129) + `","password":"password-1","node_id":12}`, status: http.StatusBadRequest},
		{name: "short password", body: `{"operation_id":"` + validOperation + `","username":"alice","password":"short","node_id":12}`, status: http.StatusBadRequest},
		{name: "oversized invitation", body: `{"operation_id":"` + validOperation + `","username":"alice","password":"password-1","invitation_code":"` + strings.Repeat("x", 257) + `","node_id":12}`, status: http.StatusBadRequest},
		{
			name: "missing node", body: `{"operation_id":"` + validOperation + `","username":"alice","password":"password-1","node_id":12}`,
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`FROM nodes WHERE id=\$1`).WithArgs(int64(12)).WillReturnError(errors.New("node lookup failed"))
			},
			status: http.StatusBadRequest,
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
			req := httptest.NewRequest(http.MethodPost, "https://control.example/api/auth/register", strings.NewReader(tc.body))
			if tc.crossSite {
				req.Header.Set("Sec-Fetch-Site", "cross-site")
			}
			recorder := httptest.NewRecorder()
			server.handleRegister(recorder, req)
			if recorder.Code != tc.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWriteRegistrationStartErrorMapsDurableConflicts(t *testing.T) {
	t.Parallel()
	server := &Server{}
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{name: "invitation", err: store.ErrRegistrationInvitationRequired, status: http.StatusBadRequest},
		{name: "node policy", err: store.ErrRegistrationNodeUnavailable, status: http.StatusConflict},
		{name: "request conflict", err: store.ErrRegistrationConflict, status: http.StatusConflict},
		{name: "read only", err: store.ErrNoActiveController, status: http.StatusServiceUnavailable},
		{name: "store failure", err: errors.New("store failed"), status: http.StatusServiceUnavailable},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			recorder := httptest.NewRecorder()
			server.writeRegistrationStartError(recorder, tc.err)
			if recorder.Code != tc.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}
