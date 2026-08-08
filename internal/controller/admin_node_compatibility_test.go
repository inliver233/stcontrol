package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-chi/chi/v5"
	"stcontrol/internal/store"
)

func TestAdminNodeCompatibilityIncidentStatus(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 8, 9, 4, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT state,reason_code,compatible_observations`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{
			"state", "reason_code", "compatible_observations", "observed_agent_version",
			"observed_tavern_version", "first_seen_at", "last_seen_at", "resolved_at",
		}).AddRow("verifying", "fingerprint_changed", 2, "agent-v2", "tavern-v2", now, now, nil))
	server := &Server{Store: &store.Store{DB: db}}
	request := httptest.NewRequest(http.MethodGet, "/api/admin/nodes/12/compatibility-incident", nil)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", "12")
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
	recorder := httptest.NewRecorder()
	server.handleAdminNodeCompatibilityIncidentStatus(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"required_observations":3`) ||
		!strings.Contains(recorder.Body.String(), `"reason_code":"fingerprint_changed"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAdminNodeCompatibilityIncidentStatusRejectsInvalidNode(t *testing.T) {
	t.Parallel()
	server := &Server{}
	request := httptest.NewRequest(http.MethodGet, "/api/admin/nodes/not-a-node/compatibility-incident", nil)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", "not-a-node")
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
	recorder := httptest.NewRecorder()
	server.handleAdminNodeCompatibilityIncidentStatus(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
