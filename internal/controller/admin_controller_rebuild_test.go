package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"stcontrol/internal/store"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestAdminControllerRebuildReportsNotRequiredBeforePromotion(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`FROM controller_rebuild_operations`).WillReturnRows(
		sqlmock.NewRows([]string{
			"id", "operation_id", "generation", "previous_generation", "source",
			"state", "total_nodes", "reconciled_nodes", "error_code",
			"started_at", "updated_at", "completed_at",
		}),
	)
	server := &Server{Store: &store.Store{DB: db}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/admin/controller/rebuild", nil)
	server.handleAdminControllerRebuild(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"state":"not_required"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
