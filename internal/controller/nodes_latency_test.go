package controller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"stcontrol/internal/store"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestReportNodeLatencyPersistsValidatedSample(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{Store: &store.Store{DB: db}}
	mock.ExpectExec(`(?s)UPDATE nodes SET.*client_latency_ms=CASE.*client_latency_observed_at=\$3.*WHERE id=\$1`).
		WithArgs(int64(12), int64(88), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	request := httptest.NewRequest(http.MethodPost, "/api/users/me/node-latency",
		bytes.NewReader([]byte(`{"node_id":12,"latency_ms":88}`)))
	recorder := httptest.NewRecorder()
	server.handleReportNodeLatency(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReportNodeLatencyRejectsUnknownNode(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{Store: &store.Store{DB: db}}
	// A node id the console never listed (stale page or probe) updates zero
	// rows and must surface as 404, not a silent success.
	mock.ExpectExec(`(?s)UPDATE nodes SET.*WHERE id=\$1`).
		WithArgs(int64(404), int64(120), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 0))
	request := httptest.NewRequest(http.MethodPost, "/api/users/me/node-latency",
		bytes.NewReader([]byte(`{"node_id":404,"latency_ms":120}`)))
	recorder := httptest.NewRecorder()
	server.handleReportNodeLatency(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s want 404", recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReportNodeLatencyRejectsInvalidSamples(t *testing.T) {
	t.Parallel()
	db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{Store: &store.Store{DB: db}}
	for _, body := range []string{
		`{"node_id":0,"latency_ms":88}`,
		`{"node_id":12,"latency_ms":-5}`,
		`{"node_id":12,"latency_ms":4000000}`,
		`{"node_id":"x","latency_ms":88}`,
		`{"latency_ms":88}`,
		`{"node_id":12,"latency_ms":88,"extra":true}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/api/users/me/node-latency",
			bytes.NewReader([]byte(body)))
		recorder := httptest.NewRecorder()
		server.handleReportNodeLatency(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d want 400", body, recorder.Code)
		}
	}
}
