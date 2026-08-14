package store

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestInsertAIAdvisoryRequestAndListDue(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := &Store{DB: db}
	now := time.Now().UTC()
	mock.ExpectQuery(`INSERT INTO ai_advisory_requests`).
		WithArgs("monitoring_inspection", "1.0", "2026-08-14.1", "mock-model",
			[]byte("digest"), []byte(`{"observation_id":"obs_x"}`), "monitor_20260814", now.Add(2*time.Minute), "queued").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(42))
	id, err := st.InsertAIAdvisoryRequest(ctx(), AIAdvisoryRequest{
		TaskType: "monitoring_inspection", SchemaVersion: "1.0", PromptVersion: "2026-08-14.1",
		ModelID: "mock-model", ObservationDigest: []byte("digest"),
		ObservationJSON: []byte(`{"observation_id":"obs_x"}`), DedupKey: "monitor_20260814",
		DeadlineAt: now.Add(2 * time.Minute), State: "queued",
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if id != 42 {
		t.Fatalf("id=%d", id)
	}
	mock.ExpectQuery(`SELECT id, task_type, schema_version, prompt_version, model_id`).
		WithArgs(4).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_type", "schema_version", "prompt_version", "model_id",
			"observation_digest", "observation_json", "dedup_key",
			"requested_at", "deadline_at", "state", "error_code",
		}).AddRow(42, "monitoring_inspection", "1.0", "2026-08-14.1", "mock-model",
			[]byte("digest"), []byte(`{"observation_id":"obs_x"}`), "monitor_20260814",
			now, now.Add(2*time.Minute), "queued", ""))
	rows, err := st.ListDueAIAdvisoryRequests(ctx(), 4)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != 42 || rows[0].TaskType != "monitoring_inspection" {
		t.Fatalf("rows=%+v", rows)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet: %v", err)
	}
}

func TestInsertAIAdvisoryAndOutcome(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := &Store{DB: db}
	now := time.Now().UTC()
	mock.ExpectQuery(`INSERT INTO ai_advisories`).
		WithArgs(int64(42), "NO_ACTION", sqlmock.AnyArg(), 0.9, false, "一切正常",
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			[]byte("raw-digest"), now.Add(15*time.Minute)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(7))
	if _, err := st.InsertAIAdvisory(ctx(), AIAdvisory{
		RequestID: 42, Action: "NO_ACTION", CandidateRefs: []string{},
		Confidence: 0.9, Abstain: false, ReasonSummary: "一切正常",
		EvidenceRefs: []string{}, RiskFlags: []string{}, RequestedObs: []string{},
		RawResponseDigest: []byte("raw-digest"), ExpiresAt: now.Add(15 * time.Minute),
	}); err != nil {
		t.Fatalf("advisory: %v", err)
	}
	mock.ExpectExec(`INSERT INTO ai_advisory_outcomes`).
		WithArgs(int64(42), "shown", "", "none", "", "stored").
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := st.InsertAIAdvisoryOutcome(ctx(), struct {
		RequestID        int64
		Decision         string
		ValidatorCode    string
		ActorType        string
		DeterministicRef string
		ObservedOutcome  string
	}{RequestID: 42, Decision: "shown", ActorType: "none", ObservedOutcome: "stored"}); err != nil {
		t.Fatalf("outcome: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet: %v", err)
	}
}

func TestMarkAIAdvisoryRequestState(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := &Store{DB: db}
	mock.ExpectExec(`UPDATE ai_advisory_requests`).
		WithArgs(int64(42), "succeeded", "").
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := st.MarkAIAdvisoryRequestState(ctx(), 42, "succeeded", ""); err != nil {
		t.Fatalf("mark: %v", err)
	}
}

func TestListRecentAIAdvisoriesAndCountByTask(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := &Store{DB: db}
	now := time.Now().UTC()
	mock.ExpectQuery(`SELECT a.request_id, a.id, r.task_type, r.model_id, a.action`).
		WithArgs(20).
		WillReturnRows(sqlmock.NewRows([]string{
			"request_id", "id", "task_type", "model_id", "action",
			"confidence", "abstain", "reason_summary", "created_at",
		}).AddRow(42, 7, "monitoring_inspection", "mock-model", "NO_ACTION",
			0.9, false, "一切正常", now))
	rows, err := st.ListRecentAIAdvisories(ctx(), 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].TaskType != "monitoring_inspection" || rows[0].ReasonSummary != "一切正常" {
		t.Fatalf("rows=%+v", rows)
	}
	// The admin AI page reads snake_case keys; the response must never
	// serialize Go field names (regression guard for the contract bug that
	// rendered Invalid Date / NaN% in the console).
	payload, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{"advisory_id", "task_type", "reason_summary", "created_at", "model_id", "action", "confidence"} {
		if !bytes.Contains(payload, []byte(`"`+key+`"`)) {
			t.Fatalf("advisory JSON missing snake_case key %q: %s", key, payload)
		}
	}
	for _, goName := range []string{"AdvisoryID", "TaskType", "ReasonSummary", "CreatedAt"} {
		if bytes.Contains(payload, []byte(`"`+goName+`"`)) {
			t.Fatalf("advisory JSON leaked Go field name %q: %s", goName, payload)
		}
	}
	mock.ExpectQuery(`SELECT task_type, COUNT\(\*\) FROM ai_advisory_requests GROUP BY task_type`).
		WillReturnRows(sqlmock.NewRows([]string{"task_type", "count"}).
			AddRow("monitoring_inspection", int64(3)))
	counts, err := st.CountAIAdvisoryRequestsByTask(ctx())
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if counts["monitoring_inspection"] != 3 {
		t.Fatalf("counts=%+v", counts)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet: %v", err)
	}
}

func TestListAIAdvisoryRequestsPage(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := &Store{DB: db}
	now := time.Now().UTC()
	mock.ExpectQuery(`SELECT id, task_type, schema_version, prompt_version, model_id`).
		WithArgs(int64(0), "", 20).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_type", "schema_version", "prompt_version", "model_id",
			"observation_digest", "observation_json", "dedup_key",
			"requested_at", "deadline_at", "state", "error_code",
		}).AddRow(1, "monitoring_inspection", "1.0", "2026-08-14.1", "mock-model",
			[]byte("d"), []byte(`{}`), "k", now, now, "succeeded", ""))
	rows, err := st.ListAIAdvisoryRequestsPage(ctx(), 0, 20, "")
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != 1 {
		t.Fatalf("rows=%+v", rows)
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{"requested_at", "model_id", "error_code", "task_type", "state"} {
		if !bytes.Contains(payload, []byte(`"`+key+`"`)) {
			t.Fatalf("request JSON missing snake_case key %q: %s", key, payload)
		}
	}
	if bytes.Contains(payload, []byte(`"RequestedAt"`)) || bytes.Contains(payload, []byte(`"ModelID"`)) {
		t.Fatalf("request JSON leaked Go field names: %s", payload)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet: %v", err)
	}
}

func ctx() context.Context { return context.Background() }

var _ = regexp.MustCompile
