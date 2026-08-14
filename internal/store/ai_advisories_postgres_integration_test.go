package store

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// TestPostgresAIAdvisoryRoundTrip exercises the AI 监管层 persistence against
// real PostgreSQL: insert request (idempotent dedup), list due, mark state,
// store advisory + outcome, list recent, page, and per-task counts.
func TestPostgresAIAdvisoryRoundTrip(t *testing.T) {
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	defer cleanupSchema()
	st, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	req := AIAdvisoryRequest{
		TaskType: "monitoring_inspection", SchemaVersion: "1.0", PromptVersion: "2026-08-14.1",
		ModelID: "test-model", ObservationDigest: []byte("digest-material"),
		ObservationJSON: []byte(`{"observation_id":"obs_test1234567890","nodes":[]}`),
		DedupKey:        "monitor_20260814T0000",
		DeadlineAt:      now.Add(2 * time.Minute), State: "queued",
	}
	id, err := st.InsertAIAdvisoryRequest(ctx, req)
	if err != nil {
		t.Fatalf("insert request: %v", err)
	}
	if id <= 0 {
		t.Fatalf("id=%d", id)
	}
	id2, err := st.InsertAIAdvisoryRequest(ctx, req)
	if err != nil {
		t.Fatalf("insert duplicate: %v", err)
	}
	if id2 != id {
		t.Fatalf("dedup broken: first=%d second=%d", id, id2)
	}

	due, err := st.ListDueAIAdvisoryRequests(ctx, 10)
	if err != nil {
		t.Fatalf("list due: %v", err)
	}
	found := false
	for _, d := range due {
		if d.ID == id && d.State == "queued" {
			var got, want map[string]any
			_ = json.Unmarshal(d.ObservationJSON, &got)
			_ = json.Unmarshal(req.ObservationJSON, &want)
			if fmt.Sprintf("%v", got) == fmt.Sprintf("%v", want) {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("due request not found: %+v", due)
	}

	if err := st.MarkAIAdvisoryRequestState(ctx, id, "succeeded", ""); err != nil {
		t.Fatalf("mark succeeded: %v", err)
	}

	advID, err := st.InsertAIAdvisory(ctx, AIAdvisory{
		RequestID: id, Action: "NO_ACTION", CandidateRefs: []string{},
		Confidence: 0.9, Abstain: false, ReasonSummary: "一切正常",
		EvidenceRefs: []string{}, RiskFlags: []string{}, RequestedObs: []string{},
		RawResponseDigest: []byte("raw-digest"), ExpiresAt: now.Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("insert advisory: %v", err)
	}
	if advID <= 0 {
		t.Fatalf("advID=%d", advID)
	}

	if err := st.InsertAIAdvisoryOutcome(ctx, struct {
		RequestID        int64
		Decision         string
		ValidatorCode    string
		ActorType        string
		DeterministicRef string
		ObservedOutcome  string
	}{RequestID: id, Decision: "shown", ActorType: "none", ObservedOutcome: "stored"}); err != nil {
		t.Fatalf("insert outcome: %v", err)
	}

	recent, err := st.ListRecentAIAdvisories(ctx, 10)
	if err != nil {
		t.Fatalf("list recent: %v", err)
	}
	if len(recent) != 1 || recent[0].RequestID != id || recent[0].ReasonSummary != "一切正常" {
		t.Fatalf("recent=%+v", recent)
	}

	page, err := st.ListAIAdvisoryRequestsPage(ctx, 0, 10, "monitoring_inspection")
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if len(page) != 1 || page[0].ID != id || page[0].State != "succeeded" {
		t.Fatalf("page=%+v", page)
	}

	counts, err := st.CountAIAdvisoryRequestsByTask(ctx)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if counts["monitoring_inspection"] != 1 {
		t.Fatalf("counts=%+v", counts)
	}
}

// TestPostgresExpireOverdueAIAdvisoryRequests exercises the overdue-queued
// sweep (suggestion #4) against real PostgreSQL.
func TestPostgresExpireOverdueAIAdvisoryRequests(t *testing.T) {
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	defer cleanupSchema()
	st, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	now := time.Now().UTC()
	seed := func(dedup string, deadline time.Time) {
		t.Helper()
		if _, err := st.DB.ExecContext(ctx, `
			INSERT INTO ai_advisory_requests (
			  task_type,schema_version,prompt_version,model_id,observation_digest,
			  dedup_key,deadline_at,state
			) VALUES ('monitoring_inspection','1.0','v1','m',$1,$2,$3,'queued')`,
			make32Byte(dedup), dedup, deadline); err != nil {
			t.Fatalf("seed %s: %v", dedup, err)
		}
	}
	seed("stale-a", now.Add(-time.Minute))
	seed("stale-b", now.Add(-time.Second))
	seed("fresh-a", now.Add(time.Minute))

	expired, err := st.ExpireOverdueAIAdvisoryRequests(ctx, now)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if expired != 2 {
		t.Fatalf("expired=%d, want 2", expired)
	}
	var state, errorCode string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state,error_code FROM ai_advisory_requests WHERE dedup_key='stale-a'`).
		Scan(&state, &errorCode); err != nil {
		t.Fatal(err)
	}
	if state != "superseded" || errorCode != "deadline_passed" {
		t.Fatalf("stale row state=%q error=%q", state, errorCode)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state FROM ai_advisory_requests WHERE dedup_key='fresh-a'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "queued" {
		t.Fatalf("fresh row state=%q, want queued", state)
	}
	// Idempotent.
	if expired, err = st.ExpireOverdueAIAdvisoryRequests(ctx, now); err != nil || expired != 0 {
		t.Fatalf("second sweep expired=%d err=%v, want 0", expired, err)
	}
}
