package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestPostgresAIAdoptionEffectsLifecycle exercises the decision-④ adoption
// persistence (migration 0048) against real PostgreSQL: the widened
// decision CHECK accepts auto_adopted, effects are idempotent per
// (request, kind), the live read paths honour expiry, and the per-request
// getters decode JSONB columns.
func TestPostgresAIAdoptionEffectsLifecycle(t *testing.T) {
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

	reqID, err := st.InsertAIAdvisoryRequest(ctx, AIAdvisoryRequest{
		TaskType: "schedule_recommendation", SchemaVersion: "1.0", PromptVersion: "v1",
		ModelID: "test-model", ObservationDigest: make32Byte("adopt"),
		ObservationJSON: []byte(`{"observation_id":"obs_adopt1234567890"}`),
		DedupKey:        "schedule_adopt_test", DeadlineAt: now.Add(2 * time.Minute), State: "queued",
	})
	if err != nil {
		t.Fatalf("insert request: %v", err)
	}
	advID, err := st.InsertAIAdvisory(ctx, AIAdvisory{
		RequestID: reqID, Action: "RECOMMEND_NODE_ORDER", CandidateRefs: []string{"ref_a", "ref_b"},
		Confidence: 0.9, ReasonSummary: "排序", EvidenceRefs: []string{}, RiskFlags: []string{},
		RequestedObs: []string{}, RawResponseDigest: make32Byte("raw"), ExpiresAt: now.Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("insert advisory: %v", err)
	}

	// The 0048 CHECK must accept auto_adopted (and keep rejecting garbage).
	if err := st.InsertAIAdvisoryOutcome(ctx, struct {
		RequestID        int64
		Decision         string
		ValidatorCode    string
		ActorType        string
		DeterministicRef string
		ObservedOutcome  string
	}{RequestID: reqID, Decision: "auto_adopted", ActorType: "system",
		DeterministicRef: "node_order_hint:3,1,2", ObservedOutcome: "applied"}); err != nil {
		t.Fatalf("auto_adopted outcome rejected by CHECK: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO ai_advisory_outcomes (request_id,decision,actor_type)
		VALUES ($1,'bogus_decision','system')`, reqID); err == nil {
		t.Fatal("bogus decision must violate the CHECK constraint")
	}

	// Effects: insert, idempotent replay, live reads, expiry.
	effect := AIAdoptionEffect{
		RequestID: reqID, AdvisoryID: advID, EffectKind: "node_order_hint",
		TargetRef: "registration", Payload: []byte(`{"order":[3,1,2]}`),
		ExpiresAt: now.Add(15 * time.Minute),
	}
	if err := st.InsertAIAdoptionEffect(ctx, effect); err != nil {
		t.Fatalf("insert effect: %v", err)
	}
	if err := st.InsertAIAdoptionEffect(ctx, effect); err != nil {
		t.Fatalf("replay insert must be idempotent: %v", err)
	}
	var count int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM ai_adoption_effects WHERE request_id=$1`, reqID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("effect rows=%d, want 1 (idempotent)", count)
	}

	latest, err := st.GetLatestAIAdoptionEffect(ctx, "node_order_hint", "registration", now)
	if err != nil || latest == nil {
		t.Fatalf("latest=%+v err=%v", latest, err)
	}
	hint, ok := AIOrderingHintFrom(latest)
	if !ok || len(hint.Order) != 3 || hint.Order[0] != 3 || hint.Order[1] != 1 || hint.Order[2] != 2 {
		t.Fatalf("hint decode=%+v ok=%v", hint, ok)
	}
	// Expired hint is invisible.
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE ai_adoption_effects SET expires_at=$2 WHERE request_id=$1`, reqID, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if latest, err = st.GetLatestAIAdoptionEffect(ctx, "node_order_hint", "registration", now); err != nil || latest != nil {
		t.Fatalf("expired hint must be gone: %+v err=%v", latest, err)
	}

	// Alert notes list: newest per target wins, expired rows disappear.
	seedNote := func(dedup, target, note string, expires time.Time) {
		t.Helper()
		noteReq, err := st.InsertAIAdvisoryRequest(ctx, AIAdvisoryRequest{
			TaskType: "anomaly_attribution", SchemaVersion: "1.0", PromptVersion: "v1",
			ModelID: "test-model", ObservationDigest: make32Byte(dedup),
			DedupKey: dedup, DeadlineAt: now.Add(2 * time.Minute), State: "succeeded",
		})
		if err != nil {
			t.Fatalf("seed %s request: %v", dedup, err)
		}
		noteAdv, err := st.InsertAIAdvisory(ctx, AIAdvisory{
			RequestID: noteReq, Action: "EXPLAIN_ALERT", Confidence: 0.9,
			ReasonSummary: note, RawResponseDigest: make32Byte(dedup + "raw"),
			ExpiresAt: expires,
		})
		if err != nil {
			t.Fatalf("seed %s advisory: %v", dedup, err)
		}
		if err := st.InsertAIAdoptionEffect(ctx, AIAdoptionEffect{
			RequestID: noteReq, AdvisoryID: noteAdv, EffectKind: "alert_note",
			TargetRef: target, Payload: []byte(`{"note":"` + note + `"}`), ExpiresAt: expires,
		}); err != nil {
			t.Fatalf("seed %s effect: %v", dedup, err)
		}
	}
	seedNote("note_old", "user-a", "旧说明", now.Add(10*time.Minute))
	seedNote("note_new", "user-a", "新说明", now.Add(10*time.Minute))
	seedNote("note_dead", "user-b", "过期说明", now.Add(-time.Second))
	notes, err := st.ListActiveAIAdoptionEffects(ctx, "alert_note", now)
	if err != nil {
		t.Fatalf("list notes: %v", err)
	}
	if len(notes) != 1 || notes[0].TargetRef != "user-a" {
		t.Fatalf("notes=%+v, want only newest live user-a note", notes)
	}
	var note struct {
		Note string `json:"note"`
	}
	if err := json.Unmarshal(notes[0].Payload, &note); err != nil || note.Note != "新说明" {
		t.Fatalf("note payload=%s err=%v", notes[0].Payload, err)
	}

	// Outcome counting for the admin status panel.
	n, err := st.CountAIAdvisoryOutcomesSince(ctx, "auto_adopted", now.Add(-time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("auto_adopted count=%d err=%v, want 1", n, err)
	}

	// Per-request getters decode JSONB columns.
	gotAdv, err := st.GetAIAdvisoryByRequestID(ctx, reqID)
	if err != nil {
		t.Fatalf("get advisory: %v", err)
	}
	if gotAdv.AdvisoryID != advID || gotAdv.Action != "RECOMMEND_NODE_ORDER" ||
		len(gotAdv.CandidateRefs) != 2 || gotAdv.Confidence != 0.9 {
		t.Fatalf("gotAdv=%+v", gotAdv)
	}
	gotReq, err := st.GetAIAdvisoryRequest(ctx, reqID)
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	if gotReq.TaskType != "schedule_recommendation" {
		t.Fatalf("gotReq task=%q", gotReq.TaskType)
	}
	var obsID struct {
		ObservationID string `json:"observation_id"`
	}
	if err := json.Unmarshal(gotReq.ObservationJSON, &obsID); err != nil || obsID.ObservationID != "obs_adopt1234567890" {
		t.Fatalf("gotReq observation=%s err=%v", gotReq.ObservationJSON, err)
	}
}
