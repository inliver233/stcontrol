package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/ai"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

// TestControllerAIAdoptionOrderingHardGates exercises the decision-④
// adoption executor end to end against real PostgreSQL: full orderings of
// currently eligible nodes are persisted as reversible hint effects, partial
// or stale orderings fail closed, and the consumed hint can only reorder
// nodes inside the deterministic rank tiers (never promote ineligible nodes).
func TestControllerAIAdoptionOrderingHardGates(t *testing.T) {
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	defer cleanupSchema()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	cfg := config.DefaultController()
	cfg.StaticDir = t.TempDir()
	cfg.Relay.Listen = ""
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	server := New(cfg, st, secretKey)

	n1 := createControllerBackupNode(t, ctx, st, "ai-adopt-n1", "compute", false, 1)
	n2 := createControllerBackupNode(t, ctx, st, "ai-adopt-n2", "compute", false, 1)
	n3 := createControllerBackupNode(t, ctx, st, "ai-adopt-n3", "compute", false, 1)
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET connectivity_state='offline' WHERE id=$1`, n3.ID); err != nil {
		t.Fatal(err)
	}

	obsID := "obs_adoptorder1234"
	redactor := ai.NewRedactor(secretKey)
	ref1 := redactor.Ref("node", obsID, itoa64(n1.ID))
	ref2 := redactor.Ref("node", obsID, itoa64(n2.ID))

	seedAdoption := func(task, action string, candidateRefs, evidenceRefs []string, confidence float64) (int64, *ai.Advisory, int64) {
		t.Helper()
		obsJSON := []byte(`{"observation_id":"` + obsID + `","evidence_catalog":[],"candidate_catalog":[]}`)
		reqID, err := st.InsertAIAdvisoryRequest(ctx, store.AIAdvisoryRequest{
			TaskType: task, SchemaVersion: ai.SchemaVersion, PromptVersion: ai.PromptVersion,
			ModelID: "test-model", ObservationDigest: make32Byte("adopt"), ObservationJSON: obsJSON,
			DedupKey:   "adopt_" + action + "_" + time.Now().Format("150405.000000000"),
			DeadlineAt: time.Now().UTC().Add(2 * time.Minute), State: "succeeded",
		})
		if err != nil {
			t.Fatalf("insert request: %v", err)
		}
		advID, err := st.InsertAIAdvisory(ctx, store.AIAdvisory{
			RequestID: reqID, Action: action, CandidateRefs: candidateRefs, Confidence: confidence,
			ReasonSummary: "测试建议", EvidenceRefs: evidenceRefs, RiskFlags: []string{},
			RequestedObs: []string{}, RawResponseDigest: make32Byte("raw"),
			ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
		})
		if err != nil {
			t.Fatalf("insert advisory: %v", err)
		}
		return reqID, &ai.Advisory{
			SchemaVersion: ai.SchemaVersion, TaskType: task, ObservationID: obsID,
			Action: action, CandidateRefs: candidateRefs, Confidence: confidence,
			ReasonSummary: "测试建议", EvidenceRefs: evidenceRefs, RiskFlags: []string{},
		}, advID
	}

	adopter := &aiAdopter{srv: server}

	// 1) Full ordering of both eligible nodes: adopted and persisted.
	reqID, adv, advID := seedAdoption(string(ai.TaskScheduleRecommend),
		string(ai.ActionRecommendNodeOrder), []string{ref2, ref1}, nil, 0.9)
	res, err := adopter.Adopt(ctx, ai.AIAdvisoryRequestLike{ID: reqID}, adv, advID)
	if err != nil || res.ObservedOutcome != "applied" {
		t.Fatalf("adopt full ordering: res=%+v err=%v", res, err)
	}
	if res.EffectRef != "node_order_hint:"+itoa64(n2.ID)+","+itoa64(n1.ID) {
		t.Fatalf("effect ref=%q", res.EffectRef)
	}

	// 2) The consumed hint reorders the available-node list within the same
	// deterministic tier; the offline node stays last regardless.
	listNodes := func() []availableNode {
		t.Helper()
		rec := httptest.NewRecorder()
		server.handleAvailableNodes(rec, httptest.NewRequest(http.MethodGet, "/api/nodes/available", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("available nodes: %d %s", rec.Code, rec.Body.String())
		}
		var payload struct {
			Nodes []availableNode `json:"nodes"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return payload.Nodes
	}
	got := listNodes()
	if len(got) != 3 {
		t.Fatalf("nodes=%d", len(got))
	}
	// Deterministic order without a hint is by rank then stable input order
	// (node id); the adopted hint puts n2 first among the eligible tier.
	if got[0].ID != n2.ID || got[1].ID != n1.ID {
		t.Fatalf("hint did not reorder eligible tier: got [%d %d %d]",
			got[0].ID, got[1].ID, got[2].ID)
	}
	if got[2].ID != n3.ID {
		t.Fatalf("offline node must stay last: got [%d %d %d]", got[0].ID, got[1].ID, got[2].ID)
	}

	// 3) Partial ordering (only one of two eligible nodes): fail closed.
	reqID2, adv2, advID2 := seedAdoption(string(ai.TaskScheduleRecommend),
		string(ai.ActionRecommendNodeOrder), []string{ref1}, nil, 0.9)
	if _, err := adopter.Adopt(ctx, ai.AIAdvisoryRequestLike{ID: reqID2}, adv2, advID2); !errors.Is(err, ai.ErrAdoptionNotExecutable) {
		t.Fatalf("partial ordering must be refused, err=%v", err)
	}

	// 4) Stale ordering: a candidate that is no longer eligible (n2 went
	// offline after the observation) must be refused entirely.
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET connectivity_state='offline' WHERE id=$1`, n2.ID); err != nil {
		t.Fatal(err)
	}
	reqID3, adv3, advID3 := seedAdoption(string(ai.TaskScheduleRecommend),
		string(ai.ActionRecommendNodeOrder), []string{ref2, ref1}, nil, 0.9)
	if _, err := adopter.Adopt(ctx, ai.AIAdvisoryRequestLike{ID: reqID3}, adv3, advID3); !errors.Is(err, ai.ErrAdoptionNotExecutable) {
		t.Fatalf("stale ordering must be refused, err=%v", err)
	}
	// The previously stored hint must not survive as an effect for req3.
	if effect, err := st.GetLatestAIAdoptionEffect(ctx, "node_order_hint", "registration", time.Now().UTC()); err != nil {
		t.Fatalf("latest effect: %v", err)
	} else if effect != nil && effect.RequestID == reqID3 {
		t.Fatal("refused adoption must not persist an effect")
	}
}

// TestControllerAIAdoptionAlertNotes exercises EXPLAIN_ALERT adoption: the
// note lands next to the cited alert (ai_note merge field) without touching
// the deterministic summary, and a summary failing the secret re-scan is
// refused.
func TestControllerAIAdoptionAlertNotes(t *testing.T) {
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	defer cleanupSchema()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	cfg := config.DefaultController()
	cfg.StaticDir = t.TempDir()
	cfg.Relay.Listen = ""
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	server := New(cfg, st, secretKey)

	node := createControllerBackupNode(t, ctx, st, "ai-note-node", "compute", false, 1)
	user := createControllerBackupUser(t, ctx, st, node.ID, "ai-note-user")
	var userUUID string
	var globalUserID int64
	// CreateUser already writes the legacy global_users mapping; reuse it
	// instead of inserting a duplicate row (legacy_user_id is unique).
	if err := st.DB.QueryRowContext(ctx, `
		SELECT id,uuid::text FROM global_users WHERE legacy_user_id=$1`, user.ID).
		Scan(&globalUserID, &userUUID); err != nil {
		t.Fatalf("load global user: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO alerts (id,deduplication_key,severity,state,category,user_id,node_id,summary)
		VALUES (gen_random_uuid(),$1,'warning','open','user_protection',$2,$3,'用户当前没有可恢复副本')`,
		"user-protection:"+userUUID, globalUserID, node.ID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}

	obsID := "obs_adoptnote12345"
	redactor := ai.NewRedactor(secretKey)
	alertRef := redactor.Ref("alert", obsID, userUUID)
	// Mirror the standard monitoring inspection evidence formula.
	evidenceRef := "ev_" + ai.EvidenceShortHash(redactor, obsID, "alert",
		alertRef+"/warning/user_protection")

	seedAdvisory := func(reason string, evidence []string) (int64, *ai.Advisory, int64) {
		t.Helper()
		obsJSON := []byte(`{"observation_id":"` + obsID + `"}`)
		reqID, err := st.InsertAIAdvisoryRequest(ctx, store.AIAdvisoryRequest{
			TaskType: string(ai.TaskMonitoringInspect), SchemaVersion: ai.SchemaVersion,
			PromptVersion: ai.PromptVersion, ModelID: "test-model",
			ObservationDigest: make32Byte("note"), ObservationJSON: obsJSON,
			DedupKey:   "note_" + time.Now().Format("150405.000000000"),
			DeadlineAt: time.Now().UTC().Add(2 * time.Minute), State: "succeeded",
		})
		if err != nil {
			t.Fatalf("insert request: %v", err)
		}
		advID, err := st.InsertAIAdvisory(ctx, store.AIAdvisory{
			RequestID: reqID, Action: string(ai.ActionExplainAlert), Confidence: 0.9,
			ReasonSummary: reason, EvidenceRefs: evidence, RiskFlags: []string{},
			RequestedObs: []string{}, RawResponseDigest: make32Byte("raw"),
			ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
		})
		if err != nil {
			t.Fatalf("insert advisory: %v", err)
		}
		return reqID, &ai.Advisory{
			SchemaVersion: ai.SchemaVersion, TaskType: string(ai.TaskMonitoringInspect),
			ObservationID: obsID, Action: string(ai.ActionExplainAlert), Confidence: 0.9,
			ReasonSummary: reason, EvidenceRefs: evidence, RiskFlags: []string{},
		}, advID
	}

	adopter := &aiAdopter{srv: server}
	reqID, adv, advID := seedAdvisory("存储节点短期离线导致副本保护降级", []string{evidenceRef})
	res, err := adopter.Adopt(ctx, ai.AIAdvisoryRequestLike{ID: reqID}, adv, advID)
	if err != nil || res.EffectRef == "" {
		t.Fatalf("adopt alert note: res=%+v err=%v", res, err)
	}

	// The admin alert view merges the note without touching the summary.
	rec := httptest.NewRecorder()
	server.handleAdminProtectionAlerts(rec, httptest.NewRequest(http.MethodGet, "/api/admin/alerts/protection?limit=10", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("alerts: %d", rec.Code)
	}
	var payload struct {
		Alerts []struct {
			Summary string `json:"summary"`
			AINote  string `json:"ai_note"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Alerts) != 1 {
		t.Fatalf("alerts=%+v", payload.Alerts)
	}
	if payload.Alerts[0].Summary != "用户当前没有可恢复副本" {
		t.Fatalf("deterministic summary overwritten: %q", payload.Alerts[0].Summary)
	}
	if !strings.Contains(payload.Alerts[0].AINote, "存储节点短期离线") {
		t.Fatalf("ai_note missing: %+v", payload.Alerts[0])
	}

	// A reason that fails the fresh secret scan is refused.
	reqID2, adv2, advID2 := seedAdvisory("token=abcdef123456789012345 的告警", []string{evidenceRef})
	if _, err := adopter.Adopt(ctx, ai.AIAdvisoryRequestLike{ID: reqID2}, adv2, advID2); !errors.Is(err, ai.ErrAdoptionNotExecutable) {
		t.Fatalf("secret-bearing note must be refused, err=%v", err)
	}
}

func itoa64(v int64) string { return strconv.FormatInt(v, 10) }

func make32Byte(seed string) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = seed[i%len(seed)]
	}
	return out
}
