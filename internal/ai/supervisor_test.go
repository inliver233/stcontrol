package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeStore implements Store in memory for supervisor flow tests.
type fakeStore struct {
	mu         sync.Mutex
	requests   []AIAdvisoryRequestLike
	advisories []AIAdvisoryLike
	outcomes   []AIAdvisoryOutcomeLike
}

func (f *fakeStore) InsertAIAdvisoryRequest(_ context.Context, req AIAdvisoryRequestLike) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	req.ID = int64(len(f.requests) + 1)
	f.requests = append(f.requests, req)
	return req.ID, nil
}

func (f *fakeStore) ListDueAIAdvisoryRequests(_ context.Context, limit int) ([]AIAdvisoryRequestLike, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []AIAdvisoryRequestLike
	for _, r := range f.requests {
		if r.State == "queued" {
			out = append(out, r)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (f *fakeStore) ExpireOverdueAIAdvisoryRequests(_ context.Context, now time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for i := range f.requests {
		if f.requests[i].State == "queued" && !f.requests[i].DeadlineAt.After(now) {
			f.requests[i].State = "superseded"
			f.requests[i].ErrorCode = "deadline_passed"
			n++
		}
	}
	return n, nil
}

func (f *fakeStore) MarkAIAdvisoryRequestState(_ context.Context, id int64, state, errorCode string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.requests {
		if f.requests[i].ID == id {
			f.requests[i].State = state
			f.requests[i].ErrorCode = errorCode
		}
	}
	return nil
}

func (f *fakeStore) InsertAIAdvisory(_ context.Context, adv AIAdvisoryLike) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.advisories = append(f.advisories, adv)
	return int64(len(f.advisories)), nil
}

func (f *fakeStore) InsertAIAdvisoryOutcome(_ context.Context, outcome AIAdvisoryOutcomeLike) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outcomes = append(f.outcomes, outcome)
	return nil
}

// buildTestObservation returns a minimal valid observation JSON.
func buildTestObservation(obsID string) []byte {
	raw, _, _, _, err := BuildObservation(
		NewRedactor([]byte("key")), obsID, time.Now(),
		[]NodeObservation{{Ref: "ref_abcdefghijklmnop", Role: "compute", Connectivity: "online", Capacity: "open", Compatibility: "compatible", EligibleForNew: true}},
		nil, nil, ProtectionObservation{},
	)
	if err != nil {
		return nil
	}
	return raw
}

func TestSupervisorProcessesQueuedRequestEndToEnd(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	obsID := "obs_test1234567890"
	obsJSON := buildTestObservation(obsID)
	digest := hexDigest(obsJSON)
	_, _ = st.InsertAIAdvisoryRequest(context.Background(), AIAdvisoryRequestLike{
		TaskType: string(TaskMonitoringInspect), SchemaVersion: SchemaVersion,
		PromptVersion: PromptVersion, ModelID: "mock-model",
		ObservationDigest: []byte(digest), ObservationJSON: obsJSON,
		DedupKey: "monitor_x", DeadlineAt: time.Now().Add(time.Minute), State: "queued",
	})
	response := fmt.Sprintf(`{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"%s","action":"NO_ACTION","candidate_refs":[],"confidence":0.9,"abstain":false,"reason_summary":"一切正常","evidence_refs":[],"risk_flags":[],"requested_observations":[]}`, obsID)
	provider := MockProvider([]string{response}, nil)
	sup := NewSupervisor(st, provider, NewRedactor([]byte("key")), ModeShadow, "mock-model", time.Second)
	if err := sup.processDue(context.Background()); err != nil {
		t.Fatalf("processDue: %v", err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.requests) != 1 || st.requests[0].State != "succeeded" {
		t.Fatalf("requests=%+v", st.requests)
	}
	if len(st.advisories) != 1 || st.advisories[0].Action != "NO_ACTION" {
		t.Fatalf("advisories=%+v", st.advisories)
	}
	if len(st.outcomes) != 1 {
		t.Fatalf("outcomes=%+v", st.outcomes)
	}
	if len(provider.Calls()) != 1 {
		t.Fatalf("provider calls=%d", len(provider.Calls()))
	}
	call := provider.Calls()[0]
	if call.SystemPrompt == "" || call.TaskPrompt == "" || len(call.Observation) == 0 {
		t.Fatalf("call params incomplete: %+v", call)
	}
}

func TestSupervisorCircuitBreakerOpensAfterFailures(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	obsID := "obs_test1234567890"
	obsJSON := buildTestObservation(obsID)
	for i := 0; i < 6; i++ {
		_, _ = st.InsertAIAdvisoryRequest(context.Background(), AIAdvisoryRequestLike{
			TaskType: string(TaskMonitoringInspect), SchemaVersion: SchemaVersion,
			PromptVersion: PromptVersion, ModelID: "mock-model",
			ObservationDigest: []byte("d"), ObservationJSON: obsJSON,
			DedupKey:   "monitor_" + string(rune('a'+i)),
			DeadlineAt: time.Now().Add(time.Minute), State: "queued",
		})
	}
	// Provider always fails technically.
	provider := MockProvider(nil, []error{errProviderDown})
	sup := NewSupervisor(st, provider, NewRedactor([]byte("key")), ModeShadow, "mock-model", time.Second)
	// The worker drains 4 requests per pass; run two passes to consume all 6.
	if err := sup.processDue(context.Background()); err != nil {
		t.Fatalf("processDue#1: %v", err)
	}
	if err := sup.processDue(context.Background()); err != nil {
		t.Fatalf("processDue#2: %v", err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.requests) != 6 {
		t.Fatalf("requests=%d", len(st.requests))
	}
	// First 5 fail with provider_error; the 6th is skipped by the breaker.
	if st.requests[0].State != "failed" || st.requests[0].ErrorCode != "provider_error" {
		t.Fatalf("req0=%+v", st.requests[0])
	}
	if st.requests[5].State != "skipped" || st.requests[5].ErrorCode != "circuit_open" {
		t.Fatalf("req5=%+v", st.requests[5])
	}
}

func TestSupervisorRejectsForgedResponseAndRecordsFailure(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	obsID := "obs_test1234567890"
	obsJSON := buildTestObservation(obsID)
	_, _ = st.InsertAIAdvisoryRequest(context.Background(), AIAdvisoryRequestLike{
		TaskType: string(TaskMonitoringInspect), SchemaVersion: SchemaVersion,
		PromptVersion: PromptVersion, ModelID: "mock-model",
		ObservationDigest: []byte("d"), ObservationJSON: obsJSON,
		DedupKey: "monitor_forged", DeadlineAt: time.Now().Add(time.Minute), State: "queued",
	})
	// Response cites evidence that was never in the observation.
	response := fmt.Sprintf(`{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"%s","action":"EXPLAIN_ALERT","candidate_refs":[],"confidence":0.9,"abstain":false,"reason_summary":"x","evidence_refs":["ev_forgedfakefakefake"],"risk_flags":[],"requested_observations":[]}`, obsID)
	provider := MockProvider([]string{response}, nil)
	sup := NewSupervisor(st, provider, NewRedactor([]byte("key")), ModeShadow, "mock-model", time.Second)
	if err := sup.processDue(context.Background()); err != nil {
		t.Fatalf("processDue: %v", err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.requests[0].State != "failed" || st.requests[0].ErrorCode != "unsupported_evidence" {
		t.Fatalf("req=%+v", st.requests[0])
	}
	if len(st.advisories) != 0 {
		t.Fatalf("forged advisory must not be stored: %+v", st.advisories)
	}
}

var errProviderDown = &providerDownError{}

type providerDownError struct{}

func (e *providerDownError) Error() string { return "provider down" }

var _ = json.Marshal

// TestSupervisorWritesRejectedOutcomeOnValidationFailure guards decision ⑤:
// a validator rejection must leave a durable ai_advisory_outcomes row with
// decision='rejected' and the validator error code, not only a failed request.
func TestSupervisorWritesRejectedOutcomeOnValidationFailure(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	obsID := "obs_test1234567890"
	obsJSON := buildTestObservation(obsID)
	_, _ = st.InsertAIAdvisoryRequest(context.Background(), AIAdvisoryRequestLike{
		TaskType: string(TaskMonitoringInspect), SchemaVersion: SchemaVersion,
		PromptVersion: PromptVersion, ModelID: "mock-model",
		ObservationDigest: []byte("d"), ObservationJSON: obsJSON,
		DedupKey: "monitor_rejected", DeadlineAt: time.Now().Add(time.Minute), State: "queued",
	})
	response := fmt.Sprintf(`{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"%s","action":"NO_ACTION","candidate_refs":[],"confidence":0.9,"abstain":false,"reason_summary":"x","evidence_refs":[],"risk_flags":["INVENTED_FLAG"],"requested_observations":[]}`, obsID)
	provider := MockProvider([]string{response}, nil)
	sup := NewSupervisor(st, provider, NewRedactor([]byte("key")), ModeShadow, "mock-model", time.Second)
	if err := sup.processDue(context.Background()); err != nil {
		t.Fatalf("processDue: %v", err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.requests[0].State != "failed" || st.requests[0].ErrorCode != "invalid_risk_flag" {
		t.Fatalf("req=%+v", st.requests[0])
	}
	if len(st.outcomes) != 1 || st.outcomes[0].Decision != "rejected" ||
		st.outcomes[0].ValidatorCode != "invalid_risk_flag" || st.outcomes[0].ActorType != "system" {
		t.Fatalf("rejected outcome row missing or malformed: %+v", st.outcomes)
	}
}

// TestSupervisorOrderingAdvisoryRoundTrip guards D5 end to end: an
// observation that serializes candidate_catalog must let an ordering action
// (RECOMMEND_NODE_ORDER) pass validation, get stored as an advisory and be
// audited as shown - previously the catalog was never serialized, so every
// ordering advisory died with empty_candidates and pushed the breaker open.
func TestSupervisorOrderingAdvisoryRoundTrip(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	obsID := "obs_test1234567890"
	obsJSON := []byte(`{"observation_id":"` + obsID + `","evidence_catalog":[{"ref":"ev_abcdefghijklmnopqrst","kind":"node_capacity","value":"open"}],"candidate_catalog":[{"ref":"ref_aaaaaaaaaaaaaaaa","kind":"node"},{"ref":"ref_bbbbbbbbbbbbbbbb","kind":"node"}]}`)
	_, _ = st.InsertAIAdvisoryRequest(context.Background(), AIAdvisoryRequestLike{
		TaskType: string(TaskScheduleRecommend), SchemaVersion: SchemaVersion,
		PromptVersion: PromptVersion, ModelID: "mock-model",
		ObservationDigest: []byte("d"), ObservationJSON: obsJSON,
		DedupKey: "schedule_roundtrip", DeadlineAt: time.Now().Add(time.Minute), State: "queued",
	})
	response := fmt.Sprintf(`{"schema_version":"1.0","task_type":"schedule_recommendation","observation_id":"%s","action":"RECOMMEND_NODE_ORDER","candidate_refs":["ref_aaaaaaaaaaaaaaaa","ref_bbbbbbbbbbbbbbbb"],"confidence":0.8,"abstain":false,"reason_summary":"两个节点均开放","evidence_refs":["ev_abcdefghijklmnopqrst"],"risk_flags":[],"requested_observations":[]}`, obsID)
	provider := MockProvider([]string{response}, nil)
	sup := NewSupervisor(st, provider, NewRedactor([]byte("key")), ModeShadow, "mock-model", time.Second)
	if err := sup.processDue(context.Background()); err != nil {
		t.Fatalf("processDue: %v", err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.requests[0].State != "succeeded" || st.requests[0].ErrorCode != "" {
		t.Fatalf("request=%+v, want succeeded without error", st.requests[0])
	}
	if len(st.advisories) != 1 || st.advisories[0].Action != "RECOMMEND_NODE_ORDER" ||
		len(st.advisories[0].CandidateRefs) != 2 {
		t.Fatalf("advisories=%+v", st.advisories)
	}
	if len(st.outcomes) != 1 || st.outcomes[0].Decision != "shown" {
		t.Fatalf("outcomes=%+v", st.outcomes)
	}
}

// TestSupervisorExpiresOverdueQueuedRequests guards suggestion #4: queued
// requests whose deadline passed (worker downtime, provider outage) must
// reach a terminal superseded state instead of lingering forever.
func TestSupervisorExpiresOverdueQueuedRequests(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	_, _ = st.InsertAIAdvisoryRequest(context.Background(), AIAdvisoryRequestLike{
		TaskType: string(TaskMonitoringInspect), SchemaVersion: SchemaVersion,
		PromptVersion: PromptVersion, ModelID: "mock-model",
		DedupKey: "stale", DeadlineAt: time.Now().Add(-time.Minute), State: "queued",
	})
	_, _ = st.InsertAIAdvisoryRequest(context.Background(), AIAdvisoryRequestLike{
		TaskType: string(TaskMonitoringInspect), SchemaVersion: SchemaVersion,
		PromptVersion: PromptVersion, ModelID: "mock-model",
		DedupKey: "fresh", DeadlineAt: time.Now().Add(time.Minute), State: "queued",
	})
	provider := MockProvider([]string{`{"schema_version":"9.9"}`}, nil)
	sup := NewSupervisor(st, provider, NewRedactor([]byte("key")), ModeShadow, "mock-model", time.Second)
	if err := sup.processDue(context.Background()); err != nil {
		t.Fatalf("processDue: %v", err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.requests[0].State != "superseded" || st.requests[0].ErrorCode != "deadline_passed" {
		t.Fatalf("overdue request=%+v, want superseded/deadline_passed", st.requests[0])
	}
	if st.requests[1].State == "superseded" {
		t.Fatalf("fresh request must not be expired: %+v", st.requests[1])
	}
}

// fakeAdopter records adoption attempts for decision-④ gate tests.
type fakeAdopter struct {
	calls  int
	result AdoptionResult
	err    error
}

func (f *fakeAdopter) Adopt(_ context.Context, _ AIAdvisoryRequestLike, _ *Advisory, _ int64) (AdoptionResult, error) {
	f.calls++
	if f.err != nil {
		return AdoptionResult{}, f.err
	}
	return f.result, nil
}

func enqueueAdoptableRequest(st *fakeStore, task TaskType, obsJSON []byte, dedup string) {
	_, _ = st.InsertAIAdvisoryRequest(context.Background(), AIAdvisoryRequestLike{
		TaskType: string(task), SchemaVersion: SchemaVersion,
		PromptVersion: PromptVersion, ModelID: "mock-model",
		ObservationDigest: []byte("d"), ObservationJSON: obsJSON,
		DedupKey: dedup, DeadlineAt: time.Now().Add(time.Minute), State: "queued",
	})
}

// TestSupervisorAutoLowRiskAdoptsLowRiskAdvisory guards decision ④: in
// auto_low_risk mode a confident, non-abstaining, validator-whitelisted
// advisory is executed by the adopter and audited as auto_adopted/system with
// a deterministic effect reference.
func TestSupervisorAutoLowRiskAdoptsLowRiskAdvisory(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	obsID := "obs_test1234567890"
	obsJSON := buildTestObservation(obsID)
	enqueueAdoptableRequest(st, TaskMonitoringInspect, obsJSON, "adopt_ok")
	response := fmt.Sprintf(`{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"%s","action":"NO_ACTION","candidate_refs":[],"confidence":0.95,"abstain":false,"reason_summary":"一切正常","evidence_refs":[],"risk_flags":[],"requested_observations":[]}`, obsID)
	provider := MockProvider([]string{response}, nil)
	adopter := &fakeAdopter{result: AdoptionResult{EffectRef: "inspection_summary:cluster", ObservedOutcome: "applied"}}
	sup := NewSupervisor(st, provider, NewRedactor([]byte("key")), ModeAutoLowRisk, "mock-model", time.Second).
		WithAdopter(adopter, 0.8)
	if err := sup.processDue(context.Background()); err != nil {
		t.Fatalf("processDue: %v", err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.requests[0].State != "succeeded" {
		t.Fatalf("request=%+v", st.requests[0])
	}
	if adopter.calls != 1 {
		t.Fatalf("adopter calls=%d", adopter.calls)
	}
	if len(st.outcomes) != 1 || st.outcomes[0].Decision != "auto_adopted" ||
		st.outcomes[0].ActorType != "system" ||
		st.outcomes[0].DeterministicRef != "inspection_summary:cluster" ||
		st.outcomes[0].ObservedOutcome != "applied" {
		t.Fatalf("outcome=%+v, want auto_adopted/system with deterministic ref", st.outcomes)
	}
}

// TestSupervisorAdoptionModeGate: shadow and advisory modes must NEVER call
// the adopter even when it is wired; every advisory stays shown. Auto-adoption
// exists only in auto_low_risk mode.
func TestSupervisorAdoptionModeGate(t *testing.T) {
	for _, mode := range []Mode{ModeShadow, ModeAdvisory} {
		t.Run(string(mode), func(t *testing.T) {
			st := &fakeStore{}
			obsID := "obs_test1234567890"
			obsJSON := buildTestObservation(obsID)
			enqueueAdoptableRequest(st, TaskMonitoringInspect, obsJSON, "gate_"+string(mode))
			response := fmt.Sprintf(`{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"%s","action":"NO_ACTION","candidate_refs":[],"confidence":0.95,"abstain":false,"reason_summary":"ok","evidence_refs":[],"risk_flags":[],"requested_observations":[]}`, obsID)
			provider := MockProvider([]string{response}, nil)
			adopter := &fakeAdopter{result: AdoptionResult{EffectRef: "x"}}
			sup := NewSupervisor(st, provider, NewRedactor([]byte("key")), mode, "mock-model", time.Second).
				WithAdopter(adopter, 0.8)
			if err := sup.processDue(context.Background()); err != nil {
				t.Fatalf("processDue: %v", err)
			}
			st.mu.Lock()
			defer st.mu.Unlock()
			if adopter.calls != 0 {
				t.Fatalf("adopter must not run in %s mode, calls=%d", mode, adopter.calls)
			}
			if len(st.outcomes) != 1 || st.outcomes[0].Decision != "shown" || st.outcomes[0].ActorType != "none" {
				t.Fatalf("outcome=%+v, want shown/none in %s mode", st.outcomes, mode)
			}
		})
	}
}

// TestSupervisorAdoptionHardGates: even in auto_low_risk mode with a wired
// adopter, adoption is refused for (a) abstaining advisories, (b) confidence
// below the configured floor, (c) disaster/conflict/import task families,
// (d) risk flags demanding human confirmation.
func TestSupervisorAdoptionHardGates(t *testing.T) {
	obsID := "obs_test1234567890"
	obsJSON := buildTestObservation(obsID)
	disasterObs := []byte(`{"observation_id":"` + obsID + `","evidence_catalog":[],"mode_events":[]}`)
	cases := []struct {
		name     string
		task     TaskType
		obs      []byte
		response string
	}{
		{"abstain", TaskMonitoringInspect, obsJSON, fmt.Sprintf(`{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"%s","action":"NO_ACTION","candidate_refs":[],"confidence":0.95,"abstain":true,"reason_summary":"x","evidence_refs":[],"risk_flags":[],"requested_observations":[]}`, obsID)},
		{"low_confidence", TaskMonitoringInspect, obsJSON, fmt.Sprintf(`{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"%s","action":"NO_ACTION","candidate_refs":[],"confidence":0.6,"abstain":false,"reason_summary":"x","evidence_refs":[],"risk_flags":[],"requested_observations":[]}`, obsID)},
		{"disaster_task", TaskDisasterReview, disasterObs, fmt.Sprintf(`{"schema_version":"1.0","task_type":"disaster_review","observation_id":"%s","action":"NO_ACTION","candidate_refs":[],"confidence":0.95,"abstain":false,"reason_summary":"x","evidence_refs":[],"risk_flags":[],"requested_observations":[]}`, obsID)},
		{"human_confirm_flag", TaskMonitoringInspect, obsJSON, fmt.Sprintf(`{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"%s","action":"NO_ACTION","candidate_refs":[],"confidence":0.95,"abstain":false,"reason_summary":"x","evidence_refs":[],"risk_flags":["DATA_LOSS_RISK"],"requested_observations":[]}`, obsID)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &fakeStore{}
			enqueueAdoptableRequest(st, tc.task, tc.obs, "gate_"+tc.name)
			provider := MockProvider([]string{tc.response}, nil)
			adopter := &fakeAdopter{result: AdoptionResult{EffectRef: "x"}}
			sup := NewSupervisor(st, provider, NewRedactor([]byte("key")), ModeAutoLowRisk, "mock-model", time.Second).
				WithAdopter(adopter, 0.8)
			if err := sup.processDue(context.Background()); err != nil {
				t.Fatalf("processDue: %v", err)
			}
			st.mu.Lock()
			defer st.mu.Unlock()
			if adopter.calls != 0 {
				t.Fatalf("adopter must be gated (%s), calls=%d", tc.name, adopter.calls)
			}
			if len(st.outcomes) != 1 || st.outcomes[0].Decision != "shown" {
				t.Fatalf("outcome=%+v, want shown for %s", st.outcomes, tc.name)
			}
		})
	}
}

// TestSupervisorAdoptionFailureNeverFailsRequest: an executor error (or a
// not-executable action) keeps the request succeeded and the advisory shown;
// AI adoption problems can never degrade the advisory pipeline itself.
func TestSupervisorAdoptionFailureNeverFailsRequest(t *testing.T) {
	t.Parallel()
	obsID := "obs_test1234567890"
	obsJSON := buildTestObservation(obsID)
	response := fmt.Sprintf(`{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"%s","action":"NO_ACTION","candidate_refs":[],"confidence":0.95,"abstain":false,"reason_summary":"ok","evidence_refs":[],"risk_flags":[],"requested_observations":[]}`, obsID)

	st1 := &fakeStore{}
	enqueueAdoptableRequest(st1, TaskMonitoringInspect, obsJSON, "adopt_notexec")
	sup1 := NewSupervisor(st1, MockProvider([]string{response}, nil), NewRedactor([]byte("key")), ModeAutoLowRisk, "mock-model", time.Second).
		WithAdopter(&fakeAdopter{err: ErrAdoptionNotExecutable}, 0.8)
	if err := sup1.processDue(context.Background()); err != nil {
		t.Fatalf("processDue: %v", err)
	}
	st1.mu.Lock()
	if st1.requests[0].State != "succeeded" || len(st1.outcomes) != 1 ||
		st1.outcomes[0].Decision != "shown" || st1.outcomes[0].ObservedOutcome != "no_executor" {
		st1.mu.Unlock()
		t.Fatalf("not-executable case: request=%+v outcomes=%+v", st1.requests, st1.outcomes)
	}
	st1.mu.Unlock()

	st2 := &fakeStore{}
	enqueueAdoptableRequest(st2, TaskMonitoringInspect, obsJSON, "adopt_err")
	sup2 := NewSupervisor(st2, MockProvider([]string{response}, nil), NewRedactor([]byte("key")), ModeAutoLowRisk, "mock-model", time.Second).
		WithAdopter(&fakeAdopter{err: fmt.Errorf("boom")}, 0.8)
	if err := sup2.processDue(context.Background()); err != nil {
		t.Fatalf("processDue: %v", err)
	}
	st2.mu.Lock()
	defer st2.mu.Unlock()
	if st2.requests[0].State != "succeeded" || len(st2.outcomes) != 1 ||
		st2.outcomes[0].Decision != "shown" || st2.outcomes[0].ObservedOutcome != "adoption_error" {
		t.Fatalf("error case: request=%+v outcomes=%+v", st2.requests, st2.outcomes)
	}
}
