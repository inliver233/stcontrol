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
