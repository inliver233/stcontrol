package ai

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRedactorRefsAreStablePerObservationAndUncorrelatable(t *testing.T) {
	t.Parallel()
	r := NewRedactor([]byte("master-secret"))
	a1 := r.Ref("ev", "salt-1", "node-42")
	a2 := r.Ref("ev", "salt-1", "node-42")
	if a1 != a2 {
		t.Fatalf("same salt+id must derive same ref: %q vs %q", a1, a2)
	}
	b := r.Ref("ev", "salt-2", "node-42")
	if a1 == b {
		t.Fatal("different salt must derive different ref")
	}
	if !ValidRef(a1) {
		t.Fatalf("ref %q must be valid", a1)
	}
}

func TestContainsSecretCatchesKeysTokensAndPaths(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		"api_key=sk-abc123secretvalue",
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
		"secret: hunter2password123",
		"/home/alice/.ssh/id_rsa",
		"C:\\Users\\bob\\AppData\\secret",
		"https://internal.example/data",
	} {
		if hit, _ := ContainsSecret(text); !hit {
			t.Errorf("secret pattern not detected in %q", text)
		}
	}
	for _, text := range []string{
		"节点正常，无异常",
		"workflow failed with code timeout",
		"disk 72% used",
	} {
		if hit, _ := ContainsSecret(text); hit {
			t.Errorf("false positive on %q", text)
		}
	}
}

func TestSanitizeTextRedactsAndTruncates(t *testing.T) {
	t.Parallel()
	out := SanitizeText("token=abcdefghijklmnopqrstuvwxyz123456 more text")
	if strings.Contains(out, "abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("sanitize leaked token: %q", out)
	}
	long := strings.Repeat("字", 600)
	out = SanitizeText(long)
	if len(out) > 520 {
		t.Fatalf("sanitize did not truncate: %d", len(out))
	}
}

func TestValidateAdvisoryAcceptsValidResponse(t *testing.T) {
	t.Parallel()
	evidence := map[string]bool{"ev_abcdefghijklmnopqrst": true}
	raw := `{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"obs_test1234567890","action":"NO_ACTION","candidate_refs":[],"confidence":0.95,"abstain":false,"reason_summary":"一切正常","evidence_refs":["ev_abcdefghijklmnopqrst"],"risk_flags":[],"requested_observations":[]}`
	adv, err := ValidateAdvisory(raw, TaskMonitoringInspect, "obs_test1234567890", evidence, nil)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if adv.Action != "NO_ACTION" || adv.Confidence != 0.95 {
		t.Fatalf("advisory=%+v", adv)
	}
}

func TestValidateAdvisoryRejectsForgedEvidence(t *testing.T) {
	t.Parallel()
	raw := `{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"obs_test1234567890","action":"EXPLAIN_ALERT","candidate_refs":[],"confidence":0.9,"abstain":false,"reason_summary":"x","evidence_refs":["ev_fakefakefakefakefake"],"risk_flags":[],"requested_observations":[]}`
	_, err := ValidateAdvisory(raw, TaskMonitoringInspect, "obs_test1234567890", map[string]bool{}, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported_evidence") {
		t.Fatalf("expected unsupported_evidence, got %v", err)
	}
}

func TestValidateAdvisoryRejectsDisallowedAction(t *testing.T) {
	t.Parallel()
	raw := `{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"obs_test1234567890","action":"RECOMMEND_NODE_ORDER","candidate_refs":[],"confidence":0.9,"abstain":false,"reason_summary":"x","evidence_refs":[],"risk_flags":[],"requested_observations":[]}`
	_, err := ValidateAdvisory(raw, TaskMonitoringInspect, "obs_test1234567890", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "action_not_allowed") {
		t.Fatalf("expected action_not_allowed, got %v", err)
	}
}

func TestValidateAdvisoryRejectsSchemaTaskAndObservationMismatch(t *testing.T) {
	t.Parallel()
	raw := `{"schema_version":"9.9","task_type":"monitoring_inspection","observation_id":"obs_test1234567890","action":"NO_ACTION","candidate_refs":[],"confidence":0.9,"abstain":false,"reason_summary":"x","evidence_refs":[],"risk_flags":[],"requested_observations":[]}`
	if _, err := ValidateAdvisory(raw, TaskMonitoringInspect, "obs_test1234567890", nil, nil); err == nil {
		t.Fatal("schema mismatch accepted")
	}
	raw = `{"schema_version":"1.0","task_type":"anomaly_attribution","observation_id":"obs_test1234567890","action":"NO_ACTION","candidate_refs":[],"confidence":0.9,"abstain":false,"reason_summary":"x","evidence_refs":[],"risk_flags":[],"requested_observations":[]}`
	if _, err := ValidateAdvisory(raw, TaskMonitoringInspect, "obs_test1234567890", nil, nil); err == nil {
		t.Fatal("task mismatch accepted")
	}
	raw = `{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"obs_other0000000000","action":"NO_ACTION","candidate_refs":[],"confidence":0.9,"abstain":false,"reason_summary":"x","evidence_refs":[],"risk_flags":[],"requested_observations":[]}`
	if _, err := ValidateAdvisory(raw, TaskMonitoringInspect, "obs_test1234567890", nil, nil); err == nil {
		t.Fatal("observation mismatch accepted")
	}
}

func TestValidateAdvisoryRejectsSecretInSummary(t *testing.T) {
	t.Parallel()
	raw := `{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"obs_test1234567890","action":"NO_ACTION","candidate_refs":[],"confidence":0.9,"abstain":false,"reason_summary":"password=supersecretvalue123","evidence_refs":[],"risk_flags":[],"requested_observations":[]}`
	_, err := ValidateAdvisory(raw, TaskMonitoringInspect, "obs_test1234567890", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "secret_leak") {
		t.Fatalf("expected secret_leak, got %v", err)
	}
}

func TestHumanConfirmAndAutoAdoptBoundaries(t *testing.T) {
	t.Parallel()
	low := &Advisory{Action: string(ActionExplainAlert), RiskFlags: []string{}}
	if !AutoAdoptable(TaskAnomalyAttribution, low) {
		t.Fatal("EXPLAIN_ALERT should be auto-adoptable")
	}
	risky := &Advisory{Action: string(ActionRecommendMergePreview), RiskFlags: []string{}}
	if AutoAdoptable(TaskConflictReview, risky) {
		t.Fatal("conflict merge must never auto-adopt")
	}
	if !HumanConfirmRequired(TaskDisasterReview, low) {
		t.Fatal("disaster review always requires human confirmation")
	}
	flagged := &Advisory{Action: string(ActionNoAction), RiskFlags: []string{string(RiskDataLoss)}}
	if !HumanConfirmRequired(TaskMonitoringInspect, flagged) {
		t.Fatal("data-loss flag requires human confirmation")
	}
	// An abstaining suggestion carries nothing to apply, regardless of the
	// otherwise-low-risk action.
	abstainer := &Advisory{Action: string(ActionExplainAlert), Abstain: true}
	if AutoAdoptable(TaskAnomalyAttribution, abstainer) {
		t.Fatal("abstaining advisories must never auto-adopt")
	}
}

func TestBuildObservationProducesDigestAndCatalogs(t *testing.T) {
	t.Parallel()
	r := NewRedactor([]byte("key"))
	obsID := ObservationID()
	nodes := []NodeObservation{
		{Ref: r.Ref("node", obsID, "1"), Role: "compute", Connectivity: "online", Capacity: "open", Compatibility: "compatible", EligibleForNew: true},
		{Ref: r.Ref("node", obsID, "2"), Role: "storage", Connectivity: "offline", Capacity: "unknown", Compatibility: "unknown", EligibleAsBackup: false},
	}
	alerts := []AlertObservation{{Ref: r.Ref("alert", obsID, "a1"), Severity: "warning", Category: "capacity", AgeSec: 120}}
	workflows := []WorkflowObservation{{Ref: r.Ref("wf", obsID, "w1"), Type: "backup", State: "running", Attempt: 2, AgeSec: 300}}
	raw, evidence, candidates, digest, err := BuildObservation(r, obsID, time.Now(), nodes, alerts, workflows, ProtectionObservation{TotalUsers: 3, ProtectedCount: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) == 0 || len(candidates) != 1 {
		t.Fatalf("evidence=%d candidates=%d", len(evidence), len(candidates))
	}
	if len(digest) != sha256.Size*2 {
		t.Fatalf("digest=%q", digest)
	}
	var decoded Observation
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ObservationID != obsID || len(decoded.Nodes) != 2 {
		t.Fatalf("decoded=%+v", decoded)
	}
}

func TestMockProviderRoundRobin(t *testing.T) {
	t.Parallel()
	p := MockProvider([]string{"first", "second"}, nil)
	got1, err := p.Complete(context.Background(), CallParams{})
	if err != nil || got1 != "first" {
		t.Fatalf("first=%q err=%v", got1, err)
	}
	got2, _ := p.Complete(context.Background(), CallParams{})
	if got2 != "second" {
		t.Fatalf("second=%q", got2)
	}
	got3, _ := p.Complete(context.Background(), CallParams{})
	if got3 != "second" {
		t.Fatalf("repeat=%q", got3)
	}
}

func TestValidateAdvisoryRejectsUnknownRiskFlagAndRequestedObservation(t *testing.T) {
	t.Parallel()
	raw := `{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"obs_test1234567890","action":"NO_ACTION","candidate_refs":[],"confidence":0.9,"abstain":false,"reason_summary":"x","evidence_refs":[],"risk_flags":["TOTALLY_MADE_UP_FLAG"],"requested_observations":[]}`
	if _, err := ValidateAdvisory(raw, TaskMonitoringInspect, "obs_test1234567890", nil, nil); err == nil ||
		!strings.Contains(err.Error(), "invalid_risk_flag") {
		t.Fatalf("expected invalid_risk_flag, got %v", err)
	}
	raw = `{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"obs_test1234567890","action":"NO_ACTION","candidate_refs":[],"confidence":0.9,"abstain":false,"reason_summary":"x","evidence_refs":[],"risk_flags":["STALE_DATA"],"requested_observations":["FREE_STUFF_PLEASE"]}`
	if _, err := ValidateAdvisory(raw, TaskMonitoringInspect, "obs_test1234567890", nil, nil); err == nil ||
		!strings.Contains(err.Error(), "invalid_requested_observation") {
		t.Fatalf("expected invalid_requested_observation, got %v", err)
	}
	// The full §6.2 enumerations stay accepted.
	raw = `{"schema_version":"1.0","task_type":"monitoring_inspection","observation_id":"obs_test1234567890","action":"NO_ACTION","candidate_refs":[],"confidence":0.9,"abstain":false,"reason_summary":"x","evidence_refs":[],"risk_flags":["STALE_DATA","HUMAN_CONFIRMATION_REQUIRED"],"requested_observations":["FRESH_NODE_METRICS","OPERATOR_CONTEXT"]}`
	if _, err := ValidateAdvisory(raw, TaskMonitoringInspect, "obs_test1234567890", nil, nil); err != nil {
		t.Fatalf("valid enumeration rejected: %v", err)
	}
}

func TestValidateAdvisoryBoundedSchemaAndReferenceMatrix(t *testing.T) {
	t.Parallel()
	const observationID = "obs_test1234567890"
	const evidenceRef = "ev_abcdefghijklmnopqrst"
	const candidateRef = "ref_abcdefghijklmnopqrst"
	encode := func(advisory Advisory) string {
		t.Helper()
		payload, err := json.Marshal(advisory)
		if err != nil {
			t.Fatal(err)
		}
		return string(payload)
	}
	base := Advisory{
		SchemaVersion: SchemaVersion, TaskType: string(TaskMonitoringInspect),
		ObservationID: observationID, Action: string(ActionNoAction),
		Confidence: 0.5, ReasonSummary: "bounded result",
		CandidateRefs: []string{}, EvidenceRefs: []string{}, RiskFlags: []string{}, RequestedObservations: []string{},
	}
	repeat := func(value string, count int) []string {
		out := make([]string, count)
		for index := range out {
			out[index] = value
		}
		return out
	}
	testCases := []struct {
		name                 string
		raw                  string
		task                 TaskType
		code                 string
		evidence, candidates map[string]bool
	}{
		{name: "empty", raw: "", task: TaskMonitoringInspect, code: "empty_response"},
		{name: "oversized", raw: strings.Repeat("x", maxAIResponseBytes+1), task: TaskMonitoringInspect, code: "oversized_response"},
		{name: "invalid utf8", raw: string([]byte{0xff}), task: TaskMonitoringInspect, code: "invalid_utf8"},
		{name: "invalid json", raw: `{`, task: TaskMonitoringInspect, code: "invalid_json"},
		{name: "unknown field", raw: strings.TrimSuffix(encode(base), "}") + `,"unknown":true}`, task: TaskMonitoringInspect, code: "invalid_json"},
		{name: "too many candidates", raw: func() string { v := base; v.CandidateRefs = repeat(candidateRef, 21); return encode(v) }(), task: TaskMonitoringInspect, code: "too_many_candidates"},
		{name: "too many evidence", raw: func() string { v := base; v.EvidenceRefs = repeat(evidenceRef, 13); return encode(v) }(), task: TaskMonitoringInspect, code: "too_many_evidence"},
		{name: "too many risks", raw: func() string { v := base; v.RiskFlags = repeat(string(RiskStaleData), 11); return encode(v) }(), task: TaskMonitoringInspect, code: "too_many_risks"},
		{name: "too many requests", raw: func() string {
			v := base
			v.RequestedObservations = repeat(string(ReqOperatorContext), 9)
			return encode(v)
		}(), task: TaskMonitoringInspect, code: "too_many_requests"},
		{name: "reason too long", raw: func() string { v := base; v.ReasonSummary = strings.Repeat("界", 301); return encode(v) }(), task: TaskMonitoringInspect, code: "reason_too_long"},
		{name: "negative confidence", raw: func() string { v := base; v.Confidence = -0.1; return encode(v) }(), task: TaskMonitoringInspect, code: "confidence_out_of_range"},
		{name: "high confidence", raw: func() string { v := base; v.Confidence = 1.1; return encode(v) }(), task: TaskMonitoringInspect, code: "confidence_out_of_range"},
		{name: "malformed evidence", raw: func() string { v := base; v.EvidenceRefs = []string{"bad"}; return encode(v) }(), task: TaskMonitoringInspect, code: "malformed_evidence_ref"},
		{name: "duplicate evidence", raw: func() string { v := base; v.EvidenceRefs = []string{evidenceRef, evidenceRef}; return encode(v) }(), task: TaskMonitoringInspect, code: "duplicate_evidence_ref", evidence: map[string]bool{evidenceRef: true}},
		{name: "empty ordering", raw: func() string {
			v := base
			v.TaskType = string(TaskScheduleRecommend)
			v.Action = string(ActionRecommendNodeOrder)
			return encode(v)
		}(), task: TaskScheduleRecommend, code: "empty_candidates"},
		{name: "malformed candidate", raw: func() string {
			v := base
			v.TaskType = string(TaskScheduleRecommend)
			v.Action = string(ActionRecommendNodeOrder)
			v.CandidateRefs = []string{"bad"}
			return encode(v)
		}(), task: TaskScheduleRecommend, code: "malformed_candidate_ref"},
		{name: "unsupported candidate", raw: func() string {
			v := base
			v.TaskType = string(TaskScheduleRecommend)
			v.Action = string(ActionRecommendNodeOrder)
			v.CandidateRefs = []string{candidateRef}
			return encode(v)
		}(), task: TaskScheduleRecommend, code: "unsupported_candidate"},
		{name: "duplicate candidate", raw: func() string {
			v := base
			v.TaskType = string(TaskScheduleRecommend)
			v.Action = string(ActionRecommendNodeOrder)
			v.CandidateRefs = []string{candidateRef, candidateRef}
			return encode(v)
		}(), task: TaskScheduleRecommend, code: "duplicate_candidate_ref", candidates: map[string]bool{candidateRef: true}},
		{name: "abstain conflict", raw: func() string { v := base; v.Abstain = true; v.Action = string(ActionExplainAlert); return encode(v) }(), task: TaskMonitoringInspect, code: "abstain_action_conflict"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := ValidateAdvisory(testCase.raw, testCase.task, observationID, testCase.evidence, testCase.candidates)
			if err == nil || !strings.Contains(err.Error(), testCase.code) {
				t.Fatalf("error=%v, want code %q", err, testCase.code)
			}
		})
	}

	fenced := "```json\n" + encode(base) + "\n```"
	if _, err := ValidateAdvisory(fenced, TaskMonitoringInspect, observationID, nil, nil); err != nil {
		t.Fatalf("single JSON code fence rejected: %v", err)
	}
	ordering := base
	ordering.TaskType = string(TaskScheduleRecommend)
	ordering.Action = string(ActionRecommendNodeOrder)
	ordering.CandidateRefs = []string{candidateRef}
	if _, err := ValidateAdvisory(encode(ordering), TaskScheduleRecommend, observationID, nil, map[string]bool{candidateRef: true}); err != nil {
		t.Fatalf("valid ordering rejected: %v", err)
	}
}
