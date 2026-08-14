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
