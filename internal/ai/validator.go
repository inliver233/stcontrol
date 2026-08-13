package ai

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// validator.go implements the post-provider validation chain
// (ai接入优化方案详细.md §5.4). A model response must pass every step before it
// becomes an advisory; any failure discards the response and falls back.

// ValidationError carries a stable code for audit (rejected outcome).
type ValidationError struct {
	Code string
	Msg  string
}

func (e *ValidationError) Error() string { return e.Code + ": " + e.Msg }

func validationErrorf(code, format string, args ...any) error {
	return &ValidationError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// ValidateAdvisory checks a raw model response against the unified schema and
// the per-task semantic rules. observationID/task must be the exact values
// that were sent; evidenceCatalog is the set of evidence refs the observation
// contained; candidateCatalog is the set of eligible candidate refs.
func ValidateAdvisory(
	raw string,
	task TaskType,
	observationID string,
	evidenceCatalog map[string]bool,
	candidateCatalog map[string]bool,
) (*Advisory, error) {
	if raw == "" {
		return nil, validationErrorf("empty_response", "provider returned empty response")
	}
	if len(raw) > maxAIResponseBytes {
		return nil, validationErrorf("oversized_response", "response exceeds %d bytes", maxAIResponseBytes)
	}
	if !utf8.ValidString(raw) {
		return nil, validationErrorf("invalid_utf8", "response is not valid UTF-8")
	}
	// Strip one optional code fence if the model wrapped JSON despite the rule.
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "```") {
		first := strings.Index(trimmed, "\n")
		last := strings.LastIndex(trimmed, "```")
		if first > 0 && last > first {
			trimmed = strings.TrimSpace(trimmed[first+1 : last])
		}
	}
	var adv Advisory
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&adv); err != nil {
		return nil, validationErrorf("invalid_json", "response is not valid JSON: %v", err)
	}
	if adv.SchemaVersion != SchemaVersion {
		return nil, validationErrorf("schema_mismatch", "schema_version %q != %q", adv.SchemaVersion, SchemaVersion)
	}
	if adv.TaskType != string(task) {
		return nil, validationErrorf("task_mismatch", "task_type %q != %q", adv.TaskType, task)
	}
	if adv.ObservationID != observationID {
		return nil, validationErrorf("observation_mismatch", "observation_id %q != %q", adv.ObservationID, observationID)
	}
	action := Action(adv.Action)
	if !allowedActions[task][action] {
		return nil, validationErrorf("action_not_allowed", "action %q not allowed for task %q", adv.Action, task)
	}
	if len(adv.CandidateRefs) > 20 {
		return nil, validationErrorf("too_many_candidates", "candidate_refs exceeds 20")
	}
	if len(adv.EvidenceRefs) > 12 {
		return nil, validationErrorf("too_many_evidence", "evidence_refs exceeds 12")
	}
	if len(adv.RiskFlags) > 10 {
		return nil, validationErrorf("too_many_risks", "risk_flags exceeds 10")
	}
	if len(adv.RequestedObservations) > 8 {
		return nil, validationErrorf("too_many_requests", "requested_observations exceeds 8")
	}
	if utf8.RuneCountInString(adv.ReasonSummary) > 300 {
		return nil, validationErrorf("reason_too_long", "reason_summary exceeds 300 chars")
	}
	if adv.Confidence < 0 || adv.Confidence > 1 {
		return nil, validationErrorf("confidence_out_of_range", "confidence %v out of [0,1]", adv.Confidence)
	}
	// Evidence refs must exist in the observation's catalog.
	seenEvidence := map[string]bool{}
	for _, ref := range adv.EvidenceRefs {
		if !ValidRef(ref) {
			return nil, validationErrorf("malformed_evidence_ref", "evidence ref %q malformed", ref)
		}
		if !evidenceCatalog[ref] {
			return nil, validationErrorf("unsupported_evidence", "evidence ref %q not in observation", ref)
		}
		if seenEvidence[ref] {
			return nil, validationErrorf("duplicate_evidence_ref", "evidence ref %q duplicated", ref)
		}
		seenEvidence[ref] = true
	}
	// Candidate refs must exist in the eligible candidate catalog when the
	// action orders anything.
	if action == ActionRecommendNodeOrder || action == ActionRecommendBackupOrder ||
		action == ActionRecommendRestoreOrder || action == ActionRecommendRecoveryOrder {
		if len(adv.CandidateRefs) == 0 {
			return nil, validationErrorf("empty_candidates", "ordering action requires candidate_refs")
		}
		seenCands := map[string]bool{}
		for _, ref := range adv.CandidateRefs {
			if !ValidRef(ref) {
				return nil, validationErrorf("malformed_candidate_ref", "candidate ref %q malformed", ref)
			}
			if !candidateCatalog[ref] {
				return nil, validationErrorf("unsupported_candidate", "candidate ref %q not eligible", ref)
			}
			if seenCands[ref] {
				return nil, validationErrorf("duplicate_candidate_ref", "candidate ref %q duplicated", ref)
			}
			seenCands[ref] = true
		}
	}
	// Secret scan: the summary must not contain credential patterns.
	if hit, _ := ContainsSecret(adv.ReasonSummary); hit {
		return nil, validationErrorf("secret_leak", "reason_summary matched secret pattern")
	}
	// Abstain requires NO_ACTION or REQUEST_MORE_OBSERVATION.
	if adv.Abstain && action != ActionNoAction && action != ActionRequestMoreObservation {
		return nil, validationErrorf("abstain_action_conflict", "abstain=true requires NO_ACTION or REQUEST_MORE_OBSERVATION")
	}
	return &adv, nil
}

// HumanConfirmRequired reports whether an advisory's risk flags or action
// demand explicit human confirmation before any adoption (always true for
// disaster/conflict/identity actions regardless of model claims).
func HumanConfirmRequired(task TaskType, adv *Advisory) bool {
	if task == TaskDisasterReview || task == TaskConflictReview || task == TaskImportReview {
		return true
	}
	for _, flag := range adv.RiskFlags {
		switch RiskFlag(flag) {
		case RiskDataLoss, RiskIdentity, RiskHumanConfirmation, RiskPromptInjection:
			return true
		}
	}
	switch Action(adv.Action) {
	case ActionRecommendConfirmation, ActionRecommendReview, ActionRecommendHold,
		ActionRecommendMergePreview, ActionRecommendUseSource, ActionRecommendPreserveBoth:
		return true
	}
	return false
}

// AutoAdoptable reports whether a task/action may be auto-adopted in
// auto_low_risk mode (only reversible, non-destructive suggestions).
func AutoAdoptable(task TaskType, adv *Advisory) bool {
	if task == TaskDisasterReview || task == TaskConflictReview || task == TaskImportReview ||
		task == TaskRecoveryPlan {
		return false
	}
	switch Action(adv.Action) {
	case ActionExplainAlert, ActionNoAction:
		return true
	case ActionRecommendNodeOrder, ActionRecommendBackupOrder:
		return true
	default:
		return false
	}
}
