package ai

// schemas.go defines the fixed, versioned task/schema vocabulary for the AI
// 监管层 (ai接入优化方案详细.md §6). Versions never change in place: bump the
// version and add a new validator/prompt pair instead.

// SchemaVersion is the current advisory output schema version.
const SchemaVersion = "1.0"

// PromptVersion is the current system+task prompt pair version.
const PromptVersion = "2026-08-14.1"

// TaskType enumerates advisory task kinds.
type TaskType string

const (
	TaskConflictReview     TaskType = "conflict_review"
	TaskDisasterReview     TaskType = "disaster_review"
	TaskRecoveryPlan       TaskType = "recovery_plan"
	TaskScheduleRecommend  TaskType = "schedule_recommendation"
	TaskAnomalyAttribution TaskType = "anomaly_attribution"
	TaskMonitoringInspect  TaskType = "monitoring_inspection"
	TaskImportReview       TaskType = "import_review"
)

// ParseTaskType validates a configured task type.
func ParseTaskType(value string) (TaskType, error) {
	switch TaskType(value) {
	case TaskConflictReview, TaskDisasterReview, TaskRecoveryPlan,
		TaskScheduleRecommend, TaskAnomalyAttribution, TaskMonitoringInspect,
		TaskImportReview:
		return TaskType(value), nil
	default:
		return "", errUnknownTask(value)
	}
}

// Action enumerates the allowed advisory action types (§4.2). These are
// suggestion kinds, never execution commands.
type Action string

const (
	ActionNoAction               Action = "NO_ACTION"
	ActionExplainAlert           Action = "EXPLAIN_ALERT"
	ActionRequestMoreObservation Action = "REQUEST_MORE_OBSERVATION"
	ActionRecommendNodeOrder     Action = "RECOMMEND_NODE_ORDER"
	ActionRecommendBackupOrder   Action = "RECOMMEND_BACKUP_TARGET_ORDER"
	ActionRecommendRestoreOrder  Action = "RECOMMEND_RESTORE_TARGET_ORDER"
	ActionRecommendRecoveryOrder Action = "RECOMMEND_RECOVERY_STEP_ORDER"
	ActionRecommendImportProof   Action = "RECOMMEND_IMPORT_PROOF_METHOD"
	ActionRecommendHold          Action = "RECOMMEND_HOLD_AND_OBSERVE"
	ActionRecommendReview        Action = "RECOMMEND_OPERATOR_REVIEW"
	ActionRecommendConfirmation  Action = "RECOMMEND_USER_CONFIRMATION"
	ActionRecommendUseSource     Action = "RECOMMEND_CONFLICT_USE_SOURCE"
	ActionRecommendPreserveBoth  Action = "RECOMMEND_CONFLICT_PRESERVE_BOTH"
	ActionRecommendMergePreview  Action = "RECOMMEND_CONFLICT_MERGE_PREVIEW"
)

// allowedActions maps each task to its action whitelist (§6.3).
var allowedActions = map[TaskType]map[Action]bool{
	TaskMonitoringInspect: {
		ActionNoAction: true, ActionRequestMoreObservation: true,
		ActionExplainAlert: true, ActionRecommendReview: true,
	},
	TaskAnomalyAttribution: {
		ActionNoAction: true, ActionRequestMoreObservation: true,
		ActionExplainAlert: true, ActionRecommendReview: true,
	},
	TaskScheduleRecommend: {
		ActionNoAction: true, ActionRequestMoreObservation: true,
		ActionRecommendNodeOrder: true, ActionRecommendBackupOrder: true,
		ActionRecommendHold: true,
	},
	TaskRecoveryPlan: {
		ActionNoAction: true, ActionRequestMoreObservation: true,
		ActionRecommendRestoreOrder: true, ActionRecommendRecoveryOrder: true,
		ActionRecommendReview: true, ActionRecommendConfirmation: true,
	},
	TaskImportReview: {
		ActionNoAction: true, ActionRequestMoreObservation: true,
		ActionRecommendImportProof: true, ActionRecommendReview: true,
	},
	TaskDisasterReview: {
		ActionNoAction: true, ActionRequestMoreObservation: true,
		ActionRecommendHold: true, ActionRecommendReview: true,
		ActionRecommendConfirmation: true,
	},
	TaskConflictReview: {
		ActionNoAction: true, ActionRequestMoreObservation: true,
		ActionRecommendConfirmation: true, ActionRecommendUseSource: true,
		ActionRecommendPreserveBoth: true, ActionRecommendMergePreview: true,
	},
}

// RiskFlag enumerates advisory risk flags (§6.2).
type RiskFlag string

const (
	RiskStaleData           RiskFlag = "STALE_DATA"
	RiskConflictingSignals  RiskFlag = "CONFLICTING_SIGNALS"
	RiskLowTelemetryQuality RiskFlag = "LOW_TELEMETRY_QUALITY"
	RiskCapacity            RiskFlag = "CAPACITY_RISK"
	RiskDataLoss            RiskFlag = "DATA_LOSS_RISK"
	RiskIdentity            RiskFlag = "IDENTITY_RISK"
	RiskPrivacy             RiskFlag = "PRIVACY_RISK"
	RiskPromptInjection     RiskFlag = "PROMPT_INJECTION_SUSPECTED"
	RiskHumanConfirmation   RiskFlag = "HUMAN_CONFIRMATION_REQUIRED"
)

// RequestedObservation enumerates follow-up observation kinds (§6.2).
type RequestedObservation string

const (
	ReqFreshNodeMetrics    RequestedObservation = "FRESH_NODE_METRICS"
	ReqSessionCounts       RequestedObservation = "SESSION_COUNTS"
	ReqWorkflowStatus      RequestedObservation = "WORKFLOW_STATUS"
	ReqReplicaFreshness    RequestedObservation = "REPLICA_FRESHNESS"
	ReqConflictAggregates  RequestedObservation = "CONFLICT_AGGREGATES"
	ReqCompatibilityStatus RequestedObservation = "COMPATIBILITY_STATUS"
	ReqRegistrationPolicy  RequestedObservation = "REGISTRATION_POLICY_STATUS"
	ReqOperatorContext     RequestedObservation = "OPERATOR_CONTEXT"
)

// Advisory is the validated model output (unified schema §6.2).
type Advisory struct {
	SchemaVersion         string   `json:"schema_version"`
	TaskType              string   `json:"task_type"`
	ObservationID         string   `json:"observation_id"`
	Action                string   `json:"action"`
	CandidateRefs         []string `json:"candidate_refs"`
	Confidence            float64  `json:"confidence"`
	Abstain               bool     `json:"abstain"`
	ReasonSummary         string   `json:"reason_summary"`
	EvidenceRefs          []string `json:"evidence_refs"`
	RiskFlags             []string `json:"risk_flags"`
	RequestedObservations []string `json:"requested_observations"`
}

func errUnknownTask(value string) error {
	return &TaskError{Value: value}
}

// TaskError reports an unknown task type from model/config input.
type TaskError struct{ Value string }

func (e *TaskError) Error() string { return "unknown ai task type: " + e.Value }
