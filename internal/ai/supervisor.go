package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// supervisor.go implements the AI worker: a bounded queue, per
// provider+model+task circuit breaker, and shadow/advisory/auto_low_risk
// modes (§3.4/§5.2). The worker never runs on a business request path; the
// controller starts it in the background. AI failure is equivalent to no AI.

// Mode is the runtime supervision mode.
type Mode string

const (
	ModeShadow      Mode = "shadow"
	ModeAdvisory    Mode = "advisory"
	ModeAutoLowRisk Mode = "auto_low_risk"
)

// ParseMode validates a configured mode.
func ParseMode(value string) (Mode, error) {
	switch Mode(value) {
	case ModeShadow, ModeAdvisory, ModeAutoLowRisk:
		return Mode(value), nil
	default:
		return "", fmt.Errorf("unsupported ai supervisor mode %q", value)
	}
}

// Store is the minimal persistence surface the supervisor needs (implemented
// by *store.Store through small adapters in the controller package).
type Store interface {
	InsertAIAdvisoryRequest(ctx context.Context, req AIAdvisoryRequestLike) (int64, error)
	ListDueAIAdvisoryRequests(ctx context.Context, limit int) ([]AIAdvisoryRequestLike, error)
	ExpireOverdueAIAdvisoryRequests(ctx context.Context, now time.Time) (int64, error)
	MarkAIAdvisoryRequestState(ctx context.Context, id int64, state, errorCode string) error
	InsertAIAdvisory(ctx context.Context, adv AIAdvisoryLike) (int64, error)
	InsertAIAdvisoryOutcome(ctx context.Context, outcome AIAdvisoryOutcomeLike) error
}

// AIAdvisoryRequestLike is the structural view the supervisor needs; the
// controller package adapts *store.Store to it.
type AIAdvisoryRequestLike struct {
	ID                int64
	TaskType          string
	SchemaVersion     string
	PromptVersion     string
	ModelID           string
	ObservationDigest []byte
	ObservationJSON   json.RawMessage
	DedupKey          string
	RequestedAt       time.Time
	DeadlineAt        time.Time
	State             string
	ErrorCode         string
}

// AIAdvisoryLike mirrors the stored advisory record.
type AIAdvisoryLike struct {
	RequestID         int64
	Action            string
	CandidateRefs     []string
	Confidence        float64
	Abstain           bool
	ReasonSummary     string
	EvidenceRefs      []string
	RiskFlags         []string
	RequestedObs      []string
	RawResponseDigest []byte
	ExpiresAt         time.Time
}

// AIAdvisoryOutcomeLike mirrors the stored outcome record.
type AIAdvisoryOutcomeLike struct {
	RequestID        int64
	Decision         string
	ValidatorCode    string
	ActorType        string
	DeterministicRef string
	ObservedOutcome  string
}

// breaker is a per provider+model+task circuit breaker (§5.2).
type breaker struct {
	mu          sync.Mutex
	failures    int
	openedAt    time.Time
	halfOpenTry bool
}

func (b *breaker) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openedAt.IsZero() {
		return true
	}
	if now.Sub(b.openedAt) >= 10*time.Minute && !b.halfOpenTry {
		// half-open: admit exactly one low-sensitivity probe.
		b.halfOpenTry = true
		return true
	}
	return false
}

func (b *breaker) record(ok bool, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ok {
		b.failures = 0
		b.openedAt = time.Time{}
		b.halfOpenTry = false
		return
	}
	b.failures++
	if b.failures >= 5 {
		b.openedAt = now
		b.halfOpenTry = false
	}
}

// Supervisor drives the AI worker.
type Supervisor struct {
	store    Store
	provider Provider
	redactor *Redactor
	mode     Mode
	model    string
	timeout  time.Duration

	mu       sync.Mutex
	breakers map[string]*breaker
}

// NewSupervisor wires the worker. provider may be nil only when the worker is
// disabled (the controller must not start it then).
func NewSupervisor(store Store, provider Provider, redactor *Redactor, mode Mode, model string, timeout time.Duration) *Supervisor {
	return &Supervisor{
		store:    store,
		provider: provider,
		redactor: redactor,
		mode:     mode,
		model:    model,
		timeout:  timeout,
		breakers: make(map[string]*breaker),
	}
}

// EnqueueTask persists one queued advisory request for any task type (used
// by phase workers: alert attribution, schedule, recovery, import, disaster,
// conflict). The caller supplies the redacted observation JSON and a dedupKey
// so the same fact is only asked once.
func (s *Supervisor) EnqueueTask(ctx context.Context, taskType string, observationJSON []byte, dedupKey string) error {
	digest := sha256.Sum256(observationJSON)
	_, err := s.store.InsertAIAdvisoryRequest(ctx, AIAdvisoryRequestLike{
		TaskType:          taskType,
		SchemaVersion:     SchemaVersion,
		PromptVersion:     PromptVersion,
		ModelID:           s.model,
		ObservationDigest: digest[:],
		ObservationJSON:   observationJSON,
		DedupKey:          dedupKey,
		DeadlineAt:        time.Now().UTC().Add(2 * time.Minute),
		State:             "queued",
	})
	return err
}

// Run processes the advisory queue until ctx is cancelled. inspectEvery
// controls the periodic monitoring-inspection enqueue; buildObservation must
// return (observationJSON, evidenceCatalog, candidateCatalog, dedupKey,
// taskType, error).
func (s *Supervisor) Run(ctx context.Context, inspectEvery time.Duration, buildObservation func(ctx context.Context) ([]byte, map[string]bool, map[string]bool, string, string, error)) {
	go func() {
		ticker := time.NewTicker(inspectEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.enqueueMonitoring(ctx, buildObservation); err != nil && ctx.Err() == nil {
					log.Printf("ai: enqueue monitoring inspection: %v", err)
				}
			}
		}
	}()
	for ctx.Err() == nil {
		if err := s.processDue(ctx); err != nil && ctx.Err() == nil {
			log.Printf("ai: process advisory queue: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// enqueueMonitoring builds and persists one monitoring inspection request.
func (s *Supervisor) enqueueMonitoring(ctx context.Context, build func(ctx context.Context) ([]byte, map[string]bool, map[string]bool, string, string, error)) error {
	if build == nil {
		return nil
	}
	obsJSON, _, _, dedupKey, taskType, err := build(ctx)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(obsJSON)
	_, err = s.store.InsertAIAdvisoryRequest(ctx, AIAdvisoryRequestLike{
		TaskType:          taskType,
		SchemaVersion:     SchemaVersion,
		PromptVersion:     PromptVersion,
		ModelID:           s.model,
		ObservationDigest: digest[:],
		ObservationJSON:   obsJSON,
		DedupKey:          dedupKey,
		DeadlineAt:        time.Now().UTC().Add(2 * time.Minute),
		State:             "queued",
	})
	return err
}

// processDue drains one batch of due requests. Overdue queued rows (deadline
// passed while the worker was down or the provider was broken) first get a
// terminal superseded state so they can never linger in the queue forever.
func (s *Supervisor) processDue(ctx context.Context) error {
	if expired, err := s.store.ExpireOverdueAIAdvisoryRequests(ctx, time.Now().UTC()); err != nil {
		log.Printf("ai: expire overdue advisory requests: %v", err)
	} else if expired > 0 {
		log.Printf("ai: superseded %d overdue advisory request(s)", expired)
	}
	reqs, err := s.store.ListDueAIAdvisoryRequests(ctx, 4)
	if err != nil {
		return err
	}
	for _, req := range reqs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.processOne(ctx, req)
	}
	return nil
}

// processOne executes one queued request through provider → validator → store.
func (s *Supervisor) processOne(ctx context.Context, req AIAdvisoryRequestLike) {
	task, err := ParseTaskType(req.TaskType)
	if err != nil {
		_ = s.store.MarkAIAdvisoryRequestState(ctx, req.ID, "failed", "unknown_task")
		return
	}
	now := time.Now().UTC()
	brk := s.breakerFor(s.model + "/" + req.TaskType)
	if !brk.allow(now) {
		_ = s.store.MarkAIAdvisoryRequestState(ctx, req.ID, "skipped", "circuit_open")
		return
	}
	taskPrompt, err := TaskPrompt(task)
	if err != nil {
		_ = s.store.MarkAIAdvisoryRequestState(ctx, req.ID, "failed", "no_prompt")
		return
	}
	timeout := s.timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	raw, err := s.provider.Complete(ctx, CallParams{
		Model:        s.model,
		SystemPrompt: SystemPrompt(),
		TaskPrompt:   taskPrompt,
		Observation:  req.ObservationJSON,
		Timeout:      timeout,
	})
	if err != nil {
		brk.record(false, now)
		_ = s.store.MarkAIAdvisoryRequestState(ctx, req.ID, "failed", "provider_error")
		return
	}
	evidenceCatalog, candidateCatalog := catalogsFromObservation(req.ObservationJSON)
	adv, verr := ValidateAdvisory(raw, task, observationIDFrom(req), evidenceCatalog, candidateCatalog)
	if verr != nil {
		brk.record(false, now)
		code := "invalid_response"
		if ve, ok := verr.(*ValidationError); ok {
			code = ve.Code
		}
		_ = s.store.MarkAIAdvisoryRequestState(ctx, req.ID, "failed", code)
		// Decision ⑤ (audit black box): every validator rejection leaves a
		// durable rejected outcome row so the review can replay what was
		// offered and why it was refused.
		_ = s.store.InsertAIAdvisoryOutcome(ctx, AIAdvisoryOutcomeLike{
			RequestID:       req.ID,
			Decision:        "rejected",
			ValidatorCode:   code,
			ActorType:       "system",
			ObservedOutcome: "validation_failed",
		})
		return
	}
	brk.record(true, now)
	digest := sha256.Sum256([]byte(raw))
	_, err = s.store.InsertAIAdvisory(ctx, AIAdvisoryLike{
		RequestID:         req.ID,
		Action:            adv.Action,
		CandidateRefs:     adv.CandidateRefs,
		Confidence:        adv.Confidence,
		Abstain:           adv.Abstain,
		ReasonSummary:     adv.ReasonSummary,
		EvidenceRefs:      adv.EvidenceRefs,
		RiskFlags:         adv.RiskFlags,
		RequestedObs:      adv.RequestedObservations,
		RawResponseDigest: digest[:],
		ExpiresAt:         now.Add(15 * time.Minute),
	})
	if err != nil {
		_ = s.store.MarkAIAdvisoryRequestState(ctx, req.ID, "failed", "store_error")
		return
	}
	_ = s.store.MarkAIAdvisoryRequestState(ctx, req.ID, "succeeded", "")
	_ = s.store.InsertAIAdvisoryOutcome(ctx, AIAdvisoryOutcomeLike{
		RequestID:       req.ID,
		Decision:        "shown",
		ActorType:       "none",
		ObservedOutcome: "stored",
	})
}

func (s *Supervisor) breakerFor(key string) *breaker {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.breakers[key]
	if !ok {
		b = &breaker{}
		s.breakers[key] = b
	}
	return b
}

// observationIDFrom extracts obs_… from the stored observation JSON.
func observationIDFrom(req AIAdvisoryRequestLike) string {
	var obs struct {
		ObservationID string `json:"observation_id"`
	}
	_ = json.Unmarshal(req.ObservationJSON, &obs)
	return obs.ObservationID
}

// catalogsFromObservation rebuilds evidence/candidate catalogs from the stored
// observation (the same data the model saw).
func catalogsFromObservation(obsJSON []byte) (map[string]bool, map[string]bool) {
	evidence := make(map[string]bool)
	candidates := make(map[string]bool)
	var obs struct {
		EvidenceCatalog []struct {
			Ref string `json:"ref"`
		} `json:"evidence_catalog"`
		CandidateCatalog []struct {
			Ref string `json:"ref"`
		} `json:"candidate_catalog"`
	}
	if err := json.Unmarshal(obsJSON, &obs); err != nil {
		return evidence, candidates
	}
	for _, e := range obs.EvidenceCatalog {
		evidence[e.Ref] = true
	}
	for _, c := range obs.CandidateCatalog {
		candidates[c.Ref] = true
	}
	return evidence, candidates
}

// hexDigest is a tiny helper for tests.
func hexDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
