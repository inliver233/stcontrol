package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"stcontrol/internal/ai"
	"stcontrol/internal/store"
)

// ai_supervisor.go wires the AI 监管层 into the Controller: it adapts
// *store.Store to the ai.Store interface, builds redacted observations from
// live store facts, and starts the background supervisor worker. All AI work
// stays out of business request paths; AI off (default) changes nothing.

// aiStoreAdapter adapts *store.Store to ai.Store.
type aiStoreAdapter struct{ st *store.Store }

func (a *aiStoreAdapter) InsertAIAdvisoryRequest(ctx context.Context, req ai.AIAdvisoryRequestLike) (int64, error) {
	return a.st.InsertAIAdvisoryRequest(ctx, store.AIAdvisoryRequest{
		TaskType:          req.TaskType,
		SchemaVersion:     req.SchemaVersion,
		PromptVersion:     req.PromptVersion,
		ModelID:           req.ModelID,
		ObservationDigest: req.ObservationDigest,
		ObservationJSON:   req.ObservationJSON,
		DedupKey:          req.DedupKey,
		DeadlineAt:        req.DeadlineAt,
		State:             req.State,
	})
}

func (a *aiStoreAdapter) ListDueAIAdvisoryRequests(ctx context.Context, limit int) ([]ai.AIAdvisoryRequestLike, error) {
	rows, err := a.st.ListDueAIAdvisoryRequests(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := make([]ai.AIAdvisoryRequestLike, 0, len(rows))
	for _, r := range rows {
		out = append(out, ai.AIAdvisoryRequestLike{
			ID: r.ID, TaskType: r.TaskType, SchemaVersion: r.SchemaVersion,
			PromptVersion: r.PromptVersion, ModelID: r.ModelID,
			ObservationDigest: r.ObservationDigest, ObservationJSON: r.ObservationJSON,
			DedupKey: r.DedupKey, RequestedAt: r.RequestedAt, DeadlineAt: r.DeadlineAt,
			State: r.State, ErrorCode: r.ErrorCode,
		})
	}
	return out, nil
}

func (a *aiStoreAdapter) ExpireOverdueAIAdvisoryRequests(ctx context.Context, now time.Time) (int64, error) {
	return a.st.ExpireOverdueAIAdvisoryRequests(ctx, now)
}

func (a *aiStoreAdapter) MarkAIAdvisoryRequestState(ctx context.Context, id int64, state, errorCode string) error {
	return a.st.MarkAIAdvisoryRequestState(ctx, id, state, errorCode)
}

func (a *aiStoreAdapter) InsertAIAdvisory(ctx context.Context, adv ai.AIAdvisoryLike) (int64, error) {
	return a.st.InsertAIAdvisory(ctx, store.AIAdvisory{
		RequestID: adv.RequestID, Action: adv.Action, CandidateRefs: adv.CandidateRefs,
		Confidence: adv.Confidence, Abstain: adv.Abstain, ReasonSummary: adv.ReasonSummary,
		EvidenceRefs: adv.EvidenceRefs, RiskFlags: adv.RiskFlags, RequestedObs: adv.RequestedObs,
		RawResponseDigest: adv.RawResponseDigest, ExpiresAt: adv.ExpiresAt,
	})
}

func (a *aiStoreAdapter) InsertAIAdvisoryOutcome(ctx context.Context, outcome ai.AIAdvisoryOutcomeLike) error {
	return a.st.InsertAIAdvisoryOutcome(ctx, struct {
		RequestID        int64
		Decision         string
		ValidatorCode    string
		ActorType        string
		DeterministicRef string
		ObservedOutcome  string
	}{
		RequestID: outcome.RequestID, Decision: outcome.Decision,
		ValidatorCode: outcome.ValidatorCode, ActorType: outcome.ActorType,
		DeterministicRef: outcome.DeterministicRef, ObservedOutcome: outcome.ObservedOutcome,
	})
}

// buildAIObservation assembles one redacted monitoring observation from live
// store facts and returns (json, evidenceCatalog, candidateCatalog, dedupKey,
// taskType, err). It never reads user content; summaries are sanitized.
func (s *Server) buildAIObservation(ctx context.Context) ([]byte, map[string]bool, map[string]bool, string, string, error) {
	now := time.Now().UTC()
	obsID := ai.ObservationID()
	redactor := ai.NewRedactor(s.secretKey)
	salt := obsID

	nodes, err := s.Store.ListNodes(ctx)
	if err != nil {
		return nil, nil, nil, "", "", err
	}
	nodeObs := make([]ai.NodeObservation, 0, len(nodes))
	for _, n := range nodes {
		ref := redactor.Ref("node", salt, fmt.Sprintf("%d", n.ID))
		obs := ai.NodeObservation{
			Ref:           ref,
			Role:          n.Role,
			Connectivity:  n.ConnectivityState,
			Operational:   n.OperationalState,
			Capacity:      n.CapacityState,
			Compatibility: n.CompatibilityState,
		}
		if n.Region.Valid {
			obs.RegionBucket = n.Region.String
		}
		if n.CapacityReasonCode.Valid {
			obs.CapacityReason = n.CapacityReasonCode.String
		}
		if n.CompatibilityReasonCode.Valid {
			obs.CompatReason = n.CompatibilityReasonCode.String
		}
		if n.CPUWindowAvg.Valid {
			obs.CPUWindowAvg = ai.Bucket(n.CPUWindowAvg.Float64)
		}
		if n.MemWindowAvg.Valid {
			obs.MemWindowAvg = ai.Bucket(n.MemWindowAvg.Float64)
		}
		if n.DiskPct.Valid {
			obs.DiskPct = ai.Bucket(n.DiskPct.Float64)
		}
		if n.DiskAvailableBytes.Valid && n.DiskTotalBytes.Valid {
			obs.DiskFreeBucket = ai.BucketDiskFree(n.DiskAvailableBytes.Int64, n.DiskTotalBytes.Int64)
		}
		if n.LastSeenAt.Valid {
			obs.TelemetryAgeSec = int64(now.Sub(n.LastSeenAt.Time).Seconds())
			if obs.TelemetryAgeSec < 0 {
				obs.TelemetryAgeSec = 0
			}
		}
		obs.EligibleForNew = nodeEligibleForNewLoad(n)
		obs.EligibleAsBackup = nodeEligibleAsBackupTarget(n)
		nodeObs = append(nodeObs, obs)
	}

	alerts, err := s.Store.ListVisibleProtectionAlerts(ctx, 100, now)
	if err != nil {
		alerts = nil
	}
	alertObs := make([]ai.AlertObservation, 0, len(alerts))
	for _, a := range alerts {
		alertObs = append(alertObs, ai.AlertObservation{
			Ref:      redactor.Ref("alert", salt, a.UserUUID),
			Severity: a.Severity,
			State:    a.State,
			Category: a.Category,
			AgeSec:   int64(now.Sub(a.FirstSeenAt).Seconds()),
			Count:    1,
			Summary:  ai.SanitizeText(a.Summary),
		})
	}

	protectionAgg, aggErr := s.Store.AggregateProtectionStates(ctx, now)
	if aggErr != nil {
		// The aggregates are advisory context only; never fail the observation.
		protectionAgg = store.ProtectionAggregate{}
	}
	protection := ai.ProtectionObservation{
		TotalUsers:       protectionAgg.TotalUsers,
		ProtectedCount:   protectionAgg.ProtectedCount,
		UnprotectedCount: protectionAgg.UnprotectedCount,
		ConflictCount:    protectionAgg.ConflictCount,
		CorruptCount:     protectionAgg.CorruptCount,
		AvgReplicaAgeSec: protectionAgg.AvgReplicaAgeSec,
	}

	raw, evidence, candidates, digest, err := ai.BuildObservation(redactor, obsID, now, nodeObs, alertObs, nil, protection)
	if err != nil {
		return nil, nil, nil, "", "", err
	}
	_ = digest
	return raw, evidence, candidates, "monitor_" + now.UTC().Truncate(10*time.Minute).Format("20060102T1504"), string(ai.TaskMonitoringInspect), nil
}

// nodeEligibleForNewLoad mirrors the deterministic eligibility rules the
// controller already enforces elsewhere; AI may only order within this set.
func nodeEligibleForNewLoad(n *store.Node) bool {
	if n == nil || n.Role != "compute" {
		return false
	}
	return n.ConnectivityState == "online" && n.OperationalState == "active" &&
		n.CompatibilityState == "compatible" &&
		(n.CapacityState == "open" || n.CapacityState == "busy")
}

// nodeEligibleAsBackupTarget mirrors the backup-target eligibility.
func nodeEligibleAsBackupTarget(n *store.Node) bool {
	if n == nil || n.Role != "storage" {
		return false
	}
	return n.ConnectivityState == "online" && n.OperationalState == "active" &&
		n.CompatibilityState == "compatible" && n.CapacityState != "full"
}

// startAISupervisor starts the background AI worker when configured.
func (s *Server) startAISupervisor(ctx context.Context) {
	policy := s.Cfg.AISupervisor
	if !policy.Enabled {
		return
	}
	fail := func(reason string) {
		// Never crash the controller over an optional subsystem, but never stay
		// silent either: an operator must see why AI supervision did not start.
		log.Printf("ai supervisor disabled: %s", reason)
	}
	mode, err := ai.ParseMode(policy.Mode)
	if err != nil {
		fail(err.Error())
		return
	}
	kind, err := ai.ParseProviderKind(policy.Provider)
	if err != nil {
		fail(err.Error())
		return
	}
	apiKeyEnv := policy.APIKeyEnv
	if apiKeyEnv == "" {
		apiKeyEnv = "STCONTROL_AI_API_KEY"
	}
	timeout := time.Duration(policy.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	provider, err := ai.NewProvider(ai.ProviderConfig{
		Kind:    kind,
		BaseURL: policy.BaseURL,
		APIKey:  envOr(apiKeyEnv, ""),
		Model:   policy.Model,
		Timeout: timeout,
	})
	if err != nil {
		fail(err.Error())
		return
	}
	inspectEvery := time.Duration(policy.InspectEverySec) * time.Second
	if inspectEvery <= 0 {
		inspectEvery = 10 * time.Minute
	}
	supervisor := ai.NewSupervisor(&aiStoreAdapter{st: s.Store}, provider, ai.NewRedactor(s.secretKey), mode, policy.Model, timeout)
	// Decision ④: wire the adoption executor only in auto_low_risk mode.
	// shadow/advisory keep zero-effect behavior; advisory-mode operators can
	// still apply suggestions one by one via the admin adopt endpoint.
	if mode == ai.ModeAutoLowRisk {
		supervisor.WithAdopter(&aiAdopter{srv: s}, policy.AutoAdoptMinConfidence)
	}
	s.aiSupervisor = supervisor
	go supervisor.Run(ctx, inspectEvery, s.buildAIObservation)
	s.startAIPhaseWorkers(ctx)
}

// envOr reads an environment variable with a fallback.
func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return fallback
}

var _ = json.RawMessage{}
