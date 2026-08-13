package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"stcontrol/internal/ai"
)

// ai_phase_tasks.go implements the six per-task observation builders
// (Phases 2-6B). Each builder queries only allowlisted store aggregates,
// redacts every field, and enqueues a deduplicated advisory request through
// the supervisor. Deterministic logic is never bypassed: these are shadow
// suggestions only.

// ---------- Phase 2: 告警归因 (anomaly_attribution) ----------

type aiAnomalyObservation struct {
	ObservationID   string                `json:"observation_id"`
	GeneratedAt     string                `json:"generated_at"`
	EvidenceCatalog []ai.Evidence         `json:"evidence_catalog"`
	AlertCounts     map[string]int64      `json:"alert_counts"`
	Alerts          []ai.AlertObservation `json:"alerts"`
	Nodes           []ai.NodeObservation  `json:"nodes"`
}

func (s *Server) enqueueAnomalyAttribution(ctx context.Context) error {
	now := time.Now().UTC()
	obsID := ai.ObservationID()
	redactor := ai.NewRedactor(s.secretKey)
	alerts, err := s.Store.ListVisibleProtectionAlerts(ctx, 50, now)
	if err != nil {
		return err
	}
	alertObs := make([]ai.AlertObservation, 0, len(alerts))
	for _, a := range alerts {
		alertObs = append(alertObs, ai.AlertObservation{
			Ref:      redactor.Ref("alert", obsID, a.UserUUID),
			Severity: a.Severity,
			State:    a.State,
			Category: a.Category,
			AgeSec:   int64(now.Sub(a.FirstSeenAt).Seconds()),
			Count:    1,
			Summary:  ai.SanitizeText(a.Summary),
		})
	}
	counts, err := s.Store.CountOpenAlertsBySeverity(ctx)
	if err != nil {
		counts = map[string]int64{}
	}
	evidence := make([]ai.Evidence, 0, len(alertObs))
	evidenceCatalog := make(map[string]bool)
	for _, a := range alertObs {
		ref := "ev_" + redactor.Ref("alert", obsID, a.Ref)[3:]
		evidence = append(evidence, ai.Evidence{Ref: ref, Kind: "alert", Value: a.Category})
		evidenceCatalog[ref] = true
	}
	raw, err := json.Marshal(aiAnomalyObservation{
		ObservationID: obsID, GeneratedAt: now.UTC().Format(time.RFC3339),
		EvidenceCatalog: evidence, AlertCounts: counts, Alerts: alertObs,
		Nodes: nil,
	})
	if err != nil {
		return err
	}
	_ = evidenceCatalog
	if len(alertObs) == 0 {
		return nil // nothing anomalous worth an AI call
	}
	dedup := "anomaly_" + now.UTC().Truncate(5*time.Minute).Format("20060102T1504")
	return s.aiSupervisor.EnqueueTask(ctx, string(ai.TaskAnomalyAttribution), raw, dedup)
}

// ---------- Phase 3: 节点/备份排序 (schedule_recommendation) ----------

func (s *Server) enqueueScheduleRecommendation(ctx context.Context) error {
	now := time.Now().UTC()
	obsID := ai.ObservationID()
	redactor := ai.NewRedactor(s.secretKey)
	nodes, err := s.Store.ListNodes(ctx)
	if err != nil {
		return err
	}
	nodeObs := make([]ai.NodeObservation, 0, len(nodes))
	candidateCatalog := make(map[string]bool)
	evidence := make([]ai.Evidence, 0)
	for _, n := range nodes {
		ref := redactor.Ref("node", obsID, fmt.Sprintf("%d", n.ID))
		obs := ai.NodeObservation{
			Ref: ref, Role: n.Role, Connectivity: n.ConnectivityState,
			Operational: n.OperationalState, Capacity: n.CapacityState,
			Compatibility: n.CompatibilityState,
		}
		if n.Region.Valid {
			obs.RegionBucket = n.Region.String
		}
		if n.CPUWindowAvg.Valid {
			obs.CPUWindowAvg = ai.Bucket(n.CPUWindowAvg.Float64)
		}
		if n.MemWindowAvg.Valid {
			obs.MemWindowAvg = ai.Bucket(n.MemWindowAvg.Float64)
		}
		obs.EligibleForNew = nodeEligibleForNewLoad(n)
		obs.EligibleAsBackup = nodeEligibleAsBackupTarget(n)
		if obs.EligibleForNew || obs.EligibleAsBackup {
			candidateCatalog[ref] = true
			evidence = append(evidence, ai.Evidence{Ref: "ev_" + ref[5:], Kind: "node_capacity", Value: ref + "/" + obs.Capacity})
		}
		nodeObs = append(nodeObs, obs)
	}
	if len(candidateCatalog) < 2 {
		return nil // fewer than two eligible candidates: nothing to order
	}
	raw, err := json.Marshal(aiAnomalyObservation{
		ObservationID: obsID, GeneratedAt: now.UTC().Format(time.RFC3339),
		EvidenceCatalog: evidence, Nodes: nodeObs,
	})
	if err != nil {
		return err
	}
	dedup := "schedule_" + now.UTC().Truncate(30*time.Minute).Format("20060102T1504")
	return s.aiSupervisor.EnqueueTask(ctx, string(ai.TaskScheduleRecommend), raw, dedup)
}

// ---------- Phase 4: 恢复编排 (recovery_plan) ----------

type aiRecoveryObservation struct {
	ObservationID   string                   `json:"observation_id"`
	GeneratedAt     string                   `json:"generated_at"`
	EvidenceCatalog []ai.Evidence            `json:"evidence_catalog"`
	Workflows       []ai.WorkflowObservation `json:"workflows"`
}

func (s *Server) enqueueRecoveryPlan(ctx context.Context) error {
	now := time.Now().UTC()
	obsID := ai.ObservationID()
	redactor := ai.NewRedactor(s.secretKey)
	workflows, err := s.Store.ListRecentRestoreWorkflowSummaries(ctx, 10)
	if err != nil {
		return err
	}
	evidence := make([]ai.Evidence, 0, len(workflows))
	wfObs := make([]ai.WorkflowObservation, 0, len(workflows))
	for _, w := range workflows {
		ref := redactor.Ref("wf", obsID, w.WorkflowID)
		wfObs = append(wfObs, ai.WorkflowObservation{
			Ref: ref, Type: "restore", State: w.State, Attempt: w.Attempt,
			AgeSec: int64(now.Sub(w.UpdatedAt).Seconds()), ErrorCode: w.ErrorCode,
		})
		evidence = append(evidence, ai.Evidence{Ref: "ev_" + ref[3:], Kind: "restore_workflow", Value: w.State})
	}
	if len(wfObs) == 0 {
		return nil
	}
	raw, err := json.Marshal(aiRecoveryObservation{
		ObservationID: obsID, GeneratedAt: now.UTC().Format(time.RFC3339),
		EvidenceCatalog: evidence, Workflows: wfObs,
	})
	if err != nil {
		return err
	}
	dedup := "recovery_" + now.UTC().Truncate(30*time.Minute).Format("20060102T1504")
	return s.aiSupervisor.EnqueueTask(ctx, string(ai.TaskRecoveryPlan), raw, dedup)
}

// ---------- Phase 5: 导入歧义说明 (import_review) ----------

type aiImportObservation struct {
	ObservationID   string                       `json:"observation_id"`
	GeneratedAt     string                       `json:"generated_at"`
	EvidenceCatalog []ai.Evidence                `json:"evidence_catalog"`
	Candidates      []importCandidateObservation `json:"candidates"`
}

type importCandidateObservation struct {
	Ref         string `json:"ref"`
	Telemetry   string `json:"telemetry"`
	AccountKind string `json:"account_kind"`
	Resolution  string `json:"resolution"`
	SizeBucket  string `json:"size_bucket"`
}

func (s *Server) enqueueImportReview(ctx context.Context) error {
	now := time.Now().UTC()
	obsID := ai.ObservationID()
	redactor := ai.NewRedactor(s.secretKey)
	candidates, err := s.Store.ListUnresolvedImportCandidates(ctx, 50)
	if err != nil {
		return err
	}
	evidence := make([]ai.Evidence, 0, len(candidates))
	obs := make([]importCandidateObservation, 0, len(candidates))
	for _, c := range candidates {
		ref := redactor.Ref("cand", obsID, c.BatchID)
		obs = append(obs, importCandidateObservation{
			Ref: ref, Telemetry: c.Telemetry, AccountKind: c.AccountKind,
			Resolution: c.Resolution, SizeBucket: c.SizeBucket,
		})
		evidence = append(evidence, ai.Evidence{Ref: "ev_" + ref[5:], Kind: "import_candidate", Value: c.Resolution})
	}
	if len(obs) == 0 {
		return nil
	}
	raw, err := json.Marshal(aiImportObservation{
		ObservationID: obsID, GeneratedAt: now.UTC().Format(time.RFC3339),
		EvidenceCatalog: evidence, Candidates: obs,
	})
	if err != nil {
		return err
	}
	dedup := "import_" + now.UTC().Truncate(30*time.Minute).Format("20060102T1504")
	return s.aiSupervisor.EnqueueTask(ctx, string(ai.TaskImportReview), raw, dedup)
}

// ---------- Phase 6A: 灾难判断 (disaster_review) ----------

type aiDisasterObservation struct {
	ObservationID      string                         `json:"observation_id"`
	GeneratedAt        string                         `json:"generated_at"`
	EvidenceCatalog    []ai.Evidence                  `json:"evidence_catalog"`
	ModeEvents         []disasterModeEventObservation `json:"mode_events"`
	HardFloorSatisfied bool                           `json:"deterministic_hard_floor_satisfied"`
}

type disasterModeEventObservation struct {
	Ref      string `json:"ref"`
	Reported string `json:"reported_mode"`
	Desired  string `json:"desired_mode"`
	Reason   string `json:"reason_code"`
	AgeSec   int64  `json:"age_sec"`
}

func (s *Server) enqueueDisasterReview(ctx context.Context) error {
	now := time.Now().UTC()
	obsID := ai.ObservationID()
	redactor := ai.NewRedactor(s.secretKey)
	events, err := s.Store.ListRecentNodeControlModeEvents(ctx, 10)
	if err != nil {
		return err
	}
	evidence := make([]ai.Evidence, 0, len(events))
	obs := make([]disasterModeEventObservation, 0, len(events))
	hardFloor := false
	for _, e := range events {
		ref := redactor.Ref("mode", obsID, fmt.Sprintf("%d", e.NodeRef))
		obs = append(obs, disasterModeEventObservation{
			Ref: ref, Reported: e.Reported, Desired: e.Desired, Reason: e.ReasonCode,
			AgeSec: int64(now.Sub(e.ObservedAt).Seconds()),
		})
		evidence = append(evidence, ai.Evidence{Ref: "ev_" + ref[5:], Kind: "control_mode", Value: e.Reported})
		// Hard floor: a node actually reached independent (or draining).
		if e.Reported == "independent" || e.Reported == "independent-draining" {
			hardFloor = true
		}
	}
	if len(obs) == 0 {
		return nil
	}
	raw, err := json.Marshal(aiDisasterObservation{
		ObservationID: obsID, GeneratedAt: now.UTC().Format(time.RFC3339),
		EvidenceCatalog: evidence, ModeEvents: obs, HardFloorSatisfied: hardFloor,
	})
	if err != nil {
		return err
	}
	dedup := "disaster_" + now.UTC().Truncate(5*time.Minute).Format("20060102T1504")
	return s.aiSupervisor.EnqueueTask(ctx, string(ai.TaskDisasterReview), raw, dedup)
}

// ---------- Phase 6B: 冲突元数据建议 (conflict_review) ----------

type aiConflictObservation struct {
	ObservationID   string                         `json:"observation_id"`
	GeneratedAt     string                         `json:"generated_at"`
	EvidenceCatalog []ai.Evidence                  `json:"evidence_catalog"`
	Conflicts       []conflictAggregateObservation `json:"conflicts"`
}

type conflictAggregateObservation struct {
	Ref              string `json:"ref"`
	State            string `json:"state"`
	SourceCount      int64  `json:"source_count"`
	FileCount        int64  `json:"file_count"`
	TotalBytes       int64  `json:"total_bytes"`
	HasReadyEvidence bool   `json:"evidence_ready"`
	AgeSec           int64  `json:"age_sec"`
}

func (s *Server) enqueueConflictReview(ctx context.Context) error {
	now := time.Now().UTC()
	obsID := ai.ObservationID()
	redactor := ai.NewRedactor(s.secretKey)
	conflicts, err := s.Store.ListOpenConflictAggregates(ctx, 10)
	if err != nil {
		return err
	}
	evidence := make([]ai.Evidence, 0, len(conflicts))
	obs := make([]conflictAggregateObservation, 0, len(conflicts))
	for _, c := range conflicts {
		ref := redactor.Ref("conflict", obsID, fmt.Sprintf("%d", c.UserRef))
		obs = append(obs, conflictAggregateObservation{
			Ref: ref, State: c.State, SourceCount: c.SourceCount,
			FileCount: c.FileCount, TotalBytes: c.TotalBytes,
			HasReadyEvidence: c.HasReadyEvidence, AgeSec: int64(now.Sub(c.UpdatedAt).Seconds()),
		})
		evidence = append(evidence, ai.Evidence{Ref: "ev_" + ref[9:], Kind: "conflict", Value: c.State})
	}
	if len(obs) == 0 {
		return nil
	}
	raw, err := json.Marshal(aiConflictObservation{
		ObservationID: obsID, GeneratedAt: now.UTC().Format(time.RFC3339),
		EvidenceCatalog: evidence, Conflicts: obs,
	})
	if err != nil {
		return err
	}
	dedup := "conflict_" + now.UTC().Truncate(5*time.Minute).Format("20060102T1504")
	return s.aiSupervisor.EnqueueTask(ctx, string(ai.TaskConflictReview), raw, dedup)
}
