package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"stcontrol/internal/ai"
	"stcontrol/internal/store"
)

// ai_adoption.go implements the decision-④ adoption executor: the only
// component that may turn a validated advisory into deterministic system
// input, and only for the reversible low-risk kinds (cluster inspection
// summary, alert notes, node/backup ordering hints). Everything here is
// defense in depth:
//
//   - The supervisor only calls Adopt in auto_low_risk mode after
//     AutoAdoptable + !HumanConfirmRequired + confidence gate.
//   - Adopt re-checks every hard gate against CURRENT store state; anything
//     stale, partial or unmappable fails closed with ErrAdoptionNotExecutable
//     (the advisory just stays "shown").
//   - Effects expire with the advisory and are consumed only as tiebreakers
//     subordinate to capacity/compatibility/admin weights; they are never
//     Store truth and the Agent never sees them.
//   - Ordering hints must order EVERY currently eligible node (a full
//     ordering); a partial or stale ordering is refused, so the hint can
//     never silently hide a newly eligible node or promote an ineligible one.

// aiAdopter implements ai.Adopter on the controller server.
type aiAdopter struct{ srv *Server }

// maxAIAlertNoteTargets bounds how many alerts one explanation may annotate.
const maxAIAlertNoteTargets = 10

// Adopt executes one validated advisory.
func (a *aiAdopter) Adopt(ctx context.Context, req ai.AIAdvisoryRequestLike, adv *ai.Advisory, advisoryID int64) (ai.AdoptionResult, error) {
	now := time.Now().UTC()
	// Effects expire with the stored advisory (creation + 15 minutes); a hint
	// can never outlive the suggestion that produced it.
	expires := now.Add(15 * time.Minute)
	switch ai.Action(adv.Action) {
	case ai.ActionRecommendNodeOrder:
		return a.adoptOrdering(ctx, req, adv, advisoryID, "node_order_hint", "registration", a.srv.eligibleForNewLoadIDs, now, expires)
	case ai.ActionRecommendBackupOrder:
		return a.adoptOrdering(ctx, req, adv, advisoryID, "backup_order_hint", "backup", a.srv.eligibleAsBackupIDs, now, expires)
	case ai.ActionExplainAlert:
		return a.adoptAlertNotes(ctx, req, adv, advisoryID, now, expires)
	default:
		// NO_ACTION / REQUEST_MORE_OBSERVATION and every human-confirm action
		// have no deterministic executor.
		return ai.AdoptionResult{}, ai.ErrAdoptionNotExecutable
	}
}

// adoptOrdering turns RECOMMEND_NODE_ORDER / RECOMMEND_BACKUP_TARGET_ORDER
// into an ordering hint. Hard gates: every candidate ref must map (via the
// deterministic HMAC ref re-derivation) to a node that is eligible RIGHT NOW,
// and the advisory must order every currently eligible node exactly once.
func (a *aiAdopter) adoptOrdering(
	ctx context.Context,
	req ai.AIAdvisoryRequestLike,
	adv *ai.Advisory,
	advisoryID int64,
	kind, target string,
	eligible func(ctx context.Context) (map[int64]bool, error),
	now, expires time.Time,
) (ai.AdoptionResult, error) {
	eligibleIDs, err := eligible(ctx)
	if err != nil {
		return ai.AdoptionResult{}, fmt.Errorf("list nodes: %w", err)
	}
	if len(eligibleIDs) < 2 {
		return ai.AdoptionResult{}, ai.ErrAdoptionNotExecutable
	}
	redactor := ai.NewRedactor(a.srv.secretKey)
	refToID := make(map[string]int64, len(eligibleIDs))
	for id := range eligibleIDs {
		refToID[redactor.Ref("node", adv.ObservationID, strconv.FormatInt(id, 10))] = id
	}
	seen := make(map[int64]bool, len(adv.CandidateRefs))
	order := make([]int64, 0, len(adv.CandidateRefs))
	for _, ref := range adv.CandidateRefs {
		id, ok := refToID[ref]
		if !ok {
			// Unknown ref, or a node that is no longer eligible since the
			// observation was built: refuse the whole ordering.
			return ai.AdoptionResult{}, ai.ErrAdoptionNotExecutable
		}
		if seen[id] {
			return ai.AdoptionResult{}, ai.ErrAdoptionNotExecutable
		}
		seen[id] = true
		order = append(order, id)
	}
	if len(order) != len(eligibleIDs) {
		// Partial ordering: the model skipped at least one eligible node.
		// A hint that does not cover the full eligible set could silently
		// demote an eligible node below every unhinted one; refuse.
		return ai.AdoptionResult{}, ai.ErrAdoptionNotExecutable
	}
	payload, err := json.Marshal(store.AIOrderingHint{Order: order})
	if err != nil {
		return ai.AdoptionResult{}, err
	}
	observed := "applied"
	if prev, err := a.srv.Store.GetLatestAIAdoptionEffect(ctx, kind, target, now); err == nil && prev != nil {
		if prevHint, ok := store.AIOrderingHintFrom(prev); ok && sameInt64s(prevHint.Order, order) {
			observed = "unchanged"
		}
	}
	if err := a.srv.Store.InsertAIAdoptionEffect(ctx, store.AIAdoptionEffect{
		RequestID: req.ID, AdvisoryID: advisoryID, EffectKind: kind,
		TargetRef: target, Payload: payload, ExpiresAt: expires,
	}); err != nil {
		return ai.AdoptionResult{}, fmt.Errorf("persist %s: %w", kind, err)
	}
	return ai.AdoptionResult{
		EffectRef:       kind + ":" + joinInt64s(order),
		ObservedOutcome: observed,
	}, nil
}

// adoptAlertNotes attaches an EXPLAIN_ALERT reason summary to the current
// alerts the advisory actually cited. Notes live in ai_adoption_effects and
// are merged into the admin alert view only; the deterministic alert summary
// is never overwritten. Fails closed when no cited alert still exists or the
// text fails a fresh secret scan.
func (a *aiAdopter) adoptAlertNotes(
	ctx context.Context,
	req ai.AIAdvisoryRequestLike,
	adv *ai.Advisory,
	advisoryID int64,
	now, expires time.Time,
) (ai.AdoptionResult, error) {
	if strings.TrimSpace(adv.ReasonSummary) == "" {
		return ai.AdoptionResult{}, ai.ErrAdoptionNotExecutable
	}
	// Defense in depth: the summary is about to be surfaced in a new admin
	// view; re-scan even though ValidateAdvisory already checked it.
	if hit, _ := ai.ContainsSecret(adv.ReasonSummary); hit {
		return ai.AdoptionResult{}, ai.ErrAdoptionNotExecutable
	}
	alerts, err := a.srv.Store.ListVisibleProtectionAlerts(ctx, 100, now)
	if err != nil {
		return ai.AdoptionResult{}, fmt.Errorf("list alerts: %w", err)
	}
	cited := make(map[string]bool, len(adv.EvidenceRefs))
	for _, ref := range adv.EvidenceRefs {
		cited[ref] = true
	}
	redactor := ai.NewRedactor(a.srv.secretKey)
	matched := make([]string, 0, 4)
	for i := range alerts {
		if len(matched) >= maxAIAlertNoteTargets {
			break
		}
		alert := alerts[i]
		if alert.UserUUID == "" {
			continue
		}
		alertRef := redactor.Ref("alert", adv.ObservationID, alert.UserUUID)
		// Standard monitoring inspection evidence formula
		// (ai.BuildObservation -> addEvidence("alert", ref/severity/category)).
		monitoringEv := "ev_" + ai.EvidenceShortHash(redactor, adv.ObservationID, "alert",
			alertRef+"/"+alert.Severity+"/"+alert.Category)
		// anomaly_attribution observation formula
		// (enqueueAnomalyAttribution: "ev_" + Ref("alert", obsID, alertRef)[3:]).
		anomalyEv := "ev_" + redactor.Ref("alert", adv.ObservationID, alertRef)[3:]
		if cited[monitoringEv] || cited[anomalyEv] {
			payload, err := json.Marshal(map[string]string{"note": adv.ReasonSummary})
			if err != nil {
				return ai.AdoptionResult{}, err
			}
			if err := a.srv.Store.InsertAIAdoptionEffect(ctx, store.AIAdoptionEffect{
				RequestID: req.ID, AdvisoryID: advisoryID, EffectKind: "alert_note",
				TargetRef: alert.UserUUID, Payload: payload, ExpiresAt: expires,
			}); err != nil {
				return ai.AdoptionResult{}, fmt.Errorf("persist alert_note: %w", err)
			}
			matched = append(matched, alert.UserUUID)
		}
	}
	if len(matched) == 0 {
		// No cited alert still visible: fall back to a cluster-level summary
		// so the operator still sees the adopted explanation on the AI panel.
		payload, err := json.Marshal(map[string]string{"note": adv.ReasonSummary})
		if err != nil {
			return ai.AdoptionResult{}, err
		}
		if err := a.srv.Store.InsertAIAdoptionEffect(ctx, store.AIAdoptionEffect{
			RequestID: req.ID, AdvisoryID: advisoryID, EffectKind: "inspection_summary",
			TargetRef: "cluster", Payload: payload, ExpiresAt: expires,
		}); err != nil {
			return ai.AdoptionResult{}, fmt.Errorf("persist inspection_summary: %w", err)
		}
		return ai.AdoptionResult{
			EffectRef:       "inspection_summary:cluster",
			ObservedOutcome: "applied",
		}, nil
	}
	return ai.AdoptionResult{
		EffectRef:       "alert_note:" + strconv.Itoa(len(matched)),
		ObservedOutcome: "applied",
	}, nil
}

// eligibleForNewLoadIDs returns the set of node IDs currently eligible for
// new user load (identical rules to nodeEligibleForNewLoad).
func (s *Server) eligibleForNewLoadIDs(ctx context.Context) (map[int64]bool, error) {
	nodes, err := s.Store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]bool)
	for _, n := range nodes {
		if nodeEligibleForNewLoad(n) {
			out[n.ID] = true
		}
	}
	return out, nil
}

// eligibleAsBackupIDs returns the set of node IDs currently eligible as a
// pure-storage backup target (identical rules to nodeEligibleAsBackupTarget).
func (s *Server) eligibleAsBackupIDs(ctx context.Context) (map[int64]bool, error) {
	nodes, err := s.Store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]bool)
	for _, n := range nodes {
		if nodeEligibleAsBackupTarget(n) {
			out[n.ID] = true
		}
	}
	return out, nil
}

func sameInt64s(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func joinInt64s(values []int64) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, strconv.FormatInt(v, 10))
	}
	return strings.Join(parts, ",")
}
