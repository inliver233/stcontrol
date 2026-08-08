package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"stcontrol/internal/store"
)

// TestControllerDisasterDrainAndMultiNodeWriteConflict uses real PostgreSQL to
// prove that recovery never skips independent-draining, cannot trust a lost
// adapter marker over durable reconciliation work, and converts independent
// writes reported by two nodes into the normal frozen conflict workflow.
func TestControllerDisasterDrainAndMultiNodeWriteConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller disaster PostgreSQL integration is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated Controller disaster store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	secretKey := []byte("0123456789abcdef0123456789abcdef")
	generation, err := st.GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatalf("read disaster Controller generation: %v", err)
	}
	nodeA := createControllerBackupNode(t, ctx, st, "disaster-compute-a", "compute", false, generation)
	nodeB := createControllerBackupNode(t, ctx, st, "disaster-compute-b", "compute", false, generation)
	seedControllerBackupCredential(t, ctx, st, secretKey, nodeA.ID, generation, "disaster-node-a-psk")
	seedControllerBackupCredential(t, ctx, st, secretKey, nodeB.ID, generation, "disaster-node-b-psk")

	solo := createControllerBackupUser(t, ctx, st, nodeA.ID, "disaster-solo")
	split := createControllerBackupUser(t, ctx, st, nodeA.ID, "disaster-split")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO node_accounts (user_id,node_id,local_handle,status,updated_at)
		VALUES ($1,$2,$3,'active',$4)`, split.GlobalID, nodeB.ID, split.Username, now); err != nil {
		t.Fatalf("seed second-node disaster account: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,data_version,state,last_sync_at,checksum,size_bytes)
		VALUES ($1,$3,'home',1,'ready',$5,'solo-a',100),
		       ($2,$3,'home',4,'ready',$5,'split-a',400),
		       ($2,$4,'hot_standby',3,'ready',$5,'split-b',300)`,
		solo.ID, split.ID, nodeA.ID, nodeB.ID, now); err != nil {
		t.Fatalf("seed disaster replica facts: %v", err)
	}
	if _, err := st.AcquireActivityLease(ctx, store.AcquireActivityLeaseParams{
		OperationID: "d1000000-0000-4000-8000-000000000001",
		UserID:      split.GlobalID, WriterNodeID: nodeA.ID,
		SessionID:            "d1000000-0000-4000-8000-000000000002",
		ControllerGeneration: generation, TTL: time.Hour, Now: now,
	}); err != nil {
		t.Fatalf("seed pre-disaster writer lease: %v", err)
	}

	// First prove the ordinary single-node path. A pending durable marker keeps
	// the node draining even if a restarted adapter transiently reports zero.
	soloMarker := "d1000000-0000-4000-8000-000000000003"
	soloPending := []store.IndependentSyncFact{{
		Handle: solo.Username, Marker: soloMarker,
		ChangedAt: now.Add(-time.Minute), Reason: "independent_write",
	}}
	decision, err := st.ReconcileNodeControlMode(ctx, nodeA.ID,
		controllerDisasterFact(generation, 2, store.NodeModeIndependent, now, 1, soloPending))
	if err != nil || decision.DesiredMode != store.NodeModeIndependentDraining || decision.ModeGeneration != 3 {
		t.Fatalf("independent recovery decision=%+v err=%v", decision, err)
	}
	decision, err = st.ReconcileNodeControlMode(ctx, nodeA.ID,
		controllerDisasterFact(generation, 3, store.NodeModeIndependentDraining, now.Add(time.Second), 1, soloPending))
	if err != nil || decision.DesiredMode != store.NodeModeIndependentDraining {
		t.Fatalf("active session escaped draining: decision=%+v err=%v", decision, err)
	}
	decision, err = st.ReconcileNodeControlMode(ctx, nodeA.ID,
		controllerDisasterFact(generation, 3, store.NodeModeIndependentDraining, now.Add(2*time.Second), 0, nil))
	if err != nil || decision.DesiredMode != store.NodeModeIndependentDraining {
		t.Fatalf("lost adapter marker escaped durable draining: decision=%+v err=%v", decision, err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE independent_user_reconciliations SET state='succeeded',completed_at=$2,updated_at=$2
		WHERE node_id=$1 AND marker=$3::uuid`, nodeA.ID, now.Add(3*time.Second), soloMarker); err != nil {
		t.Fatalf("complete simulated single-user reconciliation: %v", err)
	}
	decision, err = st.ReconcileNodeControlMode(ctx, nodeA.ID,
		controllerDisasterFact(generation, 3, store.NodeModeIndependentDraining, now.Add(4*time.Second), 0, nil))
	if err != nil || decision.DesiredMode != store.NodeModeManaged || decision.ModeGeneration != 4 {
		t.Fatalf("fully drained node did not return managed: decision=%+v err=%v", decision, err)
	}
	decision, err = st.ReconcileNodeControlMode(ctx, nodeA.ID, store.NodeControlModeFact{
		Mode: store.NodeModeManaged, ModeGeneration: 4,
		ControllerGeneration: generation, ReasonCode: "controller_reconciled",
		ObservedAt: now.Add(5 * time.Second),
	})
	if err != nil || decision.DesiredMode != store.NodeModeManaged {
		t.Fatalf("apply managed mode after complete drain: decision=%+v err=%v", decision, err)
	}
	if ready, err := st.IsControlPlaneReady(ctx); err != nil || !ready {
		t.Fatalf("control plane not ready after complete drain: ready=%v err=%v", ready, err)
	}

	// A later partition produces independent writes for the same identity on A
	// and B. Exact heartbeat replay must not duplicate facts; the conflict is
	// latched, user-scoped, and closes the write lease after projection.
	markerA := "d1000000-0000-4000-8000-000000000004"
	markerB := "d1000000-0000-4000-8000-000000000005"
	pendingA := []store.IndependentSyncFact{{
		Handle: split.Username, Marker: markerA,
		ChangedAt: now.Add(6 * time.Second), Reason: "independent_write",
	}}
	pendingB := []store.IndependentSyncFact{{
		Handle: split.Username, Marker: markerB,
		ChangedAt: now.Add(7 * time.Second), Reason: "independent_write",
	}}
	decisionA, err := st.ReconcileNodeControlMode(ctx, nodeA.ID,
		controllerDisasterFact(generation, 5, store.NodeModeIndependent, now.Add(8*time.Second), 1, pendingA))
	if err != nil || decisionA.DesiredMode != store.NodeModeIndependentDraining || decisionA.ModeGeneration != 6 {
		t.Fatalf("node A second disaster decision=%+v err=%v", decisionA, err)
	}
	decisionB, err := st.ReconcileNodeControlMode(ctx, nodeB.ID,
		controllerDisasterFact(generation, 2, store.NodeModeIndependent, now.Add(9*time.Second), 1, pendingB))
	if err != nil || decisionB.DesiredMode != store.NodeModeIndependentDraining || decisionB.ModeGeneration != 3 {
		t.Fatalf("node B disaster decision=%+v err=%v", decisionB, err)
	}
	replayed, err := st.ReconcileNodeControlMode(ctx, nodeB.ID,
		controllerDisasterFact(generation, 2, store.NodeModeIndependent, now.Add(10*time.Second), 1, pendingB))
	if err != nil || replayed.DesiredMode != decisionB.DesiredMode || replayed.ModeGeneration != decisionB.ModeGeneration {
		t.Fatalf("replayed node B disaster decision=%+v err=%v", replayed, err)
	}

	var reconciliationCount, conflictCount int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*),count(*) FILTER (WHERE state='conflict')
		FROM independent_user_reconciliations WHERE user_id=$1`, split.GlobalID).
		Scan(&reconciliationCount, &conflictCount); err != nil {
		t.Fatalf("query multi-node independent reconciliation facts: %v", err)
	}
	if reconciliationCount != 2 || conflictCount != 2 {
		t.Fatalf("multi-node write facts: total=%d conflict=%d", reconciliationCount, conflictCount)
	}
	if _, err := st.ReconcileProtectionStates(ctx, now.Add(11*time.Second), time.Minute); err != nil {
		t.Fatalf("project independent-write conflict: %v", err)
	}
	var globalStatus, legacyStatus, leaseState, protectionState string
	var openConflicts int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT global_user.status,legacy.status,lease.state,protection.state,
		  (SELECT count(*) FROM replica_conflicts conflict
		   WHERE conflict.user_id=global_user.id AND conflict.state NOT IN ('resolved','failed'))
		FROM global_users global_user
		JOIN users legacy ON legacy.id=global_user.legacy_user_id
		JOIN user_activity_leases lease ON lease.user_id=global_user.id
		JOIN user_protection_states protection ON protection.user_id=global_user.id
		WHERE global_user.id=$1`, split.GlobalID).
		Scan(&globalStatus, &legacyStatus, &leaseState, &protectionState, &openConflicts); err != nil {
		t.Fatalf("query frozen independent-write conflict: %v", err)
	}
	if globalStatus != "conflict" || legacyStatus != "conflict" || leaseState != "conflict" ||
		protectionState != "conflict" || openConflicts != 1 {
		t.Fatalf("independent-write conflict was not frozen: global=%s legacy=%s lease=%s protection=%s conflicts=%d",
			globalStatus, legacyStatus, leaseState, protectionState, openConflicts)
	}

	// Even an empty subsequent Agent report cannot bypass the durable conflict.
	decisionA, err = st.ReconcileNodeControlMode(ctx, nodeA.ID,
		controllerDisasterFact(generation, 6, store.NodeModeIndependentDraining, now.Add(12*time.Second), 0, nil))
	if err != nil || decisionA.DesiredMode != store.NodeModeIndependentDraining {
		t.Fatalf("durable conflict escaped draining: decision=%+v err=%v", decisionA, err)
	}
	if ready, err := st.IsControlPlaneReady(ctx); err != nil || ready {
		t.Fatalf("control plane opened during independent conflict: ready=%v err=%v", ready, err)
	}

	var confirmedAt time.Time
	var evidenceEvents int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT max((evidence->>'confirmed_outage_started_at')::timestamptz),count(*) FROM node_control_mode_events
		WHERE node_id=$1 AND evidence ? 'confirmed_outage_started_at'
		  AND evidence->>'confirmed_outage_started_at'<>''`, nodeA.ID).
		Scan(&confirmedAt, &evidenceEvents); err != nil {
		t.Fatalf("query confirmed outage evidence events: %v", err)
	}
	if confirmedAt.IsZero() || evidenceEvents < 1 {
		t.Fatalf("confirmed outage evidence missing: timestamp=%v events=%d", confirmedAt, evidenceEvents)
	}

	stale := controllerDisasterFact(generation, 4, store.NodeModeIndependent, now.Add(13*time.Second), 1, pendingA)
	if _, err := st.ReconcileNodeControlMode(ctx, nodeA.ID, stale); !errors.Is(err, store.ErrStaleNodeControlMode) {
		t.Fatalf("stale disaster mode generation accepted: %v", err)
	}
}

func controllerDisasterFact(
	controllerGeneration, modeGeneration int64,
	mode string,
	observedAt time.Time,
	activeSessions int,
	pending []store.IndependentSyncFact,
) store.NodeControlModeFact {
	fact := store.NodeControlModeFact{
		Mode: mode, ModeGeneration: modeGeneration,
		ControllerGeneration:      controllerGeneration,
		ReasonCode:                "controller_recovered",
		ActiveIndependentSessions: activeSessions,
		PendingUserSyncs:          len(pending), PendingUsers: pending,
		ObservedAt: observedAt,
	}
	if mode == store.NodeModeIndependent {
		fact.ReasonCode = "sustained_multi_signal_controller_loss"
		fact.ConsecutiveHeartbeatFails = 64
		fact.ConsecutiveHealthProbeFails = 64
		fact.OutageStartedAt = observedAt.Add(-20 * time.Minute)
		fact.ConfirmedOutageStartedAt = observedAt.Add(-16 * time.Minute)
		fact.IndependentSince = observedAt.Add(-time.Minute)
	}
	return fact
}
