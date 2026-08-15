package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func independentModeFact(now time.Time) NodeControlModeFact {
	return NodeControlModeFact{
		Mode: NodeModeIndependent, ModeGeneration: 3, ControllerGeneration: 5,
		ReasonCode:                "sustained_peer_confirmed_controller_loss",
		ConsecutiveHeartbeatFails: 60, ConsecutiveHealthProbeFails: 60,
		ConsecutivePeerWitnessFails: 60,
		OutageStartedAt:             now.Add(-15 * time.Minute),
		ConfirmedOutageStartedAt:    now.Add(-14 * time.Minute),
		IndependentSince:            now.Add(-time.Minute),
		ActiveIndependentSessions:   2, PendingUserSyncs: 0, ObservedAt: now,
	}
}

func TestValidNodeControlModeFactRejectsTakeoverBeyondReportedGeneration(t *testing.T) {
	t.Parallel()
	fact := independentModeFact(time.Now().UTC())
	fact.ConfirmedTakeovers = []IndependentTakeoverFact{{
		OperationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Handle: "alice",
		ParentClaimID:        "1111111111111111111111111111111111111111111111111111111111111111",
		ClaimID:              "2222222222222222222222222222222222222222222222222222222222222222",
		ControllerGeneration: fact.ControllerGeneration + 1,
		ActivityEpoch:        9, TakeoverSequence: 1, ConfirmedAt: fact.ObservedAt,
	}}
	if validNodeControlModeFact(fact) {
		t.Fatal("future-generation takeover was accepted")
	}
}

func TestReconcileIndependentModeAlwaysReturnsDrainingBoundary(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	fact := independentModeFact(now)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT n.role,n.control_mode,n.control_mode_generation`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{
			"role", "control_mode", "control_mode_generation", "desired_control_mode", "desired_mode_generation", "generation",
		}).AddRow("compute", NodeModeIndependent, int64(3), NodeModeIndependentDraining, int64(4), int64(5)))
	mock.ExpectExec(`UPDATE nodes SET control_mode=\$2`).WithArgs(
		int64(12), NodeModeIndependent, int64(3), NodeModeIndependentDraining, int64(4),
		fact.ReasonCode, now, int64(5), fact.OutageStartedAt, nil, fact.IndependentSince,
		60, 60, 2, 0, fact.ConfirmedOutageStartedAt, int64(5), 60,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO node_control_mode_events`).WithArgs(
		int64(12), NodeModeIndependent, int64(3), NodeModeIndependentDraining, int64(4),
		int64(5), fact.ReasonCode, sqlmock.AnyArg(), now,
	).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(`UPDATE controller_rebuild_nodes item SET`).WithArgs(
		int64(12), int64(5), int64(5), NodeModeIndependent,
		NodeModeIndependentDraining, now,
	).WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()
	decision, err := st.ReconcileNodeControlMode(context.Background(), 12, fact)
	if err != nil || decision.DesiredMode != NodeModeIndependentDraining ||
		decision.ModeGeneration != 4 || decision.ControllerGeneration != 5 {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	assertMockExpectations(t, mock)
}

func TestReconcileDrainingOnlyReturnsManagedAfterSessionsAndSyncsFinish(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 10, 1, 0, 0, time.UTC)
	fact := independentModeFact(now)
	fact.Mode = NodeModeIndependentDraining
	fact.ModeGeneration = 4
	fact.ActiveIndependentSessions = 0
	fact.PendingUserSyncs = 0
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT n.role,n.control_mode,n.control_mode_generation`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{
			"role", "control_mode", "control_mode_generation", "desired_control_mode", "desired_mode_generation", "generation",
		}).AddRow("compute", NodeModeIndependentDraining, int64(4), NodeModeIndependentDraining, int64(4), int64(5)))
	mock.ExpectQuery(`(?s)SELECT EXISTS .*independent_user_reconciliations`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{"pending"}).AddRow(false))
	mock.ExpectExec(`UPDATE nodes SET control_mode=\$2`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO node_control_mode_events`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(`UPDATE controller_rebuild_nodes item SET`).WithArgs(
		int64(12), int64(5), int64(5), NodeModeIndependentDraining,
		NodeModeManaged, now,
	).WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()
	decision, err := st.ReconcileNodeControlMode(context.Background(), 12, fact)
	if err != nil || decision.DesiredMode != NodeModeManaged || decision.ModeGeneration != 5 {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	assertMockExpectations(t, mock)
}

func TestReconcileDrainingCannotTrustAnEmptyAgentReportOverDurablePendingWork(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 10, 2, 0, 0, time.UTC)
	fact := independentModeFact(now)
	fact.Mode = NodeModeIndependentDraining
	fact.ModeGeneration = 4
	fact.ActiveIndependentSessions = 0
	fact.PendingUserSyncs = 0
	fact.PendingUsers = nil
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT n.role,n.control_mode,n.control_mode_generation`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{
			"role", "control_mode", "control_mode_generation", "desired_control_mode", "desired_mode_generation", "generation",
		}).AddRow("compute", NodeModeIndependentDraining, int64(4), NodeModeIndependentDraining, int64(4), int64(5)))
	mock.ExpectQuery(`(?s)SELECT EXISTS .*independent_user_reconciliations`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{"pending"}).AddRow(true))
	mock.ExpectExec(`UPDATE nodes SET control_mode=\$2`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO node_control_mode_events`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(`UPDATE controller_rebuild_nodes item SET`).WithArgs(
		int64(12), int64(5), int64(5), NodeModeIndependentDraining,
		NodeModeIndependentDraining, now,
	).WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()
	decision, err := st.ReconcileNodeControlMode(context.Background(), 12, fact)
	if err != nil || decision.DesiredMode != NodeModeIndependentDraining || decision.ModeGeneration != 4 {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	assertMockExpectations(t, mock)
}

func TestReconcileNodeControlModeRejectsGenerationRollback(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	fact := independentModeFact(time.Now().UTC())
	fact.ModeGeneration = 2
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT n.role,n.control_mode,n.control_mode_generation`).WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{
			"role", "control_mode", "control_mode_generation", "desired_control_mode", "desired_mode_generation", "generation",
		}).AddRow("compute", NodeModeManaged, int64(3), NodeModeManaged, int64(3), int64(5)))
	mock.ExpectRollback()
	_, err := st.ReconcileNodeControlMode(context.Background(), 12, fact)
	if !errors.Is(err, ErrStaleNodeControlMode) {
		t.Fatalf("err=%v", err)
	}
	assertMockExpectations(t, mock)
}

func TestReconcileIndependentModeRejectsMissingPeerWitnessEvidence(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	fact := independentModeFact(time.Now().UTC())
	fact.ConsecutivePeerWitnessFails = 0
	if _, err := st.ReconcileNodeControlMode(context.Background(), 12, fact); err == nil {
		t.Fatal("independent mode without peer-witness evidence was accepted")
	}
	assertMockExpectations(t, mock)
}

func TestControllerRebuildAllowsOldCredentialForHeartbeatOnly(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 4, 0, 0, 0, time.UTC)
	fact := NodeControlModeFact{
		Mode: NodeModeManaged, ModeGeneration: 2,
		ControllerGeneration: 5, ObservedAt: now,
	}

	t.Run("durable rebuild scope", func(t *testing.T) {
		st, mock, closeDB := newMockStore(t)
		defer closeDB()
		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT n.role,n.control_mode,n.control_mode_generation`).WithArgs(int64(12)).
			WillReturnRows(sqlmock.NewRows([]string{
				"role", "control_mode", "control_mode_generation", "desired_control_mode", "desired_mode_generation", "generation",
			}).AddRow("compute", NodeModeManaged, int64(2), NodeModeManaged, int64(2), int64(6)))
		mock.ExpectQuery(`(?s)SELECT EXISTS .*controller_rebuild_operations.*ready_with_deferred`).WithArgs(
			int64(6), int64(12), int64(4),
		).WillReturnRows(sqlmock.NewRows([]string{"allowed"}).AddRow(true))
		mock.ExpectQuery(`UPDATE controller_rebuild_nodes item SET`).WithArgs(
			int64(12), int64(6), int64(4), NodeModeManaged, NodeModeManaged, now,
		).WillReturnRows(sqlmock.NewRows([]string{"rebuild_id"}).
			AddRow("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
		mock.ExpectExec(`UPDATE controller_rebuild_nodes item`).WithArgs(
			"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", now,
		).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(`(?s)count\(\*\).*FILTER`).WithArgs("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").
			WillReturnRows(sqlmock.NewRows([]string{"total", "reconciled", "ready"}).AddRow(1, 0, 0))
		mock.ExpectExec(`UPDATE controller_rebuild_operations SET total_nodes`).WithArgs(
			"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 1, 0, now,
		).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(`UPDATE controller_rebuild_operations\s+SET state=\$2`).WithArgs(
			"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "reconciling", now,
		).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		decision, err := st.ReconcileNodeControlModeAuthenticated(
			context.Background(), 12, fact, 4,
		)
		if err != nil || decision.ControllerGeneration != 6 || decision.DesiredMode != NodeModeManaged {
			t.Fatalf("decision=%+v err=%v", decision, err)
		}
		assertMockExpectations(t, mock)
	})

	t.Run("no rebuild scope", func(t *testing.T) {
		st, mock, closeDB := newMockStore(t)
		defer closeDB()
		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT n.role,n.control_mode,n.control_mode_generation`).WithArgs(int64(12)).
			WillReturnRows(sqlmock.NewRows([]string{
				"role", "control_mode", "control_mode_generation", "desired_control_mode", "desired_mode_generation", "generation",
			}).AddRow("compute", NodeModeManaged, int64(2), NodeModeManaged, int64(2), int64(6)))
		mock.ExpectQuery(`(?s)SELECT EXISTS .*controller_rebuild_operations.*ready_with_deferred`).WithArgs(
			int64(6), int64(12), int64(4),
		).WillReturnRows(sqlmock.NewRows([]string{"allowed"}).AddRow(false))
		mock.ExpectRollback()
		_, err := st.ReconcileNodeControlModeAuthenticated(context.Background(), 12, fact, 4)
		if !errors.Is(err, ErrStaleControllerMode) {
			t.Fatalf("error=%v", err)
		}
		assertMockExpectations(t, mock)
	})
}

func TestControlPlaneReadinessIgnoresOfflineNodes(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	// An offline compute node with an old generation must NOT block readiness:
	// when it reconnects, the previous-generation credential can only reach the
	// recovery heartbeat and must rotate before leasing commands.
	mock.ExpectQuery(`(?s)SELECT EXISTS .*controller_epochs.*ready_with_deferred`).WillReturnRows(
		sqlmock.NewRows([]string{"ready"}).AddRow(true),
	)
	ready, err := st.IsControlPlaneReady(context.Background())
	if err != nil || !ready {
		t.Fatalf("ready=%v err=%v", ready, err)
	}
	assertMockExpectations(t, mock)
}
func TestControlPlaneReadinessRequiresActiveGenerationAndManagedNodes(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`(?s)SELECT EXISTS .*controller_epochs.*ready_with_deferred`).WillReturnRows(
		sqlmock.NewRows([]string{"ready"}).AddRow(false),
	)
	ready, err := st.IsControlPlaneReady(context.Background())
	if err != nil || ready {
		t.Fatalf("ready=%v err=%v", ready, err)
	}
	assertMockExpectations(t, mock)
}
