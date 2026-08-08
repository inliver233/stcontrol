package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func independentModeFact(now time.Time) NodeControlModeFact {
	return NodeControlModeFact{
		Mode: NodeModeIndependent, ModeGeneration: 3, ControllerGeneration: 5,
		ReasonCode:                "sustained_multi_signal_controller_loss",
		ConsecutiveHeartbeatFails: 60, ConsecutiveHealthProbeFails: 60,
		OutageStartedAt: now.Add(-15 * time.Minute), IndependentSince: now.Add(-time.Minute),
		ActiveIndependentSessions: 2, PendingUserSyncs: 1, ObservedAt: now,
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
		60, 60, 2, 1,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO node_control_mode_events`).WithArgs(
		int64(12), NodeModeIndependent, int64(3), NodeModeIndependentDraining, int64(4),
		int64(5), fact.ReasonCode, sqlmock.AnyArg(), now,
	).WillReturnResult(sqlmock.NewResult(1, 1))
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
	mock.ExpectExec(`UPDATE nodes SET control_mode=\$2`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO node_control_mode_events`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	decision, err := st.ReconcileNodeControlMode(context.Background(), 12, fact)
	if err != nil || decision.DesiredMode != NodeModeManaged || decision.ModeGeneration != 5 {
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

func TestControlPlaneReadinessRequiresActiveGenerationAndManagedNodes(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	mock.ExpectQuery(`SELECT EXISTS .*controller_epochs`).WillReturnRows(
		sqlmock.NewRows([]string{"ready"}).AddRow(false),
	)
	ready, err := st.IsControlPlaneReady(context.Background())
	if err != nil || ready {
		t.Fatalf("ready=%v err=%v", ready, err)
	}
	assertMockExpectations(t, mock)
}
