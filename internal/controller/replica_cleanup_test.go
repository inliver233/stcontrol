package controller

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func TestMatchingReplicaCleanupReceiptRequiresExactScopeAndKnownOutcome(t *testing.T) {
	t.Parallel()
	task := store.ReplicaCleanupTask{
		ID:           "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		SnapshotID:   "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		GlobalUserID: 70, NodeID: 9, Handle: "alice", ReplicaKind: "hot_standby",
	}
	base := protocol.DeleteReplicaReceipt{
		CleanupID: task.ID, SnapshotID: task.SnapshotID, GlobalUserID: task.GlobalUserID,
		Handle: task.Handle, ReplicaKind: task.ReplicaKind, TargetNodeID: task.NodeID,
	}
	for _, outcome := range []string{
		protocol.DeleteReplicaOutcomeDeleted,
		protocol.DeleteReplicaOutcomeAlreadyAbsent,
		protocol.DeleteReplicaOutcomeSuperseded,
	} {
		receipt := base
		receipt.Outcome = outcome
		if !matchingReplicaCleanupReceipt(&receipt, task) {
			t.Errorf("valid outcome %q was rejected", outcome)
		}
	}
	if matchingReplicaCleanupReceipt(nil, task) {
		t.Fatal("nil cleanup receipt was accepted")
	}

	tests := map[string]func(*protocol.DeleteReplicaReceipt){
		"cleanup": func(receipt *protocol.DeleteReplicaReceipt) {
			receipt.CleanupID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		},
		"snapshot": func(receipt *protocol.DeleteReplicaReceipt) {
			receipt.SnapshotID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		},
		"user":    func(receipt *protocol.DeleteReplicaReceipt) { receipt.GlobalUserID++ },
		"handle":  func(receipt *protocol.DeleteReplicaReceipt) { receipt.Handle = "bob" },
		"kind":    func(receipt *protocol.DeleteReplicaReceipt) { receipt.ReplicaKind = "archive" },
		"node":    func(receipt *protocol.DeleteReplicaReceipt) { receipt.TargetNodeID++ },
		"outcome": func(receipt *protocol.DeleteReplicaReceipt) { receipt.Outcome = "unknown" },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			receipt := base
			receipt.Outcome = protocol.DeleteReplicaOutcomeDeleted
			mutate(&receipt)
			if matchingReplicaCleanupReceipt(&receipt, task) {
				t.Fatalf("mismatched receipt was accepted: %+v", receipt)
			}
		})
	}
}

func controllerCleanupTask() store.ReplicaCleanupTask {
	return store.ReplicaCleanupTask{
		ID:           "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ReplicaID:    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		GlobalUserID: 70, LegacyUserID: 7, NodeID: 9,
		SnapshotID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		Handle:     "alice", ReplicaKind: "hot_standby", ReasonCode: "superseded_hot_standby",
		Attempt: 2, OperationID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		ControllerGeneration: 4, LeaseOwner: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
	}
}

func expectControllerCleanupNode(
	mock sqlmock.Sqlmock,
	now time.Time,
	role, connectivity string,
) {
	mock.ExpectQuery(`(?s)SELECT .*connectivity_state.*capacity_state.* FROM nodes WHERE id=\$1`).WithArgs(int64(9)).
		WillReturnRows(loginRedirectNodeRows(now, role, connectivity, "active", "compatible", "managed", "managed"))
}

func expectControllerCleanupRetry(mock sqlmock.Sqlmock, task store.ReplicaCleanupTask, code string) {
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE replica_cleanup_tasks SET state='retry_wait'`).WithArgs(
		task.ID, task.OperationID, task.ControllerGeneration, sqlmock.AnyArg(), sqlmock.AnyArg(), code, task.LeaseOwner,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

func newReplicaCleanupWorkerTestServer(t *testing.T) (*Server, sqlmock.Sqlmock, []byte) {
	t.Helper()
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	key := []byte("01234567890123456789012345678901")
	return New(config.DefaultController(), &store.Store{DB: database}, key), mock, key
}

func expectControllerCleanupCommandResult(
	t *testing.T,
	mock sqlmock.Sqlmock,
	key []byte,
	task store.ReplicaCleanupTask,
	summary agentCommandSummary,
	state string,
) {
	t.Helper()
	ciphertext, err := controlcrypto.Encrypt(key, []byte("cleanup-node-agent-secret"))
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`FROM agent_credentials credential`).WithArgs(task.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"secret_ciphertext", "credential_version", "controller_generation"}).
			AddRow([]byte(ciphertext), int64(1), int64(4)))
	mock.ExpectQuery(`INSERT INTO agent_commands`).WillReturnRows(
		sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(4)),
	)
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`(?s)WITH expired AS .*FROM agent_commands WHERE operation_id=\$1`).WithArgs(task.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"state", "result_summary", "updated_at"}).
			AddRow(state, encoded, time.Now().UTC()))
}

func TestExecuteReplicaCleanupTaskRetriesUnavailableOrWrongRoleNode(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 8, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		role string
		rows bool
	}{
		{name: "node missing", rows: false},
		{name: "wrong role", role: "storage", rows: true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server, mock, _ := newReplicaCleanupWorkerTestServer(t)
			task := controllerCleanupTask()
			query := mock.ExpectQuery(`(?s)SELECT .*connectivity_state.*capacity_state.* FROM nodes WHERE id=\$1`).
				WithArgs(task.NodeID)
			if tc.rows {
				query.WillReturnRows(loginRedirectNodeRows(now, tc.role, "online", "active", "compatible", "managed", "managed"))
			} else {
				query.WillReturnRows(sqlmock.NewRows([]string{"id"}))
			}
			expectControllerCleanupRetry(mock, task, "node_unavailable")
			server.executeReplicaCleanupTask(context.Background(), task)
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExecuteReplicaCleanupTaskClassifiesAgentCredentialFailure(t *testing.T) {
	t.Parallel()
	server, mock, _ := newReplicaCleanupWorkerTestServer(t)
	task := controllerCleanupTask()
	expectControllerCleanupNode(mock, time.Now().UTC(), "compute", "online")
	mock.ExpectQuery(`FROM agent_credentials credential`).WithArgs(task.NodeID).
		WillReturnRows(sqlmock.NewRows([]string{"secret_ciphertext"}))
	expectControllerCleanupRetry(mock, task, "agent_command_unavailable")
	server.executeReplicaCleanupTask(context.Background(), task)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteReplicaCleanupTaskFailsTerminalIdentityError(t *testing.T) {
	t.Parallel()
	server, mock, key := newReplicaCleanupWorkerTestServer(t)
	task := controllerCleanupTask()
	expectControllerCleanupNode(mock, time.Now().UTC(), "compute", "online")
	expectControllerCleanupCommandResult(t, mock, key, task, agentCommandSummary{
		OK: false, Code: "replica_identity_unavailable",
	}, "failed")
	sentinel := errors.New("terminal cleanup persistence unavailable")
	mock.ExpectBegin().WillReturnError(sentinel)
	server.executeReplicaCleanupTask(context.Background(), task)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteReplicaCleanupTaskRetriesMismatchedReceipt(t *testing.T) {
	t.Parallel()
	server, mock, key := newReplicaCleanupWorkerTestServer(t)
	task := controllerCleanupTask()
	expectControllerCleanupNode(mock, time.Now().UTC(), "compute", "online")
	receipt := &protocol.DeleteReplicaReceipt{
		CleanupID: task.ID, SnapshotID: task.SnapshotID, GlobalUserID: task.GlobalUserID,
		Handle: task.Handle, ReplicaKind: task.ReplicaKind, TargetNodeID: task.NodeID + 1,
		Outcome: protocol.DeleteReplicaOutcomeDeleted,
	}
	expectControllerCleanupCommandResult(t, mock, key, task, agentCommandSummary{OK: true, ReplicaCleanup: receipt}, "succeeded")
	expectControllerCleanupRetry(mock, task, "receipt_mismatch")
	server.executeReplicaCleanupTask(context.Background(), task)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteReplicaCleanupTaskHandsBoundReceiptToCompletion(t *testing.T) {
	t.Parallel()
	server, mock, key := newReplicaCleanupWorkerTestServer(t)
	task := controllerCleanupTask()
	expectControllerCleanupNode(mock, time.Now().UTC(), "compute", "online")
	receipt := &protocol.DeleteReplicaReceipt{
		CleanupID: task.ID, SnapshotID: task.SnapshotID, GlobalUserID: task.GlobalUserID,
		Handle: task.Handle, ReplicaKind: task.ReplicaKind, TargetNodeID: task.NodeID,
		Outcome: protocol.DeleteReplicaOutcomeAlreadyAbsent,
	}
	expectControllerCleanupCommandResult(t, mock, key, task, agentCommandSummary{OK: true, ReplicaCleanup: receipt}, "succeeded")
	mock.ExpectBegin().WillReturnError(errors.New("completion deliberately fenced"))
	server.executeReplicaCleanupTask(context.Background(), task)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func expectReplicaCleanupScheduling(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE replica_cleanup_tasks task SET state='cancelled'`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)INSERT INTO replica_cleanup_tasks .*'superseded_archive'`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO replica_cleanup_tasks .*'stable_archive_available'`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

func TestReconcileReplicaCleanupHonorsGateCapacityAndClaimFailure(t *testing.T) {
	t.Parallel()
	t.Run("control plane gate", func(t *testing.T) {
		server, mock, _ := newReplicaCleanupWorkerTestServer(t)
		server.setControlPlaneGate(true, "recovery")
		server.reconcileReplicaCleanup(context.Background())
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("schedule failure", func(t *testing.T) {
		server, mock, _ := newReplicaCleanupWorkerTestServer(t)
		mock.ExpectBegin().WillReturnError(errors.New("schedule unavailable"))
		server.reconcileReplicaCleanup(context.Background())
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("capacity full", func(t *testing.T) {
		server, mock, _ := newReplicaCleanupWorkerTestServer(t)
		expectReplicaCleanupScheduling(mock)
		server.replicaCleanupSlots <- struct{}{}
		server.replicaCleanupSlots <- struct{}{}
		server.reconcileReplicaCleanup(context.Background())
		if len(server.replicaCleanupSlots) != cap(server.replicaCleanupSlots) {
			t.Fatalf("slot count=%d capacity=%d", len(server.replicaCleanupSlots), cap(server.replicaCleanupSlots))
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("claim failure releases slot", func(t *testing.T) {
		server, mock, _ := newReplicaCleanupWorkerTestServer(t)
		expectReplicaCleanupScheduling(mock)
		mock.ExpectBegin().WillReturnError(errors.New("claim unavailable"))
		server.reconcileReplicaCleanup(context.Background())
		if len(server.replicaCleanupSlots) != 0 {
			t.Fatalf("slot leak after claim failure: %d", len(server.replicaCleanupSlots))
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestReplicaCleanupReconcilerStopsOnCancellation(t *testing.T) {
	t.Parallel()
	server, mock, _ := newReplicaCleanupWorkerTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	server.replicaCleanupReconciler(ctx)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
