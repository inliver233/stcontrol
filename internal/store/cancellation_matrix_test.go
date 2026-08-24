package store

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// TestStoreWorkflowEntryPointsPropagateCanceledContext exercises the public
// database boundary shared by the long-running reconcilers. A shutdown or HTTP
// disconnect must stop before any transaction or mutation can be started.
func TestStoreWorkflowEntryPointsPropagateCanceledContext(t *testing.T) {
	t.Parallel()
	const (
		id1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		id2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		id3 = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		id4 = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	)
	now := time.Now().UTC()
	hash := bytes.Repeat([]byte{1}, 32)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		run  func(*Store) error
	}{
		{name: "create snapshot", run: func(st *Store) error {
			_, err := st.CreateSnapshotWorkflow(ctx, CreateSnapshotWorkflowParams{
				WorkflowID: id1, OperationID: id2, SnapshotID: id3, CapabilityID: id4,
				CapabilityHash: hash, LegacyBackupJobID: 1, LegacyUserID: 2, GlobalUserID: 3,
				SourceNodeID: 4, TargetNodeID: 5, DestinationKind: "archive",
				CapabilityExpires: now.Add(time.Hour), Now: now,
			})
			return err
		}},
		{name: "get snapshot execution", run: func(st *Store) error { _, err := st.GetSnapshotWorkflowExecution(ctx, id1); return err }},
		{name: "list resumable snapshots", run: func(st *Store) error { _, err := st.ListResumableSnapshotWorkflowIDs(ctx, 10); return err }},
		{name: "claim snapshot", run: func(st *Store) error { _, err := st.ClaimSnapshotWorkflow(ctx, id1, id2, now, time.Minute); return err }},
		{name: "renew snapshot", run: func(st *Store) error { return st.RenewSnapshotWorkflow(ctx, id1, id2, now, time.Minute) }},
		{name: "schedule snapshot retry", run: func(st *Store) error {
			_, err := st.ScheduleSnapshotRetry(ctx, id1, "timeout", "safe", now, time.Minute)
			return err
		}},
		{name: "switch snapshot relay", run: func(st *Store) error { return st.SwitchSnapshotWorkflowToRelay(ctx, id1, now) }},
		{name: "resume snapshot retry", run: func(st *Store) error { return st.ResumeSnapshotRetry(ctx, id1, now) }},
		{name: "release snapshot", run: func(st *Store) error { return st.ReleaseSnapshotWorkflow(ctx, id1, id2) }},
		{name: "rotate snapshot capability", run: func(st *Store) error {
			return st.RotateSnapshotCapability(ctx, id1, id2, hash, now.Add(time.Hour), now)
		}},
		{name: "set snapshot state", run: func(st *Store) error { return st.SetSnapshotWorkflowState(ctx, id1, "scheduled", "quiescing", now) }},
		{name: "set snapshot progress", run: func(st *Store) error { return st.SetSnapshotWorkflowProgress(ctx, id1, id2, 4, "drained", now) }},
		{name: "complete snapshot step", run: func(st *Store) error { return st.CompleteSnapshotWorkflowStep(ctx, id1, "verify", now) }},
		{name: "complete snapshot", run: func(st *Store) error {
			_, err := st.CompleteSnapshotWorkflow(ctx, CompleteSnapshotWorkflowParams{
				WorkflowID: id1, SnapshotID: id2, CapabilityHash: hash, TargetNodeID: 5,
				ReplicaKind: "archive", ReplicaOrigin: "configured", ManifestSHA256: hash,
				ArchiveSHA256: hash, FileCount: 1, TotalBytes: 1, Now: now,
			})
			return err
		}},
		{name: "fail snapshot", run: func(st *Store) error { return st.FailSnapshotWorkflow(ctx, id1, "timeout", "safe", now) }},
		{name: "cancel snapshot", run: func(st *Store) error { return st.CancelSnapshotWorkflow(ctx, id1, "shutdown", now) }},

		{name: "list restore targets", run: func(st *Store) error { _, err := st.ListRestoreTargets(ctx, 3, 10); return err }},
		{name: "create restore", run: func(st *Store) error {
			_, err := st.CreateRestoreWorkflow(ctx, CreateRestoreWorkflowParams{
				OperationID: id1, RequestDigest: hash, WorkflowID: id2, RestoreSnapshotID: id3,
				CapabilityID: id4, CapabilityHash: hash, GlobalUserID: 3, TargetNodeID: 5,
				ExpectedRecoveryAt: now.Add(-time.Hour), CapabilityExpires: now.Add(time.Hour), Now: now,
			})
			return err
		}},
		{name: "get restore account", run: func(st *Store) error { _, err := st.GetWorkflowTargetAccountProvision(ctx, id1); return err }},
		{name: "get restore execution", run: func(st *Store) error { _, err := st.GetRestoreWorkflowExecution(ctx, id1); return err }},
		{name: "complete restore account", run: func(st *Store) error { return st.CompleteRestoreAccountProvision(ctx, id1, 2, "local-user", now) }},
		{name: "list resumable restores", run: func(st *Store) error { _, err := st.ListResumableRestoreWorkflowIDs(ctx, 10); return err }},
		{name: "claim restore", run: func(st *Store) error { _, err := st.ClaimRestoreWorkflow(ctx, id1, id2, now, time.Minute); return err }},
		{name: "reset restore retry", run: func(st *Store) error { return st.ResetRestoreTransferForRetry(ctx, id1, now) }},
		{name: "get restore status", run: func(st *Store) error { _, err := st.GetRestoreOperationStatus(ctx, 3, id1); return err }},
		{name: "complete restore", run: func(st *Store) error {
			return st.CompleteRestoreWorkflow(ctx, CompleteRestoreWorkflowParams{
				WorkflowID: id1, RestoreSnapshotID: id2, CapabilityHash: hash,
				ManifestSHA256: hash, ArchiveSHA256: hash, FileCount: 1, TotalBytes: 1, Now: now,
			})
		}},
		{name: "fail restore", run: func(st *Store) error { return st.FailRestoreWorkflow(ctx, id1, "timeout", "safe", now) }},

		{name: "create conflict resolution", run: func(st *Store) error {
			_, err := st.CreateConflictResolution(ctx, CreateConflictResolutionParams{
				OperationID: id1, RequestDigest: hash, WorkflowID: id2, ConflictID: id3,
				ResultSnapshotID: id4, GlobalUserID: 3, BaseNodeID: 4,
				ExpectedConflictVersion: 1, DefaultAction: "use_base", Now: now,
			})
			return err
		}},
		{name: "get conflict execution", run: func(st *Store) error { _, err := st.GetConflictResolutionExecution(ctx, id1); return err }},
		{name: "get conflict by operation", run: func(st *Store) error { _, err := st.GetConflictResolutionExecutionByOperation(ctx, id1); return err }},
		{name: "list conflict resolutions", run: func(st *Store) error { _, err := st.ListResumableConflictResolutionIDs(ctx, 10); return err }},
		{name: "claim conflict resolution", run: func(st *Store) error {
			_, err := st.ClaimConflictResolution(ctx, id1, id2, now, time.Minute)
			return err
		}},
		{name: "mark conflict transfer", run: func(st *Store) error { return st.MarkConflictResolutionTransferComplete(ctx, id1, id2, hash, now) }},
		{name: "rotate conflict transfer", run: func(st *Store) error {
			return st.RotateConflictResolutionTransfer(ctx, id1, id2, id3, hash, now.Add(time.Hour), now)
		}},
		{name: "mark conflict publishing", run: func(st *Store) error { return st.MarkConflictResolutionPublishing(ctx, id1, now) }},
		{name: "get conflict status", run: func(st *Store) error { _, err := st.GetConflictResolutionStatus(ctx, 3, id1); return err }},
		{name: "complete conflict resolution", run: func(st *Store) error {
			return st.CompleteConflictResolution(ctx, CompleteConflictResolutionParams{
				WorkflowID: id1, OperationID: id2, ConflictID: id3, ResultSnapshotID: id4,
				EntriesSHA256: hash, FileCount: 1, TotalBytes: 1, Now: now,
			})
		}},
		{name: "fail conflict resolution", run: func(st *Store) error { return st.FailConflictResolution(ctx, id1, "timeout", "safe", now) }},
		{name: "restart conflict resolution", run: func(st *Store) error { _, err := st.RestartConflictResolution(ctx, 3, id1, now); return err }},

		{name: "report user data fault", run: func(st *Store) error {
			_, err := st.ReportUserDataFault(ctx, ReportUserDataFaultParams{
				OperationID: id1, RequestDigest: hash, UserUUID: id2, ExpectedHomeNodeID: 4,
				ReasonCode: "user_directory_missing", AdminID: 5, Now: now,
			})
			return err
		}},
		{name: "get data fault", run: func(st *Store) error { _, err := st.GetUserDataFaultByID(ctx, id1); return err }},
		{name: "get data fault by user", run: func(st *Store) error { _, err := st.GetUserDataFaultByUserUUID(ctx, id1); return err }},
		{name: "list data faults", run: func(st *Store) error { _, err := st.ListSchedulableUserDataFaultIDs(ctx, 10); return err }},
		{name: "claim data fault", run: func(st *Store) error {
			_, err := st.ClaimUserDataFault(ctx, id1, id2, id3, now, time.Minute)
			return err
		}},
		{name: "list data fault releases", run: func(st *Store) error { _, err := st.ListSchedulableUserDataFaultReleaseIDs(ctx, 10); return err }},
		{name: "claim data fault release", run: func(st *Store) error {
			_, err := st.ClaimUserDataFaultRelease(ctx, id1, id2, id3, now, time.Minute)
			return err
		}},
		{name: "complete data fault freeze", run: func(st *Store) error { _, err := st.CompleteUserDataFaultFreeze(ctx, id1, id2, id3, now); return err }},
		{name: "retry data fault", run: func(st *Store) error { return st.RetryUserDataFault(ctx, id1, id2, id3, "timeout", now, time.Minute) }},
		{name: "complete data fault release", run: func(st *Store) error { return st.CompleteUserDataFaultRelease(ctx, id1, id2, id3, now) }},
		{name: "retry data fault release", run: func(st *Store) error {
			return st.RetryUserDataFaultRelease(ctx, id1, id2, id3, "timeout", now, time.Minute)
		}},

		{name: "schedule replica cleanup", run: func(st *Store) error { _, err := st.ScheduleReplicaCleanupTasks(ctx, now); return err }},
		{name: "claim replica cleanup", run: func(st *Store) error {
			_, err := st.ClaimReplicaCleanupTask(ctx, id1, id2, now, time.Minute)
			return err
		}},
		{name: "complete replica cleanup", run: func(st *Store) error {
			return st.CompleteReplicaCleanupTask(ctx, ReplicaCleanupTask{
				ID: id1, OperationID: id2, LeaseOwner: id3, SnapshotID: id4, ControllerGeneration: 1,
			}, "deleted", now)
		}},
		{name: "retry replica cleanup", run: func(st *Store) error {
			return st.RetryReplicaCleanupTask(ctx, ReplicaCleanupTask{
				ID: id1, OperationID: id2, LeaseOwner: id3, ControllerGeneration: 1,
			}, "timeout", now, time.Minute)
		}},
		{name: "fail replica cleanup", run: func(st *Store) error {
			return st.FailReplicaCleanupTask(ctx, ReplicaCleanupTask{
				ID: id1, OperationID: id2, LeaseOwner: id3, ControllerGeneration: 1,
			}, "identity_unavailable", now)
		}},

		{name: "get retirement status", run: func(st *Store) error { _, err := st.GetNodeRetirementStatus(ctx, 4); return err }},
		{name: "list retirements", run: func(st *Store) error { _, err := st.ListSchedulableNodeRetirementIDs(ctx, 10); return err }},
		{name: "claim retirement", run: func(st *Store) error {
			_, err := st.ClaimNodeRetirement(ctx, id1, id2, id3, now, time.Minute)
			return err
		}},
		{name: "release retirement", run: func(st *Store) error { return st.ReleaseNodeRetirement(ctx, id1, id2) }},
		{name: "get retirement item", run: func(st *Store) error { _, err := st.GetNextNodeRetirementItem(ctx, id1, now); return err }},
		{name: "retry retirement item", run: func(st *Store) error {
			return st.RetryNodeRetirementItem(ctx, id1, "retry_wait", "timeout", false, now, time.Minute)
		}},
		{name: "defer retirement", run: func(st *Store) error { return st.DeferNodeRetirement(ctx, id1, id2, "timeout", now, time.Minute) }},
		{name: "retirement target", run: func(st *Store) error { _, err := st.RetirementTargetAvailable(ctx, 3, 4, "alice"); return err }},
		{name: "complete retirement home", run: func(st *Store) error { return st.CompleteNodeRetirementHomeMigration(ctx, id1, id2, now) }},
		{name: "complete retirement replica", run: func(st *Store) error { return st.CompleteNodeRetirementReplicaItem(ctx, id1, now) }},
		{name: "finalize retirement", run: func(st *Store) error { _, err := st.FinalizeNodeRetirement(ctx, id1, id2, now); return err }},

		{name: "match import claim", run: func(st *Store) error { _, err := st.AccountImportClaimOperationMatches(ctx, id1, 3, 4); return err }},
		{name: "list import claim targets", run: func(st *Store) error { _, err := st.ListAccountImportClaimTargets(ctx, 3); return err }},
		{name: "resolve oauth import", run: func(st *Store) error {
			_, err := st.ResolveOAuthUnmatchedCandidates(ctx, "discord", "fingerprint", 3, now)
			return err
		}},
		{name: "complete import claim", run: func(st *Store) error {
			return st.CompleteAccountImportClaim(ctx, CompleteAccountImportClaimParams{
				OperationID: id1, GlobalUserID: 3, NodeID: 4,
				LocalHandle: "alice", LocalUserID: "local-alice", Now: now,
			})
		}},
		{name: "list oauth subjects", run: func(st *Store) error { _, err := st.ListActiveOAuthIdentitySubjects(ctx); return err }},
		{name: "ingest account imports", run: func(st *Store) error {
			_, err := st.IngestAccountImportBatch(ctx, CreateAccountImportBatchParams{
				ID: id1, OperationID: id2, NodeID: 4, InventoryDigest: hash,
				Source: "adapter", CreatedByAdminID: 5, Now: now,
			})
			return err
		}},
		{name: "get import batch", run: func(st *Store) error { _, err := st.GetAccountImportBatch(ctx, id1); return err }},
		{name: "list unscanned nodes", run: func(st *Store) error {
			_, err := st.ListUnscannedComputeNodes(ctx, now.Add(-time.Hour), 10)
			return err
		}},
		{name: "get latest import batch", run: func(st *Store) error { _, err := st.GetLatestAccountImportBatch(ctx, 4); return err }},
		{name: "get import operation", run: func(st *Store) error { _, err := st.GetAccountImportBatchByOperation(ctx, id1, 0, 10); return err }},

		{name: "create registration", run: func(st *Store) error {
			_, err := st.CreateRegistrationWorkflow(ctx, CreateRegistrationWorkflowParams{
				WorkflowID: id1, OperationID: id2, RequestDigest: hash, PendingTokenHash: hash,
				ClientExpiresAt: now.Add(time.Hour), NodeID: 4, PolicyVersion: 1,
				LocalHandle: "alice", DisplayName: "Alice", AuthProvider: "password",
				PasswordHash: "login-hash", PasswordMaterialHash: "node-hash",
				PasswordMaterialSalt: "node-salt", Now: now,
			})
			return err
		}},
		{name: "get registration status", run: func(st *Store) error { _, err := st.GetRegistrationWorkflowStatus(ctx, hash, now); return err }},
		{name: "get registration execution", run: func(st *Store) error { _, err := st.GetRegistrationWorkflowExecution(ctx, id1); return err }},
		{name: "list registrations", run: func(st *Store) error { _, err := st.ListRunnableRegistrationWorkflowIDs(ctx, 10, now); return err }},
		{name: "claim registration", run: func(st *Store) error {
			_, err := st.ClaimRegistrationWorkflow(ctx, id1, id2, now, time.Minute)
			return err
		}},
		{name: "release registration", run: func(st *Store) error { return st.ReleaseRegistrationWorkflow(ctx, id1, id2) }},
		{name: "retry registration", run: func(st *Store) error {
			_, err := st.ScheduleRegistrationRetry(ctx, id1, id2, "timeout", now.Add(time.Minute), now)
			return err
		}},
		{name: "expire registrations", run: func(st *Store) error { _, err := st.ReleaseExpiredRegistrationReservations(ctx, now); return err }},
		{name: "fail registration", run: func(st *Store) error { return st.FailRegistrationWorkflow(ctx, id1, id2, "timeout", now) }},
		{name: "complete registration", run: func(st *Store) error {
			_, err := st.CompleteRegistrationWorkflow(ctx, id1, id2, "local-alice", now)
			return err
		}},

		{name: "reconcile protection", run: func(st *Store) error { _, err := st.ReconcileProtectionStates(ctx, now, time.Minute); return err }},
		{name: "get protection", run: func(st *Store) error { _, err := st.GetUserProtectionState(ctx, 3); return err }},
		{name: "list protection alerts", run: func(st *Store) error { _, err := st.ListVisibleProtectionAlerts(ctx, 10, now); return err }},
		{name: "list storage repairs", run: func(st *Store) error { _, err := st.ListStorageRepairCandidates(ctx, 10, now); return err }},
		{name: "get hot recovery point", run: func(st *Store) error { _, err := st.GetImmutableHotStandbyRecoveryPoint(ctx, 3, 4); return err }},
		{name: "confirm takeover", run: func(st *Store) error {
			_, err := st.ConfirmReplicaTakeover(ctx, ConfirmReplicaTakeoverParams{
				OperationID: id1, RequestDigest: hash, GlobalUserID: 3,
				TargetNodeID: 4, ExpectedRecoveryAt: now.Add(-time.Hour), Now: now,
			})
			return err
		}},
		{name: "aggregate protection", run: func(st *Store) error { _, err := st.AggregateProtectionStates(ctx, now); return err }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			st, _, closeDB := newMockStore(t)
			defer closeDB()
			if err := test.run(st); err == nil {
				t.Fatal("canceled store operation unexpectedly succeeded")
			}
		})
	}
}
