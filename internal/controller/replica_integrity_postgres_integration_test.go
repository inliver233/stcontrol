package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func TestControllerReplicaIntegrityRunsTieredDurableCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller replica-integrity PostgreSQL integration is disabled in short mode")
	}
	ctx, st, generation, _ := newControllerRetirementStore(t)
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	home := createControllerBackupNode(t, ctx, st, "integrity-controller-home", "compute", false, generation)
	storageNode := createControllerBackupNode(t, ctx, st, "integrity-controller-storage", "storage", true, generation)
	const psk = "integrity-controller-storage-psk"
	seedControllerBackupCredential(t, ctx, st, secretKey, storageNode.ID, generation, psk)
	corruptUser, corruptReplicaID := seedControllerIntegrityCopy(
		t, ctx, st, generation, home.ID, storageNode.ID, "integrity-controller-corrupt",
	)
	escalateUser, escalateReplicaID := seedControllerIntegrityCopy(
		t, ctx, st, generation, home.ID, storageNode.ID, "integrity-controller-escalate",
	)

	harness := newControllerDurableCommandHarness(
		ctx, st, map[int64]string{storageNode.ID: psk},
		func(nodeID int64, lease *store.AgentCommandLease, plaintext []byte) (agentCommandSummary, bool, error) {
			if nodeID != storageNode.ID || lease.CommandType != "verify_replica_integrity_v2" {
				return agentCommandSummary{}, false, fmt.Errorf("unexpected integrity command %q on node %d", lease.CommandType, nodeID)
			}
			var request protocol.VerifyReplicaIntegrityRequest
			if err := json.Unmarshal(plaintext, &request); err != nil || request.OperationID != lease.OperationID ||
				(request.CheckKind != "light" && request.CheckKind != "deep") {
				return agentCommandSummary{}, false, fmt.Errorf("invalid integrity request=%+v err=%v", request, err)
			}
			if request.Handle == corruptUser.Username && request.CheckKind == "deep" {
				return agentCommandSummary{OK: false, Code: "replica_integrity_mismatch"}, false, nil
			}
			receipt := &protocol.ReplicaIntegrityReceipt{
				SnapshotID: request.SnapshotID, CheckKind: request.CheckKind,
				ManifestSHA256: request.ManifestSHA256, ArchiveSHA256: request.ArchiveSHA256,
				FileCount: request.FileCount, TotalBytes: request.TotalBytes,
			}
			if request.Handle == escalateUser.Username && request.CheckKind == "light" {
				receipt.ArchiveSHA256 = hex.EncodeToString(make([]byte, sha256.Size))
			}
			return agentCommandSummary{OK: true, ReplicaIntegrity: receipt}, true, nil
		},
	)
	t.Cleanup(harness.stop)
	server := New(config.DefaultController(), st, secretKey)
	server.reconcileReplicaIntegrity(ctx)
	waitControllerIntegrityState(t, ctx, st, corruptReplicaID, "ready", "verified", 5*time.Second)
	waitControllerIntegrityState(t, ctx, st, escalateReplicaID, "ready", "due", 5*time.Second)
	if harness.commandCount("verify_replica_integrity_v2") != 2 {
		t.Fatalf("first-tier integrity commands=%d", harness.commandCount("verify_replica_integrity_v2"))
	}

	// The first user's next scheduled check is forced to deep; the second was
	// escalated immediately by its mismatched light receipt. Both are claimed
	// through the same two-slot scheduler.
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE replica_copies SET integrity_next_check_at=now()-interval '1 second',
		  integrity_deep_check_at=now()-interval '1 second' WHERE id=$1`, corruptReplicaID); err != nil {
		t.Fatalf("schedule corrupt deep integrity check: %v", err)
	}
	server.reconcileReplicaIntegrity(ctx)
	waitControllerIntegrityState(t, ctx, st, corruptReplicaID, "corrupt", "corrupt", 5*time.Second)
	waitControllerIntegrityState(t, ctx, st, escalateReplicaID, "ready", "verified", 5*time.Second)
	if harness.commandCount("verify_replica_integrity_v2") != 4 {
		t.Fatalf("tiered integrity commands=%d", harness.commandCount("verify_replica_integrity_v2"))
	}
	var alertSeverity, legacyCorruptState string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT alert.severity,replica.state
		FROM replica_copies copy
		JOIN global_users global_user ON global_user.id=copy.user_id
		JOIN user_replicas replica ON replica.user_id=global_user.legacy_user_id AND replica.node_id=copy.node_id
		JOIN alerts alert ON alert.deduplication_key='replica-integrity:'||copy.id::text
		WHERE copy.id=$1`, corruptReplicaID).Scan(&alertSeverity, &legacyCorruptState); err != nil ||
		alertSeverity != "critical" || legacyCorruptState != "corrupt" {
		t.Fatalf("deep corruption alert=%q legacy=%q err=%v", alertSeverity, legacyCorruptState, err)
	}

	_, unavailableReplicaID := seedControllerIntegrityCopy(
		t, ctx, st, generation, home.ID, storageNode.ID, "integrity-controller-unavailable",
	)
	unavailableOperationID, err := newUUID()
	if err != nil {
		t.Fatalf("create unavailable integrity operation ID: %v", err)
	}
	unavailableTask, err := st.ClaimReplicaIntegrityTask(
		ctx, unavailableOperationID, time.Now().UTC(), replicaIntegrityLeaseTTL,
	)
	if err != nil || unavailableTask == nil || unavailableTask.ReplicaID != unavailableReplicaID {
		t.Fatalf("claim integrity task before node loss: task=%+v err=%v", unavailableTask, err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET connectivity_state='offline' WHERE id=$1`, storageNode.ID); err != nil {
		t.Fatalf("make integrity node unavailable: %v", err)
	}
	server.executeReplicaIntegrityTask(ctx, *unavailableTask)
	waitControllerIntegrityState(t, ctx, st, unavailableReplicaID, "ready", "retry_wait", 5*time.Second)
	var errorCode string
	if err := st.DB.QueryRowContext(ctx, `SELECT integrity_error_code FROM replica_copies WHERE id=$1`, unavailableReplicaID).Scan(&errorCode); err != nil || errorCode != "node_unavailable" {
		t.Fatalf("unavailable integrity code=%q err=%v", errorCode, err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	server.replicaIntegrityReconciler(cancelled)
	if errs := harness.errors(); len(errs) > 0 {
		t.Fatalf("integrity durable command harness errors: %v", errs)
	}
}

func seedControllerIntegrityCopy(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	generation, homeNodeID, storageNodeID int64,
	handle string,
) (*store.User, string) {
	t.Helper()
	user := createControllerBackupUser(t, ctx, st, homeNodeID, handle)
	workflowID, err := newUUID()
	if err != nil {
		t.Fatalf("create integrity workflow ID: %v", err)
	}
	operationID, err := newUUID()
	if err != nil {
		t.Fatalf("create integrity operation ID: %v", err)
	}
	snapshotID, err := newUUID()
	if err != nil {
		t.Fatalf("create integrity snapshot ID: %v", err)
	}
	replicaID, err := newUUID()
	if err != nil {
		t.Fatalf("create integrity replica ID: %v", err)
	}
	now := time.Now().UTC()
	manifestHash := sha256.Sum256([]byte("integrity-manifest:" + handle))
	archiveHash := sha256.Sum256([]byte("integrity-archive:" + handle))
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO workflows (
		  id,operation_id,workflow_type,state,user_id,source_node_id,target_node_id,
		  activity_epoch,controller_generation,created_at,updated_at,finished_at
		) VALUES ($1,$2,'snapshot','succeeded',$3,$4,$5,1,$6,$7,$7,$7)`,
		workflowID, operationID, user.GlobalID, homeNodeID, storageNodeID, generation, now); err != nil {
		t.Fatalf("seed integrity workflow: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO snapshot_manifests (
		  id,workflow_id,user_id,source_node_id,activity_epoch,format_version,
		  manifest_sha256,archive_sha256,file_count,total_bytes,state,created_at
		) VALUES ($1,$2,$3,$4,1,1,$5,$6,2,30,'immutable',$7)`,
		snapshotID, workflowID, user.GlobalID, homeNodeID, manifestHash[:], archiveHash[:], now); err != nil {
		t.Fatalf("seed integrity manifest: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO replica_copies (
		  id,user_id,node_id,snapshot_id,replica_kind,state,origin,is_authoritative,
		  compatibility_state,published_at,verified_at,created_at,updated_at,
		  integrity_state,integrity_check_kind,integrity_next_check_at,integrity_deep_check_at,
		  integrity_last_light_at,integrity_last_deep_at
		) VALUES ($1,$2,$3,$4,'archive','ready','configured',false,'compatible',$5,$5,$5,$5,
		  'verified','deep',$6,$7,$5,$5)`,
		replicaID, user.GlobalID, storageNodeID, snapshotID, now,
		now.Add(-time.Hour), now.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("seed integrity replica copy: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,state,data_version,checksum,size_bytes,last_sync_at)
		VALUES ($1,$2,'archive','ready',1,$3,30,$4)`,
		user.ID, storageNodeID, hex.EncodeToString(manifestHash[:]), now); err != nil {
		t.Fatalf("seed integrity legacy replica: %v", err)
	}
	return user, replicaID
}

func waitControllerIntegrityState(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	replicaID, wantCopyState, wantIntegrityState string,
	timeout time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var copyState, integrityState string
		err := st.DB.QueryRowContext(ctx, `
			SELECT state,integrity_state FROM replica_copies WHERE id=$1`, replicaID).Scan(&copyState, &integrityState)
		if err == nil && copyState == wantCopyState && integrityState == wantIntegrityState {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("integrity replica %s state=%q/%q want=%q/%q err=%v",
				replicaID, copyState, integrityState, wantCopyState, wantIntegrityState, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
