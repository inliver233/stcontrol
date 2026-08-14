package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// TestPostgresReplicaCleanupFailRecovery is the real-PostgreSQL regression
// test for B1: FailReplicaCleanupTask must terminate a running cleanup task
// and return both replica projections (replica_copies + user_replicas) to a
// writable state.  Before the fix the user_replicas UPDATE passed four
// arguments against three placeholders, $2 served two different values, and
// the table had no updated_at column at all, so the recovery path aborted the
// whole transaction and permanently blocked the user's snapshot/restore.
func TestPostgresReplicaCleanupFailRecovery(t *testing.T) {
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	defer cleanupSchema()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	run := func(t *testing.T, kind, wantState string) {
		t.Helper()
		now := time.Now().UTC().Truncate(time.Microsecond)
		homeNodeID := insertIntegrationNode(t, st, "cleanup-fail-home-"+kind)
		targetNodeID := insertIntegrationNode(t, st, "cleanup-fail-target-"+kind)
		if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET role='storage' WHERE id=$1`, targetNodeID); err != nil {
			t.Fatalf("configure storage node: %v", err)
		}
		var legacyUserID, globalUserID int64
		if err := st.DB.QueryRowContext(ctx, `
			INSERT INTO users (username,display_name,auth_provider,home_node_id,status)
			VALUES ('cleanup-fail-'||$2,'Cleanup Fail','password',$1,'active') RETURNING id`,
			homeNodeID, kind).Scan(&legacyUserID); err != nil {
			t.Fatalf("insert legacy user: %v", err)
		}
		if err := st.DB.QueryRowContext(ctx, `
			INSERT INTO global_users (uuid,legacy_user_id,display_name,status)
			VALUES (gen_random_uuid(),$1,'Cleanup Fail','active') RETURNING id`,
			legacyUserID).Scan(&globalUserID); err != nil {
			t.Fatalf("insert global user: %v", err)
		}
		manifestHash := sha256.Sum256([]byte("cleanup-fail-manifest-" + kind))
		if _, err := st.DB.ExecContext(ctx, `
			INSERT INTO workflows (
			  id,operation_id,workflow_type,state,user_id,source_node_id,target_node_id,
			  activity_epoch,controller_generation,created_at,updated_at,finished_at
			) VALUES (
			  gen_random_uuid(),gen_random_uuid(),'snapshot','succeeded',$1,$2,$3,1,1,$4,$4,$4)`,
			globalUserID, homeNodeID, targetNodeID, now); err != nil {
			t.Fatalf("insert workflow: %v", err)
		}
		var manifestID string
		if err := st.DB.QueryRowContext(ctx, `
			INSERT INTO snapshot_manifests (
			  id,workflow_id,user_id,source_node_id,activity_epoch,format_version,
			  manifest_sha256,file_count,total_bytes,state,created_at
			) VALUES (
			  gen_random_uuid(),(SELECT id FROM workflows WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1),
			  $1,$2,1,1,$3,1,64,'immutable',$4) RETURNING id::text`,
			globalUserID, homeNodeID, manifestHash[:], now).Scan(&manifestID); err != nil {
			t.Fatalf("insert manifest: %v", err)
		}
		replicaID := "ffffffff-ffff-4fff-8fff-ffffffffff0" + map[bool]string{true: "1", false: "0"}[kind == "archive"]
		if _, err := st.DB.ExecContext(ctx, `
			INSERT INTO replica_copies (
			  id,user_id,node_id,snapshot_id,replica_kind,state,origin,is_authoritative,
			  compatibility_state,created_at,updated_at
			) VALUES ($1,$2,$3,$4,$5,'deleting','configured',false,'compatible',$6,$6)`,
			replicaID, globalUserID, targetNodeID, manifestID, kind, now); err != nil {
			t.Fatalf("insert replica copy: %v", err)
		}
		if _, err := st.DB.ExecContext(ctx, `
			INSERT INTO user_replicas (user_id,node_id,kind,state,last_sync_at)
			VALUES ($1,$2,$3,'deleting',$4)`, legacyUserID, targetNodeID, kind, now); err != nil {
			t.Fatalf("insert legacy replica: %v", err)
		}
		taskID := "cccccccc-cccc-4ccc-8ccc-cccccccccc0" + map[bool]string{true: "1", false: "0"}[kind == "archive"]
		operationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa0" + map[bool]string{true: "1", false: "0"}[kind == "archive"]
		if _, err := st.DB.ExecContext(ctx, `
			INSERT INTO replica_cleanup_tasks (
			  id,replica_id,user_id,legacy_user_id,node_id,snapshot_id,handle,replica_kind,
			  reason_code,state,attempt,next_attempt_at,operation_id,controller_generation,
			  lease_owner,lease_until,created_at,updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,'cleanup-fail',$7,'superseded_archive','running',1,$8,
			  $9,7,'cleanup-fail-worker',$10,$8,$8)`,
			taskID, replicaID, globalUserID, legacyUserID, targetNodeID, manifestID,
			kind, now, operationID, now.Add(time.Minute)); err != nil {
			t.Fatalf("insert cleanup task: %v", err)
		}

		task := ReplicaCleanupTask{
			ID: taskID, ReplicaID: replicaID, GlobalUserID: globalUserID,
			LegacyUserID: legacyUserID, NodeID: targetNodeID, SnapshotID: manifestID,
			Handle: "cleanup-fail", ReplicaKind: kind, ReasonCode: "superseded_archive",
			Attempt: 1, OperationID: operationID, ControllerGeneration: 7,
			LeaseOwner: "cleanup-fail-worker",
		}
		if err := st.FailReplicaCleanupTask(ctx, task, "replica_identity_unavailable", now.Add(time.Second)); err != nil {
			t.Fatalf("FailReplicaCleanupTask: %v", err)
		}

		var taskState, errorCode string
		var taskFinished time.Time
		if err := st.DB.QueryRowContext(ctx, `
			SELECT state,error_code,finished_at FROM replica_cleanup_tasks WHERE id=$1`, taskID).
			Scan(&taskState, &errorCode, &taskFinished); err != nil {
			t.Fatalf("read failed task: %v", err)
		}
		if taskState != "failed" || errorCode != "replica_identity_unavailable" || taskFinished.IsZero() {
			t.Fatalf("task state=%q error=%q finished=%v", taskState, errorCode, taskFinished)
		}
		var copyState, replicaState string
		if err := st.DB.QueryRowContext(ctx, `
			SELECT state FROM replica_copies WHERE id=$1`, replicaID).Scan(&copyState); err != nil {
			t.Fatalf("read replica copy: %v", err)
		}
		var replicaUpdated time.Time
		if err := st.DB.QueryRowContext(ctx, `
			SELECT state,updated_at FROM user_replicas
			WHERE user_id=$1 AND node_id=$2 AND kind=$3`, legacyUserID, targetNodeID, kind).
			Scan(&replicaState, &replicaUpdated); err != nil {
			t.Fatalf("read legacy replica: %v", err)
		}
		if copyState != wantState || replicaState != wantState {
			t.Fatalf("recovered copy=%q replica=%q, want %q", copyState, replicaState, wantState)
		}
		if replicaUpdated.IsZero() || replicaUpdated.Before(now) {
			t.Fatalf("user_replicas.updated_at not bumped: %v", replicaUpdated)
		}
		// The failure is terminal: replaying it must hit the state fence.
		if err := st.FailReplicaCleanupTask(ctx, task, "replica_identity_unavailable", now.Add(2*time.Second)); !errors.Is(err, ErrReplicaCleanupFence) {
			t.Fatalf("replay error=%v, want ErrReplicaCleanupFence", err)
		}
	}

	t.Run("archive returns to stale", func(t *testing.T) { run(t, "archive", "stale") })
	t.Run("hot standby returns to ready", func(t *testing.T) { run(t, "hot_standby", "ready") })
}
