package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"
)

const postgresIntegrationDSNEnv = "STCONTROL_TEST_POSTGRES_DSN"

// TestPostgresCriticalConcurrency is intentionally skipped in the fast unit
// suite. Acceptance/CI supplies a superuser test database through
// STCONTROL_TEST_POSTGRES_DSN; every run creates and drops an isolated schema.
func TestPostgresCriticalConcurrency(t *testing.T) {
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	var stores []*Store
	defer func() {
		for _, st := range stores {
			_ = st.Close()
		}
		cleanupSchema()
	}()

	stores = openStoresConcurrently(t, dsn, 8)
	assertAllMigrationsApplied(t, stores[0])
	assertLeadershipDoesNotBlockMigrationVerification(t, stores[0], dsn)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	generation, err := stores[0].GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatalf("GetActiveControllerGeneration: %v", err)
	}
	nodeA := insertIntegrationNode(t, stores[0], "writer-a")
	nodeB := insertIntegrationNode(t, stores[0], "writer-b")
	recoveryNode := insertIntegrationNode(t, stores[0], "controller-rebuild")

	t.Run("controller promotion only permits heartbeat recovery before credential rotation", func(t *testing.T) {
		generation = assertPostgresControllerRebuild(t, stores[0], recoveryNode, generation)
	})

	t.Run("single writer and operation binding", func(t *testing.T) {
		userID := insertIntegrationGlobalUser(t, stores[0], "lease-user")
		assertConcurrentSingleWriter(t, stores[0], userID, nodeA, nodeB, generation)
	})

	t.Run("one-use handoff redemption", func(t *testing.T) {
		userID := insertIntegrationGlobalUser(t, stores[0], "handoff-user")
		assertConcurrentHandoffRedemption(t, stores[0], userID, nodeA)
	})

	t.Run("confirmed disaster takeover is immutable and idempotent", func(t *testing.T) {
		assertPostgresIndependentTakeoverAudit(t, stores[0], generation)
	})

	t.Run("node lifecycle binds replay and retires only after durable drain", func(t *testing.T) {
		assertPostgresNodeLifecycleHardening(t, stores[0], nodeA)
	})

	t.Run("node retirement executor persists and atomically promotes home", func(t *testing.T) {
		assertPostgresNodeRetirementExecutor(t, stores[0])
	})

	t.Run("tiered replica integrity escalates light anomalies before quarantine", func(t *testing.T) {
		assertPostgresTieredReplicaIntegrity(t, stores[0], generation)
	})

	t.Run("external upgrade compatibility incidents isolate and require stable reopen", func(t *testing.T) {
		assertPostgresNodeCompatibilityIncident(t, stores[0])
	})

	t.Run("authoritative user data faults freeze one user and resume across generation change", func(t *testing.T) {
		assertPostgresUserDataFaultLifecycle(t, stores[0], generation)
	})

	t.Run("ten-thousand account inventory is durable and page bounded", func(t *testing.T) {
		assertPostgresAccountInventoryScale(t, stores[0], nodeA)
	})
}

func assertPostgresIndependentTakeoverAudit(t *testing.T, st *Store, generation int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	nodeID := insertIntegrationNode(t, st, "independent-takeover")
	fact := NodeControlModeFact{
		Mode: NodeModeManaged, ModeGeneration: 1, ControllerGeneration: generation,
		ObservedAt: now,
		ConfirmedTakeovers: []IndependentTakeoverFact{{
			OperationID: "76000000-0000-4000-8000-000000000001", Handle: "takeover-user",
			ParentClaimID: strings.Repeat("a", 64), ClaimID: strings.Repeat("b", 64),
			ControllerGeneration: generation, ActivityEpoch: 8, TakeoverSequence: 1,
			ConfirmedAt: now.Add(-time.Minute),
		}},
	}
	if _, err := st.ReconcileNodeControlMode(ctx, nodeID, fact); err != nil {
		t.Fatalf("record independent takeover: %v", err)
	}
	fact.ObservedAt = now.Add(time.Second)
	if _, err := st.ReconcileNodeControlMode(ctx, nodeID, fact); err != nil {
		t.Fatalf("replay independent takeover: %v", err)
	}
	var count int
	var firstObserved, lastObserved time.Time
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*),min(first_observed_at),max(last_observed_at)
		FROM independent_activity_takeovers WHERE operation_id=$1::uuid`,
		fact.ConfirmedTakeovers[0].OperationID).Scan(&count, &firstObserved, &lastObserved); err != nil {
		t.Fatalf("read independent takeover: %v", err)
	}
	if count != 1 || !firstObserved.Equal(now) || !lastObserved.Equal(fact.ObservedAt) {
		t.Fatalf("takeover count=%d first=%s last=%s", count, firstObserved, lastObserved)
	}
	fact.ConfirmedTakeovers[0].ClaimID = strings.Repeat("c", 64)
	fact.ObservedAt = now.Add(2 * time.Second)
	if _, err := st.ReconcileNodeControlMode(ctx, nodeID, fact); err == nil ||
		!strings.Contains(err.Error(), "operation conflict") {
		t.Fatalf("mutated takeover replay error=%v", err)
	}
}

func assertPostgresControllerRebuild(
	t *testing.T,
	st *Store,
	nodeID, previousGeneration int64,
) int64 {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO agent_credentials (
		  id,node_id,credential_version,credential_type,secret_ciphertext,
		  controller_generation,created_at
		) VALUES (
		  '73000000-0000-4000-8000-000000000001',$1,1,'hmac',$2,$3,$4
		)`, nodeID, []byte("old-controller-secret"), previousGeneration, now); err != nil {
		t.Fatalf("insert controller rebuild credential: %v", err)
	}
	nextGeneration, err := st.PromoteControllerEpoch(ctx, "postgres-rebuild-test", now.Add(time.Second))
	if err != nil || nextGeneration != previousGeneration+1 {
		t.Fatalf("promote controller generation=%d err=%v", nextGeneration, err)
	}
	status, err := st.GetLatestControllerRebuild(ctx)
	if err != nil || status == nil || status.State != "reconciling" ||
		status.Generation != nextGeneration || status.TotalNodes != 1 ||
		len(status.Nodes) != 1 || status.Nodes[0].State != "awaiting_heartbeat" {
		t.Fatalf("initial controller rebuild=%+v err=%v", status, err)
	}
	ready, err := st.IsControlPlaneReady(ctx)
	if err != nil || ready {
		t.Fatalf("control plane opened before rebuild: ready=%v err=%v", ready, err)
	}

	payloadDigest := sha256.Sum256([]byte("rebuild-fenced-command"))
	if _, err := st.EnqueueAgentCommand(ctx, EnqueueAgentCommandParams{
		ID: "73000000-0000-4000-8000-000000000002", OperationID: "73000000-0000-4000-8000-000000000003",
		NodeID: nodeID, CommandType: "verify_user", EncryptedPayload: json.RawMessage(`{"ciphertext":"test"}`),
		PayloadSHA256: payloadDigest[:], ExpiresAt: now.Add(time.Hour), Now: now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("enqueue generation-fenced rebuild command: %v", err)
	}
	lease, err := st.LeaseAgentCommand(
		ctx, nodeID, "rebuild-worker-old", now.Add(3*time.Second), time.Minute,
	)
	if err != nil || lease != nil {
		t.Fatalf("old credential node leased new generation command: lease=%+v err=%v", lease, err)
	}

	fact := NodeControlModeFact{
		Mode: NodeModeManaged, ModeGeneration: 1,
		ControllerGeneration: previousGeneration, ObservedAt: now.Add(4 * time.Second),
	}
	decision, err := st.ReconcileNodeControlModeAuthenticated(
		ctx, nodeID, fact, previousGeneration,
	)
	if err != nil || decision.ControllerGeneration != nextGeneration ||
		decision.DesiredMode != NodeModeManaged {
		t.Fatalf("old credential recovery heartbeat decision=%+v err=%v", decision, err)
	}
	status, err = st.GetLatestControllerRebuild(ctx)
	if err != nil || status.Nodes[0].State != "heartbeat_verified" {
		t.Fatalf("verified controller rebuild heartbeat=%+v err=%v", status, err)
	}
	intermediateGeneration := nextGeneration
	nextGeneration, err = st.PromoteControllerEpoch(
		ctx, "postgres-rebuild-restart-test", now.Add(5*time.Second),
	)
	if err != nil || nextGeneration != intermediateGeneration+1 {
		t.Fatalf("restart promotion generation=%d err=%v", nextGeneration, err)
	}
	var supersededState, supersededError string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state,error_code FROM controller_rebuild_operations
		WHERE generation=$1`, intermediateGeneration).
		Scan(&supersededState, &supersededError); err != nil ||
		supersededState != "failed" || supersededError != "superseded_by_generation" {
		t.Fatalf("superseded rebuild state=%q error=%q err=%v", supersededState, supersededError, err)
	}
	status, err = st.GetLatestControllerRebuild(ctx)
	if err != nil || status.State != "reconciling" ||
		status.Generation != nextGeneration || status.Nodes[0].State != "awaiting_heartbeat" {
		t.Fatalf("replacement controller rebuild=%+v err=%v", status, err)
	}
	// The Agent may have durably accepted the intermediate generation before
	// the Controller crashed, while still authenticating with the older active
	// credential. A still-higher rebuild must converge this state rather than
	// deadlock it.
	fact.ControllerGeneration = intermediateGeneration
	fact.ObservedAt = now.Add(6 * time.Second)
	decision, err = st.ReconcileNodeControlModeAuthenticated(
		ctx, nodeID, fact, previousGeneration,
	)
	if err != nil || decision.ControllerGeneration != nextGeneration {
		t.Fatalf("intermediate generation recovery decision=%+v err=%v", decision, err)
	}

	rotation, err := st.EnsureAgentCredentialRotation(ctx, EnsureAgentCredentialRotationParams{
		ID: "73000000-0000-4000-8000-000000000004", OperationID: "73000000-0000-4000-8000-000000000005",
		NodeID: nodeID, ProposedCiphertext: []byte("new-controller-secret"),
		ControllerGeneration: nextGeneration, Now: now.Add(7 * time.Second),
		ExpiresAt: now.Add(24 * time.Hour),
	})
	if err != nil || rotation == nil || rotation.CredentialVersion != 2 {
		t.Fatalf("controller rebuild rotation=%+v err=%v", rotation, err)
	}
	status, err = st.GetLatestControllerRebuild(ctx)
	if err != nil || status.Nodes[0].State != "rotation_pending" {
		t.Fatalf("pending controller rebuild rotation=%+v err=%v", status, err)
	}
	activatedGeneration, err := st.ActivateAgentCredentialRotation(
		ctx, nodeID, rotation.CredentialVersion, now.Add(8*time.Second),
	)
	if err != nil || activatedGeneration != nextGeneration {
		t.Fatalf("activate controller rebuild rotation generation=%d err=%v", activatedGeneration, err)
	}
	status, err = st.GetLatestControllerRebuild(ctx)
	if err != nil || status.State != "succeeded" || status.ReconciledNodes != 1 ||
		status.CompletedAt == nil || status.Nodes[0].State != "reconciled" {
		t.Fatalf("completed controller rebuild=%+v err=%v", status, err)
	}
	ready, err = st.IsControlPlaneReady(ctx)
	if err != nil || !ready {
		t.Fatalf("control plane remained closed after rebuild: ready=%v err=%v", ready, err)
	}
	if _, err := st.ReconcileNodeControlModeAuthenticated(
		ctx, nodeID, fact, previousGeneration,
	); !errors.Is(err, ErrStaleControllerMode) {
		t.Fatalf("old credential accepted after rebuild completion: %v", err)
	}

	secondDigest := sha256.Sum256([]byte("rebuild-current-command"))
	if _, err := st.EnqueueAgentCommand(ctx, EnqueueAgentCommandParams{
		ID: "73000000-0000-4000-8000-000000000006", OperationID: "73000000-0000-4000-8000-000000000007",
		NodeID: nodeID, CommandType: "verify_user", EncryptedPayload: json.RawMessage(`{"ciphertext":"test"}`),
		PayloadSHA256: secondDigest[:], ExpiresAt: now.Add(time.Hour), Now: now.Add(9 * time.Second),
	}); err != nil {
		t.Fatalf("enqueue post-rebuild command: %v", err)
	}
	lease, err = st.LeaseAgentCommand(
		ctx, nodeID, "rebuild-worker-current", now.Add(10*time.Second), time.Minute,
	)
	if err != nil || lease == nil || lease.ControllerGeneration != nextGeneration {
		t.Fatalf("current credential node could not lease command: lease=%+v err=%v", lease, err)
	}
	return nextGeneration
}

func assertPostgresUserDataFaultLifecycle(t *testing.T, st *Store, generation int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	activeGeneration, err := st.GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatalf("load active generation for data fault: %v", err)
	}
	generation = activeGeneration
	homeNodeID := insertIntegrationNode(t, st, "data-fault-home")
	otherNodeID := insertIntegrationNode(t, st, "data-fault-other")
	var adminID int64
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO admins (uuid,username,password_hash,status)
		VALUES ('74000000-0000-4000-8000-000000000001','data-fault-admin','test-hash','active')
		RETURNING id`).Scan(&adminID); err != nil {
		t.Fatalf("insert data-fault admin: %v", err)
	}
	var legacyUserID, globalUserID int64
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO users (uuid,username,display_name,auth_provider,home_node_id,status)
		VALUES ('74000000-0000-4000-8000-000000000002','data-fault-user',
		  'Data Fault User','password',$1,'active') RETURNING id`, homeNodeID).
		Scan(&legacyUserID); err != nil {
		t.Fatalf("insert data-fault legacy user: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO global_users (uuid,legacy_user_id,display_name,status)
		VALUES ('74000000-0000-4000-8000-000000000002',$1,'Data Fault User','active')
		RETURNING id`, legacyUserID).Scan(&globalUserID); err != nil {
		t.Fatalf("insert data-fault global user: %v", err)
	}
	var isolatedLegacyUserID, isolatedGlobalUserID int64
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO users (uuid,username,display_name,auth_provider,home_node_id,status)
		VALUES ('74000000-0000-4000-8000-000000000003','data-fault-isolated',
		  'Data Fault Isolated','password',$1,'active') RETURNING id`, homeNodeID).
		Scan(&isolatedLegacyUserID); err != nil {
		t.Fatalf("insert isolated legacy user: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO global_users (uuid,legacy_user_id,display_name,status)
		VALUES ('74000000-0000-4000-8000-000000000003',$1,'Data Fault Isolated','active')
		RETURNING id`, isolatedLegacyUserID).Scan(&isolatedGlobalUserID); err != nil {
		t.Fatalf("insert isolated global user: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO node_accounts (user_id,node_id,local_handle,status)
		VALUES ($1,$3,'data-fault-user','active'),($2,$3,'data-fault-isolated','active')`,
		globalUserID, isolatedGlobalUserID, homeNodeID); err != nil {
		t.Fatalf("insert data-fault node accounts: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,state,last_sync_at)
		VALUES ($1,$3,'home','ready',$4),($2,$3,'home','ready',$4)`,
		legacyUserID, isolatedLegacyUserID, homeNodeID, now); err != nil {
		t.Fatalf("insert data-fault legacy replicas: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO replica_copies (
		  id,user_id,node_id,replica_kind,state,origin,is_authoritative,
		  compatibility_state,created_at,updated_at
		) VALUES
		  ('74000000-0000-4000-8000-000000000004',$1,$3,'active','ready','primary',true,'compatible',$4,$4),
		  ('74000000-0000-4000-8000-000000000005',$2,$3,'active','ready','primary',true,'compatible',$4,$4)`,
		globalUserID, isolatedGlobalUserID, homeNodeID, now); err != nil {
		t.Fatalf("insert data-fault replica facts: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_activity_leases (
		  user_id,writer_node_id,session_id,activity_epoch,state,lease_expires_at,
		  last_page_heartbeat_at,last_request_at,in_flight_reads,in_flight_writes,
		  controller_generation,updated_at
		) VALUES ($1,$2,'74000000-0000-4000-8000-000000000006',6,'active',$3,$4,$4,2,1,$5,$4)`,
		globalUserID, homeNodeID, now.Add(time.Hour), now, generation); err != nil {
		t.Fatalf("insert data-fault writer lease: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO control_tickets (
		  jti,ticket_type,issuer,audience,subject,user_id,target_node_id,session_id,
		  activity_epoch,key_id,controller_generation,issued_at,not_before,expires_at,
		  operation_id,secret_hash
		) VALUES (
		  '74000000-0000-4000-8000-000000000007','user_login','https://controller.example',
		  'https://data-fault-home.example','data-fault-user',$1,$2,
		  '74000000-0000-4000-8000-000000000006',6,'controller-v1',$5,$4,$4,$3,
		  '74000000-0000-4000-8000-000000000008',decode(repeat('11',32),'hex'))`,
		globalUserID, homeNodeID, now.Add(time.Hour), now, generation); err != nil {
		t.Fatalf("insert data-fault control ticket: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO tickets (jti,user_id,node_id,expires_at)
		VALUES ('data-fault-legacy-ticket',$1,$2,$3)`,
		legacyUserID, homeNodeID, now.Add(time.Hour)); err != nil {
		t.Fatalf("insert data-fault legacy ticket: %v", err)
	}

	digest := sha256.Sum256([]byte("data-fault-request"))
	params := ReportUserDataFaultParams{
		OperationID:   "74000000-0000-4000-8000-000000000009",
		RequestDigest: digest[:], UserUUID: "74000000-0000-4000-8000-000000000002",
		ExpectedHomeNodeID: homeNodeID, ReasonCode: "user_database_corrupt",
		AdminID: adminID, Now: now.Add(time.Second),
	}
	status, err := st.ReportUserDataFault(ctx, params)
	if err != nil || status == nil || status.State != "reported" || status.ActivityEpoch != 6 || status.Replayed {
		t.Fatalf("report data fault: status=%+v err=%v", status, err)
	}
	replay, err := st.ReportUserDataFault(ctx, params)
	if err != nil || replay == nil || !replay.Replayed || replay.ID != status.ID {
		t.Fatalf("replay data fault: status=%+v err=%v", replay, err)
	}
	changedDigest := params
	otherDigest := sha256.Sum256([]byte("changed-data-fault-request"))
	changedDigest.RequestDigest = otherDigest[:]
	if _, err := st.ReportUserDataFault(ctx, changedDigest); !errors.Is(err, ErrUserDataFaultOperationConflict) {
		t.Fatalf("changed digest error=%v", err)
	}
	wrongHome := params
	wrongHome.OperationID = "74000000-0000-4000-8000-000000000010"
	wrongHome.ExpectedHomeNodeID = otherNodeID
	if _, err := st.ReportUserDataFault(ctx, wrongHome); !errors.Is(err, ErrUserDataFaultHomeConflict) {
		t.Fatalf("wrong home error=%v", err)
	}
	secondOpen := params
	secondOpen.OperationID = "74000000-0000-4000-8000-000000000011"
	if _, err := st.ReportUserDataFault(ctx, secondOpen); !errors.Is(err, ErrUserDataFaultAlreadyOpen) {
		t.Fatalf("second open fault error=%v", err)
	}

	var replicaState, copyState, isolatedState, leaseState string
	var controlRevokedAt, legacyUsedAt sql.NullTime
	var reads, writes int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state FROM user_replicas WHERE user_id=$1 AND node_id=$2`,
		legacyUserID, homeNodeID).Scan(&replicaState); err != nil {
		t.Fatalf("read corrupt legacy home: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state FROM replica_copies WHERE user_id=$1 AND node_id=$2`,
		globalUserID, homeNodeID).Scan(&copyState); err != nil {
		t.Fatalf("read corrupt normalized home: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state FROM user_replicas WHERE user_id=$1 AND node_id=$2`,
		isolatedLegacyUserID, homeNodeID).Scan(&isolatedState); err != nil {
		t.Fatalf("read isolated user home: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state,in_flight_reads,in_flight_writes FROM user_activity_leases WHERE user_id=$1`,
		globalUserID).Scan(&leaseState, &reads, &writes); err != nil {
		t.Fatalf("read ended writer lease: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT revoked_at FROM control_tickets WHERE user_id=$1`, globalUserID).
		Scan(&controlRevokedAt); err != nil {
		t.Fatalf("read revoked control ticket: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT used_at FROM tickets WHERE user_id=$1`, legacyUserID).
		Scan(&legacyUsedAt); err != nil {
		t.Fatalf("read invalidated legacy ticket: %v", err)
	}
	if replicaState != "corrupt" || copyState != "corrupt" || isolatedState != "ready" ||
		leaseState != "ended" || reads != 0 || writes != 0 || !controlRevokedAt.Valid || !legacyUsedAt.Valid {
		t.Fatalf("fault facts replica=%s copy=%s isolated=%s lease=%s reads=%d writes=%d control=%v legacy=%v",
			replicaState, copyState, isolatedState, leaseState, reads, writes,
			controlRevokedAt.Valid, legacyUsedAt.Valid)
	}

	workerID := "74000000-0000-4000-8000-000000000012"
	firstFreezeOperation := "74000000-0000-4000-8000-000000000013"
	claimAt := now.Add(2 * time.Second)
	task, err := st.ClaimUserDataFault(ctx, status.ID, firstFreezeOperation, workerID, claimAt, 2*time.Minute)
	if err != nil || task == nil || task.OperationID != firstFreezeOperation || task.ActivityEpoch != 6 {
		t.Fatalf("first fault claim: task=%+v err=%v", task, err)
	}
	promotionAt := now.Add(3 * time.Second)
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE controller_epochs SET state='revoked',revoked_at=$1 WHERE state='active'`,
		promotionAt); err != nil {
		t.Fatalf("revoke controller generation during freeze: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO controller_epochs (
		  generation,operation_id,controller_id,source,state,signing_key_version,activated_at
		) VALUES ($2,'74000000-0000-4000-8000-000000000014',
		  '74000000-0000-4000-8000-000000000015','data-fault-generation-test','active',2,$1)`,
		promotionAt, generation+1); err != nil {
		t.Fatalf("promote controller generation during freeze: %v", err)
	}
	if _, err := st.CompleteUserDataFaultFreeze(
		ctx, status.ID, firstFreezeOperation, workerID, promotionAt.Add(time.Second),
	); !errors.Is(err, ErrUserDataFaultState) {
		t.Fatalf("stale generation completion error=%v", err)
	}
	secondFreezeOperation := "74000000-0000-4000-8000-000000000016"
	reclaimAt := claimAt.Add(2*time.Minute + time.Second)
	task, err = st.ClaimUserDataFault(ctx, status.ID, secondFreezeOperation, workerID, reclaimAt, 2*time.Minute)
	if err != nil || task == nil || task.OperationID != secondFreezeOperation ||
		task.ControllerGeneration != generation+1 {
		t.Fatalf("generation-resumed fault claim: task=%+v err=%v", task, err)
	}
	if _, err := st.ReconcileProtectionStates(ctx, reclaimAt, time.Hour); err != nil {
		t.Fatalf("reconcile fault protection: %v", err)
	}
	completed, err := st.CompleteUserDataFaultFreeze(
		ctx, status.ID, secondFreezeOperation, workerID, reclaimAt.Add(time.Second),
	)
	if err != nil || completed == nil || completed.State != "recovery_unavailable" ||
		completed.ProtectionState != "unavailable" || completed.FrozenAt == nil {
		t.Fatalf("complete resumed data fault: status=%+v err=%v", completed, err)
	}
	if err := st.RetryUserDataFault(
		ctx, status.ID, secondFreezeOperation, workerID, "agent_unavailable",
		reclaimAt.Add(2*time.Second), time.Minute,
	); !errors.Is(err, ErrUserDataFaultState) {
		t.Fatalf("terminal frozen fault was made retryable: %v", err)
	}

	// A separate user with an immutable hot standby may recover only after the
	// node-local freeze is confirmed. The takeover and incident resolution are
	// committed in one serializable transaction.
	hotNodeID := insertIntegrationNode(t, st, "data-fault-hot-standby")
	var takeoverLegacyUserID, takeoverGlobalUserID int64
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO users (uuid,username,display_name,auth_provider,home_node_id,status)
		VALUES ('74100000-0000-4000-8000-000000000001','data-fault-takeover',
		  'Data Fault Takeover','password',$1,'active') RETURNING id`, homeNodeID).
		Scan(&takeoverLegacyUserID); err != nil {
		t.Fatalf("insert takeover legacy user: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO global_users (uuid,legacy_user_id,display_name,status)
		VALUES ('74100000-0000-4000-8000-000000000001',$1,'Data Fault Takeover','active')
		RETURNING id`, takeoverLegacyUserID).Scan(&takeoverGlobalUserID); err != nil {
		t.Fatalf("insert takeover global user: %v", err)
	}
	recoveryAt := reclaimAt.Add(10 * time.Second).Truncate(time.Microsecond)
	manifestHash := sha256.Sum256([]byte("data-fault-hot-standby-manifest"))
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO workflows (
		  id,operation_id,workflow_type,state,user_id,source_node_id,target_node_id,
		  activity_epoch,controller_generation,created_at,updated_at,finished_at
		) VALUES (
		  '74100000-0000-4000-8000-000000000002','74100000-0000-4000-8000-000000000003',
		  'snapshot','succeeded',$1,$2,$3,4,$4,$5,$5,$5)`,
		takeoverGlobalUserID, homeNodeID, hotNodeID, generation+1, recoveryAt); err != nil {
		t.Fatalf("insert takeover snapshot workflow: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO snapshot_manifests (
		  id,workflow_id,user_id,source_node_id,activity_epoch,format_version,
		  manifest_sha256,file_count,total_bytes,state,created_at
		) VALUES (
		  '74100000-0000-4000-8000-000000000004','74100000-0000-4000-8000-000000000002',
		  $1,$2,4,1,$3,2,128,'immutable',$4)`,
		takeoverGlobalUserID, homeNodeID, manifestHash[:], recoveryAt); err != nil {
		t.Fatalf("insert takeover snapshot manifest: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO node_accounts (user_id,node_id,local_handle,status)
		VALUES ($1,$2,'data-fault-takeover','active'),
		  ($1,$3,'data-fault-takeover','active')`,
		takeoverGlobalUserID, homeNodeID, hotNodeID); err != nil {
		t.Fatalf("insert takeover node accounts: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,state,last_sync_at)
		VALUES ($1,$2,'home','ready',$4),($1,$3,'hot_standby','ready',$4)`,
		takeoverLegacyUserID, homeNodeID, hotNodeID, recoveryAt); err != nil {
		t.Fatalf("insert takeover legacy replicas: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO replica_copies (
		  id,user_id,node_id,snapshot_id,replica_kind,state,origin,is_authoritative,
		  compatibility_state,published_at,verified_at,created_at,updated_at
		) VALUES
		  ('74100000-0000-4000-8000-000000000005',$1,$2,NULL,'active','ready',
		    'primary',true,'compatible',NULL,$4,$4,$4),
		  ('74100000-0000-4000-8000-000000000006',$1,$3,
		    '74100000-0000-4000-8000-000000000004','hot_standby','ready',
		    'temporary_failure_protection',false,'compatible',$4,$4,$4,$4)`,
		takeoverGlobalUserID, homeNodeID, hotNodeID, recoveryAt); err != nil {
		t.Fatalf("insert takeover normalized replicas: %v", err)
	}
	takeoverDigest := sha256.Sum256([]byte("data-fault-takeover-request"))
	takeoverFault, err := st.ReportUserDataFault(ctx, ReportUserDataFaultParams{
		OperationID:   "74100000-0000-4000-8000-000000000007",
		RequestDigest: takeoverDigest[:], UserUUID: "74100000-0000-4000-8000-000000000001",
		ExpectedHomeNodeID: homeNodeID, ReasonCode: "authoritative_integrity_mismatch",
		AdminID: adminID, Now: recoveryAt.Add(time.Second),
	})
	if err != nil || takeoverFault == nil {
		t.Fatalf("report takeover data fault: status=%+v err=%v", takeoverFault, err)
	}
	takeoverWorkerID := "74100000-0000-4000-8000-000000000008"
	takeoverFreezeOperation := "74100000-0000-4000-8000-000000000009"
	takeoverClaimAt := recoveryAt.Add(2 * time.Second)
	if task, err := st.ClaimUserDataFault(
		ctx, takeoverFault.ID, takeoverFreezeOperation, takeoverWorkerID,
		takeoverClaimAt, 2*time.Minute,
	); err != nil || task == nil || task.OperationID != takeoverFreezeOperation {
		t.Fatalf("claim takeover data fault: task=%+v err=%v", task, err)
	}
	if _, err := st.ReconcileProtectionStates(ctx, takeoverClaimAt, time.Hour); err != nil {
		t.Fatalf("project takeover recovery: %v", err)
	}
	takeoverFault, err = st.CompleteUserDataFaultFreeze(
		ctx, takeoverFault.ID, takeoverFreezeOperation, takeoverWorkerID,
		takeoverClaimAt.Add(time.Second),
	)
	if err != nil || takeoverFault.State != "recovery_available" ||
		takeoverFault.ProtectionState != "takeover_available" {
		t.Fatalf("publish takeover recovery: status=%+v err=%v", takeoverFault, err)
	}
	takeoverOperation := "74100000-0000-4000-8000-000000000010"
	takeoverRequestDigest := sha256.Sum256([]byte("confirmed-data-fault-takeover"))
	takeoverResult, err := st.ConfirmReplicaTakeover(ctx, ConfirmReplicaTakeoverParams{
		OperationID: takeoverOperation, RequestDigest: takeoverRequestDigest[:],
		GlobalUserID: takeoverGlobalUserID, TargetNodeID: hotNodeID,
		ExpectedRecoveryAt: recoveryAt, Now: takeoverClaimAt.Add(2 * time.Second),
	})
	if err != nil || takeoverResult.TargetNodeID != hotNodeID || takeoverResult.Replayed {
		t.Fatalf("confirm data-fault takeover: result=%+v err=%v", takeoverResult, err)
	}
	resolvedFault, err := st.GetUserDataFaultByID(ctx, takeoverFault.ID)
	if err != nil || resolvedFault.State != "resolved" ||
		resolvedFault.ResolutionKind != "takeover" ||
		resolvedFault.ResolutionOperationID != takeoverOperation || resolvedFault.ResolvedAt == nil {
		t.Fatalf("resolved takeover fault: status=%+v err=%v", resolvedFault, err)
	}
	var newHomeNodeID int64
	var oldHomeState, newHomeState, faultAlertState string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT legacy.home_node_id,old_home.state,new_home.state,alert.state
		FROM users legacy
		JOIN user_replicas old_home ON old_home.user_id=legacy.id AND old_home.node_id=$2
		JOIN user_replicas new_home ON new_home.user_id=legacy.id AND new_home.node_id=$3
		JOIN alerts alert ON alert.deduplication_key='user-data-fault:'||$1::text
		WHERE legacy.id=$4`, takeoverGlobalUserID, homeNodeID, hotNodeID, takeoverLegacyUserID).
		Scan(&newHomeNodeID, &oldHomeState, &newHomeState, &faultAlertState); err != nil {
		t.Fatalf("read completed takeover facts: %v", err)
	}
	if newHomeNodeID != hotNodeID || oldHomeState != "stale" || newHomeState != "ready" ||
		faultAlertState != "resolved" {
		t.Fatalf("takeover facts home=%d old=%s new=%s alert=%s",
			newHomeNodeID, oldHomeState, newHomeState, faultAlertState)
	}
	replayedTakeover, err := st.ConfirmReplicaTakeover(ctx, ConfirmReplicaTakeoverParams{
		OperationID: takeoverOperation, RequestDigest: takeoverRequestDigest[:],
		GlobalUserID: takeoverGlobalUserID, TargetNodeID: hotNodeID,
		ExpectedRecoveryAt: recoveryAt, Now: takeoverClaimAt.Add(3 * time.Second),
	})
	if err != nil || !replayedTakeover.Replayed {
		t.Fatalf("replay completed takeover: result=%+v err=%v", replayedTakeover, err)
	}
}

func newPostgresIntegrationSchema(t *testing.T) (string, func()) {
	t.Helper()
	baseDSN := strings.TrimSpace(os.Getenv(postgresIntegrationDSNEnv))
	if baseDSN == "" {
		t.Skipf("set %s to run real PostgreSQL tests", postgresIntegrationDSNEnv)
	}
	parsed, err := url.Parse(baseDSN)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatalf("%s must be a PostgreSQL URL: %v", postgresIntegrationDSNEnv, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	adminDB, err := sql.Open("postgres", baseDSN)
	if err != nil {
		t.Fatalf("open PostgreSQL integration database: %v", err)
	}
	if err := adminDB.PingContext(ctx); err != nil {
		_ = adminDB.Close()
		t.Fatalf("ping PostgreSQL integration database: %v", err)
	}
	schema := fmt.Sprintf("stcontrol_it_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := adminDB.ExecContext(ctx, `CREATE SCHEMA `+pq.QuoteIdentifier(schema)); err != nil {
		_ = adminDB.Close()
		t.Fatalf("create PostgreSQL integration schema: %v", err)
	}

	query := parsed.Query()
	query.Set("search_path", schema)
	query.Set("application_name", "stcontrol-integration")
	parsed.RawQuery = query.Encode()
	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := adminDB.ExecContext(cleanupCtx, `DROP SCHEMA `+pq.QuoteIdentifier(schema)+` CASCADE`); err != nil {
			t.Errorf("drop PostgreSQL integration schema: %v", err)
		}
		_ = adminDB.Close()
	}
	return parsed.String(), cleanup
}

func openStoresConcurrently(t *testing.T, dsn string, count int) []*Store {
	t.Helper()
	type result struct {
		store *Store
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, count)
	var wait sync.WaitGroup
	for range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			st, err := Open(ctx, dsn)
			results <- result{store: st, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	stores := make([]*Store, 0, count)
	for result := range results {
		if result.err != nil {
			for _, st := range stores {
				_ = st.Close()
			}
			t.Fatalf("concurrent Store.Open: %v", result.err)
		}
		stores = append(stores, result.store)
	}
	if len(stores) != count {
		t.Fatalf("opened %d PostgreSQL stores, want %d", len(stores), count)
	}
	return stores
}

func assertAllMigrationsApplied(t *testing.T, st *Store) {
	t.Helper()
	want, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	rows, err := st.DB.Query(`SELECT version,name,checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	defer rows.Close()
	var index int
	for rows.Next() {
		if index >= len(want) {
			t.Fatalf("database contains an unexpected migration at index %d", index)
		}
		var version int64
		var name, checksum string
		if err := rows.Scan(&version, &name, &checksum); err != nil {
			t.Fatalf("scan schema_migrations: %v", err)
		}
		if version != want[index].Version || name != want[index].Name || checksum != want[index].Checksum {
			t.Fatalf("migration[%d]=(%d,%q,%q), want (%d,%q,%q)", index,
				version, name, checksum, want[index].Version, want[index].Name, want[index].Checksum)
		}
		index++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate schema_migrations: %v", err)
	}
	if index != len(want) {
		t.Fatalf("database contains %d migrations, want %d", index, len(want))
	}
}

func assertLeadershipDoesNotBlockMigrationVerification(t *testing.T, leaderStore *Store, dsn string) {
	t.Helper()
	leadership, acquired, err := leaderStore.TryAcquireControllerLeadership(context.Background())
	if err != nil || !acquired {
		t.Fatalf("first leadership acquisition: acquired=%v err=%v", acquired, err)
	}
	defer leadership.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	passiveStore, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("passive Store.Open was blocked by active leadership: %v", err)
	}
	defer passiveStore.Close()
	otherLeadership, acquired, err := passiveStore.TryAcquireControllerLeadership(ctx)
	if err != nil || acquired || otherLeadership != nil {
		t.Fatalf("second leadership acquisition: leadership=%+v acquired=%v err=%v", otherLeadership, acquired, err)
	}

	if err := leadership.Close(); err != nil {
		t.Fatalf("release first leadership: %v", err)
	}
	replacement, acquired, err := passiveStore.TryAcquireControllerLeadership(ctx)
	if err != nil || !acquired || replacement == nil {
		t.Fatalf("replacement leadership acquisition: acquired=%v err=%v", acquired, err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatalf("release replacement leadership: %v", err)
	}
}

func insertIntegrationNode(t *testing.T, st *Store, name string) int64 {
	t.Helper()
	var id int64
	err := st.DB.QueryRow(`
		INSERT INTO nodes (
		  uuid,name,role,base_url,status,connectivity_state,operational_state,
		  capacity_state,compatibility_state
		) VALUES (gen_random_uuid(),$1,'compute',$2,'online','online','active','open','compatible')
		RETURNING id`, name, "https://"+name+".example").Scan(&id)
	if err != nil {
		t.Fatalf("insert integration node %q: %v", name, err)
	}
	return id
}

func insertIntegrationGlobalUser(t *testing.T, st *Store, displayName string) int64 {
	t.Helper()
	var id int64
	if err := st.DB.QueryRow(`
		INSERT INTO global_users (uuid,display_name,status)
		VALUES (gen_random_uuid(),$1,'active') RETURNING id`, displayName).Scan(&id); err != nil {
		t.Fatalf("insert integration global user: %v", err)
	}
	return id
}

func assertPostgresNodeCompatibilityIncident(t *testing.T, st *Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	nodeID := insertIntegrationNode(t, st, "compatibility-upgrade")
	fingerprintA := strings.Repeat("a", 64)
	fingerprintB := strings.Repeat("b", 64)

	heartbeat := func(at time.Time, state, reason, fingerprint, version string) {
		t.Helper()
		facts := testNodeHeartbeat(at)
		facts.CompatibilityState = state
		facts.CompatibilityReasonCode = reason
		facts.CompatibilityFingerprint = fingerprint
		facts.AgentVersion = version
		facts.TavernVersion = version
		facts.RegistrationPolicy.ObservedAt = at
		facts.RegistrationPolicy.ExpiresAt = at.Add(time.Minute)
		if err := st.UpdateNodeHeartbeat(ctx, nodeID, facts, testNodeCapacityPolicy()); err != nil {
			t.Fatalf("heartbeat at %s (%s): %v", at, state, err)
		}
	}
	assertNodeState := func(wantState, wantReason string) {
		t.Helper()
		node, err := st.GetNodeByID(ctx, nodeID)
		if err != nil || node == nil || node.CompatibilityState != wantState ||
			node.CompatibilityReasonCode.String != wantReason {
			t.Fatalf("node compatibility state=%+v err=%v, want %s/%s", node, err, wantState, wantReason)
		}
	}
	assertIncident := func(wantState, wantReason string, wantObservations int) {
		t.Helper()
		status, err := st.GetNodeCompatibilityIncidentStatus(ctx, nodeID)
		if err != nil || status == nil || status.State != wantState || status.ReasonCode != wantReason ||
			status.CompatibleObservations != wantObservations || status.RequiredObservations != 3 {
			t.Fatalf("incident=%+v err=%v, want %s/%s/%d", status, err, wantState, wantReason, wantObservations)
		}
	}

	heartbeat(now, "compatible", "", fingerprintA, "v1")
	assertNodeState("compatible", "")
	if status, err := st.GetNodeCompatibilityIncidentStatus(ctx, nodeID); err != nil || status != nil {
		t.Fatalf("initial enrollment created an incident: status=%+v err=%v", status, err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET status='offline',connectivity_state='offline' WHERE id=$1`, nodeID); err != nil {
		t.Fatalf("mark compatibility node offline: %v", err)
	}

	reconnectedAt := now.Add(10 * time.Second)
	heartbeat(reconnectedAt, "compatible", "", fingerprintA, "v1")
	assertNodeState("unknown", "upgrade_verifying")
	assertIncident("verifying", "node_reconnected", 1)
	restartedGeneration := advanceIntegrationControllerGeneration(t, st, now.Add(20*time.Second))
	heartbeat(now.Add(25*time.Second), "compatible", "", fingerprintA, "v1")
	assertIncident("verifying", "node_reconnected", 2)
	var incidentGeneration int64
	if err := st.DB.QueryRowContext(ctx, `
		SELECT controller_generation FROM node_compatibility_incidents
		WHERE node_id=$1 AND state='verifying'`, nodeID).Scan(&incidentGeneration); err != nil ||
		incidentGeneration != restartedGeneration {
		t.Fatalf("incident generation=%d err=%v, want restarted generation %d", incidentGeneration, err, restartedGeneration)
	}
	heartbeat(now.Add(40*time.Second), "compatible", "", fingerprintA, "v1")
	assertNodeState("compatible", "")
	assertIncident("resolved", "node_reconnected", 3)

	heartbeat(now.Add(50*time.Second), "compatible", "", fingerprintB, "v2")
	assertNodeState("unknown", "upgrade_verifying")
	assertIncident("verifying", "fingerprint_changed", 1)
	heartbeat(now.Add(60*time.Second), "incompatible", "missing_capability", fingerprintB, "v2")
	assertNodeState("incompatible", "missing_capability")
	assertIncident("isolated", "missing_capability", 0)
	heartbeat(now.Add(70*time.Second), "compatible", "", fingerprintB, "v2")
	assertIncident("verifying", "missing_capability", 1)
	heartbeat(now.Add(85*time.Second), "compatible", "", fingerprintB, "v2")
	assertIncident("verifying", "missing_capability", 2)
	heartbeat(now.Add(100*time.Second), "compatible", "", fingerprintB, "v2")
	assertNodeState("compatible", "")
	assertIncident("resolved", "missing_capability", 3)

	// A lost response may cause an exact heartbeat retry. It must be a no-op,
	// while an older observation must never regress the durable state.
	heartbeat(now.Add(100*time.Second), "compatible", "", fingerprintB, "v2")
	stale := testNodeHeartbeat(now.Add(99 * time.Second))
	stale.CompatibilityFingerprint = fingerprintB
	stale.AgentVersion = "v2"
	stale.TavernVersion = "v2"
	stale.RegistrationPolicy.ObservedAt = stale.ObservedAt
	stale.RegistrationPolicy.ExpiresAt = stale.ObservedAt.Add(time.Minute)
	if err := st.UpdateNodeHeartbeat(ctx, nodeID, stale, testNodeCapacityPolicy()); !errors.Is(err, ErrStaleNodeHeartbeat) {
		t.Fatalf("older heartbeat error=%v, want ErrStaleNodeHeartbeat", err)
	}
	assertNodeState("compatible", "")

	var resolvedIncidents, metricSamples, auditEvents int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM node_compatibility_incidents
		WHERE node_id=$1 AND state='resolved'`, nodeID).Scan(&resolvedIncidents); err != nil {
		t.Fatalf("count resolved compatibility incidents: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `SELECT count(*) FROM node_metric_samples WHERE node_id=$1`, nodeID).
		Scan(&metricSamples); err != nil {
		t.Fatalf("count compatibility metrics: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM audit_events
		WHERE target_type='node' AND target_id=$1::text AND action LIKE 'node-compatibility-%'`, nodeID).
		Scan(&auditEvents); err != nil {
		t.Fatalf("count compatibility audits: %v", err)
	}
	var alertState string
	var alertOccurrences int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state,occurrence_count FROM alerts
		WHERE deduplication_key='node-compatibility:'||$1::text`, nodeID).
		Scan(&alertState, &alertOccurrences); err != nil {
		t.Fatalf("read compatibility alert: %v", err)
	}
	if resolvedIncidents != 2 || metricSamples != 9 || auditEvents != 6 ||
		alertState != "resolved" || alertOccurrences != 3 {
		t.Fatalf("resolved=%d metrics=%d audits=%d alert=%s/%d",
			resolvedIncidents, metricSamples, auditEvents, alertState, alertOccurrences)
	}
}

func advanceIntegrationControllerGeneration(t *testing.T, st *Store, now time.Time) int64 {
	t.Helper()
	tx, err := st.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatalf("begin controller restart: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	var generation, signingKeyVersion int64
	if err := tx.QueryRow(`
		SELECT generation,signing_key_version FROM controller_epochs
		WHERE state='active' FOR UPDATE`).Scan(&generation, &signingKeyVersion); err != nil {
		t.Fatalf("lock active controller for restart: %v", err)
	}
	if _, err := tx.Exec(`
		UPDATE controller_epochs SET state='revoked',revoked_at=$2
		WHERE generation=$1 AND state='active'`, generation, now); err != nil {
		t.Fatalf("revoke controller for restart: %v", err)
	}
	next := generation + 1
	if _, err := tx.Exec(`
		INSERT INTO controller_epochs (
		  generation,operation_id,controller_id,source,state,signing_key_version,activated_at
		) VALUES ($1,gen_random_uuid(),gen_random_uuid(),'integration-restart','active',$2,$3)`,
		next, signingKeyVersion+1, now); err != nil {
		t.Fatalf("activate restarted controller: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit controller restart: %v", err)
	}
	return next
}

func assertPostgresTieredReplicaIntegrity(t *testing.T, st *Store, generation int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	homeNodeID := insertIntegrationNode(t, st, "integrity-home")
	storageNodeID := insertIntegrationNode(t, st, "integrity-storage")
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET role='storage',is_backup_target=true,
		  transfer_url='https://integrity-storage.example/transfer'
		WHERE id=$1`, storageNodeID); err != nil {
		t.Fatalf("configure integrity storage: %v", err)
	}
	var legacyUserID, globalUserID int64
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO users (username,display_name,auth_provider,home_node_id,status)
		VALUES ('integrity-user','Integrity User','password',$1,'active') RETURNING id`, homeNodeID).
		Scan(&legacyUserID); err != nil {
		t.Fatalf("insert integrity legacy user: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO global_users (uuid,legacy_user_id,display_name,status)
		VALUES ('73000000-0000-4000-8000-000000000009',$1,'Integrity User','active') RETURNING id`,
		legacyUserID).Scan(&globalUserID); err != nil {
		t.Fatalf("insert integrity global user: %v", err)
	}
	manifestHash := sha256.Sum256([]byte("tiered-integrity-manifest"))
	archiveHash := sha256.Sum256([]byte("tiered-integrity-archive"))
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO workflows (
		  id,operation_id,workflow_type,state,user_id,source_node_id,target_node_id,
		  activity_epoch,controller_generation,created_at,updated_at,finished_at
		) VALUES (
		  '73000000-0000-4000-8000-000000000002','73000000-0000-4000-8000-000000000003',
		  'snapshot','succeeded',$1,$2,$3,1,$4,$5,$5,$5
		)`, globalUserID, homeNodeID, storageNodeID, generation, now); err != nil {
		t.Fatalf("insert tiered integrity workflow: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO snapshot_manifests (
		  id,workflow_id,user_id,source_node_id,activity_epoch,format_version,
		  manifest_sha256,archive_sha256,file_count,total_bytes,state,created_at
		) VALUES (
		  '73000000-0000-4000-8000-000000000004','73000000-0000-4000-8000-000000000002',
		  $1,$2,1,1,$3,$4,2,30,'immutable',$5
		)`, globalUserID, homeNodeID, manifestHash[:], archiveHash[:], now); err != nil {
		t.Fatalf("insert tiered integrity manifest: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO replica_copies (
		  id,user_id,node_id,snapshot_id,replica_kind,state,origin,is_authoritative,
		  compatibility_state,published_at,verified_at,created_at,updated_at,
		  integrity_state,integrity_check_kind,integrity_next_check_at,integrity_deep_check_at,
		  integrity_last_light_at,integrity_last_deep_at
		) VALUES (
		  '73000000-0000-4000-8000-000000000001',$1,$2,
		  '73000000-0000-4000-8000-000000000004','archive','ready','configured',false,
		  'compatible',$3,$3,$3,$3,'verified','deep',$4,$5,$3,$3
		)`, globalUserID, storageNodeID, now, now.Add(-time.Hour), now.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("insert tiered integrity copy: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,state,data_version,checksum,size_bytes,last_sync_at)
		VALUES ($1,$2,'archive','ready',1,$3,30,$4)`,
		legacyUserID, storageNodeID, fmt.Sprintf("%x", manifestHash), now); err != nil {
		t.Fatalf("insert tiered integrity legacy replica: %v", err)
	}

	light, err := st.ClaimReplicaIntegrityTask(
		ctx, "73000000-0000-4000-8000-000000000005", now, time.Hour,
	)
	if err != nil || light == nil || light.CheckKind != "light" {
		t.Fatalf("claim light integrity task=%+v err=%v", light, err)
	}
	if err := st.FailReplicaIntegrityTask(
		ctx, light.ReplicaID, light.OperationID, "replica_integrity_mismatch", true,
		now.Add(time.Second), time.Hour,
	); !errors.Is(err, ErrReplicaIntegrityState) {
		t.Fatalf("light task direct corruption error=%v", err)
	}
	if err := st.EscalateReplicaIntegrityTask(
		ctx, light.ReplicaID, light.OperationID, "lightweight_integrity_anomaly", now.Add(time.Second),
	); err != nil {
		t.Fatalf("escalate light integrity task: %v", err)
	}
	var copyState, integrityState string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state,integrity_state FROM replica_copies WHERE id=$1`, light.ReplicaID).
		Scan(&copyState, &integrityState); err != nil || copyState != "ready" || integrityState != "due" {
		t.Fatalf("light escalation copy=%q integrity=%q err=%v", copyState, integrityState, err)
	}

	deep, err := st.ClaimReplicaIntegrityTask(
		ctx, "73000000-0000-4000-8000-000000000006", now.Add(2*time.Second), time.Hour,
	)
	if err != nil || deep == nil || deep.CheckKind != "deep" {
		t.Fatalf("claim escalated deep integrity task=%+v err=%v", deep, err)
	}
	if err := st.CompleteReplicaIntegrityTask(ctx, CompleteReplicaIntegrityParams{
		ReplicaID: deep.ReplicaID, OperationID: deep.OperationID, SnapshotID: deep.SnapshotID,
		ManifestSHA256: deep.ManifestSHA256, ArchiveSHA256: deep.ArchiveSHA256,
		FileCount: deep.FileCount, TotalBytes: deep.TotalBytes, CheckKind: "deep",
		Now: now.Add(3 * time.Second), NextCheckAfter: ReplicaIntegrityLightInterval,
		NextDeepAfter: ReplicaIntegrityDeepInterval,
	}); err != nil {
		t.Fatalf("complete deep integrity task: %v", err)
	}
	var lastDeep time.Time
	if err := st.DB.QueryRowContext(ctx, `
		SELECT integrity_last_deep_at FROM replica_copies WHERE id=$1`, deep.ReplicaID).Scan(&lastDeep); err != nil ||
		!lastDeep.Equal(now.Add(3*time.Second)) {
		t.Fatalf("deep completion at=%v err=%v", lastDeep, err)
	}

	if _, err := st.DB.ExecContext(ctx, `
		UPDATE replica_copies SET integrity_next_check_at=$2 WHERE id=$1`,
		deep.ReplicaID, now.Add(4*time.Second)); err != nil {
		t.Fatalf("schedule next light integrity task: %v", err)
	}
	lightAgain, err := st.ClaimReplicaIntegrityTask(
		ctx, "73000000-0000-4000-8000-000000000007", now.Add(4*time.Second), time.Hour,
	)
	if err != nil || lightAgain == nil || lightAgain.CheckKind != "light" {
		t.Fatalf("claim next light integrity task=%+v err=%v", lightAgain, err)
	}
	if err := st.CompleteReplicaIntegrityTask(ctx, CompleteReplicaIntegrityParams{
		ReplicaID: lightAgain.ReplicaID, OperationID: lightAgain.OperationID, SnapshotID: lightAgain.SnapshotID,
		ManifestSHA256: lightAgain.ManifestSHA256, ArchiveSHA256: lightAgain.ArchiveSHA256,
		FileCount: lightAgain.FileCount, TotalBytes: lightAgain.TotalBytes, CheckKind: "light",
		Now: now.Add(5 * time.Second), NextCheckAfter: ReplicaIntegrityLightInterval,
		NextDeepAfter: ReplicaIntegrityDeepInterval,
	}); err != nil {
		t.Fatalf("complete next light integrity task: %v", err)
	}
	var lastDeepAfterLight time.Time
	if err := st.DB.QueryRowContext(ctx, `
		SELECT integrity_last_deep_at FROM replica_copies WHERE id=$1`, lightAgain.ReplicaID).
		Scan(&lastDeepAfterLight); err != nil || !lastDeepAfterLight.Equal(lastDeep) {
		t.Fatalf("light check changed deep cursor: before=%v after=%v err=%v", lastDeep, lastDeepAfterLight, err)
	}

	if _, err := st.DB.ExecContext(ctx, `
		UPDATE replica_copies SET integrity_next_check_at=$2,integrity_deep_check_at=$2 WHERE id=$1`,
		deep.ReplicaID, now.Add(6*time.Second)); err != nil {
		t.Fatalf("schedule corruption deep check: %v", err)
	}
	corrupt, err := st.ClaimReplicaIntegrityTask(
		ctx, "73000000-0000-4000-8000-000000000008", now.Add(6*time.Second), time.Hour,
	)
	if err != nil || corrupt == nil || corrupt.CheckKind != "deep" {
		t.Fatalf("claim corruption deep task=%+v err=%v", corrupt, err)
	}
	if err := st.FailReplicaIntegrityTask(
		ctx, corrupt.ReplicaID, corrupt.OperationID, "replica_integrity_mismatch", true,
		now.Add(7*time.Second), time.Hour,
	); err != nil {
		t.Fatalf("quarantine corrupt deep replica: %v", err)
	}
	var legacyState, alertSeverity string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT copy.state,copy.integrity_state,legacy.state,alert.severity
		FROM replica_copies copy
		JOIN user_replicas legacy ON legacy.user_id=$2 AND legacy.node_id=copy.node_id
		JOIN alerts alert ON alert.deduplication_key='replica-integrity:'||copy.id::text
		WHERE copy.id=$1`, corrupt.ReplicaID, legacyUserID).
		Scan(&copyState, &integrityState, &legacyState, &alertSeverity); err != nil ||
		copyState != "corrupt" || integrityState != "corrupt" || legacyState != "corrupt" || alertSeverity != "critical" {
		t.Fatalf("deep corruption copy=%q integrity=%q legacy=%q alert=%q err=%v",
			copyState, integrityState, legacyState, alertSeverity, err)
	}
}

func assertPostgresAccountInventoryScale(t *testing.T, st *Store, nodeID int64) {
	t.Helper()
	var adminID int64
	if err := st.DB.QueryRow(`
		INSERT INTO admins (uuid,username,password_hash,status)
		VALUES ('70000000-0000-4000-8000-000000000001','inventory-admin','test-hash','active')
		RETURNING id`).Scan(&adminID); err != nil {
		t.Fatalf("insert inventory administrator: %v", err)
	}
	candidates := make([]AccountImportCandidateInput, 0, maxAccountImportCandidates)
	for index := 1; index <= maxAccountImportCandidates; index++ {
		candidates = append(candidates, AccountImportCandidateInput{
			ID:          fmt.Sprintf("60000000-0000-4000-8000-%012x", index),
			LocalUserID: fmt.Sprintf("local-%05d", index),
			LocalHandle: fmt.Sprintf("user-%05d", index),
			SizeBytes:   int64(index), DirectoryFingerprint: strings.Repeat("a", 64),
			Source: "directory_fallback", AccountKind: "unknown",
		})
	}
	digest := sha256.Sum256([]byte("ten-thousand-account-inventory"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	started := time.Now()
	result, err := st.IngestAccountImportBatch(ctx, CreateAccountImportBatchParams{
		ID:          "80000000-0000-4000-8000-000000000001",
		OperationID: "80000000-0000-4000-8000-000000000002",
		NodeID:      nodeID, InventoryDigest: digest[:], Source: "directory_fallback",
		CreatedByAdminID: adminID, Candidates: candidates, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("ingest ten-thousand account inventory: %v", err)
	}
	if result == nil || result.Batch.CandidateCount != maxAccountImportCandidates ||
		len(result.Candidates) != MaxAccountImportPageSize || !result.HasMore ||
		result.NextCandidateOffset != MaxAccountImportPageSize {
		t.Fatalf("bounded first inventory page=%+v", result)
	}
	last, err := st.GetAccountImportBatchPage(
		ctx, "80000000-0000-4000-8000-000000000001", maxAccountImportCandidates-10, 10,
	)
	if err != nil || last == nil || len(last.Candidates) != 10 || last.HasMore ||
		last.Candidates[0].LocalHandle != "user-09991" || last.Candidates[9].LocalHandle != "user-10000" {
		t.Fatalf("last inventory page=%+v err=%v", last, err)
	}
	var persisted int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM account_import_candidates WHERE batch_id=$1`,
		"80000000-0000-4000-8000-000000000001").Scan(&persisted); err != nil ||
		persisted != maxAccountImportCandidates {
		t.Fatalf("persisted inventory candidates=%d err=%v", persisted, err)
	}
	t.Logf("persisted and paged %d inventory candidates in %s", persisted, time.Since(started))
}

func assertPostgresNodeRetirementExecutor(t *testing.T, st *Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Microsecond)
	var adminID int64
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO admins (uuid,username,password_hash,status)
		VALUES ('72000000-0000-4000-8000-000000000001','retirement-admin','test-hash','active')
		RETURNING id`).Scan(&adminID); err != nil {
		t.Fatalf("insert retirement administrator: %v", err)
	}

	emptyNodeID := insertIntegrationNode(t, st, "retirement-empty")
	emptyDrain := TransitionNodeLifecycleParams{
		OperationID: "72000000-0000-4000-8000-000000000002", NodeID: emptyNodeID,
		ToState: "draining", ReasonCode: "operator_draining", AdminID: adminID, Now: now,
	}
	if state, err := st.TransitionNodeLifecycle(ctx, emptyDrain); err != nil || state != "draining" {
		t.Fatalf("start empty retirement: state=%q err=%v", state, err)
	}
	emptyStatus, err := st.GetNodeRetirementStatus(ctx, emptyNodeID)
	if err != nil || emptyStatus == nil || emptyStatus.State != "verifying" || emptyStatus.TotalItems != 0 {
		t.Fatalf("empty retirement status=%+v err=%v", emptyStatus, err)
	}
	workerID := "72000000-0000-4000-8000-000000000003"
	claimed, err := st.ClaimNodeRetirement(
		ctx, emptyStatus.ID, workerID, "72000000-0000-4000-8000-000000000004",
		now.Add(time.Second), 2*time.Minute,
	)
	if err != nil || !claimed {
		t.Fatalf("claim empty retirement: claimed=%v err=%v", claimed, err)
	}
	reentrantClaim, err := st.ClaimNodeRetirement(
		ctx, emptyStatus.ID, workerID, "72000000-0000-4000-8000-000000000025",
		now.Add(1250*time.Millisecond), 2*time.Minute,
	)
	if err != nil || reentrantClaim {
		t.Fatalf("reentrant retirement claim=%v err=%v", reentrantClaim, err)
	}
	competingClaim, err := st.ClaimNodeRetirement(
		ctx, emptyStatus.ID, "72000000-0000-4000-8000-000000000023",
		"72000000-0000-4000-8000-000000000024", now.Add(1500*time.Millisecond), 2*time.Minute,
	)
	if err != nil || competingClaim {
		t.Fatalf("competing retirement claim=%v err=%v", competingClaim, err)
	}
	if err := st.ReleaseNodeRetirement(ctx, emptyStatus.ID, workerID); err != nil {
		t.Fatalf("release empty retirement: %v", err)
	}
	claimed, err = st.ClaimNodeRetirement(
		ctx, emptyStatus.ID, workerID, "72000000-0000-4000-8000-000000000005",
		now.Add(2*time.Second), 2*time.Minute,
	)
	if err != nil || !claimed {
		t.Fatalf("reclaim empty retirement: claimed=%v err=%v", claimed, err)
	}
	finalized, err := st.FinalizeNodeRetirement(
		ctx, emptyStatus.ID, "72000000-0000-4000-8000-000000000006", now.Add(3*time.Second),
	)
	if err != nil || !finalized {
		t.Fatalf("finalize empty retirement: finalized=%v err=%v", finalized, err)
	}
	finalized, err = st.FinalizeNodeRetirement(
		ctx, emptyStatus.ID, "72000000-0000-4000-8000-000000000006", now.Add(3*time.Second),
	)
	if err != nil || !finalized {
		t.Fatalf("replay empty retirement: finalized=%v err=%v", finalized, err)
	}
	var emptyNodeState, emptyOperationState string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT node.operational_state,operation.state
		FROM nodes node JOIN node_retirement_operations operation ON operation.node_id=node.id
		WHERE node.id=$1`, emptyNodeID).Scan(&emptyNodeState, &emptyOperationState); err != nil ||
		emptyNodeState != "decommissioned" || emptyOperationState != "decommissioned" {
		t.Fatalf("empty final state node=%q operation=%q err=%v", emptyNodeState, emptyOperationState, err)
	}

	sourceNodeID := insertIntegrationNode(t, st, "retirement-source")
	targetNodeID := insertIntegrationNode(t, st, "retirement-target")
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET transfer_url='https://retirement.example/transfer'
		WHERE id IN ($1,$2)`, sourceNodeID, targetNodeID); err != nil {
		t.Fatalf("configure retirement data plane: %v", err)
	}
	var legacyUserID, globalUserID int64
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO users (username,display_name,auth_provider,home_node_id,status)
		VALUES ('retirement-user','Retirement User','password',$1,'active') RETURNING id`, sourceNodeID).
		Scan(&legacyUserID); err != nil {
		t.Fatalf("insert retirement legacy user: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO global_users (uuid,legacy_user_id,display_name,status)
		VALUES ('72000000-0000-4000-8000-000000000007',$1,'Retirement User','active') RETURNING id`,
		legacyUserID).Scan(&globalUserID); err != nil {
		t.Fatalf("insert retirement global user: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO node_accounts (
		  user_id,node_id,local_handle,local_user_id,status,password_material_version,
		  password_hash,password_salt
		) VALUES ($1,$2,'retirement-user','source-user','active',3,'retirement-node-hash','retirement-node-salt')`,
		globalUserID, sourceNodeID); err != nil {
		t.Fatalf("insert retirement node accounts: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,state)
		VALUES ($1,$2,'home','ready'),($1,$3,'hot_standby','empty')`,
		legacyUserID, sourceNodeID, targetNodeID); err != nil {
		t.Fatalf("insert retirement legacy replicas: %v", err)
	}
	homeDrain := TransitionNodeLifecycleParams{
		OperationID: "72000000-0000-4000-8000-000000000008", NodeID: sourceNodeID,
		ToState: "draining", ReasonCode: "operator_draining", AdminID: adminID, Now: now.Add(4 * time.Second),
	}
	if state, err := st.TransitionNodeLifecycle(ctx, homeDrain); err != nil || state != "draining" {
		t.Fatalf("start home retirement: state=%q err=%v", state, err)
	}
	homeStatus, err := st.GetNodeRetirementStatus(ctx, sourceNodeID)
	if err != nil || homeStatus == nil || homeStatus.TotalItems != 1 || homeStatus.PendingItems != 1 {
		t.Fatalf("home retirement status=%+v err=%v", homeStatus, err)
	}
	claimed, err = st.ClaimNodeRetirement(
		ctx, homeStatus.ID, workerID, "72000000-0000-4000-8000-000000000009",
		now.Add(5*time.Second), 2*time.Minute,
	)
	if err != nil || !claimed {
		t.Fatalf("claim home retirement: claimed=%v err=%v", claimed, err)
	}
	item, err := st.GetNextNodeRetirementItem(ctx, homeStatus.ID, now.Add(5*time.Second))
	if err != nil || item == nil || item.ItemKind != "authoritative_home" || item.UserBusy {
		t.Fatalf("home retirement item=%+v err=%v", item, err)
	}
	capabilityHash := sha256.Sum256([]byte("retirement-capability"))
	workflowID := "72000000-0000-4000-8000-000000000010"
	snapshotID := "72000000-0000-4000-8000-000000000012"
	homeSnapshotParams := CreateSnapshotWorkflowParams{
		WorkflowID: workflowID, OperationID: "72000000-0000-4000-8000-000000000011",
		SnapshotID: snapshotID, CapabilityID: "72000000-0000-4000-8000-000000000013",
		CapabilityHash: capabilityHash[:], LegacyUserID: legacyUserID, GlobalUserID: globalUserID,
		SourceNodeID: sourceNodeID, TargetNodeID: targetNodeID, DestinationKind: "hot_standby",
		RetirementItemID: item.ID, RetirementTrigger: "node_retirement",
		CapabilityExpires: now.Add(time.Hour), Now: now.Add(6 * time.Second),
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET capacity_state='full' WHERE id=$1`, targetNodeID); err != nil {
		t.Fatalf("saturate retirement target: %v", err)
	}
	if _, err := st.CreateSnapshotWorkflow(ctx, homeSnapshotParams); !errors.Is(err, ErrNodeRetirementState) {
		t.Fatalf("full retirement target error=%v", err)
	}
	var rejectedWorkflowCount, rejectedJobCount int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT (SELECT count(*) FROM workflows WHERE id=$1),
		  (SELECT count(*) FROM backup_jobs WHERE trigger='node_retirement' AND user_id=$2)`,
		workflowID, legacyUserID).Scan(&rejectedWorkflowCount, &rejectedJobCount); err != nil ||
		rejectedWorkflowCount != 0 || rejectedJobCount != 0 {
		t.Fatalf("rejected target artifacts workflows=%d jobs=%d err=%v",
			rejectedWorkflowCount, rejectedJobCount, err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET capacity_state='open' WHERE id=$1`, targetNodeID); err != nil {
		t.Fatalf("restore retirement target capacity: %v", err)
	}
	workflow, err := st.CreateSnapshotWorkflow(ctx, homeSnapshotParams)
	if err != nil || workflow.WorkflowID != workflowID {
		t.Fatalf("create retirement snapshot workflow=%+v err=%v", workflow, err)
	}
	provision, err := st.GetWorkflowTargetAccountProvision(ctx, workflowID)
	if err != nil || provision == nil || provision.Status != "pending" || provision.TargetNodeID != targetNodeID ||
		provision.AccountVersion != 1 || provision.PasswordHash != "retirement-node-hash" ||
		provision.PasswordSalt != "retirement-node-salt" {
		t.Fatalf("retirement target provision=%+v err=%v", provision, err)
	}
	if err := st.CompleteWorkflowTargetAccountProvision(
		ctx, workflowID, provision.AccountVersion, "target-user", now.Add(6500*time.Millisecond),
	); err != nil {
		t.Fatalf("activate retirement target account: %v", err)
	}
	provision, err = st.GetWorkflowTargetAccountProvision(ctx, workflowID)
	if err != nil || provision == nil || provision.Status != "active" || provision.LocalUserID != "target-user" {
		t.Fatalf("active retirement target provision=%+v err=%v", provision, err)
	}
	if err := st.SetSnapshotWorkflowState(ctx, workflowID, "scheduled", "quiescing", now.Add(7*time.Second)); err != nil {
		t.Fatalf("quiesce retirement snapshot: %v", err)
	}
	for index, progress := range []struct {
		state  string
		nodeID int64
	}{
		{state: "drained", nodeID: sourceNodeID},
		{state: "snapshotting", nodeID: sourceNodeID},
		{state: "transferring", nodeID: sourceNodeID},
		{state: "verifying", nodeID: targetNodeID},
		{state: "publishing", nodeID: targetNodeID},
	} {
		if err := st.SetSnapshotWorkflowProgress(
			ctx, workflowID, snapshotID, progress.nodeID, progress.state,
			now.Add(time.Duration(8+index)*time.Second),
		); err != nil {
			t.Fatalf("advance retirement snapshot to %s: %v", progress.state, err)
		}
	}
	manifestHash := sha256.Sum256([]byte("retirement-manifest"))
	archiveHash := sha256.Sum256([]byte("retirement-archive"))
	if _, err := st.CompleteSnapshotWorkflow(ctx, CompleteSnapshotWorkflowParams{
		WorkflowID: workflowID, SnapshotID: snapshotID, CapabilityHash: capabilityHash[:],
		TargetNodeID: targetNodeID, ReplicaKind: "hot_standby", ReplicaOrigin: "migration",
		ManifestSHA256: manifestHash[:], ArchiveSHA256: archiveHash[:], FileCount: 3, TotalBytes: 1024,
		Now: now.Add(14 * time.Second),
	}); err != nil {
		t.Fatalf("publish retirement snapshot: %v", err)
	}
	if err := st.CompleteNodeRetirementHomeMigration(ctx, item.ID, workflowID, now.Add(15*time.Second)); err != nil {
		t.Fatalf("promote retirement target: %v", err)
	}
	if err := st.CompleteNodeRetirementHomeMigration(ctx, item.ID, workflowID, now.Add(15*time.Second)); err != nil {
		t.Fatalf("replay retirement promotion: %v", err)
	}
	var homeNodeID int64
	var sourceReplicaState, targetReplicaKind, targetReplicaState, copyKind, copyOrigin string
	var authoritative bool
	if err := st.DB.QueryRowContext(ctx, `
		SELECT legacy.home_node_id,source_replica.state,target_replica.kind,target_replica.state,
		  copy.replica_kind,copy.origin,copy.is_authoritative
		FROM users legacy
		JOIN user_replicas source_replica ON source_replica.user_id=legacy.id AND source_replica.node_id=$2
		JOIN user_replicas target_replica ON target_replica.user_id=legacy.id AND target_replica.node_id=$3
		JOIN replica_copies copy ON copy.user_id=$4 AND copy.node_id=$3
		WHERE legacy.id=$1`, legacyUserID, sourceNodeID, targetNodeID, globalUserID).Scan(
		&homeNodeID, &sourceReplicaState, &targetReplicaKind, &targetReplicaState,
		&copyKind, &copyOrigin, &authoritative,
	); err != nil || homeNodeID != targetNodeID || sourceReplicaState != "stale" ||
		targetReplicaKind != "home" || targetReplicaState != "ready" || copyKind != "active" ||
		copyOrigin != "migration" || !authoritative {
		t.Fatalf("promoted home=%d source=%q target=%q/%q copy=%q/%q authoritative=%v err=%v",
			homeNodeID, sourceReplicaState, targetReplicaKind, targetReplicaState,
			copyKind, copyOrigin, authoritative, err)
	}
	if next, err := st.GetNextNodeRetirementItem(ctx, homeStatus.ID, now.Add(16*time.Second)); err != nil || next != nil {
		t.Fatalf("completed retirement next=%+v err=%v", next, err)
	}
	finalized, err = st.FinalizeNodeRetirement(
		ctx, homeStatus.ID, "72000000-0000-4000-8000-000000000014", now.Add(17*time.Second),
	)
	if err != nil || !finalized {
		t.Fatalf("finalize home retirement: finalized=%v err=%v", finalized, err)
	}
	homeStatus, err = st.GetNodeRetirementStatus(ctx, sourceNodeID)
	if err != nil || homeStatus.State != "decommissioned" || homeStatus.CompletedItems != 1 {
		t.Fatalf("completed home retirement status=%+v err=%v", homeStatus, err)
	}

	retiringStorageID := insertIntegrationNode(t, st, "retirement-storage-old")
	replacementStorageID := insertIntegrationNode(t, st, "retirement-storage-new")
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET role='storage',is_backup_target=true,
		  transfer_url='https://retirement-storage.example/transfer'
		WHERE id IN ($1,$2)`, retiringStorageID, replacementStorageID); err != nil {
		t.Fatalf("configure retirement storage nodes: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO replica_copies (
		  id,user_id,node_id,snapshot_id,replica_kind,state,origin,is_authoritative,
		  compatibility_state,published_at,verified_at,created_at,updated_at
		) VALUES (
		  '72000000-0000-4000-8000-000000000015',$1,$2,$3,'archive','ready','configured',false,
		  'compatible',$4,$4,$4,$4
		)`, globalUserID, retiringStorageID, snapshotID, now.Add(18*time.Second)); err != nil {
		t.Fatalf("insert retiring archive copy: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,state)
		VALUES ($1,$2,'archive','ready'),($1,$3,'archive','empty')`,
		legacyUserID, retiringStorageID, replacementStorageID); err != nil {
		t.Fatalf("insert retiring archive read models: %v", err)
	}
	storageDrain := TransitionNodeLifecycleParams{
		OperationID: "72000000-0000-4000-8000-000000000016", NodeID: retiringStorageID,
		ToState: "draining", ReasonCode: "operator_draining", AdminID: adminID, Now: now.Add(19 * time.Second),
	}
	if state, err := st.TransitionNodeLifecycle(ctx, storageDrain); err != nil || state != "draining" {
		t.Fatalf("start storage retirement: state=%q err=%v", state, err)
	}
	storageStatus, err := st.GetNodeRetirementStatus(ctx, retiringStorageID)
	if err != nil || storageStatus == nil || storageStatus.TotalItems != 1 || storageStatus.PendingItems != 1 {
		t.Fatalf("storage retirement status=%+v err=%v", storageStatus, err)
	}
	claimed, err = st.ClaimNodeRetirement(
		ctx, storageStatus.ID, workerID, "72000000-0000-4000-8000-000000000017",
		now.Add(20*time.Second), 2*time.Minute,
	)
	if err != nil || !claimed {
		t.Fatalf("claim storage retirement: claimed=%v err=%v", claimed, err)
	}
	storageItem, err := st.GetNextNodeRetirementItem(ctx, storageStatus.ID, now.Add(20*time.Second))
	if err != nil || storageItem == nil || storageItem.ItemKind != "archive_replica" ||
		storageItem.HomeNodeID != targetNodeID || storageItem.UserBusy {
		t.Fatalf("storage retirement item=%+v err=%v", storageItem, err)
	}
	storageCapabilityHash := sha256.Sum256([]byte("storage-retirement-capability"))
	storageWorkflowID := "72000000-0000-4000-8000-000000000018"
	storageSnapshotID := "72000000-0000-4000-8000-000000000020"
	storageWorkflow, err := st.CreateSnapshotWorkflow(ctx, CreateSnapshotWorkflowParams{
		WorkflowID: storageWorkflowID, OperationID: "72000000-0000-4000-8000-000000000019",
		SnapshotID: storageSnapshotID, CapabilityID: "72000000-0000-4000-8000-000000000021",
		CapabilityHash: storageCapabilityHash[:], LegacyUserID: legacyUserID, GlobalUserID: globalUserID,
		SourceNodeID: targetNodeID, TargetNodeID: replacementStorageID, DestinationKind: "archive",
		RetirementItemID: storageItem.ID, RetirementTrigger: "node_retirement_storage",
		CapabilityExpires: now.Add(time.Hour), Now: now.Add(21 * time.Second),
	})
	if err != nil || storageWorkflow.WorkflowID != storageWorkflowID {
		t.Fatalf("create storage retirement workflow=%+v err=%v", storageWorkflow, err)
	}
	if err := st.SetSnapshotWorkflowState(
		ctx, storageWorkflowID, "scheduled", "quiescing", now.Add(22*time.Second),
	); err != nil {
		t.Fatalf("quiesce storage retirement snapshot: %v", err)
	}
	for index, progress := range []struct {
		state  string
		nodeID int64
	}{
		{state: "drained", nodeID: targetNodeID},
		{state: "snapshotting", nodeID: targetNodeID},
		{state: "transferring", nodeID: targetNodeID},
		{state: "verifying", nodeID: replacementStorageID},
		{state: "publishing", nodeID: replacementStorageID},
	} {
		if err := st.SetSnapshotWorkflowProgress(
			ctx, storageWorkflowID, storageSnapshotID, progress.nodeID, progress.state,
			now.Add(time.Duration(23+index)*time.Second),
		); err != nil {
			t.Fatalf("advance storage retirement snapshot to %s: %v", progress.state, err)
		}
	}
	storageManifestHash := sha256.Sum256([]byte("storage-retirement-manifest"))
	storageArchiveHash := sha256.Sum256([]byte("storage-retirement-archive"))
	if _, err := st.CompleteSnapshotWorkflow(ctx, CompleteSnapshotWorkflowParams{
		WorkflowID: storageWorkflowID, SnapshotID: storageSnapshotID,
		CapabilityHash: storageCapabilityHash[:], TargetNodeID: replacementStorageID,
		ReplicaKind: "archive", ReplicaOrigin: "migration",
		ManifestSHA256: storageManifestHash[:], ArchiveSHA256: storageArchiveHash[:],
		FileCount: 4, TotalBytes: 2048, Now: now.Add(29 * time.Second),
	}); err != nil {
		t.Fatalf("publish storage retirement snapshot: %v", err)
	}
	if err := st.CompleteNodeRetirementReplicaItem(ctx, storageItem.ID, now.Add(30*time.Second)); err != nil {
		t.Fatalf("complete storage retirement item: %v", err)
	}
	if err := st.CompleteNodeRetirementReplicaItem(ctx, storageItem.ID, now.Add(30*time.Second)); err != nil {
		t.Fatalf("replay storage retirement item: %v", err)
	}
	finalized, err = st.FinalizeNodeRetirement(
		ctx, storageStatus.ID, "72000000-0000-4000-8000-000000000022", now.Add(31*time.Second),
	)
	if err != nil || !finalized {
		t.Fatalf("finalize storage retirement: finalized=%v err=%v", finalized, err)
	}
	var oldArchiveState, newArchiveState, newArchiveOrigin, storageNodeState string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT old_copy.state,new_copy.state,new_copy.origin,node.operational_state
		FROM replica_copies old_copy
		JOIN replica_copies new_copy ON new_copy.user_id=old_copy.user_id AND new_copy.node_id=$3
		JOIN nodes node ON node.id=old_copy.node_id
		WHERE old_copy.user_id=$1 AND old_copy.node_id=$2`,
		globalUserID, retiringStorageID, replacementStorageID).Scan(
		&oldArchiveState, &newArchiveState, &newArchiveOrigin, &storageNodeState,
	); err != nil || oldArchiveState != "stale" || newArchiveState != "ready" ||
		newArchiveOrigin != "migration" || storageNodeState != "decommissioned" {
		t.Fatalf("storage copies old=%q new=%q origin=%q node=%q err=%v",
			oldArchiveState, newArchiveState, newArchiveOrigin, storageNodeState, err)
	}
}

func assertPostgresNodeLifecycleHardening(t *testing.T, st *Store, peerNodeID int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Microsecond)
	nodeID := insertIntegrationNode(t, st, "lifecycle-node")
	otherNodeID := insertIntegrationNode(t, st, "lifecycle-other")
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET allow_register=true,is_backup_target=true WHERE id=$1`, nodeID); err != nil {
		t.Fatalf("configure lifecycle node: %v", err)
	}
	var adminID int64
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO admins (uuid,username,password_hash,status)
		VALUES ('71000000-0000-4000-8000-000000000001','lifecycle-admin','test-hash','active')
		RETURNING id`).Scan(&adminID); err != nil {
		t.Fatalf("insert lifecycle administrator: %v", err)
	}
	captureNodeID := insertIntegrationNode(t, st, "lifecycle-capture")
	var captureLegacyUserID, captureGlobalUserID int64
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO users (username,display_name,auth_provider,home_node_id,status)
		VALUES ('lifecycle-captured-user','Lifecycle Captured','password',$1,'active') RETURNING id`, captureNodeID).
		Scan(&captureLegacyUserID); err != nil {
		t.Fatalf("insert captured legacy user: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO global_users (uuid,legacy_user_id,display_name,status)
		VALUES ('71000000-0000-4000-8000-000000000022',$1,'Lifecycle Captured','active') RETURNING id`,
		captureLegacyUserID).Scan(&captureGlobalUserID); err != nil {
		t.Fatalf("insert captured global user: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO node_accounts (user_id,node_id,local_handle,status)
		VALUES ($1,$2,'lifecycle-captured-user','active')`, captureGlobalUserID, captureNodeID); err != nil {
		t.Fatalf("insert captured retirement account: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,state)
		VALUES ($1,$2,'home','ready')`, captureLegacyUserID, captureNodeID); err != nil {
		t.Fatalf("insert captured retirement replica: %v", err)
	}
	captureDrain := TransitionNodeLifecycleParams{
		OperationID: "71000000-0000-4000-8000-000000000023",
		NodeID:      captureNodeID, ToState: "draining", ReasonCode: "operator_draining",
		AdminID: adminID, Now: now,
	}
	if state, err := st.TransitionNodeLifecycle(ctx, captureDrain); err != nil || state != "draining" {
		t.Fatalf("capture retirement items: state=%q err=%v", state, err)
	}
	if state, err := st.TransitionNodeLifecycle(ctx, captureDrain); err != nil || state != "draining" {
		t.Fatalf("replay captured retirement: state=%q err=%v", state, err)
	}
	captureStatus, err := st.GetNodeRetirementStatus(ctx, captureNodeID)
	if err != nil || captureStatus == nil || captureStatus.TotalItems != 1 || captureStatus.PendingItems != 1 ||
		captureStatus.State != "scheduled" {
		t.Fatalf("captured retirement status=%+v err=%v", captureStatus, err)
	}
	var capturedKind string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT item_kind FROM node_retirement_items WHERE retirement_id=$1`, captureStatus.ID).
		Scan(&capturedKind); err != nil || capturedKind != "authoritative_home" {
		t.Fatalf("captured retirement kind=%q err=%v", capturedKind, err)
	}
	drainingSecret := sha256.Sum256([]byte("draining-allocation"))
	if _, err := st.CreateLoginHandoff(ctx, CreateLoginHandoffParams{
		OperationID:     "71000000-0000-4000-8000-000000000026",
		JTI:             "71000000-0000-4000-8000-000000000027",
		SecretHash:      drainingSecret[:],
		UserID:          captureGlobalUserID,
		RequestedNodeID: captureNodeID,
		SessionID:       "71000000-0000-4000-8000-000000000028",
		Issuer:          "https://controller.example",
		Subject:         "lifecycle-captured-user",
		KeyID:           "controller-v1",
		TicketTTL:       time.Minute,
		LeaseTTL:        15 * time.Minute,
		Now:             now.Add(500 * time.Millisecond),
	}); !errors.Is(err, ErrLoginHandoffUnavailable) {
		t.Fatalf("new draining allocation error=%v", err)
	}
	var drainingLeaseCount int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM user_activity_leases WHERE user_id=$1`, captureGlobalUserID).
		Scan(&drainingLeaseCount); err != nil || drainingLeaseCount != 0 {
		t.Fatalf("draining allocation left lease count=%d err=%v", drainingLeaseCount, err)
	}
	captureCancel := TransitionNodeLifecycleParams{
		OperationID: "71000000-0000-4000-8000-000000000024",
		NodeID:      captureNodeID, ToState: "maintenance", ReasonCode: "operator_maintenance",
		AdminID: adminID, Now: now.Add(time.Second),
	}
	if state, err := st.TransitionNodeLifecycle(ctx, captureCancel); err != nil || state != "maintenance" {
		t.Fatalf("cancel captured retirement: state=%q err=%v", state, err)
	}
	captureStatus, err = st.GetNodeRetirementStatus(ctx, captureNodeID)
	if err != nil || captureStatus.State != "cancelled" || captureStatus.CompletedItems != 1 {
		t.Fatalf("cancelled retirement status=%+v err=%v", captureStatus, err)
	}

	maintenance := TransitionNodeLifecycleParams{
		OperationID: "71000000-0000-4000-8000-000000000002",
		NodeID:      nodeID, ToState: "maintenance", ReasonCode: "operator_maintenance",
		AdminID: adminID, Now: now,
	}
	if state, err := st.TransitionNodeLifecycle(ctx, maintenance); err != nil || state != "maintenance" {
		t.Fatalf("enter maintenance: state=%q err=%v", state, err)
	}
	if state, err := st.TransitionNodeLifecycle(ctx, maintenance); err != nil || state != "maintenance" {
		t.Fatalf("exact lifecycle replay: state=%q err=%v", state, err)
	}
	collision := maintenance
	collision.NodeID = otherNodeID
	if _, err := st.TransitionNodeLifecycle(ctx, collision); !errors.Is(err, ErrNodeLifecycleBlocked) {
		t.Fatalf("cross-node operation replay error=%v", err)
	}
	collision = maintenance
	collision.ReasonCode = "different_reason"
	if _, err := st.TransitionNodeLifecycle(ctx, collision); !errors.Is(err, ErrNodeLifecycleBlocked) {
		t.Fatalf("changed lifecycle payload replay error=%v", err)
	}
	var state string
	var allowRegister, backupTarget bool
	if err := st.DB.QueryRowContext(ctx, `
		SELECT operational_state,allow_register,is_backup_target FROM nodes WHERE id=$1`, nodeID).
		Scan(&state, &allowRegister, &backupTarget); err != nil || state != "maintenance" ||
		!allowRegister || !backupTarget {
		t.Fatalf("maintenance preserved operator settings: state=%q allow=%v backup=%v err=%v",
			state, allowRegister, backupTarget, err)
	}

	draining := TransitionNodeLifecycleParams{
		OperationID: "71000000-0000-4000-8000-000000000003",
		NodeID:      nodeID, ToState: "draining", ReasonCode: "operator_draining",
		AdminID: adminID, Now: now.Add(time.Second),
	}
	if state, err := st.TransitionNodeLifecycle(ctx, draining); err != nil || state != "draining" {
		t.Fatalf("enter draining: state=%q err=%v", state, err)
	}
	drainStatus, err := st.GetNodeRetirementStatus(ctx, nodeID)
	if err != nil || drainStatus == nil || drainStatus.State != "verifying" || drainStatus.TotalItems != 0 {
		t.Fatalf("empty drain status=%+v err=%v", drainStatus, err)
	}
	pauseDrain := TransitionNodeLifecycleParams{
		OperationID: "71000000-0000-4000-8000-000000000025",
		NodeID:      nodeID, ToState: "maintenance", ReasonCode: "operator_maintenance",
		AdminID: adminID, Now: now.Add(1500 * time.Millisecond),
	}
	if state, err := st.TransitionNodeLifecycle(ctx, pauseDrain); err != nil || state != "maintenance" {
		t.Fatalf("pause empty drain: state=%q err=%v", state, err)
	}
	userID := insertIntegrationGlobalUser(t, st, "lifecycle-user")
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO node_accounts (user_id,node_id,local_handle,status)
		VALUES ($1,$2,'lifecycle-user','active')`, userID, nodeID); err != nil {
		t.Fatalf("insert lifecycle account dependency: %v", err)
	}
	retire := TransitionNodeLifecycleParams{
		OperationID: "71000000-0000-4000-8000-000000000004",
		NodeID:      nodeID, ToState: "retired", ReasonCode: "operator_retired",
		AdminID: adminID, Now: now.Add(2 * time.Second),
	}
	if _, err := st.TransitionNodeLifecycle(ctx, retire); !errors.Is(err, ErrNodeLifecycleBlocked) {
		t.Fatalf("retirement with active node account error=%v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `DELETE FROM node_accounts WHERE user_id=$1 AND node_id=$2`, userID, nodeID); err != nil {
		t.Fatalf("remove lifecycle account dependency: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO replica_copies (
		  id,user_id,node_id,replica_kind,state,origin,is_authoritative,compatibility_state
		) VALUES ('71000000-0000-4000-8000-000000000005',$1,$2,'archive','ready','configured',false,'compatible')`,
		userID, nodeID); err != nil {
		t.Fatalf("insert normalized replica dependency: %v", err)
	}
	retire.OperationID = "71000000-0000-4000-8000-000000000006"
	if _, err := st.TransitionNodeLifecycle(ctx, retire); !errors.Is(err, ErrNodeLifecycleBlocked) {
		t.Fatalf("retirement with normalized replica error=%v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `DELETE FROM replica_copies WHERE id='71000000-0000-4000-8000-000000000005'`); err != nil {
		t.Fatalf("remove normalized replica dependency: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET control_mode='independent-draining' WHERE id=$1`, nodeID); err != nil {
		t.Fatalf("set independent drain mode: %v", err)
	}
	retire.OperationID = "71000000-0000-4000-8000-000000000007"
	if _, err := st.TransitionNodeLifecycle(ctx, retire); !errors.Is(err, ErrNodeLifecycleBlocked) {
		t.Fatalf("retirement during independent drain error=%v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET control_mode='managed' WHERE id=$1`, nodeID); err != nil {
		t.Fatalf("restore managed mode: %v", err)
	}

	generation, err := st.GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatalf("read lifecycle generation: %v", err)
	}
	credentialSecret := []byte("encrypted-agent-secret")
	payloadDigest := sha256.Sum256([]byte("lifecycle-command"))
	tokenDigest := sha256.Sum256([]byte("lifecycle-enrollment"))
	capabilityDigest := sha256.Sum256([]byte("lifecycle-capability"))
	manifestDigest := sha256.Sum256([]byte("lifecycle-manifest"))
	legacyUsername := fmt.Sprintf("lifecycle-legacy-%d", nodeID)
	var legacyUserID int64
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO users (username,display_name,auth_provider,status)
		VALUES ($1,'Lifecycle Legacy','password','active') RETURNING id`, legacyUsername).
		Scan(&legacyUserID); err != nil {
		t.Fatalf("insert lifecycle legacy user: %v", err)
	}
	setupTx, err := st.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin lifecycle fact setup: %v", err)
	}
	defer func() { _ = setupTx.Rollback() }()
	setupExec := func(query string, args ...any) {
		t.Helper()
		if _, err := setupTx.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("insert lifecycle revocation fact: %v", err)
		}
	}
	setupExec(`INSERT INTO agent_credentials (
		id,node_id,credential_version,credential_type,secret_ciphertext,controller_generation
	) VALUES ('71000000-0000-4000-8000-000000000008',$1,1,'hmac',$2,$3)`,
		nodeID, credentialSecret, generation)
	setupExec(`INSERT INTO agent_credential_rotations (
		id,operation_id,node_id,credential_version,secret_ciphertext,controller_generation,state,expires_at,created_at
	) VALUES ('71000000-0000-4000-8000-000000000009','71000000-0000-4000-8000-000000000010',$1,2,$2,$3,'pending',$4,$5)`,
		nodeID, credentialSecret, generation, now.Add(time.Hour), now)
	setupExec(`INSERT INTO enrollment_tokens (
		id,operation_id,token_hash,expected_role,expected_node_id,expires_at,created_at
	) VALUES ('71000000-0000-4000-8000-000000000011','71000000-0000-4000-8000-000000000012',$1,'compute',$2,$3,$4)`,
		tokenDigest[:], nodeID, now.Add(time.Hour), now)
	setupExec(`INSERT INTO agent_commands (
		id,operation_id,node_id,command_type,payload,payload_sha256,state,controller_generation,expires_at,created_at,updated_at
	) VALUES ('71000000-0000-4000-8000-000000000013','71000000-0000-4000-8000-000000000014',$1,'health_probe','{}'::jsonb,$2,'queued',$3,$4,$5,$5)`,
		nodeID, payloadDigest[:], generation, now.Add(time.Hour), now)
	setupExec(`INSERT INTO admin_node_links (admin_id,node_id,local_handle,state,last_verified_at)
		VALUES ($1,$2,'lifecycle-admin','verified',$3)`, adminID, nodeID, now)
	setupExec(`INSERT INTO control_tickets (
		jti,operation_id,secret_hash,ticket_type,issuer,audience,subject,admin_id,target_node_id,key_id,
		controller_generation,issued_at,not_before,expires_at
	) VALUES ('71000000-0000-4000-8000-000000000015','71000000-0000-4000-8000-000000000021',$6,
		'node_admin','controller','node','lifecycle-admin',$1,$2,'k1',$3,$4,$4,$5)`,
		adminID, nodeID, generation, now, now.Add(time.Hour), payloadDigest[:])
	setupExec(`INSERT INTO tickets (jti,user_id,node_id,expires_at)
		VALUES ('lifecycle-legacy-ticket',$1,$2,$3)`, legacyUserID, nodeID, now.Add(time.Hour))
	setupExec(`INSERT INTO workflows (
		id,operation_id,workflow_type,state,user_id,source_node_id,target_node_id,
		activity_epoch,controller_generation,created_at,updated_at,finished_at
	) VALUES ('71000000-0000-4000-8000-000000000016','71000000-0000-4000-8000-000000000017',
		'snapshot','succeeded',$1,$2,$3,1,$4,$5,$5,$5)`, userID, peerNodeID, nodeID, generation, now)
	setupExec(`INSERT INTO snapshot_manifests (
		id,workflow_id,user_id,source_node_id,activity_epoch,format_version,
		manifest_sha256,file_count,total_bytes,state,created_at
	) VALUES ('71000000-0000-4000-8000-000000000018','71000000-0000-4000-8000-000000000016',
		$1,$2,1,1,$3,0,0,'immutable',$4)`, userID, peerNodeID, manifestDigest[:], now)
	setupExec(`INSERT INTO snapshot_transfer_capabilities (
		id,workflow_id,snapshot_id,source_node_id,target_node_id,token_hash,state,
		controller_generation,expires_at,created_at
	) VALUES ('71000000-0000-4000-8000-000000000019','71000000-0000-4000-8000-000000000016',
		'71000000-0000-4000-8000-000000000018',$1,$2,$3,'prepared',$4,$5,$6)`,
		peerNodeID, nodeID, capabilityDigest[:], generation, now.Add(time.Hour), now)
	if err := setupTx.Commit(); err != nil {
		t.Fatalf("commit lifecycle fact setup: %v", err)
	}
	retire.OperationID = "71000000-0000-4000-8000-000000000020"
	retire.Now = now.Add(3 * time.Second)
	if state, err := st.TransitionNodeLifecycle(ctx, retire); err != nil || state != "retired" {
		t.Fatalf("retire drained node: state=%q err=%v", state, err)
	}
	if state, err := st.TransitionNodeLifecycle(ctx, retire); err != nil || state != "retired" {
		t.Fatalf("replay retired transition: state=%q err=%v", state, err)
	}

	var status, rotationState, commandState, linkState, linkError, capabilityState string
	var credentialRevoked, ticketRevoked sql.NullTime
	var legacyExpiry time.Time
	var enrollmentCount int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT operational_state,status,allow_register,is_backup_target FROM nodes WHERE id=$1`, nodeID).
		Scan(&state, &status, &allowRegister, &backupTarget); err != nil || state != "retired" ||
		status != "offline" || allowRegister || backupTarget {
		t.Fatalf("retired node facts: state=%q status=%q allow=%v backup=%v err=%v",
			state, status, allowRegister, backupTarget, err)
	}
	if err := st.DB.QueryRowContext(ctx, `SELECT revoked_at FROM agent_credentials WHERE node_id=$1`, nodeID).
		Scan(&credentialRevoked); err != nil || !credentialRevoked.Valid {
		t.Fatalf("agent credential revocation=%v err=%v", credentialRevoked, err)
	}
	if err := st.DB.QueryRowContext(ctx, `SELECT state FROM agent_credential_rotations WHERE node_id=$1`, nodeID).
		Scan(&rotationState); err != nil || rotationState != "revoked" {
		t.Fatalf("credential rotation state=%q err=%v", rotationState, err)
	}
	if err := st.DB.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_tokens WHERE expected_node_id=$1`, nodeID).
		Scan(&enrollmentCount); err != nil || enrollmentCount != 0 {
		t.Fatalf("enrollment count=%d err=%v", enrollmentCount, err)
	}
	if err := st.DB.QueryRowContext(ctx, `SELECT state FROM agent_commands WHERE node_id=$1`, nodeID).
		Scan(&commandState); err != nil || commandState != "expired" {
		t.Fatalf("agent command state=%q err=%v", commandState, err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state,last_error_code FROM admin_node_links WHERE admin_id=$1 AND node_id=$2`, adminID, nodeID).
		Scan(&linkState, &linkError); err != nil || linkState != "revoked" || linkError != "node_retired" {
		t.Fatalf("admin link state=%q error=%q err=%v", linkState, linkError, err)
	}
	if err := st.DB.QueryRowContext(ctx, `SELECT revoked_at FROM control_tickets WHERE target_node_id=$1`, nodeID).
		Scan(&ticketRevoked); err != nil || !ticketRevoked.Valid {
		t.Fatalf("control ticket revocation=%v err=%v", ticketRevoked, err)
	}
	if err := st.DB.QueryRowContext(ctx, `SELECT expires_at FROM tickets WHERE node_id=$1`, nodeID).
		Scan(&legacyExpiry); err != nil || legacyExpiry.After(retire.Now) {
		t.Fatalf("legacy ticket expiry=%v err=%v", legacyExpiry, err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state FROM snapshot_transfer_capabilities WHERE id='71000000-0000-4000-8000-000000000019'`).
		Scan(&capabilityState); err != nil || capabilityState != "revoked" {
		t.Fatalf("transfer capability state=%q err=%v", capabilityState, err)
	}
}

func assertConcurrentSingleWriter(
	t *testing.T,
	st *Store,
	userID, nodeA, nodeB, generation int64,
) {
	t.Helper()
	const attempts = 32
	now := time.Now().UTC().Truncate(time.Microsecond)
	type result struct {
		params AcquireActivityLeaseParams
		lease  AcquireActivityLeaseResult
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, attempts)
	var wait sync.WaitGroup
	for index := range attempts {
		params := AcquireActivityLeaseParams{
			OperationID:          fmt.Sprintf("10000000-0000-4000-8000-%012x", index+1),
			UserID:               userID,
			WriterNodeID:         nodeA,
			SessionID:            fmt.Sprintf("20000000-0000-4000-8000-%012x", index+1),
			ControllerGeneration: generation,
			TTL:                  15 * time.Minute,
			Now:                  now,
		}
		if index%2 == 1 {
			params.WriterNodeID = nodeB
		}
		wait.Add(1)
		go func(params AcquireActivityLeaseParams) {
			defer wait.Done()
			<-start
			lease, err := st.AcquireActivityLease(context.Background(), params)
			results <- result{params: params, lease: lease, err: err}
		}(params)
	}
	close(start)
	wait.Wait()
	close(results)

	var acquired, existing int
	var first result
	for result := range results {
		if result.err != nil {
			t.Fatalf("AcquireActivityLease(%s): %v", result.params.OperationID, result.err)
		}
		if first.params.OperationID == "" {
			first = result
		}
		if result.lease.Acquired {
			acquired++
		}
		if result.lease.Existing {
			existing++
		}
	}
	if acquired != 1 || existing != attempts-1 {
		t.Fatalf("concurrent lease outcomes: acquired=%d existing=%d", acquired, existing)
	}

	replayed, err := st.AcquireActivityLease(context.Background(), first.params)
	if err != nil || replayed.Acquired != first.lease.Acquired || replayed.Existing != first.lease.Existing ||
		replayed.Lease.WriterNodeID != first.lease.Lease.WriterNodeID ||
		replayed.Lease.ActivityEpoch != first.lease.Lease.ActivityEpoch {
		t.Fatalf("lease replay=%+v original=%+v err=%v", replayed, first.lease, err)
	}
	conflict := first.params
	conflict.WriterNodeID = nodeA
	if conflict.WriterNodeID == first.params.WriterNodeID {
		conflict.WriterNodeID = nodeB
	}
	if _, err := st.AcquireActivityLease(context.Background(), conflict); !errors.Is(err, ErrLeaseOperationConflict) {
		t.Fatalf("operation payload conflict error=%v, want ErrLeaseOperationConflict", err)
	}

	var leaseRows int
	if err := st.DB.QueryRow(`SELECT count(*) FROM user_activity_leases WHERE user_id=$1`, userID).Scan(&leaseRows); err != nil {
		t.Fatalf("count writer leases: %v", err)
	}
	if leaseRows != 1 {
		t.Fatalf("writer lease rows=%d, want 1", leaseRows)
	}
}

func assertConcurrentHandoffRedemption(t *testing.T, st *Store, userID, nodeID int64) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	secretHash := sha256.Sum256([]byte("one-use-handoff-secret"))
	params := CreateLoginHandoffParams{
		OperationID:     "30000000-0000-4000-8000-000000000001",
		JTI:             "40000000-0000-4000-8000-000000000001",
		SecretHash:      secretHash[:],
		UserID:          userID,
		RequestedNodeID: nodeID,
		SessionID:       "50000000-0000-4000-8000-000000000001",
		Issuer:          "https://controller.example",
		Subject:         "handoff-user",
		KeyID:           "controller-v1",
		TicketTTL:       time.Minute,
		LeaseTTL:        15 * time.Minute,
		Now:             now,
	}
	handoff, err := st.CreateLoginHandoff(context.Background(), params)
	if err != nil || !handoff.Acquired {
		t.Fatalf("CreateLoginHandoff: handoff=%+v err=%v", handoff, err)
	}
	replay, err := st.CreateLoginHandoff(context.Background(), params)
	if err != nil || !replay.Replayed || replay.JTI != handoff.JTI || replay.ActivityEpoch != handoff.ActivityEpoch {
		t.Fatalf("CreateLoginHandoff replay=%+v err=%v", replay, err)
	}
	wrongSecret := sha256.Sum256([]byte("wrong-secret"))
	if _, ok, err := st.ConsumeLoginHandoff(context.Background(), params.JTI, wrongSecret[:], nodeID, now, 15*time.Minute); err != nil || ok {
		t.Fatalf("wrong-secret redemption ok=%v err=%v", ok, err)
	}

	const attempts = 32
	type result struct {
		redemption LoginRedemption
		ok         bool
		err        error
	}
	start := make(chan struct{})
	results := make(chan result, attempts)
	var wait sync.WaitGroup
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			redemption, ok, err := st.ConsumeLoginHandoff(
				context.Background(), params.JTI, secretHash[:], nodeID, now.Add(time.Second), 15*time.Minute,
			)
			results <- result{redemption: redemption, ok: ok, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	var consumed int
	for result := range results {
		if result.err != nil {
			t.Fatalf("ConsumeLoginHandoff: %v", result.err)
		}
		if result.ok {
			consumed++
			if result.redemption.UserID != userID || result.redemption.Handle != params.Subject ||
				result.redemption.SessionID != params.SessionID || result.redemption.ActivityEpoch != handoff.ActivityEpoch {
				t.Fatalf("unexpected redemption: %+v", result.redemption)
			}
		}
	}
	if consumed != 1 {
		t.Fatalf("handoff consumed %d times, want exactly once", consumed)
	}
	if _, ok, err := st.ConsumeLoginHandoff(
		context.Background(), params.JTI, secretHash[:], nodeID, now.Add(2*time.Second), 15*time.Minute,
	); err != nil || ok {
		t.Fatalf("post-consumption replay ok=%v err=%v", ok, err)
	}
}
