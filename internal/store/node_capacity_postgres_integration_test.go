package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestPostgresNodeCapacityAtFourDigitOnlineScale exercises the durable health
// window against a realistic four-digit online fact set. It intentionally uses
// the public Store methods after bulk seeding so that PostgreSQL constraints,
// pagination, admission fencing, stale-report handling, and retention all take
// part in the assertion.
func TestPostgresNodeCapacityAtFourDigitOnlineScale(t *testing.T) {
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	var st *Store
	defer func() {
		if st != nil {
			_ = st.Close()
		}
		cleanupSchema()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var err error
	st, err = Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL capacity store: %v", err)
	}
	nodeID := insertIntegrationNode(t, st, "capacity-four-digit")
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET allow_register=true,controller_generation=(
		  SELECT generation FROM controller_epochs WHERE state='active'
		) WHERE id=$1`, nodeID); err != nil {
		t.Fatalf("prepare capacity node: %v", err)
	}

	seedStarted := time.Now()
	if _, err := st.DB.ExecContext(ctx, `
		WITH legacy AS (
		  INSERT INTO users (username,display_name,home_node_id,status)
		  SELECT 'capacity-user-'||lpad(value::text,4,'0'),
		    'Capacity User '||value,$1,'active'
		  FROM generate_series(1,1000) AS value
		  RETURNING id,uuid,username,display_name
		), global_account AS (
		  INSERT INTO global_users (uuid,legacy_user_id,display_name,status)
		  SELECT uuid,id,display_name,'active' FROM legacy
		  RETURNING id,legacy_user_id
		), local_account AS (
		  INSERT INTO node_accounts (user_id,node_id,local_handle,status,verified_at)
		  SELECT global_account.id,$1,legacy.username,'active',now()
		  FROM global_account JOIN legacy ON legacy.id=global_account.legacy_user_id
		  RETURNING user_id
		)
		INSERT INTO user_activity_leases (
		  user_id,writer_node_id,session_id,activity_epoch,state,lease_expires_at,
		  last_page_heartbeat_at,last_request_at,controller_generation
		)
		SELECT global_account.id,$1,gen_random_uuid(),1,'active',now()+interval '10 minutes',
		  now(),now(),(SELECT generation FROM controller_epochs WHERE state='active')
		FROM global_account`, nodeID); err != nil {
		t.Fatalf("seed 1000 online users: %v", err)
	}
	if elapsed := time.Since(seedStarted); elapsed > 10*time.Second {
		t.Fatalf("seed 1000 online users took %s, want <=10s", elapsed)
	}
	var onlineCount int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM user_activity_leases
		WHERE writer_node_id=$1 AND state='active'`, nodeID).Scan(&onlineCount); err != nil || onlineCount != 1000 {
		t.Fatalf("active online users=%d err=%v, want 1000", onlineCount, err)
	}

	seenUsers := 0
	var cursor int64
	for {
		page, err := st.ListUsersPage(ctx, UserPageParams{AfterID: cursor, Limit: 100})
		if err != nil {
			t.Fatalf("read bounded user page after %d: %v", cursor, err)
		}
		if len(page.Users) == 0 || len(page.Users) > 100 {
			t.Fatalf("unbounded or empty page after %d: size=%d", cursor, len(page.Users))
		}
		seenUsers += len(page.Users)
		if !page.HasMore {
			if page.NextCursor != 0 {
				t.Fatalf("terminal page retained cursor %d", page.NextCursor)
			}
			break
		}
		if page.NextCursor <= cursor {
			t.Fatalf("user cursor did not advance: before=%d after=%d", cursor, page.NextCursor)
		}
		cursor = page.NextCursor
	}
	if seenUsers != 1000 {
		t.Fatalf("paged users=%d, want 1000", seenUsers)
	}

	policy := NodeCapacityPolicy{
		CPUBusyPct: 50, MemBusyPct: 50, DiskBusyPct: 50, HardPct: 60,
		Window: 2 * time.Minute, Sustain: 2 * time.Minute,
		Recovery: 2 * time.Minute, Cooldown: 3 * time.Minute,
		MinDiskFreeBytes: 10 << 30, MaxOnlineUsers: 1200, MaxTaskQueueDepth: 100,
	}
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	heartbeat := func(at time.Time, cpu float64, users, queue int, metricsValid bool) {
		t.Helper()
		facts := testNodeHeartbeat(at)
		facts.CPUPct = cpu
		facts.MemPct = 20
		facts.DiskPct = 20
		facts.MetricsValid = metricsValid
		facts.OnlineUsers = users
		facts.TaskQueueDepth = queue
		facts.TelemetrySource = "adapter"
		facts.RegistrationPolicy = NodeRegistrationPolicy{
			State: "open", Version: 11, ExpiresAt: at.Add(time.Hour), ObservedAt: at,
		}
		if err := st.UpdateNodeHeartbeat(ctx, nodeID, facts, policy); err != nil {
			t.Fatalf("heartbeat at %s: %v", at, err)
		}
	}
	assertCapacity := func(state, reason string) {
		t.Helper()
		node, err := st.GetNodeByID(ctx, nodeID)
		if err != nil || node == nil || node.CapacityState != state ||
			node.CapacityReasonCode.String != reason {
			t.Fatalf("capacity=%+v err=%v, want %s/%s", node, err, state, reason)
		}
	}

	heartbeat(t0, 61, 1000, 10, true)
	assertCapacity("busy", "cpu_sustained")
	heartbeat(t0.Add(2*time.Minute), 61, 1000, 10, true)
	assertCapacity("full", "cpu_sustained")

	var metricSamples int
	if err := st.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM node_metric_samples WHERE node_id=$1`, nodeID).
		Scan(&metricSamples); err != nil || metricSamples != 2 {
		t.Fatalf("metric samples=%d err=%v, want 2", metricSamples, err)
	}
	equalFacts := testNodeHeartbeat(t0.Add(2 * time.Minute))
	equalFacts.CPUPct = 5
	equalFacts.OnlineUsers = 1
	equalFacts.TelemetrySource = "adapter"
	equalFacts.RegistrationPolicy = NodeRegistrationPolicy{
		State: "open", Version: 11, ExpiresAt: t0.Add(time.Hour), ObservedAt: t0.Add(2 * time.Minute),
	}
	if err := st.UpdateNodeHeartbeat(ctx, nodeID, equalFacts, policy); err != nil {
		t.Fatalf("equal heartbeat replay: %v", err)
	}
	assertCapacity("full", "cpu_sustained")
	if err := st.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM node_metric_samples WHERE node_id=$1`, nodeID).
		Scan(&metricSamples); err != nil || metricSamples != 2 {
		t.Fatalf("equal replay inserted samples=%d err=%v", metricSamples, err)
	}
	staleFacts := equalFacts
	staleFacts.ObservedAt = t0.Add(time.Minute)
	staleFacts.RegistrationPolicy.ObservedAt = staleFacts.ObservedAt
	if err := st.UpdateNodeHeartbeat(ctx, nodeID, staleFacts, policy); !errors.Is(err, ErrStaleNodeHeartbeat) {
		t.Fatalf("stale heartbeat error=%v", err)
	}

	_, err = st.CreateRegistrationWorkflow(ctx, CreateRegistrationWorkflowParams{
		WorkflowID:    "88000000-0000-4000-8000-000000000001",
		OperationID:   "88000000-0000-4000-8000-000000000002",
		RequestDigest: bytes.Repeat([]byte{1}, 32), PendingTokenHash: bytes.Repeat([]byte{2}, 32),
		ClientExpiresAt: t0.Add(30 * time.Minute), NodeID: nodeID, PolicyVersion: 11,
		LocalHandle: "capacity-new-user", DisplayName: "Capacity New User", AuthProvider: "password",
		PasswordHash: "bcrypt", PasswordMaterialHash: "node-hash", PasswordMaterialSalt: "node-salt",
		Now: t0.Add(2*time.Minute + time.Second),
	})
	if !errors.Is(err, ErrRegistrationNodeUnavailable) {
		t.Fatalf("full node accepted registration: %v", err)
	}

	heartbeat(t0.Add(2*time.Minute+time.Second), 10, 100, 10, true)
	assertCapacity("full", "cpu_sustained")
	heartbeat(t0.Add(5*time.Minute+time.Second), 10, 100, 10, true)
	assertCapacity("open", "")
	heartbeat(t0.Add(6*time.Minute), 10, policy.MaxOnlineUsers, 10, true)
	assertCapacity("full", "online_user_limit")
	heartbeat(t0.Add(7*time.Minute), 10, 100, 10, true)
	assertCapacity("full", "online_user_limit")
	heartbeat(t0.Add(9*time.Minute), 10, 100, 10, true)
	assertCapacity("open", "")
	heartbeat(t0.Add(10*time.Minute), 10, 100, policy.MaxTaskQueueDepth, true)
	assertCapacity("full", "task_queue_limit")
	heartbeat(t0.Add(11*time.Minute), 0, 100, 0, false)
	assertCapacity("unknown", "metrics_unavailable")

	removed, err := st.CleanupNodeMetricSamples(ctx, t0.Add(6*time.Minute))
	if err != nil || removed != 4 {
		t.Fatalf("metric retention removed=%d err=%v, want 4", removed, err)
	}
	if err := st.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM node_metric_samples WHERE node_id=$1`, nodeID).
		Scan(&metricSamples); err != nil || metricSamples != 4 {
		t.Fatalf("retained metric samples=%d err=%v, want 4", metricSamples, err)
	}

	var first, last string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT MIN(username),MAX(username) FROM users WHERE username LIKE 'capacity-user-%'`).
		Scan(&first, &last); err != nil || first != "capacity-user-0001" || last != "capacity-user-1000" {
		t.Fatalf("seeded user bounds=%q..%q err=%v", first, last, err)
	}

	secondNodeID := insertIntegrationNode(t, st, "capacity-queue-peer")
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET controller_generation=(
		  SELECT generation FROM controller_epochs WHERE state='active'
		) WHERE id=$1`, secondNodeID); err != nil {
		t.Fatalf("prepare peer command queue: %v", err)
	}
	payload := json.RawMessage(`{}`)
	digest := sha256.Sum256(payload)
	queueBase := t0.Add(20 * time.Minute)
	enqueue := func(targetNodeID int64, sequence int, createdAt time.Time) string {
		t.Helper()
		commandID := fmt.Sprintf("89000000-0000-4000-8000-%012d", sequence)
		operationID := fmt.Sprintf("8a000000-0000-4000-8000-%012d", sequence)
		generation, err := st.EnqueueAgentCommand(ctx, EnqueueAgentCommandParams{
			ID: commandID, OperationID: operationID, NodeID: targetNodeID,
			CommandType: "health_probe", EncryptedPayload: payload, PayloadSHA256: digest[:],
			ExpiresAt: createdAt.Add(time.Hour), Now: createdAt,
		})
		if err != nil || generation <= 0 {
			t.Fatalf("enqueue node %d command %d: generation=%d err=%v", targetNodeID, sequence, generation, err)
		}
		return operationID
	}
	wantPrimary := make([]string, 32)
	wantPeer := make([]string, 32)
	queueStarted := time.Now()
	for index := range 32 {
		wantPrimary[index] = enqueue(nodeID, index+1, queueBase.Add(time.Duration(index*2)*time.Microsecond))
		wantPeer[index] = enqueue(secondNodeID, index+1001, queueBase.Add(time.Duration(index*2+1)*time.Microsecond))
	}
	for index := range 32 {
		peerLease, err := st.LeaseAgentCommand(ctx, secondNodeID, "peer-worker", queueBase.Add(time.Minute), time.Minute)
		if err != nil || peerLease == nil || peerLease.OperationID != wantPeer[index] {
			t.Fatalf("peer lease[%d]=%+v err=%v, want %s", index, peerLease, err, wantPeer[index])
		}
		primaryLease, err := st.LeaseAgentCommand(ctx, nodeID, "primary-worker", queueBase.Add(time.Minute), time.Minute)
		if err != nil || primaryLease == nil || primaryLease.OperationID != wantPrimary[index] {
			t.Fatalf("primary lease[%d]=%+v err=%v, want %s", index, primaryLease, err, wantPrimary[index])
		}
	}
	if elapsed := time.Since(queueStarted); elapsed > 5*time.Second {
		t.Fatalf("enqueue and isolate two 32-command queues took %s, want <=5s", elapsed)
	}
	for _, target := range []struct {
		nodeID int64
		worker string
	}{{nodeID, "primary-worker"}, {secondNodeID, "peer-worker"}} {
		lease, err := st.LeaseAgentCommand(ctx, target.nodeID, target.worker, queueBase.Add(time.Minute), time.Minute)
		if err != nil || lease != nil {
			t.Fatalf("drained node %d queue lease=%+v err=%v", target.nodeID, lease, err)
		}
	}
}
