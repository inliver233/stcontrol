package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func TestControllerUserDataFaultHTTPFreezesOneUserThroughDurableCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller user-data-fault PostgreSQL integration is disabled in short mode")
	}
	ctx, st, generation, adminID := newControllerRetirementStore(t)
	const (
		adminUsername = "retirement-controller-admin"
		adminPassword = "data-fault-admin-password-2026"
	)
	adminHash, err := controlcrypto.HashPassword(adminPassword)
	if err != nil {
		t.Fatalf("hash data-fault administrator password: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE admins SET password_hash=$2 WHERE id=$1`, adminID, adminHash); err != nil {
		t.Fatalf("install data-fault administrator password: %v", err)
	}
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	node := createControllerBackupNode(t, ctx, st, "data-fault-controller-home", "compute", false, generation)
	const psk = "data-fault-controller-agent-psk"
	seedControllerBackupCredential(t, ctx, st, secretKey, node.ID, generation, psk)
	user := createControllerBackupUser(t, ctx, st, node.ID, "data-fault-controller-user")
	seedControllerFaultAuthoritativeReplica(t, ctx, st, user, node.ID)

	harness := newControllerDurableCommandHarness(
		ctx, st, map[int64]string{node.ID: psk},
		func(nodeID int64, lease *store.AgentCommandLease, plaintext []byte) (agentCommandSummary, bool, error) {
			if nodeID != node.ID || lease.CommandType != "freeze_user_data" {
				return agentCommandSummary{}, false, fmt.Errorf("unexpected data-fault command %q on node %d", lease.CommandType, nodeID)
			}
			var request protocol.FreezeUserDataRequest
			if err := json.Unmarshal(plaintext, &request); err != nil || request.OperationID != lease.OperationID ||
				request.ControllerGeneration != lease.ControllerGeneration || request.GlobalUserID != user.GlobalID ||
				request.Handle != user.Username || request.ActivityEpoch != 1 {
				return agentCommandSummary{}, false, fmt.Errorf("invalid data-fault command payload: request=%+v err=%v", request, err)
			}
			return agentCommandSummary{OK: true, UserDataFreeze: &protocol.FreezeUserDataResponse{
				OK: true, OperationID: request.OperationID,
				ControllerGeneration: request.ControllerGeneration, FaultID: request.FaultID,
				GlobalUserID: request.GlobalUserID, Handle: request.Handle,
				ActivityEpoch: request.ActivityEpoch, Frozen: true, Drained: true,
			}}, true, nil
		},
	)
	t.Cleanup(harness.stop)
	cfg := config.DefaultController()
	cfg.StaticDir = t.TempDir()
	cfg.Relay.Listen = ""
	server := New(cfg, st, secretKey)
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	cfg.PublicURL = httpServer.URL
	client := newControllerHTTPClient(t)
	assertControllerHTTPStatus(t, client, http.MethodPost, httpServer.URL+"/api/auth/admin/login", map[string]string{
		"username": adminUsername, "password": adminPassword,
	}, false, http.StatusOK)

	operationID := "83000000-0000-4000-8000-000000000001"
	path := httpServer.URL + "/api/admin/users/" + user.UUID + "/data-faults"
	request := map[string]any{
		"operation_id": operationID, "expected_home_node_id": node.ID,
		"reason_code": "user_database_corrupt", "acknowledge_risk": true,
	}
	statusCode, _, body := controllerHTTPRequest(t, client, http.MethodPost, path, request, true)
	if statusCode != http.StatusOK {
		t.Fatalf("report and freeze user data fault: status=%d body=%s", statusCode, body)
	}
	var reported store.UserDataFaultStatus
	if err := json.Unmarshal(body, &reported); err != nil || reported.State != "recovery_unavailable" ||
		reported.ProtectionState != "unavailable" || reported.FrozenAt == nil {
		t.Fatalf("completed HTTP data-fault response=%+v err=%v body=%s", reported, err, body)
	}
	if harness.commandCount("freeze_user_data") != 1 {
		t.Fatalf("freeze command count=%d", harness.commandCount("freeze_user_data"))
	}

	// The exact request is a durable replay and cannot dispatch a second
	// command after an HTTP response is lost.
	statusCode, _, replayBody := controllerHTTPRequest(t, client, http.MethodPost, path, request, true)
	if statusCode != http.StatusOK || harness.commandCount("freeze_user_data") != 1 {
		t.Fatalf("data-fault HTTP replay status=%d commands=%d body=%s",
			statusCode, harness.commandCount("freeze_user_data"), replayBody)
	}
	request["operation_id"] = "83000000-0000-4000-8000-000000000002"
	assertControllerHTTPStatus(t, client, http.MethodPost, path, request, true, http.StatusConflict)
	statusPath := httpServer.URL + "/api/admin/users/" + user.UUID + "/data-fault"
	assertControllerHTTPStatus(t, client, http.MethodGet, statusPath, nil, false, http.StatusOK)
	assertControllerHTTPStatus(t, client, http.MethodGet,
		httpServer.URL+"/api/admin/users/not-a-uuid/data-fault", nil, false, http.StatusBadRequest)
	assertControllerHTTPStatus(t, client, http.MethodGet,
		httpServer.URL+"/api/admin/users/83000000-0000-4000-8000-000000000099/data-fault", nil, false, http.StatusNotFound)

	var copyState, legacyState, faultState string
	var commands, auditEvents int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT copy.state,replica.state,fault.state,
		  (SELECT count(*) FROM agent_commands WHERE operation_id=fault.freeze_operation_id),
		  (SELECT count(*) FROM audit_events WHERE target_type='user' AND target_id=fault.user_id::text
		     AND action IN ('user-data-fault-reported','user-data-fault-frozen'))
		FROM user_data_faults fault
		JOIN replica_copies copy ON copy.user_id=fault.user_id AND copy.node_id=fault.node_id
		JOIN global_users global_user ON global_user.id=fault.user_id
		JOIN user_replicas replica ON replica.user_id=global_user.legacy_user_id AND replica.node_id=fault.node_id
		WHERE fault.id=$1`, reported.ID).Scan(
		&copyState, &legacyState, &faultState, &commands, &auditEvents,
	); err != nil || copyState != "corrupt" || legacyState != "corrupt" ||
		faultState != "recovery_unavailable" || commands != 1 || auditEvents < 2 {
		t.Fatalf("durable fault facts copy=%q legacy=%q fault=%q commands=%d audits=%d err=%v",
			copyState, legacyState, faultState, commands, auditEvents, err)
	}
	if errs := harness.errors(); len(errs) > 0 {
		t.Fatalf("data-fault durable command harness errors: %v", errs)
	}
}

func TestControllerUserDataFaultResumesAfterNodeAndWorkerRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller user-data-fault PostgreSQL integration is disabled in short mode")
	}
	ctx, st, generation, adminID := newControllerRetirementStore(t)
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	node := createControllerBackupNode(t, ctx, st, "data-fault-restart-home", "compute", false, generation)
	const psk = "data-fault-restart-agent-psk"
	seedControllerBackupCredential(t, ctx, st, secretKey, node.ID, generation, psk)
	user := createControllerBackupUser(t, ctx, st, node.ID, "data-fault-restart-user")
	seedControllerFaultAuthoritativeReplica(t, ctx, st, user, node.ID)
	digest := sha256.Sum256([]byte("data-fault-restart-request"))
	fault, err := st.ReportUserDataFault(ctx, store.ReportUserDataFaultParams{
		OperationID: "83100000-0000-4000-8000-000000000001", RequestDigest: digest[:],
		UserUUID: user.UUID, ExpectedHomeNodeID: node.ID,
		ReasonCode: "user_directory_unreadable", AdminID: adminID, Now: time.Now().UTC(),
	})
	if err != nil || fault == nil {
		t.Fatalf("create restartable user data fault: fault=%+v err=%v", fault, err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET connectivity_state='offline' WHERE id=$1`, node.ID); err != nil {
		t.Fatalf("make data-fault node unavailable: %v", err)
	}
	first := New(config.DefaultController(), st, secretKey)
	first.runUserDataFaultOnce(ctx, fault.ID)
	current, err := st.GetUserDataFaultByID(ctx, fault.ID)
	if err != nil || current == nil || current.State != "retry_wait" || current.ErrorCode != "agent_unavailable" || current.Attempt != 1 {
		t.Fatalf("first unavailable fault attempt=%+v err=%v", current, err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET connectivity_state='online' WHERE id=$1`, node.ID); err != nil {
		t.Fatalf("restore data-fault node: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE user_data_faults SET next_attempt_at=now()-interval '1 second' WHERE id=$1`, fault.ID); err != nil {
		t.Fatalf("advance data-fault retry: %v", err)
	}

	harness := newControllerDurableCommandHarness(
		ctx, st, map[int64]string{node.ID: psk},
		func(_ int64, lease *store.AgentCommandLease, plaintext []byte) (agentCommandSummary, bool, error) {
			if lease.CommandType != "freeze_user_data" {
				return agentCommandSummary{}, false, fmt.Errorf("unexpected restart command %q", lease.CommandType)
			}
			var request protocol.FreezeUserDataRequest
			if err := json.Unmarshal(plaintext, &request); err != nil {
				return agentCommandSummary{}, false, err
			}
			return agentCommandSummary{OK: true, UserDataFreeze: &protocol.FreezeUserDataResponse{
				OK: true, OperationID: request.OperationID,
				ControllerGeneration: request.ControllerGeneration, FaultID: request.FaultID,
				GlobalUserID: request.GlobalUserID, Handle: request.Handle,
				ActivityEpoch: request.ActivityEpoch, Frozen: true, Drained: true,
			}}, true, nil
		},
	)
	t.Cleanup(harness.stop)
	restarted := New(config.DefaultController(), st, secretKey)
	if restarted.workflowWorkerID == first.workflowWorkerID {
		t.Fatal("Controller restart reused user-data-fault worker identity")
	}
	restarted.reconcileUserDataFaults(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		current, err = st.GetUserDataFaultByID(ctx, fault.ID)
		if err == nil && current != nil && current.State == "recovery_unavailable" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("restarted data fault did not converge: fault=%+v err=%v", current, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if current.Attempt != 2 || harness.commandCount("freeze_user_data") != 1 {
		t.Fatalf("resumed fault attempt=%d commands=%d", current.Attempt, harness.commandCount("freeze_user_data"))
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	restarted.userDataFaultReconciler(cancelled)
	if (&Server{}).startUserDataFault(ctx, fault.ID) || (&Server{}).startUserDataFault(cancelled, fault.ID) {
		t.Fatal("user-data-fault scheduler accepted a missing worker pool")
	}
	if errs := harness.errors(); len(errs) > 0 {
		t.Fatalf("restarted data-fault command harness errors: %v", errs)
	}
}

func TestControllerUserDataFaultReleaseUsesDurableCommandAndCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller user-data-fault PostgreSQL integration is disabled in short mode")
	}
	ctx, st, generation, adminID := newControllerRetirementStore(t)
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	node := createControllerBackupNode(t, ctx, st, "data-fault-release-home", "compute", false, generation)
	const psk = "data-fault-release-agent-psk"
	seedControllerBackupCredential(t, ctx, st, secretKey, node.ID, generation, psk)
	user := createControllerBackupUser(t, ctx, st, node.ID, "data-fault-release-user")
	seedControllerFaultAuthoritativeReplica(t, ctx, st, user, node.ID)
	fault := seedResolvedControllerFaultRelease(t, ctx, st, user, node.ID, adminID, "83200000-0000-4000-8000-000000000001")

	harness := newControllerDurableCommandHarness(
		ctx, st, map[int64]string{node.ID: psk},
		func(nodeID int64, lease *store.AgentCommandLease, plaintext []byte) (agentCommandSummary, bool, error) {
			if nodeID != node.ID || lease.CommandType != "release_user_data" {
				return agentCommandSummary{}, false, fmt.Errorf("unexpected release command %q on node %d", lease.CommandType, nodeID)
			}
			var request protocol.ReleaseUserDataRequest
			if err := json.Unmarshal(plaintext, &request); err != nil || request.OperationID != lease.OperationID ||
				request.ControllerGeneration != lease.ControllerGeneration ||
				request.FaultID != fault.ID || request.GlobalUserID != user.GlobalID ||
				request.Handle != user.Username || request.ActivityEpoch != 1 {
				return agentCommandSummary{}, false, fmt.Errorf("invalid release command payload: request=%+v err=%v", request, err)
			}
			return agentCommandSummary{
				OK: true,
				UserDataRelease: &protocol.ReleaseUserDataResponse{
					OK: true, OperationID: request.OperationID,
					ControllerGeneration: request.ControllerGeneration,
					FaultID:              request.FaultID, GlobalUserID: request.GlobalUserID,
					Handle: request.Handle, ActivityEpoch: request.ActivityEpoch, Released: true,
				},
			}, true, nil
		},
	)
	t.Cleanup(harness.stop)
	server := New(config.DefaultController(), st, secretKey)
	server.reconcileUserDataFaults(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		current, err := st.GetUserDataFaultByID(ctx, fault.ID)
		if err == nil && current != nil && current.ReleaseState == "released" && current.ReleaseReleasedAt != nil {
			break
		}
		if time.Now().After(deadline) {
			current, _ := st.GetUserDataFaultByID(ctx, fault.ID)
			t.Fatalf("release did not converge: fault=%+v err=%v", current, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if harness.commandCount("release_user_data") != 1 {
		t.Fatalf("release command count=%d", harness.commandCount("release_user_data"))
	}
	if errs := harness.errors(); len(errs) > 0 {
		t.Fatalf("release command harness errors: %v", errs)
	}
}

func TestControllerUserDataFaultReleaseRetriesAfterNodeAndWorkerRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller user-data-fault PostgreSQL integration is disabled in short mode")
	}
	ctx, st, generation, adminID := newControllerRetirementStore(t)
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	node := createControllerBackupNode(t, ctx, st, "data-fault-release-restart-home", "compute", false, generation)
	const psk = "data-fault-release-restart-agent-psk"
	seedControllerBackupCredential(t, ctx, st, secretKey, node.ID, generation, psk)
	user := createControllerBackupUser(t, ctx, st, node.ID, "data-fault-release-restart-user")
	seedControllerFaultAuthoritativeReplica(t, ctx, st, user, node.ID)
	fault := seedResolvedControllerFaultRelease(t, ctx, st, user, node.ID, adminID, "83300000-0000-4000-8000-000000000001")

	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET connectivity_state='offline' WHERE id=$1`, node.ID); err != nil {
		t.Fatalf("make release node unavailable: %v", err)
	}
	first := New(config.DefaultController(), st, secretKey)
	first.reconcileUserDataFaults(ctx)
	current, err := st.GetUserDataFaultByID(ctx, fault.ID)
	if err != nil || current == nil || current.ReleaseState != "retry_wait" ||
		current.ReleaseErrorCode != "agent_unavailable" || current.ReleaseAttempt != 1 {
		t.Fatalf("first unavailable release attempt=%+v err=%v", current, err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET connectivity_state='online' WHERE id=$1`, node.ID); err != nil {
		t.Fatalf("restore release node: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE user_data_faults SET release_next_attempt_at=now()-interval '1 second' WHERE id=$1`, fault.ID); err != nil {
		t.Fatalf("advance release retry: %v", err)
	}

	harness := newControllerDurableCommandHarness(
		ctx, st, map[int64]string{node.ID: psk},
		func(_ int64, lease *store.AgentCommandLease, plaintext []byte) (agentCommandSummary, bool, error) {
			if lease.CommandType != "release_user_data" {
				return agentCommandSummary{}, false, fmt.Errorf("unexpected restart release command %q", lease.CommandType)
			}
			var request protocol.ReleaseUserDataRequest
			if err := json.Unmarshal(plaintext, &request); err != nil {
				return agentCommandSummary{}, false, err
			}
			return agentCommandSummary{
				OK: true,
				UserDataRelease: &protocol.ReleaseUserDataResponse{
					OK: true, OperationID: request.OperationID,
					ControllerGeneration: request.ControllerGeneration,
					FaultID:              request.FaultID, GlobalUserID: request.GlobalUserID,
					Handle: request.Handle, ActivityEpoch: request.ActivityEpoch, Released: true,
				},
			}, true, nil
		},
	)
	t.Cleanup(harness.stop)
	restarted := New(config.DefaultController(), st, secretKey)
	restarted.reconcileUserDataFaults(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		current, err = st.GetUserDataFaultByID(ctx, fault.ID)
		if err == nil && current != nil && current.ReleaseState == "released" && current.ReleaseReleasedAt != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("restarted release did not converge: fault=%+v err=%v", current, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if current.ReleaseAttempt != 2 || harness.commandCount("release_user_data") != 1 {
		t.Fatalf("resumed release attempt=%d commands=%d", current.ReleaseAttempt, harness.commandCount("release_user_data"))
	}
	if errs := harness.errors(); len(errs) > 0 {
		t.Fatalf("restarted release command harness errors: %v", errs)
	}
}

func seedControllerFaultAuthoritativeReplica(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	user *store.User,
	nodeID int64,
) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,state,last_sync_at)
		VALUES ($1,$2,'home','ready',$3)`, user.ID, nodeID, now); err != nil {
		t.Fatalf("seed fault legacy replica: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO replica_copies (
		  id,user_id,node_id,replica_kind,state,origin,is_authoritative,
		  compatibility_state,created_at,updated_at
		) VALUES (gen_random_uuid(),$1,$2,'active','ready','primary',true,'compatible',$3,$3)`,
		user.GlobalID, nodeID, now); err != nil {
		t.Fatalf("seed fault authoritative replica: %v", err)
	}
}

func seedResolvedControllerFaultRelease(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	user *store.User,
	nodeID int64,
	adminID int64,
	operationID string,
) *store.UserDataFaultStatus {
	t.Helper()
	now := time.Now().UTC()
	digest := sha256.Sum256([]byte("resolved-release:" + operationID))
	fault, err := st.ReportUserDataFault(ctx, store.ReportUserDataFaultParams{
		OperationID: operationID, RequestDigest: digest[:],
		UserUUID: user.UUID, ExpectedHomeNodeID: nodeID,
		ReasonCode: "user_database_corrupt", AdminID: adminID, Now: now,
	})
	if err != nil || fault == nil {
		t.Fatalf("create resolved release fault: fault=%+v err=%v", fault, err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE user_data_faults SET state='resolved',freeze_operation_id=$2::uuid,
		  attempt=1,protection_state='takeover_available',error_code=NULL,next_attempt_at=NULL,
		  frozen_at=$3,resolved_at=$3,resolution_kind='takeover',
		  resolution_operation_id=$4::uuid,release_state='pending',
		  release_operation_id=NULL,release_controller_generation=NULL,release_attempt=0,
		  release_lease_owner=NULL,release_lease_until=NULL,release_next_attempt_at=$3,
		  release_error_code=NULL,release_released_at=NULL,updated_at=$3
		WHERE id=$1::uuid`, fault.ID,
		"84444444-4444-4444-8444-444444444444", now,
		"85555555-5555-4555-8555-555555555555"); err != nil {
		t.Fatalf("prepare resolved release fault: %v", err)
	}
	updated, err := st.GetUserDataFaultByID(ctx, fault.ID)
	if err != nil || updated == nil {
		t.Fatalf("reload resolved release fault: fault=%+v err=%v", updated, err)
	}
	return updated
}

type controllerDurableCommandHandler func(
	nodeID int64,
	lease *store.AgentCommandLease,
	plaintext []byte,
) (agentCommandSummary, bool, error)

type controllerDurableCommandHarness struct {
	store   *store.Store
	psks    map[int64]string
	handler controllerDurableCommandHandler

	ctx      context.Context
	cancel   context.CancelFunc
	stopOnce sync.Once
	wg       sync.WaitGroup

	mu       sync.Mutex
	commands map[string]int
	errs     []error
}

func newControllerDurableCommandHarness(
	parent context.Context,
	st *store.Store,
	psks map[int64]string,
	handler controllerDurableCommandHandler,
) *controllerDurableCommandHarness {
	ctx, cancel := context.WithCancel(parent)
	harness := &controllerDurableCommandHarness{
		store: st, psks: psks, handler: handler, ctx: ctx, cancel: cancel,
		commands: make(map[string]int),
	}
	for nodeID := range psks {
		harness.wg.Add(1)
		go harness.runWorker(nodeID)
	}
	return harness
}

func (h *controllerDurableCommandHarness) stop() {
	h.stopOnce.Do(func() {
		h.cancel()
		h.wg.Wait()
	})
}

func (h *controllerDurableCommandHarness) commandCount(commandType string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.commands[commandType]
}

func (h *controllerDurableCommandHarness) errors() []error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]error(nil), h.errs...)
}

func (h *controllerDurableCommandHarness) recordError(err error) {
	if err == nil {
		return
	}
	h.mu.Lock()
	h.errs = append(h.errs, err)
	h.mu.Unlock()
}

func (h *controllerDurableCommandHarness) runWorker(nodeID int64) {
	defer h.wg.Done()
	workerID := fmt.Sprintf("controller-durable-command-worker-%d", nodeID)
	for {
		select {
		case <-h.ctx.Done():
			return
		default:
		}
		lease, err := h.store.LeaseAgentCommand(h.ctx, nodeID, workerID, time.Now().UTC(), time.Minute)
		if err != nil {
			if h.ctx.Err() == nil {
				h.recordError(fmt.Errorf("lease durable command for node %d: %w", nodeID, err))
			}
			return
		}
		if lease == nil {
			select {
			case <-h.ctx.Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		ok, err := h.store.AckAgentCommand(
			h.ctx, lease.ID, nodeID, workerID, lease.ControllerGeneration,
			time.Now().UTC(), time.Minute,
		)
		if err != nil || !ok {
			h.recordError(fmt.Errorf("ack durable command %s: ok=%v err=%w", lease.ID, ok, err))
			continue
		}
		plaintext, decodeErr := decryptControllerBackupCommand(lease, h.psks[nodeID])
		summary, succeeded, handleErr := agentCommandSummary{}, false, decodeErr
		if handleErr == nil && h.handler != nil {
			summary, succeeded, handleErr = h.handler(nodeID, lease, plaintext)
		}
		if handleErr != nil {
			h.recordError(handleErr)
			summary = agentCommandSummary{OK: false, Code: "test_agent_error"}
			succeeded = false
		}
		result, err := json.Marshal(summary)
		if err != nil {
			h.recordError(fmt.Errorf("marshal durable command %s result: %w", lease.ID, err))
			continue
		}
		digest := sha256.Sum256(result)
		ok, err = h.store.FinishAgentCommand(h.ctx, store.FinishAgentCommandParams{
			ID: lease.ID, NodeID: nodeID, WorkerID: workerID,
			ControllerGeneration: lease.ControllerGeneration, Succeeded: succeeded,
			ResultSummary: result, ResultDigest: digest[:], Now: time.Now().UTC(),
		})
		if err != nil || !ok {
			h.recordError(fmt.Errorf("finish durable command %s: ok=%v err=%w", lease.ID, ok, err))
			continue
		}
		h.mu.Lock()
		h.commands[lease.CommandType]++
		h.mu.Unlock()
	}
}
