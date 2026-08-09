package controller

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// TestControllerAgentHTTPEnrollmentRotationAndCommandQueue exercises the
// actual Agent HTTP surface against PostgreSQL. It proves that enrollment is
// node/fingerprint scoped and single-use, HMAC nonces are consumed once,
// pending credentials cannot call normal routes, rotation revokes the old
// credential, and command lease/ACK/result transitions remain generation and
// worker fenced through the router rather than only through direct Store calls.
func TestControllerAgentHTTPEnrollmentRotationAndCommandQueue(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller Agent PostgreSQL HTTP integration is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated Controller Agent store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	node := &store.Node{
		Name: "agent-http-compute", Role: "compute", Status: "pending",
		BaseURL: "https://agent-http.example/control",
	}
	if err := st.CreateNode(ctx, node); err != nil {
		t.Fatalf("pre-create enrollment node: %v", err)
	}
	info := protocol.NodeInfo{
		TavernVersion: "1.13.4", TavernPort: 8000, DataRoot: "/srv/sillytavern/data",
		BaseURLGuess: "https://agent-http.example/control", OS: "linux", Arch: "amd64",
	}
	fingerprint := protocol.NodeFingerprint(info)
	const enrollmentToken = "single-use-agent-enrollment-secret"
	tokenHash := sha256.Sum256([]byte(enrollmentToken))
	now := time.Now().UTC()
	if err := st.CreateEnrollmentToken(ctx, store.CreateEnrollmentTokenParams{
		ID: "74000000-0000-4000-8000-000000000001", OperationID: "74000000-0000-4000-8000-000000000002",
		TokenHash: tokenHash[:], ExpectedNodeID: node.ID, ExpectedRole: node.Role,
		ExpectedFingerprint: fingerprint, ExpiresAt: now.Add(15 * time.Minute), Now: now,
	}); err != nil {
		t.Fatalf("create scoped enrollment token: %v", err)
	}

	cfg := config.DefaultController()
	cfg.Activity.LeaseTTLSec = 120
	cfg.StaticDir = t.TempDir()
	cfg.Relay.Listen = ""
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	server := New(cfg, st, secretKey)
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	cfg.PublicURL = httpServer.URL
	client := &http.Client{Timeout: 10 * time.Second}

	register := func(request protocol.RegisterAgentRequest) (int, []byte) {
		t.Helper()
		return agentUnsignedJSONRequest(t, client, http.MethodPost, httpServer.URL+"/api/agent/register", request)
	}
	invalidRole := protocol.RegisterAgentRequest{
		Token: enrollmentToken, Role: "passive_controller", Fingerprint: fingerprint, Info: info,
	}
	if status, body := register(invalidRole); status != http.StatusForbidden {
		t.Fatalf("invalid enrollment role: status=%d body=%s", status, body)
	}
	wrongInfo := info
	wrongInfo.DataRoot = "/srv/other/data"
	wrongFingerprint := protocol.NodeFingerprint(wrongInfo)
	if status, body := register(protocol.RegisterAgentRequest{
		Token: enrollmentToken, Role: node.Role, Fingerprint: wrongFingerprint, Info: wrongInfo,
	}); status != http.StatusForbidden {
		t.Fatalf("wrong enrollment fingerprint: status=%d body=%s", status, body)
	}

	status, body := register(protocol.RegisterAgentRequest{
		Token: enrollmentToken, Role: node.Role, Fingerprint: fingerprint, Info: info,
	})
	if status != http.StatusOK {
		t.Fatalf("valid enrollment: status=%d body=%s", status, body)
	}
	var enrollment protocol.RegisterAgentResponse
	if err := json.Unmarshal(body, &enrollment); err != nil || enrollment.NodeID != node.ID ||
		enrollment.AgentPSK == "" || enrollment.CredentialVersion != 1 || enrollment.ControllerGeneration <= 0 {
		t.Fatalf("enrollment response=%+v err=%v body=%s", enrollment, err, body)
	}
	if status, replayBody := register(protocol.RegisterAgentRequest{
		Token: enrollmentToken, Role: node.Role, Fingerprint: fingerprint, Info: info,
	}); status != http.StatusForbidden {
		t.Fatalf("replayed enrollment: status=%d body=%s", status, replayBody)
	}
	var consumedAt *time.Time
	var storedTokenHash []byte
	if err := st.DB.QueryRowContext(ctx, `
		SELECT token_hash,consumed_at FROM enrollment_tokens
		WHERE expected_node_id=$1`, node.ID).Scan(&storedTokenHash, &consumedAt); err != nil ||
		!bytes.Equal(storedTokenHash, tokenHash[:]) || consumedAt == nil ||
		bytes.Contains(storedTokenHash, []byte(enrollmentToken)) {
		t.Fatalf("enrollment persistence: consumed=%v digest=%x err=%v", consumedAt, storedTokenHash, err)
	}

	generation := enrollment.ControllerGeneration
	psk := enrollment.AgentPSK
	activityPasswordHash, err := controlcrypto.HashPassword("activity-test-password")
	if err != nil {
		t.Fatalf("hash activity user password: %v", err)
	}
	activityUser := &store.User{
		Username: "agent-http-activity", DisplayName: "Agent HTTP Activity",
		PasswordHash: sql.NullString{String: activityPasswordHash, Valid: true}, AuthProvider: "password",
		HomeNodeID: sql.NullInt64{Int64: node.ID, Valid: true}, Status: "active",
	}
	if err := st.CreateUser(ctx, activityUser); err != nil {
		t.Fatalf("create activity user: %v", err)
	}
	const activitySessionID = "74000000-0000-4000-8000-000000000010"
	activityLease, err := st.AcquireActivityLease(ctx, store.AcquireActivityLeaseParams{
		OperationID: "74000000-0000-4000-8000-000000000011", UserID: activityUser.GlobalID,
		WriterNodeID: node.ID, SessionID: activitySessionID, ControllerGeneration: generation,
		TTL: 30 * time.Second, Now: time.Now().UTC(),
	})
	if err != nil || !activityLease.Acquired {
		t.Fatalf("seed activity lease: result=%+v err=%v", activityLease, err)
	}
	activityObservedAt := time.Now().UTC()
	heartbeat := protocol.HeartbeatRequest{
		NodeID: node.ID, AgentVersion: "agent-http/v1", TavernVersion: info.TavernVersion,
		CPUPct: 12, MemPct: 18, DiskPct: 20, MetricsValid: true,
		DiskTotalBytes: 100 << 30, DiskAvailableBytes: 80 << 30,
		DiskQuotaBytes: 90 << 30, AllocatedDiskBytes: 1 << 30,
		OnlineUsers: 0, TaskQueueDepth: 0, TelemetrySource: "adapter",
		Compatibility: protocol.NodeCompatibilityReport{State: "compatible", Fingerprint: strings.Repeat("a", 64)},
		TransferURL:   "https://agent-http.example/data",
		RegistrationPolicy: protocol.RegistrationPolicyReport{
			State: "open", Version: 1, ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
		},
		ControlMode: protocol.NodeControlModeReport{
			Mode: protocol.NodeModeManaged, ModeGeneration: 1,
			ControllerGeneration: generation, ReasonCode: "controller_reachable",
			LastControllerSuccessAt: time.Now().UTC(),
		},
		Users: []protocol.UserStatus{{
			Handle: activityUser.Username, SessionID: activitySessionID,
			ActivityEpoch: activityLease.Lease.ActivityEpoch, ControllerGeneration: generation,
			LoginMode: protocol.NodeModeManaged, IsOnline: true,
			LastActivity: activityObservedAt.UnixMilli(), LastPageHeartbeat: activityObservedAt.UnixMilli(),
			LastRequest: activityObservedAt.UnixMilli(),
		}},
	}

	if status, body := agentSignedJSONRequest(t, client, http.MethodPost, httpServer.URL+"/api/agent/heartbeat", node.ID, "wrong-psk", heartbeat); status != http.StatusUnauthorized {
		t.Fatalf("wrong Agent PSK: status=%d body=%s", status, body)
	}
	if status, body := agentSignedJSONRequest(t, client, http.MethodPost, httpServer.URL+"/api/agent/heartbeat", node.ID+999, psk, heartbeat); status != http.StatusUnauthorized {
		t.Fatalf("unknown Agent identity: status=%d body=%s", status, body)
	}
	status, body = agentSignedJSONRequest(t, client, http.MethodPost, httpServer.URL+"/api/agent/heartbeat", node.ID, psk, heartbeat)
	if status != http.StatusOK {
		t.Fatalf("initial signed heartbeat: status=%d body=%s", status, body)
	}
	var heartbeatResponse protocol.HeartbeatResponse
	if err := json.Unmarshal(body, &heartbeatResponse); err != nil || !heartbeatResponse.OK ||
		heartbeatResponse.ControllerGeneration != generation || heartbeatResponse.CredentialRotation != nil {
		t.Fatalf("initial heartbeat response=%+v err=%v body=%s", heartbeatResponse, err, body)
	}
	var leaseState string
	var leaseExpiresAt time.Time
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state,lease_expires_at FROM user_activity_leases WHERE user_id=$1`, activityUser.GlobalID).
		Scan(&leaseState, &leaseExpiresAt); err != nil || leaseState != "active" ||
		leaseExpiresAt.Before(activityObservedAt.Add(115*time.Second)) ||
		leaseExpiresAt.After(activityObservedAt.Add(130*time.Second)) {
		t.Fatalf("configured activity lease state=%q expires=%s observed=%s err=%v",
			leaseState, leaseExpiresAt, activityObservedAt, err)
	}

	// A directory mtime fallback is not authoritative proof of logout. It may
	// update capacity metrics, but it cannot end the durable writer or leave an
	// offline fact that the backup scheduler could consume.
	heartbeat.TelemetrySource = "directory_fallback"
	heartbeat.Users[0].Ended = true
	heartbeat.Users[0].IsOnline = false
	heartbeat.Users[0].LastActivity = time.Now().Add(-time.Hour).UnixMilli()
	heartbeat.Users[0].LastPageHeartbeat = 0
	heartbeat.Users[0].LastRequest = 0
	heartbeat.RegistrationPolicy.ExpiresAt = time.Now().UTC().Add(10 * time.Minute)
	heartbeat.ControlMode.LastControllerSuccessAt = time.Now().UTC()
	if status, fallbackBody := agentSignedJSONRequest(t, client, http.MethodPost,
		httpServer.URL+"/api/agent/heartbeat", node.ID, psk, heartbeat); status != http.StatusOK {
		t.Fatalf("fallback heartbeat: status=%d body=%s", status, fallbackBody)
	}
	if err := st.DB.QueryRowContext(ctx, `SELECT state FROM user_activity_leases WHERE user_id=$1`,
		activityUser.GlobalID).Scan(&leaseState); err != nil || leaseState != "active" {
		t.Fatalf("fallback ended durable lease: state=%q err=%v", leaseState, err)
	}
	server.actMu.Lock()
	_, retainedFallback := server.activity[node.ID]
	server.actMu.Unlock()
	if retainedFallback {
		t.Fatal("fallback heartbeat retained schedulable activity facts")
	}

	// A stale but schema-valid adapter tombstone cannot end a replacement
	// session or become an offline scheduling fact.
	heartbeat.TelemetrySource = "adapter"
	heartbeat.Users[0].SessionID = "74000000-0000-4000-8000-000000000012"
	heartbeat.RegistrationPolicy.ExpiresAt = time.Now().UTC().Add(10 * time.Minute)
	heartbeat.ControlMode.LastControllerSuccessAt = time.Now().UTC()
	if status, staleBody := agentSignedJSONRequest(t, client, http.MethodPost,
		httpServer.URL+"/api/agent/heartbeat", node.ID, psk, heartbeat); status != http.StatusOK {
		t.Fatalf("stale ended heartbeat: status=%d body=%s", status, staleBody)
	}
	if err := st.DB.QueryRowContext(ctx, `SELECT state FROM user_activity_leases WHERE user_id=$1`,
		activityUser.GlobalID).Scan(&leaseState); err != nil || leaseState != "active" {
		t.Fatalf("stale adapter ended replacement lease: state=%q err=%v", leaseState, err)
	}
	server.actMu.Lock()
	staleFact := server.activity[node.ID][activityUser.Username]
	server.actMu.Unlock()
	if !staleFact.IsOnline {
		t.Fatal("stale adapter tombstone became schedulable offline evidence")
	}
	heartbeat.Users[0].SessionID = activitySessionID

	// The same fully fenced ended fact from the adapter is authoritative and
	// atomically terminates the lease.
	heartbeat.TelemetrySource = "adapter"
	heartbeat.RegistrationPolicy.ExpiresAt = time.Now().UTC().Add(10 * time.Minute)
	heartbeat.ControlMode.LastControllerSuccessAt = time.Now().UTC()
	if status, endedBody := agentSignedJSONRequest(t, client, http.MethodPost,
		httpServer.URL+"/api/agent/heartbeat", node.ID, psk, heartbeat); status != http.StatusOK {
		t.Fatalf("adapter ended heartbeat: status=%d body=%s", status, endedBody)
	}
	if err := st.DB.QueryRowContext(ctx, `SELECT state FROM user_activity_leases WHERE user_id=$1`,
		activityUser.GlobalID).Scan(&leaseState); err != nil || leaseState != "ended" {
		t.Fatalf("adapter did not end durable lease: state=%q err=%v", leaseState, err)
	}
	heartbeat.Users = nil

	// Force the normal 30-day rotation path without changing the Controller
	// generation; the HTTP mechanics and pending-credential restrictions are
	// identical to recovery rotation, while promotion/rebuild has its own
	// process-level acceptance matrix.
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE agent_credentials SET created_at=now()-interval '31 days'
		WHERE node_id=$1 AND revoked_at IS NULL`, node.ID); err != nil {
		t.Fatalf("age active Agent credential: %v", err)
	}
	heartbeat.RegistrationPolicy.ExpiresAt = time.Now().UTC().Add(10 * time.Minute)
	heartbeat.ControlMode.LastControllerSuccessAt = time.Now().UTC()
	status, body = agentSignedJSONRequest(t, client, http.MethodPost, httpServer.URL+"/api/agent/heartbeat", node.ID, psk, heartbeat)
	if status != http.StatusOK {
		t.Fatalf("rotation heartbeat: status=%d body=%s", status, body)
	}
	if err := json.Unmarshal(body, &heartbeatResponse); err != nil || heartbeatResponse.CredentialRotation == nil ||
		heartbeatResponse.CredentialRotation.CredentialVersion != 2 {
		t.Fatalf("rotation offer=%+v err=%v body=%s", heartbeatResponse.CredentialRotation, err, body)
	}
	rotation := heartbeatResponse.CredentialRotation
	plaintext, err := controlcrypto.Decrypt(controlcrypto.DeriveAgentCredentialRotationKey(psk), rotation.EncryptedPSK)
	if err != nil || len(plaintext) < 32 {
		t.Fatalf("unwrap rotated Agent credential: bytes=%d err=%v", len(plaintext), err)
	}
	rotatedPSK := string(plaintext)

	if status, body := agentSignedJSONRequest(t, client, http.MethodPost, httpServer.URL+"/api/agent/heartbeat", node.ID, rotatedPSK, heartbeat); status != http.StatusUnauthorized {
		t.Fatalf("pending credential reached normal route: status=%d body=%s", status, body)
	}
	confirmURL := httpServer.URL + "/api/agent/credentials/confirm"
	if status, body := agentSignedJSONRequest(t, client, http.MethodPost, confirmURL, node.ID, rotatedPSK,
		protocol.ConfirmAgentCredentialRequest{CredentialVersion: rotation.CredentialVersion + 1}); status != http.StatusBadRequest {
		t.Fatalf("mismatched credential confirmation: status=%d body=%s", status, body)
	}
	status, body = agentSignedJSONRequest(t, client, http.MethodPost, confirmURL, node.ID, rotatedPSK,
		protocol.ConfirmAgentCredentialRequest{CredentialVersion: rotation.CredentialVersion})
	if status != http.StatusOK {
		t.Fatalf("activate rotated credential: status=%d body=%s", status, body)
	}
	if status, body := agentSignedJSONRequest(t, client, http.MethodPost, httpServer.URL+"/api/agent/heartbeat", node.ID, psk, heartbeat); status != http.StatusUnauthorized {
		t.Fatalf("revoked credential remained usable: status=%d body=%s", status, body)
	}
	heartbeat.RegistrationPolicy.ExpiresAt = time.Now().UTC().Add(10 * time.Minute)
	heartbeat.ControlMode.LastControllerSuccessAt = time.Now().UTC()
	if status, body := agentSignedJSONRequest(t, client, http.MethodPost, httpServer.URL+"/api/agent/heartbeat", node.ID, rotatedPSK, heartbeat); status != http.StatusOK {
		t.Fatalf("rotated credential heartbeat: status=%d body=%s", status, body)
	}

	// Authentication consumes the nonce before the handler validates its
	// body. Replaying the byte-identical signed request must therefore fail at
	// the middleware even though the first request only reached a 400.
	replayBody := []byte(`{"worker_id":"short","highest_generation":0}`)
	replayRequest := newAgentSignedRequest(t, http.MethodPost, httpServer.URL+"/api/agent/commands/lease", node.ID, rotatedPSK, replayBody)
	replayHeaders := replayRequest.Header.Clone()
	if got, body := executeAgentRequest(t, client, replayRequest); got != http.StatusBadRequest {
		t.Fatalf("first invalid lease: status=%d body=%s", got, body)
	}
	replayed, err := http.NewRequest(http.MethodPost, httpServer.URL+"/api/agent/commands/lease", bytes.NewReader(replayBody))
	if err != nil {
		t.Fatalf("create replayed Agent request: %v", err)
	}
	replayed.Header = replayHeaders
	if got, body := executeAgentRequest(t, client, replayed); got != http.StatusUnauthorized {
		t.Fatalf("replayed Agent nonce: status=%d body=%s", got, body)
	}

	currentNode, err := st.GetNodeByID(ctx, node.ID)
	if err != nil || currentNode == nil {
		t.Fatalf("reload enrolled node: node=%+v err=%v", currentNode, err)
	}
	const operationID = "74000000-0000-4000-8000-000000000003"
	commandGeneration, err := server.enqueueAgentCommand(ctx, currentNode, "health_probe", map[string]string{"probe": "ready"}, operationID)
	if err != nil || commandGeneration != generation {
		t.Fatalf("enqueue durable Agent command: generation=%d err=%v", commandGeneration, err)
	}
	const workerID = "agent-http-worker-0001"
	leaseURL := httpServer.URL + "/api/agent/commands/lease"
	status, body = agentSignedJSONRequest(t, client, http.MethodPost, leaseURL, node.ID, rotatedPSK,
		protocol.LeaseCommandRequest{WorkerID: workerID, HighestGeneration: generation})
	if status != http.StatusOK {
		t.Fatalf("lease durable command: status=%d body=%s", status, body)
	}
	var command protocol.AgentCommand
	if err := json.Unmarshal(body, &command); err != nil || command.OperationID != operationID ||
		command.CommandType != "health_probe" || command.Attempt != 1 || command.ControllerGeneration != generation {
		t.Fatalf("leased command=%+v err=%v body=%s", command, err, body)
	}
	var envelope encryptedCommandEnvelope
	if err := json.Unmarshal(command.EncryptedPayload, &envelope); err != nil || envelope.Version != 2 {
		t.Fatalf("decode encrypted command envelope: envelope=%+v err=%v", envelope, err)
	}
	commandPlaintext, err := controlcrypto.Decrypt(controlcrypto.DeriveAgentCommandKey(rotatedPSK), envelope.Ciphertext)
	if err != nil || string(commandPlaintext) != `{"probe":"ready"}` {
		t.Fatalf("decrypt leased command: plaintext=%q err=%v", commandPlaintext, err)
	}
	payloadDigest, err := hex.DecodeString(command.PayloadSHA256)
	if err != nil {
		t.Fatalf("decode command authenticator: %v", err)
	}
	payloadMAC := hmac.New(sha256.New, controlcrypto.DeriveAgentCommandAuthKey(rotatedPSK))
	_, _ = payloadMAC.Write(commandPlaintext)
	if !hmac.Equal(payloadDigest, payloadMAC.Sum(nil)) {
		t.Fatal("leased command payload authenticator does not match plaintext")
	}

	ackURL := httpServer.URL + "/api/agent/commands/" + command.ID + "/ack"
	if status, body := agentSignedJSONRequest(t, client, http.MethodPost, ackURL, node.ID, rotatedPSK,
		protocol.AckCommandRequest{WorkerID: "different-worker-0001", ControllerGeneration: generation}); status != http.StatusConflict {
		t.Fatalf("wrong-worker command ACK: status=%d body=%s", status, body)
	}
	if status, body := agentSignedJSONRequest(t, client, http.MethodPost, ackURL, node.ID, rotatedPSK,
		protocol.AckCommandRequest{WorkerID: workerID, ControllerGeneration: generation}); status != http.StatusOK {
		t.Fatalf("valid command ACK: status=%d body=%s", status, body)
	}
	resultURL := httpServer.URL + "/api/agent/commands/" + command.ID + "/result"
	invalidResult := []byte(`{"worker_id":"agent-http-worker-0001","controller_generation":1,"succeeded":true,"result":`)
	if status, body := agentSignedRawRequest(t, client, http.MethodPost, resultURL, node.ID, rotatedPSK, invalidResult); status != http.StatusBadRequest {
		t.Fatalf("invalid command result: status=%d body=%s", status, body)
	}
	finish := protocol.FinishCommandRequest{
		WorkerID: workerID, ControllerGeneration: generation, Succeeded: true,
		Result: json.RawMessage(`{"ok":true}`),
	}
	if status, body := agentSignedJSONRequest(t, client, http.MethodPost, resultURL, node.ID, rotatedPSK, finish); status != http.StatusOK {
		t.Fatalf("finish durable command: status=%d body=%s", status, body)
	}
	if status, body := agentSignedJSONRequest(t, client, http.MethodPost, resultURL, node.ID, rotatedPSK, finish); status != http.StatusConflict {
		t.Fatalf("replayed command result: status=%d body=%s", status, body)
	}
	result, err := st.GetAgentCommandResult(ctx, operationID)
	var resultSummary struct {
		OK bool `json:"ok"`
	}
	if err == nil && result != nil {
		err = json.Unmarshal(result.ResultSummary, &resultSummary)
	}
	if err != nil || result == nil || result.State != "succeeded" || !resultSummary.OK {
		t.Fatalf("durable command result=%+v err=%v", result, err)
	}

	if status, body := agentSignedJSONRequest(t, client, http.MethodPost, httpServer.URL+"/api/agent/snapshots/progress", node.ID, rotatedPSK,
		map[string]string{"workflow_id": "invalid", "snapshot_id": "invalid", "state": "publishing"}); status != http.StatusBadRequest {
		t.Fatalf("invalid snapshot progress: status=%d body=%s", status, body)
	}
}

func agentUnsignedJSONRequest(t *testing.T, client *http.Client, method, target string, body any) (int, []byte) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode unsigned Agent request: %v", err)
	}
	req, err := http.NewRequest(method, target, bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("create unsigned Agent request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return executeAgentRequest(t, client, req)
}

func agentSignedJSONRequest(
	t *testing.T,
	client *http.Client,
	method, target string,
	nodeID int64,
	psk string,
	body any,
) (int, []byte) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode signed Agent request: %v", err)
	}
	return agentSignedRawRequest(t, client, method, target, nodeID, psk, encoded)
}

func agentSignedRawRequest(
	t *testing.T,
	client *http.Client,
	method, target string,
	nodeID int64,
	psk string,
	body []byte,
) (int, []byte) {
	t.Helper()
	return executeAgentRequest(t, client, newAgentSignedRequest(t, method, target, nodeID, psk, body))
}

func newAgentSignedRequest(
	t *testing.T,
	method, target string,
	nodeID int64,
	psk string,
	body []byte,
) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create signed Agent request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	protocol.SignRequest(req, nodeID, psk, body)
	return req
}

func executeAgentRequest(t *testing.T, client *http.Client, req *http.Request) (int, []byte) {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("execute Agent request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read Agent response: %v", err)
	}
	return resp.StatusCode, body
}
