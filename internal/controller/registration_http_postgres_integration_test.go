package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// TestControllerPasswordRegistrationSurvivesResponseLoss proves the public
// registration handoff against PostgreSQL and the durable Agent command queue.
// Besides the successful path it verifies origin, invitation, operation replay,
// request-conflict and secret-at-rest boundaries through the actual router.
func TestControllerPasswordRegistrationSurvivesResponseLoss(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller registration PostgreSQL HTTP integration is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated Controller registration store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	const (
		password       = "registration-password-2026"
		invitationCode = "single-use-node-invitation"
		operationID    = "76000000-0000-4000-8000-000000000001"
		psk            = "registration-agent-psk-01234567890123456789"
	)
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	node := createControllerBackupNode(t, ctx, st, "registration-http-compute", "compute", false, 1)
	seedControllerBackupCredential(t, ctx, st, secretKey, node.ID, 1, psk)
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE nodes SET allow_register=true,registration_policy_state='invitation_required',
		  registration_policy_version=7,registration_policy_expires_at=now()+interval '1 hour',
		  registration_policy_observed_at=now()
		WHERE id=$1`, node.ID); err != nil {
		t.Fatalf("publish node-owned registration policy: %v", err)
	}

	cfg := config.DefaultController()
	cfg.StaticDir = t.TempDir()
	cfg.Relay.Listen = ""
	server := New(cfg, st, secretKey)
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	cfg.PublicURL = httpServer.URL
	registrationURL := httpServer.URL + "/api/auth/register"
	statusURL := httpServer.URL + "/api/auth/registration/status"

	emptyClient := newControllerHTTPClient(t)
	assertControllerHTTPStatus(t, emptyClient, http.MethodGet, statusURL, nil, false, http.StatusUnauthorized)
	request := map[string]any{
		"operation_id": operationID,
		"username":     "registration-http-user",
		"display_name": "Registration HTTP User",
		"password":     password,
		"node_id":      node.ID,
	}
	assertControllerHTTPStatus(t, emptyClient, http.MethodPost, registrationURL, request, false, http.StatusBadRequest)

	// validMutationOrigin must reject a cross-site browser even though the
	// endpoint is unauthenticated.
	crossSiteBody, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encode cross-site registration: %v", err)
	}
	crossSiteRequest, err := http.NewRequest(http.MethodPost, registrationURL, bytes.NewReader(crossSiteBody))
	if err != nil {
		t.Fatalf("create cross-site registration: %v", err)
	}
	crossSiteRequest.Header.Set("Origin", "https://attacker.invalid")
	crossSiteRequest.Header.Set("Content-Type", "application/json")
	crossSiteResponse, err := emptyClient.Do(crossSiteRequest)
	if err != nil {
		t.Fatalf("execute cross-site registration: %v", err)
	}
	_ = crossSiteResponse.Body.Close()
	if crossSiteResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site registration status=%d, want %d", crossSiteResponse.StatusCode, http.StatusForbidden)
	}

	request["invitation_code"] = invitationCode
	client := newControllerHTTPClient(t)
	status, headers, body := controllerHTTPRequest(t, client, http.MethodPost, registrationURL, request, false)
	if status != http.StatusAccepted || !stringsContainNoStore(headers.Get("Cache-Control")) {
		t.Fatalf("start registration: status=%d cache=%q body=%s", status, headers.Get("Cache-Control"), body)
	}
	pendingToken := controllerCookieValue(t, client, statusURL, registrationPendingCookie)
	if pendingToken == "" {
		t.Fatal("registration response did not issue an opaque pending cookie")
	}
	pendingHash := sha256.Sum256([]byte(pendingToken))
	var (
		storedPendingHash []byte
		requestDigest     []byte
		invitationCipher  string
		passwordHash      string
		materialHash      string
		materialSalt      string
	)
	if err := st.DB.QueryRowContext(ctx, `
		SELECT pending_token_hash,request_digest,invitation_ciphertext,password_hash,
		  password_material_hash,password_material_salt
		FROM registration_workflows WHERE workflow_id=(
		  SELECT id FROM workflows WHERE operation_id=$1
		)`, operationID).Scan(
		&storedPendingHash, &requestDigest, &invitationCipher, &passwordHash, &materialHash, &materialSalt,
	); err != nil {
		t.Fatalf("read durable registration handoff: %v", err)
	}
	if !bytes.Equal(storedPendingHash, pendingHash[:]) || len(requestDigest) != sha256.Size ||
		bytes.Contains(storedPendingHash, []byte(pendingToken)) || invitationCipher == invitationCode ||
		passwordHash == password || materialHash == password || materialSalt == password {
		t.Fatal("registration stored a bearer token, invitation or password without one-way/encrypted protection")
	}

	// Start the Agent only after the first response has been returned. Polling
	// the pending cookie must therefore recover a deliberately lost response.
	workerResult := make(chan error, 1)
	go func() {
		workerResult <- finishRegistrationCommand(ctx, st, node.ID, psk, password, invitationCode)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, _, body = controllerHTTPRequest(t, client, http.MethodGet, statusURL, nil, false)
		if status == http.StatusOK {
			break
		}
		if status != http.StatusAccepted || time.Now().After(deadline) {
			t.Fatalf("poll registration: status=%d body=%s", status, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := <-workerResult; err != nil {
		t.Fatal(err)
	}
	if controllerCookieValue(t, client, statusURL, registrationPendingCookie) != "" {
		t.Fatal("terminal registration left the pending cookie active")
	}
	assertControllerSessionCookies(t, client, httpServer.URL+"/api/users/me")
	assertControllerHTTPStatus(t, client, http.MethodGet, httpServer.URL+"/api/users/me", nil, false, http.StatusOK)

	var (
		workflowState, reservationState string
		legacyUserID, globalUserID      int64
		localUserID                     string
		storedCommand                   []byte
	)
	if err := st.DB.QueryRowContext(ctx, `
		SELECT workflow.state,registration.reservation_state,registration.result_user_id,
		  global_user.id,node_account.local_user_id,command.payload
		FROM workflows workflow
		JOIN registration_workflows registration ON registration.workflow_id=workflow.id
		JOIN users legacy ON legacy.id=registration.result_user_id
		JOIN global_users global_user ON global_user.legacy_user_id=legacy.id
		JOIN node_accounts node_account ON node_account.user_id=global_user.id AND node_account.node_id=workflow.target_node_id
		JOIN agent_commands command ON command.node_id=workflow.target_node_id
		  AND command.command_type='provision_user'
		WHERE workflow.operation_id=$1`, operationID).Scan(
		&workflowState, &reservationState, &legacyUserID, &globalUserID, &localUserID, &storedCommand,
	); err != nil {
		t.Fatalf("read atomically published registration facts: %v", err)
	}
	if workflowState != "succeeded" || reservationState != "published" || legacyUserID <= 0 ||
		globalUserID <= 0 || localUserID != "local-registration-http-user" ||
		bytes.Contains(storedCommand, []byte(password)) || bytes.Contains(storedCommand, []byte(invitationCode)) {
		t.Fatalf("published facts: workflow=%q reservation=%q legacy=%d global=%d local=%q command=%s",
			workflowState, reservationState, legacyUserID, globalUserID, localUserID, storedCommand)
	}

	// An exact retry gets the already-published outcome with a replacement
	// hash-only pending token; changing the digest under the same operation ID
	// is rejected and cannot mutate the completed workflow.
	replayClient := newControllerHTTPClient(t)
	status, _, body = controllerHTTPRequest(t, replayClient, http.MethodPost, registrationURL, request, false)
	if status != http.StatusOK {
		t.Fatalf("exact registration replay: status=%d body=%s", status, body)
	}
	conflictRequest := make(map[string]any, len(request))
	for key, value := range request {
		conflictRequest[key] = value
	}
	conflictRequest["display_name"] = "Different Request"
	assertControllerHTTPStatus(t, newControllerHTTPClient(t), http.MethodPost, registrationURL, conflictRequest, false, http.StatusConflict)
	var workflowCount int
	if err := st.DB.QueryRowContext(ctx, `SELECT count(*) FROM workflows WHERE operation_id=$1`, operationID).Scan(&workflowCount); err != nil || workflowCount != 1 {
		t.Fatalf("registration operation rows=%d err=%v, want one", workflowCount, err)
	}
}

func finishRegistrationCommand(
	ctx context.Context,
	st *store.Store,
	nodeID int64,
	psk, rawPassword, invitationCode string,
) error {
	const workerID = "registration-agent-worker-0001"
	deadline := time.Now().Add(10 * time.Second)
	for {
		lease, err := st.LeaseAgentCommand(ctx, nodeID, workerID, time.Now().UTC(), time.Minute)
		if err != nil {
			return fmt.Errorf("lease registration command: %w", err)
		}
		if lease == nil {
			if time.Now().After(deadline) {
				return fmt.Errorf("registration command was not enqueued")
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		if lease.CommandType != "provision_user" {
			return fmt.Errorf("leased command type %q, want provision_user", lease.CommandType)
		}
		ok, err := st.AckAgentCommand(
			ctx, lease.ID, nodeID, workerID, lease.ControllerGeneration,
			time.Now().UTC(), time.Minute,
		)
		if err != nil || !ok {
			return fmt.Errorf("ack registration command: ok=%v err=%w", ok, err)
		}
		plaintext, err := decryptControllerBackupCommand(lease, psk)
		if err != nil {
			return fmt.Errorf("decrypt registration command: %w", err)
		}
		var request protocol.ProvisionUserRequest
		if err := json.Unmarshal(plaintext, &request); err != nil {
			return fmt.Errorf("decode registration command: %w", err)
		}
		if request.RegistrationID == "" || request.PolicyVersion != 7 ||
			request.Handle != "registration-http-user" || request.Name != "Registration HTTP User" ||
			request.PasswordHash == "" || request.PasswordSalt == "" ||
			request.PasswordHash == rawPassword || request.PasswordSalt == rawPassword ||
			request.InvitationCode != invitationCode || bytes.Contains(plaintext, []byte(rawPassword)) {
			return fmt.Errorf("registration command did not bind the expected protected identity material")
		}
		summary, err := json.Marshal(agentCommandSummary{
			OK: true, LocalUserID: "local-registration-http-user",
		})
		if err != nil {
			return fmt.Errorf("encode registration result: %w", err)
		}
		digest := sha256.Sum256(summary)
		ok, err = st.FinishAgentCommand(ctx, store.FinishAgentCommandParams{
			ID: lease.ID, NodeID: nodeID, WorkerID: workerID,
			ControllerGeneration: lease.ControllerGeneration, Succeeded: true,
			ResultSummary: summary, ResultDigest: digest[:], Now: time.Now().UTC(),
		})
		if err != nil || !ok {
			return fmt.Errorf("finish registration command: ok=%v err=%w", ok, err)
		}
		return nil
	}
}

func stringsContainNoStore(value string) bool {
	return bytes.Contains([]byte(value), []byte("no-store"))
}
