package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

// TestControllerAccountImportScanAndPasswordClaim exercises the bounded
// inventory protocol and account-control proof through the real admin/user
// routes, encrypted command queue and PostgreSQL classification transaction.
func TestControllerAccountImportScanAndPasswordClaim(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller account import PostgreSQL HTTP integration is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated Controller import store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	const (
		adminUsername  = "import-root-admin"
		adminPassword  = "import-root-password-2026"
		claimPassword  = "local-account-password-2026"
		psk            = "import-agent-psk-012345678901234567890123"
		scanOperation  = "77000000-0000-4000-8000-000000000001"
		claimOperation = "77000000-0000-4000-8000-000000000002"
	)
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	adminHash, err := controlcrypto.HashPassword(adminPassword)
	if err != nil {
		t.Fatalf("hash import administrator password: %v", err)
	}
	created, err := st.BootstrapAdmin(ctx, adminUsername, adminHash, time.Now().UTC())
	if err != nil || !created {
		t.Fatalf("bootstrap import administrator: created=%v err=%v", created, err)
	}

	sourceNode := createControllerBackupNode(t, ctx, st, "import-http-source", "compute", false, 1)
	importNode := createControllerBackupNode(t, ctx, st, "import-http-target", "compute", false, 1)
	otherNode := createControllerBackupNode(t, ctx, st, "import-http-other", "compute", false, 1)
	seedControllerBackupCredential(t, ctx, st, secretKey, importNode.ID, 1, psk)

	claimUser := createControllerBackupUser(t, ctx, st, sourceNode.ID, "import-http-user")
	claimHash, err := controlcrypto.HashPassword(claimPassword)
	if err != nil {
		t.Fatalf("hash claim user password: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE users SET password_hash=$2 WHERE id=$1`, claimUser.ID, claimHash); err != nil {
		t.Fatalf("install claim user's legacy password hash: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE auth_identities SET password_hash=$2
		WHERE user_id=$1 AND provider='password'`, claimUser.GlobalID, claimHash); err != nil {
		t.Fatalf("install claim user's global password hash: %v", err)
	}

	managedUser := createControllerBackupUser(t, ctx, st, importNode.ID, "already-managed-user")
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE node_accounts SET local_user_id='local-0001',verified_at=now()
		WHERE user_id=$1 AND node_id=$2`, managedUser.GlobalID, importNode.ID); err != nil {
		t.Fatalf("seed already-managed local identity: %v", err)
	}
	oauthUser := createControllerBackupUser(t, ctx, st, sourceNode.ID, "oauth-match-user")
	conflictDiscordUser := createControllerBackupUser(t, ctx, st, sourceNode.ID, "discord-conflict-user")
	conflictLinuxDOUser := createControllerBackupUser(t, ctx, st, sourceNode.ID, "linuxdo-conflict-user")
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO auth_identities (user_id,provider,provider_subject,status)
		VALUES ($1,'discord','discord-oauth-match','active'),
		       ($2,'discord','discord-split-match','active'),
		       ($3,'linuxdo','linuxdo-split-match','active')`,
		oauthUser.GlobalID, conflictDiscordUser.GlobalID, conflictLinuxDOUser.GlobalID); err != nil {
		t.Fatalf("seed import OAuth subjects: %v", err)
	}

	inventory := []protocol.ScanExistingUser{
		{
			LocalUserID: "local-0001", Handle: managedUser.Username, Size: 101,
			DirectoryFingerprint: importTestFingerprint("directory-managed"),
			Source:               "adapter", AccountKind: "password",
		},
		{
			LocalUserID: "local-0002", Handle: claimUser.Username, Size: 102,
			DirectoryFingerprint: importTestFingerprint("directory-claim"),
			Source:               "adapter", AccountKind: "password",
		},
		{
			LocalUserID: "local-0003", Handle: "node-oauth-match", Size: 103,
			DirectoryFingerprint: importTestFingerprint("directory-oauth"),
			Source:               "adapter", AccountKind: "oauth", Identities: []protocol.ScanExistingIdentity{{
				Provider: "discord",
				Fingerprint: controlcrypto.AgentInventoryFingerprint(
					psk, "oauth-subject", "discord", "discord-oauth-match",
				),
			}},
		},
		{
			LocalUserID: "local-0004", Handle: "node-split-identity", Size: 104,
			DirectoryFingerprint: importTestFingerprint("directory-conflict"),
			Source:               "adapter", AccountKind: "mixed", Identities: []protocol.ScanExistingIdentity{
				{
					Provider: "discord",
					Fingerprint: controlcrypto.AgentInventoryFingerprint(
						psk, "oauth-subject", "discord", "discord-split-match",
					),
				},
				{
					Provider: "linuxdo",
					Fingerprint: controlcrypto.AgentInventoryFingerprint(
						psk, "oauth-subject", "linuxdo", "linuxdo-split-match",
					),
				},
			},
		},
		{
			LocalUserID: "local-0005", Handle: "node-unmatched-oauth", Size: 105,
			DirectoryFingerprint: importTestFingerprint("directory-unmatched"),
			Source:               "adapter", AccountKind: "oauth", Identities: []protocol.ScanExistingIdentity{{
				Provider: "discord", Fingerprint: importTestFingerprint("unmatched-oauth-subject"),
			}},
		},
		{
			LocalUserID: "local-0006", Handle: "node-recovery-only", Size: 106,
			DirectoryFingerprint: importTestFingerprint("directory-recovery"),
			Source:               "adapter", AccountKind: "password",
		},
	}

	cfg := config.DefaultController()
	cfg.StaticDir = t.TempDir()
	cfg.Relay.Listen = ""
	server := New(cfg, st, secretKey)
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	cfg.PublicURL = httpServer.URL
	adminClient := newControllerHTTPClient(t)
	assertControllerHTTPStatus(t, adminClient, http.MethodPost, httpServer.URL+"/api/auth/admin/login",
		map[string]string{"username": adminUsername, "password": adminPassword}, false, http.StatusOK)

	scanResult := make(chan error, 1)
	go func() {
		scanResult <- finishImportCommand(ctx, st, importNode.ID, psk, "scan_existing_page", func(plaintext []byte) (agentCommandSummary, error) {
			var request protocol.ScanExistingPageRequest
			if err := json.Unmarshal(plaintext, &request); err != nil {
				return agentCommandSummary{}, fmt.Errorf("decode inventory page request: %w", err)
			}
			if request.Cursor != 0 || request.InventoryRevision != "" || request.Limit != protocol.MaxAccountInventoryPageUsers {
				return agentCommandSummary{}, fmt.Errorf("unexpected inventory page request: %+v", request)
			}
			return agentCommandSummary{OK: true, InventoryPage: &protocol.ScanExistingPageResult{
				Users: inventory, Cursor: 0, TotalUsers: len(inventory),
				InventoryRevision: importTestFingerprint("inventory-revision"), HasMore: false,
			}}, nil
		})
	}()
	scanURL := fmt.Sprintf("%s/api/admin/nodes/%d/scan-existing", httpServer.URL, importNode.ID)
	status, headers, body := controllerHTTPRequest(t, adminClient, http.MethodPost, scanURL,
		map[string]string{"operation_id": scanOperation}, true)
	if status != http.StatusOK || !stringsContainNoStore(headers.Get("Cache-Control")) {
		t.Fatalf("scan existing accounts: status=%d cache=%q body=%s", status, headers.Get("Cache-Control"), body)
	}
	if err := <-scanResult; err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(psk)) || bytes.Contains(body, []byte("discord-oauth-match")) ||
		bytes.Contains(body, []byte("linuxdo-split-match")) {
		t.Fatalf("import response exposed Agent or raw provider identity material: %s", body)
	}
	var imported store.AccountImportResult
	if err := json.Unmarshal(body, &imported); err != nil {
		t.Fatalf("decode imported batch: %v body=%s", err, body)
	}
	if imported.Batch.NodeID != importNode.ID || imported.Batch.CandidateCount != 6 ||
		imported.Batch.AutoLinkedCount != 2 || imported.Batch.UnresolvedCount != 4 ||
		len(imported.Candidates) != 6 {
		t.Fatalf("classified import batch=%+v candidates=%+v", imported.Batch, imported.Candidates)
	}
	wantStates := map[string]string{
		managedUser.Username:   "already_managed",
		claimUser.Username:     "claim_required",
		"node-oauth-match":     "auto_linked",
		"node-split-identity":  "identity_conflict",
		"node-unmatched-oauth": "oauth_unmatched",
		"node-recovery-only":   "recovery_required",
	}
	for _, candidate := range imported.Candidates {
		if want := wantStates[candidate.LocalHandle]; want == "" || candidate.ResolutionState != want {
			t.Fatalf("candidate %q state=%q, want %q", candidate.LocalHandle, candidate.ResolutionState, want)
		}
	}

	// The durable operation result is returned without dispatching another
	// Agent scan, while attempting to reuse it for another node is rejected.
	status, _, body = controllerHTTPRequest(t, adminClient, http.MethodPost, scanURL,
		map[string]string{"operation_id": scanOperation}, true)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"replayed":true`)) {
		t.Fatalf("replay import scan: status=%d body=%s", status, body)
	}
	otherScanURL := fmt.Sprintf("%s/api/admin/nodes/%d/scan-existing", httpServer.URL, otherNode.ID)
	assertControllerHTTPStatus(t, adminClient, http.MethodPost, otherScanURL,
		map[string]string{"operation_id": scanOperation}, true, http.StatusConflict)
	latestURL := fmt.Sprintf("%s/api/admin/nodes/%d/imports/latest?limit=2&offset=0", httpServer.URL, importNode.ID)
	status, _, body = controllerHTTPRequest(t, adminClient, http.MethodGet, latestURL, nil, false)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"has_more":true`)) ||
		!bytes.Contains(body, []byte(`"next_candidate_offset":2`)) {
		t.Fatalf("paged latest import: status=%d body=%s", status, body)
	}

	userClient := newControllerHTTPClient(t)
	assertControllerHTTPStatus(t, userClient, http.MethodPost, httpServer.URL+"/api/auth/login",
		map[string]string{"username": claimUser.Username, "password": claimPassword}, false, http.StatusOK)
	claimsURL := httpServer.URL + "/api/users/me/import-claims"
	status, _, body = controllerHTTPRequest(t, userClient, http.MethodGet, claimsURL, nil, false)
	if status != http.StatusOK || !bytes.Contains(body, []byte(claimUser.Username)) ||
		!bytes.Contains(body, []byte(fmt.Sprintf(`"node_id":%d`, importNode.ID))) {
		t.Fatalf("list password claim target: status=%d body=%s", status, body)
	}

	badProofResult := make(chan error, 1)
	go func() {
		badProofResult <- finishImportCommand(ctx, st, importNode.ID, psk, "verify_local_user", func(plaintext []byte) (agentCommandSummary, error) {
			var request protocol.VerifyLocalUserRequest
			if err := json.Unmarshal(plaintext, &request); err != nil {
				return agentCommandSummary{}, fmt.Errorf("decode rejected claim proof: %w", err)
			}
			if request.Handle != claimUser.Username || request.Password != "wrong-local-password" {
				return agentCommandSummary{}, fmt.Errorf("unexpected rejected claim request")
			}
			return agentCommandSummary{OK: true, LocalUserProof: &protocol.VerifyLocalUserResponse{
				Handle: claimUser.Username, Verified: false,
			}}, nil
		})
	}()
	assertControllerHTTPStatus(t, userClient, http.MethodPost, claimsURL, map[string]any{
		"operation_id": "77000000-0000-4000-8000-000000000003",
		"node_id":      importNode.ID,
		"password":     "wrong-local-password",
	}, true, http.StatusForbidden)
	if err := <-badProofResult; err != nil {
		t.Fatal(err)
	}

	claimResult := make(chan error, 1)
	go func() {
		claimResult <- finishImportCommand(ctx, st, importNode.ID, psk, "verify_local_user", func(plaintext []byte) (agentCommandSummary, error) {
			var request protocol.VerifyLocalUserRequest
			if err := json.Unmarshal(plaintext, &request); err != nil {
				return agentCommandSummary{}, fmt.Errorf("decode accepted claim proof: %w", err)
			}
			if request.Handle != claimUser.Username || request.Password != claimPassword {
				return agentCommandSummary{}, fmt.Errorf("accepted claim did not bind the submitted local credentials")
			}
			return agentCommandSummary{OK: true, LocalUserProof: &protocol.VerifyLocalUserResponse{
				Handle: claimUser.Username, LocalUserID: "local-0002", Verified: true,
			}}, nil
		})
	}()
	claimRequest := map[string]any{
		"operation_id": claimOperation, "node_id": importNode.ID, "password": claimPassword,
	}
	assertControllerHTTPStatus(t, userClient, http.MethodPost, claimsURL, claimRequest, true, http.StatusOK)
	if err := <-claimResult; err != nil {
		t.Fatal(err)
	}
	status, _, body = controllerHTTPRequest(t, userClient, http.MethodGet, claimsURL, nil, false)
	if status != http.StatusOK || bytes.Contains(body, []byte(claimUser.Username)) {
		t.Fatalf("claimed target remained pending: status=%d body=%s", status, body)
	}

	// Response-loss retry uses the durable claim operation and does not send
	// the password to the node again. Rebinding the operation to another node
	// is fenced as a conflict.
	status, _, body = controllerHTTPRequest(t, userClient, http.MethodPost, claimsURL, claimRequest, true)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"replayed":true`)) {
		t.Fatalf("replay imported account claim: status=%d body=%s", status, body)
	}
	conflictingClaim := map[string]any{
		"operation_id": claimOperation, "node_id": otherNode.ID, "password": claimPassword,
	}
	assertControllerHTTPStatus(t, userClient, http.MethodPost, claimsURL, conflictingClaim, true, http.StatusConflict)

	var (
		linkedLocalID string
		claimOps      int
		secretLeaks   int
		auditRows     int
	)
	if err := st.DB.QueryRowContext(ctx, `
		SELECT local_user_id FROM node_accounts WHERE user_id=$1 AND node_id=$2`,
		claimUser.GlobalID, importNode.ID).Scan(&linkedLocalID); err != nil || linkedLocalID != "local-0002" {
		t.Fatalf("claimed node account local_id=%q err=%v", linkedLocalID, err)
	}
	if err := st.DB.QueryRowContext(ctx, `SELECT count(*) FROM account_import_claim_operations WHERE operation_id=$1`, claimOperation).Scan(&claimOps); err != nil || claimOps != 1 {
		t.Fatalf("durable claim operations=%d err=%v, want one", claimOps, err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM agent_commands
		WHERE payload::text LIKE '%' || $1 || '%' OR payload::text LIKE '%' || $2 || '%'`,
		claimPassword, "wrong-local-password").Scan(&secretLeaks); err != nil || secretLeaks != 0 {
		t.Fatalf("encrypted Agent queue secret leaks=%d err=%v", secretLeaks, err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM audit_logs WHERE action IN ('account-import-scan','account-import-claim')`).Scan(&auditRows); err != nil || auditRows != 2 {
		t.Fatalf("account import audit rows=%d err=%v, want two", auditRows, err)
	}
}

func finishImportCommand(
	ctx context.Context,
	st *store.Store,
	nodeID int64,
	psk, commandType string,
	handle func([]byte) (agentCommandSummary, error),
) error {
	workerID := "import-agent-worker-" + commandType
	deadline := time.Now().Add(10 * time.Second)
	for {
		lease, err := st.LeaseAgentCommand(ctx, nodeID, workerID, time.Now().UTC(), time.Minute)
		if err != nil {
			return fmt.Errorf("lease %s command: %w", commandType, err)
		}
		if lease == nil {
			if time.Now().After(deadline) {
				return fmt.Errorf("%s command was not enqueued", commandType)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		if lease.CommandType != commandType {
			return fmt.Errorf("leased command type %q, want %q", lease.CommandType, commandType)
		}
		ok, err := st.AckAgentCommand(
			ctx, lease.ID, nodeID, workerID, lease.ControllerGeneration,
			time.Now().UTC(), time.Minute,
		)
		if err != nil {
			return fmt.Errorf("ack %s command: %w", commandType, err)
		}
		if !ok {
			return fmt.Errorf("ack %s command was fenced", commandType)
		}
		plaintext, err := decryptControllerBackupCommand(lease, psk)
		if err != nil {
			return fmt.Errorf("decrypt %s command: %w", commandType, err)
		}
		summary, err := handle(plaintext)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(summary)
		if err != nil {
			return fmt.Errorf("encode %s result: %w", commandType, err)
		}
		digest := sha256.Sum256(encoded)
		ok, err = st.FinishAgentCommand(ctx, store.FinishAgentCommandParams{
			ID: lease.ID, NodeID: nodeID, WorkerID: workerID,
			ControllerGeneration: lease.ControllerGeneration, Succeeded: true,
			ResultSummary: encoded, ResultDigest: digest[:], Now: time.Now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("finish %s command: %w", commandType, err)
		}
		if !ok {
			return fmt.Errorf("finish %s command was fenced", commandType)
		}
		return nil
	}
}

func importTestFingerprint(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
