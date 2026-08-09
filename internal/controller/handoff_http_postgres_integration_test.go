package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
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

// TestControllerUserAndAdminHandoffsAreNodeBoundAndSingleUse drives both
// browser handoff issuers and the Agent-authenticated redemption endpoints.
// The test deliberately tries the wrong node before the right one so a failed
// binding check cannot burn an otherwise valid one-time credential.
func TestControllerUserAndAdminHandoffsAreNodeBoundAndSingleUse(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller handoff PostgreSQL HTTP integration is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated Controller handoff store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	const (
		adminUsername      = "handoff-root-admin"
		adminPassword      = "handoff-root-password-2026"
		userPassword       = "handoff-user-password-2026"
		localAdminHandle   = "node-root"
		localAdminID       = "local-node-root-id"
		localAdminPassword = "node-root-password-2026"
		primaryPSK         = "handoff-primary-agent-psk-012345678901234"
		otherPSK           = "handoff-other-agent-psk-01234567890123456"
	)
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	adminHash, err := controlcrypto.HashPassword(adminPassword)
	if err != nil {
		t.Fatalf("hash handoff administrator password: %v", err)
	}
	created, err := st.BootstrapAdmin(ctx, adminUsername, adminHash, time.Now().UTC())
	if err != nil || !created {
		t.Fatalf("bootstrap handoff administrator: created=%v err=%v", created, err)
	}
	admin, err := st.GetAdminByUsername(ctx, adminUsername)
	if err != nil || admin == nil {
		t.Fatalf("load handoff administrator: admin=%+v err=%v", admin, err)
	}
	otherAdmin, err := st.CreateAdmin(ctx, "handoff-other-admin", adminHash, admin.ID, time.Now().UTC())
	if err != nil {
		t.Fatalf("create alternate handoff administrator: %v", err)
	}

	primaryNode := createControllerBackupNode(t, ctx, st, "handoff-http-primary", "compute", false, 1)
	otherNode := createControllerBackupNode(t, ctx, st, "handoff-http-other", "compute", false, 1)
	seedControllerBackupCredential(t, ctx, st, secretKey, primaryNode.ID, 1, primaryPSK)
	seedControllerBackupCredential(t, ctx, st, secretKey, otherNode.ID, 1, otherPSK)

	user := &store.User{
		Username: "handoff-http-user", DisplayName: "Handoff HTTP User",
		PasswordHash: sql.NullString{}, AuthProvider: "password",
		HomeNodeID: sql.NullInt64{Int64: primaryNode.ID, Valid: true}, Status: "active",
	}
	userHash, err := controlcrypto.HashPassword(userPassword)
	if err != nil {
		t.Fatalf("hash handoff user password: %v", err)
	}
	user.PasswordHash = sql.NullString{String: userHash, Valid: true}
	if err := st.CreateUser(ctx, user); err != nil {
		t.Fatalf("create handoff user: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,data_version,state,last_sync_at)
		VALUES ($1,$2,'home',1,'ready',now())`, user.ID, primaryNode.ID); err != nil {
		t.Fatalf("seed ready home replica: %v", err)
	}

	cfg := config.DefaultController()
	cfg.StaticDir = t.TempDir()
	cfg.Relay.Listen = ""
	cfg.Backup.AbortOnLogin = false
	server := New(cfg, st, secretKey)
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	cfg.PublicURL = httpServer.URL
	adminClient := newControllerHTTPClient(t)
	userClient := newControllerHTTPClient(t)
	assertControllerHTTPStatus(t, adminClient, http.MethodPost, httpServer.URL+"/api/auth/admin/login",
		map[string]string{"username": adminUsername, "password": adminPassword}, false, http.StatusOK)
	assertControllerHTTPStatus(t, userClient, http.MethodPost, httpServer.URL+"/api/auth/login",
		map[string]string{"username": user.Username, "password": userPassword}, false, http.StatusOK)

	nodePath := fmt.Sprintf("%s/api/admin/nodes/%d", httpServer.URL, primaryNode.ID)
	assertControllerHTTPStatus(t, adminClient, http.MethodGet, httpServer.URL+"/api/admin/node-links", nil, false, http.StatusOK)
	assertControllerHTTPStatus(t, adminClient, http.MethodPost, nodePath+"/admin-link",
		map[string]string{"operation_id": "invalid"}, true, http.StatusBadRequest)

	verifyOperation := "78000000-0000-4000-8000-000000000001"
	verificationResult := make(chan error, 1)
	go func() {
		verificationResult <- finishImportCommand(ctx, st, primaryNode.ID, primaryPSK, "verify_node_admin", func(plaintext []byte) (agentCommandSummary, error) {
			var request protocol.VerifyNodeAdminRequest
			if err := json.Unmarshal(plaintext, &request); err != nil {
				return agentCommandSummary{}, fmt.Errorf("decode node administrator verification: %w", err)
			}
			if request.OperationID != verifyOperation || request.Handle != localAdminHandle ||
				request.Password != localAdminPassword {
				return agentCommandSummary{}, fmt.Errorf("node administrator verification did not bind the submitted credentials")
			}
			return agentCommandSummary{OK: true, NodeAdmin: &protocol.NodeAdminVerification{
				Handle: localAdminHandle, LocalUserID: localAdminID,
				IsAdmin: true, PermissionVersion: 7,
			}}, nil
		})
	}()
	verifyRequest := map[string]any{
		"operation_id": verifyOperation, "handle": localAdminHandle, "password": localAdminPassword,
	}
	status, _, body := controllerHTTPRequest(t, adminClient, http.MethodPost, nodePath+"/admin-link", verifyRequest, true)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"state":"verified"`)) ||
		bytes.Contains(body, []byte(localAdminPassword)) {
		t.Fatalf("verify node administrator: status=%d body=%s", status, body)
	}
	if err := <-verificationResult; err != nil {
		t.Fatal(err)
	}
	// The same command/result and verification operation are both durable.
	assertControllerHTTPStatus(t, adminClient, http.MethodPost, nodePath+"/admin-link", verifyRequest, true, http.StatusOK)
	status, _, body = controllerHTTPRequest(t, adminClient, http.MethodGet, httpServer.URL+"/api/admin/node-links", nil, false)
	if status != http.StatusOK || !bytes.Contains(body, []byte(localAdminHandle)) ||
		!bytes.Contains(body, []byte(`"permission_version":7`)) {
		t.Fatalf("list verified node administrator link: status=%d body=%s", status, body)
	}

	adminHandoffOperation := "78000000-0000-4000-8000-000000000002"
	adminRecheckResult := make(chan error, 1)
	go func() {
		adminRecheckResult <- finishImportCommand(ctx, st, primaryNode.ID, primaryPSK, "check_node_admin", func(plaintext []byte) (agentCommandSummary, error) {
			var request protocol.CheckNodeAdminRequest
			if err := json.Unmarshal(plaintext, &request); err != nil || request.Handle != localAdminHandle {
				return agentCommandSummary{}, fmt.Errorf("decode node administrator recheck: handle=%q err=%v", request.Handle, err)
			}
			return agentCommandSummary{OK: true, NodeAdmin: &protocol.NodeAdminVerification{
				Handle: localAdminHandle, LocalUserID: localAdminID,
				IsAdmin: true, PermissionVersion: 8,
			}}, nil
		})
	}()
	handoffRequest := map[string]string{"operation_id": adminHandoffOperation}
	status, headers, body := controllerHTTPRequest(t, adminClient, http.MethodPost, nodePath+"/admin-handoff", handoffRequest, true)
	if status != http.StatusOK || !stringsContainNoStore(headers.Get("Cache-Control")) ||
		bytes.Contains(body, []byte(localAdminPassword)) {
		t.Fatalf("issue administrator handoff: status=%d cache=%q body=%s", status, headers.Get("Cache-Control"), body)
	}
	if err := <-adminRecheckResult; err != nil {
		t.Fatal(err)
	}
	var adminHandoff adminHandoffResponse
	if err := json.Unmarshal(body, &adminHandoff); err != nil || adminHandoff.Code == "" ||
		adminHandoff.TargetNodeID != primaryNode.ID || adminHandoff.FieldName != loginHandoffField {
		t.Fatalf("decode administrator handoff: handoff=%+v err=%v body=%s", adminHandoff, err, body)
	}
	if bytes.Contains([]byte(adminHandoff.PostURL), []byte(adminHandoff.Code)) {
		t.Fatal("administrator handoff placed its bearer code in the URL")
	}
	// Replay before redemption returns the same unpersisted secret/code.
	status, _, replayBody := controllerHTTPRequest(t, adminClient, http.MethodPost, nodePath+"/admin-handoff", handoffRequest, true)
	var replayedAdminHandoff adminHandoffResponse
	if err := json.Unmarshal(replayBody, &replayedAdminHandoff); err != nil || status != http.StatusOK ||
		replayedAdminHandoff.Code != adminHandoff.Code {
		t.Fatalf("replay administrator handoff: status=%d handoff=%+v err=%v body=%s", status, replayedAdminHandoff, err, replayBody)
	}
	adminJTI, adminSecret, ok := parseLoginHandoffCode(adminHandoff.Code)
	if !ok {
		t.Fatalf("parse issued administrator handoff code")
	}
	assertStoredHandoffHash(t, ctx, st, adminJTI, adminSecret, adminHandoff.Code)
	adminRedeemURL := httpServer.URL + "/api/tickets/redeem-admin"
	userRedeemURL := httpServer.URL + "/api/tickets/redeem"
	assertMalformedHandoffBodiesDoNotConsume(
		t, ctx, st, adminJTI, adminRedeemURL, primaryNode.ID, primaryPSK, adminHandoff.Code,
	)
	adminClaims := readStoredHandoffClaims(t, ctx, st, adminJTI)
	assertHandoffClaimMutationsDoNotConsume(t, ctx, st, adminClaims, adminRedeemURL,
		primaryNode.ID, primaryPSK, adminHandoff.Code, []handoffClaimMutation{
			{name: "type", assignment: "ticket_type=$2,admin_id=NULL", args: []any{"user_login"}},
			{name: "issuer", assignment: "issuer=$2", args: []any{"https://wrong-controller.example"}},
			{name: "audience", assignment: "audience=$2", args: []any{otherNode.BaseURL}},
			{name: "subject", assignment: "subject=$2", args: []any{"wrong-local-administrator"}},
			{name: "admin identity", assignment: "admin_id=$2", args: []any{otherAdmin.ID}},
			{name: "target node", assignment: "target_node_id=$2", args: []any{otherNode.ID}},
			{name: "key id", assignment: "key_id=$2", args: []any{"wrong-key"}},
			{name: "generation", assignment: "controller_generation=$2", args: []any{adminClaims.ControllerGeneration + 1}},
			{name: "future issued at", assignment: "issued_at=$2,not_before=$2,expires_at=$3", args: []any{time.Now().UTC().Add(time.Hour), time.Now().UTC().Add(2 * time.Hour)}},
			{name: "not before", assignment: "not_before=$2,expires_at=$3", args: []any{time.Now().UTC().Add(time.Hour), time.Now().UTC().Add(2 * time.Hour)}},
			{name: "expired", assignment: "issued_at=$2,not_before=$2,expires_at=$3", args: []any{time.Now().UTC().Add(-2 * time.Hour), time.Now().UTC().Add(-time.Hour)}},
		},
	)
	if got, response := agentSignedJSONRequest(t, &http.Client{Timeout: 10 * time.Second}, http.MethodPost,
		userRedeemURL, primaryNode.ID, primaryPSK, map[string]string{"code": adminHandoff.Code}); got != http.StatusForbidden {
		t.Fatalf("administrator code accepted by user redeemer: status=%d body=%s", got, response)
	}
	if got, response := agentSignedJSONRequest(t, &http.Client{Timeout: 10 * time.Second}, http.MethodPost,
		adminRedeemURL, otherNode.ID, otherPSK, map[string]string{"code": adminHandoff.Code}); got != http.StatusForbidden {
		t.Fatalf("wrong-node administrator redemption: status=%d body=%s", got, response)
	}
	if got, response := agentSignedJSONRequest(t, &http.Client{Timeout: 10 * time.Second}, http.MethodPost,
		adminRedeemURL, primaryNode.ID, primaryPSK, map[string]string{"code": adminHandoff.Code}); got != http.StatusOK ||
		!bytes.Contains(response, []byte(localAdminHandle)) {
		t.Fatalf("administrator redemption: status=%d body=%s", got, response)
	}
	if got, response := agentSignedJSONRequest(t, &http.Client{Timeout: 10 * time.Second}, http.MethodPost,
		adminRedeemURL, primaryNode.ID, primaryPSK, map[string]string{"code": adminHandoff.Code}); got != http.StatusForbidden {
		t.Fatalf("replayed administrator redemption: status=%d body=%s", got, response)
	}

	loginOperation := "78000000-0000-4000-8000-000000000003"
	loginURL := httpServer.URL + "/api/login/redirect"
	loginRequest := map[string]any{"operation_id": loginOperation, "node_id": primaryNode.ID}
	status, headers, body = controllerHTTPRequest(t, userClient, http.MethodPost, loginURL, loginRequest, true)
	if status != http.StatusOK || !stringsContainNoStore(headers.Get("Cache-Control")) {
		t.Fatalf("issue user handoff: status=%d cache=%q body=%s", status, headers.Get("Cache-Control"), body)
	}
	var userHandoff loginHandoffResponse
	if err := json.Unmarshal(body, &userHandoff); err != nil || userHandoff.Code == "" ||
		userHandoff.TargetNodeID != primaryNode.ID || userHandoff.FieldName != loginHandoffField {
		t.Fatalf("decode user handoff: handoff=%+v err=%v body=%s", userHandoff, err, body)
	}
	if bytes.Contains([]byte(userHandoff.PostURL), []byte(userHandoff.Code)) {
		t.Fatal("user handoff placed its bearer code in the URL")
	}
	status, _, replayBody = controllerHTTPRequest(t, userClient, http.MethodPost, loginURL, loginRequest, true)
	var replayedUserHandoff loginHandoffResponse
	if err := json.Unmarshal(replayBody, &replayedUserHandoff); err != nil || status != http.StatusOK ||
		replayedUserHandoff.Code != userHandoff.Code {
		t.Fatalf("replay user handoff: status=%d handoff=%+v err=%v body=%s", status, replayedUserHandoff, err, replayBody)
	}
	userJTI, userSecret, ok := parseLoginHandoffCode(userHandoff.Code)
	if !ok {
		t.Fatalf("parse issued user handoff code")
	}
	assertStoredHandoffHash(t, ctx, st, userJTI, userSecret, userHandoff.Code)
	assertMalformedHandoffBodiesDoNotConsume(
		t, ctx, st, userJTI, userRedeemURL, primaryNode.ID, primaryPSK, userHandoff.Code,
	)
	userClaims := readStoredHandoffClaims(t, ctx, st, userJTI)
	assertHandoffClaimMutationsDoNotConsume(t, ctx, st, userClaims, userRedeemURL,
		primaryNode.ID, primaryPSK, userHandoff.Code, []handoffClaimMutation{
			{name: "type", assignment: "ticket_type=$2,user_id=NULL,admin_id=$3", args: []any{"node_admin", admin.ID}},
			{name: "issuer", assignment: "issuer=$2", args: []any{"https://wrong-controller.example"}},
			{name: "audience", assignment: "audience=$2", args: []any{otherNode.BaseURL}},
			{name: "subject UUID", assignment: "subject=$2", args: []any{"00000000-0000-4000-8000-000000000099"}},
			{name: "user identity", assignment: "user_id=NULL"},
			{name: "target node", assignment: "target_node_id=$2", args: []any{otherNode.ID}},
			{name: "session", assignment: "session_id=$2", args: []any{"00000000-0000-4000-8000-000000000098"}},
			{name: "activity epoch", assignment: "activity_epoch=activity_epoch+1"},
			{name: "key id", assignment: "key_id=$2", args: []any{"wrong-key"}},
			{name: "generation", assignment: "controller_generation=$2", args: []any{userClaims.ControllerGeneration + 1}},
			{name: "future issued at", assignment: "issued_at=$2,not_before=$2,expires_at=$3", args: []any{time.Now().UTC().Add(time.Hour), time.Now().UTC().Add(2 * time.Hour)}},
			{name: "not before", assignment: "not_before=$2,expires_at=$3", args: []any{time.Now().UTC().Add(time.Hour), time.Now().UTC().Add(2 * time.Hour)}},
			{name: "expired", assignment: "issued_at=$2,not_before=$2,expires_at=$3", args: []any{time.Now().UTC().Add(-2 * time.Hour), time.Now().UTC().Add(-time.Hour)}},
		},
	)
	if got, response := agentSignedJSONRequest(t, &http.Client{Timeout: 10 * time.Second}, http.MethodPost,
		adminRedeemURL, primaryNode.ID, primaryPSK, map[string]string{"code": userHandoff.Code}); got != http.StatusForbidden {
		t.Fatalf("user code accepted by administrator redeemer: status=%d body=%s", got, response)
	}
	if got, response := agentSignedJSONRequest(t, &http.Client{Timeout: 10 * time.Second}, http.MethodPost,
		userRedeemURL, otherNode.ID, otherPSK, map[string]string{"code": userHandoff.Code}); got != http.StatusForbidden {
		t.Fatalf("wrong-node user redemption: status=%d body=%s", got, response)
	}
	if got, response := agentSignedJSONRequest(t, &http.Client{Timeout: 10 * time.Second}, http.MethodPost,
		userRedeemURL, primaryNode.ID, primaryPSK, map[string]string{"code": userHandoff.Code}); got != http.StatusOK ||
		!bytes.Contains(response, []byte(user.Username)) || !bytes.Contains(response, []byte(user.UUID)) ||
		!bytes.Contains(response, []byte(`"activity_epoch":1`)) {
		t.Fatalf("user redemption: status=%d body=%s", got, response)
	}
	if got, response := agentSignedJSONRequest(t, &http.Client{Timeout: 10 * time.Second}, http.MethodPost,
		userRedeemURL, primaryNode.ID, primaryPSK, map[string]string{"code": userHandoff.Code}); got != http.StatusForbidden {
		t.Fatalf("replayed user redemption: status=%d body=%s", got, response)
	}

	// Leave a second administrator ticket unconsumed, then prove that a later
	// permission downgrade makes the link stale and revokes that credential.
	pendingTicketResult := make(chan error, 1)
	go func() {
		pendingTicketResult <- finishImportCommand(ctx, st, primaryNode.ID, primaryPSK, "check_node_admin", func(plaintext []byte) (agentCommandSummary, error) {
			var request protocol.CheckNodeAdminRequest
			if err := json.Unmarshal(plaintext, &request); err != nil || request.Handle != localAdminHandle {
				return agentCommandSummary{}, fmt.Errorf("decode pending-ticket administrator recheck: handle=%q err=%v", request.Handle, err)
			}
			return agentCommandSummary{OK: true, NodeAdmin: &protocol.NodeAdminVerification{
				Handle: localAdminHandle, LocalUserID: localAdminID,
				IsAdmin: true, PermissionVersion: 9,
			}}, nil
		})
	}()
	status, _, body = controllerHTTPRequest(t, adminClient, http.MethodPost, nodePath+"/admin-handoff",
		map[string]string{"operation_id": "78000000-0000-4000-8000-000000000004"}, true)
	if status != http.StatusOK {
		t.Fatalf("issue pending administrator handoff: status=%d body=%s", status, body)
	}
	if err := <-pendingTicketResult; err != nil {
		t.Fatal(err)
	}
	var pendingAdminHandoff adminHandoffResponse
	if err := json.Unmarshal(body, &pendingAdminHandoff); err != nil || pendingAdminHandoff.Code == "" {
		t.Fatalf("decode pending administrator handoff: handoff=%+v err=%v", pendingAdminHandoff, err)
	}
	pendingJTI, _, ok := parseLoginHandoffCode(pendingAdminHandoff.Code)
	if !ok {
		t.Fatal("parse pending administrator handoff code")
	}

	downgradeResult := make(chan error, 1)
	go func() {
		downgradeResult <- finishImportCommand(ctx, st, primaryNode.ID, primaryPSK, "check_node_admin", func(plaintext []byte) (agentCommandSummary, error) {
			var request protocol.CheckNodeAdminRequest
			if err := json.Unmarshal(plaintext, &request); err != nil || request.Handle != localAdminHandle {
				return agentCommandSummary{}, fmt.Errorf("decode downgraded administrator recheck: handle=%q err=%v", request.Handle, err)
			}
			return agentCommandSummary{OK: true, NodeAdmin: &protocol.NodeAdminVerification{
				Handle: localAdminHandle, LocalUserID: localAdminID,
				IsAdmin: false, PermissionVersion: 10,
			}}, nil
		})
	}()
	assertControllerHTTPStatus(t, adminClient, http.MethodPost, nodePath+"/admin-handoff",
		map[string]string{"operation_id": "78000000-0000-4000-8000-000000000005"}, true, http.StatusForbidden)
	if err := <-downgradeResult; err != nil {
		t.Fatal(err)
	}
	var linkState, linkError string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT state,COALESCE(last_error_code,'') FROM admin_node_links
		WHERE admin_id=$1 AND node_id=$2`, admin.ID, primaryNode.ID).Scan(&linkState, &linkError); err != nil ||
		linkState != "stale" || linkError != "permission_revoked" {
		t.Fatalf("downgraded link state=%q error=%q err=%v", linkState, linkError, err)
	}
	if got, response := agentSignedJSONRequest(t, &http.Client{Timeout: 10 * time.Second}, http.MethodPost,
		adminRedeemURL, primaryNode.ID, primaryPSK, map[string]string{"code": pendingAdminHandoff.Code}); got != http.StatusForbidden {
		t.Fatalf("revoked pending administrator redemption: status=%d body=%s", got, response)
	}
	var revokedAt *time.Time
	if err := st.DB.QueryRowContext(ctx, `SELECT revoked_at FROM control_tickets WHERE jti=$1`, pendingJTI).Scan(&revokedAt); err != nil || revokedAt == nil {
		t.Fatalf("pending administrator ticket revoked_at=%v err=%v", revokedAt, err)
	}
	assertControllerHTTPStatus(t, adminClient, http.MethodDelete, nodePath+"/admin-link", nil, true, http.StatusOK)
	assertControllerHTTPStatus(t, adminClient, http.MethodPost, nodePath+"/admin-handoff",
		map[string]string{"operation_id": "78000000-0000-4000-8000-000000000006"}, true, http.StatusForbidden)

	var secretLeaks int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM agent_commands
		WHERE payload::text LIKE '%' || $1 || '%'`, localAdminPassword).Scan(&secretLeaks); err != nil || secretLeaks != 0 {
		t.Fatalf("encrypted administrator verification secret leaks=%d err=%v", secretLeaks, err)
	}
}

func assertStoredHandoffHash(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	jti string,
	secret []byte,
	code string,
) {
	t.Helper()
	var storedHash []byte
	if err := st.DB.QueryRowContext(ctx, `SELECT secret_hash FROM control_tickets WHERE jti=$1`, jti).Scan(&storedHash); err != nil {
		t.Fatalf("read handoff secret hash: %v", err)
	}
	want := sha256.Sum256(secret)
	if !bytes.Equal(storedHash, want[:]) || bytes.Contains(storedHash, []byte(code)) || bytes.Contains(storedHash, secret) {
		t.Fatalf("handoff bearer credential was not stored hash-only")
	}
}

type storedHandoffClaims struct {
	JTI                  string
	TicketType           string
	Issuer               string
	Audience             string
	Subject              string
	UserID               sql.NullInt64
	AdminID              sql.NullInt64
	TargetNodeID         sql.NullInt64
	SessionID            sql.NullString
	ActivityEpoch        sql.NullInt64
	KeyID                string
	ControllerGeneration int64
	IssuedAt             time.Time
	NotBefore            time.Time
	ExpiresAt            time.Time
}

type handoffClaimMutation struct {
	name       string
	assignment string
	args       []any
}

func readStoredHandoffClaims(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	jti string,
) storedHandoffClaims {
	t.Helper()
	var claims storedHandoffClaims
	claims.JTI = jti
	if err := st.DB.QueryRowContext(ctx, `
		SELECT ticket_type,issuer,audience,subject,user_id,admin_id,target_node_id,
		  session_id::text,activity_epoch,key_id,controller_generation,
		  issued_at,not_before,expires_at
		FROM control_tickets WHERE jti=$1`, jti).Scan(
		&claims.TicketType, &claims.Issuer, &claims.Audience, &claims.Subject,
		&claims.UserID, &claims.AdminID, &claims.TargetNodeID, &claims.SessionID,
		&claims.ActivityEpoch, &claims.KeyID, &claims.ControllerGeneration,
		&claims.IssuedAt, &claims.NotBefore, &claims.ExpiresAt,
	); err != nil {
		t.Fatalf("read stored handoff claims: %v", err)
	}
	return claims
}

func restoreStoredHandoffClaims(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	claims storedHandoffClaims,
) {
	t.Helper()
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE control_tickets SET
		  ticket_type=$2,issuer=$3,audience=$4,subject=$5,user_id=$6,admin_id=$7,
		  target_node_id=$8,session_id=$9,activity_epoch=$10,key_id=$11,
		  controller_generation=$12,issued_at=$13,not_before=$14,expires_at=$15
		WHERE jti=$1`, claims.JTI, claims.TicketType, claims.Issuer, claims.Audience,
		claims.Subject, claims.UserID, claims.AdminID, claims.TargetNodeID,
		claims.SessionID, claims.ActivityEpoch, claims.KeyID, claims.ControllerGeneration,
		claims.IssuedAt, claims.NotBefore, claims.ExpiresAt); err != nil {
		t.Fatalf("restore stored handoff claims: %v", err)
	}
}

func assertHandoffClaimMutationsDoNotConsume(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	claims storedHandoffClaims,
	redeemURL string,
	nodeID int64,
	psk, code string,
	mutations []handoffClaimMutation,
) {
	t.Helper()
	for _, mutation := range mutations {
		args := append([]any{claims.JTI}, mutation.args...)
		query := fmt.Sprintf("UPDATE control_tickets SET %s WHERE jti=$1", mutation.assignment)
		if _, err := st.DB.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("mutate %s handoff claim: %v", mutation.name, err)
		}
		status, response := agentSignedJSONRequest(t, &http.Client{Timeout: 10 * time.Second},
			http.MethodPost, redeemURL, nodeID, psk, map[string]string{"code": code})
		if status != http.StatusForbidden {
			t.Fatalf("%s handoff claim accepted: status=%d body=%s", mutation.name, status, response)
		}
		var consumedAt sql.NullTime
		if err := st.DB.QueryRowContext(ctx, `SELECT consumed_at FROM control_tickets WHERE jti=$1`,
			claims.JTI).Scan(&consumedAt); err != nil || consumedAt.Valid {
			t.Fatalf("%s handoff claim consumed credential: consumed=%v err=%v", mutation.name, consumedAt, err)
		}
		restoreStoredHandoffClaims(t, ctx, st, claims)
	}
}

func assertMalformedHandoffBodiesDoNotConsume(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	jti, redeemURL string,
	nodeID int64,
	psk, code string,
) {
	t.Helper()
	encodedCode, err := json.Marshal(code)
	if err != nil {
		t.Fatalf("encode handoff code for malformed matrix: %v", err)
	}
	bodies := [][]byte{
		[]byte(`{}`),
		[]byte(`{"code":123}`),
		[]byte(`{"code":null}`),
		[]byte(`[]`),
		[]byte(fmt.Sprintf(`{"code":%s,"unexpected":true}`, encodedCode)),
		[]byte(fmt.Sprintf(`{"code":%s} {}`, encodedCode)),
	}
	for index, body := range bodies {
		status, response := agentSignedRawRequest(t, &http.Client{Timeout: 10 * time.Second},
			http.MethodPost, redeemURL, nodeID, psk, body)
		if status != http.StatusBadRequest {
			t.Fatalf("malformed handoff body %d accepted: status=%d body=%s", index, status, response)
		}
		var consumedAt sql.NullTime
		if err := st.DB.QueryRowContext(ctx, `SELECT consumed_at FROM control_tickets WHERE jti=$1`,
			jti).Scan(&consumedAt); err != nil || consumedAt.Valid {
			t.Fatalf("malformed handoff body %d consumed credential: consumed=%v err=%v", index, consumedAt, err)
		}
	}
}
