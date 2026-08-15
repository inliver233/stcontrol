package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"stcontrol/internal/config"
	controlcrypto "stcontrol/internal/crypto"
	"stcontrol/internal/protocol"
	"stcontrol/internal/store"
)

func TestControllerPasswordChangeStagesAndResumesEveryNode(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller password-sync PostgreSQL integration is disabled in short mode")
	}
	ctx, st, generation, _ := newControllerRetirementStore(t)
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	online := createControllerBackupNode(t, ctx, st, "password-sync-online", "compute", false, generation)
	delayed := createControllerBackupNode(t, ctx, st, "password-sync-delayed", "compute", false, generation)
	psks := map[int64]string{
		online.ID:  "password-sync-online-psk",
		delayed.ID: "password-sync-delayed-psk",
	}
	for nodeID, psk := range psks {
		seedControllerBackupCredential(t, ctx, st, secretKey, nodeID, generation, psk)
	}
	const (
		oldPassword = "password-sync-old-2026"
		newPassword = "password-sync-new-2026"
	)
	oldHash, err := controlcrypto.HashPassword(oldPassword)
	if err != nil {
		t.Fatalf("hash old password-sync password: %v", err)
	}
	user := createControllerBackupUser(t, ctx, st, online.ID, "password-sync-user")
	if _, err := st.DB.ExecContext(ctx, `UPDATE users SET password_hash=$2 WHERE id=$1`, user.ID, oldHash); err != nil {
		t.Fatalf("install legacy password verifier: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE auth_identities SET password_hash=$2 WHERE user_id=$1 AND provider='password'`,
		user.GlobalID, oldHash); err != nil {
		t.Fatalf("install global password verifier: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO node_accounts (user_id,node_id,local_handle,status)
		VALUES ($1,$2,$3,'active')`, user.GlobalID, delayed.ID, user.Username); err != nil {
		t.Fatalf("seed delayed password-sync account: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET connectivity_state='offline' WHERE id=$1`, delayed.ID); err != nil {
		t.Fatalf("make delayed password-sync node offline: %v", err)
	}
	var delayedFailures atomic.Int32
	var materialMu sync.Mutex
	var deliveredNodeHash, deliveredNodeSalt string
	harness := newControllerDurableCommandHarness(
		ctx, st, psks,
		func(nodeID int64, lease *store.AgentCommandLease, plaintext []byte) (agentCommandSummary, bool, error) {
			if lease.CommandType != "set_password" {
				return agentCommandSummary{}, false, fmt.Errorf("unexpected password-sync command %q", lease.CommandType)
			}
			var request protocol.SetPasswordRequest
			if err := json.Unmarshal(plaintext, &request); err != nil || request.Handle != user.Username ||
				request.PasswordHash == "" || request.PasswordSalt == "" || request.Version != 1 ||
				bytes.Contains(plaintext, []byte(newPassword)) {
				return agentCommandSummary{}, false, fmt.Errorf("invalid password-sync payload on node %d: request=%+v err=%v", nodeID, request, err)
			}
			materialMu.Lock()
			if deliveredNodeHash == "" {
				deliveredNodeHash, deliveredNodeSalt = request.PasswordHash, request.PasswordSalt
			}
			materialMatches := deliveredNodeHash == request.PasswordHash && deliveredNodeSalt == request.PasswordSalt
			materialMu.Unlock()
			if !materialMatches {
				return agentCommandSummary{}, false, fmt.Errorf("password-sync retry changed durable material on node %d", nodeID)
			}
			if nodeID == delayed.ID && delayedFailures.Add(1) == 1 {
				return agentCommandSummary{OK: false, Code: "set_password_failed"}, false, nil
			}
			return agentCommandSummary{OK: true}, true, nil
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
	assertControllerHTTPStatus(t, client, http.MethodPost, httpServer.URL+"/api/auth/login", map[string]string{
		"username": user.Username, "password": oldPassword,
	}, false, http.StatusOK)
	passwordPath := httpServer.URL + "/api/users/me/password"
	assertControllerHTTPStatus(t, client, http.MethodPost, passwordPath, map[string]string{
		"old_password": oldPassword, "new_password": "short",
	}, true, http.StatusBadRequest)
	assertControllerHTTPStatus(t, client, http.MethodPost, passwordPath, map[string]string{
		"old_password": "wrong-password", "new_password": newPassword,
	}, true, http.StatusForbidden)
	statusCode, _, body := controllerHTTPRequest(t, client, http.MethodPost, passwordPath, map[string]string{
		"old_password": oldPassword, "new_password": newPassword,
	}, true)
	if statusCode != http.StatusAccepted || !bytes.Contains(body, []byte(`"node_sync":"pending"`)) {
		t.Fatalf("stage partial password change: status=%d body=%s", statusCode, body)
	}
	if harness.commandCount("set_password") != 1 {
		t.Fatalf("immediate password commands=%d", harness.commandCount("set_password"))
	}
	// While a node has not yet converged (the delayed node is still pending),
	// login must still accept the immediately-previous password so an offline
	// node does not create a split where only some locations recognize it.
	assertControllerHTTPStatus(t, newControllerHTTPClient(t), http.MethodPost,
		httpServer.URL+"/api/auth/login", map[string]string{
			"username": user.Username, "password": oldPassword,
		}, false, http.StatusOK)
	assertControllerHTTPStatus(t, newControllerHTTPClient(t), http.MethodPost,
		httpServer.URL+"/api/auth/login", map[string]string{
			"username": user.Username, "password": newPassword,
		}, false, http.StatusOK)
	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET connectivity_state='online' WHERE id=$1`, delayed.ID); err != nil {
		t.Fatalf("restore delayed password-sync node: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE node_accounts SET updated_at=now()-interval '3 minutes'
		WHERE user_id=$1 AND node_id=$2`, user.GlobalID, delayed.ID); err != nil {
		t.Fatalf("advance delayed password-sync account: %v", err)
	}
	restarted := New(config.DefaultController(), st, secretKey)
	restarted.reconcilePendingPasswords(ctx)
	waitControllerNodeAccountState(t, ctx, st, user.GlobalID, delayed.ID, "error", 5*time.Second)
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE node_accounts SET updated_at=now()-interval '3 minutes'
		WHERE user_id=$1 AND node_id=$2`, user.GlobalID, delayed.ID); err != nil {
		t.Fatalf("advance failed password-sync retry: %v", err)
	}
	pendingSyncs, err := st.ListPendingPasswordSyncs(ctx, 20, time.Now().UTC())
	if err != nil || len(pendingSyncs) != 1 || pendingSyncs[0].NodeID != delayed.ID {
		t.Fatalf("load durable password retry: syncs=%+v err=%v", pendingSyncs, err)
	}
	if synced, pending := restarted.deliverPasswordSyncs(ctx, pendingSyncs); synced != 1 || pending != 0 {
		t.Fatalf("deliver durable password retry: synced=%d pending=%d harness_errors=%v",
			synced, pending, harness.errors())
	}
	waitControllerNodeAccountState(t, ctx, st, user.GlobalID, delayed.ID, "active", 5*time.Second)
	if harness.commandCount("set_password") != 3 || delayedFailures.Load() != 2 {
		t.Fatalf("password retry commands=%d delayed attempts=%d",
			harness.commandCount("set_password"), delayedFailures.Load())
	}
	materialMu.Lock()
	persistedNodeHash, persistedNodeSalt := deliveredNodeHash, deliveredNodeSalt
	materialMu.Unlock()
	var activeAccounts, materialMatches int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE status='active'),
		  count(*) FILTER (WHERE password_hash=$2 AND password_salt=$3 AND password_material_version=1)
		FROM node_accounts WHERE user_id=$1`, user.GlobalID, persistedNodeHash, persistedNodeSalt).Scan(
		&activeAccounts, &materialMatches,
	); err != nil || activeAccounts != 2 || materialMatches != 2 {
		t.Fatalf("password convergence active=%d material=%d err=%v", activeAccounts, materialMatches, err)
	}
	// Once every node has confirmed the new version, the previous verifier is
	// dropped and the old password is rejected everywhere (no permanent split).
	assertControllerHTTPStatus(t, newControllerHTTPClient(t), http.MethodPost,
		httpServer.URL+"/api/auth/login", map[string]string{
			"username": user.Username, "password": oldPassword,
		}, false, http.StatusForbidden)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	restarted.passwordSyncReconciler(cancelled)
	if synced, pending := restarted.deliverPasswordSyncs(cancelled, []store.PendingPasswordSync{{}, {}}); synced != 0 || pending != 2 {
		t.Fatalf("cancelled password delivery synced=%d pending=%d", synced, pending)
	}
	if errs := harness.errors(); len(errs) > 0 {
		t.Fatalf("password-sync durable command harness errors: %v", errs)
	}
}

func TestControllerPasswordRemovalUsesExactVersionAndCancelsStaleOfflineRemoval(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller password-removal PostgreSQL integration is disabled in short mode")
	}
	ctx, st, generation, _ := newControllerRetirementStore(t)
	secretKey := []byte("0123456789abcdef0123456789abcdef")
	online := createControllerBackupNode(t, ctx, st, "password-removal-online", "compute", false, generation)
	offline := createControllerBackupNode(t, ctx, st, "password-removal-offline", "compute", false, generation)
	psks := map[int64]string{
		online.ID:  "password-removal-online-psk",
		offline.ID: "password-removal-offline-psk",
	}
	for nodeID, psk := range psks {
		seedControllerBackupCredential(t, ctx, st, secretKey, nodeID, generation, psk)
	}
	user := createControllerBackupUser(t, ctx, st, online.ID, "password-removal-user")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO node_accounts (user_id,node_id,local_handle,status,updated_at)
		VALUES ($1,$2,$3,'active',$4)`, user.GlobalID, offline.ID, user.Username, now); err != nil {
		t.Fatalf("seed offline password-removal account: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO auth_identities (user_id,provider,provider_subject,status,created_at,updated_at)
		VALUES ($1,'discord',$2,'active',$3,$3)`, user.GlobalID, "password-removal-discord", now); err != nil {
		t.Fatalf("seed secondary oauth identity: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET connectivity_state='offline' WHERE id=$1`, offline.ID); err != nil {
		t.Fatalf("make offline password-removal node offline: %v", err)
	}
	if err := st.UnbindUserIdentity(ctx, user.ID, user.GlobalID, "password", now); err != nil {
		t.Fatalf("unbind password identity: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE node_account_password_removals
		SET updated_at=$2
		WHERE global_user_id=$1`, user.GlobalID, now.Add(-3*time.Minute)); err != nil {
		t.Fatalf("age password removals: %v", err)
	}
	var removalVersions int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM node_account_password_removals
		WHERE global_user_id=$1 AND password_material_version=1 AND state='pending'`, user.GlobalID).
		Scan(&removalVersions); err != nil || removalVersions != 2 {
		t.Fatalf("pending removal versions=%d err=%v", removalVersions, err)
	}

	var removeCalls atomic.Int32
	harness := newControllerDurableCommandHarness(
		ctx, st, psks,
		func(nodeID int64, lease *store.AgentCommandLease, plaintext []byte) (agentCommandSummary, bool, error) {
			if lease.CommandType != "set_password" {
				return agentCommandSummary{}, false, fmt.Errorf("unexpected password-removal command %q", lease.CommandType)
			}
			var request protocol.SetPasswordRequest
			if err := json.Unmarshal(plaintext, &request); err != nil ||
				request.Handle != user.Username || !request.Remove || request.Version != 1 {
				return agentCommandSummary{}, false, fmt.Errorf(
					"invalid password-removal payload on node %d: request=%+v err=%v", nodeID, request, err,
				)
			}
			removeCalls.Add(1)
			return agentCommandSummary{OK: true}, true, nil
		},
	)
	t.Cleanup(harness.stop)
	server := New(config.DefaultController(), st, secretKey)
	removals, err := st.ListPendingPasswordRemovals(ctx, 20, time.Now().UTC())
	if err != nil || len(removals) != 1 || removals[0].NodeID != online.ID || removals[0].Version != 1 {
		t.Fatalf("load online password removals: removals=%+v err=%v", removals, err)
	}
	if synced, pending := server.deliverPasswordRemovals(ctx, removals); synced != 1 || pending != 0 {
		t.Fatalf("deliver password removals synced=%d pending=%d harness_errors=%v", synced, pending, harness.errors())
	}
	if removeCalls.Load() != 1 {
		t.Fatalf("password removal command count=%d", removeCalls.Load())
	}

	if err := st.BindPasswordIdentity(
		ctx, user.ID, user.GlobalID, "rebound-bcrypt-hash", "rebound-node-hash", "rebound-node-salt", now.Add(time.Second),
	); err != nil {
		t.Fatalf("rebind password identity: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE nodes SET connectivity_state='online' WHERE id=$1`, offline.ID); err != nil {
		t.Fatalf("restore offline password-removal node: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE node_account_password_removals
		SET updated_at=$2
		WHERE global_user_id=$1`, user.GlobalID, now.Add(-6*time.Minute)); err != nil {
		t.Fatalf("re-age password removals after rebind: %v", err)
	}
	removals, err = st.ListPendingPasswordRemovals(ctx, 20, time.Now().UTC())
	if err != nil || len(removals) != 0 {
		t.Fatalf("stale password removals survived rebind: removals=%+v err=%v", removals, err)
	}
	var pendingCount int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM node_account_password_removals
		WHERE global_user_id=$1 AND state='pending'`, user.GlobalID).Scan(&pendingCount); err != nil || pendingCount != 0 {
		t.Fatalf("pending password removals=%d err=%v", pendingCount, err)
	}
	if errs := harness.errors(); len(errs) > 0 {
		t.Fatalf("password-removal durable command harness errors: %v", errs)
	}
}

func waitControllerNodeAccountState(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	globalUserID, nodeID int64,
	want string,
	timeout time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var status string
		err := st.DB.QueryRowContext(ctx, `
			SELECT status FROM node_accounts WHERE user_id=$1 AND node_id=$2`, globalUserID, nodeID).Scan(&status)
		if err == nil && status == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("node account %d/%d status=%q want=%q err=%v", globalUserID, nodeID, status, want, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
