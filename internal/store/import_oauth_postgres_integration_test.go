package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"testing"
	"time"
)

func TestPostgresOAuthImportLoginProofFreezesIndependentNodeData(t *testing.T) {
	if testing.Short() {
		t.Skip("OAuth import PostgreSQL integration is disabled in short mode")
	}
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	t.Cleanup(cleanupSchema)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open OAuth import store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	firstNodeID := insertIntegrationNode(t, st, "oauth-import-first")
	secondNodeID := insertIntegrationNode(t, st, "oauth-import-second")
	user := &User{
		Username: "oauth-import-home", DisplayName: "OAuth import home",
		PasswordHash: sql.NullString{String: "oauth-import-password-hash", Valid: true},
		AuthProvider: "password", HomeNodeID: sql.NullInt64{Int64: firstNodeID, Valid: true},
		Status: "active",
	}
	if err := st.CreateUser(ctx, user); err != nil {
		t.Fatalf("create OAuth import user: %v", err)
	}
	if err := st.BindOAuthIdentity(ctx, user.GlobalID, "discord", "oauth-import-subject", time.Now().UTC()); err != nil {
		t.Fatalf("bind OAuth import identity: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	fingerprint := hex.EncodeToString(bytes.Repeat([]byte{0xcc}, 32))
	batch, err := st.IngestAccountImportBatch(ctx, CreateAccountImportBatchParams{
		ID:          "75400000-0000-4000-8000-000000000001",
		OperationID: "75400000-0000-4000-8000-000000000002",
		NodeID:      secondNodeID, InventoryDigest: bytes.Repeat([]byte{0xdd}, 32),
		Source: "adapter", Now: now,
		Candidates: []AccountImportCandidateInput{{
			ID:          "75400000-0000-4000-8000-000000000003",
			LocalUserID: "oauth-import-local-2", LocalHandle: "oauth-import-remote",
			SizeBytes: 42, DirectoryFingerprint: fingerprint, Source: "adapter", AccountKind: "oauth",
			Identities: []AccountImportIdentityFingerprint{{Provider: "discord", Fingerprint: fingerprint}},
		}},
	})
	if err != nil || batch == nil || len(batch.Candidates) != 1 ||
		batch.Candidates[0].ResolutionState != "oauth_unmatched" {
		t.Fatalf("ingest unmatched OAuth import: batch=%+v err=%v", batch, err)
	}
	resolved, err := st.ResolveOAuthUnmatchedCandidates(
		ctx, "discord", fingerprint, user.GlobalID, now.Add(time.Second),
	)
	if err != nil || resolved != 1 {
		t.Fatalf("resolve OAuth import login proof: resolved=%d err=%v", resolved, err)
	}
	if _, err := st.ReconcileProtectionStates(ctx, now.Add(2*time.Second), time.Minute); err != nil {
		t.Fatalf("reconcile OAuth import conflict: %v", err)
	}

	var globalStatus, secondHandle, secondStatus string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT global_user.status,account.local_handle,account.status
		FROM global_users global_user JOIN node_accounts account ON account.user_id=global_user.id
		WHERE global_user.id=$1 AND account.node_id=$2`, user.GlobalID, secondNodeID).
		Scan(&globalStatus, &secondHandle, &secondStatus); err != nil ||
		globalStatus != "conflict" || secondHandle != "oauth-import-remote" || secondStatus != "conflict" {
		t.Fatalf("resolved OAuth import status global=%q handle=%q account=%q err=%v",
			globalStatus, secondHandle, secondStatus, err)
	}
	var replicas, sources int
	if err := st.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM user_replicas WHERE user_id=$1 AND state='conflict'`, user.ID).
		Scan(&replicas); err != nil || replicas != 2 {
		t.Fatalf("OAuth import conflict replicas=%d err=%v", replicas, err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM replica_conflict_sources source
		JOIN replica_conflicts conflict ON conflict.id=source.conflict_id
		WHERE conflict.user_id=$1 AND source.local_handle IN ($2,$3)`,
		user.GlobalID, user.Username, "oauth-import-remote").Scan(&sources); err != nil || sources != 2 {
		t.Fatalf("OAuth import conflict sources=%d err=%v", sources, err)
	}
}
