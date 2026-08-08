package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
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

	t.Run("single writer and operation binding", func(t *testing.T) {
		userID := insertIntegrationGlobalUser(t, stores[0], "lease-user")
		assertConcurrentSingleWriter(t, stores[0], userID, nodeA, nodeB, generation)
	})

	t.Run("one-use handoff redemption", func(t *testing.T) {
		userID := insertIntegrationGlobalUser(t, stores[0], "handoff-user")
		assertConcurrentHandoffRedemption(t, stores[0], userID, nodeA)
	})

	t.Run("node lifecycle binds replay and retires only after durable drain", func(t *testing.T) {
		assertPostgresNodeLifecycleHardening(t, stores[0], nodeA)
	})

	t.Run("ten-thousand account inventory is durable and page bounded", func(t *testing.T) {
		assertPostgresAccountInventoryScale(t, stores[0], nodeA)
	})
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
