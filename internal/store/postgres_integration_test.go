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
