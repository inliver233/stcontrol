package store

import (
	"context"
	"testing"
	"time"
)

// TestPostgresAIObservationAggregates exercises the Phase 2-6B observation
// queries against real PostgreSQL with empty tables (they must return empty
// slices without errors, and the control-mode/conflict queries must accept
// real NULLable columns).
func TestPostgresAIObservationAggregates(t *testing.T) {
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	defer cleanupSchema()
	st, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	events, err := st.ListRecentNodeControlModeEvents(ctx, 10)
	if err != nil {
		t.Fatalf("control mode events: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("events=%+v", events)
	}
	conflicts, err := st.ListOpenConflictAggregates(ctx, 10)
	if err != nil {
		t.Fatalf("conflict aggregates: %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("conflicts=%+v", conflicts)
	}
	workflows, err := st.ListRecentRestoreWorkflowSummaries(ctx, 10)
	if err != nil {
		t.Fatalf("restore workflows: %v", err)
	}
	if len(workflows) != 0 {
		t.Fatalf("workflows=%+v", workflows)
	}
	candidates, err := st.ListUnresolvedImportCandidates(ctx, 50)
	if err != nil {
		t.Fatalf("import candidates: %v", err)
	}
	if len(candidates) != 0 {
		t.Fatalf("candidates=%+v", candidates)
	}
	counts, err := st.CountOpenAlertsBySeverity(ctx)
	if err != nil {
		t.Fatalf("alert counts: %v", err)
	}
	if len(counts) != 0 {
		t.Fatalf("counts=%+v", counts)
	}
}

// TestPostgresAggregateProtectionStates exercises the D6 protection aggregate
// SQL against real PostgreSQL, both on empty tables and with one seeded
// protected user + one corrupt replica.
func TestPostgresAggregateProtectionStates(t *testing.T) {
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	defer cleanupSchema()
	st, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	empty, err := st.AggregateProtectionStates(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("aggregate on empty store: %v", err)
	}
	if empty != (ProtectionAggregate{}) {
		t.Fatalf("empty aggregate=%+v, want all zeros", empty)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	homeNodeID := insertIntegrationNode(t, st, "aggregate-home")
	var legacyUserID, globalUserID int64
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO users (username,display_name,auth_provider,home_node_id,status)
		VALUES ('aggregate-user','Aggregate User','password',$1,'active') RETURNING id`,
		homeNodeID).Scan(&legacyUserID); err != nil {
		t.Fatalf("insert legacy user: %v", err)
	}
	if err := st.DB.QueryRowContext(ctx, `
		INSERT INTO global_users (uuid,legacy_user_id,display_name,status)
		VALUES (gen_random_uuid(),$1,'Aggregate User','active') RETURNING id`,
		legacyUserID).Scan(&globalUserID); err != nil {
		t.Fatalf("insert global user: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_protection_states (user_id,state,reason_code,changed_at,evaluated_at)
		VALUES ($1,'protected','healthy',$2,$2)`, globalUserID, now); err != nil {
		t.Fatalf("insert protection state: %v", err)
	}
	storageNodeID := insertIntegrationNode(t, st, "aggregate-storage")
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO user_replicas (user_id,node_id,kind,state,last_sync_at)
		VALUES ($1,$2,'home','corrupt',$4),($1,$3,'archive','ready',$5)`,
		legacyUserID, homeNodeID, storageNodeID, now.Add(-time.Hour), now); err != nil {
		t.Fatalf("insert replicas: %v", err)
	}
	agg, err := st.AggregateProtectionStates(ctx, now)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if agg.TotalUsers != 1 || agg.ProtectedCount != 1 || agg.UnprotectedCount != 0 ||
		agg.ConflictCount != 0 || agg.CorruptCount != 1 {
		t.Fatalf("aggregate=%+v", agg)
	}
	// Two replicas averaged: one synced now, one an hour ago -> ~30min age.
	if agg.AvgReplicaAgeSec < 1700 || agg.AvgReplicaAgeSec > 1900 {
		t.Fatalf("avg replica age=%d, want ~1800", agg.AvgReplicaAgeSec)
	}
}
