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
