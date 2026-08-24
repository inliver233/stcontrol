package store

import (
	"context"
	"testing"
	"time"
)

func TestPostgresListControllerDisasterBackupsPageEmptyAndFiltered(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller disaster backup PostgreSQL integration is disabled in short mode")
	}
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	defer cleanupSchema()
	st, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	empty, err := st.ListControllerDisasterBackupsPage(ctx, ListControllerDisasterBackupPageParams{})
	if err != nil {
		t.Fatalf("list empty controller backups: %v", err)
	}
	if empty == nil || len(empty) != 0 {
		t.Fatalf("empty controller backups = %#v, want non-nil empty slice", empty)
	}

	nodeID := insertIntegrationNode(t, st, "controller-backup-list")
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err = st.DB.ExecContext(ctx, `
		INSERT INTO controller_disaster_backups (
		  operation_id,node_id,state,controller_generation,backup_kind,attempt,
		  next_attempt_at,started_at,updated_at,created_at
		) VALUES (
		  '11111111-1111-4111-8111-111111111111',$1,'failed',
		  (SELECT generation FROM controller_epochs WHERE state='active'),
		  'full',2,$2,$2,$2,$2
		)`, nodeID, now)
	if err != nil {
		t.Fatalf("insert controller backup: %v", err)
	}

	runs, err := st.ListControllerDisasterBackupsPage(ctx, ListControllerDisasterBackupPageParams{
		State: ControllerBackupFailed,
		Limit: 1,
	})
	if err != nil {
		t.Fatalf("list filtered controller backups: %v", err)
	}
	if len(runs) != 1 || runs[0].NodeName != "controller-backup-list" ||
		runs[0].State != ControllerBackupFailed || runs[0].Attempt != 2 {
		t.Fatalf("filtered controller backups = %+v", runs)
	}

	before, err := st.ListControllerDisasterBackupsPage(ctx, ListControllerDisasterBackupPageParams{
		BeforeAt: now.Add(-time.Second),
		Limit:    101,
	})
	if err != nil {
		t.Fatalf("list controller backups before cursor: %v", err)
	}
	if before == nil || len(before) != 0 {
		t.Fatalf("controller backups before cursor = %#v, want non-nil empty slice", before)
	}
}
