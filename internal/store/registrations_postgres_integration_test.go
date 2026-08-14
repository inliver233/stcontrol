package store

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"
)

// TestPostgresReleaseExpiredRegistrationReservations is the real-PostgreSQL
// regression test for B2: releasing an expired pending handle reservation
// used to send one argument against two placeholders ($1 never appeared,
// $2 was unbound), so PostgreSQL aborted the transaction and the R15 handle
// reservation TTL never actually released anything.
func TestPostgresReleaseExpiredRegistrationReservations(t *testing.T) {
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	defer cleanupSchema()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	now := time.Now().UTC().Truncate(time.Microsecond)
	seedWorkflow := func(handle, state string, createdAt time.Time) string {
		t.Helper()
		var workflowID string
		if err := st.DB.QueryRowContext(ctx, `
			INSERT INTO workflows (
			  id,operation_id,workflow_type,state,controller_generation,created_at,updated_at
			) VALUES (gen_random_uuid(),gen_random_uuid(),'registration',$2,1,$1,$1)
			RETURNING id::text`, createdAt, state).Scan(&workflowID); err != nil {
			t.Fatalf("insert workflow for %q: %v", handle, err)
		}
		if _, err := st.DB.ExecContext(ctx, `
			INSERT INTO registration_workflows (
			  workflow_id,request_digest,pending_token_hash,client_expires_at,
			  local_handle,display_name,auth_provider,password_hash,
			  password_material_hash,password_material_salt,
			  registration_policy_version,reservation_state,created_at,updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,'password','hash','mat-hash','mat-salt',
			  1,$7,$8,$8)`,
			workflowID, make32Byte("digest-"+handle), make32Byte("token-"+handle),
			createdAt.Add(time.Hour), handle, handle, "pending", createdAt); err != nil {
			t.Fatalf("insert registration workflow %q: %v", handle, err)
		}
		return workflowID
	}
	expiredID := seedWorkflow("expired-handle", "scheduled", now.Add(-RegistrationReservationTTL-time.Hour))
	freshID := seedWorkflow("fresh-handle", "scheduled", now.Add(-time.Minute))

	released, err := st.ReleaseExpiredRegistrationReservations(ctx, now)
	if err != nil {
		t.Fatalf("release expired reservations: %v", err)
	}
	if released != 1 {
		t.Fatalf("released=%d, want 1", released)
	}
	assertReservation := func(workflowID, wantWorkflowState, wantReservation string) {
		t.Helper()
		var workflowState, errorCode, reservation string
		if err := st.DB.QueryRowContext(ctx, `
			SELECT workflow.state,COALESCE(workflow.error_code,''),registration.reservation_state
			FROM workflows workflow
			JOIN registration_workflows registration ON registration.workflow_id=workflow.id
			WHERE workflow.id=$1`, workflowID).
			Scan(&workflowState, &errorCode, &reservation); err != nil {
			t.Fatalf("read reservation %s: %v", workflowID, err)
		}
		if workflowState != wantWorkflowState || reservation != wantReservation {
			t.Fatalf("workflow=%s/%s reservation=%s, want %s/%s",
				workflowState, errorCode, reservation, wantWorkflowState, wantReservation)
		}
	}
	assertReservation(expiredID, "failed", "released")
	assertReservation(freshID, "scheduled", "pending")

	// Idempotent: nothing left to release.
	released, err = st.ReleaseExpiredRegistrationReservations(ctx, now.Add(time.Minute))
	if err != nil || released != 0 {
		t.Fatalf("second sweep released=%d err=%v, want 0", released, err)
	}
}

func make32Byte(seed string) []byte {
	return sha256SumForSeed(seed)
}

func sha256SumForSeed(seed string) []byte {
	sum := sha256.Sum256([]byte(seed))
	return sum[:]
}
