package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"testing"
	"time"
)

// A planned restart continues the generation; anything else promotes, and a
// promotion lets the existing writer take its users back at once.
func TestPostgresControllerCleanRestartAndStaleLeaseRenewal(t *testing.T) {
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	defer cleanupSchema()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	t.Run("only the lock holder can mark a clean shutdown, and the next start resumes once", func(t *testing.T) {
		assertPostgresCleanShutdownResume(t, st)
	})
	t.Run("a stale-generation lease is renewed on its writer only", func(t *testing.T) {
		assertPostgresStaleLeaseRenewal(t, st)
	})
}

func assertPostgresCleanShutdownResume(t *testing.T, st *Store) {
	t.Helper()
	ctx := context.Background()
	generation, err := st.GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatalf("GetActiveControllerGeneration: %v", err)
	}
	marker := func() sql.NullTime {
		t.Helper()
		var at sql.NullTime
		if err := st.DB.QueryRow(`SELECT clean_shutdown_at FROM controller_epochs WHERE generation=$1`, generation).Scan(&at); err != nil {
			t.Fatalf("read clean shutdown marker: %v", err)
		}
		return at
	}

	// No record: nothing to resume and nothing changes.
	if got, resumed, err := st.ResumeControllerEpoch(ctx, "test-restart", 10*time.Minute, time.Now().UTC()); err != nil || resumed || got != 0 {
		t.Fatalf("resume without marker: generation=%d resumed=%v err=%v", got, resumed, err)
	}

	leadership, acquired, err := st.TryAcquireControllerLeadership(ctx)
	if err != nil || !acquired {
		t.Fatalf("acquire leadership: acquired=%v err=%v", acquired, err)
	}
	// A connection that released the advisory lock cannot mark the generation.
	if _, err := leadership.conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, controllerAdvisoryLockID); err != nil {
		t.Fatalf("release advisory lock: %v", err)
	}
	if marked, err := leadership.MarkCleanShutdown(ctx, generation, time.Now().UTC()); err != nil || marked {
		t.Fatalf("mark without the lock: marked=%v err=%v", marked, err)
	}
	if marker().Valid {
		t.Fatal("marker written without holding the lock")
	}
	if _, err := leadership.conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, controllerAdvisoryLockID); err != nil {
		t.Fatalf("re-acquire advisory lock: %v", err)
	}
	// A revoked or unknown generation is never marked.
	if marked, err := leadership.MarkCleanShutdown(ctx, generation+100, time.Now().UTC()); err != nil || marked {
		t.Fatalf("mark another generation: marked=%v err=%v", marked, err)
	}
	stoppedAt := time.Now().UTC().Truncate(time.Microsecond)
	if marked, err := leadership.MarkCleanShutdown(ctx, generation, stoppedAt); err != nil || !marked {
		t.Fatalf("mark while holding the lock: marked=%v err=%v", marked, err)
	}
	if err := leadership.Close(); err != nil {
		t.Fatalf("close leadership: %v", err)
	}
	// A closed leadership connection cannot mark anything.
	if marked, err := leadership.MarkCleanShutdown(ctx, generation, time.Now().UTC()); err == nil || marked {
		t.Fatalf("mark after close: marked=%v err=%v", marked, err)
	}

	got, resumed, err := st.ResumeControllerEpoch(ctx, "test-restart", 10*time.Minute, stoppedAt.Add(20*time.Second))
	if err != nil || !resumed || got != generation {
		t.Fatalf("resume after clean shutdown: generation=%d resumed=%v err=%v", got, resumed, err)
	}
	if after, err := st.GetActiveControllerGeneration(ctx); err != nil || after != generation {
		t.Fatalf("generation after resume=%d err=%v", after, err)
	}
	if marker().Valid {
		t.Fatal("resume must consume the marker")
	}
	var audits int
	if err := st.DB.QueryRow(`
		SELECT count(*) FROM audit_events
		WHERE action='controller-generation-resumed' AND controller_generation=$1
		  AND detail->>'source'='test-restart'`, generation).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("resume audit events=%d err=%v", audits, err)
	}
	// The record is single use.
	if got, resumed, err := st.ResumeControllerEpoch(ctx, "test-restart", 10*time.Minute, time.Now().UTC()); err != nil || resumed || got != 0 {
		t.Fatalf("second resume: generation=%d resumed=%v err=%v", got, resumed, err)
	}

	// Down for longer than the window: not resumed, and the record is cleared.
	if _, err := st.DB.Exec(`UPDATE controller_epochs SET clean_shutdown_at=$2 WHERE generation=$1`,
		generation, time.Now().UTC().Add(-11*time.Minute)); err != nil {
		t.Fatalf("age marker: %v", err)
	}
	if got, resumed, err := st.ResumeControllerEpoch(ctx, "test-restart", 10*time.Minute, time.Now().UTC()); err != nil || resumed || got != 0 {
		t.Fatalf("resume after a long stop: generation=%d resumed=%v err=%v", got, resumed, err)
	}
	if marker().Valid {
		t.Fatal("an unusable marker must be cleared")
	}
}

func assertPostgresStaleLeaseRenewal(t *testing.T, st *Store) {
	t.Helper()
	ctx := context.Background()
	writer := insertIntegrationNode(t, st, "renewal-writer")
	other := insertIntegrationNode(t, st, "renewal-other")
	userID := insertIntegrationGlobalUser(t, st, "renewal-user")
	var userUUID string
	if err := st.DB.QueryRow(`SELECT uuid::text FROM global_users WHERE id=$1`, userID).Scan(&userUUID); err != nil {
		t.Fatalf("load user uuid: %v", err)
	}
	for _, nodeID := range []int64{writer, other} {
		if _, err := st.DB.Exec(`
			INSERT INTO node_accounts (user_id,node_id,local_handle,status)
			VALUES ($1,$2,'renewal-user','active')`, userID, nodeID); err != nil {
			t.Fatalf("insert node account: %v", err)
		}
	}
	secretHash := sha256.Sum256([]byte("renewal-handoff-secret"))
	now := time.Now().UTC().Truncate(time.Microsecond)
	handoffParams := func(n int, requested int64, existingOnly bool, at time.Time) CreateLoginHandoffParams {
		suffix := []byte("000000000000")
		suffix[11] = byte('0' + n)
		return CreateLoginHandoffParams{
			OperationID:        "31000000-0000-4000-8000-" + string(suffix),
			JTI:                "41000000-0000-4000-8000-" + string(suffix),
			SecretHash:         secretHash[:],
			UserID:             userID,
			RequestedNodeID:    requested,
			SessionID:          "51000000-0000-4000-8000-" + string(suffix),
			Issuer:             "https://controller.example",
			Subject:            userUUID,
			KeyID:              "controller-v1",
			TicketTTL:          time.Minute,
			LeaseTTL:           15 * time.Minute,
			ExistingWriterOnly: existingOnly,
			Now:                at,
		}
	}

	first, err := st.CreateLoginHandoff(ctx, handoffParams(1, writer, false, now))
	if err != nil || !first.Acquired || first.TargetNodeID != writer {
		t.Fatalf("first handoff=%+v err=%v", first, err)
	}
	oldGeneration := first.ControllerGeneration

	newGeneration, err := st.PromoteControllerEpoch(ctx, "renewal-test", now.Add(time.Second))
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	lease := func() *ActivityLease {
		t.Helper()
		got, err := st.GetActivityLease(ctx, userID)
		if err != nil || got == nil {
			t.Fatalf("read lease=%+v err=%v", got, err)
		}
		return got
	}

	// The writer has not reconnected in the new generation yet: nothing changes.
	if _, err := st.CreateLoginHandoff(ctx, handoffParams(2, writer, false, now.Add(2*time.Second))); !errors.Is(err, ErrLoginHandoffUnavailable) {
		t.Fatalf("handoff before the writer reconnects: err=%v", err)
	}
	if got := lease(); got.ControllerGeneration != oldGeneration || got.ActivityEpoch != first.ActivityEpoch || got.SessionID != first.SessionID {
		t.Fatalf("lease changed by a failed handoff: %+v", got)
	}

	// The other node reconnects first; the user asks for it, but the old writer
	// is still offline, so it must not become a second writer.
	if _, err := st.DB.Exec(`
		UPDATE nodes SET status='online',connectivity_state='online',controller_generation=$2
		WHERE id=$1`, other, newGeneration); err != nil {
		t.Fatalf("reconnect other node: %v", err)
	}
	if _, err := st.CreateLoginHandoff(ctx, handoffParams(3, other, false, now.Add(3*time.Second))); !errors.Is(err, ErrLoginHandoffUnavailable) {
		t.Fatalf("handoff to another node while the old lease is live: err=%v", err)
	}
	if got := lease(); got.WriterNodeID != writer || got.ControllerGeneration != oldGeneration {
		t.Fatalf("another node took the lease: %+v", got)
	}

	// The writer reconnects: a standby-style request is routed back to it and
	// the lease is renewed there under the new generation.
	if _, err := st.DB.Exec(`
		UPDATE nodes SET status='online',connectivity_state='online',controller_generation=$2
		WHERE id=$1`, writer, newGeneration); err != nil {
		t.Fatalf("reconnect writer: %v", err)
	}
	renewalParams := handoffParams(4, other, true, now.Add(4*time.Second))
	renewed, err := st.CreateLoginHandoff(ctx, renewalParams)
	if err != nil || renewed.TargetNodeID != writer || !renewed.Existing || renewed.Acquired ||
		renewed.ControllerGeneration != newGeneration || renewed.ActivityEpoch != first.ActivityEpoch+1 ||
		renewed.SessionID != renewalParams.SessionID {
		t.Fatalf("renewal handoff=%+v err=%v", renewed, err)
	}
	if got := lease(); got.WriterNodeID != writer || got.ControllerGeneration != newGeneration ||
		got.ActivityEpoch != first.ActivityEpoch+1 || got.SessionID != renewalParams.SessionID || got.State != "active" {
		t.Fatalf("renewed lease=%+v", got)
	}
	replay, err := st.CreateLoginHandoff(ctx, renewalParams)
	if err != nil || !replay.Replayed || replay.JTI != renewed.JTI || !replay.Existing || replay.TargetNodeID != writer {
		t.Fatalf("renewal replay=%+v err=%v", replay, err)
	}

	// The old generation's session can no longer extend the lease; the new one can.
	if _, matched, err := st.UpdateActivityLeaseTelemetry(ctx, ActivityLeaseTelemetry{
		UserID: userID, WriterNodeID: writer, SessionID: first.SessionID, ActivityEpoch: first.ActivityEpoch,
		ControllerGeneration: oldGeneration, Online: true, Now: now.Add(5 * time.Second), TTL: 15 * time.Minute,
	}); err != nil || matched {
		t.Fatalf("old session telemetry matched=%v err=%v", matched, err)
	}
	redemption, ok, err := st.ConsumeLoginHandoff(ctx, renewed.JTI, secretHash[:], writer,
		renewalParams.Issuer, renewalParams.KeyID, now.Add(5*time.Second), 15*time.Minute)
	if err != nil || !ok || redemption.SessionID != renewalParams.SessionID ||
		redemption.ActivityEpoch != renewed.ActivityEpoch || redemption.ControllerGeneration != newGeneration {
		t.Fatalf("redeem renewed ticket: redemption=%+v ok=%v err=%v", redemption, ok, err)
	}

	// Now current, the lease behaves as any live lease: another node is refused
	// and the user is routed to the existing writer without another renewal.
	again, err := st.CreateLoginHandoff(ctx, handoffParams(5, other, false, now.Add(6*time.Second)))
	if err != nil || again.TargetNodeID != writer || !again.Existing || again.ActivityEpoch != renewed.ActivityEpoch {
		t.Fatalf("handoff after renewal=%+v err=%v", again, err)
	}
	var outcomes []string
	rows, err := st.DB.Query(`SELECT outcome FROM activity_lease_operations WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		t.Fatalf("read lease operations: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var outcome string
		if err := rows.Scan(&outcome); err != nil {
			t.Fatalf("scan outcome: %v", err)
		}
		outcomes = append(outcomes, outcome)
	}
	if len(outcomes) != 3 || outcomes[0] != "acquired" || outcomes[1] != "renewed" || outcomes[2] != "existing" {
		t.Fatalf("lease operations=%v", outcomes)
	}

	// Once expired, an old-generation lease is simply replaced as before.
	if _, err := st.DB.Exec(`
		UPDATE user_activity_leases SET controller_generation=$2, lease_expires_at=$3 WHERE user_id=$1`,
		userID, oldGeneration, now.Add(-time.Minute)); err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	expired, err := st.CreateLoginHandoff(ctx, handoffParams(6, other, false, now.Add(7*time.Second)))
	if err != nil || !expired.Acquired || expired.TargetNodeID != other {
		t.Fatalf("handoff after expiry=%+v err=%v", expired, err)
	}
}
