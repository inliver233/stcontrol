package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func takeoverParams(now time.Time) ConfirmReplicaTakeoverParams {
	return ConfirmReplicaTakeoverParams{
		OperationID:        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		RequestDigest:      bytes.Repeat([]byte{1}, 32),
		GlobalUserID:       70,
		TargetNodeID:       9,
		ExpectedRecoveryAt: now.Add(-time.Hour),
		Now:                now,
	}
}

func TestReconcileProtectionStatesPersistsProjectionAndDelayedAlerts(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	grace := time.Hour
	mock.ExpectBegin()
	mock.ExpectExec(`(?s)WITH facts AS .*home_replica.state='ready'.*previous.state='conflict'.*conflicting_copy.*snapshot.user_id=global_user.id.*INSERT INTO user_protection_states`).WithArgs(now).
		WillReturnResult(sqlmock.NewResult(0, 10))
	mock.ExpectExec(`(?s)WITH conflicted AS .*UPDATE control_tickets.*UPDATE user_activity_leases`).WithArgs(now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO alerts .*user-protection`).WithArgs(now, now.Add(grace)).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(`UPDATE alerts alert SET state='resolved'`).WithArgs(now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()
	result, err := st.ReconcileProtectionStates(context.Background(), now, grace)
	if err != nil || result.Evaluated != 10 || result.Alerted != 3 || result.Resolved != 2 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err := st.ReconcileProtectionStates(context.Background(), now, 0); err == nil {
		t.Fatal("zero alert grace was accepted")
	}
	assertMockExpectations(t, mock)
}

func TestGetUserProtectionStateAndVisibleAlertsReturnSafeFacts(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 10, 10, 0, 0, time.UTC)
	mock.ExpectQuery(`FROM user_protection_states protection`).WithArgs(int64(70)).
		WillReturnRows(sqlmock.NewRows([]string{
			"user_id", "state", "reason", "authoritative_id", "authoritative_name",
			"recovery_id", "recovery_name", "snapshot_id", "recovery_at", "writer_id", "writer_name",
			"version", "changed_at", "evaluated_at",
		}).AddRow(int64(70), "takeover_available", "hot_standby_ready", int64(8), "node-a",
			int64(9), "node-b", "snapshot", now.Add(-time.Hour), int64(8), "node-a", int64(2), now, now))
	state, err := st.GetUserProtectionState(context.Background(), 70)
	if err != nil || state == nil || state.RecoveryNodeID.Int64 != 9 || state.ActiveWriterNodeID.Int64 != 8 ||
		state.State != "takeover_available" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	mock.ExpectQuery(`FROM alerts alert`).WithArgs(100, now).
		WillReturnRows(sqlmock.NewRows([]string{
			"severity", "state", "category", "uuid", "username", "node_name", "summary", "first", "last",
		}).AddRow("critical", "open", "user_protection", "uuid", "alice", "node-a", "需要接管", now, now))
	alerts, err := st.ListVisibleProtectionAlerts(context.Background(), 0, now)
	if err != nil || len(alerts) != 1 || alerts[0].UserUUID != "uuid" {
		t.Fatalf("alerts=%+v err=%v", alerts, err)
	}
	assertMockExpectations(t, mock)
}

func TestGetImmutableHotStandbyRecoveryPointRequiresOwnedEligibleSnapshot(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	published := time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`(?s)FROM replica_copies copy.*snapshot.user_id=copy.user_id.*account.status='active'.*copy.compatibility_state='compatible'`).
		WithArgs(int64(70), int64(9)).
		WillReturnRows(sqlmock.NewRows([]string{"published_at"}).AddRow(published))
	point, err := st.GetImmutableHotStandbyRecoveryPoint(context.Background(), 70, 9)
	if err != nil || !point.Valid || !point.Time.Equal(published) {
		t.Fatalf("point=%+v err=%v", point, err)
	}
	mock.ExpectQuery(`FROM replica_copies copy`).WithArgs(int64(70), int64(10)).
		WillReturnRows(sqlmock.NewRows([]string{"published_at"}))
	point, err = st.GetImmutableHotStandbyRecoveryPoint(context.Background(), 70, 10)
	if err != nil || point.Valid {
		t.Fatalf("missing point=%+v err=%v", point, err)
	}
	if _, err := st.GetImmutableHotStandbyRecoveryPoint(context.Background(), 0, 9); err == nil {
		t.Fatal("invalid user was accepted")
	}
	assertMockExpectations(t, mock)
}

func TestListStorageRepairCandidatesRequiresSafeHomeAndNoWriter(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`(?s)FROM user_protection_states protection.*home_replica.state='ready'.*archive_snapshot.state='immutable'.*lease.lease_expires_at>\$2.*workflow.workflow_type='snapshot'`).
		WithArgs(50, now).
		WillReturnRows(sqlmock.NewRows([]string{"legacy_user_id", "global_user_id", "home_node_id"}).
			AddRow(int64(7), int64(70), int64(8)))
	candidates, err := st.ListStorageRepairCandidates(context.Background(), 0, now)
	if err != nil || len(candidates) != 1 || candidates[0].GlobalUserID != 70 || candidates[0].HomeNodeID != 8 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	assertMockExpectations(t, mock)
}

func TestConfirmReplicaTakeoverReplaysExactOperation(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Now().UTC()
	p := takeoverParams(now)
	published := now.Add(-time.Hour)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.GlobalUserID))
	mock.ExpectQuery(`FROM replica_takeover_operations`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{
			"request_digest", "user_id", "source", "target", "snapshot", "published", "generation",
		}).AddRow(p.RequestDigest, p.GlobalUserID, int64(8), p.TargetNodeID, "snapshot", published, int64(4)))
	mock.ExpectCommit()
	result, err := st.ConfirmReplicaTakeover(context.Background(), p)
	if err != nil || !result.Replayed || result.SourceNodeID != 8 || result.TargetNodeID != 9 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	assertMockExpectations(t, mock)
}

func TestConfirmReplicaTakeoverRejectsLiveSourceLease(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 10, 30, 0, 0, time.UTC)
	p := takeoverParams(now)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.GlobalUserID))
	mock.ExpectQuery(`FROM replica_takeover_operations`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"request_digest"}))
	mock.ExpectQuery(`SELECT global_user.legacy_user_id`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"legacy_user_id", "home_node_id"}).AddRow(int64(7), int64(8)))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
	mock.ExpectQuery(`SELECT user_id, writer_node_id`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{
			"user_id", "writer_node_id", "session_id", "activity_epoch", "state", "lease_expires_at",
			"last_page", "last_request", "reads", "writes", "generation", "updated_at",
		}).AddRow(p.GlobalUserID, int64(8), "session", int64(3), "active", now.Add(time.Minute),
			now, now, 0, 0, int64(4), now))
	mock.ExpectRollback()
	_, err := st.ConfirmReplicaTakeover(context.Background(), p)
	if !errors.Is(err, ErrReplicaTakeoverLeaseActive) {
		t.Fatalf("error=%v", err)
	}
	assertMockExpectations(t, mock)
}

func TestConfirmReplicaTakeoverAtomicallyPromotesImmutableHotStandby(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 8, 11, 0, 0, 0, time.UTC)
	p := takeoverParams(now)
	published := now.Add(-2 * time.Hour)
	p.ExpectedRecoveryAt = published
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.GlobalUserID))
	mock.ExpectQuery(`FROM replica_takeover_operations`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"request_digest"}))
	mock.ExpectQuery(`SELECT global_user.legacy_user_id`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"legacy_user_id", "home_node_id"}).AddRow(int64(7), int64(8)))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(4)))
	mock.ExpectQuery(`SELECT user_id, writer_node_id`).WithArgs(p.GlobalUserID).
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
	mock.ExpectQuery(`(?s)SELECT copy.snapshot_id::text.*snapshot.user_id=\$2.*copy.published_at=\$4`).
		WithArgs(int64(7), p.GlobalUserID, p.TargetNodeID, published).
		WillReturnRows(sqlmock.NewRows([]string{"snapshot_id", "published_at"}).AddRow("snapshot", published))
	mock.ExpectExec(`UPDATE user_replicas SET kind='hot_standby'`).WithArgs(int64(7), int64(8)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE user_replicas SET kind='home'`).WithArgs(int64(7), p.TargetNodeID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE users SET home_node_id`).WithArgs(int64(7), p.TargetNodeID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE control_tickets`).WithArgs(p.GlobalUserID, now).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`UPDATE replica_copies SET is_authoritative=false`).WithArgs(p.GlobalUserID, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO replica_copies`).WithArgs(p.GlobalUserID, int64(8), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE replica_copies SET replica_kind='active'`).WithArgs(
		p.GlobalUserID, p.TargetNodeID, "snapshot", now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE node_accounts`).WithArgs(p.GlobalUserID, p.TargetNodeID, now, int64(8)).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`INSERT INTO replica_takeover_operations`).WithArgs(
		p.OperationID, p.RequestDigest, p.GlobalUserID, int64(8), p.TargetNodeID,
		"snapshot", published, nil, int64(4), now,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO user_protection_states`).WithArgs(p.GlobalUserID, p.TargetNodeID, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(
		p.GlobalUserID, p.OperationID, int64(4), p.RequestDigest, int64(8), p.TargetNodeID, published,
	).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	result, err := st.ConfirmReplicaTakeover(context.Background(), p)
	if err != nil || result.SourceNodeID != 8 || result.SnapshotID != "snapshot" || result.Replayed {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	assertMockExpectations(t, mock)
}

func TestConfirmReplicaTakeoverRejectsInvalidInputBeforeTransaction(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	_, err := st.ConfirmReplicaTakeover(context.Background(), ConfirmReplicaTakeoverParams{})
	if !errors.Is(err, ErrInvalidReplicaTakeover) {
		t.Fatalf("error=%v", err)
	}
	assertMockExpectations(t, mock)
}

func TestGetUserProtectionStateRejectsInvalidUser(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	state, err := st.GetUserProtectionState(context.Background(), 0)
	if err == nil || state != nil {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	assertMockExpectations(t, mock)
}
