package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func testHandoffParams(now time.Time) CreateLoginHandoffParams {
	return CreateLoginHandoffParams{
		OperationID:     "11111111-1111-4111-8111-111111111111",
		JTI:             "22222222-2222-4222-8222-222222222222",
		SecretHash:      make([]byte, 32),
		UserID:          70,
		RequestedNodeID: 20,
		SessionID:       "33333333-3333-4333-8333-333333333333",
		Issuer:          "https://control.example",
		Subject:         "alice",
		KeyID:           "controller-master-v1",
		TicketTTL:       time.Minute,
		LeaseTTL:        15 * time.Minute,
		Now:             now,
	}
}

func TestCreateLoginHandoffRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	store := &Store{}
	_, err := store.CreateLoginHandoff(context.Background(), CreateLoginHandoffParams{})
	if !errors.Is(err, ErrInvalidLoginHandoff) {
		t.Fatalf("CreateLoginHandoff error=%v, want ErrInvalidLoginHandoff", err)
	}
}

func TestCreateLoginHandoffCommitsLeaseAndTicketTogether(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 14, 0, 0, 0, time.UTC)
	p := testHandoffParams(now)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users WHERE id=\$1 FOR UPDATE`).
		WithArgs(p.UserID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.UserID))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(3)))
	mock.ExpectQuery(`SELECT user_id, requested_node_id, requested_session_id, outcome`).
		WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows(splitColumns(opColumns)))
	mock.ExpectQuery(`SELECT user_id, writer_node_id, session_id, activity_epoch, state, lease_expires_at`).
		WithArgs(p.UserID).
		WillReturnRows(sqlmock.NewRows(splitColumns(leaseColumns)))
	mock.ExpectExec(`INSERT INTO user_activity_leases`).
		WithArgs(p.UserID, p.RequestedNodeID, p.SessionID, int64(1), now.Add(p.LeaseTTL), now, int64(3)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`INSERT INTO activity_lease_operations`).
		WithArgs(p.OperationID, p.UserID, p.RequestedNodeID, p.SessionID, "acquired",
			p.RequestedNodeID, p.SessionID, int64(1), now).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(`SELECT base_url FROM nodes`).
		WithArgs(p.RequestedNodeID).
		WillReturnRows(sqlmock.NewRows([]string{"base_url"}).AddRow("https://node.example"))
	mock.ExpectExec(`INSERT INTO control_tickets`).
		WithArgs(p.JTI, p.OperationID, p.SecretHash, p.Issuer, "https://node.example", p.Subject,
			p.UserID, p.RequestedNodeID, p.SessionID, int64(1), p.KeyID, int64(3), now, now.Add(p.TicketTTL)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	handoff, err := store.CreateLoginHandoff(context.Background(), p)
	if err != nil {
		t.Fatalf("CreateLoginHandoff: %v", err)
	}
	if !handoff.Acquired || handoff.Existing || handoff.Replayed {
		t.Fatalf("unexpected handoff flags: %+v", handoff)
	}
	if handoff.TargetNodeID != p.RequestedNodeID || handoff.ActivityEpoch != 1 || handoff.ControllerGeneration != 3 {
		t.Fatalf("unexpected handoff: %+v", handoff)
	}
	assertMockExpectations(t, mock)
}

func TestCreateLoginHandoffRollsBackLeaseWhenTicketInsertFails(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 14, 0, 0, 0, time.UTC)
	p := testHandoffParams(now)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.UserID))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(3)))
	mock.ExpectQuery(`SELECT user_id, requested_node_id, requested_session_id, outcome`).
		WillReturnRows(sqlmock.NewRows(splitColumns(opColumns)))
	mock.ExpectQuery(`SELECT user_id, writer_node_id`).WillReturnRows(sqlmock.NewRows(splitColumns(leaseColumns)))
	mock.ExpectExec(`INSERT INTO user_activity_leases`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`INSERT INTO activity_lease_operations`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(`SELECT base_url FROM nodes`).WillReturnRows(sqlmock.NewRows([]string{"base_url"}).AddRow("https://node.example"))
	mock.ExpectExec(`INSERT INTO control_tickets`).WillReturnError(errors.New("disk full"))
	mock.ExpectRollback()

	if _, err := store.CreateLoginHandoff(context.Background(), p); err == nil {
		t.Fatal("CreateLoginHandoff succeeded, want ticket insert error")
	}
	assertMockExpectations(t, mock)
}

func TestCreateLoginHandoffReplaysOriginalResult(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 14, 0, 0, 0, time.UTC)
	p := testHandoffParams(now)
	originalJTI := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM global_users`).WithArgs(p.UserID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(p.UserID))
	mock.ExpectQuery(`SELECT generation FROM controller_epochs`).
		WillReturnRows(sqlmock.NewRows([]string{"generation"}).AddRow(int64(3)))
	mock.ExpectQuery(`SELECT user_id, requested_node_id, requested_session_id, outcome`).WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows(splitColumns(opColumns)).AddRow(
			p.UserID, p.RequestedNodeID, p.SessionID, "existing", int64(30), p.SessionID, int64(8),
		))
	mock.ExpectQuery(`SELECT t.operation_id, t.jti`).
		WithArgs(p.OperationID, p.UserID, p.RequestedNodeID, now).
		WillReturnRows(sqlmock.NewRows([]string{
			"operation_id", "jti", "user_id", "target_node_id", "base_url", "subject",
			"session_id", "activity_epoch", "controller_generation", "expires_at", "outcome",
		}).AddRow(p.OperationID, originalJTI, p.UserID, int64(30), "https://writer.example", "alice",
			p.SessionID, int64(8), int64(3), now.Add(30*time.Second), "existing"))
	mock.ExpectCommit()

	handoff, err := store.CreateLoginHandoff(context.Background(), p)
	if err != nil {
		t.Fatalf("CreateLoginHandoff retry: %v", err)
	}
	if !handoff.Replayed || !handoff.Existing || handoff.JTI != originalJTI || handoff.TargetNodeID != 30 {
		t.Fatalf("unexpected replay result: %+v", handoff)
	}
	assertMockExpectations(t, mock)
}

func TestConsumeLoginHandoffIsFencedAndOneUse(t *testing.T) {
	t.Parallel()
	store, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 14, 0, 0, 0, time.UTC)
	hash := make([]byte, 32)

	mock.ExpectQuery(`WITH consumed AS`).
		WithArgs("ticket-jti", int64(20), hash, now, now.Add(15*time.Minute)).
		WillReturnRows(sqlmock.NewRows([]string{
			"user_id", "subject", "session_id", "activity_epoch", "controller_generation",
		}).AddRow(int64(70), "alice", "session", int64(4), int64(3)))

	redemption, ok, err := store.ConsumeLoginHandoff(
		context.Background(), "ticket-jti", hash, 20, now, 15*time.Minute,
	)
	if err != nil || !ok {
		t.Fatalf("ConsumeLoginHandoff ok=%v err=%v", ok, err)
	}
	if redemption.Handle != "alice" || redemption.ActivityEpoch != 4 || redemption.ControllerGeneration != 3 {
		t.Fatalf("unexpected redemption: %+v", redemption)
	}

	mock.ExpectQuery(`WITH consumed AS`).
		WithArgs("ticket-jti", int64(20), hash, now, now.Add(15*time.Minute)).
		WillReturnRows(sqlmock.NewRows([]string{
			"user_id", "subject", "session_id", "activity_epoch", "controller_generation",
		}))
	_, ok, err = store.ConsumeLoginHandoff(context.Background(), "ticket-jti", hash, 20, now, 15*time.Minute)
	if err != nil || ok {
		t.Fatalf("second ConsumeLoginHandoff ok=%v err=%v, want false", ok, err)
	}
	assertMockExpectations(t, mock)
}
