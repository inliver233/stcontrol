package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func commandParams(now time.Time) EnqueueAgentCommandParams {
	return EnqueueAgentCommandParams{
		ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", OperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		NodeID: 22, CommandType: "scan_existing", EncryptedPayload: []byte(`{"version":1,"ciphertext":"secret"}`),
		PayloadSHA256: make([]byte, 32), ExpiresAt: now.Add(10 * time.Minute), Now: now,
	}
}

func TestEnqueueAgentCommandBindsActiveGeneration(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := commandParams(time.Date(2026, 8, 7, 18, 30, 0, 0, time.UTC))
	mock.ExpectQuery(`INSERT INTO agent_commands`).
		WithArgs(p.ID, p.OperationID, p.NodeID, p.CommandType, p.EncryptedPayload, p.PayloadSHA256, p.ExpiresAt, p.Now).
		WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(8)))
	generation, err := st.EnqueueAgentCommand(context.Background(), p)
	if err != nil || generation != 8 {
		t.Fatalf("generation=%d err=%v", generation, err)
	}
	assertMockExpectations(t, mock)
}

func TestEnqueueAgentCommandIdempotencyRejectsSemanticMismatch(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := commandParams(time.Date(2026, 8, 7, 18, 30, 0, 0, time.UTC))
	mock.ExpectQuery(`INSERT INTO agent_commands`).
		WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}))
	mock.ExpectQuery(`SELECT node_id, command_type, payload_sha256, controller_generation`).
		WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"node_id", "command_type", "payload_sha256", "controller_generation"}).
			AddRow(int64(99), p.CommandType, p.PayloadSHA256, int64(8)))
	_, err := st.EnqueueAgentCommand(context.Background(), p)
	if !errors.Is(err, ErrAgentCommandConflict) {
		t.Fatalf("error=%v, want ErrAgentCommandConflict", err)
	}
	assertMockExpectations(t, mock)
}

func TestEnqueueAgentCommandAllowsExactIdempotentReplay(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	p := commandParams(time.Date(2026, 8, 7, 18, 30, 0, 0, time.UTC))
	mock.ExpectQuery(`INSERT INTO agent_commands`).
		WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}))
	mock.ExpectQuery(`SELECT node_id, command_type, payload_sha256, controller_generation`).
		WithArgs(p.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"node_id", "command_type", "payload_sha256", "controller_generation"}).
			AddRow(p.NodeID, p.CommandType, p.PayloadSHA256, int64(8)))
	generation, err := st.EnqueueAgentCommand(context.Background(), p)
	if err != nil || generation != 8 {
		t.Fatalf("generation=%d err=%v", generation, err)
	}
	assertMockExpectations(t, mock)
}

func TestLeaseAckAndFinishAgentCommandAreFenced(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 18, 30, 0, 0, time.UTC)
	leaseUntil := now.Add(45 * time.Second)
	expiresAt := now.Add(10 * time.Minute)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT command.id, command.operation_id`).WithArgs(int64(22), now).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "operation_id", "command_type", "payload", "payload_sha256", "attempt", "controller_generation", "expires_at",
		}).AddRow("command-id", "operation-id", "scan_existing", []byte(`{"version":1}`), make([]byte, 32), 0, int64(8), expiresAt))
	mock.ExpectExec(`UPDATE agent_commands`).
		WithArgs("command-id", "worker-identity-1", leaseUntil, 1, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	lease, err := st.LeaseAgentCommand(context.Background(), 22, "worker-identity-1", now, 45*time.Second)
	if err != nil || lease == nil || lease.Attempt != 1 || !lease.LeaseUntil.Equal(leaseUntil) {
		t.Fatalf("lease=%+v err=%v", lease, err)
	}

	mock.ExpectExec(`SET state='running'`).
		WithArgs("command-id", int64(22), "worker-identity-1", int64(8), now, now.Add(5*time.Minute)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := st.AckAgentCommand(context.Background(), "command-id", 22, "worker-identity-1", 8, now, 5*time.Minute)
	if err != nil || !ok {
		t.Fatalf("ack ok=%v err=%v", ok, err)
	}

	result := []byte(`{"ok":true}`)
	digest := make([]byte, 32)
	mock.ExpectExec(`SET state=\$5, result_summary=\$6`).
		WithArgs("command-id", int64(22), "worker-identity-1", int64(8), "succeeded", result, digest, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err = st.FinishAgentCommand(context.Background(), FinishAgentCommandParams{
		ID: "command-id", NodeID: 22, WorkerID: "worker-identity-1", ControllerGeneration: 8,
		Succeeded: true, ResultSummary: result, ResultDigest: digest, Now: now,
	})
	if err != nil || !ok {
		t.Fatalf("finish ok=%v err=%v", ok, err)
	}
	assertMockExpectations(t, mock)
}

func TestLeaseAgentCommandReturnsNilWhenQueueEmpty(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	now := time.Date(2026, 8, 7, 18, 30, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT command.id, command.operation_id`).WithArgs(int64(22), now).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "operation_id", "command_type", "payload", "payload_sha256", "attempt", "controller_generation", "expires_at",
		}))
	mock.ExpectCommit()
	lease, err := st.LeaseAgentCommand(context.Background(), 22, "worker-identity-1", now, time.Minute)
	if err != nil || lease != nil {
		t.Fatalf("lease=%+v err=%v", lease, err)
	}
	assertMockExpectations(t, mock)
}
