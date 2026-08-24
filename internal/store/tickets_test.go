package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestTicketAndRegistrationTokenLifecycle(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	ctx := context.Background()
	now := time.Date(2026, 8, 24, 2, 0, 0, 0, time.UTC)
	ticket := &Ticket{JTI: "ticket-jti", UserID: 7, NodeID: 8, ExpiresAt: now.Add(time.Minute)}

	mock.ExpectExec(`INSERT INTO tickets`).WithArgs(ticket.JTI, ticket.UserID, ticket.NodeID, ticket.ExpiresAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := st.CreateTicket(ctx, ticket); err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	mock.ExpectExec(`UPDATE tickets SET used_at`).WithArgs(ticket.JTI, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT user_id, node_id FROM tickets`).WithArgs(ticket.JTI).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "node_id"}).AddRow(int64(7), int64(8)))
	userID, nodeID, ok, err := st.ConsumeTicket(ctx, ticket.JTI, now)
	if err != nil || !ok || userID != 7 || nodeID != 8 {
		t.Fatalf("ConsumeTicket user=%d node=%d ok=%v err=%v", userID, nodeID, ok, err)
	}

	mock.ExpectExec(`INSERT INTO register_tokens`).WithArgs("register-token", "test", ticket.ExpiresAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := st.CreateRegisterToken(ctx, "register-token", "test", ticket.ExpiresAt); err != nil {
		t.Fatalf("CreateRegisterToken: %v", err)
	}
	mock.ExpectExec(`UPDATE register_tokens SET used=true`).WithArgs("register-token").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if accepted, err := st.ConsumeRegisterToken(ctx, "register-token"); err != nil || !accepted {
		t.Fatalf("ConsumeRegisterToken accepted=%v err=%v", accepted, err)
	}
	assertMockExpectations(t, mock)
}

func TestConsumeTicketRejectsMissingAndDatabaseFailures(t *testing.T) {
	t.Parallel()
	st, mock, closeDB := newMockStore(t)
	defer closeDB()
	ctx := context.Background()
	now := time.Date(2026, 8, 24, 2, 0, 0, 0, time.UTC)

	mock.ExpectExec(`UPDATE tickets SET used_at`).WithArgs("missing", now).
		WillReturnResult(sqlmock.NewResult(0, 0))
	if _, _, ok, err := st.ConsumeTicket(ctx, "missing", now); err != nil || ok {
		t.Fatalf("missing ticket ok=%v err=%v", ok, err)
	}
	dbErr := errors.New("database unavailable")
	mock.ExpectExec(`UPDATE tickets SET used_at`).WithArgs("exec-error", now).WillReturnError(dbErr)
	if _, _, ok, err := st.ConsumeTicket(ctx, "exec-error", now); !errors.Is(err, dbErr) || ok {
		t.Fatalf("exec failure ok=%v err=%v", ok, err)
	}
	mock.ExpectExec(`UPDATE tickets SET used_at`).WithArgs("rows-error", now).
		WillReturnResult(sqlmock.NewErrorResult(dbErr))
	if _, _, ok, err := st.ConsumeTicket(ctx, "rows-error", now); !errors.Is(err, dbErr) || ok {
		t.Fatalf("RowsAffected failure ok=%v err=%v", ok, err)
	}
	mock.ExpectExec(`UPDATE tickets SET used_at`).WithArgs("vanished", now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT user_id, node_id FROM tickets`).WithArgs("vanished").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "node_id"}))
	if _, _, ok, err := st.ConsumeTicket(ctx, "vanished", now); err != nil || ok {
		t.Fatalf("vanished ticket ok=%v err=%v", ok, err)
	}
	assertMockExpectations(t, mock)
}
