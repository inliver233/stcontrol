package controller

import (
	"context"
	"database/sql/driver"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

type secretFreeJSON struct {
	forbidden string
}

func (m secretFreeJSON) Match(value driver.Value) bool {
	data, ok := value.([]byte)
	return ok && !strings.Contains(string(data), m.forbidden) && strings.Contains(string(data), "ciphertext")
}

func TestEnqueueAgentCommandEncryptsDurablePayload(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := New(config.DefaultController(), &store.Store{DB: db}, make([]byte, 32))
	node := &store.Node{ID: 12, AgentPSK: "agent-secret"}
	mock.ExpectQuery(`INSERT INTO agent_commands`).
		WithArgs(sqlmock.AnyArg(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", int64(12), "set_password",
			secretFreeJSON{forbidden: "plaintext-password"}, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"controller_generation"}).AddRow(int64(3)))
	generation, err := server.enqueueAgentCommand(context.Background(), node, "set_password", map[string]string{
		"password_hash": "plaintext-password",
	}, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	if err != nil || generation != 3 {
		t.Fatalf("generation=%d err=%v", generation, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
